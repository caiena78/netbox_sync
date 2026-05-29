#!/usr/bin/env python3
"""
sync_netbox_interfaces.py
=========================
Fetch Cisco devices from NetBox, collect live interface data, VLANs, trunk
configuration, and IP addresses, then sync everything back into NetBox.

Sync stages (each independently toggleable)
-------------------------------------------
1. Interface inventory  — name, description, speed, duplex
2. VLAN sync            — create VLANs in the site VLAN group
3. Trunk VLAN sync      — set 802.1Q mode / tagged / native VLANs on interfaces
4. IP + Prefix sync     — ensure prefix exists in correct site; link to VLAN

Transport selection
-------------------
  --transport auto      IOS-XE: NETCONF → RESTCONF → CLI (mandatory order)
                        NX-OS / IOS: CLI first
  --transport netconf|restconf|cli   Explicit: no fallback

Output
------
JSON array to **stdout**; logs to **stderr**.  One element per device::

    {
        "device":                       "core-rtr-01",
        "status":                       "success" | "failed",
        "transport_used":               "netconf" | "restconf" | "cli" | null,
        "interfaces_updated":           4,
        "interfaces_created":           0,
        "interfaces_skipped":           18,
        "vlan_created_count":           3,
        "vlan_existing_count":          10,
        "trunk_interfaces_updated_count": 2,
        "prefixes_created_count":       1,
        "prefixes_updated_count":       0,
        "prefixes_moved_site_count":    0,
        "errors":                       [],
        "attempts":                     [...]
    }
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import logging
import os
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional, Set, Tuple

from cisco_device_client import CiscoDeviceClient, CiscoDeviceClientError
from netbox_client import NetBoxClient, NetBoxClientError
from vault_client import (
    VaultClient,
    VaultError,
    add_vault_parser_args,
    is_vault_configured,
    resolve_vault_auth,
)

# --------------------------------------------------------------------------- #
# Platform slug → os_type mapping                                              #
# --------------------------------------------------------------------------- #

# Maximum number of individual NetBox VLAN lookups we will make per trunk
# interface when resolving VIDs not yet in the preloaded vid_map.  When the
# missing count exceeds this threshold (e.g. "1-4094" on NX-OS produces
# thousands of unknowns), we rely exclusively on the preloaded map rather
# than issuing thousands of API calls.
_VLAN_BULK_RESOLVE_LIMIT: int = 50

PLATFORM_SLUG_MAP: Dict[str, str] = {
    "iosxe": "iosxe", "ios-xe": "iosxe", "ios_xe": "iosxe",
    "cisco-iosxe": "iosxe", "cisco_iosxe": "iosxe",
    "nxos": "nxos", "nx-os": "nxos", "nx_os": "nxos",
    "cisco-nxos": "nxos", "cisco_nxos": "nxos",
    "ios": "ios", "cisco-ios": "ios", "cisco_ios": "ios",
}

log = logging.getLogger("sync_netbox_interfaces")

# Writes WARNING+ to sync_errors.log; handler is attached in _configure_logging.
_sync_err_log = logging.getLogger("sync_errors")

# --------------------------------------------------------------------------- #
# Interface name expansion                                                     #
# --------------------------------------------------------------------------- #

# Each tuple is (lowercase_prefix, canonical_long_form).
# MUST be sorted longest-prefix-first so the most specific match wins.
# E.g. "tengigabitethernet" must appear before "te".
_IFACE_EXPANSIONS: List[Tuple[str, str]] = sorted(
    [
        # Full canonical names (already expanded — normalise case)
        ("fortygigabitethernet",      "FortyGigabitEthernet"),
        ("hundredgigabitethernet",    "HundredGigabitEthernet"),
        ("appgigabitethernet",        "AppGigabitEthernet"),
        ("tengigabitethernet",        "TenGigabitEthernet"),
        ("gigabitethernet",           "GigabitEthernet"),
        ("twentyfivegige",            "TwentyFiveGigE"),
        ("fiftygige",                 "FiftyGigE"),     # Catalyst 9000 50G ports
        ("fastethernet",              "FastEthernet"),
        ("port-channel",              "Port-channel"),
        ("portchannel",               "Port-channel"),
        ("hundredgige",               "HundredGigE"),
        ("management",                "Management"),
        ("loopback",                  "Loopback"),
        ("ethernet",                  "Ethernet"),
        ("cellular",                  "Cellular"),
        ("dialer",                    "Dialer"),
        ("tunnel",                    "Tunnel"),
        ("serial",                    "Serial"),
        ("vlan",                      "Vlan"),
        ("mgmt",                      "mgmt"),     # NX-OS — keep lowercase
        ("nve",                       "nve"),       # NX-OS VxLAN
        ("bdi",                       "BDI"),
        # 3-char abbreviations
        ("twe",                       "TwentyFiveGigE"),
        ("fif",                       "FiftyGigE"),   # e.g. Fif2/1/0/48
        ("gig",                       "GigabitEthernet"),
        ("ten",                       "TenGigabitEthernet"),
        ("hun",                       "HundredGigE"),
        # 2-char abbreviations (checked after all longer prefixes)
        ("ap",                        "AppGigabitEthernet"),   # Ap1/0/1 → AppGigabitEthernet1/0/1
        ("gi",                        "GigabitEthernet"),
        ("ge",                        "GigabitEthernet"),
        ("te",                        "TenGigabitEthernet"),
        ("tw",                        "TwentyFiveGigE"),
        ("hu",                        "HundredGigE"),
        ("fo",                        "FortyGigabitEthernet"),
        ("fa",                        "FastEthernet"),
        ("lo",                        "Loopback"),
        ("po",                        "Port-channel"),
        ("tu",                        "Tunnel"),
        ("se",                        "Serial"),
        ("mg",                        "Management"),
        ("ma",                        "Management"),
        ("et",                        "Ethernet"),
        ("vl",                        "Vlan"),
    ],
    key=lambda x: len(x[0]),
    reverse=True,   # longest match first
)
# Expansion smoke-test (evaluated once at import; raises AssertionError on regression):
# Fif2/1/0/48   → FiftyGigE2/1/0/48
# fif2/1/0/48   → FiftyGigE2/1/0/48
# FiftyGigE2/1  → FiftyGigE2/1  (already canonical)
assert "FiftyGigE" in [c for _, c in _IFACE_EXPANSIONS], "FiftyGigE missing from expansions"

# Physical interface type prefixes that carry a VC member / chassis-slot
# number as their first numeric component (e.g. GigabitEthernet**1**/0/1).
# Logical interfaces (Loopback, Port-channel, Vlan, Tunnel …) are excluded.
_VC_ROUTABLE_PREFIXES: frozenset = frozenset({
    "GigabitEthernet",
    "FastEthernet",
    "TenGigabitEthernet",
    "TwentyFiveGigE",
    "FiftyGigE",            # Catalyst 9000 50G — e.g. FiftyGigE2/1/0/48
    "FortyGigabitEthernet",
    "HundredGigE",
    "HundredGigabitEthernet",
    "AppGigabitEthernet",
    "Ethernet",   # NX-OS
})


def expand_interface_name(name: str) -> str:
    """
    Expand a Cisco interface abbreviation to its full canonical name.

    The expansion is a longest-prefix match on the alphabetic portion of the
    name; the numeric suffix (port numbers, subinterface ID, etc.) is
    preserved verbatim.

    Examples
    --------
    ``gi1/0/1``       → ``GigabitEthernet1/0/1``
    ``Te2/1/1``       → ``TenGigabitEthernet2/1/1``
    ``Po10``          → ``Port-channel10``
    ``Lo0``           → ``Loopback0``
    ``Vlan100``       → ``Vlan100``
    ``Ethernet1/1``   → ``Ethernet1/1``  (NX-OS, already correct)
    ``mgmt0``         → ``mgmt0``        (NX-OS management, kept lowercase)
    """
    name = name.strip()
    name_lower = name.lower()
    for prefix_lower, canonical in _IFACE_EXPANSIONS:
        if name_lower.startswith(prefix_lower):
            suffix = name[len(prefix_lower):]
            return canonical + suffix
    return name


# Map from expanded canonical interface prefix → NetBox type identifier.
# Ordered longest-first so a more specific prefix takes priority if two
# entries share a common leading substring.
_NETBOX_TYPE_MAP: List[Tuple[str, str]] = sorted(
    [
        ("HundredGigabitEthernet", "100gbase-x-qsfp28"),
        ("HundredGigE",            "100gbase-x-qsfp28"),
        ("FortyGigabitEthernet",   "40gbase-x-qsfpp"),
        ("TwentyFiveGigE",         "25gbase-x-sfp28"),
        ("FiftyGigE",              "50gbase-x-sfp28"),
        ("TenGigabitEthernet",     "10gbase-x-sfpp"),
        ("AppGigabitEthernet",     "1000base-t"),
        ("GigabitEthernet",        "1000base-t"),
        ("FastEthernet",           "100base-tx"),
        ("Management",             "1000base-t"),
        ("mgmt",                   "1000base-t"),
        ("Port-channel",           "lag"),
        ("Loopback",               "virtual"),
        ("Vlan",                   "virtual"),
        ("Tunnel",                 "virtual"),
        ("BDI",                    "virtual"),
        ("nve",                    "virtual"),
    ],
    key=lambda x: len(x[0]),
    reverse=True,
)


# Speed-based NetBox type for NX-OS "Ethernet" ports (speed in kbps).
# Sorted descending so the first match wins on the highest speed tier.
_ETHERNET_SPEED_KBPS: List[Tuple[int, str]] = sorted(
    [
        (400_000_000, "400gbase-x-qsfpdd"),
        (100_000_000, "100gbase-x-qsfp28"),
         (40_000_000, "40gbase-x-qsfpp"),
         (25_000_000, "25gbase-x-sfp28"),
         (10_000_000, "10gbase-x-sfpp"),
          (1_000_000, "1000base-x-sfp"),   # refined to copper below if no transceiver
            (100_000, "100base-tx"),
    ],
    key=lambda x: x[0],
    reverse=True,
)


def _infer_ethernet_type(
    speed_kbps: Optional[int],
    has_transceiver: Optional[bool],
) -> str:
    """
    Guess the NetBox type for a NX-OS ``Ethernet`` port whose speed cannot be
    determined from the interface name alone.

    At 1 G:
    - transceiver present  → ``"1000base-x-sfp"`` (fibre/optical SFP)
    - transceiver absent   → ``"1000base-t"``      (copper RJ-45)
    - transceiver unknown  → ``"1000base-x-sfp"``  (NX-OS ports are almost
                             always SFP-based; conservative guess)

    At all other speeds the transceiver is implied by the speed tier.
    Returns ``"other"`` when speed is unavailable or zero.
    """
    if not speed_kbps:
        return "other"
    for threshold, nb_type in _ETHERNET_SPEED_KBPS:
        if speed_kbps >= threshold:
            # Refine 1G: copper if we *know* no transceiver is present
            if nb_type == "1000base-x-sfp" and has_transceiver is False:
                return "1000base-t"
            return nb_type
    return "other"


def infer_netbox_interface_type(
    iface_name: str,
    speed_kbps: Optional[int] = None,
    has_transceiver: Optional[bool] = None,
) -> str:
    """
    Return the NetBox ``type`` identifier for *iface_name*.

    The name is expected to already be expanded (``expand_interface_name()``
    output), but the function re-runs the expansion as a safety net.

    For NX-OS ``Ethernet`` ports (speed not encoded in the name), the optional
    *speed_kbps* and *has_transceiver* hints are used to make a best-effort
    guess.  Pass them from the interface inventory and transceiver map.

    Returns ``"other"`` when no mapping rule matches and no speed hint is
    available.
    """
    expanded = expand_interface_name(iface_name)
    for prefix, nb_type in _NETBOX_TYPE_MAP:
        if expanded.startswith(prefix):
            return nb_type
    # NX-OS bare "Ethernet" — speed + transceiver determine the type
    if expanded.startswith("Ethernet"):
        return _infer_ethernet_type(speed_kbps, has_transceiver)
    return "other"


def get_vc_member_slot(name: str) -> Optional[int]:
    """
    Return the VC member / chassis slot number embedded in *name*.

    The slot is the first integer in the interface identifier, which on
    Cisco stacked and modular platforms represents the switch / line-card
    number:

    ``GigabitEthernet1/0/1``  → 1  (stack member 1)
    ``TenGigabitEthernet3/1/1`` → 3  (stack member 3)
    ``Ethernet2/1``           → 2  (NX-OS module 2)

    Returns ``None`` for logical interfaces (Loopback, Port-channel, Vlan,
    Tunnel, etc.) where the first number does not identify a physical slot.
    """
    # Only route physical interface types — logical types are device-wide
    expanded = expand_interface_name(name)
    if not any(expanded.startswith(p) for p in _VC_ROUTABLE_PREFIXES):
        return None
    m = re.search(r"(\d+)", expanded)
    return int(m.group(1)) if m else None


# --------------------------------------------------------------------------- #
# Device model family classification                                           #
# --------------------------------------------------------------------------- #

_MODEL_FAMILY_C9600   = "c9600"    # Catalyst 9606/9610/9616 — StackWise Virtual
_MODEL_FAMILY_C3750   = "c3750"    # Catalyst 3750 / WS-C3750 stacks
_MODEL_FAMILY_C9K     = "c9k"      # Catalyst 9200/9300/9400/9500 — physical stacks
_MODEL_FAMILY_GENERIC = "generic"  # All other platforms

# (pattern, family) in priority order — first match wins.
_MODEL_PATTERNS: List[Tuple["re.Pattern[str]", str]] = [
    (re.compile(r"C9606|C9610|C9616|C96\d\d|Catalyst\s*96\d\d", re.I), _MODEL_FAMILY_C9600),
    (re.compile(r"WS-C3750|C3750|Catalyst\s*3750",               re.I), _MODEL_FAMILY_C3750),
    (re.compile(r"C9[2345]\d\d|Catalyst\s*9[2345]\d\d",          re.I), _MODEL_FAMILY_C9K),
]


def classify_device_model(model_string: str) -> str:
    """
    Map a Cisco device model string to a known family slug.

    Parameters
    ----------
    model_string : str
        The ``device_type.model`` value from NetBox (case-insensitive).

    Returns
    -------
    str
        One of ``_MODEL_FAMILY_*`` constants.  Falls back to
        ``_MODEL_FAMILY_GENERIC`` when no pattern matches.
    """
    for pattern, family in _MODEL_PATTERNS:
        if pattern.search(model_string or ""):
            return family
    return _MODEL_FAMILY_GENERIC


def parse_cisco_interface(name: str) -> dict:
    """
    Parse a Cisco interface name into its structural components.

    Component assignment by numeric-part count after the interface type
    prefix (e.g. the ``2/1/0/28`` in ``TwentyFiveGigE2/1/0/28``):

    ======  ===========================================
    Parts   Interpretation
    ======  ===========================================
    1       port only  (e.g. Loopback0 — non-physical)
    2       module / port  (NX-OS Ethernet2/1 style)
    3       member / module / port
    4       member / module / subslot / port (C9600)
    5+      member=raw[0], module=raw[1], port=raw[-1]
    ======  ===========================================

    The *subslot* component (index 2 in 4-part names) is captured in
    ``raw_components`` but intentionally ignored for NetBox module
    matching per the spec.

    Only interfaces whose expanded name starts with a prefix in
    ``_VC_ROUTABLE_PREFIXES`` are treated as physical; all others
    return ``is_physical=False`` with ``member/module/port = None``.

    Parameters
    ----------
    name : str
        Raw interface name as reported by the device (abbreviated or full).

    Returns
    -------
    dict::

        {
            "is_physical":     bool,
            "normalized_name": str,         # expand_interface_name() result
            "member":          int | None,  # VC / stack member number
            "module":          int | None,  # line-card / slot (subslot ignored)
            "port":            int | None,  # final port index
            "raw_components":  list[int],   # every numeric token, in order
        }

    Examples
    --------
    ``TwentyFiveGigE2/1/0/28``  → member=2, module=1, port=28, raw=[2,1,0,28]
    ``FastEthernet3/0/9``       → member=3, module=0, port=9,  raw=[3,0,9]
    ``GigabitEthernet1/1/1``    → member=1, module=1, port=1,  raw=[1,1,1]
    ``GigabitEthernet1/0/24``   → member=1, module=0, port=24, raw=[1,0,24]
    ``Ethernet2/1``             → member=None, module=2, port=1, raw=[2,1]
    """
    normalized = expand_interface_name(name)
    is_physical = any(normalized.startswith(p) for p in _VC_ROUTABLE_PREFIXES)

    result: dict = {
        "is_physical":     is_physical,
        "normalized_name": normalized,
        "member":          None,
        "module":          None,
        "port":            None,
        "raw_components":  [],
    }

    if not is_physical:
        return result

    m = re.search(r"(\d+(?:[/.]\d+)*)", normalized)
    if not m:
        return result

    raw = [int(x) for x in re.split(r"[/.]", m.group(1))]
    result["raw_components"] = raw
    n = len(raw)

    if n == 1:
        result["port"] = raw[0]
    elif n == 2:
        # NX-OS Ethernet<module>/<port> — no separate VC member
        result["module"] = raw[0]
        result["port"]   = raw[1]
    elif n == 3:
        result["member"] = raw[0]
        result["module"] = raw[1]
        result["port"]   = raw[2]
    elif n == 4:
        # C9600 style: member / slot / subslot / port — subslot (raw[2]) ignored
        result["member"] = raw[0]
        result["module"] = raw[1]
        result["port"]   = raw[3]
    else:
        result["member"] = raw[0]
        result["module"] = raw[1]
        result["port"]   = raw[-1]

    return result


# Matches SVI interface names: Vlan162, vlan2162, VLAN10, etc.
_SVI_RE = re.compile(r"(?i)^vlan(\d+)$")


def _resolve_prefix_vlan(
    iface_name: str,
    vlan_id_map: Dict[int, int],
    nb: NetBoxClient,
    device_name: str,
    prefix_net: str,
) -> Optional[int]:
    """
    Return the NetBox VLAN ID that should be linked to *prefix_net*.

    Only SVI interfaces (``Vlan<N>``, case-insensitive) provide a
    deterministic interface → VLAN relationship.  All other interface
    types return ``None`` so no VLAN is guessed.

    Lookup order
    ------------
    1. ``vlan_id_map`` — VLANs already synced or preloaded this run (fast).
    2. Direct NetBox query via ``nb.find_vlan_id_by_vid()`` — fallback for
       VLANs that exist in NetBox but were not discovered on this device
       during this run (e.g. inter-device VLANs or pre-existing records).

    Parameters
    ----------
    iface_name : str
        Interface name exactly as reported by the device (e.g. ``"Vlan162"``).
    vlan_id_map : dict
        ``{802.1Q_vid: netbox_vlan_id}`` populated during the VLAN sync stage.
    nb : NetBoxClient
    device_name : str
        Used only for log messages.
    prefix_net : str
        Used only for log messages.

    Returns
    -------
    int or None
        NetBox VLAN primary key, or ``None`` when no deterministic link
        can be established.
    """
    m = _SVI_RE.match(iface_name.strip())
    if not m:
        return None   # not an SVI — no safe VLAN inference

    svi_vid = int(m.group(1))

    # ── Fast path: VLAN already in the local map ──────────────────────────
    nb_vlan_id = vlan_id_map.get(svi_vid)
    if nb_vlan_id is not None:
        log.debug(
            "%-30s  prefix %-22s  ← SVI Vlan%s → nb_vlan_id=%s (map)",
            device_name, prefix_net, svi_vid, nb_vlan_id,
        )
        return nb_vlan_id

    # ── Slow path: VID not in map — query NetBox directly ─────────────────
    log.debug(
        "%-30s  prefix %-22s  ← SVI Vlan%s not in vlan_id_map, querying NetBox",
        device_name, prefix_net, svi_vid,
    )
    nb_vlan_id = nb.find_vlan_id_by_vid(svi_vid)
    if nb_vlan_id is not None:
        log.debug(
            "%-30s  prefix %-22s  ← SVI Vlan%s → nb_vlan_id=%s (NetBox lookup)",
            device_name, prefix_net, svi_vid, nb_vlan_id,
        )
        return nb_vlan_id

    log.warning(
        "%-30s  prefix %-22s  ← SVI Vlan%s: no matching VLAN found in NetBox "
        "— prefix will be written without a VLAN assignment",
        device_name, prefix_net, svi_vid,
    )
    return None


def build_vc_member_map(vc_id: int, nb: NetBoxClient) -> Dict[int, int]:
    """
    Build a ``{vc_position: device_id}`` map for all members of a virtual
    chassis.

    Parameters
    ----------
    vc_id : int
        NetBox virtual chassis primary key.
    nb : NetBoxClient

    Returns
    -------
    dict
        Maps each member's ``vc_position`` to its NetBox device ID.
        Members without a ``vc_position`` are skipped.
    """
    mapping: Dict[int, int] = {}
    try:
        members = nb.get_virtual_chassis_members(vc_id)
        for m in members:
            pos = m.get("vc_position")
            dev_id = m.get("id")
            if pos is not None and dev_id is not None:
                mapping[int(pos)] = int(dev_id)
    except NetBoxClientError as exc:
        log.warning("Could not build VC member map for vc_id=%s: %s", vc_id, exc)
    return mapping


def resolve_target_device_id(
    iface_name: str,
    default_device_id: int,
    vc_member_map: Dict[int, int],
) -> int:
    """
    Return the correct NetBox device ID for *iface_name*.

    When *vc_member_map* is non-empty the interface's slot number is
    extracted and matched to the appropriate VC member.  Falls back to
    *default_device_id* when the interface is logical, the slot number is
    not in the map, or no VC map is provided.
    """
    if not vc_member_map:
        return default_device_id
    slot = get_vc_member_slot(iface_name)
    if slot is None:
        return default_device_id
    return vc_member_map.get(slot, default_device_id)


def build_vc_module_maps(
    vc_member_map: Dict[int, int],
    nb: NetBoxClient,
    device_id: int,
) -> Dict[int, Dict[int, int]]:
    """
    Build per-device module maps for every device in *vc_member_map*.

    Queries ``dcim.module_bays`` and the installed modules for each member
    device (plus the connected *device_id*) and returns a nested dict::

        {device_id: {slot_number: module_id}, ...}

    When no module bays / modules are installed on a device, its inner dict
    is empty.  Failures per-device are logged at DEBUG level and produce an
    empty inner dict rather than propagating an exception.

    Parameters
    ----------
    vc_member_map : dict
        ``{vc_position: device_id}`` map (may be empty for non-VC devices).
    nb : NetBoxClient
    device_id : int
        The directly-connected device (master or only member).

    Returns
    -------
    dict
        ``{device_id: {slot_number: module_id}}``
    """
    all_device_ids: Set[int] = {device_id} | set(vc_member_map.values())
    maps: Dict[int, Dict[int, int]] = {}
    for dev_id in all_device_ids:
        try:
            maps[dev_id] = nb.build_device_module_map(dev_id)
        except NetBoxClientError as exc:
            log.debug(
                "build_vc_module_maps: could not build module map for "
                "device_id=%s: %s", dev_id, exc,
            )
            maps[dev_id] = {}
    return maps


def resolve_target_module_id(
    module_slot: Optional[int],
    device_module_map: Dict[int, int],
) -> Optional[int]:
    """
    Return the NetBox module ID for *module_slot* from *device_module_map*.

    Returns ``None`` when:
    - *module_slot* is ``None`` (interface has no slot component)
    - *module_slot* is ``0`` (mid-segment zero — no dedicated module bay)
    - The slot has no installed module in the map

    In all three cases the interface should be created at the device level
    with no ``module`` association.

    Parameters
    ----------
    module_slot : int or None
    device_module_map : dict
        ``{slot_number: module_id}`` for the target device.
    """
    if not module_slot:   # None or 0
        return None
    return device_module_map.get(module_slot)


def _resolve_vrf_id(
    vrf_name: Optional[str],
    vrf_cache: Dict[str, int],
    nb: NetBoxClient,
    device_name: str,
    dry_run: bool,
) -> Optional[int]:
    """
    Resolve a VRF name to a NetBox VRF primary key.

    - Returns ``None`` immediately when *vrf_name* is ``None`` or blank
      (global routing table — no VRF assignment needed).
    - On the first encounter of a name, calls :meth:`NetBoxClient.ensure_vrf`
      (or just looks it up in dry-run mode) and caches the result.
    - Subsequent calls for the same name (case-insensitive) are served from
      the cache without additional API calls.
    - When VRF creation / lookup fails, logs a warning and returns ``None``
      (graceful degradation — the IP/prefix is written to the global table
      rather than blocking the entire device sync).

    Parameters
    ----------
    vrf_name : str or None
        Raw VRF name from the device running-config.
    vrf_cache : dict
        Mutable ``{lowercase_vrf_name: vrf_id}`` dict — shared across all
        stages of the same device sync run.
    nb : NetBoxClient
    device_name : str
        Used only in log messages.
    dry_run : bool

    Returns
    -------
    int or None
        NetBox VRF primary key, or ``None`` for the global table.
    """
    if not vrf_name or not vrf_name.strip():
        return None

    vrf_name = vrf_name.strip()
    cache_key = vrf_name.lower()

    if cache_key in vrf_cache:
        return vrf_cache[cache_key]

    if dry_run:
        # Attempt a read-only lookup; log "would create" when absent.
        try:
            vrf = nb.get_vrf_by_name(vrf_name)
        except NetBoxClientError:
            vrf = None

        if vrf:
            vrf_id = vrf["id"]
            vrf_cache[cache_key] = vrf_id
            log.debug(
                "%-30s  VRF %r exists in NetBox id=%s", device_name, vrf_name, vrf_id
            )
            return vrf_id

        log.info(
            "DRY-RUN  %-30s  VRF %r not in NetBox — would create",
            device_name, vrf_name,
        )
        return None   # cannot create in dry-run; treat as global for this run

    # Live mode — create if absent.
    try:
        vrf = nb.ensure_vrf(vrf_name)
        vrf_id = vrf["id"]
        action = vrf.get("_action", "existing")
        if action == "created":
            log.info(
                "%-30s  VRF %r not found in NetBox, creating... id=%s",
                device_name, vrf_name, vrf_id,
            )
        else:
            log.debug(
                "%-30s  VRF %r → id=%s (existing)", device_name, vrf_name, vrf_id
            )
        vrf_cache[cache_key] = vrf_id
        return vrf_id
    except NetBoxClientError as exc:
        log.warning(
            "%-30s  VRF %r: ensure failed: %s — treating as global",
            device_name, vrf_name, exc,
        )
        return None


# --------------------------------------------------------------------------- #
# CLI argument parser                                                          #
# --------------------------------------------------------------------------- #

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Sync Cisco device inventory into NetBox.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    nb = p.add_argument_group("NetBox connection")
    nb.add_argument(
        "--netbox-url",
        default=os.environ.get("NETBOX_URL", ""),
        metavar="URL",
        help="NetBox base URL (env: NETBOX_URL). Ignored when Vault is configured.",
    )
    nb.add_argument(
        "--netbox-token",
        default=os.environ.get("NETBOX_API", ""),
        metavar="TOKEN",
        help="NetBox API token (env: NETBOX_API). Ignored when Vault is configured.",
    )
    nb.add_argument(
        "--netbox-verify-ssl",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Verify NetBox TLS certificate (default: true)",
    )

    sel = p.add_argument_group("Device selection (pick one, or omit for all)")
    sel.add_argument("--device", metavar="NAME", help="Single device name")
    sel.add_argument("--devices", metavar="NAME,...", help="Comma-separated device names")
    sel.add_argument("--device-file", metavar="PATH",
                     help="File with one device name per line (#comments ignored)")
    sel.add_argument(
        "--device-filter", default="{}",
        metavar="JSON",
        help="NetBox DCIM device filter as JSON (default: all devices)",
    )
    sel.add_argument("--all", dest="all_devices", action="store_true",
                     help="Explicit 'process all' flag")
    sel.add_argument(
        "--site-slug",
        default="",
        metavar="SLUG",
        help=(
            "Limit processing to devices in this NetBox site (site slug, not name). "
            "Example: --site-slug lakeview.  When omitted all sites are included.  "
            "This filter stacks with --device-filter."
        ),
    )

    cred = p.add_argument_group("Cisco credentials")
    cred.add_argument("--username",
                      default=os.environ.get("CISCO_SRV_ACCOUNT", ""),
                      help="SSH username (env: CISCO_SRV_ACCOUNT). Ignored when Vault is configured.")
    cred.add_argument("--password",
                      default=os.environ.get("CISCO_SRV_PWD", ""),
                      help="SSH password (env: CISCO_SRV_PWD). Ignored when Vault is configured.")
    cred.add_argument("--enable-secret",
                      default=os.environ.get("CISCO_ENABLE_PWD", ""),
                      help="Enable-mode secret (env: CISCO_ENABLE_PWD)")

    run = p.add_argument_group("Runtime options")
    run.add_argument(
        "--transport",
        choices=["auto", "cli", "restconf", "netconf"],
        default="auto",
        type=str.lower,   # accept "CLI", "NetConf", etc. — normalise to lowercase
        help="Transport (auto applies OS fallback chain; default: auto)",
    )
    run.add_argument("--dry-run", action="store_true",
                     help="Print changes without writing to NetBox")
    run.add_argument(
        "--force", action="store_true",
        help=(
            "Relocate interfaces that are assigned to the wrong VC member device "
            "and remove duplicate source interfaces when the destination already "
            "has a correctly-placed copy. Without this flag, misplaced or "
            "duplicate interfaces are left untouched and a warning is logged "
            "instead. Module-slot corrections (wrong module association on the "
            "same device) are always applied regardless of this flag."
        ),
    )
    run.add_argument(
        "--force-type", action="store_true",
        help=(
            "Write the inferred interface type to NetBox. "
            "Without this flag the 'type' field is never included in the "
            "payload, so existing NetBox values are preserved and newly "
            "created interfaces default to NetBox's own default. "
            "With this flag the inferred type is written for every interface "
            "— new and existing — and any mismatched value is overwritten."
        ),
    )
    run.add_argument("--max-workers", type=int, default=5, metavar="N",
                     help=(
                         "Concurrent device threads (default: 5). "
                         "Each thread holds one SSH session and makes concurrent "
                         "NetBox API calls. Beyond ~20 threads, SSH device limits "
                         "and NetBox rate-limits dominate — 10-20 is optimal for "
                         "most environments; 100 can cause connection exhaustion."
                     ))
    run.add_argument("--max-api-connections", type=int, default=None, metavar="N",
                     help=(
                         "Size of the HTTP connection pool for NetBox API calls. "
                         "Defaults to max-workers + 10 to prevent pool exhaustion "
                         "under high concurrency."
                     ))
    run.add_argument("--timeout", type=int, default=30, metavar="SEC",
                     help="Device timeout seconds (default: 30)")
    run.add_argument("--fail-fast", action="store_true",
                     help="Abort remaining work for a device on first critical error")
    run.add_argument("--profile", action="store_true",
                     help=(
                         "Enable cProfile CPU profiling. Writes sync_profile.prof "
                         "to the current directory and logs the top-20 hotspots. "
                         "Safe in production; adds negligible overhead."
                     ))
    run.add_argument("--mem-profile", action="store_true",
                     help=(
                         "Enable tracemalloc memory profiling. Logs the top-15 "
                         "allocation sites when the run completes. "
                         "Adds ~20%% memory overhead; disable in production."
                     ))
    run.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="INFO",
    )
    run.add_argument(
        "--log-file",
        metavar="PATH",
        default=None,
        help=(
            "Also write log output to this file (appended, UTF-8). "
            "Stderr output is always kept regardless of this setting."
        ),
    )

    sync = p.add_argument_group("Sync stage toggles")
    sync.add_argument("--sync-vlans", action=argparse.BooleanOptionalAction,
                      default=True, help="Sync VLANs to NetBox (default: true)")
    sync.add_argument("--sync-trunks", action=argparse.BooleanOptionalAction,
                      default=True, help="Sync trunk VLAN config (default: true)")
    sync.add_argument("--sync-prefixes", action=argparse.BooleanOptionalAction,
                      default=True, help="Sync IP prefixes to NetBox (default: true)")
    sync.add_argument(
        "--skip-vlan-ids",
        default="1,1002,1003,1004,1005",
        metavar="IDS",
        help=(
            "Comma-separated VLAN IDs to skip (default: 1,1002,1003,1004,1005). "
            "1002-1005 are Cisco IOS reserved VLANs (fddi-default, trcrf-default, "
            "fddinet-default, trbrf-default) that must never appear in NetBox."
        ),
    )
    sync.add_argument(
        "--deny-vlan-group-name-substring",
        default="internet",
        metavar="STR",
        help="Exclude VLAN groups whose name contains this substring (default: internet)",
    )

    vault_grp = p.add_argument_group("Vault authentication")
    add_vault_parser_args(vault_grp)

    return p


# --------------------------------------------------------------------------- #
# NetBox helpers                                                               #
# --------------------------------------------------------------------------- #

def _site_slug_matches(device: dict, site_slug: str) -> bool:
    """
    Return ``True`` when *device* belongs to the site identified by
    *site_slug*, or when *site_slug* is empty (no filter applied).

    The site slug is taken from the nested ``site.slug`` field that NetBox
    returns on every device record.  Devices with no site assignment are
    always excluded when a slug filter is active.
    """
    if not site_slug:
        return True
    site = device.get("site")
    if not site:
        log.warning(
            "Device %r has no site assigned — excluded by --site-slug %r",
            device.get("name", "?"), site_slug,
        )
        return False
    slug = site.get("slug", "") if isinstance(site, dict) else ""
    if slug != site_slug:
        log.debug(
            "Device %r is in site %r, not %r — skipped by site filter",
            device.get("name", "?"), slug, site_slug,
        )
        return False
    return True


def resolve_single_device(name: str, nb: NetBoxClient) -> Optional[dict]:
    """
    Resolve one name to a usable device dict.

    Lookup order
    ------------
    1. **Virtual chassis** — search ``dcim.virtual_chassis`` by name.
       If found, iterate members (master first, then by ``vc_position``).
       Return the first member that has a primary IP or OOB IP.
    2. **Regular device** — fall back to ``dcim.devices`` by name.

    The returned dict is a standard NetBox device dict.  When the device
    came from a virtual chassis lookup the dict is augmented with two
    read-only keys:

    * ``"_vc_name"`` — the virtual chassis name that was searched
    * ``"_vc_id"``   — the virtual chassis NetBox ID

    Returns ``None`` when no usable device can be found.
    """
    # ── 1. Try virtual chassis ─────────────────────────────────────────────
    try:
        vc = nb.find_virtual_chassis(name)
        if vc:
            vc_id   = vc["id"]
            vc_name = vc.get("name", name)
            members = nb.get_virtual_chassis_members(vc_id)
            if not members:
                log.warning(
                    "Virtual chassis %r (id=%s) has no member devices.", vc_name, vc_id
                )
            else:
                for member in members:
                    ip = get_device_mgmt_ip(member)
                    if ip:
                        member["_vc_name"] = vc_name
                        member["_vc_id"]   = vc_id
                        log.info(
                            "Virtual chassis %r → using member %r  ip=%s  "
                            "vc_position=%s",
                            vc_name,
                            member.get("name"),
                            ip,
                            member.get("vc_position"),
                        )
                        return member
                log.warning(
                    "Virtual chassis %r found but no member has a reachable IP "
                    "(checked primary_ip4, primary_ip6, oob_ip).",
                    vc_name,
                )
                return None
    except NetBoxClientError as exc:
        log.warning("Virtual chassis lookup error for %r: %s", name, exc)

    # ── 2. Fall back to regular device ─────────────────────────────────────
    d = nb.get_device(name=name)
    if d:
        return d
    log.warning("%r not found as virtual chassis or device in NetBox.", name)
    return None


def resolve_device_list(args: argparse.Namespace, nb: NetBoxClient) -> List[dict]:
    """
    Return the ordered list of NetBox device dicts to process.

    For named lookups (--device / --devices / --device-file) each name is
    resolved via :func:`resolve_single_device`, which tries virtual chassis
    first, then falls back to a regular device search.

    When no device selector is given all devices matching --device-filter
    are returned directly (no virtual-chassis expansion).
    """
    site_slug: str = getattr(args, "site_slug", "") or ""

    if args.device:
        d = resolve_single_device(args.device.strip(), nb)
        if d and _site_slug_matches(d, site_slug):
            return [d]
        return []

    if args.devices:
        names = [n.strip() for n in args.devices.split(",") if n.strip()]
        result = []
        for name in names:
            d = resolve_single_device(name, nb)
            if d and _site_slug_matches(d, site_slug):
                result.append(d)
        return result

    if args.device_file:
        try:
            with open(args.device_file) as fh:
                names = [
                    ln.strip() for ln in fh
                    if ln.strip() and not ln.strip().startswith("#")
                ]
        except OSError as exc:
            log.error("Cannot read --device-file %r: %s", args.device_file, exc)
            sys.exit(1)
        result = []
        for name in names:
            d = resolve_single_device(name, nb)
            if d and _site_slug_matches(d, site_slug):
                result.append(d)
        return result

    # Default: all devices matching --device-filter (no VC expansion).
    # Merge site slug into the API filter so NetBox does the filtering
    # server-side — avoids fetching the full device list unnecessarily.
    try:
        nb_filter: dict = json.loads(args.device_filter)
    except json.JSONDecodeError as exc:
        log.error("Invalid --device-filter JSON: %s", exc)
        sys.exit(1)
    if site_slug:
        nb_filter["site"] = site_slug
    devices = nb.get_devices(filters=nb_filter)
    log.info(
        "NetBox returned %d device(s) matching filter %s", len(devices), nb_filter
    )
    return devices


def _device_has_primary_ip(device: dict) -> bool:
    """
    Return ``True`` when the device has at least one primary IP configured
    in NetBox (``primary_ip4`` or ``primary_ip6``).

    ``oob_ip`` is intentionally excluded — the requirement is that a primary
    IP must exist before we attempt any device connection.
    """
    return bool(device.get("primary_ip4") or device.get("primary_ip6"))


def get_device_mgmt_ip(device: dict) -> Optional[str]:
    """
    Return the best available management IP for a device dict.

    Priority: ``primary_ip4`` → ``primary_ip6`` → ``oob_ip``.
    Returns the address without its prefix length.
    """
    for field in ("primary_ip4", "primary_ip6", "oob_ip"):
        ip_field = device.get(field)
        if not ip_field:
            continue
        addr = (
            ip_field.get("address", "")
            if isinstance(ip_field, dict)
            else str(ip_field)
        )
        if addr:
            return addr.split("/")[0]
    return None


def get_device_os_type(device: dict) -> Optional[str]:
    """Map NetBox platform slug/name to os_type string."""
    platform = device.get("platform")
    if not platform:
        return None
    slug = (
        (platform.get("slug") or platform.get("name") or "").lower().strip()
        if isinstance(platform, dict)
        else str(platform).lower().strip()
    )
    return PLATFORM_SLUG_MAP.get(slug)


def compute_prefix_cidr(ip_cidr: str) -> Optional[str]:
    """
    Return the network address of *ip_cidr*.

    ``"10.1.2.3/24"`` → ``"10.1.2.0/24"``.
    Returns ``None`` when *ip_cidr* has no prefix length or is unparseable.
    """
    if not ip_cidr or "/" not in ip_cidr:
        return None
    try:
        return str(ipaddress.ip_interface(ip_cidr).network)
    except ValueError:
        return None


# --------------------------------------------------------------------------- #
# Per-device sync stages                                                       #
# --------------------------------------------------------------------------- #

def _sync_vlans(
    cisco: CiscoDeviceClient,
    nb: NetBoxClient,
    device_name: str,
    site_id: int,
    skip_vids: Set[int],
    deny_substring: str,
    dry_run: bool,
) -> tuple:
    """
    Collect VLANs from device and ensure they exist in NetBox.

    Returns
    -------
    tuple
        ``(vlan_id_map, vlan_created, vlan_existing, errors, ok)``
        where ``vlan_id_map`` maps vid→NetBox VLAN ID, and ``ok`` is False
        when a fatal error (missing VLAN group) prevents any VLAN sync.
    """
    vlan_id_map: Dict[int, int] = {}
    created = existing = 0
    errors: List[str] = []

    # ── Find (or fail on) the site VLAN group ─────────────────────────────
    try:
        vlan_group = nb.find_vlan_group_for_site(site_id, deny_substring=deny_substring)
    except NetBoxClientError as exc:
        errors.append(str(exc))
        return vlan_id_map, created, existing, errors, False

    vlan_group_id = vlan_group["id"]
    log.debug("%-30s  using VLAN group id=%s %r", device_name, vlan_group_id,
              vlan_group.get("name"))

    # ── Preload ALL existing VLANs from the group ─────────────────────────
    # This ensures trunk VLAN assignment works even for VLANs that were
    # already in NetBox before this run.
    try:
        preloaded = nb.get_vlans_for_group(vlan_group_id)
        vlan_id_map.update(preloaded)
        log.debug("%-30s  preloaded %d VLANs from group", device_name, len(preloaded))
    except NetBoxClientError as exc:
        log.warning("%-30s  could not preload VLANs from group: %s", device_name, exc)

    # ── Collect VLANs from device ─────────────────────────────────────────
    try:
        device_vlans = cisco.get_vlans_inventory()
    except Exception as exc:
        errors.append(f"VLAN collection failed: {exc}")
        return vlan_id_map, created, existing, errors, True  # non-fatal; map may still be useful

    log.info("%-30s  device reported %d VLANs", device_name, len(device_vlans))

    # ── Create / confirm each device VLAN in NetBox ───────────────────────
    for vlan in device_vlans:
        vid = vlan.get("vid")
        if vid is None or vid in skip_vids:
            continue

        if dry_run:
            if vid not in vlan_id_map:
                log.info("DRY-RUN  %-30s  VLAN %-5s  %r  → would create",
                         device_name, vid, vlan.get("name"))
                vlan_id_map[vid] = -(vid)   # placeholder
                created += 1
            else:
                log.debug("DRY-RUN  %-30s  VLAN %-5s  already in NetBox", device_name, vid)
                existing += 1
            continue

        try:
            nb_vlan = nb.ensure_vlan_in_site_group(
                site_id=site_id,
                vlan_group_id=vlan_group_id,
                vid=vid,
                name=vlan.get("name"),
            )
            vlan_id_map[vid] = nb_vlan["id"]
            if nb_vlan.get("_action") == "created":
                created += 1
                log.info("%-30s  VLAN created  vid=%-5s  name=%r",
                         device_name, vid, vlan.get("name"))
            else:
                existing += 1
        except NetBoxClientError as exc:
            err = f"VLAN {vid}: {exc}"
            log.warning("%-30s  %s", device_name, err)
            errors.append(err)

    log.info("%-30s  VLANs: created=%d existing=%d map_size=%d",
             device_name, created, existing, len(vlan_id_map))
    return vlan_id_map, created, existing, errors, True


def _sync_trunks(
    cisco: CiscoDeviceClient,
    nb: NetBoxClient,
    device_name: str,
    device_id: int,
    vlan_id_map: Dict[int, int],
    skip_vids: Set[int],
    dry_run: bool,
    vc_member_map: Optional[Dict[int, int]] = None,
    site_id: Optional[int] = None,
) -> tuple:
    """
    Collect trunk interfaces and sync VLAN config to NetBox.

    Interface names are expanded to their canonical long form before any
    NetBox write.  When *vc_member_map* is supplied each interface is
    routed to the correct VC member device based on its slot/switch number.

    When *site_id* is supplied, the missing-VID resolution step only
    accepts VLANs that belong to the same site **or** are global (no site).
    This prevents NetBox 400 errors caused by assigning a VLAN from a
    different site to a trunk interface.

    Returns ``(updated_count, errors)``.
    """
    updated = 0
    errors: List[str] = []
    vc_member_map   = vc_member_map or {}
    # Working copy — we extend it if we find VIDs in NetBox that weren't in
    # the preloaded map (e.g. VLANs synced from a different device).
    vid_map = dict(vlan_id_map)

    try:
        trunks = cisco.get_trunk_interfaces_inventory()
    except Exception as exc:
        errors.append(f"Trunk collection failed: {exc}")
        return updated, errors

    log.info("%-30s  trunk: %d trunk interface(s) collected", device_name, len(trunks))

    # ── Build VC interface→device map ─────────────────────────────────────
    # resolve_target_device_id relies on vc_position values being set on
    # every NetBox VC member.  When vc_position is absent or wrong it falls
    # back to the master device, causing GigabitEthernet2/0/1 and similar
    # "wrong-member" interfaces to be looked up on the wrong device.
    #
    # To fix this without relying on vc_position, we fetch the actual
    # interfaces from EVERY VC member device once (N API calls where N is
    # the member count) and build an authoritative {iface_name: device_id}
    # map.  This map is used in preference to the slot-number heuristic.
    _vc_iface_device: Dict[str, int] = {}
    if vc_member_map:
        all_vc_dev_ids: List[int] = list({device_id} | set(vc_member_map.values()))
        for _dev_id in all_vc_dev_ids:
            try:
                for _iface in nb.get_interfaces(device_id=_dev_id):
                    _name = _iface.get("name", "")
                    if _name and _name not in _vc_iface_device:
                        _vc_iface_device[_name] = _dev_id
            except NetBoxClientError as _exc:
                log.debug(
                    "%-30s  trunk: could not load interfaces for "
                    "dev_id=%s — falling back to slot routing: %s",
                    device_name, _dev_id, _exc,
                )
        log.debug(
            "%-30s  trunk: VC iface→device map loaded (%d entries across "
            "%d member(s))",
            device_name, len(_vc_iface_device), len(all_vc_dev_ids),
        )

    for trunk in trunks:
        raw_name    = trunk.get("name", "")
        iface_name  = expand_interface_name(raw_name)
        native_vid  = trunk.get("native_vlan")
        allowed_vid = [v for v in trunk.get("allowed_vlans", []) if v not in skip_vids]

        # ── Resolve any VIDs not yet in the preloaded map ────────────────
        missing_vids: Set[int] = {v for v in allowed_vid if v not in vid_map}
        if native_vid and native_vid not in vid_map:
            missing_vids.add(native_vid)

        if missing_vids and len(missing_vids) <= _VLAN_BULK_RESOLVE_LIMIT:
            # Resolve each VID individually from NetBox — but ONLY accept
            # VLANs that belong to the same site as the device (or are
            # global / no-site).  Assigning a VLAN from a different site to
            # a trunk interface causes a NetBox 400 error.
            for mv in missing_vids:
                try:
                    if site_id is not None:
                        # 1. Try same-site first
                        recs = list(nb.nb.ipam.vlans.filter(vid=mv, site_id=site_id))
                        if not recs:
                            # 2. Fall back to global VLANs (site field is null)
                            all_recs = list(nb.nb.ipam.vlans.filter(vid=mv))
                            recs = [r for r in all_recs if not getattr(r, "site", None)]
                    else:
                        recs = list(nb.nb.ipam.vlans.filter(vid=mv))

                    if recs:
                        vid_map[mv] = int(recs[0].id)
                        log.debug(
                            "%-30s  resolved VID %s → nb_id=%s from NetBox",
                            device_name, mv, vid_map[mv],
                        )
                    elif site_id is not None:
                        log.debug(
                            "%-30s  VID %s not in site_id=%s or global — "
                            "excluded from trunk",
                            device_name, mv, site_id,
                        )
                except Exception:
                    pass  # skip; VID simply won't appear in tagged list
        elif missing_vids:
            # Large set (e.g. "1-4094" on NX-OS) — bulk API resolution would
            # hammer NetBox with thousands of requests.  Use only the VLANs
            # already in the preloaded map; anything else is silently skipped.
            log.debug(
                "%-30s  trunk %-30s  %d VIDs absent from preloaded map "
                "(> limit=%d) — using preloaded VLANs only (%d known)",
                device_name, iface_name, len(missing_vids),
                _VLAN_BULK_RESOLVE_LIMIT, len(vid_map),
            )

        native_nb_id  = vid_map.get(native_vid) if native_vid else None
        tagged_nb_ids = [vid_map[v] for v in allowed_vid if v in vid_map]

        # Route to the correct VC member / line-card device.
        # Prefer the live map (where each interface actually lives in NetBox)
        # over the slot-number heuristic so that stacks without vc_position
        # set still route correctly (e.g. GigabitEthernet2/0/1 → member 2).
        target_id = _vc_iface_device.get(iface_name) or resolve_target_device_id(
            iface_name, device_id, vc_member_map
        )

        if dry_run:
            log.info(
                "DRY-RUN  %-30s  trunk %-40s  dev_id=%-6s  "
                "native_nb=%s  tagged=%d vlans",
                device_name, iface_name, target_id,
                native_nb_id, len(tagged_nb_ids),
            )
            updated += 1
            continue

        try:
            result = nb.upsert_interface_vlans(
                device_id=target_id,
                interface_name=iface_name,
                mode="trunk",
                native_vlan_id=native_nb_id,
                tagged_vlan_ids=tagged_nb_ids,
            )
            action = result.get("_action", "")
            if action == "updated":
                updated += 1
                log.info("%-30s  trunk updated  %-40s  tagged=%d",
                         device_name, iface_name, len(tagged_nb_ids))
            elif action == "skipped":
                log.debug("%-30s  trunk unchanged %s", device_name, iface_name)
        except NetBoxClientError as exc:
            err = f"Trunk {iface_name!r}: {exc}"
            log.warning("%-30s  %s", device_name, err)
            errors.append(err)

    return updated, errors


def _sync_prefixes(
    cisco: CiscoDeviceClient,
    nb: NetBoxClient,
    device_name: str,
    site_id: int,
    vlan_id_map: Dict[int, int],
    dry_run: bool,
    iface_vrf_map: Optional[Dict[str, Optional[str]]] = None,
    vrf_cache: Optional[Dict[str, int]] = None,
    device_id: int = 0,
    vc_member_map: Optional[Dict[int, int]] = None,
) -> tuple:
    """
    Collect interface IPs, compute their network prefixes, and ensure each
    prefix exists in NetBox with the correct site, VLAN, and VRF assignment.
    Also assign the **host IP address** to the corresponding NetBox interface
    record for all non-SVI interfaces (Port-channels, routed physical ports,
    sub-interfaces, etc.).

    SVI interfaces (``Vlan<N>``) are handled by :func:`_sync_svi_bindings`
    which reads IPs directly from running-config.  They are skipped here to
    avoid double-assignment.

    When *iface_vrf_map* is provided the VRF assignment for each interface
    (collected from running-config) is resolved to a NetBox VRF ID and
    included in the prefix create/update payload.  This ensures prefixes
    under the same CIDR in different VRFs are written as distinct records.

    Returns ``(created, updated, moved_site, ips_assigned, errors)``.
    """
    created = updated = moved = ips_assigned = 0
    errors: List[str] = []
    _vrf_map      = iface_vrf_map or {}
    _vrf_cache    = vrf_cache if vrf_cache is not None else {}
    _vc_member_map = vc_member_map or {}

    try:
        ip_inventory = cisco.get_interface_ip_inventory()
    except Exception as exc:
        errors.append(f"IP collection failed: {exc}")
        return created, updated, moved, ips_assigned, errors

    log.info(
        "%-30s  prefix: %d interface IP(s) collected", device_name, len(ip_inventory)
    )

    for entry in ip_inventory:
        iface_name = entry.get("name", "")
        ip_cidr    = entry.get("ip")
        if not ip_cidr:
            continue
        prefix_net = compute_prefix_cidr(ip_cidr)
        if not prefix_net:
            log.debug(
                "%-30s  skip %-25s — no prefix length in %r",
                device_name, iface_name, ip_cidr,
            )
            continue

        # ── Resolve VRF for this interface ────────────────────────────────
        raw_vrf   = _vrf_map.get(iface_name) or _vrf_map.get(
            expand_interface_name(iface_name)
        )
        nb_vrf_id = _resolve_vrf_id(
            raw_vrf, _vrf_cache, nb, device_name, dry_run
        )
        if raw_vrf:
            log.debug(
                "%-30s  prefix %-22s  Detected VRF %r on interface %s",
                device_name, prefix_net, raw_vrf, iface_name,
            )

        # Determine the NetBox VLAN ID for this prefix.
        # Only SVIs give a deterministic interface→VLAN relationship.
        nb_vlan_id = _resolve_prefix_vlan(
            iface_name=iface_name,
            vlan_id_map=vlan_id_map,
            nb=nb,
            device_name=device_name,
            prefix_net=prefix_net,
        )

        # SVIs are handled by _sync_svi_bindings (running-config parse).
        # Expand here so the name matches what is stored in NetBox (Stage 1
        # always writes expanded names, e.g. "Port-channel24" not "Po24").
        expanded_name = expand_interface_name(iface_name)
        is_svi        = bool(_SVI_RE.match(expanded_name))

        # Target device for the IP assignment — logical interfaces (LAGs,
        # Port-channels, SVIs) stay on the master; physical interfaces are
        # routed to the correct VC member via the slot number.
        target_device_id = resolve_target_device_id(
            expanded_name, device_id, _vc_member_map
        )

        if dry_run:
            log.info(
                "DRY-RUN  %-30s  prefix %-22s  vlan_id=%-6s  "
                "vrf=%s  iface=%s",
                device_name, prefix_net, nb_vlan_id,
                raw_vrf or "global", iface_name,
            )
            if not is_svi and "/" in ip_cidr and device_id:
                log.info(
                    "DRY-RUN  %-30s  would assign IP %-22s → %s",
                    device_name, ip_cidr, expanded_name,
                )
            created += 1
            continue

        try:
            result = nb.ensure_prefix(
                prefix_cidr=prefix_net,
                site_id=site_id,
                vlan_id=nb_vlan_id,
                vrf_id=nb_vrf_id,
            )
            action = result.get("_action", "existing")
            if action == "created":
                created += 1
                log.info(
                    "%-30s  prefix created   %-22s  vlan_id=%s  vrf=%s",
                    device_name, prefix_net, nb_vlan_id, raw_vrf or "global",
                )
            elif action == "moved_site":
                moved += 1
                log.info(
                    "%-30s  prefix moved site %-22s  vlan_id=%s  vrf=%s",
                    device_name, prefix_net, nb_vlan_id, raw_vrf or "global",
                )
            elif action == "updated":
                updated += 1
                log.info(
                    "%-30s  prefix updated   %-22s  vlan_id=%s  vrf=%s",
                    device_name, prefix_net, nb_vlan_id, raw_vrf or "global",
                )
        except NetBoxClientError as exc:
            err = f"Prefix {prefix_net} (iface={iface_name}): {exc}"
            log.warning("%-30s  %s", device_name, err)
            errors.append(err)

        # ── Assign the host IP to the interface in NetBox ─────────────────
        # SVIs skip this block — they are handled (including IP assignment)
        # by _sync_svi_bindings which reads the exact host address from
        # running-config.  All other routed interfaces (Port-channels,
        # physical routed ports, sub-interfaces) are covered here.
        #
        # Guard: ip_cidr must include a prefix length so NetBox gets the
        # full address object (e.g. "172.18.5.164/31", not just "172.18.5.164").
        # device_id=0 means we were called without a device context — skip.
        if not is_svi and "/" in ip_cidr and device_id:
            try:
                ip_result = nb.ensure_ip_on_interface(
                    ip_cidr=ip_cidr,
                    device_id=target_device_id,
                    interface_name=expanded_name,
                    vrf_id=nb_vrf_id,
                )
                ip_action = ip_result.get("_action", "skipped")
                if ip_action in ("created", "updated"):
                    ips_assigned += 1
                    log.info(
                        "%-30s  IP %-22s → %s (%s)",
                        device_name, ip_cidr, expanded_name, ip_action,
                    )
                else:
                    log.debug(
                        "%-30s  IP %-22s already on %s — no change",
                        device_name, ip_cidr, expanded_name,
                    )
            except NetBoxClientError as exc:
                # Non-fatal: log and continue — prefix was already created.
                log.warning(
                    "%-30s  IP %r → %r: %s",
                    device_name, ip_cidr, expanded_name, exc,
                )
                errors.append(f"IP {ip_cidr!r} → {expanded_name!r}: {exc}")

    return created, updated, moved, ips_assigned, errors


def _sync_svi_bindings(
    cisco: CiscoDeviceClient,
    nb: NetBoxClient,
    device_name: str,
    device_id: int,
    site_id: int,
    site_name: str,
    vlan_id_map: Dict[int, int],
    dry_run: bool,
    iface_vrf_map: Optional[Dict[str, Optional[str]]] = None,
    vrf_cache: Optional[Dict[str, int]] = None,
) -> tuple:
    """
    Enforce the full SVI → VLAN → Prefix → Site relationship for every
    SVI (``Vlan<N>``) on the device.

    Steps per SVI
    -------------
    1. Fetch ``{vid: prefix_cidr}`` from ``show run | section ^interface Vlan``
       (the only reliable source for SVI IP addresses and their subnet masks).
    2. Resolve NetBox VLAN ID from *vlan_id_map* or a live NetBox lookup.
    3. Enforce VLAN site consistency (move VLAN to device site if needed).
    4. Ensure the SVI interface record (type=virtual) is linked to the VLAN.
    5. Derive the network prefix from the SVI IP and call ``ensure_prefix``,
       binding ``prefix.vlan`` to the NetBox VLAN.

    Returns
    -------
    tuple
        ``(svi_bound, vlan_site_corrections, pfx_created, pfx_updated, errors)``
    """
    svi_bound = 0
    vlan_site_corrections = 0
    pfx_created = 0
    pfx_updated = 0
    ips_assigned = 0
    errors: List[str] = []
    _vrf_map   = iface_vrf_map or {}
    _vrf_cache = vrf_cache if vrf_cache is not None else {}

    # ── Collect SVI network-prefix map from running config ─────────────────
    # Returns {vid: "192.168.20.0/24"} — network address used for prefix sync.
    try:
        svi_prefix_map: Dict[int, str] = cisco.get_svi_prefix_map()
        log.info(
            "%-30s  SVI prefix map: %d SVI(s) with IPs from show run",
            device_name, len(svi_prefix_map),
        )
    except Exception as exc:
        errors.append(f"SVI bindings: get_svi_prefix_map failed: {exc}")
        svi_prefix_map = {}

    # ── Collect SVI host-IP map from running config ────────────────────────
    # Returns {vid: "192.168.20.1/24"} — host address to assign to the
    # SVI interface in NetBox.  Works for both IOS (dotted mask) and
    # NX-OS (CIDR notation) by using the same running-config source.
    try:
        svi_host_ip_map: Dict[int, str] = cisco.get_svi_host_ip_map()
        log.info(
            "%-30s  SVI host IP map: %d SVI(s) with host IPs from show run",
            device_name, len(svi_host_ip_map),
        )
    except Exception as exc:
        log.warning(
            "%-30s  get_svi_host_ip_map failed: %s "
            "— IPs will NOT be assigned to SVI interfaces this run",
            device_name, exc,
        )
        svi_host_ip_map = {}

    # ── Build the set of VIDs to process ──────────────────────────────────
    # Only include VIDs that actually have an SVI ("interface Vlan<N>")
    # configured on the device — i.e. VIDs that appear in the running-config
    # SVI maps (parsed from "show run | section ^interface Vlan").
    #
    # Pure L2 VLANs (no interface Vlan<N> on the device) are handled by
    # _sync_vlans and must NOT trigger SVI interface creation here.
    all_svi_vids: Set[int] = (
        set(svi_prefix_map.keys())
        | set(svi_host_ip_map.keys())
    )

    # Pre-resolve the site's VLAN group once so we can auto-create VLANs
    # that have an SVI configured on the device but were never discovered by
    # _sync_vlans() (e.g. NX-OS SVIs whose VLAN has no active member ports
    # and therefore does not appear in ``show vlan brief``).
    _auto_vlan_group_id: Optional[int] = None
    try:
        _vg = nb.find_vlan_group_for_site(site_id)
        _auto_vlan_group_id = _vg["id"]
    except NetBoxClientError:
        log.debug(
            "%-30s  SVI auto-VLAN: no VLAN group for site_id=%s — "
            "auto-create disabled",
            device_name, site_id,
        )

    for svi_vid in sorted(all_svi_vids):
        iface_name  = f"Vlan{svi_vid}"
        prefix_cidr = svi_prefix_map.get(svi_vid)    # network address or None
        host_ip     = svi_host_ip_map.get(svi_vid)   # host IP with prefix or None

        # ── Resolve VRF for this SVI ───────────────────────────────────────
        raw_vrf   = _vrf_map.get(iface_name)
        nb_vrf_id = _resolve_vrf_id(raw_vrf, _vrf_cache, nb, device_name, dry_run)
        if raw_vrf:
            log.debug(
                "%-30s  Detected VRF %r on interface %s",
                device_name, raw_vrf, iface_name,
            )

        # Resolve NetBox VLAN ID — fast path from map, slow path from NetBox.
        nb_vlan_id = vlan_id_map.get(svi_vid) or nb.find_vlan_id_by_vid(svi_vid)

        if nb_vlan_id is None:
            # VLAN not in NetBox yet.  Auto-create it in the site VLAN group
            # when possible so that the rest of the SVI binding can proceed.
            if _auto_vlan_group_id is not None:
                try:
                    new_vlan = nb.ensure_vlan_in_site_group(
                        site_id=site_id,
                        vlan_group_id=_auto_vlan_group_id,
                        vid=svi_vid,
                    )
                    nb_vlan_id = new_vlan["id"]
                    vlan_id_map[svi_vid] = nb_vlan_id
                    log.info(
                        "%-30s  SVI %s: VLAN %s auto-created "
                        "(not discovered via show vlan brief)",
                        device_name, iface_name, svi_vid,
                    )
                except NetBoxClientError as exc:
                    log.warning(
                        "%-30s  SVI %s: VLAN %s not found and could not be "
                        "created: %s — binding skipped",
                        device_name, iface_name, svi_vid, exc,
                    )
                    continue
            else:
                log.warning(
                    "%-30s  SVI %s: VLAN %s not in NetBox and no VLAN group "
                    "available for auto-create — binding skipped",
                    device_name, iface_name, svi_vid,
                )
                continue

        log.info(
            "%-30s  SVI %s → binding to VLAN %s  host_ip=%s  prefix=%s",
            device_name, iface_name, svi_vid,
            host_ip or "(none)",
            prefix_cidr or "(no IP — SVI is shutdown or unconfigured)",
        )

        if dry_run:
            log.info(
                "DRY-RUN  %-30s  SVI %-15s → VLAN %-5s  "
                "host_ip=%-22s  prefix=%-22s  site=%r  vrf=%s",
                device_name, iface_name, svi_vid,
                host_ip or "none", prefix_cidr or "none", site_name,
                raw_vrf or "global",
            )
            svi_bound += 1
            continue

        # ── 1. VLAN site consistency ───────────────────────────────────────
        try:
            v_result = nb.ensure_vlan_site_consistency(nb_vlan_id, site_id)
            if v_result.get("_action") == "updated":
                vlan_site_corrections += 1
                log.info(
                    "%-30s  VLAN %s moved to site %r",
                    device_name, svi_vid, site_name,
                )
        except NetBoxClientError as exc:
            err = f"VLAN {svi_vid} site consistency: {exc}"
            log.warning("%-30s  %s", device_name, err)
            errors.append(err)

        # ── 2. SVI interface → VLAN binding ───────────────────────────────
        try:
            i_result = nb.ensure_svi_interface(device_id, iface_name, nb_vlan_id)
            action = i_result.get("_action", "skipped")
            if action in ("created", "updated"):
                svi_bound += 1
                log.info(
                    "%-30s  SVI %s %s and linked to VLAN %s",
                    device_name, iface_name, action, svi_vid,
                )
        except NetBoxClientError as exc:
            err = f"SVI {iface_name!r} → VLAN bind: {exc}"
            log.warning("%-30s  %s", device_name, err)
            errors.append(err)

        # ── 2.5. Host IP → SVI interface assignment ────────────────────────
        # This is the step that assigns the configured IP address (e.g.
        # "192.168.20.1/24") to the Vlan20 interface object in NetBox.
        # It is intentionally separate from prefix sync (step 3) which
        # handles the network-level prefix object ("192.168.20.0/24").
        #
        # NX-OS: host_ip comes from "ip address A.B.C.D/L" lines in
        # show run.  IOS/IOS-XE: from "ip address A.B.C.D M.M.M.M" lines.
        # Both are handled by get_svi_host_ip_map().
        if host_ip:
            if nb_vrf_id is not None:
                log.info(
                    "%-30s  Assigning VRF %r to IP %s on %s",
                    device_name, raw_vrf, host_ip, iface_name,
                )
            try:
                ip_result = nb.ensure_ip_on_interface(
                    ip_cidr=host_ip,
                    device_id=device_id,
                    interface_name=iface_name,
                    vrf_id=nb_vrf_id,
                )
                ip_action = ip_result.get("_action", "skipped")
                if ip_action in ("created", "updated"):
                    ips_assigned += 1
                    log.info(
                        "%-30s  IP %-22s → %s (%s)",
                        device_name, host_ip, iface_name, ip_action,
                    )
                else:
                    log.debug(
                        "%-30s  IP %-22s already on %s — no change",
                        device_name, host_ip, iface_name,
                    )
            except NetBoxClientError as exc:
                err = f"IP {host_ip!r} → {iface_name!r}: {exc}"
                log.warning("%-30s  %s", device_name, err)
                errors.append(err)
        else:
            log.debug(
                "%-30s  SVI %s has no configured IP — skipping IP assignment",
                device_name, iface_name,
            )

        # ── 3. Prefix → VLAN + site assignment ────────────────────────────
        if not prefix_cidr:
            continue   # SVI has no IP (shutdown); no prefix to assign

        log.info(
            "%-30s  Vlan%s SVI ip → prefix %s → assigning to VLAN %s",
            device_name, svi_vid, prefix_cidr, svi_vid,
        )
        try:
            p_result = nb.ensure_prefix(
                prefix_cidr=prefix_cidr,
                site_id=site_id,
                vlan_id=nb_vlan_id,
                vrf_id=nb_vrf_id,
            )
            p_action = p_result.get("_action", "existing")
            if p_action == "created":
                pfx_created += 1
                log.info(
                    "%-30s  prefix created   %-22s  vlan=%s  site=%r  vrf=%s",
                    device_name, prefix_cidr, svi_vid, site_name,
                    raw_vrf or "global",
                )
            elif p_action in ("updated", "moved_site"):
                pfx_updated += 1
                log.info(
                    "%-30s  prefix %-8s %-22s  vlan=%s  site=%r  vrf=%s",
                    device_name, p_action, prefix_cidr, svi_vid, site_name,
                    raw_vrf or "global",
                )
        except NetBoxClientError as exc:
            err = f"Prefix {prefix_cidr} → VLAN {svi_vid}: {exc}"
            log.warning("%-30s  %s", device_name, err)
            errors.append(err)

    return svi_bound, vlan_site_corrections, pfx_created, pfx_updated, ips_assigned, errors


def _sync_portchannel_membership(
    cisco: CiscoDeviceClient,
    nb: NetBoxClient,
    device_name: str,
    device_id: int,
    dry_run: bool,
    vc_member_map: Optional[Dict[int, int]] = None,
) -> tuple:
    """
    Stage 5 — Sync port-channel (LAG) membership to NetBox.

    For each LAG discovered on the device:
    1. Ensure the LAG interface (type=lag) exists in NetBox (always on
       the master/default device — LAGs are logical).
    2. Set the ``lag`` field on every physical member interface, routing
       each to the correct VC member device via *vc_member_map* so that
       e.g. ``GigabitEthernet2/0/1`` is found on member-2, not the master.

    Returns ``(members_synced, errors)``.
    """
    members_synced = 0
    errors: List[str] = []
    vc_member_map  = vc_member_map or {}

    try:
        po_list = cisco.get_portchannel_membership()
    except Exception as exc:
        errors.append(f"Port-channel discovery failed: {exc}")
        return members_synced, errors

    log.info("%-30s  port-channel: %d LAG(s) discovered", device_name, len(po_list))

    for po in po_list:
        lag_name: str  = po["lag"]
        members:  list = po["members"]

        if dry_run:
            log.info(
                "DRY-RUN  %-30s  LAG %-20s  members=%s",
                device_name, lag_name, members,
            )
            members_synced += len(members)
            continue

        # LAG interface is logical — always lives on the master device.
        try:
            lag_result = nb.ensure_lag_interface(device_id, lag_name)
            lag_id = lag_result["id"]
            if lag_result.get("_action") == "created":
                log.info("%-30s  LAG created: %s", device_name, lag_name)
        except NetBoxClientError as exc:
            errors.append(f"LAG {lag_name}: {exc}")
            continue

        # Attach each physical member, routing to the correct VC slot.
        for member_name in members:
            expanded  = expand_interface_name(member_name)
            target_id = resolve_target_device_id(expanded, device_id, vc_member_map)
            try:
                result = nb.set_interface_lag(target_id, expanded, lag_id)
                if result.get("_action") == "updated":
                    members_synced += 1
                    log.info(
                        "%-30s  %s → LAG %s  (dev_id=%s)",
                        device_name, expanded, lag_name, target_id,
                    )
            except NetBoxClientError as exc:
                errors.append(f"LAG member {expanded}: {exc}")

    return members_synced, errors


def _sync_interface_states(
    cisco: CiscoDeviceClient,
    nb: NetBoxClient,
    device_name: str,
    device_id: int,
    dry_run: bool,
    vc_member_map: Optional[Dict[int, int]] = None,
    vc_member_module_maps: Optional[Dict[int, Dict[int, int]]] = None,
) -> tuple:
    """
    Stage 6 — Sync interface admin/oper state to NetBox ``enabled`` and
    ``mark_connected`` fields.

    When *vc_member_map* is supplied, physical interfaces are routed to
    the correct VC member device based on their slot number — the same
    logic used by :func:`_sync_trunks`.

    When an interface is not found in NetBox it is created on the correct
    device and module (using *vc_member_module_maps*) before the state
    update is retried.

    Returns ``(updated_count, errors)``.
    """
    updated = 0
    errors: List[str] = []
    vc_member_map = vc_member_map or {}
    vc_member_module_maps = vc_member_module_maps or {}

    try:
        states = cisco.get_interface_state_inventory()
    except Exception as exc:
        errors.append(f"Interface state discovery failed: {exc}")
        return updated, errors

    log.info(
        "%-30s  interface states: %d interface(s) found",
        device_name, len(states),
    )

    for state in states:
        iface_name     = expand_interface_name(state["name"])
        enabled        = state["enabled"]
        mark_connected = state["mark_connected"]
        iface_state    = state.get("state") or "UNKNOWN"

        # Port-channels are logical aggregates — NetBox does not support
        # mark_connected on LAG interfaces.
        if iface_name.startswith("Port-channel"):
            mark_connected = False

        # Route to the correct VC member device, just like _sync_trunks does.
        target_id = resolve_target_device_id(iface_name, device_id, vc_member_map)

        log.debug(
            "%-30s  Interface %s state detected as %s",
            device_name, iface_name, iface_state,
        )

        if dry_run:
            try:
                _dr_exists = nb.get_interface_by_name(target_id, iface_name) is not None
            except NetBoxClientError:
                _dr_exists = True  # assume exists on lookup error
            if not _dr_exists:
                _dr_parsed  = parse_cisco_interface(iface_name)
                _dr_mod_id  = resolve_target_module_id(
                    _dr_parsed["module"],
                    vc_member_module_maps.get(target_id, {}),
                )
                log.info(
                    "DRY-RUN  %-30s  WOULD CREATE (not in NetBox) %-38s  "
                    "dev_id=%s mod_id=%s  then state=%s enabled=%s connected=%s",
                    device_name, iface_name, target_id, _dr_mod_id,
                    iface_state, enabled, mark_connected,
                )
            else:
                log.info(
                    "DRY-RUN  %-30s  state %-38s  dev_id=%-6s  enabled=%s  "
                    "connected=%s",
                    device_name, iface_name, target_id,
                    enabled, mark_connected,
                )
            updated += 1
            continue

        # ── Update enabled + mark_connected ───────────────────────────────
        # STATE / state_change custom-field updates are handled by the
        # dedicated netbox_update_State.py script; do not duplicate them here.
        try:
            result = nb.update_interface_admin_oper(
                target_id, iface_name, enabled, mark_connected
            )
            if result.get("_action") == "updated":
                updated += 1
                log.debug(
                    "%-30s  state updated  %-38s  enabled=%s connected=%s",
                    device_name, iface_name, enabled, mark_connected,
                )
            elif result.get("_action") == "not_found":
                # ── Interface missing from NetBox — create it, then retry ──
                _parsed    = parse_cisco_interface(iface_name)
                _mod_id    = resolve_target_module_id(
                    _parsed["module"],
                    vc_member_module_maps.get(target_id, {}),
                )
                _nb_payload: dict = {"type": infer_netbox_interface_type(iface_name)}
                if _mod_id is not None:
                    _nb_payload["module"] = _mod_id
                log.info(
                    "%-30s  CREATE (not in NetBox) %-42s  "
                    "dev_id=%s mod_id=%s",
                    device_name, iface_name, target_id, _mod_id,
                )
                try:
                    nb.upsert_interface(
                        device_id=target_id,
                        name=iface_name,
                        payload=_nb_payload,
                    )
                except NetBoxClientError as exc:
                    errors.append(
                        f"Create missing {iface_name!r} (dev_id={target_id}): {exc}"
                    )
                    log.error(
                        "%-30s  CREATE missing %r failed: %s",
                        device_name, iface_name, exc,
                    )
                else:
                    # Retry state update now that the record exists.
                    try:
                        _retry = nb.update_interface_admin_oper(
                            target_id, iface_name, enabled, mark_connected
                        )
                        if _retry.get("_action") in ("updated", "skipped"):
                            updated += 1
                            log.debug(
                                "%-30s  state set (after create) %-38s  "
                                "enabled=%s connected=%s",
                                device_name, iface_name, enabled, mark_connected,
                            )
                    except NetBoxClientError as exc:
                        errors.append(
                            f"State {iface_name!r} (after create): {exc}"
                        )
        except NetBoxClientError as exc:
            errors.append(f"State {iface_name!r}: {exc}")

    return updated, errors


def _sync_device_facts(
    cisco: CiscoDeviceClient,
    nb: NetBoxClient,
    device_name: str,
    device_id: int,
    vc_id: Optional[int],
    dry_run: bool,
) -> Tuple[int, int, int, List[str]]:
    """
    Stage 7 — Sync software custom fields AND platform from ``show version``,
    then propagate both to every Virtual Chassis member.

    Steps
    -----
    1. Run ``show version`` once via :meth:`CiscoDeviceClient.get_software_facts`.
    2. Write ``software_version`` / ``software_image`` custom fields to the
       connected device.
    3. Detect OS platform (``ios`` / ``iosxe`` / ``nxos``) from the same
       output and update the NetBox ``platform`` field when it differs.
    4. If the device belongs to a Virtual Chassis, repeat steps 2–3 for every
       VC member so all share the same software and platform data.

    Returns
    -------
    tuple
        ``(sw_updated, platform_updated, vc_members_updated, errors)``
    """
    errors: List[str]  = []
    sw_updated         = 0
    platform_updated   = 0
    vc_members_updated = 0

    # ── 1. Collect facts from show version ────────────────────────────────
    try:
        facts = cisco.get_software_facts()
    except Exception as exc:
        errors.append(f"Software facts collection failed: {exc}")
        return sw_updated, platform_updated, vc_members_updated, errors

    # Split platform out — it goes to the device record, not custom_fields.
    detected_platform: Optional[str] = facts.pop("platform", None)
    cf = {k: v for k, v in facts.items() if v is not None}

    if dry_run:
        if cf:
            log.info("DRY-RUN  %-30s  software: %s", device_name, cf)
        if detected_platform:
            log.info("DRY-RUN  %-30s  platform: %s", device_name, detected_platform)
        return (
            1 if cf else 0,
            1 if detected_platform else 0,
            0,
            errors,
        )

    # ── 2. Update software custom fields on the connected device ──────────
    if cf:
        try:
            r = nb.update_device_custom_fields(device_id, cf)
            if r.get("_action") == "updated":
                sw_updated = 1
                log.info("%-30s  software updated: %s", device_name, cf)
        except NetBoxClientError as exc:
            errors.append(f"Software custom fields: {exc}")

    # ── 3. Update platform on the connected device ────────────────────────
    if detected_platform:
        try:
            r = nb.update_device_platform_by_slug(device_id, detected_platform)
            if r.get("_action") == "updated":
                platform_updated = 1
                log.info(
                    "%-30s  platform updated → %s", device_name, detected_platform
                )
            else:
                log.debug(
                    "%-30s  platform already %r — no change",
                    device_name, detected_platform,
                )
        except NetBoxClientError as exc:
            log.warning("%-30s  platform update skipped: %s", device_name, exc)
            errors.append(f"Platform update: {exc}")

    # ── 4. Propagate to all Virtual Chassis members ───────────────────────
    if vc_id:
        try:
            members = nb.get_virtual_chassis_members(vc_id)
        except NetBoxClientError as exc:
            errors.append(f"VC member list failed: {exc}")
            members = []

        for member in members:
            m_id   = member.get("id")
            m_name = member.get("name", f"id={m_id}")
            if m_id is None or m_id == device_id:
                continue   # skip the device already updated above

            member_changed = False

            if cf:
                try:
                    r = nb.update_device_custom_fields(m_id, cf)
                    if r.get("_action") == "updated":
                        member_changed = True
                        log.info(
                            "%-30s  VC member %-25r  software synced",
                            device_name, m_name,
                        )
                except NetBoxClientError as exc:
                    errors.append(f"VC member {m_name!r} software: {exc}")

            if detected_platform:
                try:
                    r = nb.update_device_platform_by_slug(m_id, detected_platform)
                    if r.get("_action") == "updated":
                        member_changed = True
                        log.info(
                            "%-30s  VC member %-25r  platform → %s",
                            device_name, m_name, detected_platform,
                        )
                except NetBoxClientError as exc:
                    errors.append(f"VC member {m_name!r} platform: {exc}")

            if member_changed:
                vc_members_updated += 1

    return sw_updated, platform_updated, vc_members_updated, errors


def _touch_interface_timestamps(
    nb: NetBoxClient,
    device_name: str,
    device_id: int,
    dry_run: bool,
    vc_member_map: Optional[Dict[int, int]] = None,
) -> int:
    """
    Stage 8 — Stamp ``if_last_update`` on every interface of the device.

    For a Virtual Chassis all member device IDs are derived from
    *vc_member_map* so every member's interfaces are timestamped, not
    just the master's.

    Returns the number of interfaces successfully timestamped.
    """
    if dry_run:
        log.info("DRY-RUN  %-30s  interface timestamps skipped", device_name)
        return 0

    # Collect all device IDs that belong to this device / VC.
    all_device_ids: List[int] = list(
        {device_id} | set((vc_member_map or {}).values())
    )

    touched = 0
    for dev_id in all_device_ids:
        try:
            ifaces = nb.get_interfaces(device_id=dev_id)
        except NetBoxClientError as exc:
            log.warning(
                "%-30s  touch_interface_timestamps: could not list interfaces "
                "for device_id=%s: %s",
                device_name, dev_id, exc,
            )
            continue

        for iface in ifaces:
            iface_name = iface.get("name", "")
            if not iface_name:
                continue
            try:
                nb.touch_interface_last_update(dev_id, iface_name)
                touched += 1
            except NetBoxClientError as exc:
                log.debug(
                    "%-30s  if_last_update skipped dev_id=%s %r: %s",
                    device_name, dev_id, iface_name, exc,
                )

    log.info("%-30s  if_last_update stamped on %d interface(s)", device_name, touched)
    return touched


def _touch_ip_timestamps(
    nb: NetBoxClient,
    device_name: str,
    device_id: int,
    dry_run: bool,
    vc_member_map: Optional[Dict[int, int]] = None,
) -> int:
    """
    Stage 9 — Stamp ``IP_Last_update`` on every IP address assigned to the
    device's interfaces.

    For a Virtual Chassis all member device IDs are covered so IPs on
    every member are timestamped, not just the master's.

    Returns the number of IPs successfully timestamped.
    """
    if dry_run:
        log.info("DRY-RUN  %-30s  IP timestamps skipped", device_name)
        return 0

    all_device_ids: List[int] = list(
        {device_id} | set((vc_member_map or {}).values())
    )

    touched = 0
    for dev_id in all_device_ids:
        try:
            ip_records = list(nb.nb.ipam.ip_addresses.filter(device_id=dev_id))
        except Exception as exc:
            log.warning(
                "%-30s  touch_ip_timestamps: could not list IPs for "
                "device_id=%s: %s",
                device_name, dev_id, exc,
            )
            continue

        for ip_rec in ip_records:
            ip_id = ip_rec.id
            try:
                nb.touch_ip_last_update(ip_id)
                touched += 1
            except NetBoxClientError as exc:
                log.debug(
                    "%-30s  IP_Last_update skipped for ip_id=%s: %s",
                    device_name, ip_id, exc,
                )

    log.info("%-30s  IP_Last_update stamped on %d IP(s)", device_name, touched)
    return touched


# --------------------------------------------------------------------------- #
# FHRP group sync (HSRP / VRRP / GLBP)                                        #
# --------------------------------------------------------------------------- #

def _resolve_fhrp_vip_cidr(
    vip: str,
    iface_prefix_map: Dict[str, str],
    iface_name: str,
    device_name: str,
) -> str:
    """
    Return the CIDR form of an FHRP VIP.

    Cisco devices report FHRP VIPs as bare host addresses (e.g.
    ``"10.254.9.1"``) — the prefix length is never included because the
    VIP is not configured with a mask; it simply belongs to the same subnet
    as the interface IP.

    The correct prefix length is therefore borrowed from the interface's own
    IP address: if the interface has ``10.254.9.3/24``, the VIP should be
    stored in NetBox as ``10.254.9.1/24``, **not** ``/32``.

    Parameters
    ----------
    vip : str
        VIP address as reported by the device.  If it already contains a
        ``"/"`` (uncommon but possible) it is returned unchanged.
    iface_prefix_map : dict
        ``{expanded_interface_name: prefix_len_str}`` built once per sync
        run from the device's IP inventory (e.g.
        ``{"GigabitEthernet1/0/1": "24", "Vlan9": "24"}``).
    iface_name : str
        Expanded (canonical) interface name — used as the map lookup key
        and in debug log messages.
    device_name : str
        For log messages only.

    Returns
    -------
    str
        VIP in CIDR notation, e.g. ``"10.254.9.1/24"``.
        Falls back to ``"<vip>/32"`` when no interface IP is found.
    """
    if "/" in vip:
        return vip  # already includes a prefix length — leave untouched

    prefix_len = iface_prefix_map.get(iface_name)
    if prefix_len:
        vip_cidr = f"{vip}/{prefix_len}"
        log.debug(
            "%-30s  FHRP VIP %r on %s → using /%s from interface IP",
            device_name, vip, iface_name, prefix_len,
        )
        return vip_cidr

    log.debug(
        "%-30s  FHRP VIP %r on %s — interface not found in IP inventory; "
        "falling back to /32",
        device_name, vip, iface_name,
    )
    return f"{vip}/32"


def _sync_fhrp_groups(
    cisco: CiscoDeviceClient,
    nb: NetBoxClient,
    device_name: str,
    device_id: int,
    os_type: Optional[str],
    dry_run: bool,
) -> Tuple[int, List[str]]:
    """
    Sync all FHRP (HSRP / VRRP / GLBP) groups discovered on the device.

    **NX-OS** — uses ``show hsrp`` (detailed output) as the single source of
    truth.  This command returns the interface, group number, virtual IP,
    configured priority, and live operational state in one shot — more
    reliable than parsing running-config blocks.

    **IOS / IOS-XE** — parses running-config for group config, then fetches
    the live state separately from ``show standby brief``.

    For every group found:

    1. Resolve the NetBox interface record it belongs to.
    2. Call :meth:`NetBoxClient.ensure_fhrp_group` — creates the FHRP group
       if absent, updates ``description`` with the current operational state.
    3. Call :meth:`NetBoxClient.ensure_fhrp_assignment` — attaches the group
       to the interface with the configured priority.

    Operational state mapping
    -------------------------
    * HSRP Active / VRRP Master / GLBP Active → ``"active"``
    * HSRP Standby / VRRP Backup / GLBP Standby → ``"standby"``
    * Listen / Init / anything else → ``"unknown"``

    Returns
    -------
    tuple
        ``(fhrp_groups_synced, errors)``
    """
    synced = 0
    errors: List[str] = []

    # ── Collect FHRP group data ────────────────────────────────────────────
    # NX-OS: ``show hsrp`` (detailed) gives interface, group, VIP, priority
    # AND live state in a single command — no separate config parse needed.
    #
    # IOS / IOS-XE: parse running-config for config, then fetch oper state
    # separately from ``show standby brief``.

    fhrp_entries: List[dict] = []
    oper_state:   Dict[str, Dict[int, str]] = {}

    if os_type == "nxos":
        try:
            raw_groups = cisco.get_nxos_hsrp_groups()
        except Exception as exc:
            errors.append(f"FHRP: show hsrp failed: {exc}")
            return synced, errors

        # State is embedded — extract it into oper_state while normalising
        # the entries into the same schema the downstream code expects.
        for g in raw_groups:
            fhrp_entries.append({
                "interface": g["interface"],
                "protocol":  g["protocol"],
                "group":     g["group"],
                "vip":       g["vip"],
                "priority":  g["priority"],
            })
            oper_state.setdefault(g["interface"], {})[g["group"]] = g["state"]

        log.info(
            "%-30s  FHRP: %d HSRP group(s) from show hsrp",
            device_name, len(fhrp_entries),
        )
    else:
        # IOS / IOS-XE path ──────────────────────────────────────────────
        try:
            fhrp_entries = cisco.get_fhrp_config()
        except Exception as exc:
            errors.append(f"FHRP config collection failed: {exc}")
            return synced, errors

        log.info(
            "%-30s  FHRP: %d group(s) found in config", device_name, len(fhrp_entries)
        )

        try:
            oper_state = cisco.get_fhrp_oper_state()
            log.debug(
                "%-30s  FHRP oper state: %d interface(s)",
                device_name, len(oper_state),
            )
        except Exception as exc:
            log.warning(
                "%-30s  FHRP oper state unavailable: %s — groups set to 'unknown'",
                device_name, exc,
            )

    if not fhrp_entries:
        log.info("%-30s  FHRP: no groups found", device_name)
        return synced, errors

    # ── Build interface → prefix-length map for VIP CIDR resolution ───────
    # FHRP VIPs reported by Cisco carry only the host address; the prefix
    # length must be borrowed from the same interface's own IP so that the
    # VIP is stored in the correct subnet (e.g. /24) rather than as /32.
    _iface_prefix_map: Dict[str, str] = {}
    try:
        for ip_entry in cisco.get_interface_ip_inventory():
            raw_ip = ip_entry.get("ip") or ""
            if "/" not in raw_ip:
                continue
            expanded = expand_interface_name(ip_entry.get("name", ""))
            _iface_prefix_map.setdefault(expanded, raw_ip.split("/")[1])
        if _iface_prefix_map:
            log.debug(
                "%-30s  FHRP: built prefix map for %d interface(s)",
                device_name, len(_iface_prefix_map),
            )
    except Exception as exc:
        log.debug(
            "%-30s  FHRP: IP inventory unavailable for VIP mask resolution: %s "
            "— VIPs without explicit mask will fall back to /32",
            device_name, exc,
        )

    # ── 3. Process each group ──────────────────────────────────────────────
    for entry in fhrp_entries:
        iface_name = entry["interface"]
        protocol   = entry["protocol"]
        group      = entry["group"]
        vip        = entry["vip"]
        priority   = entry.get("priority")

        # Determine operational state for this interface + group
        nb_state = oper_state.get(iface_name, {}).get(group, "unknown")

        # Resolve the VIP CIDR before the dry-run guard so the log always
        # shows the correct subnet (e.g. /24 not /32).
        expanded_iface = expand_interface_name(iface_name)
        vip_cidr = _resolve_fhrp_vip_cidr(
            vip=vip,
            iface_prefix_map=_iface_prefix_map,
            iface_name=expanded_iface,
            device_name=device_name,
        )

        if dry_run:
            log.info(
                "DRY-RUN  %-30s  FHRP %-5s grp=%-3s vip=%-20s "
                "iface=%-30s state=%s",
                device_name, protocol, group, vip_cidr, iface_name, nb_state,
            )
            synced += 1
            continue

        # Resolve the NetBox interface ID
        try:
            iface_recs = list(
                nb.nb.dcim.interfaces.filter(device_id=device_id, name=iface_name)
            )
        except Exception as exc:
            errors.append(
                f"FHRP {protocol} grp {group}: interface lookup failed: {exc}"
            )
            continue

        if not iface_recs:
            log.warning(
                "%-30s  FHRP: interface %r not found in NetBox "
                "— skipping %s group %s",
                device_name, iface_name, protocol, group,
            )
            continue

        iface_id = iface_recs[0].id

        # Ensure FHRP group record exists in NetBox
        try:
            grp_result = nb.ensure_fhrp_group(
                protocol=protocol,
                group_id=group,
                vip=vip_cidr,
                description=nb_state,
                dry_run=dry_run,
            )
            grp_action = grp_result.get("_action", "existing")
            fhrp_id    = grp_result["id"]
            if grp_action == "created":
                log.info(
                    "%-30s  FHRP created:  %s grp=%s vip=%s state=%s",
                    device_name, protocol, group, vip, nb_state,
                )
            elif grp_action == "updated":
                log.info(
                    "%-30s  FHRP updated:  %s grp=%s state=%s",
                    device_name, protocol, group, nb_state,
                )
            else:
                log.debug(
                    "%-30s  FHRP existing: %s grp=%s id=%s",
                    device_name, protocol, group, fhrp_id,
                )
        except NetBoxClientError as exc:
            errors.append(
                f"FHRP {protocol} grp {group}: ensure_fhrp_group failed: {exc}"
            )
            continue

        # Assign the FHRP group to the interface
        try:
            assign_result = nb.ensure_fhrp_assignment(
                fhrp_group_id=fhrp_id,
                interface_id=iface_id,
                priority=priority,
            )
            assign_action = assign_result.get("_action", "existing")
            if assign_action in ("created", "updated"):
                log.info(
                    "%-30s  FHRP %s grp=%s → %s (%s)",
                    device_name, protocol, group, iface_name, assign_action,
                )
            else:
                log.debug(
                    "%-30s  FHRP %s grp=%s → %s already assigned",
                    device_name, protocol, group, iface_name,
                )
            synced += 1
        except NetBoxClientError as exc:
            errors.append(
                f"FHRP {protocol} grp {group}: ensure_fhrp_assignment failed: {exc}"
            )

    return synced, errors


# --------------------------------------------------------------------------- #
# NX-OS Port-Channel HSRP IP sync                                             #
# --------------------------------------------------------------------------- #

def _sync_nxos_port_channel_ips(
    cisco: "CiscoDeviceClient",
    nb: NetBoxClient,
    device_name: str,
    device_id: int,
    dry_run: bool,
) -> Tuple[int, List[str]]:
    """
    Assign HSRP virtual IPs discovered on NX-OS Port-Channel interfaces to
    the matching NetBox interface records.

    Returns
    -------
    tuple
        ``(ips_assigned, errors)``
    """
    ips_assigned = 0
    errors: List[str] = []

    try:
        hsrp_map: Dict[str, str] = cisco.get_nxos_port_channel_hsrp_ips()
    except Exception as exc:
        errors.append(f"NX-OS PC HSRP IPs: get failed: {exc}")
        return ips_assigned, errors

    if not hsrp_map:
        log.info("%-30s  NX-OS PC HSRP: no HSRP VIPs found on port-channels", device_name)
        return ips_assigned, errors

    for iface_name, vip in hsrp_map.items():
        try:
            ip_cidr = f"{vip}/32"
            if dry_run:
                log.info(
                    "%-30s  [DRY-RUN] would assign HSRP VIP %s → %s",
                    device_name, ip_cidr, iface_name,
                )
                ips_assigned += 1
                continue
            nb.ensure_ip_on_interface(ip_cidr, device_id, iface_name)
            log.info(
                "%-30s  HSRP VIP %s assigned to %s", device_name, ip_cidr, iface_name
            )
            ips_assigned += 1
        except Exception as exc:
            msg = f"NX-OS PC HSRP: assign {vip} → {iface_name} failed: {exc}"
            log.warning("%-30s  %s", device_name, msg)
            errors.append(msg)

    return ips_assigned, errors


# --------------------------------------------------------------------------- #
# Interface relocation helpers (Stage 1)                                       #
# --------------------------------------------------------------------------- #

def _nb_id(obj: Any) -> Optional[int]:
    """
    Extract a NetBox primary key from a nested object returned by pynetbox.

    Handles: plain ``int``, ``dict`` with ``"id"`` key, pynetbox Record with
    ``id`` attribute.  Returns ``None`` when the ID cannot be determined.
    """
    if obj is None:
        return None
    if isinstance(obj, int):
        return obj
    if isinstance(obj, dict):
        v = obj.get("id")
        return int(v) if v is not None else None
    v = getattr(obj, "id", None)
    return int(v) if v is not None else None


def _snapshot_interface(iface: dict) -> dict:
    """
    Extract all re-creatable fields from a NetBox interface dict.

    Fields that are device/module/name (set separately during recreate),
    auto-populated timestamps, cable state, and read-only counters are
    excluded.

    Choice fields (``type``, ``mode``, ``duplex``) are unwrapped from
    ``{"value": "...", "label": "..."}`` to the plain value string.
    FK fields (``untagged_vlan``, ``lag``) are reduced to their integer ID.
    List fields (``tagged_vlans``) are reduced to a list of integer IDs.

    Parameters
    ----------
    iface : dict
        Plain dict from ``NetBoxClient._to_dict()``.

    Returns
    -------
    dict
        Payload-ready dict suitable for ``create_interface``.
    """
    _SKIP: Set[str] = {
        "id", "url", "display", "device", "module", "name",
        "created", "last_updated", "_action",
        "cable", "cable_end", "link_peers", "connected_endpoints",
        "wireless_link", "count_ipaddresses", "count_fhrp_groups",
        "occupied",
    }
    snap: dict = {}
    for key, val in iface.items():
        if key in _SKIP or val is None:
            continue
        if isinstance(val, dict):
            if "value" in val:
                snap[key] = val["value"]   # choice field → scalar string
            elif "id" in val:
                snap[key] = val["id"]      # FK / nested object → ID
            # complex nested dicts without id/value are skipped
        elif isinstance(val, list):
            ids = []
            for item in val:
                if isinstance(item, dict) and "id" in item:
                    ids.append(item["id"])
                elif isinstance(item, int):
                    ids.append(item)
            if ids:
                snap[key] = ids
        else:
            snap[key] = val
    return snap


def _relocate_interface(
    nb: NetBoxClient,
    existing: dict,
    target_device_id: int,
    target_module_id: Optional[int],
    iface_name: str,
    device_name: str,
    summary: dict,
) -> None:
    """
    Move an interface to the correct VC member device and/or module slot.

    Steps
    -----
    a. Snapshot current interface properties (description, speed, mode, etc.).
    b. Collect all IP addresses assigned to the interface.
    c. Delete the misplaced interface record.
       - If delete fails (e.g. a cable is attached), log an error and abort
         so IPs are never orphaned from a partially-relocated interface.
    d. Recreate the interface on the correct ``target_device_id`` /
       ``target_module_id`` with the snapshotted properties.
    e. Reassign every collected IP to the new interface record.

    Updates ``summary["interfaces_relocated"]`` on success.

    Parameters
    ----------
    nb : NetBoxClient
    existing : dict
        Full interface record (from ``find_interface_by_name_vc``).
    target_device_id : int
        The device the interface *should* be on.
    target_module_id : int or None
        The module the interface *should* be associated with (``None`` →
        device-level, no module).
    iface_name : str
        Canonical interface name (expanded form).
    device_name : str
        Used only in log messages.
    summary : dict
        Running per-device summary dict — ``interfaces_relocated`` is
        incremented on success.
    """
    existing_id = existing.get("id")
    old_dev_id  = _nb_id(existing.get("device"))
    old_mod_id  = _nb_id(existing.get("module"))

    log.info(
        "%-30s  RELOCATE %-42s  dev %s→%s  module %s→%s",
        device_name, iface_name,
        old_dev_id, target_device_id,
        old_mod_id, target_module_id,
    )

    # ── a. Snapshot properties ────────────────────────────────────────────
    snap = _snapshot_interface(existing)

    # ── b. Collect assigned IPs ───────────────────────────────────────────
    try:
        ip_records = nb.list_interface_ips(existing_id)
    except NetBoxClientError as exc:
        log.error(
            "%-30s  RELOCATE %r: IP list failed — aborting to avoid "
            "orphaned IPs: %s", device_name, iface_name, exc,
        )
        summary["errors"].append(
            f"Relocate {iface_name!r}: IP list failed: {exc}"
        )
        return

    # ── c. Detach cable (if present) then delete misplaced interface ─────────
    # NetBox rejects delete_interface when a cable is attached; the cable must
    # be removed first.  This is safe here because we are about to recreate the
    # interface on the correct device in step d.
    try:
        cable_info = nb.get_interface_cable_info(existing_id)
    except NetBoxClientError as exc:
        log.error(
            "%-30s  RELOCATE %r: cable lookup failed — aborting to avoid "
            "orphaned cable: %s", device_name, iface_name, exc,
        )
        summary["errors"].append(
            f"Relocate {iface_name!r}: cable lookup failed: {exc}"
        )
        return

    if cable_info is not None:
        cable_id  = cable_info["cable_id"]
        peer_ids  = cable_info.get("peer_ids", [])
        log.info(
            "%-30s  RELOCATE %r: cable_id=%s (peer_iface_ids=%s) — "
            "deleting cable before interface delete",
            device_name, iface_name, cable_id, peer_ids,
        )
        try:
            nb.delete_cable(cable_id)
        except NetBoxClientError as exc:
            log.error(
                "%-30s  RELOCATE %r: cable_id=%s delete failed — "
                "aborting: %s", device_name, iface_name, cable_id, exc,
            )
            summary["errors"].append(
                f"Relocate {iface_name!r}: cable delete (cable_id={cable_id}) "
                f"failed: {exc}"
            )
            return
        log.info(
            "%-30s  RELOCATE %r: cable_id=%s deleted",
            device_name, iface_name, cable_id,
        )

    try:
        nb.delete_interface(existing_id)
    except NetBoxClientError as exc:
        log.error(
            "%-30s  RELOCATE %r: interface delete failed — "
            "aborting: %s", device_name, iface_name, exc,
        )
        summary["errors"].append(
            f"Relocate {iface_name!r}: interface delete failed: {exc}"
        )
        return

    # ── d. Recreate on correct device / module ────────────────────────────
    create_payload: dict = {
        "device": target_device_id,
        "name":   iface_name,
    }
    if target_module_id is not None:
        create_payload["module"] = target_module_id
    create_payload.update(snap)
    # Ensure "type" is present (required field)
    create_payload.setdefault("type", "other")

    try:
        new_iface = nb.create_interface(create_payload)
    except NetBoxClientError as exc:
        log.error(
            "%-30s  RELOCATE %r: recreate failed: %s", device_name, iface_name, exc,
        )
        summary["errors"].append(
            f"Relocate {iface_name!r}: recreate failed: {exc}"
        )
        return

    new_iface_id = new_iface["id"]

    # ── e. Reassign IPs to new interface record ────────────────────────────
    for ip_rec in ip_records:
        ip_id   = ip_rec.get("id")
        ip_addr = ip_rec.get("address") or ""
        if isinstance(ip_addr, dict):
            ip_addr = ip_addr.get("address", "")
        try:
            nb.reassign_ip_to_interface(ip_id, new_iface_id)
            log.info(
                "%-30s  RELOCATE %r: IP %s → new iface_id=%s",
                device_name, iface_name, ip_addr, new_iface_id,
            )
        except NetBoxClientError as exc:
            log.warning(
                "%-30s  RELOCATE %r: IP %s reassign failed: %s",
                device_name, iface_name, ip_addr, exc,
            )
            summary["errors"].append(
                f"Relocate {iface_name!r}: IP {ip_addr} reassign failed: {exc}"
            )

    summary["interfaces_relocated"] = summary.get("interfaces_relocated", 0) + 1
    log.info(
        "%-30s  RELOCATE %-42s  DONE → dev_id=%s mod_id=%s  "
        "%d IP(s) reassigned",
        device_name, iface_name, target_device_id, target_module_id,
        len(ip_records),
    )


def _remove_duplicate_source_interface(
    nb: NetBoxClient,
    existing: dict,
    iface_name: str,
    device_name: str,
    target_id: int,
    summary: dict,
) -> None:
    """
    Delete a misplaced interface record when the destination device already
    holds a correctly-placed copy with the same name.

    Called only when ``--force`` is active and the duplicate state is
    unambiguous: ``existing`` is confirmed to be on the wrong device and
    ``target_id`` already owns an interface with the same name.

    If the interface has a cable attached, the cable is deleted first so that
    the subsequent interface delete does not fail with a constraint error.

    Parameters
    ----------
    nb : NetBoxClient
    existing : dict
        The misplaced interface record (source of truth for what to delete).
    iface_name : str
        Interface name — used in log messages only.
    device_name : str
        Logical device name — used in log messages only.
    target_id : int
        Device ID that already has the correct interface (for log clarity).
    summary : dict
        Running per-device summary; ``interfaces_removed_duplicates``
        incremented on success, ``errors`` appended on failure.
    """
    existing_id = existing.get("id")
    source_dev  = _nb_id(existing.get("device"))
    source_mod  = _nb_id(existing.get("module"))

    log.info(
        "%-30s  FORCE-REMOVE DUPLICATE %-42s  "
        "from dev_id=%s mod_id=%s (already exists on target dev_id=%s)",
        device_name, iface_name, source_dev, source_mod, target_id,
    )

    # ── 1. Detach cable if one is present ────────────────────────────────────
    try:
        cable_info = nb.get_interface_cable_info(existing_id)
    except NetBoxClientError as exc:
        _sync_err_log.error(
            "duplicate_cable_lookup_failed | device=%s iface=%s "
            "existing_id=%s source_dev=%s error=%s",
            device_name, iface_name, existing_id, source_dev, exc,
        )
        log.error(
            "%-30s  FORCE-REMOVE DUPLICATE %r: cable lookup failed — "
            "aborting to avoid orphaned cable: %s",
            device_name, iface_name, exc,
        )
        summary["errors"].append(
            f"Remove duplicate {iface_name!r} (id={existing_id}): "
            f"cable lookup failed: {exc}"
        )
        return

    if cable_info is not None:
        cable_id  = cable_info["cable_id"]
        peer_ids  = cable_info.get("peer_ids", [])
        log.info(
            "%-30s  FORCE-REMOVE DUPLICATE %-42s  "
            "cable_id=%s peer_iface_ids=%s — deleting cable first",
            device_name, iface_name, cable_id, peer_ids,
        )
        try:
            nb.delete_cable(cable_id)
        except NetBoxClientError as exc:
            _sync_err_log.error(
                "duplicate_cable_delete_failed | device=%s iface=%s "
                "existing_id=%s cable_id=%s error=%s",
                device_name, iface_name, existing_id, cable_id, exc,
            )
            log.error(
                "%-30s  FORCE-REMOVE DUPLICATE %r: cable_id=%s delete "
                "failed — aborting: %s",
                device_name, iface_name, cable_id, exc,
            )
            summary["errors"].append(
                f"Remove duplicate {iface_name!r} (id={existing_id}): "
                f"cable delete (cable_id={cable_id}) failed: {exc}"
            )
            return
        log.info(
            "%-30s  FORCE-REMOVE DUPLICATE %-42s  cable_id=%s deleted",
            device_name, iface_name, cable_id,
        )

    # ── 2. Delete the misplaced interface ─────────────────────────────────────
    try:
        nb.delete_interface(existing_id)
    except NetBoxClientError as exc:
        _sync_err_log.error(
            "duplicate_delete_failed | device=%s iface=%s "
            "existing_id=%s source_dev=%s error=%s",
            device_name, iface_name, existing_id, source_dev, exc,
        )
        log.error(
            "%-30s  FORCE-REMOVE DUPLICATE %r: interface delete failed: %s",
            device_name, iface_name, exc,
        )
        summary["errors"].append(
            f"Remove duplicate {iface_name!r} (id={existing_id}): "
            f"interface delete failed: {exc}"
        )
        return

    summary["interfaces_removed_duplicates"] = (
        summary.get("interfaces_removed_duplicates", 0) + 1
    )
    log.info(
        "%-30s  FORCE-REMOVE DUPLICATE %-42s  DONE — "
        "source id=%s removed; target dev_id=%s is authoritative",
        device_name, iface_name, existing_id, target_id,
    )


# --------------------------------------------------------------------------- #
# Transport selection                                                          #
# --------------------------------------------------------------------------- #

def _collect_interface_inventory(
    cisco: "CiscoDeviceClient",
    transport: str,
    device_name: str,
) -> Tuple[List[dict], Optional[str], List[dict]]:
    """
    Collect the interface inventory from a Cisco device using the requested
    transport, applying strict enforcement rules.

    **Explicit transport** (``"cli"``, ``"netconf"``, ``"restconf"``)
        A single attempt is made against that transport.  On failure the
        exception propagates immediately — **no fallback is attempted**.

    **Auto transport** (``"auto"``)
        Transports are tried in the OS-appropriate order
        (``NETCONF → RESTCONF → CLI`` for IOS-XE; ``CLI`` for NX-OS / IOS).
        Each attempt is logged individually so the caller can see exactly
        what succeeded or failed.

    Parameters
    ----------
    cisco : CiscoDeviceClient
        Already-constructed (but not necessarily connected) client.
    transport : str
        One of ``"auto"``, ``"cli"``, ``"netconf"``, ``"restconf"``
        (lowercase; normalisation is the caller's responsibility).
    device_name : str
        Used in log messages.

    Returns
    -------
    tuple
        ``(interfaces, transport_used, attempts)``

        - *interfaces* — list of normalised interface dicts
        - *transport_used* — the transport that succeeded, or ``None``
        - *attempts* — list of ``{"transport": str, "ok": bool, "error": str|None}``
          dicts, one per attempted transport

    Raises
    ------
    CiscoDeviceClientError
        When the selected transport fails (explicit mode) or all transports
        fail (auto mode).
    """
    transport = transport.lower()

    # ── Explicit transport: one attempt, zero fallback ─────────────────────
    if transport != "auto":
        t_label = transport.upper()
        log.info(
            "%-30s  Transport mode set to %s (no fallback)",
            device_name, t_label,
        )
        log.info(
            "%-30s  Attempting %s only (fallback disabled)",
            device_name, t_label,
        )
        try:
            interfaces = cisco.get_interfaces_inventory(transport=transport)
            attempts   = [{"transport": transport, "ok": True, "error": None}]
            return interfaces, transport, attempts
        except CiscoDeviceClientError as exc:
            log.error(
                "%-30s  %s connection failed — no fallback due to explicit "
                "transport setting: %s",
                device_name, t_label, exc,
            )
            raise   # propagate to sync_device for summary recording

    # ── Auto transport: OS-aware fallback chain ─────────────────────────────
    # The CiscoDeviceClient already knows the correct per-OS order
    # (NETCONF → RESTCONF → CLI for IOS-XE; CLI for NX-OS / IOS).
    # We delegate the actual connection attempts to get_interfaces_inventory_auto()
    # and emit INFO-level logs per attempt so operators see the full picture.
    from cisco_device_client import _AUTO_TRANSPORT_ORDER   # module constant
    order = _AUTO_TRANSPORT_ORDER.get(cisco.os_type, ["cli"])
    order_str = " → ".join(t.upper() for t in order)
    log.info(
        "%-30s  Transport mode AUTO: trying %s",
        device_name, order_str,
    )

    result = cisco.get_interfaces_inventory_auto()

    # Emit one INFO line per attempt so the log tells the full story.
    for attempt in result.get("attempts", []):
        t_label = attempt["transport"].upper()
        if attempt["ok"]:
            log.info("%-30s  Attempting %s... succeeded", device_name, t_label)
        else:
            err = attempt.get("error") or "unknown error"
            log.info("%-30s  Attempting %s... failed: %s", device_name, t_label, err)

    interfaces     = result.get("interfaces") or []
    transport_used = result.get("transport_used")
    attempts       = result.get("attempts") or []

    if not transport_used:
        log.error(
            "%-30s  All transport methods failed for device", device_name
        )
        raise CiscoDeviceClientError(
            f"All transports failed for {device_name}: "
            + "; ".join(
                f"{a['transport']}={a.get('error', 'failed')}"
                for a in attempts
            )
        )

    return interfaces, transport_used, attempts


# --------------------------------------------------------------------------- #
# Per-device orchestration                                                     #
# --------------------------------------------------------------------------- #

def sync_device(
    device: dict,
    nb: NetBoxClient,
    args: argparse.Namespace,
    skip_vids: Set[int],
) -> dict:
    """
    Full sync for one device: interface inventory, VLANs, trunks, prefixes.

    Never raises — all errors are captured in the returned summary dict.
    """
    device_name = device.get("name", "unknown")
    device_id   = device.get("id")

    summary: dict = {
        "device":                          device_name,
        "status":                          "failed",
        "transport_used":                  None,
        "interfaces_updated":              0,
        "interfaces_created":              0,
        "interfaces_skipped":              0,
        "vlan_created_count":              0,
        "vlan_existing_count":             0,
        "svi_interfaces_bound":            0,
        "vlan_site_corrections":           0,
        "svi_ips_assigned":                0,
        "svi_prefixes_created":            0,
        "svi_prefixes_updated":            0,
        "lag_members_synced":              0,
        "interface_states_updated":        0,
        "software_fields_updated":         0,
        "interfaces_timestamped":          0,
        "ips_timestamped":                 0,
        "trunk_interfaces_updated_count":  0,
        "prefixes_created_count":          0,
        "prefixes_updated_count":          0,
        "prefixes_moved_site_count":       0,
        "routed_ips_assigned":             0,
        "nxos_pc_ips_assigned":            0,
        "fhrp_groups_synced":              0,
        "platform_updated":                0,
        "vc_members_updated":              0,
        "interfaces_relocated":                      0,
        "interfaces_removed_duplicates":             0,
        "interfaces_relocation_skipped_dest_exists": 0,
        "interfaces_skipped_missing_vc_member":      0,
        "interfaces_skipped_missing_module":         0,
        "errors":                          [],
        "attempts":                        [],
        "unknown_interface_types":         [],
    }

    # ── Hard gate: device MUST have a primary IP in NetBox ────────────────
    # oob_ip alone is not sufficient — primary_ip4 or primary_ip6 required.
    if not _device_has_primary_ip(device):
        summary["errors"].append(
            "Device has no primary_ip4 or primary_ip6 in NetBox — skipped. "
            "Assign a primary IP to this device in NetBox before syncing."
        )
        log.warning(
            "%-30s  SKIPPED — no primary_ip4 / primary_ip6 in NetBox",
            device_name,
        )
        return summary

    # ── Resolve management IP and OS type ──────────────────────────────────
    mgmt_ip = get_device_mgmt_ip(device)
    if not mgmt_ip:
        summary["errors"].append(
            "No primary IP configured in NetBox — cannot connect."
        )
        return summary

    os_type = get_device_os_type(device)
    if not os_type:
        summary["errors"].append(
            f"Cannot determine os_type from platform "
            f"{device.get('platform')!r}. Add slug to PLATFORM_SLUG_MAP."
        )
        return summary

    log.info(
        "%-30s  ip=%-18s  os_type=%-6s  transport=%s",
        device_name, mgmt_ip, os_type, args.transport,
    )

    # ── Resolve site ───────────────────────────────────────────────────────
    try:
        site = nb.get_site_for_device(device_id)
    except NetBoxClientError as exc:
        summary["errors"].append(f"Site lookup failed: {exc}")
        return summary

    site_id   = site["id"]
    site_name = site.get("name", f"id={site_id}")
    log.info("%-30s  site=%s", device_name, site_name)

    # ── Build VC member map (position → device_id) if this is a VC ────────
    vc_member_map: Dict[int, int] = {}
    vc_id = device.get("_vc_id")
    if vc_id:
        vc_member_map = build_vc_member_map(vc_id, nb)
        if vc_member_map:
            log.info(
                "%-30s  VC id=%s  member map: %s",
                device_name, vc_id,
                {pos: did for pos, did in sorted(vc_member_map.items())},
            )
        else:
            log.warning(
                "%-30s  VC id=%s found but no members have vc_position set — "
                "interfaces will be created on the master device.",
                device_name, vc_id,
            )

    # ── Determine device model family for interface parsing ────────────────
    _dt = device.get("device_type") or {}
    _model_str = (_dt.get("model", "") if isinstance(_dt, dict) else "") or ""
    device_model_family = classify_device_model(_model_str)
    log.debug(
        "%-30s  device_type.model=%r → family=%s",
        device_name, _model_str, device_model_family,
    )

    # ── Build per-device module maps (slot_number → module_id) ────────────
    # Queries NetBox module bays for every VC member.  Devices with no
    # module bays / no installed modules produce an empty inner dict.
    vc_member_module_maps: Dict[int, Dict[int, int]] = build_vc_module_maps(
        vc_member_map, nb, device_id
    )
    if any(vc_member_module_maps.values()):
        log.info(
            "%-30s  module maps: %s",
            device_name,
            {
                did: list(slot_map.keys())
                for did, slot_map in vc_member_module_maps.items()
                if slot_map
            },
        )
    else:
        log.debug("%-30s  no installed modules found in NetBox", device_name)

    # ── All VC device IDs for cross-member interface lookup ────────────────
    all_vc_device_ids: List[int] = list(
        {device_id} | set(vc_member_map.values())
    )

    # ── Connect to device ──────────────────────────────────────────────────
    enable_secret = args.enable_secret or None
    cisco = CiscoDeviceClient(
        host=mgmt_ip,
        username=args.username,
        password=args.password,
        os_type=os_type,
        enable_secret=enable_secret,
        timeout=args.timeout,
        verify_ssl=False,
    )
    # Honour the --transport flag for ALL collection methods, not just Stage 1.
    # Every method that defaults to transport=None resolves against this value,
    # so setting it here prevents _auto_collect from firing on VLAN, trunk, and
    # IP inventory when an explicit transport was requested.
    cisco.transport = args.transport

    # ── Stage 1: interface inventory (speed / duplex / description) ────────
    try:
        interfaces, transport_used, attempts = _collect_interface_inventory(
            cisco=cisco,
            transport=args.transport,
            device_name=device_name,
        )
        summary["transport_used"] = transport_used
        summary["attempts"]       = attempts
    except CiscoDeviceClientError as exc:
        summary["errors"].append(f"Interface collection failed: {exc}")
        summary["attempts"] = [
            {"transport": args.transport, "ok": False, "error": str(exc)}
        ]
        cisco._cli_disconnect()
        return summary

    _n_ifaces = len(interfaces)
    log.info(
        "%-30s  collected %d interface(s) via %s",
        device_name, _n_ifaces, summary["transport_used"],
    )

    # ── Collect VRF assignments from running-config (always CLI) ──────────
    # This is independent of the transport used for interface inventory.
    # Failures are non-fatal: all interfaces fall back to the global table.
    iface_vrf_map: Dict[str, Optional[str]] = {}
    try:
        iface_vrf_map = cisco.get_interface_vrf_map()
        vrf_ifaces = {k: v for k, v in iface_vrf_map.items() if v}
        if vrf_ifaces:
            log.info(
                "%-30s  VRF map: %d interface(s) have a non-global VRF",
                device_name, len(vrf_ifaces),
            )
        else:
            log.debug(
                "%-30s  VRF map: no VRF assignments found — "
                "all interfaces treated as global",
                device_name,
            )
    except Exception as exc:
        log.warning(
            "%-30s  VRF map collection failed: %s "
            "— all interfaces treated as global",
            device_name, exc,
        )

    # Shared VRF name → NetBox VRF ID cache; mutated by _resolve_vrf_id
    # as each VRF is encountered and (if absent) created in NetBox.
    vrf_cache: Dict[str, int] = {}

    # ── Transceiver map (NX-OS only) — improves type inference for Ethernet ─
    # Non-fatal: if the command fails we fall back to speed-only heuristics.
    transceiver_map: Dict[str, dict] = {}
    if os_type == "nxos":
        try:
            transceiver_map = cisco.get_interface_transceiver_map()
            log.debug(
                "%-30s  transceiver map: %d interface(s) queried",
                device_name, len(transceiver_map),
            )
        except Exception as exc:
            log.warning(
                "%-30s  transceiver map failed: %s "
                "— NX-OS Ethernet type inference will use speed only",
                device_name, exc,
            )

    _unknown_types: List[dict] = []

    # ── Preload NetBox interfaces for every VC member (one batch per device) ──
    # Replaces the per-interface find_interface_by_name_vc API call with a
    # single upfront fetch so the inner loop does only dict lookups.
    # get_interfaces() returns List[dict] (already _to_dict()-converted), which
    # is compatible with _snapshot_interface / _relocate_interface.
    nb_ifaces_by_device: Dict[int, Dict[str, dict]] = {}
    for _did in all_vc_device_ids:
        nb_ifaces_by_device[_did] = {}
        try:
            for _iface in nb.get_interfaces(device_id=_did):
                _iname = _iface.get("name", "")
                if _iname:
                    nb_ifaces_by_device[_did][_iname] = _iface
        except NetBoxClientError as exc:
            log.warning(
                "%-30s  Stage 1: could not preload interfaces for dev_id=%s: %s",
                device_name, _did, exc,
            )
    log.info(
        "%-30s  Stage 1: preloaded %d interface(s) across %d VC member(s)",
        device_name,
        sum(len(m) for m in nb_ifaces_by_device.values()),
        len(all_vc_device_ids),
    )

    for iface in interfaces:
        raw_name = iface.get("name", "")
        if not raw_name:
            continue

        # ── Expand and parse the interface name ───────────────────────────
        iface_name = expand_interface_name(raw_name)
        parsed     = parse_cisco_interface(raw_name)

        # ── Detect missing VC member (hard error — log + skip) ────────────
        # Only physical interfaces carry a slot number; logical ones return
        # None from get_vc_member_slot and are always kept on the master.
        _vc_slot = get_vc_member_slot(iface_name) if vc_member_map else None
        if vc_member_map and _vc_slot is not None and _vc_slot not in vc_member_map:
            _sync_err_log.warning(
                "missing_vc_member | device=%s vc_id=%s iface=%s vc_slot=%s",
                device_name, vc_id, iface_name, _vc_slot,
            )
            summary["interfaces_skipped_missing_vc_member"] += 1
            continue

        # ── Route to the correct VC member device ─────────────────────────
        target_id = resolve_target_device_id(iface_name, device_id, vc_member_map)

        # ── Resolve target module/slot ────────────────────────────────────
        # Returns None when module==0 (no dedicated linecard bay) or when
        # no matching module bay is found in NetBox (falls back to device-
        # level interface creation and logs a warning via resolve_target_module_id).
        device_module_map = vc_member_module_maps.get(target_id, {})
        target_module_id  = resolve_target_module_id(parsed["module"], device_module_map)

        if parsed["module"] and not target_module_id:
            # module_slot is present in the interface name but the target
            # device has no matching installed module in NetBox — do not
            # create or relocate; operator must install the module bay first.
            _sync_err_log.warning(
                "missing_module | device=%s vc_id=%s iface=%s "
                "vc_slot=%s module_slot=%s target_device_id=%s",
                device_name, vc_id, iface_name,
                parsed["member"], parsed["module"], target_id,
            )
            summary["interfaces_skipped_missing_module"] += 1
            continue

        # ── Build NetBox payload ──────────────────────────────────────────
        nb_payload: dict = {}
        if iface.get("description") is not None:
            nb_payload["description"] = iface["description"]
        if iface.get("speed_kbps") is not None:
            nb_payload["speed"] = iface["speed_kbps"]
        if iface.get("duplex") is not None:
            nb_payload["duplex"] = iface["duplex"]
        if target_module_id is not None:
            nb_payload["module"] = target_module_id

        # ── Interface type inference ──────────────────────────────────────
        _xcvr = transceiver_map.get(iface_name) or transceiver_map.get(raw_name)
        _iface_type = infer_netbox_interface_type(
            iface_name,
            speed_kbps=iface.get("speed_kbps"),
            has_transceiver=_xcvr.get("has_transceiver") if _xcvr else None,
        )
        if _iface_type == "other":
            _unknown_types.append({"name": iface_name, "reason": "no mapping rule matched"})
        # Always include type when creating a new interface — mirrors the
        # _relocate_interface path which calls create_payload.setdefault("type", "other").
        _is_missing = not nb_ifaces_by_device.get(target_id, {}).get(iface_name)
        if _is_missing or args.force_type:
            nb_payload["type"] = _iface_type

        # ── Log VRF detection (Stage 1 is inventory only; VRF is set on IPs) ─
        _stage1_vrf = iface_vrf_map.get(iface_name) or iface_vrf_map.get(raw_name)
        if _stage1_vrf:
            log.debug(
                "%-30s  Detected VRF %r on interface %s",
                device_name, _stage1_vrf, iface_name,
            )

        # ── Dry-run: report intent using preloaded maps (no API calls) ───────
        if args.dry_run:
            if len(all_vc_device_ids) > 1 or target_module_id is not None:
                # Mirror find_interface_by_name_vc: first match wins in order.
                _existing_dr: Optional[dict] = None
                for _did_dr in all_vc_device_ids:
                    _existing_dr = nb_ifaces_by_device.get(_did_dr, {}).get(iface_name)
                    if _existing_dr is not None:
                        break
                if _existing_dr is not None:
                    ex_dev_id = _nb_id(_existing_dr.get("device"))
                    ex_mod_id = _nb_id(_existing_dr.get("module"))
                    wrong_dev = ex_dev_id is not None and ex_dev_id != target_id
                    wrong_mod = (
                        target_module_id is not None
                        and ex_mod_id != target_module_id
                    )
                    if wrong_dev or wrong_mod:
                        # Duplicate guard: if moving across devices, check dest.
                        dest_occupied = (
                            wrong_dev
                            and bool(
                                nb_ifaces_by_device.get(target_id, {}).get(iface_name)
                            )
                        )
                        if dest_occupied:
                            if args.force:
                                log.info(
                                    "DRY-RUN  %-30s  WOULD FORCE-REMOVE DUPLICATE "
                                    "%r from dev_id=%s "
                                    "(dest dev_id=%s already correct)  "
                                    "module %s→%s",
                                    device_name, iface_name, ex_dev_id,
                                    target_id, ex_mod_id, target_module_id,
                                )
                            else:
                                log.info(
                                    "DRY-RUN  %-30s  WOULD SKIP RELOCATION "
                                    "(dest dev_id=%s already has %r)  "
                                    "existing dev_id=%s  module %s→%s  "
                                    "(use --force to remove duplicate source)",
                                    device_name, target_id, iface_name,
                                    ex_dev_id, ex_mod_id, target_module_id,
                                )
                        elif wrong_dev and not args.force:
                            log.info(
                                "DRY-RUN  %-30s  WRONG VC MEMBER %-42s  "
                                "existing dev_id=%s  target dev_id=%s  "
                                "(add --force to relocate)",
                                device_name, iface_name, ex_dev_id, target_id,
                            )
                        else:
                            log.info(
                                "DRY-RUN  %-30s  WOULD RELOCATE %-42s  "
                                "dev %s→%s  module %s→%s",
                                device_name, iface_name,
                                ex_dev_id, target_id,
                                ex_mod_id, target_module_id,
                            )
                    else:
                        # Interface correctly placed; scan other VC members for stale copies.
                        for _stale_did_dr in all_vc_device_ids:
                            if _stale_did_dr == target_id:
                                continue
                            _stale_rec_dr = nb_ifaces_by_device.get(
                                _stale_did_dr, {}
                            ).get(iface_name)
                            if _stale_rec_dr is None:
                                continue
                            _stale_dev_dr = _nb_id(_stale_rec_dr.get("device"))
                            if args.force:
                                log.info(
                                    "DRY-RUN  %-30s  WOULD FORCE-REMOVE STALE COPY "
                                    "%r from dev_id=%s "
                                    "(correct copy already on dev_id=%s)",
                                    device_name, iface_name,
                                    _stale_dev_dr, target_id,
                                )
                            else:
                                log.info(
                                    "DRY-RUN  %-30s  STALE COPY %r on dev_id=%s "
                                    "(correct copy on dev_id=%s) — "
                                    "use --force to remove",
                                    device_name, iface_name,
                                    _stale_dev_dr, target_id,
                                )
                elif not nb_ifaces_by_device.get(target_id, {}).get(iface_name):
                    log.info(
                        "DRY-RUN  %-30s  WOULD CREATE %-42s  "
                        "dev_id=%-6s  mod_id=%-6s",
                        device_name, iface_name, target_id, target_module_id,
                    )
            log.info(
                "DRY-RUN  %-30s  iface=%-40s  dev_id=%-6s  mod_id=%-6s  %s",
                device_name, iface_name, target_id, target_module_id, nb_payload,
            )
            summary["interfaces_skipped"] += 1
            continue

        # ── Live: relocation check using preloaded maps (no extra API call) ──
        # Mirrors find_interface_by_name_vc: iterate all_vc_device_ids in order
        # and take the first hit.  The dicts are already _to_dict()-converted so
        # they are safe to pass directly to _relocate_interface / _snapshot_interface.
        if len(all_vc_device_ids) > 1 or target_module_id is not None:
            _existing: Optional[dict] = None
            for _did_search in all_vc_device_ids:
                _existing = nb_ifaces_by_device.get(_did_search, {}).get(iface_name)
                if _existing is not None:
                    break

            if _existing is not None:
                ex_dev_id = _nb_id(_existing.get("device"))
                ex_mod_id = _nb_id(_existing.get("module"))
                wrong_dev = ex_dev_id is not None and ex_dev_id != target_id
                wrong_mod = (
                    target_module_id is not None
                    and ex_mod_id != target_module_id
                )
                if wrong_dev or wrong_mod:
                    # Duplicate guard: when moving to a different VC member,
                    # abort if the destination already has the same name to
                    # prevent creating a second record and orphaning the first.
                    dest_has_iface = (
                        wrong_dev
                        and bool(nb_ifaces_by_device.get(target_id, {}).get(iface_name))
                    )
                    if dest_has_iface:
                        if args.force:
                            _remove_duplicate_source_interface(
                                nb=nb,
                                existing=_existing,
                                iface_name=iface_name,
                                device_name=device_name,
                                target_id=target_id,
                                summary=summary,
                            )
                            # Remove stale map entry so later same-name lookups
                            # in this pass don't collide with the deleted record.
                            if ex_dev_id in nb_ifaces_by_device:
                                nb_ifaces_by_device[ex_dev_id].pop(iface_name, None)
                        else:
                            _sync_err_log.warning(
                                "dest_exists_duplicate | device=%s iface=%s "
                                "existing_dev=%s existing_mod=%s "
                                "target_dev=%s target_mod=%s "
                                "reason=dest_interface_exists_source_not_cleaned",
                                device_name, iface_name,
                                ex_dev_id, ex_mod_id,
                                target_id, target_module_id,
                            )
                            log.warning(
                                "%-30s  DUPLICATE %-42s  detected on dest "
                                "dev_id=%s — skipping relocation "
                                "(use --force to clean up source dev_id=%s)",
                                device_name, iface_name, target_id, ex_dev_id,
                            )
                            summary["interfaces_relocation_skipped_dest_exists"] += 1
                        # Upsert below still runs against the correctly-placed
                        # target interface to apply any field updates.
                    elif wrong_dev and not args.force:
                        # Interface is on the wrong VC member but --force was not
                        # given.  Log an error and leave it untouched.
                        _sync_err_log.warning(
                            "wrong_vc_member_no_force | device=%s iface=%s "
                            "existing_dev=%s target_dev=%s",
                            device_name, iface_name, ex_dev_id, target_id,
                        )
                        log.error(
                            "%-30s  WRONG VC MEMBER %-42s  "
                            "existing dev_id=%s, expected dev_id=%s — "
                            "re-run with --force to relocate",
                            device_name, iface_name, ex_dev_id, target_id,
                        )
                        summary["errors"].append(
                            f"Interface {iface_name!r} is on wrong VC member "
                            f"(dev_id={ex_dev_id}, expected dev_id={target_id}). "
                            f"Re-run with --force to relocate."
                        )
                    else:
                        _relocate_interface(
                            nb=nb,
                            existing=_existing,
                            target_device_id=target_id,
                            target_module_id=target_module_id,
                            iface_name=iface_name,
                            device_name=device_name,
                            summary=summary,
                        )
                        # Update preloaded maps so any later same-name lookup
                        # in this sync pass sees the new placement.
                        if wrong_dev and ex_dev_id in nb_ifaces_by_device:
                            nb_ifaces_by_device[ex_dev_id].pop(iface_name, None)
                        nb_ifaces_by_device.setdefault(target_id, {})[iface_name] = _existing
                        # After relocation upsert below applies remaining field updates.
                else:
                    # Interface is already on the correct device/module.
                    # The first-hit search may have found the correct record
                    # while a stale copy on another VC member went undetected.
                    # Scan every other member now and clean up stale copies.
                    for _stale_did in all_vc_device_ids:
                        if _stale_did == target_id:
                            continue
                        _stale_rec = nb_ifaces_by_device.get(_stale_did, {}).get(iface_name)
                        if _stale_rec is None:
                            continue
                        _stale_dev_id = _nb_id(_stale_rec.get("device"))
                        if args.force:
                            _remove_duplicate_source_interface(
                                nb=nb,
                                existing=_stale_rec,
                                iface_name=iface_name,
                                device_name=device_name,
                                target_id=target_id,
                                summary=summary,
                            )
                            if _stale_did in nb_ifaces_by_device:
                                nb_ifaces_by_device[_stale_did].pop(iface_name, None)
                        else:
                            _sync_err_log.warning(
                                "stale_copy_no_force | device=%s iface=%s "
                                "stale_dev=%s target_dev=%s",
                                device_name, iface_name, _stale_dev_id, target_id,
                            )
                            log.warning(
                                "%-30s  STALE COPY %-42s  on dev_id=%s "
                                "(correct copy on dev_id=%s) — "
                                "use --force to remove",
                                device_name, iface_name, _stale_dev_id, target_id,
                            )
                            summary["interfaces_relocation_skipped_dest_exists"] += 1

        try:
            result = nb.upsert_interface(
                device_id=target_id, name=iface_name, payload=nb_payload
            )
            action = result.get("action", "")
            if action == "created":
                summary["interfaces_created"] += 1
            elif action == "updated":
                summary["interfaces_updated"] += 1
            else:
                summary["interfaces_skipped"] += 1
        except NetBoxClientError as exc:
            err = f"upsert_interface({iface_name!r}, dev={target_id}): {exc}"
            log.warning("%-30s  %s", device_name, err)
            summary["errors"].append(err)

    # Release the interfaces list — it is only used in the Stage 1 loop above.
    # With 100 concurrent threads each holding ~50 interface dicts, this saves
    # tens of MB of peak RSS before the remaining 8 stages run.
    del interfaces, _n_ifaces

    # Record any interfaces whose type fell back to "other".
    summary["unknown_interface_types"] = _unknown_types
    if _unknown_types:
        log.info(
            "%-30s  %d interface(s) with unknown type (set to 'other'): %s",
            device_name, len(_unknown_types),
            [e["name"] for e in _unknown_types],
        )

    # ── Stage 2: VLAN sync ─────────────────────────────────────────────────
    vlan_id_map: Dict[int, int] = {}
    if args.sync_vlans:
        vlan_id_map, v_created, v_existing, v_errors, vlan_ok = _sync_vlans(
            cisco=cisco,
            nb=nb,
            device_name=device_name,
            site_id=site_id,
            skip_vids=skip_vids,
            deny_substring=args.deny_vlan_group_name_substring,
            dry_run=args.dry_run,
        )
        summary["vlan_created_count"]  = v_created
        summary["vlan_existing_count"] = v_existing
        summary["errors"].extend(v_errors)
        if not vlan_ok and args.fail_fast:
            cisco._cli_disconnect()
            return summary

    # ── Stage 2.5: SVI bindings — interface ↔ VLAN + VLAN site consistency ──
    if args.sync_vlans:
        svi_bound, vlan_site_fixes, pfx_created, pfx_updated, ips_assigned, svi_errors = \
            _sync_svi_bindings(
                cisco=cisco,
                nb=nb,
                device_name=device_name,
                device_id=device_id,
                site_id=site_id,
                site_name=site_name,
                vlan_id_map=vlan_id_map,
                dry_run=args.dry_run,
                iface_vrf_map=iface_vrf_map,
                vrf_cache=vrf_cache,
            )
        summary["svi_interfaces_bound"]  = svi_bound
        summary["vlan_site_corrections"] = vlan_site_fixes
        summary["svi_ips_assigned"]      = ips_assigned
        summary["svi_prefixes_created"]  = pfx_created
        summary["svi_prefixes_updated"]  = pfx_updated
        summary["errors"].extend(svi_errors)

    # ── Stage 3: trunk VLAN sync ───────────────────────────────────────────
    if args.sync_trunks:
        t_updated, t_errors = _sync_trunks(
            cisco=cisco,
            nb=nb,
            device_name=device_name,
            device_id=device_id,
            vlan_id_map=vlan_id_map,
            skip_vids=skip_vids,
            dry_run=args.dry_run,
            vc_member_map=vc_member_map,
            site_id=site_id,
        )
        summary["trunk_interfaces_updated_count"] = t_updated
        summary["errors"].extend(t_errors)

    # ── Stage 4: IP + prefix sync ──────────────────────────────────────────
    if args.sync_prefixes:
        p_created, p_updated, p_moved, p_ips, p_errors = _sync_prefixes(
            cisco=cisco,
            nb=nb,
            device_name=device_name,
            site_id=site_id,
            vlan_id_map=vlan_id_map,
            dry_run=args.dry_run,
            iface_vrf_map=iface_vrf_map,
            vrf_cache=vrf_cache,
            device_id=device_id,
            vc_member_map=vc_member_map,
        )
        summary["prefixes_created_count"]    = p_created
        summary["prefixes_updated_count"]    = p_updated
        summary["prefixes_moved_site_count"] = p_moved
        summary["routed_ips_assigned"]       = p_ips
        summary["errors"].extend(p_errors)

    # ── Stage 4.5: NX-OS Port-Channel HSRP virtual IPs ───────────────────
    if args.sync_prefixes and os_type == "nxos":
        pc_ips, pc_errors = _sync_nxos_port_channel_ips(
            cisco=cisco,
            nb=nb,
            device_name=device_name,
            device_id=device_id,
            dry_run=args.dry_run,
        )
        summary["nxos_pc_ips_assigned"] = pc_ips
        summary["errors"].extend(pc_errors)

    # ── Stage 4.6: FHRP groups (HSRP / VRRP / GLBP) ─────────────────────
    if args.sync_prefixes:
        fhrp_synced, fhrp_errors = _sync_fhrp_groups(
            cisco=cisco,
            nb=nb,
            device_name=device_name,
            device_id=device_id,
            os_type=os_type,
            dry_run=args.dry_run,
        )
        summary["fhrp_groups_synced"] = fhrp_synced
        summary["errors"].extend(fhrp_errors)

    # VRF data (iface_vrf_map, vrf_cache) is no longer needed after Stages
    # 2.5 / 4 / 4.6.  Release now to reduce per-thread peak RSS.
    del iface_vrf_map, vrf_cache

    # ── Stage 5: Port-channel / LAG membership ────────────────────────────
    lag_synced, lag_errors = _sync_portchannel_membership(
        cisco=cisco, nb=nb,
        device_name=device_name, device_id=device_id,
        dry_run=args.dry_run,
        vc_member_map=vc_member_map,
    )
    summary["lag_members_synced"] = lag_synced
    summary["errors"].extend(lag_errors)

    # ── Stage 6: Interface admin / oper state ─────────────────────────────
    state_updated, state_errors = _sync_interface_states(
        cisco=cisco, nb=nb,
        device_name=device_name, device_id=device_id,
        dry_run=args.dry_run,
        vc_member_map=vc_member_map,
        vc_member_module_maps=vc_member_module_maps,
    )
    summary["interface_states_updated"] = state_updated
    summary["errors"].extend(state_errors)

    # ── Stage 7: Software, platform, and VC propagation ──────────────────
    sw_updated, plat_updated, vc_updated, fact_errors = _sync_device_facts(
        cisco=cisco,
        nb=nb,
        device_name=device_name,
        device_id=device_id,
        vc_id=device.get("_vc_id"),
        dry_run=args.dry_run,
    )
    summary["software_fields_updated"] = sw_updated
    summary["platform_updated"]        = plat_updated
    summary["vc_members_updated"]      = vc_updated
    summary["errors"].extend(fact_errors)

    # ── Stage 8: Touch interface if_last_update ───────────────────────────
    if_ts = _touch_interface_timestamps(
        nb=nb, device_name=device_name, device_id=device_id,
        dry_run=args.dry_run,
        vc_member_map=vc_member_map,
    )
    summary["interfaces_timestamped"] = if_ts

    # ── Stage 9: Touch IP_Last_update ─────────────────────────────────────
    ip_ts = _touch_ip_timestamps(
        nb=nb, device_name=device_name, device_id=device_id,
        dry_run=args.dry_run,
        vc_member_map=vc_member_map,
    )
    summary["ips_timestamped"] = ip_ts

    # Release per-device lookup structures before returning the summary.
    # These can be large for VC stacks and are no longer needed.
    del vc_member_map, vc_member_module_maps, all_vc_device_ids

    cisco._cli_disconnect()
    summary["status"] = "success"
    return summary


# --------------------------------------------------------------------------- #
# Logging setup                                                                #
# --------------------------------------------------------------------------- #

def _configure_logging(level: str, log_file: Optional[str] = None) -> None:
    """
    Configure the root logger.

    Logs are always written to **stderr**.  When *log_file* is supplied they
    are also appended (UTF-8) to that file so the operator can watch the
    terminal in real time and keep a persistent record simultaneously.

    Parameters
    ----------
    level : str
        One of ``"DEBUG"``, ``"INFO"``, ``"WARNING"``, ``"ERROR"``.
    log_file : str or None
        Path to an optional log file.  The file is opened in append mode so
        successive runs accumulate rather than overwrite.
    """
    fmt  = "%(asctime)s %(levelname)-8s %(name)s: %(message)s"
    root = logging.getLogger()
    root.setLevel(getattr(logging, level))
    root.handlers.clear()   # prevent duplicate handlers on repeated calls

    stderr_h = logging.StreamHandler(sys.stderr)
    stderr_h.setFormatter(logging.Formatter(fmt))
    root.addHandler(stderr_h)

    # Always append WARNING+ to sync_errors.log; never echo to stderr.
    _sync_err_log.handlers.clear()
    try:
        _err_h = logging.FileHandler("sync_errors.log", mode="a", encoding="utf-8")
        _err_h.setLevel(logging.WARNING)
        _err_h.setFormatter(logging.Formatter(fmt))
        _sync_err_log.setLevel(logging.WARNING)
        _sync_err_log.addHandler(_err_h)
        _sync_err_log.propagate = False   # keep out of stderr / root logger
    except OSError as exc:
        log.warning(
            "Cannot open sync_errors.log: %s — VC/module errors to stderr only",
            exc,
        )

    if log_file:
        try:
            file_h = logging.FileHandler(log_file, mode="a", encoding="utf-8")
            file_h.setFormatter(logging.Formatter(fmt))
            root.addHandler(file_h)
            logging.getLogger(__name__).info(
                "Log file: %s", log_file
            )
        except OSError as exc:
            logging.getLogger(__name__).warning(
                "Cannot open log file %r: %s — logging to stderr only", log_file, exc
            )


# --------------------------------------------------------------------------- #
# Entry point                                                                  #
# --------------------------------------------------------------------------- #

def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    _configure_logging(args.log_level, args.log_file)

    if is_vault_configured(args):
        vault_addr, vault_role_id, vault_secret_id = resolve_vault_auth(args)
        vault = VaultClient(
            addr=vault_addr,
            role_id=vault_role_id,
            secret_id=vault_secret_id,
            mount=args.vault_mount,
            path=args.vault_path,
        )
        try:
            secrets = vault.get_secrets()
        except VaultError as exc:
            log.error("Failed to load credentials from Vault: %s", exc)
            _sync_err_log.error("vault_error | %s", exc)
            sys.exit(1)
        args.username = secrets["user"]
        args.password = secrets["password"]
        netbox_url   = secrets["netbox_url"]
        netbox_token = secrets["netbox_token"]
    else:
        missing: List[str] = []
        if not args.netbox_url:
            missing.append("--netbox-url / NETBOX_URL")
        if not args.netbox_token:
            missing.append("--netbox-token / NETBOX_API")
        if not args.username:
            missing.append("--username / CISCO_SRV_ACCOUNT")
        if not args.password:
            missing.append("--password / CISCO_SRV_PWD")
        if missing:
            log.error("Missing required credentials: %s", ", ".join(missing))
            sys.exit(1)
        netbox_url   = args.netbox_url
        netbox_token = args.netbox_token

    # Parse skip VLAN IDs
    skip_vids: Set[int] = set()
    for part in args.skip_vlan_ids.split(","):
        part = part.strip()
        if part:
            try:
                skip_vids.add(int(part))
            except ValueError:
                log.warning("Invalid --skip-vlan-ids entry %r — ignored", part)
    log.debug("Skip VLAN IDs: %s", sorted(skip_vids))

    if args.dry_run:
        log.info("*** DRY-RUN mode — no changes will be written to NetBox ***")

    # ── HTTP connection pool sizing ────────────────────────────────────────
    # The default pool_size of 20 is wildly undersized for --max-workers=100.
    # Undersize → threads block waiting for a socket → latency snowballs →
    # urllib3 creates extra sockets OUTSIDE the pool → socket exhaustion over
    # several hours (the "crawl" symptom).
    # Rule: pool_size ≥ max_workers so each thread always gets a connection.
    _pool_size = max(
        args.max_api_connections or (args.max_workers + 10),
        20,
    )
    log.debug("NetBox HTTP pool size: %d", _pool_size)

    nb = NetBoxClient(
        base_url=netbox_url,
        token=netbox_token,
        verify_ssl=args.netbox_verify_ssl,
        threading=True,
        pool_size=_pool_size,
    )

    devices = resolve_device_list(args, nb)
    if not devices:
        log.warning("No devices to process.")
        print(json.dumps([], indent=2))
        return

    log.info(
        "Processing %d device(s), %d worker(s), transport=%s  "
        "(NetBox pool=%d)",
        len(devices), args.max_workers, args.transport, _pool_size,
    )

    # ── Optional CPU profiling ─────────────────────────────────────────────
    _profiler = None
    if args.profile:
        import cProfile
        _profiler = cProfile.Profile()
        _profiler.enable()
        log.info("CPU profiling enabled — will write sync_profile.prof")

    # ── Optional memory profiling ──────────────────────────────────────────
    if args.mem_profile:
        import tracemalloc
        tracemalloc.start(10)   # keep 10 frames per trace
        log.info("Memory profiling enabled (tracemalloc)")

    summaries: List[dict] = []
    with ThreadPoolExecutor(max_workers=args.max_workers) as pool:
        future_to_device = {
            pool.submit(sync_device, device, nb, args, skip_vids): device
            for device in devices
        }
        for future in as_completed(future_to_device):
            # pop() releases the completed Future and its result reference
            # immediately instead of waiting until the entire executor block
            # exits — critical at 100 threads where each result can be large.
            device      = future_to_device.pop(future)
            device_name = device.get("name", "unknown")
            try:
                result = future.result()
                summaries.append(result)
                log.info(
                    "%-30s  status=%-8s  ifaces u=%d/c=%d/s=%d  "
                    "vlans c=%d  trunks u=%d  pfx c=%d/u=%d/mv=%d  errs=%d",
                    device_name,
                    result.get("status", "?"),
                    result.get("interfaces_updated", 0),
                    result.get("interfaces_created", 0),
                    result.get("interfaces_skipped", 0),
                    result.get("vlan_created_count", 0),
                    result.get("trunk_interfaces_updated_count", 0),
                    result.get("prefixes_created_count", 0),
                    result.get("prefixes_updated_count", 0),
                    result.get("prefixes_moved_site_count", 0),
                    len(result.get("errors", [])),
                )
            except Exception as exc:
                log.error("Unexpected error for %s: %s", device_name, exc)
                summaries.append({
                    "device":  device_name,
                    "status":  "failed",
                    "errors":  [str(exc)],
                    "attempts": [],
                })
            finally:
                del future   # release Future object and any retained traceback

    # ── Profiling teardown ─────────────────────────────────────────────────
    if _profiler is not None:
        import pstats, io as _io
        _profiler.disable()
        _prof_file = "sync_profile.prof"
        _profiler.dump_stats(_prof_file)
        _s = _io.StringIO()
        pstats.Stats(_profiler, stream=_s).sort_stats("cumulative").print_stats(20)
        log.info("CPU profile written to %s. Top 20 hotspots:\n%s",
                 _prof_file, _s.getvalue())

    if args.mem_profile:
        _snap = tracemalloc.take_snapshot()
        tracemalloc.stop()
        _top = _snap.statistics("lineno")[:15]
        log.info("Top 15 memory allocation sites:")
        for _st in _top:
            log.info("  %s", _st)

    # ── Optional RSS logging (requires psutil) ─────────────────────────────
    try:
        import psutil as _psutil  # type: ignore[import-untyped]
        _rss = _psutil.Process().memory_info().rss / 1_048_576
        log.info("Process RSS at finish: %.1f MB", _rss)
    except ImportError:
        pass  # psutil is optional — install with: pip install psutil

    summaries.sort(key=lambda s: s.get("device", ""))

    # Overall totals to stderr
    total_ok   = sum(1 for s in summaries if s["status"] == "success")
    total_fail = sum(1 for s in summaries if s["status"] == "failed")
    log.info(
        "DONE  devices=%d ok=%d failed=%d  "
        "ifaces: updated=%d created=%d  vlans: created=%d  "
        "trunks: updated=%d  prefixes: created=%d moved=%d",
        len(summaries), total_ok, total_fail,
        sum(s.get("interfaces_updated", 0) for s in summaries),
        sum(s.get("interfaces_created", 0) for s in summaries),
        sum(s.get("vlan_created_count", 0) for s in summaries),
        sum(s.get("trunk_interfaces_updated_count", 0) for s in summaries),
        sum(s.get("prefixes_created_count", 0) for s in summaries),
        sum(s.get("prefixes_moved_site_count", 0) for s in summaries),
    )

    print(json.dumps(summaries, indent=2))


if __name__ == "__main__":
    main()
