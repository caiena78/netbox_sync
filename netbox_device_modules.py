#!/usr/bin/env python3
"""
netbox_device_modules.py  v1.0.0
=================================
Sync hardware module inventory (linecards, supervisors, power supplies) from
Cisco devices into NetBox using live ``show inventory`` output.

Supported platforms
-------------------
  Catalyst 4500 / 4510         (IOS / IOS-XE)
  Catalyst 3750 / 3850 stacks  (IOS / IOS-XE)
  Catalyst 9000 series         (IOS-XE)
  Cisco Nexus 5k / 7k / 9k    (NX-OS)

Workflow per device
-------------------
1. Connect via CiscoDeviceClient (SSH/CLI).
2. Run ``show inventory`` (+ ``show module`` on NX-OS for slot confirmation).
3. Parse every block into (NAME, DESCR, PID, VID, SN).
4. Classify each block: CHASSIS | SUPERVISOR | LINECARD | PSU | FAN | TRANSCEIVER.
5. Map each module to a NetBox module bay based on platform slot conventions.
6. For VC/stack devices, route modules to the correct member device.
7. Before inserting a module, delete any interfaces in NetBox that belong
   to that slot (they will be recreated by sync_netbox_interfaces.py).
8. Upsert the module (create or update serial / description).
9. Upsert power supplies as dcim.inventory_items.
10. Log every missing module type / PSU type and continue.

Environment variables  (per README.md)
---------------------------------------
  NETBOX_URL           NetBox base URL
  NETBOX_API           NetBox API token
  CISCO_SRV_ACCOUNT    SSH username
  CISCO_SRV_PWD        SSH password
  CISCO_ENABLE_PWD     Enable secret (optional)

Usage
-----
  # Single device (VC-aware)
  python netbox_device_modules.py --device core-sw-01

  # Multiple devices
  python netbox_device_modules.py --devices core-sw-01,core-sw-02

  # All devices in a site
  python netbox_device_modules.py --site-slug dc1 --dry-run

  # NetBox filter (JSON)
  python netbox_device_modules.py --device-filter '{"site": "dc1", "role": "distribution"}'

  # Legacy shorthand (equivalent to --device-filter)
  python netbox_device_modules.py --site dc1 --role distribution --limit 10
"""

from __future__ import annotations

import argparse
import json
import logging
import logging.handlers
import os
import re
import sys
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

import pynetbox

from cisco_device_client import CiscoDeviceClient, CiscoDeviceClientError
from netbox_client import NetBoxClient, NetBoxClientError
from sync_netbox_interfaces import (
    build_vc_member_map,
    classify_device_model,
    expand_interface_name,
    get_device_mgmt_ip,
    get_device_os_type,
    resolve_device_list,
    _MODEL_FAMILY_C3750,
    _MODEL_FAMILY_C9K,
    _MODEL_FAMILY_C9600,
    _MODEL_FAMILY_GENERIC,
)

__version__ = "1.0.0"
_TOOL = "netbox_device_modules.py"

log     = logging.getLogger("device_modules")
err_log = logging.getLogger("device_modules_errors")

# --------------------------------------------------------------------------- #
# Platform family constants                                                    #
# --------------------------------------------------------------------------- #

_FAM_C4500   = "c4500"    # Catalyst 4500 / 4510 — modular chassis
_FAM_C3750   = "c3750"    # Catalyst 3750 stack
_FAM_C3850   = "c3850"    # Catalyst 3850 / 9300 stack
_FAM_C9K     = "c9k"      # Catalyst 9200/9300/9400/9500 stack (IOS-XE)
_FAM_C9600   = "c9600"    # Catalyst 9600 — modular chassis
_FAM_NEXUS   = "nexus"    # NX-OS (Nexus any)
_FAM_GENERIC = "generic"

# --------------------------------------------------------------------------- #
# Component-type constants                                                     #
# --------------------------------------------------------------------------- #

_KIND_CHASSIS     = "chassis"
_KIND_SUPERVISOR  = "supervisor"
_KIND_LINECARD    = "linecard"
_KIND_PSU         = "power-supply"
_KIND_FAN         = "fan"
_KIND_TRANSCEIVER = "transceiver"
_KIND_UNKNOWN     = "unknown"

# --------------------------------------------------------------------------- #
# Classification keyword tables                                                #
# --------------------------------------------------------------------------- #

_CHASSIS_KW     = ("chassis", "backplane", "base chassis", "c4510", "c4507", "c4506",
                   "c4503", "c4500", "nexus7000", "nexus 7000", "nexus9000",
                   "n7k-c70", "n9k-c90", "ws-c45")
_SUPERVISOR_KW  = ("supervisor", "sup ", "sup-", "supervisor-engine",
                   "sup7", "sup8", "sup6", "sup4", "vs-s2", "n7k-sup",
                   "n9k-sup", "c9600-sup")
_PSU_KW         = ("power supply", "power-supply", "power module",
                   "pwr", "ac power", "dc power", "psu", "c3kx-pwr",
                   "c9k-pwr", "n7k-ac", "n7k-dc", "n5k-pac", "n9k-pac",
                   "ws-c45-pwr")
_FAN_KW         = ("fan tray", "fan module", "cooling module", "fan assembly",
                   "ws-x4582", "ws-c4500-fan", "n7k-c7010-fan", "c9k-fan")
_TRANSCEIVER_KW = ("sfp", "qsfp", "gbic", "transceiver", "xcvr", "dwdm",
                   "x2 ", "xenpak")

# --------------------------------------------------------------------------- #
# Interface-slot regex per platform family                                     #
# --------------------------------------------------------------------------- #
# Each regex captures (member_or_module, slot_or_none) for matching.
# Groups: group(1) = primary number (member/slot), group(2) = secondary (slot for stacks)

_SLOT_IFACE_RE: Dict[str, re.Pattern] = {
    # C4500: GigabitEthernetX/Y  TenGigabitEthernetX/Y  X=slot
    _FAM_C4500: re.compile(
        r"^(?:GigabitEthernet|TenGigabitEthernet|FastEthernet|"
        r"TwentyFiveGigE|HundredGigE|FortyGigabitEthernet)"
        r"(\d+)/\d+$",
        re.IGNORECASE,
    ),
    # C9600: same as C4500 — TenGigabitEthernetX/Y/Z, X=slot
    _FAM_C9600: re.compile(
        r"^(?:GigabitEthernet|TenGigabitEthernet|TwentyFiveGigE|"
        r"HundredGigE|FortyGigabitEthernet)"
        r"(\d+)/\d+(?:/\d+)?$",
        re.IGNORECASE,
    ),
    # C3750/C3850/C9K stack: GigabitEthernetM/S/P  M=member, S=slot
    _FAM_C3750: re.compile(
        r"^(?:GigabitEthernet|TenGigabitEthernet|FastEthernet|"
        r"TwentyFiveGigE|HundredGigE|AppGigabitEthernet)"
        r"(\d+)/(\d+)/\d+$",
        re.IGNORECASE,
    ),
    _FAM_C3850: re.compile(
        r"^(?:GigabitEthernet|TenGigabitEthernet|TwentyFiveGigE|"
        r"HundredGigE|AppGigabitEthernet)"
        r"(\d+)/(\d+)/\d+$",
        re.IGNORECASE,
    ),
    _FAM_C9K: re.compile(
        r"^(?:GigabitEthernet|TenGigabitEthernet|TwentyFiveGigE|"
        r"HundredGigE|AppGigabitEthernet|FortyGigabitEthernet)"
        r"(\d+)/(\d+)/\d+$",
        re.IGNORECASE,
    ),
    # NX-OS: EthernetX/Y  X=module
    _FAM_NEXUS: re.compile(
        r"^Ethernet(\d+)/\d+$",
        re.IGNORECASE,
    ),
}

# --------------------------------------------------------------------------- #
# Data structures                                                              #
# --------------------------------------------------------------------------- #

@dataclass
class InventoryEntry:
    """One parsed block from ``show inventory``."""
    raw_name:   str
    descr:      str
    pid:        str
    vid:        str
    serial:     str
    kind:       str = _KIND_UNKNOWN
    # Slot-mapping results (filled by map_component_to_slot)
    switch_num: Optional[int] = None   # stack/VC member number
    slot_num:   Optional[int] = None   # slot / module number within device
    bay_name:   Optional[str] = None   # target NetBox module-bay name

    def label(self) -> str:
        return f"NAME={self.raw_name!r} PID={self.pid} SN={self.serial}"


@dataclass
class SyncResult:
    device_name:          str
    device_mgmt_ip:       str = ""
    modules_added:        int = 0
    modules_updated:      int = 0
    modules_skipped:      int = 0
    psus_added:           int = 0
    psus_updated:         int = 0
    missing_module_types: List[str] = field(default_factory=list)
    missing_psu_types:    List[str] = field(default_factory=list)
    errors:               List[str] = field(default_factory=list)


# --------------------------------------------------------------------------- #
# show inventory parser                                                        #
# --------------------------------------------------------------------------- #

_INV_NAME_RE = re.compile(
    r'NAME:\s*"([^"]*)"[^,\n]*,\s*DESCR:\s*"([^"]*)"',
    re.IGNORECASE,
)
_INV_PID_RE = re.compile(
    r"PID:\s*([^\s,]*)\s*,\s*VID:\s*([^\s,]*)\s*,\s*SN:\s*([^\s,]*)",
    re.IGNORECASE,
)


def parse_inventory_blocks(raw: str) -> List[InventoryEntry]:
    """
    Parse raw ``show inventory`` text into a list of InventoryEntry objects.

    Handles IOS, IOS-XE, and NX-OS formats.  NAME/DESCR and PID/VID/SN lines
    are matched as pairs; up to three intervening lines are tolerated.
    Entries with a blank PID are retained (classified _KIND_UNKNOWN later).
    """
    entries: List[InventoryEntry] = []
    lines = raw.splitlines()
    i = 0
    while i < len(lines):
        name_m = _INV_NAME_RE.search(lines[i])
        if name_m:
            raw_name = name_m.group(1).strip()
            descr    = name_m.group(2).strip()
            pid = vid = serial = ""
            # Search up to 4 lines ahead for the PID line
            for j in range(i + 1, min(i + 5, len(lines))):
                pid_m = _INV_PID_RE.search(lines[j])
                if pid_m:
                    pid    = pid_m.group(1).strip()
                    vid    = pid_m.group(2).strip()
                    serial = pid_m.group(3).strip()
                    i = j
                    break
            entries.append(InventoryEntry(
                raw_name=raw_name,
                descr=descr,
                pid=pid,
                vid=vid,
                serial=serial,
            ))
        i += 1
    return entries


# --------------------------------------------------------------------------- #
# NX-OS show module parser (slot confirmation)                                 #
# --------------------------------------------------------------------------- #

# show module NX-OS line: "1    0    Supervisor...    N7K-SUP1    active *"
_NXOS_MOD_RE = re.compile(
    r"^\s*(\d+)\s+\d+\s+\S.*?\s+((?:N\d[EK]-|N\d+-|DS-)\S+)\s+\w",
    re.IGNORECASE | re.MULTILINE,
)


def parse_show_module_nxos(raw: str) -> Dict[int, str]:
    """
    Return ``{slot_number: pid}`` from NX-OS ``show module`` output.
    Used to confirm the slot-number → PID mapping when inventory NAME is ambiguous.
    """
    result: Dict[int, str] = {}
    for m in _NXOS_MOD_RE.finditer(raw):
        slot = int(m.group(1))
        pid  = m.group(2).strip()
        result[slot] = pid
    return result


# --------------------------------------------------------------------------- #
# Component classification                                                     #
# --------------------------------------------------------------------------- #

def classify_component(entry: InventoryEntry) -> str:
    """
    Classify an InventoryEntry by its NAME and DESCR.

    Priority: CHASSIS > SUPERVISOR > PSU > FAN > TRANSCEIVER > LINECARD > UNKNOWN
    Returns one of the _KIND_* constants.
    """
    combined  = (entry.raw_name + " " + entry.descr).lower()
    pid_lower = entry.pid.lower()

    def _any(keywords: tuple) -> bool:
        return any(k in combined for k in keywords)

    if _any(_CHASSIS_KW):
        return _KIND_CHASSIS
    if _any(_SUPERVISOR_KW):
        return _KIND_SUPERVISOR
    if _any(_PSU_KW):
        return _KIND_PSU
    if _any(_FAN_KW):
        return _KIND_FAN
    if _any(_TRANSCEIVER_KW):
        return _KIND_TRANSCEIVER

    # Linecard detection via DESCR keywords or PID prefix patterns
    lc_kw = ("linecard", "line card", "ethernet module", "port adapter",
              "slot ", "uplink module", "network module", "service module")
    if _any(lc_kw):
        return _KIND_LINECARD

    lc_pid = (
        r"^ws-x\d",            # C4500 blades: WS-X4648-..., WS-X45-...
        r"^n[57]k-[mf]",       # Nexus linecards: N7K-F248, N5K-M160
        r"^n9k-lc",            # Nexus 9k linecards
        r"^c3850-nm",          # 3850 uplink modules
        r"^c9[0-9]+-lc",       # C9k linecards
        r"^c9600-lc",          # C9600 linecards
    )
    if any(re.search(p, pid_lower) for p in lc_pid):
        return _KIND_LINECARD

    return _KIND_UNKNOWN


# --------------------------------------------------------------------------- #
# Platform family detection                                                    #
# --------------------------------------------------------------------------- #

def determine_platform_family(model_string: str, os_type: str) -> str:
    """
    Map a NetBox ``device_type.model`` + ``os_type`` string to a platform family slug.

    Resolution order
    ----------------
    1. NX-OS   → _FAM_NEXUS  (regardless of model)
    2. C4500   family patterns
    3. C9600   family patterns
    4. C3850 / C9K stacked IOS-XE
    5. C3750   family patterns
    6. Fallback to _FAM_GENERIC
    """
    if os_type == "nxos":
        return _FAM_NEXUS

    m = (model_string or "").upper()

    if re.search(r"C4510|C4507|C4506|C4503|C4500|WS-C45\d\d|CATALYST[\s-]*45\d\d", m):
        return _FAM_C4500

    if re.search(r"C9606|C9610|C9616|C96\d\d|CATALYST[\s-]*96\d\d", m):
        return _FAM_C9600

    # "Catalyst 3850-48U" style names (NetBox device-type model field) must
    # match here; the bare "C3850" pattern does not match them.
    if re.search(r"C3850|WS-C3850|CATALYST[\s-]*3850|C9300|C9200|CATALYST[\s-]*9[23]00", m):
        return _FAM_C3850

    if re.search(r"C9[45]\d\d|C9500|C9400|CATALYST[\s-]*9[45]\d\d", m):
        return _FAM_C9K

    # classify_device_model already handles C3750 / C9K patterns
    base_family = classify_device_model(model_string)
    if base_family == _MODEL_FAMILY_C3750:
        return _FAM_C3750
    if base_family in (_MODEL_FAMILY_C9K, _MODEL_FAMILY_C9600):
        return _FAM_C9K

    return _FAM_GENERIC


# --------------------------------------------------------------------------- #
# Slot / bay mapping                                                           #
# --------------------------------------------------------------------------- #

# Regexes to extract numbers from inventory NAME fields
_SLOT_IN_NAME_RE   = re.compile(r"\bslot\s*(\d+)\b",    re.IGNORECASE)
_MODULE_IN_NAME_RE = re.compile(r"\bmodule\s*(\d+)\b",   re.IGNORECASE)
_MEMBER_IN_NAME_RE = re.compile(r"\bmember\s*(\d+)\b",   re.IGNORECASE)

# Matches the identifier suffix of a PSU name: "Power Supply A", "PSU-2", etc.
_PSU_LABEL_RE = re.compile(
    r"\b(?:power[\s\-]*supply|psu|ps)[\s\-]*([A-Za-z0-9]+)\s*$",
    re.IGNORECASE,
)

# Explicit "Switch N" extractor — used for VC member routing.
# Defined here so both map_component_to_slot and _sync_module share the same pattern.
_SWITCH_NUM_RE = re.compile(r"\bSwitch\s+(\d+)\b", re.IGNORECASE)


def _extract_switch_num(raw_name: str) -> Optional[int]:
    """
    Return the stack member number embedded in an inventory NAME field.

    Matches "Switch N" first, then "Member N" as a fallback.
    Returns None when no match is found (caller should default to member 1).

    Examples
    --------
    "Switch 5 - Power Supply A"  → 5
    "Switch 3 FRU Uplink Module 1" → 3
    "Switch 1 FRU Uplink Module 1" → 1
    """
    m = _SWITCH_NUM_RE.search(raw_name)
    if m:
        return int(m.group(1))
    m = _MEMBER_IN_NAME_RE.search(raw_name)
    if m:
        return int(m.group(1))
    return None


def _derive_psu_bay_name(raw_name: str) -> str:
    """
    Return a normalised PSU module-bay name from a raw inventory NAME.

    The convention is ``"PS-<identifier>"`` where the identifier is the
    letter or number that distinguishes redundant power supplies on the
    same device.

    Examples
    --------
    ``"Switch 1 - Power Supply A"``  → ``"PS-A"``
    ``"Switch 2 Power Supply B"``    → ``"PS-B"``
    ``"WS-C4510R+E Power Supply A"`` → ``"PS-A"``
    ``"Power Supply 1"``             → ``"PS-1"``
    ``"Power Supply 2"``             → ``"PS-2"``
    ``"N7K-C7010 Power Supply 1"``   → ``"PS-1"``
    """
    m = _PSU_LABEL_RE.search(raw_name)
    if m:
        return f"PS-{m.group(1).upper()}"
    # Last-resort: trailing single letter or digit after a separator
    m2 = re.search(r"[- ]([A-Za-z0-9])\s*$", raw_name.strip())
    if m2:
        return f"PS-{m2.group(1).upper()}"
    return "PS-A"


def map_component_to_slot(
    entry: InventoryEntry,
    family: str,
) -> InventoryEntry:
    """
    Fill ``entry.switch_num``, ``entry.slot_num``, and ``entry.bay_name``
    based on the inventory NAME field and platform family.

    Modifies *entry* in-place and returns it.

    Bay-name conventions
    --------------------
    PSUs (all platforms)
        Always ``"PS-A"``, ``"PS-B"``, ``"PS-1"``, ``"PS-2"`` — a
        ``dcim.module_bay`` is created on the target device (or VC member)
        with this name and a ``dcim.module`` is installed in it.

    C4500 / C9600
        ``"Slot 1"``, ``"Slot 2"``, …  Supervisor without an explicit slot
        number uses ``"Supervisor"``.

    C3750 / C3850 / C9K stacks (VC members)
        Network/uplink modules: ``"Network Module"`` on the target VC member.
        PSUs: ``"PS-A"`` / ``"PS-B"`` on the target VC member.
        The member is identified by the switch number in the inventory NAME.

    NX-OS
        ``"Module 1"``, ``"Module 2"``, …
    """
    name = entry.raw_name

    # ── Power supplies: uniform "PS-X" bay name across all platforms ──────
    # PSU bays are created directly under the target device (or VC member).
    # This is done before platform-specific handling so the PSU path is
    # identical regardless of which device family is being processed.
    if entry.kind == _KIND_PSU:
        entry.bay_name = _derive_psu_bay_name(name)
        # Always parse "Switch N" / "Member N" so the correct VC member is
        # targeted even when family detection falls back to _FAM_GENERIC.
        entry.switch_num = _extract_switch_num(name)
        return entry

    # ── Module-slot mapping (non-PSU components) ───────────────────────────

    # Matches "Slot N", "FRU Uplink Module", "Network Module", "Uplink Module"
    # keywords that indicate a physical module slot.
    _has_module_slot = bool(re.search(
        r"\bslot\b"
        r"|\buplink[\s\-]*module\b"
        r"|\bnetwork[\s\-]*module\b"
        r"|\bfru\b",
        name, re.IGNORECASE,
    ))

    if family in (_FAM_C4500, _FAM_C9600):
        m = _SLOT_IN_NAME_RE.search(name)
        if m:
            entry.slot_num = int(m.group(1))
            entry.bay_name = f"Slot {entry.slot_num}"
        elif entry.kind == _KIND_SUPERVISOR:
            entry.bay_name = "Supervisor"

    elif family in (_FAM_C3750, _FAM_C3850, _FAM_C9K):
        slot_m = _SLOT_IN_NAME_RE.search(name)
        entry.switch_num = _extract_switch_num(name)
        if slot_m:
            entry.slot_num = int(slot_m.group(1))
        elif _has_module_slot:
            # "Switch 1 FRU Uplink Module 1" — extract trailing digit as slot
            trailing = re.search(r"\b(\d+)\s*$", name)
            if trailing:
                entry.slot_num = int(trailing.group(1))

        if entry.switch_num is not None and (entry.slot_num is not None or _has_module_slot):
            # Linecards, supervisors, uplink modules → "Network Module" bay
            entry.bay_name = "Network Module"
        # else: bare chassis row for this member — no module bay

    elif family == _FAM_NEXUS:
        mod_m = _MODULE_IN_NAME_RE.search(name)
        if mod_m:
            entry.slot_num = int(mod_m.group(1))
            entry.bay_name = f"Module {entry.slot_num}"
        # Some NX-OS supervisors show as "Supervisor Module-1"
        if entry.kind == _KIND_SUPERVISOR and entry.slot_num is None:
            digits = re.findall(r"\d+", name)
            if digits:
                entry.slot_num = int(digits[-1])
                entry.bay_name = f"Module {entry.slot_num}"

    return entry


# --------------------------------------------------------------------------- #
# Interface-to-slot matching                                                   #
# --------------------------------------------------------------------------- #

def interface_belongs_to_slot(
    iface_name: str,
    family: str,
    slot_num: Optional[int],
    switch_num: Optional[int] = None,
) -> bool:
    """
    Return True when *iface_name* belongs to the specified slot and (for
    stacks) switch member.

    Interfaces on port-channels, SVIs, loopbacks, tunnels, etc. are never
    considered to belong to a physical slot and always return False.
    """
    if slot_num is None and switch_num is None:
        return False

    expanded = expand_interface_name(iface_name)

    # Logical interfaces never belong to a physical slot
    if re.match(
        r"^(Loopback|Port-channel|Vlan|Tunnel|Management|mgmt|BDI|nve)",
        expanded, re.IGNORECASE,
    ):
        return False

    pattern = _SLOT_IFACE_RE.get(family)
    if pattern is None:
        return False

    m = pattern.match(expanded)
    if not m:
        return False

    if family in (_FAM_C4500, _FAM_C9600, _FAM_NEXUS):
        # Single number captures the slot/module
        return int(m.group(1)) == slot_num

    # Stack families: group(1)=member, group(2)=slot
    member = int(m.group(1))
    slot   = int(m.group(2))

    if switch_num is not None and member != switch_num:
        return False
    if slot_num is not None and slot != slot_num:
        return False
    return True


# --------------------------------------------------------------------------- #
# NetBoxModuleAPI — thin wrapper for module/inventory-item pynetbox calls     #
# --------------------------------------------------------------------------- #

class NetBoxModuleAPI:
    """
    Module-bay, installed-module, and inventory-item helpers.

    Uses ``nb.nb`` (raw pynetbox) for the DCIM module endpoints that are not
    yet exposed as high-level NetBoxClient methods.
    """

    def __init__(self, nb: NetBoxClient) -> None:
        self._nb  = nb
        self._api = nb.nb
        # Caches keyed on (device_id,) or model string
        self._bay_cache:    Dict[int, List[dict]]     = {}
        self._mtype_cache:  Dict[str, Optional[dict]] = {}
        self._role_cache:   Dict[str, Optional[dict]] = {}
        self._mfr_cache:    Dict[str, Optional[dict]] = {}

    # ── Module-bay helpers ────────────────────────────────────────────────

    def get_module_bays(self, device_id: int) -> List[dict]:
        """Return all module bays for *device_id* (cached per run)."""
        if device_id not in self._bay_cache:
            try:
                recs = list(self._api.dcim.module_bays.filter(device_id=device_id))
                self._bay_cache[device_id] = [self._nb._to_dict(r) for r in recs]
            except pynetbox.RequestError as exc:
                raise NetBoxClientError(
                    f"get_module_bays(device_id={device_id}): {exc}"
                ) from exc
        return self._bay_cache[device_id]

    def invalidate_bay_cache(self, device_id: int) -> None:
        self._bay_cache.pop(device_id, None)

    def find_module_bay(
        self,
        device_id: int,
        bay_name: str,
        position: Optional[int] = None,
    ) -> Optional[dict]:
        """
        Return the bay matching *bay_name* on *device_id*.

        When *position* is supplied an exact name+position match is
        preferred.  Falls back to a name-only match so bays that were
        created without a position value are still located.  Returns None
        when no name match exists at all.
        """
        name_only: Optional[dict] = None
        for bay in self.get_module_bays(device_id):
            if (bay.get("name") or "").strip().lower() != bay_name.strip().lower():
                continue
            if position is None:
                return bay
            # position may be stored as int or str depending on NetBox version
            try:
                if int(bay.get("position")) == int(position):
                    return bay
            except (TypeError, ValueError):
                pass
            if name_only is None:
                name_only = bay

        if name_only is not None and position is not None:
            log.debug(
                "find_module_bay: no position=%s match for %r on device_id=%s "
                "(bay found with position=%s) — using name-only match",
                position, bay_name, device_id, name_only.get("position"),
            )
        return name_only

    def ensure_module_bay(
        self,
        device_id: int,
        name: str,
        position: Optional[int] = None,
    ) -> dict:
        """
        Return an existing module bay or create a new one.

        Returns dict with ``_action``: ``"existing"`` or ``"created"``.
        """
        existing = self.find_module_bay(device_id, name, position=position)
        if existing:
            existing["_action"] = "existing"
            return existing
        payload: dict = {"device": device_id, "name": name, "label": name}
        if position is not None:
            payload["position"] = position
        try:
            rec = self._api.dcim.module_bays.create(payload)
            d   = self._nb._to_dict(rec)
            d["_action"] = "created"
            self.invalidate_bay_cache(device_id)
            return d
        except pynetbox.RequestError as exc:
            raise NetBoxClientError(
                f"ensure_module_bay(device={device_id}, name={name!r}): {exc}"
            ) from exc

    # ── Module-type lookup ────────────────────────────────────────────────

    def get_module_type_by_model(self, model: str) -> Optional[dict]:
        """
        Look up a NetBox module type by ``model`` (PID).  Cached per run.
        Returns None when not found — caller must log and continue.
        """
        key = model.upper()
        if key not in self._mtype_cache:
            try:
                recs = list(self._api.dcim.module_types.filter(model=model))
                self._mtype_cache[key] = (
                    self._nb._to_dict(recs[0]) if recs else None
                )
            except pynetbox.RequestError as exc:
                log.debug("module_type lookup failed for %r: %s", model, exc)
                self._mtype_cache[key] = None
        return self._mtype_cache.get(key)

    def ensure_module_type(
        self,
        model: str,
        description: str = "",
    ) -> Optional[dict]:
        """
        Return the NetBox module type for *model*, auto-creating it when absent.

        Manufacturer is resolved (or auto-created) as ``Cisco``.  The PID
        is used as both ``model`` and ``part_number``.  Returns None only
        when the Cisco manufacturer cannot be resolved and the create call
        fails — callers should then log and skip the entry.
        """
        existing = self.get_module_type_by_model(model)
        if existing is not None:
            return existing

        mfr_id = self.get_manufacturer_id("Cisco")
        if mfr_id is None:
            log.warning(
                "ensure_module_type: Cisco manufacturer not found — "
                "cannot auto-create module type %r",
                model,
            )
            return None

        payload: dict = {
            "manufacturer": mfr_id,
            "model":        model,
            "part_number":  model,
        }
        if description:
            payload["comments"] = description[:200]

        try:
            rec = self._api.dcim.module_types.create(payload)
            d   = self._nb._to_dict(rec)
            self._mtype_cache[model.upper()] = d
            log.info(
                "Module type AUTO-CREATED: model=%r  id=%s  mfr_id=%s",
                model, d.get("id"), mfr_id,
            )
            return d
        except pynetbox.RequestError as exc:
            # Race condition — another process may have just created it
            log.debug(
                "ensure_module_type: create conflict for %r (%s) — re-fetching",
                model, exc,
            )
            refetched = self.get_module_type_by_model(model)
            if refetched:
                return refetched
            log.warning(
                "ensure_module_type: cannot create or find module type %r: %s",
                model, exc,
            )
            return None

    # ── Installed-module helpers ──────────────────────────────────────────

    def get_module_by_bay(self, bay_id: int) -> Optional[dict]:
        """Return the module installed in *bay_id*, or None."""
        try:
            recs = list(self._api.dcim.modules.filter(module_bay_id=bay_id))
            return self._nb._to_dict(recs[0]) if recs else None
        except pynetbox.RequestError as exc:
            log.debug("get_module_by_bay(bay_id=%s): %s", bay_id, exc)
            return None

    def upsert_module(
        self,
        device_id: int,
        bay_id: int,
        module_type_id: int,
        serial: str,
        description: str,
    ) -> Tuple[dict, str]:
        """
        Idempotently install a module in a bay.

        Returns ``(module_dict, action)`` where action is
        ``"created"`` | ``"updated"`` | ``"skipped"``.
        """
        existing = self.get_module_by_bay(bay_id)

        if existing is None:
            payload = {
                "device":       device_id,
                "module_bay":   bay_id,
                "module_type":  module_type_id,
                "status":       "active",
            }
            if serial:
                payload["serial"] = serial
            if description:
                payload["description"] = description[:200]
            try:
                rec = self._api.dcim.modules.create(payload)
                return self._nb._to_dict(rec), "created"
            except pynetbox.RequestError as exc:
                raise NetBoxClientError(
                    f"create module bay_id={bay_id}: {exc}"
                ) from exc

        # Module exists — check whether anything differs
        ex_type_id = self._extract_id(existing.get("module_type"))
        ex_serial  = (existing.get("serial") or "").strip()
        ex_desc    = (existing.get("description") or "").strip()
        need_update = (
            ex_type_id != module_type_id
            or (serial and ex_serial != serial)
            or (description and ex_desc != description[:200])
        )
        if not need_update:
            return existing, "skipped"

        patch: dict = {"module_type": module_type_id}
        if serial:
            patch["serial"] = serial
        if description:
            patch["description"] = description[:200]
        try:
            mod_id  = existing.get("id")
            rec     = self._api.dcim.modules.get(mod_id)
            rec.update(patch)
            return self._nb._to_dict(rec), "updated"
        except pynetbox.RequestError as exc:
            raise NetBoxClientError(
                f"update module id={existing.get('id')}: {exc}"
            ) from exc

    def delete_module(self, module_id: int) -> None:
        """Delete a module by ID.  No-op if already gone."""
        try:
            rec = self._api.dcim.modules.get(module_id)
            if rec:
                rec.delete()
        except pynetbox.RequestError as exc:
            raise NetBoxClientError(
                f"delete_module(id={module_id}): {exc}"
            ) from exc

    # ── Inventory items (PSUs) ─────────────────────────────────────────────

    def get_inventory_items(self, device_id: int) -> List[dict]:
        """Return all inventory items for *device_id*."""
        try:
            recs = list(self._api.dcim.inventory_items.filter(device_id=device_id))
            return [self._nb._to_dict(r) for r in recs]
        except pynetbox.RequestError as exc:
            raise NetBoxClientError(
                f"get_inventory_items(device_id={device_id}): {exc}"
            ) from exc

    def upsert_inventory_item(
        self,
        device_id: int,
        name: str,
        part_id: str,
        serial: str,
        description: str,
        manufacturer_id: Optional[int] = None,
        role_id: Optional[int] = None,
    ) -> Tuple[dict, str]:
        """
        Idempotently create or update an inventory item (used for PSUs).

        Matching is done by ``device + name`` (case-insensitive).
        Returns ``(item_dict, action)``.
        """
        existing_items = self.get_inventory_items(device_id)
        existing = next(
            (i for i in existing_items
             if (i.get("name") or "").strip().lower() == name.strip().lower()),
            None,
        )

        payload: dict = {
            "device":      device_id,
            "name":        name,
            "part_id":     part_id,
            "description": description[:200] if description else "",
        }
        if serial:
            payload["serial"] = serial
        if manufacturer_id:
            payload["manufacturer"] = manufacturer_id
        if role_id:
            payload["role"] = role_id

        if existing is None:
            try:
                rec = self._api.dcim.inventory_items.create(payload)
                return self._nb._to_dict(rec), "created"
            except pynetbox.RequestError as exc:
                raise NetBoxClientError(
                    f"create inventory_item name={name!r} device={device_id}: {exc}"
                ) from exc

        # Update if serial or part_id changed
        ex_serial  = (existing.get("serial") or "").strip()
        ex_part_id = (existing.get("part_id") or "").strip()
        if (serial and ex_serial != serial) or (part_id and ex_part_id != part_id):
            patch: dict = {}
            if serial:
                patch["serial"]  = serial
            if part_id:
                patch["part_id"] = part_id
            try:
                rec = self._api.dcim.inventory_items.get(existing["id"])
                rec.update(patch)
                return self._nb._to_dict(rec), "updated"
            except pynetbox.RequestError as exc:
                raise NetBoxClientError(
                    f"update inventory_item id={existing['id']}: {exc}"
                ) from exc

        return existing, "skipped"

    # ── Inventory-item role lookup / ensure ───────────────────────────────

    def ensure_inventory_item_role(self, slug: str, name: str) -> Optional[int]:
        """
        Return the ID of an inventory item role by slug, creating it if absent.
        Returns None on failure (caller continues without a role).
        """
        if slug in self._role_cache:
            return self._role_cache[slug]
        try:
            recs = list(self._api.dcim.inventory_item_roles.filter(slug=slug))
            if recs:
                self._role_cache[slug] = int(recs[0].id)
                return self._role_cache[slug]
            rec = self._api.dcim.inventory_item_roles.create(
                {"name": name, "slug": slug, "color": "0097a7"}
            )
            self._role_cache[slug] = int(rec.id)
            return self._role_cache[slug]
        except Exception as exc:
            log.debug("inventory_item_role ensure failed slug=%r: %s", slug, exc)
            self._role_cache[slug] = None
            return None

    # ── Manufacturer lookup ───────────────────────────────────────────────

    def get_manufacturer_id(self, name: str) -> Optional[int]:
        """Return the NetBox manufacturer ID for *name*, or None."""
        key = name.lower()
        if key not in self._mfr_cache:
            try:
                mfr = self._nb.ensure_manufacturer(name)
                self._mfr_cache[key] = mfr.get("id")
            except Exception as exc:
                log.debug("manufacturer lookup failed name=%r: %s", name, exc)
                self._mfr_cache[key] = None
        return self._mfr_cache.get(key)

    # ── Port-conflict helpers ─────────────────────────────────────────────

    @staticmethod
    def _is_port_connected(port: Any) -> bool:
        """Return True if *port* has any cable / endpoint / link-peer attachment."""
        return any([
            getattr(port, "cable",              None),
            getattr(port, "connected_endpoint", None),
            getattr(port, "link_peers",         None),
            getattr(port, "link_peers_type",    None),
        ])

    def get_power_port_template_names(self, module_type_id: int) -> List[str]:
        """Return power port template names for *module_type_id* (empty list on failure)."""
        try:
            templates = list(
                self._api.dcim.power_port_templates.filter(module_type_id=module_type_id)
            )
            return [t.name for t in templates]
        except pynetbox.RequestError as exc:
            log.debug(
                "power_port_templates lookup failed module_type_id=%s: %s",
                module_type_id, exc,
            )
            return []

    def get_console_port_template_names(self, module_type_id: int) -> List[str]:
        """Return console port template names for *module_type_id* (empty list on failure)."""
        try:
            templates = list(
                self._api.dcim.console_port_templates.filter(module_type_id=module_type_id)
            )
            return [t.name for t in templates]
        except pynetbox.RequestError as exc:
            log.debug(
                "console_port_templates lookup failed module_type_id=%s: %s",
                module_type_id, exc,
            )
            return []

    def ensure_unconnected_power_port_removed(
        self,
        device_id: int,
        port_name: str,
        dry_run: bool,
        device_name: str = "",
    ) -> bool:
        """
        Delete an unconnected power port named *port_name* on *device_id*.

        Returns True if a port was deleted (or would-delete in dry-run).
        Connected ports are never touched.  All exceptions are logged; the
        caller continues regardless.
        """
        try:
            ports = list(self._api.dcim.power_ports.filter(
                device_id=device_id, name=port_name
            ))
        except pynetbox.RequestError as exc:
            log.warning(
                "%s  Cannot query power ports (name=%r device_id=%s): %s",
                device_name, port_name, device_id, exc,
            )
            return False

        deleted = False
        for port in ports:
            if self._is_port_connected(port):
                log.info(
                    "%s  PRESERVE power port %r (device_id=%s, port_id=%s)"
                    " — connected, skipping delete",
                    device_name, port_name, device_id, port.id,
                )
                continue
            if dry_run:
                log.info(
                    "%s  [DRY-RUN] would DELETE power port %r"
                    " (device_id=%s, port_id=%s) — unconnected",
                    device_name, port_name, device_id, port.id,
                )
                deleted = True
                continue
            try:
                port.delete()
                log.info(
                    "%s  DELETED power port %r (device_id=%s, port_id=%s)"
                    " — unconnected, clearing conflict before PSU install",
                    device_name, port_name, device_id, port.id,
                )
                deleted = True
            except pynetbox.RequestError as exc:
                log.warning(
                    "%s  Failed to delete power port %r"
                    " (device_id=%s, port_id=%s): %s",
                    device_name, port_name, device_id, port.id, exc,
                )
        return deleted

    def ensure_unconnected_console_port_removed(
        self,
        device_id: int,
        port_name: str,
        dry_run: bool,
        device_name: str = "",
    ) -> bool:
        """
        Delete an unconnected console port named *port_name* on *device_id*.

        Returns True if a port was deleted (or would-delete in dry-run).
        Connected ports are never touched.  All exceptions are logged; the
        caller continues regardless.
        """
        try:
            ports = list(self._api.dcim.console_ports.filter(
                device_id=device_id, name=port_name
            ))
        except pynetbox.RequestError as exc:
            log.warning(
                "%s  Cannot query console ports (name=%r device_id=%s): %s",
                device_name, port_name, device_id, exc,
            )
            return False

        deleted = False
        for port in ports:
            if self._is_port_connected(port):
                log.info(
                    "%s  PRESERVE console port %r (device_id=%s, port_id=%s)"
                    " — connected, skipping delete",
                    device_name, port_name, device_id, port.id,
                )
                continue
            if dry_run:
                log.info(
                    "%s  [DRY-RUN] would DELETE console port %r"
                    " (device_id=%s, port_id=%s) — unconnected",
                    device_name, port_name, device_id, port.id,
                )
                deleted = True
                continue
            try:
                port.delete()
                log.info(
                    "%s  DELETED console port %r (device_id=%s, port_id=%s)"
                    " — unconnected, clearing conflict before module install",
                    device_name, port_name, device_id, port.id,
                )
                deleted = True
            except pynetbox.RequestError as exc:
                log.warning(
                    "%s  Failed to delete console port %r"
                    " (device_id=%s, port_id=%s): %s",
                    device_name, port_name, device_id, port.id, exc,
                )
        return deleted

    # ── Utility ───────────────────────────────────────────────────────────

    @staticmethod
    def _extract_id(obj: Any) -> Optional[int]:
        if obj is None:
            return None
        if isinstance(obj, int):
            return obj
        if isinstance(obj, dict):
            v = obj.get("id")
            return int(v) if v is not None else None
        v = getattr(obj, "id", None)
        return int(v) if v is not None else None


# --------------------------------------------------------------------------- #
# Interface deletion for a slot                                                #
# --------------------------------------------------------------------------- #

def delete_interfaces_for_slot(
    nb: NetBoxClient,
    device_id: int,
    family: str,
    slot_num: Optional[int],
    switch_num: Optional[int],
    dry_run: bool,
) -> Tuple[int, List[str]]:
    """
    Delete unbound (module=null) NetBox interfaces on *device_id* that belong
    to the given slot.

    Only interfaces with no module association are removed.  Interfaces that
    are already bound to an installed module are left alone — NetBox cascade-
    deletes them automatically when their owning module is deleted.

    This targeted deletion avoids removing interfaces that belong to other
    modules sharing the same device, and only clears the stale free records
    that would cause a unique-constraint 500 error on module installation.

    Returns ``(deleted_count, list_of_errors)``.
    """
    deleted = 0
    errors: List[str] = []

    try:
        ifaces = nb.get_interfaces(device_id=device_id)
    except NetBoxClientError as exc:
        return 0, [f"Cannot fetch interfaces for device_id={device_id}: {exc}"]

    targets = [
        iface for iface in ifaces
        if interface_belongs_to_slot(
            iface.get("name", ""),
            family,
            slot_num,
            switch_num,
        )
        and not iface.get("module")   # skip interfaces already bound to a module
    ]

    if not targets:
        log.debug(
            "delete_interfaces_for_slot: no interfaces match "
            "device_id=%s slot=%s member=%s",
            device_id, slot_num, switch_num,
        )
        return 0, []

    log.info(
        "%s  slot %s  — deleting %d unbound interface(s) before module insert",
        "DRY-RUN" if dry_run else "LIVE",
        slot_num, len(targets),
    )

    for iface in targets:
        iface_id   = iface.get("id")
        iface_name = iface.get("name", "?")
        print(
            f"  {'[DRY-RUN] ' if dry_run else ''}DELETE interface "
            f"{iface_name} (dev_id={device_id})",
            flush=True,
        )
        if dry_run:
            deleted += 1
            continue
        try:
            nb.delete_interface(iface_id)
            deleted += 1
        except NetBoxClientError as exc:
            msg = f"Failed to delete interface {iface_name!r} (id={iface_id}): {exc}"
            log.warning(msg)
            errors.append(msg)

    return deleted, errors


# --------------------------------------------------------------------------- #
# Per-device inventory collection                                              #
# --------------------------------------------------------------------------- #

def get_inventory_raw(cisco: CiscoDeviceClient) -> str:
    """Run ``show inventory`` and return raw output."""
    raw, _, _ = cisco._cli_run_command("show inventory", parse=False)
    return raw or ""


def get_show_module_raw(cisco: CiscoDeviceClient) -> str:
    """Run ``show module`` (NX-OS) and return raw output; empty on failure."""
    try:
        raw, _, _ = cisco._cli_run_command("show module", parse=False)
        return raw or ""
    except CiscoDeviceClientError:
        return ""


# --------------------------------------------------------------------------- #
# Core per-device sync                                                         #
# --------------------------------------------------------------------------- #

def sync_device_modules(
    device: dict,
    nb: NetBoxClient,
    module_api: NetBoxModuleAPI,
    dry_run: bool,
    include_transceivers: bool = False,
    username: str = "",
    password: str = "",
    enable_secret: str = "",
    timeout: int = 30,
    force: bool = False,
) -> SyncResult:
    """
    Full module sync for one device.

    Parameters
    ----------
    device : dict
        NetBox device dict (may include ``_vc_id`` when resolved from VC).
    nb : NetBoxClient
    module_api : NetBoxModuleAPI
    dry_run : bool
    include_transceivers : bool
        When False (default) transceivers are logged but not synced.

    Returns
    -------
    SyncResult
    """
    device_name   = device.get("name", "unknown")
    device_id     = device.get("id")
    mgmt_ip       = get_device_mgmt_ip(device)
    os_type       = get_device_os_type(device)

    result = SyncResult(device_name=device_name, device_mgmt_ip=mgmt_ip or "")

    print(f"\n{'='*60}", flush=True)
    print(f"  Device: {device_name}  IP: {mgmt_ip}  OS: {os_type}", flush=True)
    print(f"{'='*60}", flush=True)

    if not mgmt_ip:
        msg = "No management IP — skipping."
        log.warning("%s  %s", device_name, msg)
        result.errors.append(msg)
        return result

    if not os_type:
        msg = "Cannot determine OS type from NetBox platform — skipping."
        log.warning("%s  %s", device_name, msg)
        result.errors.append(msg)
        return result

    # ── Determine platform family ─────────────────────────────────────────
    dt   = device.get("device_type") or {}
    model_str = (dt.get("model", "") if isinstance(dt, dict) else "") or ""
    family = determine_platform_family(model_str, os_type)
    log.info("%s  model=%r  family=%s", device_name, model_str, family)
    print(f"  Platform family: {family}", flush=True)

    # ── Build VC member map {switch_num: device_id} ───────────────────────
    vc_member_map: Dict[int, int] = {}
    vc_id = device.get("_vc_id")
    if vc_id:
        try:
            vc_member_map = build_vc_member_map(vc_id, nb)
            log.info(
                "%s  VC id=%s  members: %s", device_name, vc_id,
                {k: v for k, v in sorted(vc_member_map.items())},
            )
        except Exception as exc:
            log.warning("%s  VC member map failed: %s", device_name, exc)

    # ── Connect to device ─────────────────────────────────────────────────
    cisco = CiscoDeviceClient(
        host=mgmt_ip,
        username=username or os.environ.get("CISCO_SRV_ACCOUNT", ""),
        password=password or os.environ.get("CISCO_SRV_PWD", ""),
        os_type=os_type,
        enable_secret=enable_secret or os.environ.get("CISCO_ENABLE_PWD") or None,
        timeout=timeout,
        verify_ssl=False,
    )

    print(f"  Connecting to {mgmt_ip} …", flush=True)
    try:
        cisco._cli_connect()
    except CiscoDeviceClientError as exc:
        msg = f"SSH connection failed: {exc}"
        log.error("%s  %s", device_name, msg)
        result.errors.append(msg)
        return result
    print("  Connected.", flush=True)

    # ── Collect show inventory ─────────────────────────────────────────────
    print("  Running: show inventory", flush=True)
    try:
        raw_inventory = get_inventory_raw(cisco)
    except Exception as exc:
        msg = f"show inventory failed: {exc}"
        log.error("%s  %s", device_name, msg)
        result.errors.append(msg)
        cisco._cli_disconnect()
        return result

    entries = parse_inventory_blocks(raw_inventory)
    log.info("%s  parsed %d inventory blocks", device_name, len(entries))
    print(f"  Parsed {len(entries)} inventory blocks.", flush=True)

    # ── Optional: NX-OS show module for slot confirmation ─────────────────
    nxos_slot_map: Dict[int, str] = {}
    if family == _FAM_NEXUS:
        print("  Running: show module (NX-OS)", flush=True)
        raw_module = get_show_module_raw(cisco)
        if raw_module:
            nxos_slot_map = parse_show_module_nxos(raw_module)
            log.debug("%s  NX-OS slot map: %s", device_name, nxos_slot_map)

    cisco._cli_disconnect()
    print("  Disconnected.", flush=True)

    # ── Classify and map every entry ──────────────────────────────────────
    for entry in entries:
        entry.kind = classify_component(entry)
        if entry.kind not in (_KIND_CHASSIS, _KIND_UNKNOWN, _KIND_FAN):
            map_component_to_slot(entry, family)

    # ── Process each entry ────────────────────────────────────────────────
    for entry in entries:
        # ── SKIP: chassis, fan, unknown ───────────────────────────────────
        if entry.kind in (_KIND_CHASSIS, _KIND_FAN, _KIND_UNKNOWN):
            log.debug(
                "%s  SKIP %s %s", device_name, entry.kind, entry.label()
            )
            continue

        # ── SKIP: transceiver unless opted in ────────────────────────────
        if entry.kind == _KIND_TRANSCEIVER and not include_transceivers:
            log.debug("%s  SKIP transceiver %s", device_name, entry.label())
            continue

        if not entry.pid:
            log.debug(
                "%s  SKIP entry with blank PID: NAME=%r", device_name, entry.raw_name
            )
            continue

        # ── POWER SUPPLY path ─────────────────────────────────────────────
        # PSUs always go into dcim.module_bays (PS-A / PS-B) on every
        # platform.  map_component_to_slot() already set entry.bay_name
        # via _derive_psu_bay_name().  The same _sync_module() function
        # handles bay creation, module insertion, and VC member routing.
        if entry.kind == _KIND_PSU:
            _sync_module(
                entry=entry,
                device=device,
                device_id=device_id,
                device_name=device_name,
                family=family,
                vc_member_map=vc_member_map,
                nb=nb,
                module_api=module_api,
                dry_run=dry_run,
                force=force,
                result=result,
            )
            continue

        # ── MODULE path (LINECARD / SUPERVISOR / TRANSCEIVER) ─────────────
        _sync_module(
            entry=entry,
            device=device,
            device_id=device_id,
            device_name=device_name,
            family=family,
            vc_member_map=vc_member_map,
            nb=nb,
            module_api=module_api,
            dry_run=dry_run,
            force=force,
            result=result,
        )

    # ── Summary ──────────────────────────────────────────────────────────
    print(
        f"\n  Summary: modules +{result.modules_added} "
        f"updated={result.modules_updated} skipped={result.modules_skipped}  "
        f"PSUs +{result.psus_added} updated={result.psus_updated}",
        flush=True,
    )
    return result


def _sync_module(
    entry: InventoryEntry,
    device: dict,
    device_id: int,
    device_name: str,
    family: str,
    vc_member_map: Dict[int, int],
    nb: NetBoxClient,
    module_api: NetBoxModuleAPI,
    dry_run: bool,
    force: bool,
    result: SyncResult,
) -> None:
    """Upsert one linecard / supervisor module."""
    if not entry.bay_name:
        log.debug(
            "%s  SKIP %s — no bay_name derived: %s",
            device_name, entry.kind, entry.label(),
        )
        return

    # ── Resolve the target device_id for VC stack members ────────────────
    target_device_id = device_id
    if entry.switch_num is not None and vc_member_map:
        resolved = vc_member_map.get(entry.switch_num)
        if resolved is not None:
            target_device_id = resolved
            log.debug(
                "%s  %s switch=%s → device_id=%s",
                device_name, entry.kind, entry.switch_num, target_device_id,
            )
        else:
            log.warning(
                "%s  Switch %s not in vc_member_map (keys=%s) — "
                "defaulting to device_id=%s; check NetBox VC positions",
                device_name, entry.switch_num,
                sorted(vc_member_map.keys()), device_id,
            )

    print(
        f"  {'[DRY-RUN] ' if dry_run else ''}{entry.kind.upper()}  "
        f"bay={entry.bay_name!r}  PID={entry.pid}  SN={entry.serial or '(none)'}",
        flush=True,
    )

    # ── Look up module type, auto-creating from PID if absent ────────────
    module_type = module_api.ensure_module_type(entry.pid, description=entry.descr)
    if module_type is None:
        msg = (
            f"MODULE TYPE MISSING (auto-create failed): device={device_name} "
            f"pid={entry.pid} name={entry.raw_name!r} "
            f"descr={entry.descr!r} sn={entry.serial}"
        )
        log.error(msg)
        err_log.error(
            "missing_module_type | device=%s pid=%s name=%r descr=%r sn=%s",
            device_name, entry.pid, entry.raw_name, entry.descr, entry.serial,
        )
        result.missing_module_types.append(entry.pid)
        return

    module_type_id = module_type.get("id")

    # ── Ensure the module bay exists ──────────────────────────────────────
    log.debug(
        "%s  Bay lookup: device_id=%s  name=%r  position=%s",
        device_name, target_device_id, entry.bay_name, entry.slot_num,
    )
    bay: Optional[dict] = module_api.find_module_bay(
        target_device_id, entry.bay_name, position=entry.slot_num
    )
    if bay is None:
        log.warning(
            "%s  No module bay found for device_id=%s  name=%r  position=%s — %s",
            device_name, target_device_id, entry.bay_name, entry.slot_num,
            "creating" if not dry_run else "skipping (dry-run)",
        )
        if not dry_run:
            try:
                bay = module_api.ensure_module_bay(
                    target_device_id,
                    entry.bay_name,
                    position=entry.slot_num,
                )
                log.info(
                    "%s  Bay %r %s (id=%s)",
                    device_name, entry.bay_name,
                    bay.get("_action"), bay.get("id"),
                )
            except NetBoxClientError as exc:
                msg = f"Cannot ensure bay {entry.bay_name!r} on device_id={target_device_id}: {exc}"
                log.error("%s  %s", device_name, msg)
                result.errors.append(msg)
                return
        else:
            log.info("%s  [DRY-RUN] would create bay %r", device_name, entry.bay_name)
    else:
        log.debug(
            "%s  Found bay %r  id=%s  position=%s  device_id=%s",
            device_name, entry.bay_name, bay.get("id"),
            bay.get("position"), target_device_id,
        )

    bay_id = bay.get("id") if bay else None

    # ── Early exit: already installed with correct module type ────────────
    # Skip port cleanup, interface cleanup, and upsert entirely when the bay
    # already contains a module of the expected type.  A matching type means
    # its ports are already present; there is nothing to clean up or recreate.
    if bay_id and module_type_id:
        _existing_check = module_api.get_module_by_bay(bay_id)
        if _existing_check is not None:
            _ex_type_id = module_api._extract_id(_existing_check.get("module_type"))
            if _ex_type_id == module_type_id:
                _label = "PSU" if entry.kind == _KIND_PSU else "Module"
                log.debug(
                    "%s  %s already installed in bay %r (module_type_id=%s) — skipping",
                    device_name, _label, entry.bay_name, module_type_id,
                )
                result.modules_skipped += 1
                return

    # ── Pre-install power-port / console-port conflict cleanup ───────────
    # Remove unconnected ports whose names collide with what the module-type
    # template would auto-create on install.  This prevents unique-constraint
    # 500 errors.  Connected ports are NEVER deleted.
    if module_type_id:
        if entry.kind == _KIND_PSU:
            for pname in module_api.get_power_port_template_names(module_type_id):
                module_api.ensure_unconnected_power_port_removed(
                    device_id=target_device_id,
                    port_name=pname,
                    dry_run=dry_run,
                    device_name=device_name,
                )
        else:
            for cname in module_api.get_console_port_template_names(module_type_id):
                module_api.ensure_unconnected_console_port_removed(
                    device_id=target_device_id,
                    port_name=cname,
                    dry_run=dry_run,
                    device_name=device_name,
                )

    # ── Pre-install interface cleanup ─────────────────────────────────────
    # NetBox auto-creates interfaces from module-type templates when a module
    # is installed.  If those interfaces already exist as free (unbound)
    # records the insert fails with a 500 unique-constraint error.
    # Deletion is only performed when --force is set; without it an error is
    # logged and the entry is skipped so no data is accidentally removed.
    # PSU bays never have associated interfaces; skip for them.
    if bay_id and not dry_run and entry.kind != _KIND_PSU:
        existing_mod = module_api.get_module_by_bay(bay_id)
        if existing_mod:
            ex_type_id = module_api._extract_id(existing_mod.get("module_type"))
            if ex_type_id != module_type_id:
                if not force:
                    msg = (
                        f"Bay {entry.bay_name!r} is occupied by a different module "
                        f"type (id={ex_type_id}, required={module_type_id}). "
                        f"Re-run with --force to delete existing interfaces and "
                        f"replace the module."
                    )
                    log.error("%s  %s", device_name, msg)
                    result.errors.append(msg)
                    return
                log.info(
                    "%s  Bay %r occupied by wrong type (id=%s) — replacing (--force)",
                    device_name, entry.bay_name, ex_type_id,
                )
                deleted, del_errors = delete_interfaces_for_slot(
                    nb, target_device_id, family,
                    entry.slot_num, entry.switch_num, dry_run=False,
                )
                if deleted:
                    log.info(
                        "%s  Deleted %d interface(s) for slot %s",
                        device_name, deleted, entry.slot_num,
                    )
                result.errors.extend(del_errors)
                try:
                    module_api.delete_module(existing_mod["id"])
                except NetBoxClientError as exc:
                    msg = f"Failed to remove stale module id={existing_mod['id']}: {exc}"
                    log.error("%s  %s", device_name, msg)
                    result.errors.append(msg)
                    return
        elif entry.slot_num is not None:
            # Bay is empty — stale slot interfaces from a prior run may exist.
            if force:
                deleted, del_errors = delete_interfaces_for_slot(
                    nb, target_device_id, family,
                    entry.slot_num, entry.switch_num, dry_run=False,
                )
                if deleted:
                    log.info(
                        "%s  Deleted %d stale interface(s) for slot %s "
                        "before module install (--force)",
                        device_name, deleted, entry.slot_num,
                    )
                result.errors.extend(del_errors)
            # Without --force we proceed to upsert; if stale interfaces exist
            # NetBox will return a 500 which is caught below with a --force hint.

    if dry_run:
        if entry.kind == _KIND_PSU:
            result.psus_added += 1
        else:
            result.modules_added += 1
        return

    if bay_id is None:
        # Bay creation failed above — skip
        return

    # ── Upsert the module ─────────────────────────────────────────────────
    try:
        mod, action = module_api.upsert_module(
            device_id=target_device_id,
            bay_id=bay_id,
            module_type_id=module_type_id,
            serial=entry.serial,
            description=entry.descr,
        )
        is_psu = entry.kind == _KIND_PSU
        if action == "created":
            if is_psu:
                result.psus_added += 1
            else:
                result.modules_added += 1
            log.info(
                "%s  %s CREATED  bay=%r  pid=%s  sn=%s  id=%s",
                device_name, "PSU" if is_psu else "Module",
                entry.bay_name, entry.pid, entry.serial, mod.get("id"),
            )
        elif action == "updated":
            if is_psu:
                result.psus_updated += 1
            else:
                result.modules_updated += 1
            log.info(
                "%s  %s UPDATED  bay=%r  pid=%s  sn=%s",
                device_name, "PSU" if is_psu else "Module",
                entry.bay_name, entry.pid, entry.serial,
            )
        else:
            result.modules_skipped += 1
            log.debug(
                "%s  %s unchanged  bay=%r  pid=%s",
                device_name, "PSU" if is_psu else "Module",
                entry.bay_name, entry.pid,
            )
    except NetBoxClientError as exc:
        exc_str = str(exc)
        if "duplicate key value" in exc_str and "unique constraint" in exc_str and not force:
            msg = (
                f"Module install failed for bay={entry.bay_name!r} pid={entry.pid}: "
                f"interfaces already exist on this slot in NetBox. "
                f"Re-run with --force to delete them and install the module."
            )
        else:
            msg = (
                f"upsert_module failed bay={entry.bay_name!r} "
                f"pid={entry.pid} sn={entry.serial}: {exc}"
            )
        log.error("%s  %s", device_name, msg)
        err_log.error(
            "module_upsert_failed | device=%s bay=%r pid=%s sn=%s | %s",
            device_name, entry.bay_name, entry.pid, entry.serial, exc,
        )
        result.errors.append(msg)


# --------------------------------------------------------------------------- #
# Logging setup                                                                #
# --------------------------------------------------------------------------- #

def _configure_logging(log_level: str, log_file: Optional[str] = None) -> None:
    level = getattr(logging, log_level.upper(), logging.INFO)
    fmt   = "%(asctime)s %(levelname)-8s %(name)s: %(message)s"

    root = logging.getLogger()
    root.setLevel(level)
    root.handlers.clear()

    sh = logging.StreamHandler(sys.stderr)
    sh.setFormatter(logging.Formatter(fmt))
    root.addHandler(sh)

    if log_file:
        try:
            fh = logging.FileHandler(log_file, mode="a", encoding="utf-8")
            fh.setFormatter(logging.Formatter(fmt))
            root.addHandler(fh)
        except OSError as exc:
            log.warning("Cannot open log file %r: %s", log_file, exc)

    # Error log file — WARNING and above only
    err_log.handlers.clear()
    try:
        fh = logging.FileHandler(
            "netbox_device_modules_errors.log", mode="a", encoding="utf-8"
        )
        fh.setLevel(logging.WARNING)
        fh.setFormatter(logging.Formatter(fmt))
        err_log.setLevel(logging.WARNING)
        err_log.addHandler(fh)
        err_log.propagate = False
    except OSError as exc:
        log.warning("Cannot open error log file: %s", exc)


# --------------------------------------------------------------------------- #
# CLI argument parser                                                          #
# --------------------------------------------------------------------------- #

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=_TOOL,
        description="Sync Cisco hardware module inventory into NetBox.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Environment variables:
  NETBOX_URL           NetBox base URL
  NETBOX_API           NetBox API token
  CISCO_SRV_ACCOUNT    SSH username  (overridden by --username)
  CISCO_SRV_PWD        SSH password  (overridden by --password)
  CISCO_ENABLE_PWD     Enable secret (overridden by --enable-secret)

Examples:
  # Single device
  python netbox_device_modules.py --device core-sw-01

  # Comma-separated list
  python netbox_device_modules.py --devices core-sw-01,core-sw-02

  # Device file (one name per line, # comments ignored)
  python netbox_device_modules.py --device-file hosts.txt

  # NetBox filter (JSON)
  python netbox_device_modules.py --device-filter '{"site": "dc1", "role": "distribution"}'

  # All active devices in a site
  python netbox_device_modules.py --site-slug dc1

  # Legacy single-filter shortcuts
  python netbox_device_modules.py --site dc1 --dry-run
  python netbox_device_modules.py --role distribution --limit 5

  # Verbose logging
  python netbox_device_modules.py --device core-sw-01 --log-level DEBUG
""",
    )

    nb_grp = p.add_argument_group("NetBox connection")
    nb_grp.add_argument("--netbox-url",   default=os.environ.get("NETBOX_URL",  ""), metavar="URL",
                        help="NetBox base URL (env: NETBOX_URL)")
    nb_grp.add_argument("--netbox-token", default=os.environ.get("NETBOX_API",  ""), metavar="TOKEN",
                        help="NetBox API token (env: NETBOX_API)")
    nb_grp.add_argument("--netbox-verify-ssl", action=argparse.BooleanOptionalAction, default=True,
                        help="Verify NetBox TLS certificate (default: true)")

    sel_grp = p.add_argument_group("Device selection (pick one, or omit for all)")
    sel_grp.add_argument("--device",      metavar="NAME",
                         help="Single device by NetBox name")
    sel_grp.add_argument("--devices",     metavar="NAME,...",
                         help="Comma-separated device names")
    sel_grp.add_argument("--device-file", metavar="PATH",
                         help="File with one device name per line (#comments ignored)")
    sel_grp.add_argument("--device-filter", default="{}",  metavar="JSON",
                         help="NetBox DCIM device filter as JSON (default: all devices)")
    sel_grp.add_argument("--all", dest="all_devices", action="store_true",
                         help="Explicit 'process all' flag (use with caution)")
    sel_grp.add_argument("--site-slug", default="", metavar="SLUG",
                         help="Limit to devices in this NetBox site slug (stacks with --device-filter)")

    leg_grp = p.add_argument_group("Legacy device selection (alternative to --device-filter)")
    leg_grp.add_argument("--site",  metavar="SLUG", help="All devices in this site slug")
    leg_grp.add_argument("--role",  metavar="SLUG", help="Filter by device role slug")
    leg_grp.add_argument("--tag",   metavar="SLUG", help="Filter by device tag slug")
    leg_grp.add_argument("--limit", type=int, metavar="N", help="Process at most N devices")

    cred_grp = p.add_argument_group("Cisco credentials")
    cred_grp.add_argument("--username",
                          default=os.environ.get("CISCO_SRV_ACCOUNT", ""),
                          help="SSH username (env: CISCO_SRV_ACCOUNT)")
    cred_grp.add_argument("--password",
                          default=os.environ.get("CISCO_SRV_PWD", ""),
                          help="SSH password (env: CISCO_SRV_PWD)")
    cred_grp.add_argument("--enable-secret",
                          default=os.environ.get("CISCO_ENABLE_PWD", ""),
                          help="Enable-mode secret (env: CISCO_ENABLE_PWD)")

    run_grp = p.add_argument_group("Run options")
    run_grp.add_argument("--dry-run", action="store_true",
                         help="Print what would change without writing to NetBox")
    run_grp.add_argument("--force", action="store_true",
                         help=(
                             "Delete existing slot interfaces before installing a module. "
                             "Required when NetBox already has interfaces on a slot that "
                             "would conflict with the module's auto-created interfaces. "
                             "Without this flag conflicting interfaces are left untouched "
                             "and an error is logged instead."
                         ))
    run_grp.add_argument("--include-transceivers", action="store_true",
                         help="Also sync SFP/QSFP transceivers as modules (disabled by default)")
    run_grp.add_argument("--timeout", type=int, default=30, metavar="SEC",
                         help="Device SSH timeout in seconds (default: 30)")
    run_grp.add_argument("--log-level", choices=["DEBUG", "INFO", "WARNING", "ERROR"],
                         default="INFO",
                         help="Log verbosity (default: INFO; use DEBUG for verbose output)")
    run_grp.add_argument("--log-file", metavar="PATH", default=None,
                         help="Also write logs to this file (appended, UTF-8)")

    return p


# --------------------------------------------------------------------------- #
# Main                                                                         #
# --------------------------------------------------------------------------- #

def main() -> None:
    parser = build_parser()
    args   = parser.parse_args()
    _configure_logging(args.log_level, args.log_file)

    # ── Validate required config ──────────────────────────────────────────
    missing: list = []
    if not args.netbox_url:
        missing.append("--netbox-url / NETBOX_URL")
    if not args.netbox_token:
        missing.append("--netbox-token / NETBOX_API")
    if not args.username:
        missing.append("--username / CISCO_SRV_ACCOUNT")
    if not args.password:
        missing.append("--password / CISCO_SRV_PWD")
    if missing:
        log.error("Missing required config:\n  %s", "\n  ".join(missing))
        sys.exit(1)

    # ── Ensure at least one device selector is given ──────────────────────
    has_new_selector = any([
        args.device,
        getattr(args, "devices", None),
        getattr(args, "device_file", None),
        args.all_devices,
        args.device_filter != "{}",
        args.site_slug,
    ])
    has_legacy_selector = any([args.site, args.role, args.tag])

    if not has_new_selector and not has_legacy_selector:
        log.error(
            "Specify at least one device selector: "
            "--device, --devices, --device-file, --device-filter, "
            "--all, --site-slug, --site, --role, or --tag"
        )
        sys.exit(1)

    # ── Bridge legacy --site/--role/--tag into --device-filter ───────────
    # resolve_device_list understands --device-filter but not --site/--role/--tag.
    if has_legacy_selector and not has_new_selector:
        try:
            nb_filter: dict = json.loads(args.device_filter)
        except json.JSONDecodeError:
            nb_filter = {}
        nb_filter.setdefault("status", "active")
        nb_filter.setdefault("has_primary_ip", True)
        if args.site:
            nb_filter["site"] = args.site
        if args.role:
            nb_filter["role"] = args.role
        if args.tag:
            nb_filter["tag"] = args.tag
        args.device_filter = json.dumps(nb_filter)

    if args.dry_run:
        log.info("*** DRY-RUN — no changes will be written to NetBox ***")

    nb         = NetBoxClient(
        base_url=args.netbox_url,
        token=args.netbox_token,
        verify_ssl=args.netbox_verify_ssl,
    )
    module_api = NetBoxModuleAPI(nb)

    # ── Resolve device list ───────────────────────────────────────────────
    devices = resolve_device_list(args, nb)
    log.info("Processing %d device(s).", len(devices))

    if not devices:
        log.warning("No devices matched the given selectors.")
        sys.exit(0)

    if args.limit:
        devices = devices[: args.limit]

    # ── Run sync per device ───────────────────────────────────────────────
    all_results: list[SyncResult] = []
    for device in devices:
        # Attach VC context if present
        try:
            vc_obj = device.get("virtual_chassis")
            if isinstance(vc_obj, dict) and vc_obj.get("id"):
                device["_vc_id"] = vc_obj["id"]
        except Exception:
            pass

        result = sync_device_modules(
            device=device,
            nb=nb,
            module_api=module_api,
            dry_run=args.dry_run,
            include_transceivers=args.include_transceivers,
            username=args.username,
            password=args.password,
            enable_secret=args.enable_secret,
            timeout=args.timeout,
            force=args.force,
        )
        all_results.append(result)

    # ── Final summary ─────────────────────────────────────────────────────
    print("\n" + "=" * 60)
    print(f"  FINAL SUMMARY  ({len(all_results)} device(s))")
    print("=" * 60)
    total_mod_add = sum(r.modules_added   for r in all_results)
    total_mod_upd = sum(r.modules_updated for r in all_results)
    total_psu_add = sum(r.psus_added      for r in all_results)
    total_psu_upd = sum(r.psus_updated    for r in all_results)
    miss_mod_pids = sorted({p for r in all_results for p in r.missing_module_types})
    miss_psu_pids = sorted({p for r in all_results for p in r.missing_psu_types})

    print(f"  Modules  : +{total_mod_add} created  {total_mod_upd} updated")
    print(f"  PSUs     : +{total_psu_add} created  {total_psu_upd} updated")
    print(f"  Missing module types ({len(miss_mod_pids)}): {miss_mod_pids}")
    print(f"  Missing PSU types    ({len(miss_psu_pids)}): {miss_psu_pids}")
    print(f"  Errors logged to: netbox_device_modules_errors.log")

    for r in all_results:
        if r.errors or r.missing_module_types or r.missing_psu_types:
            status = "ERRORS" if r.errors else "MISSING TYPES"
            print(f"    [{status}] {r.device_name}")
            for e in r.errors[:3]:
                print(f"      - {e}")

    if args.dry_run:
        print("\n  *** DRY-RUN — no changes were written ***")


if __name__ == "__main__":
    main()
