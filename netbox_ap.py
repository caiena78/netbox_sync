#!/usr/bin/env python3
"""
netbox_ap.py
============
Discover Cisco Access Points via CDP and build (create / update) those AP
device objects in NetBox.

For each selected parent Cisco device the script:

1. Connects via SSH and runs ``show cdp neighbors detail``.
2. Parses every CDP block and extracts: Device ID, IP address, platform /
   model string, serial number, remote port ID, and software version.
3. Filters to only Cisco AP models (``AIR-*``, ``C91*``, etc.).
4. For each AP:
   a. Normalises the device name to lowercase (REQ 0).
   b. Verifies the required DeviceType exists in NetBox (fatal if missing).
   c. Idempotently creates or updates the device record.
   d. Idempotently updates the ``software_version`` custom field (REQ 1).
   e. Ensures a single uplink interface exists on the AP device.
   f. Resolves the management IP to the longest-matching NetBox prefix
      (REQ 2) and assigns the CIDR to that interface.
   g. Sets the device ``primary_ip4`` if not already set.

All CLI flags are shared with ``sync_netbox_interfaces.py`` via the same
``build_parser()`` / ``resolve_device_list()`` helpers that
``netbox_update_State.py`` uses.

Output
------
JSON array to **stdout** (one element per parent device); all logs go to
**stderr**.

AP role in NetBox
-----------------
The script uses a device role named ``"Access Point"``; it creates the role
automatically (cyan colour) if it does not yet exist.

DeviceType pre-requisite
------------------------
Every AP model **must** have a matching DeviceType already defined in NetBox
before running this script.  If any model is missing the script exits
non-zero and prints the exact missing model string.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set

from cisco_device_client import CiscoDeviceClient, CiscoDeviceClientError
from netbox_client import NetBoxClient, NetBoxClientError
from vault_client import VaultClient, VaultError, add_vault_parser_args, is_vault_configured, resolve_vault_auth

# Reuse the shared parser, device-selection, and helper functions so flags
# remain byte-for-byte identical to the rest of the repo.
from sync_netbox_interfaces import (
    _configure_logging,
    _device_has_primary_ip,
    build_parser,
    get_device_mgmt_ip,
    get_device_os_type,
    resolve_device_list,
)

# --------------------------------------------------------------------------- #
# Constants                                                                    #
# --------------------------------------------------------------------------- #

_AP_ROLE_NAME          = "Access Point"
_AP_ROLE_COLOR         = "00bcd4"   # teal
_AP_DEFAULT_IFACE_NAME = "GigabitEthernet0"
_AP_DEFAULT_IFACE_TYPE = "1000base-t"
_CISCO_MANUFACTURER    = "Cisco"

log = logging.getLogger("netbox_ap")

# --------------------------------------------------------------------------- #
# REQ 0 — Device name normalisation                                           #
# --------------------------------------------------------------------------- #


def _normalize_device_name(raw: str) -> str:
    """
    Return *raw* stripped and lowercased.

    All NetBox device lookups and creates/updates must use the value returned
    by this function so that the stored name is always lowercase and consistent
    regardless of how CDP or other sources report the hostname.
    """
    return raw.strip().lower()


# --------------------------------------------------------------------------- #
# AP identification                                                            #
# --------------------------------------------------------------------------- #

# Patterns matched against the *model* string extracted from the CDP platform line.
_AP_MODEL_PATTERNS: List[re.Pattern] = [
    re.compile(r"^AIR-",    re.IGNORECASE),   # AIR-CAP*, AIR-AP*, AIR-*
    re.compile(r"^C91",     re.IGNORECASE),   # C9115AX, C9120AX, C9130AX, …
    re.compile(r"^CW91",    re.IGNORECASE),   # Catalyst 9100 wave-2 variants
    re.compile(r"^AP\d",    re.IGNORECASE),   # APxxxx generic Cisco AP names
]


def is_cisco_ap(model_string: str, platform_line: str = "") -> bool:
    """
    Return ``True`` when *model_string* looks like a Cisco Access Point.

    Both *model_string* (the stripped model, e.g. ``"AIR-CAP3502I-A-K9"``) and
    the raw *platform_line* (e.g. ``"cisco AIR-CAP3502I-A-K9, Capabilities…"``)
    are checked so that either a clean model or a raw platform line can be
    passed without pre-processing.
    """
    for s in (model_string, platform_line):
        for pattern in _AP_MODEL_PATTERNS:
            if pattern.search(s):
                return True
    return False


# --------------------------------------------------------------------------- #
# CDP parsing                                                                  #
# --------------------------------------------------------------------------- #

# Compiled once at module level for speed.
_BLOCK_SEP_RE  = re.compile(r"^-{5,}", re.MULTILINE)

_DEVICE_ID_RE  = re.compile(r"^Device\s+ID\s*:\s*(.+)$",              re.IGNORECASE)
_PLATFORM_RE   = re.compile(r"Platform\s*:\s*(.+?),",                 re.IGNORECASE)
_PORT_ID_RE    = re.compile(r"Port\s+ID\s*\(outgoing\s+port\)\s*:\s*(\S+)", re.IGNORECASE)
_SERIAL_RE     = re.compile(
    r"(?:Serial\s+number|SN|System\s+Serial\s+Number)\s*:\s*(\S+)",
    re.IGNORECASE,
)
# Management address preferred over entry address.
_MGMT_IP_RE    = re.compile(
    r"Management\s+address(?:es)?\s*[:\(].*?IP\s+address\s*:\s*(\d+\.\d+\.\d+\.\d+)",
    re.IGNORECASE | re.DOTALL,
)
_ENTRY_IP_RE   = re.compile(
    r"Entry\s+address(?:es)?\s*[:\(].*?IP\s+address\s*:\s*(\d+\.\d+\.\d+\.\d+)",
    re.IGNORECASE | re.DOTALL,
)
# Single-line fallback for any "IP address: x.x.x.x" not matched above.
_IP_FALLBACK_RE = re.compile(
    r"IP\s+address\s*:\s*(\d+\.\d+\.\d+\.\d+)",
    re.IGNORECASE,
)

# REQ 1: software version extraction.
#
# CDP blocks use two formats:
#   Multi-line (most common on APs):
#     "Version :\n"
#     "Cisco IOS Software, C3500 Software ..., Version 15.3(3)JD17, ..."
#   Inline (rare):
#     "Version: 15.3(3)JD17"
#
# Pattern explanation:
#   Branch 1: "Version" + optional spaces + ":" + optional spaces/tabs + newline
#             + optional leading whitespace + captured content line
#   Branch 2: "Version" + optional spaces + ":" + required space/tab + content on same line
#
# [ \t] is used instead of \s so that the newline is matched explicitly by \n.
_VERSION_RE = re.compile(
    r"Version\s*:[ \t]*\n[ \t]*(.+)"
    r"|"
    r"Version\s*:[ \t]+(.+)",
    re.IGNORECASE,
)


def _parse_model_from_platform(platform_line: str) -> str:
    """
    Extract the model string from a raw CDP ``Platform:`` line.

    Example input : ``"cisco AIR-CAP3502I-A-K9,  Capabilities: Trans-Bridge"``
    Example output: ``"AIR-CAP3502I-A-K9"``

    Strips the leading ``"cisco "`` prefix (case-insensitive) and takes
    everything up to the first comma.
    """
    cleaned = re.sub(r"^cisco\s+", "", platform_line.strip(), flags=re.IGNORECASE)
    return cleaned.split(",")[0].strip()


def parse_cdp_neighbors_detail(raw: str) -> List[dict]:
    """
    Parse raw ``show cdp neighbors detail`` output into structured dicts.

    Returns
    -------
    list[dict]
        Each entry::

            {
                "neighbor_device":    str,          # raw Device ID (not lowercased here)
                "neighbor_ip":        str | None,
                "platform_line":      str,
                "model":              str,
                "serial":             str | None,
                "neighbor_interface": str | None,   # AP outgoing port
                "local_interface":    str | None,   # local port on parent
                "software_version":   str | None,   # REQ 1
            }
    """
    # Split on separator lines, then re-split on any "Device ID:" header so
    # devices that omit separator lines between blocks are also handled.
    blocks: List[str] = _BLOCK_SEP_RE.split(raw)
    expanded: List[str] = []
    for block in blocks:
        parts = re.split(r"(?=^Device\s+ID\s*:)", block, flags=re.MULTILINE)
        expanded.extend(parts)

    neighbors: List[dict] = []

    for block in expanded:
        lines = block.strip().splitlines()
        if not lines:
            continue

        # ── Device ID ────────────────────────────────────────────────────
        device_id: Optional[str] = None
        for line in lines:
            m = _DEVICE_ID_RE.match(line.strip())
            if m:
                device_id = m.group(1).strip()
                break
        if not device_id:
            continue

        block_text = "\n".join(lines)

        # ── Platform / model ─────────────────────────────────────────────
        platform_line = ""
        model         = ""
        m = _PLATFORM_RE.search(block_text)
        if m:
            raw_plat      = m.group(1).strip()
            platform_line = raw_plat
            model         = _parse_model_from_platform(raw_plat)

        # ── IP address (management preferred over entry) ──────────────────
        neighbor_ip: Optional[str] = None
        m = _MGMT_IP_RE.search(block_text)
        if m:
            neighbor_ip = m.group(1)
        else:
            m = _ENTRY_IP_RE.search(block_text)
            if m:
                neighbor_ip = m.group(1)
            else:
                m = _IP_FALLBACK_RE.search(block_text)
                if m:
                    neighbor_ip = m.group(1)

        # ── Serial number ─────────────────────────────────────────────────
        serial: Optional[str] = None
        m = _SERIAL_RE.search(block_text)
        if m:
            serial = m.group(1).strip()

        # ── Port IDs ──────────────────────────────────────────────────────
        neighbor_interface: Optional[str] = None
        local_interface:    Optional[str] = None
        m = _PORT_ID_RE.search(block_text)
        if m:
            neighbor_interface = m.group(1).strip()
        iface_m = re.search(r"Interface\s*:\s*(\S+?),", block_text, re.IGNORECASE)
        if iface_m:
            local_interface = iface_m.group(1).rstrip(",").strip()

        # ── Software version (REQ 1) ──────────────────────────────────────
        software_version: Optional[str] = None
        m = _VERSION_RE.search(block_text)
        if m:
            # Branch 1 (multi-line) is group 1; branch 2 (inline) is group 2.
            raw_ver = (m.group(1) or m.group(2) or "").strip()
            software_version = raw_ver if raw_ver else None

        neighbors.append({
            "neighbor_device":    device_id,
            "neighbor_ip":        neighbor_ip,
            "platform_line":      platform_line,
            "model":              model,
            "serial":             serial,
            "neighbor_interface": neighbor_interface,
            "local_interface":    local_interface,
            "software_version":   software_version,
        })

    return neighbors


# --------------------------------------------------------------------------- #
# REQ 2 — Longest-prefix match for IP CIDR resolution                        #
# --------------------------------------------------------------------------- #


def resolve_ip_cidr_from_netbox(
    ip_str: str,
    nb: NetBoxClient,
    site_id: Optional[int] = None,
    prefix_cache: Optional[Dict[str, str]] = None,
) -> str:
    """
    Return ``"<ip>/<prefixlen>"`` using the longest-matching NetBox prefix.

    Algorithm
    ---------
    1. Check *prefix_cache* (keyed by *ip_str*) and return immediately on hit.
    2. Query NetBox for all prefixes that contain *ip_str* using the server-side
       ``contains`` filter.  When *site_id* is supplied the search is narrowed
       to that site first; if the site-scoped search returns nothing it falls
       back to a global search so APs in border-leaf sites are still covered.
    3. Among returned prefixes select the one with the largest prefix length
       (most specific / longest match).
    4. Cache and return ``"<ip>/<prefixlen>"``.
    5. If no containing prefix is found, log a warning and return ``"<ip>/32"``.

    Parameters
    ----------
    ip_str : str
        Bare IPv4 address from CDP, e.g. ``"10.254.175.57"``.
    nb : NetBoxClient
    site_id : int, optional
        NetBox site ID of the parent Cisco device.  Used to narrow the
        prefix search; a global fallback is always attempted when the
        site-scoped search returns no results.
    prefix_cache : dict, optional
        Caller-supplied dict for caching ``ip_str → cidr`` within a single
        parent-device processing pass.  Pass the same dict for all APs seen
        on the same parent switch to avoid redundant API calls.

    Returns
    -------
    str
        CIDR string, e.g. ``"10.254.175.57/24"``.
    """
    if prefix_cache is not None and ip_str in prefix_cache:
        return prefix_cache[ip_str]

    candidate_prefixes: List[dict] = []

    # Site-scoped search first (more specific → cheaper if prefix is local).
    if site_id is not None:
        try:
            candidate_prefixes = nb.get_prefixes_containing_ip(ip_str, site_id=site_id)
        except NetBoxClientError as exc:
            log.warning(
                "Prefix lookup failed (site_id=%s) for %s: %s",
                site_id, ip_str, exc,
            )

    # Global fallback when site-scoped search returns nothing.
    if not candidate_prefixes:
        try:
            candidate_prefixes = nb.get_prefixes_containing_ip(ip_str)
        except NetBoxClientError as exc:
            log.warning("Global prefix lookup failed for %s: %s", ip_str, exc)

    if not candidate_prefixes:
        log.warning(
            "No containing prefix found for %s; using /32", ip_str
        )
        result = f"{ip_str}/32"
        if prefix_cache is not None:
            prefix_cache[ip_str] = result
        return result

    # Pick the most specific prefix (largest prefixlen).
    try:
        ip_obj = ipaddress.ip_address(ip_str)
    except ValueError:
        log.warning("Invalid IP address %r; using /32", ip_str)
        result = f"{ip_str}/32"
        if prefix_cache is not None:
            prefix_cache[ip_str] = result
        return result

    best_net: Optional[ipaddress.IPv4Network] = None
    for p in candidate_prefixes:
        prefix_str = p.get("prefix", "")
        try:
            net = ipaddress.ip_network(prefix_str, strict=False)
            if ip_obj in net:
                if best_net is None or net.prefixlen > best_net.prefixlen:
                    best_net = net
        except ValueError:
            continue

    if best_net is None:
        log.warning("No valid containing prefix for %s; using /32", ip_str)
        result = f"{ip_str}/32"
    else:
        result = f"{ip_str}/{best_net.prefixlen}"
        log.debug(
            "resolve_ip_cidr: %s → %s (via %s)", ip_str, result, best_net
        )

    if prefix_cache is not None:
        prefix_cache[ip_str] = result
    return result


# --------------------------------------------------------------------------- #
# PART 1 — last_seen helpers                                                  #
# --------------------------------------------------------------------------- #


def get_current_datetime_iso() -> str:
    """Return the current UTC datetime as ISO 8601 with 'Z' suffix."""
    return datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def update_device_last_seen(nb: NetBoxClient, device_id: int, device_name: str) -> None:
    """PATCH the device's last_seen custom field to the current UTC datetime."""
    ts = get_current_datetime_iso()
    try:
        nb.update_device_custom_fields(device_id, {"last_seen": ts})
        log.info("%-30s  last_seen updated to %s", device_name, ts)
    except NetBoxClientError as exc:
        log.warning("%-30s  last_seen update failed: %s", device_name, exc)


# --------------------------------------------------------------------------- #
# PART 2 — MAC address table helpers                                           #
# --------------------------------------------------------------------------- #

_IFACE_PREFIX_MAP: List[tuple] = [
    (re.compile(r"^GigabitEthernet",     re.IGNORECASE), "Gi"),
    (re.compile(r"^FastEthernet",        re.IGNORECASE), "Fa"),
    (re.compile(r"^TenGigabitEthernet",  re.IGNORECASE), "Te"),
    (re.compile(r"^TwentyFiveGigE",      re.IGNORECASE), "Twe"),
    (re.compile(r"^FortyGigabitEthernet",re.IGNORECASE), "Fo"),
    (re.compile(r"^HundredGigE",         re.IGNORECASE), "Hu"),
    (re.compile(r"^Port-channel",        re.IGNORECASE), "Po"),
    (re.compile(r"^Ethernet",            re.IGNORECASE), "Et"),
]

_MAC_DOTTED_RE = re.compile(r"^[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}$", re.IGNORECASE)
_MAC_COLON_RE  = re.compile(
    r"^([0-9a-f]{2}):([0-9a-f]{2}):([0-9a-f]{2})"
    r":([0-9a-f]{2}):([0-9a-f]{2}):([0-9a-f]{2})$",
    re.IGNORECASE,
)
_MAC_HYPHEN_RE = re.compile(
    r"^([0-9a-f]{2})-([0-9a-f]{2})-([0-9a-f]{2})"
    r"-([0-9a-f]{2})-([0-9a-f]{2})-([0-9a-f]{2})$",
    re.IGNORECASE,
)


def normalize_to_short_interface(expanded_iface: str) -> str:
    """
    Convert an expanded Cisco interface name to short lowercase form.

    Examples:
        "GigabitEthernet4/0/28" -> "gi4/0/28"
        "Gi4/0/28"              -> "gi4/0/28"
    """
    iface = expanded_iface.strip()
    for pattern, short in _IFACE_PREFIX_MAP:
        m = pattern.match(iface)
        if m:
            return (short + iface[m.end():]).lower()
    return iface.lower()


def _normalize_mac(mac: str) -> Optional[str]:
    """
    Normalise *mac* to lowercase Cisco dotted format (aaaa.bbbb.cccc).
    Returns None if the string is not a recognisable MAC address.
    """
    mac = mac.strip().lower()
    if _MAC_DOTTED_RE.match(mac):
        return mac
    m = _MAC_COLON_RE.match(mac)
    if m:
        o = [m.group(i) for i in range(1, 7)]
        return f"{o[0]}{o[1]}.{o[2]}{o[3]}.{o[4]}{o[5]}"
    m = _MAC_HYPHEN_RE.match(mac)
    if m:
        o = [m.group(i) for i in range(1, 7)]
        return f"{o[0]}{o[1]}.{o[2]}{o[3]}.{o[4]}{o[5]}"
    return None


def get_switch_mac_table(client) -> dict:
    """
    Runs ``show mac address-table dynamic`` and returns a dict mapping
    short_interface_lower -> mac_lower (one MAC per port, deterministic).

    For ports with multiple MACs the lexicographically lowest is chosen.
    Returns an empty dict on any collection error (non-fatal).
    """
    try:
        raw = client._cli_connection.send_command("show mac address-table dynamic")
    except Exception as exc:
        log.warning("MAC table collection failed: %s", exc)
        return {}

    port_macs: Dict[str, List[str]] = {}
    entry_count = 0

    for line in raw.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if re.match(r"^[-*=\s]+$", stripped):
            continue
        if re.search(r"Mac Address Table|Mac Address\s+Type|Protocols", stripped, re.IGNORECASE):
            continue

        parts = stripped.split()
        if len(parts) < 3:
            continue

        # Locate the MAC field (any supported format).
        mac_idx: Optional[int] = None
        for i, part in enumerate(parts):
            if (_MAC_DOTTED_RE.match(part)
                    or _MAC_COLON_RE.match(part)
                    or _MAC_HYPHEN_RE.match(part)):
                mac_idx = i
                break

        if mac_idx is None:
            continue

        # Port is always the last field in all common IOS / IOS-XE formats.
        port_str = parts[-1]

        # Skip CPU and VLAN (SVI) pseudo-ports.
        if port_str.upper() in ("CPU", "SWITCH", "VLAN"):
            continue
        if re.match(r"^(Vl|Vlan)\d+", port_str, re.IGNORECASE):
            continue

        mac_norm = _normalize_mac(parts[mac_idx])
        if not mac_norm:
            continue

        port_key = normalize_to_short_interface(port_str)
        port_macs.setdefault(port_key, []).append(mac_norm)
        entry_count += 1

    log.info("MAC table: parsed %d entries across %d port(s)", entry_count, len(port_macs))

    # One deterministic MAC per port: lexicographically lowest.
    return {port: sorted(macs)[0] for port, macs in port_macs.items()}


# --------------------------------------------------------------------------- #
# PART 3 — AP interface MAC update                                             #
# --------------------------------------------------------------------------- #


def update_ap_interface_mac(
    nb: NetBoxClient,
    interface_id: int,
    mac: str,
    current_iface: Optional[dict] = None,
) -> None:
    """
    Ensure a MAC address object exists in NetBox for *interface_id*, then
    update both ``mac_address`` (legacy string) and ``primary_mac_address``
    (FK → dcim.mac_addresses, requires integer ID) on the interface.

    Uses the same ``ensure_mac_address`` path as ``client_mac_address.py``
    so that MAC objects are created / reassigned idempotently.

    Parameters
    ----------
    nb : NetBoxClient
    interface_id : int
        Primary key of the interface to update.
    mac : str
        Lowercase Cisco dotted MAC, e.g. ``"1cd1.e0d2.c774"``.
    current_iface : dict, optional
        Interface record dict from the most recent upsert/fetch.  When
        supplied, used to skip both API calls if both MAC fields already
        carry the correct value (avoids redundant writes on re-runs).
    """
    def _cur_mac_str(val) -> str:
        # primary_mac_address is a nested object in the API response:
        # {"id": 123, "mac_address": "AAAA.BBBB.CCCC", ...}
        if isinstance(val, dict):
            return (val.get("mac_address") or "").lower()
        return (val or "").lower()

    mac_lower = mac.lower()

    # Idempotency: skip when both fields already carry the correct MAC.
    if current_iface is not None:
        cur_mac     = _cur_mac_str(current_iface.get("mac_address"))
        cur_pri_mac = _cur_mac_str(current_iface.get("primary_mac_address"))
        if cur_mac == mac_lower and cur_pri_mac == mac_lower:
            log.debug(
                "Interface id=%s MAC already %s — skipping update",
                interface_id, mac,
            )
            return

    # Step 1 — ensure the dcim.mac_addresses object exists and is assigned
    # to this interface (mirrors the client_mac_address.py workflow).
    # Returns the MAC record dict which includes its integer "id".
    try:
        mac_result = nb.ensure_mac_address(
            mac=mac,
            interface_id=interface_id,
            now_iso=get_current_datetime_iso(),
            description="Added via netbox_ap.py",
        )
    except NetBoxClientError as exc:
        log.warning(
            "MAC object ensure failed for interface id=%s (%s): %s",
            interface_id, mac, exc,
        )
        return

    mac_obj_id = mac_result["id"]
    log.debug(
        "Interface id=%s  MAC object id=%s  action=%s",
        interface_id, mac_obj_id, mac_result.get("_action"),
    )

    # Step 2 — PATCH the interface:
    #   mac_address         → plain MAC string  (legacy field, accepts string)
    #   primary_mac_address → integer ID of the dcim.mac_addresses object
    #                         (FK field; passing a string causes 400 Bad Request)
    try:
        nb.update_interface(interface_id, {
            "mac_address":         mac,
            "primary_mac_address": mac_obj_id,
        })
        log.info(
            "Interface id=%s  mac_address=%s  primary_mac_address id=%s",
            interface_id, mac, mac_obj_id,
        )
    except NetBoxClientError as exc:
        log.warning(
            "MAC update failed for interface id=%s: %s",
            interface_id, exc,
        )


# --------------------------------------------------------------------------- #
# NetBox pre-flight helpers                                                    #
# --------------------------------------------------------------------------- #


def _resolve_role_id(nb: NetBoxClient) -> int:
    """
    Ensure the ``"Access Point"`` device role exists and return its ID.

    Creates the role (cyan) when absent.
    """
    role = nb.ensure_device_role(_AP_ROLE_NAME, color=_AP_ROLE_COLOR)
    return role["id"]


def _resolve_device_type_id(model: str, nb: NetBoxClient) -> Optional[int]:
    """
    Return the NetBox DeviceType ID for *model*, or ``None`` when not found.

    Searches by ``model`` field first, then by ``part_number`` (handled
    inside :meth:`NetBoxClient.get_device_type_by_model`).  When neither
    field matches, logs an ERROR and returns ``None`` so the caller can
    accumulate all missing models before writing ``missing_ap_models.txt``
    and exiting non-zero.
    """
    dt = nb.get_device_type_by_model(model)
    if not dt:
        log.error("ERROR: Missing NetBox DeviceType for AP model: %s", model)
        return None
    return dt["id"]


def _write_missing_ap_models(models: Set[str]) -> None:
    """
    Write *models* to ``missing_ap_models.txt`` in the current directory.

    The file is overwritten on each call.  Each line contains one missing
    model string.  A brief header explains how to use the file.
    """
    path = "missing_ap_models.txt"
    ts   = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(f"# Missing AP DeviceType models — generated {ts}\n")
        fh.write(
            "# These AP models were discovered via CDP but have no matching\n"
            "# DeviceType in NetBox (neither 'model' nor 'part_number' matched).\n"
            "# Create a DeviceType for each model, or set its part_number,\n"
            "# then re-run netbox_ap.py.\n"
            "#\n"
        )
        for m in sorted(models):
            fh.write(f"{m}\n")
    log.error(
        "Missing DeviceType for %d AP model(s) — written to %s: %s",
        len(models), path, sorted(models),
    )


# --------------------------------------------------------------------------- #
# Per-AP build logic                                                           #
# --------------------------------------------------------------------------- #


def _build_ap_in_netbox(
    neighbor: dict,
    parent_device: dict,
    nb: NetBoxClient,
    role_id: int,
    dry_run: bool,
    prefix_cache: Optional[Dict[str, str]] = None,
    mac_table: Optional[Dict[str, str]] = None,
) -> dict:
    """
    Create or update one AP's NetBox representation.

    Parameters
    ----------
    neighbor : dict
        Parsed CDP entry from :func:`parse_cdp_neighbors_detail`.
    parent_device : dict
        NetBox device dict for the Cisco switch/router that reported this
        CDP neighbor.  Used to inherit ``site`` and ``tenant``.
    nb : NetBoxClient
    role_id : int
        NetBox DeviceRole ID for ``"Access Point"``.
    dry_run : bool
    prefix_cache : dict, optional
        Shared ``{ip_str: cidr}`` cache for the current parent-device pass.

    Returns
    -------
    dict::

        {
            "name":    str,
            "model":   str,
            "ip":      str | None,
            "action":  "created" | "updated" | "skipped" | "dry_run" | "error",
            "error":   str | None,
        }
    """
    # ── REQ 0: normalise device name to lowercase ─────────────────────────
    raw_device_id = neighbor["neighbor_device"]
    ap_name       = _normalize_device_name(raw_device_id)
    if ap_name != raw_device_id:
        log.info(
            "Normalizing device name to lowercase: %r -> %r",
            raw_device_id, ap_name,
        )

    model            = neighbor["model"]
    ip_str           = neighbor["neighbor_ip"]
    serial           = neighbor["serial"]
    ap_port          = neighbor["neighbor_interface"] or _AP_DEFAULT_IFACE_NAME
    software_version = neighbor.get("software_version")

    result: dict = {
        "name":               ap_name,
        "model":              model,
        "ip":                 ip_str,
        "action":             "skipped",
        "error":              None,
        "missing_device_type": False,
    }

    # ── Resolve parent site ───────────────────────────────────────────────
    site_field = parent_device.get("site")
    site_id    = site_field.get("id") if isinstance(site_field, dict) else site_field
    if not site_id:
        result["action"] = "error"
        result["error"]  = "Parent device has no site in NetBox"
        log.warning("%-30s  AP %r — parent has no site, skipping", ap_name, ap_name)
        return result

    # ── Resolve parent tenant (optional, inherited) ───────────────────────
    tenant_field = parent_device.get("tenant")
    tenant_id    = (
        tenant_field.get("id")
        if isinstance(tenant_field, dict)
        else tenant_field
    )

    # ── Resolve DeviceType ────────────────────────────────────────────────
    # Returns None when not found; main() aggregates all missing models and
    # writes missing_ap_models.txt after all workers finish.
    device_type_id = _resolve_device_type_id(model, nb)
    if device_type_id is None:
        result["action"]              = "error"
        result["error"]               = f"Missing NetBox DeviceType for AP model: {model}"
        result["missing_device_type"] = True
        return result

    # ── Dry-run short-circuit ─────────────────────────────────────────────
    if dry_run:
        log.info(
            "DRY-RUN  AP %-40s  model=%-25s  ip=%s  site_id=%s  sw_ver=%s",
            ap_name, model, ip_str or "(none)", site_id,
            software_version or "(none)",
        )
        result["action"] = "dry_run"
        return result

    # ── Create / update device ────────────────────────────────────────────
    log.info(
        "%-30s  model=%-25s  ip=%s", ap_name, model, ip_str or "(none)"
    )
    try:
        dev_result = nb.ensure_ap_device(
            name=ap_name,
            device_type_id=device_type_id,
            role_id=role_id,
            site_id=site_id,
            serial=serial or None,
            tenant_id=tenant_id,
            status="active",
        )
        ap_device_id = dev_result["id"]
        result["action"] = dev_result.get("_action", "skipped")

        action_word = {
            "created": "Creating",
            "updated": "Updating",
            "skipped": "Verified",
        }.get(result["action"], result["action"])
        log.info(
            "%-30s  %s device %r  dev_id=%s",
            ap_name, action_word, ap_name, ap_device_id,
        )
    except NetBoxClientError as exc:
        result["action"] = "error"
        result["error"]  = str(exc)
        log.error("%-30s  device upsert failed: %s", ap_name, exc)
        return result

    # ── PART 1: always refresh last_seen custom field ─────────────────────
    update_device_last_seen(nb, ap_device_id, ap_name)

    # ── REQ 1: update software_version custom field (idempotent) ─────────
    if software_version is not None:
        old_sw_ver = (dev_result.get("custom_fields") or {}).get("software_version")
        if old_sw_ver != software_version:
            log.info(
                "%-30s  Updating %r software_version: %r -> %r",
                ap_name, ap_name, old_sw_ver, software_version,
            )
            try:
                nb.update_device_custom_fields(
                    ap_device_id,
                    {"software_version": software_version},
                )
            except NetBoxClientError as exc:
                log.warning(
                    "%-30s  software_version update failed: %s", ap_name, exc
                )
        else:
            log.debug(
                "%-30s  software_version unchanged (%r), skipping patch",
                ap_name, software_version,
            )
    else:
        log.warning(
            "%-30s  no software_version in CDP — leaving field unchanged",
            ap_name,
        )

    # ── Ensure uplink interface ───────────────────────────────────────────
    try:
        iface_result = nb.upsert_interface(
            device_id=ap_device_id,
            name=ap_port,
            payload={"type": _AP_DEFAULT_IFACE_TYPE},
        )
        iface_id = iface_result["id"]
        log.debug(
            "%-30s  interface %r  action=%s  id=%s",
            ap_name, ap_port, iface_result.get("action"), iface_id,
        )
    except NetBoxClientError as exc:
        log.warning("%-30s  interface upsert failed: %s", ap_name, exc)
        result["error"] = f"interface: {exc}"
        return result

    # ── PART 3: lookup MAC via switch port and update AP interface ────────
    if mac_table:
        cdp_local_iface = neighbor.get("local_interface") or ""
        short_key       = normalize_to_short_interface(cdp_local_iface) if cdp_local_iface else ""
        log.debug(
            "%-30s  MAC lookup — CDP local iface=%r  short_key=%r",
            ap_name, cdp_local_iface, short_key,
        )
        if short_key and short_key in mac_table:
            found_mac = mac_table[short_key]
            log.info(
                "%-30s  MAC found (%s) for switch port %r — updating AP iface %r (id=%s)",
                ap_name, found_mac, short_key, ap_port, iface_id,
            )
            update_ap_interface_mac(nb, iface_id, found_mac, current_iface=iface_result)
        else:
            log.warning(
                "%-30s  MAC not found in table for switch port %r (CDP local=%r)",
                ap_name, short_key, cdp_local_iface,
            )

    # ── REQ 2: assign management IP using longest-match prefix ────────────
    if ip_str:
        ip_cidr = resolve_ip_cidr_from_netbox(
            ip_str=ip_str,
            nb=nb,
            site_id=site_id,
            prefix_cache=prefix_cache,
        )
        try:
            ip_result = nb.ensure_ip_on_interface(
                ip_cidr=ip_cidr,
                device_id=ap_device_id,
                interface_name=ap_port,
            )
            ip_id = ip_result["id"]
            log.debug(
                "%-30s  IP %s  action=%s  ip_id=%s",
                ap_name, ip_cidr, ip_result.get("_action"), ip_id,
            )
            # Set primary_ip4 if not already set.
            try:
                nb.set_device_primary_ip4(ap_device_id, ip_id)
            except NetBoxClientError as exc:
                log.warning(
                    "%-30s  set primary_ip4 failed: %s", ap_name, exc
                )
        except NetBoxClientError as exc:
            log.warning("%-30s  IP assign failed: %s", ap_name, exc)
            result["error"] = f"IP: {exc}"
    else:
        log.warning(
            "%-30s  no management IP in CDP — skipping IP assignment", ap_name
        )

    return result


# --------------------------------------------------------------------------- #
# Per-device worker                                                            #
# --------------------------------------------------------------------------- #


def process_device(
    device: dict,
    nb: NetBoxClient,
    role_id: int,
    args,
) -> dict:
    """
    Connect to *device*, run CDP, and build AP objects in NetBox.

    Never raises — all errors are captured in the returned summary.

    Returns
    -------
    dict::

        {
            "device":           str,
            "status":           "success" | "failed",
            "neighbors_parsed": int,
            "aps_discovered":   int,
            "aps_created":      int,
            "aps_updated":      int,
            "aps_skipped":      int,
            "aps":              list[dict],
            "errors":           list[str],
        }
    """
    device_name = device.get("name", "unknown")

    summary: dict = {
        "device":               device_name,
        "status":               "failed",
        "neighbors_parsed":     0,
        "aps_discovered":       0,
        "aps_created":          0,
        "aps_updated":          0,
        "aps_skipped":          0,
        "aps":                  [],
        "missing_device_types": [],   # models with no DeviceType in NetBox
        "errors":               [],
    }

    # ── Gate: must have a management IP ──────────────────────────────────
    if not _device_has_primary_ip(device):
        summary["errors"].append(
            "Device has no primary_ip4 or primary_ip6 in NetBox — skipped."
        )
        log.warning("%-30s  SKIPPED — no primary IP in NetBox", device_name)
        return summary

    mgmt_ip = get_device_mgmt_ip(device)
    if not mgmt_ip:
        summary["errors"].append("No primary IP in NetBox — cannot connect.")
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

    # ── Connect to parent device ──────────────────────────────────────────
    enable_secret = getattr(args, "enable_secret", None) or None
    cisco = CiscoDeviceClient(
        host=mgmt_ip,
        username=args.username,
        password=args.password,
        os_type=os_type,
        enable_secret=enable_secret,
        timeout=args.timeout,
        verify_ssl=False,
    )
    cisco.transport = args.transport

    # ── Run CDP + collect MAC table (single SSH session) ─────────────────
    mac_table: Dict[str, str] = {}
    try:
        cisco._cli_connect()
        raw_cdp: str = cisco._cli_connection.send_command("show cdp n d")
        # PART 2: build MAC hash while still connected
        mac_table = get_switch_mac_table(cisco)
        log.info("%-30s  MAC table: %d port(s) indexed", device_name, len(mac_table))
    except Exception as exc:
        summary["errors"].append(f"CDP collection failed: {exc}")
        log.error("%-30s  CDP collection failed: %s", device_name, exc)
        cisco._cli_disconnect()
        return summary

    log.info("%-30s  Collected CDP neighbors from %s", device_name, device_name)

    # ── Parse CDP output ──────────────────────────────────────────────────
    try:
        all_neighbors = parse_cdp_neighbors_detail(raw_cdp)
    except Exception as exc:
        summary["errors"].append(f"CDP parse failed: {exc}")
        log.error("%-30s  CDP parse failed: %s", device_name, exc)
        cisco._cli_disconnect()
        return summary
    finally:
        cisco._cli_disconnect()

    summary["neighbors_parsed"] = len(all_neighbors)
    log.info(
        "%-30s  %d CDP neighbor(s) parsed", device_name, len(all_neighbors)
    )

    # ── Filter to AP-only neighbors ───────────────────────────────────────
    ap_neighbors = [
        n for n in all_neighbors
        if is_cisco_ap(n["model"], n["platform_line"])
    ]
    summary["aps_discovered"] = len(ap_neighbors)
    log.info(
        "%-30s  %d AP neighbor(s) identified", device_name, len(ap_neighbors)
    )

    if not ap_neighbors:
        summary["status"] = "success"
        return summary

    # ── Log discovered APs (including name normalisation notice) ──────────
    for n in ap_neighbors:
        ap_name = _normalize_device_name(n["neighbor_device"])
        if not n["serial"]:
            log.warning(
                "%-30s  AP %r — no serial number in CDP output",
                device_name, ap_name,
            )
        if not n["software_version"]:
            log.warning(
                "%-30s  AP %r — no software_version in CDP output",
                device_name, ap_name,
            )
        log.info(
            "%-30s  Discovered AP %-40s  model=%-25s  ip=%s",
            device_name, ap_name, n["model"], n["neighbor_ip"] or "(none)",
        )

    # ── REQ 2: per-worker prefix cache (keyed by raw IP string) ──────────
    # All APs on the same parent share the same site and often live in the
    # same subnet, so caching prefix-lookup results within this pass avoids
    # duplicate API calls for APs that share a subnet.
    prefix_cache: Dict[str, str] = {}

    # ── Build each AP in NetBox ───────────────────────────────────────────
    for neighbor in ap_neighbors:
        ap_name = _normalize_device_name(neighbor["neighbor_device"])
        try:
            ap_result = _build_ap_in_netbox(
                neighbor=neighbor,
                parent_device=device,
                nb=nb,
                role_id=role_id,
                dry_run=args.dry_run,
                prefix_cache=prefix_cache,
                mac_table=mac_table,
            )
        except Exception as exc:
            ap_result = {
                "name":                ap_name,
                "model":               neighbor["model"],
                "ip":                  neighbor["neighbor_ip"],
                "action":              "error",
                "error":               str(exc),
                "missing_device_type": False,
            }
            log.error(
                "%-30s  AP %r unexpected error: %s", device_name, ap_name, exc
            )

        summary["aps"].append(ap_result)

        action = ap_result.get("action", "skipped")
        if action == "created":
            summary["aps_created"] += 1
        elif action == "updated":
            summary["aps_updated"] += 1
        elif action in ("skipped", "dry_run"):
            summary["aps_skipped"] += 1
        elif action == "error":
            summary["errors"].append(
                f"AP {ap_name!r}: {ap_result.get('error', 'unknown error')}"
            )
            if ap_result.get("missing_device_type"):
                m = ap_result["model"]
                if m not in summary["missing_device_types"]:
                    summary["missing_device_types"].append(m)

    summary["status"] = "success"
    return summary


# --------------------------------------------------------------------------- #
# Entry point                                                                  #
# --------------------------------------------------------------------------- #


def main() -> None:
    parser = build_parser()
    parser.prog        = "netbox_ap"
    parser.description = (
        "Discover Cisco Access Points via CDP and build them in NetBox "
        "(device + uplink interface + management IP + software_version)."
    )
    args = parser.parse_args()

    _configure_logging(args.log_level, getattr(args, "log_file", None))

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
            sys.exit(1)
        args.username = secrets["user"]
        args.password = secrets["password"]
        netbox_url   = secrets["netbox_url"]
        netbox_token = secrets["netbox_token"]
    else:
        missing = []
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

    if args.dry_run:
        log.info("*** DRY-RUN mode — no changes will be written to NetBox ***")

    # ── NetBox client ─────────────────────────────────────────────────────
    pool_size = max(
        getattr(args, "max_api_connections", None) or (args.max_workers + 10),
        20,
    )
    nb = NetBoxClient(
        base_url=netbox_url,
        token=netbox_token,
        verify_ssl=args.netbox_verify_ssl,
        threading=True,
        pool_size=pool_size,
    )

    # ── Device selection ──────────────────────────────────────────────────
    devices = resolve_device_list(args, nb)
    if not devices:
        log.warning("No devices to process.")
        print(json.dumps([], indent=2))
        return

    log.info(
        "Processing %d device(s), %d worker(s), transport=%s",
        len(devices), args.max_workers, args.transport,
    )

    # ── Pre-flight: ensure role + manufacturer exist (single-threaded) ────
    try:
        role_id = _resolve_role_id(nb)
        log.debug("Device role %r id=%s", _AP_ROLE_NAME, role_id)
    except NetBoxClientError as exc:
        log.error("Cannot ensure device role %r: %s", _AP_ROLE_NAME, exc)
        sys.exit(1)

    try:
        nb.ensure_manufacturer(_CISCO_MANUFACTURER)
    except NetBoxClientError as exc:
        log.warning("Manufacturer %r check failed: %s", _CISCO_MANUFACTURER, exc)

    # ── Concurrent per-device processing ─────────────────────────────────
    summaries: List[dict] = []
    with ThreadPoolExecutor(max_workers=args.max_workers) as pool:
        future_to_device = {
            pool.submit(process_device, device, nb, role_id, args): device
            for device in devices
        }
        for future in as_completed(future_to_device):
            device      = future_to_device.pop(future)
            device_name = device.get("name", "unknown")
            try:
                result = future.result()
                summaries.append(result)
                log.info(
                    "%-30s  status=%-8s  neighbors=%d  aps=%d  "
                    "created=%d  updated=%d  errs=%d",
                    device_name,
                    result.get("status", "?"),
                    result.get("neighbors_parsed", 0),
                    result.get("aps_discovered", 0),
                    result.get("aps_created", 0),
                    result.get("aps_updated", 0),
                    len(result.get("errors", [])),
                )
            except Exception as exc:
                log.error(
                    "Unexpected error for %s: %s", device_name, exc, exc_info=True
                )
                summaries.append({
                    "device":           device_name,
                    "status":           "failed",
                    "neighbors_parsed": 0,
                    "aps_discovered":   0,
                    "aps_created":      0,
                    "aps_updated":      0,
                    "aps_skipped":      0,
                    "aps":              [],
                    "errors":           [str(exc)],
                })

    summaries.sort(key=lambda s: s.get("device", ""))

    # ── Collect all missing DeviceType models across every worker ─────────
    missing_models: Set[str] = set()
    for s in summaries:
        for m in s.get("missing_device_types", []):
            missing_models.add(m)

    if missing_models:
        _write_missing_ap_models(missing_models)

    total_ok   = sum(1 for s in summaries if s.get("status") == "success")
    total_fail = len(summaries) - total_ok
    log.info(
        "DONE  devices=%d ok=%d failed=%d  "
        "aps: discovered=%d created=%d updated=%d",
        len(summaries), total_ok, total_fail,
        sum(s.get("aps_discovered", 0) for s in summaries),
        sum(s.get("aps_created", 0) for s in summaries),
        sum(s.get("aps_updated", 0) for s in summaries),
    )

    print(json.dumps(summaries, indent=2))

    if missing_models:
        sys.exit(1)


if __name__ == "__main__":
    main()
