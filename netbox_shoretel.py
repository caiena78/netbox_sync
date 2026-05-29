#!/usr/bin/env python3
"""
netbox_shoretel.py
==================
Discover ShoreTel and Mitel IP phones via LLDP on Cisco switches and model
them in NetBox.

For each selected parent Cisco switch the script:

1. Connects via SSH and runs ``show lldp neighbors detail``.
2. Parses every LLDP block and extracts: local interface, chassis ID (IP),
   port ID (MAC), serial number, and software version.
3. Filters to ShoreTel phones (System Description contains "ShoreTel IP") AND
   Mitel phones (System Name / Description contains "Mitel IP Phone" or
   MED Manufacturer: Mitel).
4. For each phone:
   a. Normalises the device name deterministically:
      - ShoreTel: ``"shoretel-<serial_lower>"``
      - Mitel:    ``"mitel-<normalized_serial>"`` (hyphens/colons stripped)
   b. Verifies the required DeviceType exists in NetBox (fatal if missing):
      - ShoreTel → model ``"IP480g"`` (slug ``ip480g``)
      - Mitel    → model ``"mitel"``  (part_number ``mitel001``)
   c. Idempotently creates or updates the phone device record.
   d. Updates ``custom_fields.software_version``.
   e. Updates ``custom_fields.last_seen`` to current UTC datetime (always).
   f. Ensures the ``eth0`` interface exists on the phone device.
   g. Resolves the chassis-ID IP to the longest-matching NetBox prefix and
      assigns the CIDR to ``eth0``.
   h. Sets ``primary_ip4`` if not already set.
   i. Creates a cable between the switch port and ``eth0`` when neither side
      already has a cable (never modifies or deletes an existing cable).
   j. Optionally sets ``mac_address`` / ``primary_mac_address`` on ``eth0``
      when a port-id MAC is found in the LLDP block.

All CLI flags are shared with ``sync_netbox_interfaces.py`` via the same
``build_parser()`` / ``resolve_device_list()`` helpers that ``netbox_ap.py``
uses — byte-for-byte identical flags.

Output
------
JSON array to **stdout** (one element per parent switch); all logs to **stderr**.

DeviceType pre-requisites
-------------------------
ShoreTel: DeviceType with model ``"IP480g"`` (slug ``ip480g``) must exist.
Mitel:    DeviceType with model ``"mitel"`` (part_number ``mitel001``) must exist.
Both are validated at startup; a missing DeviceType exits non-zero.

Phone role
----------
The script uses a device role named ``"IP Phone"``; it creates the role
automatically (purple colour) if it does not yet exist.
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
# remain byte-for-byte identical to the rest of the repo — same import list
# as netbox_ap.py.
from sync_netbox_interfaces import (
    _configure_logging,
    _device_has_primary_ip,
    build_parser,
    expand_interface_name,
    get_device_mgmt_ip,
    get_device_os_type,
    resolve_device_list,
)

# --------------------------------------------------------------------------- #
# Constants                                                                    #
# --------------------------------------------------------------------------- #

_PHONE_ROLE_NAME                = "IP Phone"
_PHONE_ROLE_COLOR               = "9c27b0"   # purple
_PHONE_IFACE_NAME               = "eth0"
_PHONE_IFACE_TYPE               = "1000base-t"
_PHONE_CABLE_TYPE               = "cat6"     # phones are always copper

# ShoreTel
_SHORETEL_DEVICE_TYPE_MODEL     = "IP480g"
_SHORETEL_MANUFACTURER          = "ShoreTel"

# Mitel
_MITEL_DEVICE_TYPE_MODEL        = "mitel"
_MITEL_DEVICE_TYPE_PART_NUMBER  = "mitel001"
_MITEL_MANUFACTURER             = "Mitel"

log = logging.getLogger("netbox_shoretel")

# --------------------------------------------------------------------------- #
# LLDP parsing                                                                 #
# --------------------------------------------------------------------------- #

_LLDP_BLOCK_SEP_RE = re.compile(r"^-{5,}", re.MULTILINE)

_LOCAL_INTF_RE = re.compile(
    r"^Local\s+Intf\s*:\s*(\S+)", re.IGNORECASE | re.MULTILINE
)
_CHASSIS_ID_RE = re.compile(
    r"^Chassis\s+id\s*:\s*(\S+)", re.IGNORECASE | re.MULTILINE
)
_PORT_ID_RE = re.compile(
    r"^Port\s+id\s*:\s*(\S+)", re.IGNORECASE | re.MULTILINE
)
_SYS_NAME_RE = re.compile(
    r"^System\s+Name\s*:\s*(.+)$", re.IGNORECASE | re.MULTILINE
)
# "Serial Number: 001049413D4B" may appear inside the System Name field
_SERIAL_RE = re.compile(r"Serial\s+Number\s*:\s*(\S+)", re.IGNORECASE)
# Software Version extracted from the System Description line (ShoreTel)
_SW_VER_RE = re.compile(r"Software\s+Version\s*:\s*(\S+)", re.IGNORECASE)

# MED section fields (Mitel phones)
# "    S/W revision: 5.2.1.1071"
_MED_SW_REV_RE = re.compile(r"S/W\s+revision\s*:\s*(\S+)", re.IGNORECASE)
# "    F/W revision: 5.2.1.1071"
_MED_FW_REV_RE = re.compile(r"F/W\s+revision\s*:\s*(\S+)", re.IGNORECASE)
# "    Serial number: 08-00-0F-D6-B3-6B"
_MED_SERIAL_RE = re.compile(
    r"^\s*Serial\s+number\s*:\s*(.+)$", re.IGNORECASE | re.MULTILINE
)
# "    Manufacturer: Mitel"
_MED_MANUF_RE = re.compile(
    r"^\s*Manufacturer\s*:\s*(.+)$", re.IGNORECASE | re.MULTILINE
)


def _extract_sys_description(block: str) -> str:
    """
    Return the content of the ``System Description:`` field from one LLDP block.

    Cisco IOS/IOS-XE puts the value on the *next* line after the field label:

        System Description:
        ShoreTel IP480g Kernel Version: ...  Software Version: ...

    We collect every non-empty line that follows until a blank line or a new
    field label (``<word> :<anything>`` pattern) is encountered.
    """
    lines = block.splitlines()
    desc_lines: List[str] = []
    in_desc = False

    for line in lines:
        if re.match(r"^\s*System\s+Description\s*:", line, re.IGNORECASE):
            in_desc = True
            # Grab any inline text on the same line
            inline = re.sub(
                r"^\s*System\s+Description\s*:\s*", "", line, flags=re.IGNORECASE
            ).strip()
            if inline:
                desc_lines.append(inline)
            continue

        if in_desc:
            stripped = line.strip()
            if not stripped:
                break
            # Stop when a new LLDP field starts (e.g. "Auto Negotiation - ...")
            # A field line looks like "Keyword: value" or "Keyword - value"
            if re.match(r"^[A-Za-z].*[-:]", stripped) and len(stripped.split()) > 1:
                # Ambiguous — keep accumulating if it could still be desc text.
                # Stop only if the line starts a recognised field pattern
                if re.match(
                    r"^(Auto\s+Neg|Time\s+Rem|System\s+Cap|Enabled\s+Cap|"
                    r"Management\s+Add|VLAN|PoE)",
                    stripped,
                    re.IGNORECASE,
                ):
                    break
            desc_lines.append(stripped)

    return " ".join(desc_lines).strip()


def parse_lldp_neighbors_detail(raw: str) -> List[dict]:
    """
    Parse raw ``show lldp neighbors detail`` output into structured dicts.

    Returns
    -------
    list[dict]
        Each entry::

            {
                "local_intf_raw":   str,          # e.g. "Gi3/0/20"
                "local_intf":       str,          # e.g. "GigabitEthernet3/0/20"
                "chassis_id":       str | None,   # chassis IP
                "port_id":          str | None,   # phone MAC (dotted lower)
                "serial":           str | None,   # raw serial as-is
                "software_version": str | None,   # version string
                "is_shoretel":      bool,
                "is_mitel":         bool,
                "is_phone":         bool,         # True when either vendor matched
                "vendor":           str | None,   # "shoretel" | "mitel" | None
            }
    """
    blocks: List[str] = _LLDP_BLOCK_SEP_RE.split(raw)
    neighbors: List[dict] = []

    for block in blocks:
        block = block.strip()
        if not block:
            continue

        # Skip blocks that do not contain a Local Intf line
        if not re.search(r"^Local\s+Intf\s*:", block, re.IGNORECASE | re.MULTILINE):
            continue

        # ── Local interface ───────────────────────────────────────────────
        local_intf_raw: Optional[str] = None
        m = _LOCAL_INTF_RE.search(block)
        if m:
            local_intf_raw = m.group(1).strip()
        local_intf = expand_interface_name(local_intf_raw) if local_intf_raw else None

        # ── Chassis ID (management IP) ────────────────────────────────────
        chassis_id: Optional[str] = None
        m = _CHASSIS_ID_RE.search(block)
        if m:
            chassis_id = m.group(1).strip()

        # ── Port ID (MAC address) ─────────────────────────────────────────
        port_id: Optional[str] = None
        m = _PORT_ID_RE.search(block)
        if m:
            port_id = m.group(1).strip().lower()

        # ── System Name raw value (used for both vendors' detection) ──────
        sys_name_val: str = ""
        m = _SYS_NAME_RE.search(block)
        if m:
            sys_name_val = m.group(1).strip()

        # ── System Description ────────────────────────────────────────────
        sys_desc = _extract_sys_description(block)

        # ── Vendor detection (ShoreTel wins on conflict — very unlikely) ──
        is_shoretel = bool(re.search(r"ShoreTel\s+IP", sys_desc, re.IGNORECASE))

        # Mitel: System Name OR System Description contains "Mitel IP Phone"
        # OR MED section has "Manufacturer: Mitel"
        med_manufacturer: str = ""
        m_manuf = _MED_MANUF_RE.search(block)
        if m_manuf:
            med_manufacturer = m_manuf.group(1).strip()
        is_mitel = (
            not is_shoretel
            and bool(
                re.search(r"Mitel\s+IP\s+Phone", sys_name_val, re.IGNORECASE)
                or re.search(r"Mitel\s+IP\s+Phone", sys_desc, re.IGNORECASE)
                or re.search(r"^mitel$", med_manufacturer, re.IGNORECASE)
            )
        )

        vendor: Optional[str] = (
            "shoretel" if is_shoretel else ("mitel" if is_mitel else None)
        )

        # ── Serial number ─────────────────────────────────────────────────
        # ShoreTel: "System Name: Serial Number: 001049413D4B"
        # Mitel:    MED "Serial number: 08-00-0F-D6-B3-6B"
        serial: Optional[str] = None
        if is_shoretel:
            sm = _SERIAL_RE.search(sys_name_val)
            if sm:
                serial = sm.group(1).strip()
        elif is_mitel:
            m_ser = _MED_SERIAL_RE.search(block)
            if m_ser:
                serial = m_ser.group(1).strip()

        # ── Software version ──────────────────────────────────────────────
        # ShoreTel: "Software Version: 804.2002.1100.0" in System Description
        # Mitel:    MED "S/W revision:" preferred over "F/W revision:"
        software_version: Optional[str] = None
        if is_shoretel:
            m = _SW_VER_RE.search(sys_desc)
            if m:
                software_version = m.group(1).strip()
        elif is_mitel:
            m_sw = _MED_SW_REV_RE.search(block)
            if m_sw:
                software_version = m_sw.group(1).strip()
            else:
                m_fw = _MED_FW_REV_RE.search(block)
                if m_fw:
                    software_version = m_fw.group(1).strip()

        neighbors.append({
            "local_intf_raw":   local_intf_raw,
            "local_intf":       local_intf,
            "chassis_id":       chassis_id,
            "port_id":          port_id,
            "serial":           serial,
            "software_version": software_version,
            "is_shoretel":      is_shoretel,
            "is_mitel":         is_mitel,
            "is_phone":         is_shoretel or is_mitel,
            "vendor":           vendor,
        })

    return neighbors


# --------------------------------------------------------------------------- #
# IP / prefix helpers  (same algorithm as netbox_ap.py)                       #
# --------------------------------------------------------------------------- #


def _resolve_ip_cidr(
    ip_str: str,
    nb: NetBoxClient,
    site_id: Optional[int] = None,
    prefix_cache: Optional[Dict[str, str]] = None,
) -> str:
    """
    Return ``"<ip>/<prefixlen>"`` using the longest-matching NetBox prefix.

    Mirrors ``resolve_ip_cidr_from_netbox`` in ``netbox_ap.py`` exactly.
    Site-scoped search first; global fallback when that returns nothing.
    """
    if prefix_cache is not None and ip_str in prefix_cache:
        return prefix_cache[ip_str]

    candidates: List[dict] = []

    if site_id is not None:
        try:
            candidates = nb.get_prefixes_containing_ip(ip_str, site_id=site_id)
        except NetBoxClientError as exc:
            log.warning("Prefix lookup (site_id=%s) for %s failed: %s", site_id, ip_str, exc)

    if not candidates:
        try:
            candidates = nb.get_prefixes_containing_ip(ip_str)
        except NetBoxClientError as exc:
            log.warning("Global prefix lookup for %s failed: %s", ip_str, exc)

    if not candidates:
        log.warning("No containing prefix for %s; using /32", ip_str)
        result = f"{ip_str}/32"
        if prefix_cache is not None:
            prefix_cache[ip_str] = result
        return result

    try:
        ip_obj = ipaddress.ip_address(ip_str)
    except ValueError:
        result = f"{ip_str}/32"
        if prefix_cache is not None:
            prefix_cache[ip_str] = result
        return result

    best_net: Optional[ipaddress.IPv4Network] = None
    for p in candidates:
        try:
            net = ipaddress.ip_network(p.get("prefix", ""), strict=False)
            if ip_obj in net:
                if best_net is None or net.prefixlen > best_net.prefixlen:
                    best_net = net
        except ValueError:
            continue

    result = f"{ip_str}/{best_net.prefixlen}" if best_net else f"{ip_str}/32"
    if prefix_cache is not None:
        prefix_cache[ip_str] = result
    return result


# --------------------------------------------------------------------------- #
# NetBox pre-flight helpers                                                    #
# --------------------------------------------------------------------------- #


def _resolve_role_id(nb: NetBoxClient) -> int:
    """Ensure the ``"IP Phone"`` device role exists and return its ID."""
    role = nb.ensure_device_role(_PHONE_ROLE_NAME, color=_PHONE_ROLE_COLOR)
    return role["id"]


def _normalize_mitel_serial(raw: str) -> str:
    """
    Return a slug-safe identifier from a Mitel serial number or MAC.

    Lowercases the string and strips hyphens, colons, and dots so that both
    "08-00-0F-D6-B3-6B" and "0800.0fd6.b36b" normalise to "08000fd6b36b".
    """
    return re.sub(r"[:\-.]", "", raw).lower()


def _resolve_device_type_id(nb: NetBoxClient) -> Optional[int]:
    """Return the NetBox DeviceType ID for ``IP480g`` (ShoreTel), or None."""
    dt = nb.get_device_type_by_model(_SHORETEL_DEVICE_TYPE_MODEL)
    if not dt:
        log.error(
            "ERROR: Missing NetBox DeviceType for ShoreTel model: %s",
            _SHORETEL_DEVICE_TYPE_MODEL,
        )
        return None
    return dt["id"]


def _resolve_mitel_device_type_id(nb: NetBoxClient) -> Optional[int]:
    """
    Return the NetBox DeviceType ID for the Mitel phone DeviceType, or None.

    Looks up by model name ``"mitel"``.  If the DeviceType is found, validates
    that its ``part_number`` equals ``"mitel001"`` and logs a warning on
    mismatch (continues anyway — the caller decides whether to abort).
    """
    dt = nb.get_device_type_by_model(_MITEL_DEVICE_TYPE_MODEL)
    if not dt:
        log.error(
            "ERROR: Missing NetBox DeviceType for Mitel model: %s",
            _MITEL_DEVICE_TYPE_MODEL,
        )
        return None
    pn = dt.get("part_number") or ""
    if pn != _MITEL_DEVICE_TYPE_PART_NUMBER:
        log.warning(
            "Mitel DeviceType %r has part_number=%r; expected %r — proceeding anyway",
            _MITEL_DEVICE_TYPE_MODEL, pn, _MITEL_DEVICE_TYPE_PART_NUMBER,
        )
    return dt["id"]


# --------------------------------------------------------------------------- #
# Cable safety helpers  (mirrors netbox_cables.py guarantee)                  #
# --------------------------------------------------------------------------- #


def _iface_member_number(iface_name: str) -> Optional[int]:
    """
    Extract the VC stack/member number from a 3-part Cisco interface name.

    Cisco Virtual Chassis interfaces follow the pattern
    ``<type><member>/<slot>/<port>`` (e.g. ``GigabitEthernet3/0/43``).
    The leading digit(s) before the first ``/`` are the VC member number.

    2-part interfaces (``GigabitEthernet0/1``) belong to a standalone
    chassis — they carry no member number and return ``None``.

    Examples
    --------
    ``GigabitEthernet3/0/43`` → ``3``
    ``GigabitEthernet1/0/1``  → ``1``
    ``GigabitEthernet0/1``    → ``None``
    """
    m = re.match(r"^[A-Za-z\-]+(\d+)((?:/\d+)+)$", iface_name)
    if not m:
        return None
    trailing_parts = m.group(2).count("/")   # number of "/" after the first number
    if trailing_parts < 2:
        # Only one "/" → 2-part interface (slot/port); no member number
        return None
    try:
        return int(m.group(1))
    except ValueError:
        return None


def _resolve_switch_device_for_iface(
    nb: NetBoxClient,
    parent_device: dict,
    iface_name: str,
) -> int:
    """
    Return the NetBox device ID that physically owns *iface_name*.

    Standalone switch
    -----------------
    Returns ``parent_device["id"]`` directly — the interface lives on the
    one device we SSH'd into.

    Virtual Chassis
    ---------------
    Cisco VC interfaces encode the member number in the name:
    ``GigabitEthernet3/0/43`` lives on the member whose ``vc_position`` is 3.
    We resolve the VC, find that member, and return its device ID.

    Falls back to ``parent_device["id"]`` with a warning when:
    - The interface name has no extractable member number (2-part names).
    - The VC member list has no entry matching the member number.
    - Any API call fails.
    """
    parent_id = parent_device.get("id")

    # Only act when the parent device is a VC member
    vc_field = parent_device.get("virtual_chassis")
    if not vc_field:
        return parent_id

    vc_id = vc_field.get("id") if isinstance(vc_field, dict) else int(vc_field)
    if not vc_id:
        return parent_id

    member_num = _iface_member_number(iface_name)
    if member_num is None:
        log.debug(
            "Interface %r has no VC member number — using parent device id=%s",
            iface_name, parent_id,
        )
        return parent_id

    try:
        members = nb.get_virtual_chassis_members(vc_id)
    except NetBoxClientError as exc:
        log.warning(
            "VC member lookup for vc_id=%s failed: %s — using parent device id=%s",
            vc_id, exc, parent_id,
        )
        return parent_id

    target = next(
        (m for m in members if m.get("vc_position") == member_num),
        None,
    )
    if target:
        log.debug(
            "Interface %r → VC member %r (vc_position=%s, device_id=%s)",
            iface_name, target.get("name"), member_num, target.get("id"),
        )
        return target["id"]

    log.warning(
        "VC vc_id=%s has no member with vc_position=%s for interface %r "
        "— using parent device id=%s",
        vc_id, member_num, iface_name, parent_id,
    )
    return parent_id


def _iface_id_on_device(
    nb: NetBoxClient,
    device_id: int,
    iface_name: str,
) -> Optional[int]:
    """
    Return the NetBox interface ID for *iface_name* on *device_id*, or None.

    Uses a direct server-side filter (device_id + name) so the result is
    exact and does not depend on fetching every interface on the device then
    doing a Python-side string comparison — which silently misses when the
    full interface list is large or when _to_dict() serialises the name field
    in an unexpected way.  This mirrors the pattern used in
    client_mac_address.py.
    """
    try:
        recs = list(nb.nb.dcim.interfaces.filter(device_id=device_id, name=iface_name))
        if recs:
            return recs[0].id
        log.warning(
            "Interface %r not found on device_id=%s in NetBox",
            iface_name, device_id,
        )
        return None
    except Exception as exc:
        log.warning(
            "Interface lookup failed device_id=%s iface=%r: %s",
            device_id, iface_name, exc,
        )
        return None


def _ensure_cable(
    nb: NetBoxClient,
    parent_device: dict,
    switch_iface_name: str,
    phone_iface_id: int,
    phone_name: str,
) -> str:
    """
    Create a cable between the switch port and the phone's ``eth0``.

    Handles Virtual Chassis correctly: the interface ``GigabitEthernet3/0/43``
    belongs to VC member 3, not necessarily to the device we SSH'd into.
    ``_resolve_switch_device_for_iface`` is called first to find the right
    member device ID before looking up the interface.

    Safety rules (mirrors netbox_cables.py):
    - Never modify or delete an existing cable.
    - Skip if either side already has a cable; log and return "skipped".
    - Returns "created", "skipped", or "error".
    """
    # Resolve the correct device (VC member or standalone) that owns this port
    switch_device_id = _resolve_switch_device_for_iface(
        nb, parent_device, switch_iface_name
    )

    sw_iface_id = _iface_id_on_device(nb, switch_device_id, switch_iface_name)
    if sw_iface_id is None:
        log.warning(
            "%-30s  cable skip — switch interface %r not found on device_id=%s",
            phone_name, switch_iface_name, switch_device_id,
        )
        return "skipped"

    # Check switch side
    try:
        if nb.interface_has_cable(sw_iface_id):
            log.info(
                "%-30s  cable skip — switch port %r (id=%s) already has a cable",
                phone_name, switch_iface_name, sw_iface_id,
            )
            return "skipped"
    except NetBoxClientError as exc:
        log.warning(
            "%-30s  cable check failed for switch port %r: %s",
            phone_name, switch_iface_name, exc,
        )
        return "error"

    # Check phone side
    try:
        if nb.interface_has_cable(phone_iface_id):
            log.info(
                "%-30s  cable skip — phone eth0 (id=%s) already has a cable",
                phone_name, phone_iface_id,
            )
            return "skipped"
    except NetBoxClientError as exc:
        log.warning(
            "%-30s  cable check failed for phone eth0 (id=%s): %s",
            phone_name, phone_iface_id, exc,
        )
        return "error"

    # Create cable — cat6 for copper phone ports
    try:
        nb.ensure_cable(sw_iface_id, phone_iface_id, _PHONE_CABLE_TYPE)
        log.info(
            "%-30s  CABLE  %s (sw id=%s)  ↔  eth0 (phone id=%s)  type=%s",
            phone_name, switch_iface_name, sw_iface_id, phone_iface_id, _PHONE_CABLE_TYPE,
        )
        return "created"
    except NetBoxClientError as exc:
        exc_str = str(exc).lower()
        # Retry without type if NetBox rejects the cat6 slug (mirrors
        # _create_cable_safe in netbox_cables.py)
        if any(h in exc_str for h in ("\"type\"", "'type'", "invalid choice", "not a valid choice")):
            log.warning(
                "%-30s  cable type %r rejected — retrying without type",
                phone_name, _PHONE_CABLE_TYPE,
            )
            try:
                nb.ensure_cable(sw_iface_id, phone_iface_id, None)
                log.info(
                    "%-30s  CABLE  %s ↔ eth0  type=(none, retry ok)",
                    phone_name, switch_iface_name,
                )
                return "created"
            except NetBoxClientError as exc2:
                log.warning("%-30s  cable retry (no type) failed: %s", phone_name, exc2)
                return "error"
        log.warning("%-30s  cable creation failed: %s", phone_name, exc)
        return "error"


# --------------------------------------------------------------------------- #
# MAC address helpers  (same pattern as netbox_ap.py)                         #
# --------------------------------------------------------------------------- #


def _get_current_datetime_iso() -> str:
    """Return current UTC datetime as ISO 8601 with 'Z' suffix."""
    return datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _update_device_last_seen(
    nb: NetBoxClient,
    device_id: int,
    device_name: str,
) -> bool:
    """
    PATCH the device's ``last_seen`` custom field to the current UTC datetime.

    Called after every device create or verify so the field is always fresh.
    Mirrors ``update_device_last_seen`` in ``netbox_ap.py``.

    Returns ``True`` on success, ``False`` on API failure (non-fatal).
    """
    ts = _get_current_datetime_iso()
    try:
        nb.update_device_custom_fields(device_id, {"last_seen": ts})
        log.info("%-30s  last_seen updated to %s", device_name, ts)
        return True
    except NetBoxClientError as exc:
        log.warning("%-30s  last_seen update failed: %s", device_name, exc)
        return False


def _update_phone_iface_mac(
    nb: NetBoxClient,
    interface_id: int,
    mac: str,
    current_iface: Optional[dict] = None,
) -> None:
    """
    Ensure a dcim.mac_addresses object exists and set both
    ``mac_address`` (string) and ``primary_mac_address`` (FK → integer ID)
    on the phone interface.

    Mirrors ``update_ap_interface_mac`` in ``netbox_ap.py`` exactly.
    """
    def _cur_mac(val) -> str:
        if isinstance(val, dict):
            return (val.get("mac_address") or "").lower()
        return (val or "").lower()

    mac_lower = mac.lower()

    # Skip if both fields already carry the correct MAC
    if current_iface is not None:
        if (
            _cur_mac(current_iface.get("mac_address")) == mac_lower
            and _cur_mac(current_iface.get("primary_mac_address")) == mac_lower
        ):
            log.debug("Interface id=%s MAC already %s — skipping", interface_id, mac)
            return

    # Step 1: ensure the dcim.mac_addresses object (create / reassign)
    try:
        mac_result = nb.ensure_mac_address(
            mac=mac,
            interface_id=interface_id,
            now_iso=_get_current_datetime_iso(),
            description="Added via netbox_shoretel.py",
        )
    except NetBoxClientError as exc:
        log.warning("MAC object ensure failed iface id=%s (%s): %s", interface_id, mac, exc)
        return

    mac_obj_id = mac_result["id"]

    # Step 2: PATCH the interface
    # primary_mac_address is a FK → must receive the integer ID, not the string
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
        log.warning("MAC update failed iface id=%s: %s", interface_id, exc)


# --------------------------------------------------------------------------- #
# Per-phone build logic                                                        #
# --------------------------------------------------------------------------- #


def build_phone_in_netbox(
    neighbor: dict,
    parent_device: dict,
    nb: NetBoxClient,
    role_id: int,
    device_type_id: int,
    dry_run: bool,
    vendor: str = "shoretel",
    prefix_cache: Optional[Dict[str, str]] = None,
) -> dict:
    """
    Create or update one phone's (ShoreTel or Mitel) NetBox representation.

    Parameters
    ----------
    neighbor : dict
        Parsed LLDP entry from :func:`parse_lldp_neighbors_detail`.
    parent_device : dict
        NetBox device dict for the Cisco switch that reported this neighbor.
    nb : NetBoxClient
    role_id : int
        NetBox DeviceRole ID for ``"IP Phone"``.
    device_type_id : int
        NetBox DeviceType ID (IP480g for ShoreTel, mitel for Mitel).
    dry_run : bool
    vendor : str
        ``"shoretel"`` or ``"mitel"``.
    prefix_cache : dict, optional
        Shared ``{ip_str: cidr}`` cache for the current parent-device pass.

    Returns
    -------
    dict
        Summary with keys: vendor, name, serial, ip, software_version,
        switch_port, action, last_seen_updated, cabled, error.
    """
    serial      = neighbor.get("serial")
    chassis_id  = neighbor.get("chassis_id")
    local_intf  = neighbor.get("local_intf")
    sw_ver      = neighbor.get("software_version")
    port_id_mac = neighbor.get("port_id")

    # ── Deterministic device name based on vendor ─────────────────────────
    if vendor == "mitel":
        # Prefer serial; fall back to port_id (MAC) if serial is absent
        name_src = serial or port_id_mac or ""
        phone_name = f"mitel-{_normalize_mitel_serial(name_src)}"
    else:
        # ShoreTel: serial is already validated as present by the caller
        phone_name = f"shoretel-{serial.lower()}"

    result: dict = {
        "vendor":            vendor,
        "name":              phone_name,
        "serial":            serial,
        "ip":                chassis_id,
        "software_version":  sw_ver,
        "switch_port":       local_intf,
        "action":            "skipped",
        "last_seen_updated": False,
        "cabled":            "skipped",
        "error":             None,
    }

    # ── Resolve parent site ───────────────────────────────────────────────
    site_field = parent_device.get("site")
    site_id    = site_field.get("id") if isinstance(site_field, dict) else site_field
    if not site_id:
        result["action"] = "error"
        result["error"]  = "Parent device has no site in NetBox"
        log.warning("%-30s  %s — parent has no site, skipping", phone_name, vendor)
        return result

    # ── Resolve parent tenant (optional, inherited) ───────────────────────
    tenant_field = parent_device.get("tenant")
    tenant_id    = (
        tenant_field.get("id") if isinstance(tenant_field, dict) else tenant_field
    )

    # ── Dry-run short-circuit ─────────────────────────────────────────────
    if dry_run:
        log.info(
            "DRY-RUN  [%s] %-40s  serial=%-20s  ip=%s  sw_ver=%s",
            vendor, phone_name, serial or "(none)",
            chassis_id or "(none)", sw_ver or "(none)",
        )
        result["action"] = "dry_run"
        return result

    # ── Create / update device ────────────────────────────────────────────
    log.info(
        "%-30s  [%s]  serial=%-20s  ip=%s",
        phone_name, vendor, serial or "(none)", chassis_id or "(none)",
    )
    try:
        # ensure_ap_device is device-type-agnostic — works for any device type
        dev_result = nb.ensure_ap_device(
            name=phone_name,
            device_type_id=device_type_id,
            role_id=role_id,
            site_id=site_id,
            serial=serial,
            tenant_id=tenant_id,
            status="active",
        )
        phone_device_id = dev_result["id"]
        result["action"] = dev_result.get("_action", "skipped")
        log.info(
            "%-30s  %s device  dev_id=%s",
            phone_name,
            {"created": "Created", "updated": "Updated", "skipped": "Verified"}.get(
                result["action"], result["action"]
            ),
            phone_device_id,
        )
    except NetBoxClientError as exc:
        result["action"] = "error"
        result["error"]  = str(exc)
        log.error("%-30s  device upsert failed: %s", phone_name, exc)
        return result

    # ── Always refresh last_seen (create AND existing devices) ────────────
    result["last_seen_updated"] = _update_device_last_seen(
        nb, phone_device_id, phone_name
    )

    # ── Update software_version custom field ──────────────────────────────
    if sw_ver:
        old_ver = (dev_result.get("custom_fields") or {}).get("software_version")
        if old_ver != sw_ver:
            log.info(
                "%-30s  software_version: %r -> %r", phone_name, old_ver, sw_ver
            )
            try:
                nb.update_device_custom_fields(
                    phone_device_id, {"software_version": sw_ver}
                )
            except NetBoxClientError as exc:
                log.warning("%-30s  software_version update failed: %s", phone_name, exc)
    else:
        log.warning("%-30s  no software_version in LLDP — field unchanged", phone_name)

    # ── Ensure eth0 interface ─────────────────────────────────────────────
    try:
        iface_result = nb.upsert_interface(
            device_id=phone_device_id,
            name=_PHONE_IFACE_NAME,
            payload={"type": _PHONE_IFACE_TYPE, "enabled": True},
        )
        iface_id = iface_result["id"]
        log.debug(
            "%-30s  interface %r  action=%s  id=%s",
            phone_name, _PHONE_IFACE_NAME, iface_result.get("action"), iface_id,
        )
    except NetBoxClientError as exc:
        log.warning("%-30s  eth0 upsert failed: %s", phone_name, exc)
        result["error"] = f"interface: {exc}"
        return result

    # ── Optional: set MAC on eth0 ─────────────────────────────────────────
    if port_id_mac:
        _update_phone_iface_mac(
            nb, iface_id, port_id_mac, current_iface=iface_result
        )

    # ── Assign management IP using longest-match prefix ───────────────────
    if chassis_id:
        ip_cidr = _resolve_ip_cidr(
            ip_str=chassis_id,
            nb=nb,
            site_id=site_id,
            prefix_cache=prefix_cache,
        )
        try:
            ip_result = nb.ensure_ip_on_interface(
                ip_cidr=ip_cidr,
                device_id=phone_device_id,
                interface_name=_PHONE_IFACE_NAME,
            )
            ip_id = ip_result["id"]
            log.debug(
                "%-30s  IP %s  action=%s  ip_id=%s",
                phone_name, ip_cidr, ip_result.get("_action"), ip_id,
            )
            try:
                nb.set_device_primary_ip4(phone_device_id, ip_id)
            except NetBoxClientError as exc:
                log.warning("%-30s  set primary_ip4 failed: %s", phone_name, exc)
        except NetBoxClientError as exc:
            log.warning("%-30s  IP assign failed: %s", phone_name, exc)
            result["error"] = f"IP: {exc}"
    else:
        log.warning("%-30s  no chassis IP in LLDP — skipping IP assignment", phone_name)

    # ── Cable: switch port ↔ phone eth0 ───────────────────────────────────
    # Safety guarantee from netbox_cables.py: never modify or delete an
    # existing cable; skip if either side already has one.
    if local_intf:
        result["cabled"] = _ensure_cable(
            nb=nb,
            parent_device=parent_device,
            switch_iface_name=local_intf,
            phone_iface_id=iface_id,
            phone_name=phone_name,
        )
    else:
        log.warning("%-30s  no local_intf in LLDP block — cable skipped", phone_name)

    return result


# --------------------------------------------------------------------------- #
# Per-device worker                                                            #
# --------------------------------------------------------------------------- #


def process_device(
    device: dict,
    nb: NetBoxClient,
    role_id: int,
    device_type_id: int,
    mitel_device_type_id: int,
    args,
) -> dict:
    """
    Connect to *device*, run LLDP, and build phone objects in NetBox.

    Handles both ShoreTel and Mitel phones.  Never raises — all errors are
    captured in the returned summary.

    Returns
    -------
    dict::

        {
            "device":              str,
            "status":              "success" | "failed",
            "neighbors_parsed":    int,
            "phones_discovered":   int,
            "phones_created":      int,
            "phones_updated":      int,
            "phones_skipped":      int,
            "cables_created":      int,
            "phones":              list[dict],
            "errors":              list[str],
        }
    """
    device_name = device.get("name", "unknown")

    summary: dict = {
        "device":            device_name,
        "status":            "failed",
        "neighbors_parsed":  0,
        "phones_discovered": 0,
        "phones_created":    0,
        "phones_updated":    0,
        "phones_skipped":    0,
        "cables_created":    0,
        "phones":            [],
        "errors":            [],
    }

    # ── Gate: must have a management IP ──────────────────────────────────
    if not _device_has_primary_ip(device):
        summary["errors"].append("Device has no primary IP in NetBox — skipped.")
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

    # ── Connect to parent switch ──────────────────────────────────────────
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

    # ── Run LLDP ──────────────────────────────────────────────────────────
    try:
        cisco._cli_connect()
        raw_lldp: str = cisco._cli_connection.send_command(
            "show lldp neighbors detail"
        )
    except Exception as exc:
        summary["errors"].append(f"LLDP collection failed: {exc}")
        log.error("%-30s  LLDP collection failed: %s", device_name, exc)
        cisco._cli_disconnect()
        return summary

    log.info("%-30s  Collected LLDP neighbors from %s", device_name, device_name)

    # ── Parse LLDP output ─────────────────────────────────────────────────
    try:
        all_neighbors = parse_lldp_neighbors_detail(raw_lldp)
    except Exception as exc:
        summary["errors"].append(f"LLDP parse failed: {exc}")
        log.error("%-30s  LLDP parse failed: %s", device_name, exc)
        cisco._cli_disconnect()
        return summary
    finally:
        cisco._cli_disconnect()

    summary["neighbors_parsed"] = len(all_neighbors)
    log.info(
        "%-30s  %d LLDP neighbor(s) parsed", device_name, len(all_neighbors)
    )

    # ── Filter to ShoreTel + Mitel phones ────────────────────────────────
    phone_neighbors = [n for n in all_neighbors if n.get("is_phone")]
    n_shoretel = sum(1 for n in phone_neighbors if n.get("is_shoretel"))
    n_mitel    = sum(1 for n in phone_neighbors if n.get("is_mitel"))
    summary["phones_discovered"] = len(phone_neighbors)
    log.info(
        "%-30s  %d phone(s) identified (%d ShoreTel, %d Mitel)",
        device_name, len(phone_neighbors), n_shoretel, n_mitel,
    )

    if not phone_neighbors:
        summary["status"] = "success"
        return summary

    # ── Log discovered phones and validate required fields ────────────────
    valid_neighbors: List[dict] = []
    for n in phone_neighbors:
        vendor = n.get("vendor", "unknown")

        # ShoreTel: serial required (used directly in device name)
        # Mitel:    serial OR port_id needed (port_id is fallback name source)
        if n.get("is_shoretel") and not n.get("serial"):
            log.warning(
                "%-30s  [shoretel] LLDP block local_intf=%r — no serial; skipping",
                device_name, n.get("local_intf_raw"),
            )
            summary["errors"].append(
                f"[shoretel] LLDP block {n.get('local_intf_raw')!r}: missing serial"
            )
            continue

        if n.get("is_mitel") and not n.get("serial") and not n.get("port_id"):
            log.warning(
                "%-30s  [mitel] LLDP block local_intf=%r — no serial or port_id; skipping",
                device_name, n.get("local_intf_raw"),
            )
            summary["errors"].append(
                f"[mitel] LLDP block {n.get('local_intf_raw')!r}: missing serial and port_id"
            )
            continue

        # Chassis ID must be a valid IPv4 address
        chassis_id = n.get("chassis_id") or ""
        try:
            ipaddress.ip_address(chassis_id)
        except ValueError:
            log.warning(
                "%-30s  [%s] chassis_id %r is not an IPv4 address; skipping",
                device_name, vendor, chassis_id,
            )
            summary["errors"].append(
                f"[{vendor}] local_intf={n.get('local_intf_raw')!r}: "
                f"chassis_id {chassis_id!r} not IPv4"
            )
            continue

        log.info(
            "%-30s  [%s] serial=%-20s  ip=%s  sw_ver=%s",
            device_name, vendor,
            n.get("serial") or "(none)",
            chassis_id,
            n.get("software_version") or "(none)",
        )
        valid_neighbors.append(n)

    # ── Per-worker prefix cache ───────────────────────────────────────────
    # Phones on the same switch share a site and often a subnet → cache prefix
    # lookups to avoid redundant API calls (same pattern as netbox_ap.py).
    prefix_cache: Dict[str, str] = {}

    # ── Build each phone in NetBox ────────────────────────────────────────
    for neighbor in valid_neighbors:
        vendor = neighbor.get("vendor", "shoretel")
        # Choose DeviceType based on vendor
        dt_id = mitel_device_type_id if vendor == "mitel" else device_type_id
        # Compute name here only for the except-branch error dict
        if vendor == "mitel":
            _ns = neighbor.get("serial") or neighbor.get("port_id") or ""
            phone_name = f"mitel-{_normalize_mitel_serial(_ns)}"
        else:
            phone_name = f"shoretel-{neighbor['serial'].lower()}"

        try:
            phone_result = build_phone_in_netbox(
                neighbor=neighbor,
                parent_device=device,
                nb=nb,
                role_id=role_id,
                device_type_id=dt_id,
                dry_run=args.dry_run,
                vendor=vendor,
                prefix_cache=prefix_cache,
            )
        except Exception as exc:
            phone_result = {
                "vendor":            vendor,
                "name":              phone_name,
                "serial":            neighbor.get("serial"),
                "ip":                neighbor.get("chassis_id"),
                "software_version":  neighbor.get("software_version"),
                "switch_port":       neighbor.get("local_intf"),
                "action":            "error",
                "last_seen_updated": False,
                "cabled":            "skipped",
                "error":             str(exc),
            }
            log.error(
                "%-30s  [%s] phone %r unexpected error: %s",
                device_name, vendor, phone_name, exc,
            )

        summary["phones"].append(phone_result)

        action = phone_result.get("action", "skipped")
        if action == "created":
            summary["phones_created"] += 1
        elif action == "updated":
            summary["phones_updated"] += 1
        elif action in ("skipped", "dry_run"):
            summary["phones_skipped"] += 1
        elif action == "error":
            summary["errors"].append(
                f"phone {phone_name!r}: {phone_result.get('error', 'unknown error')}"
            )

        if phone_result.get("cabled") == "created":
            summary["cables_created"] += 1

    summary["status"] = "success"
    return summary


# --------------------------------------------------------------------------- #
# Entry point                                                                  #
# --------------------------------------------------------------------------- #


def main() -> None:
    parser = build_parser()
    parser.prog        = "netbox_shoretel"
    parser.description = (
        "Discover ShoreTel and Mitel IP phones via LLDP and build them in NetBox "
        "(device + eth0 interface + management IP + software_version + last_seen + cable)."
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

    # ── Pre-flight: role + both DeviceTypes + manufacturers ──────────────
    # All are validated before spawning threads — fail fast with a clear message.
    try:
        role_id = _resolve_role_id(nb)
        log.debug("Device role %r id=%s", _PHONE_ROLE_NAME, role_id)
    except NetBoxClientError as exc:
        log.error("Cannot ensure device role %r: %s", _PHONE_ROLE_NAME, exc)
        sys.exit(1)

    device_type_id = _resolve_device_type_id(nb)
    if device_type_id is None:
        log.error(
            "ShoreTel DeviceType %r not found in NetBox — create it and re-run.",
            _SHORETEL_DEVICE_TYPE_MODEL,
        )
        sys.exit(1)
    log.debug("ShoreTel DeviceType %r id=%s", _SHORETEL_DEVICE_TYPE_MODEL, device_type_id)

    mitel_device_type_id = _resolve_mitel_device_type_id(nb)
    if mitel_device_type_id is None:
        log.error(
            "Mitel DeviceType %r not found in NetBox — create it and re-run.",
            _MITEL_DEVICE_TYPE_MODEL,
        )
        sys.exit(1)
    log.debug("Mitel DeviceType %r id=%s", _MITEL_DEVICE_TYPE_MODEL, mitel_device_type_id)

    for mfr in (_SHORETEL_MANUFACTURER, _MITEL_MANUFACTURER):
        try:
            nb.ensure_manufacturer(mfr)
        except NetBoxClientError as exc:
            log.warning("Manufacturer %r check failed: %s", mfr, exc)

    # ── Concurrent per-device processing ─────────────────────────────────
    summaries: List[dict] = []
    with ThreadPoolExecutor(max_workers=args.max_workers) as pool:
        future_to_device = {
            pool.submit(
                process_device, device, nb, role_id,
                device_type_id, mitel_device_type_id, args,
            ): device
            for device in devices
        }
        for future in as_completed(future_to_device):
            device      = future_to_device.pop(future)
            device_name = device.get("name", "unknown")
            try:
                result = future.result()
                summaries.append(result)
                log.info(
                    "%-30s  status=%-8s  neighbors=%d  phones=%d  "
                    "created=%d  updated=%d  cables=%d  errs=%d",
                    device_name,
                    result.get("status", "?"),
                    result.get("neighbors_parsed", 0),
                    result.get("phones_discovered", 0),
                    result.get("phones_created", 0),
                    result.get("phones_updated", 0),
                    result.get("cables_created", 0),
                    len(result.get("errors", [])),
                )
            except Exception as exc:
                log.error(
                    "Unexpected error for %s: %s", device_name, exc, exc_info=True
                )
                summaries.append({
                    "device":            device_name,
                    "status":            "failed",
                    "neighbors_parsed":  0,
                    "phones_discovered": 0,
                    "phones_created":    0,
                    "phones_updated":    0,
                    "phones_skipped":    0,
                    "cables_created":    0,
                    "phones":            [],
                    "errors":            [str(exc)],
                })

    summaries.sort(key=lambda s: s.get("device", ""))

    total_ok   = sum(1 for s in summaries if s.get("status") == "success")
    total_fail = len(summaries) - total_ok
    log.info(
        "DONE  devices=%d ok=%d failed=%d  "
        "phones: discovered=%d created=%d updated=%d  cables=%d",
        len(summaries), total_ok, total_fail,
        sum(s.get("phones_discovered", 0) for s in summaries),
        sum(s.get("phones_created", 0)    for s in summaries),
        sum(s.get("phones_updated", 0)    for s in summaries),
        sum(s.get("cables_created", 0)    for s in summaries),
    )

    print(json.dumps(summaries, indent=2))


if __name__ == "__main__":
    main()
