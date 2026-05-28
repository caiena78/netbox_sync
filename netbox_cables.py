#!/usr/bin/env python3
"""
netbox_cables.py
================
Discover physical connectivity via CDP and create cables in NetBox.

SAFETY GUARANTEES
- Never modifies or deletes an existing cable.
- Skips any interface that already has a cable on either side.
- Skips SVIs, LAGs, Loopbacks, Tunnels, and other logical interfaces.
- Skips neighbors whose device cannot be resolved in NetBox.

Virtual Chassis support
-----------------------
Both source devices and CDP neighbors are resolved with a "VC-first" strategy.

When a neighbor name like ``"3850-E-4"`` is received:
  1. The script searches for a Virtual Chassis named ``"3850-E-4"`` first.
  2. If found, the first member device is selected using this priority order:
       a. Device named ``"{vc_name}(1)"``  e.g. ``"3850-E-4(1)"`` — explicit
          slot-1 naming convention used by NetBox for VC members.
       b. Member whose ``vc_position`` field is 1.
       c. Member with the smallest ``vc_position`` (``None`` sorted last).
       d. Name ascending.
  3. All cables are terminated on the *member* device; the VC object itself
     is never used as a cable endpoint.
  4. If no VC exists, a regular device lookup is attempted.

Two-path VC discovery is used to guard against pynetbox edge cases:
  - Primary:  ``dcim.virtual_chassis.get(name=…)``
  - Fallback: ``dcim.virtual_chassis.filter(name=…)`` (avoids ValueError
    when the primary path silently returns None on multiple results)

Cable type mapping
------------------
Optic classification (from raw transceiver output):
  SR / SX / LRM  → "multi mode om3"
  LR / LX / ER / ZR / EX → "single mode"
  Unknown / no transceiver → type field omitted from NetBox payload

If NetBox rejects the type (400 "invalid choice"), the cable is retried
without a type field.  If that also fails the pair is skipped and logged.

Output
------
JSON array to **stdout** (one entry per device); logs to **stderr**.

Usage examples
--------------
    python netbox_cables.py --device-filter '{"status":"active"}'
    python netbox_cables.py --device sw1 --dry-run
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Set

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
# Platform slug → os_type                                                      #
# --------------------------------------------------------------------------- #

PLATFORM_SLUG_MAP: Dict[str, str] = {
    "iosxe": "iosxe", "ios-xe": "iosxe", "ios_xe": "iosxe",
    "cisco-iosxe": "iosxe", "cisco_iosxe": "iosxe",
    "nxos": "nxos", "nx-os": "nxos", "nx_os": "nxos",
    "cisco-nxos": "nxos", "cisco_nxos": "nxos",
    "ios": "ios", "cisco-ios": "ios", "cisco_ios": "ios",
}

# Interface name prefixes that must never have a physical cable
_LOGICAL_PREFIXES: tuple = (
    "Vlan", "vlan", "Loopback", "loopback",
    "Port-channel", "port-channel",
    "Tunnel", "tunnel", "Null", "null",
    "BDI", "bdi", "nve", "Nve",
    "AppGigabit", "Mgmt", "mgmt",
)

log = logging.getLogger("netbox_cables")

# --------------------------------------------------------------------------- #
# Optic classification                                                         #
# --------------------------------------------------------------------------- #

# Matches SR-family optics (multimode): SR, SX, LRM, SRL, BASE-SR, SRn
_SR_RE = re.compile(
    r"\b(?:BASE[-_]SR|SR[0-9]*|SX|LRM|SRL)\b", re.IGNORECASE
)
# Matches LR-family optics (singlemode): LR, LX, LH (Cisco long-haul),
# ER, ZR, EX, BASE-LR, LRn, ERn
_LR_RE = re.compile(
    r"\b(?:BASE[-_]LR|LR[0-9]*|LX|LH|ER[0-9]*|ZR[0-9]*|EX)\b", re.IGNORECASE
)

# Phrases that confirm NO transceiver / optic is installed.
# When any of these appear in the raw output the port is treated as copper.
_NO_TRANSCEIVER_HINTS: tuple = (
    "no optical",
    "no transceiver",
    "not present",
    "not installed",
    "sfp absent",
    "sfpabsent",
    "no sfp",
    "unrecognized sfp",
    "% invalid input",
    "not supported",
    "% error",
)

# NetBox cable type slugs — must match the choices in dcim/choices.py exactly.
#
#   mmf-om3  → Multimode Fiber (OM3)      used for SR optics (≤300 m)
#   smf-os2  → Single-mode Fiber (OS2)    used for LR / LH / ER / ZR optics
#   cat6     → CAT6 copper                used when no SFP / transceiver found
#
# If NetBox rejects any slug the cable is retried without a type so the
# connection is still created (see _create_cable_safe).
_OPTIC_CABLE_TYPE: Dict[str, str] = {
    "SR":     "mmf-om3",   # multimode OM3
    "LR":     "smf-os2",   # single-mode OS2
    "COPPER": "cat6",      # no transceiver — RJ-45 copper port
}


def _classify_optic(raw: str) -> Optional[str]:
    """
    Classify transceiver output and return one of four values:

    ``"SR"``     — short-reach multimode optic detected (SR, SX, LRM …)
    ``"LR"``     — long-reach single-mode optic detected (LR, LX, LH, ER, ZR …)
    ``"COPPER"`` — no transceiver / no SFP installed (RJ-45 copper port)
    ``None``     — transceiver present but type is unrecognised; caller
                   should omit the cable type so NetBox accepts the record

    The distinction between ``"COPPER"`` and ``None`` is intentional:
    copper ports get ``cat6``; unrecognised optics get no type at all
    so the cable is not rejected.
    """
    if not raw:
        # Empty output almost always means a copper port — the transceiver
        # query returned nothing or the command is not applicable.
        return "COPPER"

    raw_l = raw.lower()

    # Explicit "no transceiver" / command-error messages → copper port
    if any(h in raw_l for h in _NO_TRANSCEIVER_HINTS):
        return "COPPER"

    # Optic type classification (SR wins if both patterns match)
    if _SR_RE.search(raw):
        return "SR"
    if _LR_RE.search(raw):
        return "LR"

    # Transceiver is present but we cannot classify it (e.g. proprietary
    # QSFP or unsupported module).  Return None so no type is set.
    return None


def _cable_type_for_optic(optic_class: Optional[str]) -> Optional[str]:
    """
    Map an optic classification to the correct NetBox cable type slug.

    Returns
    -------
    str
        NetBox ``cable.type`` slug, or ``None`` when the optic class is
        unknown (``None`` input).  ``None`` tells the caller to omit the
        ``type`` field so NetBox uses its own default and the cable is not
        rejected.
    """
    if optic_class is None:
        return None   # unknown optic — omit type, let NetBox decide
    return _OPTIC_CABLE_TYPE.get(optic_class)


# --------------------------------------------------------------------------- #
# Cable creation with type-rejection retry                                     #
# --------------------------------------------------------------------------- #

# Substrings in a pynetbox error string that indicate the cable type value
# was rejected by NetBox (so we can retry without it).
_TYPE_ERROR_HINTS = ("\"type\"", "'type'", "invalid choice", "is not a valid choice",
                     "does not exist", "type field")


def _create_cable_safe(
    nb: NetBoxClient,
    local_id: int,
    remote_id: int,
    cable_type: Optional[str],
    device_name: str,
    local_iface: str,
    remote_iface: str,
    remote_dev: str,
) -> bool:
    """
    Create a NetBox cable, retrying without ``type`` if the type slug is
    rejected with a 400 error.

    Returns ``True`` on success, ``False`` when the pair must be skipped.

    Retry logic
    -----------
    1. Try with *cable_type* (when not None).
    2. If NetBox returns a 400 whose message mentions the ``type`` field or
       "invalid choice" → retry *once* without a type field.
    3. If the retry also fails → log and return False.
    """
    def _attempt(ct: Optional[str]) -> bool:
        try:
            nb.ensure_cable(local_id, remote_id, ct)
            log.info(
                "%-30s  CABLE %-35s ↔ %-35s @%s  type=%s",
                device_name, local_iface, remote_iface, remote_dev,
                ct if ct else "(none)",
            )
            return True
        except NetBoxClientError as exc:
            exc_lower = str(exc).lower()
            # Detect type-field-specific 400 rejection
            if ct and any(hint in exc_lower for hint in _TYPE_ERROR_HINTS):
                log.warning(
                    "%-30s  cable type %r rejected by NetBox — retrying without type",
                    device_name, ct,
                )
                # Retry without type — do NOT recurse; call directly
                try:
                    nb.ensure_cable(local_id, remote_id, None)
                    log.info(
                        "%-30s  CABLE %-35s ↔ %-35s @%s  type=(none, retry)",
                        device_name, local_iface, remote_iface, remote_dev,
                    )
                    return True
                except NetBoxClientError as exc2:
                    log.warning(
                        "%-30s  cable retry (no type) also failed: %s",
                        device_name, exc2,
                    )
                    return False
            log.warning(
                "%-30s  cable %r ↔ %r failed: %s",
                device_name, local_iface, remote_iface, exc,
            )
            return False

    return _attempt(cable_type)


# --------------------------------------------------------------------------- #
# CLI parser                                                                   #
# --------------------------------------------------------------------------- #

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Discover CDP neighbors and create cables in NetBox.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    nb = p.add_argument_group("NetBox connection")
    nb.add_argument("--netbox-url",
                    default=os.environ.get("NETBOX_URL", ""),
                    help="NetBox base URL (env: NETBOX_URL). Ignored when Vault is configured.")
    nb.add_argument("--netbox-token",
                    default=os.environ.get("NETBOX_API", ""),
                    help="NetBox API token (env: NETBOX_API). Ignored when Vault is configured.")
    nb.add_argument("--netbox-verify-ssl",
                    action=argparse.BooleanOptionalAction, default=True)

    sel = p.add_argument_group("Device selection")
    sel.add_argument("--device",      metavar="NAME",    help="Single device")
    sel.add_argument("--devices",     metavar="NAME,...", help="Comma-separated devices")
    sel.add_argument("--device-file", metavar="PATH",
                     help="File with one device per line")
    sel.add_argument("--device-filter", default="{}",
                     metavar="JSON", help="NetBox DCIM filter (default: all)")
    sel.add_argument(
        "--site-slug",
        default="",
        metavar="SLUG",
        help=(
            "Limit cable discovery to devices in this NetBox site (site slug). "
            "Example: --site-slug lakeview.  Stacks with --device-filter.  "
            "When omitted all sites are included."
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
                      help="Enable secret (env: CISCO_ENABLE_PWD)")

    run = p.add_argument_group("Runtime")
    run.add_argument("--transport",
                     choices=["auto", "cli", "netconf", "restconf"],
                     default="auto")
    run.add_argument("--dry-run", action="store_true",
                     help="Discover only; no NetBox writes")
    run.add_argument(
        "--force",
        action="store_true",
        help=(
            "Replace cables that connect to the wrong device. "
            "Without --force, any interface that already has a cable is "
            "skipped unconditionally. With --force, the script checks whether "
            "the existing cable matches the CDP-discovered peer. If it does not "
            "match, the wrong cable is deleted and the correct one is created. "
            "Cables that are already correct are left untouched."
        ),
    )
    run.add_argument("--max-workers", type=int, default=5)
    run.add_argument("--timeout",     type=int, default=30)
    run.add_argument("--log-level",
                     choices=["DEBUG", "INFO", "WARNING", "ERROR"],
                     default="INFO")
    run.add_argument(
        "--log-file",
        metavar="PATH",
        default=None,
        help=(
            "Also write log output to this file (appended, UTF-8). "
            "Stderr output is always kept regardless of this setting."
        ),
    )

    vault_grp = p.add_argument_group(
        "Vault authentication",
        "HashiCorp Vault AppRole credentials. CLI args take precedence over env vars. "
        "Use --use-env-only to restrict to environment variables only.",
    )
    add_vault_parser_args(vault_grp)

    return p


# --------------------------------------------------------------------------- #
# Device / management IP helpers                                               #
# --------------------------------------------------------------------------- #

def _device_has_primary_ip(device: dict) -> bool:
    """
    Return ``True`` when the device has at least one primary IP in NetBox
    (``primary_ip4`` or ``primary_ip6``).

    ``oob_ip`` alone is not accepted — a primary IP is a hard prerequisite
    for cable discovery.
    """
    return bool(device.get("primary_ip4") or device.get("primary_ip6"))


def _site_slug_matches(device: dict, site_slug: str) -> bool:
    """
    Return ``True`` when *device* is in the site identified by *site_slug*,
    or when *site_slug* is empty (no filter).

    Devices with no site assignment are always excluded when a slug is given.
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


def _get_mgmt_ip(device: dict) -> Optional[str]:
    """Return the first available management IP (without prefix length)."""
    for field in ("primary_ip4", "primary_ip6", "oob_ip"):
        ip = device.get(field)
        if not ip:
            continue
        addr = ip.get("address", "") if isinstance(ip, dict) else str(ip)
        if addr:
            return addr.split("/")[0]
    return None


def _get_os_type(device: dict) -> Optional[str]:
    platform = device.get("platform")
    if not platform:
        return None
    slug = (
        (platform.get("slug") or platform.get("name") or "").lower().strip()
        if isinstance(platform, dict) else str(platform).lower().strip()
    )
    return PLATFORM_SLUG_MAP.get(slug)


# --------------------------------------------------------------------------- #
# Virtual Chassis resolution helpers                                           #
# --------------------------------------------------------------------------- #

def _pick_vc_member(members: List[dict]) -> Optional[dict]:
    """
    Return the deterministic "first" member of a virtual chassis.

    Sort order:
    1. Smallest ``vc_position`` (members with ``None`` position sorted last).
    2. Name ascending.
    3. First in the API-returned list.
    """
    if not members:
        return None

    def _key(m: dict):
        pos = m.get("vc_position")
        return (0 if pos is not None else 1, pos or 0, m.get("name", ""))

    return sorted(members, key=_key)[0]


def _resolve_vc(name: str, nb: NetBoxClient) -> Optional[dict]:
    """
    Look up a virtual chassis by *name* and return its first member device.

    Two-path VC lookup
    ------------------
    1. ``nb.find_virtual_chassis(name)`` — uses pynetbox ``.get(name=…)``.
       This can silently return ``None`` if pynetbox raises a ``ValueError``
       (multiple results) internally.
    2. Fallback: direct ``.filter(name=…)`` call so that path-1 failures
       do not hide a real VC.

    Member selection priority
    -------------------------
    1. Device whose name is ``"{vc_name}(1)"`` — the explicit slot-1 naming
       convention NetBox uses when VC members are numbered (e.g. ``"3850-E-4(1)"``).
    2. Member whose ``vc_position`` field is ``1``.
    3. Member with the smallest ``vc_position`` (``None`` sorted last).
    4. Name ascending.
    5. First returned by the API.

    A management IP is **not** required — for cable termination we only need
    the device ID to look up interface records.
    """
    try:
        # Normalise to lowercase before every NetBox search so that case
        # differences between CDP-reported names and NetBox records do not
        # prevent a match (e.g. "3850-E-4" vs "3850-e-4").
        search_name = name.lower()

        # ── Path 1: standard helper (uses .get()) ─────────────────────────
        vc = nb.find_virtual_chassis(search_name)

        # ── Path 2: .filter() fallback ────────────────────────────────────
        # find_virtual_chassis() can return None when pynetbox's .get()
        # raises a ValueError (multiple matches) that is caught internally.
        # filter() returns a list and never raises on multiple results.
        if vc is None:
            try:
                vc_list = list(nb.nb.dcim.virtual_chassis.filter(name=search_name))
                if vc_list:
                    vc = nb._to_dict(vc_list[0])
                    log.debug(
                        "VC %r found via filter() fallback (id=%s)",
                        name, vc.get("id"),
                    )
            except Exception as inner:
                log.debug("VC filter fallback for %r failed: %s", name, inner)

        if not vc:
            return None

        vc_id   = vc["id"]
        vc_name = vc.get("name", name)

        members = nb.get_virtual_chassis_members(vc_id)
        if not members:
            log.debug("VC %r (id=%s) has no member devices", vc_name, vc_id)
            return None

        # ── Priority 1: explicit "(1)" name suffix ────────────────────────
        # NetBox names VC members as "{vc_name}(N)" e.g. "3850-E-4(1)".
        # This is the most reliable indicator of the primary member.
        slot1_name = f"{vc_name}(1)"
        for m in members:
            if m.get("name", "") == slot1_name:
                m["_vc_name"] = vc_name
                m["_vc_id"]   = vc_id
                log.debug(
                    "VC %r → member %r (slot-1 name match)",
                    vc_name, m["name"],
                )
                return m

        # ── Priority 2: vc_position == 1 ─────────────────────────────────
        for m in members:
            if m.get("vc_position") == 1:
                m["_vc_name"] = vc_name
                m["_vc_id"]   = vc_id
                log.debug(
                    "VC %r → member %r (vc_position=1)",
                    vc_name, m.get("name"),
                )
                return m

        # ── Priority 3: deterministic sort ───────────────────────────────
        member = _pick_vc_member(members)
        if member:
            member["_vc_name"] = vc_name
            member["_vc_id"]   = vc_id
            log.debug(
                "VC %r → member %r (deterministic pick, vc_position=%s)",
                vc_name, member.get("name"), member.get("vc_position"),
            )
            return member

    except Exception as exc:
        log.debug("VC lookup failed for %r: %s", name, exc)

    return None


# --------------------------------------------------------------------------- #
# Device resolution                                                            #
# --------------------------------------------------------------------------- #

def _resolve_single_device(name: str, nb: NetBoxClient) -> Optional[dict]:
    """
    Resolve a *source* device name (the device we will SSH into).

    For source devices a management IP is required.

    Resolution order
    ----------------
    1. Virtual chassis by exact name → pick first member **with an IP**.
    2. Regular device lookup by exact name.
    """
    # ── 1. Virtual chassis ─────────────────────────────────────────────────
    try:
        vc = nb.find_virtual_chassis(name.lower())
        if vc:
            members = nb.get_virtual_chassis_members(vc["id"])
            # Apply deterministic sort; require a management IP
            for m in sorted(members, key=lambda m: (
                0 if m.get("vc_position") is not None else 1,
                m.get("vc_position") or 0,
                m.get("name", ""),
            )):
                if _get_mgmt_ip(m):
                    m["_vc_name"] = vc.get("name", name)
                    m["_vc_id"]   = vc["id"]
                    return m
    except Exception:
        pass

    # ── 2. Regular device ──────────────────────────────────────────────────
    return nb.get_device(name=name.lower())


def _resolve_device_list(args: argparse.Namespace, nb: NetBoxClient) -> List[dict]:
    site_slug: str = getattr(args, "site_slug", "") or ""

    if args.device:
        d = _resolve_single_device(args.device.strip(), nb)
        if d and _site_slug_matches(d, site_slug):
            return [d]
        return []
    if args.devices:
        result = []
        for name in [n.strip() for n in args.devices.split(",") if n.strip()]:
            d = _resolve_single_device(name, nb)
            if d and _site_slug_matches(d, site_slug):
                result.append(d)
        return result
    if args.device_file:
        try:
            with open(args.device_file) as fh:
                names = [ln.strip() for ln in fh
                         if ln.strip() and not ln.strip().startswith("#")]
        except OSError as exc:
            log.error("Cannot read --device-file %r: %s", args.device_file, exc)
            sys.exit(1)
        result = []
        for name in names:
            d = _resolve_single_device(name, nb)
            if d and _site_slug_matches(d, site_slug):
                result.append(d)
        return result
    try:
        nb_filter: dict = json.loads(args.device_filter)
    except json.JSONDecodeError as exc:
        log.error("Invalid --device-filter JSON: %s", exc)
        sys.exit(1)
    if site_slug:
        nb_filter["site"] = site_slug
    devices = nb.get_devices(filters=nb_filter)
    log.info("NetBox returned %d device(s) matching filter %s", len(devices), nb_filter)
    return devices


# --------------------------------------------------------------------------- #
# Neighbor device resolution                                                   #
# --------------------------------------------------------------------------- #

def _resolve_neighbor(
    nb: NetBoxClient,
    neighbor_name: str,
    neighbor_ip: Optional[str],
) -> Optional[dict]:
    """
    Resolve a CDP neighbor name to a NetBox device dict for cable termination.

    A management IP is **not** required — only the device ID is needed to
    look up and create interface records.

    Resolution order
    ----------------
    1. **Virtual Chassis lookup** — full cleaned name (lowercase).
    2. **Regular device lookup** — full cleaned name (lowercase).
       When the CDP-reported name is an FQDN (contains ``"."``), the full
       FQDN is tried first so that any device stored with that exact name
       in NetBox is found without unnecessary stripping.
    3. **FQDN hostname strip** — when the name is an FQDN, strip the
       domain suffix (e.g. ``"umc-acb-mer-cucm-8300-r1.lcmchealth.org"``
       → ``"umc-acb-mer-cucm-8300-r1"``) and retry steps 1 + 2.
    4. **Numeric-suffix strip** — strip trailing ``-<digits>``
       (e.g. ``"3850-E-4"`` → ``"3850-E"``) and try VC lookup only.
       This is a last resort for environments where the CDP-reported name
       includes a unit number that is not part of the VC name in NetBox.
    5. **Primary-IP fallback** — IPAM lookup by management IP.
    """
    # ── Strip serial-number suffix (parenthetical) ───────────────────────
    # Some Cisco platforms (NX-OS in particular) append a hardware serial
    # number to the CDP device-id:
    #   "UMC-ACB-MER-COR-01(JAF1730AKBT)"  →  "UMC-ACB-MER-COR-01"
    # Strip everything from the first "(" to the end of the string so the
    # resulting name matches what is stored in NetBox.
    clean_name = re.sub(r"\s*\([^)]*\).*$", "", neighbor_name).strip()
    if clean_name != neighbor_name:
        log.debug(
            "Neighbor %r: stripped serial suffix → %r",
            neighbor_name, clean_name,
        )

    # All lookups are performed with the name lowercased so that
    # case differences between the CDP report and NetBox are ignored.
    clean_lower = clean_name.lower()

    # ── FQDN detection ────────────────────────────────────────────────────
    # When the CDP device-id is a fully-qualified domain name (contains a
    # dot), try the full FQDN first so that devices stored with their FQDN
    # in NetBox are found.  If the FQDN lookup fails, fall back to the
    # hostname-only portion (everything before the first dot).
    #
    # Example: "umc-acb-mer-cucm-8300-r1.lcmchealth.org"
    #   candidate 1 → "umc-acb-mer-cucm-8300-r1.lcmchealth.org"  (full FQDN)
    #   candidate 2 → "umc-acb-mer-cucm-8300-r1"                 (hostname only)
    is_fqdn    = "." in clean_lower
    candidates: List[str] = [clean_lower]

    if is_fqdn:
        hostname_only = clean_lower.split(".")[0]
        if hostname_only and hostname_only != clean_lower:
            candidates.append(hostname_only)
            log.debug(
                "Neighbor %r: FQDN detected — will also search by "
                "hostname-only %r if full FQDN is not found in NetBox",
                neighbor_name, hostname_only,
            )

    # ── Steps 1 + 2: VC then device, for each candidate name ─────────────
    for candidate in candidates:

        # Emit an INFO line when falling back from FQDN to hostname-only so
        # operators can see the resolution path without enabling DEBUG.
        if is_fqdn and candidate != clean_lower:
            log.info(
                "Neighbor %r: FQDN %r not found in NetBox — "
                "retrying with hostname-only %r",
                neighbor_name, clean_lower, candidate,
            )

        # Step 1 — Virtual Chassis lookup (always first)
        d = _resolve_vc(candidate, nb)
        if d:
            log.info(
                "Neighbor %r → Virtual Chassis %r → member %r",
                neighbor_name, d.get("_vc_name"), d.get("name"),
            )
            return d

        # Step 2 — regular device lookup via filter() not get().
        # pynetbox's get() raises ValueError when the API returns more than
        # one match for the name filter — that error was previously swallowed
        # by "except Exception: pass", silently preventing the device from
        # being found even when it exists in NetBox.
        # filter() always returns a list so it never raises ValueError.
        try:
            recs = list(nb.nb.dcim.devices.filter(name=candidate))
            if recs:
                d = nb._to_dict(recs[0])
                if is_fqdn and candidate != clean_lower:
                    log.info(
                        "Neighbor %r: found in NetBox as hostname-only %r "
                        "(after stripping FQDN suffix)",
                        neighbor_name, candidate,
                    )
                else:
                    log.debug("Neighbor %r → device %r", neighbor_name, candidate)
                return d
        except Exception as exc:
            log.debug(
                "Neighbor %r: device lookup for %r failed (%s: %s) — skipping",
                neighbor_name, candidate, type(exc).__name__, exc,
            )

    # ── Step 4: numeric-suffix strip → VC only ───────────────────────────
    # Try stripping a trailing unit number from each candidate and look for
    # a VC with the resulting base name.  Device lookup is intentionally
    # skipped here because a stripped name is unlikely to be a real device.
    for candidate in candidates:
        m = re.match(r"^(.+?)-\d+$", candidate)
        if not m:
            continue
        base = m.group(1)
        if not base:
            continue
        log.debug("Neighbor %r: trying base VC name %r", neighbor_name, base)
        d = _resolve_vc(base, nb)
        if d:
            log.info(
                "Neighbor %r → Virtual Chassis %r (base-name strip) → member %r",
                neighbor_name, d.get("_vc_name"), d.get("name"),
            )
            return d

    # ── Step 5: primary-IP fallback ──────────────────────────────────────
    if neighbor_ip:
        try:
            ip_records = list(nb.nb.ipam.ip_addresses.filter(address=neighbor_ip))
            for ip_rec in ip_records:
                assigned_obj = getattr(ip_rec, "assigned_object", None)
                if assigned_obj:
                    dev_rec = getattr(assigned_obj, "device", None)
                    if dev_rec:
                        d = nb.get_device(id=int(dev_rec.id))
                        if d:
                            log.debug(
                                "Neighbor %r resolved via IP %s → device %r",
                                neighbor_name, neighbor_ip, d.get("name"),
                            )
                            return d
        except Exception as exc:
            log.debug(
                "IP-based lookup for %r (%s) failed: %s",
                neighbor_name, neighbor_ip, exc,
            )

    return None


# --------------------------------------------------------------------------- #
# Interface safety checks                                                      #
# --------------------------------------------------------------------------- #

def _is_logical_interface(name: str) -> bool:
    """Return True for interface types that must never receive a cable."""
    return any(name.startswith(p) for p in _LOGICAL_PREFIXES)


def _clear_connected_if_needed(
    nb: NetBoxClient,
    interface_id: int,
    interface_rec: dict,
    iface_label: str,
    device_name: str,
) -> bool:
    """
    Clear ``mark_connected`` on *interface_id* if it is currently ``True``.

    NetBox rejects cable creation on any interface that has
    ``mark_connected=True`` — the two states are mutually exclusive.  This
    function clears the flag so cable creation can proceed.

    Uses the already-fetched *interface_rec* to decide whether a write is
    needed, avoiding an extra API round-trip when the flag is already ``False``.

    Parameters
    ----------
    interface_rec : dict
        Full interface dict from ``_get_or_create_interface`` (contains
        ``mark_connected``).
    iface_label : str
        Short human-readable name used in log messages.

    Returns
    -------
    bool
        ``True`` when the flag was already clear or was successfully cleared.
        ``False`` when the PATCH failed (cable creation will likely also fail;
        the caller logs the cable failure separately).
    """
    if not interface_rec.get("mark_connected"):
        return True   # already False — nothing to do

    try:
        nb.update_interface(interface_id, {"mark_connected": False})
        log.info(
            "%-30s  Cleared connected flag on interface %s before cable creation",
            device_name, iface_label,
        )
        return True
    except NetBoxClientError as exc:
        log.warning(
            "%-30s  Failed to clear connected flag on %s: %s "
            "— cable creation may fail",
            device_name, iface_label, exc,
        )
        return False   # non-fatal: let _create_cable_safe surface the real error


def _get_or_create_interface(
    nb: NetBoxClient,
    device_id: int,
    iface_name: str,
) -> Optional[dict]:
    """
    Return the NetBox interface record for *iface_name* on *device_id*.

    Creates a minimal placeholder (``type=other``) if the interface does
    not yet exist in NetBox.  Returns ``None`` on any error.
    """
    try:
        existing = list(
            nb.nb.dcim.interfaces.filter(device_id=device_id, name=iface_name)
        )
        if existing:
            return nb._to_dict(existing[0])
        payload = {"device": device_id, "name": iface_name, "type": "other"}
        rec = nb.nb.dcim.interfaces.create(payload)
        log.debug(
            "Created placeholder interface %r on device_id=%s", iface_name, device_id
        )
        return nb._to_dict(rec)
    except Exception as exc:
        log.warning(
            "Could not get/create interface %r on device_id=%s: %s",
            iface_name, device_id, exc,
        )
        return None


# --------------------------------------------------------------------------- #
# Per-device cable processing                                                  #
# --------------------------------------------------------------------------- #

def process_device_cables(
    device: dict,
    nb: NetBoxClient,
    args: argparse.Namespace,
) -> dict:
    """
    Discover CDP neighbors on one device and create cables in NetBox.

    SAFETY GUARANTEES (unchanged)
    - Never modifies an existing cable.
    - Skips any pair where either interface already has a cable.
    - Skips logical interfaces (SVIs, LAGs, loopbacks, tunnels …).
    - Skips neighbors that cannot be resolved in NetBox.

    Returns a JSON-serialisable summary dict.
    """
    device_name = device.get("name", "unknown")
    device_id   = device.get("id")

    summary: dict = {
        "device":                 device_name,
        "status":                 "failed",
        "neighbors_seen":         0,
        "cables_created":         0,
        "cables_replaced":        0,
        "skipped_existing_cable": 0,
        "skipped_missing_device": 0,
        "skipped_logical_iface":  0,
        "errors":                 [],
    }

    # ── Hard gate: primary IP required ────────────────────────────────────
    if not _device_has_primary_ip(device):
        summary["errors"].append(
            "Device has no primary_ip4 or primary_ip6 in NetBox — skipped. "
            "Assign a primary IP in NetBox before running cable discovery."
        )
        log.warning(
            "%-30s  SKIPPED — no primary_ip4 / primary_ip6 in NetBox",
            device_name,
        )
        return summary

    mgmt_ip = _get_mgmt_ip(device)
    if not mgmt_ip:
        summary["errors"].append("No primary IP — cannot connect.")
        return summary

    os_type = _get_os_type(device)
    if not os_type:
        summary["errors"].append(
            f"Unknown platform {device.get('platform')!r} — add to PLATFORM_SLUG_MAP."
        )
        return summary

    log.info("%-30s  ip=%-18s  os_type=%s", device_name, mgmt_ip, os_type)

    # ── Connect and discover CDP neighbors ────────────────────────────────
    cisco = CiscoDeviceClient(
        host=mgmt_ip,
        username=args.username,
        password=args.password,
        os_type=os_type,
        enable_secret=args.enable_secret or None,
        timeout=args.timeout,
        verify_ssl=False,
    )
    try:
        neighbors = cisco.get_cdp_neighbors()
    except CiscoDeviceClientError as exc:
        summary["errors"].append(f"CDP discovery failed: {exc}")
        cisco._cli_disconnect()
        return summary

    summary["neighbors_seen"] = len(neighbors)
    log.info("%-30s  CDP: %d neighbor(s) discovered", device_name, len(neighbors))

    # Track local interface IDs already processed this run to avoid
    # creating duplicate cables from bi-directional CDP entries.
    seen_local_iface_ids: Set[int] = set()

    for nbr in neighbors:
        # Expand abbreviated names to canonical Cisco long form before any
        # NetBox lookup or creation — prevents duplicates caused by short vs
        # long name mismatches (e.g. "gi1/0/1" vs "GigabitEthernet1/0/1").
        _raw_local  = nbr.get("local_interface") or ""
        _raw_remote = nbr.get("neighbor_interface") or ""
        local_iface_name    = CiscoDeviceClient._expand_iface(_raw_local)    if _raw_local    else ""
        neighbor_iface_name = CiscoDeviceClient._expand_iface(_raw_remote)   if _raw_remote   else ""
        neighbor_dev_name   = nbr.get("neighbor_device", "").lower()
        neighbor_ip         = nbr.get("neighbor_ip")

        if not local_iface_name or not neighbor_iface_name:
            continue

        # ── Skip logical interface types ─────────────────────────────────
        if _is_logical_interface(local_iface_name) or \
           _is_logical_interface(neighbor_iface_name):
            log.debug(
                "%-30s  skip logical  local=%s  remote=%s",
                device_name, local_iface_name, neighbor_iface_name,
            )
            summary["skipped_logical_iface"] += 1
            continue

        # ── Resolve neighbor device (VC-first, with suffix fallback) ─────
        neighbor_device = _resolve_neighbor(nb, neighbor_dev_name, neighbor_ip)
        if not neighbor_device:
            log.warning(
                "%-30s  neighbor %r not found in NetBox — skipping",
                device_name, neighbor_dev_name,
            )
            summary["skipped_missing_device"] += 1
            continue

        neighbor_device_id = neighbor_device.get("id")
        resolved_name = neighbor_device.get("_vc_name") or neighbor_device.get("name", neighbor_dev_name)

        # ── Resolve / create both interface records ───────────────────────
        local_iface_rec = _get_or_create_interface(nb, device_id, local_iface_name)
        if not local_iface_rec:
            summary["errors"].append(
                f"Could not resolve local interface {local_iface_name!r}"
            )
            continue

        remote_iface_rec = _get_or_create_interface(
            nb, neighbor_device_id, neighbor_iface_name
        )
        if not remote_iface_rec:
            summary["errors"].append(
                f"Could not resolve remote interface {neighbor_iface_name!r} "
                f"on {resolved_name!r}"
            )
            continue

        local_id  = local_iface_rec["id"]
        remote_id = remote_iface_rec["id"]

        # ── Dedup: skip if already processed this local interface ─────────
        if local_id in seen_local_iface_ids:
            continue

        # ── Check for existing cables ─────────────────────────────────────
        try:
            local_cabled  = nb.interface_has_cable(local_id)
            remote_cabled = nb.interface_has_cable(remote_id)
        except NetBoxClientError as exc:
            summary["errors"].append(f"Cable-check failed: {exc}")
            continue

        if local_cabled or remote_cabled:
            if not args.force:
                # Default (safe) mode — leave any existing cable alone.
                log.info(
                    "%-30s  SKIP (existing cable)  local=%s  remote=%s@%s",
                    device_name, local_iface_name, neighbor_iface_name, resolved_name,
                )
                summary["skipped_existing_cable"] += 1
                seen_local_iface_ids.add(local_id)
                continue

            # ── --force mode: inspect existing cable(s) ──────────────────
            # Fetch full cable info (including peer interface IDs) for each
            # side that is currently cabled.  Uses the detail endpoint so
            # that link_peers is populated.
            local_cable_info  = None
            remote_cable_info = None

            if local_cabled:
                try:
                    local_cable_info = nb.get_interface_cable_info(local_id)
                except NetBoxClientError as exc:
                    log.warning(
                        "%-30s  FORCE: cannot read cable info for local %s: %s "
                        "— skipping",
                        device_name, local_iface_name, exc,
                    )
                    summary["errors"].append(
                        f"Force cable-info {local_iface_name!r}: {exc}"
                    )
                    continue

            if remote_cabled:
                try:
                    remote_cable_info = nb.get_interface_cable_info(remote_id)
                except NetBoxClientError as exc:
                    log.warning(
                        "%-30s  FORCE: cannot read cable info for remote %s: %s "
                        "— skipping",
                        device_name, neighbor_iface_name, exc,
                    )
                    summary["errors"].append(
                        f"Force cable-info {neighbor_iface_name!r}: {exc}"
                    )
                    continue

            # A cable is correct when local's peer IS the intended remote
            # interface (or equivalently, remote's peer IS local).
            cable_is_correct = (
                (local_cable_info  and remote_id in local_cable_info["peer_ids"])
                or
                (remote_cable_info and local_id  in remote_cable_info["peer_ids"])
            )

            if cable_is_correct:
                log.debug(
                    "%-30s  FORCE: cable already correct  %s ↔ %s@%s — no action",
                    device_name, local_iface_name, neighbor_iface_name, resolved_name,
                )
                seen_local_iface_ids.add(local_id)
                continue

            # Cable(s) exist but connect to the wrong endpoint — delete them.
            # Collect unique cable IDs from both sides (they may share one cable
            # or have independent wrong cables).
            cables_to_delete: Set[int] = set()
            if local_cable_info:
                cables_to_delete.add(local_cable_info["cable_id"])
            if remote_cable_info:
                cables_to_delete.add(remote_cable_info["cable_id"])

            log.warning(
                "%-30s  FORCE: wrong cable(s) %s on %s — will replace with "
                "%s ↔ %s@%s",
                device_name, sorted(cables_to_delete),
                local_iface_name, local_iface_name, neighbor_iface_name, resolved_name,
            )

            if args.dry_run:
                for cid in sorted(cables_to_delete):
                    log.info(
                        "DRY-RUN  %-30s  FORCE would delete cable id=%s",
                        device_name, cid,
                    )
                log.info(
                    "DRY-RUN  %-30s  FORCE would create cable %s ↔ %s@%s",
                    device_name, local_iface_name, neighbor_iface_name, resolved_name,
                )
                summary["cables_replaced"] += 1
                seen_local_iface_ids.add(local_id)
                continue

            # Live: delete the wrong cable(s) then fall through to creation.
            delete_ok = True
            for cid in sorted(cables_to_delete):
                try:
                    nb.delete_cable(cid)
                    log.info(
                        "%-30s  FORCE deleted cable id=%s",
                        device_name, cid,
                    )
                except NetBoxClientError as exc:
                    log.warning(
                        "%-30s  FORCE: delete cable id=%s failed: %s — skipping",
                        device_name, cid, exc,
                    )
                    summary["errors"].append(f"Force delete cable {cid}: {exc}")
                    delete_ok = False

            if not delete_ok:
                continue

            # Track this as a replacement; the cable creation below will
            # increment cables_created as well so operators see both metrics.
            summary["cables_replaced"] += 1
            # Fall through to mark_connected clearing and cable creation.

        # ── Clear mark_connected on both sides before cable creation ──────
        # NetBox rejects cable creation if either endpoint has
        # mark_connected=True.  Use the already-fetched interface records
        # to decide — no extra API call unless the flag is actually set.
        _clear_connected_if_needed(
            nb, local_id, local_iface_rec, local_iface_name, device_name
        )
        _clear_connected_if_needed(
            nb, remote_id, remote_iface_rec, neighbor_iface_name, device_name
        )

        # ── Classify transceiver → cable type ────────────────────────────
        try:
            transceiver_raw = cisco.get_interface_transceiver_raw(local_iface_name)
        except Exception:
            transceiver_raw = ""

        optic_class = _classify_optic(transceiver_raw)
        cable_type  = _cable_type_for_optic(optic_class)

        if args.dry_run:
            log.info(
                "DRY-RUN  %-30s  cable %-35s ↔ %-35s @%s  optic=%s  type=%s",
                device_name, local_iface_name, neighbor_iface_name, resolved_name,
                optic_class or "unknown", cable_type or "(none)",
            )
            summary["cables_created"] += 1
            seen_local_iface_ids.add(local_id)
            continue

        # ── Create cable (with type-rejection retry) ──────────────────────
        ok = _create_cable_safe(
            nb=nb,
            local_id=local_id,
            remote_id=remote_id,
            cable_type=cable_type,
            device_name=device_name,
            local_iface=local_iface_name,
            remote_iface=neighbor_iface_name,
            remote_dev=resolved_name,
        )
        if ok:
            summary["cables_created"] += 1
            seen_local_iface_ids.add(local_id)
        else:
            summary["errors"].append(
                f"Cable {local_iface_name!r} ↔ {neighbor_iface_name!r}@{resolved_name!r} failed"
            )

    cisco._cli_disconnect()
    summary["status"] = "success"
    return summary


# --------------------------------------------------------------------------- #
# Logging setup                                                                #
# --------------------------------------------------------------------------- #

def _configure_logging(level: str, log_file=None) -> None:
    """stderr always on; optionally also append to *log_file*."""
    fmt  = "%(asctime)s %(levelname)-8s %(name)s: %(message)s"
    root = logging.getLogger()
    root.setLevel(getattr(logging, level))
    root.handlers.clear()

    stderr_h = logging.StreamHandler(sys.stderr)
    stderr_h.setFormatter(logging.Formatter(fmt))
    root.addHandler(stderr_h)

    if log_file:
        try:
            file_h = logging.FileHandler(log_file, mode="a", encoding="utf-8")
            file_h.setFormatter(logging.Formatter(fmt))
            root.addHandler(file_h)
            logging.getLogger(__name__).info("Log file: %s", log_file)
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
        log.info("*** DRY-RUN — no NetBox writes ***")

    nb = NetBoxClient(
        base_url=netbox_url,
        token=netbox_token,
        verify_ssl=args.netbox_verify_ssl,
        threading=True,
    )

    devices = _resolve_device_list(args, nb)
    if not devices:
        log.warning("No devices to process.")
        print(json.dumps([], indent=2))
        return

    log.info("Processing %d device(s), %d worker(s)", len(devices), args.max_workers)

    summaries: List[dict] = []
    with ThreadPoolExecutor(max_workers=args.max_workers) as pool:
        future_to_device = {
            pool.submit(process_device_cables, device, nb, args): device
            for device in devices
        }
        for future in as_completed(future_to_device):
            device      = future_to_device[future]
            device_name = device.get("name", "unknown")
            try:
                result = future.result()
                summaries.append(result)
                log.info(
                    "%-30s  status=%-8s  seen=%d  created=%d  replaced=%d  "
                    "skip_cable=%d  skip_no_dev=%d  errs=%d",
                    device_name, result.get("status", "?"),
                    result.get("neighbors_seen", 0),
                    result.get("cables_created", 0),
                    result.get("cables_replaced", 0),
                    result.get("skipped_existing_cable", 0),
                    result.get("skipped_missing_device", 0),
                    len(result.get("errors", [])),
                )
            except Exception as exc:
                log.error("Unexpected error for %s: %s", device_name, exc)
                summaries.append({
                    "device":                 device_name,
                    "status":                 "failed",
                    "neighbors_seen":         0,
                    "cables_created":         0,
                    "skipped_existing_cable": 0,
                    "skipped_missing_device": 0,
                    "skipped_logical_iface":  0,
                    "errors":                 [str(exc)],
                })

    summaries.sort(key=lambda s: s.get("device", ""))

    total_created  = sum(s.get("cables_created", 0)         for s in summaries)
    total_replaced = sum(s.get("cables_replaced", 0)        for s in summaries)
    total_skipped  = sum(s.get("skipped_existing_cable", 0) for s in summaries)
    log.info(
        "DONE  devices=%d  cables_created=%d  cables_replaced=%d  "
        "skipped_existing=%d",
        len(summaries), total_created, total_replaced, total_skipped,
    )

    print(json.dumps(summaries, indent=2))


if __name__ == "__main__":
    main()
