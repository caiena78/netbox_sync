#!/usr/bin/env python3
"""
client_ip_mac.py
================
Discover client IP-to-MAC mappings from Cisco ARP and MAC address tables,
then synchronise the data to NetBox with full timestamp tracking.

What it does per device
-----------------------
1. Runs ``show ip arp`` to get the IP → MAC mapping table.
2. Runs ``show mac address-table dynamic`` to find which switch port each
   MAC was last seen on.
3. Joins ARP and MAC tables on the MAC address to produce:
       IP  →  MAC  →  switch port  →  VLAN
4. For each client discovered:
   a. Ensures a NetBox IP Address object (/32) exists and is assigned to
      the switch interface where the MAC was seen.
   b. Ensures a NetBox MAC Address object (``dcim.mac_addresses``) is
      created / reassigned / refreshed for that interface (idempotent).
   c. Merges the IP into the interface ``client_ips`` custom field as a
      JSON dict keyed by IP, with ``last_seen`` timestamp and MAC address.
   d. Updates ``IP_Last_update`` on the IP Address record.
   e. Updates ``mac_address_lastseen`` on the MAC Address record.

NetBox custom fields required (create these before running)
-----------------------------------------------------------
``dcim.interface``    → ``client_ips``            (JSON or Text)
``dcim.mac_address``  → ``mac_address_lastseen``  (Text/DateTime)
``ipam.ip_address``   → ``IP_Last_update``         (Text/DateTime)

MAC address handling
--------------------
- Works for both access and trunk ports (no mode dependency).
- Idempotent: re-running updates timestamps; no duplicates are created.
- If a MAC is on the wrong interface it is reassigned automatically.
- ``mac_address_lastseen`` is only updated for MACs processed this run.

Idempotency
-----------
- Re-running only updates timestamps; no duplicates are ever created.
- IPs already on the correct interface are never moved.
- IPs in ``client_ips`` that are NOT seen this run are preserved.

Output
------
JSON summary array to **stdout**; logs to **stderr**.

Usage examples
--------------
Windows PowerShell:
    python client_ip_mac.py --device core-sw-01
    python client_ip_mac.py --site-slug lakeview --dry-run
    python client_ip_mac.py --device-filter '{\"status\": \"active\"}'

Linux / macOS:
    python client_ip_mac.py --device core-sw-01
    python client_ip_mac.py --site-slug lakeview --dry-run
    python client_ip_mac.py --device-filter '{"status": "active"}'
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set, Tuple

from cisco_device_client import CiscoDeviceClient, CiscoDeviceClientError
from netbox_client import NetBoxClient, NetBoxClientError

# --------------------------------------------------------------------------- #
# Platform slug → os_type                                                      #
# --------------------------------------------------------------------------- #

PLATFORM_SLUG_MAP: Dict[str, str] = {
    "iosxe":       "iosxe", "ios-xe":      "iosxe", "ios_xe":      "iosxe",
    "cisco-iosxe": "iosxe", "cisco_iosxe": "iosxe",
    "nxos":        "nxos",  "nx-os":       "nxos",  "nx_os":       "nxos",
    "cisco-nxos":  "nxos",  "cisco_nxos":  "nxos",
    "ios":         "ios",   "cisco-ios":   "ios",   "cisco_ios":   "ios",
}

log = logging.getLogger("client_ip_mac")


# --------------------------------------------------------------------------- #
# Timestamp helpers                                                            #
# --------------------------------------------------------------------------- #

def _now_iso() -> str:
    """Return the current local time as an ISO 8601 string with UTC offset."""
    return datetime.now().astimezone().isoformat(timespec="seconds")


# --------------------------------------------------------------------------- #
# CLI argument parser                                                          #
# --------------------------------------------------------------------------- #

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description=(
            "Discover client IP-to-MAC mappings from Cisco ARP / MAC tables "
            "and sync to NetBox with timestamps."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    nb = p.add_argument_group("NetBox connection")
    nb.add_argument("--netbox-url",
                    default=os.environ.get("NETBOX_URL", ""),
                    help="NetBox base URL (env: NETBOX_URL)")
    nb.add_argument("--netbox-token",
                    default=os.environ.get("NETBOX_API", ""),
                    help="NetBox API token (env: NETBOX_API)")
    nb.add_argument("--netbox-verify-ssl",
                    action=argparse.BooleanOptionalAction, default=True,
                    help="Verify NetBox TLS certificate (default: true)")

    sel = p.add_argument_group("Device selection (pick one, or omit for all)")
    sel.add_argument("--device",      metavar="NAME",
                     help="Single device name")
    sel.add_argument("--devices",     metavar="NAME,...",
                     help="Comma-separated device names")
    sel.add_argument("--device-file", metavar="PATH",
                     help="File with one device name per line (#comments ignored)")
    sel.add_argument("--device-filter", default="{}",
                     metavar="JSON",
                     help="NetBox DCIM device filter as JSON (default: all)")
    sel.add_argument("--site-slug",   default="", metavar="SLUG",
                     help="Limit to devices in this NetBox site (slug)")

    cred = p.add_argument_group("Cisco credentials")
    cred.add_argument("--username",
                      default=os.environ.get("CISCO_SRV_ACCOUNT", ""),
                      help="SSH username (env: CISCO_SRV_ACCOUNT)")
    cred.add_argument("--password",
                      default=os.environ.get("CISCO_SRV_PWD", ""),
                      help="SSH password (env: CISCO_SRV_PWD)")
    cred.add_argument("--enable-secret",
                      default=os.environ.get("CISCO_ENABLE_PWD", ""),
                      help="Enable secret (env: CISCO_ENABLE_PWD)")

    run = p.add_argument_group("Runtime options")
    run.add_argument("--transport",
                     choices=["auto", "cli", "restconf", "netconf"],
                     default="cli",
                     help="Transport (default: cli — ARP/MAC commands are CLI-only)")
    run.add_argument("--dry-run", action="store_true",
                     help="Print discovered data without writing to NetBox")
    run.add_argument("--max-workers", type=int, default=5, metavar="N",
                     help="Concurrent threads (default: 5)")
    run.add_argument("--timeout", type=int, default=30, metavar="SEC",
                     help="Device timeout seconds (default: 30)")
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
    run.add_argument(
        "--skip-macs", default="", metavar="MAC,...",
        help=(
            "Comma-separated MAC addresses to ignore (e.g. router/gateway MACs). "
            "Accepts colon, dash, or Cisco dotted formats."
        ),
    )

    return p


# --------------------------------------------------------------------------- #
# Device resolution helpers (mirrors sync_netbox_interfaces.py pattern)       #
# --------------------------------------------------------------------------- #

def _get_mgmt_ip(device: dict) -> Optional[str]:
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
        if isinstance(platform, dict)
        else str(platform).lower().strip()
    )
    return PLATFORM_SLUG_MAP.get(slug)


def _device_has_primary_ip(device: dict) -> bool:
    """Return True when the device has primary_ip4 or primary_ip6."""
    return bool(device.get("primary_ip4") or device.get("primary_ip6"))


def _site_slug_matches(device: dict, site_slug: str) -> bool:
    if not site_slug:
        return True
    site = device.get("site")
    if not site:
        log.warning(
            "Device %r has no site — excluded by --site-slug %r",
            device.get("name", "?"), site_slug,
        )
        return False
    slug = site.get("slug", "") if isinstance(site, dict) else ""
    return slug == site_slug


def _resolve_single_device(name: str, nb: NetBoxClient) -> Optional[dict]:
    try:
        vc = nb.find_virtual_chassis(name)
        if vc:
            members = nb.get_virtual_chassis_members(vc["id"])
            for m in members:
                if _get_mgmt_ip(m):
                    m["_vc_name"] = vc.get("name", name)
                    m["_vc_id"]   = vc["id"]
                    return m
    except NetBoxClientError:
        pass
    try:
        return nb.get_device(name=name)
    except NetBoxClientError:
        return None


def _resolve_device_list(args: argparse.Namespace, nb: NetBoxClient) -> List[dict]:
    site_slug = getattr(args, "site_slug", "") or ""

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
                names = [
                    ln.strip() for ln in fh
                    if ln.strip() and not ln.strip().startswith("#")
                ]
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
# MAC normalisation                                                            #
# --------------------------------------------------------------------------- #

def _normalize_mac(mac: str) -> str:
    """Normalise any Cisco MAC format to lowercase colon-separated hex."""
    stripped = mac.lower().replace(".", "").replace(":", "").replace("-", "")
    if len(stripped) != 12:
        return mac.lower()
    return ":".join(stripped[i:i+2] for i in range(0, 12, 2))


def _parse_skip_macs(raw: str) -> Set[str]:
    """Parse --skip-macs argument into a set of normalised MAC strings."""
    result: Set[str] = set()
    for part in raw.split(","):
        part = part.strip()
        if part:
            result.add(_normalize_mac(part))
    return result


# --------------------------------------------------------------------------- #
# ARP + MAC table correlation                                                  #
# --------------------------------------------------------------------------- #

def _correlate(
    arp_entries: List[dict],
    mac_entries: List[dict],
    skip_macs: Set[str],
) -> List[dict]:
    """
    Join ARP and MAC address table on the MAC address.

    For each ARP entry whose MAC appears in the MAC address table, produce::

        {
            "ip":        "10.10.10.50",
            "mac":       "a1:b2:c3:d4:e5:f6",
            "interface": "GigabitEthernet1/0/5",  # switch port from MAC table
            "vlan":      10,                       # VLAN from MAC table
        }

    Entries with no matching MAC table record are silently dropped (the device
    may be reachable via a trunk or may have aged out of the MAC table).
    """
    # Build MAC → (interface, vlan) index from MAC table
    mac_index: Dict[str, dict] = {}
    for entry in mac_entries:
        mac = entry["mac"]
        if mac and mac not in mac_index:
            mac_index[mac] = entry

    result: List[dict] = []
    for arp in arp_entries:
        mac = arp["mac"]
        if not mac or mac in skip_macs:
            continue
        mac_entry = mac_index.get(mac)
        if not mac_entry:
            continue   # MAC not in MAC table — skip
        result.append({
            "ip":        arp["ip"],
            "mac":       mac,
            "interface": mac_entry["interface"],
            "vlan":      mac_entry.get("vlan"),
        })

    return result


# --------------------------------------------------------------------------- #
# Per-entry NetBox sync                                                        #
# --------------------------------------------------------------------------- #

def _sync_entry(
    entry: dict,
    nb: NetBoxClient,
    device_id: int,
    device_name: str,
    now: str,
    dry_run: bool,
) -> Tuple[str, bool, bool, str, Optional[str]]:
    """
    Sync one (IP, MAC, interface) triple to NetBox.

    Steps
    -----
    1. Ensure IP /32 address object exists and is assigned to the interface.
    2. Update ``IP_Last_update`` on the IP Address record.
    3. Resolve the interface ID and call ``ensure_mac_address`` on the MAC
       Address record (create / reassign / refresh — idempotent).
    4. Merge IP into the interface ``client_ips`` custom field.

    Returns
    -------
    tuple
        ``(ip, ip_touched, client_ips_updated, mac_action, error_msg)``
        where ``mac_action`` is ``"created"|"reassigned"|"refreshed"|"skipped"|"error"``.
    """
    ip_str     = entry["ip"]
    mac_str    = entry["mac"]
    iface_name = entry["interface"]
    ip_cidr    = f"{ip_str}/32"
    ip_touched = False
    cf_touched = False
    mac_action = "skipped"
    error_msg: Optional[str] = None

    if dry_run:
        log.info(
            "DRY-RUN  %-30s  ip=%-18s  mac=%-20s  iface=%s",
            device_name, ip_cidr, mac_str, iface_name,
        )
        return ip_str, True, True, "skipped", None

    # ── 1. Ensure IP address object and assign to interface ───────────────
    try:
        ip_result = nb.ensure_ip_on_interface(
            ip_cidr=ip_cidr,
            device_id=device_id,
            interface_name=iface_name,
        )
        action     = ip_result.get("_action", "skipped")
        ip_touched = action in ("created", "updated")
        ip_id      = ip_result.get("id")
        log.debug(
            "%-30s  IP %s → %s  action=%s", device_name, ip_cidr, iface_name, action
        )
    except NetBoxClientError as exc:
        error_msg = f"IP assign {ip_cidr} → {iface_name!r}: {exc}"
        log.warning("%-30s  %s", device_name, error_msg)
        return ip_str, False, False, "error", error_msg

    # ── 2. Update IP_Last_update custom field ─────────────────────────────
    if ip_id:
        try:
            nb.touch_ip_last_update(ip_id)
        except NetBoxClientError as exc:
            log.debug(
                "%-30s  IP_Last_update failed ip_id=%s: %s", device_name, ip_id, exc
            )

    # ── 3. Resolve interface ID for MAC assignment ────────────────────────
    iface_id: Optional[int] = None
    try:
        iface_recs = list(
            nb.nb.dcim.interfaces.filter(device_id=device_id, name=iface_name)
        )
        if iface_recs:
            iface_id = iface_recs[0].id
    except Exception as exc:
        log.debug(
            "%-30s  interface lookup failed for %r: %s", device_name, iface_name, exc
        )

    # ── 4. Ensure MAC address object in NetBox ────────────────────────────
    if iface_id is not None:
        try:
            mac_result = nb.ensure_mac_address(
                mac=mac_str,
                interface_id=iface_id,
                now_iso=now,
            )
            mac_action = mac_result.get("_action", "skipped")
            log.info(
                "%-30s  MAC %-20s  iface=%-30s  action=%s",
                device_name, mac_str, iface_name, mac_action,
            )
        except NetBoxClientError as exc:
            mac_err = f"MAC {mac_str!r} → {iface_name!r}: {exc}"
            log.warning("%-30s  %s", device_name, mac_err)
            if error_msg is None:
                error_msg = mac_err
            mac_action = "error"
    else:
        log.warning(
            "%-30s  interface %r not found in NetBox — MAC %s not assigned",
            device_name, iface_name, mac_str,
        )
        mac_action = "skipped"

    # ── 5. Merge IP into interface client_ips custom field ────────────────
    updates = {ip_str: {"last_seen": now, "mac": mac_str}}
    try:
        cf_result = nb.update_interface_client_ips_cf(
            device_id=device_id,
            interface_name=iface_name,
            updates=updates,
        )
        cf_touched = cf_result.get("_action") == "updated"
        log.debug(
            "%-30s  client_ips CF on %s: action=%s",
            device_name, iface_name, cf_result.get("_action"),
        )
    except NetBoxClientError as exc:
        cf_err = f"client_ips CF {iface_name!r}: {exc}"
        log.warning("%-30s  %s", device_name, cf_err)
        if error_msg is None:
            error_msg = cf_err

    return ip_str, ip_touched, cf_touched, mac_action, error_msg


# --------------------------------------------------------------------------- #
# Per-device orchestration                                                     #
# --------------------------------------------------------------------------- #

def process_device(
    device: dict,
    nb: NetBoxClient,
    args: argparse.Namespace,
    skip_macs: Set[str],
) -> dict:
    """
    Discover client IPs on one device and sync to NetBox.

    Returns a JSON-serialisable summary dict.
    """
    device_name = device.get("name", "unknown")
    device_id   = device.get("id")

    summary: dict = {
        "device":             device_name,
        "status":             "failed",
        "arp_entries":        0,
        "mac_entries":        0,
        "clients_correlated": 0,
        "ips_synced":         0,
        "macs_created":       0,
        "macs_reassigned":    0,
        "macs_refreshed":     0,
        "client_ips_updated": 0,
        "errors":             [],
    }

    # ── Hard gate: primary IP required ────────────────────────────────────
    if not _device_has_primary_ip(device):
        summary["errors"].append(
            "Device has no primary_ip4 or primary_ip6 — skipped."
        )
        log.warning("%-30s  SKIPPED — no primary IP in NetBox", device_name)
        return summary

    mgmt_ip = _get_mgmt_ip(device)
    if not mgmt_ip:
        summary["errors"].append("No management IP — cannot connect.")
        return summary

    os_type = _get_os_type(device)
    if not os_type:
        summary["errors"].append(
            f"Unknown platform {device.get('platform')!r} — "
            f"add to PLATFORM_SLUG_MAP."
        )
        return summary

    log.info(
        "%-30s  ip=%-18s  os_type=%s", device_name, mgmt_ip, os_type
    )

    # ── Connect ───────────────────────────────────────────────────────────
    cisco = CiscoDeviceClient(
        host=mgmt_ip,
        username=args.username,
        password=args.password,
        os_type=os_type,
        enable_secret=args.enable_secret or None,
        timeout=args.timeout,
        verify_ssl=False,
    )

    # ── Collect ARP table ─────────────────────────────────────────────────
    try:
        arp_entries = cisco.get_arp_table()
        summary["arp_entries"] = len(arp_entries)
        log.info(
            "%-30s  ARP: %d entry(ies)", device_name, len(arp_entries)
        )
    except CiscoDeviceClientError as exc:
        summary["errors"].append(f"ARP table failed: {exc}")
        cisco._cli_disconnect()
        return summary

    # ── Collect MAC address table ─────────────────────────────────────────
    try:
        mac_entries = cisco.get_mac_address_table()
        summary["mac_entries"] = len(mac_entries)
        log.info(
            "%-30s  MAC table: %d entry(ies)", device_name, len(mac_entries)
        )
    except CiscoDeviceClientError as exc:
        summary["errors"].append(f"MAC table failed: {exc}")
        cisco._cli_disconnect()
        return summary

    cisco._cli_disconnect()

    # ── Correlate: IP → MAC → switch port ────────────────────────────────
    clients = _correlate(arp_entries, mac_entries, skip_macs)
    summary["clients_correlated"] = len(clients)
    log.info("%-30s  correlated %d client(s)", device_name, len(clients))

    if not clients:
        summary["status"] = "success"
        return summary

    # ── Sync each client to NetBox ────────────────────────────────────────
    now = _now_iso()

    for entry in clients:
        ip, ip_ok, cf_ok, mac_action, err = _sync_entry(
            entry=entry,
            nb=nb,
            device_id=device_id,
            device_name=device_name,
            now=now,
            dry_run=args.dry_run,
        )
        if err:
            summary["errors"].append(err)
        if ip_ok:
            summary["ips_synced"] += 1
        if cf_ok:
            summary["client_ips_updated"] += 1
        if mac_action == "created":
            summary["macs_created"] += 1
        elif mac_action == "reassigned":
            summary["macs_reassigned"] += 1
        elif mac_action == "refreshed":
            summary["macs_refreshed"] += 1

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
    args   = parser.parse_args()

    _configure_logging(args.log_level, args.log_file)

    # Validate required credentials
    missing: List[str] = []
    if not args.netbox_url:
        missing.append("--netbox-url  or  NETBOX_URL")
    if not args.netbox_token:
        missing.append("--netbox-token  or  NETBOX_API")
    if not args.username:
        missing.append("--username  or  CISCO_SRV_ACCOUNT")
    if not args.password:
        missing.append("--password  or  CISCO_SRV_PWD")
    if missing:
        log.error("Missing required arguments:\n  %s", "\n  ".join(missing))
        sys.exit(1)

    if args.dry_run:
        log.info("*** DRY-RUN — no changes will be written to NetBox ***")

    skip_macs = _parse_skip_macs(args.skip_macs)
    if skip_macs:
        log.debug("Skipping MACs: %s", skip_macs)

    nb = NetBoxClient(
        base_url=args.netbox_url,
        token=args.netbox_token,
        verify_ssl=args.netbox_verify_ssl,
        threading=True,
    )

    devices = _resolve_device_list(args, nb)
    if not devices:
        log.warning("No devices to process.")
        print(json.dumps([], indent=2))
        return

    log.info(
        "Processing %d device(s) with %d worker(s)",
        len(devices), args.max_workers,
    )

    summaries: List[dict] = []
    with ThreadPoolExecutor(max_workers=args.max_workers) as pool:
        future_map = {
            pool.submit(process_device, device, nb, args, skip_macs): device
            for device in devices
        }
        for future in as_completed(future_map):
            device      = future_map[future]
            device_name = device.get("name", "unknown")
            try:
                result = future.result()
                summaries.append(result)
                log.info(
                    "%-30s  status=%-8s  arp=%d  mac_tbl=%d  clients=%d  "
                    "ips=%d  mac(c=%d/r=%d/~=%d)  cf=%d  errs=%d",
                    device_name,
                    result.get("status", "?"),
                    result.get("arp_entries", 0),
                    result.get("mac_entries", 0),
                    result.get("clients_correlated", 0),
                    result.get("ips_synced", 0),
                    result.get("macs_created", 0),
                    result.get("macs_reassigned", 0),
                    result.get("macs_refreshed", 0),
                    result.get("client_ips_updated", 0),
                    len(result.get("errors", [])),
                )
            except Exception as exc:
                log.error("Unexpected error for %s: %s", device_name, exc)
                summaries.append({
                    "device":  device_name,
                    "status":  "failed",
                    "errors":  [str(exc)],
                })

    summaries.sort(key=lambda s: s.get("device", ""))

    total_ok   = sum(1 for s in summaries if s["status"] == "success")
    total_fail = sum(1 for s in summaries if s["status"] == "failed")
    log.info(
        "DONE  devices=%d ok=%d failed=%d  "
        "ips_synced=%d  macs(c=%d/r=%d/~=%d)  client_ips_cf=%d",
        len(summaries), total_ok, total_fail,
        sum(s.get("ips_synced", 0) for s in summaries),
        sum(s.get("macs_created", 0) for s in summaries),
        sum(s.get("macs_reassigned", 0) for s in summaries),
        sum(s.get("macs_refreshed", 0) for s in summaries),
        sum(s.get("client_ips_updated", 0) for s in summaries),
    )

    print(json.dumps(summaries, indent=2))


if __name__ == "__main__":
    main()
