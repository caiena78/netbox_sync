#!/usr/bin/env python3
"""
client_mac_address.py
=====================
Read the dynamic MAC address table from each selected Cisco device and
synchronise every entry as a ``dcim.mac_addresses`` object in NetBox,
keeping the ``mac_address_lastseen`` custom field current on every run.

What it does per device
-----------------------
1. Connects to the device via SSH (CLI — MAC table commands are CLI-only).
2. Runs ``show mac address-table dynamic`` (falls back to
   ``show mac address-table`` when needed).
3. For every MAC entry returned:
   a. Resolves or creates the matching NetBox interface record.
   b. Calls :func:`NetBoxClient.ensure_mac_address`, which is idempotent:
      - **Not found** → created, assigned to interface, lastseen = now
      - **Found on same interface** → only lastseen updated
      - **Found on wrong interface** → reassigned + lastseen updated
4. Returns a per-device JSON summary to **stdout**; logs to **stderr**.

This script does NOT process ARP or IP address data.

NetBox custom field required (create before running)
-----------------------------------------------------
``dcim.mac_address`` → ``mac_address_lastseen``  (type: Text or DateTime)

Device requirements
-------------------
- Device must have ``primary_ip4`` **or** ``primary_ip6`` in NetBox.
- Platform slug must be ``ios``, ``iosxe``, or ``nxos`` (or a variant
  listed in ``PLATFORM_SLUG_MAP``).

CLI argument behaviour
----------------------
Identical to ``sync_netbox_interfaces.py``:
- ``--device`` / ``--devices`` / ``--device-file`` / ``--device-filter``
- ``--site-slug``
- ``--dry-run``
- ``--max-workers`` / ``--timeout`` / ``--log-level``

Usage examples (Windows PowerShell)
------------------------------------
    python client_mac_address.py --device core-sw-01
    python client_mac_address.py --site-slug lakeview --dry-run
    python client_mac_address.py --device-filter '{\"status\": \"active\"}'

Usage examples (Linux / macOS)
-------------------------------
    python client_mac_address.py --device core-sw-01
    python client_mac_address.py --site-slug lakeview --dry-run
    python client_mac_address.py --device-filter '{"status": "active"}'
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Dict, List, Optional, Set

from cisco_device_client import CiscoDeviceClient, CiscoDeviceClientError
from netbox_client import NetBoxClient, NetBoxClientError

# --------------------------------------------------------------------------- #
# Platform slug → os_type  (identical mapping used in all sibling scripts)    #
# --------------------------------------------------------------------------- #

PLATFORM_SLUG_MAP: Dict[str, str] = {
    "iosxe":       "iosxe", "ios-xe":      "iosxe", "ios_xe":      "iosxe",
    "cisco-iosxe": "iosxe", "cisco_iosxe": "iosxe",
    "nxos":        "nxos",  "nx-os":       "nxos",  "nx_os":       "nxos",
    "cisco-nxos":  "nxos",  "cisco_nxos":  "nxos",
    "ios":         "ios",   "cisco-ios":   "ios",   "cisco_ios":   "ios",
}

log = logging.getLogger("client_mac_address")


# --------------------------------------------------------------------------- #
# CLI argument parser                                                          #
# --------------------------------------------------------------------------- #

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description=(
            "Sync Cisco device MAC address tables to NetBox "
            "dcim.mac_addresses with last-seen timestamps."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    nb = p.add_argument_group("NetBox connection")
    nb.add_argument(
        "--netbox-url",
        default=os.environ.get("NETBOX_URL", ""),
        metavar="URL",
        help="NetBox base URL (env: NETBOX_URL)",
    )
    nb.add_argument(
        "--netbox-token",
        default=os.environ.get("NETBOX_API", ""),
        metavar="TOKEN",
        help="NetBox API token (env: NETBOX_API)",
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
    sel.add_argument(
        "--device-file", metavar="PATH",
        help="File with one device name per line (#comments ignored)",
    )
    sel.add_argument(
        "--device-filter", default="{}",
        metavar="JSON",
        help="NetBox DCIM device filter as JSON (default: all devices)",
    )
    sel.add_argument("--all", dest="all_devices", action="store_true",
                     help="Explicit 'process all' flag")
    sel.add_argument(
        "--site-slug", default="", metavar="SLUG",
        help="Limit to devices in this NetBox site (slug, optional)",
    )

    cred = p.add_argument_group("Cisco credentials")
    cred.add_argument(
        "--username",
        default=os.environ.get("CISCO_SRV_ACCOUNT", ""),
        help="SSH username (env: CISCO_SRV_ACCOUNT)",
    )
    cred.add_argument(
        "--password",
        default=os.environ.get("CISCO_SRV_PWD", ""),
        help="SSH password (env: CISCO_SRV_PWD)",
    )
    cred.add_argument(
        "--enable-secret",
        default=os.environ.get("CISCO_ENABLE_PWD", ""),
        help="Enable secret (env: CISCO_ENABLE_PWD)",
    )

    run = p.add_argument_group("Runtime options")
    run.add_argument(
        "--transport",
        choices=["auto", "cli", "restconf", "netconf"],
        default="cli",
        help="Transport (default: cli — MAC table commands are CLI-only)",
    )
    run.add_argument("--dry-run", action="store_true",
                     help="Print changes without writing to NetBox")
    run.add_argument("--max-workers", type=int, default=5, metavar="N",
                     help="Concurrent threads (default: 5)")
    run.add_argument("--timeout", type=int, default=30, metavar="SEC",
                     help="Device timeout seconds (default: 30)")
    run.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="INFO",
    )

    return p


# --------------------------------------------------------------------------- #
# Device helpers  (same logic as sync_netbox_interfaces.py)                   #
# --------------------------------------------------------------------------- #

def _device_has_primary_ip(device: dict) -> bool:
    """Return True when the device has primary_ip4 or primary_ip6 in NetBox."""
    return bool(device.get("primary_ip4") or device.get("primary_ip6"))


def get_device_mgmt_ip(device: dict) -> Optional[str]:
    """Return the first usable management IP (strips prefix length)."""
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
    """Map the NetBox platform slug to an os_type string."""
    platform = device.get("platform")
    if not platform:
        return None
    slug = (
        (platform.get("slug") or platform.get("name") or "").lower().strip()
        if isinstance(platform, dict)
        else str(platform).lower().strip()
    )
    return PLATFORM_SLUG_MAP.get(slug)


def _site_slug_matches(device: dict, site_slug: str) -> bool:
    """Return True when the device is in *site_slug*, or no filter is set."""
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


def _resolve_single_device(name: str, nb: NetBoxClient) -> Optional[dict]:
    """
    Resolve a device name to a usable NetBox device dict.

    Tries virtual-chassis lookup first, then falls back to a regular device
    search — identical behaviour to sync_netbox_interfaces.py.
    """
    try:
        vc = nb.find_virtual_chassis(name)
        if vc:
            vc_id   = vc["id"]
            vc_name = vc.get("name", name)
            members = nb.get_virtual_chassis_members(vc_id)
            for member in members:
                if get_device_mgmt_ip(member):
                    member["_vc_name"] = vc_name
                    member["_vc_id"]   = vc_id
                    log.info(
                        "Virtual chassis %r → using member %r  ip=%s",
                        vc_name, member.get("name"), get_device_mgmt_ip(member),
                    )
                    return member
            log.warning(
                "Virtual chassis %r found but no member has a reachable IP.", vc_name
            )
            return None
    except NetBoxClientError as exc:
        log.warning("Virtual chassis lookup error for %r: %s", name, exc)

    d = nb.get_device(name=name)
    if d:
        return d
    log.warning("%r not found as virtual chassis or device in NetBox.", name)
    return None


def resolve_device_list(args: argparse.Namespace, nb: NetBoxClient) -> List[dict]:
    """
    Return the ordered list of NetBox device dicts to process.

    Logic and argument handling are identical to sync_netbox_interfaces.py
    so that all scripts in this toolset behave consistently.
    """
    site_slug: str = getattr(args, "site_slug", "") or ""

    if args.device:
        d = _resolve_single_device(args.device.strip(), nb)
        if d and _site_slug_matches(d, site_slug):
            return [d]
        return []

    if args.devices:
        names = [n.strip() for n in args.devices.split(",") if n.strip()]
        result = []
        for name in names:
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

    # Default: filter-based bulk fetch (server-side filtering via NetBox API)
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


# --------------------------------------------------------------------------- #
# Interface resolution                                                         #
# --------------------------------------------------------------------------- #

def _get_or_create_interface(
    nb: NetBoxClient,
    device_id: int,
    iface_name: str,
) -> Optional[int]:
    """
    Return the NetBox interface ID for *iface_name* on *device_id*.

    Creates a minimal placeholder (``type=other``) when the interface does
    not yet exist.  Returns ``None`` on any API failure so callers can skip
    gracefully rather than aborting the whole run.
    """
    try:
        existing = list(
            nb.nb.dcim.interfaces.filter(device_id=device_id, name=iface_name)
        )
        if existing:
            return existing[0].id

        # Interface not found — create a placeholder
        rec = nb.nb.dcim.interfaces.create({
            "device": device_id,
            "name":   iface_name,
            "type":   "other",
        })
        log.debug(
            "Created placeholder interface %r on device_id=%s", iface_name, device_id
        )
        return rec.id

    except Exception as exc:
        log.warning(
            "Could not resolve/create interface %r on device_id=%s: %s",
            iface_name, device_id, exc,
        )
        return None


# --------------------------------------------------------------------------- #
# Per-device MAC sync                                                          #
# --------------------------------------------------------------------------- #

def process_device(
    device: dict,
    nb: NetBoxClient,
    args: argparse.Namespace,
) -> dict:
    """
    Collect the MAC address table from one device and sync to NetBox.

    Returns a JSON-serialisable summary dict.
    """
    device_name = device.get("name", "unknown")
    device_id   = device.get("id")

    summary: dict = {
        "device":              device_name,
        "status":              "failed",
        "mac_entries_seen":    0,
        "mac_created":         0,
        "mac_reassigned":      0,
        "mac_lastseen_updated": 0,
        "skipped":             0,
        "errors":              0,
        "error_messages":      [],
    }

    # ── Hard gate: primary IP required ────────────────────────────────────
    if not _device_has_primary_ip(device):
        summary["error_messages"].append(
            "Device has no primary_ip4 or primary_ip6 — skipped."
        )
        summary["errors"] = 1
        log.warning("%-30s  SKIPPED — no primary IP in NetBox", device_name)
        return summary

    mgmt_ip = get_device_mgmt_ip(device)
    if not mgmt_ip:
        summary["error_messages"].append("No management IP resolved — skipped.")
        summary["errors"] = 1
        return summary

    os_type = get_device_os_type(device)
    if not os_type:
        summary["error_messages"].append(
            f"Unknown platform {device.get('platform')!r} — "
            "add slug to PLATFORM_SLUG_MAP and retry."
        )
        summary["errors"] = 1
        return summary

    log.info("%-30s  ip=%-18s  os_type=%s", device_name, mgmt_ip, os_type)

    # ── Connect and collect MAC table ─────────────────────────────────────
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
        mac_entries = cisco.get_mac_address_table()
    except CiscoDeviceClientError as exc:
        summary["error_messages"].append(f"MAC table collection failed: {exc}")
        summary["errors"] = 1
        cisco._cli_disconnect()
        return summary
    finally:
        cisco._cli_disconnect()

    summary["mac_entries_seen"] = len(mac_entries)
    log.info("%-30s  MAC table: %d entry(ies)", device_name, len(mac_entries))

    if not mac_entries:
        summary["status"] = "success"
        return summary

    # ── Sync each MAC entry to NetBox ─────────────────────────────────────
    now = datetime.now().astimezone().isoformat(timespec="seconds")

    for entry in mac_entries:
        mac_str    = entry.get("mac", "")
        iface_name = entry.get("interface", "")

        if not mac_str or not iface_name:
            summary["skipped"] += 1
            continue

        if dry_run := args.dry_run:
            log.info(
                "DRY-RUN  %-30s  MAC %-20s  iface=%s",
                device_name, mac_str, iface_name,
            )
            summary["mac_lastseen_updated"] += 1
            continue

        # ── Resolve / create the interface ────────────────────────────────
        iface_id = _get_or_create_interface(nb, device_id, iface_name)
        if iface_id is None:
            log.warning(
                "%-30s  skip MAC %s — cannot resolve interface %r",
                device_name, mac_str, iface_name,
            )
            summary["skipped"] += 1
            continue

        # ── Ensure MAC object in NetBox (create / reassign / refresh) ─────
        try:
            result = nb.ensure_mac_address(
                mac=mac_str,
                interface_id=iface_id,
                now_iso=now,
                description="Added via client_mac_address.py",
            )
            action = result.get("_action", "skipped")

            if action == "created":
                summary["mac_created"] += 1
                log.info(
                    "%-30s  MAC created    %-20s  iface=%s",
                    device_name, mac_str, iface_name,
                )
            elif action == "reassigned":
                summary["mac_reassigned"] += 1
                log.info(
                    "%-30s  MAC reassigned %-20s  iface=%s",
                    device_name, mac_str, iface_name,
                )
            elif action == "refreshed":
                summary["mac_lastseen_updated"] += 1
                log.debug(
                    "%-30s  MAC refreshed  %-20s  iface=%s",
                    device_name, mac_str, iface_name,
                )
            else:
                summary["skipped"] += 1
                log.debug(
                    "%-30s  MAC skipped    %-20s  action=%s",
                    device_name, mac_str, action,
                )

        except NetBoxClientError as exc:
            err = f"MAC {mac_str!r} on {iface_name!r}: {exc}"
            log.warning("%-30s  %s", device_name, err)
            summary["error_messages"].append(err)
            summary["errors"] += 1

    summary["status"] = "success"
    return summary


# --------------------------------------------------------------------------- #
# Entry point                                                                  #
# --------------------------------------------------------------------------- #

def main() -> None:
    parser = build_parser()
    args   = parser.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
        stream=sys.stderr,
    )

    # Validate required arguments
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
        log.error(
            "Missing required arguments / environment variables:\n  %s",
            "\n  ".join(missing),
        )
        sys.exit(1)

    if args.dry_run:
        log.info("*** DRY-RUN — no changes will be written to NetBox ***")

    nb = NetBoxClient(
        base_url=args.netbox_url,
        token=args.netbox_token,
        verify_ssl=args.netbox_verify_ssl,
        threading=True,
    )

    devices = resolve_device_list(args, nb)
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
            pool.submit(process_device, device, nb, args): device
            for device in devices
        }
        for future in as_completed(future_map):
            device      = future_map[future]
            device_name = device.get("name", "unknown")
            try:
                result = future.result()
                summaries.append(result)
                log.info(
                    "%-30s  status=%-8s  seen=%d  "
                    "created=%d  reassigned=%d  refreshed=%d  "
                    "skipped=%d  errors=%d",
                    device_name,
                    result.get("status", "?"),
                    result.get("mac_entries_seen", 0),
                    result.get("mac_created", 0),
                    result.get("mac_reassigned", 0),
                    result.get("mac_lastseen_updated", 0),
                    result.get("skipped", 0),
                    result.get("errors", 0),
                )
            except Exception as exc:
                log.error("Unexpected error for %s: %s", device_name, exc)
                summaries.append({
                    "device":         device_name,
                    "status":         "failed",
                    "mac_entries_seen": 0,
                    "mac_created":    0,
                    "mac_reassigned": 0,
                    "mac_lastseen_updated": 0,
                    "skipped":        0,
                    "errors":         1,
                    "error_messages": [str(exc)],
                })

    summaries.sort(key=lambda s: s.get("device", ""))

    total_ok   = sum(1 for s in summaries if s["status"] == "success")
    total_fail = sum(1 for s in summaries if s["status"] == "failed")
    log.info(
        "DONE  devices=%d ok=%d failed=%d  "
        "MACs: created=%d  reassigned=%d  refreshed=%d",
        len(summaries), total_ok, total_fail,
        sum(s.get("mac_created", 0) for s in summaries),
        sum(s.get("mac_reassigned", 0) for s in summaries),
        sum(s.get("mac_lastseen_updated", 0) for s in summaries),
    )

    print(json.dumps(summaries, indent=2))


if __name__ == "__main__":
    main()
