#!/usr/bin/env python3
"""
netbox_dhcp_helper.py
=====================
Sync DHCP helper / relay addresses from Cisco devices (IOS, IOS-XE, NX-OS)
into the ``dhcp_helper`` custom field on the matching NetBox interfaces.

The field holds a comma separated, numerically sorted list (``10.1.0.1,10.2.0.1``).
An interface is only written when its current list differs from the device;
interfaces with no helper on the device are cleared.  Virtual Chassis member
interfaces are routed to the correct member device.

Device selection, credentials and Vault options match find_dhcp_helper.py /
sync_netbox_interfaces.py.  Use --dry-run to see what would change.
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List

from cisco_device_client import CiscoDeviceClient, CiscoDeviceClientError
from netbox_client import NetBoxClient, NetBoxClientError
from sync_netbox_interfaces import (
    _configure_logging,
    _device_has_primary_ip,
    build_vc_member_map,
    expand_interface_name,
    get_device_mgmt_ip,
    get_device_os_type,
    resolve_device_list,
    resolve_target_device_id,
)
from vault_client import (
    VaultClient,
    VaultError,
    add_vault_parser_args,
    is_vault_configured,
    resolve_vault_auth,
)

log = logging.getLogger("netbox_dhcp_helper")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Sync DHCP helper addresses from Cisco devices to the "
                    "NetBox interface 'dhcp_helper' custom field.",
    )

    nb = p.add_argument_group("NetBox connection")
    nb.add_argument("--netbox-url", default=os.environ.get("NETBOX_URL", ""),
                    metavar="URL", help="NetBox base URL (env: NETBOX_URL). Ignored when Vault is configured.")
    nb.add_argument("--netbox-token", default=os.environ.get("NETBOX_API", ""),
                    metavar="TOKEN", help="NetBox API token (env: NETBOX_API). Ignored when Vault is configured.")
    nb.add_argument("--netbox-verify-ssl", action=argparse.BooleanOptionalAction,
                    default=True, help="Verify NetBox TLS certificate (default: true)")

    sel = p.add_argument_group("Device selection (pick one, or omit for all)")
    sel.add_argument("--device", metavar="NAME", help="Single device name")
    sel.add_argument("--devices", metavar="NAME,...", help="Comma-separated device names")
    sel.add_argument("--device-file", metavar="PATH",
                     help="File with one device name per line (#comments ignored)")
    sel.add_argument("--device-filter", default="{}", metavar="JSON",
                     help="NetBox DCIM device filter as JSON (default: all devices)")
    sel.add_argument("--all", dest="all_devices", action="store_true",
                     help="Explicit 'process all' flag")
    sel.add_argument("--site-slug", default="", metavar="SLUG",
                     help="Limit to devices in this NetBox site (slug). Stacks with --device-filter.")

    cred = p.add_argument_group("Cisco credentials")
    cred.add_argument("--username", default=os.environ.get("CISCO_SRV_ACCOUNT", ""),
                      help="SSH username (env: CISCO_SRV_ACCOUNT). Ignored when Vault is configured.")
    cred.add_argument("--password", default=os.environ.get("CISCO_SRV_PWD", ""),
                      help="SSH password (env: CISCO_SRV_PWD). Ignored when Vault is configured.")
    cred.add_argument("--enable-secret", default=os.environ.get("CISCO_ENABLE_PWD", ""),
                      help="Enable-mode secret (env: CISCO_ENABLE_PWD)")

    run = p.add_argument_group("Runtime options")
    run.add_argument("--dry-run", action="store_true",
                     help="Report what would change without writing to NetBox")
    run.add_argument("--max-workers", type=int, default=5, metavar="N",
                     help="Concurrent device threads (default: 5)")
    run.add_argument("--timeout", type=int, default=30, metavar="SEC",
                     help="Device connect timeout seconds (default: 30)")
    run.add_argument("--read-timeout", type=int, default=90, metavar="SEC",
                     help="Seconds to wait for command output (default: 90)")
    run.add_argument("--log-level", choices=["DEBUG", "INFO", "WARNING", "ERROR"],
                     default="INFO")
    run.add_argument("--log-file", metavar="PATH", default=None,
                     help="Also write log output to this file (appended, UTF-8).")

    add_vault_parser_args(p.add_argument_group("Vault authentication"))
    return p


def sync_device_helpers(device: dict, nb: NetBoxClient, args: argparse.Namespace) -> dict:
    """Sync one device.  Never raises; errors land in the returned dict."""
    name = device.get("name") or "unknown"
    result = {"device": name, "status": "failed", "updated": 0, "error": None}

    if not _device_has_primary_ip(device):
        result["error"] = "no primary IP in NetBox"
        return result
    os_type = get_device_os_type(device)
    if not os_type:
        result["error"] = f"unsupported/unknown platform {device.get('platform')!r}"
        return result

    device_id = device["id"]
    vc = device.get("virtual_chassis")
    vc_id = device.get("_vc_id") or (vc.get("id") if isinstance(vc, dict) else None)
    vc_member_map = build_vc_member_map(vc_id, nb) if vc_id else {}
    all_ids = {device_id} | set(vc_member_map.values())

    try:
        with CiscoDeviceClient(
            host=get_device_mgmt_ip(device),
            username=args.username,
            password=args.password,
            os_type=os_type,
            enable_secret=args.enable_secret,
            timeout=args.timeout,
        ) as cisco:
            cisco._cli_connect()
            # shortcut: Netmiko >=4.1 attribute; default 10s is too short for show run under load.
            cisco._cli_connection.read_timeout_override = args.read_timeout
            helper_map = cisco.get_interface_dhcp_helper_map()
    except (CiscoDeviceClientError, Exception) as exc:
        result["error"] = str(exc)
        return result

    if helper_map is None:
        # Never treat a failed fetch as "no helpers" — that would clear every field.
        result["error"] = "interface config unavailable"
        return result

    desired: Dict[int, Dict[str, str]] = {i: {} for i in all_ids}
    for raw_name, ips in helper_map.items():
        n = expand_interface_name(raw_name)
        desired[resolve_target_device_id(n, device_id, vc_member_map)][n] = ips

    try:
        result["updated"] = sum(
            nb.sync_interface_dhcp_helpers(i, m, dry_run=args.dry_run)
            for i, m in desired.items()
        )
    except NetBoxClientError as exc:
        result["error"] = str(exc)
        return result

    result["status"] = "success"
    return result


def main() -> None:
    args = build_parser().parse_args()
    _configure_logging(args.log_level, args.log_file)

    if is_vault_configured(args):
        addr, role_id, secret_id = resolve_vault_auth(args)
        vault = VaultClient(addr=addr, role_id=role_id, secret_id=secret_id,
                            mount=args.vault_mount, path=args.vault_path)
        try:
            secrets = vault.get_secrets()
        except VaultError as exc:
            log.error("Failed to load credentials from Vault: %s", exc)
            sys.exit(1)
        args.username = secrets["user"]
        args.password = secrets["password"]
        netbox_url, netbox_token = secrets["netbox_url"], secrets["netbox_token"]
    else:
        missing: List[str] = [
            flag for flag, val in (
                ("--netbox-url / NETBOX_URL", args.netbox_url),
                ("--netbox-token / NETBOX_API", args.netbox_token),
                ("--username / CISCO_SRV_ACCOUNT", args.username),
                ("--password / CISCO_SRV_PWD", args.password),
            ) if not val
        ]
        if missing:
            log.error("Missing required credentials: %s", ", ".join(missing))
            sys.exit(1)
        netbox_url, netbox_token = args.netbox_url, args.netbox_token

    nb = NetBoxClient(
        base_url=netbox_url,
        token=netbox_token,
        verify_ssl=args.netbox_verify_ssl,
        threading=True,
        pool_size=max(args.max_workers + 10, 20),
    )

    devices = resolve_device_list(args, nb)
    if not devices:
        log.warning("No devices to process.")
        return
    log.info("Syncing DHCP helpers for %d device(s), %d worker(s)%s",
             len(devices), args.max_workers, "  [DRY-RUN]" if args.dry_run else "")

    results: List[dict] = []
    with ThreadPoolExecutor(max_workers=args.max_workers) as pool:
        futures = {pool.submit(sync_device_helpers, d, nb, args): d for d in devices}
        for fut in as_completed(futures):
            dev_name = futures.pop(fut).get("name", "unknown")
            try:
                r = fut.result()
            except Exception as exc:
                r = {"device": dev_name, "status": "failed", "updated": 0, "error": str(exc)}
            results.append(r)
            if r["status"] == "success":
                log.info("%-30s  dhcp_helper %s on %d interface(s)", dev_name,
                         "would update" if args.dry_run else "updated", r["updated"])
            else:
                log.warning("%-30s  skipped: %s", dev_name, r["error"])

    ok = sum(1 for r in results if r["status"] == "success")
    log.info("DONE  devices=%d ok=%d failed=%d  interfaces_%s=%d",
             len(results), ok, len(results) - ok,
             "to_update" if args.dry_run else "updated",
             sum(r["updated"] for r in results))


if __name__ == "__main__":
    main()
