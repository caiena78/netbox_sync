#!/usr/bin/env python3
"""
find_dhcp_helper.py
====================
Search Cisco devices (IOS, IOS-XE, NX-OS) pulled from NetBox for a DHCP
helper / relay address, and record which devices have it configured.

For every resolved device this runs::

    show running-config | include <dhcp-helper-ip>

If the address shows up anywhere in the output, the device name is written
to the output file (default: helper_devices.txt).

Device selection and NetBox connection options mirror
sync_netbox_interfaces.py so the same filters can be reused here.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional

from cisco_device_client import CiscoDeviceClient, CiscoDeviceClientError
from netbox_client import NetBoxClient, NetBoxClientError
from vault_client import (
    VaultClient,
    VaultError,
    add_vault_parser_args,
    is_vault_configured,
    resolve_vault_auth,
)

DEFAULT_OUTPUT_FILE = "helper_devices.txt"

# CiscoDeviceClient only knows how to speak to these platforms.
PLATFORM_SLUG_MAP: Dict[str, str] = {
    "iosxe": "iosxe", "ios-xe": "iosxe", "ios_xe": "iosxe",
    "cisco-iosxe": "iosxe", "cisco_iosxe": "iosxe",
    "nxos": "nxos", "nx-os": "nxos", "nx_os": "nxos",
    "cisco-nxos": "nxos", "cisco_nxos": "nxos",
    "ios": "ios", "cisco-ios": "ios", "cisco_ios": "ios",
}

log = logging.getLogger("find_dhcp_helper")


# --------------------------------------------------------------------------- #
# CLI argument parser                                                          #
# --------------------------------------------------------------------------- #

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Find Cisco devices configured with a given DHCP helper address.",
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
        "--dhcp-helper",
        required=True,
        metavar="IP",
        help="DHCP helper / relay address to search for in each device's running-config",
    )
    run.add_argument(
        "--output-file",
        default=DEFAULT_OUTPUT_FILE,
        metavar="PATH",
        help=f"File to write matching device names to (default: {DEFAULT_OUTPUT_FILE})",
    )
    run.add_argument("--max-workers", type=int, default=5, metavar="N",
                     help="Concurrent device threads (default: 5)")
    run.add_argument("--timeout", type=int, default=30, metavar="SEC",
                     help="Device timeout seconds (default: 30)")
    run.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="INFO",
    )
    run.add_argument(
        "--log-file",
        metavar="PATH",
        default=None,
        help="Also write log output to this file (appended, UTF-8).",
    )

    vault_grp = p.add_argument_group("Vault authentication")
    add_vault_parser_args(vault_grp)

    return p


# --------------------------------------------------------------------------- #
# NetBox helpers                                                               #
# --------------------------------------------------------------------------- #

def _site_slug_matches(device: dict, site_slug: str) -> bool:
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
        return False
    return True


def resolve_device_list(args: argparse.Namespace, nb: NetBoxClient) -> List[dict]:
    """Return the ordered list of NetBox device dicts to process."""
    site_slug: str = getattr(args, "site_slug", "") or ""

    if args.device:
        d = nb.get_device(name=args.device.strip())
        if d and _site_slug_matches(d, site_slug):
            return [d]
        return []

    if args.devices:
        names = [n.strip() for n in args.devices.split(",") if n.strip()]
        result = []
        for name in names:
            d = nb.get_device(name=name)
            if d and _site_slug_matches(d, site_slug):
                result.append(d)
            elif not d:
                log.warning("%r not found in NetBox.", name)
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
            d = nb.get_device(name=name)
            if d and _site_slug_matches(d, site_slug):
                result.append(d)
            elif not d:
                log.warning("%r not found in NetBox.", name)
        return result

    # Default: all devices matching --device-filter (--all or no selector given).
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
    return bool(device.get("primary_ip4") or device.get("primary_ip6"))


def get_device_mgmt_ip(device: dict) -> Optional[str]:
    """Return the best available management IP for a device dict."""
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


# --------------------------------------------------------------------------- #
# Per-device check                                                             #
# --------------------------------------------------------------------------- #

def check_device_for_helper(
    device: dict,
    args: argparse.Namespace,
) -> dict:
    """
    Connect to *device* and check whether --dhcp-helper appears in its
    running-config.

    Returns
    -------
    dict
        ``{"device": str, "status": "success"|"failed", "found": bool, "error": str|None}``
    """
    device_name = device.get("name") or "unknown"
    result = {"device": device_name, "status": "failed", "found": False, "error": None}

    if not _device_has_primary_ip(device):
        result["error"] = "no primary or OOB IP in NetBox"
        return result

    ip = get_device_mgmt_ip(device)
    os_type = get_device_os_type(device)
    if not os_type:
        result["error"] = f"unsupported/unknown platform {device.get('platform')!r}"
        return result

    command = f"show running-config | include {args.dhcp_helper}"
    try:
        with CiscoDeviceClient(
            host=ip,
            username=args.username,
            password=args.password,
            os_type=os_type,
            enable_secret=args.enable_secret,
            timeout=args.timeout,
        ) as cisco:
            raw, _parsed, _parser = cisco._cli_run_command(command, parse=False)
    except (CiscoDeviceClientError, Exception) as exc:
        result["error"] = str(exc)
        return result

    result["status"] = "success"
    result["found"] = args.dhcp_helper in raw
    return result


# --------------------------------------------------------------------------- #
# Logging setup                                                               #
# --------------------------------------------------------------------------- #

def _configure_logging(level: str, log_file: Optional[str] = None) -> None:
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

    log.info(
        "Checking %d device(s) for DHCP helper %s, %d worker(s)",
        len(devices), args.dhcp_helper, args.max_workers,
    )

    results: List[dict] = []
    with ThreadPoolExecutor(max_workers=args.max_workers) as pool:
        future_to_device = {
            pool.submit(check_device_for_helper, device, args): device
            for device in devices
        }
        for future in as_completed(future_to_device):
            device = future_to_device.pop(future)
            device_name = device.get("name", "unknown")
            try:
                result = future.result()
            except Exception as exc:
                result = {
                    "device": device_name,
                    "status": "failed",
                    "found": False,
                    "error": str(exc),
                }
            results.append(result)
            if result["status"] == "success":
                log.info(
                    "%-30s  helper %s: %s",
                    device_name, args.dhcp_helper,
                    "FOUND" if result["found"] else "not found",
                )
            else:
                log.warning("%-30s  skipped: %s", device_name, result["error"])

    found_devices = sorted(r["device"] for r in results if r["found"])

    with open(args.output_file, "w", encoding="utf-8") as fh:
        for name in found_devices:
            fh.write(name + "\n")

    total_ok   = sum(1 for r in results if r["status"] == "success")
    total_fail = sum(1 for r in results if r["status"] == "failed")
    log.info(
        "DONE  devices=%d checked=%d failed=%d  matches=%d  output=%s",
        len(results), total_ok, total_fail, len(found_devices), args.output_file,
    )


if __name__ == "__main__":
    main()
