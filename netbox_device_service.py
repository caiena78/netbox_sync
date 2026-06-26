#!/usr/bin/env python3
"""
netbox_device_service.py
========================
Probe each NetBox device for running TCP services and update the corresponding
device custom fields with true/false.

Services tested
---------------
  telnet  — TCP port  23
  http    — TCP port  80
  https   — TCP port 443
  netconf — TCP port 830

For each device the script:
  1. Resolves its primary management IP (primary_ip4 → primary_ip6 → oob_ip).
  2. Attempts a non-blocking TCP connect to each port.
  3. PATCHes the device's custom_fields on NetBox with the results.

Usage examples
--------------
    python netbox_device_service.py --device-filter '{"status":"active"}'
    python netbox_device_service.py --device sw1 --dry-run
    python netbox_device_service.py --site-slug lakeview
    python netbox_device_service.py --devices sw1,sw2,sw3
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Tuple

from netbox_client import NetBoxClient, NetBoxClientError
from vault_client import (
    VaultClient,
    VaultError,
    add_vault_parser_args,
    is_vault_configured,
    resolve_vault_auth,
)

# --------------------------------------------------------------------------- #
# Service definitions                                                          #
# --------------------------------------------------------------------------- #

SERVICES: List[Tuple[str, int]] = [
    ("telnet",  23),
    ("http",    80),
    ("https",   443),
    ("netconf", 830),
]

log = logging.getLogger("netbox_device_service")


# --------------------------------------------------------------------------- #
# TCP probe                                                                    #
# --------------------------------------------------------------------------- #

def _probe_port(host: str, port: int, timeout: float = 3.0) -> tuple:
    """
    Attempt a TCP connection to host:port.

    Returns (is_open: bool, reason: str) where reason is one of:
      "open"      — TCP handshake succeeded
      "refused"   — connection actively rejected (port closed on host)
      "timeout"   — no reply within timeout (firewall drop or unreachable)
      "error: …"  — other OS/network error
    """
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True, "open"
    except ConnectionRefusedError:
        return False, "refused"
    except (socket.timeout, TimeoutError):
        return False, "timeout"
    except OSError as exc:
        return False, f"error: {exc}"


# --------------------------------------------------------------------------- #
# Device helpers                                                               #
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
        log.debug(
            "Device %r is in site %r, not %r — skipped by site filter",
            device.get("name", "?"), slug, site_slug,
        )
        return False
    return True


def _resolve_device_list(args: argparse.Namespace, nb: NetBoxClient) -> List[dict]:
    site_slug: str = getattr(args, "site_slug", "") or ""

    if args.device:
        d = nb.get_device(name=args.device.strip())
        if d and _site_slug_matches(d, site_slug):
            return [d]
        return []

    if args.devices:
        result = []
        for name in [n.strip() for n in args.devices.split(",") if n.strip()]:
            d = nb.get_device(name=name)
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
            d = nb.get_device(name=name)
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
# Per-device service probe                                                     #
# --------------------------------------------------------------------------- #

def probe_device_services(
    device: dict,
    nb: NetBoxClient,
    args: argparse.Namespace,
) -> dict:
    """
    Probe TCP services on one device and update its NetBox custom fields.

    Returns a JSON-serialisable summary dict.
    """
    device_name = device.get("name", "unknown")
    device_id   = device.get("id")

    summary: dict = {
        "device":   device_name,
        "status":   "failed",
        "ip":       None,
        "services": {},
        "errors":   [],
    }

    mgmt_ip = _get_mgmt_ip(device)
    if not mgmt_ip:
        msg = "No primary IP — skipped."
        summary["errors"].append(msg)
        log.warning("%-30s  SKIPPED — %s", device_name, msg)
        return summary

    summary["ip"] = mgmt_ip
    log.info("%-30s  ip=%s", device_name, mgmt_ip)

    results: Dict[str, bool] = {}
    for svc_name, port in SERVICES:
        is_open, reason = _probe_port(mgmt_ip, port, timeout=args.connect_timeout)
        results[svc_name] = is_open
        log.info(
            "%-30s  %-8s port=%-5d  %s",
            device_name, svc_name, port, reason,
        )

    summary["services"] = results

    if args.dry_run:
        log.info(
            "DRY-RUN  %-30s  would update custom_fields=%s",
            device_name, results,
        )
        summary["status"] = "dry-run"
        return summary

    try:
        nb.update_device(device_id, {"custom_fields": results})
        log.info("%-30s  custom_fields updated", device_name)
        summary["status"] = "success"
    except NetBoxClientError as exc:
        summary["errors"].append(f"NetBox update failed: {exc}")
        log.error("%-30s  update failed: %s", device_name, exc)

    return summary


# --------------------------------------------------------------------------- #
# CLI parser                                                                   #
# --------------------------------------------------------------------------- #

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Probe NetBox devices for TCP services and update custom fields.",
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
    sel.add_argument("--device",       metavar="NAME",
                     help="Single device by name")
    sel.add_argument("--devices",      metavar="NAME,...",
                     help="Comma-separated list of device names")
    sel.add_argument("--device-file",  metavar="PATH",
                     help="File with one device name per line")
    sel.add_argument("--device-filter", default="{}",
                     metavar="JSON", help="NetBox DCIM filter JSON (default: all devices)")
    sel.add_argument("--site-slug",    default="", metavar="SLUG",
                     help="Limit to devices in this NetBox site slug. Stacks with --device-filter.")

    run = p.add_argument_group("Runtime")
    run.add_argument("--dry-run", action="store_true",
                     help="Probe services but make no NetBox writes")
    run.add_argument("--max-workers", type=int, default=10,
                     help="Number of concurrent device threads (default: 10)")
    run.add_argument("--connect-timeout", type=float, default=3.0,
                     help="TCP connect timeout per port in seconds (default: 3)")
    run.add_argument("--log-level",
                     choices=["DEBUG", "INFO", "WARNING", "ERROR"],
                     default="INFO")
    run.add_argument("--log-file", metavar="PATH", default=None,
                     help="Also write log output to this file (appended, UTF-8)")

    vault_grp = p.add_argument_group(
        "Vault authentication",
        "HashiCorp Vault AppRole credentials. CLI args take precedence over env vars.",
    )
    add_vault_parser_args(vault_grp)

    return p


# --------------------------------------------------------------------------- #
# Logging setup                                                                #
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
            log.info("Log file: %s", log_file)
        except OSError as exc:
            log.warning("Cannot open log file %r: %s — logging to stderr only", log_file, exc)


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
        netbox_url   = secrets["netbox_url"]
        netbox_token = secrets["netbox_token"]
    else:
        missing = []
        if not args.netbox_url:
            missing.append("--netbox-url / NETBOX_URL")
        if not args.netbox_token:
            missing.append("--netbox-token / NETBOX_API")
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

    log.info("Processing %d device(s) with %d worker(s)", len(devices), args.max_workers)

    summaries: List[dict] = []
    with ThreadPoolExecutor(max_workers=args.max_workers) as pool:
        future_to_device = {
            pool.submit(probe_device_services, device, nb, args): device
            for device in devices
        }
        for future in as_completed(future_to_device):
            device      = future_to_device[future]
            device_name = device.get("name", "unknown")
            try:
                result = future.result()
                summaries.append(result)
                log.info(
                    "%-30s  status=%-8s  services=%s  errs=%d",
                    device_name, result.get("status", "?"),
                    result.get("services", {}),
                    len(result.get("errors", [])),
                )
            except Exception as exc:
                log.error("Unexpected error for %s: %s", device_name, exc)
                summaries.append({
                    "device":   device_name,
                    "status":   "failed",
                    "ip":       None,
                    "services": {},
                    "errors":   [str(exc)],
                })

    summaries.sort(key=lambda s: s.get("device", ""))

    total_success = sum(1 for s in summaries if s.get("status") == "success")
    total_dryrun  = sum(1 for s in summaries if s.get("status") == "dry-run")
    total_failed  = sum(1 for s in summaries if s.get("status") == "failed")

    log.info(
        "DONE  devices=%d  success=%d  dry-run=%d  failed=%d",
        len(summaries), total_success, total_dryrun, total_failed,
    )

    print(json.dumps(summaries, indent=2))


if __name__ == "__main__":
    main()
