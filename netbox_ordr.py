#!/usr/bin/env python3
"""
netbox_ordr.py
==============
Fetch the MAC address table from each switch and verify that every MAC is
known to Ordr.  Any MAC not found in Ordr is logged to
logs/<device_name>_<ip_address>.txt.

All credentials live in one Vault path (--vault-path, default: network/device):
  user            — Cisco SSH username
  password        — Cisco SSH password
  netbox_url      — NetBox base URL
  netbox_token    — NetBox API token
  ORDR_USER       — Ordr API username
  ORDR_PASSWORD   — Ordr API password
  ORDR_TENANTGUID — Ordr tenant GUID
  ORDR_URL        — Ordr base URL

Without Vault, set env vars for each key (same names as above).

Device filter flags (same as netbox_cables.py)
----------------------------------------------
  --device NAME
  --devices NAME,...
  --device-file PATH
  --device-filter JSON
  --site-slug SLUG

Usage examples
--------------
    python netbox_ordr.py --device sw1
    python netbox_ordr.py --site-slug lakeview
    python netbox_ordr.py --device-filter '{"status":"active"}'
    python netbox_ordr.py --device-filter '{"status":"active"}' --max-workers 10
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set
from urllib.parse import urlparse

import hvac
import hvac.exceptions
import requests
from urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

from cisco_device_client import CiscoDeviceClient, CiscoDeviceClientError
from netbox_client import NetBoxClient
from vault_client import (
    VaultError,
    add_vault_parser_args,
    is_vault_configured,
    resolve_vault_auth,
)

# --------------------------------------------------------------------------- #
# Platform slug → os_type (same mapping as netbox_cables.py)                  #
# --------------------------------------------------------------------------- #

PLATFORM_SLUG_MAP: Dict[str, str] = {
    "iosxe": "iosxe", "ios-xe": "iosxe", "ios_xe": "iosxe",
    "cisco-iosxe": "iosxe", "cisco_iosxe": "iosxe",
    "nxos": "nxos", "nx-os": "nxos", "nx_os": "nxos",
    "cisco-nxos": "nxos", "cisco_nxos": "nxos",
    "ios": "ios", "cisco-ios": "ios", "cisco_ios": "ios",
}

_ORDR_BASE_URL     = "https://pdmg5uxb.cloud.ordr.net"
_ORDR_DEVICES_PATH = "/Rest/Devices"


def _ordr_origin(url: str) -> str:
    """Return just scheme+host from *url*, discarding any path component.

    Prevents double-path errors when ORDR_URL in Vault already includes
    a path segment (e.g. 'https://host/Rest') and _ORDR_DEVICES_PATH
    would otherwise be appended on top of it.
    """
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}"

# All keys the script requires from the Vault secret (or env vars)
_REQUIRED_KEYS = frozenset({
    "user", "password", "netbox_url", "netbox_token",
    "ORDR_USER", "ORDR_PASSWORD", "ORDR_TENANTGUID", "ORDR_URL",
})

# Candidate field names for the MAC address in an Ordr device object.
# The first one found in the first device record is used for all devices.
_ORDR_MAC_FIELDS = ("macAddress", "mac", "MacAddress", "MAC", "clientMacToken")

log = logging.getLogger("netbox_ordr")


# --------------------------------------------------------------------------- #
# Vault: single raw fetch for all credentials                                  #
# --------------------------------------------------------------------------- #

def _fetch_vault_secrets(
    addr: str,
    role_id: str,
    secret_id: str,
    mount: str,
    path: str,
) -> Dict[str, str]:
    """
    Authenticate with Vault using AppRole and return ALL keys from *path* as
    a flat string dict.  Validates that every key in _REQUIRED_KEYS is present.
    """
    try:
        client = hvac.Client(url=addr)
        client.auth.approle.login(role_id=role_id, secret_id=secret_id)
    except hvac.exceptions.VaultError as exc:
        raise VaultError(f"Vault AppRole auth failed: {exc}") from exc
    except Exception as exc:
        raise VaultError(f"Unexpected Vault auth error: {exc}") from exc

    if not client.is_authenticated():
        raise VaultError("Vault auth completed but no valid token was issued.")

    try:
        resp = client.secrets.kv.v2.read_secret_version(
            mount_point=mount,
            path=path,
            raise_on_deleted_version=True,
        )
    except hvac.exceptions.InvalidPath as exc:
        raise VaultError(
            f"Vault secret not found — mount={mount!r} path={path!r}: {exc}"
        ) from exc
    except hvac.exceptions.Forbidden as exc:
        raise VaultError(
            f"Vault permission denied — mount={mount!r} path={path!r}: {exc}"
        ) from exc
    except hvac.exceptions.VaultError as exc:
        raise VaultError(f"Vault secret read error: {exc}") from exc

    raw: dict = resp.get("data", {}).get("data", {})
    missing = sorted(_REQUIRED_KEYS - raw.keys())
    if missing:
        raise VaultError(
            f"Vault secret at '{mount}/{path}' is missing required key(s): "
            f"{', '.join(missing)}"
        )

    return {k: str(v) for k, v in raw.items()}


# --------------------------------------------------------------------------- #
# MAC normalisation                                                            #
# --------------------------------------------------------------------------- #

def _normalize_mac(mac: str) -> str:
    """Normalise any MAC address format to lowercase colon-separated hex."""
    stripped = mac.lower().replace(".", "").replace(":", "").replace("-", "")
    if len(stripped) != 12 or not all(c in "0123456789abcdef" for c in stripped):
        return mac.lower()
    return ":".join(stripped[i:i + 2] for i in range(0, 12, 2))


# --------------------------------------------------------------------------- #
# Ordr API                                                                     #
# --------------------------------------------------------------------------- #

def _ordr_get(url: str, params: dict, user: str, password: str) -> dict:
    headers = {"Accept": "application/json"}
    resp = requests.get(
        url, params=params, headers=headers,
        auth=(user, password), verify=False, timeout=60,
    )
    resp.raise_for_status()
    return resp.json()


def fetch_ordr_mac_set(secrets: Dict[str, str]) -> Set[str]:
    """
    Fetch all Ordr devices (paginated) and return a set of normalised MAC
    addresses.  The MAC field in each device object is auto-detected from
    common field names.  Returns an empty set (with a warning) when the MAC
    field cannot be determined.
    """
    origin      = _ordr_origin(secrets.get("ORDR_URL", _ORDR_BASE_URL) or _ORDR_BASE_URL)
    tenant_guid = secrets["ORDR_TENANTGUID"]
    user        = secrets["ORDR_USER"]
    password    = secrets["ORDR_PASSWORD"]

    devices_url = origin + _ORDR_DEVICES_PATH
    all_devices: List[dict] = []
    next_path: Optional[str] = None

    log.info("Fetching Ordr device inventory (tenant=%s) ...", tenant_guid)
    while True:
        if next_path:
            current_url = origin + next_path
            data = _ordr_get(current_url, {}, user, password)
        else:
            data = _ordr_get(devices_url, {"tenantGuid": tenant_guid}, user, password)

        batch = data.get("Devices", [])
        all_devices.extend(batch)
        next_path = data.get("MetaData", {}).get("next")

        log.debug("Ordr page: %d device(s)  (running total: %d)", len(batch), len(all_devices))
        if not next_path:
            break

    log.info("Ordr: fetched %d device(s) total", len(all_devices))

    if not all_devices:
        log.warning("Ordr returned 0 devices — all MACs will be reported as missing")
        return set()

    # Auto-detect MAC field from the first device object
    mac_field: Optional[str] = None
    for candidate in _ORDR_MAC_FIELDS:
        if candidate in all_devices[0]:
            mac_field = candidate
            log.debug("Ordr MAC field detected: %r", mac_field)
            break

    if not mac_field:
        log.warning(
            "Could not detect a MAC address field in Ordr device objects "
            "(checked: %s).  All switch MACs will be reported as missing.  "
            "Use --ordr-mac-field to specify the correct field name.",
            ", ".join(_ORDR_MAC_FIELDS),
        )
        return set()

    mac_set: Set[str] = set()
    for dev in all_devices:
        raw_mac = dev.get(mac_field, "")
        if raw_mac:
            mac_set.add(_normalize_mac(str(raw_mac)))

    log.info("Ordr: extracted %d unique MAC(s)", len(mac_set))
    return mac_set


def _lookup_mac_ordr(mac: str, secrets: Dict[str, str]) -> bool:
    """
    Per-MAC Ordr lookup.  Used as a fallback when bulk MAC extraction fails.
    Returns True if the MAC is found in Ordr, False otherwise.
    """
    origin      = _ordr_origin(secrets.get("ORDR_URL", _ORDR_BASE_URL) or _ORDR_BASE_URL)
    tenant_guid = secrets["ORDR_TENANTGUID"]
    user        = secrets["ORDR_USER"]
    password    = secrets["ORDR_PASSWORD"]

    devices_url = origin + _ORDR_DEVICES_PATH
    try:
        data = _ordr_get(
            devices_url,
            {"mac": mac.upper(), "tenantGuid": tenant_guid},
            user, password,
        )
        return bool(data.get("Devices"))
    except Exception as exc:
        log.debug("Ordr per-MAC lookup failed for %s: %s", mac, exc)
        return False


# --------------------------------------------------------------------------- #
# NetBox device helpers (mirrors netbox_cables.py)                             #
# --------------------------------------------------------------------------- #

def _device_has_primary_ip(device: dict) -> bool:
    return bool(device.get("primary_ip4") or device.get("primary_ip6"))


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
        if isinstance(platform, dict) else str(platform).lower().strip()
    )
    return PLATFORM_SLUG_MAP.get(slug)


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
    return slug == site_slug


def _resolve_single_device(name: str, nb: NetBoxClient) -> Optional[dict]:
    """
    Resolve one device name.  Tries Virtual Chassis first (picks first member
    with a management IP), then falls back to a regular device lookup.
    """
    try:
        vc = nb.find_virtual_chassis(name.lower())
        if vc:
            members = nb.get_virtual_chassis_members(vc["id"])
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
# Per-device processing                                                        #
# --------------------------------------------------------------------------- #

def _write_missing_log(
    log_dir: Path,
    device_name: str,
    mgmt_ip: str,
    missing: List[dict],
) -> None:
    """Write missing MACs to logs/<device_name>_<ip>.txt."""
    safe_name = re.sub(r"[^\w\-.]", "_", device_name)
    safe_ip   = mgmt_ip.replace(":", "_")   # guard against IPv6
    log_path  = log_dir / f"{safe_name}_{safe_ip}.txt"
    log_dir.mkdir(parents=True, exist_ok=True)

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines = [
        f"Switch: {device_name}",
        f"Management IP: {mgmt_ip}",
        f"Run: {now}",
        f"Missing from Ordr ({len(missing)} MAC(s)):",
        "",
    ]
    for entry in sorted(missing, key=lambda e: e.get("mac", "")):
        mac   = entry.get("mac", "unknown")
        vlan  = entry.get("vlan", "?")
        iface = entry.get("interface", "?")
        lines.append(f"  {mac}  vlan={vlan}  interface={iface}")

    log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    log.info("%-30s  log written: %s", device_name, log_path)


def process_device(
    device: dict,
    args: argparse.Namespace,
    secrets: Dict[str, str],
    ordr_mac_set: Set[str],
    log_dir: Path,
) -> dict:
    """
    Collect the MAC address table from one switch and check each entry against
    the Ordr device inventory.  Missing MACs are written to a log file.
    """
    device_name = device.get("name", "unknown")
    summary: dict = {
        "device":        device_name,
        "status":        "failed",
        "mac_count":     0,
        "missing_count": 0,
        "errors":        [],
    }

    if not _device_has_primary_ip(device):
        msg = "No primary_ip4 / primary_ip6 in NetBox — skipped"
        summary["errors"].append(msg)
        log.warning("%-30s  SKIPPED — %s", device_name, msg)
        return summary

    mgmt_ip = _get_mgmt_ip(device)
    if not mgmt_ip:
        summary["errors"].append("No management IP — cannot connect")
        return summary

    os_type = _get_os_type(device)
    if not os_type:
        summary["errors"].append(
            f"Unknown platform {device.get('platform')!r} — add to PLATFORM_SLUG_MAP"
        )
        return summary

    log.info("%-30s  ip=%-18s  os_type=%s", device_name, mgmt_ip, os_type)

    cisco = CiscoDeviceClient(
        host=mgmt_ip,
        username=secrets["user"],
        password=secrets["password"],
        os_type=os_type,
        enable_secret=args.enable_secret or None,
        timeout=args.timeout,
        verify_ssl=False,
    )

    try:
        mac_entries = cisco.get_mac_address_table()
    except CiscoDeviceClientError as exc:
        summary["errors"].append(f"MAC table collection failed: {exc}")
        cisco._cli_disconnect()
        return summary

    cisco._cli_disconnect()

    summary["mac_count"] = len(mac_entries)
    log.info("%-30s  MAC table: %d entry(ies)", device_name, len(mac_entries))

    if not mac_entries:
        summary["status"] = "success"
        return summary

    # Use bulk set when available, otherwise fall back to per-MAC API lookups
    use_bulk = bool(ordr_mac_set)

    missing: List[dict] = []
    for entry in mac_entries:
        mac = entry.get("mac", "")
        if not mac:
            continue
        norm = _normalize_mac(mac)
        found = norm in ordr_mac_set if use_bulk else _lookup_mac_ordr(norm, secrets)
        if not found:
            missing.append(entry)

    summary["missing_count"] = len(missing)
    log.info(
        "%-30s  missing from Ordr: %d / %d MAC(s)",
        device_name, len(missing), len(mac_entries),
    )

    if missing:
        _write_missing_log(log_dir, device_name, mgmt_ip, missing)

    summary["status"] = "success"
    return summary


# --------------------------------------------------------------------------- #
# CLI parser                                                                   #
# --------------------------------------------------------------------------- #

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Check switch MAC tables against the Ordr device inventory.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    sel = p.add_argument_group("Device selection")
    sel.add_argument("--device",       metavar="NAME",    help="Single device by name")
    sel.add_argument("--devices",      metavar="NAME,...", help="Comma-separated device names")
    sel.add_argument("--device-file",  metavar="PATH",
                     help="File with one device name per line")
    sel.add_argument("--device-filter", default="{}",
                     metavar="JSON",   help="NetBox DCIM filter JSON (default: all)")
    sel.add_argument(
        "--site-slug", default="", metavar="SLUG",
        help="Limit to devices in this NetBox site slug. Stacks with --device-filter.",
    )

    ordr_grp = p.add_argument_group("Ordr")
    ordr_grp.add_argument(
        "--ordr-mac-field", default=None, metavar="FIELD",
        help=(
            "Force a specific MAC field name in Ordr device objects "
            "(e.g. macAddress).  Auto-detected when omitted."
        ),
    )

    run = p.add_argument_group("Runtime")
    run.add_argument("--enable-secret",
                     default=os.environ.get("CISCO_ENABLE_PWD", ""),
                     help="Cisco enable secret (env: CISCO_ENABLE_PWD)")
    run.add_argument("--netbox-verify-ssl",
                     action=argparse.BooleanOptionalAction, default=True)
    run.add_argument("--max-workers", type=int, default=5,
                     help="Concurrent devices to process (default: 5)")
    run.add_argument("--timeout",     type=int, default=30,
                     help="SSH connect timeout in seconds (default: 30)")
    run.add_argument(
        "--log-dir", default="logs", metavar="PATH",
        help="Directory for per-switch missing-MAC log files (default: logs)",
    )
    run.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="INFO",
    )
    run.add_argument(
        "--log-file", metavar="PATH", default=None,
        help="Also write log output to this file (appended, UTF-8).",
    )

    vault_grp = p.add_argument_group(
        "Vault authentication",
        "HashiCorp Vault AppRole credentials. "
        "All secrets (Cisco, NetBox, Ordr) are read from one Vault path.",
    )
    add_vault_parser_args(vault_grp)

    # Pull VAULT_MOUNT and VAULT_PATH from env vars; add_vault_parser_args()
    # hardcodes their defaults so we override them here.
    p.set_defaults(
        vault_mount=os.environ.get("VAULT_MOUNT", "secret"),
        vault_path=os.environ.get("VAULT_PATH",  "network/device"),
    )

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
            log.warning(
                "Cannot open log file %r: %s — logging to stderr only", log_file, exc
            )


# --------------------------------------------------------------------------- #
# Entry point                                                                  #
# --------------------------------------------------------------------------- #

def main() -> None:
    parser = build_parser()
    args   = parser.parse_args()

    _configure_logging(args.log_level, args.log_file)

    # ── Credential resolution ─────────────────────────────────────────────
    if is_vault_configured(args):
        vault_addr, vault_role_id, vault_secret_id = resolve_vault_auth(args)
        try:
            secrets = _fetch_vault_secrets(
                addr=vault_addr,
                role_id=vault_role_id,
                secret_id=vault_secret_id,
                mount=args.vault_mount,
                path=args.vault_path,
            )
        except VaultError as exc:
            log.error("Failed to load credentials from Vault: %s", exc)
            sys.exit(1)
        log.debug("Vault secrets loaded from %s/%s", args.vault_mount, args.vault_path)
    else:
        # Fall back to environment variables (same key names as Vault)
        secrets = {k: os.environ.get(k, "") for k in _REQUIRED_KEYS}
        missing = sorted(k for k in _REQUIRED_KEYS if not secrets[k])
        if missing:
            log.error(
                "Missing required credentials.  Set env vars or configure Vault.  "
                "Missing: %s",
                ", ".join(missing),
            )
            sys.exit(1)

    # ── NetBox client ─────────────────────────────────────────────────────
    nb = NetBoxClient(
        base_url=secrets["netbox_url"],
        token=secrets["netbox_token"],
        verify_ssl=args.netbox_verify_ssl,
        threading=True,
    )

    devices = _resolve_device_list(args, nb)
    if not devices:
        log.warning("No devices to process.")
        print(json.dumps([], indent=2))
        return

    log.info("Processing %d device(s), %d worker(s)", len(devices), args.max_workers)

    # ── Fetch full Ordr MAC inventory once (shared across all threads) ────
    mac_field_override = getattr(args, "ordr_mac_field", None)
    if mac_field_override:
        global _ORDR_MAC_FIELDS  # noqa: PLW0603
        _ORDR_MAC_FIELDS = (mac_field_override,) + tuple(
            f for f in _ORDR_MAC_FIELDS if f != mac_field_override
        )

    try:
        ordr_mac_set = fetch_ordr_mac_set(secrets)
    except Exception as exc:
        log.error("Failed to fetch Ordr device inventory: %s", exc)
        sys.exit(1)

    # ── Process devices concurrently ──────────────────────────────────────
    log_dir   = Path(args.log_dir)
    summaries: List[dict] = []

    with ThreadPoolExecutor(max_workers=args.max_workers) as pool:
        future_to_device = {
            pool.submit(process_device, device, args, secrets, ordr_mac_set, log_dir): device
            for device in devices
        }
        for future in as_completed(future_to_device):
            device      = future_to_device[future]
            device_name = device.get("name", "unknown")
            try:
                result = future.result()
                summaries.append(result)
                log.info(
                    "%-30s  status=%-8s  mac_count=%d  missing=%d  errs=%d",
                    device_name,
                    result.get("status", "?"),
                    result.get("mac_count",     0),
                    result.get("missing_count", 0),
                    len(result.get("errors", [])),
                )
            except Exception as exc:
                log.error("Unexpected error for %s: %s", device_name, exc)
                summaries.append({
                    "device":        device_name,
                    "status":        "failed",
                    "mac_count":     0,
                    "missing_count": 0,
                    "errors":        [str(exc)],
                })

    summaries.sort(key=lambda s: s.get("device", ""))

    total_macs    = sum(s.get("mac_count",     0) for s in summaries)
    total_missing = sum(s.get("missing_count", 0) for s in summaries)

    log.info(
        "DONE  devices=%d  total_macs=%d  total_missing=%d",
        len(summaries), total_macs, total_missing,
    )

    print(json.dumps(summaries, indent=2))


if __name__ == "__main__":
    main()
