#!/usr/bin/env python3
"""
netbox_device_connections.py
============================
For a given Virtual Chassis name or device name, enumerate every cabled
interface across all matching devices and print one JSON array to stdout.

Output fields per connection
----------------------------
  device_name               local device hostname
  device_primary_ip         local device management IP (no prefix length)
  interface                 local interface name
  remote_device             remote device hostname
  remote_device_primary_ip  remote device management IP (no prefix length)
  remote_interface          remote interface name

Authentication
--------------
Two modes, tried in this order:

  1. Basic Auth (--username + --password)
     Authenticates as the interactive user account — carries the same full
     permissions the browser session uses.  Preferred when the API token has
     restricted object permissions (returns 403 on list endpoints).

  2. Token Auth (--netbox-token only)
     Uses ``Authorization: Token <token>``.  Works when the token's user has
     unrestricted view permissions on dcim.device and dcim.virtualchassis.

If only the token is supplied and API calls return 403, re-run with
--username / --password to use the account's full permissions.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from typing import Any, Dict, Iterator, List, Optional

import requests

from vault_client import (
    VaultClient,
    VaultError,
    add_vault_parser_args,
    is_vault_configured,
    resolve_vault_auth,
)

log = logging.getLogger("netbox_connections")


# --------------------------------------------------------------------------- #
# Session / low-level HTTP                                                     #
# --------------------------------------------------------------------------- #

def _make_session(
    token: str,
    username: Optional[str] = None,
    password: Optional[str] = None,
) -> requests.Session:
    """
    Build a requests Session for NetBox REST API calls.

    Authentication priority
    -----------------------
    1. If *username* AND *password* are supplied → HTTP Basic Auth.
       This runs under the user account's full object permissions, which
       matches what a browser session sees.  Use this when the API token
       has restricted permissions (403 on list endpoints).

    2. Token only → ``Authorization: Token <token>``.
    """
    s = requests.Session()
    s.headers.update({
        "Accept":       "application/json",
        "Content-Type": "application/json",
    })

    if username and password:
        s.auth = (username, password)
        log.info("Auth mode: Basic Auth (username=%r)", username)
    else:
        s.headers["Authorization"] = f"Token {token}"
        log.info("Auth mode: Token")

    return s


def _get_all(session: requests.Session, url: str, params: Optional[Dict] = None) -> List[dict]:
    """
    Paginate through a NetBox list endpoint and return every result.

    Follows the ``next`` link in the response envelope until it is null.
    Passes ``limit=0`` by default so NetBox returns the maximum page size;
    if the server still paginates we handle it transparently.
    """
    collected: List[dict] = []
    p = dict(params or {})
    p.setdefault("limit", 0)
    next_url: Optional[str] = url

    while next_url:
        try:
            resp = session.get(next_url, params=p, timeout=30)

            if resp.status_code == 403:
                log.error(
                    "403 Forbidden: %s\n"
                    "  The current credentials lack permission for this endpoint.\n"
                    "  If you are using --netbox-token only, re-run with\n"
                    "  --username and --password to authenticate as the full user account.",
                    next_url,
                )
                break

            resp.raise_for_status()
        except requests.exceptions.RequestException as exc:
            log.error("API call failed %s: %s", next_url, exc)
            break

        data = resp.json()

        # After the first request the pagination links are in the response;
        # clear params so they are not double-appended on the next URL.
        p = {}

        if isinstance(data, list):
            # Some older endpoints return a bare list
            collected.extend(data)
            break

        results = data.get("results", [])
        collected.extend(results)
        next_url = data.get("next")   # None when we have reached the last page

    return collected


def _get_one(session: requests.Session, url: str) -> Optional[dict]:
    """Fetch a single object by its detail URL; return None on any error."""
    try:
        resp = session.get(url, timeout=30)
        resp.raise_for_status()
        return resp.json()
    except requests.exceptions.RequestException as exc:
        log.warning("Could not fetch %s: %s", url, exc)
        return None


# --------------------------------------------------------------------------- #
# Helpers                                                                      #
# --------------------------------------------------------------------------- #

def _primary_ip(device: dict) -> Optional[str]:
    """Return the primary IP address string (without /prefix-length), or None."""
    for field in ("primary_ip4", "primary_ip6"):
        ip_obj = device.get(field)
        if not ip_obj:
            continue
        addr = ip_obj.get("address") if isinstance(ip_obj, dict) else str(ip_obj)
        if addr:
            return addr.split("/")[0]
    return None


def _pick_vc_master(members: List[dict]) -> Optional[dict]:
    """
    Return the 'first' member of a VC from a list of device dicts.

    Priority:
      1. member whose virtual_chassis_position == 1
      2. member with the lowest virtual_chassis_position (None positions sorted last)
      3. first item returned by the API
    """
    if not members:
        return None

    def _pos(m: dict) -> tuple:
        pos = m.get("vc_position") or m.get("virtual_chassis_position")
        if pos is None:
            return (1, float("inf"))
        return (0, pos)

    return sorted(members, key=_pos)[0]


def resolve_device_primary_ip(
    device: dict,
    session: requests.Session,
    base: str,
    vc_cache: Dict[int, Optional[str]],
) -> Optional[str]:
    """
    Return the primary IP for *device*, falling back to the VC master's IP
    when the device itself has no primary IP configured.

    *vc_cache* maps vc_id → resolved IP string (or None) so each VC is only
    queried once across all interfaces in a run.

    Resolution order
    ----------------
    1. device.primary_ip4 or primary_ip6  → return immediately
    2. device.virtual_chassis is not null  → look up all VC members
       a. Pick the member with vc_position == 1 (or lowest position)
       b. Return that member's primary IP (or None if it also has none)
    3. No VC                              → return None
    """
    ip = _primary_ip(device)
    if ip:
        return ip

    vc_field = device.get("virtual_chassis")
    if not vc_field:
        return None

    vc_id = _id_of(vc_field)
    if vc_id is None:
        return None

    # Return cached result if we have already resolved this VC
    if vc_id in vc_cache:
        return vc_cache[vc_id]

    members = _get_all(
        session,
        f"{base}/api/dcim/devices/",
        {"virtual_chassis_id": vc_id},
    )
    master = _pick_vc_master(members)
    result = _primary_ip(master) if master else None
    vc_cache[vc_id] = result
    log.debug(
        "VC id=%s — master=%r  fallback_ip=%s",
        vc_id,
        master.get("name") if master else None,
        result,
    )
    return result


def _id_of(obj: Any) -> Optional[int]:
    """Extract the integer id from a nested object or bare int."""
    if isinstance(obj, dict):
        return obj.get("id")
    if isinstance(obj, int):
        return obj
    return None


def _name_of(obj: Any) -> Optional[str]:
    """Extract the name string from a nested object."""
    if isinstance(obj, dict):
        return obj.get("name")
    return None


# --------------------------------------------------------------------------- #
# Device resolution                                                            #
# --------------------------------------------------------------------------- #

def _resolve_devices(
    session: requests.Session,
    base: str,
    name: str,
) -> List[dict]:
    """
    Return the list of NetBox device dicts to process.

    Resolution order
    ----------------
    1. GET /api/dcim/virtual-chassis/?name=<name>
       If found → return all member devices of that VC.
    2. Else GET /api/dcim/devices/?q=<name>
       Return all matching device dicts.
    """
    # ── 1. Virtual chassis lookup ─────────────────────────────────────────
    vc_results = _get_all(session, f"{base}/api/dcim/virtual-chassis/", {"name": name})
    if vc_results:
        vc_id = vc_results[0]["id"]
        vc_name = vc_results[0].get("name", name)
        log.info("Virtual chassis %r found (id=%s) — loading member devices", vc_name, vc_id)
        devices = _get_all(
            session,
            f"{base}/api/dcim/devices/",
            {"virtual_chassis_id": vc_id},
        )
        if not devices:
            log.warning("Virtual chassis id=%s has no member devices", vc_id)
        return devices

    # ── 2. Device search fallback ─────────────────────────────────────────
    log.info("No virtual chassis named %r — searching devices (q=%r)", name, name)
    devices = _get_all(session, f"{base}/api/dcim/devices/", {"q": name})
    if not devices:
        log.warning("No devices found matching %r", name)
    return devices


# --------------------------------------------------------------------------- #
# Remote endpoint resolution                                                   #
# --------------------------------------------------------------------------- #

def _resolve_remote_endpoints(
    session: requests.Session,
    base: str,
    iface: dict,
) -> List[Dict[str, Any]]:
    """
    Return a list of ``{device, interface}`` dicts for the remote side(s) of
    the cable attached to *iface*.

    Strategy (in order):
    1. ``link_peers``          — populated by NetBox 3.3+ on detailed reads
    2. ``connected_endpoints`` — populated on detailed reads (older field)
    3. ``connected_endpoint``  — single-object legacy field
    4. Fetch cable via /api/dcim/cables/<cable_id>/ and walk terminations

    Each returned dict has:
      ``device``    → NetBox device dict (or None)
      ``interface`` → NetBox interface dict
    """
    results: List[Dict[str, Any]] = []

    # ── Try link_peers first (most complete, no extra round-trip) ─────────
    link_peers = iface.get("link_peers") or []
    if link_peers:
        for peer in link_peers:
            if not isinstance(peer, dict):
                continue
            obj_type = peer.get("object_type", "") or peer.get("_occupied_url", "")
            # link_peers entries have a "device" sub-key for interface peers
            dev = peer.get("device")
            if dev is not None:
                results.append({"device": dev, "interface": peer})
        if results:
            return results

    # ── Try connected_endpoints ───────────────────────────────────────────
    connected_endpoints = iface.get("connected_endpoints") or []
    if connected_endpoints:
        for ep in connected_endpoints:
            if not isinstance(ep, dict):
                continue
            dev = ep.get("device")
            if dev is not None:
                results.append({"device": dev, "interface": ep})
        if results:
            return results

    # ── Try single connected_endpoint ─────────────────────────────────────
    ep = iface.get("connected_endpoint")
    if ep and isinstance(ep, dict) and ep.get("device") is not None:
        results.append({"device": ep["device"], "interface": ep})
        return results

    # ── Fall back: walk the cable object ──────────────────────────────────
    cable_obj = iface.get("cable")
    if not cable_obj:
        return results

    cable_id = _id_of(cable_obj)
    if cable_id is None:
        return results

    cable = _get_one(session, f"{base}/api/dcim/cables/{cable_id}/")
    if not cable:
        return results

    local_iface_id = iface.get("id")

    for side in ("a_terminations", "b_terminations"):
        terminations = cable.get(side) or []
        for term in terminations:
            if not isinstance(term, dict):
                continue
            obj_type = (term.get("object_type") or "").lower()
            if "interface" not in obj_type:
                continue
            obj_id = _id_of(term.get("object_id") or term.get("object"))
            if obj_id is None:
                # object may be inlined
                obj_id = _id_of(term.get("object"))
            if obj_id == local_iface_id:
                continue   # this is the local side

            # Fetch the remote interface to get device info
            remote_iface = _get_one(session, f"{base}/api/dcim/interfaces/{obj_id}/")
            if remote_iface:
                results.append({
                    "device":    remote_iface.get("device"),
                    "interface": remote_iface,
                })

    # Also check if the object itself is embedded in the termination
    if not results:
        for side in ("a_terminations", "b_terminations"):
            terminations = cable.get(side) or []
            for term in terminations:
                if not isinstance(term, dict):
                    continue
                obj = term.get("object")
                if not isinstance(obj, dict):
                    continue
                if obj.get("id") == local_iface_id:
                    continue
                dev = obj.get("device")
                if dev is not None:
                    results.append({"device": dev, "interface": obj})

    return results


# --------------------------------------------------------------------------- #
# Per-device connection enumeration                                            #
# --------------------------------------------------------------------------- #

def _connections_for_device(
    session: requests.Session,
    base: str,
    device: dict,
    vc_cache: Dict[int, Optional[str]],
) -> Iterator[dict]:
    """
    Yield one connection record dict for every cabled interface on *device*.
    Logs warnings and continues on per-interface errors.

    *vc_cache* is a shared dict (vc_id → ip) so the VC master lookup is only
    performed once per VC across all devices processed in a single run.
    """
    device_id   = device.get("id")
    device_name = device.get("name") or f"device-{device_id}"
    device_ip   = resolve_device_primary_ip(device, session, base, vc_cache)

    ifaces = _get_all(
        session,
        f"{base}/api/dcim/interfaces/",
        {"device_id": device_id},
    )
    log.info("  %s — %d interface(s)", device_name, len(ifaces))

    for iface in ifaces:
        # Skip interfaces without a cable
        if not iface.get("cable"):
            continue

        iface_name = iface.get("name") or f"iface-{iface.get('id')}"

        try:
            remotes = _resolve_remote_endpoints(session, base, iface)
        except Exception as exc:
            log.warning(
                "%s / %s — error resolving remote endpoint: %s",
                device_name, iface_name, exc,
            )
            continue

        if not remotes:
            log.debug("%s / %s — cable present but no remote endpoint resolved", device_name, iface_name)
            continue

        for remote in remotes:
            remote_iface  = remote.get("interface") or {}
            remote_dev    = remote.get("device")

            # remote_dev may be a nested dict on the interface object
            if remote_dev is None:
                remote_dev = remote_iface.get("device")

            # NetBox returns a stub device object on nested fields — it has
            # id/url/display/name but NOT primary_ip4, virtual_chassis, etc.
            # Detect stubs by the absence of primary_ip4 and fetch the full
            # record so IP resolution and VC fallback work correctly.
            if isinstance(remote_dev, dict) and "primary_ip4" not in remote_dev:
                rd_id = _id_of(remote_dev)
                if rd_id:
                    fetched = _get_one(session, f"{base}/api/dcim/devices/{rd_id}/")
                    if fetched:
                        remote_dev = fetched
                        log.debug("Fetched full device record for %r (id=%s)", remote_dev.get("name"), rd_id)

            remote_name = _name_of(remote_dev) if isinstance(remote_dev, dict) else None
            remote_ip   = (
                resolve_device_primary_ip(remote_dev, session, base, vc_cache)
                if isinstance(remote_dev, dict)
                else None
            )
            remote_iface_name = remote_iface.get("name") if isinstance(remote_iface, dict) else None

            yield {
                "device_name":             device_name,
                "device_primary_ip":       device_ip,
                "interface":               iface_name,
                "remote_device":           remote_name,
                "remote_device_primary_ip": remote_ip,
                "remote_interface":        remote_iface_name,
            }


# --------------------------------------------------------------------------- #
# Main logic                                                                   #
# --------------------------------------------------------------------------- #

def run(
    base_url: str,
    token: str,
    name: str,
    username: Optional[str] = None,
    password: Optional[str] = None,
) -> None:
    session = _make_session(token, username=username, password=password)
    base    = base_url.rstrip("/")

    devices = _resolve_devices(session, base, name)
    if not devices:
        log.error("No devices resolved for %r — nothing to output.", name)
        sys.exit(1)

    log.info("Processing %d device(s)", len(devices))

    # Shared cache so the same VC master is only fetched once across all devices
    vc_cache: Dict[int, Optional[str]] = {}

    connections: List[dict] = []
    for device in devices:
        for record in _connections_for_device(session, base, device, vc_cache):
            connections.append(record)

    print(json.dumps(connections, indent=2))


# --------------------------------------------------------------------------- #
# Entry point                                                                  #
# --------------------------------------------------------------------------- #

def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "List all cabled interface connections for a NetBox Virtual Chassis "
            "or device.  Output is a JSON array to stdout."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "--netbox-url",
        default=os.environ.get("NETBOX_URL", ""),
        help="NetBox base URL (env: NETBOX_URL). Ignored when Vault is configured.",
    )
    parser.add_argument(
        "--netbox-token",
        default=os.environ.get("NETBOX_API", ""),
        help="NetBox API token (env: NETBOX_API). Ignored when Vault is configured.",
    )
    parser.add_argument(
        "--username",
        default=os.environ.get("NETBOX_USERNAME", ""),
        help="NetBox username for Basic Auth (env: NETBOX_USERNAME). Ignored when Vault is configured.",
    )
    parser.add_argument(
        "--password",
        default=os.environ.get("NETBOX_PASSWORD", ""),
        help="NetBox password for Basic Auth (env: NETBOX_PASSWORD). Ignored when Vault is configured.",
    )
    parser.add_argument(
        "--name",
        required=True,
        help="Virtual chassis name or device name / search term",
    )
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="WARNING",
        help="Log verbosity written to stderr (default: WARNING)",
    )

    vault_grp = parser.add_argument_group(
        "Vault authentication",
        "HashiCorp Vault AppRole credentials. CLI args take precedence over env vars. "
        "Use --use-env-only to restrict to environment variables only.",
    )
    add_vault_parser_args(vault_grp)

    args = parser.parse_args()

    logging.basicConfig(
        stream=sys.stderr,
        level=getattr(logging, args.log_level),
        format="%(levelname)-8s %(message)s",
    )

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
        netbox_url = secrets["netbox_url"]
        netbox_token = secrets["netbox_token"]
        username = secrets["user"] or None
        password = secrets["password"] or None
    else:
        missing = []
        if not args.netbox_url:
            missing.append("--netbox-url / NETBOX_URL")
        if not args.netbox_token:
            missing.append("--netbox-token / NETBOX_API")
        if missing:
            log.error("Missing required credentials: %s", ", ".join(missing))
            sys.exit(1)
        netbox_url = args.netbox_url
        netbox_token = args.netbox_token
        username = args.username or None
        password = args.password or None

    run(
        base_url=netbox_url.rstrip("/"),
        token=netbox_token,
        name=args.name,
        username=username,
        password=password,
    )


if __name__ == "__main__":
    main()
