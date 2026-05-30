#!/usr/bin/env python3
"""
network_tracer.py — Phase 1: Gateway discovery.

Given a source IP address:
  1. Find the most specific NetBox prefix that contains it.
  2. Calculate the first usable IP in that subnet (the expected gateway).
  3. Attempt an SSH connection to the gateway and report the device hostname.

Later phases will extend this with ARP/MAC tracing, CDP/LLDP path walking,
routing-table analysis, ECMP parallel tracing, and full hop-by-hop output.
"""

from __future__ import annotations

import argparse
import ipaddress
import logging
import os
import sys
from typing import Dict, List, Optional, Tuple

try:
    from netmiko import ConnectHandler, NetmikoAuthenticationException, NetmikoTimeoutException
except ImportError:
    print("ERROR: netmiko is required — pip install netmiko", file=sys.stderr)
    sys.exit(1)

try:
    import pynetbox
except ImportError:
    print("ERROR: pynetbox is required — pip install pynetbox", file=sys.stderr)
    sys.exit(1)

# Vault is optional — gracefully degrade when vault_client.py is absent.
try:
    from vault_client import (
        VaultClient,
        VaultError,
        add_vault_parser_args,
        is_vault_configured,
        resolve_vault_auth,
    )
    _VAULT_AVAILABLE = True
except ImportError:
    _VAULT_AVAILABLE = False

    class VaultError(Exception):  # type: ignore[no-redef]
        pass

    class VaultClient:  # type: ignore[no-redef]
        pass

    def add_vault_parser_args(*_) -> None:  # type: ignore[misc]
        pass

    def is_vault_configured(*_) -> bool:  # type: ignore[misc]
        return False

    def resolve_vault_auth(*_) -> Tuple[str, str, str]:  # type: ignore[misc]
        raise SystemExit(1)


# ─────────────────────────────────────────────────────────────────────────────
# Logging
# ─────────────────────────────────────────────────────────────────────────────

LOG_FILE = "network_tracer.log"


def _configure_logging(verbose: bool = False) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    fmt = "%(asctime)s %(levelname)-8s %(name)-25s %(message)s"
    logging.basicConfig(
        level=level,
        format=fmt,
        handlers=[
            logging.FileHandler(LOG_FILE, encoding="utf-8"),
            logging.StreamHandler(sys.stderr),
        ],
    )


log = logging.getLogger("network_tracer")


# ─────────────────────────────────────────────────────────────────────────────
# Exceptions
# ─────────────────────────────────────────────────────────────────────────────


class GatewayConnectionError(Exception):
    """Raised when SSH to the gateway device fails."""


# ─────────────────────────────────────────────────────────────────────────────
# Phase 1 functions
# ─────────────────────────────────────────────────────────────────────────────


def get_prefixes_from_netbox(
    nb_url: str,
    nb_token: str,
    verify_ssl: bool = True,
    contains: Optional[str] = None,
) -> List[str]:
    """Return prefix strings from NetBox IPAM.

    When *contains* is supplied, the NetBox ``contains`` filter is used so only
    prefixes that contain that address are fetched — much faster than pulling
    all prefixes on large instances.  Without it every prefix is returned.
    """
    try:
        nb = pynetbox.api(nb_url.rstrip("/"), token=nb_token)
        if not verify_ssl:
            import urllib3  # noqa: PLC0415
            urllib3.disable_warnings()
            nb.http_session.verify = False

        if contains:
            raw = list(nb.ipam.prefixes.filter(contains=contains))
        else:
            raw = list(nb.ipam.prefixes.all())

        prefixes = [str(p.prefix) for p in raw if p.prefix]
        log.debug("Fetched %d prefix(es) from NetBox (contains=%s)", len(prefixes), contains)
        return prefixes

    except Exception as exc:
        log.error("NetBox prefix lookup failed: %s", exc)
        return []


def find_longest_prefix_match(ip: str, prefixes: List[str]) -> Optional[str]:
    """Return the most specific prefix (longest prefix length) that contains *ip*.

    Returns ``None`` when no prefix matches.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        log.error("Invalid IP address: %r", ip)
        return None

    best: Optional[ipaddress.IPv4Network | ipaddress.IPv6Network] = None

    for raw in prefixes:
        try:
            net = ipaddress.ip_network(raw, strict=False)
        except ValueError:
            log.debug("Skipping malformed prefix: %r", raw)
            continue

        if addr in net:
            if best is None or net.prefixlen > best.prefixlen:
                best = net

    if best:
        log.debug("Longest prefix match for %s: %s", ip, best)
        return str(best)

    log.debug("No prefix match found for %s", ip)
    return None


def calculate_first_usable_ip(prefix: str) -> Optional[str]:
    """Return the first usable host address in *prefix*.

    Handling:
      - /32 or /128 → the single address itself.
      - /31         → the network address (RFC 3021 point-to-point links).
      - All others  → network address + 1 (the conventional gateway slot).
    """
    try:
        net = ipaddress.ip_network(prefix, strict=False)
    except ValueError:
        log.error("Invalid prefix: %r", prefix)
        return None

    if net.num_addresses == 1:
        return str(net.network_address)          # /32 or /128
    if net.prefixlen >= 31:
        return str(net.network_address)          # /31 — both ends are hosts
    return str(net.network_address + 1)          # .1 of the subnet


def connect_to_device(ip: str, credentials: Dict[str, str]) -> str:
    """Open an SSH session to *ip* and return the device hostname.

    The hostname is extracted from the CLI prompt (``hostname#`` →
    ``hostname``).  Raises :exc:`GatewayConnectionError` on any failure so
    the caller can produce a clean ``[ERROR]`` line without a traceback.
    """
    params: Dict = {
        "device_type":  "cisco_ios",
        "host":         ip,
        "username":     credentials.get("username", ""),
        "password":     credentials.get("password", ""),
        "secret":       credentials.get("secret", ""),
        "timeout":      int(credentials.get("timeout", 30)),
        "conn_timeout": int(credentials.get("timeout", 30)),
        "fast_cli":     False,
    }

    try:
        conn = ConnectHandler(**params)
    except NetmikoAuthenticationException as exc:
        raise GatewayConnectionError(f"authentication failed for {ip}: {exc}") from exc
    except NetmikoTimeoutException as exc:
        raise GatewayConnectionError(f"connection timed out for {ip}") from exc
    except Exception as exc:
        raise GatewayConnectionError(f"SSH error for {ip}: {exc}") from exc

    try:
        prompt = conn.find_prompt()
        hostname = prompt.rstrip("#>").strip()
        log.debug("Connected to %s — prompt: %r", ip, prompt)
        return hostname or ip
    except Exception as exc:
        raise GatewayConnectionError(f"prompt detection failed for {ip}: {exc}") from exc
    finally:
        try:
            conn.disconnect()
        except Exception:
            pass


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="network_tracer.py",
        description=(
            "Reconstruct the network path between two IPs using NetBox, "
            "ARP/NDP, MAC tables, CDP/LLDP, VRFs, FHRP, and routing tables. "
            "Supports IPv4, IPv6, Vault credentials, and parallel ECMP tracing."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Direct credentials
  python network_tracer.py 10.1.1.100 10.2.2.200 \\
      --netbox-url https://netbox.example.com --netbox-token abc123 \\
      --username admin --password secret

  # HashiCorp Vault credentials
  python network_tracer.py 10.1.1.100 10.2.2.200 \\
      --VAULT_ADDR https://vault.example.com \\
      --VAULT_ROLE_ID <role> --VAULT_SECRET_ID <secret>

  # Reverse trace + ECMP parallel + IPv6
  python network_tracer.py 2001:db8::1 2001:db8::2 --reverse --ecmp

  # Via environment variables
  export NETBOX_URL=https://netbox.example.com NETBOX_TOKEN=abc123
  export DEVICE_USER=admin DEVICE_PASS=secret
  python network_tracer.py 10.1.1.100 10.2.2.200
        """,
    )

    p.add_argument("src_ip", help="Source IP address (IPv4 or IPv6)")
    p.add_argument("dst_ip", help="Destination IP address (IPv4 or IPv6)")

    nb = p.add_argument_group("NetBox (ignored when Vault is configured)")
    nb.add_argument(
        "--netbox-url",
        default=None,
        help="NetBox base URL (env: NETBOX_URL)",
    )
    nb.add_argument(
        "--netbox-token",
        default=None,
        help="NetBox API token (env: NETBOX_TOKEN)",
    )
    nb.add_argument(
        "--no-ssl-verify",
        action="store_true",
        help="Disable TLS verification for NetBox",
    )

    dev = p.add_argument_group("Device credentials (ignored when Vault is configured)")
    dev.add_argument(
        "--username",
        default=None,
        help="SSH username (env: DEVICE_USER)",
    )
    dev.add_argument(
        "--password",
        default=None,
        help="SSH password (env: DEVICE_PASS)",
    )
    dev.add_argument(
        "--secret",
        default=os.environ.get("DEVICE_SECRET", ""),
        help="Enable secret (env: DEVICE_SECRET)",
    )
    dev.add_argument(
        "--timeout",
        type=int,
        default=30,
        help="SSH timeout in seconds (default: 30)",
    )

    if _VAULT_AVAILABLE:
        vault_grp = p.add_argument_group(
            "Vault authentication (optional — overrides --username/--password/--netbox-*)"
        )
        add_vault_parser_args(vault_grp)

    tr = p.add_argument_group("Trace options")
    tr.add_argument(
        "--reverse",
        action="store_true",
        help="Also run reverse trace (dst → src)",
    )
    tr.add_argument(
        "--ecmp",
        action="store_true",
        help="Trace all ECMP paths in parallel (one SSH session per path)",
    )
    tr.add_argument(
        "--max-hops",
        type=int,
        default=30,
        help="Max hops before stopping (default: 30)",
    )
    tr.add_argument(
        "--out-dir",
        default=".",
        help="Output directory for JSON/CSV (default: current dir)",
    )
    tr.add_argument(
        "--verbose",
        action="store_true",
        help="Enable DEBUG logging",
    )

    return p


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────


def main() -> int:
    parser = build_parser()
    args   = parser.parse_args()
    _configure_logging(verbose=args.verbose)

    # ── Credential resolution ─────────────────────────────────────────────────
    if _VAULT_AVAILABLE and is_vault_configured(args):
        try:
            addr, role_id, secret_id = resolve_vault_auth(args)
            vc = VaultClient(
                addr, role_id, secret_id,
                mount=getattr(args, "vault_mount", "secret"),
                path=getattr(args, "vault_path",  "network/device"),
            )
            secrets = vc.get_secrets()
        except VaultError as exc:
            log.error("Vault error: %s", exc)
            return 1
        username     = secrets["user"]
        password     = secrets["password"]
        netbox_url   = secrets["netbox_url"]
        netbox_token = secrets["netbox_token"]
        log.info("Credentials loaded from Vault")
    else:
        username     = args.username     or os.environ.get("DEVICE_USER",  "")
        password     = args.password     or os.environ.get("DEVICE_PASS",  "")
        netbox_url   = args.netbox_url   or os.environ.get("NETBOX_URL",   "")
        netbox_token = args.netbox_token or os.environ.get("NETBOX_TOKEN", "")

    # ── Validate required credentials ─────────────────────────────────────────
    errors: List[str] = []
    if not netbox_url:
        errors.append("NetBox URL required (--netbox-url, NETBOX_URL, or Vault)")
    if not netbox_token:
        errors.append("NetBox token required (--netbox-token, NETBOX_TOKEN, or Vault)")
    if not username:
        errors.append("SSH username required (--username, DEVICE_USER, or Vault)")
    if not password:
        errors.append("SSH password required (--password, DEVICE_PASS, or Vault)")
    if errors:
        for e in errors:
            print(f"ERROR: {e}", file=sys.stderr)
        parser.print_usage(sys.stderr)
        return 1

    verify_ssl = not args.no_ssl_verify
    src_ip     = args.src_ip

    creds: Dict[str, str] = {
        "username": username,
        "password": password,
        "secret":   args.secret,
        "timeout":  str(args.timeout),
    }

    # ── Phase 1: locate the gateway and verify SSH connectivity ───────────────

    print(f"[INFO] Source IP: {src_ip}")

    # 1. Fetch only the prefixes that contain the source IP (efficient).
    prefixes = get_prefixes_from_netbox(
        netbox_url, netbox_token, verify_ssl, contains=src_ip
    )
    if not prefixes:
        print(f"[ERROR] No matching subnet found for {src_ip} in NetBox")
        log.error("No NetBox prefix contains %s", src_ip)
        return 1

    # 2. Longest prefix match among the candidates.
    matched = find_longest_prefix_match(src_ip, prefixes)
    if not matched:
        print(f"[ERROR] No matching subnet found for {src_ip} in NetBox")
        log.error("Longest-prefix match failed for %s among %d candidates", src_ip, len(prefixes))
        return 1

    print(f"[INFO] Matched subnet: {matched}")

    # 3. First usable IP in the matched subnet → expected gateway.
    gateway = calculate_first_usable_ip(matched)
    if not gateway:
        print(f"[ERROR] Could not determine gateway for subnet {matched}")
        log.error("calculate_first_usable_ip(%r) returned None", matched)
        return 1

    print(f"[INFO] Gateway IP (first usable): {gateway}")
    print("[INFO] Attempting connection to gateway...")

    # 4. Verify SSH connectivity and retrieve the device hostname.
    try:
        hostname = connect_to_device(gateway, creds)
        print(f"[SUCCESS] Connected to {hostname}")
    except GatewayConnectionError as exc:
        print(f"[ERROR] Failed to connect: {exc}")
        log.error("Gateway connection failed: %s", exc)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
