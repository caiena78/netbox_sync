#!/usr/bin/env python3
"""
tcp_traceroute_netbox.py
========================
TCP traceroute with per-hop NetBox enrichment.

Traces the network path to a host using TCP SYN packets (identical to
tcp_traceroute.py) and enriches each responding hop IP with the device
name and interface name found in NetBox IPAM.

Display format (per hop)::

    13   22.294 ms   23.664 ms   21.376 ms  216.239.48.111  core-rtr-01  GigabitEthernet0/0/1

Hops whose IP is not in NetBox are shown without enrichment::

    12   19.004 ms   18.892 ms   19.101 ms  203.0.113.5

How it works
------------
1. A TCP SYN packet is crafted with TTL = 1 and sent toward the target.
2. The first router decrements the TTL to 0 and replies with ICMP
   Time-Exceeded (type 11, code 0), revealing its address.
3. TTL is incremented and the process repeats.
4. The trace terminates when the destination replies with TCP RST / SYN-ACK,
   ICMP Destination-Unreachable, or the maximum hop count is reached.

NetBox credentials
------------------
Preferred: HashiCorp Vault (use the ``--vault-*`` flags).
Fallback : ``--netbox-url`` / ``--netbox-token`` (or env vars
           ``NETBOX_URL`` / ``NETBOX_API``).

Requirements
------------
  pip install scapy
  Windows : Npcap installed (https://npcap.com) + run as Administrator
  Linux   : run as root

Usage examples
--------------
  python tcp_traceroute_netbox.py google.com --vault-addr https://vault.example.com ...
  python tcp_traceroute_netbox.py 10.0.0.1 --port 443 --netbox-url http://netbox/ --netbox-token TOKEN
  python tcp_traceroute_netbox.py example.com -p 22 -m 20 -q 1 -t 1.0
"""

from __future__ import annotations

import argparse
import os
import socket
import sys
import time
from typing import List, Optional, Tuple

try:
    from scapy.all import IP, TCP, ICMP, conf, send, sr1
    conf.verb = 0
except ImportError:
    print(
        "scapy is required.  Install with:\n"
        "  pip install scapy\n"
        "Windows also requires Npcap: https://npcap.com",
        file=sys.stderr,
    )
    sys.exit(1)

try:
    from netbox_client import NetBoxClient
except ImportError:
    print("netbox_client.py not found — ensure it is in the same directory.", file=sys.stderr)
    sys.exit(1)

try:
    from vault_client import (
        VaultClient,
        VaultError,
        add_vault_parser_args,
        is_vault_configured,
        resolve_vault_auth,
    )
except ImportError:
    print("vault_client.py not found — ensure it is in the same directory.", file=sys.stderr)
    sys.exit(1)


# --------------------------------------------------------------------------- #
# Helpers — resolution / display                                               #
# --------------------------------------------------------------------------- #

def _normalize_target(target: str) -> str:
    return target.strip().rstrip(".")


def _resolve_all_ipv4(target: str) -> List[str]:
    try:
        infos = socket.getaddrinfo(target, None, socket.AF_INET, socket.SOCK_STREAM)
        return sorted({info[4][0] for info in infos})
    except socket.gaierror:
        return []


def resolve_host(target: str) -> str:
    normalized = _normalize_target(target)
    try:
        infos = socket.getaddrinfo(normalized, None, socket.AF_INET, socket.SOCK_STREAM)
        if not infos:
            raise socket.gaierror("no IPv4 address records found")
        return infos[0][4][0]
    except socket.gaierror as exc:
        print(f"error: cannot resolve {target!r}: {exc}", file=sys.stderr)
        sys.exit(1)


def reverse_dns(ip: str) -> Optional[str]:
    try:
        name = socket.gethostbyaddr(ip)[0]
        return name if name != ip else None
    except (socket.herror, socket.gaierror, OSError):
        return None


def _fmt_rtt(rtt_ms: Optional[float]) -> str:
    return f"{rtt_ms:7.3f} ms" if rtt_ms is not None else "      *   "


def _hop_label(ip: str, name: Optional[str]) -> str:
    return f"{name} ({ip})" if name else ip


# --------------------------------------------------------------------------- #
# NetBox enrichment                                                            #
# --------------------------------------------------------------------------- #

def _netbox_lookup(
    nb: NetBoxClient,
    hop_ip: str,
) -> Tuple[Optional[str], Optional[str]]:
    """
    Return ``(device_name, interface_name)`` for *hop_ip* by querying NetBox
    IPAM, or ``(None, None)`` if the IP is not found / not assigned.

    Tries both exact-prefix forms via ``find_ips_by_host_address`` which
    searches by host address regardless of prefix length.
    """
    try:
        recs = nb.find_ips_by_host_address(hop_ip)
    except Exception:
        return None, None

    for rec in recs:
        assigned = rec.get("assigned_object") if isinstance(rec, dict) else getattr(rec, "assigned_object", None)
        if assigned is None:
            continue
        if isinstance(assigned, dict):
            iface_name = assigned.get("name")
            device = assigned.get("device") or {}
            dev_name = device.get("name") if isinstance(device, dict) else getattr(device, "name", None)
        else:
            iface_name = getattr(assigned, "name", None)
            device = getattr(assigned, "device", None)
            dev_name = getattr(device, "name", None) if device else None
        if dev_name:
            return dev_name, iface_name

    return None, None


# --------------------------------------------------------------------------- #
# Core                                                                         #
# --------------------------------------------------------------------------- #

def tcp_traceroute(
    target: str,
    nb: NetBoxClient,
    port: int = 80,
    max_hops: int = 30,
    timeout: float = 2.0,
    probes: int = 3,
) -> None:
    """
    Perform a TCP SYN traceroute to *target*:*port* with NetBox enrichment.
    """
    normalized = _normalize_target(target)
    dest_ip    = resolve_host(normalized)

    all_ips = _resolve_all_ipv4(normalized)
    if normalized == dest_ip:
        dest_label = dest_ip
    elif len(all_ips) > 1:
        other = ", ".join(ip for ip in all_ips if ip != dest_ip)
        dest_label = f"{normalized} ({dest_ip}, also: {other})"
    else:
        dest_label = f"{normalized} ({dest_ip})"

    print(f"\ntcp traceroute to {dest_label}, port {port}/tcp")
    print(f"{max_hops} hops max, {probes} probe(s) per hop, {timeout}s timeout\n")

    BASE_SPORT = 50000
    MAX_PROBES = 10

    for ttl in range(1, max_hops + 1):
        rtts: List[Optional[float]] = []
        hop_ip: Optional[str]   = None
        hop_name: Optional[str] = None
        reached = False

        for probe in range(probes):
            sport = BASE_SPORT + ttl * MAX_PROBES + probe

            pkt = IP(dst=dest_ip, ttl=ttl) / TCP(
                sport=sport,
                dport=port,
                flags="S",
                seq=0,
            )

            t0 = time.perf_counter()
            reply = sr1(pkt, timeout=timeout, verbose=0)
            rtt_ms = (time.perf_counter() - t0) * 1000 if reply is not None else None

            rtts.append(rtt_ms)

            if reply is None:
                continue

            if hop_ip is None:
                hop_ip   = reply.src
                hop_name = reverse_dns(hop_ip)

            if reply.haslayer(TCP):
                tcp_flags = reply.getlayer(TCP).flags
                if tcp_flags & 0x12 == 0x12:
                    rst = IP(dst=dest_ip) / TCP(
                        sport=sport,
                        dport=port,
                        flags="R",
                        seq=reply.getlayer(TCP).ack,
                    )
                    send(rst, verbose=0)
                reached = True

            elif reply.haslayer(ICMP):
                icmp_type = reply.getlayer(ICMP).type
                if icmp_type == 11:
                    pass
                elif icmp_type == 3:
                    reached = True

        # ── Print hop line ────────────────────────────────────────────────
        rtt_col = "  ".join(_fmt_rtt(r) for r in rtts)

        if hop_ip is None:
            stars = "  ".join("*" for _ in range(probes))
            print(f"{ttl:3d}  {stars}")
        else:
            dev_name, iface_name = _netbox_lookup(nb, hop_ip)
            label = _hop_label(hop_ip, hop_name)
            nb_col = ""
            if dev_name:
                nb_col = f"  {dev_name}"
                if iface_name:
                    nb_col += f"  {iface_name}"
            print(f"{ttl:3d}  {rtt_col}  {label}{nb_col}")

        if reached:
            print("\nTrace complete.")
            return

    print("\nMax hops reached — destination not found.")


# --------------------------------------------------------------------------- #
# CLI                                                                          #
# --------------------------------------------------------------------------- #

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="tcp_traceroute_netbox",
        description=(
            "TCP traceroute with NetBox enrichment.\n\n"
            "Traces the path to a host using TCP SYN packets and annotates each\n"
            "hop with the device name and interface from NetBox IPAM."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  python tcp_traceroute_netbox.py google.com --netbox-url http://nb/ --netbox-token TOKEN\n"
            "  python tcp_traceroute_netbox.py 10.0.0.1 --port 443 --vault-addr https://vault/ ...\n"
            "  python tcp_traceroute_netbox.py example.com -p 22 -m 20 -q 1\n"
        ),
    )

    p.add_argument("target", help="Destination hostname or IP address")
    p.add_argument("--port", "-p", type=int, default=80, metavar="PORT",
                   help="TCP destination port (default: 80)")
    p.add_argument("--max-hops", "-m", type=int, default=30, metavar="N",
                   help="Maximum TTL / hop count (default: 30)")
    p.add_argument("--timeout", "-t", type=float, default=2.0, metavar="SEC",
                   help="Per-probe receive timeout in seconds (default: 2.0)")
    p.add_argument("--probes", "-q", type=int, default=3, metavar="N",
                   help="Number of SYN probes per TTL level (default: 3)")

    nb_grp = p.add_argument_group("NetBox credentials")
    nb_grp.add_argument("--netbox-url",
                        default=os.environ.get("NETBOX_URL", ""),
                        help="NetBox base URL (env: NETBOX_URL). Ignored when Vault is configured.")
    nb_grp.add_argument("--netbox-token",
                        default=os.environ.get("NETBOX_API", ""),
                        help="NetBox API token (env: NETBOX_API). Ignored when Vault is configured.")
    nb_grp.add_argument("--netbox-verify-ssl",
                        action=argparse.BooleanOptionalAction, default=True)

    vault_grp = p.add_argument_group("HashiCorp Vault (optional — overrides --netbox-* flags)")
    add_vault_parser_args(vault_grp)

    return p


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if not (1 <= args.port <= 65535):
        parser.error("--port must be between 1 and 65535")
    if not (1 <= args.max_hops <= 255):
        parser.error("--max-hops must be between 1 and 255")
    if not (1 <= args.probes <= 10):
        parser.error("--probes must be between 1 and 10")
    if args.timeout <= 0:
        parser.error("--timeout must be greater than 0")

    # ── Resolve NetBox credentials ────────────────────────────────────────
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
            print(f"error: failed to load credentials from Vault: {exc}", file=sys.stderr)
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
            print(
                f"error: missing required credentials: {', '.join(missing)}\n"
                "Use --vault-* flags or set the environment variables.",
                file=sys.stderr,
            )
            sys.exit(1)
        netbox_url   = args.netbox_url
        netbox_token = args.netbox_token

    nb = NetBoxClient(
        base_url=netbox_url,
        token=netbox_token,
        verify_ssl=args.netbox_verify_ssl,
    )

    tcp_traceroute(
        target=args.target,
        nb=nb,
        port=args.port,
        max_hops=args.max_hops,
        timeout=args.timeout,
        probes=args.probes,
    )


if __name__ == "__main__":
    main()
