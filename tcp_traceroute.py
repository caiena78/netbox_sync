#!/usr/bin/env python3
"""
tcp_traceroute.py
=================
TCP traceroute — traces the network path to a host by sending TCP SYN
packets with incrementing TTL values and collecting ICMP Time-Exceeded
replies from each intermediate router.

How it works
------------
1. A TCP SYN packet is crafted with TTL = 1 and sent toward the target.
2. The first router decrements the TTL to 0 and replies with an ICMP
   Time-Exceeded message (type 11, code 0), revealing its address.
3. TTL is incremented by 1 and the process repeats.
4. The trace terminates when:
     a. The destination responds with a TCP RST or SYN-ACK (port reached).
     b. The destination responds with ICMP Destination-Unreachable (type 3).
     c. The maximum hop count is reached.

Each TTL level is probed ``--probes`` times.  RTT is measured for every
probe; non-responding hops are displayed as ``*``.

When a SYN-ACK is received the script sends a TCP RST to cleanly close
the half-open connection before exiting.

Requirements
------------
  pip install scapy
  Windows : Npcap installed (https://npcap.com) + run as Administrator
  Linux   : run as root  (sudo python tcp_traceroute.py ...)
  macOS   : run as root

Usage examples
--------------
  python tcp_traceroute.py google.com
  python tcp_traceroute.py 10.0.0.1 --port 443
  python tcp_traceroute.py example.com --port 22 --max-hops 20 --probes 1
  python tcp_traceroute.py 192.168.1.1 -p 80 -m 15 -q 1 -t 1.0
"""

from __future__ import annotations

import argparse
import socket
import sys
import time
from typing import List, Optional

try:
    from scapy.all import IP, TCP, ICMP, conf, send, sr1
    conf.verb = 0  # suppress all scapy console noise
except ImportError:
    print(
        "scapy is required.  Install with:\n"
        "  pip install scapy\n"
        "Windows also requires Npcap: https://npcap.com",
        file=sys.stderr,
    )
    sys.exit(1)


# --------------------------------------------------------------------------- #
# Helpers                                                                      #
# --------------------------------------------------------------------------- #

def _normalize_target(target: str) -> str:
    """
    Strip the trailing dot used in fully-qualified domain names and remove
    surrounding whitespace.

    ``"mail.example.com."`` → ``"mail.example.com"``
    ``"8.8.8.8"``          → ``"8.8.8.8"``  (unchanged)
    """
    return target.strip().rstrip(".")


def _resolve_all_ipv4(target: str) -> List[str]:
    """
    Return a sorted, deduplicated list of all IPv4 addresses for *target*.

    Uses ``getaddrinfo`` so that round-robin DNS, multi-homed hosts, and
    IDN names all work correctly.  Returns an empty list on failure.
    """
    try:
        infos = socket.getaddrinfo(target, None, socket.AF_INET, socket.SOCK_STREAM)
        return sorted({info[4][0] for info in infos})
    except socket.gaierror:
        return []


def resolve_host(target: str) -> str:
    """
    Resolve *target* to its first IPv4 address, or exit with an error.

    Handles:
    - Bare hostnames           (``router``)
    - Relative domain names    (``google.com``)
    - Fully-qualified names    (``mail.example.com.``)  — trailing dot stripped
    - Raw IPv4 addresses       (``8.8.8.8``)
    """
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
    """Return the PTR hostname for *ip*, or ``None`` on failure."""
    try:
        name = socket.gethostbyaddr(ip)[0]
        return name if name != ip else None
    except (socket.herror, socket.gaierror, OSError):
        return None


def _fmt_rtt(rtt_ms: Optional[float]) -> str:
    """Format one RTT sample for display (7 chars wide)."""
    return f"{rtt_ms:7.3f} ms" if rtt_ms is not None else "      *   "


def _hop_label(ip: str, name: Optional[str]) -> str:
    return f"{name} ({ip})" if name else ip


# --------------------------------------------------------------------------- #
# Core                                                                         #
# --------------------------------------------------------------------------- #

def tcp_traceroute(
    target: str,
    port: int = 80,
    max_hops: int = 30,
    timeout: float = 2.0,
    probes: int = 3,
) -> None:
    """
    Perform a TCP SYN traceroute to *target*:*port*.

    Parameters
    ----------
    target    : Hostname or IP address of the destination.
    port      : TCP destination port for the SYN probes.
    max_hops  : Maximum TTL value (trace gives up after this many hops).
    timeout   : Per-probe receive timeout in seconds.
    probes    : Number of SYN probes sent at each TTL level.
    """
    # Normalize the target so FQDNs with trailing dots resolve cleanly.
    normalized = _normalize_target(target)
    dest_ip    = resolve_host(normalized)

    # Build the header line.  When a name resolves to multiple A records show
    # all of them so the operator knows which address is being traced.
    all_ips = _resolve_all_ipv4(normalized)
    if normalized == dest_ip:
        # Raw IP address was given — no hostname to display.
        dest_label = dest_ip
    elif len(all_ips) > 1:
        other = ", ".join(ip for ip in all_ips if ip != dest_ip)
        dest_label = f"{normalized} ({dest_ip}, also: {other})"
    else:
        dest_label = f"{normalized} ({dest_ip})"

    print(f"\ntcp traceroute to {dest_label}, port {port}/tcp")
    print(f"{max_hops} hops max, {probes} probe(s) per hop, {timeout}s timeout\n")

    # Source ports are spread across a predictable window so that responses
    # can be correlated to the correct probe even across NAT devices.
    # Window: 50000 + (ttl * max_probes + probe_index), stays well under 65535
    # for any realistic hop/probe combination.
    BASE_SPORT = 50000
    MAX_PROBES = 10  # upper bound from argparse

    for ttl in range(1, max_hops + 1):
        rtts: List[Optional[float]] = []
        hop_ip: Optional[str]   = None
        hop_name: Optional[str] = None
        reached = False

        for probe in range(probes):
            sport = BASE_SPORT + ttl * MAX_PROBES + probe

            # Craft a TCP SYN with the desired TTL.
            pkt = IP(dst=dest_ip, ttl=ttl) / TCP(
                sport=sport,
                dport=port,
                flags="S",  # SYN only
                seq=0,
            )

            t0 = time.perf_counter()
            reply = sr1(pkt, timeout=timeout, verbose=0)
            rtt_ms = (time.perf_counter() - t0) * 1000 if reply is not None else None

            rtts.append(rtt_ms)

            if reply is None:
                continue  # probe timed out

            # First responding IP for this TTL level becomes the hop label.
            if hop_ip is None:
                hop_ip   = reply.src
                hop_name = reverse_dns(hop_ip)

            # ── Evaluate the reply ────────────────────────────────────────
            if reply.haslayer(TCP):
                # The destination itself replied — we have arrived.
                tcp_flags = reply.getlayer(TCP).flags

                # SYN-ACK (0x12): port is open; send RST to avoid half-open.
                if tcp_flags & 0x12 == 0x12:
                    rst = IP(dst=dest_ip) / TCP(
                        sport=sport,
                        dport=port,
                        flags="R",
                        seq=reply.getlayer(TCP).ack,
                    )
                    send(rst, verbose=0)

                # RST (0x04) or RST-ACK (0x14): port is closed — still arrived.
                reached = True

            elif reply.haslayer(ICMP):
                icmp_type = reply.getlayer(ICMP).type
                icmp_code = reply.getlayer(ICMP).code

                if icmp_type == 11:
                    # Time-Exceeded — normal in-path hop, keep going.
                    pass
                elif icmp_type == 3:
                    # Destination Unreachable — we reached the destination
                    # network but the port/host is unreachable.
                    reached = True

        # ── Print hop line ────────────────────────────────────────────────
        rtt_col = "  ".join(_fmt_rtt(r) for r in rtts)

        if hop_ip is None:
            # All probes for this TTL timed out.
            stars = "  ".join("*" for _ in range(probes))
            print(f"{ttl:3d}  {stars}")
        else:
            print(f"{ttl:3d}  {rtt_col}  {_hop_label(hop_ip, hop_name)}")

        if reached:
            print("\nTrace complete.")
            return

    print("\nMax hops reached — destination not found.")


# --------------------------------------------------------------------------- #
# CLI                                                                          #
# --------------------------------------------------------------------------- #

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="tcp_traceroute",
        description=(
            "TCP traceroute — traces the path to a host using TCP SYN packets.\n\n"
            "Each router along the path responds with an ICMP Time-Exceeded\n"
            "message when it drops the probe due to TTL expiry.  The trace\n"
            "ends when the destination replies with TCP RST or SYN-ACK."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  python tcp_traceroute.py google.com\n"
            "  python tcp_traceroute.py 10.0.0.1 --port 443\n"
            "  python tcp_traceroute.py example.com -p 22 -m 20 -q 1\n"
        ),
    )
    p.add_argument(
        "target",
        help="Destination hostname or IP address",
    )
    p.add_argument(
        "--port", "-p",
        type=int,
        default=80,
        metavar="PORT",
        help="TCP destination port for SYN probes (default: 80)",
    )
    p.add_argument(
        "--max-hops", "-m",
        type=int,
        default=30,
        metavar="N",
        help="Maximum TTL / hop count before giving up (default: 30)",
    )
    p.add_argument(
        "--timeout", "-t",
        type=float,
        default=2.0,
        metavar="SEC",
        help="Per-probe receive timeout in seconds (default: 2.0)",
    )
    p.add_argument(
        "--probes", "-q",
        type=int,
        default=3,
        metavar="N",
        help="Number of SYN probes sent per TTL level (default: 3)",
    )
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

    tcp_traceroute(
        target=args.target,
        port=args.port,
        max_hops=args.max_hops,
        timeout=args.timeout,
        probes=args.probes,
    )


if __name__ == "__main__":
    main()
