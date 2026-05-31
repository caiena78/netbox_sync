#!/usr/bin/env python3
"""
network_tracer.py — Phase 1 + 2: Gateway discovery + Layer 2 MAC trace.

Given a source IP address:
  Phase 1:
    1. Find the most specific NetBox prefix that contains it.
    2. Calculate the first usable IP in that subnet (the expected gateway).
    3. Attempt an SSH connection to the gateway and report the device hostname.

  Phase 2 (L2 trace):
    4. ARP lookup on the gateway to resolve the source IP to a MAC address.
    5. Hop-by-hop MAC table lookup starting at the gateway:
         a. Find the VLAN and switchport for the MAC.
         b. Expand port-channels to their physical members.
         c. Check CDP/LLDP on the resolved interface.
         d. If the neighbor is a switch or router, connect to it and repeat.
         e. Stop at APs, VMware hosts, endpoints (no CDP/LLDP), or when
            the neighbor IP cannot be resolved.

Later phases will extend this with routing-table analysis, ECMP parallel
tracing, and full hop-by-hop output.
"""

from __future__ import annotations

import argparse
import io
import ipaddress
import json
import logging
import os
import re
import sys
from typing import Dict, List, Optional, Tuple

try:
    from cisco_device_client import (
        CiscoDeviceClient,
        AuthenticationError as DeviceAuthError,
        TransportError    as DeviceTransportError,
    )
except ImportError:
    print("ERROR: cisco_device_client.py is required in the same directory", file=sys.stderr)
    sys.exit(1)

try:
    from netbox_client import NetBoxClient, NetBoxClientError
except ImportError:
    print("ERROR: netbox_client.py is required in the same directory", file=sys.stderr)
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
# Constants
# ─────────────────────────────────────────────────────────────────────────────

_VMWARE_KEYWORDS: Tuple[str, ...] = (
    "vmware", "esxi", "vsphere", "vswitch", "vmnic", "esx",
)

_AP_ROLE_KEYWORDS: Tuple[str, ...] = (
    "ap", "access-point", "wireless", "aironet",
    "catalyst-9100", "catalyst-9105", "catalyst-9115",
    "catalyst-9120", "catalyst-9130",
)


# ─────────────────────────────────────────────────────────────────────────────
# Exceptions
# ─────────────────────────────────────────────────────────────────────────────


class GatewayConnectionError(Exception):
    """Raised when SSH to a network device fails."""


# ─────────────────────────────────────────────────────────────────────────────
# NetBox helpers
# ─────────────────────────────────────────────────────────────────────────────


def _get_nb_client(nb_url: str, nb_token: str, verify_ssl: bool = True) -> NetBoxClient:
    """Return a configured NetBoxClient instance."""
    return NetBoxClient(nb_url, nb_token, verify_ssl=verify_ssl)


def get_prefixes_from_netbox(
    nb_url: str,
    nb_token: str,
    verify_ssl: bool = True,
    contains: Optional[str] = None,
) -> List[str]:
    """Return prefix strings from NetBox IPAM.

    When *contains* is supplied the NetBox ``contains`` filter is used so only
    prefixes that contain that address are fetched.
    """
    try:
        nb = _get_nb_client(nb_url, nb_token, verify_ssl)
        if contains:
            raw = list(nb.nb.ipam.prefixes.filter(contains=contains))
        else:
            raw = list(nb.nb.ipam.prefixes.all())
        prefixes = [str(p.prefix) for p in raw if p.prefix]
        log.debug("Fetched %d prefix(es) from NetBox (contains=%s)", len(prefixes), contains)
        return prefixes
    except NetBoxClientError as exc:
        log.error("NetBox prefix lookup failed: %s", exc)
        return []
    except Exception as exc:
        log.error("NetBox prefix lookup unexpected error: %s", exc)
        return []


def _resolve_mgmt_ip_from_netbox(
    nb_url: str,
    nb_token: str,
    next_hop_ip: str,
    verify_ssl: bool = True,
) -> Optional[str]:
    """Resolve *next_hop_ip* to a Cisco device in NetBox and return its primary IPv4.

    Flow:
      1. Search NetBox IPAM for an IP address record matching *next_hop_ip*.
      2. Follow the assignment from that IP record → device interface → device.
      3. Return the device's ``primary_ip4`` (the management address to SSH to).

    Returns None when the IP is not found in NetBox, is not assigned to a
    device interface, or has no primary IPv4 set.

    Note: virtual-machine interfaces are intentionally skipped — only
    physical Cisco device interfaces are followed.
    """
    try:
        nb = _get_nb_client(nb_url, nb_token, verify_ssl)

        # Step 1 — find the IPAM record for this IP.
        # NetBox stores IPs in CIDR notation; try /32 first, then bare.
        ip_recs: list = []
        for addr in (f"{next_hop_ip}/32", next_hop_ip):
            ip_recs = list(nb.nb.ipam.ip_addresses.filter(address=addr))
            if ip_recs:
                break

        if not ip_recs:
            log.debug("NetBox: no IP address record found for %s", next_hop_ip)
            return None

        rec      = ip_recs[0]
        obj_type = str(getattr(rec, "assigned_object_type", "") or "")
        obj_id   = getattr(rec, "assigned_object_id", None)

        if not obj_id:
            log.debug("NetBox: IP %s exists but is not assigned to any interface", next_hop_ip)
            return None

        # Step 2 — follow to the device that owns this interface.
        if "dcim.interface" not in obj_type:
            log.debug(
                "NetBox: IP %s is assigned to %r (not a device interface) — skipping",
                next_hop_ip, obj_type,
            )
            return None

        iface = nb.nb.dcim.interfaces.get(obj_id)
        if not iface or not iface.device:
            log.debug("NetBox: interface id=%s has no associated device", obj_id)
            return None

        device_id = int(iface.device.id)

        # Step 3 — get the device record and return its primary IPv4.
        devs = nb.get_devices({"id": device_id})
        if not devs:
            log.debug("NetBox: device id=%s not found", device_id)
            return None

        device     = devs[0]
        device_name = device.get("name", "unknown")
        primary_ip  = nb.get_device_mgmt_ip(device)

        if primary_ip:
            print(
                f"[L3]   NetBox: {next_hop_ip} → device '{device_name}' → primary IPv4 {primary_ip}"
            )
        else:
            log.debug("NetBox: device '%s' has no primary IPv4 set", device_name)

        return primary_ip

    except Exception as exc:
        log.debug("NetBox resolution for %s failed: %s", next_hop_ip, exc)
        return None




def resolve_neighbor_ip(neighbor_info: Dict[str, str]) -> Optional[str]:
    """Return the CDP/LLDP-reported IP for this neighbor.

    Uses only the IP advertised by the neighbor itself — no NetBox lookup.
    """
    ip = neighbor_info.get("neighbor_ip")
    log.debug(
        "Resolved neighbor %s -> %s (via CDP/LLDP)",
        neighbor_info.get("neighbor_id", "?"), ip or "None",
    )
    return ip


# ─────────────────────────────────────────────────────────────────────────────
# Phase 1 — prefix / gateway helpers
# ─────────────────────────────────────────────────────────────────────────────


def find_longest_prefix_match(ip: str, prefixes: List[str]) -> Optional[str]:
    """Return the most specific prefix (longest prefix-length) containing *ip*."""
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

    /32 or /128 → the address itself; /31 → network address; all others → net+1.
    """
    try:
        net = ipaddress.ip_network(prefix, strict=False)
    except ValueError:
        log.error("Invalid prefix: %r", prefix)
        return None
    if net.num_addresses == 1:
        return str(net.network_address)
    if net.prefixlen >= 31:
        return str(net.network_address)
    return str(net.network_address + 1)


# ─────────────────────────────────────────────────────────────────────────────
# SSH connection helpers
# ─────────────────────────────────────────────────────────────────────────────


def _open_device_client(
    ip: str,
    os_type: str,
    credentials: Dict[str, str],
) -> CiscoDeviceClient:
    """Create a CiscoDeviceClient and open its CLI connection.

    The caller is responsible for calling ``client._cli_disconnect()`` when done.
    Raises :exc:`GatewayConnectionError` on any connection failure.
    """
    try:
        client = CiscoDeviceClient(
            host          = ip,
            username      = credentials.get("username", ""),
            password      = credentials.get("password", ""),
            os_type       = os_type,
            enable_secret = credentials.get("secret") or None,
            timeout       = int(credentials.get("timeout", 30)),
        )
        client._cli_connect()
        return client
    except DeviceAuthError as exc:
        raise GatewayConnectionError(f"authentication failed for {ip}: {exc}") from exc
    except DeviceTransportError as exc:
        raise GatewayConnectionError(f"connection failed for {ip}: {exc}") from exc
    except Exception as exc:
        raise GatewayConnectionError(f"SSH error for {ip}: {exc}") from exc


def _send_cmd(client: CiscoDeviceClient, cmd: str) -> str:
    """Send a CLI command via *client* and return the raw text output."""
    try:
        raw, _, _ = client._cli_run_command(cmd, parse=False)
        return raw
    except DeviceTransportError as exc:
        raise GatewayConnectionError(f"Command {cmd!r} failed: {exc}") from exc


def connect_to_device(
    ip: str,
    credentials: Dict[str, str],
    device_type: str = "ios",
) -> str:
    """Open an SSH session to *ip*, retrieve the hostname prompt, then disconnect.

    Returns the hostname string (falls back to *ip*).
    Raises :exc:`GatewayConnectionError` on any failure.
    """
    client = _open_device_client(ip, device_type, credentials)
    try:
        prompt   = client._cli_connection.find_prompt()
        hostname = prompt.rstrip("#>").strip()
        log.debug("Connected to %s — prompt: %r", ip, prompt)
        return hostname or ip
    except Exception as exc:
        raise GatewayConnectionError(f"prompt detection failed for {ip}: {exc}") from exc
    finally:
        client._cli_disconnect()


# ─────────────────────────────────────────────────────────────────────────────
# Phase 2 — MAC address normalization
# ─────────────────────────────────────────────────────────────────────────────


def normalize_mac(raw: str) -> Optional[str]:
    """Normalize any common MAC format to xx:xx:xx:xx:xx:xx (lowercase).

    Accepts colon, dash, Cisco-dot, or no-delimiter inputs.
    Returns None when the input is not a valid 48-bit MAC.
    """
    digits = re.sub(r"[:\-\.]", "", raw.strip()).lower()
    if len(digits) != 12 or not re.fullmatch(r"[0-9a-f]{12}", digits):
        return None
    return ":".join(digits[i : i + 2] for i in range(0, 12, 2))


def mac_to_cisco_fmt(mac: str) -> str:
    """Convert a normalized xx:xx:xx:xx:xx:xx MAC to Cisco xxxx.xxxx.xxxx notation."""
    digits = mac.replace(":", "")
    return f"{digits[0:4]}.{digits[4:8]}.{digits[8:12]}"


# ─────────────────────────────────────────────────────────────────────────────
# Phase 2 — ARP lookup
# ─────────────────────────────────────────────────────────────────────────────


def arp_lookup(
    client: CiscoDeviceClient,
    device_type: str,  # noqa: ARG001 — reserved for future platform-specific ARP variants
    target_ip: str,
) -> Optional[str]:
    """Run ``show ip arp <target_ip>`` and return the normalized MAC, or None."""
    cmd = f"show ip arp {target_ip}"
    try:
        output = _send_cmd(client, cmd)
    except Exception as exc:
        log.error("ARP command failed (%s): %s", cmd, exc)
        return None

    log.debug("ARP output for %s:\n%s", target_ip, output)

    # Cisco dotted: xxxx.xxxx.xxxx
    m = re.search(r"([0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4})", output)
    if m:
        return normalize_mac(m.group(1))

    # Colon-separated: xx:xx:xx:xx:xx:xx
    m = re.search(
        r"([0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}"
        r":[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2})",
        output,
    )
    if m:
        return normalize_mac(m.group(1))

    log.debug("No MAC found in ARP output for %s", target_ip)
    return None


# ─────────────────────────────────────────────────────────────────────────────
# Phase 2 — gateway SVI / routed-interface lookup
# ─────────────────────────────────────────────────────────────────────────────


def _parse_all_routes(output: str) -> List[Dict[str, Optional[str]]]:
    """Parse every ECMP route entry from ``show ip route <ip>`` output.

    Returns a list — one dict per next-hop — so callers get all ECMP paths.
    Each dict has keys: prefix, next_hop, exit_interface, route_source,
    route_tag, route_age.

    Age / uptime handling:
      - IOS-XE descriptor: "10.0.0.2, from X, 2w2d ago, via Gi1/0/1"
        → age extracted per-entry from the "<age> ago" token on that line.
      - NX-OS *via:        "*via 10.0.0.2, Eth1/1, [110/2], 00:01:02, …"
        → age is the token after [metric].
      - IOS-XE brief:      "via 10.0.0.2, 00:01:02, GigabitEthernet1/0/1"
        → age is the second comma-separated token.
      - Fallback:          "Last update from X on Gi1/0/1, 2w2d ago"
        → age applied to all entries that lack a per-entry age.

    Tag handling:
      - IOS-XE route-level:   "Tag 91, type extern 2, …"  → applied to all entries
      - IOS-XE per-descriptor: "Route tag 91"              → applied to that ECMP entry
      - NX-OS inline:          "*via …, tag 91"            → applied to that *via line

    Patterns tried in priority order (first group that yields ≥1 result wins):

      1. IOS-XE routing descriptor block – line-by-line parse to associate
         per-entry "Route tag X" and "<age> ago" with the correct ECMP entry.

      2. NX-OS *via lines:
           *via 10.0.0.2, Eth1/1, [110/2], 00:01:02, ospf-1, intra, tag 91

      3. IOS-XE brief with age+interface:
           O 192.168.0.0/24 [110/2] via 10.0.0.2, 00:01:02, GigabitEthernet1/0/1

      4. IOS-XE brief C/L directly connected:
           C 192.168.0.0/24 is directly connected, Vlan200

      5. Fallback: any "via <ip>" (interface unknown)
    """
    routes: List[Dict[str, Optional[str]]] = []

    # ── Common fields ─────────────────────────────────────────────────────────
    prefix:     Optional[str] = None
    source:     Optional[str] = None
    global_tag: Optional[str] = None
    global_age: Optional[str] = None

    m = re.search(r"Routing entry for\s+(\S+)", output, re.IGNORECASE)
    if m:
        prefix = m.group(1)
    if not prefix:
        m = re.search(r"^(\d+\.\d+\.\d+\.\d+/\d+),\s+ubest", output, re.MULTILINE)
        if m:
            prefix = m.group(1)

    m = re.search(r'Known via\s+"([^"]+)"', output, re.IGNORECASE)
    if m:
        source = m.group(1)

    # IOS-XE route-level tag: "  Tag 91, type extern 2, forward metric 1"
    m = re.search(r"^\s+Tag\s+(\d+)", output, re.IGNORECASE | re.MULTILINE)
    if m:
        global_tag = m.group(1)

    # Global age fallback from Last update line.
    # Handles both:
    #   OSPF/Static: "Last update from X on TwentyFiveGigE1/5/0/3, 2w2d ago"
    #   BGP:         "Last update from 198.18.255.93 2w4d ago"   (no "on Interface")
    m = re.search(
        r"Last update from\s+\S+(?:\s+on\s+\S+,)?\s+(\S+)\s+ago",
        output, re.IGNORECASE,
    )
    if m:
        global_age = m.group(1)

    def _entry(
        nh: str,
        iface: Optional[str],
        src:  Optional[str] = None,
        tag:  Optional[str] = None,
        age:  Optional[str] = None,
    ) -> Dict[str, Optional[str]]:
        return {
            "prefix":        prefix,
            "next_hop":      nh,
            "exit_interface": iface,
            "route_source":  src or source,
            "route_tag":     tag if tag is not None else global_tag,
            "route_age":     age if age is not None else global_age,
        }

    # ── Pattern 1: IOS-XE routing descriptor block (line-by-line) ────────────
    #
    # OSPF / Static descriptor (interface present):
    #   "  * 10.0.0.2, from 198.18.x.x, 2w2d ago, via GigabitEthernet1/0/1"
    #   "    10.0.0.6, from 198.18.x.x, 2w2d ago, via GigabitEthernet1/0/2"
    #
    # BGP internal descriptor (NO interface — recursive next-hop):
    #   "  * 198.18.255.93, from 198.18.255.93, 2w4d ago"
    #
    # Directly connected:
    #   "  * directly connected, via Vlan128"
    #
    # _DESC_IP captures group(1)=next-hop IP, group(2)=interface or None (BGP).
    # _RAGE_PER uses \b...\b so it matches "2w4d" even at end-of-line.
    #
    _DESC_IP  = re.compile(
        r"^\s+\*?\s*(\d+\.\d+\.\d+\.\d+),(?:.*?via\s+(\S+))?",
        re.IGNORECASE,
    )
    _DESC_DC  = re.compile(r"^\s+\*?\s*directly connected,\s+via\s+(\S+)",  re.IGNORECASE)
    _RTAG_PER = re.compile(r"^\s+Route tag\s+(\d+)",                        re.IGNORECASE)
    _RAGE_PER = re.compile(r"\b(\S+)\s+ago\b",                              re.IGNORECASE)

    pending: Optional[Dict[str, Optional[str]]] = None

    for line in output.splitlines():
        m = _DESC_IP.search(line)
        if m:
            if pending is not None:
                routes.append(pending)
            age_m = _RAGE_PER.search(line)
            iface = m.group(2).rstrip(",") if m.group(2) else None
            pending = _entry(
                m.group(1),
                iface,
                age=age_m.group(1) if age_m else None,
            )
            continue

        m = _DESC_DC.search(line)
        if m:
            if pending is not None:
                routes.append(pending)
            pending = _entry("directly connected", m.group(1).rstrip(","), "connected")
            continue

        m = _RTAG_PER.search(line)
        if m and pending is not None:
            pending["route_tag"] = m.group(1)

    if pending is not None:
        routes.append(pending)

    if routes:
        # Interface fallback for entries that have a next-hop but no interface.
        # Handles OSPF: "Last update from X on TwentyFiveGigE1/5/0/3, 2w2d ago"
        fb = re.search(r"Last update from\s+\S+\s+on\s+(\S+),", output, re.IGNORECASE)
        for r in routes:
            if not r["exit_interface"] and fb:
                r["exit_interface"] = fb.group(1).rstrip(",")
        return routes

    # ── Pattern 2: NX-OS *via lines (age is 4th field, after [metric]) ───────
    # "*via 10.0.0.2, Eth1/1, [110/2], 00:01:02, ospf-1, intra, tag 91"
    for m in re.finditer(
        r"^\s*\*via\s+(\d+\.\d+\.\d+\.\d+),\s+([^\s,]+)"
        r"(?:,\s+\[[^\]]+\],\s+([^,]+))?"     # optional: [metric], age
        r"(?:.*?\btag\s+(\d+))?",
        output, re.IGNORECASE | re.MULTILINE,
    ):
        tag = m.group(4) or global_tag
        age = m.group(3).strip() if m.group(3) else None
        routes.append(_entry(m.group(1), m.group(2), tag=tag, age=age))

    if routes:
        return routes

    # ── Pattern 3: IOS-XE brief with age+interface ───────────────────────────
    # "O  192.168.0.0/24 [110/2] via 10.0.0.2, 00:01:02, GigabitEthernet1/0/1"
    # "O E2 10.10.218.0/23 [110/1] via 10.254.80.6, 2w2d, TwentyFiveGigE1/1/0/47"
    # Age can be HH:MM:SS *or* Cisco duration format (2w2d, 1d12h, 3d23h, etc.).
    for m in re.finditer(
        r"\bvia\s+(\d+\.\d+\.\d+\.\d+),\s+([^,\s]+),\s+(\S+)",
        output, re.IGNORECASE,
    ):
        routes.append(_entry(m.group(1), m.group(3).rstrip(","), age=m.group(2)))

    if routes:
        return routes

    # ── Pattern 4: IOS-XE brief directly connected ───────────────────────────
    for m in re.finditer(r"is directly connected,\s+(\S+)", output, re.IGNORECASE):
        routes.append(_entry("directly connected", m.group(1).rstrip(","), "connected"))

    if routes:
        return routes

    # ── Pattern 5: any "via <ip>" (no interface) ─────────────────────────────
    for m in re.finditer(r"\bvia\s+(\d+\.\d+\.\d+\.\d+)", output, re.IGNORECASE):
        routes.append(_entry(m.group(1), None))

    return routes


def get_routes_for_ip(client: CiscoDeviceClient, ip: str) -> List[Dict[str, Optional[str]]]:
    """Run ``show ip route <ip>`` and return all matching ECMP routes."""
    try:
        output = _send_cmd(client, f"show ip route {ip}")
    except Exception as exc:
        log.error("Route lookup for %s failed: %s", ip, exc)
        return []
    log.debug("show ip route %s:\n%s", ip, output)
    return _parse_all_routes(output)


def get_gateway_interface(client: CiscoDeviceClient, gateway_ip: str) -> Optional[str]:
    """Return the interface on the gateway that carries *gateway_ip*.

    Delegates to ``get_routes_for_ip`` and returns the exit_interface of the
    first matching route (the gateway's own IP is always directly connected).
    """
    for route in get_routes_for_ip(client, gateway_ip):
        if route.get("exit_interface"):
            log.debug("Gateway %s is on interface %s", gateway_ip, route["exit_interface"])
            return route["exit_interface"]
    log.debug("Could not resolve gateway interface for %s", gateway_ip)
    return None


def get_route_for_destination(
    client: CiscoDeviceClient,
    dst_ip: str,
) -> List[Dict[str, Optional[str]]]:
    """Return all ECMP routes for *dst_ip* from ``show ip route <dst_ip>``.

    Returns a list (one entry per ECMP path).  Each entry has:
      prefix, next_hop, exit_interface, route_source.
    """
    routes = get_routes_for_ip(client, dst_ip)
    log.debug("Routes for %s: %s", dst_ip, routes)
    return routes


# ─────────────────────────────────────────────────────────────────────────────
# Phase 2 — MAC table lookup
# ─────────────────────────────────────────────────────────────────────────────

# Matches the start of any Cisco/NX-OS interface abbreviation.
_IFACE_RE = re.compile(
    r"^(Gi|Fa|Te|Fo|Hu|Twe|Po|Eth|GigabitEthernet|FastEthernet"
    r"|TenGigabitEthernet|Port-channel|port-channel|ae|bundle)",
    re.IGNORECASE,
)


def _parse_mac_table_output(output: str, mac: str) -> Optional[Dict[str, str]]:
    """Parse ``show mac address-table`` output and return {vlan, interface, mac}."""
    search_mac = mac_to_cisco_fmt(mac).lower()

    for line in output.splitlines():
        if search_mac not in line.lower():
            continue

        # Strip NX-OS leading flag characters (* G R C ~ +) and whitespace.
        clean = re.sub(r"^\s*[*GRC~+\s]+", "", line).strip()
        parts = clean.split()
        if len(parts) < 3:
            continue

        vlan      : Optional[str] = None
        interface : Optional[str] = None

        # VLAN — first token that is purely numeric.
        if parts[0].isdigit():
            vlan = parts[0]

        # Interface — rightmost token that looks like a network interface.
        for token in reversed(parts):
            if _IFACE_RE.match(token):
                interface = token
                break

        if vlan and interface:
            log.debug("MAC table: VLAN=%s, interface=%s", vlan, interface)
            return {"vlan": vlan, "interface": interface, "mac": mac}

    log.debug("Could not parse MAC table output:\n%s", output)
    return None


def mac_table_lookup(
    client: CiscoDeviceClient,
    device_type: str,  # noqa: ARG001 — reserved for future platform-specific MAC table commands
    mac: str,
) -> Optional[Dict[str, str]]:
    """Look up *mac* in the forwarding table and return {vlan, interface, mac}."""
    cisco_mac = mac_to_cisco_fmt(mac)
    cmd = f"show mac address-table address {cisco_mac}"
    try:
        output = _send_cmd(client, cmd)
    except Exception as exc:
        log.error("MAC table command failed (%s): %s", cmd, exc)
        return None
    log.debug("MAC table output:\n%s", output)
    return _parse_mac_table_output(output, mac)


# ─────────────────────────────────────────────────────────────────────────────
# Phase 2 — port-channel member lookup
# ─────────────────────────────────────────────────────────────────────────────


def is_portchannel(interface: str) -> bool:
    """Return True when *interface* is a LAG/port-channel logical interface."""
    return bool(
        re.match(r"^(port-?channel|Po|ae|bundle-?ether)\d+", interface, re.IGNORECASE)
    )


def _parse_ios_portchannel_members(output: str, po_num: str) -> List[str]:
    """Extract physical members of Port-channel *po_num* from IOS/IOS-XE etherchannel summary.

    Typical line format:
        1    Po1(SU)    LACP    Gi1/0/47(P) Gi2/0/47(P)
    """
    members: List[str] = []
    capturing = False

    for line in output.splitlines():
        if re.search(rf"\bPo{po_num}\b", line, re.IGNORECASE):
            capturing = True
        elif capturing and re.search(r"\bPo\d+\b", line):
            break  # start of next group

        if not capturing:
            continue

        for raw in re.findall(r"((?:Gi|Fa|Te|Fo|Hu|Twe)\d[\d/\.]*)", line):
            clean = re.sub(r"\([^)]*\)", "", raw).strip()
            if clean and clean not in members:
                members.append(clean)

    return members


def _parse_nxos_portchannel_members(output: str, po_num: str) -> List[str]:
    """Extract physical members of Po *po_num* from NX-OS port-channel summary.

    Typical line format:
        1    Po1(SU)    Eth    LACP    Eth1/1(P) Eth1/2(P)
    """
    members: List[str] = []
    capturing = False

    for line in output.splitlines():
        if re.search(rf"\bPo{po_num}\b", line, re.IGNORECASE):
            capturing = True
        elif capturing and re.search(r"\bPo\d+\b", line):
            break

        if not capturing:
            continue

        for raw in re.findall(r"(Eth\d+/\d+(?:/\d+)?)", line):
            clean = re.sub(r"\([^)]*\)", "", raw).strip()
            if clean and clean not in members:
                members.append(clean)

    return members


def get_portchannel_members(
    client: CiscoDeviceClient,
    device_type: str,
    interface: str,
) -> List[str]:
    """Return the physical member interfaces of the given port-channel.

    Uses platform-appropriate commands:
      IOS/IOS-XE: ``show etherchannel summary``
      NX-OS:      ``show port-channel summary``
    """
    m = re.search(r"\d+", interface)
    if not m:
        log.debug("Cannot extract port-channel number from %r", interface)
        return []

    po_num = m.group(0)
    try:
        if "nxos" in device_type:
            output  = _send_cmd(client, "show port-channel summary")
            members = _parse_nxos_portchannel_members(output, po_num)
        else:
            output  = _send_cmd(client, "show etherchannel summary")
            members = _parse_ios_portchannel_members(output, po_num)
    except Exception as exc:
        log.error("Port-channel member lookup failed: %s", exc)
        return []

    log.debug("Port-channel %s members: %s", interface, members)
    return members


# ─────────────────────────────────────────────────────────────────────────────
# Phase 2 — CDP / LLDP neighbor lookup
# ─────────────────────────────────────────────────────────────────────────────


def _get_cdp_neighbor(
    client: CiscoDeviceClient,
    device_type: str,
    interface: str,
) -> Optional[Dict[str, str]]:
    """Return a CDP neighbor detail dict for *interface*, or None."""
    if "nxos" in device_type:
        cmd = f"show cdp neighbors interface {interface} detail"
    else:
        cmd = f"show cdp neighbors {interface} detail"

    try:
        output = _send_cmd(client, cmd)
    except Exception as exc:
        log.debug("CDP command failed on %s: %s", interface, exc)
        return None

    if not output or "device id" not in output.lower():
        return None

    info: Dict[str, str] = {"protocol": "CDP"}

    m = re.search(r"Device ID:\s*(\S+)", output, re.IGNORECASE)
    if m:
        info["neighbor_id"] = m.group(1)

    m = re.search(r"Platform:\s*([^,\r\n]+)", output, re.IGNORECASE)
    if m:
        info["platform"] = m.group(1).strip()

    m = re.search(r"IP [Aa]ddress:\s*(\S+)", output, re.IGNORECASE)
    if m:
        info["neighbor_ip"] = m.group(1)

    m = re.search(r"Port ID \(outgoing port\):\s*(\S+)", output, re.IGNORECASE)
    if m:
        info["remote_port"] = m.group(1)

    return info if "neighbor_id" in info else None


def _get_lldp_neighbor(
    client: CiscoDeviceClient,
    device_type: str,
    interface: str,
) -> Optional[Dict[str, str]]:
    """Return an LLDP neighbor detail dict for *interface*, or None."""
    if "nxos" in device_type:
        cmd = f"show lldp neighbors interface {interface} detail"
    else:
        cmd = f"show lldp neighbors {interface} detail"

    try:
        output = _send_cmd(client, cmd)
    except Exception as exc:
        log.debug("LLDP command failed on %s: %s", interface, exc)
        return None

    if not output or "chassis id" not in output.lower():
        return None

    info: Dict[str, str] = {"protocol": "LLDP"}

    m = re.search(r"System Name:\s*(\S+)", output, re.IGNORECASE)
    if m:
        info["neighbor_id"] = m.group(1)

    m = re.search(r"System Description:\s*(.+)", output, re.IGNORECASE)
    if m:
        info["platform"] = m.group(1).strip()[:80]

    m = re.search(r"Management Address:\s*(\S+)", output, re.IGNORECASE)
    if m:
        info["neighbor_ip"] = m.group(1)

    m = re.search(r"Port ID:\s*(\S+)", output, re.IGNORECASE)
    if m:
        info["remote_port"] = m.group(1)

    return info if "neighbor_id" in info else None


def get_neighbor_info(
    client: CiscoDeviceClient,
    device_type: str,
    interface: str,
) -> Optional[Dict[str, str]]:
    """Return CDP or LLDP neighbor info for *interface*, preferring CDP. Returns None if none found."""
    cdp = _get_cdp_neighbor(client, device_type, interface)
    if cdp:
        return cdp
    return _get_lldp_neighbor(client, device_type, interface)


# ─────────────────────────────────────────────────────────────────────────────
# Phase 2 — stop-condition evaluation and result output
# ─────────────────────────────────────────────────────────────────────────────


def should_stop_trace(
    neighbor_info: Optional[Dict[str, str]],
) -> Tuple[bool, str]:
    """Return (stop, reason) based on CDP/LLDP neighbor information.

    Returns (True, reason) when the trace should end at the current switchport:
      - No CDP/LLDP neighbor found (endpoint-facing port).
      - Neighbor is a VMware host (ESXi/vSwitch).
      - Neighbor is an access point.

    Returns (False, "") when the neighbor is a routable network device
    (switch or router) and the trace should continue to that device.
    """
    if not neighbor_info:
        return True, "No CDP/LLDP neighbor on this port — closest switchport"

    combined = (
        neighbor_info.get("neighbor_id", "") + " " + neighbor_info.get("platform", "")
    ).lower()

    if any(kw in combined for kw in _VMWARE_KEYWORDS):
        return True, f"Neighbor is VMware ({neighbor_info.get('neighbor_id', 'unknown')})"

    if any(kw in combined for kw in _AP_ROLE_KEYWORDS):
        return True, f"Neighbor is an AP ({neighbor_info.get('neighbor_id', 'unknown')})"

    return False, ""



def _log_intermediate_hop(
    hop_num: int,
    hostname: str,
    switch_ip: str,
    vlan: str,
    interface: str,
    portchannel_members: List[str],
    neighbor_info: Dict[str, str],
    neighbor_ip: str,
) -> None:
    """Print a single [HOP] line for an intermediate switch during the trace."""
    po_detail   = f" (members: {', '.join(portchannel_members)})" if portchannel_members else ""
    neighbor_id = neighbor_info.get("neighbor_id", "unknown")
    protocol    = neighbor_info.get("protocol", "CDP")
    print(
        f"[HOP {hop_num:>2}] {hostname} ({switch_ip})  "
        f"VLAN={vlan}  iface={interface}{po_detail}  "
        f"--{protocol}-->  {neighbor_id} ({neighbor_ip})"
    )


# ─────────────────────────────────────────────────────────────────────────────
# Phase 2 — path dict assembly and summary output
# ─────────────────────────────────────────────────────────────────────────────


def build_path_dict(
    target_ip: str,
    mac: Optional[str],
    gateway_ip: str,
    downstream_hops: List[Dict],
    gateway_interface: Optional[str] = None,
    dst_route: Optional[List[Dict]] = None,
    dst_ip: str = "",
    stop_reason: str = "",
) -> Dict:
    """Reverse the downstream hop list to produce an upstream (device→gateway) path dict.

    The downstream trace visits switches in gateway→device order.  Each hop
    record contains:
      local_interface   – the interface on *that* switch pointing toward the device
                          (the MAC table result; egress in downstream, ingress in upstream)
      portchannel_members – physical members of local_interface if it is a port-channel
      remote_port       – "Port ID (outgoing port)" from CDP, i.e. the port on the
                          *neighbor* switch that connects back to us.  In upstream terms
                          this is the *egress* of the upstream hop whose d_idx is one
                          lower.

    Reversal formula (j = upstream hop index, d_idx = n-1-j):
      ingress_interface = downstream_hops[d_idx].local_interface
      egress_interface  = downstream_hops[d_idx-1].remote_port  (None when d_idx == 0)

    For the last upstream hop (the gateway, d_idx == 0), egress_interface is set
    to *gateway_interface* — the SVI or routed interface that carries *gateway_ip*.
    """
    n = len(downstream_hops)
    upstream_path: List[Dict] = []

    for j in range(n):
        d_idx = n - 1 - j
        d_hop = downstream_hops[d_idx]

        ingress         = d_hop.get("local_interface")
        ingress_members = d_hop.get("portchannel_members", [])

        if d_idx == 0:
            # This is the gateway — egress is the SVI / routed port with the gateway IP.
            egress = gateway_interface
        else:
            egress = downstream_hops[d_idx - 1].get("remote_port")

        upstream_path.append({
            "hop":                         j + 1,
            "hostname":                    d_hop.get("hostname"),
            "switch_ip":                   d_hop.get("switch_ip"),
            "vlan":                        d_hop.get("vlan"),
            "ingress_interface":           ingress,
            "ingress_portchannel_members": ingress_members,
            "egress_interface":            egress,
            "is_gateway":                  d_idx == 0,
        })

    return {
        "target_ip":   target_ip,
        "mac":         mac_to_cisco_fmt(mac) if mac else None,
        "gateway_ip":  gateway_ip,
        "total_hops":  n,
        "path":        upstream_path,
        "dst_route":   dst_route or [],
        "dst_ip":      dst_ip,
        "stop_reason": stop_reason,
    }


def print_path_summary(path_dict: Dict) -> None:
    """Print the complete device→gateway path to the console."""
    SEP = "=" * 64
    print()
    print(SEP)
    print("  PATH SUMMARY  (device --> gateway)")
    print(SEP)
    print(f"  Target IP  : {path_dict['target_ip']}")
    print(f"  ARP MAC    : {path_dict['mac'] or '—'}")
    print(f"  Gateway    : {path_dict['gateway_ip']}")
    print(f"  Total hops : {path_dict['total_hops']}")
    print(SEP)

    for hop in path_dict["path"]:
        hostname   = hop["hostname"] or hop["switch_ip"]
        sw_ip      = hop["switch_ip"]
        vlan       = hop["vlan"] or "—"
        ingress    = hop["ingress_interface"] or "—"
        i_mbrs     = hop.get("ingress_portchannel_members", [])
        is_gateway = hop.get("is_gateway", False)

        if is_gateway:
            gw_iface = hop["egress_interface"]
            egress   = f"{gw_iface}  ({path_dict['gateway_ip']})" if gw_iface else "(gateway — interface not resolved)"
        else:
            egress = hop["egress_interface"] or "—"

        print(f"\n  Hop {hop['hop']}: {hostname}  ({sw_ip})")
        print(f"    VLAN    : {vlan}")
        print(f"    Ingress : {ingress}", end="")
        if i_mbrs:
            print(f"  [members: {', '.join(i_mbrs)}]", end="")
        print()
        print(f"    Egress  : {egress}")

    dst_routes = path_dict.get("dst_route", [])
    if dst_routes:
        queried = path_dict.get("dst_ip", "")
        print(f"\n  Destination Routes  ({queried})")
        for idx, r in enumerate(dst_routes, 1):
            prefix = r.get("prefix") or queried
            nh     = r.get("next_hop") or "?"
            iface  = r.get("exit_interface", "")
            src    = r.get("route_source", "")
            tag    = r.get("route_tag", "")
            age    = r.get("route_age", "")
            line   = f"    {idx}. {prefix}  via {nh}"
            if iface:
                line += f"  [{iface}]"
            if src:
                line += f"  [{src}]"
            if tag:
                line += f"  tag:{tag}"
            if age:
                line += f"  age:{age}"
            print(line)

    print()
    print(SEP)
    print()


# ─────────────────────────────────────────────────────────────────────────────
# Phase 3 — L3 path trace (gateway → destination, all ECMP paths)
# ─────────────────────────────────────────────────────────────────────────────


def _run_l2_at_final_hop(
    client: CiscoDeviceClient,
    device_type: str,
    dst_ip: str,
) -> Dict:
    """Run a Layer 2 trace for *dst_ip* on the device that has its subnet directly connected.

    Executes the same three-step flow used in the initial L2 trace:
      1. ``show ip arp <dst_ip>``                    → resolve to MAC address
      2. ``show mac address-table address <mac>``     → VLAN + switchport
      3. ``show cdp neighbors <port> detail``         → next-hop device (if any)

    Returns a dict with keys:
      dst_ip, mac, vlan, port, portchannel_members, cdp_neighbor, error
    """
    result: Dict = {
        "dst_ip":              dst_ip,
        "mac":                 None,
        "vlan":                None,
        "port":                None,
        "portchannel_members": [],
        "cdp_neighbor":        None,
        "error":               None,
    }

    # Step 1 — ARP lookup
    print(f"[L2]   show ip arp {dst_ip}")
    mac = arp_lookup(client, device_type, dst_ip)
    if not mac:
        result["error"] = f"No ARP entry for {dst_ip}"
        return result

    result["mac"] = mac_to_cisco_fmt(mac)
    print(f"[L2]   ARP: {dst_ip} → {mac_to_cisco_fmt(mac)}")

    # Step 2 — MAC address-table lookup
    print(f"[L2]   show mac address-table address {mac_to_cisco_fmt(mac)}")
    mac_entry = mac_table_lookup(client, device_type, mac)
    if not mac_entry:
        result["error"] = f"MAC {mac_to_cisco_fmt(mac)} not in address table"
        return result

    result["vlan"] = mac_entry["vlan"]
    result["port"] = mac_entry["interface"]
    print(f"[L2]   MAC table: VLAN={mac_entry['vlan']}  Port={mac_entry['interface']}")

    # Step 2a — port-channel expansion (if applicable)
    check_iface = mac_entry["interface"]
    if is_portchannel(mac_entry["interface"]):
        members = get_portchannel_members(client, device_type, mac_entry["interface"])
        result["portchannel_members"] = members
        if members:
            print(f"[L2]   Port-channel members: {', '.join(members)}")
            check_iface = members[0]

    # Step 3 — CDP/LLDP neighbor on the resolved physical port
    print(f"[L2]   show cdp neighbors {check_iface} detail")
    neighbor = get_neighbor_info(client, device_type, check_iface)
    if neighbor:
        result["cdp_neighbor"] = {
            "hostname": neighbor.get("neighbor_id"),
            "ip":       neighbor.get("neighbor_ip"),
            "platform": neighbor.get("platform"),
            "port":     neighbor.get("remote_port"),
            "protocol": neighbor.get("protocol", "CDP"),
        }
        nid = neighbor.get("neighbor_id", "unknown")
        nip = neighbor.get("neighbor_ip", "")
        print(f"[L2]   CDP neighbor: {nid}" + (f" ({nip})" if nip else ""))
    else:
        print(f"[L2]   No CDP/LLDP neighbor on {check_iface} — endpoint port")

    return result


def run_l3_path_trace(
    gateway_ip: str,
    gw_hostname: str,
    gw_ingress_interface: Optional[str],
    dst_ip: str,
    initial_routes: List[Dict],
    creds: Dict[str, str],
    nb_url: str = "",
    nb_token: str = "",
    verify_ssl: bool = True,
    max_hops: int = 15,
) -> List[List[Dict]]:
    """BFS traversal of all ECMP L3 paths from *gateway_ip* toward *dst_ip*.

    At every hop:
      - ``show ip route <prev_ip>``  → ingress interfaces (how traffic arrived)
      - ``show ip route <dst_ip>``   → egress routes (all ECMP next-hops onward)

    Each unique next-hop spawns a new path branch.  Returns a list of
    complete paths, each path being an ordered list of hop dicts.

    Stop conditions per branch:
      - Destination is directly connected on the current device.
      - No route found for dst_ip.
      - Cannot connect to next-hop.
      - Loop detected (IP already visited on this branch).
      - max_hops reached.
    """
    from collections import deque  # noqa: PLC0415

    complete_paths: List[List[Dict]] = []

    gw_hop: Dict = {
        "hostname":           gw_hostname,
        "ip":                 gateway_ip,
        "ingress_interfaces": [gw_ingress_interface] if gw_ingress_interface else [],
        "egress_routes":      initial_routes,
        "note":               "",
    }

    # If the destination is already directly reachable from the gateway, done.
    if any(r.get("next_hop") == "directly connected" for r in initial_routes):
        return [[gw_hop]]

    # Seed the BFS queue: (path_so_far, next_hop_to_visit, visited_ips_on_this_branch)
    # Each branch gets its own copy of gw_hop stamped with the specific route it follows
    # so print_l3_paths can label the path and show the exact egress interface.
    queue: deque = deque()
    for route in initial_routes:
        nh = route.get("next_hop")
        if nh and nh != "directly connected":
            branch_gw_hop = dict(gw_hop)
            branch_gw_hop["selected_route"] = route   # the one route this branch follows
            queue.append(([branch_gw_hop], nh, {gateway_ip}))

    if not queue:
        return [[gw_hop]]

    while queue:
        path_so_far, current_ip, visited = queue.popleft()

        if current_ip in visited:
            complete_paths.append(
                path_so_far + [{"hostname": current_ip, "ip": current_ip,
                                "note": f"Loop detected at {current_ip}",
                                "ingress_interfaces": [], "egress_routes": []}]
            )
            continue

        if len(path_so_far) >= max_hops:
            complete_paths.append(
                path_so_far + [{"hostname": current_ip, "ip": current_ip,
                                "note": f"Max hops ({max_hops}) reached",
                                "ingress_interfaces": [], "egress_routes": []}]
            )
            continue

        print(f"[L3] Hop {len(path_so_far) + 1}: connecting to {current_ip}...")

        # ── Connection with NetBox primary-IP fallback ────────────────────────
        connect_ip = current_ip
        client     = None
        connect_err: str = ""

        # ── Try direct SSH first ──────────────────────────────────────────────
        try:
            client = _open_device_client(connect_ip, "ios", creds)
        except GatewayConnectionError as exc:
            connect_err = str(exc)
            log.debug("Direct connect to %s failed: %s", connect_ip, exc)

            # ── Fallback: resolve the IP to a Cisco device in NetBox ──────────
            if nb_url and nb_token:
                print(f"[L3]   Cannot reach {current_ip} — querying NetBox to resolve device...")
                primary_ip = _resolve_mgmt_ip_from_netbox(
                    nb_url, nb_token, current_ip, verify_ssl
                )
                if primary_ip and primary_ip != current_ip:
                    print(f"[L3]   Connecting to device primary IPv4: {primary_ip}...")
                    connect_ip = primary_ip
                    try:
                        client = _open_device_client(connect_ip, "ios", creds)
                        connect_err = ""
                        print(f"[L3]   Connected via primary IP {connect_ip}")
                    except GatewayConnectionError as exc2:
                        connect_err = str(exc2)
                        log.debug(
                            "Primary IP connect to %s also failed: %s", connect_ip, exc2
                        )
                elif primary_ip == current_ip:
                    log.debug(
                        "NetBox primary IP for %s is the same address — no fallback available",
                        current_ip,
                    )

        if client is None:
            note = f"Cannot connect to {current_ip}"
            if connect_ip != current_ip:
                note += f"; also tried NetBox primary {connect_ip}"
            if connect_err:
                note += f": {connect_err}"
            complete_paths.append(
                path_so_far + [{"hostname": current_ip, "ip": current_ip,
                                "connect_ip": connect_ip,
                                "note": note,
                                "ingress_interfaces": [], "egress_routes": []}]
            )
            continue

        hostname        = current_ip
        ingress_ifaces: List[str]  = []
        egress_routes:  List[Dict] = []
        l2_trace:       Optional[Dict] = None

        try:
            try:
                hostname = client._cli_connection.find_prompt().rstrip("#>").strip() or current_ip
            except Exception:
                pass

            prev_ip = path_so_far[-1]["ip"]
            print(f"[L3]   show ip route {prev_ip} → ingress interfaces")
            for r in get_routes_for_ip(client, prev_ip):
                if r.get("exit_interface") and r["exit_interface"] not in ingress_ifaces:
                    ingress_ifaces.append(r["exit_interface"])

            print(f"[L3]   show ip route {dst_ip} → egress routes")
            egress_routes = get_routes_for_ip(client, dst_ip)

            # If this device has the destination subnet directly connected,
            # run the full L2 trace (ARP → MAC table → CDP) while still connected.
            if any(r.get("next_hop") == "directly connected" for r in egress_routes):
                print(f"[L3]   {dst_ip} subnet is directly connected — running L2 trace...")
                l2_trace = _run_l2_at_final_hop(client, "ios", dst_ip)

        finally:
            try:
                client._cli_disconnect()
            except Exception:
                pass

        current_hop: Dict = {
            "hostname":           hostname,
            "ip":                 current_ip,
            "connect_ip":         connect_ip,
            "ingress_interfaces": ingress_ifaces,
            "egress_routes":      egress_routes,
            "l2_trace":           l2_trace,
            "note":               "",
        }
        new_path    = path_so_far + [current_hop]
        new_visited = visited | {current_ip, connect_ip}  # prevent re-visiting either IP

        if not egress_routes:
            current_hop["note"] = "No route to destination"
            complete_paths.append(new_path)
            continue

        if any(r.get("next_hop") == "directly connected" for r in egress_routes):
            complete_paths.append(new_path)
            continue

        # Expand ECMP — each unique next-hop spawns a new branch.
        next_hops: List[str] = []
        for r in egress_routes:
            nh = r.get("next_hop")
            if nh and nh != "directly connected" and nh not in next_hops:
                next_hops.append(nh)

        if not next_hops:
            current_hop["note"] = "No reachable next-hop"
            complete_paths.append(new_path)
            continue

        for nh in next_hops:
            queue.append((new_path, nh, new_visited))

    return complete_paths


def print_l3_paths(paths: List[List[Dict]], dst_ip: str) -> None:
    """Print all L3 ECMP paths (gateway → destination) to the console."""
    if not paths:
        return

    SEP = "=" * 64
    print()
    print(SEP)
    print(f"  L3 PATH TRACE  (gateway --> {dst_ip})")
    print(SEP)

    for path_num, path in enumerate(paths, 1):
        # Label the path with the specific route (next-hop + egress interface) it follows.
        first_hop = path[0] if path else {}
        sel = first_hop.get("selected_route", {})
        path_nh    = sel.get("next_hop", "")
        path_iface = sel.get("exit_interface", "")
        path_label = f"  via {path_nh}" + (f"  [{path_iface}]" if path_iface else "")
        print(f"\n  Path {path_num}:{path_label}")

        for hop_num, hop in enumerate(path, 1):
            hostname = hop.get("hostname") or hop.get("ip", "unknown")
            ip       = hop.get("ip", "")
            note     = hop.get("note", "")

            connect_ip = hop.get("connect_ip", ip)
            ip_label   = f"({ip})" if connect_ip == ip else f"({ip})  [connected via {connect_ip}]"
            print(f"\n    Hop {hop_num}: {hostname}  {ip_label}")

            if note:
                print(f"      [{note}]")
                continue

            ifaces = hop.get("ingress_interfaces", [])
            if ifaces:
                print(f"      Ingress : {', '.join(ifaces)}")

            # For the gateway hop: show the specific egress interface this path uses.
            sel_route = hop.get("selected_route")
            if sel_route:
                sel_nh    = sel_route.get("next_hop", "?")
                sel_iface = sel_route.get("exit_interface", "")
                sel_age   = sel_route.get("route_age", "")
                sel_tag   = sel_route.get("route_tag", "")
                egress_line = f"      Egress  : {sel_iface or '—'}  (→ {sel_nh})"
                if sel_age:
                    egress_line += f"  age:{sel_age}"
                if sel_tag:
                    egress_line += f"  tag:{sel_tag}"
                print(egress_line)

            reached = False
            for r in hop.get("egress_routes", []):
                prefix = r.get("prefix") or dst_ip
                nh     = r.get("next_hop") or "?"
                iface  = r.get("exit_interface", "")
                src    = r.get("route_source", "")
                tag    = r.get("route_tag", "")
                age    = r.get("route_age", "")
                line   = f"      Route   : {prefix}  via {nh}"
                if iface:
                    line += f"  [{iface}]"
                if src:
                    line += f"  [{src}]"
                if tag:
                    line += f"  tag:{tag}"
                if age:
                    line += f"  age:{age}"
                print(line)
                if nh == "directly connected":
                    reached = True

            if reached:
                print(f"      [DESTINATION REACHED]")
                l2 = hop.get("l2_trace")
                if l2:
                    print(f"\n      Layer 2 Trace  ({l2.get('dst_ip', '')})")
                    if l2.get("error"):
                        print(f"        Error       : {l2['error']}")
                    else:
                        if l2.get("mac"):
                            print(f"        ARP MAC     : {l2['mac']}")
                        if l2.get("vlan"):
                            print(f"        VLAN        : {l2['vlan']}")
                        if l2.get("port"):
                            print(f"        Port        : {l2['port']}")
                        if l2.get("portchannel_members"):
                            print(f"        Po members  : {', '.join(l2['portchannel_members'])}")
                        cdp = l2.get("cdp_neighbor")
                        if cdp:
                            name  = cdp.get("hostname", "unknown")
                            nip   = cdp.get("ip", "")
                            nport = cdp.get("port", "")
                            plat  = cdp.get("platform", "")
                            proto = cdp.get("protocol", "CDP")
                            print(
                                f"        {proto} Neighbor: {name}"
                                + (f"  ({nip})" if nip else "")
                            )
                            if nport:
                                print(f"        Remote Port : {nport}")
                            if plat:
                                print(f"        Platform    : {plat}")
                        else:
                            print(f"        CDP         : no neighbor on port (endpoint)")

    print()
    print(SEP)
    print()


def print_trace_summary(result: Dict) -> None:
    """Print the complete L2 + L3 trace summary from the combined output dict.

    Called once at the very end of the trace so all output is consolidated.

    *result* is the dict returned by ``run_l2_trace``::

        {
          "src_ip":     str,
          "dst_ip":     str,
          "gateway_ip": str,
          "layer2":     dict | None,          # from build_path_dict
          "layer3":     list[list[dict]] | None,  # from run_l3_path_trace
        }
    """
    SEP = "=" * 70
    print()
    print(SEP)
    print("  NETWORK TRACE SUMMARY")
    print(SEP)
    print(f"  Source      : {result.get('src_ip', '—')}")
    print(f"  Destination : {result.get('dst_ip', '—')}")
    print(f"  Gateway     : {result.get('gateway_ip', '—')}")
    print(SEP)

    layer2 = result.get("layer2")
    if layer2:
        print(f"\n  ── Layer 2 Path  (device → gateway) ──────────────────────────────")
        stop = layer2.get("stop_reason", "")
        if stop:
            print(f"  L2 stop reason : {stop}")
        print_path_summary(layer2)
    else:
        print("\n  [Layer 2 trace produced no path data]")

    layer3 = result.get("layer3")
    if layer3:
        print(f"\n  ── Layer 3 Paths  (gateway → destination) ─────────────────────────")
        print_l3_paths(layer3, result.get("dst_ip", ""))

    print()
    print(SEP)
    print()


# ─────────────────────────────────────────────────────────────────────────────
# Phase 2 — L2 trace orchestration
# ─────────────────────────────────────────────────────────────────────────────


def run_l2_trace(
    target_ip: str,
    dst_ip: str,
    gateway_ip: str,
    creds: Dict[str, str],
    source_is_ap: bool,
    device_type: Optional[str] = None,
    max_hops: int = 30,
    nb_url: str = "",
    nb_token: str = "",
    verify_ssl: bool = True,
) -> Optional[Dict]:
    """Run the hop-by-hop Layer 2 trace for *target_ip* starting at *gateway_ip*.

    Phase A — ARP (gateway only, once):
        Resolves *target_ip* to a MAC address.

    Phase B — hop loop (up to *max_hops* switches):
        On each switch:
          1. MAC table lookup   → VLAN + interface
          2. Port-channel expansion (if applicable)
          3. CDP/LLDP on the resolved physical interface
          4a. Neighbor is AP, VMware, or absent → record final hop and stop.
          4b. Neighbor is a switch/router → record intermediate hop, resolve
              its management IP, and connect to continue the trace.

    After the loop the collected hops are reversed to produce a
    device→gateway path dict that is printed as a summary table.

    Pass *device_type* to skip the NetBox platform lookup for the gateway
    (saves one API call when the caller already fetched it for Phase 1).
    """
    # ── Phase A: ARP lookup on the gateway (done exactly once) ───────────────
    if device_type is None:
        device_type = "ios"  # direct SSH — no NetBox platform lookup

    log.info(
        "L2 trace start: target=%s  gateway=%s  device_type=%s",
        target_ip, gateway_ip, device_type,
    )

    try:
        client = _open_device_client(gateway_ip, device_type, creds)
    except GatewayConnectionError as exc:
        print(f"[ERROR] L2 trace — cannot connect to gateway {gateway_ip}: {exc}")
        return None

    mac: Optional[str]          = None
    gw_hostname: str            = gateway_ip
    gw_interface: Optional[str] = None
    dst_routes: List[Dict]      = []

    try:
        try:
            gw_hostname = client._cli_connection.find_prompt().rstrip("#>").strip() or gateway_ip
        except Exception:
            pass

        print(f"[INFO] ARP lookup for {target_ip} on {gw_hostname} ({gateway_ip})...")
        mac = arp_lookup(client, device_type, target_ip)

        gw_interface = get_gateway_interface(client, gateway_ip)
        if gw_interface:
            print(f"[INFO] Gateway IP {gateway_ip} is on interface {gw_interface}")

        print(f"[INFO] Route lookup for destination {dst_ip} on {gw_hostname}...")
        dst_routes = get_route_for_destination(client, dst_ip)
        if dst_routes:
            for r in dst_routes:
                nh    = r.get("next_hop", "?")
                iface = r.get("exit_interface", "")
                print(
                    f"[INFO] Route to {dst_ip}: "
                    f"{r.get('prefix') or dst_ip}  via {nh}"
                    + (f"  [{iface}]" if iface else "")
                )
        else:
            print(f"[WARN] No route found for {dst_ip} on {gw_hostname}")
    finally:
        try:
            client._cli_disconnect()
        except Exception:
            pass

    if not mac:
        print(f"[WARN] No ARP entry for {target_ip} on {gw_hostname}")
        return {
            "src_ip":     target_ip,
            "dst_ip":     dst_ip,
            "gateway_ip": gateway_ip,
            "layer2":     {"stop_reason": "ARP entry not found", "path": [], "mac": None},
            "layer3":     None,
        }

    print(f"[INFO] ARP resolved: {target_ip} -> {mac_to_cisco_fmt(mac)}")
    if source_is_ap:
        print(f"[INFO] Source {target_ip} is an AP — will stop at the access switchport")

    # ── Phase B: hop-by-hop MAC trace ─────────────────────────────────────────
    # path_hops accumulates records in *downstream* order (gateway → device).
    # Each record stores what is needed to later reconstruct the upstream path.
    #
    #   local_interface   – the MAC-table result on this switch (egress toward device)
    #   portchannel_members – physical members of local_interface if it is a Po
    #   remote_port       – CDP "Port ID (outgoing port)" = the port on the *next*
    #                        switch (toward device) that connects back to us.
    #                        This becomes the upstream egress of the *previous* hop.
    #
    path_hops: List[Dict] = []

    current_ip          = gateway_ip
    current_device_type = device_type
    visited: set        = {gateway_ip}

    final_stop_reason: str = f"Max hops ({max_hops}) reached"

    for hop_num in range(1, max_hops + 1):
        try:
            client = _open_device_client(current_ip, current_device_type, creds)
        except GatewayConnectionError as exc:
            final_stop_reason = f"Cannot connect to {current_ip}: {exc}"
            break

        hostname        : str            = current_ip
        mac_entry       : Optional[Dict] = None
        portchannel_mbrs: List[str]      = []
        neighbor_info   : Optional[Dict] = None

        try:
            try:
                hostname = client._cli_connection.find_prompt().rstrip("#>").strip() or current_ip
            except Exception:
                pass

            # Step 1 — MAC table lookup
            print(f"[INFO] MAC table lookup on {hostname} ({current_ip})...")
            mac_entry = mac_table_lookup(client, current_device_type, mac)
            if not mac_entry:
                final_stop_reason = (
                    f"MAC {mac_to_cisco_fmt(mac)} not found in table on {hostname}"
                )
                break

            vlan      = mac_entry["vlan"]
            interface = mac_entry["interface"]
            print(f"[INFO] MAC table: VLAN={vlan}  Interface={interface}")

            # Step 2 — port-channel expansion
            if is_portchannel(interface):
                print(f"[INFO] {interface} is a port-channel — resolving members...")
                portchannel_mbrs = get_portchannel_members(client, current_device_type, interface)
                if portchannel_mbrs:
                    print(f"[INFO] Port-channel members: {', '.join(portchannel_mbrs)}")
                else:
                    print(f"[WARN] No members resolved for {interface}")

            # Step 3 — CDP/LLDP on the resolved physical interface
            check_iface = portchannel_mbrs[0] if portchannel_mbrs else interface
            print(f"[INFO] Checking CDP/LLDP on {check_iface}...")
            neighbor_info = get_neighbor_info(client, current_device_type, check_iface)

        finally:
            try:
                client._cli_disconnect()
            except Exception:
                pass

        # Always record this hop (downstream order) before deciding to stop/continue.
        path_hops.append({
            "hostname":           hostname,
            "switch_ip":          current_ip,
            "vlan":               mac_entry["vlan"],
            "local_interface":    mac_entry["interface"],
            "portchannel_members": portchannel_mbrs,
            # remote_port = CDP "outgoing port" on the next-hop switch (toward device).
            # Left as None when this is a stop hop (endpoint / AP / VMware port).
            "remote_port":        neighbor_info.get("remote_port") if neighbor_info else None,
        })

        # Step 4 — stop-condition evaluation
        should_stop, reason = should_stop_trace(neighbor_info)
        if should_stop:
            final_stop_reason = reason or "Closest switchport found"
            break

        # Neighbor is a network device — resolve its management IP and continue.
        neighbor_ip = resolve_neighbor_ip(neighbor_info)
        if not neighbor_ip:
            final_stop_reason = (
                f"Cannot resolve management IP for "
                f"{neighbor_info.get('neighbor_id', 'unknown')} — stopping"
            )
            # The remote_port is not useful when we cannot reach the neighbor.
            path_hops[-1]["remote_port"] = None
            break

        if neighbor_ip in visited:
            final_stop_reason = f"Loop detected — already visited {neighbor_ip}"
            path_hops[-1]["remote_port"] = None
            break

        # Log this switch as an intermediate hop and advance.
        _log_intermediate_hop(
            hop_num, hostname, current_ip,
            mac_entry["vlan"], mac_entry["interface"],
            portchannel_mbrs, neighbor_info, neighbor_ip,
        )

        visited.add(neighbor_ip)
        current_device_type = "ios"  # direct SSH — no NetBox platform lookup
        current_ip          = neighbor_ip

    # ── Build L2 path dict ────────────────────────────────────────────────────
    layer2_dict: Optional[Dict] = None
    if path_hops:
        layer2_dict = build_path_dict(
            target_ip       = target_ip,
            mac             = mac,
            gateway_ip      = gateway_ip,
            downstream_hops = path_hops,
            gateway_interface = gw_interface,
            dst_route       = dst_routes,
            dst_ip          = dst_ip,
            stop_reason     = final_stop_reason,
        )

    # ── Phase 3: L3 path trace (gateway → destination, all ECMP paths) ────────
    layer3_paths: List[List[Dict]] = []
    if dst_routes:
        layer3_paths = run_l3_path_trace(
            gateway_ip           = gateway_ip,
            gw_hostname          = gw_hostname,
            gw_ingress_interface = gw_interface,
            dst_ip               = dst_ip,
            initial_routes       = dst_routes,
            creds                = creds,
            nb_url               = nb_url,
            nb_token             = nb_token,
            verify_ssl           = verify_ssl,
            max_hops             = max_hops,
        )

    # ── Return combined output dict (caller prints at the end) ────────────────
    return {
        "src_ip":     target_ip,
        "dst_ip":     dst_ip,
        "gateway_ip": gateway_ip,
        "layer2":     layer2_dict,
        "layer3":     layer3_paths or None,
    }


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
    nb.add_argument("--netbox-url",   default=None, help="NetBox base URL (env: NETBOX_URL)")
    nb.add_argument("--netbox-token", default=None, help="NetBox API token (env: NETBOX_TOKEN)")
    nb.add_argument("--no-ssl-verify", action="store_true", help="Disable TLS verification for NetBox")

    dev = p.add_argument_group("Device credentials (ignored when Vault is configured)")
    dev.add_argument("--username", default=None, help="SSH username (env: DEVICE_USER)")
    dev.add_argument("--password", default=None, help="SSH password (env: DEVICE_PASS)")
    dev.add_argument(
        "--secret",
        default=os.environ.get("DEVICE_SECRET", ""),
        help="Enable secret (env: DEVICE_SECRET)",
    )
    dev.add_argument("--timeout", type=int, default=30, help="SSH timeout in seconds (default: 30)")

    if _VAULT_AVAILABLE:
        vault_grp = p.add_argument_group(
            "Vault authentication (optional — overrides --username/--password/--netbox-*)"
        )
        add_vault_parser_args(vault_grp)

    tr = p.add_argument_group("Trace options")
    tr.add_argument("--reverse",  action="store_true", help="Also run reverse trace (dst -> src)")
    tr.add_argument("--ecmp",     action="store_true", help="Trace all ECMP paths in parallel")
    tr.add_argument("--max-hops", type=int, default=30, help="Max hops before stopping (default: 30)")
    tr.add_argument("--out-dir",  default=".",         help="Output directory for JSON/CSV (default: current dir)")
    tr.add_argument("--verbose",  action="store_true", help="Enable DEBUG logging")

    out = p.add_argument_group("Output format")
    out.add_argument(
        "--json",
        nargs="?",
        const="trace_result.json",
        default=None,
        metavar="FILE",
        help=(
            "Write the complete L2+L3 trace as a pretty-printed JSON object to FILE. "
            "When FILE is omitted the output goes to trace_result.json. "
            "All console progress messages are suppressed."
        ),
    )

    return p


# ─────────────────────────────────────────────────────────────────────────────
# JSON flat-path assembly
# ─────────────────────────────────────────────────────────────────────────────


def _flat_l2_hops(layer2: Dict) -> List[Dict]:
    """Convert the L2 upstream path to flat hop dicts (non-gateway entries only)."""
    hops: List[Dict] = []
    for hop in (layer2.get("path") or []):
        if hop.get("is_gateway"):
            continue
        details: Dict = {}
        if hop.get("vlan"):
            try:
                details["vlan"] = int(hop["vlan"])
            except (ValueError, TypeError):
                details["vlan"] = hop["vlan"]
        egress = hop.get("egress_interface")
        if egress:
            details["egress_interface"] = egress
        mbrs = hop.get("ingress_portchannel_members")
        if mbrs:
            details["portchannel_members"] = mbrs
        hops.append({
            "layer":     "L2",
            "device":    hop.get("hostname") or hop.get("switch_ip", "unknown"),
            "interface": hop.get("ingress_interface") or "—",
            "details":   details,
        })
    return hops


def _flat_l3_hops(l3_path: List[Dict]) -> List[Dict]:
    """Convert one L3 path (list of hop dicts) to flat hop dicts.

    The first hop in *l3_path* is always the gateway (it has ``selected_route``).
    Subsequent hops are intermediate L3 devices, ending with the hop that has
    the destination subnet directly connected.  That final hop also carries the
    ``l2_trace`` result which expands into additional L2 entries.
    """
    hops: List[Dict] = []

    for hop in l3_path:
        note     = hop.get("note", "")
        hostname = hop.get("hostname") or hop.get("ip", "unknown")
        ingress  = (hop.get("ingress_interfaces") or [None])[0]

        if note:
            hops.append({
                "layer":     "L3",
                "device":    hostname,
                "interface": ingress or "—",
                "details":   {"note": note},
            })
            continue

        sel = hop.get("selected_route")  # set only on the gateway hop

        if sel:
            # Gateway hop — show which ECMP route this path follows.
            iface   = ingress or "—"
            details = {k: v for k, v in {
                "gateway_ip":   hop.get("ip"),
                "next_hop_ip":  sel.get("next_hop"),
                "egress_iface": sel.get("exit_interface"),
                "prefix":       sel.get("prefix"),
                "route_source": sel.get("route_source"),
                "route_tag":    sel.get("route_tag"),
                "route_age":    sel.get("route_age"),
            }.items() if v is not None}
        else:
            # Intermediate or final L3 hop.
            iface    = ingress or "—"
            egresses = hop.get("egress_routes") or []
            dc       = next(
                (r for r in egresses if r.get("next_hop") == "directly connected"), None
            )
            if dc:
                details = {k: v for k, v in {
                    "prefix":              dc.get("prefix"),
                    "connected_interface": dc.get("exit_interface"),
                    "route_source":        dc.get("route_source"),
                }.items() if v is not None}
            elif egresses:
                r = egresses[0]
                details = {k: v for k, v in {
                    "next_hop_ip":  r.get("next_hop"),
                    "prefix":       r.get("prefix"),
                    "egress_iface": r.get("exit_interface"),
                    "route_source": r.get("route_source"),
                    "route_tag":    r.get("route_tag"),
                }.items() if v is not None}
            else:
                details = {}

        hops.append({
            "layer":     "L3",
            "device":    hostname,
            "interface": iface,
            "details":   details,
        })

        # L2 trace at the final hop (destination subnet is directly connected).
        l2t = hop.get("l2_trace")
        if l2t and not l2t.get("error"):
            vlan_raw = l2t.get("vlan")
            l2_det: Dict = {}
            if l2t.get("mac"):
                l2_det["mac"] = l2t["mac"]
            if vlan_raw is not None:
                try:
                    l2_det["vlan"] = int(vlan_raw)
                except (ValueError, TypeError):
                    l2_det["vlan"] = vlan_raw
            mbrs = l2t.get("portchannel_members")
            if mbrs:
                l2_det["portchannel_members"] = mbrs

            hops.append({
                "layer":     "L2",
                "device":    hostname,
                "interface": l2t.get("port") or "—",
                "details":   l2_det,
            })

            cdp = l2t.get("cdp_neighbor")
            if cdp and cdp.get("hostname"):
                cdp_det = {k: v for k, v in {
                    "protocol": cdp.get("protocol", "CDP"),
                    "ip":       cdp.get("ip"),
                    "platform": cdp.get("platform"),
                }.items() if v is not None}
                hops.append({
                    "layer":     "L2",
                    "device":    cdp["hostname"],
                    "interface": cdp.get("port") or "—",
                    "details":   cdp_det,
                })

    return hops


def build_flat_paths(result: Dict) -> List[Dict]:
    """Transform the combined trace result into a JSON array of flat path objects.

    Each entry in the returned list is ONE complete path from source to destination.
    When multiple ECMP L3 routes exist the L2 segment is duplicated so every
    L3 route appears as an independent, self-contained path object.

    Path structure per object:
      src_ip, dst_ip, gateway_ip, path: [
        {layer: "L2"|"L3", device: str, interface: str, details: {…}}, …
      ]
    """
    src_ip     = result.get("src_ip", "")
    dst_ip     = result.get("dst_ip", "")
    gateway_ip = result.get("gateway_ip", "")
    layer2     = result.get("layer2") or {}
    layer3     = result.get("layer3") or []

    # Shared L2 prefix: switches between the source device and the gateway.
    l2_prefix = _flat_l2_hops(layer2)

    if not layer3:
        # L2-only result or trace that never reached L3 routing.
        return [{
            "src_ip":     src_ip,
            "dst_ip":     dst_ip,
            "gateway_ip": gateway_ip,
            "path":       l2_prefix,
        }]

    # One flat path object per ECMP route.
    paths: List[Dict] = []
    for l3_path in layer3:
        if not l3_path:
            continue
        paths.append({
            "src_ip":     src_ip,
            "dst_ip":     dst_ip,
            "gateway_ip": gateway_ip,
            "path":       l2_prefix + _flat_l3_hops(l3_path),
        })

    return paths or [{
        "src_ip":     src_ip,
        "dst_ip":     dst_ip,
        "gateway_ip": gateway_ip,
        "path":       l2_prefix,
    }]


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────


def main() -> int:
    parser = build_parser()
    args   = parser.parse_args()
    _configure_logging(verbose=args.verbose)

    # args.json is None (flag absent), or a filename string (flag present).
    json_file    = args.json               # e.g. "trace_result.json" or custom name
    json_mode    = json_file is not None
    _orig_stdout = sys.stdout
    _trace_result: Optional[Dict] = None   # set inside try; read by finally

    # In JSON mode redirect stdout so no progress messages appear.
    # The finally block always runs (even after early return 1) and
    # writes the JSON file — or an error object when the trace fails.
    if json_mode:
        sys.stdout = io.StringIO()

    try:
        # ── Credential resolution ─────────────────────────────────────────────
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

        # ── Validate required credentials ─────────────────────────────────────
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

        # ── Phase 1: locate the gateway and verify SSH connectivity ───────────
        print(f"[INFO] Source IP: {src_ip}")

        prefixes = get_prefixes_from_netbox(netbox_url, netbox_token, verify_ssl, contains=src_ip)
        if not prefixes:
            print(f"[ERROR] No matching subnet found for {src_ip} in NetBox")
            log.error("No NetBox prefix contains %s", src_ip)
            return 1

        matched = find_longest_prefix_match(src_ip, prefixes)
        if not matched:
            print(f"[ERROR] No matching subnet found for {src_ip} in NetBox")
            log.error("Longest-prefix match failed for %s among %d candidates", src_ip, len(prefixes))
            return 1

        print(f"[INFO] Matched subnet: {matched}")

        gateway = calculate_first_usable_ip(matched)
        if not gateway:
            print(f"[ERROR] Could not determine gateway for subnet {matched}")
            log.error("calculate_first_usable_ip(%r) returned None", matched)
            return 1

        print(f"[INFO] Gateway IP (first usable): {gateway}")
        print("[INFO] Attempting connection to gateway...")
        try:
            hostname = connect_to_device(gateway, creds)
            print(f"[SUCCESS] Connected to {hostname}")
        except GatewayConnectionError as exc:
            print(f"[ERROR] Failed to connect: {exc}")
            log.error("Gateway connection failed: %s", exc)
            return 1

        # ── Phase 2: L2 + L3 trace → collect all data, print once at the end ─
        result = run_l2_trace(
            target_ip    = src_ip,
            dst_ip       = args.dst_ip,
            gateway_ip   = gateway,
            creds        = creds,
            source_is_ap = False,
            max_hops     = args.max_hops,
            nb_url       = netbox_url,
            nb_token     = netbox_token,
            verify_ssl   = verify_ssl,
        )

        _trace_result = result

        if result and not json_mode:
            print_trace_summary(result)

        return 0

    finally:
        if json_mode:
            sys.stdout = _orig_stdout

            if _trace_result is not None:
                flat   = build_flat_paths(_trace_result)
                output = json.dumps(flat, indent=2, default=str)
            else:
                output = json.dumps([{
                    "error":   "Trace did not complete — see log file for details",
                    "src_ip":  getattr(args, "src_ip",  ""),
                    "dst_ip":  getattr(args, "dst_ip",  ""),
                }], indent=2)

            try:
                with open(json_file, "w", encoding="utf-8") as fh:
                    fh.write(output)
                    fh.write("\n")
                print(f"[JSON] Trace written to {json_file}", file=sys.stderr)
            except OSError as exc:
                print(
                    f"[ERROR] Cannot write JSON to {json_file!r}: {exc}",
                    file=sys.stderr,
                )


if __name__ == "__main__":
    sys.exit(main())
