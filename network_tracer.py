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
import ipaddress
import logging
import os
import re
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
# Constants
# ─────────────────────────────────────────────────────────────────────────────

# NetBox platform slug → netmiko device_type.
_PLATFORM_MAP: Dict[str, str] = {
    "ios":      "cisco_ios",
    "ios-xe":   "cisco_xe",
    "ios_xe":   "cisco_xe",
    "iosxe":    "cisco_xe",
    "nxos":     "cisco_nxos",
    "nx-os":    "cisco_nxos",
    "nx_os":    "cisco_nxos",
    "cisco_nx": "cisco_nxos",
}

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


def _get_nb_api(nb_url: str, nb_token: str, verify_ssl: bool = True):
    """Return a configured pynetbox API instance."""
    nb = pynetbox.api(nb_url.rstrip("/"), token=nb_token)
    if not verify_ssl:
        import urllib3  # noqa: PLC0415
        urllib3.disable_warnings()
        nb.http_session.verify = False
    return nb


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
        nb = _get_nb_api(nb_url, nb_token, verify_ssl)
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


def get_platform_from_netbox(
    nb_url: str,
    nb_token: str,
    device_ip: str,
    verify_ssl: bool = True,
) -> Optional[str]:
    """Return the NetBox platform slug for the device whose primary IP is *device_ip*."""
    try:
        nb = _get_nb_api(nb_url, nb_token, verify_ssl)
        candidates = list(nb.dcim.devices.filter(primary_ip4=device_ip))
        if not candidates:
            candidates = list(nb.dcim.devices.filter(primary_ip4=f"{device_ip}/32"))
        if not candidates:
            log.debug("No NetBox device found for IP %s", device_ip)
            return None
        device = candidates[0]
        if device.platform:
            slug = device.platform.slug
            log.debug("NetBox platform for %s: %s", device_ip, slug)
            return slug
        return None
    except Exception as exc:
        log.error("NetBox platform lookup failed for %s: %s", device_ip, exc)
        return None


def is_ap_in_netbox(
    nb_url: str,
    nb_token: str,
    ip: str,
    verify_ssl: bool = True,
) -> bool:
    """Return True if the NetBox device with *ip* as its primary IP is an AP."""
    try:
        nb = _get_nb_api(nb_url, nb_token, verify_ssl)
        candidates = list(nb.dcim.devices.filter(primary_ip4=ip))
        if not candidates:
            candidates = list(nb.dcim.devices.filter(primary_ip4=f"{ip}/32"))
        for dev in candidates:
            role_slug  = (dev.device_role.slug  if dev.device_role  else "").lower()
            type_model = (dev.device_type.model if dev.device_type  else "").lower()
            if any(kw in role_slug or kw in type_model for kw in _AP_ROLE_KEYWORDS):
                log.debug("Device %s (%s) identified as AP via NetBox", ip, dev.name)
                return True
        return False
    except Exception as exc:
        log.debug("NetBox AP check failed for %s: %s", ip, exc)
        return False


def _get_device_primary_ip_from_netbox(
    nb_url: str,
    nb_token: str,
    device_name: str,
    verify_ssl: bool = True,
) -> Optional[str]:
    """Return the primary IPv4 address (no prefix-length) for *device_name* in NetBox.

    Falls back to a short-hostname match when CDP reports an FQDN.
    """
    try:
        nb = _get_nb_api(nb_url, nb_token, verify_ssl)
        candidates = list(nb.dcim.devices.filter(name=device_name))
        if not candidates:
            short = device_name.split(".")[0]
            candidates = list(nb.dcim.devices.filter(name=short))
        if not candidates:
            log.debug("No NetBox device found for name %r", device_name)
            return None
        dev = candidates[0]
        if dev.primary_ip4:
            return str(dev.primary_ip4).split("/")[0]
        return None
    except Exception as exc:
        log.debug("NetBox device IP lookup failed for %r: %s", device_name, exc)
        return None


def resolve_neighbor_ip(
    neighbor_info: Dict[str, str],
    nb_url: str,
    nb_token: str,
    verify_ssl: bool = True,
) -> Optional[str]:
    """Resolve the management IP for a CDP/LLDP neighbor.

    Preference order:
      1. NetBox primary IP for the device named in ``neighbor_id``
         (authoritative management address, avoids transit/interface IPs).
      2. IP address reported directly by CDP/LLDP as a fallback.
    """
    neighbor_id = neighbor_info.get("neighbor_id", "")
    if neighbor_id:
        nb_ip = _get_device_primary_ip_from_netbox(nb_url, nb_token, neighbor_id, verify_ssl)
        if nb_ip:
            log.debug("Resolved neighbor %s -> %s (via NetBox)", neighbor_id, nb_ip)
            return nb_ip

    cdp_ip = neighbor_info.get("neighbor_ip")
    if cdp_ip:
        log.debug("Resolved neighbor %s -> %s (via CDP/LLDP)", neighbor_id, cdp_ip)
        return cdp_ip

    log.debug("Cannot resolve management IP for neighbor %r", neighbor_id)
    return None


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


def platform_to_device_type(platform_slug: Optional[str]) -> str:
    """Map a NetBox platform slug to a netmiko device_type. Defaults to cisco_ios."""
    if not platform_slug:
        return "cisco_ios"
    return _PLATFORM_MAP.get(platform_slug.lower(), "cisco_ios")


def open_connection(
    ip: str,
    device_type: str,
    credentials: Dict[str, str],
) -> ConnectHandler:
    """Open and return a live SSH session. Caller must call disconnect()."""
    params: Dict = {
        "device_type":  device_type,
        "host":         ip,
        "username":     credentials.get("username", ""),
        "password":     credentials.get("password", ""),
        "secret":       credentials.get("secret", ""),
        "timeout":      int(credentials.get("timeout", 30)),
        "conn_timeout": int(credentials.get("timeout", 30)),
        "fast_cli":     False,
    }
    try:
        return ConnectHandler(**params)
    except NetmikoAuthenticationException as exc:
        raise GatewayConnectionError(f"authentication failed for {ip}: {exc}") from exc
    except NetmikoTimeoutException as exc:
        raise GatewayConnectionError(f"connection timed out for {ip}") from exc
    except Exception as exc:
        raise GatewayConnectionError(f"SSH error for {ip}: {exc}") from exc


def connect_to_device(
    ip: str,
    credentials: Dict[str, str],
    device_type: str = "cisco_ios",
) -> str:
    """Open an SSH session to *ip*, retrieve the hostname prompt, then disconnect.

    Returns the hostname string (falls back to *ip*).
    Raises :exc:`GatewayConnectionError` on any failure.
    """
    conn = open_connection(ip, device_type, credentials)
    try:
        prompt   = conn.find_prompt()
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
    conn: ConnectHandler,
    device_type: str,  # noqa: ARG001 — reserved for future platform-specific ARP variants
    target_ip: str,
) -> Optional[str]:
    """Run ``show ip arp <target_ip>`` and return the normalized MAC, or None."""
    cmd = f"show ip arp {target_ip}"
    try:
        output = conn.send_command(cmd)
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
    conn: ConnectHandler,
    device_type: str,  # noqa: ARG001 — reserved for future platform-specific MAC table commands
    mac: str,
) -> Optional[Dict[str, str]]:
    """Look up *mac* in the forwarding table and return {vlan, interface, mac}."""
    cisco_mac = mac_to_cisco_fmt(mac)
    cmd = f"show mac address-table address {cisco_mac}"
    try:
        output = conn.send_command(cmd)
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
    conn: ConnectHandler,
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
            output  = conn.send_command("show port-channel summary")
            members = _parse_nxos_portchannel_members(output, po_num)
        else:
            output  = conn.send_command("show etherchannel summary")
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
    conn: ConnectHandler,
    device_type: str,
    interface: str,
) -> Optional[Dict[str, str]]:
    """Return a CDP neighbor detail dict for *interface*, or None."""
    if "nxos" in device_type:
        cmd = f"show cdp neighbors interface {interface} detail"
    else:
        cmd = f"show cdp neighbors {interface} detail"

    try:
        output = conn.send_command(cmd)
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
    conn: ConnectHandler,
    device_type: str,
    interface: str,
) -> Optional[Dict[str, str]]:
    """Return an LLDP neighbor detail dict for *interface*, or None."""
    if "nxos" in device_type:
        cmd = f"show lldp neighbors interface {interface} detail"
    else:
        cmd = f"show lldp neighbors {interface} detail"

    try:
        output = conn.send_command(cmd)
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
    conn: ConnectHandler,
    device_type: str,
    interface: str,
) -> Optional[Dict[str, str]]:
    """Return CDP or LLDP neighbor info for *interface*, preferring CDP. Returns None if none found."""
    cdp = _get_cdp_neighbor(conn, device_type, interface)
    if cdp:
        return cdp
    return _get_lldp_neighbor(conn, device_type, interface)


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


def log_trace_result(
    target_ip: str,
    mac: Optional[str],
    hostname: Optional[str],
    switch_ip: str,
    vlan: Optional[str],
    interface: Optional[str],
    portchannel_members: Optional[List[str]],
    stop_reason: str,
) -> None:
    """Print a structured [TRACE] result block to the console."""
    print()
    print(f"[TRACE] Target IP:    {target_ip}")
    if mac:
        print(f"[TRACE] ARP MAC:      {mac_to_cisco_fmt(mac)}")
    if hostname:
        print(f"[TRACE] Switch:       {hostname}")
    print(f"[TRACE] Switch IP:    {switch_ip}")
    if vlan:
        print(f"[TRACE] VLAN:         {vlan}")
    if interface:
        print(f"[TRACE] Interface:    {interface}")
    if portchannel_members:
        print(f"[TRACE] Po members:   {', '.join(portchannel_members)}")
    print(f"[TRACE] Stop reason:  {stop_reason}")
    print()


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
    """
    n = len(downstream_hops)
    upstream_path: List[Dict] = []

    for j in range(n):
        d_idx = n - 1 - j
        d_hop = downstream_hops[d_idx]

        ingress         = d_hop.get("local_interface")
        ingress_members = d_hop.get("portchannel_members", [])
        egress          = downstream_hops[d_idx - 1].get("remote_port") if d_idx > 0 else None

        upstream_path.append({
            "hop":                     j + 1,
            "hostname":                d_hop.get("hostname"),
            "switch_ip":               d_hop.get("switch_ip"),
            "vlan":                    d_hop.get("vlan"),
            "ingress_interface":       ingress,
            "ingress_portchannel_members": ingress_members,
            "egress_interface":        egress,
        })

    return {
        "target_ip":  target_ip,
        "mac":        mac_to_cisco_fmt(mac) if mac else None,
        "gateway_ip": gateway_ip,
        "total_hops": n,
        "path":       upstream_path,
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
        hostname = hop["hostname"] or hop["switch_ip"]
        sw_ip    = hop["switch_ip"]
        vlan     = hop["vlan"] or "—"
        ingress  = hop["ingress_interface"] or "—"
        i_mbrs   = hop.get("ingress_portchannel_members", [])
        egress   = hop["egress_interface"] or "(gateway — end of trace)"

        print(f"\n  Hop {hop['hop']}: {hostname}  ({sw_ip})")
        print(f"    VLAN    : {vlan}")
        print(f"    Ingress : {ingress}", end="")
        if i_mbrs:
            print(f"  [members: {', '.join(i_mbrs)}]", end="")
        print()
        print(f"    Egress  : {egress}")

    print()
    print(SEP)
    print()


# ─────────────────────────────────────────────────────────────────────────────
# Phase 2 — L2 trace orchestration
# ─────────────────────────────────────────────────────────────────────────────


def run_l2_trace(
    target_ip: str,
    gateway_ip: str,
    nb_url: str,
    nb_token: str,
    creds: Dict[str, str],
    verify_ssl: bool,
    source_is_ap: bool,
    device_type: Optional[str] = None,
    max_hops: int = 30,
) -> None:
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
        platform_slug = get_platform_from_netbox(nb_url, nb_token, gateway_ip, verify_ssl)
        device_type   = platform_to_device_type(platform_slug)

    log.info(
        "L2 trace start: target=%s  gateway=%s  device_type=%s",
        target_ip, gateway_ip, device_type,
    )

    try:
        conn = open_connection(gateway_ip, device_type, creds)
    except GatewayConnectionError as exc:
        print(f"[ERROR] L2 trace — cannot connect to gateway {gateway_ip}: {exc}")
        return

    mac: Optional[str] = None
    gw_hostname: str   = gateway_ip

    try:
        try:
            gw_hostname = conn.find_prompt().rstrip("#>").strip() or gateway_ip
        except Exception:
            pass
        print(f"[INFO] ARP lookup for {target_ip} on {gw_hostname} ({gateway_ip})...")
        mac = arp_lookup(conn, device_type, target_ip)
    finally:
        try:
            conn.disconnect()
        except Exception:
            pass

    if not mac:
        print(f"[WARN] No ARP entry for {target_ip} on {gw_hostname}")
        log_trace_result(
            target_ip, None, gw_hostname, gateway_ip,
            None, None, None, "ARP entry not found",
        )
        return

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

    final_hostname        : str           = gw_hostname
    final_vlan            : Optional[str] = None
    final_interface       : Optional[str] = None
    final_portchannel_mbrs: List[str]     = []
    final_stop_reason     : str           = f"Max hops ({max_hops}) reached"

    for hop_num in range(1, max_hops + 1):
        try:
            conn = open_connection(current_ip, current_device_type, creds)
        except GatewayConnectionError as exc:
            final_stop_reason = f"Cannot connect to {current_ip}: {exc}"
            break

        hostname        : str            = current_ip
        mac_entry       : Optional[Dict] = None
        portchannel_mbrs: List[str]      = []
        neighbor_info   : Optional[Dict] = None

        try:
            try:
                hostname = conn.find_prompt().rstrip("#>").strip() or current_ip
            except Exception:
                pass

            # Step 1 — MAC table lookup
            print(f"[INFO] MAC table lookup on {hostname} ({current_ip})...")
            mac_entry = mac_table_lookup(conn, current_device_type, mac)
            if not mac_entry:
                final_hostname    = hostname
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
                portchannel_mbrs = get_portchannel_members(conn, current_device_type, interface)
                if portchannel_mbrs:
                    print(f"[INFO] Port-channel members: {', '.join(portchannel_mbrs)}")
                else:
                    print(f"[WARN] No members resolved for {interface}")

            # Step 3 — CDP/LLDP on the resolved physical interface
            check_iface = portchannel_mbrs[0] if portchannel_mbrs else interface
            print(f"[INFO] Checking CDP/LLDP on {check_iface}...")
            neighbor_info = get_neighbor_info(conn, current_device_type, check_iface)

        finally:
            try:
                conn.disconnect()
            except Exception:
                pass

        # Snapshot final-hop state in case this is the last iteration.
        final_hostname         = hostname
        final_vlan             = mac_entry["vlan"]
        final_interface        = mac_entry["interface"]
        final_portchannel_mbrs = portchannel_mbrs

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
        neighbor_ip = resolve_neighbor_ip(neighbor_info, nb_url, nb_token, verify_ssl)
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
        next_platform       = get_platform_from_netbox(nb_url, nb_token, neighbor_ip, verify_ssl)
        current_device_type = platform_to_device_type(next_platform)
        current_ip          = neighbor_ip

    # ── Inline stop detail ────────────────────────────────────────────────────
    log_trace_result(
        target_ip           = target_ip,
        mac                 = mac,
        hostname            = final_hostname,
        switch_ip           = current_ip,
        vlan                = final_vlan,
        interface           = final_interface,
        portchannel_members = final_portchannel_mbrs or None,
        stop_reason         = final_stop_reason,
    )

    # ── Full path summary (device → gateway) ─────────────────────────────────
    if path_hops:
        path_dict = build_path_dict(target_ip, mac, gateway_ip, path_hops)
        print_path_summary(path_dict)


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
    print("[INFO] Fetching gateway platform from NetBox...")

    gw_platform    = get_platform_from_netbox(netbox_url, netbox_token, gateway, verify_ssl)
    gw_device_type = platform_to_device_type(gw_platform)
    log.info("Gateway platform: %s -> device_type: %s", gw_platform or "unknown", gw_device_type)

    print("[INFO] Attempting connection to gateway...")
    try:
        hostname = connect_to_device(gateway, creds, device_type=gw_device_type)
        print(f"[SUCCESS] Connected to {hostname}")
    except GatewayConnectionError as exc:
        print(f"[ERROR] Failed to connect: {exc}")
        log.error("Gateway connection failed: %s", exc)
        return 1

    # ── Phase 2: L2 trace (ARP -> MAC table -> port-channel -> CDP/LLDP) ─────

    source_is_ap = is_ap_in_netbox(netbox_url, netbox_token, src_ip, verify_ssl)
    if source_is_ap:
        print(f"[INFO] Source {src_ip} is an AP in NetBox — will stop at first switchport")

    run_l2_trace(
        target_ip    = src_ip,
        gateway_ip   = gateway,
        nb_url       = netbox_url,
        nb_token     = netbox_token,
        creds        = creds,
        verify_ssl   = verify_ssl,
        source_is_ap = source_is_ap,
        device_type  = gw_device_type,  # reuse — avoids a second NetBox platform call
        max_hops     = args.max_hops,
    )

    return 0


if __name__ == "__main__":
    sys.exit(main())
