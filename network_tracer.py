#!/usr/bin/env python3
"""
network_tracer.py — Reconstruct the network path between two IPs using
NetBox, ARP/NDP, MAC tables, port-channel data, CDP, LLDP, VRFs, FHRP,
and routing tables.  Supports Cisco IOS, IOS-XE, and NX-OS.
Supports IPv4 and IPv6, HashiCorp Vault credentials, and parallel ECMP tracing.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import csv
import ipaddress
import json
import logging
import os
import re
import sys
import threading
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
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
# Data classes
# ─────────────────────────────────────────────────────────────────────────────


@dataclass
class ArpEntry:
    ip: str
    mac: str
    interface: str
    vrf: str = "global"
    age_minutes: Optional[float] = None


@dataclass
class MacEntry:
    mac: str
    vlan: int
    interface: str
    entry_type: str = "dynamic"


@dataclass
class RouteResult:
    prefix: str
    protocol: str
    next_hop: str
    egress_iface: str
    vrf: str = "global"
    admin_distance: int = 0
    metric: int = 0


@dataclass
class CdpNeighbor:
    local_interface: str
    neighbor_device: str
    neighbor_interface: str
    neighbor_ip: str = ""
    platform: str = ""
    capabilities: str = ""
    protocol: str = "CDP"   # CDP or LLDP


@dataclass
class FhrpInfo:
    protocol: str
    interface: str
    group: int
    virtual_ip: str
    state: str
    priority: int = 100


@dataclass
class HopResult:
    hop_number: int
    device_name: str
    device_ip: str
    ingress_interface: str
    egress_interface: str
    vrf: str
    next_hop_ip: str
    next_device_name: str
    method: str
    arp_entry: Optional[ArpEntry] = None
    mac_entry: Optional[MacEntry] = None
    cdp_neighbor: Optional[CdpNeighbor] = None
    route: Optional[RouteResult] = None
    fhrp: Optional[FhrpInfo] = None
    branch: int = 0         # 0 = single-path; 1..N = ECMP branch number
    ecmp_total: int = 1     # total ECMP branches at this level
    notes: List[str] = field(default_factory=list)


# ─────────────────────────────────────────────────────────────────────────────
# Utility helpers
# ─────────────────────────────────────────────────────────────────────────────

_IFACE_EXPANSIONS: List[Tuple[str, str]] = sorted([
    ("appgigabitethernet", "AppGigabitEthernet"),
    ("tengigabitethernet", "TenGigabitEthernet"),
    ("twentyfivegige",     "TwentyFiveGigE"),
    ("gigabitethernet",    "GigabitEthernet"),
    ("fastethernet",       "FastEthernet"),
    ("hundredgige",        "HundredGigE"),
    ("fortygige",          "FortyGigE"),
    ("tengige",            "TenGigE"),
    ("port-channel",       "Port-channel"),
    ("portchannel",        "Port-channel"),
    ("ethernet",           "Ethernet"),
    ("loopback",           "Loopback"),
    ("management",         "Management"),
    ("vlan",               "Vlan"),
], key=lambda t: len(t[0]), reverse=True)

_IFACE_ABBREVS: Dict[str, str] = {
    "te": "TenGigabitEthernet",
    "gi": "GigabitEthernet",
    "fa": "FastEthernet",
    "ap": "AppGigabitEthernet",
    "po": "Port-channel",
    "vl": "Vlan",
    "lo": "Loopback",
    "mg": "Management",
    "hu": "HundredGigE",
    "fo": "FortyGigE",
    "tw": "TwentyFiveGigE",
    "et": "Ethernet",
}


def normalize_iface(name: str) -> str:
    s = name.strip()
    low = s.lower()
    for full_lower, canonical in _IFACE_EXPANSIONS:
        if low.startswith(full_lower):
            return canonical + s[len(full_lower):]
    for abbr, canonical in _IFACE_ABBREVS.items():
        if low.startswith(abbr) and len(s) > len(abbr) and s[len(abbr)].isdigit():
            return canonical + s[len(abbr):]
    return s


def normalize_mac(mac: str) -> str:
    digits = re.sub(r"[^0-9a-fA-F]", "", mac)
    if len(digits) != 12:
        return mac.lower()
    return ":".join(digits[i : i + 2] for i in range(0, 12, 2)).lower()


def is_valid_ip(addr: str) -> bool:
    try:
        ipaddress.ip_address(addr)
        return True
    except ValueError:
        return False


def is_ipv6_addr(addr: str) -> bool:
    try:
        return isinstance(ipaddress.ip_address(addr), ipaddress.IPv6Address)
    except ValueError:
        return False


def ip_in_prefix(ip: str, prefix: str) -> bool:
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(prefix, strict=False)
    except ValueError:
        return False


def _prefix_len(r: RouteResult) -> int:
    try:
        return int(r.prefix.split("/")[1])
    except (IndexError, ValueError):
        return 0


# ─────────────────────────────────────────────────────────────────────────────
# Parser functions
# ─────────────────────────────────────────────────────────────────────────────

# ── IPv4 ARP ──────────────────────────────────────────────────────────────────

_ARP_IOS_RE = re.compile(
    r"Internet\s+([\d.]+)\s+(\S+)\s+"
    r"([0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}|\S{11,17})\s+(\S+)"
)
_ARP_NXOS_RE = re.compile(
    r"^([\d.]+)\s+(\S+)\s+([0-9a-fA-F:.]{11,17})\s+(\S+)",
    re.MULTILINE,
)


def parse_arp_ios(text: str, vrf: str = "global") -> List[ArpEntry]:
    entries: List[ArpEntry] = []
    for m in _ARP_IOS_RE.finditer(text):
        ip_addr, age_raw, mac_raw, iface = m.groups()
        if not is_valid_ip(ip_addr):
            continue
        age: Optional[float] = None
        if age_raw not in ("-", ""):
            try:
                age = float(age_raw)
            except ValueError:
                pass
        entries.append(ArpEntry(ip=ip_addr, mac=normalize_mac(mac_raw),
                                interface=normalize_iface(iface), vrf=vrf, age_minutes=age))
    return entries


def parse_arp_nxos(text: str, vrf: str = "global") -> List[ArpEntry]:
    entries: List[ArpEntry] = []
    for m in _ARP_NXOS_RE.finditer(text):
        ip_addr, age_raw, mac_raw, iface = m.groups()
        if not is_valid_ip(ip_addr):
            continue
        age: Optional[float] = None
        try:
            age = float(age_raw)
        except ValueError:
            pass
        entries.append(ArpEntry(ip=ip_addr, mac=normalize_mac(mac_raw),
                                interface=normalize_iface(iface), vrf=vrf, age_minutes=age))
    return entries


# ── IPv6 NDP (Neighbor Discovery) ─────────────────────────────────────────────

# IOS:  2001:DB8::1   0  0050.7966.6800  REACH  GigabitEthernet0/0
_NDP_IOS_RE = re.compile(
    r"^([0-9a-fA-F:]+)\s+(\S+)\s+"
    r"([0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4})\s+\S+\s+(\S+)",
    re.MULTILINE,
)
# NX-OS: 2001:db8::1   00:05:20  1234.5678.9abc  50  icmpv6  Eth1/1
_NDP_NXOS_RE = re.compile(
    r"^([0-9a-fA-F:]+)\s+\S+\s+"
    r"([0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4})\s+\d+\s+\S+\s+(\S+)",
    re.MULTILINE,
)


def parse_ndp_ios(text: str, vrf: str = "global") -> List[ArpEntry]:
    entries: List[ArpEntry] = []
    for m in _NDP_IOS_RE.finditer(text):
        ip_addr, age_raw, mac_raw, iface = m.groups()
        if not is_valid_ip(ip_addr):
            continue
        age: Optional[float] = None
        try:
            age = float(age_raw)
        except ValueError:
            pass
        entries.append(ArpEntry(ip=ip_addr.lower(), mac=normalize_mac(mac_raw),
                                interface=normalize_iface(iface), vrf=vrf, age_minutes=age))
    return entries


def parse_ndp_nxos(text: str, vrf: str = "global") -> List[ArpEntry]:
    entries: List[ArpEntry] = []
    for m in _NDP_NXOS_RE.finditer(text):
        ip_addr, mac_raw, iface = m.groups()
        if not is_valid_ip(ip_addr):
            continue
        entries.append(ArpEntry(ip=ip_addr.lower(), mac=normalize_mac(mac_raw),
                                interface=normalize_iface(iface), vrf=vrf))
    return entries


# ── MAC table ─────────────────────────────────────────────────────────────────

_MAC_IOS_RE = re.compile(
    r"^\s*(\d+)\s+([0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4})\s+"
    r"(DYNAMIC|STATIC|dynamic|static|self)\s+(\S+)",
    re.MULTILINE,
)
_MAC_NXOS_RE = re.compile(
    r"^\*?\s*(\d+)\s+([0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4})\s+"
    r"(dynamic|static|secure|self)\s+\S+\s+\S+\s+(\S+)",
    re.IGNORECASE | re.MULTILINE,
)


def parse_mac_table_ios(text: str) -> List[MacEntry]:
    entries: List[MacEntry] = []
    for m in _MAC_IOS_RE.finditer(text):
        vlan_s, mac_raw, etype, iface = m.groups()
        try:
            vlan = int(vlan_s)
        except ValueError:
            continue
        entries.append(MacEntry(mac=normalize_mac(mac_raw), vlan=vlan,
                                interface=normalize_iface(iface), entry_type=etype.lower()))
    return entries


def parse_mac_table_nxos(text: str) -> List[MacEntry]:
    entries: List[MacEntry] = []
    for m in _MAC_NXOS_RE.finditer(text):
        vlan_s, mac_raw, etype, iface = m.groups()
        try:
            vlan = int(vlan_s)
        except ValueError:
            continue
        entries.append(MacEntry(mac=normalize_mac(mac_raw), vlan=vlan,
                                interface=normalize_iface(iface), entry_type=etype.lower()))
    return entries


# ── EtherChannel / Port-Channel ───────────────────────────────────────────────

_PC_IOS_HDR_RE   = re.compile(r"(Port-channel\d+)\s+\(", re.IGNORECASE)
_PC_IOS_MEMB_RE  = re.compile(r"((?:Gi|Fa|Te|Hu|Fo|Tw|Et)\S+)\(")
_PC_NXOS_HDR_RE  = re.compile(r"^(port-channel\d+)\s+", re.IGNORECASE | re.MULTILINE)
_PC_NXOS_MEMB_RE = re.compile(r"Eth\d+/\d+(?:/\d+)?", re.IGNORECASE)


def parse_etherchannel_ios(text: str) -> Dict[str, List[str]]:
    result: Dict[str, List[str]] = {}
    current: Optional[str] = None
    for line in text.splitlines():
        hm = _PC_IOS_HDR_RE.search(line)
        if hm:
            current = normalize_iface(hm.group(1))
            result.setdefault(current, [])
        if current:
            for mm in _PC_IOS_MEMB_RE.finditer(line):
                m_iface = normalize_iface(mm.group(1))
                if m_iface not in result[current]:
                    result[current].append(m_iface)
    return result


def parse_etherchannel_nxos(text: str) -> Dict[str, List[str]]:
    result: Dict[str, List[str]] = {}
    current: Optional[str] = None
    for line in text.splitlines():
        hm = _PC_NXOS_HDR_RE.match(line.strip())
        if hm:
            current = normalize_iface(hm.group(1))
            result.setdefault(current, [])
            continue
        if current:
            for mm in _PC_NXOS_MEMB_RE.finditer(line):
                m_iface = normalize_iface(mm.group(0))
                if m_iface not in result[current]:
                    result[current].append(m_iface)
    return result


# ── IPv4 Routes ───────────────────────────────────────────────────────────────

_RT_IOS_RE = re.compile(
    r"^\s*([A-Z][A-Z* ]{0,5})\s+([\d.]+(?:/\d+)?)\s+"
    r"(?:\[(\d+)/(\d+)\]\s+via\s+([\d.]+)(?:[^,\n]*,\s+(\S+))?|is directly connected,\s+(\S+))",
    re.MULTILINE,
)
_RT_IOS_CONT_RE = re.compile(
    r"^\s+\[(\d+)/(\d+)\]\s+via\s+([\d.]+)(?:[^,\n]*,\s+(\S+))?",
    re.MULTILINE,
)
_RT_NXOS_PFX_RE = re.compile(r"^([\d.]+/\d+),\s+\d+\s+ubest", re.MULTILINE)
_RT_NXOS_NH_RE  = re.compile(
    r"^\s+\*?via\s+([\d.]+)(?:,\s+(\S+))?,\s+\[(\d+)/(\d+)\]",
    re.MULTILINE,
)


def parse_routes_ios(text: str, target_ip: str = "", vrf: str = "global") -> List[RouteResult]:
    results: List[RouteResult] = []
    last_prefix = ""
    for line in text.splitlines():
        m = _RT_IOS_RE.match(line)
        if m:
            proto, prefix, ad, metric, nh, iface_nh, iface_dc = m.groups()
            proto = proto.strip()
            last_prefix = prefix
            if "/" not in prefix:
                prefix = prefix + "/32"
            if target_ip and not ip_in_prefix(target_ip, prefix):
                continue
            if iface_dc:
                results.append(RouteResult(prefix=prefix, protocol=proto, next_hop="",
                                           egress_iface=normalize_iface(iface_dc), vrf=vrf))
            elif nh:
                results.append(RouteResult(prefix=prefix, protocol=proto, next_hop=nh,
                                           egress_iface=normalize_iface(iface_nh) if iface_nh else "",
                                           vrf=vrf,
                                           admin_distance=int(ad) if ad else 0,
                                           metric=int(metric) if metric else 0))
        else:
            mc = _RT_IOS_CONT_RE.match(line)
            if mc and last_prefix:
                ad_c, metric_c, nh_c, iface_c = mc.groups()
                pfx = last_prefix if "/" in last_prefix else last_prefix + "/32"
                if target_ip and not ip_in_prefix(target_ip, pfx):
                    continue
                results.append(RouteResult(prefix=pfx, protocol="", next_hop=nh_c,
                                           egress_iface=normalize_iface(iface_c) if iface_c else "",
                                           vrf=vrf,
                                           admin_distance=int(ad_c), metric=int(metric_c)))
    return results


def parse_routes_nxos(text: str, target_ip: str = "", vrf: str = "global") -> List[RouteResult]:
    results: List[RouteResult] = []
    pfx_matches = list(_RT_NXOS_PFX_RE.finditer(text))
    for i, pm in enumerate(pfx_matches):
        prefix = pm.group(1)
        if target_ip and not ip_in_prefix(target_ip, prefix):
            continue
        start = pm.end()
        end   = pfx_matches[i + 1].start() if i + 1 < len(pfx_matches) else len(text)
        for nm in _RT_NXOS_NH_RE.finditer(text[start:end]):
            nh, iface, ad, metric = nm.groups()
            results.append(RouteResult(prefix=prefix, protocol="", next_hop=nh,
                                       egress_iface=normalize_iface(iface) if iface else "",
                                       vrf=vrf, admin_distance=int(ad), metric=int(metric)))
    return results


# ── IPv6 Routes ───────────────────────────────────────────────────────────────

# IOS:
#   O   2001:DB8::/48 [110/1]
#        via FE80::1, GigabitEthernet0/0
#   C   2001:DB8:1::/64 [0/0]
#        via GigabitEthernet0/0, directly connected

_RT6_IOS_HDR_RE  = re.compile(
    r"^\s*([A-Z][A-Z0-9 ]{0,8})\s+([0-9a-fA-F:]+/\d+)\s+\[(\d+)/(\d+)\]",
    re.MULTILINE,
)
_RT6_IOS_VIA_RE  = re.compile(
    r"^\s+via\s+([0-9a-fA-F:]+)(?:,\s+(\S+))?",
    re.MULTILINE,
)
_RT6_IOS_CONN_RE = re.compile(
    r"^\s+via\s+(\S+),\s+directly connected",
    re.MULTILINE,
)

_RT6_NXOS_PFX_RE = re.compile(r"^([0-9a-fA-F:]+/\d+),\s+\d+\s+ubest", re.MULTILINE)
_RT6_NXOS_NH_RE  = re.compile(
    r"^\s+\*?via\s+([0-9a-fA-F:]+)(?:,\s+(\S+))?,\s+\[(\d+)/(\d+)\]",
    re.MULTILINE,
)


def parse_routes_ipv6_ios(text: str, target_ip: str = "", vrf: str = "global") -> List[RouteResult]:
    results: List[RouteResult] = []
    hdrs = list(_RT6_IOS_HDR_RE.finditer(text))
    for i, hm in enumerate(hdrs):
        proto, prefix, ad, metric = hm.groups()
        proto = proto.strip()
        if target_ip and not ip_in_prefix(target_ip, prefix):
            continue
        blk_start = hm.end()
        blk_end   = hdrs[i + 1].start() if i + 1 < len(hdrs) else len(text)
        block     = text[blk_start:blk_end]
        conn_m = _RT6_IOS_CONN_RE.search(block)
        if conn_m:
            results.append(RouteResult(prefix=prefix, protocol=proto, next_hop="",
                                       egress_iface=normalize_iface(conn_m.group(1)),
                                       vrf=vrf))
            continue
        for vm in _RT6_IOS_VIA_RE.finditer(block):
            nh, iface = vm.groups()
            results.append(RouteResult(prefix=prefix, protocol=proto, next_hop=nh,
                                       egress_iface=normalize_iface(iface) if iface else "",
                                       vrf=vrf,
                                       admin_distance=int(ad), metric=int(metric)))
    return results


def parse_routes_ipv6_nxos(text: str, target_ip: str = "", vrf: str = "global") -> List[RouteResult]:
    results: List[RouteResult] = []
    pfx_matches = list(_RT6_NXOS_PFX_RE.finditer(text))
    for i, pm in enumerate(pfx_matches):
        prefix = pm.group(1)
        if target_ip and not ip_in_prefix(target_ip, prefix):
            continue
        start = pm.end()
        end   = pfx_matches[i + 1].start() if i + 1 < len(pfx_matches) else len(text)
        for nm in _RT6_NXOS_NH_RE.finditer(text[start:end]):
            nh, iface, ad, metric = nm.groups()
            results.append(RouteResult(prefix=prefix, protocol="", next_hop=nh,
                                       egress_iface=normalize_iface(iface) if iface else "",
                                       vrf=vrf, admin_distance=int(ad), metric=int(metric)))
    return results


# ── VRF list ──────────────────────────────────────────────────────────────────

_VRF_NAME_RE = re.compile(r"^(\S+)\s+\d+", re.MULTILINE)
_VRF_SKIP    = {"name", "vrf", "default", "mgmt-vrf", "management"}


def parse_vrf_list(text: str) -> List[str]:
    return [m.group(1) for m in _VRF_NAME_RE.finditer(text)
            if m.group(1).lower() not in _VRF_SKIP]


# ── FHRP parsers ──────────────────────────────────────────────────────────────

_FHRP_IFACE_GRP_RE = re.compile(r"^(\S+)\s+-\s+Group\s+(\d+)", re.MULTILINE)


def _parse_fhrp_blocks(text: str, protocol: str) -> List[FhrpInfo]:
    entries: List[FhrpInfo] = []
    parts = _FHRP_IFACE_GRP_RE.split(text)
    i = 1
    while i + 2 <= len(parts):
        iface, group_str, body = parts[i], parts[i + 1], (parts[i + 2] if i + 2 < len(parts) else "")
        vip_m   = re.search(r"(?:Virtual IP address|Virtual IP) (?:is |:\s*)([\d.]+)", body, re.I)
        state_m = re.search(r"(?:State|VRRP state|GLBP state) (?:is |:\s*)(\S+)", body, re.I)
        pri_m   = re.search(r"(?:Priority|Weighting)\s+[:\s]*(\d+)", body, re.I)
        entries.append(FhrpInfo(protocol=protocol, interface=normalize_iface(iface),
                                group=int(group_str),
                                virtual_ip=vip_m.group(1) if vip_m else "",
                                state=state_m.group(1) if state_m else "",
                                priority=int(pri_m.group(1)) if pri_m else 100))
        i += 3
    return entries


def parse_hsrp(text: str) -> List[FhrpInfo]:
    return _parse_fhrp_blocks(text, "HSRP")


def parse_vrrp(text: str) -> List[FhrpInfo]:
    return _parse_fhrp_blocks(text, "VRRP")


def parse_glbp(text: str) -> List[FhrpInfo]:
    return _parse_fhrp_blocks(text, "GLBP")


# ── CDP neighbors detail ──────────────────────────────────────────────────────

_CDP_DEV_RE    = re.compile(r"Device ID:\s+(\S+)")
_CDP_IP_RE     = re.compile(r"IP(?:v4)? [Aa]ddress:\s+([\d.]+)")
_CDP_PLAT_RE   = re.compile(r"Platform:\s+(.+?),")
_CDP_CAP_RE    = re.compile(r"Capabilities:\s+(.+)")
_CDP_LIFACE_RE = re.compile(r"Interface:\s+(\S+),")
_CDP_RIFACE_RE = re.compile(r"Port ID \(outgoing port\):\s+(\S+)")


def parse_cdp_neighbors_detail(text: str) -> List[CdpNeighbor]:
    entries: List[CdpNeighbor] = []
    for block in re.split(r"-{20,}", text):
        dev_m = _CDP_DEV_RE.search(block)
        if not dev_m:
            continue
        ip_m     = _CDP_IP_RE.search(block)
        plat_m   = _CDP_PLAT_RE.search(block)
        cap_m    = _CDP_CAP_RE.search(block)
        liface_m = _CDP_LIFACE_RE.search(block)
        riface_m = _CDP_RIFACE_RE.search(block)
        entries.append(CdpNeighbor(
            local_interface    = normalize_iface(liface_m.group(1)) if liface_m else "",
            neighbor_device    = dev_m.group(1),
            neighbor_interface = normalize_iface(riface_m.group(1)) if riface_m else "",
            neighbor_ip        = ip_m.group(1) if ip_m else "",
            platform           = plat_m.group(1).strip() if plat_m else "",
            capabilities       = cap_m.group(1).strip() if cap_m else "",
            protocol           = "CDP",
        ))
    return entries


# ── LLDP neighbors detail ─────────────────────────────────────────────────────

# IOS/IOS-XE  show lldp neighbors detail
_LLDP_LIFACE_RE  = re.compile(r"Local Intf:\s+(\S+)",   re.IGNORECASE)
_LLDP_SYSNAME_RE = re.compile(r"System Name:\s+(\S+)",  re.IGNORECASE)
_LLDP_PORTID_RE  = re.compile(r"Port id:\s+(\S+)",      re.IGNORECASE)
_LLDP_MGMTIP_RE  = re.compile(r"IP:\s+([\d.]+)")
_LLDP_PLAT_RE    = re.compile(r"System Description:\s*\n\s*(.+)", re.IGNORECASE)


def parse_lldp_neighbors_detail(text: str) -> List[CdpNeighbor]:
    entries: List[CdpNeighbor] = []
    for block in re.split(r"-{20,}", text):
        liface_m = _LLDP_LIFACE_RE.search(block)
        if not liface_m:
            continue
        sysname_m = _LLDP_SYSNAME_RE.search(block)
        portid_m  = _LLDP_PORTID_RE.search(block)
        mgmtip_m  = _LLDP_MGMTIP_RE.search(block)
        plat_m    = _LLDP_PLAT_RE.search(block)
        neighbor  = sysname_m.group(1) if sysname_m else ""
        if not neighbor:
            continue
        entries.append(CdpNeighbor(
            local_interface    = normalize_iface(liface_m.group(1)),
            neighbor_device    = neighbor,
            neighbor_interface = normalize_iface(portid_m.group(1)) if portid_m else "",
            neighbor_ip        = mgmtip_m.group(1) if mgmtip_m else "",
            platform           = plat_m.group(1).strip() if plat_m else "",
            capabilities       = "",
            protocol           = "LLDP",
        ))
    return entries


# ── Switchport mode ───────────────────────────────────────────────────────────

_SP_NAME_RE   = re.compile(r"^Name:\s+(\S+)", re.MULTILINE)
_SP_SWPORT_RE = re.compile(r"Switchport:\s+(\S+)", re.IGNORECASE)
_SP_ADMODE_RE = re.compile(r"Administrative Mode:\s+(.+)", re.IGNORECASE)


def parse_switchport_mode(text: str) -> Dict[str, str]:
    result: Dict[str, str] = {}
    headers = list(_SP_NAME_RE.finditer(text))
    for i, hdr in enumerate(headers):
        iface   = normalize_iface(hdr.group(1))
        start   = hdr.start()
        end     = headers[i + 1].start() if i + 1 < len(headers) else len(text)
        section = text[start:end]
        sw_m = _SP_SWPORT_RE.search(section)
        if sw_m and sw_m.group(1).strip().lower() == "disabled":
            result[iface] = "routed"
            continue
        mode_m = _SP_ADMODE_RE.search(section)
        if not mode_m:
            result[iface] = "unknown"
            continue
        adm = mode_m.group(1).strip().lower()
        result[iface] = "access" if "access" in adm else "trunk" if "trunk" in adm else "unknown"
    return result


# ── Interface status ──────────────────────────────────────────────────────────

_IFACE_STAT_RE = re.compile(
    r"^(\S+)\s+(?:\S+\s+)??(up|down|administratively down|err-disabled)\s+(up|down)",
    re.IGNORECASE | re.MULTILINE,
)


def parse_interface_status(text: str) -> Dict[str, str]:
    result: Dict[str, str] = {}
    for m in _IFACE_STAT_RE.finditer(text):
        iface, line_s, _ = m.groups()
        ls = line_s.lower()
        result[normalize_iface(iface)] = (
            "admin_down" if "admin" in ls else "up" if ls == "up" else "down"
        )
    return result


# ─────────────────────────────────────────────────────────────────────────────
# NetBoxClient
# ─────────────────────────────────────────────────────────────────────────────


class NetBoxClientError(Exception):
    pass


class NetBoxClient:
    """Thin pynetbox wrapper for IP, prefix, device, and interface lookups."""

    def __init__(self, url: str, token: str, verify_ssl: bool = True) -> None:
        self._nb = pynetbox.api(url.rstrip("/"), token=token)
        if not verify_ssl:
            import urllib3
            urllib3.disable_warnings()
            self._nb.http_session.verify = False
        self.log = logging.getLogger("network_tracer.netbox")

    def lookup_ip(self, ip: str) -> Optional[dict]:
        try:
            recs = list(self._nb.ipam.ip_addresses.filter(address=ip))
            return dict(recs[0]) if recs else None
        except Exception as exc:
            self.log.warning("lookup_ip(%s): %s", ip, exc)
            return None

    def lookup_prefix(self, ip: str) -> Optional[dict]:
        try:
            recs = list(self._nb.ipam.prefixes.filter(contains=ip))
            if not recs:
                return None
            return dict(sorted(recs, key=lambda r: int(str(r.prefix).split("/")[1]), reverse=True)[0])
        except Exception as exc:
            self.log.warning("lookup_prefix(%s): %s", ip, exc)
            return None

    def lookup_vrf_by_ip(self, ip: str) -> Optional[str]:
        rec = self.lookup_ip(ip)
        if rec and rec.get("vrf"):
            v = rec["vrf"]
            return v["name"] if isinstance(v, dict) else str(v)
        return None

    def get_device_by_ip(self, ip: str) -> Optional[dict]:
        try:
            for attr in ("primary_ip", "primary_ip4", "primary_ip6"):
                recs = list(self._nb.dcim.devices.filter(**{attr: ip}))
                if recs:
                    return dict(recs[0])
            return None
        except Exception as exc:
            self.log.warning("get_device_by_ip(%s): %s", ip, exc)
            return None

    def get_device_by_name(self, name: str) -> Optional[dict]:
        try:
            rec = self._nb.dcim.devices.get(name=name)
            return dict(rec) if rec else None
        except Exception as exc:
            self.log.warning("get_device_by_name(%s): %s", name, exc)
            return None

    def get_primary_ip(self, device_name: str) -> Optional[str]:
        rec = self.get_device_by_name(device_name)
        if not rec:
            return None
        for key in ("primary_ip", "primary_ip4"):
            val = rec.get(key)
            if val:
                addr = val.get("address", "") if isinstance(val, dict) else str(val)
                return addr.split("/")[0]
        return None

    def get_ip_for_interface(self, device_name: str, iface_name: str) -> Optional[str]:
        try:
            recs = list(self._nb.ipam.ip_addresses.filter(device=device_name, interface=iface_name))
            if recs:
                return str(recs[0].address).split("/")[0]
            return None
        except Exception as exc:
            self.log.warning("get_ip_for_interface(%s, %s): %s", device_name, iface_name, exc)
            return None


# ─────────────────────────────────────────────────────────────────────────────
# CiscoDeviceSession
# ─────────────────────────────────────────────────────────────────────────────


class CiscoDeviceSession:
    """Netmiko-backed session with platform auto-detection and retry."""

    def __init__(self, host: str, username: str, password: str, secret: str = "",
                 port: int = 22, timeout: int = 30, retries: int = 2,
                 device_type: str = "cisco_ios") -> None:
        self.host        = host
        self.username    = username
        self.password    = password
        self.secret      = secret
        self.port        = port
        self.timeout     = timeout
        self.retries     = retries
        self.device_type = device_type
        self._conn       = None
        self._platform   = "ios"
        self.log = logging.getLogger(f"network_tracer.session.{host}")

    def connect(self) -> None:
        last_exc: Optional[Exception] = None
        for attempt in range(1, self.retries + 2):
            try:
                self.log.info("Connecting to %s (attempt %d)", self.host, attempt)
                self._conn = ConnectHandler(
                    device_type=self.device_type, host=self.host,
                    username=self.username, password=self.password,
                    secret=self.secret or "", port=self.port,
                    timeout=self.timeout, global_delay_factor=2,
                )
                if self.secret:
                    try:
                        self._conn.enable()
                    except Exception:
                        pass
                self._detect_platform()
                return
            except (NetmikoTimeoutException, NetmikoAuthenticationException) as exc:
                last_exc = exc
                self.log.warning("Attempt %d failed: %s", attempt, exc)
                time.sleep(2 * attempt)
            except Exception as exc:
                last_exc = exc
                self.log.warning("Attempt %d error: %s", attempt, exc)
                time.sleep(2 * attempt)
        raise ConnectionError(
            f"Cannot connect to {self.host} after {self.retries + 1} attempts: {last_exc}"
        )

    def _detect_platform(self) -> None:
        try:
            out = self._conn.send_command("show version", read_timeout=30)
            self._platform = "nxos" if ("NX-OS" in out or "Nexus" in out) else "ios"
            self.log.debug("Platform: %s", self._platform)
        except Exception:
            self._platform = "ios"

    def disconnect(self) -> None:
        if self._conn:
            try:
                self._conn.disconnect()
            except Exception:
                pass
            self._conn = None

    @property
    def platform(self) -> str:
        return self._platform

    def send_command(self, cmd: str, timeout: int = 60) -> str:
        if not self._conn:
            raise RuntimeError(f"Not connected to {self.host}")
        try:
            return self._conn.send_command(cmd, read_timeout=timeout) or ""
        except Exception as exc:
            self.log.warning("send_command(%r) failed: %s", cmd, exc)
            return ""

    def __enter__(self) -> "CiscoDeviceSession":
        self.connect()
        return self

    def __exit__(self, *_: object) -> None:
        self.disconnect()


# ─────────────────────────────────────────────────────────────────────────────
# Layer2Resolver
# ─────────────────────────────────────────────────────────────────────────────


class Layer2Resolver:
    """Resolves ARP/NDP, MAC table, port-channel membership, CDP, and LLDP."""

    def __init__(self, session: CiscoDeviceSession, nb: Optional[NetBoxClient] = None) -> None:
        self._s  = session
        self._nb = nb
        self.log = logging.getLogger(f"network_tracer.l2.{session.host}")
        self._arp: Dict[str, ArpEntry]       = {}   # "arp:vrf:ip" or "ndp:vrf:ip"
        self._mac: Dict[str, List[MacEntry]] = {}
        self._pc:  Dict[str, List[str]]      = {}
        self._cdp: Optional[List[CdpNeighbor]] = None
        self._lldp: Optional[List[CdpNeighbor]] = None
        self._pc_loaded = False

    # ── ARP (IPv4) ────────────────────────────────────────────────────────────

    def get_arp_entry(self, ip: str, vrf: str = "global") -> Optional[ArpEntry]:
        key = f"arp:{vrf}:{ip}"
        if key in self._arp:
            return self._arp[key]
        cmd = "show ip arp" if vrf == "global" else f"show ip arp vrf {vrf}"
        raw = self._s.send_command(cmd)
        if not raw:
            return None
        parser = parse_arp_nxos if self._s.platform == "nxos" else parse_arp_ios
        for e in parser(raw, vrf=vrf):
            self._arp[f"arp:{e.vrf}:{e.ip}"] = e
        return self._arp.get(key)

    # ── NDP (IPv6) ────────────────────────────────────────────────────────────

    def get_ndp_entry(self, ip: str, vrf: str = "global") -> Optional[ArpEntry]:
        ip_lower = ip.lower()
        key = f"ndp:{vrf}:{ip_lower}"
        if key in self._arp:
            return self._arp[key]
        if self._s.platform == "nxos":
            cmd = "show ipv6 neighbor" if vrf == "global" else f"show ipv6 neighbor vrf {vrf}"
        else:
            cmd = "show ipv6 neighbors" if vrf == "global" else f"show ipv6 neighbors vrf {vrf}"
        raw = self._s.send_command(cmd)
        if not raw:
            return None
        parser = parse_ndp_nxos if self._s.platform == "nxos" else parse_ndp_ios
        for e in parser(raw, vrf=vrf):
            self._arp[f"ndp:{e.vrf}:{e.ip}"] = e
        return self._arp.get(key)

    # ── MAC table ─────────────────────────────────────────────────────────────

    def get_mac_entries(self, mac: str) -> List[MacEntry]:
        mac_n = normalize_mac(mac)
        if mac_n in self._mac:
            return self._mac[mac_n]
        raw = self._s.send_command(f"show mac address-table address {mac_n}")
        if not raw:
            return []
        parser = parse_mac_table_nxos if self._s.platform == "nxos" else parse_mac_table_ios
        for e in parser(raw):
            self._mac.setdefault(normalize_mac(e.mac), []).append(e)
        return self._mac.get(mac_n, [])

    def get_mac_for_vlan(self, vlan: int) -> List[MacEntry]:
        raw = self._s.send_command(f"show mac address-table vlan {vlan}")
        if not raw:
            return []
        return (parse_mac_table_nxos if self._s.platform == "nxos" else parse_mac_table_ios)(raw)

    def find_mac_port(self, mac: str, hint_vlan: Optional[int] = None) -> Optional[MacEntry]:
        entries = self.get_mac_entries(mac)
        if not entries and hint_vlan is not None:
            mac_n = normalize_mac(mac)
            entries = [e for e in self.get_mac_for_vlan(hint_vlan) if normalize_mac(e.mac) == mac_n]
        if not entries:
            return None
        physical = [e for e in entries if not normalize_iface(e.interface).lower().startswith("port-channel")]
        return (physical or entries)[0]

    # ── Port-channel ──────────────────────────────────────────────────────────

    def _load_port_channels(self) -> None:
        if self._pc_loaded:
            return
        if self._s.platform == "nxos":
            raw = self._s.send_command("show port-channel summary")
            self._pc = parse_etherchannel_nxos(raw) if raw else {}
        else:
            raw = self._s.send_command("show etherchannel summary")
            self._pc = parse_etherchannel_ios(raw) if raw else {}
        self._pc_loaded = True

    def resolve_port_channel(self, iface: str) -> str:
        if not iface.lower().startswith("port-channel"):
            return iface
        self._load_port_channels()
        members = self._pc.get(iface, [])
        return members[0] if members else iface

    # ── CDP ───────────────────────────────────────────────────────────────────

    def get_cdp_neighbors(self) -> List[CdpNeighbor]:
        if self._cdp is not None:
            return self._cdp
        raw = self._s.send_command("show cdp neighbors detail")
        self._cdp = parse_cdp_neighbors_detail(raw) if raw else []
        return self._cdp

    def cdp_for_interface(self, iface: str) -> Optional[CdpNeighbor]:
        phys = self.resolve_port_channel(iface)
        for n in self.get_cdp_neighbors():
            if normalize_iface(n.local_interface) == normalize_iface(phys):
                return n
        return None

    # ── LLDP ──────────────────────────────────────────────────────────────────

    def get_lldp_neighbors(self) -> List[CdpNeighbor]:
        if self._lldp is not None:
            return self._lldp
        raw = self._s.send_command("show lldp neighbors detail")
        self._lldp = parse_lldp_neighbors_detail(raw) if raw else []
        return self._lldp

    def lldp_for_interface(self, iface: str) -> Optional[CdpNeighbor]:
        phys = self.resolve_port_channel(iface)
        for n in self.get_lldp_neighbors():
            if normalize_iface(n.local_interface) == normalize_iface(phys):
                return n
        return None

    # ── CDP + LLDP combined ───────────────────────────────────────────────────

    def discovery_neighbor_for_interface(self, iface: str) -> Optional[CdpNeighbor]:
        """Try CDP first; fall back to LLDP for non-Cisco peers."""
        return self.cdp_for_interface(iface) or self.lldp_for_interface(iface)

    # ── Switchport VLAN ───────────────────────────────────────────────────────

    def get_access_vlan(self, iface: str) -> Optional[int]:
        raw = self._s.send_command(f"show interfaces {iface} switchport")
        if not raw:
            return None
        for pattern in (r"Access Mode VLAN:\s+(\d+)", r"Access Vlan:\s+(\d+)"):
            m = re.search(pattern, raw, re.IGNORECASE)
            if m:
                return int(m.group(1))
        return None


# ─────────────────────────────────────────────────────────────────────────────
# RouteResolver
# ─────────────────────────────────────────────────────────────────────────────


class RouteResolver:
    """Route lookups across global and all named VRF tables; IPv4 and IPv6."""

    def __init__(self, session: CiscoDeviceSession) -> None:
        self._s   = session
        self.log  = logging.getLogger(f"network_tracer.route.{session.host}")
        self._vrfs: Optional[List[str]] = None

    def get_vrfs(self) -> List[str]:
        if self._vrfs is not None:
            return self._vrfs
        cmd = "show vrf" if self._s.platform == "nxos" else "show vrf brief"
        raw = self._s.send_command(cmd)
        self._vrfs = parse_vrf_list(raw) if raw else []
        return self._vrfs

    def lookup_route(self, ip: str, vrf: str = "global") -> List[RouteResult]:
        v6 = is_ipv6_addr(ip)
        if v6:
            cmd = f"show ipv6 route {ip}" if vrf == "global" else f"show ipv6 route vrf {vrf} {ip}"
            raw = self._s.send_command(cmd)
            if not raw:
                return []
            parser = parse_routes_ipv6_nxos if self._s.platform == "nxos" else parse_routes_ipv6_ios
        else:
            cmd = f"show ip route {ip}" if vrf == "global" else f"show ip route vrf {vrf} {ip}"
            raw = self._s.send_command(cmd)
            if not raw:
                return []
            parser = parse_routes_nxos if self._s.platform == "nxos" else parse_routes_ios
        return parser(raw, target_ip=ip, vrf=vrf)

    def lookup_all_vrfs(self, ip: str) -> List[RouteResult]:
        results = self.lookup_route(ip, vrf="global")
        for vrf in self.get_vrfs():
            results.extend(self.lookup_route(ip, vrf=vrf))
        return results

    def ecmp_routes(self, ip: str, preferred_vrf: str = "global") -> List[RouteResult]:
        """Return all routes for the most-specific matching prefix (ECMP set)."""
        routes = self.lookup_route(ip, vrf=preferred_vrf)
        if not routes:
            routes = self.lookup_all_vrfs(ip)
        if not routes:
            return []
        # Connected/local routes take priority
        connected = [r for r in routes if r.protocol.strip() in ("C", "L")]
        if connected:
            return connected
        best_len = max(_prefix_len(r) for r in routes)
        return [r for r in routes if _prefix_len(r) == best_len]

    def best_route(self, ip: str, preferred_vrf: str = "global") -> Optional[RouteResult]:
        candidates = self.ecmp_routes(ip, preferred_vrf)
        if not candidates:
            return None
        return sorted(candidates, key=lambda r: (r.admin_distance, r.metric))[0]


# ─────────────────────────────────────────────────────────────────────────────
# FHRPResolver
# ─────────────────────────────────────────────────────────────────────────────


class FHRPResolver:
    """Detects HSRP/VRRP/GLBP gateways and checks if an IP is a VIP."""

    def __init__(self, session: CiscoDeviceSession) -> None:
        self._s   = session
        self.log  = logging.getLogger(f"network_tracer.fhrp.{session.host}")
        self._all: Optional[List[FhrpInfo]] = None

    def _load(self) -> None:
        if self._all is not None:
            return
        results: List[FhrpInfo] = []
        for cmd, parser in [("show standby", parse_hsrp),
                             ("show vrrp",    parse_vrrp),
                             ("show glbp",    parse_glbp)]:
            raw = self._s.send_command(cmd)
            if raw:
                results.extend(parser(raw))
        self._all = results

    def all_fhrp(self) -> List[FhrpInfo]:
        self._load()
        return self._all or []

    def is_virtual_ip(self, ip: str) -> Optional[FhrpInfo]:
        return next((f for f in self.all_fhrp() if f.virtual_ip == ip), None)

    def active_gateway_for_vip(self, ip: str) -> Optional[FhrpInfo]:
        return next((f for f in self.all_fhrp()
                     if f.virtual_ip == ip and f.state.lower() in ("active", "master")), None)


# ─────────────────────────────────────────────────────────────────────────────
# TraceEngine
# ─────────────────────────────────────────────────────────────────────────────

_MAX_HOPS = 30

# Platforms we are willing to SSH into and run show commands on.
_ALLOWED_PLATFORM_SLUGS: frozenset = frozenset({
    "ios", "cisco-ios", "cisco_ios",
    "iosxe", "ios-xe", "ios_xe", "cisco-iosxe",
    "nxos", "nx-os", "nx_os", "cisco-nxos",
})

# Device-role slugs that are never switches or routers — skip without SSH.
_BLOCKED_ROLE_SLUGS: frozenset = frozenset({
    "access-point", "access_point", "ap", "wireless-ap", "wireless_ap",
    "ip-phone", "ip_phone", "phone", "printer", "camera", "iot",
    "workstation", "server", "ups",
})

# Detects a wireless access point from CDP/LLDP platform or capabilities strings.
# Covers: Cisco Aironet (AIR-*), Catalyst Wi-Fi (C9105/9115/9117/9120/9130/9136),
# and LLDP "Wlan-Access-Point" capability.
_AP_PLATFORM_RE = re.compile(
    r"\bAIR-[A-Z]"            # AIR-AP*, AIR-CAP*, AIR-LAP*
    r"|\bAIRONET\b"           # "Aironet" standalone word
    r"|\bC9(?:105|115|117|120|130|136)[A-Z]"  # Catalyst Wi-Fi AX models
    r"|\bCisco\s+AP\b",       # LLDP system description: "Cisco AP ..."
    re.IGNORECASE,
)


def _neighbor_is_access_point(disc: "CdpNeighbor") -> bool:
    """Return True if a CDP/LLDP neighbor is a wireless access point.

    Checks platform string first (most reliable), then capabilities:
    - CDP APs advertise "Trans-Bridge" and NOT Router/Switch capabilities.
    - LLDP APs may advertise "wlan-access-point" capability.
    """
    if _AP_PLATFORM_RE.search(disc.platform):
        return True
    caps = disc.capabilities.lower()
    if "wlan-access-point" in caps:
        return True
    # Trans-Bridge without Router or Switch → classic CDP AP fingerprint
    if "trans-bridge" in caps and "router" not in caps and "switch" not in caps:
        return True
    return False


class TraceEngine:
    """Orchestrates forward/reverse path trace with loop detection, IPv6, and ECMP."""

    def __init__(self, nb: NetBoxClient, credentials: Dict[str, str],
                 max_hops: int = _MAX_HOPS, parallel_ecmp: bool = False) -> None:
        self._nb           = nb
        self._creds        = credentials
        self._max_hops     = max_hops
        self._parallel_ecmp = parallel_ecmp
        self.log           = logging.getLogger("network_tracer.engine")
        self._sessions:  Dict[str, CiscoDeviceSession] = {}
        self._hops:      List[HopResult] = []
        self._visited:   set = set()
        self._hops_lock  = threading.Lock()

    def _session(self, host_ip: str, device_name: str = "") -> Optional[CiscoDeviceSession]:
        if host_ip in self._sessions:
            return self._sessions[host_ip]
        try:
            s = CiscoDeviceSession(
                host=host_ip,
                username=self._creds["username"],
                password=self._creds["password"],
                secret=self._creds.get("secret", ""),
                timeout=int(self._creds.get("timeout", "30")),
            )
            s.connect()
            self._sessions[host_ip] = s
            return s
        except Exception as exc:
            self.log.error("Cannot connect to %s (%s): %s", device_name or host_ip, host_ip, exc)
            return None

    def close_all(self) -> None:
        for s in self._sessions.values():
            s.disconnect()
        self._sessions.clear()

    # ── Public entry points ───────────────────────────────────────────────────

    def trace(self, src_ip: str, dst_ip: str) -> List[HopResult]:
        self._hops    = []
        self._visited = set()
        self.log.info("Forward trace: %s → %s", src_ip, dst_ip)
        print(f"\n[TRACE] {src_ip}  →  {dst_ip}\n")

        # If the source is a non-traceable device (AP, phone, etc.), locate it
        # via its subnet gateway then start routing from the access switch.
        src_rec = self._nb.get_device_by_ip(src_ip)
        if src_rec:
            ok, _ = self._is_cisco_network_device(src_rec.get("name", src_ip), src_ip)
            if not ok:
                self._trace_from_end_device(src_ip, dst_ip)
                return self._hops

        name, mgmt = self._resolve_start_device(src_ip)
        self._step(name, mgmt, dst_ip, ingress="", vrf="global", hop_num=1)
        return self._hops

    def trace_reverse(self, src_ip: str, dst_ip: str) -> List[HopResult]:
        self._hops    = []
        self._visited = set()
        self.log.info("Reverse trace: %s → %s", dst_ip, src_ip)
        print(f"\n[REVERSE TRACE] {dst_ip}  →  {src_ip}\n")
        name, mgmt = self._resolve_start_device(dst_ip)
        self._step(name, mgmt, src_ip, ingress="", vrf="global", hop_num=1)
        return self._hops

    # ── End-device source handling ────────────────────────────────────────────

    def _find_gateway_for_ip(self, ip: str) -> Optional[str]:
        """Return the first host address of the most-specific NetBox prefix for ip."""
        prefix_rec = self._nb.lookup_prefix(ip)
        if not prefix_rec:
            return None
        try:
            net = ipaddress.ip_network(prefix_rec.get("prefix", ""), strict=False)
            hosts = list(net.hosts())
            return str(hosts[0]) if hosts else None
        except ValueError:
            return None

    def _trace_from_end_device(self, end_ip: str, dst_ip: str) -> None:
        """Source is a non-traceable end device (AP, phone, etc.).

        1. Find the gateway for the end device's subnet prefix.
        2. Connect to the gateway; do ARP→MAC→CDP/LLDP to walk toward the
           access port where end_ip is directly attached.
        3. Once the access port is found, start the normal routing trace from
           that device toward dst_ip.
        """
        gateway_ip = self._find_gateway_for_ip(end_ip)
        if not gateway_ip:
            self.log.error("No NetBox prefix found for %s — cannot determine gateway", end_ip)
            print(f"   ERROR: No prefix found for {end_ip} in NetBox — cannot trace")
            return

        gw_name, gw_mgmt = self._resolve_start_device(gateway_ip)
        print(f"   Source {end_ip} is a non-traceable end device")
        print(f"   Locating via gateway {gw_name} ({gateway_ip}) ...\n")

        is_v6 = is_ipv6_addr(end_ip)
        cur_name, cur_mgmt = gw_name, gw_mgmt
        hop_num = 1
        location_visited: set = set()   # separate from routing visited; avoids poisoning _visited

        while hop_num <= self._max_hops:
            lk = cur_name.lower()
            if lk in location_visited:
                self.log.warning("Location loop detected at %s — stopping", cur_name)
                break
            location_visited.add(lk)

            ok, reason = self._is_cisco_network_device(cur_name, cur_mgmt)
            if not ok:
                self.log.warning("Non-traceable device %s in location path: %s", cur_name, reason)
                break

            sess = self._session(cur_mgmt, cur_name)
            if not sess:
                self.log.error("Cannot connect to %s (%s) while locating %s",
                               cur_name, cur_mgmt, end_ip)
                break

            l2 = Layer2Resolver(sess, self._nb)
            print(f"  Hop {hop_num:>2}:  {cur_name:<30} ({cur_mgmt})  [locating {end_ip}]")

            # ARP (v4) or NDP (v6) lookup for the end device
            if is_v6:
                nbr = l2.get_ndp_entry(end_ip, vrf="global")
            else:
                nbr = l2.get_arp_entry(end_ip, vrf="global")
                if not nbr:
                    for vrf_name in l2.get_vrfs():
                        nbr = l2.get_arp_entry(end_ip, vrf=vrf_name)
                        if nbr:
                            break

            if not nbr:
                self.log.warning("%s has no ARP/NDP entry for %s", cur_name, end_ip)
                print(f"         ✗ No ARP/NDP entry for {end_ip} — stopping location walk")
                break

            hop = HopResult(
                hop_number=hop_num, device_name=cur_name, device_ip=cur_mgmt,
                ingress_interface="", egress_interface="",
                vrf=nbr.vrf, next_hop_ip=end_ip, next_device_name="",
                method="arp", arp_entry=nbr, branch=0, ecmp_total=1,
            )

            vlan = l2.get_access_vlan(nbr.interface)
            mac_e = l2.find_mac_port(nbr.mac, hint_vlan=vlan)

            if mac_e:
                hop.mac_entry = mac_e
                mac_phys = l2.resolve_port_channel(mac_e.interface)
                hop.egress_interface = mac_phys
                disc = l2.discovery_neighbor_for_interface(mac_phys)

                if disc:
                    # End device is behind another switch — keep walking
                    next_ip = (disc.neighbor_ip
                               or self._nb.get_primary_ip(disc.neighbor_device) or "")
                    hop.cdp_neighbor     = disc
                    hop.next_device_name = disc.neighbor_device
                    hop.next_hop_ip      = next_ip
                    hop.method           = disc.protocol.lower()
                    hop.notes.append(
                        f"{end_ip} reachable via {disc.protocol} neighbor "
                        f"{disc.neighbor_device} on {mac_phys}"
                    )
                    print(f"         → {disc.protocol}: {end_ip} is behind "
                          f"{disc.neighbor_device} via {mac_phys} — following")
                    with self._hops_lock:
                        self._hops.append(hop)
                    cur_name = disc.neighbor_device
                    cur_mgmt = next_ip
                    hop_num += 1
                    continue  # walk to next switch

                # No CDP/LLDP — end device is directly on this port
                hop.method = "mac"
                hop.notes.append(
                    f"End device {end_ip} (MAC {nbr.mac}) directly on port {mac_phys}"
                )
                print(f"         ✓ {end_ip} is on port {mac_phys} of {cur_name} (access port)")

            else:
                # MAC not in table — ARP only, treat as directly attached
                phys = l2.resolve_port_channel(nbr.interface)
                hop.egress_interface = phys
                hop.method = "arp"
                hop.notes.append(f"ARP for {end_ip} on {phys}; MAC not in table")
                print(f"         → ARP only: {end_ip} on {phys} — no MAC table entry")

            with self._hops_lock:
                self._hops.append(hop)

            # Access port found — begin routing trace toward dst_ip from here
            print(f"\n   Routing from {cur_name} toward {dst_ip} ...\n")
            self._step(cur_name, cur_mgmt, dst_ip, ingress="", vrf="global",
                       hop_num=hop_num + 1)
            return

        self.log.error("Could not locate end device %s on the network", end_ip)
        print(f"   ERROR: Could not locate {end_ip} — trace incomplete")

    # ── Device eligibility check ──────────────────────────────────────────────

    def _is_cisco_network_device(self, dev_name: str, dev_ip: str) -> Tuple[bool, str]:
        """Return (True, "") if safe to SSH into; (False, reason) to skip.

        Rules (applied only when the device is found in NetBox):
          - Must have a platform whose slug is in _ALLOWED_PLATFORM_SLUGS
          - Must NOT have a device role whose slug is in _BLOCKED_ROLE_SLUGS
        Devices not in NetBox are allowed through so CDP/LLDP-discovered
        next-hops can still be traced.
        """
        nb_rec = None
        if dev_ip and dev_ip != dev_name:
            nb_rec = self._nb.get_device_by_ip(dev_ip)
        if not nb_rec and dev_name and dev_name != dev_ip:
            nb_rec = self._nb.get_device_by_name(dev_name)

        if not nb_rec:
            return True, ""

        display = nb_rec.get("name") or dev_name

        # Platform must be set and must be a known Cisco OS slug.
        platform = nb_rec.get("platform")
        if not platform:
            return False, f"{display}: no platform set in NetBox — skipping"
        plat_slug = (platform.get("slug", "") if isinstance(platform, dict) else str(platform)).lower()
        if plat_slug not in _ALLOWED_PLATFORM_SLUGS:
            return False, f"{display}: platform '{plat_slug}' is not a supported Cisco OS — skipping"

        # Device role must not be a known non-switch/router type.
        role = nb_rec.get("device_role") or nb_rec.get("role")
        if role:
            role_slug = (role.get("slug", "") if isinstance(role, dict) else str(role)).lower()
            if role_slug in _BLOCKED_ROLE_SLUGS:
                return False, f"{display}: device role '{role_slug}' is not a switch or router — skipping"

        return True, ""

    # ── Device resolution ─────────────────────────────────────────────────────

    def _resolve_start_device(self, ip: str) -> Tuple[str, str]:
        dev = self._nb.get_device_by_ip(ip)
        if dev:
            name = dev.get("name", ip)
            return name, self._nb.get_primary_ip(name) or ip
        return ip, ip

    def _resolve_next_device(self, next_hop_ip: str, l2: Layer2Resolver,
                              vrf: str, egress_iface: str = "") -> Tuple[str, str]:
        dev = self._nb.get_device_by_ip(next_hop_ip)
        if dev:
            name = dev.get("name", next_hop_ip)
            return name, self._nb.get_primary_ip(name) or next_hop_ip

        # ARP (v4) or NDP (v6) → discovery protocol
        if is_ipv6_addr(next_hop_ip):
            nbr_e = l2.get_ndp_entry(next_hop_ip, vrf=vrf)
        else:
            nbr_e = (l2.get_arp_entry(next_hop_ip, vrf=vrf)
                     or l2.get_arp_entry(next_hop_ip, vrf="global"))

        if nbr_e:
            disc = l2.discovery_neighbor_for_interface(nbr_e.interface)
            if disc:
                name = disc.neighbor_device
                return name, disc.neighbor_ip or self._nb.get_primary_ip(name) or next_hop_ip

        # Link-local IPv6 or unresolved: try CDP/LLDP on egress interface
        if egress_iface:
            disc2 = l2.discovery_neighbor_for_interface(egress_iface)
            if disc2:
                name = disc2.neighbor_device
                return name, disc2.neighbor_ip or self._nb.get_primary_ip(name) or next_hop_ip

        return next_hop_ip, next_hop_ip

    # ── Core recursive step ───────────────────────────────────────────────────

    def _step(self, dev_name: str, dev_ip: str, target: str,
              ingress: str, vrf: str, hop_num: int,
              branch: int = 0, ecmp_total: int = 1) -> None:

        if hop_num > self._max_hops:
            self.log.warning("Max hops (%d) reached — stopping", self._max_hops)
            return

        loop_key = (dev_name.lower(), vrf)
        if loop_key in self._visited:
            self.log.warning("Loop detected: %s vrf=%s — stopping", dev_name, vrf)
            return
        self._visited.add(loop_key)

        branch_tag = f" [ECMP {branch}/{ecmp_total}]" if branch else ""
        print(f"  Hop {hop_num:>2}{branch_tag}:  {dev_name:<30} ({dev_ip})  [vrf={vrf}]")

        hop = HopResult(
            hop_number=hop_num, device_name=dev_name, device_ip=dev_ip,
            ingress_interface=ingress, egress_interface="",
            vrf=vrf, next_hop_ip="", next_device_name="",
            method="unknown", branch=branch, ecmp_total=ecmp_total,
        )

        ok, reason = self._is_cisco_network_device(dev_name, dev_ip)
        if not ok:
            self.log.info("Skipping %s: %s", dev_name, reason)
            print(f"         ↷ SKIPPED  {reason}")
            hop.method = "skipped"
            hop.notes.append(reason)
            with self._hops_lock:
                self._hops.append(hop)
            return

        sess = self._session(dev_ip, dev_name)
        if not sess:
            hop.method = "unreachable"
            hop.notes.append(f"SSH connection to {dev_ip} failed")
            with self._hops_lock:
                self._hops.append(hop)
            return

        l2 = Layer2Resolver(sess, self._nb)
        rr = RouteResolver(sess)
        fr = FHRPResolver(sess)
        is_v6 = is_ipv6_addr(target)

        # ── 1. Does this device own the target IP? ────────────────────────────
        if self._device_owns_ip(sess, target):
            hop.method = "destination"
            hop.notes.append(f"{dev_name} owns {target} — destination reached")
            print(f"         ✓ DESTINATION REACHED  ({target})")
            with self._hops_lock:
                self._hops.append(hop)
            return

        # ── 2. FHRP (IPv4 only — HSRP/VRRP/GLBP are v4 protocols) ───────────
        if not is_v6:
            fhrp = fr.active_gateway_for_vip(target)
            if fhrp:
                hop.fhrp = fhrp
                hop.egress_interface = fhrp.interface
                hop.notes.append(
                    f"{fhrp.protocol} group {fhrp.group}: Active gateway for VIP {target}"
                )

        # ── 3. ARP (v4) or NDP (v6) lookup ───────────────────────────────────
        if is_v6:
            nbr = l2.get_ndp_entry(target, vrf=vrf)
            if not nbr and vrf != "global":
                nbr = l2.get_ndp_entry(target, vrf="global")
        else:
            nbr = l2.get_arp_entry(target, vrf=vrf)
            if not nbr and vrf != "global":
                nbr = l2.get_arp_entry(target, vrf="global")

        if nbr:
            hop.arp_entry = nbr
            phys_iface = l2.resolve_port_channel(nbr.interface)
            vlan = l2.get_access_vlan(nbr.interface)
            mac_e = l2.find_mac_port(nbr.mac, hint_vlan=vlan)

            if mac_e:
                hop.mac_entry = mac_e
                mac_phys = l2.resolve_port_channel(mac_e.interface)
                disc = l2.discovery_neighbor_for_interface(mac_phys)
                if disc:
                    hop.cdp_neighbor     = disc
                    hop.egress_interface = mac_phys
                    hop.next_device_name = disc.neighbor_device
                    hop.next_hop_ip      = (disc.neighbor_ip
                                            or self._nb.get_primary_ip(disc.neighbor_device) or "")

                    if _neighbor_is_access_point(disc):
                        # Target is a wireless client — stop at the AP, do not SSH into it
                        hop.method = "wireless"
                        hop.notes.append(
                            f"Wireless client — connected to AP {disc.neighbor_device}"
                            f" ({disc.platform}) via {mac_phys}"
                        )
                        print(f"         ✓ WIRELESS: {target} is a wireless client on"
                              f" AP {disc.neighbor_device} via {mac_phys}")
                        with self._hops_lock:
                            self._hops.append(hop)
                        return

                    hop.method = disc.protocol.lower()  # "cdp" or "lldp"
                    print(f"         → {disc.protocol}: {disc.neighbor_device} via {mac_phys}")
                    with self._hops_lock:
                        self._hops.append(hop)
                    if hop.next_hop_ip:
                        self._step(disc.neighbor_device, hop.next_hop_ip, target,
                                   disc.neighbor_interface, vrf, hop_num + 1, branch, ecmp_total)
                    return

                hop.egress_interface = mac_phys
                hop.next_hop_ip      = target
                hop.method = "mac"
                hop.notes.append(f"MAC {nbr.mac} on {mac_phys} — no discovery neighbor, end host")
                print(f"         ✓ End host via {mac_phys}  (no CDP/LLDP)")
                with self._hops_lock:
                    self._hops.append(hop)
                return

            hop.egress_interface = phys_iface
            hop.next_hop_ip      = target
            hop.method = "arp"
            hop.notes.append(f"{'NDP' if is_v6 else 'ARP'} on {phys_iface}; no MAC entry — directly attached")
            print(f"         ✓ Directly attached on {phys_iface}  ({'NDP' if is_v6 else 'ARP'} only)")
            with self._hops_lock:
                self._hops.append(hop)
            return

        # ── 4. Route lookup ───────────────────────────────────────────────────
        ecmp = rr.ecmp_routes(target, preferred_vrf=vrf)
        route = ecmp[0] if ecmp else None

        if route:
            hop.route            = route
            hop.vrf              = route.vrf
            hop.egress_interface = route.egress_iface
            hop.method = "route"

            if route.next_hop:
                hop.next_hop_ip = route.next_hop

                if self._parallel_ecmp and len(ecmp) > 1:
                    # Multiple ECMP next-hops — trace each path in parallel
                    hop.notes.append(f"ECMP: {len(ecmp)} equal-cost paths to {route.prefix}")
                    print(f"         → ECMP: {len(ecmp)} paths — spawning parallel branches")
                    with self._hops_lock:
                        self._hops.append(hop)
                    self._step_ecmp_parallel(ecmp, target, hop_num, l2)
                else:
                    next_name, next_mgmt = self._resolve_next_device(
                        route.next_hop, l2, route.vrf, route.egress_iface
                    )
                    hop.next_device_name = next_name
                    print(f"         → Route [{route.protocol.strip()}] {route.prefix}"
                          f"  via {route.next_hop}  egress {route.egress_iface}")
                    with self._hops_lock:
                        self._hops.append(hop)
                    self._step(next_name, next_mgmt, target, "", route.vrf,
                               hop_num + 1, branch, ecmp_total)
            else:
                hop.notes.append(f"Directly connected on {route.egress_iface}")
                print(f"         → Directly connected on {route.egress_iface}")
                with self._hops_lock:
                    self._hops.append(hop)
            return

        # ── 5. Dead end ───────────────────────────────────────────────────────
        hop.method = "no_route"
        hop.notes.append(f"No route to {target} from {dev_name}")
        self.log.warning("No route to %s from %s", target, dev_name)
        print(f"         ✗ No route to {target}")
        with self._hops_lock:
            self._hops.append(hop)

    # ── Parallel ECMP ─────────────────────────────────────────────────────────

    def _step_ecmp_parallel(self, routes: List[RouteResult], target: str,
                             hop_num: int, parent_l2: Layer2Resolver) -> None:
        n = len(routes)

        def run_branch(route: RouteResult, branch_id: int) -> List[HopResult]:
            next_name, next_mgmt = self._resolve_next_device(
                route.next_hop, parent_l2, route.vrf, route.egress_iface
            )
            sub = TraceEngine(nb=self._nb, credentials=self._creds,
                              max_hops=self._max_hops, parallel_ecmp=False)
            sub._visited = set(self._visited)  # copy loop-detection state
            sub._step(next_name, next_mgmt, target, "", route.vrf,
                      hop_num + 1, branch=branch_id, ecmp_total=n)
            branch_hops = list(sub._hops)
            sub.close_all()
            return branch_hops

        branch_results: List[List[HopResult]] = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=n) as ex:
            futures = {ex.submit(run_branch, r, i + 1): i for i, r in enumerate(routes)}
            for fut in concurrent.futures.as_completed(futures):
                try:
                    branch_results.append(fut.result())
                except Exception as exc:
                    self.log.error("ECMP branch %d failed: %s", futures[fut] + 1, exc)

        # Append branches in order 1..N for consistent output
        branch_results.sort(key=lambda br: br[0].branch if br else 999)
        with self._hops_lock:
            for br_hops in branch_results:
                self._hops.extend(br_hops)

    # ── Ownership check ───────────────────────────────────────────────────────

    def _device_owns_ip(self, sess: CiscoDeviceSession, ip: str) -> bool:
        if is_ipv6_addr(ip):
            # IPv6: check ipv6 interface brief
            raw = sess.send_command(f"show ipv6 interface brief | include {ip}")
            if raw and ip.lower() in raw.lower():
                return True
            # Broader check for NX-OS
            raw2 = sess.send_command("show ipv6 interface brief")
            return bool(raw2 and ip.lower() in raw2.lower())
        else:
            raw = sess.send_command(f"show ip interface brief | include {ip}")
            if raw and ip in raw:
                return True
            raw2 = sess.send_command(f"show interface brief | include {ip}")
            return bool(raw2 and ip in raw2)


# ─────────────────────────────────────────────────────────────────────────────
# OutputWriter
# ─────────────────────────────────────────────────────────────────────────────


class OutputWriter:
    """Writes trace results to JSON report, CSV summary, and console."""

    def __init__(self, src_ip: str, dst_ip: str, hops: List[HopResult],
                 out_dir: str = ".", run_id: Optional[str] = None) -> None:
        self._src  = src_ip
        self._dst  = dst_ip
        self._hops = hops
        self._dir  = Path(out_dir)
        self._dir.mkdir(parents=True, exist_ok=True)
        self._ts   = run_id or datetime.now().strftime("%Y%m%d_%H%M%S")
        self.log   = logging.getLogger("network_tracer.output")

    def write_all(self) -> None:
        jp = self._write_json()
        cp = self._write_csv()
        self._print_summary()
        print(f"\n[OUTPUT] JSON: {jp}")
        print(f"[OUTPUT] CSV:  {cp}")
        print(f"[OUTPUT] Log:  {LOG_FILE}")

    def _write_json(self) -> Path:
        report = {
            "trace_id":  self._ts,
            "src_ip":    self._src,
            "dst_ip":    self._dst,
            "hop_count": len(self._hops),
            "timestamp": datetime.now().isoformat(),
            "hops": [self._hop_dict(h) for h in self._hops],
        }
        path = self._dir / f"trace_{self._src}_{self._dst}_{self._ts}.json"
        with path.open("w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, default=str)
        self.log.info("JSON: %s", path)
        return path

    def _hop_dict(self, h: HopResult) -> dict:
        d = asdict(h)
        for key in ("arp_entry", "mac_entry", "cdp_neighbor", "route", "fhrp"):
            if d.get(key) is None:
                d.pop(key, None)
        return d

    def _write_csv(self) -> Path:
        path = self._dir / f"trace_{self._src}_{self._dst}_{self._ts}.csv"
        cols = ["hop", "branch", "ecmp_total", "device_name", "device_ip",
                "ingress_interface", "egress_interface", "vrf",
                "next_hop_ip", "next_device_name", "method", "notes"]
        with path.open("w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=cols)
            w.writeheader()
            for h in self._hops:
                w.writerow({
                    "hop":               h.hop_number,
                    "branch":            h.branch,
                    "ecmp_total":        h.ecmp_total,
                    "device_name":       h.device_name,
                    "device_ip":         h.device_ip,
                    "ingress_interface": h.ingress_interface,
                    "egress_interface":  h.egress_interface,
                    "vrf":               h.vrf,
                    "next_hop_ip":       h.next_hop_ip,
                    "next_device_name":  h.next_device_name,
                    "method":            h.method,
                    "notes":             "; ".join(h.notes),
                })
        self.log.info("CSV: %s", path)
        return path

    def _print_summary(self) -> None:
        w = 76
        print(f"\n{'═' * w}")
        print(f"  TRACE: {self._src}  →  {self._dst}")
        print(f"{'═' * w}")
        print(f"  {'HOP':<4} {'BR':<4} {'DEVICE':<26} {'EGRESS IFACE':<22} {'NEXT HOP':<16} METHOD")
        print(f"  {'─'*4} {'─'*4} {'─'*26} {'─'*22} {'─'*16} {'─'*12}")
        for h in self._hops:
            br = f"{h.branch}/{h.ecmp_total}" if h.branch else "-"
            print(f"  {h.hop_number:<4} {br:<4} {h.device_name:<26} "
                  f"{h.egress_interface:<22} {h.next_hop_ip:<16} {h.method}")
        if self._hops:
            single_path = [h for h in self._hops if h.branch == 0]
            last = (single_path or self._hops)[-1]
            reached = last.method in ("destination", "mac", "arp")
            print(f"\n  {'✓' if reached else '✗'} Destination "
                  f"{'REACHED' if reached else 'NOT REACHED'} in "
                  f"{len(self._hops)} hop(s)")
        print(f"{'═' * w}\n")


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
    nb.add_argument("--netbox-url",    default=None,
                    help="NetBox base URL (env: NETBOX_URL)")
    nb.add_argument("--netbox-token",  default=None,
                    help="NetBox API token (env: NETBOX_TOKEN)")
    nb.add_argument("--no-ssl-verify", action="store_true",
                    help="Disable TLS verification for NetBox")

    dev = p.add_argument_group("Device credentials (ignored when Vault is configured)")
    dev.add_argument("--username", default=None,
                     help="SSH username (env: DEVICE_USER)")
    dev.add_argument("--password", default=None,
                     help="SSH password (env: DEVICE_PASS)")
    dev.add_argument("--secret",   default=os.environ.get("DEVICE_SECRET", ""),
                     help="Enable secret (env: DEVICE_SECRET)")
    dev.add_argument("--timeout",  type=int, default=30,
                     help="SSH timeout in seconds (default: 30)")

    if _VAULT_AVAILABLE:
        vault_grp = p.add_argument_group(
            "Vault authentication (optional — overrides --username/--password/--netbox-*)"
        )
        add_vault_parser_args(vault_grp)

    tr = p.add_argument_group("Trace options")
    tr.add_argument("--reverse",  action="store_true",
                    help="Also run reverse trace (dst → src)")
    tr.add_argument("--ecmp",     action="store_true",
                    help="Trace all ECMP paths in parallel (one SSH session per path)")
    tr.add_argument("--max-hops", type=int, default=30,
                    help="Max hops before stopping (default: 30)")
    tr.add_argument("--out-dir",  default=".",
                    help="Output directory for JSON/CSV (default: current dir)")
    tr.add_argument("--verbose",  action="store_true",
                    help="Enable DEBUG logging")

    return p


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
                path=getattr(args, "vault_path", "network/device"),
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
        username     = args.username     or os.environ.get("DEVICE_USER",   "")
        password     = args.password     or os.environ.get("DEVICE_PASS",   "")
        netbox_url   = args.netbox_url   or os.environ.get("NETBOX_URL",    "")
        netbox_token = args.netbox_token or os.environ.get("NETBOX_TOKEN",  "")

    # ── Validation ────────────────────────────────────────────────────────────
    errors: List[str] = []
    if not is_valid_ip(args.src_ip):
        errors.append(f"Invalid source IP: {args.src_ip!r}")
    if not is_valid_ip(args.dst_ip):
        errors.append(f"Invalid destination IP: {args.dst_ip!r}")
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

    nb = NetBoxClient(url=netbox_url, token=netbox_token,
                      verify_ssl=not args.no_ssl_verify)
    creds = {
        "username": username,
        "password": password,
        "secret":   args.secret,
        "timeout":  str(args.timeout),
    }
    run_id = datetime.now().strftime("%Y%m%d_%H%M%S")
    engine = TraceEngine(nb=nb, credentials=creds, max_hops=args.max_hops,
                         parallel_ecmp=args.ecmp)

    try:
        fwd_hops = engine.trace(args.src_ip, args.dst_ip)
        OutputWriter(src_ip=args.src_ip, dst_ip=args.dst_ip, hops=fwd_hops,
                     out_dir=args.out_dir, run_id=run_id + "_fwd").write_all()

        if args.reverse:
            rev_hops = engine.trace_reverse(args.src_ip, args.dst_ip)
            OutputWriter(src_ip=args.dst_ip, dst_ip=args.src_ip, hops=rev_hops,
                         out_dir=args.out_dir, run_id=run_id + "_rev").write_all()
    finally:
        engine.close_all()

    return 0


if __name__ == "__main__":
    sys.exit(main())
