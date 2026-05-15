"""
cisco_device_client.py
======================
Production-quality client for Cisco IOS, IOS-XE, and NX-OS devices.

Transports
----------
- CLI       : SSH via Netmiko
- RESTCONF  : HTTPS REST via requests + YANG
- NETCONF   : ncclient

Structured parsing (CLI)
------------------------
1. Genie / pyATS  (install ``pyats[full]`` or ``genie`` separately)
2. TextFSM via Netmiko + ntc-templates
3. Graceful fallback: ``{"raw": "...", "parsed": None, "parser": "none"}``
"""

from __future__ import annotations

import ipaddress
import json
import logging
import re
import warnings
from typing import Any, Dict, List, Optional, Tuple, Union

import requests
import xmltodict
from netmiko import ConnectHandler
from netmiko.exceptions import (
    NetmikoAuthenticationException,
    NetmikoTimeoutException,
)
from ncclient import manager as ncclient_manager
from ncclient.transport.errors import AuthenticationError as NcclientAuthError
from ncclient.transport.errors import SSHError as NcclientSSHError

# --------------------------------------------------------------------------- #
# Custom exceptions                                                            #
# --------------------------------------------------------------------------- #


class CiscoDeviceClientError(Exception):
    """Base exception for all CiscoDeviceClient errors."""


class AuthenticationError(CiscoDeviceClientError):
    """Raised when SSH or HTTP authentication fails."""


class TransportError(CiscoDeviceClientError):
    """Raised when a transport-level error occurs (timeout, unreachable, etc.)."""


# --------------------------------------------------------------------------- #
# OS-type → transport mappings                                                 #
# --------------------------------------------------------------------------- #

_NETMIKO_DEVICE_TYPES: Dict[str, str] = {
    "ios":   "cisco_ios",
    "iosxe": "cisco_xe",
    "nxos":  "cisco_nxos",
}

_NCCLIENT_DEVICE_PARAMS: Dict[str, Dict[str, str]] = {
    "iosxe": {"name": "iosxe"},
    "nxos":  {"name": "nexus"},
    "ios":   {"name": "csr"},
}

# Lookup table: (os_type, friendly_name) → YANG path segment used in RESTCONF.
# Callers may override any path by passing yang_path= to the public methods.
_RESTCONF_YANG_PATHS: Dict[Tuple[str, str], str] = {
    ("iosxe", "interfaces"):    "Cisco-IOS-XE-interfaces-oper:interfaces",
    ("iosxe", "running-config"): "Cisco-IOS-XE-native:native",
    ("iosxe", "version"):       "Cisco-IOS-XE-native:native/version",
    ("iosxe", "cdp-neighbors"): "Cisco-IOS-XE-cdp-oper:cdp-neighbor-details",
    ("nxos",  "interfaces"):    "Cisco-NX-OS-device:System/intf-items",
    ("nxos",  "running-config"): "Cisco-NX-OS-device:System",
    ("ios",   "interfaces"):    "ietf-interfaces:interfaces",
    ("ios",   "running-config"): "ietf-interfaces:interfaces",
    # VLAN operational data
    ("iosxe", "vlans"):         "Cisco-IOS-XE-vlan-oper:vlan-states",
}


# Automatic transport fallback order per OS type.
# IOS-XE mandate: NETCONF → RESTCONF → CLI (per project requirement).
_AUTO_TRANSPORT_ORDER: Dict[str, List[str]] = {
    "iosxe": ["netconf", "restconf", "cli"],
    "nxos":  ["cli"],
    "ios":   ["cli"],
}

# ---------------------------------------------------------------------------
# Speed / duplex normalisation helpers (module-level so they can be tested
# independently of the class).
# ---------------------------------------------------------------------------

# Matches an optional "a-" prefix (auto-negotiated), a number, and an
# optional SI unit prefix followed by optional "bit", "bps", or "b/s".
_SPEED_RE = re.compile(
    r"(?:a-)?(\d+(?:\.\d+)?)\s*(t|g|m|k)?(?:b(?:it|ps|\/s)?)?$",
    re.IGNORECASE,
)
_SPEED_UNIT_TO_KBPS: Dict[str, int] = {
    "k": 1,
    "m": 1_000,
    "g": 1_000_000,
    "t": 1_000_000_000,
}


def _parse_speed_string_kbps(raw: Any) -> Optional[int]:
    """
    Convert a human-readable speed value to a kbps integer.

    Handles formats such as ``"1000"``, ``"10G"``, ``"a-1000"``,
    ``"100 Mbps"``, ``"1 Gbps"``.  Returns ``None`` when the value is
    absent, ``"auto"``, or otherwise unparseable.

    The default unit when none is given is **Mbps** (matching the typical
    output of ``show interfaces status``).
    """
    if raw is None:
        return None
    s = str(raw).strip().lower().replace(",", "").replace(" ", "")
    if not s or s in ("auto", "unknown", "n/a", "-", "none", ""):
        return None
    if s.startswith("a-"):
        s = s[2:]
    m = _SPEED_RE.match(s)
    if not m:
        return None
    number = float(m.group(1))
    unit = (m.group(2) or "m")[0].lower()
    return int(number * _SPEED_UNIT_TO_KBPS.get(unit, 1_000))


def _normalize_duplex(raw: Any) -> Optional[str]:
    """
    Normalise a duplex string to ``"full"``, ``"half"``, ``"auto"``, or
    ``None``.

    Handles IOS/NX-OS variants such as ``"a-full"``, ``"full-duplex"``,
    ``"Full"``, ``"half"``, ``"auto"``, and YANG model values like
    ``"full-duplex"`` / ``"half-duplex"``.
    """
    if not raw:
        return None
    s = str(raw).strip().lower()
    if not s or s in ("unknown", "n/a", "-", "none", ""):
        return None
    if "full" in s:
        return "full"
    if "half" in s:
        return "half"
    return "auto"


# NETCONF XML filters for VLAN and IP/interface operational data.
_VLAN_NETCONF_FILTER: Dict[str, Optional[str]] = {
    "iosxe": (
        "<filter>"
        '<vlan-states xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-vlan-oper"/>'
        "</filter>"
    ),
    "nxos": None,   # NX-OS VLAN YANG varies; auto falls back to CLI
    "ios":  None,
}

_IP_NETCONF_FILTER: Dict[str, Optional[str]] = {
    "iosxe": (
        "<filter>"
        '<interfaces xmlns="urn:ietf:params:xml:ns:yang:ietf-interfaces"/>'
        "</filter>"
    ),
    "nxos": None,
    "ios":  None,
}


def _normalize_cisco_mac(mac: str) -> str:
    """
    Normalise a Cisco MAC address to lowercase colon-separated format.

    Handles all common representations:

    * Cisco dotted quad:  ``a1b2.c3d4.e5f6``  →  ``a1:b2:c3:d4:e5:f6``
    * Colon-separated:    ``A1:B2:C3:D4:E5:F6``  →  ``a1:b2:c3:d4:e5:f6``
    * Hyphen-separated:   ``a1-b2-c3-d4-e5-f6``  →  ``a1:b2:c3:d4:e5:f6``
    """
    stripped = mac.lower().replace(".", "").replace(":", "").replace("-", "")
    if len(stripped) != 12:
        return mac.lower()
    return ":".join(stripped[i:i+2] for i in range(0, 12, 2))


def _parse_vlan_range_string(s: str) -> List[int]:
    """
    Parse a VLAN range string (e.g. ``"1,10,20-30,100"``) to a sorted,
    deduplicated list of integers.  Returns ``[]`` for empty / unparseable
    input.
    """
    if not s or not str(s).strip():
        return []
    result: List[int] = []
    for part in str(s).split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            try:
                lo, hi = part.split("-", 1)
                result.extend(range(int(lo.strip()), int(hi.strip()) + 1))
            except (ValueError, TypeError):
                pass
        else:
            try:
                result.append(int(part))
            except (ValueError, TypeError):
                pass
    return sorted(set(result))


def _extract_vlan_from_iface_name(name: str) -> Optional[int]:
    """
    Infer a VLAN ID from an interface name.

    - SVI:          ``Vlan10``    → 10
    - Subinterface: ``Gi0/0.10`` → 10
    - Other:        ``None``
    """
    name_lower = name.lower()
    m = re.match(r"vlan\s*(\d+)", name_lower)
    if m:
        return int(m.group(1))
    m = re.search(r"\.(\d+)$", name)
    if m:
        return int(m.group(1))
    return None


# ---------------------------------------------------------------------------
# SVI running-config parsing helpers (module-level compile for efficiency)
# ---------------------------------------------------------------------------

# Matches the start of a Vlan interface block: "interface Vlan162"
_SVI_IFACE_HDR_RE = re.compile(r"^interface\s+[Vv]lan(\d+)\s*$", re.IGNORECASE)
# Matches any interface line (used to detect end-of-Vlan-block in full show run)
_ANY_IFACE_RE = re.compile(r"^interface\s+", re.IGNORECASE)
# IOS/IOS-XE: "  ip address 10.1.2.3 255.255.255.0 [secondary]"
_IP_MASK_RE = re.compile(
    r"^\s+ip\s+address\s+"
    r"((?:\d{1,3}\.){3}\d{1,3})\s+"
    r"((?:\d{1,3}\.){3}\d{1,3})"
    r"(?P<secondary>\s+secondary)?",
    re.IGNORECASE,
)
# NX-OS: "  ip address 10.1.2.3/24 [secondary]"
_IP_CIDR_RE = re.compile(
    r"^\s+ip\s+address\s+((?:\d{1,3}\.){3}\d{1,3}/\d{1,2})(?P<secondary>\s+secondary)?",
    re.IGNORECASE,
)

# --------------------------------------------------------------------------- #
# Main class                                                                   #
# --------------------------------------------------------------------------- #


class CiscoDeviceClient:
    """
    Unified client for Cisco IOS, IOS-XE, and NX-OS devices.

    All public ``show_*`` methods return a standardised dict::

        {
            "host":      str,
            "os_type":   str,
            "command":   str,          # CLI command or "restconf:…" / "netconf:…"
            "transport": str,          # "cli" | "restconf" | "netconf"
            "raw":       str,          # raw CLI output / JSON text / XML string
            "parsed":    dict|list|None,
            "parser":    str,          # "genie"|"textfsm"|"restconf"|"netconf"|"none"
        }

    When a parser is unavailable or fails the result is the graceful fallback::

        {"raw": "...", "parsed": None, "parser": "none"}

    Parameters
    ----------
    host : str
        Device hostname or IP address.
    username : str
        Login username.
    password : str
        Login password.
    os_type : str
        One of ``"ios"``, ``"iosxe"``, ``"nxos"``.
    enable_secret : str, optional
        Enable-mode password (IOS / IOS-XE only).
    port : int
        SSH port for CLI transport (default ``22``).
    timeout : int
        Connection and read timeout in seconds (default ``30``).
    verify_ssl : bool
        Verify TLS certificates for RESTCONF requests (default ``False``).
    restconf_port : int
        HTTPS port for RESTCONF (default ``443``).
    restconf_base : str
        Base path for RESTCONF (default ``"/restconf"``).
    netconf_port : int
        SSH port for NETCONF (default ``830``).
    log : logging.Logger, optional
        Caller-supplied logger; a module-level logger is used when omitted.
    """

    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        os_type: str,
        enable_secret: Optional[str] = None,
        port: int = 22,
        timeout: int = 30,
        verify_ssl: bool = False,
        restconf_port: int = 443,
        restconf_base: str = "/restconf",
        netconf_port: int = 830,
        log: Optional[logging.Logger] = None,
    ) -> None:
        os_type = os_type.lower()
        if os_type not in _NETMIKO_DEVICE_TYPES:
            raise ValueError(
                f"os_type must be one of {list(_NETMIKO_DEVICE_TYPES)!r}, got {os_type!r}"
            )

        self.host           = host
        self.username       = username
        self.password       = password
        self.os_type        = os_type
        self.enable_secret  = enable_secret
        self.port           = port
        self.timeout        = timeout
        self.verify_ssl     = verify_ssl
        self.restconf_port  = restconf_port
        self.restconf_base  = restconf_base.rstrip("/")
        self.netconf_port   = netconf_port
        self.log            = log or logging.getLogger(__name__)

        self._cli_connection: Optional[ConnectHandler] = None

        if not verify_ssl:
            warnings.filterwarnings("ignore", message="Unverified HTTPS request")

    # ----------------------------------------------------------------------- #
    # Public show_* methods                                                    #
    # ----------------------------------------------------------------------- #

    def show_run(
        self,
        transport: str = "cli",
        yang_path: Optional[str] = None,
    ) -> dict:
        """
        Retrieve the running configuration.

        Parameters
        ----------
        transport : str
            ``"cli"``, ``"restconf"``, or ``"netconf"``.
        yang_path : str, optional
            Override the default YANG path for RESTCONF.

        Returns
        -------
        dict
            Standardised result (see class docstring).
        """
        return self._dispatch(
            transport=transport,
            cli_cmd="show running-config",
            rc_name="running-config",
            yang_path=yang_path,
            nc_type="get-config",
            nc_filter=None,
        )

    def show_int(
        self,
        transport: str = "cli",
        yang_path: Optional[str] = None,
    ) -> dict:
        """
        Retrieve interface summary / operational state.

        Parameters
        ----------
        transport : str
            ``"cli"``, ``"restconf"``, or ``"netconf"``.
        yang_path : str, optional
            Override the default YANG path for RESTCONF.

        Returns
        -------
        dict
            Standardised result (see class docstring).
        """
        nc_filter = (
            "<filter>"
            '<interfaces xmlns="urn:ietf:params:xml:ns:yang:ietf-interfaces"/>'
            "</filter>"
        )
        return self._dispatch(
            transport=transport,
            cli_cmd="show interfaces",
            rc_name="interfaces",
            yang_path=yang_path,
            nc_type="get",
            nc_filter=nc_filter,
        )

    def show_ver(
        self,
        transport: str = "cli",
        yang_path: Optional[str] = None,
    ) -> dict:
        """
        Retrieve platform version information.

        Parameters
        ----------
        transport : str
            ``"cli"``, ``"restconf"``, or ``"netconf"``.
        yang_path : str, optional
            Override the default YANG path for RESTCONF.

        Returns
        -------
        dict
            Standardised result (see class docstring).
        """
        return self._dispatch(
            transport=transport,
            cli_cmd="show version",
            rc_name="version",
            yang_path=yang_path,
            nc_type="get",
            nc_filter=None,
        )

    def show_cdp_neighbors_detail(
        self,
        transport: str = "cli",
        yang_path: Optional[str] = None,
    ) -> dict:
        """
        Retrieve CDP neighbour detail.

        RESTCONF / NETCONF support is currently limited to IOS-XE.  On
        other platforms with those transports, ``parsed`` will be ``None``
        and ``parser`` will be ``"none"``.

        Parameters
        ----------
        transport : str
            ``"cli"``, ``"restconf"``, or ``"netconf"``.
        yang_path : str, optional
            Override the default YANG path for RESTCONF.

        Returns
        -------
        dict
            Standardised result (see class docstring).
        """
        nc_filter: Optional[str] = None
        if self.os_type == "iosxe":
            nc_filter = (
                "<filter>"
                '<cdp-neighbor-details xmlns="http://cisco.com/ns/yang/'
                'Cisco-IOS-XE-cdp-oper"/>'
                "</filter>"
            )
        return self._dispatch(
            transport=transport,
            cli_cmd="show cdp neighbors detail",
            rc_name="cdp-neighbors",
            yang_path=yang_path,
            nc_type="get",
            nc_filter=nc_filter,
        )

    # ----------------------------------------------------------------------- #
    # Internal dispatcher                                                      #
    # ----------------------------------------------------------------------- #

    def _dispatch(
        self,
        transport: str,
        cli_cmd: str,
        rc_name: str,
        yang_path: Optional[str],
        nc_type: str,
        nc_filter: Optional[str],
    ) -> dict:
        """Route a request to the correct transport implementation."""
        transport = transport.lower()

        if transport == "cli":
            raw, parsed, parser = self._cli_run_command(cli_cmd, parse=True)
            return self._build_result(cli_cmd, "cli", raw, parsed, parser)

        if transport == "restconf":
            path = yang_path or _RESTCONF_YANG_PATHS.get((self.os_type, rc_name))
            if not path:
                raise TransportError(
                    f"No RESTCONF YANG path defined for os_type={self.os_type!r}, "
                    f"name={rc_name!r}.  Pass yang_path= explicitly."
                )
            raw, parsed = self._restconf_get(path)
            return self._build_result(
                f"restconf:{rc_name}", "restconf", raw, parsed, "restconf"
            )

        if transport == "netconf":
            if nc_type == "get-config":
                raw, parsed = self._netconf_get_config(nc_filter)
                cmd_label = "netconf:get-config"
            else:
                raw, parsed = self._netconf_get(nc_filter)
                cmd_label = "netconf:get"
            return self._build_result(cmd_label, "netconf", raw, parsed, "netconf")

        raise TransportError(
            f"Unknown transport {transport!r}. Use 'cli', 'restconf', or 'netconf'."
        )

    # ----------------------------------------------------------------------- #
    # CLI helpers                                                              #
    # ----------------------------------------------------------------------- #

    def _cli_connect(self) -> None:
        """Open a persistent Netmiko SSH connection (no-op if already alive)."""
        if self._cli_connection and self._cli_connection.is_alive():
            return

        device_type = _NETMIKO_DEVICE_TYPES[self.os_type]
        params: Dict[str, Any] = {
            "device_type":     device_type,
            "host":            self.host,
            "username":        self.username,
            "password":        self.password,
            "port":            self.port,
            "timeout":         self.timeout,
            "session_timeout": self.timeout,
            "conn_timeout":    self.timeout,
            "auth_timeout":    self.timeout,
        }
        if self.enable_secret:
            params["secret"] = self.enable_secret

        self.log.debug(
            "CLI connect: %s@%s:%s [%s]",
            self.username, self.host, self.port, device_type,
        )
        try:
            self._cli_connection = ConnectHandler(**params)
            if self.enable_secret:
                self._cli_connection.enable()
        except NetmikoAuthenticationException as exc:
            raise AuthenticationError(
                f"SSH authentication failed for {self.host}: {exc}"
            ) from exc
        except NetmikoTimeoutException as exc:
            raise TransportError(
                f"SSH connection timed out to {self.host}: {exc}"
            ) from exc
        except Exception as exc:
            raise TransportError(
                f"SSH connection failed to {self.host}: {exc}"
            ) from exc

    def _cli_disconnect(self) -> None:
        """Close the Netmiko SSH connection if one is open."""
        if self._cli_connection:
            try:
                self._cli_connection.disconnect()
            except Exception:
                pass
            self._cli_connection = None

    def _cli_run_command(
        self,
        command: str,
        parse: bool = True,
    ) -> Tuple[str, Optional[Any], str]:
        """
        Execute a CLI command and attempt structured parsing.

        Parsing order: Genie → TextFSM → raw fallback.

        Parameters
        ----------
        command : str
            IOS / NX-OS CLI command string.
        parse : bool
            When ``False``, skip all parsing and return raw output only.

        Returns
        -------
        tuple
            ``(raw_output, parsed_output_or_None, parser_name)``
        """
        self._cli_connect()
        self.log.debug("CLI send_command: %r", command)
        try:
            raw: str = self._cli_connection.send_command(command)
        except Exception as exc:
            raise TransportError(
                f"Command {command!r} failed on {self.host}: {exc}"
            ) from exc

        if not parse:
            return raw, None, "none"

        parsed, parser = self._try_parse_genie(command, raw)
        if parsed is not None:
            return raw, parsed, parser

        parsed = self._try_parse_textfsm(command)
        if parsed is not None:
            return raw, parsed, "textfsm"

        return raw, None, "none"

    def _try_parse_genie(
        self,
        command: str,
        raw: str,
    ) -> Tuple[Optional[Any], str]:
        """
        Attempt to parse *raw* output with Genie.

        Genie is optional; this method silently skips if it is not installed.

        Parameters
        ----------
        command : str
            The CLI command that produced *raw*.
        raw : str
            Raw CLI output string.

        Returns
        -------
        tuple
            ``(parsed_dict_or_None, parser_label)``
        """
        try:
            from genie.libs.parser.utils import get_parser  # type: ignore[import]
            from genie.conf.base import Device as GenieDevice  # type: ignore[import]

            genie_os = self.os_type  # "ios" | "iosxe" | "nxos" match Genie names
            dev = GenieDevice(self.host, os=genie_os)
            parser_cls = get_parser(command, dev)
            result = parser_cls(device=dev)
            parsed = result.parse(output=raw)
            return parsed, "genie"
        except ModuleNotFoundError:
            self.log.debug("genie not installed; skipping Genie parsing")
        except Exception as exc:
            self.log.debug("Genie parse failed for %r: %s", command, exc)
        return None, "none"

    def _try_parse_textfsm(self, command: str) -> Optional[Any]:
        """
        Re-run *command* with ``use_textfsm=True`` to leverage ntc-templates.

        Netmiko returns the raw string unchanged when no template exists, so
        we check the return type to detect a successful parse.

        Parameters
        ----------
        command : str
            The CLI command to (re-)send.

        Returns
        -------
        list[dict] or None
            Parsed rows from TextFSM, or ``None`` if no template matched.
        """
        if self._cli_connection is None:
            return None
        try:
            result = self._cli_connection.send_command(command, use_textfsm=True)
            if isinstance(result, list):
                # Netmiko 4.x lowercases TextFSM Value names; normalise to
                # UPPERCASE so all extraction helpers work across every version.
                return [{k.upper(): v for k, v in row.items()} for row in result]
        except Exception as exc:
            self.log.debug("TextFSM parse failed for %r: %s", command, exc)
        return None

    # ----------------------------------------------------------------------- #
    # RESTCONF helpers                                                         #
    # ----------------------------------------------------------------------- #

    def _restconf_get(self, yang_path: str) -> Tuple[str, Optional[Any]]:
        """
        Perform an HTTP GET against the RESTCONF data store.

        Parameters
        ----------
        yang_path : str
            YANG path relative to ``{restconf_base}/data/``.

        Returns
        -------
        tuple
            ``(raw_response_text, parsed_json_or_None)``

        Raises
        ------
        AuthenticationError
            On HTTP 401.
        TransportError
            On connection error, timeout, or non-2xx response.
        """
        url = (
            f"https://{self.host}:{self.restconf_port}"
            f"{self.restconf_base}/data/{yang_path}"
        )
        headers = {
            "Accept":       "application/yang-data+json",
            "Content-Type": "application/yang-data+json",
        }
        self.log.debug("RESTCONF GET %s", url)
        try:
            resp = requests.get(
                url,
                auth=(self.username, self.password),
                headers=headers,
                verify=self.verify_ssl,
                timeout=self.timeout,
            )
        except requests.exceptions.ConnectionError as exc:
            raise TransportError(
                f"RESTCONF connection error to {self.host}: {exc}"
            ) from exc
        except requests.exceptions.Timeout as exc:
            raise TransportError(
                f"RESTCONF request timed out to {self.host}: {exc}"
            ) from exc

        if resp.status_code == 401:
            raise AuthenticationError(
                f"RESTCONF authentication failed for {self.host} (HTTP 401)"
            )
        if not resp.ok:
            raise TransportError(
                f"RESTCONF GET {url!r} returned HTTP {resp.status_code}: "
                f"{resp.text[:300]}"
            )

        raw = resp.text
        try:
            parsed = resp.json()
        except ValueError:
            parsed = None

        return raw, parsed

    # ----------------------------------------------------------------------- #
    # NETCONF helpers                                                          #
    # ----------------------------------------------------------------------- #

    def _netconf_connect(self):
        """
        Open a new ncclient manager connection.

        A fresh connection is opened each time; use as a context manager::

            with self._netconf_connect() as nc:
                nc.get_config(...)

        Raises
        ------
        AuthenticationError
            On NETCONF / SSH authentication failure.
        TransportError
            On SSH or other connection failure.
        """
        device_params = _NCCLIENT_DEVICE_PARAMS.get(
            self.os_type, {"name": "default"}
        )
        self.log.debug(
            "NETCONF connect: %s@%s:%s params=%s",
            self.username, self.host, self.netconf_port, device_params,
        )
        try:
            return ncclient_manager.connect(
                host=self.host,
                port=self.netconf_port,
                username=self.username,
                password=self.password,
                device_params=device_params,
                hostkey_verify=self.verify_ssl,
                timeout=self.timeout,
                look_for_keys=False,
                allow_agent=False,
            )
        except NcclientAuthError as exc:
            raise AuthenticationError(
                f"NETCONF authentication failed for {self.host}: {exc}"
            ) from exc
        except NcclientSSHError as exc:
            raise TransportError(
                f"NETCONF SSH error connecting to {self.host}: {exc}"
            ) from exc
        except Exception as exc:
            raise TransportError(
                f"NETCONF connection failed to {self.host}: {exc}"
            ) from exc

    def _netconf_get_config(
        self,
        filter_xml: Optional[str] = None,
    ) -> Tuple[str, Optional[Any]]:
        """
        Retrieve the running configuration via NETCONF ``<get-config>``.

        Parameters
        ----------
        filter_xml : str, optional
            XML subtree filter string.  ``None`` fetches the full config.

        Returns
        -------
        tuple
            ``(raw_xml_string, parsed_dict_or_None)``
        """
        nc_filter = ("subtree", filter_xml) if filter_xml else None
        with self._netconf_connect() as nc:
            try:
                response = nc.get_config(source="running", filter=nc_filter)
            except Exception as exc:
                raise TransportError(
                    f"NETCONF get-config failed on {self.host}: {exc}"
                ) from exc

        raw = str(response)
        return raw, self._xml_to_dict(raw)

    def _netconf_get(
        self,
        filter_xml: Optional[str] = None,
    ) -> Tuple[str, Optional[Any]]:
        """
        Retrieve operational state via NETCONF ``<get>``.

        Parameters
        ----------
        filter_xml : str, optional
            XML subtree filter string.  ``None`` fetches all operational data.

        Returns
        -------
        tuple
            ``(raw_xml_string, parsed_dict_or_None)``
        """
        nc_filter = ("subtree", filter_xml) if filter_xml else None
        with self._netconf_connect() as nc:
            try:
                response = nc.get(filter=nc_filter)
            except Exception as exc:
                raise TransportError(
                    f"NETCONF get failed on {self.host}: {exc}"
                ) from exc

        raw = str(response)
        return raw, self._xml_to_dict(raw)

    # ----------------------------------------------------------------------- #
    # Shared utilities                                                         #
    # ----------------------------------------------------------------------- #

    @staticmethod
    def _xml_to_dict(xml_str: str) -> Optional[dict]:
        """Convert an XML string to an ordered dict via xmltodict."""
        try:
            return xmltodict.parse(xml_str)
        except Exception:
            return None

    def _build_result(
        self,
        command: str,
        transport: str,
        raw: str,
        parsed: Optional[Any],
        parser: str,
    ) -> dict:
        """
        Assemble the standard result dict returned by all public methods.

        When *parsed* is ``None`` the parser label is forced to ``"none"``
        regardless of what was passed as *parser*.
        """
        return {
            "host":      self.host,
            "os_type":   self.os_type,
            "command":   command,
            "transport": transport,
            "raw":       raw,
            "parsed":    parsed,
            "parser":    parser if parsed is not None else "none",
        }

    # ----------------------------------------------------------------------- #
    # Interface inventory — normalised output                                  #
    # ----------------------------------------------------------------------- #

    def get_interfaces_inventory(self, transport: str = "cli") -> List[dict]:
        """
        Return a normalised interface inventory from the device.

        Each entry in the returned list::

            {
                "name":        str,
                "description": str | None,
                "speed_kbps":  int | None,   # kbps
                "duplex":      "full" | "half" | "auto" | None,
            }

        Parameters
        ----------
        transport : str
            ``"cli"``, ``"restconf"``, or ``"netconf"``.

        Returns
        -------
        list[dict]
        """
        transport = transport.lower()
        if transport == "cli":
            return self._inventory_via_cli()
        if transport == "restconf":
            result = self.show_int(transport="restconf")
            return self._extract_interfaces_restconf(result.get("parsed") or {})
        if transport == "netconf":
            result = self.show_int(transport="netconf")
            return self._extract_interfaces_netconf(result.get("parsed") or {})
        raise TransportError(
            f"Unknown transport {transport!r}. Use 'cli', 'restconf', or 'netconf'."
        )

    def get_interfaces_inventory_auto(self) -> dict:
        """
        Return a normalised interface inventory using automatic transport
        selection with a per-OS fallback chain.

        Fallback order
        --------------
        - ``iosxe`` : NETCONF → RESTCONF → CLI  (mandatory per project rules)
        - ``nxos``  : CLI
        - ``ios``   : CLI

        Returns
        -------
        dict::

            {
                "transport_used": str | None,
                "attempts": [
                    {"transport": str, "ok": bool, "error": str | None},
                    ...
                ],
                "interfaces": list[dict],
            }
        """
        order = _AUTO_TRANSPORT_ORDER.get(self.os_type, ["cli"])
        attempts: List[dict] = []
        interfaces: List[dict] = []
        transport_used: Optional[str] = None

        for transport in order:
            try:
                self.log.debug(
                    "auto-transport: trying %r for %s", transport, self.host
                )
                interfaces = self.get_interfaces_inventory(transport=transport)
                attempts.append({"transport": transport, "ok": True, "error": None})
                transport_used = transport
                break
            except Exception as exc:
                err = str(exc)
                self.log.warning(
                    "auto-transport: %r failed for %s: %s", transport, self.host, err
                )
                attempts.append({"transport": transport, "ok": False, "error": err})

        return {
            "transport_used": transport_used,
            "attempts":       attempts,
            "interfaces":     interfaces,
        }

    # ----------------------------------------------------------------------- #
    # Interface inventory — internal extraction helpers                        #
    # ----------------------------------------------------------------------- #

    def _inventory_via_cli(self) -> List[dict]:
        """Route CLI inventory collection to the correct OS-specific method."""
        if self.os_type == "nxos":
            return self._inventory_nxos_cli()
        return self._inventory_ios_cli()

    def _inventory_ios_cli(self) -> List[dict]:
        """
        Collect interface inventory from IOS / IOS-XE via CLI.

        Primary: ``show interfaces`` parsed by Genie or TextFSM.
        Fallback: ``show interfaces status`` + ``show interfaces description``.
        """
        raw, parsed, parser = self._cli_run_command("show interfaces", parse=True)

        if parser == "genie" and isinstance(parsed, dict):
            return self._extract_genie_show_int(parsed)

        if parser == "textfsm" and isinstance(parsed, list):
            return self._extract_textfsm_show_int(parsed)

        return self._inventory_ios_fallback()

    def _inventory_ios_fallback(self) -> List[dict]:
        """
        Best-effort IOS/IOS-XE fallback when ``show interfaces`` is unparseable.

        Attempts ``show interfaces status`` for speed/duplex, then merges
        descriptions from ``show interfaces description``.
        """
        inv: Dict[str, dict] = {}

        try:
            _, status_parsed, status_parser = self._cli_run_command(
                "show interfaces status", parse=True
            )
            if status_parser == "textfsm" and isinstance(status_parsed, list):
                for row in status_parsed:
                    name = row.get("PORT") or row.get("INTERFACE", "")
                    if not name:
                        continue
                    inv[name] = {
                        "name":        name,
                        "description": row.get("NAME") or row.get("DESCRIPTION") or None,
                        "speed_kbps":  _parse_speed_string_kbps(row.get("SPEED", "")),
                        "duplex":      _normalize_duplex(row.get("DUPLEX", "")),
                    }
        except Exception as exc:
            self.log.debug("show interfaces status fallback failed: %s", exc)

        try:
            _, desc_parsed, desc_parser = self._cli_run_command(
                "show interfaces description", parse=True
            )
            if desc_parser == "textfsm" and isinstance(desc_parsed, list):
                for row in desc_parsed:
                    name = row.get("PORT") or row.get("INTERFACE", "")
                    desc = row.get("DESCRIP") or row.get("DESCRIPTION") or ""
                    if not name:
                        continue
                    if name in inv:
                        if not inv[name]["description"]:
                            inv[name]["description"] = desc or None
                    else:
                        inv[name] = {
                            "name":        name,
                            "description": desc or None,
                            "speed_kbps":  None,
                            "duplex":      None,
                        }
        except Exception as exc:
            self.log.debug("show interfaces description fallback failed: %s", exc)

        if not inv:
            self.log.warning(
                "No structured interface data obtained for %s via CLI", self.host
            )
        return list(inv.values())

    def _inventory_nxos_cli(self) -> List[dict]:
        """
        Collect interface inventory from NX-OS via CLI.

        Primary: ``show interface status`` (TextFSM or Genie).
        """
        _, parsed, parser = self._cli_run_command(
            "show interface status", parse=True
        )

        if parser == "textfsm" and isinstance(parsed, list):
            result = []
            for row in parsed:
                name = row.get("PORT") or row.get("INTERFACE", "")
                if not name:
                    continue
                result.append({
                    "name":        name,
                    "description": row.get("NAME") or row.get("DESCRIPTION") or None,
                    "speed_kbps":  _parse_speed_string_kbps(row.get("SPEED", "")),
                    "duplex":      _normalize_duplex(row.get("DUPLEX", "")),
                })
            return result

        if parser == "genie" and isinstance(parsed, dict):
            return self._extract_genie_nxos_int_status(parsed)

        self.log.warning(
            "NX-OS: no structured interface data for %s — returning empty list",
            self.host,
        )
        return []

    def _extract_genie_show_int(self, parsed: dict) -> List[dict]:
        """
        Build inventory from Genie ``show interfaces`` output.

        Genie uses ``bandwidth`` (kbps) and ``duplex_mode`` for IOS/IOS-XE.
        """
        result = []
        for name, data in parsed.items():
            if not isinstance(data, dict):
                continue
            bw = data.get("bandwidth")
            speed_kbps = int(bw) if isinstance(bw, (int, float)) and bw > 0 else None
            result.append({
                "name":        name,
                "description": data.get("description") or None,
                "speed_kbps":  speed_kbps,
                "duplex":      _normalize_duplex(data.get("duplex_mode", "")),
            })
        return result

    def _extract_genie_nxos_int_status(self, parsed: dict) -> List[dict]:
        """Build inventory from Genie NX-OS ``show interface status`` output."""
        result = []
        # Genie may nest under "interfaces" or expose as top-level interface keys.
        interfaces = (
            parsed.get("interfaces")
            or parsed.get("interface")
            or parsed
        )
        if not isinstance(interfaces, dict):
            return result
        for name, data in interfaces.items():
            if not isinstance(data, dict):
                continue
            speed_raw = (
                data.get("port_speed")
                or data.get("speed")
                or data.get("bandwidth", "")
            )
            result.append({
                "name":        name,
                "description": data.get("description") or data.get("name") or None,
                "speed_kbps":  _parse_speed_string_kbps(speed_raw),
                "duplex":      _normalize_duplex(data.get("duplex", "")),
            })
        return result

    def _extract_textfsm_show_int(self, parsed: list) -> List[dict]:
        """Build inventory from TextFSM ``show interfaces`` rows (ntc-templates)."""
        result = []
        for row in parsed:
            name = row.get("INTERFACE", "")
            if not name:
                continue
            result.append({
                "name":        name,
                "description": row.get("DESCRIPTION") or None,
                "speed_kbps":  _parse_speed_string_kbps(
                    row.get("SPEED") or row.get("BANDWIDTH", "")
                ),
                "duplex":      _normalize_duplex(row.get("DUPLEX", "")),
            })
        return result

    def _extract_interfaces_restconf(self, parsed: dict) -> List[dict]:
        """
        Build inventory from a RESTCONF YANG-JSON response.

        Navigates past the YANG module wrapper key to find the interface list.
        RESTCONF operational speed values are in **bps** and are converted
        to kbps by dividing by 1000.
        """
        if not parsed:
            return []
        # The outer key is the YANG module name; find the dict that contains
        # an "interface" list regardless of the module prefix.
        iface_list: Optional[List[dict]] = None
        for val in parsed.values():
            if isinstance(val, dict) and "interface" in val:
                iface_list = val["interface"]
                break
            if isinstance(val, list):
                iface_list = val
                break
        if iface_list is None:
            return []
        if isinstance(iface_list, dict):
            iface_list = [iface_list]

        result = []
        for iface in iface_list:
            if not isinstance(iface, dict):
                continue
            speed_raw = iface.get("speed") or iface.get("bandwidth")
            if isinstance(speed_raw, (int, float)) and speed_raw > 0:
                # RESTCONF oper speed is reported in bps.
                speed_kbps: Optional[int] = int(speed_raw) // 1000
            else:
                speed_kbps = _parse_speed_string_kbps(speed_raw)

            duplex_raw = (
                iface.get("duplex")
                or iface.get("duplex-mode")
                or iface.get("negotiated-duplex-mode", "")
            )
            name = iface.get("name", "")
            if not name:
                continue
            result.append({
                "name":        name,
                "description": iface.get("description") or None,
                "speed_kbps":  speed_kbps,
                "duplex":      _normalize_duplex(duplex_raw),
            })
        return result

    def _extract_interfaces_netconf(self, parsed: dict) -> List[dict]:
        """
        Build inventory from an xmltodict-parsed NETCONF response.

        Walks the dict recursively to find an interface list using common
        YANG path patterns (ietf-interfaces, Cisco-IOS-XE-interfaces-oper,
        NX-OS).

        Speed heuristic: values > 10,000,000 are treated as **bps** and
        converted to kbps; smaller values are assumed to already be kbps.
        """
        if not parsed:
            return []
        iface_list = self._dig_netconf_interface_list(parsed)
        if not iface_list:
            return []

        result = []
        for iface in iface_list:
            if not isinstance(iface, dict):
                continue
            name = (
                iface.get("name")
                or iface.get("intf-name")
                or iface.get("if-name", "")
            )
            if not name:
                continue

            speed_raw = (
                iface.get("speed")
                or iface.get("bandwidth")
                or iface.get("speed-kbps")
            )
            speed_kbps: Optional[int] = None
            if speed_raw is not None:
                try:
                    v = int(speed_raw)
                    speed_kbps = v // 1000 if v > 10_000_000 else v
                except (ValueError, TypeError):
                    speed_kbps = _parse_speed_string_kbps(speed_raw)

            duplex_raw = (
                iface.get("duplex")
                or iface.get("duplex-mode")
                or iface.get("negotiated-duplex-mode", "")
            )
            result.append({
                "name":        str(name),
                "description": iface.get("description") or None,
                "speed_kbps":  speed_kbps,
                "duplex":      _normalize_duplex(duplex_raw),
            })
        return result

    def _dig_netconf_interface_list(
        self, d: Any, _depth: int = 0
    ) -> Optional[List[dict]]:
        """
        Recursively search a parsed NETCONF dict for a list of interface dicts.

        Strips YANG module prefixes from key names (e.g.
        ``"Cisco-IOS-XE-interfaces-oper:interfaces"`` → ``"interfaces"``).
        Stops at recursion depth 8 to avoid runaway searches.
        """
        if _depth > 8 or not isinstance(d, dict):
            return None
        for key, val in d.items():
            bare_key = key.lower().split(":")[-1]
            if bare_key in ("interface", "interfaces"):
                if isinstance(val, list) and val and isinstance(val[0], dict):
                    return val
                if isinstance(val, dict):
                    if "name" in val:
                        # Single interface returned as a dict rather than a list.
                        return [val]
                    sub = self._dig_netconf_interface_list(val, _depth + 1)
                    if sub:
                        return sub
            if isinstance(val, dict):
                sub = self._dig_netconf_interface_list(val, _depth + 1)
                if sub:
                    return sub
        return None

    # ----------------------------------------------------------------------- #
    # VLAN inventory                                                           #
    # ----------------------------------------------------------------------- #

    def get_vlans_inventory(self, transport: str = "auto") -> List[dict]:
        """
        Return a normalised VLAN list from the device.

        Each entry::

            {"vid": int, "name": str|None, "status": str|None}

        VLAN 1 is included — the caller is responsible for filtering it.

        Parameters
        ----------
        transport : str
            ``"cli"``, ``"restconf"``, ``"netconf"``, or ``"auto"``.
            In auto mode the per-OS fallback chain is applied.

        Returns
        -------
        list[dict]
        """
        if transport == "auto":
            return self._auto_collect(self._vlans_via_transport)
        return self._vlans_via_transport(transport)

    def _vlans_via_transport(self, transport: str) -> List[dict]:
        """Dispatch VLAN collection to the named transport."""
        if transport == "cli":
            return self._vlans_via_cli()
        if transport == "netconf":
            nc_filter = _VLAN_NETCONF_FILTER.get(self.os_type)
            if not nc_filter:
                raise TransportError(
                    f"No VLAN NETCONF filter for os_type={self.os_type!r} — try cli"
                )
            _, parsed = self._netconf_get(nc_filter)
            return self._extract_vlans_from_netconf(parsed or {})
        if transport == "restconf":
            yang_path = _RESTCONF_YANG_PATHS.get((self.os_type, "vlans"))
            if not yang_path:
                raise TransportError(
                    f"No RESTCONF YANG path for VLANs on os_type={self.os_type!r}"
                )
            _, parsed = self._restconf_get(yang_path)
            return self._extract_vlans_from_restconf(parsed or {})
        raise TransportError(f"Unknown transport {transport!r}.")

    def _vlans_via_cli(self) -> List[dict]:
        """
        Collect the VLAN table via CLI.

        Command order
        -------------
        NX-OS  : ``show vlan`` only.
        IOS/XE : ``show vlan brief`` first; falls back to ``show vlan`` when
                 the brief form returns an empty table (rare on older images).

        Parser waterfall per command
        ----------------------------
        1. Genie (if installed)
        2. TextFSM / ntc-templates (keys are uppercase-normalised; see
           ``_try_parse_textfsm``)
        3. Regex raw-text parser (``_parse_vlans_raw``)

        If every method yields 0 VLANs an ERROR is logged and ``[]`` is
        returned so the caller layer can decide how to proceed.
        """
        if self.os_type == "nxos":
            cmds = ["show vlan"]
        else:
            cmds = ["show vlan brief", "show vlan"]   # brief preferred, full as backup

        for cmd in cmds:
            raw, parsed, parser = self._cli_run_command(cmd, parse=True)

            self.log.debug(
                "%s: %r returned %d chars (parser=%r).  Preview: %s",
                self.host, cmd, len(raw or ""),
                parser, (raw or "")[:120].replace("\n", "\\n"),
            )

            if not raw or not raw.strip():
                self.log.debug("%s: %r returned empty output — trying next command", self.host, cmd)
                continue

            # ── Genie ──────────────────────────────────────────────────────
            if parser == "genie" and isinstance(parsed, dict):
                result = self._extract_genie_vlans(parsed)
                if result:
                    self.log.debug(
                        "%s: Parsed %d VLANs from %s (%s via Genie). First 5: %s",
                        self.host, len(result), self.os_type, cmd, result[:5],
                    )
                    return result
                self.log.debug(
                    "%s: Genie returned 0 VLANs for %r — falling through", self.host, cmd
                )

            # ── TextFSM ─────────────────────────────────────────────────────
            if parser == "textfsm" and isinstance(parsed, list):
                result = self._extract_textfsm_vlans(parsed)
                if result:
                    self.log.debug(
                        "%s: Parsed %d VLANs from %s (%s via TextFSM). First 5: %s",
                        self.host, len(result), self.os_type, cmd, result[:5],
                    )
                    return result
                self.log.debug(
                    "%s: TextFSM yielded %d rows but 0 extracted for %r — "
                    "falling through to raw parse",
                    self.host, len(parsed), cmd,
                )

            # ── Regex raw-text fallback ──────────────────────────────────────
            result = self._parse_vlans_raw(raw)
            if result:
                self.log.debug(
                    "%s: Parsed %d VLANs from %s via raw-text regex. First 5: %s",
                    self.host, len(result), cmd, result[:5],
                )
                return result

            self.log.debug(
                "%s: All parsers returned 0 VLANs for %r — trying next command",
                self.host, cmd,
            )

        self.log.error(
            "%s: VLAN parse failure on %s — all commands and parsers returned empty list.",
            self.host, self.os_type,
        )
        return []

    def _extract_genie_vlans(self, parsed: dict) -> List[dict]:
        """Extract VLANs from Genie ``show vlan brief`` output."""
        result = []
        vlans_data = parsed.get("vlans", parsed)
        for vid_str, data in vlans_data.items():
            if not isinstance(data, dict):
                continue
            try:
                vid = int(vid_str)
            except (ValueError, TypeError):
                continue
            result.append({
                "vid":    vid,
                "name":   data.get("name") or None,
                "status": data.get("state") or data.get("status") or None,
            })
        return result

    def _extract_textfsm_vlans(self, parsed: list) -> List[dict]:
        """
        Extract VLANs from TextFSM ``show vlan brief`` rows.

        Keys are checked in both UPPERCASE (post-normalisation by
        ``_try_parse_textfsm``) and lowercase (raw Netmiko 4.x output)
        so the method is robust regardless of which layer calls it.

        ntc-templates field names accepted: ``VLAN_ID``, ``VLAN``,
        ``NAME``, ``VLAN_NAME``, ``STATUS``, ``STATE``.
        """
        result = []
        for row in parsed:
            vid_str = (
                row.get("VLAN_ID") or row.get("vlan_id")
                or row.get("VLAN")  or row.get("vlan", "")
            )
            if not vid_str:
                self.log.debug(
                    "TextFSM VLAN row has no VID field; available keys: %s",
                    list(row.keys())[:10],
                )
                continue
            try:
                vid = int(str(vid_str).strip())
            except (ValueError, TypeError):
                continue
            name = (
                row.get("NAME")      or row.get("name")
                or row.get("VLAN_NAME") or row.get("vlan_name")
            ) or None
            status = (
                row.get("STATUS") or row.get("status")
                or row.get("STATE")  or row.get("state")
            ) or None
            result.append({"vid": vid, "name": name, "status": status})
        return result

    def _extract_vlans_from_netconf(self, parsed: dict) -> List[dict]:
        """Best-effort VLAN extraction from an xmltodict NETCONF response."""
        result = []
        vlan_list = self._dig_key(parsed, {"vlan-states", "vlan-state", "vlans", "vlan"})
        if isinstance(vlan_list, dict):
            vlan_list = [vlan_list]
        if not isinstance(vlan_list, list):
            return result
        for entry in vlan_list:
            if not isinstance(entry, dict):
                continue
            vid_raw = entry.get("id") or entry.get("vlan-id") or entry.get("vid")
            if vid_raw is None:
                continue
            try:
                vid = int(vid_raw)
            except (ValueError, TypeError):
                continue
            result.append({
                "vid":    vid,
                "name":   entry.get("name") or None,
                "status": entry.get("status") or entry.get("state") or None,
            })
        return result

    def _extract_vlans_from_restconf(self, parsed: dict) -> List[dict]:
        """Best-effort VLAN extraction from a RESTCONF YANG-JSON response."""
        result = []
        for top_val in parsed.values():
            if not isinstance(top_val, dict):
                continue
            for k, v in top_val.items():
                if "vlan" in k.lower() and isinstance(v, list):
                    for entry in v:
                        vid_raw = entry.get("id") or entry.get("vlan-id")
                        if vid_raw is None:
                            continue
                        try:
                            vid = int(vid_raw)
                        except (ValueError, TypeError):
                            continue
                        result.append({
                            "vid":    vid,
                            "name":   entry.get("name") or None,
                            "status": entry.get("status") or None,
                        })
                    break
        return result

    # Pre-compiled once at class level so it is not rebuilt on every call.
    _VLAN_LINE_RE = re.compile(
        r"^\s*(\d{1,4})"          # group 1: VLAN ID (1–4 digits)
        r"\s+(\S+)"               # group 2: name   (no spaces in IOS VLAN names)
        r"(?:\s+(\S+))?"          # group 3: status (optional — e.g. act/unsup)
    )

    def _parse_vlans_raw(self, raw: str) -> List[dict]:
        """
        Regex-based last-resort VLAN parser for IOS / IOS-XE / NX-OS.

        Matches any line whose first token is a 1–4 digit integer (the VLAN
        ID).  Header lines (``VLAN``, ``----``) and port-list continuation
        lines (leading spaces followed by interface names) are naturally
        rejected because they cannot start with a numeric token.

        Handles:
        - Status strings that contain ``/`` such as ``act/unsup``
        - Lines with or without a trailing port list
        - Lines that have no status column (very old IOS images)
        """
        result = []
        for line in raw.splitlines():
            m = self._VLAN_LINE_RE.match(line)
            if not m:
                continue
            vid_str, name, status = m.group(1), m.group(2), m.group(3)
            try:
                vid = int(vid_str)
            except ValueError:
                continue
            result.append({
                "vid":    vid,
                "name":   name if name not in ("----", "---") else None,
                "status": status or None,
            })
        return result

    # ----------------------------------------------------------------------- #
    # Trunk interface inventory                                                #
    # ----------------------------------------------------------------------- #

    def get_trunk_interfaces_inventory(self, transport: str = "auto") -> List[dict]:
        """
        Return trunk interface details from the device.

        Each entry::

            {
                "name":          str,
                "mode":          "trunk" | "access" | "unknown",
                "native_vlan":   int | None,
                "allowed_vlans": list[int],   # caller filters VLAN 1
            }

        Parameters
        ----------
        transport : str
            ``"cli"``, ``"restconf"``, ``"netconf"``, or ``"auto"``.

        Returns
        -------
        list[dict]
        """
        if transport == "auto":
            return self._auto_collect(self._trunk_via_transport)
        return self._trunk_via_transport(transport)

    def _trunk_via_transport(self, transport: str) -> List[dict]:
        """
        Dispatch trunk collection.

        NETCONF and RESTCONF switchport/trunk YANG data is highly
        platform-specific; both fall through to CLI for reliability.
        """
        if transport in ("netconf", "restconf"):
            self.log.debug(
                "Trunk inventory: %r not directly supported — using CLI", transport
            )
            return self._trunk_via_cli()
        if transport == "cli":
            return self._trunk_via_cli()
        raise TransportError(f"Unknown transport {transport!r}.")

    def _trunk_via_cli(self) -> List[dict]:
        """Route CLI trunk collection to the correct OS implementation."""
        if self.os_type == "nxos":
            return self._trunk_nxos_cli()
        return self._trunk_ios_cli()

    def _trunk_ios_cli(self) -> List[dict]:
        """Collect trunk interfaces from IOS / IOS-XE via ``show interfaces trunk``."""
        raw, parsed, parser = self._cli_run_command(
            "show interfaces trunk", parse=True
        )
        if parser == "genie" and isinstance(parsed, dict):
            return self._extract_genie_trunk(parsed)
        if parser == "textfsm" and isinstance(parsed, list):
            return self._extract_textfsm_trunk(parsed)
        return self._parse_trunk_raw_ios(raw)

    def _trunk_nxos_cli(self) -> List[dict]:
        """Collect trunk interfaces from NX-OS via ``show interface trunk``."""
        raw, parsed, parser = self._cli_run_command(
            "show interface trunk", parse=True
        )
        if parser == "genie" and isinstance(parsed, dict):
            return self._extract_genie_trunk(parsed)
        if parser == "textfsm" and isinstance(parsed, list):
            return self._extract_textfsm_trunk(parsed)
        # Genie / TextFSM unavailable — fall back to direct text parsing
        return self._parse_trunk_raw_nxos(raw)

    def _parse_trunk_raw_nxos(self, raw: str) -> List[dict]:
        """
        Parse NX-OS ``show interface trunk`` tabular output.

        NX-OS uses a single flat table (no multi-section layout like IOS)::

            Port        Type          Trunk_Status  Native_VLAN  Allowed_VLANs
            ------------------------------------------------------------------
            Eth1/5      Ethernet      trunk         999          1-4094
            Eth1/19     Ethernet      trunk         666          4,52,54,56,58
            Po1         Port-Channel  trunk         1            1-4094
            Po132       Port-Channel  trunk         999          4,52,54,56,58,999,3002

        Only rows whose ``Trunk_Status`` column equals ``trunk`` are returned.
        The interface name is expanded to its canonical long form
        (``Eth1/5`` → ``Ethernet1/5``, ``Po1`` → ``Port-channel1``).

        Returns
        -------
        list[dict]
            Each entry: ``{name, mode, native_vlan, allowed_vlans}``
        """
        result: List[dict] = []
        raw = raw.replace("\r\n", "\n").replace("\r", "\n")

        for line in raw.splitlines():
            stripped = line.strip()
            # Skip blank lines, separator lines (---), and the header row
            if not stripped or stripped.startswith("-"):
                continue
            parts = stripped.split()
            if len(parts) < 5:
                continue
            # Header row: first token is literally "Port"
            if parts[0].lower() == "port":
                continue

            port         = parts[0]
            trunk_status = parts[2].lower()
            native_raw   = parts[3]
            allowed_raw  = parts[4]

            if trunk_status != "trunk":
                continue

            native: Optional[int] = None
            try:
                v = int(native_raw)
                if 1 <= v <= 4094:
                    native = v
            except (ValueError, TypeError):
                pass

            iface_name = self._expand_iface(port)
            allowed    = _parse_vlan_range_string(allowed_raw)

            self.log.debug(
                "%s: NX-OS trunk  %-30s  native=%-4s  allowed=%d VID(s)",
                self.host, iface_name, native, len(allowed),
            )
            result.append({
                "name":          iface_name,
                "mode":          "trunk",
                "native_vlan":   native,
                "allowed_vlans": allowed,
            })

        return result

    def _extract_genie_trunk(self, parsed: dict) -> List[dict]:
        """
        Extract trunk details from Genie trunk output.

        Genie schema: top-level ``"interface"`` dict keyed by interface name.
        Active VLAN list prefers ``vlans_allowed_active_in_mgmt_domain`` over
        the full configured range.
        """
        result = []
        interfaces = parsed.get("interface", parsed)
        for name, data in interfaces.items():
            if not isinstance(data, dict):
                continue
            native = None
            try:
                nv = data.get("native_vlan") or data.get("native_vlan_id")
                if nv is not None:
                    native = int(nv)
            except (ValueError, TypeError):
                pass
            allowed_raw = (
                data.get("vlans_allowed_active_in_mgmt_domain")
                or data.get("trunking_vlans")
                or data.get("vlans_allowed_on_trunk", "")
            )
            if isinstance(allowed_raw, list):
                # Genie sometimes gives a list of range strings
                allowed = []
                for part in allowed_raw:
                    allowed.extend(_parse_vlan_range_string(str(part)))
            else:
                allowed = _parse_vlan_range_string(str(allowed_raw))
            result.append({
                "name":          name,
                "mode":          "trunk",
                "native_vlan":   native,
                "allowed_vlans": allowed,
            })
        return result

    def _extract_textfsm_trunk(self, parsed: list) -> List[dict]:
        """
        Extract trunk details from TextFSM ``show interfaces trunk`` rows.

        Prefers ``VLANS_ALLOWED_ACTIVE`` (active in mgmt domain) over the
        full configured allowed list.
        """
        result = []
        for row in parsed:
            name = row.get("PORT") or row.get("INTERFACE", "")
            if not name:
                continue
            native = None
            try:
                nv = row.get("NATIVE_VLAN", "")
                if nv and nv not in ("", "-", "none"):
                    native = int(nv)
            except (ValueError, TypeError):
                pass
            vlans_str = (
                row.get("VLANS_ALLOWED_ACTIVE")
                or row.get("VLANS_ALLOWED_AND_ACTIVE")
                or row.get("VLANS_ALLOWED", "")
            )
            result.append({
                "name":          name,
                "mode":          "trunk",
                "native_vlan":   native,
                "allowed_vlans": _parse_vlan_range_string(vlans_str),
            })
        return result

    def _parse_trunk_raw_ios(self, raw: str) -> List[dict]:
        """Last-resort raw-text trunk parsing for IOS / IOS-XE."""
        interfaces: Dict[str, dict] = {}
        section = ""
        for line in raw.splitlines():
            line_s = line.strip()
            if "Mode" in line_s and "Encapsulation" in line_s:
                section = "header"
                continue
            if "Vlans allowed and active" in line_s:
                section = "active"
                continue
            if "Vlans allowed on trunk" in line_s:
                section = "allowed"
                continue
            if "Vlans in spanning tree" in line_s:
                section = "stp"
                continue
            if not line_s or line_s.startswith("-"):
                continue
            parts = line_s.split()
            if not parts:
                continue
            iface = parts[0]
            if section == "header" and len(parts) >= 5:
                native = None
                try:
                    native = int(parts[4])
                except (ValueError, TypeError, IndexError):
                    pass
                interfaces.setdefault(iface, {
                    "name": iface, "mode": "trunk",
                    "native_vlan": native, "allowed_vlans": [],
                })
            elif section == "active" and iface in interfaces:
                vlans_str = parts[1] if len(parts) > 1 else ""
                interfaces[iface]["allowed_vlans"] = _parse_vlan_range_string(vlans_str)
        return list(interfaces.values())

    # ----------------------------------------------------------------------- #
    # Interface IP inventory                                                   #
    # ----------------------------------------------------------------------- #

    def get_interface_ip_inventory(self, transport: str = "auto") -> List[dict]:
        """
        Return interface IP addresses with prefix lengths.

        Each entry::

            {
                "name":  str,
                "ip":    "x.x.x.x/prefix_len" | None,
                "vlan":  int | None,  # inferred from SVI name or subinterface encapsulation
            }

        Parameters
        ----------
        transport : str
            ``"cli"``, ``"restconf"``, ``"netconf"``, or ``"auto"``.

        Returns
        -------
        list[dict]
        """
        if transport == "auto":
            return self._auto_collect(self._ip_via_transport)
        return self._ip_via_transport(transport)

    def _ip_via_transport(self, transport: str) -> List[dict]:
        """Dispatch IP inventory to the named transport."""
        if transport == "cli":
            return self._ip_via_cli()
        if transport == "netconf":
            nc_filter = _IP_NETCONF_FILTER.get(self.os_type)
            if not nc_filter:
                raise TransportError(
                    f"No IP NETCONF filter for os_type={self.os_type!r}"
                )
            _, parsed = self._netconf_get(nc_filter)
            return self._extract_ip_from_netconf(parsed or {})
        if transport == "restconf":
            yang_path = _RESTCONF_YANG_PATHS.get((self.os_type, "interfaces"))
            if not yang_path:
                raise TransportError(
                    f"No RESTCONF YANG path for interfaces on os_type={self.os_type!r}"
                )
            _, parsed = self._restconf_get(yang_path)
            return self._extract_ip_from_restconf(parsed or {})
        raise TransportError(f"Unknown transport {transport!r}.")

    def _ip_via_cli(self) -> List[dict]:
        """Route CLI IP inventory to the correct OS implementation."""
        if self.os_type == "nxos":
            return self._ip_nxos_cli()
        return self._ip_ios_cli()

    def _ip_ios_cli(self) -> List[dict]:
        """
        Collect interface IPs from IOS / IOS-XE.

        Attempts in order:
        1. ``show interfaces``    via Genie  (gives IP + prefix in ``ipv4`` key)
        2. ``show ip interface``  via Genie  (detailed, includes prefix length)
        3. ``show ip interface brief``  via TextFSM  (IP only, no prefix length)
        """
        raw, parsed, parser = self._cli_run_command("show interfaces", parse=True)
        if parser == "genie" and isinstance(parsed, dict):
            return self._extract_ip_from_genie_show_int(parsed)

        raw2, parsed2, parser2 = self._cli_run_command("show ip interface", parse=True)
        if parser2 == "genie" and isinstance(parsed2, dict):
            return self._extract_ip_from_genie_ip_int(parsed2)

        raw3, parsed3, parser3 = self._cli_run_command(
            "show ip interface brief", parse=True
        )
        if parser3 == "textfsm" and isinstance(parsed3, list):
            return self._extract_ip_from_textfsm_brief(parsed3)
        return []

    def _ip_nxos_cli(self) -> List[dict]:
        """Collect interface IPs from NX-OS."""
        raw, parsed, parser = self._cli_run_command(
            "show ip interface brief", parse=True
        )
        if parser == "textfsm" and isinstance(parsed, list):
            return self._extract_ip_from_textfsm_brief(parsed)
        if parser == "genie" and isinstance(parsed, dict):
            return self._extract_ip_from_genie_show_int(parsed)
        return []

    def _extract_ip_from_genie_show_int(self, parsed: dict) -> List[dict]:
        """
        Extract IPs from Genie ``show interfaces`` output.

        Genie places IPv4 info under ``interface["ipv4"]`` as a dict keyed
        by ``"x.x.x.x/n"`` where each value carries a ``"secondary"`` flag.
        """
        result = []
        for name, data in parsed.items():
            if not isinstance(data, dict):
                continue
            ip_cidr: Optional[str] = None
            ipv4 = data.get("ipv4", {})
            if isinstance(ipv4, dict):
                for ip_key, ip_info in ipv4.items():
                    if isinstance(ip_info, dict) and not ip_info.get("secondary"):
                        ip_cidr = ip_key   # already "x.x.x.x/24"
                        break
            result.append({
                "name": name,
                "ip":   ip_cidr,
                "vlan": _extract_vlan_from_iface_name(name),
            })
        return result

    def _extract_ip_from_genie_ip_int(self, parsed: dict) -> List[dict]:
        """
        Extract IPs from Genie ``show ip interface`` output.

        Genie schema: ``{iface: {"ipv4": {"x.x.x.x": {"prefix_length": "n"}}}}``.
        """
        result = []
        for name, data in parsed.items():
            if not isinstance(data, dict):
                continue
            ip_cidr: Optional[str] = None
            ipv4 = data.get("ipv4", {})
            if isinstance(ipv4, dict):
                for ip_addr, ip_info in ipv4.items():
                    if isinstance(ip_info, dict):
                        pfx = ip_info.get("prefix_length", "")
                        ip_cidr = f"{ip_addr}/{pfx}" if pfx else ip_addr
                        break
            result.append({
                "name": name,
                "ip":   ip_cidr,
                "vlan": _extract_vlan_from_iface_name(name),
            })
        return result

    def _extract_ip_from_textfsm_brief(self, parsed: list) -> List[dict]:
        """
        Extract IPs from TextFSM ``show ip interface brief`` rows.

        Note: this template does not carry prefix length; ``ip`` will be
        a bare address string (e.g. ``"10.0.0.1"``) without CIDR notation.
        """
        result = []
        for row in parsed:
            name = row.get("INTF") or row.get("INTERFACE", "")
            ip = row.get("IPADDR") or row.get("IP_ADDRESS") or row.get("IPADDRESS", "")
            if not name:
                continue
            ip_cidr = (
                ip.strip()
                if ip and ip.strip() not in ("unassigned", "-", "", "none")
                else None
            )
            result.append({
                "name": name,
                "ip":   ip_cidr,
                "vlan": _extract_vlan_from_iface_name(name),
            })
        return result

    def _extract_ip_from_restconf(self, parsed: dict) -> List[dict]:
        """
        Extract IPs from a RESTCONF YANG-JSON interface response.

        Supports the Cisco IOS-XE oper model (``ipv4.ip-address`` +
        ``ipv4.subnet-mask``) and the IETF interfaces model
        (``ietf-ip:ipv4.address[].{ip, prefix-length}``).
        """
        if not parsed:
            return []
        iface_list: List[dict] = []
        for val in parsed.values():
            if isinstance(val, dict) and "interface" in val:
                raw_ifaces = val["interface"]
                iface_list = [raw_ifaces] if isinstance(raw_ifaces, dict) else raw_ifaces
                break
        result = []
        for iface in iface_list:
            if not isinstance(iface, dict):
                continue
            name = iface.get("name", "")
            if not name:
                continue
            ip_cidr: Optional[str] = None
            # Cisco IOS-XE oper: ipv4.ip-address + ipv4.subnet-mask
            ipv4_oper = iface.get("ipv4")
            if isinstance(ipv4_oper, dict):
                addr = ipv4_oper.get("ip-address")
                mask = ipv4_oper.get("subnet-mask")
                if addr and mask:
                    try:
                        pfx = ipaddress.IPv4Network(
                            f"0.0.0.0/{mask}", strict=False
                        ).prefixlen
                        ip_cidr = f"{addr}/{pfx}"
                    except ValueError:
                        ip_cidr = addr
            # IETF interfaces: ietf-ip:ipv4.address[].{ip, prefix-length}
            if not ip_cidr:
                for key in ("ietf-ip:ipv4", "ipv4"):
                    ipv4_data = iface.get(key, {})
                    if not isinstance(ipv4_data, dict):
                        continue
                    addrs = ipv4_data.get("address", [])
                    if isinstance(addrs, dict):
                        addrs = [addrs]
                    for addr_entry in (addrs or []):
                        addr = addr_entry.get("ip")
                        pfx = addr_entry.get("prefix-length")
                        if addr and pfx is not None:
                            ip_cidr = f"{addr}/{pfx}"
                            break
                    if ip_cidr:
                        break
            result.append({
                "name": name,
                "ip":   ip_cidr,
                "vlan": _extract_vlan_from_iface_name(name),
            })
        return result

    def _extract_ip_from_netconf(self, parsed: dict) -> List[dict]:
        """
        Extract IPs from an xmltodict-parsed NETCONF response.

        Searches for IETF-interfaces ``ietf-ip:ipv4.address`` entries under
        each interface.
        """
        result = []
        iface_list = self._dig_netconf_interface_list(parsed)
        if not iface_list:
            return result
        for iface in iface_list:
            if not isinstance(iface, dict):
                continue
            name = (
                iface.get("name")
                or iface.get("intf-name")
                or iface.get("if-name", "")
            )
            if not name:
                continue
            ip_cidr: Optional[str] = None
            for ipv4_key in ("ietf-ip:ipv4", "ipv4", "Cisco-IOS-XE-ip:ipv4"):
                ipv4 = iface.get(ipv4_key, {})
                if not isinstance(ipv4, dict):
                    continue
                addresses = ipv4.get("address", [])
                if isinstance(addresses, dict):
                    addresses = [addresses]
                for addr_entry in (addresses or []):
                    addr = addr_entry.get("ip")
                    pfx = addr_entry.get("prefix-length")
                    if addr and pfx is not None:
                        ip_cidr = f"{addr}/{pfx}"
                        break
                if ip_cidr:
                    break
            result.append({
                "name": str(name),
                "ip":   ip_cidr,
                "vlan": _extract_vlan_from_iface_name(str(name)),
            })
        return result

    # ----------------------------------------------------------------------- #
    # SVI prefix map (running-config based)                                    #
    # ----------------------------------------------------------------------- #

    def get_svi_prefix_map(self) -> Dict[int, str]:
        """
        Parse the running configuration to build a VLAN-ID → network-prefix
        mapping for every SVI (``interface Vlan<N>``) that has an IP address.

        Returns
        -------
        dict
            ``{vid: prefix_cidr}`` — primary IP only, e.g.
            ``{162: "10.254.162.0/24", 2162: "10.254.2162.0/24"}``.
            Secondary IPs are silently skipped.

        Method
        ------
        1. Try ``show run | section ^interface Vlan`` (efficient; only Vlan blocks).
        2. Fall back to full ``show running-config`` if the section command
           returns empty output or fails.

        Both IOS/IOS-XE (``ip address A.B.C.D M.M.M.M``) and NX-OS
        (``ip address A.B.C.D/L``) formats are supported.
        """
        self._cli_connect()
        raw = self._get_svi_raw_config()
        result = self._parse_svi_prefix_map(raw)
        self.log.debug(
            "%s: get_svi_prefix_map → %d SVI prefix(es): %s",
            self.host, len(result), result,
        )
        return result

    # Error strings that indicate the command/filter was rejected by the device.
    # NX-OS uses "Invalid command" while IOS/IOS-XE uses "Invalid input".
    _CLI_ERROR_MARKERS = ("Invalid input", "Invalid command", "% Invalid", "% Error")

    def _get_svi_raw_config(self) -> str:
        """
        Return raw config text containing Vlan interface blocks.

        NX-OS and IOS/IOS-XE have different section-filter behaviour:
        - IOS/IOS-XE: ``show run | section ^interface Vlan``
        - NX-OS: ``show running-config | section interface Vlan``
          (the ``^`` anchor is unreliable on some NX-OS releases)
        Falls back to the full running-config for both platforms.
        """
        if self.os_type == "nxos":
            cmds = (
                "show running-config | section interface Vlan",
                "show running-config",
            )
        else:
            cmds = (
                "show run | section ^interface Vlan",
                "show running-config",
            )

        for cmd in cmds:
            try:
                raw: str = self._cli_connection.send_command(cmd)
            except Exception as exc:
                self.log.debug("%s: %r failed: %s", self.host, cmd, exc)
                continue

            # Normalise line endings — NX-OS may return \r\n
            raw = raw.replace("\r\n", "\n").replace("\r", "\n")

            # Reject output that contains a device error marker
            if not raw or not raw.strip():
                self.log.debug("%s: %r returned empty output", self.host, cmd)
                continue
            if any(marker in raw for marker in self._CLI_ERROR_MARKERS):
                self.log.debug(
                    "%s: %r rejected (error in output): %.120s",
                    self.host, cmd, raw.strip(),
                )
                continue

            # Quick sanity-check: at least one "interface Vlan" line must be present
            if "interface Vlan" not in raw and "interface vlan" not in raw.lower():
                self.log.debug(
                    "%s: %r has no Vlan interface lines — skipping", self.host, cmd
                )
                continue

            self.log.debug(
                "%s: SVI config source: %r (%d chars)", self.host, cmd, len(raw)
            )
            return raw

        self.log.warning(
            "%s: could not retrieve any running-config for SVI parsing", self.host
        )
        return ""

    def _parse_svi_prefix_map(self, raw: str) -> Dict[int, str]:
        """
        Parse raw running-config text and extract ``{vid: prefix_cidr}``.

        Uses a line-by-line state machine:
        - ``interface Vlan<N>``           → enter Vlan block, set current VID
        - Any other un-indented ``interface ...`` → exit current block
        - ``ip address <ip> <mask>``      → IOS/IOS-XE primary IP
        - ``ip address <ip>/<len>``       → NX-OS primary IP
        - Secondary IP lines are skipped.
        - ``shutdown`` / ``no ip address`` → no prefix recorded for this SVI
        """
        result: Dict[int, str] = {}
        current_vid: Optional[int] = None
        block_shutdown: bool = False  # True when 'shutdown' is seen in this block

        raw = raw.replace("\r\n", "\n").replace("\r", "\n")
        for line in raw.splitlines():
            # ── Detect Vlan interface header ───────────────────────────────
            m = _SVI_IFACE_HDR_RE.match(line)
            if m:
                current_vid = int(m.group(1))
                block_shutdown = False   # reset flag for each new block
                continue

            # ── Un-indented non-Vlan line exits the current block ──────────
            if line and not line[0].isspace():
                if _ANY_IFACE_RE.match(line):
                    current_vid = None
                elif line.strip() not in ("!", ""):
                    current_vid = None
                block_shutdown = False
                continue   # "!" separator lines keep current_vid intact

            if current_vid is None:
                continue

            stripped = line.strip()

            # 'shutdown' or explicit 'no ip address' marks the block as having
            # no routable IP.  NX-OS lines like 'no ip redirects' must NOT
            # trigger this flag — only an actual address-removal command should.
            _NO_IP_ADDR_CMDS = frozenset(
                ("no ip address", "no ip addr", "no ipv4 address")
            )
            if stripped == "shutdown" or stripped in _NO_IP_ADDR_CMDS:
                block_shutdown = True
                continue

            if block_shutdown:
                continue   # skip all subsequent lines in this block

            # ── IOS / IOS-XE: ip address A.B.C.D M.M.M.M ─────────────────
            m2 = _IP_MASK_RE.match(line)
            if m2:
                if m2.group("secondary"):
                    continue   # skip secondary IPs
                ip_str, mask_str = m2.group(1), m2.group(2)
                try:
                    net = ipaddress.IPv4Network(f"{ip_str}/{mask_str}", strict=False)
                    if current_vid not in result:
                        result[current_vid] = str(net)
                        self.log.debug(
                            "%s: Vlan%s → primary prefix %s (IOS mask)",
                            self.host, current_vid, net,
                        )
                except ValueError as exc:
                    self.log.debug(
                        "%s: Vlan%s bad ip %s/%s: %s",
                        self.host, current_vid, ip_str, mask_str, exc,
                    )
                continue

            # ── NX-OS: ip address A.B.C.D/L ───────────────────────────────
            m3 = _IP_CIDR_RE.match(line)
            if m3:
                if m3.group("secondary"):
                    continue
                addr_cidr = m3.group(1)
                try:
                    net = str(ipaddress.ip_interface(addr_cidr).network)
                    if current_vid not in result:
                        result[current_vid] = net
                        self.log.debug(
                            "%s: Vlan%s → primary prefix %s (NX-OS cidr)",
                            self.host, current_vid, net,
                        )
                except ValueError as exc:
                    self.log.debug(
                        "%s: Vlan%s bad cidr %s: %s",
                        self.host, current_vid, addr_cidr, exc,
                    )

        return result

    def get_svi_host_ip_map(self) -> Dict[int, str]:
        """
        Return ``{vid: host_ip_cidr}`` for every SVI that has an IP address.

        Unlike :meth:`get_svi_prefix_map` (which returns network addresses,
        e.g. ``"192.168.20.0/24"``), this method returns the **configured
        host address** with its prefix length, e.g. ``"192.168.20.1/24"``.
        This is the value that should be created as a NetBox IP address
        object and assigned to the SVI interface.

        Both IOS/IOS-XE (dotted-decimal mask) and NX-OS (CIDR notation)
        formats are supported.  The same two-command approach is used:
        ``show run | section ^interface Vlan`` with a fallback to the full
        running configuration.

        NX-OS note
        ----------
        On NX-OS, SVIs are ``interface Vlan20`` (capital V) and the IP
        is written in CIDR form (``ip address 192.168.20.1/24``).  Both
        are handled automatically.
        """
        self._cli_connect()
        raw = self._get_svi_raw_config()
        result = self._parse_svi_host_ip_map(raw)
        self.log.debug(
            "%s: get_svi_host_ip_map → %d SVI host IP(s): %s",
            self.host, len(result), result,
        )
        return result

    def _parse_svi_host_ip_map(self, raw: str) -> Dict[int, str]:
        """
        Parse running-config text and return ``{vid: host_ip_cidr}``.

        The host IP includes the prefix length (e.g. ``"192.168.20.1/24"``)
        so it can be stored directly as a NetBox IPAM IP address object and
        assigned to the SVI interface.

        Uses the same line-by-line state machine as
        :meth:`_parse_svi_prefix_map` but retains the host address instead
        of converting to the network address.
        """
        result: Dict[int, str] = {}
        current_vid: Optional[int] = None
        block_shutdown: bool = False

        raw = raw.replace("\r\n", "\n").replace("\r", "\n")
        for line in raw.splitlines():
            m = _SVI_IFACE_HDR_RE.match(line)
            if m:
                current_vid   = int(m.group(1))
                block_shutdown = False
                continue

            if line and not line[0].isspace():
                if _ANY_IFACE_RE.match(line):
                    current_vid = None
                elif line.strip() not in ("!", ""):
                    current_vid = None
                block_shutdown = False
                continue

            if current_vid is None:
                continue

            stripped = line.strip()
            _NO_IP_ADDR_CMDS = frozenset(
                ("no ip address", "no ip addr", "no ipv4 address")
            )
            if stripped == "shutdown" or stripped in _NO_IP_ADDR_CMDS:
                block_shutdown = True
                continue

            if block_shutdown:
                continue

            # ── IOS / IOS-XE: ip address A.B.C.D M.M.M.M [secondary] ──────
            m2 = _IP_MASK_RE.match(line)
            if m2:
                if m2.group("secondary"):
                    continue
                ip_str, mask_str = m2.group(1), m2.group(2)
                try:
                    net = ipaddress.IPv4Network(f"{ip_str}/{mask_str}", strict=False)
                    if current_vid not in result:
                        # Host address with prefix length (not network address)
                        result[current_vid] = f"{ip_str}/{net.prefixlen}"
                        self.log.debug(
                            "%s: Vlan%s → host IP %s/%s (IOS mask)",
                            self.host, current_vid, ip_str, net.prefixlen,
                        )
                except ValueError as exc:
                    self.log.debug(
                        "%s: Vlan%s bad ip/mask %s/%s: %s",
                        self.host, current_vid, ip_str, mask_str, exc,
                    )
                continue

            # ── NX-OS: ip address A.B.C.D/L [secondary] ───────────────────
            m3 = _IP_CIDR_RE.match(line)
            if m3:
                if m3.group("secondary"):
                    continue
                addr_cidr = m3.group(1)
                try:
                    iface_obj = ipaddress.ip_interface(addr_cidr)
                    if current_vid not in result:
                        # str(ip_interface) gives "192.168.20.1/24" — host + prefix
                        result[current_vid] = str(iface_obj)
                        self.log.debug(
                            "%s: Vlan%s → host IP %s (NX-OS cidr)",
                            self.host, current_vid, iface_obj,
                        )
                except ValueError as exc:
                    self.log.debug(
                        "%s: Vlan%s bad cidr %s: %s",
                        self.host, current_vid, addr_cidr, exc,
                    )

        return result

    # ----------------------------------------------------------------------- #
    # NX-OS Port-Channel HSRP IP discovery                                    #
    # ----------------------------------------------------------------------- #

    def get_nxos_port_channel_hsrp_ips(self) -> Dict[str, str]:
        """
        Return HSRP virtual IPs configured on Port-Channel interfaces on NX-OS.

        Parses ``show running-config`` for blocks like::

            interface port-channelN
              hsrp <group>
                ip <virtual-ip>

        Returns
        -------
        dict[str, str]
            ``{"Port-channelN": "10.x.x.x"}`` — one entry per port-channel
            that has at least one HSRP group with a virtual IP.  When multiple
            HSRP groups exist the first one found is kept.
        """
        self._cli_connect()
        self.log.debug("%s: fetching running-config for NX-OS PC HSRP IPs", self.host)
        try:
            raw: str = self._cli_connection.send_command("show running-config")
        except Exception as exc:
            raise TransportError(
                f"get_nxos_port_channel_hsrp_ips failed on {self.host}: {exc}"
            ) from exc
        result = self._parse_nxos_port_channel_hsrp_ips(raw)
        self.log.debug(
            "%s: get_nxos_port_channel_hsrp_ips → %d entry(ies)", self.host, len(result)
        )
        return result

    def _parse_nxos_port_channel_hsrp_ips(self, raw: str) -> Dict[str, str]:
        """
        Parse NX-OS running-config for Port-Channel HSRP virtual IPs.

        State machine:
        - Enter a ``interface port-channel<N>`` block → track current_iface
        - Enter an ``hsrp <group>`` sub-block → set in_hsrp = True
        - While in_hsrp, capture ``ip <address>`` as the virtual IP
        - Any new ``interface`` line resets state
        """
        _PC_IFACE_RE  = re.compile(r"^interface\s+(port-channel\d+)", re.IGNORECASE)
        _OTHER_IFACE_RE = re.compile(r"^interface\s+", re.IGNORECASE)
        _HSRP_GROUP_RE = re.compile(r"^\s+hsrp\s+\d+", re.IGNORECASE)
        _HSRP_IP_RE    = re.compile(r"^\s+ip\s+(\d+\.\d+\.\d+\.\d+)\s*$")

        result: Dict[str, str] = {}
        current_iface: Optional[str] = None
        in_hsrp = False

        for line in raw.splitlines():
            # New interface block
            m_pc = _PC_IFACE_RE.match(line)
            if m_pc:
                current_iface = self._expand_iface(m_pc.group(1))
                in_hsrp = False
                continue

            if _OTHER_IFACE_RE.match(line):
                current_iface = None
                in_hsrp = False
                continue

            if current_iface is None:
                continue

            # Entering an HSRP group sub-block
            if _HSRP_GROUP_RE.match(line):
                in_hsrp = True
                continue

            if in_hsrp:
                m_ip = _HSRP_IP_RE.match(line)
                if m_ip:
                    vip = m_ip.group(1)
                    if current_iface not in result:
                        result[current_iface] = vip
                        self.log.debug(
                            "%s: %s HSRP VIP → %s", self.host, current_iface, vip
                        )
                    # Reset so another group in same interface doesn't overwrite
                    in_hsrp = False
                    continue
                # Any non-blank, non-indented line exits the hsrp sub-block
                if line and not line.startswith(" "):
                    in_hsrp = False

        return result

    # ----------------------------------------------------------------------- #
    # FHRP (HSRP / VRRP / GLBP) config + oper-state discovery                 #
    # ----------------------------------------------------------------------- #

    def get_fhrp_config(self) -> List[dict]:
        """
        Parse HSRP / VRRP / GLBP groups from the device running-config.

        Handles **both** platform formats:

        * IOS / IOS-XE — inline ``standby`` keyword::

              standby 2 ip 10.210.0.131
              standby 2 priority 110

        * NX-OS — block ``hsrp`` keyword::

              hsrp 2
                ip 10.210.0.131
                priority 110

        VRRP and GLBP are always parsed inline regardless of platform.

        Returns
        -------
        list[dict]
            Each entry::

                {
                    "interface": "Port-channel33",
                    "protocol":  "hsrp",   # "hsrp" | "vrrp" | "glbp"
                    "group":     2,
                    "vip":       "10.210.0.131",
                    "priority":  110,      # None when not configured
                }

            Only groups with a configured virtual IP are returned.
        """
        self._cli_connect()
        self.log.debug("%s: fetching running-config for FHRP parsing", self.host)
        try:
            raw: str = self._cli_connection.send_command("show running-config")
        except Exception as exc:
            raise TransportError(f"get_fhrp_config failed: {exc}") from exc
        raw = raw.replace("\r\n", "\n").replace("\r", "\n")
        result = self._parse_fhrp_config(raw)
        self.log.debug(
            "%s: get_fhrp_config → %d FHRP group(s)", self.host, len(result)
        )
        return result

    def _parse_fhrp_config(self, raw: str) -> List[dict]:  # noqa: C901
        """Parse FHRP configuration from running-config text."""
        _IFACE_RE       = re.compile(r"^interface\s+(\S+)", re.IGNORECASE)
        # IOS/IOS-XE inline standby (HSRP)
        _STDBY_IP_RE    = re.compile(
            r"^\s+standby\s+(\d+)\s+ip\s+(\d+\.\d+\.\d+\.\d+)", re.IGNORECASE
        )
        _STDBY_PRI_RE   = re.compile(
            r"^\s+standby\s+(\d+)\s+priority\s+(\d+)", re.IGNORECASE
        )
        # VRRP (inline on all platforms)
        _VRRP_IP_RE     = re.compile(
            r"^\s+vrrp\s+(\d+)\s+ip\s+(\d+\.\d+\.\d+\.\d+)", re.IGNORECASE
        )
        _VRRP_PRI_RE    = re.compile(
            r"^\s+vrrp\s+(\d+)\s+priority\s+(\d+)", re.IGNORECASE
        )
        # GLBP (inline on all platforms)
        _GLBP_IP_RE     = re.compile(
            r"^\s+glbp\s+(\d+)\s+ip\s+(\d+\.\d+\.\d+\.\d+)", re.IGNORECASE
        )
        _GLBP_PRI_RE    = re.compile(
            r"^\s+glbp\s+(\d+)\s+priority\s+(\d+)", re.IGNORECASE
        )
        # NX-OS block HSRP group header — matches "  hsrp 2" but NOT "  hsrp version 2"
        _NXOS_GRP_RE    = re.compile(r"^(\s+)hsrp\s+(\d+)\s*$", re.IGNORECASE)
        # NX-OS sub-block: virtual IP line (only a bare IP after "ip")
        _NXOS_IP_RE     = re.compile(
            r"^\s+ip\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s*$"
        )
        _NXOS_PRI_RE    = re.compile(r"^\s+priority\s+(\d+)", re.IGNORECASE)

        # Accumulate by (iface, protocol, group) so multi-line contributions merge.
        result_map: Dict[Tuple[str, str, int], dict] = {}

        current_iface:  Optional[str] = None
        nxos_group:     Optional[int] = None   # active NX-OS HSRP block group ID
        nxos_grp_indent: int = 0               # column of the "hsrp <N>" line

        for line in raw.splitlines():
            # ── Top-level interface header ─────────────────────────────────
            m = _IFACE_RE.match(line)
            if m:
                current_iface = self._expand_iface(m.group(1))
                nxos_group    = None
                continue

            # Un-indented non-interface lines close the current block
            if line and not line[0].isspace():
                current_iface = None
                nxos_group    = None
                continue

            if current_iface is None:
                continue

            line_indent = len(line) - len(line.lstrip())

            # ── Detect exit from NX-OS HSRP sub-block ─────────────────────
            if nxos_group is not None and line_indent <= nxos_grp_indent:
                nxos_group = None
                # Fall through — this line may start a new group

            # ── NX-OS HSRP block header: "  hsrp <N>" ─────────────────────
            m = _NXOS_GRP_RE.match(line)
            if m:
                nxos_group     = int(m.group(2))
                nxos_grp_indent = len(m.group(1))
                key = (current_iface, "hsrp", nxos_group)
                result_map.setdefault(key, {"vip": None, "priority": None})
                continue

            # ── NX-OS HSRP sub-block content ──────────────────────────────
            if nxos_group is not None:
                m = _NXOS_IP_RE.match(line)
                if m:
                    key = (current_iface, "hsrp", nxos_group)
                    result_map[key]["vip"] = m.group(1)
                    continue
                m = _NXOS_PRI_RE.match(line)
                if m:
                    key = (current_iface, "hsrp", nxos_group)
                    result_map[key]["priority"] = int(m.group(1))
                    continue
                continue  # other sub-block lines (preempt, timers, …) — skip

            # ── IOS/IOS-XE standby (HSRP) ─────────────────────────────────
            m = _STDBY_IP_RE.match(line)
            if m:
                grp, vip = int(m.group(1)), m.group(2)
                key = (current_iface, "hsrp", grp)
                result_map.setdefault(key, {"vip": None, "priority": None})
                result_map[key]["vip"] = vip
                continue

            m = _STDBY_PRI_RE.match(line)
            if m:
                grp, pri = int(m.group(1)), int(m.group(2))
                key = (current_iface, "hsrp", grp)
                result_map.setdefault(key, {"vip": None, "priority": None})
                result_map[key]["priority"] = pri
                continue

            # ── VRRP ──────────────────────────────────────────────────────
            m = _VRRP_IP_RE.match(line)
            if m:
                grp, vip = int(m.group(1)), m.group(2)
                key = (current_iface, "vrrp", grp)
                result_map.setdefault(key, {"vip": None, "priority": None})
                result_map[key]["vip"] = vip
                continue

            m = _VRRP_PRI_RE.match(line)
            if m:
                grp, pri = int(m.group(1)), int(m.group(2))
                key = (current_iface, "vrrp", grp)
                result_map.setdefault(key, {"vip": None, "priority": None})
                result_map[key]["priority"] = pri
                continue

            # ── GLBP ──────────────────────────────────────────────────────
            m = _GLBP_IP_RE.match(line)
            if m:
                grp, vip = int(m.group(1)), m.group(2)
                key = (current_iface, "glbp", grp)
                result_map.setdefault(key, {"vip": None, "priority": None})
                result_map[key]["vip"] = vip
                continue

            m = _GLBP_PRI_RE.match(line)
            if m:
                grp, pri = int(m.group(1)), int(m.group(2))
                key = (current_iface, "glbp", grp)
                result_map.setdefault(key, {"vip": None, "priority": None})
                result_map[key]["priority"] = pri
                continue

        # Only emit groups that have an actual VIP configured
        return [
            {
                "interface": iface,
                "protocol":  proto,
                "group":     grp,
                "vip":       data["vip"],
                "priority":  data["priority"],
            }
            for (iface, proto, grp), data in result_map.items()
            if data["vip"]
        ]

    def get_nxos_hsrp_groups(self) -> List[dict]:
        """
        Return all HSRP groups from NX-OS ``show hsrp`` (detailed output).

        The detailed output is the single most reliable source on NX-OS: it
        contains the interface name, group number, virtual IP, configured
        priority, **and** the current operational state — all in one command,
        with no separate config-parse or brief-parse step needed.

        Returns
        -------
        list[dict]
            Each entry::

                {
                    "interface": "Vlan2",          # canonical expanded name
                    "protocol":  "hsrp",
                    "group":     2,
                    "vip":       "10.210.0.131",
                    "priority":  110,
                    "state":     "active",         # "active"|"standby"|"unknown"
                }

            Groups with no discovered virtual IP are excluded.
        """
        self._cli_connect()
        self.log.debug("%s: show hsrp (detailed)", self.host)
        try:
            raw: str = self._cli_connection.send_command("show hsrp")
        except Exception as exc:
            raise TransportError(f"get_nxos_hsrp_groups failed: {exc}") from exc
        raw = raw.replace("\r\n", "\n").replace("\r", "\n")
        result = self._parse_hsrp_detail(raw)
        self.log.debug(
            "%s: get_nxos_hsrp_groups → %d group(s)", self.host, len(result)
        )
        return result

    def _parse_hsrp_detail(self, raw: str) -> List[dict]:
        """
        Parse NX-OS ``show hsrp`` detailed block output.

        Each HSRP group is a free-form block delimited by the header line::

            Vlan2 - Group 2 (HSRP-V2) (IPv4)
              Local state is Active, priority 110 (Cfged 110), may preempt
              ...
              Virtual IP address is 10.210.0.131 (Cfged)
              ...

        Returns
        -------
        list[dict]
            Same schema as :meth:`get_nxos_hsrp_groups`.  Only groups that
            carry a discovered virtual IP are included.
        """
        _HDR_RE   = re.compile(
            r"^(\S+)\s+-\s+Group\s+(\d+)\s+\(HSRP-V\d+\)",
            re.IGNORECASE,
        )
        # Use .+? so the full state text is captured, including parenthetical
        # qualifiers such as "Initial(Interface Down)" or "Standby(Speak)".
        _STATE_RE = re.compile(
            r"^\s+Local\s+state\s+is\s+(.+?),\s*priority\s+(\d+)",
            re.IGNORECASE,
        )
        _VIP_RE   = re.compile(
            r"^\s+Virtual\s+IP\s+address\s+is\s+(\d+\.\d+\.\d+\.\d+)",
            re.IGNORECASE,
        )
        _STATE_MAP = {
            "active":  "active",
            "standby": "standby",
            "listen":  "unknown",
            "init":    "unknown",
            "initial": "unknown",
            "learn":   "unknown",
            "speak":   "unknown",
            "coup":    "unknown",
        }
        # Substrings that indicate the underlying interface is down (not just
        # HSRP in a transient state).  Groups matching these are excluded so
        # that a down SVI does not produce a stale FHRP group in NetBox.
        _IFACE_DOWN_MARKERS = ("interface down", "intf down")

        result:  List[dict]     = []
        current: Optional[dict] = None

        for line in raw.splitlines():
            m = _HDR_RE.match(line)
            if m:
                if current is not None:
                    result.append(current)
                current = {
                    "interface":      self._expand_iface(m.group(1)),
                    "protocol":       "hsrp",
                    "group":          int(m.group(2)),
                    "vip":            None,
                    "priority":       None,
                    "state":          "unknown",
                    "_iface_down":    False,   # set True when interface is down
                }
                continue

            if current is None:
                continue

            m = _STATE_RE.match(line)
            if m:
                raw_state  = m.group(1).strip()
                state_lower = raw_state.lower()
                # Mark the entry when the state text indicates the interface
                # itself is down (e.g. "Initial(Interface Down)").
                if any(marker in state_lower for marker in _IFACE_DOWN_MARKERS):
                    current["_iface_down"] = True
                    self.log.debug(
                        "%s: HSRP %s grp %s — interface down, will skip",
                        self.host, current["interface"], current["group"],
                    )
                # Map the leading keyword to the normalised state string.
                leading = state_lower.split("(")[0].strip()
                current["state"]    = _STATE_MAP.get(leading, "unknown")
                try:
                    current["priority"] = int(m.group(2))
                except (ValueError, TypeError):
                    pass
                continue

            m = _VIP_RE.match(line)
            if m:
                current["vip"] = m.group(1)

        if current is not None:
            result.append(current)

        # Exclude groups with no VIP or whose underlying interface is down.
        return [
            {k: v for k, v in g.items() if k != "_iface_down"}
            for g in result
            if g["vip"] and not g["_iface_down"]
        ]

    def get_fhrp_oper_state(self) -> Dict[str, Dict[int, str]]:
        """
        Return the operational state of every FHRP group on the device.

        Runs ``show standby brief``, ``show hsrp brief``, ``show vrrp brief``,
        and ``show glbp brief``.  Commands that are unsupported or return no
        useful output are silently skipped.

        Returns
        -------
        dict
            ``{interface_name: {group_id: state}}`` where *state* is one of:

            * ``"active"``   — HSRP Active / VRRP Master / GLBP Active
            * ``"standby"``  — HSRP Standby / VRRP Backup / GLBP Standby
            * ``"unknown"``  — Listen / Init / Speak / anything else
        """
        self._cli_connect()
        combined: Dict[str, Dict[int, str]] = {}

        for cmd in (
            "show standby brief",   # IOS / IOS-XE HSRP
            "show hsrp brief",      # NX-OS HSRP
            "show vrrp brief",
            "show glbp brief",
        ):
            try:
                raw: str = self._cli_connection.send_command(cmd)
            except Exception:
                continue
            if not raw or not raw.strip():
                continue
            raw = raw.replace("\r\n", "\n").replace("\r", "\n")
            if any(m in raw for m in ("Invalid input", "Invalid command", "% Invalid")):
                continue
            parsed = self._parse_fhrp_oper_brief(raw)
            for iface, grp_map in parsed.items():
                combined.setdefault(iface, {}).update(grp_map)

        self.log.debug(
            "%s: get_fhrp_oper_state → %d interface(s) with FHRP state",
            self.host, len(combined),
        )
        return combined

    def _parse_fhrp_oper_brief(self, raw: str) -> Dict[str, Dict[int, str]]:
        """
        Parse ``show standby/hsrp/vrrp/glbp brief`` output.

        Expected column layout (all commands share a similar format)::

            Interface   Grp  Pri P State   Active   Standby   VIP
            Po33          2  110 P Active  local    10.x.x.x  10.210.0.131

        Returns ``{interface: {group: state_string}}``.
        """
        _STATE_MAP = {
            "active":  "active",
            "master":  "active",    # VRRP Master → active
            "standby": "standby",
            "backup":  "standby",   # VRRP Backup → standby
            "listen":  "unknown",
            "init":    "unknown",
            "learn":   "unknown",
            "speak":   "unknown",
            "coup":    "unknown",
        }
        result: Dict[str, Dict[int, str]] = {}

        for line in raw.splitlines():
            # Strip NX-OS active-router marker ("*")
            stripped = line.strip().lstrip("*")
            if not stripped:
                continue
            parts = stripped.split()
            if len(parts) < 3:
                continue
            # Skip header lines
            if parts[0].lower() in ("interface", "p", ""):
                continue

            # parts[1] must be the numeric group ID
            try:
                group = int(parts[1])
            except (ValueError, IndexError):
                continue

            iface_raw = parts[0].lstrip("*")
            try:
                iface = self._expand_iface(iface_raw)
            except Exception:
                iface = iface_raw

            # State keyword — search parts[2:] for a known keyword
            state_raw = ""
            for token in parts[2:]:
                candidate = token.lower().rstrip(".")
                if candidate in _STATE_MAP:
                    state_raw = candidate
                    break

            if not state_raw:
                continue

            result.setdefault(iface, {})[group] = _STATE_MAP[state_raw]

        return result

    # ----------------------------------------------------------------------- #
    # Interface abbreviation helper                                            #
    # ----------------------------------------------------------------------- #

    @staticmethod
    def _expand_iface(abbr: str) -> str:
        """
        Expand a Cisco interface abbreviation to its canonical long form.

        Handles the abbreviations that appear in show etherchannel summary,
        show port-channel summary, show cdp neighbors detail, etc.
        """
        # Ordered longest-prefix-first to avoid partial matches
        _MAP = [
            ("GigabitEthernet",     "GigabitEthernet"),
            ("TenGigabitEthernet",  "TenGigabitEthernet"),
            ("FortyGigabitEthernet","FortyGigabitEthernet"),
            ("HundredGigabitEthernet","HundredGigabitEthernet"),
            ("FastEthernet",        "FastEthernet"),
            ("HundredGigE",         "HundredGigE"),
            ("TwentyFiveGigE",      "TwentyFiveGigE"),
            ("Ethernet",            "Ethernet"),
            ("Loopback",            "Loopback"),
            ("Port-channel",        "Port-channel"),
            ("Portchannel",         "Port-channel"),
            ("mgmt",                "mgmt"),
            ("Twe",  "TwentyFiveGigE"),
            ("Gi",   "GigabitEthernet"),
            ("Ge",   "GigabitEthernet"),
            ("Te",   "TenGigabitEthernet"),
            ("Fo",   "FortyGigabitEthernet"),
            ("Hu",   "HundredGigE"),
            ("Fa",   "FastEthernet"),
            ("Lo",   "Loopback"),
            ("Po",   "Port-channel"),
            ("Eth",  "Ethernet"),
            ("Et",   "Ethernet"),
        ]
        for prefix, canonical in sorted(_MAP, key=lambda x: len(x[0]), reverse=True):
            if abbr.lower().startswith(prefix.lower()):
                return canonical + abbr[len(prefix):]
        return abbr

    # ----------------------------------------------------------------------- #
    # Port-channel / LAG membership                                            #
    # ----------------------------------------------------------------------- #

    def get_portchannel_membership(self) -> List[dict]:
        """
        Discover port-channel (LAG) membership on the device.

        Returns
        -------
        list[dict]
            Each entry: ``{"lag": "Port-channel1", "members": ["GigabitEthernet1/0/1", ...]}``

        Platform commands
        -----------------
        IOS / IOS-XE : ``show etherchannel summary``
        NX-OS        : ``show port-channel summary``
        """
        cmd = "show port-channel summary" if self.os_type == "nxos" \
              else "show etherchannel summary"
        self._cli_connect()
        self.log.debug("%s: %r", self.host, cmd)
        try:
            raw: str = self._cli_connection.send_command(cmd)
        except Exception as exc:
            raise TransportError(
                f"get_portchannel_membership failed on {self.host}: {exc}"
            ) from exc
        result = self._parse_portchannel(raw)
        self.log.debug(
            "%s: get_portchannel_membership → %d LAG(s)", self.host, len(result)
        )
        return result

    def _parse_portchannel(self, raw: str) -> List[dict]:
        """
        Parse ``show etherchannel summary`` / ``show port-channel summary``.

        Data line format (both IOS and NX-OS share the same pattern):
            <group>  Po<n>(<flags>)  <protocol>  <iface>(<flag>) ...
        """
        _PC_LINE = re.compile(
            r"^\s*\d+\s+Po(\d+)\(\S*\)\s+\S+\s+(.+)$", re.IGNORECASE
        )
        _MEMBER = re.compile(r"(\S+?)\(\w+\)")
        result: List[dict] = []
        for line in raw.splitlines():
            m = _PC_LINE.match(line)
            if not m:
                continue
            po_num  = m.group(1)
            members = [
                self._expand_iface(mm.group(1))
                for mm in _MEMBER.finditer(m.group(2))
            ]
            if members:
                result.append({
                    "lag":     f"Port-channel{po_num}",
                    "members": members,
                })
        return result

    # ----------------------------------------------------------------------- #
    # Trunk allowed VLAN inventory                                             #
    # ----------------------------------------------------------------------- #

    def get_interfaces_trunk_allowed(self) -> List[dict]:
        """
        Return trunk interface data using ``show interfaces trunk``.

        Uses the **"Vlans allowed on trunk"** section exclusively — this is
        the configured allowed list, not the active/forwarding subset.

        Returns
        -------
        list[dict]
            Each: ``{"name": str, "native_vlan": int|None, "allowed_vlans": list[int]}``
        """
        self._cli_connect()
        self.log.debug("%s: show interfaces trunk", self.host)
        try:
            raw: str = self._cli_connection.send_command("show interfaces trunk")
        except Exception as exc:
            raise TransportError(
                f"get_interfaces_trunk_allowed failed on {self.host}: {exc}"
            ) from exc
        result = self._parse_trunk_allowed(raw)
        self.log.debug(
            "%s: trunk inventory → %d trunk port(s)", self.host, len(result)
        )
        return result

    def _parse_trunk_allowed(self, raw: str) -> List[dict]:
        """
        Parse ``show interfaces trunk`` into structured trunk records.

        Extracts native VLAN from section 1 and the full allowed-VLAN
        range from section 2 ("Vlans allowed on trunk").  Sections 3+
        (active / STP forwarding) are intentionally ignored.
        """
        native_map:  Dict[str, Optional[int]] = {}
        allowed_map: Dict[str, str] = {}
        section = ""

        for line in raw.splitlines():
            stripped = line.strip()
            lower    = stripped.lower()
            if not stripped or stripped.startswith("-"):
                continue

            # Section detection
            if re.search(r"port\s+mode\s+encap", lower):
                section = "header"; continue
            if "vlans allowed on trunk" in lower and "active" not in lower:
                section = "allowed"; continue
            if "vlans allowed and active" in lower:
                section = "done";    continue
            if section == "done":
                continue

            parts = stripped.split()
            if len(parts) < 2:
                continue
            abbr = parts[0]

            if section == "header":
                try:
                    native_map[abbr] = int(parts[4])
                except (ValueError, IndexError):
                    native_map[abbr] = None
            elif section == "allowed":
                allowed_map[abbr] = parts[1]

        all_ifaces = set(native_map) | set(allowed_map)
        result: List[dict] = []
        for abbr in sorted(all_ifaces):
            result.append({
                "name":          self._expand_iface(abbr),
                "native_vlan":   native_map.get(abbr),
                "allowed_vlans": _parse_vlan_range_string(allowed_map.get(abbr, "")),
            })
        return result

    # ----------------------------------------------------------------------- #
    # ARP table                                                                #
    # ----------------------------------------------------------------------- #

    def get_arp_table(self) -> List[dict]:
        """
        Return dynamic ARP entries from the device.

        Runs ``show ip arp`` and returns one record per ARPA entry that has
        a non-zero MAC address.  Entries for the device's own interfaces
        (age ``-``) are included so callers can filter if needed.

        Returns
        -------
        list[dict]
            Each entry::

                {
                    "ip":        "10.10.10.50",
                    "mac":       "a1:b2:c3:d4:e5:f6",  # colon-separated
                    "interface": "Vlan10",              # L3 interface from ARP
                    "age_min":   2,                     # None when not available
                }
        """
        self._cli_connect()
        self.log.debug("%s: show ip arp (timing mode)", self.host)
        try:
            raw: str = self._cli_connection.send_command_timing(
                "show ip arp",
                delay_factor=4,
                strip_prompt=True,
                strip_command=True,
            )
        except Exception as exc:
            raise TransportError(f"get_arp_table failed: {exc}") from exc
        raw = raw.replace("\x00", "").replace("\r\n", "\n").replace("\r", "\n")
        result = self._parse_arp_table(raw)
        self.log.debug("%s: get_arp_table → %d entry(ies)", self.host, len(result))
        return result

    def _parse_arp_table(self, raw: str) -> List[dict]:  # noqa: C901
        """
        Parse ``show ip arp`` for IOS / IOS-XE / NX-OS.

        IOS / IOS-XE format::

            Protocol  Address      Age  Hardware Addr    Type  Interface
            Internet  10.10.10.50    2  a1b2.c3d4.e5f6  ARPA  GigabitEthernet1/0/5

        NX-OS format::

            Address         Age       MAC Address     Interface
            10.10.10.50     00:02:30  a1b2.c3d4.e5f6  Vlan10
        """
        _IP_RE  = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
        _MAC_RE = re.compile(
            r"^([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}"
            r"|[0-9a-f]{2}(?::[0-9a-f]{2}){5})$",
            re.IGNORECASE,
        )
        _ZERO_MACS = {"0000.0000.0000", "incomplete"}
        result: List[dict] = []

        for line in raw.splitlines():
            parts = line.split()
            if not parts:
                continue

            # IOS / IOS-XE: first token "Internet"
            if parts[0].lower() == "internet" and len(parts) >= 5:
                ip_str  = parts[1]
                age_str = parts[2]
                mac_str = parts[3]
                if_str  = parts[5] if len(parts) > 5 else ""
                if not _IP_RE.match(ip_str) or not _MAC_RE.match(mac_str):
                    continue
                if mac_str.lower() in _ZERO_MACS:
                    continue
                age_min: Optional[int] = None
                try:
                    age_min = int(age_str)
                except (ValueError, TypeError):
                    pass
                result.append({
                    "ip":        ip_str,
                    "mac":       _normalize_cisco_mac(mac_str),
                    "interface": self._expand_iface(if_str) if if_str else "",
                    "age_min":   age_min,
                })
                continue

            # NX-OS / fallback: first token is an IP address
            if _IP_RE.match(parts[0]) and len(parts) >= 3:
                ip_str  = parts[0]
                mac_str = parts[2]
                if_str  = parts[3] if len(parts) > 3 else ""
                if not _MAC_RE.match(mac_str):
                    continue
                if mac_str.lower() in _ZERO_MACS:
                    continue
                result.append({
                    "ip":        ip_str,
                    "mac":       _normalize_cisco_mac(mac_str),
                    "interface": self._expand_iface(if_str) if if_str else "",
                    "age_min":   None,
                })

        return result

    # ----------------------------------------------------------------------- #
    # MAC address table                                                        #
    # ----------------------------------------------------------------------- #

    def get_mac_address_table(self) -> List[dict]:
        """
        Return dynamic MAC address table entries from the device.

        Tries ``show mac address-table dynamic`` first; falls back to
        ``show mac address-table`` when the ``dynamic`` keyword is
        unsupported (some NX-OS / older IOS versions).

        Robustness measures
        -------------------
        * ``read_timeout=120`` — large tables (10 000+ entries) can take
          well over the Netmiko default of 10 s.
        * ``cmd_verify=False`` — skips echo-verification that can confuse
          prompt detection when the output starts with unusual characters.
        * Null-byte stripping — NX-OS occasionally emits ``\\x00`` (``^@``)
          characters that break Netmiko's end-of-output detection.

        Returns
        -------
        list[dict]
            Each entry::

                {
                    "mac":       "a1:b2:c3:d4:e5:f6",
                    "vlan":      10,          # None when VLAN not parseable
                    "interface": "GigabitEthernet1/0/5",
                }
        """
        self._cli_connect()

        # Use send_command_timing (time-based) instead of send_command
        # (prompt-based).  The prompt-based approach relies on a regex to
        # detect the CLI prompt at the end of the output buffer.  NX-OS
        # occasionally emits null bytes (\x00, shown as '^@') that land
        # inside that buffer and break the regex match, causing Netmiko to
        # raise "Pattern not detected" even though the command succeeded.
        # send_command_timing bypasses prompt detection entirely — it just
        # waits for the output to stop arriving and returns whatever it has.
        #
        # delay_factor=6 gives ≈ 90 s of patience, enough for 10 000+ entry
        # MAC tables on busy aggregation switches.
        _TIMING_KWARGS = dict(
            delay_factor=6,
            strip_prompt=True,
            strip_command=True,
        )

        raw: str = ""
        for cmd in (
            "show mac address-table dynamic",
            "show mac address-table",
        ):
            self.log.debug("%s: %r (timing mode)", self.host, cmd)
            try:
                raw = self._cli_connection.send_command_timing(cmd, **_TIMING_KWARGS)
            except Exception as exc:
                self.log.debug("%s: %r failed: %s", self.host, cmd, exc)
                raw = ""
                continue

            # Strip null bytes that NX-OS emits (the '^@' pattern).
            raw = raw.replace("\x00", "").replace("\r\n", "\n").replace("\r", "\n")

            # Reject device error output and retry with the simpler command.
            if any(m in raw for m in ("Invalid input", "Invalid command", "% Invalid")):
                self.log.debug(
                    "%s: %r rejected by device — trying fallback", self.host, cmd
                )
                raw = ""
                continue

            break   # successful read

        if not raw:
            raise TransportError(
                f"get_mac_address_table failed on {self.host}: "
                "both command variants were rejected or timed out"
            )

        result = self._parse_mac_address_table(raw)
        self.log.debug(
            "%s: get_mac_address_table → %d entry(ies)", self.host, len(result)
        )
        return result

    def _parse_mac_address_table(self, raw: str) -> List[dict]:
        """
        Parse ``show mac address-table dynamic`` for IOS / IOS-XE / NX-OS.

        Finds lines that contain a MAC address (dotted-quad or colon-separated),
        then extracts the VLAN (numeric token before the MAC) and the interface
        (alphabetic token after the MAC that is not a keyword like DYNAMIC).
        This token-scan approach handles both IOS and NX-OS column layouts.
        """
        _MAC_RE = re.compile(
            r"^([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}"
            r"|[0-9a-f]{2}(?::[0-9a-f]{2}){5})$",
            re.IGNORECASE,
        )
        _SKIP = frozenset({
            "dynamic", "static", "secure", "drop", "system",
            "true", "false", "-", "f", "t", "n",
        })
        result: List[dict] = []

        for line in raw.splitlines():
            parts = line.split()
            if not parts:
                continue

            # Locate the MAC token
            mac_raw = ""
            mac_idx = -1
            for i, p in enumerate(parts):
                if _MAC_RE.fullmatch(p):
                    mac_raw = p
                    mac_idx = i
                    break
            if not mac_raw:
                continue

            mac_norm = _normalize_cisco_mac(mac_raw)

            # VLAN: first numeric-only token before the MAC (ignore NX-OS markers)
            vlan: Optional[int] = None
            for p in parts[:mac_idx]:
                clean = p.lstrip("*+()")
                try:
                    v = int(clean)
                    if 1 <= v <= 4094:
                        vlan = v
                        break
                except (ValueError, TypeError):
                    pass

            # Interface: first token after the MAC that looks like an interface name
            # and is not a reserved keyword
            iface_raw = ""
            for p in parts[mac_idx + 1:]:
                p_clean = p.strip("()")
                if p_clean.lower() in _SKIP or not p_clean:
                    continue
                # Interface names start with a letter
                if re.match(r"[A-Za-z]", p_clean):
                    iface_raw = p_clean
                    break

            if not iface_raw:
                continue

            result.append({
                "mac":       mac_norm,
                "vlan":      vlan,
                "interface": self._expand_iface(iface_raw),
            })

        return result

    # ----------------------------------------------------------------------- #
    # Interface admin / oper state                                             #
    # ----------------------------------------------------------------------- #

    def get_interface_state_inventory(self) -> List[dict]:
        """
        Return admin/oper state per interface using ``show interfaces status``.

        Returns
        -------
        list[dict]
            Each: ``{"name": str, "enabled": bool, "mark_connected": bool}``

        State mapping
        -------------
        connected     → enabled=True,  mark_connected=True
        notconnect    → enabled=True,  mark_connected=False
        disabled      → enabled=False, mark_connected=False
        err-disabled  → enabled=False, mark_connected=False
        sfp-no-present→ enabled=True,  mark_connected=False
        """
        self._cli_connect()
        cmd = "show interface status" if self.os_type == "nxos" \
              else "show interfaces status"
        self.log.debug("%s: %r", self.host, cmd)
        try:
            raw: str = self._cli_connection.send_command(cmd)
        except Exception as exc:
            raise TransportError(
                f"get_interface_state_inventory failed on {self.host}: {exc}"
            ) from exc
        return self._parse_interface_states(raw)

    def _parse_interface_states(self, raw: str) -> List[dict]:
        """
        Parse ``show interfaces status`` into state records.

        Finds the status keyword on each data line regardless of column shift.
        """
        # Admin-shutdown states — map to enabled=False in NetBox.
        _DOWN_STATES  = {"disabled", "err-disabled", "errdisabled"}
        # Operationally connected — map to mark_connected=True.
        _UP_OP_STATES = {"connected"}
        _STATUS_KW    = _DOWN_STATES | _UP_OP_STATES | {
            "notconnect", "notconnected", "sfpabsent", "sfp-no-present",
            "inactive", "monitoring",
            # NX-OS VLAN/SVI interfaces report "down" when the VLAN has no
            # active member ports (admin-up, line-protocol down) and
            # "routed" when the interface is a routed port.
            "down", "routed",
        }
        result: List[dict] = []
        for line in raw.splitlines():
            parts = line.split()
            if not parts:
                continue
            # Skip header
            if parts[0].lower() in ("port", "interface"):
                continue
            status_lc = None
            for p in parts[1:]:
                if p.lower() in _STATUS_KW:
                    status_lc = p.lower()
                    break
            if status_lc is None:
                continue
            iface_name = self._expand_iface(parts[0])
            enabled        = status_lc not in _DOWN_STATES
            mark_connected = status_lc in _UP_OP_STATES
            result.append({
                "name":           iface_name,
                "enabled":        enabled,
                "mark_connected": mark_connected,
            })
        return result

    # ----------------------------------------------------------------------- #
    # Software facts                                                           #
    # ----------------------------------------------------------------------- #

    def get_software_facts(self) -> dict:
        """
        Extract software version, image name, and detected platform from
        ``show version``.

        Returns
        -------
        dict
            ``{"software_version": str|None, "software_image": str|None,
               "platform": "ios"|"iosxe"|"nxos"|None}``
        """
        ver_result = self.show_ver(transport="cli")
        parsed = ver_result.get("parsed")
        raw    = ver_result.get("raw", "")
        if parsed and isinstance(parsed, dict):
            facts = self._extract_software_genie(parsed)
            if facts.get("software_version"):
                facts["platform"] = self._detect_platform_raw(raw)
                return facts
        facts = self._extract_software_raw(raw)
        facts["platform"] = self._detect_platform_raw(raw)
        return facts

    def _detect_platform_raw(self, raw: str) -> Optional[str]:
        """
        Detect OS type from ``show version`` raw text.

        Precedence (most specific first):
        * "NX-OS" or "Nexus" anywhere → ``"nxos"``
        * "IOS-XE" or "IOS XE" anywhere → ``"iosxe"``
        * "IOS" anywhere → ``"ios"``
        * Otherwise → ``None`` (cannot determine confidently)
        """
        lower = raw.lower()
        if "nx-os" in lower or "nexus" in lower:
            return "nxos"
        if "ios-xe" in lower or "ios xe" in lower:
            return "iosxe"
        if "ios" in lower:
            return "ios"
        return None

    def _extract_software_genie(self, parsed: dict) -> dict:
        """Extract software facts from Genie-parsed show version dict."""
        ver_block = parsed.get("version", parsed)
        version = (
            ver_block.get("version")
            or ver_block.get("os_version")
            or None
        )
        image = (
            ver_block.get("system_image")
            or ver_block.get("image_id")
            or None
        )
        if image:
            image = image.split("/")[-1].strip('"')
        return {"software_version": version, "software_image": image}

    def _extract_software_raw(self, raw: str) -> dict:
        """Regex fallback to extract version and image from raw show version."""
        _VER_RE   = re.compile(
            r"[Vv]ersion\s+([\d.]+\([\w.]+\)[\w.]*)", re.IGNORECASE
        )
        _IMG_RE   = re.compile(
            r"[Ss]ystem image.*?\".*?/?([\w\-\.]+\.(?:bin|ova|qcow2))\"",
            re.IGNORECASE,
        )
        _NXOS_VER = re.compile(
            r"(?:system|kickstart|nxos):\s*version\s+(\S+)", re.IGNORECASE
        )
        version = image = None
        for line in raw.splitlines():
            if not version:
                m = _VER_RE.search(line) or _NXOS_VER.search(line)
                if m:
                    version = m.group(1)
            if not image:
                m = _IMG_RE.search(line)
                if m:
                    image = m.group(1).strip()
        return {"software_version": version, "software_image": image}

    # ----------------------------------------------------------------------- #
    # Transceiver / cable-type detection                                       #
    # ----------------------------------------------------------------------- #

    def get_interface_transceiver_raw(self, interface_name: str) -> str:
        """
        Return the raw text output of ``show interface <iface> transceiver``.

        Used by callers that need to classify the optic at a higher level
        (e.g. SR vs LR) rather than the coarse fiber/copper distinction.
        Returns an empty string when the command fails or is unsupported.
        """
        self._cli_connect()
        try:
            return self._cli_connection.send_command(
                f"show interface {interface_name} transceiver"
            )
        except Exception as exc:
            self.log.debug(
                "%s: get_interface_transceiver_raw(%r) failed: %s",
                self.host, interface_name, exc,
            )
            return ""

    def get_interface_transceiver_type(self, interface_name: str) -> str:
        """
        Return ``"fiber"`` or ``"copper"`` based on transceiver diagnostics.

        Runs ``show interface <iface> transceiver``.  Defaults to
        ``"copper"`` when the command is unavailable or the transceiver
        type cannot be determined.
        """
        self._cli_connect()
        try:
            raw: str = self._cli_connection.send_command(
                f"show interface {interface_name} transceiver"
            )
        except Exception:
            return "copper"
        raw_l = raw.lower()
        if any(k in raw_l for k in ("invalid input", "not supported", "% error")):
            return "copper"
        if any(k in raw_l for k in ("no optical", "no transceiver", "sfp absent",
                                     "not present", "not installed")):
            return "copper"
        if any(k in raw_l for k in ("sfp", "qsfp", "fiber", "optical",
                                     "wavelength", "dbm", "tx power")):
            return "fiber"
        return "copper"

    # ----------------------------------------------------------------------- #
    # CDP neighbor discovery                                                   #
    # ----------------------------------------------------------------------- #

    def get_cdp_neighbors(self) -> List[dict]:
        """
        Return structured CDP neighbor records from ``show cdp neighbors detail``.

        Returns
        -------
        list[dict]
            Each: ``{"local_interface", "neighbor_device", "neighbor_interface",
                      "neighbor_ip"}``
        """
        result = self.show_cdp_neighbors_detail(transport="cli")
        parsed = result.get("parsed")
        raw    = result.get("raw", "")
        if parsed and isinstance(parsed, dict):
            neighbors = self._extract_cdp_genie(parsed)
            if neighbors:
                return neighbors
        return self._extract_cdp_raw(raw)

    def _extract_cdp_genie(self, parsed: dict) -> List[dict]:
        """
        Extract neighbors from Genie ``show cdp neighbors detail`` schema.

        Genie schema key path: ``index -> N -> {device_id, local_interface,
        port_id, management_addresses}``.
        """
        neighbors: List[dict] = []
        index = parsed.get("index", {})
        for _, entry in index.items():
            mgmt = list(entry.get("management_addresses", {}).keys())
            neighbors.append({
                "local_interface":    self._expand_iface(
                    str(entry.get("local_interface", ""))
                ),
                "neighbor_device":    str(entry.get("device_id", "")).strip(),
                "neighbor_interface": self._expand_iface(
                    str(entry.get("port_id", ""))
                ),
                "neighbor_ip":        mgmt[0] if mgmt else None,
            })
        return neighbors

    def _extract_cdp_raw(self, raw: str) -> List[dict]:
        """
        Parse raw ``show cdp neighbors detail`` text into neighbor records.

        Uses a block-based approach: blocks are separated by dashes or
        double-blank lines; each block contains device ID, IP, and
        Interface / Port ID fields.
        """
        _DEV_RE   = re.compile(r"^Device ID:\s*(.+)$", re.IGNORECASE)
        _IP_RE    = re.compile(r"IP\s+address:\s*(\d+\.\d+\.\d+\.\d+)", re.IGNORECASE)
        _IFACE_RE = re.compile(
            r"Interface:\s*(\S+?),\s*Port ID.*?:\s*(\S+)", re.IGNORECASE
        )
        neighbors: List[dict] = []
        current: dict = {}

        def _flush(c: dict) -> None:
            if c.get("neighbor_device"):
                c.setdefault("local_interface",    None)
                c.setdefault("neighbor_interface", None)
                c.setdefault("neighbor_ip",        None)
                neighbors.append(c)

        for line in raw.splitlines():
            stripped = line.strip()
            if stripped.startswith("---") or stripped.startswith("==="):
                _flush(current); current = {}; continue
            m = _DEV_RE.match(stripped)
            if m:
                if current.get("neighbor_device"):
                    _flush(current); current = {}
                current["neighbor_device"] = m.group(1).strip()
                continue
            if not current:
                continue
            m = _IP_RE.search(stripped)
            if m and "neighbor_ip" not in current:
                current["neighbor_ip"] = m.group(1)
            m = _IFACE_RE.search(stripped)
            if m:
                current["local_interface"]    = self._expand_iface(
                    m.group(1).rstrip(",")
                )
                current["neighbor_interface"] = self._expand_iface(m.group(2))
        _flush(current)
        return neighbors

    # ----------------------------------------------------------------------- #
    # Generic auto-transport runner                                            #
    # ----------------------------------------------------------------------- #

    def _auto_collect(self, transport_fn) -> list:
        """
        Apply the per-OS auto transport order, calling
        ``transport_fn(transport)`` for each transport until one succeeds.

        Parameters
        ----------
        transport_fn : callable
            Bound method accepting a single ``transport`` string.

        Returns
        -------
        list
            First successful result.

        Raises
        ------
        TransportError
            When every transport in the auto order raises.
        """
        order = _AUTO_TRANSPORT_ORDER.get(self.os_type, ["cli"])
        last_exc: Optional[Exception] = None
        for transport in order:
            try:
                self.log.debug(
                    "auto-collect: trying %r for %s", transport, self.host
                )
                return transport_fn(transport)
            except Exception as exc:
                self.log.warning(
                    "auto-collect: %r failed for %s: %s", transport, self.host, exc
                )
                last_exc = exc
        raise TransportError(
            f"All transports {order} exhausted for {self.host}: {last_exc}"
        )

    # ----------------------------------------------------------------------- #
    # Generic dict-walking helper                                              #
    # ----------------------------------------------------------------------- #

    def _dig_key(self, d: Any, keys: set, _depth: int = 0) -> Any:
        """
        Walk a nested dict and return the first value whose key (bare,
        without YANG module prefix) is in *keys*.

        Stops at depth 10 to prevent runaway recursion on large configs.
        """
        if _depth > 10 or not isinstance(d, dict):
            return None
        for k, v in d.items():
            bare = k.split(":")[-1].lower()
            if bare in keys:
                return v
            sub = self._dig_key(v, keys, _depth + 1)
            if sub is not None:
                return sub
        return None

    # ----------------------------------------------------------------------- #
    # Context-manager support                                                  #
    # ----------------------------------------------------------------------- #

    def __enter__(self) -> "CiscoDeviceClient":
        return self

    def __exit__(self, *_: Any) -> None:
        self._cli_disconnect()

    def __repr__(self) -> str:
        return (
            f"CiscoDeviceClient(host={self.host!r}, os_type={self.os_type!r}, "
            f"port={self.port})"
        )
