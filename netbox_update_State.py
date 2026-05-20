#!/usr/bin/env python3
"""
netbox_update_State.py
======================
Collect interface operational state from Cisco devices and update the
``STATE`` custom field on NetBox interface objects.

For each interface discovered on a device the script:

1. Derives the operational state:  ``"UP"`` | ``"DOWN"`` | ``"ADMIN DOWN"``
   (or ``"UNKNOWN"`` when state cannot be determined).
2. Reads the current ``custom_fields["STATE"]`` value from NetBox.
3. **If the values differ** — writes ``STATE`` *and* stamps ``state_change``
   with the current UTC timestamp.
4. **If the values match** — skips the NetBox write entirely (idempotent).

Transport selection
-------------------
Follows exactly the same strict rules as ``sync_netbox_interfaces.py``:

- ``--transport cli``        → ONLY CLI (no NETCONF / RESTCONF attempts)
- ``--transport netconf``    → ONLY NETCONF
- ``--transport restconf``   → ONLY RESTCONF
- ``--transport auto``       → NETCONF → RESTCONF → CLI per-OS chain

Note: interface-state collection (``show interfaces status``) is always
executed over SSH/CLI regardless of the transport flag, because no
NETCONF/RESTCONF operational model covers this data reliably.  The
transport flag is still honoured on the CiscoDeviceClient so that future
extensions remain consistent.

Output
------
JSON array to **stdout** (one element per device); all logs go to **stderr**.
"""

from __future__ import annotations

import json
import logging
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Dict, List, Optional

from cisco_device_client import CiscoDeviceClient, CiscoDeviceClientError
from netbox_client import NetBoxClient, NetBoxClientError

# Reuse the exact same parser, helpers, and shared logic from the sync script
# so device selection, credential flags, concurrency, and transport behaviour
# are byte-for-byte identical.
from sync_netbox_interfaces import (
    _configure_logging,
    build_parser,
    build_vc_member_map,
    expand_interface_name,
    get_device_mgmt_ip,
    get_device_os_type,
    resolve_device_list,
    resolve_target_device_id,
    _device_has_primary_ip,
)

# --------------------------------------------------------------------------- #
# Constants                                                                    #
# --------------------------------------------------------------------------- #

# NetBox custom-field names (must match what is defined in the NetBox UI).
_CF_STATE          = "STATE"
_CF_LAST_INPUT     = "last_input"
_CF_IF_LAST_UPDATE = "if_last_update"

# Device-level custom fields for unused-port tracking.
_CF_UNUSED_TIME  = "unused_time"    # integer — threshold in seconds
_CF_UNUSED_PORTS = "unused_ports"   # integer — count written back after each run
_CF_STATE_UPDATE = "state_update"   # datetime string — UTC timestamp of last run

# Matches:  "Last input 00:02:13,"  "Last input never,"  "Last input 3w2d,"
# Captures everything between "Last input " and the first comma or newline.
_LAST_INPUT_RE = re.compile(r"Last input\s+([^,\n]+)", re.IGNORECASE)

# Matches the opening line of any "show interfaces" interface block.
# Deliberately permissive — does NOT require a specific state string so that
# interfaces reporting unusual states (e.g. "reset", "err-disabled") are
# still captured.
_IFACE_HEADER_RE = re.compile(
    r"^([A-Za-z][A-Za-z0-9/.\-]+)\s+is\s+",
    re.MULTILINE,
)

# Detects the "Hardware is not present" line inside an interface block.
_NO_HW_RE = re.compile(r"Hardware is not present", re.IGNORECASE)

# Extracts the OUTPUT timer from a "Last input X, output Y" line.
# Used for SVI (Vlan) interfaces where the output timer is more meaningful.
_LAST_OUTPUT_RE = re.compile(
    r"Last input\s+[^,\n]+,\s*output\s+([^,\n]+)",
    re.IGNORECASE,
)

log = logging.getLogger("netbox_update_State")

# Patterns for convert_last_input_to_seconds().
# Compiled once at import time; re-used per interface.
_LI_HHMMSS_RE = re.compile(r"^(\d+):(\d{2}):(\d{2})$")
_LI_UNITS: List = [
    # Each tuple: (compiled pattern, seconds-per-unit)
    # Handles: "4 years" / "4y" / "4Y"   "40 weeks" / "40w" / "40W"  etc.
    # Negative lookahead (?![a-zA-Z]) prevents partial-word false matches.
    (re.compile(r"(\d+)\s*(?:year[s]?|[yY])(?![a-zA-Z])"),           365 * 24 * 3600),
    (re.compile(r"(\d+)\s*(?:week[s]?|[wW])(?![a-zA-Z])"),             7 * 24 * 3600),
    (re.compile(r"(\d+)\s*(?:day[s]?|[dD])(?![a-zA-Z])"),                  24 * 3600),
    (re.compile(r"(\d+)\s*(?:hour[s]?|[hH])(?![a-zA-Z])"),                      3600),
    (re.compile(r"(\d+)\s*(?:minute[s]?|min[s]?|m)(?![a-zA-Z])"),                 60),
    (re.compile(r"(\d+)\s*(?:second[s]?|sec[s]?|[sS])(?![a-zA-Z])"),               1),
]


# --------------------------------------------------------------------------- #
# Last-input helpers                                                           #
# --------------------------------------------------------------------------- #


def _parse_block_state(block: str, no_hw: bool) -> str:
    """
    Derive the interface STATE from one ``show interfaces`` block.

    Priority order (highest first):
    1. Hardware is not present → ``"NO HW"``
    2. administratively down   → ``"ADMIN DOWN"``
    3. line protocol is up     → ``"UP"``
    4. anything else           → ``"DOWN"``
    """
    if no_hw:
        return "NO HW"
    first_line = block.split("\n", 1)[0]
    if re.search(r"\badministratively\s+down\b", first_line, re.IGNORECASE):
        return "ADMIN DOWN"
    # Search only the first ~400 chars to avoid false matches in description fields
    if re.search(r"\bline protocol is up\b", block[:400], re.IGNORECASE):
        return "UP"
    return "DOWN"


def parse_last_input(block: str) -> Optional[str]:
    """
    Extract the ``Last input`` timer from one interface block.

    Handles all Cisco IOS / IOS-XE formats seen in ``show interfaces``:

    - ``never``
    - ``00:02:13``   (HH:MM:SS)
    - ``3w2d``       (compact: weeks+days)
    - ``2y11w``      (compact: years+weeks)
    - ``0Y 5W 0D 0H 0m 0S``  (verbose long form)

    Returns the raw string as-is (stripped) so the caller stores the exact
    value the device reports.  Returns ``None`` when the pattern is absent.
    """
    m = _LAST_INPUT_RE.search(block)
    if not m:
        return None
    return m.group(1).strip()


def collect_last_input(cisco: CiscoDeviceClient):
    """
    Run ``show interfaces`` once and return
    ``(last_input_map, no_hw_set, state_map)``.

    ``last_input_map``
        ``{expanded_iface_name: timer_string}``
        For SVI (Vlan) interfaces the **output** timer is used instead of
        the input timer, because SVIs forward traffic outward and the output
        value is more representative of real activity.

    ``no_hw_set``
        ``set[expanded_iface_name]`` — interfaces with "Hardware is not present".

    ``state_map``
        ``{expanded_iface_name: "UP"|"DOWN"|"ADMIN DOWN"|"NO HW"}``
        Derived directly from the verbose ``show interfaces`` output, which
        has richer detail than ``show interfaces status`` and covers *all*
        interface types (SVIs, management, subinterfaces, etc.).

    Block splitting uses :func:`re.finditer` so every interface block is
    captured regardless of the state text that follows "is ".
    """
    try:
        raw = cisco._cli_connection.send_command("show interfaces")
    except Exception as exc:
        log.warning("show interfaces failed: %s", exc)
        return {}, set(), {}

    last_input_map: Dict[str, str] = {}
    no_hw_set:      set            = set()
    state_map:      Dict[str, str] = {}

    headers     = list(_IFACE_HEADER_RE.finditer(raw))
    total_found = len(headers)
    missing_li  = 0

    for i, hdr in enumerate(headers):
        raw_name   = hdr.group(1)
        iface_name = expand_interface_name(raw_name)

        # Slice from this header to the start of the next (or end of output)
        block_start = hdr.start()
        block_end   = headers[i + 1].start() if i + 1 < len(headers) else len(raw)
        block       = raw[block_start:block_end]

        # ── Hardware absent? ──────────────────────────────────────────────
        no_hw = bool(_NO_HW_RE.search(block))
        if no_hw:
            no_hw_set.add(iface_name)

        # ── State (derived from block, overrides show interfaces status) ──
        state_map[iface_name] = _parse_block_state(block, no_hw)

        # ── Last-input timer ──────────────────────────────────────────────
        # SVI (Vlan) interfaces: use the OUTPUT timer — input is nearly always
        # very recent because the control plane writes to the SVI itself, while
        # the output timer reflects when real data last traversed the VLAN.
        is_svi = raw_name.lower().startswith("vlan")
        if is_svi:
            m = _LAST_OUTPUT_RE.search(block)
            if m:
                last_input_map[iface_name] = m.group(1).strip()
            else:
                # Fall back to input timer when no output line is present
                li = parse_last_input(block)
                if li is not None:
                    last_input_map[iface_name] = li
                else:
                    missing_li += 1
        else:
            li = parse_last_input(block)
            if li is not None:
                last_input_map[iface_name] = li
            else:
                missing_li += 1
                log.debug("No Last input line found for %s", iface_name)

    log.info(
        "show interfaces: %d found, %d with timer, "
        "%d missing timer, %d NO HW, %d state entries",
        total_found, len(last_input_map),
        missing_li, len(no_hw_set), len(state_map),
    )

    return last_input_map, no_hw_set, state_map


def convert_last_input_to_seconds(value: str) -> Optional[int]:
    """
    Convert a Cisco ``Last input`` string to total seconds.

    Supported formats
    -----------------
    ``HH:MM:SS``
        ``01:30:00`` → 5400

    Natural language (uptime substitution output)
        ``"4 years, 40 weeks, 3 days, 1 hour, 10 minutes"`` → seconds

    Compact short (IOS default for recently-active ports)
        ``"3w2d"``, ``"2y11w"`` → seconds

    Verbose long (some IOS-XE builds)
        ``"0Y 5W 0D 0H 0m 0S"`` → seconds

    Returns ``None`` when the value cannot be parsed so the caller can skip
    the interface rather than using a wrong count.
    """
    if not value or not isinstance(value, str):
        return None

    v = value.strip()

    # ── HH:MM:SS ─────────────────────────────────────────────────────────
    m = _LI_HHMMSS_RE.fullmatch(v)
    if m:
        return int(m.group(1)) * 3600 + int(m.group(2)) * 60 + int(m.group(3))

    # ── All other formats: sum every matched unit ─────────────────────────
    total   = 0
    matched = False
    for pattern, multiplier in _LI_UNITS:
        hit = pattern.search(v)
        if hit:
            total   += int(hit.group(1)) * multiplier
            matched  = True

    return total if matched else None


def parse_switch_uptime(show_version_output: str) -> Dict[int, str]:
    """
    Parse switch uptime from ``show version`` output.

    Returns ``{switch_number: uptime_string}``.

    Stack switches
    --------------
    Looks for sections headed by ``Switch <N>`` followed by a separator line
    and a ``Switch uptime :`` field:

        Switch 01
        ---------
        Switch uptime                 : 4 years, 40 weeks, 3 days, 1 hour, 10 minutes

        Switch 02
        ---------
        Switch uptime                 : 2 years, 19 weeks, 5 days, 22 hours, 15 minutes

    Returns ``{1: "4 years, 40 weeks...", 2: "2 years, 19 weeks..."}``.

    Single switch
    -------------
    Falls back to the global uptime line:

        hostname uptime is 4 years, 40 weeks, 3 days

    Returns ``{1: "4 years, 40 weeks, 3 days"}``.
    """
    result: Dict[int, str] = {}

    # Per-stack-member header: "Switch 01" on its own line
    _stack_header_re = re.compile(r"^Switch\s+(\d+)\s*$", re.MULTILINE)
    _stack_uptime_re = re.compile(r"Switch\s+uptime\s*:\s*(.+)", re.IGNORECASE)

    headers = list(_stack_header_re.finditer(show_version_output))
    if headers:
        for i, header in enumerate(headers):
            sw_num = int(header.group(1))
            start  = header.end()
            end    = headers[i + 1].start() if i + 1 < len(headers) else len(show_version_output)
            section = show_version_output[start:end]
            m = _stack_uptime_re.search(section)
            if m:
                result[sw_num] = m.group(1).strip()
            else:
                log.debug("No 'Switch uptime' found in Switch %s section", sw_num)

    # Fallback: single-chassis global uptime line
    # Example: "hostname uptime is 4 years, 40 weeks, 3 days"
    if not result:
        m = re.search(r"^\S+\s+uptime\s+is\s+(.+)$",
                      show_version_output, re.MULTILINE | re.IGNORECASE)
        if m:
            result[1] = m.group(1).strip()

    return result


def get_interface_switch_number(interface_name: str) -> Optional[int]:
    """
    Extract the stack/member switch number from a 3-part Cisco interface name.

    ``GigabitEthernet2/0/1``    → ``2``
    ``TenGigabitEthernet3/1/1`` → ``3``
    ``GigabitEthernet0/1``      → ``None``  (2-part — not a stacked interface)

    The first numeric component is the stack member on Catalyst stacked platforms.
    2-part interfaces (module/port) belong to standalone switches and have no
    member number, so ``None`` is returned.
    """
    # Match: alpha prefix, then first_number, then at least two more /N parts
    m = re.match(r"^[A-Za-z][A-Za-z0-9\-]+?(\d+)((?:/\d+){2,})$", interface_name)
    if not m:
        return None
    try:
        return int(m.group(1))
    except ValueError:
        return None


# --------------------------------------------------------------------------- #
# Per-device worker                                                            #
# --------------------------------------------------------------------------- #


def update_device_state(device: dict, nb: NetBoxClient, args) -> dict:
    """
    Collect interface state from *device* and update NetBox ``STATE`` fields.

    Never raises — all errors are captured in the returned summary dict so the
    ThreadPoolExecutor can continue processing the remaining devices.

    Parameters
    ----------
    device : dict
        NetBox device dict (may include ``_vc_id`` / ``_vc_name`` keys when
        resolved from a Virtual Chassis via :func:`resolve_single_device`).
    nb : NetBoxClient
    args : argparse.Namespace

    Returns
    -------
    dict
        Per-device result summary::

            {
                "device":             str,
                "status":             "success" | "failed",
                "transport_used":     "cli" | None,
                "interfaces_checked": int,
                "states_updated":     int,
                "states_unchanged":   int,
                "errors":             list[str],
            }
    """
    device_name = device.get("name", "unknown")
    device_id   = device.get("id")

    summary: dict = {
        "device":               device_name,
        "status":               "failed",
        "transport_used":       None,
        "interfaces_checked":   0,
        "states_updated":       0,
        "states_unchanged":     0,
        "last_input_updated":   0,
        "last_input_unchanged": 0,
        "unused_ports":         0,
        "admin_down_ports":     0,
        "threshold_ports":      0,
        "errors":               [],
    }

    # ── Gate: device must have a primary IP ──────────────────────────────
    if not _device_has_primary_ip(device):
        summary["errors"].append(
            "Device has no primary_ip4 or primary_ip6 in NetBox — skipped. "
            "Assign a primary IP before running this script."
        )
        log.warning("%-30s  SKIPPED — no primary IP in NetBox", device_name)
        return summary

    mgmt_ip = get_device_mgmt_ip(device)
    if not mgmt_ip:
        summary["errors"].append("No primary IP configured in NetBox — cannot connect.")
        return summary

    os_type = get_device_os_type(device)
    if not os_type:
        summary["errors"].append(
            f"Cannot determine os_type from platform "
            f"{device.get('platform')!r}. Add slug to PLATFORM_SLUG_MAP."
        )
        return summary

    log.info(
        "%-30s  ip=%-18s  os_type=%-6s  transport=%s",
        device_name, mgmt_ip, os_type, args.transport,
    )

    # ── VC member map (position → device_id) ────────────────────────────
    vc_member_map: Dict[int, int] = {}
    vc_id = device.get("_vc_id")
    if vc_id:
        vc_member_map = build_vc_member_map(vc_id, nb)
        if vc_member_map:
            log.info(
                "%-30s  VC id=%s  member map: %s",
                device_name, vc_id,
                {pos: did for pos, did in sorted(vc_member_map.items())},
            )
        else:
            log.warning(
                "%-30s  VC id=%s found but no members have vc_position set — "
                "using master device for all interfaces.",
                device_name, vc_id,
            )

    # ── Connect to device ────────────────────────────────────────────────
    enable_secret = getattr(args, "enable_secret", None) or None
    cisco = CiscoDeviceClient(
        host=mgmt_ip,
        username=args.username,
        password=args.password,
        os_type=os_type,
        enable_secret=enable_secret,
        timeout=args.timeout,
        verify_ssl=False,
    )
    # Honour --transport on the client instance so every collection method
    # that respects self.transport (VLAN, trunk, IP) is also locked.
    cisco.transport = args.transport

    # ── Collect interface states ─────────────────────────────────────────
    # get_interface_state_inventory() always uses CLI (show interfaces status).
    # It is not gated by cisco.transport because no NETCONF/RESTCONF model
    # covers this operational data reliably across all platforms.
    try:
        states = cisco.get_interface_state_inventory()
    except CiscoDeviceClientError as exc:
        summary["errors"].append(f"Interface state collection failed: {exc}")
        log.error("%-30s  State collection failed: %s", device_name, exc)
        cisco._cli_disconnect()
        return summary

    summary["transport_used"] = "cli"
    log.info(
        "%-30s  collected state for %d interface(s)",
        device_name, len(states),
    )

    # ── Collect last-input timers (IOS / IOS-XE only) ────────────────────
    # "show interfaces" Last input parsing is only reliable on IOS and IOS-XE.
    # NX-OS and other platforms produce different output formats; skip them.
    _LAST_INPUT_SUPPORTED = {"ios", "iosxe"}
    last_input_map:  Dict[str, str] = {}
    no_hw_set:       set            = set()
    show_state_map:  Dict[str, str] = {}   # state derived from "show interfaces"
    if os_type not in _LAST_INPUT_SUPPORTED:
        log.info(
            "%-30s  last_input collection skipped — not supported for os_type=%r",
            device_name, os_type,
        )
    else:
        try:
            last_input_map, no_hw_set, show_state_map = collect_last_input(cisco)
            log.info(
                "%-30s  collected last_input for %d interface(s), "
                "NO HW: %d, state entries: %d",
                device_name, len(last_input_map),
                len(no_hw_set), len(show_state_map),
            )
        except Exception as exc:
            log.warning(
                "%-30s  last_input collection failed — continuing without it: %s",
                device_name, exc,
            )

    # ── Collect switch uptime (IOS / IOS-XE; used to replace "never") ───────
    # Only run "show version" when last_input_map was populated — if collection
    # was skipped (wrong OS) or failed, uptime_map stays empty and the
    # substitution loop below is a no-op.
    uptime_map: Dict[int, str] = {}
    if os_type in _LAST_INPUT_SUPPORTED and last_input_map:
        try:
            raw_ver  = cisco._cli_connection.send_command("show version")
            uptime_map = parse_switch_uptime(raw_ver)
            log.info(
                "%-30s  collected uptime for %d switch(es): %s",
                device_name, len(uptime_map),
                {k: v[:40] for k, v in uptime_map.items()},
            )
        except Exception as exc:
            log.warning(
                "%-30s  show version failed — 'never' values will not be "
                "substituted with uptime: %s",
                device_name, exc,
            )

    # ── Replace "never" last_input values with the switch's uptime ───────
    uptime_substituted = 0
    if uptime_map:
        for iface_name in list(last_input_map.keys()):
            if last_input_map[iface_name].lower() != "never":
                continue
            switch_num = get_interface_switch_number(iface_name)
            uptime = uptime_map.get(switch_num) or uptime_map.get(1)
            if uptime:
                last_input_map[iface_name] = uptime
                uptime_substituted += 1
                log.debug(
                    "%-30s  %s: last_input=never → uptime %r (switch %s)",
                    device_name, iface_name, uptime, switch_num,
                )
            else:
                log.warning(
                    "%-30s  %s: last_input=never but no uptime found for "
                    "switch %s — keeping 'never'",
                    device_name, iface_name, switch_num,
                )
    if uptime_substituted:
        log.info(
            "%-30s  replaced 'never' with uptime for %d interface(s)",
            device_name, uptime_substituted,
        )

    # Compute a single timestamp for all updates in this run so the value is
    # stable within a device pass.
    now_ts          = datetime.now().astimezone().isoformat(timespec="seconds")
    state_update_ts = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # ── Unused-ports threshold (from device custom field) ─────────────────
    raw_ut = (device.get("custom_fields") or {}).get(_CF_UNUSED_TIME)
    try:
        unused_time_secs = int(raw_ut) if raw_ut is not None else 0
    except (ValueError, TypeError):
        log.warning(
            "%-30s  unused_time CF value %r is not an integer — using 0",
            device_name, raw_ut,
        )
        unused_time_secs = 0

    unused_ports   = 0
    admin_down_cnt = 0
    threshold_cnt  = 0

    # ── Build merged interface → state mapping ────────────────────────────
    # seed from show interfaces status (existing source; may have fewer entries)
    all_iface_states: Dict[str, str] = {}
    for state_rec in states:
        name = expand_interface_name(state_rec.get("name", ""))
        if name:
            all_iface_states[name] = state_rec.get("state") or "DOWN"

    # Override / extend with show interfaces data (richer; has NO HW, SVIs, etc.)
    # This ensures every interface that appeared in show interfaces is processed
    # even when show interfaces status omitted it.
    all_iface_states.update(show_state_map)

    log.info(
        "%-30s  total_interfaces_detected=%d  (show_if=%d  show_if_status=%d)  "
        "interfaces_set_NO_HW=%d",
        device_name, len(all_iface_states),
        len(show_state_map), len(states), len(no_hw_set),
    )

    # ── Per-interface state comparison and update ────────────────────────
    for iface_name, iface_state in all_iface_states.items():

        # Route to the correct VC member device (same logic as _sync_trunks).
        target_id = resolve_target_device_id(iface_name, device_id, vc_member_map)

        summary["interfaces_checked"] += 1

        # ── Unused-ports counting ─────────────────────────────────────────
        # Runs unconditionally (dry-run and live) so the logged totals are
        # always accurate.  Writing to NetBox happens only in live mode.
        # NO HW counts as unused — the port has no physical hardware installed.
        if iface_state in ("ADMIN DOWN", "NO HW"):
            unused_ports   += 1
            admin_down_cnt += 1
        else:
            li_val = last_input_map.get(iface_name)
            if li_val is not None:
                li_secs = convert_last_input_to_seconds(li_val)
                if li_secs is None:
                    log.debug(
                        "%-30s  %s: last_input %r not parseable — "
                        "excluded from unused count",
                        device_name, iface_name, li_val,
                    )
                elif li_secs > unused_time_secs:
                    unused_ports  += 1
                    threshold_cnt += 1

        log.debug(
            "%-30s  Interface %s state detected as %s (dev_id=%s)",
            device_name, iface_name, iface_state, target_id,
        )

        if args.dry_run:
            # In dry-run mode: resolve the current NetBox value for accurate
            # logging but do not write anything.
            try:
                nb_rec = nb.get_interface_by_name(target_id, iface_name)
                nb_state = (
                    (nb_rec.get("custom_fields") or {}).get(_CF_STATE)
                    if nb_rec else None
                )
            except NetBoxClientError:
                nb_state = None

            if nb_state == iface_state:
                log.info(
                    "DRY-RUN  %-30s  STATE unchanged for %s (%s), skipping",
                    device_name, iface_name, iface_state,
                )
            else:
                log.info(
                    "DRY-RUN  %-30s  would update STATE for %s: %s → %s",
                    device_name, iface_name,
                    nb_state or "(null)", iface_state,
                )
            continue

        # ── Live mode: compare and update ────────────────────────────────
        try:
            result = nb.update_interface_state_fields(
                device_id=target_id,
                interface_name=iface_name,
                state_value=iface_state,
            )
        except NetBoxClientError as exc:
            err = f"STATE update {iface_name!r}: {exc}"
            log.error("%-30s  %s", device_name, err)
            summary["errors"].append(err)
            continue

        action    = result.get("_action", "skipped")
        old_state = result.get("old_state")

        if action == "updated":
            summary["states_updated"] += 1
            log.info(
                "%-30s  Updating STATE for %s: %s → %s",
                device_name, iface_name,
                old_state or "(null)", iface_state,
            )
        elif action == "not_found":
            log.warning(
                "%-30s  %s not found in NetBox (dev_id=%s) — skipped",
                device_name, iface_name, target_id,
            )
        else:
            summary["states_unchanged"] += 1
            log.debug(
                "%-30s  STATE unchanged for %s (%s), skipping",
                device_name, iface_name, iface_state,
            )

    # ── Unused-ports summary + device CF update ──────────────────────────
    summary["unused_ports"]     = unused_ports
    summary["admin_down_ports"] = admin_down_cnt
    summary["threshold_ports"]  = threshold_cnt

    log.info(
        "%-30s  unused_ports=%d  (admin_down=%d  threshold=%d)",
        device_name, unused_ports, admin_down_cnt, threshold_cnt,
    )

    if not args.dry_run:
        try:
            nb.update_device_custom_fields(
                device_id,
                {
                    _CF_UNUSED_PORTS: unused_ports,
                    _CF_STATE_UPDATE: state_update_ts,
                },
            )
            log.info(
                "%-30s  device CF updated: unused_ports=%d  state_update=%s",
                device_name, unused_ports, state_update_ts,
            )
        except NetBoxClientError as exc:
            log.warning("%-30s  device CF update failed: %s", device_name, exc)
            summary["errors"].append(f"device CF update: {exc}")
    else:
        log.info(
            "DRY-RUN  %-30s  would update device CF: unused_ports=%d  state_update=%s",
            device_name, unused_ports, state_update_ts,
        )

    # ── Per-interface last_input update ──────────────────────────────────
    if last_input_map and not args.dry_run:
        for iface_name, last_input_val in last_input_map.items():
            target_id = resolve_target_device_id(iface_name, device_id, vc_member_map)

            try:
                nb_rec = nb.get_interface_by_name(target_id, iface_name)
            except NetBoxClientError as exc:
                log.warning(
                    "%-30s  last_input: lookup failed for %s: %s",
                    device_name, iface_name, exc,
                )
                continue

            if nb_rec is None:
                log.debug(
                    "%-30s  last_input: %s not in NetBox — skipped",
                    device_name, iface_name,
                )
                continue

            current_val = (nb_rec.get("custom_fields") or {}).get(_CF_LAST_INPUT)
            if current_val == last_input_val:
                summary["last_input_unchanged"] += 1
                log.debug(
                    "%-30s  last_input unchanged for %s (%s)",
                    device_name, iface_name, last_input_val,
                )
                continue

            try:
                nb.update_interface(
                    nb_rec["id"],
                    {"custom_fields": {
                        _CF_LAST_INPUT:     last_input_val,
                        _CF_IF_LAST_UPDATE: now_ts,
                    }},
                )
                summary["last_input_updated"] += 1
                log.info(
                    "%-30s  last_input updated for %s: %r → %r  if_last_update=%s",
                    device_name, iface_name,
                    current_val or "(null)", last_input_val, now_ts,
                )
            except NetBoxClientError as exc:
                err = f"last_input update {iface_name!r}: {exc}"
                log.warning("%-30s  %s", device_name, err)
                summary["errors"].append(err)

    elif last_input_map and args.dry_run:
        for iface_name, last_input_val in last_input_map.items():
            log.info(
                "DRY-RUN  %-30s  would update last_input for %s: %r",
                device_name, iface_name, last_input_val,
            )

    log.info(
        "%-30s  last_input: updated=%d unchanged=%d",
        device_name,
        summary["last_input_updated"],
        summary["last_input_unchanged"],
    )

    cisco._cli_disconnect()
    summary["status"] = "success"
    return summary


# --------------------------------------------------------------------------- #
# Entry point                                                                  #
# --------------------------------------------------------------------------- #


def main() -> None:
    # Reuse the exact same parser as sync_netbox_interfaces so every flag
    # (device selection, credentials, transport, concurrency, dry-run) is
    # identical.  Sync-specific flags (--sync-vlans, --skip-vlan-ids, etc.)
    # are parsed but not used by this program.
    parser = build_parser()
    parser.prog        = "netbox_update_State"
    parser.description = (
        "Collect Cisco interface operational state and update the NetBox "
        "STATE custom field (plus state_change on transitions)."
    )
    args = parser.parse_args()

    _configure_logging(args.log_level, args.log_file)

    # ── Validate required fields ─────────────────────────────────────────
    missing: List[str] = []
    if not args.netbox_url:
        missing.append("--netbox-url  or  NETBOX_URL")
    if not args.netbox_token:
        missing.append("--netbox-token  or  NETBOX_API")
    if not args.username:
        missing.append("--username  or  CISCO_SRV_ACCOUNT")
    if not args.password:
        missing.append("--password  or  CISCO_SRV_PWD")
    if missing:
        log.error(
            "Missing required arguments / environment variables:\n  %s",
            "\n  ".join(missing),
        )
        sys.exit(1)

    if args.dry_run:
        log.info("*** DRY-RUN mode — no changes will be written to NetBox ***")

    # ── NetBox client ────────────────────────────────────────────────────
    nb = NetBoxClient(
        base_url=args.netbox_url,
        token=args.netbox_token,
        verify_ssl=args.netbox_verify_ssl,
        threading=True,
    )

    # ── Device selection ─────────────────────────────────────────────────
    devices = resolve_device_list(args, nb)
    if not devices:
        log.warning("No devices to process.")
        print(json.dumps([], indent=2))
        return

    log.info(
        "Processing %d device(s), %d worker(s), transport=%s",
        len(devices), args.max_workers, args.transport,
    )

    # ── Concurrent per-device processing ────────────────────────────────
    summaries: List[dict] = []
    with ThreadPoolExecutor(max_workers=args.max_workers) as pool:
        future_to_device = {
            pool.submit(update_device_state, device, nb, args): device
            for device in devices
        }
        for future in as_completed(future_to_device):
            device      = future_to_device[future]
            device_name = device.get("name", "unknown")
            try:
                result = future.result()
                summaries.append(result)
                log.info(
                    "%-30s  status=%-8s  checked=%d  "
                    "state_upd=%d  state_unch=%d  "
                    "last_input_upd=%d  unused=%d  errs=%d",
                    device_name,
                    result.get("status", "?"),
                    result.get("interfaces_checked", 0),
                    result.get("states_updated", 0),
                    result.get("states_unchanged", 0),
                    result.get("last_input_updated", 0),
                    result.get("unused_ports", 0),
                    len(result.get("errors", [])),
                )
            except Exception as exc:
                log.error("Unexpected error for %s: %s", device_name, exc, exc_info=True)
                summaries.append({
                    "device":             device_name,
                    "status":             "failed",
                    "transport_used":     None,
                    "interfaces_checked": 0,
                    "states_updated":     0,
                    "states_unchanged":   0,
                    "unused_ports":       0,
                    "admin_down_ports":   0,
                    "threshold_ports":    0,
                    "errors":             [str(exc)],
                })

    summaries.sort(key=lambda s: s.get("device", ""))

    # ── Totals summary to stderr ─────────────────────────────────────────
    total_ok   = sum(1 for s in summaries if s.get("status") == "success")
    total_fail = len(summaries) - total_ok
    log.info(
        "DONE  devices=%d ok=%d failed=%d  "
        "states: updated=%d unchanged=%d  "
        "last_input: updated=%d",
        len(summaries), total_ok, total_fail,
        sum(s.get("states_updated",      0) for s in summaries),
        sum(s.get("states_unchanged",    0) for s in summaries),
        sum(s.get("last_input_updated",  0) for s in summaries),
    )

    print(json.dumps(summaries, indent=2))


if __name__ == "__main__":
    main()
