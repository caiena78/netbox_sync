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
_CF_STATE         = "STATE"
_CF_STATE_CHANGE  = "state_change"

log = logging.getLogger("netbox_update_State")

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
        "device":             device_name,
        "status":             "failed",
        "transport_used":     None,
        "interfaces_checked": 0,
        "states_updated":     0,
        "states_unchanged":   0,
        "errors":             [],
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

    # Compute a single timestamp for all state-change updates in this run so
    # the value is stable within a device pass.
    now_ts = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # ── Per-interface state comparison and update ────────────────────────
    for state_rec in states:
        raw_name    = state_rec.get("name", "")
        iface_name  = expand_interface_name(raw_name)
        iface_state = state_rec.get("state") or "UNKNOWN"

        if iface_state == "UNKNOWN":
            log.warning(
                "%-30s  %s: state could not be determined — using UNKNOWN",
                device_name, iface_name,
            )

        # Route to the correct VC member device (same logic as _sync_trunks).
        target_id = resolve_target_device_id(iface_name, device_id, vc_member_map)

        summary["interfaces_checked"] += 1

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
                    "DRY-RUN  %-30s  would update STATE for %s: %s → %s; "
                    "state_change=%s",
                    device_name, iface_name,
                    nb_state or "(null)", iface_state, now_ts,
                )
            continue

        # ── Live mode: compare and update ────────────────────────────────
        try:
            result = nb.update_interface_state_fields(
                device_id=target_id,
                interface_name=iface_name,
                state_value=iface_state,
                state_change_ts=now_ts,
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
                "%-30s  Updating STATE for %s: %s → %s; state_change=%s",
                device_name, iface_name,
                old_state or "(null)", iface_state, now_ts,
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
                    "%-30s  status=%-8s  checked=%d  updated=%d  "
                    "unchanged=%d  errs=%d",
                    device_name,
                    result.get("status", "?"),
                    result.get("interfaces_checked", 0),
                    result.get("states_updated", 0),
                    result.get("states_unchanged", 0),
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
                    "errors":             [str(exc)],
                })

    summaries.sort(key=lambda s: s.get("device", ""))

    # ── Totals summary to stderr ─────────────────────────────────────────
    total_ok   = sum(1 for s in summaries if s.get("status") == "success")
    total_fail = len(summaries) - total_ok
    log.info(
        "DONE  devices=%d ok=%d failed=%d  "
        "states: updated=%d unchanged=%d",
        len(summaries), total_ok, total_fail,
        sum(s.get("states_updated",   0) for s in summaries),
        sum(s.get("states_unchanged", 0) for s in summaries),
    )

    print(json.dumps(summaries, indent=2))


if __name__ == "__main__":
    main()
