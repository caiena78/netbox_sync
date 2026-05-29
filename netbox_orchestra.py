#!/usr/bin/env python3
"""
netbox_orchestra.py
===================
Orchestrates three existing scripts in sequence for every device resolved
from NetBox:

  1. sync_netbox_interfaces.py   — interface / VLAN / trunk / prefix sync
  2. netbox_cables.py            — CDP physical cable discovery
  3. netbox_update_State.py      — interface operational-state sync

For each device the three stages are executed in the order above.  If any
stage fails the remaining stages for that device are skipped, and the next
device is processed.  A non-zero exit code is returned if any device has
any failed or only partially-completed stages.

Authentication
--------------
Credentials are resolved in the same way as the child scripts (Vault first,
then legacy CLI / env-var fallback).

  Vault mode (recommended):
    export VAULT_ADDR=https://vault.example.org
    export VAULT_ROLE_ID=<role_id>
    export VAULT_SECRET_ID=<secret_id>

  Legacy mode:
    export NETBOX_URL=https://netbox.example.org
    export NETBOX_API=<token>
    export CISCO_SRV_ACCOUNT=svc-netauto
    export CISCO_SRV_PWD=s3cr3t

Usage examples
--------------
  # Single device — Vault env vars pre-set
  python netbox_orchestra.py --device core-rtr-01

  # All active IOS-XE devices
  python netbox_orchestra.py \\
      --device-filter '{"platform": "iosxe", "status": "active"}'

  # Site slug + filter
  python netbox_orchestra.py \\
      --site-slug lakeview \\
      --device-filter '{"status": "active"}'

  # Dry run — child scripts make no NetBox writes
  python netbox_orchestra.py --device core-rtr-01 --dry-run

  # Vault credentials passed on the command line
  python netbox_orchestra.py \\
      --VAULT_ADDR https://vault.example.org \\
      --VAULT_ROLE_ID <role_id> \\
      --VAULT_SECRET_ID <secret_id> \\
      --device-filter '{"status": "active"}'

  # Legacy credentials on the command line
  python netbox_orchestra.py \\
      --netbox-url https://netbox.example.org \\
      --netbox-token <token> \\
      --username svc-netauto \\
      --password s3cr3t \\
      --device core-rtr-01

Design notes
------------
  * Device list is resolved once against NetBox; each device is then
    processed sequentially — no concurrency at the orchestrator level.
  * Child scripts are invoked with sys.executable so the same virtualenv
    is used.  No shell=True.
  * sys.argv[1:] is passed through verbatim except that device-selection
    tokens (--device, --devices, --device-file, --device-filter, --all)
    are stripped and replaced with --device <name> per invocation.
  * netbox_cables.py has a narrower argument parser than the shared
    build_parser() used by the other two scripts.  Flags that cables does
    not recognise are stripped automatically before that invocation.
  * --force in the orchestrator context applies only to sync /
    netbox_update_State (VC interface relocation).  It is intentionally
    NOT forwarded to netbox_cables.py because --force there means "replace
    existing cable records" — a destructive action with different semantics.
    Run netbox_cables.py directly with --force if cable replacement is
    desired.
"""

from __future__ import annotations

import datetime
import json
import logging
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, NamedTuple, Optional, Tuple

from netbox_client import NetBoxClient, NetBoxClientError
from sync_netbox_interfaces import (
    _configure_logging,
    build_parser,
    resolve_device_list,
)
from vault_client import (
    VaultClient,
    VaultError,
    is_vault_configured,
    resolve_vault_auth,
)

# --------------------------------------------------------------------------- #
# Module-level loggers                                                         #
# --------------------------------------------------------------------------- #

log = logging.getLogger("netbox_orchestra")
err_log = logging.getLogger("sync_errors")


# --------------------------------------------------------------------------- #
# Stage descriptor                                                             #
# --------------------------------------------------------------------------- #

class _Stage(NamedTuple):
    key:      str   # dict key used in the scripts map
    filename: str   # script filename relative to the project directory
    label:    str   # human-readable stage name used in log output


_STAGES: Tuple[_Stage, ...] = (
    _Stage("sync",   "sync_netbox_interfaces.py", "sync_interfaces"),
    _Stage("cables", "netbox_cables.py",           "cable_discovery"),
    _Stage("state",  "netbox_update_State.py",     "update_state"),
)


# --------------------------------------------------------------------------- #
# Argv filtering constants                                                     #
# --------------------------------------------------------------------------- #

# Flags that select which devices to process — stripped and replaced with
# --device <name> for each individual child invocation.
_DEVICE_SEL_WITH_VAL: frozenset = frozenset({
    "--device",
    "--devices",
    "--device-file",
    "--device-filter",
})
_DEVICE_SEL_NO_VAL: frozenset = frozenset({
    "--all",
})

# Flags that exist in build_parser() (used by sync / update_state) but are
# absent from netbox_cables.py's own parser.  Passing them to cables would
# cause argparse to raise an "unrecognised arguments" error.
_CABLES_UNSUPPORTED_WITH_VAL: frozenset = frozenset({
    "--skip-vlan-ids",
    "--deny-vlan-group-name-substring",
    "--max-api-connections",
})
_CABLES_UNSUPPORTED_NO_VAL: frozenset = frozenset({
    "--sync-vlans",  "--no-sync-vlans",
    "--sync-trunks", "--no-sync-trunks",
    "--sync-prefixes", "--no-sync-prefixes",
    "--fail-fast",
    "--force-type",
    "--profile",
    "--mem-profile",
    # Different semantics in cables (cable deletion) vs sync (VC relocation).
    "--force",
})

# Flags whose VALUES should be redacted in debug-level command logs.
_SECRET_FLAGS: frozenset = frozenset({
    "--password",
    "--VAULT_ROLE_ID",
    "--VAULT_SECRET_ID",
})


# --------------------------------------------------------------------------- #
# Path helpers                                                                 #
# --------------------------------------------------------------------------- #

def get_script_dir() -> Path:
    """Return the directory that contains this orchestrator file."""
    return Path(__file__).resolve().parent


def resolve_child_script_paths(script_dir: Path) -> Dict[str, Path]:
    """
    Build a ``{key: Path}`` map for every child script.

    Logs an error and calls sys.exit(1) if any script file is missing.
    Called before authentication so failures are reported immediately.
    """
    paths: Dict[str, Path] = {}
    missing: List[str] = []
    for stage in _STAGES:
        p = script_dir / stage.filename
        paths[stage.key] = p
        if not p.exists():
            missing.append(str(p))
    if missing:
        for path in missing:
            log.error("Child script not found: %s", path)
        sys.exit(1)
    return paths


# --------------------------------------------------------------------------- #
# Argv manipulation                                                            #
# --------------------------------------------------------------------------- #

def _strip_flags(
    argv: List[str],
    flags_with_value: frozenset,
    flags_no_value: frozenset,
) -> List[str]:
    """
    Return a copy of *argv* with the given flags (and their values) removed.

    Handles both ``--flag value`` and ``--flag=value`` forms.
    """
    result: List[str] = []
    skip_next = False
    for token in argv:
        if skip_next:
            skip_next = False
            continue
        base = token.split("=", 1)[0] if "=" in token else token
        if base in flags_with_value:
            if "=" not in token:
                skip_next = True   # next token is the value — drop it too
            continue               # drop the flag itself
        if token in flags_no_value:
            continue
        result.append(token)
    return result


def strip_device_selection_args(argv: List[str]) -> List[str]:
    """Remove all device-selection flags from *argv*."""
    return _strip_flags(argv, _DEVICE_SEL_WITH_VAL, _DEVICE_SEL_NO_VAL)


def build_child_argv(
    base_argv: List[str],
    stage_key: str,
    device_name: str,
) -> List[str]:
    """
    Return the full argument list for one child script invocation.

    For the ``cables`` stage, additional sync-only flags that netbox_cables.py
    does not recognise are removed to prevent argparse errors.
    ``--device <device_name>`` is appended at the end.
    """
    argv = list(base_argv)
    if stage_key == "cables":
        argv = _strip_flags(
            argv,
            _CABLES_UNSUPPORTED_WITH_VAL,
            _CABLES_UNSUPPORTED_NO_VAL,
        )
    argv += ["--device", device_name]
    return argv


def _redact_argv(argv: List[str]) -> List[str]:
    """Return *argv* with known secret values replaced by ``***``."""
    result: List[str] = []
    redact_next = False
    for token in argv:
        if redact_next:
            result.append("***")
            redact_next = False
            continue
        base = token.split("=", 1)[0] if "=" in token else token
        if base in _SECRET_FLAGS:
            if "=" in token:
                result.append(f"{base}=***")
            else:
                result.append(token)
                redact_next = True
        else:
            result.append(token)
    return result


# --------------------------------------------------------------------------- #
# Stage runner                                                                 #
# --------------------------------------------------------------------------- #

def run_stage(
    script_path: Path,
    argv: List[str],
    device_name: str,
    stage_label: str,
) -> Dict[str, Any]:
    """
    Launch one child script as a subprocess and return a stage-result dict.

    Child **stderr** (log lines) is forwarded to our stderr in real time,
    prefixed with ``[<device>|<stage>]``.

    Child **stdout** (JSON output) is collected silently; each line is
    available at DEBUG level.

    Returns a dict with keys:
      script, status, returncode, duration_seconds, error
    """
    cmd    = [sys.executable, str(script_path)] + argv
    prefix = f"{device_name}|{stage_label}"

    log.debug("[%s] command: %s", prefix, " ".join(_redact_argv(cmd)))
    log.info("[%s] starting", prefix)

    result: Dict[str, Any] = {
        "script":           script_path.name,
        "status":           "failed",
        "returncode":       None,
        "duration_seconds": 0.0,
        "error":            None,
    }

    t_start = time.monotonic()

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )

        stdout_lines: List[str] = []

        def _drain_stdout() -> None:
            for line in proc.stdout:
                stripped = line.rstrip("\n")
                stdout_lines.append(stripped)
                log.debug("[%s] stdout: %s", prefix, stripped)

        def _drain_stderr() -> None:
            for line in proc.stderr:
                # Forward child log lines to our stderr with a prefix so
                # the operator knows which device/stage produced each line.
                print(f"[{prefix}] {line}", end="", file=sys.stderr, flush=True)

        t_out = threading.Thread(target=_drain_stdout, daemon=True)
        t_err = threading.Thread(target=_drain_stderr, daemon=True)
        t_out.start()
        t_err.start()

        rc = proc.wait()
        t_out.join()
        t_err.join()

        elapsed = round(time.monotonic() - t_start, 2)
        result["returncode"]       = rc
        result["duration_seconds"] = elapsed

        if rc == 0:
            result["status"] = "success"
            log.info("[%s] finished  rc=0  (%.1fs)", prefix, elapsed)
        else:
            result["status"] = "failed"
            result["error"]  = f"exited with code {rc}"
            log.warning("[%s] FAILED  rc=%d  (%.1fs)", prefix, rc, elapsed)
            err_log.error(
                "stage_failed | device=%s stage=%s script=%s rc=%d",
                device_name, stage_label, script_path.name, rc,
            )

    except Exception as exc:
        elapsed = round(time.monotonic() - t_start, 2)
        result["duration_seconds"] = elapsed
        result["error"] = str(exc)
        log.error("[%s] exception: %s", prefix, exc, exc_info=True)
        err_log.error(
            "stage_exception | device=%s stage=%s error=%s",
            device_name, stage_label, exc,
        )

    return result


# --------------------------------------------------------------------------- #
# Per-device orchestration                                                     #
# --------------------------------------------------------------------------- #

def orchestrate_device(
    device: Dict[str, Any],
    scripts: Dict[str, Path],
    base_argv: List[str],
) -> Dict[str, Any]:
    """
    Execute all three stages for *device* and return a device-result dict.

    Stops at the first stage failure; the device status is then:
      ``success``  — all three stages completed with rc=0
      ``partial``  — at least one (but not all) stages succeeded
      ``failed``   — the very first stage failed (no useful work done)
    """
    device_name: str = device["name"]
    t_start    = time.monotonic()
    started_at = (
        datetime.datetime.now(datetime.timezone.utc)
        .strftime("%Y-%m-%dT%H:%M:%SZ")
    )

    log.info("─" * 60)
    log.info("Device: %s", device_name)

    stages:    List[Dict[str, Any]] = []
    succeeded: int = 0

    for stage in _STAGES:
        argv  = build_child_argv(base_argv, stage.key, device_name)
        entry = run_stage(scripts[stage.key], argv, device_name, stage.label)
        entry["stage"] = stage.label
        stages.append(entry)

        if entry["status"] == "success":
            succeeded += 1
        else:
            log.warning(
                "[%s] Stage '%s' failed — skipping remaining stages.",
                device_name, stage.label,
            )
            break

    elapsed     = round(time.monotonic() - t_start, 2)
    finished_at = (
        datetime.datetime.now(datetime.timezone.utc)
        .strftime("%Y-%m-%dT%H:%M:%SZ")
    )

    total_stages = len(_STAGES)
    if succeeded == total_stages:
        status = "success"
    elif succeeded == 0:
        status = "failed"
    else:
        status = "partial"

    log.info(
        "Device %-30s  %-8s  elapsed=%.1fs  stages=%d/%d",
        device_name, status, elapsed, succeeded, total_stages,
    )

    return {
        "device":          device_name,
        "status":          status,
        "stages":          stages,
        "started_at":      started_at,
        "finished_at":     finished_at,
        "elapsed_seconds": elapsed,
    }


# --------------------------------------------------------------------------- #
# Summary                                                                      #
# --------------------------------------------------------------------------- #

def summarize_results(results: List[Dict[str, Any]]) -> None:
    """Log a final summary and write failures/partials to sync_errors.log."""
    total     = len(results)
    succeeded = sum(1 for r in results if r["status"] == "success")
    partial   = sum(1 for r in results if r["status"] == "partial")
    failed    = sum(1 for r in results if r["status"] == "failed")

    log.info("═" * 60)
    log.info(
        "Orchestration complete — total=%d  success=%d  partial=%d  failed=%d",
        total, succeeded, partial, failed,
    )

    if failed:
        names = [r["device"] for r in results if r["status"] == "failed"]
        log.error("Failed devices: %s", ", ".join(names))
        err_log.error("orchestration_failed | %s", ", ".join(names))

    if partial:
        names = [r["device"] for r in results if r["status"] == "partial"]
        log.warning("Partial devices: %s", ", ".join(names))
        err_log.warning("orchestration_partial | %s", ", ".join(names))


# --------------------------------------------------------------------------- #
# Entry point                                                                  #
# --------------------------------------------------------------------------- #

def main() -> None:
    parser = build_parser()
    parser.prog        = "netbox_orchestra"
    parser.description = (
        "Orchestrate sync_netbox_interfaces → netbox_cables → "
        "netbox_update_State in sequence for every resolved NetBox device."
    )
    args = parser.parse_args()

    _configure_logging(args.log_level, getattr(args, "log_file", None))

    # ── Validate child script existence before anything else ──────────────
    scripts = resolve_child_script_paths(get_script_dir())

    # ── Credential resolution ─────────────────────────────────────────────
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
            err_log.error("vault_error | %s", exc)
            sys.exit(1)
        args.username = secrets["user"]
        args.password = secrets["password"]
        netbox_url    = secrets["netbox_url"]
        netbox_token  = secrets["netbox_token"]
    else:
        missing: List[str] = []
        if not args.netbox_url:
            missing.append("--netbox-url / NETBOX_URL")
        if not args.netbox_token:
            missing.append("--netbox-token / NETBOX_API")
        if not args.username:
            missing.append("--username / CISCO_SRV_ACCOUNT")
        if not args.password:
            missing.append("--password / CISCO_SRV_PWD")
        if missing:
            log.error("Missing required credentials: %s", ", ".join(missing))
            sys.exit(1)
        netbox_url   = args.netbox_url
        netbox_token = args.netbox_token

    # ── NetBoxClient for device-list resolution only ──────────────────────
    pool_size = max(
        getattr(args, "max_api_connections", None) or (args.max_workers + 10),
        20,
    )
    nb = NetBoxClient(
        base_url=netbox_url,
        token=netbox_token,
        verify_ssl=args.netbox_verify_ssl,
        threading=True,
        pool_size=pool_size,
    )

    # ── Resolve target device list ────────────────────────────────────────
    try:
        devices = resolve_device_list(args, nb)
    except (NetBoxClientError, Exception) as exc:
        log.error("Failed to resolve device list: %s", exc)
        err_log.error("device_list_error | %s", exc)
        sys.exit(1)

    if not devices:
        log.warning("No devices matched the selection criteria.")
        print(json.dumps([], indent=2))
        sys.exit(0)

    log.info(
        "Resolved %d device(s).  Processing sequentially, 3 stages each.",
        len(devices),
    )

    # ── Build passthrough argv — strip device-selection tokens once ───────
    base_argv = strip_device_selection_args(sys.argv[1:])

    # ── Process devices ───────────────────────────────────────────────────
    results: List[Dict[str, Any]] = []
    try:
        for device in devices:
            result = orchestrate_device(device, scripts, base_argv)
            results.append(result)
    except KeyboardInterrupt:
        log.warning("Interrupted — emitting partial results.")

    # ── JSON result array to stdout ───────────────────────────────────────
    print(json.dumps(results, indent=2))

    # ── Final summary and exit code ───────────────────────────────────────
    summarize_results(results)
    any_non_success = any(r["status"] != "success" for r in results)
    sys.exit(1 if any_non_success else 0)


if __name__ == "__main__":
    main()
