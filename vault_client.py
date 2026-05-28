#!/usr/bin/env python3
"""
vault_client.py
===============
Single point of contact with HashiCorp Vault for the netbox_tools repo.

THIS IS THE ONLY MODULE THAT MAY IMPORT hvac OR CALL VAULT.
All other scripts must import from here.

Public API
----------
VaultClient                  — AppRole-authenticated KV v2 client
VaultError                   — raised on auth / fetch / validation failures
resolve_vault_auth(args)     — resolves (addr, role_id, secret_id) from parsed args
add_vault_parser_args(group) — registers all Vault argparse flags onto a group/parser
check_legacy_credential_flags(args, err_log)
                             — blocks deprecated credential CLI flags; exits on violation

Secret contract
---------------
Vault secrets MUST contain exactly these keys (KV v2 data object):
  user          SSH / service-account username
  password      SSH / service-account password
  netbox_url    NetBox base URL
  netbox_token  NetBox API token

Secret VALUES are never logged or printed anywhere in this module.
"""

from __future__ import annotations

import logging
import os
import sys
from typing import Dict, Optional, Tuple

import hvac
import hvac.exceptions

log = logging.getLogger("vault_client")

_REQUIRED_SECRET_KEYS: frozenset[str] = frozenset({
    "user",
    "password",
    "netbox_url",
    "netbox_token",
})


# --------------------------------------------------------------------------- #
# Exception                                                                     #
# --------------------------------------------------------------------------- #

class VaultError(Exception):
    """Raised when Vault auth, secret fetch, or required-key validation fails."""


# --------------------------------------------------------------------------- #
# Client                                                                        #
# --------------------------------------------------------------------------- #

class VaultClient:
    """
    AppRole-authenticated client for HashiCorp Vault KV v2.

    Results are cached per instance — one Vault round-trip per process run,
    regardless of how many times get_secrets() is called.

    Usage::

        vc = VaultClient(addr, role_id, secret_id,
                         mount="secret", path="network/device")
        secrets = vc.get_secrets()
        # => {"user": "...", "password": "...",
        #     "netbox_url": "...", "netbox_token": "..."}

    Only key *names* ever appear in log messages — values are never logged.
    """

    def __init__(
        self,
        addr: str,
        role_id: str,
        secret_id: str,
        mount: str = "secret",
        path: str = "network/device",
    ) -> None:
        self._addr      = addr
        self._mount     = mount
        self._path      = path
        self._role_id   = role_id
        self._secret_id = secret_id
        self._client: Optional[hvac.Client] = None
        self._cache: Optional[Dict[str, str]] = None

    # ------------------------------------------------------------------ #

    def _authenticate(self) -> hvac.Client:
        """
        Perform AppRole login and return an authenticated hvac.Client.

        role_id and secret_id are cleared from memory after the attempt,
        whether it succeeds or fails, to minimize secret exposure window.
        """
        client = hvac.Client(url=self._addr)
        try:
            client.auth.approle.login(
                role_id=self._role_id,
                secret_id=self._secret_id,
            )
        except hvac.exceptions.VaultError as exc:
            raise VaultError(f"Vault AppRole auth failed: {exc}") from exc
        except Exception as exc:
            raise VaultError(
                f"Unexpected error during Vault authentication: {exc}"
            ) from exc
        finally:
            self._role_id   = ""
            self._secret_id = ""

        if not client.is_authenticated():
            raise VaultError(
                "Vault AppRole authentication completed but no valid token was issued."
            )

        log.debug("Vault authentication succeeded (addr=%s)", self._addr)
        return client

    # ------------------------------------------------------------------ #

    def get_secrets(self) -> Dict[str, str]:
        """
        Fetch KV v2 secret and return a dict with keys:
          user, password, netbox_url, netbox_token

        Results are cached after the first call — subsequent calls return
        the cached dict without contacting Vault again.

        Raises VaultError on any failure.
        Never logs or prints secret values.
        """
        if self._cache is not None:
            return self._cache

        if self._client is None:
            self._client = self._authenticate()

        log.debug(
            "Fetching Vault secret from mount=%r path=%r", self._mount, self._path
        )

        try:
            resp = self._client.secrets.kv.v2.read_secret_version(
                mount_point=self._mount,
                path=self._path,
                raise_on_deleted_version=True,
            )
        except hvac.exceptions.InvalidPath as exc:
            raise VaultError(
                f"Vault secret not found — mount={self._mount!r} path={self._path!r}: {exc}"
            ) from exc
        except hvac.exceptions.Forbidden as exc:
            raise VaultError(
                f"Vault permission denied — mount={self._mount!r} path={self._path!r}: {exc}"
            ) from exc
        except hvac.exceptions.VaultError as exc:
            raise VaultError(f"Vault secret read error: {exc}") from exc
        except Exception as exc:
            raise VaultError(
                f"Unexpected error reading Vault secret: {exc}"
            ) from exc

        raw: dict = resp.get("data", {}).get("data", {})

        missing = sorted(_REQUIRED_SECRET_KEYS - raw.keys())
        if missing:
            raise VaultError(
                f"Vault secret at '{self._mount}/{self._path}' is missing required "
                f"key(s): {', '.join(missing)}"
            )

        self._cache = {k: str(raw[k]) for k in _REQUIRED_SECRET_KEYS}
        log.debug(
            "Vault secrets loaded from %s/%s (keys present: %s)",
            self._mount, self._path, ", ".join(sorted(self._cache)),
        )
        return self._cache


# --------------------------------------------------------------------------- #
# Argparse helper — call from any script's build_parser()                      #
# --------------------------------------------------------------------------- #

def add_vault_parser_args(group) -> None:
    """
    Register all standard Vault CLI flags onto *group* (argparse group or parser).

    Registers:
      --VAULT_ADDR        Vault server URL          (env: VAULT_ADDR)
      --VAULT_ROLE_ID     AppRole role ID            (env: VAULT_ROLE_ID)
      --VAULT_SECRET_ID   AppRole secret ID          (env: VAULT_SECRET_ID)
      --use-env-only      Reject Vault CLI args; read only from env vars
      --vault-mount       KV v2 mount point          (default: secret)
      --vault-path        KV v2 secret path          (default: network/device)

    Example::

        vault_grp = p.add_argument_group("Vault authentication")
        add_vault_parser_args(vault_grp)
    """
    group.add_argument(
        "--VAULT_ADDR", default=None, metavar="URL",
        help="Vault server address (env: VAULT_ADDR)",
    )
    group.add_argument(
        "--VAULT_ROLE_ID", default=None, metavar="ROLE_ID",
        help="Vault AppRole role ID (env: VAULT_ROLE_ID)",
    )
    group.add_argument(
        "--VAULT_SECRET_ID", default=None, metavar="SECRET_ID",
        help="Vault AppRole secret ID (env: VAULT_SECRET_ID)",
    )
    group.add_argument(
        "--use-env-only", action="store_true",
        help=(
            "Read Vault credentials from environment variables only. "
            "Providing --VAULT_ADDR, --VAULT_ROLE_ID, or --VAULT_SECRET_ID "
            "together with this flag is treated as a configuration error."
        ),
    )
    group.add_argument(
        "--vault-mount", default="secret", metavar="MOUNT",
        help="Vault KV v2 mount point (default: secret)",
    )
    group.add_argument(
        "--vault-path", default="network/device", metavar="PATH",
        help="Vault KV v2 secret path (default: network/device)",
    )


# --------------------------------------------------------------------------- #
# Runtime helpers — call from any script's main()                              #
# --------------------------------------------------------------------------- #

def resolve_vault_auth(args) -> Tuple[str, str, str]:
    """
    Resolve ``(vault_addr, vault_role_id, vault_secret_id)`` from *args*.

    Behavior:
    - ``--use-env-only``: reads from environment variables only; exits if any
      of the three Vault CLI args are also present.
    - Default: CLI value takes precedence, falls back to environment variable.

    Exits with status 1 (via ``raise SystemExit``) on any validation failure.
    Returns a 3-tuple suitable for ``VaultClient.__init__()``.
    """
    if getattr(args, "use_env_only", False):
        vault_cli_provided = [
            flag
            for flag, val in (
                ("--VAULT_ADDR",      getattr(args, "VAULT_ADDR",      None)),
                ("--VAULT_ROLE_ID",   getattr(args, "VAULT_ROLE_ID",   None)),
                ("--VAULT_SECRET_ID", getattr(args, "VAULT_SECRET_ID", None)),
            )
            if val is not None
        ]
        if vault_cli_provided:
            log.error(
                "--use-env-only is set but Vault CLI args were also provided (%s). "
                "Remove those args when using --use-env-only.",
                ", ".join(vault_cli_provided),
            )
            raise SystemExit(1)
        addr      = os.environ.get("VAULT_ADDR",      "")
        role_id   = os.environ.get("VAULT_ROLE_ID",   "")
        secret_id = os.environ.get("VAULT_SECRET_ID", "")
    else:
        addr      = getattr(args, "VAULT_ADDR",      None) or os.environ.get("VAULT_ADDR",      "")
        role_id   = getattr(args, "VAULT_ROLE_ID",   None) or os.environ.get("VAULT_ROLE_ID",   "")
        secret_id = getattr(args, "VAULT_SECRET_ID", None) or os.environ.get("VAULT_SECRET_ID", "")

    missing = [
        name
        for name, val in (
            ("VAULT_ADDR",      addr),
            ("VAULT_ROLE_ID",   role_id),
            ("VAULT_SECRET_ID", secret_id),
        )
        if not val
    ]
    if missing:
        log.error(
            "Missing required Vault configuration: %s. "
            "Provide via CLI args or environment variables (see --help).",
            ", ".join(missing),
        )
        raise SystemExit(1)

    return addr, role_id, secret_id


def check_legacy_credential_flags(
    args,
    err_log: logging.Logger = log,
) -> None:
    """
    Exit with status 1 if any legacy credential CLI flags were supplied.

    Checks ``args`` for: ``username``, ``password``, ``netbox_url``,
    ``netbox_token``.  A non-``None`` value means the flag was passed on the
    command line (callers must set ``default=None`` for these args so that
    env-var-based defaults do not trigger a false positive).

    All credentials must come from Vault.  Direct CLI credential supply is
    forbidden and is treated as a configuration error.

    Errors are written to *err_log* so they appear in the dedicated error log.
    """
    legacy_provided = []

    if getattr(args, "username",     None) is not None:
        legacy_provided.append("--username")
    if getattr(args, "password",     None) is not None:
        legacy_provided.append("--password")
    if getattr(args, "netbox_url",   None) is not None:
        legacy_provided.append("--netbox-url")
    if getattr(args, "netbox_token", None) is not None:
        legacy_provided.append("--netbox-token")

    if legacy_provided:
        err_log.error(
            "legacy_credential_flags | The following credential flags are no longer "
            "accepted: %s. All credentials (user, password, netbox_url, netbox_token) "
            "must be sourced from Vault. See --help for Vault configuration options.",
            ", ".join(legacy_provided),
        )
        raise SystemExit(1)
