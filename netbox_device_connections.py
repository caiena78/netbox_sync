#!/usr/bin/env python3
"""
netbox_device_connections.py
============================
Export device connection data from NetBox using the custom export template
``devices_with_connection_stream``.

Authentication modes
--------------------
NetBox has two distinct authentication surfaces:

  REST API  ``/api/…``       → ``Authorization: Token <token>``   (--netbox-token)
  UI pages  ``/dcim/…``      → Django session cookie              (--username + --password)

The export template endpoint is a **UI page**.  Passing the token header
there is silently ignored and NetBox redirects to /login/.

  - If ``--username`` and ``--password`` are supplied:
    The script POSTs to ``/login/`` to obtain a session cookie, then calls
    the UI export endpoint — exactly what a browser does.

  - If only ``--netbox-token`` is supplied:
    The script tries the REST API path (``/api/dcim/devices/?export=…``).
    This works when the token has export-template permission; if it returns
    403 a clear message explains how to fix it.

Resolution order (VC vs device)
--------------------------------
1. Query ``/api/dcim/virtual-chassis/?name=<name>`` (token auth)
   - Found  → ``?virtual_chassis_id=<id>&export=devices_with_connection_stream``
   - Missing → ``?q=<name>&export=devices_with_connection_stream``
"""

from __future__ import annotations

import argparse
import json
import os
import sys

import requests


# --------------------------------------------------------------------------- #
# Session factories                                                            #
# --------------------------------------------------------------------------- #

def _make_api_session(token: str) -> requests.Session:
    """Return a session configured for NetBox REST API token auth."""
    s = requests.Session()
    s.headers.update({
        "Authorization": f"Token {token}",
        "Accept":        "application/json",
        "Content-Type":  "application/json",
    })
    return s


def _make_ui_session(base_url: str, username: str, password: str) -> requests.Session:
    """
    Authenticate via username/password and return a session carrying the
    resulting Django session cookie.

    Mimics exactly what a browser does:
      GET  /login/  →  obtain csrftoken cookie
      POST /login/  →  submit credentials  →  receive sessionid cookie

    Raises RuntimeError if login fails.
    """
    s = requests.Session()
    s.headers.update({"Accept": "text/html,application/json"})

    login_url = f"{base_url}/login/"

    # ── Step 1: GET login page to harvest CSRF cookie ─────────────────────
    try:
        resp = s.get(login_url, timeout=15)
        resp.raise_for_status()
    except requests.exceptions.RequestException as exc:
        raise RuntimeError(f"Could not reach login page {login_url!r}: {exc}") from exc

    csrf = s.cookies.get("csrftoken")
    if not csrf:
        raise RuntimeError(
            f"No csrftoken cookie from {login_url!r} — check --netbox-url."
        )

    # ── Step 2: POST credentials ──────────────────────────────────────────
    try:
        resp = s.post(
            login_url,
            data={
                "username":            username,
                "password":            password,
                "csrfmiddlewaretoken": csrf,
            },
            headers={"Referer": login_url},
            timeout=15,
            allow_redirects=True,
        )
        resp.raise_for_status()
    except requests.exceptions.RequestException as exc:
        raise RuntimeError(f"Login POST failed: {exc}") from exc

    # A successful login redirects away from /login/
    if "/login" in resp.url:
        raise RuntimeError(
            "Login failed — NetBox stayed on the login page. "
            "Check --username and --password."
        )

    print(f"[INFO] Session auth: logged in as {username!r}", file=sys.stderr)
    return s


# --------------------------------------------------------------------------- #
# Shared response guard                                                        #
# --------------------------------------------------------------------------- #

def _assert_json_response(resp: requests.Response, url: str) -> None:
    """
    Raise RuntimeError when the response body is HTML rather than JSON.

    Catches two silent failure modes:
      - NetBox rendered an HTML error page instead of the export.
      - An intermediate proxy returned an HTML page.
    """
    ct         = resp.headers.get("Content-Type", "")
    body_start = resp.text[:300].lower()

    if "text/html" in ct or "<html" in body_start:
        raise RuntimeError(
            f"Received HTML instead of JSON from {url!r}\n"
            f"  Content-Type : {ct!r}\n"
            f"  Response URL : {resp.url!r}\n"
            f"  Hint         : authentication failed or the export template "
            f"'devices_with_connection_stream' does not exist."
        )


# --------------------------------------------------------------------------- #
# Virtual chassis lookup (always token / REST API)                             #
# --------------------------------------------------------------------------- #

def _find_virtual_chassis_id(
    api_session: requests.Session,
    base_url: str,
    name: str,
) -> int | None:
    """Return the VC ID for *name*, or None (including on 403)."""
    url = f"{base_url}/api/dcim/virtual-chassis/"
    try:
        resp = api_session.get(url, params={"name": name}, timeout=15)

        if resp.status_code == 403:
            print(
                "[INFO] Virtual chassis API returned 403 — token lacks "
                "list-VC permission; skipping VC lookup.",
                file=sys.stderr,
            )
            return None

        resp.raise_for_status()
        data = resp.json()
        if data.get("count", 0) > 0:
            return data["results"][0]["id"]

    except requests.exceptions.RequestException as exc:
        print(f"[WARN] Virtual chassis lookup failed: {exc}", file=sys.stderr)

    return None


# --------------------------------------------------------------------------- #
# Export fetch — two paths                                                     #
# --------------------------------------------------------------------------- #

def _fetch_export_ui(
    ui_session: requests.Session,
    base_url: str,
    params: dict,
) -> object:
    """
    Fetch the export via the **UI** endpoint ``/dcim/devices/``.

    Requires a session cookie obtained from :func:`_make_ui_session`.
    This is the path that works in a browser.
    """
    url = f"{base_url}/dcim/devices/"
    print(f"[INFO] Export path: UI  ({url})", file=sys.stderr)
    print(f"[INFO] Params     : {params}",    file=sys.stderr)

    try:
        resp = ui_session.get(
            url,
            params=params,
            timeout=30,
            allow_redirects=False,
        )
    except requests.exceptions.RequestException as exc:
        raise RuntimeError(f"Request failed: {exc}") from exc

    print(f"[INFO] Status     : {resp.status_code}", file=sys.stderr)
    print(f"[INFO] Content-Type: {resp.headers.get('Content-Type', '(none)')}", file=sys.stderr)

    if resp.is_redirect or resp.status_code in (301, 302, 303, 307, 308):
        location = resp.headers.get("Location", "(unknown)")
        raise RuntimeError(
            f"NetBox redirected to {location!r} — session auth failed. "
            "Check --username and --password."
        )

    resp.raise_for_status()
    _assert_json_response(resp, url)
    return resp.json()


def _fetch_export_api(
    api_session: requests.Session,
    base_url: str,
    params: dict,
) -> object:
    """
    Fetch the export via the **REST API** endpoint ``/api/dcim/devices/``.

    Works when the token has both ``view_device`` and export-template
    permissions.  Returns a 403 when the token lacks export permission;
    the caller should instruct the user to add ``--username``/``--password``
    or fix the token's permissions.
    """
    url = f"{base_url}/api/dcim/devices/"
    print(f"[INFO] Export path: REST API  ({url})", file=sys.stderr)
    print(f"[INFO] Params     : {params}",           file=sys.stderr)

    try:
        resp = api_session.get(
            url,
            params=params,
            timeout=30,
            allow_redirects=False,
        )
    except requests.exceptions.RequestException as exc:
        raise RuntimeError(f"Request failed: {exc}") from exc

    print(f"[INFO] Status     : {resp.status_code}", file=sys.stderr)
    print(f"[INFO] Content-Type: {resp.headers.get('Content-Type', '(none)')}", file=sys.stderr)

    if resp.is_redirect or resp.status_code in (301, 302, 303, 307, 308):
        location = resp.headers.get("Location", "(unknown)")
        raise RuntimeError(f"Unexpected redirect to {location!r}")

    if resp.status_code == 403:
        raise RuntimeError(
            "403 Forbidden on the REST API export endpoint.\n"
            "\n"
            "The API token is valid but lacks the required permission.\n"
            "Fix one of the following:\n"
            "\n"
            "  Option A — grant the token export-template permission in NetBox\n"
            "             (Extras → Export Templates → permissions, or via\n"
            "             token object-permissions in the admin panel).\n"
            "\n"
            "  Option B — pass --username and --password to authenticate via\n"
            "             the UI login page (same as a browser session).\n"
        )

    resp.raise_for_status()
    _assert_json_response(resp, url)
    return resp.json()


# --------------------------------------------------------------------------- #
# Main logic                                                                   #
# --------------------------------------------------------------------------- #

def get_export_data(
    base_url: str,
    token: str,
    name: str,
    username: str | None = None,
    password: str | None = None,
) -> None:
    api_session = _make_api_session(token)

    # ── Step 1: resolve VC or fall back to device search ─────────────────
    vc_id = _find_virtual_chassis_id(api_session, base_url, name)

    if vc_id is not None:
        print(
            f"[INFO] Virtual chassis {name!r} found (id={vc_id}) — "
            "querying by virtual_chassis_id",
            file=sys.stderr,
        )
        params = {
            "virtual_chassis_id": vc_id,
            "export":             "devices_with_connection_stream",
        }
    else:
        print(
            f"[INFO] No virtual chassis found for {name!r} — "
            "falling back to device search (q=)",
            file=sys.stderr,
        )
        params = {
            "q":      name,
            "export": "devices_with_connection_stream",
        }

    # ── Step 2: fetch export via the appropriate auth path ────────────────
    if username and password:
        print("[INFO] Auth mode  : session (username/password)", file=sys.stderr)
        ui_session = _make_ui_session(base_url, username, password)
        data = _fetch_export_ui(ui_session, base_url, params)
    else:
        print("[INFO] Auth mode  : token (REST API)", file=sys.stderr)
        data = _fetch_export_api(api_session, base_url, params)

    print(json.dumps(data, indent=2))


# --------------------------------------------------------------------------- #
# Entry point                                                                  #
# --------------------------------------------------------------------------- #

def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Export NetBox device connection data via the "
            "'devices_with_connection_stream' export template.\n\n"
            "Authentication:\n"
            "  Token only (--netbox-token):       uses REST API — requires export permission on token.\n"
            "  Credentials (--username/--password): uses UI session — same as browser login."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "--netbox-url",
        default=os.environ.get("NETBOX_URL", ""),
        help="NetBox base URL, e.g. https://netbox.example.com  (env: NETBOX_URL)",
    )
    parser.add_argument(
        "--netbox-token",
        default=os.environ.get("NETBOX_API", ""),
        help="NetBox API token — used for VC lookup and (optionally) export  (env: NETBOX_API)",
    )
    parser.add_argument(
        "--username",
        default=os.environ.get("NETBOX_USERNAME", ""),
        help=(
            "NetBox username for session-based login (env: NETBOX_USERNAME). "
            "Required when the token lacks export-template permission."
        ),
    )
    parser.add_argument(
        "--password",
        default=os.environ.get("NETBOX_PASSWORD", ""),
        help=(
            "NetBox password for session-based login (env: NETBOX_PASSWORD). "
            "Required together with --username."
        ),
    )
    parser.add_argument(
        "--name",
        required=True,
        help="Virtual chassis name or device name / search term",
    )

    args = parser.parse_args()

    if not args.netbox_url:
        parser.error("--netbox-url is required (or set NETBOX_URL)")
    if not args.netbox_token:
        parser.error("--netbox-token is required (or set NETBOX_API)")

    try:
        get_export_data(
            base_url=args.netbox_url.rstrip("/"),
            token=args.netbox_token,
            name=args.name,
            username=args.username or None,
            password=args.password or None,
        )
    except RuntimeError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
