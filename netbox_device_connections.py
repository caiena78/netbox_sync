#!/usr/bin/env python3
"""
netbox_device_connections.py
============================
Export device connection data from NetBox using the custom export template
``devices_with_connection_stream``.

Resolution order
----------------
1. Query ``/api/dcim/virtual-chassis/?name=<name>``
   - Found  → ``/dcim/devices/?virtual_chassis_id=<id>&export=devices_with_connection_stream``
   - Missing → ``/dcim/devices/?q=<name>&export=devices_with_connection_stream``

The export endpoint is a *UI* endpoint (not the REST API), so it requires
both a valid ``Authorization: Token …`` header **and** ``Accept: application/json``.
Without the Accept header NetBox renders an HTML page instead of JSON.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

import requests


# --------------------------------------------------------------------------- #
# Helpers                                                                      #
# --------------------------------------------------------------------------- #

def _make_session(token: str) -> requests.Session:
    """
    Return a requests Session pre-configured for NetBox token auth.

    Sets both ``Authorization`` and ``Accept: application/json`` on every
    request so the UI export endpoint returns JSON instead of an HTML page.
    Redirects are NOT followed — a redirect almost always means NetBox sent
    the client to the login page, which is a sign of an auth failure.
    """
    session = requests.Session()
    session.headers.update({
        "Authorization": f"Token {token}",
        "Accept":        "application/json",
        "Content-Type":  "application/json",
    })
    # Do NOT set session.max_redirects here — it fires TooManyRedirects even
    # when a specific request passes allow_redirects=False.  Redirect detection
    # is handled per-call via allow_redirects=False + status-code inspection.
    return session


def _assert_json_response(response: requests.Response, url: str) -> None:
    """
    Raise a descriptive RuntimeError when the response is HTML rather than
    JSON.  This catches two failure modes:
    - NetBox redirected to the login page (missing / wrong token).
    - NetBox returned an HTML error page (template misconfiguration).
    """
    content_type = response.headers.get("Content-Type", "")
    body_start   = response.text[:200].lower()

    if "text/html" in content_type or "<html" in body_start:
        raise RuntimeError(
            f"Received HTML instead of JSON from {url!r}\n"
            f"  Content-Type : {content_type!r}\n"
            f"  Response URL : {response.url!r}\n"
            f"  Hint         : check that --netbox-token is correct and that\n"
            f"                 the export template 'devices_with_connection_stream' exists."
        )


# --------------------------------------------------------------------------- #
# API calls                                                                    #
# --------------------------------------------------------------------------- #

def _find_virtual_chassis_id(
    session: requests.Session,
    base_url: str,
    name: str,
) -> int | None:
    """
    Return the NetBox Virtual Chassis ID whose name matches *name*, or None.

    Uses the JSON REST API (``/api/dcim/virtual-chassis/``).

    A 403 response means the token lacks permission to list virtual chassis —
    this is treated as "no VC found" so the caller falls back to a device
    search.  Any other HTTP error is logged as a warning and also returns None.
    """
    url = f"{base_url}/api/dcim/virtual-chassis/"
    try:
        resp = session.get(url, params={"name": name}, timeout=15)

        if resp.status_code == 403:
            print(
                "[INFO] Virtual chassis API returned 403 — token lacks "
                "permission for that endpoint; skipping VC lookup.",
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


def _fetch_export(
    session: requests.Session,
    base_url: str,
    params: dict,
) -> list | dict:
    """
    Call the NetBox UI export endpoint and return parsed JSON.

    The endpoint is ``/dcim/devices/`` with ``export=devices_with_connection_stream``
    plus whatever additional query params are supplied.

    Raises
    ------
    RuntimeError
        When the response is HTML (auth failure, redirect, template missing).
    requests.HTTPError
        On 4xx / 5xx status codes.
    """
    url = f"{base_url}/dcim/devices/"

    print(f"[INFO] Export URL : {url}", file=sys.stderr)
    print(f"[INFO] Params     : {params}", file=sys.stderr)

    try:
        resp = session.get(
            url,
            params=params,
            timeout=30,
            allow_redirects=False,   # catch login-page redirects explicitly
        )
    except requests.exceptions.RequestException as exc:
        raise RuntimeError(f"Request failed: {exc}") from exc

    print(f"[INFO] Status     : {resp.status_code}", file=sys.stderr)
    print(f"[INFO] Content-Type: {resp.headers.get('Content-Type', '(none)')}", file=sys.stderr)

    # A 3xx response means NetBox redirected us — almost always to /login/
    if resp.is_redirect or resp.status_code in (301, 302, 303, 307, 308):
        location = resp.headers.get("Location", "(unknown)")
        raise RuntimeError(
            f"NetBox redirected to {location!r} — "
            "token auth failed or the export URL is wrong."
        )

    resp.raise_for_status()

    _assert_json_response(resp, url)

    return resp.json()


# --------------------------------------------------------------------------- #
# Main logic                                                                   #
# --------------------------------------------------------------------------- #

def get_export_data(base_url: str, token: str, name: str) -> None:
    session = _make_session(token)

    # ── Step 1: Virtual chassis lookup ────────────────────────────────────
    vc_id = _find_virtual_chassis_id(session, base_url, name)

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

    # ── Step 2: Export request ────────────────────────────────────────────
    data = _fetch_export(session, base_url, params)
    print(json.dumps(data, indent=2))


# --------------------------------------------------------------------------- #
# Entry point                                                                  #
# --------------------------------------------------------------------------- #

def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Export NetBox device connection data via the "
            "'devices_with_connection_stream' export template."
        )
    )
    parser.add_argument(
        "--netbox-url",
        default=os.environ.get("NETBOX_URL", ""),
        help="NetBox base URL, e.g. https://netbox.example.com  (env: NETBOX_URL)",
    )
    parser.add_argument(
        "--netbox-token",
        default=os.environ.get("NETBOX_API", ""),
        help="NetBox API token  (env: NETBOX_API)",
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
        )
    except RuntimeError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
