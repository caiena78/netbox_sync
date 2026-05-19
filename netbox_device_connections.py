#!/usr/bin/env python3

import argparse
import os
import requests
import sys


def get_headers(token):
    return {
        "Authorization": f"Token {token}",
        "Content-Type": "application/json"
    }


def get_virtual_chassis(netbox_url, name, headers):
    """
    Check if the provided name matches a virtual chassis.
    """
    url = f"{netbox_url}/api/dcim/virtual-chassis/?name={name}"

    try:
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        data = response.json()

        if data.get("count", 0) > 0:
            return data["results"][0]["id"]

    except requests.exceptions.RequestException as e:
        print(f"Error querying virtual chassis: {e}", file=sys.stderr)

    return None


def get_export_data(netbox_url, token, name):
    headers = get_headers(token)

    # --- Step 1: Check virtual chassis ---
    vc_id = get_virtual_chassis(netbox_url, name, headers)

    if vc_id:
        print(f"[INFO] Found virtual chassis '{name}' (ID={vc_id})", file=sys.stderr)

        export_url = (
            f"{netbox_url}/dcim/devices/"
            f"?virtual_chassis_id={vc_id}"
            f"&export=devices_with_connection_stream"
        )

    else:
        print(f"[INFO] No virtual chassis found. Falling back to device search for '{name}'", file=sys.stderr)

        export_url = (
            f"{netbox_url}/dcim/devices/"
            f"?q={name}"
            f"&export=devices_with_connection_stream"
        )

    # --- Step 2: Call export endpoint ---
    try:
        response = requests.get(export_url, headers=headers, timeout=30)

        # NOTE: NetBox export endpoint often returns CSV or text, not JSON
        response.raise_for_status()

        print(response.text)

    except requests.exceptions.RequestException as e:
        print(f"Error fetching export data: {e}", file=sys.stderr)
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="Fetch NetBox device export by virtual chassis or device name"
    )

    parser.add_argument("--netbox-url", required=False, default=os.environ.get("NETBOX_URL", "") , help="NetBox base URL (no trailing slash)")
    parser.add_argument("--netbox-token", required=False,  default=os.environ.get("NETBOX_API", ""), help="NetBox API token")
    parser.add_argument("--name", required=True, help="Virtual chassis name OR device name")

    args = parser.parse_args()

    get_export_data(
        netbox_url=args.netbox_url.rstrip("/"),
        token=args.netbox_token,
        name=args.name,
    )


if __name__ == "__main__":
    main()