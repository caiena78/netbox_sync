"""
example_usage.py
================
Demonstrates CiscoDeviceClient and NetBoxClient.

Edit the constants in the "Connection parameters" section, then run::

    python example_usage.py

All Cisco examples use a context manager so the SSH connection is cleanly
closed after each block.  NetBox examples create a single client instance
that is reused throughout.
"""

import json
import logging

from cisco_device_client import (
    CiscoDeviceClient,
    AuthenticationError,
    CiscoDeviceClientError,
    TransportError,
)
from netbox_client import NetBoxClient, NetBoxClientError

# --------------------------------------------------------------------------- #
# Logging                                                                      #
# --------------------------------------------------------------------------- #

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
)
log = logging.getLogger("example")

# --------------------------------------------------------------------------- #
# Connection parameters — edit these before running                            #
# --------------------------------------------------------------------------- #

CISCO_HOST    = "192.168.1.1"
CISCO_USER    = "admin"
CISCO_PASS    = "s3cr3t"
CISCO_OS      = "iosxe"          # "ios" | "iosxe" | "nxos"
CISCO_ENABLE  = "enable_s3cr3t"  # set to None if enable mode is not needed

NETBOX_URL    = "https://netbox.example.org"
NETBOX_TOKEN  = "your-netbox-api-token"
NETBOX_DEVICE = "core-rtr-01"    # name of an existing device in NetBox


# --------------------------------------------------------------------------- #
# Utility                                                                      #
# --------------------------------------------------------------------------- #

def pp(obj: dict) -> None:
    """Pretty-print any JSON-serialisable object."""
    print(json.dumps(obj, indent=2, default=str))


def section(title: str) -> None:
    print()
    print("=" * 60)
    print(f"  {title}")
    print("=" * 60)


# --------------------------------------------------------------------------- #
# 1. show version via CLI                                                      #
# --------------------------------------------------------------------------- #

section("1 — show version (CLI, Genie → TextFSM → raw fallback)")

try:
    with CiscoDeviceClient(
        host=CISCO_HOST,
        username=CISCO_USER,
        password=CISCO_PASS,
        os_type=CISCO_OS,
        enable_secret=CISCO_ENABLE,
    ) as cisco:
        result = cisco.show_ver(transport="cli")
        print(f"Parser used : {result['parser']}")
        print(f"Raw length  : {len(result['raw'])} chars")
        if result["parsed"]:
            print("Parsed keys :", list(result["parsed"].keys()))
        else:
            print("Parsed      : None (raw fallback)")
        pp(result)
except AuthenticationError as exc:
    log.error("Authentication failed: %s", exc)
except TransportError as exc:
    log.error("Transport error: %s", exc)
except CiscoDeviceClientError as exc:
    log.error("Client error: %s", exc)


# --------------------------------------------------------------------------- #
# 2. show cdp neighbors detail via CLI                                         #
# --------------------------------------------------------------------------- #

section("2 — show cdp neighbors detail (CLI)")

try:
    with CiscoDeviceClient(
        host=CISCO_HOST,
        username=CISCO_USER,
        password=CISCO_PASS,
        os_type=CISCO_OS,
        enable_secret=CISCO_ENABLE,
    ) as cisco:
        result = cisco.show_cdp_neighbors_detail(transport="cli")
        print(f"Parser used : {result['parser']}")
        pp(result)
except CiscoDeviceClientError as exc:
    log.error("CDP example failed: %s", exc)


# --------------------------------------------------------------------------- #
# 3. Running config via NETCONF                                                #
# --------------------------------------------------------------------------- #

section("3 — show run (NETCONF get-config, parsed via xmltodict)")

try:
    with CiscoDeviceClient(
        host=CISCO_HOST,
        username=CISCO_USER,
        password=CISCO_PASS,
        os_type=CISCO_OS,
        netconf_port=830,
    ) as cisco:
        result = cisco.show_run(transport="netconf")
        print(f"Parser      : {result['parser']}")
        print(f"Raw XML len : {len(result['raw'])} chars")
        if result["parsed"]:
            # xmltodict wraps everything under the root tag
            top_keys = list(result["parsed"].keys())
            print(f"Top-level XML keys: {top_keys}")
        else:
            print("Parsed      : None")
except TransportError as exc:
    log.error("NETCONF example failed: %s", exc)
except CiscoDeviceClientError as exc:
    log.error("Client error: %s", exc)


# --------------------------------------------------------------------------- #
# 4. Interfaces via RESTCONF                                                   #
# --------------------------------------------------------------------------- #

section("4 — show interfaces (RESTCONF, parsed from YANG JSON)")

try:
    with CiscoDeviceClient(
        host=CISCO_HOST,
        username=CISCO_USER,
        password=CISCO_PASS,
        os_type=CISCO_OS,
        restconf_port=443,
        verify_ssl=False,
    ) as cisco:
        result = cisco.show_int(transport="restconf")
        print(f"Parser      : {result['parser']}")
        if result["parsed"]:
            # The top-level key is the YANG module name, e.g.
            # "Cisco-IOS-XE-interfaces-oper:interfaces"
            print("Parsed keys :", list(result["parsed"].keys()))
        pp(result)
except TransportError as exc:
    log.error("RESTCONF example failed: %s", exc)
except CiscoDeviceClientError as exc:
    log.error("Client error: %s", exc)


# --------------------------------------------------------------------------- #
# 5. NetBox — query a device and its interfaces                                #
# --------------------------------------------------------------------------- #

section("5 — NetBox: get device + interfaces")

try:
    nb = NetBoxClient(base_url=NETBOX_URL, token=NETBOX_TOKEN, verify_ssl=False)

    device = nb.get_device(name=NETBOX_DEVICE)
    if device:
        print(f"Device found: {device['name']} (id={device['id']})")
        print(f"  Status  : {device.get('status')}")
        print(f"  Site    : {device.get('site')}")
        print(f"  Platform: {device.get('platform')}")

        interfaces = nb.get_interfaces(device_name=NETBOX_DEVICE)
        print(f"\nInterfaces ({len(interfaces)} total):")
        for iface in interfaces[:5]:   # show first 5
            print(
                f"  {iface.get('name'):<30}"
                f"  type={iface.get('type', {})}"
                f"  enabled={iface.get('enabled')}"
            )
    else:
        print(f"Device {NETBOX_DEVICE!r} not found in NetBox.")

    # List all active devices (all sites, limit to first 10 for display)
    print("\nAll active devices (first 10):")
    active = nb.get_devices(filters={"status": "active"})
    for d in active[:10]:
        print(f"  [{d['id']:>5}] {d.get('name')}")

except NetBoxClientError as exc:
    log.error("NetBox error: %s", exc)


# --------------------------------------------------------------------------- #
# 6. NetBox — create and update examples (commented out by default)            #
# --------------------------------------------------------------------------- #

section("6 — NetBox create / update (commented out — edit and uncomment)")

# --- Create a new device ---
# new_device = nb.create_device({
#     "name":        "leaf-sw-99",
#     "device_type": 5,        # replace with your DeviceType ID
#     "role":        3,        # replace with your DeviceRole ID
#     "site":        1,        # replace with your Site ID
#     "status":      "planned",
# })
# print("Created device id:", new_device["id"])
#
# --- Update the device (e.g. mark it active and add a comment) ---
# updated = nb.update_device(
#     device_id=new_device["id"],
#     device_payload={
#         "status":   "active",
#         "comments": "Provisioned by automation on 2025-01-01",
#     },
# )
# print("Updated device status:", updated.get("status"))
#
# --- Create an interface on the new device ---
# new_iface = nb.create_interface({
#     "device": new_device["id"],
#     "name":   "GigabitEthernet0/0/1",
#     "type":   "1000base-t",
#     "enabled": True,
# })
# print("Created interface id:", new_iface["id"])
#
# --- Update the interface description ---
# updated_iface = nb.update_interface(
#     interface_id=new_iface["id"],
#     interface_payload={
#         "description": "Uplink to core-rtr-01 Gi0/0",
#         "mtu":         9000,
#     },
# )
# print("Updated interface:", updated_iface.get("name"), "→", updated_iface.get("description"))

print("(All create/update examples are commented out in this file.)")
print("Done.")
