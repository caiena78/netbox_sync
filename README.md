# netbox_tools — Cisco ↔ NetBox Interface Sync

Automated interface inventory sync and physical cable discovery between
Cisco IOS / IOS-XE / NX-OS devices and NetBox.  Built on two reusable
classes (`CiscoDeviceClient`, `NetBoxClient`) and two runnable programs.

---

## Files

| File | Purpose |
|---|---|
| `cisco_device_client.py` | Cisco device client — CLI (Netmiko), RESTCONF, NETCONF |
| `netbox_client.py` | NetBox REST API client — get/create/update devices and interfaces |
| `sync_netbox_interfaces.py` | Interface, VLAN, prefix, LAG, and state sync program |
| `netbox_update_State.py` | Dedicated interface-state poller — updates `STATE` and `state_change` custom fields |
| `netbox_cables.py` | CDP-based physical cable discovery and creation |
| `netbox_ap.py` | CDP-based Cisco Access Point discovery — creates/updates AP devices, interfaces, IPs, and `software_version` in NetBox |
| `netbox_shoretel.py` | LLDP-based ShoreTel and Mitel IP phone discovery — creates/updates phone devices, interfaces, IPs, cables, and `software_version` / `last_seen` in NetBox |
| `netbox_device_modules.py` | Hardware module inventory sync — reads `show inventory` from Cisco devices and creates/updates linecards, supervisors, and power supplies in NetBox |
| `example_usage.py` | Short usage examples for both classes |
| `requirements.txt` | Python package dependencies |

---

## Requirements

**Python 3.9+**

Install core dependencies:

```bash
pip install -r requirements.txt
```

To enable Genie/pyATS structured CLI parsing (produces richer output,
especially for `show interfaces`):

```bash
# Full pyATS suite (recommended):
pip install "pyats[full]>=23.0"

# Lightweight Genie-only option:
pip install "genie>=23.0" "pyats>=23.0"
```

---

## Environment Variables

All credentials can be supplied as environment variables so nothing
sensitive needs to appear on the command line.

### NetBox

| Variable | CLI flag equivalent | Description |
|---|---|---|
| `NETBOX_URL` | `--netbox-url` | Full base URL, e.g. `https://netbox.example.org` |
| `NETBOX_API` | `--netbox-token` | NetBox API token |

### Cisco devices

| Variable | CLI flag equivalent | Description |
|---|---|---|
| `CISCO_SRV_ACCOUNT` | `--username` | SSH login username |
| `CISCO_SRV_PWD` | `--password` | SSH login password |
| `CISCO_ENABLE_PWD` | `--enable-secret` | Enable-mode secret (IOS/IOS-XE only; omit if not needed) |

Set them in your shell, `.env` file, or CI/CD secret store:

```bash
export NETBOX_URL=https://netbox.example.org
export NETBOX_API=your-netbox-api-token

export CISCO_SRV_ACCOUNT=svc-netauto
export CISCO_SRV_PWD=s3cr3t
export CISCO_ENABLE_PWD=en4bl3s3cr3t   # omit if not used
```

---

## Running `sync_netbox_interfaces.py`

Logs go to **stderr**; the JSON result array goes to **stdout**.

### Quickstart — all credentials from environment variables

**Linux / macOS (bash/zsh):**
```bash
python sync_netbox_interfaces.py \
    --device-filter '{"platform": "iosxe", "status": "active"}'
```

**Windows PowerShell:**
```powershell
python sync_netbox_interfaces.py `
    --device-filter '{\"platform\": \"iosxe\", \"status\": \"active\"}'
```

> **Windows PowerShell note** — PowerShell 5.1 does not preserve double quotes
> inside single-quoted strings when passing arguments to external executables.
> Use backslash-escaped double quotes (`\"`) inside single quotes, or store the
> filter in a variable first:
> ```powershell
> $f = '{"platform": "iosxe", "status": "active"}'
> python sync_netbox_interfaces.py --device-filter $f
> ```

### All matching devices with a filter

**Linux / macOS:**
```bash
python sync_netbox_interfaces.py \
    --netbox-url https://netbox.example.org \
    --netbox-token <token> \
    --username svc-netauto \
    --password s3cr3t \
    --device-filter '{"platform": "iosxe", "status": "active"}'
```

**Windows PowerShell:**
```powershell
python sync_netbox_interfaces.py `
    --netbox-url https://netbox.example.org `
    --netbox-token <token> `
    --username svc-netauto `
    --password s3cr3t `
    --device-filter '{\"platform\": \"iosxe\", \"status\": \"active\"}'
```

### Single device

```bash
python sync_netbox_interfaces.py \
    --device core-rtr-01
```

### Comma-separated list of devices

```bash
python sync_netbox_interfaces.py \
    --devices "core-rtr-01,core-rtr-02,leaf-sw-01"
```

### Device list from a file

One device name per line; lines starting with `#` are ignored.

```bash
python sync_netbox_interfaces.py \
    --device-file /etc/netauto/devices.txt
```

`devices.txt` example:

```
# Core routers
core-rtr-01
core-rtr-02

# Access switches
acc-sw-01
acc-sw-02
```

### Dry-run (no NetBox writes)

Prints what would be created or updated without touching NetBox.

```bash
python sync_netbox_interfaces.py \
    --device core-rtr-01 \
    --dry-run
```

### Interface name expansion

All interface names written to NetBox are automatically expanded from their
abbreviated form to the full Cisco canonical name:

| Device output | Written to NetBox |
|---|---|
| `gi1/0/1` | `GigabitEthernet1/0/1` |
| `Te2/1/1` | `TenGigabitEthernet2/1/1` |
| `fo3/0/1` | `FortyGigabitEthernet3/0/1` |
| `hu1/0/1` | `HundredGigE1/0/1` |
| `Po10` | `Port-channel10` |
| `Lo0` | `Loopback0` |
| `Vlan100` | `Vlan100` |
| `Ethernet1/1` | `Ethernet1/1` (NX-OS — already correct) |
| `mgmt0` | `mgmt0` (NX-OS management) |

The expansion uses longest-prefix matching so `TenGigabitEthernet` always
wins over the two-character `te` abbreviation when the full name is already
present.

---

### Interface type inference

Every interface is assigned a NetBox `type` based on its canonical name and,
for NX-OS `Ethernet` ports, the live speed and transceiver data collected
from the device.

| Canonical name prefix | NetBox type written |
|---|---|
| `GigabitEthernet`, `AppGigabitEthernet`, `Management`, `mgmt` | `1000base-t` |
| `TenGigabitEthernet` | `10gbase-x-sfpp` |
| `TwentyFiveGigE` | `25gbase-x-sfp28` |
| `FiftyGigE` | `50gbase-x-sfp28` |
| `FortyGigabitEthernet` | `40gbase-x-qsfpp` |
| `HundredGigE`, `HundredGigabitEthernet` | `100gbase-x-qsfp28` |
| `FastEthernet` | `100base-tx` |
| `Port-channel` | `lag` |
| `Loopback`, `Vlan`, `Tunnel`, `BDI`, `nve` | `virtual` |
| NX-OS `Ethernet` (speed/transceiver from device) | see table below |
| Anything else (`Serial`, `Dialer`, …) | `other` |

**NX-OS `Ethernet` ports** — the script runs `show interface transceiver`
and uses the negotiated speed from the interface inventory to resolve the type:

| Speed | Transceiver present | NetBox type |
|---|---|---|
| 100 G | — | `100gbase-x-qsfp28` |
| 40 G | — | `40gbase-x-qsfpp` |
| 25 G | — | `25gbase-x-sfp28` |
| 10 G | — | `10gbase-x-sfpp` |
| 1 G | Yes | `1000base-x-sfp` |
| 1 G | No | `1000base-t` |
| 1 G | Unknown | `1000base-x-sfp` (NX-OS ports are almost always SFP) |
| Unknown speed | — | `other` |

**`--force-type` controls whether type is written to NetBox:**

```bash
# Preview which interfaces would be typed (type never written without --force-type)
python sync_netbox_interfaces.py --device core-rtr-01 --dry-run

# Write type for the first time (creates with correct type, updates mismatches)
python sync_netbox_interfaces.py --device core-rtr-01 --force-type

# Correct existing wrong types on all active NX-OS switches
python sync_netbox_interfaces.py \
    --device-filter '{"platform": "nxos", "status": "active"}' \
    --force-type
```

Without `--force-type` the `type` field is **never included in the payload**,
so existing NetBox values are always preserved and newly created interfaces
get NetBox's own default (`other`).  The `unknown_interface_types` list in
the JSON summary is populated regardless of this flag so you can audit which
interfaces fell through to `"other"` without touching anything.

**`unknown_interface_types` in the JSON output:**

```json
{
  "device": "nxos-core-01",
  "unknown_interface_types": [
    {"name": "Ethernet1/5", "reason": "no mapping rule matched"}
  ]
}
```

An empty list means every interface on the device resolved to a known type.

---

### Virtual chassis

When you pass a name via `--device`, `--devices`, or `--device-file`, the
program searches **virtual chassis first**, then falls back to a regular
device search:

1. Query `dcim.virtual_chassis` for a chassis with that name.
2. If found, iterate its members — **master device first**, then remaining
   members ordered by `vc_position`.
3. For each member, check (in order): `primary_ip4` → `primary_ip6` → `oob_ip`.
4. The first member that has any of those IPs is used for the SSH/NETCONF/
   RESTCONF connection.
5. If no virtual chassis exists with that name, fall back to a normal
   `dcim.devices` lookup.

```bash
# Connect to a Catalyst stacked switch (virtual chassis named "acc-stack-01")
python sync_netbox_interfaces.py \
    --device acc-stack-01

# The log will show which physical member was selected, e.g.:
#   Virtual chassis 'acc-stack-01' → using member 'acc-stack-01-m1'  ip=10.0.1.5  vc_position=1
```

If a virtual chassis is found but **none of its members have a reachable
IP**, the device is skipped and an error is recorded in the JSON summary.

#### VC interface routing

When writing interfaces for a virtual chassis device, each interface is
automatically placed on the **correct member device** based on the first
number in the interface name — which on Cisco stacked and modular platforms
identifies the switch/line-card slot:

| Interface | First number | Placed on VC member |
|---|---|---|
| `GigabitEthernet1/0/1` | 1 | member with `vc_position = 1` |
| `GigabitEthernet2/0/24` | 2 | member with `vc_position = 2` |
| `TenGigabitEthernet3/1/1` | 3 | member with `vc_position = 3` |
| `Ethernet2/1` (NX-OS) | 2 | member with `vc_position = 2` |

Logical interfaces (Loopback, Port-channel, Vlan, Tunnel, etc.) are **not
routed** — they are written to the master/primary device that was used for
the connection.

If a slot number extracted from an interface name does not match any
member's `vc_position`, the interface falls back to the master device and
a debug log line is emitted.

---

### Explicit transport (no fallback)

```bash
# Force CLI only
python sync_netbox_interfaces.py \
    --device core-rtr-01 \
    --transport cli

# Force NETCONF only
python sync_netbox_interfaces.py \
    --device core-rtr-01 \
    --transport netconf

# Force RESTCONF only
python sync_netbox_interfaces.py \
    --device core-rtr-01 \
    --transport restconf
```

### Increase concurrency and verbosity

```bash
python sync_netbox_interfaces.py \
    --device-filter '{"status": "active"}' \
    --max-workers 10 \
    --timeout 60 \
    --log-level DEBUG
```

---

## Transport selection

| `--transport` | Behavior |
|---|---|
| `auto` (default) | IOS-XE: NETCONF → RESTCONF → CLI (tries each in order, stops at first success). NX-OS / IOS: CLI. |
| `netconf` | NETCONF only — fails if unavailable, no fallback. |
| `restconf` | RESTCONF only — fails if unavailable, no fallback. |
| `cli` | SSH / CLI only — fails if unavailable, no fallback. |

NETCONF uses port **830**; RESTCONF uses HTTPS port **443**.
SSH/CLI uses port **22**.  All ports can be overridden when using the
classes directly.

---

## Output format

The program writes a JSON array to stdout — one object per device:

```json
[
  {
    "device":         "core-rtr-01",
    "status":         "success",
    "transport_used": "netconf",
    "updated":        4,
    "created":        1,
    "skipped":        18,
    "errors":         [],
    "attempts": [
      { "transport": "netconf",  "ok": true,  "error": null },
    ]
  },
  {
    "device":         "legacy-ios-01",
    "status":         "success",
    "transport_used": "cli",
    "updated":        2,
    "created":        0,
    "skipped":        10,
    "errors":         [],
    "attempts": [
      { "transport": "cli", "ok": true, "error": null }
    ]
  }
]
```

Pipe to `jq` for filtering:

```bash
# Show only failed devices
python sync_netbox_interfaces.py ... | jq '[.[] | select(.status == "failed")]'

# Total interfaces updated across all devices
python sync_netbox_interfaces.py ... | jq '[.[].updated] | add'
```

Redirect stdout to a file while watching logs in the terminal:

```bash
python sync_netbox_interfaces.py ... > results.json
```

---

## Platform slug mapping

The script maps NetBox platform slugs to Cisco OS types.  The built-in
mapping covers common slug names:

| NetBox platform slug(s) | OS type |
|---|---|
| `iosxe`, `ios-xe`, `ios_xe`, `cisco-iosxe` | `iosxe` |
| `nxos`, `nx-os`, `nx_os`, `cisco-nxos` | `nxos` |
| `ios`, `cisco-ios`, `cisco_ios` | `ios` |

If your NetBox uses different slugs, add entries to `PLATFORM_SLUG_MAP`
at the top of `sync_netbox_interfaces.py`:

```python
PLATFORM_SLUG_MAP: Dict[str, str] = {
    ...
    "my-custom-slug": "iosxe",   # add your slug here
}
```

Devices whose platform slug is not in the map are skipped with an error
in the per-device summary.

---

## NetBox data model notes

| NetBox field | Value |
|---|---|
| `speed` | Stored in **kilobits per second (kbps)**. 1 Gbps = 1,000,000 kbps. |
| `duplex` | One of `full`, `half`, `auto`. |
| `description` | Free-form string. |

If your NetBox version does not support `speed` or `duplex` on
interfaces, the API will reject those fields.  Remove them from the
payload in `sync_device()` or handle the resulting `NetBoxClientError`.

---

## Using the classes directly

```python
from cisco_device_client import CiscoDeviceClient
from netbox_client import NetBoxClient

# --- Cisco ---
with CiscoDeviceClient(
    host="192.168.1.1",
    username="svc-netauto",
    password="s3cr3t",
    os_type="iosxe",
    enable_secret="en4bl3s3cr3t",
) as cisco:
    # Auto transport (NETCONF → RESTCONF → CLI for IOS-XE)
    result = cisco.get_interfaces_inventory_auto()
    print(result["transport_used"])  # "netconf"
    for iface in result["interfaces"]:
        print(iface)  # {"name": "Gi1", "description": "...", "speed_kbps": 1000000, "duplex": "full"}

    # Explicit transport
    ifaces = cisco.get_interfaces_inventory(transport="cli")

    # Raw show commands (all transports)
    ver = cisco.show_ver(transport="cli")
    print(ver["parsed"])  # Genie/TextFSM structured output or None

# --- NetBox ---
nb = NetBoxClient(
    base_url="https://netbox.example.org",
    token="your-api-token",
)

device = nb.get_device(name="core-rtr-01")
interfaces = nb.get_interfaces(device_name="core-rtr-01")

# Idempotent upsert — creates or updates, skips if nothing changed
result = nb.upsert_interface(
    device_id=device["id"],
    name="GigabitEthernet1",
    payload={"description": "Uplink", "speed": 1000000, "duplex": "full"},
)
print(result["action"])  # "created" | "updated" | "skipped"
```

---

---

## Running `netbox_update_State.py`

`netbox_update_State.py` is a focused, lightweight poller that connects to
Cisco devices, reads the operational state of every interface via
`show interfaces status`, and updates two NetBox interface custom fields:

| Custom field | Type | Written when |
|---|---|---|
| `STATE` | text — `UP` \| `DOWN` \| `ADMIN DOWN` \| `UNKNOWN` | Value differs from device |
| `state_change` | datetime (ISO 8601 UTC) | `STATE` value transitions |

**Idempotent by design** — if the device state already matches what is in
NetBox the record is not touched and `state_change` is left unchanged.

State normalization:

| Device reports | Written to NetBox |
|---|---|
| `connected` (port is up/up) | `UP` |
| `disabled` (admin shutdown) | `ADMIN DOWN` |
| `err-disabled` | `ADMIN DOWN` |
| `notconnect`, `inactive`, `sfpabsent`, `down` | `DOWN` |
| State cannot be determined | `UNKNOWN` |

Logs go to **stderr**; the JSON result array goes to **stdout**.

---

### Quickstart — credentials from environment variables

**Linux / macOS:**
```bash
python netbox_update_State.py \
    --device-filter '{"platform": "iosxe", "status": "active"}'
```

**Windows PowerShell:**
```powershell
$f = '{"platform": "iosxe", "status": "active"}'
python netbox_update_State.py --device-filter $f
```

### Single device

```bash
python netbox_update_State.py \
    --device core-sw-01
```

### Comma-separated list of devices

```bash
python netbox_update_State.py \
    --devices "core-sw-01,acc-sw-01,acc-sw-02"
```

### Device list from a file

```bash
python netbox_update_State.py \
    --device-file /etc/netauto/devices.txt
```

### Limit to a single site

```bash
# Poll only devices in the "lakeview" site
python netbox_update_State.py \
    --site-slug lakeview

# Combine with a device-filter (both conditions must match)
python netbox_update_State.py \
    --site-slug westpark \
    --device-filter '{"status": "active"}'
```

### Dry-run (no NetBox writes)

Reads device state and shows what would change without writing anything.

```bash
python netbox_update_State.py \
    --device core-sw-01 \
    --dry-run
```

Sample dry-run log:

```
INFO  netbox_update_State: *** DRY-RUN mode — no changes will be written to NetBox ***
INFO  netbox_update_State: core-sw-01              ip=10.1.1.5   os_type=iosxe  transport=auto
INFO  netbox_update_State: core-sw-01              collected state for 48 interface(s)
INFO  netbox_update_State: DRY-RUN  core-sw-01     STATE unchanged for GigabitEthernet1/0/1 (UP), skipping
INFO  netbox_update_State: DRY-RUN  core-sw-01     would update STATE for GigabitEthernet1/0/3: DOWN → UP; state_change=2026-05-17T14:30:01Z
INFO  netbox_update_State: DRY-RUN  core-sw-01     would update STATE for GigabitEthernet1/0/12: (null) → ADMIN DOWN; state_change=2026-05-17T14:30:01Z
INFO  netbox_update_State: core-sw-01              status=success   checked=48  updated=2  unchanged=46  errs=0
```

### Explicit transport (no fallback)

```bash
# SSH / CLI only — safest option for devices that do not have NETCONF/RESTCONF
python netbox_update_State.py \
    --device core-sw-01 \
    --transport cli

# NETCONF only
python netbox_update_State.py \
    --device core-sw-01 \
    --transport netconf
```

> **Note** — `get_interface_state_inventory()` always collects data over SSH
> (`show interfaces status`), so the transport flag controls how the
> `CiscoDeviceClient` instance is configured but does not change which
> protocol carries the state query.  Setting `--transport cli` is the most
> predictable choice for this script.

### Explicit credentials on the command line

```bash
python netbox_update_State.py \
    --netbox-url https://netbox.example.org \
    --netbox-token your-api-token \
    --username svc-netauto \
    --password s3cr3t \
    --enable-secret en4bl3s3cr3t \
    --device core-sw-01
```

### Increase concurrency and verbosity

```bash
python netbox_update_State.py \
    --device-filter '{"status": "active"}' \
    --max-workers 10 \
    --timeout 60 \
    --log-level DEBUG
```

### Redirect JSON output to a file

```bash
python netbox_update_State.py \
    --device-filter '{"status": "active"}' \
    > state_report.json
```

---

### Log output examples

**Unchanged interface (state already matches NetBox):**
```
DEBUG netbox_update_State: core-sw-01   Interface GigabitEthernet1/0/1 state detected as UP (dev_id=101)
DEBUG netbox_update_State: core-sw-01   STATE unchanged for GigabitEthernet1/0/1 (UP), skipping
```

**Changed interface (STATE updated + state_change stamped):**
```
DEBUG netbox_update_State: core-sw-01   Interface GigabitEthernet1/0/3 state detected as UP (dev_id=101)
INFO  netbox_update_State: core-sw-01   Updating STATE for GigabitEthernet1/0/3: DOWN → UP; state_change=2026-05-17T14:30:01Z
```

**Admin-down interface (first time seen):**
```
INFO  netbox_update_State: core-sw-01   Updating STATE for GigabitEthernet1/0/12: (null) → ADMIN DOWN; state_change=2026-05-17T14:30:01Z
```

**Interface not found in NetBox (warn and continue):**
```
WARNING netbox_update_State: core-sw-01   GigabitEthernet1/0/48 not found in NetBox (dev_id=101) — skipped
```

**State cannot be determined:**
```
WARNING netbox_update_State: core-sw-01   GigabitEthernet1/0/7: state could not be determined — using UNKNOWN
INFO    netbox_update_State: core-sw-01   Updating STATE for GigabitEthernet1/0/7: DOWN → UNKNOWN; state_change=2026-05-17T14:30:01Z
```

---

### Output format

One JSON object per device is written to stdout:

```json
[
  {
    "device":             "core-sw-01",
    "status":             "success",
    "transport_used":     "cli",
    "interfaces_checked": 48,
    "states_updated":     3,
    "states_unchanged":   45,
    "errors":             []
  },
  {
    "device":             "acc-sw-02",
    "status":             "failed",
    "transport_used":     null,
    "interfaces_checked": 0,
    "states_updated":     0,
    "states_unchanged":   0,
    "errors":             ["Interface state collection failed: SSH timeout"]
  }
]
```

Useful `jq` filters:

```bash
# Devices where at least one STATE changed
python netbox_update_State.py ... | jq '[.[] | select(.states_updated > 0)]'

# Total state changes across all devices
python netbox_update_State.py ... | jq '[.[].states_updated] | add'

# Devices with errors
python netbox_update_State.py ... | jq '[.[] | select(.errors | length > 0)]'

# Summary table: device, checked, updated
python netbox_update_State.py ... | jq '.[] | [.device, .interfaces_checked, .states_updated] | @tsv'
```

---

### Virtual chassis

`netbox_update_State.py` resolves virtual chassis names the same way as
`sync_netbox_interfaces.py` — pass the **chassis name** and the script
selects the correct master member automatically.  Each interface is then
routed to the correct VC member device for the NetBox update based on the
first number in the interface name (e.g. `GigabitEthernet2/0/1` → member
with `vc_position = 2`).

```bash
python netbox_update_State.py \
    --device acc-stack-01
# Log: Virtual chassis 'acc-stack-01' → using member 'acc-stack-01-m1'  ip=10.0.1.5  vc_position=1
```

---

### Running on a schedule

Poll interface state every 5 minutes using cron (Linux / macOS):

```cron
*/5 * * * * /usr/bin/python3 /opt/netauto/netbox_update_State.py \
    --device-filter '{"status": "active"}' \
    --transport cli \
    --max-workers 10 \
    >> /var/log/netauto/state.log 2>&1
```

Windows Task Scheduler (PowerShell action):

```powershell
python C:\netauto\netbox_update_State.py `
    --device-filter '{\"status\": \"active\"}' `
    --transport cli `
    --max-workers 10
```

---

### All `netbox_update_State.py` CLI flags

```
usage: netbox_update_State.py [-h]

  NetBox connection:
    --netbox-url URL          NetBox base URL (env: NETBOX_URL)
    --netbox-token TOKEN      NetBox API token (env: NETBOX_API)
    --netbox-verify-ssl / --no-netbox-verify-ssl

  Device selection (pick one, or omit for all):
    --device NAME             Single device name (or virtual chassis name)
    --devices NAME,...        Comma-separated device names
    --device-file PATH        File with one device name per line (#comments ignored)
    --device-filter JSON      NetBox DCIM device filter as JSON (default: {})
    --all                     Explicit "process all" flag
    --site-slug SLUG          Limit to devices in this site (slug, optional)

  Cisco credentials:
    --username USER           SSH username (env: CISCO_SRV_ACCOUNT)
    --password PASS           SSH password (env: CISCO_SRV_PWD)
    --enable-secret SECRET    Enable secret (env: CISCO_ENABLE_PWD)

  Runtime options:
    --transport {auto,cli,restconf,netconf}   (default: auto)
    --dry-run                 Show what would change; no NetBox writes
    --max-workers N           Concurrent threads (default: 5)
    --timeout SEC             Device SSH timeout in seconds (default: 30)
    --log-level {DEBUG,INFO,WARNING,ERROR}    (default: INFO)
```

---

## Running `netbox_cables.py`

`netbox_cables.py` discovers physical links by running `show cdp neighbors detail`
on every device and creates cables in NetBox where none exist.

**Safety guarantees — cables are never modified or deleted:**
- If the local interface already has a cable → skip the whole pair.
- If the remote interface already has a cable → skip the whole pair.
- SVIs, LAGs, Loopbacks, and Tunnel interfaces are never cabled.
- If the neighbor device cannot be resolved in NetBox → skip.

Cable type (`copper` / `fiber`) is detected automatically via
`show interface <X> transceiver`.

Logs go to **stderr**; the JSON summary goes to **stdout**.

---

### Quickstart — credentials from environment variables

**Linux / macOS:**
```bash
python netbox_cables.py \
    --device-filter '{"status": "active"}'
```

**Windows PowerShell:**
```powershell
python netbox_cables.py --device-filter '{\"status\": \"active\"}'
# Or use a variable:
$f = '{"status": "active"}'
python netbox_cables.py --device-filter $f
```

### Single device

```bash
python netbox_cables.py \
    --device acc-sw-01
```

### Comma-separated list of devices

```bash
python netbox_cables.py \
    --devices "acc-sw-01,acc-sw-02,core-rtr-01"
```

### Device list from a file

```bash
python netbox_cables.py \
    --device-file /etc/netauto/devices.txt
```

### Dry-run — discover only, no NetBox writes

Always run dry-run first before a production cabling session.

```bash
python netbox_cables.py \
    --device acc-sw-01 \
    --dry-run
```

Sample dry-run log output:

```
INFO  netbox_cables: acc-sw-01  CDP: 4 neighbor(s) discovered
INFO  netbox_cables: DRY-RUN  acc-sw-01  cable GigabitEthernet1/0/1 ↔ GigabitEthernet0/1@core-rtr-01  type=copper
INFO  netbox_cables: DRY-RUN  acc-sw-01  cable GigabitEthernet1/0/2 ↔ GigabitEthernet0/2@core-rtr-02  type=fiber
INFO  netbox_cables: DONE  devices=1  cables_created=2  skipped_existing=0
```

### Replace wrong cables with `--force`

By default the script **never touches an existing cable**.  Use `--force`
when you know a cable was recorded incorrectly (wrong neighbor, wrong
interface) and want it replaced with what CDP currently reports.

With `--force`:
1. If the local interface already has a cable, the script inspects it.
2. If the existing cable connects to the **same** remote interface, it is
   left in place (no change, no log noise).
3. If the existing cable connects to a **different** remote interface, the
   old cable is **deleted** and a new one is created.  The pair is counted
   in `cables_replaced` in the JSON summary.

```bash
# Re-cable a single switch, replacing any incorrect entries
python netbox_cables.py \
    --device acc-sw-01 \
    --force

# Dry-run first to see what would be replaced without touching anything
python netbox_cables.py \
    --device acc-sw-01 \
    --force \
    --dry-run
```

> **Warning** — `--force` deletes existing cable records.  Always do a
> dry-run first so you can confirm which cables would be affected.

---

### Explicit credentials on the command line

```bash
python netbox_cables.py \
    --netbox-url https://netbox.example.org \
    --netbox-token your-api-token \
    --username svc-netauto \
    --password s3cr3t \
    --enable-secret en4bl3s3cr3t \
    --device acc-sw-01
```

### Limit to a specific platform

```bash
python netbox_cables.py \
    --device-filter '{"platform": "iosxe", "status": "active"}' \
    --max-workers 10
```

### Increase concurrency and verbosity

```bash
python netbox_cables.py \
    --device-filter '{"status": "active"}' \
    --max-workers 10 \
    --timeout 60 \
    --log-level DEBUG
```

### Redirect JSON output to a file

```bash
python netbox_cables.py \
    --device-filter '{"status": "active"}' \
    > cables_report.json
```

---

### Cable output format

One JSON object per device is written to stdout:

```json
[
  {
    "device":                 "acc-sw-01",
    "status":                 "success",
    "neighbors_seen":         4,
    "cables_created":         2,
    "cables_replaced":        1,
    "skipped_existing_cable": 1,
    "skipped_missing_device": 0,
    "skipped_logical_iface":  1,
    "errors":                 []
  },
  {
    "device":                 "core-rtr-01",
    "status":                 "success",
    "neighbors_seen":         8,
    "cables_created":         0,
    "cables_replaced":        0,
    "skipped_existing_cable": 8,
    "skipped_missing_device": 0,
    "skipped_logical_iface":  0,
    "errors":                 []
  }
]
```

| Field | Meaning |
|---|---|
| `neighbors_seen` | Total CDP entries returned by the device |
| `cables_created` | New cables written to NetBox |
| `cables_replaced` | Existing cables deleted and re-created because they pointed to the wrong neighbor (`--force` only; always 0 without `--force`) |
| `skipped_existing_cable` | Pairs where the correct cable already exists (no change needed) |
| `skipped_missing_device` | Neighbors not found in NetBox |
| `skipped_logical_iface` | SVIs, LAGs, Loopbacks, Tunnels — never cabled |

Useful `jq` filters:

```bash
# Show only devices where cables were created
python netbox_cables.py ... | jq '[.[] | select(.cables_created > 0)]'

# Total cables created across the run
python netbox_cables.py ... | jq '[.[].cables_created] | add'

# Devices with errors
python netbox_cables.py ... | jq '[.[] | select(.errors | length > 0)]'
```

---

### Cable type detection

| Transceiver output | Cable type written to NetBox |
|---|---|
| Contains `SFP`, `QSFP`, `fiber`, `optical`, `dBm`, `wavelength` | `fiber` |
| `No optical transceiver`, `SFP absent`, `not present` | `copper` |
| Command unsupported / no output | `copper` (default) |

---

### What is never touched

- Existing cables are **never modified or deleted** — unless `--force` is
  passed, in which case cables that point to the wrong neighbor are replaced.
- Logical interfaces are **never given cables**: `Vlan*`, `Loopback*`,
  `Port-channel*`, `Tunnel*`, `BDI*`, `nve*`, `Null*`.
- Neighbors that cannot be resolved in NetBox by name or primary IP are skipped.

---

### Filter by site

Use `--site-slug` to process only devices assigned to a specific NetBox
site.  Pass the **slug** (not the display name) as shown in NetBox.

**Linux / macOS:**
```bash
# Cable discovery for a single site only
python netbox_cables.py --site-slug lakeview

# Combine with an additional device-filter
python netbox_cables.py \
    --site-slug westpark \
    --device-filter '{"status": "active"}'
```

**Windows PowerShell:**
```powershell
python netbox_cables.py --site-slug lakeview

python netbox_cables.py --site-slug westpark --device-filter '{\"status\": \"active\"}'
```

When `--site-slug` is omitted all sites are included (existing behaviour).

---

### All `netbox_cables.py` CLI flags

```
usage: netbox_cables.py [-h]

  NetBox connection:
    --netbox-url URL          NetBox base URL (env: NETBOX_URL)
    --netbox-token TOKEN      NetBox API token (env: NETBOX_API)
    --netbox-verify-ssl / --no-netbox-verify-ssl

  Device selection (pick one, or omit for all):
    --device NAME             Single device name
    --devices NAME,...        Comma-separated device names
    --device-file PATH        File with one device name per line
    --device-filter JSON      NetBox DCIM filter (default: {})
    --site-slug SLUG          Limit to devices in this site (slug, optional)

  Cisco credentials:
    --username USER           SSH username (env: CISCO_SRV_ACCOUNT)
    --password PASS           SSH password (env: CISCO_SRV_PWD)
    --enable-secret SECRET    Enable secret (env: CISCO_ENABLE_PWD)

  Runtime options:
    --transport {auto,cli,netconf,restconf}   (default: auto)
    --dry-run                 Discover only; no NetBox writes
    --force                   Replace cables that point to the wrong neighbor.
                             Without this flag existing cables are never touched.
                             With this flag, if a cable exists on the local
                             interface but connects to a different remote than
                             CDP reports, the old cable is deleted and a new
                             one is created. Correct cables are left in place.
                             Always combine with --dry-run first to preview.
    --max-workers N           Concurrent threads (default: 5)
    --timeout SEC             Device timeout seconds (default: 30)
    --log-level {DEBUG,INFO,WARNING,ERROR}    (default: INFO)
```

---

## All `sync_netbox_interfaces.py` CLI flags

### Filter by site

Use `--site-slug` to restrict sync to a single NetBox site.  Provide the
site **slug** (visible in the NetBox URL, e.g. `/dcim/sites/lakeview/`).

```bash
# Sync only devices in the "chnola" site
python sync_netbox_interfaces.py \
    --site-slug chnola

# Site filter + existing device-filter (they stack — both must match)
python sync_netbox_interfaces.py \
    --site-slug lakeview \
    --device-filter '{"platform": "nxos", "status": "active"}'

# Site filter + single device (device must be in the site or it is skipped)
python sync_netbox_interfaces.py \
    --site-slug westpark \
    --device noeh-mdf-fl6-9k-c1
```

When `--site-slug` is omitted all sites are included (existing behaviour).

```
usage: sync_netbox_interfaces.py [-h]
  NetBox connection:
    --netbox-url URL          NetBox base URL (env: NETBOX_URL)
    --netbox-token TOKEN      NetBox API token (env: NETBOX_API)
    --netbox-verify-ssl / --no-netbox-verify-ssl

  Device selection (pick one, or omit for all):
    --device NAME             Single device name
    --devices NAME,...        Comma-separated device names
    --device-file PATH        File with one device name per line
    --device-filter JSON      NetBox filter dict (default: {})
    --all                     Explicit "process all" flag
    --site-slug SLUG          Limit to devices in this site (slug, optional)

  Cisco credentials:
    --username USER           SSH username (env: CISCO_SRV_ACCOUNT)
    --password PASS           SSH password (env: CISCO_SRV_PWD)
    --enable-secret SECRET    Enable secret (env: CISCO_ENABLE_PWD)

  Runtime options:
    --transport {auto,cli,restconf,netconf}   (default: auto)
    --dry-run                 No NetBox writes
    --force-type              Write the inferred interface type to NetBox.
                             Without this flag the 'type' field is never
                             included in the payload — existing values are
                             preserved and new interfaces get NetBox's default.
                             With this flag the inferred type is written for
                             every interface and mismatches are overwritten.
                             NX-OS Ethernet ports use speed + transceiver
                             data for the best-effort guess.
    --max-workers N           Concurrent threads (default: 5)
    --timeout SEC             Device timeout in seconds (default: 30)
    --fail-fast               Abort device on first critical error
    --log-level {DEBUG,INFO,WARNING,ERROR}    (default: INFO)

  Sync stage toggles:
    --sync-vlans / --no-sync-vlans           (default: true)
    --sync-trunks / --no-sync-trunks         (default: true)
    --sync-prefixes / --no-sync-prefixes     (default: true)
    --skip-vlan-ids IDS      Comma-separated VIDs to never write to NetBox
                             (default: 1,1002,1003,1004,1005)
                             1002-1005 are Cisco IOS reserved VLANs
                             (fddi-default, trcrf-default, fddinet-default,
                              trbrf-default) and must not appear in NetBox.
    --deny-vlan-group-name-substring STR
                             Exclude VLAN groups whose name contains STR
                             (default: internet)
```

---

## Running `netbox_ap.py`

`netbox_ap.py` discovers Cisco Access Points via **CDP** (`show cdp neighbors
detail`) on every selected parent Cisco switch and creates or updates the AP
device records in NetBox.

For each AP found:
- Creates / updates the **device** (model looked up from NetBox DeviceType)
- Ensures a single **uplink interface** exists (default `GigabitEthernet0`)
- Assigns the **management IP** to that interface (longest-matching prefix)
- Sets `primary_ip4` if not already set
- Updates the **`software_version`** custom field
- Updates the **`last_seen`** custom field to the current UTC timestamp
- Looks up the **MAC address** from the switch MAC-address table and sets
  `mac_address` + `primary_mac_address` on the uplink interface

**NetBox pre-requisites:**
- A `DeviceType` must exist in NetBox for every AP model reported by CDP
  (matched on the `model` or `part_number` field).
- If any model is missing the script exits non-zero and writes
  `missing_ap_models.txt` listing every missing model.
- A device role named **`Access Point`** is created automatically if absent.

Logs go to **stderr**; the JSON result array goes to **stdout**.

---

### Quickstart — credentials from environment variables

**Linux / macOS:**
```bash
python netbox_ap.py \
    --device-filter '{"platform": "iosxe", "status": "active"}'
```

**Windows PowerShell:**
```powershell
$f = '{"platform": "iosxe", "status": "active"}'
python netbox_ap.py --device-filter $f
```

### Single parent switch

```bash
python netbox_ap.py \
    --device acc-sw-01
```

### All switches in a site

```bash
python netbox_ap.py \
    --site-slug lakeview
```

### Comma-separated list of switches

```bash
python netbox_ap.py \
    --devices "acc-sw-01,acc-sw-02,acc-sw-03"
```

### Switch list from a file

```bash
python netbox_ap.py \
    --device-file /etc/netauto/switches.txt
```

### Dry-run — discover APs without writing to NetBox

```bash
python netbox_ap.py \
    --device acc-sw-01 \
    --dry-run
```

Sample dry-run log:
```
INFO  netbox_ap: acc-sw-01   Collected CDP neighbors from acc-sw-01
INFO  netbox_ap: acc-sw-01   12 AP neighbor(s) identified
INFO  netbox_ap: DRY-RUN  AP ap-floor3-01          model=C9130AXI-B  ip=10.10.3.50  site_id=4  sw_ver=17.9.4
INFO  netbox_ap: DRY-RUN  AP ap-floor3-02          model=C9120AXI-B  ip=10.10.3.51  site_id=4  sw_ver=17.9.4
```

### Explicit credentials on the command line

```bash
python netbox_ap.py \
    --netbox-url https://netbox.example.org \
    --netbox-token your-api-token \
    --username svc-netauto \
    --password s3cr3t \
    --enable-secret en4bl3s3cr3t \
    --device acc-sw-01
```

### Increase concurrency and verbosity

```bash
python netbox_ap.py \
    --device-filter '{"status": "active"}' \
    --max-workers 10 \
    --timeout 60 \
    --log-level DEBUG
```

### Redirect JSON output to a file

```bash
python netbox_ap.py \
    --device-filter '{"status": "active"}' \
    > ap_report.json
```

---

### AP output format

One JSON object per **parent switch** is written to stdout:

```json
[
  {
    "device":               "acc-sw-01",
    "status":               "success",
    "neighbors_parsed":     24,
    "aps_discovered":       12,
    "aps_created":          2,
    "aps_updated":          9,
    "aps_skipped":          1,
    "missing_device_types": [],
    "aps": [
      {
        "name":    "ap-floor3-01",
        "model":   "C9130AXI-B",
        "ip":      "10.10.3.50",
        "action":  "updated",
        "error":   null,
        "missing_device_type": false
      }
    ],
    "errors": []
  }
]
```

| Field | Meaning |
|---|---|
| `aps_discovered` | AP CDP entries found on this switch |
| `aps_created` | New AP device records created in NetBox |
| `aps_updated` | Existing AP records that had at least one field change |
| `aps_skipped` | AP records that were already up-to-date |
| `missing_device_types` | Model strings that have no matching NetBox DeviceType |

Useful `jq` filters:

```bash
# APs that were newly created
python netbox_ap.py ... | jq '[.[].aps[] | select(.action == "created")]'

# Total APs discovered across all switches
python netbox_ap.py ... | jq '[.[].aps_discovered] | add'

# Missing DeviceType models (needs pre-creation in NetBox)
python netbox_ap.py ... | jq '[.[].missing_device_types[]] | unique'
```

---

### Missing DeviceType models

When CDP reports a model that has no matching `DeviceType` in NetBox the
script:

1. Logs an ERROR per missing model.
2. Continues processing all other APs.
3. Writes `missing_ap_models.txt` in the current directory listing every
   missing model.
4. Exits with a non-zero status code.

```
# missing_ap_models.txt example
# Missing AP DeviceType models — generated 2026-05-19T14:00:00Z
C9130AXI-B
AIR-AP3802I-B-K9
```

Create a `DeviceType` in NetBox for each listed model (or set its
`part_number` to match) then re-run.

---

### Virtual chassis support

Pass the **virtual chassis name** and `netbox_ap.py` selects the master
member automatically for the SSH connection, exactly as
`sync_netbox_interfaces.py` does.

```bash
python netbox_ap.py \
    --device acc-stack-01
# Log: Virtual chassis 'acc-stack-01' → using member 'acc-stack-01-m1'  ip=10.0.1.5
```

---

### All `netbox_ap.py` CLI flags

`netbox_ap.py` shares the same parser as `sync_netbox_interfaces.py`.
All device-selection, credential, and runtime flags are identical:

```
usage: netbox_ap [-h]

  NetBox connection:
    --netbox-url URL          NetBox base URL (env: NETBOX_URL)
    --netbox-token TOKEN      NetBox API token (env: NETBOX_API)
    --netbox-verify-ssl / --no-netbox-verify-ssl

  Device selection (pick one, or omit for all):
    --device NAME             Single parent switch name (or VC name)
    --devices NAME,...        Comma-separated switch names
    --device-file PATH        File with one switch name per line
    --device-filter JSON      NetBox DCIM device filter as JSON (default: {})
    --all                     Explicit "process all" flag
    --site-slug SLUG          Limit to devices in this site (slug, optional)

  Cisco credentials:
    --username USER           SSH username (env: CISCO_SRV_ACCOUNT)
    --password PASS           SSH password (env: CISCO_SRV_PWD)
    --enable-secret SECRET    Enable secret (env: CISCO_ENABLE_PWD)

  Runtime options:
    --transport {auto,cli,restconf,netconf}   (default: auto)
    --dry-run                 Discover only; no NetBox writes
    --max-workers N           Concurrent threads (default: 5)
    --timeout SEC             Device timeout seconds (default: 30)
    --log-level {DEBUG,INFO,WARNING,ERROR}    (default: INFO)
    --log-file PATH           Also write logs to this file (appended, UTF-8)
```

---

## Running `netbox_shoretel.py`

`netbox_shoretel.py` discovers **ShoreTel** and **Mitel** IP phones via
**LLDP** (`show lldp neighbors detail`) on every selected parent Cisco switch
and creates or updates the phone device records in NetBox.

For each phone found:
- Creates / updates the **device** with a vendor-specific name and DeviceType
- Ensures the **`eth0`** interface exists on the phone device
- Assigns the **management IP** (chassis ID from LLDP) to `eth0`
- Sets `primary_ip4` if not already set
- Optionally sets **`mac_address`** and **`primary_mac_address`** on `eth0`
  from the LLDP port ID field
- Updates the **`software_version`** custom field
- Updates the **`last_seen`** custom field to the current UTC timestamp (on
  every run, both for new and existing devices)
- Creates a **cable** between the switch port (Local Intf from LLDP) and the
  phone's `eth0` (never modifies or deletes an existing cable)

**Vendor identification:**

| Vendor | Detection rule | Device name | DeviceType |
|---|---|---|---|
| ShoreTel | System Description contains `ShoreTel IP` | `shoretel-<serial_lower>` | `IP480g` (slug `ip480g`) |
| Mitel | System Name / Description contains `Mitel IP Phone` or MED `Manufacturer: Mitel` | `mitel-<serial_normalized>` | `mitel` (part_number `mitel001`) |

**NetBox pre-requisites:**
- `DeviceType` with model `IP480g` (slug `ip480g`) for ShoreTel phones.
- `DeviceType` with model `mitel` and `part_number` `mitel001` for Mitel phones.
- Missing either DeviceType causes the script to exit non-zero immediately.
- A device role named **`IP Phone`** is created automatically if absent.
- Custom fields **`software_version`** and **`last_seen`** must exist on
  the `dcim.device` object.

Logs go to **stderr**; the JSON result array goes to **stdout**.

---

### Quickstart — credentials from environment variables

**Linux / macOS:**
```bash
python netbox_shoretel.py \
    --device-filter '{"platform": "iosxe", "status": "active"}'
```

**Windows PowerShell:**
```powershell
$f = '{"platform": "iosxe", "status": "active"}'
python netbox_shoretel.py --device-filter $f
```

### Single parent switch

```bash
python netbox_shoretel.py \
    --device acc-sw-01
```

### All switches in a site

```bash
python netbox_shoretel.py \
    --site-slug lakeview
```

### Comma-separated list of switches

```bash
python netbox_shoretel.py \
    --devices "acc-sw-01,acc-sw-02,acc-sw-03"
```

### Switch list from a file

```bash
python netbox_shoretel.py \
    --device-file /etc/netauto/switches.txt
```

### Dry-run — discover phones without writing to NetBox

```bash
python netbox_shoretel.py \
    --device acc-sw-01 \
    --dry-run
```

Sample dry-run log:
```
INFO  netbox_shoretel: acc-sw-01  Collected LLDP neighbors from acc-sw-01
INFO  netbox_shoretel: acc-sw-01  14 phone(s) identified (10 ShoreTel, 4 Mitel)
INFO  netbox_shoretel: DRY-RUN  [shoretel] shoretel-001049413d4b  serial=001049413D4B  ip=10.173.141.147  sw_ver=804.2002.1100.0
INFO  netbox_shoretel: DRY-RUN  [mitel]    mitel-08000fd6b36b     serial=08-00-0F-D6-B3-6B  ip=10.173.124.144  sw_ver=5.2.1.1071
```

### Explicit credentials on the command line

```bash
python netbox_shoretel.py \
    --netbox-url https://netbox.example.org \
    --netbox-token your-api-token \
    --username svc-netauto \
    --password s3cr3t \
    --enable-secret en4bl3s3cr3t \
    --device acc-sw-01
```

### Increase concurrency and verbosity

```bash
python netbox_shoretel.py \
    --device-filter '{"status": "active"}' \
    --max-workers 10 \
    --timeout 60 \
    --log-level DEBUG
```

### Redirect JSON output to a file

```bash
python netbox_shoretel.py \
    --device-filter '{"status": "active"}' \
    > phones_report.json
```

---

### Phone output format

One JSON object per **parent switch** is written to stdout:

```json
[
  {
    "device":            "acc-sw-01",
    "status":            "success",
    "neighbors_parsed":  48,
    "phones_discovered": 14,
    "phones_created":    3,
    "phones_updated":    10,
    "phones_skipped":    1,
    "cables_created":    3,
    "phones": [
      {
        "vendor":            "shoretel",
        "name":              "shoretel-001049413d4b",
        "serial":            "001049413D4B",
        "ip":                "10.173.141.147",
        "software_version":  "804.2002.1100.0",
        "switch_port":       "GigabitEthernet3/0/20",
        "action":            "updated",
        "last_seen_updated": true,
        "cabled":            "skipped",
        "error":             null
      },
      {
        "vendor":            "mitel",
        "name":              "mitel-08000fd6b36b",
        "serial":            "08-00-0F-D6-B3-6B",
        "ip":                "10.173.124.144",
        "software_version":  "5.2.1.1071",
        "switch_port":       "GigabitEthernet2/0/27",
        "action":            "created",
        "last_seen_updated": true,
        "cabled":            "created",
        "error":             null
      }
    ],
    "errors": []
  }
]
```

| Field | Meaning |
|---|---|
| `phones_discovered` | Phone LLDP entries found on this switch |
| `phones_created` | New phone device records created in NetBox |
| `phones_updated` | Existing phone records that had at least one field change |
| `phones_skipped` | Phone records already up-to-date (no changes needed) |
| `cables_created` | New cables created between switch ports and phone `eth0` interfaces |
| `cabled` | Per-phone cable result: `"created"`, `"skipped"` (cable already exists), or `"error"` |

Useful `jq` filters:

```bash
# Phones newly created this run
python netbox_shoretel.py ... | jq '[.[].phones[] | select(.action == "created")]'

# Total phones discovered across all switches
python netbox_shoretel.py ... | jq '[.[].phones_discovered] | add'

# All Mitel phones
python netbox_shoretel.py ... | jq '[.[].phones[] | select(.vendor == "mitel")]'

# Phones where cable creation failed
python netbox_shoretel.py ... | jq '[.[].phones[] | select(.cabled == "error")]'

# Switches with errors
python netbox_shoretel.py ... | jq '[.[] | select(.errors | length > 0)]'
```

---

### Device naming

| Vendor | Source | Example input | Device name in NetBox |
|---|---|---|---|
| ShoreTel | `System Name: Serial Number: <serial>` | `001049413D4B` | `shoretel-001049413d4b` |
| Mitel | MED `Serial number: <value>` | `08-00-0F-D6-B3-6B` | `mitel-08000fd6b36b` |
| Mitel (no serial) | LLDP Port ID (MAC) | `0800.0fd6.b36b` | `mitel-08000fd6b36b` |

Names are deterministic and idempotent — re-running never creates duplicates.

---

### Software version extraction

| Vendor | Source field | Example |
|---|---|---|
| ShoreTel | `Software Version:` in System Description | `804.2002.1100.0` |
| Mitel | MED `S/W revision:` (preferred) | `5.2.1.1071` |
| Mitel | MED `F/W revision:` (fallback when S/W absent) | `5.2.1.1071` |

---

### Cable safety

The cable creation follows the same safety guarantees as `netbox_cables.py`:

- If the **switch port** already has a cable → skip, log, continue.
- If the **phone `eth0`** already has a cable → skip, log, continue.
- Existing cables are **never modified or deleted**.
- A `cat6` cable type is used (phones are always copper); if the NetBox
  instance rejects that slug the creation is retried without a type.

---

### Virtual chassis switch support

When the parent switch is a Virtual Chassis, LLDP reports the local interface
in expanded form (e.g. `GigabitEthernet3/0/43`).  The script extracts the
member number from the interface name and looks up the correct VC member
before creating the cable, so the cable is always terminated on the right
physical device.

```
GigabitEthernet1/0/24  →  VC member with vc_position = 1
GigabitEthernet3/0/43  →  VC member with vc_position = 3
GigabitEthernet4/0/12  →  VC member with vc_position = 4
```

---

### All `netbox_shoretel.py` CLI flags

`netbox_shoretel.py` shares the same parser as `sync_netbox_interfaces.py`.
All device-selection, credential, and runtime flags are identical:

```
usage: netbox_shoretel [-h]

  NetBox connection:
    --netbox-url URL          NetBox base URL (env: NETBOX_URL)
    --netbox-token TOKEN      NetBox API token (env: NETBOX_API)
    --netbox-verify-ssl / --no-netbox-verify-ssl

  Device selection (pick one, or omit for all):
    --device NAME             Single parent switch name (or VC name)
    --devices NAME,...        Comma-separated switch names
    --device-file PATH        File with one switch name per line
    --device-filter JSON      NetBox DCIM device filter as JSON (default: {})
    --all                     Explicit "process all" flag
    --site-slug SLUG          Limit to devices in this site (slug, optional)

  Cisco credentials:
    --username USER           SSH username (env: CISCO_SRV_ACCOUNT)
    --password PASS           SSH password (env: CISCO_SRV_PWD)
    --enable-secret SECRET    Enable secret (env: CISCO_ENABLE_PWD)

  Runtime options:
    --transport {auto,cli,restconf,netconf}   (default: auto)
    --dry-run                 Discover only; no NetBox writes
    --max-workers N           Concurrent threads (default: 5)
    --timeout SEC             Device timeout seconds (default: 30)
    --log-level {DEBUG,INFO,WARNING,ERROR}    (default: INFO)
    --log-file PATH           Also write logs to this file (appended, UTF-8)
```

---

## Running `netbox_device_connections.py`

`netbox_device_connections.py` queries NetBox for every cabled interface on a
device (or all members of a Virtual Chassis) and prints the connection list as
a JSON array to **stdout**.  No SSH connection is made — all data comes from
the NetBox REST API.

For each interface that has a cable the output record includes:

| Field | Description |
|---|---|
| `device_name` | Local device hostname |
| `device_primary_ip` | Local device management IP (no prefix length) |
| `interface` | Local interface name |
| `remote_device` | Remote device hostname |
| `remote_device_primary_ip` | Remote device management IP (no prefix length) |
| `remote_interface` | Remote interface name |

**Authentication** — two modes, tried in this order:

1. **Basic Auth** (`--username` + `--password`) — authenticates as the full
   user account.  Use this when the API token has restricted object permissions
   (returns 403 on list endpoints).
2. **Token Auth** (`--netbox-token` only) — uses `Authorization: Token`.
   Works when the token's user has unrestricted view permission on devices and
   interfaces.

Logs go to **stderr** (default level `WARNING` — silent unless something goes
wrong); the JSON array goes to **stdout**.

---

### Quickstart — credentials from environment variables

```bash
python netbox_device_connections.py \
    --name apc4d6.662f.2c60
```

### Query a Virtual Chassis by name

The script checks for a matching Virtual Chassis first.  If found, all member
devices are included and their interfaces are enumerated.

```bash
python netbox_device_connections.py \
    --name ej-3h3-9300s-6
```

### Query a single device by name

If no Virtual Chassis matches, the script falls back to a device search.

```bash
python netbox_device_connections.py \
    --name acc-sw-01
```

### Explicit credentials on the command line

```bash
python netbox_device_connections.py \
    --netbox-url   https://netbox.example.org \
    --netbox-token your-api-token \
    --name         acc-sw-01
```

### Basic Auth when the token lacks list permissions

```bash
python netbox_device_connections.py \
    --netbox-url   https://netbox.example.org \
    --netbox-token your-api-token \
    --username     your-netbox-username \
    --password     your-netbox-password \
    --name         acc-sw-01
```

Or via environment variables:

```bash
export NETBOX_URL=https://netbox.example.org
export NETBOX_API=your-api-token
export NETBOX_USERNAME=your-netbox-username
export NETBOX_PASSWORD=your-netbox-password

python netbox_device_connections.py --name acc-sw-01
```

### Control log verbosity

By default the script is **silent** (log level `WARNING`) — only errors and
warnings appear on stderr, keeping stdout clean for JSON piping.  Raise the
level when you need to see what is happening.

```bash
# Show device / interface progress (recommended for interactive use)
python netbox_device_connections.py \
    --name acc-sw-01 \
    --log-level INFO

# Show every API call and stub-resolution step (verbose)
python netbox_device_connections.py \
    --name acc-sw-01 \
    --log-level DEBUG

# Completely silent — only JSON on stdout, nothing on stderr
python netbox_device_connections.py \
    --name acc-sw-01 \
    --log-level ERROR
```

### Redirect JSON output to a file

```bash
python netbox_device_connections.py \
    --name ej-3h3-9300s-6 \
    > connections.json
```

---

### Output format

```json
[
  {
    "device_name":              "apc4d6.662f.2c60",
    "device_primary_ip":        "10.254.213.165",
    "interface":                "GigabitEthernet0",
    "remote_device":            "ej-3h3-9300s-6(1)",
    "remote_device_primary_ip": "10.254.213.5",
    "remote_interface":         "GigabitEthernet1/0/7"
  },
  {
    "device_name":              "acc-sw-01",
    "device_primary_ip":        "10.10.1.5",
    "interface":                "GigabitEthernet1/0/1",
    "remote_device":            "core-rtr-01",
    "remote_device_primary_ip": "10.10.0.1",
    "remote_interface":         "GigabitEthernet0/0"
  }
]
```

If a device has no primary IP configured but belongs to a Virtual Chassis,
the script falls back to the VC master member's primary IP automatically.

Useful `jq` filters:

```bash
# Connections to a specific remote device
python netbox_device_connections.py --name acc-sw-01 | \
    jq '[.[] | select(.remote_device == "core-rtr-01")]'

# All unique remote devices
python netbox_device_connections.py --name acc-sw-01 | \
    jq '[.[].remote_device] | unique'

# Total connection count
python netbox_device_connections.py --name ej-3h3-9300s-6 | jq length
```

---

### All `netbox_device_connections.py` CLI flags

```
usage: netbox_device_connections.py [-h]

  NetBox connection:
    --netbox-url URL          NetBox base URL (env: NETBOX_URL)
    --netbox-token TOKEN      NetBox API token (env: NETBOX_API)

  Authentication (use when token has restricted permissions):
    --username USER           NetBox username for Basic Auth (env: NETBOX_USERNAME)
    --password PASS           NetBox password for Basic Auth (env: NETBOX_PASSWORD)

  Target:
    --name NAME               Virtual chassis name or device name / search term

  Runtime options:
    --log-level {DEBUG,INFO,WARNING,ERROR}
                             Log verbosity on stderr (default: WARNING — silent)
```

---

## Running `netbox_device_modules.py`

`netbox_device_modules.py` connects to Cisco devices via SSH, runs
`show inventory` (and `show module` on NX-OS), and creates or updates the
corresponding hardware records in NetBox:

- **Linecards and supervisors** → `dcim.modules` installed in `dcim.module_bays`
- **Power supplies** → `dcim.inventory_items` with role `power-supply`

**Idempotent by design** — re-running never creates duplicates.  Only the
serial number or description is patched when those fields differ.

**Safety guarantees:**
- Read-only on devices (`show` commands only — no config changes).
- A module is only replaced when the bay is occupied by a *different* module
  type; serial-only updates are done in-place.
- Before inserting a replacement module, interfaces belonging to that slot are
  deleted from NetBox first so they can be recreated cleanly by
  `sync_netbox_interfaces.py`.
- Transceivers (SFP/QSFP) are skipped by default; enable with
  `--include-transceivers`.

**NetBox pre-requisites:**
- `dcim.module_types` must exist for every PID you want to track.  PIDs with
  no matching module type are logged to `netbox_device_modules_errors.log` and
  skipped — the script continues to the next component.
- Module bays are created automatically when absent (name and position are
  derived from the inventory output).

Logs go to **stderr**; per-device progress is printed to **stdout** as it runs.

---

### Quickstart — credentials from environment variables

**Linux / macOS:**
```bash
python netbox_device_modules.py \
    --site dc1
```

**Windows PowerShell:**
```powershell
python netbox_device_modules.py --site dc1
```

### Single device

```bash
python netbox_device_modules.py \
    --device core-sw-01
```

### All devices in a site (dry-run first)

```bash
# Preview what would change — no NetBox writes
python netbox_device_modules.py \
    --site dc1 \
    --dry-run

# Apply after reviewing
python netbox_device_modules.py \
    --site dc1
```

### Filter by role

```bash
python netbox_device_modules.py \
    --role distribution \
    --limit 10
```

### Filter by tag

```bash
python netbox_device_modules.py \
    --tag modular-chassis
```

### Include SFP/QSFP transceivers

By default transceivers are skipped.  Pass `--include-transceivers` to sync
them as modules too (requires matching `dcim.module_types` for transceiver PIDs).

```bash
python netbox_device_modules.py \
    --device nexus-agg-01 \
    --include-transceivers
```

### Explicit credentials on the command line

```bash
python netbox_device_modules.py \
    --netbox-url   https://netbox.example.org \
    --netbox-token your-api-token \
    --device       core-sw-01
```

### Verbose debug output

```bash
python netbox_device_modules.py \
    --device core-sw-01 \
    --debug
```

---

### Platform slot mapping

The script infers which NetBox module bay to target from the `NAME` field in
`show inventory` output, using platform-specific conventions:

| Platform | `show inventory` NAME example | Target device | NetBox bay name | Interface pattern deleted before insert |
|---|---|---|---|---|
| Catalyst 4500 / 4510 | `WS-C4510R+E Slot 1` | Device itself | `Slot 1` | `GigabitEthernetX/Y` where `X = slot` |
| Catalyst 4500 supervisor | `WS-C4510R+E Slot 6` | Device itself | `Slot 6` | `TenGigabitEthernetX/Y` where `X = slot` |
| Catalyst 3750 / 3850 / 9300 / 9200 uplink module | `Switch 1 Slot 1 - C3850-NM-4-1G` | VC member `vc_position = 1` | `Network Module` | `Gi1/1/*`, `Te1/1/*` on member 1 device |
| Catalyst 3750 / 3850 / 9300 / 9200 — member 2 | `Switch 2 Slot 1 - C9300-NM-8X` | VC member `vc_position = 2` | `Network Module` | `Gi2/1/*`, `Te2/1/*` on member 2 device |
| Catalyst 9300 FRU uplink | `Switch 1 FRU Uplink Module 1` | VC member `vc_position = 1` | `Network Module` | `Gi1/1/*`, `Te1/1/*` on member 1 device |
| Nexus linecard | `Module 3` | Device itself | `Module 3` | `EthernetX/Y` where `X = module` |
| Nexus supervisor | `Module 1` | Device itself | `Module 1` | `EthernetX/Y` where `X = 1` |

**Power supply handling — stack vs. chassis platforms:**

On stacked platforms (3750 / 3850 / 9300 / 9200) power supplies are inserted
as **`dcim.modules` in `dcim.module_bays`** on the correct VC member device —
the same path used for linecards and uplink modules.  The `"Switch N – "`
prefix is stripped so the bay is named cleanly on the member device.

| `show inventory` NAME | Target device | Module bay created | NetBox object |
|---|---|---|---|
| `Switch 1 - Power Supply A` | VC member `vc_position = 1` | `Power Supply A` | `dcim.module` |
| `Switch 2 - Power Supply B` | VC member `vc_position = 2` | `Power Supply B` | `dcim.module` |
| `Switch 3 Power Supply A` | VC member `vc_position = 3` | `Power Supply A` | `dcim.module` |

On modular chassis platforms (C4500 / Nexus / generic) power supplies remain
as **`dcim.inventory_items`** since those platforms model PSUs differently.

| `show inventory` NAME | Target device | NetBox object |
|---|---|---|
| `WS-C4510R+E Power Supply A` | Device itself | `dcim.inventory_item` |
| `Power Supply 1` (Nexus) | Device itself | `dcim.inventory_item` |

> **NetBox pre-requisite for stack PSUs** — a `dcim.module_type` must exist
> for each PSU PID (e.g. `C3KX-PWR-1000WAC`, `C9300-PWR-250WAC`).  If the
> module type is missing the PSU is logged to `netbox_device_modules_errors.log`
> and skipped, identical to the behaviour for missing linecard types.

For VC/stack devices the switch number extracted from the NAME is mapped to the
correct VC member `device_id` via `vc_position`, so modules and interface
deletions always target the right physical device.

---

### Missing module types

When a PID has no matching `dcim.module_type` in NetBox:

1. An error line is written to **stderr** and to `netbox_device_modules_errors.log`.
2. The component is skipped.
3. All other components on the same device continue processing.

```
ERROR  device_modules_errors: missing_module_type | device=core-sw-01 pid=WS-X4648-RJ45V+E name='WS-C4510R+E Slot 1' descr='48-Port ...' sn=JAB12345678
```

Create the missing `ModuleType` in NetBox (Manufacturer + Model = PID) and
re-run — the script will pick it up on the next execution.

---

### Error log file

All warnings and errors are appended to `netbox_device_modules_errors.log` in
the working directory.  Each line includes a structured prefix for easy
`grep` filtering:

| Prefix | Meaning |
|---|---|
| `missing_module_type` | PID not found in `dcim.module_types` |
| `module_upsert_failed` | NetBox API error when creating/updating a module |
| `missing_psu_type` | PSU PID not found (informational — PSUs use inventory items) |

```bash
# Show all devices with missing module types
grep missing_module_type netbox_device_modules_errors.log | awk -F'|' '{print $2}'

# Show all unique missing PIDs
grep missing_module_type netbox_device_modules_errors.log \
    | grep -oP 'pid=\K\S+'  | sort -u
```

---

### Console output example

```
============================================================
  Device: core-sw-01  IP: 10.10.0.5  OS: iosxe
============================================================
  Platform family: c4500
  Connecting to 10.10.0.5 …
  Connected.
  Running: show inventory
  Parsed 12 inventory blocks.
  SUPERVISOR  bay='Slot 6'  PID=WS-X45-SUP7L-E  SN=JAE12345678
  LINECARD    bay='Slot 1'  PID=WS-X4648-RJ45V+E  SN=JAB12345678
    DELETE interface GigabitEthernet1/1 (dev_id=42)
    DELETE interface GigabitEthernet1/2 (dev_id=42)
  LINECARD    bay='Slot 2'  PID=WS-X4648-RJ45V+E  SN=JAB87654321
  PSU         'WS-C4510R+E Power Supply A'  PID=PWR-C45-1400AC  SN=AZS12345678
  PSU         'WS-C4510R+E Power Supply B'  PID=PWR-C45-1400AC  SN=AZS87654321

  Summary: modules +2 updated=1 skipped=0  PSUs +2 updated=0
```

---

### All `netbox_device_modules.py` CLI flags

```
usage: netbox_device_modules.py [-h]

  NetBox connection:
    --netbox-url URL                  NetBox base URL (env: NETBOX_URL)
    --netbox-token TOKEN              NetBox API token (env: NETBOX_API)
    --netbox-verify-ssl / --no-netbox-verify-ssl

  Device selection (pick one, or omit for all):
    --device NAME                     Single device by NetBox name (VC-aware)
    --devices NAME,...                Comma-separated device names (VC-aware)
    --device-file PATH                File with one device name per line (#comments ignored)
    --device-filter JSON              NetBox DCIM filter as JSON  (default: {})
    --all                             Explicit "process all" flag
    --site-slug SLUG                  Limit to devices in this site slug (stacks with --device-filter)

  Legacy device selection (alternative to --device-filter):
    --site SLUG                       Equivalent to --device-filter '{"site": SLUG}'
    --role SLUG                       Equivalent to --device-filter '{"role": SLUG}'
    --tag  SLUG                       Equivalent to --device-filter '{"tag": SLUG}'
    --limit N                         Process at most N devices

  Cisco credentials:
    --username USER                   SSH username (env: CISCO_SRV_ACCOUNT)
    --password PASS                   SSH password (env: CISCO_SRV_PWD)
    --enable-secret SECRET            Enable secret (env: CISCO_ENABLE_PWD)

  Run options:
    --dry-run                         Print what would change; no NetBox writes
    --include-transceivers            Also sync SFP/QSFP transceivers (disabled by default)
    --timeout SEC                     Device SSH timeout in seconds (default: 30)
    --log-level DEBUG|INFO|WARNING|ERROR
                                      Log verbosity (default: INFO)
    --log-file PATH                   Also write logs to this file (appended, UTF-8)
```

#### Device selection examples

```bash
# Single device (resolves virtual chassis automatically)
python netbox_device_modules.py --device acc-stack-01

# Several devices
python netbox_device_modules.py --devices acc-stack-01,acc-stack-02,dist-sw-01

# From a file (one name per line, lines starting with # ignored)
python netbox_device_modules.py --device-file /tmp/switches.txt

# All devices in site "dc1" with role "access"
python netbox_device_modules.py --device-filter '{"site": "dc1", "role": "access"}'

# All devices in a site using --site-slug
python netbox_device_modules.py --site-slug dc1

# Legacy shorthand (equivalent to --device-filter)
python netbox_device_modules.py --site dc1 --role distribution --limit 10
```
