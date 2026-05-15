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
| `netbox_cables.py` | CDP-based physical cable discovery and creation |
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
| `skipped_existing_cable` | Pairs where at least one interface already had a cable |
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

- Existing cables are **never modified or deleted**.
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
