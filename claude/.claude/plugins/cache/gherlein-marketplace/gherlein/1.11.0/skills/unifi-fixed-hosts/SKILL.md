---
name: unifi-fixed-hosts
description: Use when the user wants to read, add, or delete fixed IP (DHCP reservation) assignments on a UniFi/UDM controller, look up detected device MAC addresses, inspect network/subnet/DHCP-pool info, or edit a fixed-hosts file. Covers the gofips, gofimac, and gofinet CLI tools from github.com/emergingrobotics/gofi.
---

# Managing UniFi Fixed Hosts with gofips / gofimac / gofinet

## Overview

`gofips`, `gofimac`, and `gofinet` are CLI tools from [github.com/emergingrobotics/gofi](https://github.com/emergingrobotics/gofi) for managing fixed IP assignments (DHCP reservations) and inspecting networks on a UniFi controller / UDM Pro.

- **`gofips`** — reads and writes fixed IP + hostname (+ DNS) reservations, using **ISC DHCP `host {}` declarations** as its file format.
- **`gofimac`** — lists currently detected/connected clients with their MAC, IP, hostname, and manufacturer.
- **`gofinet`** — lists networks with their subnet, VLAN, and DHCP dynamic-address pool. The companion to `gofips`: use it to learn the pool range so you pick static reservations **outside** it.
- **`gofi`** — the underlying Go module (not a CLI); ignore unless writing Go code.

Core workflow to change reservations safely: **`gofinet` to see the safe (non-pool) address range → `--get` to a file → edit the file → `--set --dry-run` to preview → user reviews the file and approves → `--set` to apply.**

## Prerequisites

All three tools authenticate via environment variables. Confirm these are set before running anything:

```bash
export UNIFI_USERNAME=admin
export UNIFI_PASSWORD=your-password
export UNIFI_CONTROLLER_IP=192.168.1.1   # optional; -H overrides
```

The controller host can also be passed with `-H`. TLS is self-signed by default (accepted); pass `-k`/`--secure` only if the controller has a verifiable cert. Note: the tools' own `--help` examples all pass `-k`, which *enforces* verification and will fail against a stock UDM's self-signed cert — if a run fails on a certificate error, drop `-k`.

If the env vars are not set, ask the user for the controller host and credentials — do not guess.

## Common Flags (all tools)

| Flag | Short | Purpose |
|------|-------|---------|
| `--host` | `-H` | Controller address (or `UNIFI_CONTROLLER_IP`) |
| `--port` | `-p` | Port (default: 443) |
| `--site` | `-S` | Site name (default: `default`) |
| `--secure` | `-k` | Enforce TLS cert verification (default: accept self-signed) |

## The Fixed-Hosts File Format (ISC DHCP)

`gofips` reads and writes standard ISC DHCP `host` blocks. This is the file the user edits:

```
# gofips fixed IP assignments
# exported from UDM at 192.168.1.1

host myserver {
    hardware ethernet aa:bb:cc:dd:ee:01;
    fixed-address 192.168.1.10;
}

host printer {
    hardware ethernet aa:bb:cc:dd:ee:02;
    fixed-address 192.168.1.11;
}
```

Each block: `host <name>` + `hardware ethernet <MAC>;` + `fixed-address <IP>;`. Entries are sorted by IP on export.

## gofinet: Network / Subnet / DHCP Pool Info

Before assigning a fixed IP, use `gofinet` to see each network's subnet and its **dynamic DHCP pool** — the range the controller hands out automatically. A static reservation should sit in the subnet but **outside** that pool to avoid collisions with dynamic leases.

```bash
gofinet -H 192.168.1.1        # all networks (text table)
gofinet -H 192.168.1.1 --json # JSON (use for parsing)   (-j)
```

Text output columns:

```
NETWORK     VLAN  SUBNET           DHCP-POOL                        LEASE   GATEWAY  DNS
Default     -     192.168.4.1/24   192.168.4.100 - 192.168.4.189    86400s  -        1.1.1.1,8.8.8.8
cj-iot      2     192.168.10.1/24  192.168.10.100 - 192.168.10.200  86400s  -        -
Internet 1  -     -                (disabled)                       -       -        -
```

| Column | Meaning |
|--------|---------|
| `NETWORK` | Network name |
| `VLAN` | VLAN id (`-` if untagged) |
| `SUBNET` | Subnet in CIDR (`-` for WAN / no L3) |
| `DHCP-POOL` | Dynamic address range, or `(disabled)` when no DHCP server (WAN, VLAN-only) |
| `LEASE` | DHCP lease time (e.g. `86400s`) |
| `GATEWAY` | Gateway address (`-` if not reported) |
| `DNS` | DNS servers, comma-separated (`-` if none set) |

In the example above, `192.168.4.100–189` is dynamic, so safe fixed addresses on `Default` are e.g. `192.168.4.2–99` or `192.168.4.190–254` (avoiding `.1`, the gateway).

### gofinet JSON Fields (`--json`)

Array of network objects. Fields present depend on network type:

**Always present:** `name`, `purpose` (`corporate`/`wan`/`guest`), `enabled` (bool), `dhcp_enabled` (bool).

**When the network has L3 / DHCP:** `subnet` (CIDR), `dhcp_start`, `dhcp_stop`, `dhcp_lease` (seconds), and `vlan` (int, only if tagged). `dns` (array) appears only when DNS servers are configured.

WAN / disabled networks carry only the always-present fields.

```bash
# safe-range inputs: subnet + dynamic pool bounds for every DHCP-enabled network
gofinet -H 192.168.1.1 --json \
  | jq -r '.[] | select(.dhcp_enabled) | "\(.name): subnet \(.subnet) pool \(.dhcp_start)-\(.dhcp_stop)"'
```

## gofips: Reading Fixed Hosts

Export current reservations to stdout (ISC DHCP format). Redirect to a file to edit:

```bash
gofips -H 192.168.1.1 --get > hosts.conf
```

## gofips: Adding / Changing Fixed Hosts

**Preferred (bulk / file-based) workflow — edit then apply:**

```bash
gofips -H 192.168.1.1 --get > hosts.conf     # 1. read current state
# 2. edit hosts.conf: add/modify/remove host {} blocks
gofips -H 192.168.1.1 --set hosts.conf --dry-run   # 3. preview
# 4. STOP: show the user the file + dry-run output; get explicit approval
gofips -H 192.168.1.1 --set hosts.conf             # 5. apply (only after approval)
```

`--set` accepts a file argument or stdin (`cat hosts.conf | gofips -H ... --set`). It validates all entries before applying, skips unchanged entries, and auto-detects the network from configured subnets.

> **REQUIRED — review gate before `--set`.** `--set` mutates live network config. Before running it (without `--dry-run`), you MUST:
> 1. Run `--set ... --dry-run` and capture the output.
> 2. Show the user **both** the full contents of `hosts.conf` and the dry-run output.
> 3. Get the user's explicit confirmation to proceed.
>
> Do NOT run a mutating `--set` on the user's behalf until they have reviewed the host file and approved. This applies even when the change "seems obvious" or the user asked you to make the edit — asking to edit the file is not the same as approving the apply. If you cannot show the file and get approval, stop and ask.

**Single-host add** (no file needed):

```bash
gofips -H 192.168.1.1 --add 'host mydev { hardware ethernet aa:bb:cc:dd:ee:ff; fixed-address 192.168.1.50; }'
```

To *change* an existing reservation, edit its block in the file and `--set`, or re-`--add` with the same MAC/name.

## gofips: Deleting Fixed Hosts

Delete by name, MAC, or IP (choose **exactly one** selector):

```bash
gofips -H 192.168.1.1 --del --name mydev            # -n
gofips -H 192.168.1.1 --del --mac aa:bb:cc:dd:ee:ff  # -m
gofips -H 192.168.1.1 --del --ip 192.168.1.50        # -i
```

| Flag | Short | Purpose |
|------|-------|---------|
| `--del` | `-d` | Delete a host by identifier |
| `--name` | `-n` | Selector: hostname to delete |
| `--mac` | `-m` | Selector: MAC address to delete |
| `--ip` | `-i` | Selector: IP address to delete |
| `--force` | `-f` | Skip conflict checks; force delete of the user record |
| `--keep-dns` | `-K` | Preserve DNS records when deleting |

Deleting by editing a block out of `hosts.conf` and running `--set` may **not** remove it (unchanged/absent entries are skipped, not deleted). To remove a reservation, use `--del` explicitly.

## gofips Flags Reference

| Flag | Short | Purpose |
|------|-------|---------|
| `--get` | `-g` | Export assignments to stdout (ISC DHCP format) |
| `--set` | `-s` | Import host declarations from a file or stdin |
| `--add` | `-a` | Add a single host from an ISC DHCP declaration |
| `--del` | `-d` | Delete a host by identifier (`-n`/`-m`/`-i`) |
| `--force` | `-f` | Skip conflict checks; **with `--set`, also re-process unchanged (otherwise skipped) entries** |
| `--keep-dns` | `-K` | Preserve DNS records when deleting |
| `--dry-run` | | Preview changes without applying |

## gofimac: Finding Detected Device MAC Addresses

List currently detected/connected clients. Use this to discover the MAC of a device the user wants to give a fixed IP:

```bash
gofimac -H 192.168.1.1            # all clients (default)
gofimac -H 192.168.1.1 --wifi     # WiFi only
gofimac -H 192.168.1.1 --wired    # wired only
gofimac -H 192.168.1.1 --json     # JSON output (use for parsing)
```

**History and presence** (useful for finding devices not currently online):

```bash
gofimac -H 192.168.1.1 --since 7d          # devices seen in the last window (present + gone)
gofimac -H 192.168.1.1 --gone              # only departed devices (default window 7d)
gofimac -H 192.168.1.1 --gone=30d          # departed within 30d
gofimac -H 192.168.1.1 --sort last-seen    # sort: first-seen (default), last-seen, ip
gofimac -H 192.168.1.1 --mac aa:bb:cc:dd:ee:ff   # presence probe: exit 0 if present, 1 if gone
```

Windows accept `h`/`d`/`mo` suffixes (e.g. `24h`, `7d`, `3mo`).

Default text output is **tab-separated: `MAC  IP  hostname  manufacturer`**, sorted by IP:

```
aa:bb:cc:dd:ee:01	192.168.1.10	myserver	Dell Inc.
aa:bb:cc:dd:ee:02	192.168.1.11	printer	Hewlett Packard
```

The manufacturer comes from an IEEE OUI database cached in `~/.local/share/gofimac/` (`$XDG_DATA_HOME/gofimac/`), auto-refreshed every 30 days.

### gofimac Flags Reference

| Flag | Short | Purpose |
|------|-------|---------|
| `--wifi` | `-w` | List only WiFi clients |
| `--wired` | `-e` | List only wired clients |
| `--all` | `-a` | List all clients (default) |
| `--json` | `-j` | Output JSON instead of text |
| `--since` | | Devices seen within window (present + gone), e.g. `7d`, `24h`, `3mo` |
| `--gone` | | Only departed devices; optional window (`--gone=30d`, default `7d`) |
| `--sort` | | Sort order: `first-seen` (default), `last-seen`, `ip` |
| `--mac` | `-m` | Probe one MAC; exit 0 if present, 1 if gone/not found |

### JSON Output Fields (`--json`)

`--json` emits an array of client objects. To find a device's MAC, match on `hostname` (or `manufacturer`) and read `mac`. Unknown values appear as the string `"unknown"`, not null.

**Always present:** `mac`, `ip`, `hostname`, `manufacturer`, `is_wired` (bool), `status` (`"present"`/`"gone"`), `rx_bytes`, `tx_bytes`, `uptime` (seconds), `first_seen`, `last_seen` (Unix epoch seconds).

**Wired clients also have:** `sw_mac` (uplink switch MAC), `sw_port` (switch port number).

**WiFi clients also have:** `essid`, `ap_mac`, `channel`, `radio`, `radio_proto`, `signal`, `noise`, `rssi`, and usually `satisfaction` (0-100; may be absent).

Example — get the MAC for hostname `garage-pi` with `jq`:

```bash
gofimac -H 192.168.1.1 --json | jq -r '.[] | select(.hostname=="garage-pi") | .mac'
```

## End-to-End: Give a Detected Device a Fixed IP

1. Check the network's dynamic pool so you pick a safe address:
   ```bash
   gofinet -H $UNIFI_CONTROLLER_IP
   ```
   Choose a `fixed-address` inside the subnet but **outside** the DHCP-POOL range (and not the gateway).
2. Find the device's MAC:
   ```bash
   gofimac -H $UNIFI_CONTROLLER_IP --json
   ```
   Identify the target by hostname/manufacturer; note its MAC.
4. Snapshot current reservations:
   ```bash
   gofips -H $UNIFI_CONTROLLER_IP --get > hosts.conf
   ```
5. Add or edit the `host {}` block in `hosts.conf` with the MAC from step 2 and the safe `fixed-address` from step 1.
6. Preview:
   ```bash
   gofips -H $UNIFI_CONTROLLER_IP --set hosts.conf --dry-run
   ```
7. **Show the user `hosts.conf` and the dry-run output, and wait for explicit approval** (see the review gate above).
8. Apply only after approval:
   ```bash
   gofips -H $UNIFI_CONTROLLER_IP --set hosts.conf
   ```
   (Or, for one device, skip the file and use `--add` — the same review gate applies before applying.)

## Common Mistakes

- **Using `gofi` as a command** — `gofi` is a Go module, not a CLI. The tools are `gofips`, `gofimac`, and `gofinet`.
- **Reserving inside the DHCP pool** — a `fixed-address` within the dynamic range can collide with a leased address. Run `gofinet` first and pick an IP outside the DHCP-POOL range (and not the gateway).
- **Expecting `--set` to delete** — removing a block from the file does not delete the reservation; `--set` skips unchanged/absent entries. Use `--del`.
- **Applying `--set` without user review** — these writes change live network config. Never run a mutating `--set` until you have shown the user the host file plus the `--dry-run` output and they have approved (see the review gate).
- **Missing credentials** — with no `UNIFI_USERNAME`/`UNIFI_PASSWORD`, auth fails; ask the user rather than guessing.
- **Confusing selectors on delete** — `--del` takes exactly one of `-n`/`--name`, `-m`/`--mac`, or `-i`/`--ip`, not the full `host {}` block.
- **`-a` means different things** — in `gofips`, `-a` is `--add`; in `gofimac`, `-a` is `--all`. Don't carry the short flag across tools.
- **Re-applying "unchanged" entries** — `--set` skips entries it considers unchanged. If you need to force a re-push (e.g. to repair drift), add `-f`/`--force`.
