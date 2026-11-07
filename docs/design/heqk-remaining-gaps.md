# heqk — remaining gaps (living list, 2026-11-07 night)

Legend — **Board**: needs the CM5 (flash / power-cycle / bench). **Decision**: needs the operator.
Status `built` = committed + QEMU/host-proven, not yet on silicon.

## Security / crypto

| # | Gap | Status | Board? | Notes |
|---|---|---|---|---|
| 1 | ADR 0049 D1 signed POLICY.TXT — metal check | **metal: signature OK** (AP image `74cb1a9`, `[POLICY] signature OK — operator key, generation 2 (floor 2)`) | — | **tampered POLICY.TXT metal PASS** (admin prefix widened /32→/24, signature untouched): `signature REFUSED (DigestMismatch)` → management LOCKED; fortress mgmt ping 4/4 before → 0/4 after (`dropped=4`); AP + HTTPS still up. Evidence `~/heqk-metal-logs/20261107-ADR0049-D1-tampered-policy-metal.txt` |
| 2 | POLICY.TXT anti-rollback floor **persisted** | partial (floor compiled into the image) | **Decision** | a floor an attacker with the card cannot roll back needs the eMMC **RPMB** partition — programming its key is irreversible |
| 3 | ADR 0049 D3 response-observed scans — metal check | **metal: nmap sweep fired rule 113 (93 drops)** | Board (optional) | real `nmap -sS` / `-sT` across the passive sensor + through the AP; confirm one-sided traffic stays uncounted |
| 4 | ADR 0049 D2 IPv6 source identity (device-keyed LAN, /64 WAN) | **designed** (ADR 0049 D2 detailed design) | no | build later per operator (gap 13) |
| 5 | P-256 signing timing review | **source review done** — no secret-dependent branch/index | Board (empirical) | residual: compiler/µarch; a dudect-style timing run on the CM5 |
| 6 | Independent audit status: `sha2`/`hmac`, `ml-kem` | open | no | none found publicly; libcrux ML-KEM (formally verified) is the alternative |
| 7 | Owner CA in the browser flasher + one-time root install | open | no | task #20 (another session); device side ready (MCTLS.CRT, pubkey published) |

## Product / UI

| # | Gap | Status | Board? | Notes |
|---|---|---|---|---|
| 8 | Shield + Get Online tiles | **metal: AP Mission Control served** (`74cb1a9`) | — | Get Online = WAN facts; Shield = queries inspected + blocked (see #20) |
| 9 | HTTPS on the AP image | **metal PASS** — iPhone on the heqk AP: http://10.99.0.1 → https, owner sign-in, pages + sub-pages load (`74cb1a9`; needed the ARP-to-node fix) | — | cert SANs heqk.local / 10.99.0.1 / 10.200.0.6; owner CA re-issued with private-range constraints |
| 10 | IPv6 on the management VLAN | blocked on #4 | — | |
| 20 | Shield DNS blocklist on the AP | **built** — operator-signed BLOCK.TXT (≤ 65,536 domains, label-suffix match), blocked queries answered on-device (A → 0.0.0.0, else NODATA), Shield tile shows blocked/inspected; `[P-dnsblock]` + fuzz | **Board** | metal 2026-11-07 (`22425ea5` `[SHIELD]` heartbeat): list loads (7, signature OK), 131 iPhone queries reach the hook, `blocked=0` — **no plain query for example.org ever arrived**; the iPhone was resolving Safari through iCloud Private Relay (`mask.apple-dns.net` seen). Pending: confirm with Chrome/Firefox or Private Relay off globally. Product follow-up: show 'client uses encrypted DNS / Private Relay' in Shield (DoH/DoT/Relay bypass any DNS filter) |
| 21 | Flows + incident drill-down served by heqk | **built** — `/api/flows` (AP NAT table: first/last seen, bytes each way), `/api/incidents/:id` (explanation: deterministic rule match, `model: null`; attack path), `/timeline` (detections + the source's flows), `/processes` (honest empty: no host EDR) | **Board** | passive-sensor images keep no per-flow table → flows empty there |
| 19 | Workspaces without a heqk API showed sample data unlabeled | **built** — `/api/devices` from the host inventory (first/last seen, MAC never invented) + a "Sample data" notice on every view heqk does not back | Board (re-flash) | still sample on heqk: Protect, Automate, Intelligence, Knowledge, Business, Customers, Admin, network map/DNS |

## Architecture (ADR 0050 D4 migration — control protocols to EL0)

| # | Gap | Status | Board? | Notes |
|---|---|---|---|---|
| 11 | HTTP/TLS server in EL0 | **partial** — TLS in EL0, HTTP parse still EL1 | no | smoltcp + HTTP move with step 1 |
| 12 | DHCP server + DNS forwarder → EL0 | open | no (then Board) | |
| 13 | PPPoE / DHCPv4/v6 / RA client → EL0 | open | no (then Board) | |
| 14 | Noise control channel → EL0 | open | no | |
| 15 | WPA2 authenticator → EL0 | open | Board | moves with the CYW43455 driver |
| 16 | `uplink.rs` mgmt handler fuzzed | **done** `3b93b3b` (`mgmtproto`, 0 panics 30k) | — | |

## Field / hardware

| # | Gap | Status | Board? | Notes |
|---|---|---|---|---|
| 17 | Wi-Fi firmware TX-stall root cause | mitigated (kick) | **Board** | |
| 18 | Task #22 metal acceptance + Linux unbuild batches | open | **Board** | |
