# heqk — remaining gaps (living list, 2026-11-07 evening)

Legend — **Board**: needs the CM5 (flash / power-cycle / bench). **Decision**: needs the operator.
Status `built` = committed + QEMU/host-proven, not yet on silicon.

## Security / crypto

| # | Gap | Status | Board? | Notes |
|---|---|---|---|---|
| 1 | ADR 0049 D1 signed POLICY.TXT — metal check | built `aa24555` | **Board** | AP boot must print `[POLICY] signature OK — generation 2`; a tampered POLICY.TXT must lock management |
| 2 | POLICY.TXT anti-rollback floor **persisted** | partial (floor compiled into the image) | **Decision** | a floor an attacker with the card cannot roll back needs the eMMC **RPMB** partition — programming its key is irreversible |
| 3 | ADR 0049 D3 response-observed scans — metal check | built `9cc2520` | **Board** | real `nmap -sS` / `-sT` across the passive sensor + through the AP; confirm one-sided traffic stays uncounted |
| 4 | ADR 0049 D2 IPv6 source identity (device-keyed LAN, /64 WAN) | **designed** (ADR 0049 D2 detailed design) | no | build later per operator (gap 13) |
| 5 | P-256 signing timing review | **source review done** — no secret-dependent branch/index | Board (empirical) | residual: compiler/µarch; a dudect-style timing run on the CM5 |
| 6 | Independent audit status: `sha2`/`hmac`, `ml-kem` | open | no | none found publicly; libcrux ML-KEM (formally verified) is the alternative |
| 7 | Owner CA in the browser flasher + one-time root install | open | no | task #20 (another session); device side ready (MCTLS.CRT, pubkey published) |

## Product / UI

| # | Gap | Status | Board? | Notes |
|---|---|---|---|---|
| 8 | Shield + Get Online tiles | built `3b93b3b` (`apmc`) | **Board** | Get Online = WAN facts; Shield = DNS queries inspected (no blocklist on heqk yet) |
| 9 | HTTPS on the AP image | built `3b93b3b` | **Board** | cert SANs heqk.local / 10.99.0.1 / 10.200.0.6; owner CA re-issued with private-range constraints |
| 10 | IPv6 on the management VLAN | blocked on #4 | — | |

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
