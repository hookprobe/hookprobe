# heqk — remaining gaps (living list, 2026-11-07 evening)

Legend — **Board**: needs the CM5 (flash / power-cycle / bench). **Decision**: needs the operator.
Status `built` = committed + QEMU/host-proven, not yet on silicon.

## Security / crypto

| # | Gap | Status | Board? | Notes |
|---|---|---|---|---|
| 1 | ADR 0049 D1 signed POLICY.TXT — metal check | built `aa24555` | **Board** | AP boot must print `[POLICY] signature OK — generation 2`; a tampered POLICY.TXT must lock management |
| 2 | POLICY.TXT anti-rollback floor **persisted** | partial (floor compiled into the image) | no | the AP image has no writable sealed store; a floor in the eMMC keystore window (prod-full pattern) is the follow-up |
| 3 | ADR 0049 D3 response-observed scans — metal check | built | **Board** | real `nmap -sS` / `-sT` across the passive sensor + through the AP; confirm one-sided traffic stays uncounted |
| 4 | ADR 0049 D2 IPv6 source identity (device-keyed LAN, /64 WAN) | design only | no | operator: design now, build later (gap 13) |
| 5 | P-256 signing timing review (scalar mult + inversion) | open | no | rate limit is the mitigation meanwhile (ADR 0051) |
| 6 | Independent audit status: `sha2`/`hmac`, `ml-kem` | open | no | none found publicly; libcrux ML-KEM (formally verified) is the alternative |
| 7 | Owner CA in the browser flasher + one-time root install | open | no | task #20 (another session); device side ready (MCTLS.CRT, pubkey published) |

## Product / UI

| # | Gap | Status | Board? | Notes |
|---|---|---|---|---|
| 8 | Shield + Get Online tiles | open | no (then Board) | need Mission Control served by the AP image (`apmode` + `mcserve`) |
| 9 | HTTPS on the AP image | open | no (then Board) | follows #8 (same EL0 TLS server) |
| 10 | IPv6 on the management VLAN | blocked on #4 | — | |

## Architecture (ADR 0050 D4 migration — control protocols to EL0)

| # | Gap | Status | Board? | Notes |
|---|---|---|---|---|
| 11 | HTTP/TLS server in EL0 | **partial** — TLS in EL0, HTTP parse still EL1 | no | smoltcp + HTTP move with step 1 |
| 12 | DHCP server + DNS forwarder → EL0 | open | no (then Board) | |
| 13 | PPPoE / DHCPv4/v6 / RA client → EL0 | open | no (then Board) | |
| 14 | Noise control channel → EL0 | open | no | |
| 15 | WPA2 authenticator → EL0 | open | Board | moves with the CYW43455 driver |
| 16 | `uplink.rs` mgmt handlers fuzzed | hand-reviewed only | no | refactor off the MMIO statics (the `hal::defer` pattern) |

## Field / hardware

| # | Gap | Status | Board? | Notes |
|---|---|---|---|---|
| 17 | Wi-Fi firmware TX-stall root cause | mitigated (kick) | **Board** | |
| 18 | Task #22 metal acceptance + Linux unbuild batches | open | **Board** | |
