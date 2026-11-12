# heqk — remaining gaps (living list, 2026-11-08)

> Superseded for software gaps by `heqk-parity-gaps.md` (legacy parity inventory + fix loop) and for
> board work by `heqk-metal-test-plan.md`. This table keeps the original security/architecture items.

Legend — **Board**: needs the CM5 (flash / power-cycle / bench). **Decision**: needs the operator.
Status `built` = committed + QEMU/host-proven, not yet on silicon.

## Security / crypto

| # | Gap | Status | Board? | Notes |
|---|---|---|---|---|
| 1 | ADR 0049 D1 signed POLICY.TXT — metal check | **metal: signature OK** (AP image `74cb1a9`, `[POLICY] signature OK — operator key, generation 2 (floor 2)`) | — | **tampered POLICY.TXT metal PASS** (admin prefix widened /32→/24, signature untouched): `signature REFUSED (DigestMismatch)` → management LOCKED; fortress mgmt ping 4/4 before → 0/4 after (`dropped=4`); AP + HTTPS still up. Evidence `~/heqk-metal-logs/20261107-ADR0049-D1-tampered-policy-metal.txt` |
| 2 | POLICY.TXT generation floor **persisted** (≠ the boot SVN floor) | compile-time floor in the image | **Deferred** (decision 2026-11-08) | RPMB key programming deferred; the boot SVN compile floor is active and the OTP thermometer path exists unprovisioned — see `heqk-decisions-2026-11-08.md` §A |
| 3 | ADR 0049 D3 response-observed scans — metal check | **metal: nmap sweep fired rule 113 (93 drops)** | Board (optional) | real `nmap -sS` / `-sT` across the passive sensor + through the AP; confirm one-sided traffic stays uncounted |
| 4 | ADR 0049 D2 IPv6 source identity (device-keyed LAN, /64 WAN) | **designed** (ADR 0049 D2 detailed design) · *updated 2026-11-09: **done + metal** — see `heqk-parity-gaps.md` G24a (IPv6 scan/JA4/brute-force/beacon/IOC attributed to the lease)* | no | build later per operator (gap 13). Still open per G24a: lateral LAN↔LAN v6, IPv6-only devices |
| 5 | P-256 signing timing review | **source review done** — no secret-dependent branch/index | Board (empirical) | residual: compiler/µarch; a dudect-style timing run on the CM5 |
| 6 | Independent audit status: `sha2`/`hmac`, `ml-kem` | open | no | none found publicly; libcrux ML-KEM (formally verified) is the alternative |
| 7 | Owner CA in the browser flasher + one-time root install | open | no | task #20 (another session); device side ready (MCTLS.CRT, pubkey published) |

## Product / UI

| # | Gap | Status | Board? | Notes |
|---|---|---|---|---|
| 8 | Shield + Get Online tiles | **metal: AP Mission Control served** (`74cb1a9`) | — | Get Online = WAN facts; Shield = queries inspected + blocked (see #20) |
| 9 | HTTPS on the AP image | **metal PASS** — iPhone on the heqk AP: http://10.99.0.1 → https, owner sign-in, pages + sub-pages load (`74cb1a9`; needed the ARP-to-node fix) | — | cert SANs heqk.local / 10.99.0.1 / 10.200.0.6; owner CA re-issued with private-range constraints |
| 10 | IPv6 on the management VLAN | blocked on #4 | — | |
| 20 | Shield DNS protection on the AP | **rebuilt as Shield v2** (ADR 0052, `f9de855e`): AP is the resolver of record, all client DNS (any resolver, UDP+TCP/53) decided, DDR/canary/Private-Relay/DoH/DoT controls, NXDOMAIN+EDE15, CNAME-cloak check, query log + `/api/dns` + live Shield page; `[P-shield]` + fuzz. The v1 metal miss (blocked=0) is diagnosable now via the query log | **Board** | metal plan A1–A10 (`heqk-metal-test-plan.md`) |
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

## Status reconciled 2026-11-12 (A12 doc hygiene; main `58d83647`)

The tables above are kept as written (history). Rows that changed since, with labels (`not built`, `QEMU only`,
`metal pending`, `metal-proven (<evidence>)`, `blocked (<reason>)`):

| # | Status 2026-11-12 | Evidence |
|---|---|---|
| 2 | POLICY generation floor persisted on the device (trust anchor, `anchor.rs`): metal-proven. RPMB anchoring prepared, not an active guarantee: blocked (manufacturing key write, operator decision — release gate TC-04) | `docs/design/heqk-audit-2026-11-10.md` §3.1 J4 |
| 4 | done + metal (see the inline update and `heqk-parity-gaps.md` G24a) | `docs/design/metal-evidence/20261108-g24a-d2-v6src.md` |
| 10 | no longer blocked on #4 (done); IPv6 on the management VLAN itself: not reconciled here — see `heqk-parity-gaps.md` | — |
| 11 | done: TLS and the HTTP request parse both run in the EL0 server (ADR 0050 D4 step 1, 2026-11-10) | release gate SEC-01 text; `docs/design/metal-evidence/20261111-batch59-63.md` |
| 12 | done: DNS (step 2a) and the DHCP server parse (2b) in `el0-lansvc`; metal-proven via `[P-lansvc]` on CM5 | `docs/design/metal-evidence/20261111-batch59-63.md` |
| 13 | done: WAN DHCPv4 / RA / DHCPv6 (3a) and PPPoE / PPP (3b) parse in EL0; metal-proven via `[P-lansvc]` (incl. 3b) | `docs/design/metal-evidence/20261111-batch59-63.md` |
| 14 | closed by decision: Noise stays in EL1 (identity-key custody, operator 2026-11-11). In-session record-layer rekey added (PR #1017): QEMU only, metal pending | ADR 0050 D4; `docs/design/heqk-audit-2026-11-10.md` §2.1 #12 |
| 15 | partial: EAPOL-Key + RSNE walk (5a) metal-proven; station-frame work (5b) QEMU only; WPA3-SAE frame walk (5c, PR #1005) QEMU only, metal pending; the authenticator state machine still moves with the driver: not built (release gate SEC-01 blocked) | `docs/design/metal-evidence/20261111-batch59-63.md`; ADR 0050 D4 |
| 17 | the ~10 h WPA3 firmware trap was root-caused (REL-08b, CYW43455 PMKID-cache use-after-free) and is corrected in chip RAM (on by default with `wpa3`): 72 h soak + regression matrix metal pending; shipping blocked (written legal clearance, release gate CMP-02). The older TX-stall (release gate REL-08a): still mitigated (kick), root cause open | `docs/design/rel08-cyw43455-pmkid-trap.md` |

