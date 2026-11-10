# heqk ↔ legacy parity — gap inventory and fix loop (2026-11-07)

Source: a read-only, code-verified audit of `os/kernel` against `legacy/v1` and `legacy/linux-tier` (this
branch = main + Shield v2). Every heqk claim was checked in code; phase tags are `validate.sh` phases.
**Status** is updated as the fix loop closes items (each closure = code + QEMU phase + `validate.sh` +
`mc-e2e.sh` green + commit). Items needing the CM5 move to `heqk-metal-test-plan.md`.

## Cross-cutting findings

1. ~~The shipping AP image cannot include persistence~~ — resolved: the AP product is `apmc+appersist`
   (`kernel/src/main.rs:13-16`); persistence, the artifact store, the owner journal, the evidence log and the
   OS-image update all run in it.
2. **The AP loop (~1,400 lines inside `main.rs`, `cm5`-only) has no QEMU coverage.** Only logic already
   extracted into pure modules (apparse, ip6lan, shield, hal::policy, nat) is regression-tested.
3. No cargo unit tests: proof = QEMU phase markers + host harnesses.

## Gaps closable without the board (priority order)

| ID | Gap | Size | Status |
|---|---|---|---|
| G2 | DHCP server: leases never expire/reclaim (17th distinct MAC refused until reboot), 16-lease pool, `clients` = cumulative, no options 15/119 | S/M | **closed** `fb417999` [P-dhcpd] |
| G1 | `/api/devices` empty on the AP image (`note_host` never called there); leases hold MAC↔IP but no hostname/fingerprint (opt 12/55/60/61), no OUI | S/M | **closed** `fb417999` (+ policy/label `4b23f618`) |
| G4 | Beacon detector fed every TCP packet both ways, no refire cooldown → keep-alive FPs + alert storm evicting the 256-row ring; 16-entry tables | S | **closed** `fb417999` (SYN-only + refire cooldown) |
| G3 | Exfil detector not wired (only the selftest calls it); NAT already counts bytes per flow | S | **closed** `fb417999` |
| G11 | AP image has no wall clock (`set_clock(0)` + `disable_sntp`) → every AP timestamp is boot-relative | S | **closed** `fb417999` [P-wanntp] |
| G13 | Investigate calls `/api/reports`, `/api/evidence/graph`, `/api/evidence/stats` → 404 on heqk; `/api/engines` always `[]`; no `/api/manifest`, `/api/verdicts/dns`; SampleDataNotice marks Investigate fully live | S each | **done** (`fb417999`; all four routes served and covered by mc-e2e — register row was stale) |
| G5 | QSECBIT only scores wire-DROPPED detections → observe-only threats (beacon, lateral, IOC, ARP spoof) leave it GREEN | M | **closed** `fb417999` (severity scoring + 5-min decay) |
| G0 | Extract the AP loop into a pure `apcore` (NIC trait) + QEMU harness | L | **steps 1–3c done** (2026-11-09/10; 3b `client6`, 3c `station_relay` + eth1): client IPv4 forwarding → `apcore::forward4`, the inbound WAN leg → `apcore::wan4`, the Wi-Fi client gate chain → `apcore::client4` (`[P-apcore]`, `[P-apcore-wan]`, `[P-apcore-lan]`). Next: the rest of the Wi-Fi data arm + eth1, mgmt, `tick()` (plan in the 2026-11-09 session notes) |
| G7 | Threat intel = 4 hard-coded CIDRs; need a signed IOC pack (CIDR v4/v6, domains), LPM, per-entry expiry | M | **closed** `4b23f618` [P-ioc] |
| G8 | No DGA/lookalike scoring on Shield queries (detect-only; score the registrable label — V1's `parts[0]` bug) | S/M | **closed** `fb417999` [P-dga] |
| G9 | Local NAC: signed DEVICES.TXT (MAC → full/internet_only/lan_only/quarantine) arming `segment` without enrollment | M | **closed** `4b23f618` [P-devpolicy] |
| G23 | Read-only `/api/enforcement` (rate-limited / quarantined sources + time left) | S | **closed** `fb417999` (/api/enforcement) |
| G6 | Signed dynamic rule pack (RULES.BIN via the DET-2 gate) + NAPSE rule port; `MAX_RULES` 16 → 256 | M/L | **closed** (batch 5) [P-rulepack] — signed RULES.BIN + tools/rulepack.py + NAPSE-derived starter pack; heap-safe loader |
| G14 | Operator write APIs (logout, incident ack, quarantine/release, Shield allow/pause) + Origin check + audit ring | M | **done + metal** — ADR 0053 accepted with safeguards (`4cc172ba`, `1e36a1f9`); H7–H10 + H5-neg PASS unattended on the relay rig (`metal-evidence/20261108-relay-round-h10.md`) |
| G15 | Local SIEM export (RFC 5424 syslog / OCSF JSON) — beats both legacy tiers | M | **closed** (batch 4) [P-siem] |
| G12 | Converge AP + prod-full into one shippable image | L | **accepted** (register 2026-11-08) — ADR 0054: per-device setup credential + MAC (`bed9c46e`, `d784ab2e`), MC on the management VLAN (G12-M); metal I1/I3/I6/I8/I9 PASS; G12 persistence across a relay power cut **metal PASS** (`488ba6dc`); the sealed evidence log in the DataVolume (#54, `[P-evlog]`) keeps ~90k detections across power cycles (metal `cm5-evlog-check.sh`). Remaining: MC QR panel, setup→client hand-off UI |
| G16 | WAN health probes (ICMP/DNS) with hysteresis | M | **closed** (batch 4) [P-wanhealth] |
| G17 | IPv6 (RS + DHCPv6-PD) on DHCP/static WAN, not only PPPoE | M | **done + metal** — G17.1 RS/RA/PD/ND (`451c64ea`), G17.2 LAN MTU follows the WAN, G17.3 inbound default-deny attacked from the WAN (no answer, counted, hop-1 dropped), G17.4 PD renewed at T1 (`9247fc4e`); evidence in `metal-evidence/20261108-g17-*`, `…-g22-g17-2-g17-4.md` |
| G24a/G18 | ADR 0049 D2 IPv6 source identity → IPv6 scan/behaviour/IOC detection | M/L | **done + metal**: scan shape (`0a74b9ad`), JA4 + brute force + beacon (G35/G36), IOC IPv6 prefixes (signed pack `ip`/`cidr` v6, LPM + expiry; outbound dst + inbound src on the AP, attributed to the lease; LAN-client 16/16). Open: lateral LAN↔LAN v6 (see G10), IPv6-only devices (no lease to attribute) |
| G13e | Deterministic incident reports | M | **closed** `fb417999` (deterministic reports) |
| G20 | Signed WIFI.TXT (SSID, PSK, channel, guest) instead of build-time env | S | **closed** (batch 4) [P-wificfg] — AP builds without a build-time PSK |
| G22 | Shield per-client profiles, pause, list refresh | M | **pause done + metal** (`9247fc4e`, H11a–c); **per-client profiles done + metal**: signed DEVICES.TXT `shield=standard|off|strict`, `/api/devices` `shield_profile` (UI: for the designer). List refresh without re-flash: **built** — ADR 0056 phase 1 signed data-pack upload over Mission Control HTTPS (artifact store A/B, live reload, rollback; `[P-artstore]` `[P-upload]`, metal `cm5-upload-check.sh`). Levels: **built** — ADR 0057 categorised relaxed/balanced/strict (`[P-shield-levels]`, metal `cm5-shield-levels-check.sh`) |
| G24b | ADR 0050 D4 EL0 steps 1-4 (HTTP, DHCP/DNS, PPPoE/DHCP clients, Noise) | L each | open |
| G24c, G28 | crypto audit / libcrux ML-KEM; logout / session list / owner-key rotation | M / S | G28 logout **closed** (batch 5); **owner-key rotation done** (2026-11-10, `[P-owner-rotate]`, mc-e2e): `POST /api/owner-key`, re-auth + sealed journal record, all sessions end, a re-flashed OWNER.TXT still recovers — metal next; G24c **decision** |
| G19 | HTP/SASE tunnel over the Noise channel | L | **device side built** (2026-11-10, `[P-g19]`, mc-e2e): signed POLICY `tunnel pop <ip> full|split …` + a PoP key baked from `HEQK_POP_PUB` (none = no tunnel); unicast Noise handshake via the WAN gateway; HQT1 DATA over :7655 with the shared NAT engine on the ASSIGNed inner /32, MSS clamp, keepalive / re-handshake; inbound DATA through the normal WAN path. PoP: `onboarding/enrollment/superpop` (#923/#937). Metal against the bench PoP: queued (needs `sudo ~/superpop-bench/bench.sh start` on fortress) |
| G37 | Durable owner settings without re-signing (legacy parity #1): ADR 0055 owner policy journal | M | **done + metal** (`8bef3b08`): HMAC-chained journal in the DataVolume, re-auth + permanent confirmation, dry-run preview, precedence below floor / IOC / pinned lines; a rule survives a relay power cut (`cm5-owner-rules-check.sh` 10/10) |
| docs | `heqk-remaining-gaps.md` cites the removed `[P-dnsblock]`; `GAP_REGISTER.md` stale (July) | S | **closed** (batch 4) |

## Needs the board

G10 intra-BSS — **unicast done + metal** (firmware honours `ap_isolate`; heqk now relays station↔station after the lease + IDS gates: proxy-ARP + unicast relay, `tools/diagnostics/cm5-intrabss-check.sh` PASS, the IDS saw B's 4444 attempt at A); **multicast discovery (mDNS/SSDP/LLMNR) + IPv6 station↔station done + metal** (`076f1fd8`, `e7a495d5`) (`ap_isolate`=1 now set at AP start, batch 5 — the board shows whether the firmware honours it); Shield on a non-Relay client; `/api/flows` + drill-down on metal;
eth1 traffic; Wi-Fi TX-stall root cause; WPA3-SAE/PMF + guest SSID; LTE/USB WAN; native-IPv6 ISP (G17);
RPMB floor (G24d, operator decision, irreversible); P-256 constant time — **done on the host** (`metal-evidence/20261108-p256-ct.md`: only validity-flag declassifications); WPA2 authenticator → EL0; G12 final
acceptance (persistence across power cycle, OTA tryboot); re-flash validation of every AP-side fix.

## Legacy lessons carried into every fix

V1 "lateral on one SYN" was an FP factory · V1 `pps` was per-60 s · never ship a model with random weights ·
rule-ID collisions → `rulecat.rs` is the single catalogue · HYDRA never deleted expired IOCs · V1 NAC took
unvalidated MACs into SQL/OVS · Guardian write routes had no CSRF and a shell `/execute` · dnsXai's Bloom fast
path broke subdomain matching · V1 HTP VPN fell back to an all-zero Kyber key — never fall back silently.

## Defects found by the fix loop itself (fixed)

| Where | Defect | Fix |
|---|---|---|
| `http.rs`/`mcstate.rs` | my attack-path refactor left `/api/incidents/:id` JSON unterminated | caught by [P-mc]; fixed before commit |
| `validate.sh` row P-policy | a backtick-quoted `from` ran as a shell command on every validate (silent noise, word dropped) | quoted properly |
| `make-cm5-heqk-disk.sh` | file-offset locators read only the FIRST root-directory sector (16 entries); 18+ files made MCTLS.CRT "missing" — the browser flasher's own locator may share this assumption (task #20) | one walker over the whole root cluster chain |
| `rulepack.rs` | the BPF verifier (~4 KiB) and JIT allocate from the never-freeing heap; a large pack could exhaust it and PANIC at boot | heap-margin guard: verify only with margin, JIT only with margin (else interpreter), refusals counted |
| `mc-e2e.sh` | fixed host ports + /tmp files collided across concurrent sessions | per-run ports and run dir |

| G25 | Cable plugged after boot left WAN + management dead (GEM speed chosen once) | S | **done + metal** (`b6ebdcba`): `gem::sync_speed` on link-up; unattended late-link test re-leased 8 s after link-up (`metal-evidence/20261108-latelink.md`) |

## Detection + discovery vs legacy (2026-11-08)

Legacy inventory (agents, path:line evidence): V1 NAPSE ran as a per-packet Python sniffer on a mirror port
(IPv4 + DNS name only, ~10 thresholds), XDP in monitor mode on the mirror, Zig/Mojo scaffolds, three
QSECBIT formulas with stubbed inputs, no measured benchmark anywhere. heqk inspects inline; first measured
cost: ~0.8 µs/pkt for every tier on the CM5 A76 (`metal-evidence/20261108-ids-bench-baseline.md`).

| # | Gap | Size | Status |
|---|---|---|---|
| G29 | Brute force on one login service (legacy: >50 SYN to admin ports, no evidence) | S | **done + metal** rule 124, answered-only (D3), un-NAT fix found on metal (`74f61a68`, `d6a62268`) |
| G30 | TLS client fingerprint (legacy JA3 never started; linux-tier JA4) | M | **done + metal** JA4 + SNI inline, `/api/tls`, IOC `ja4` lines → rule 125 (`d6a62268`) |
| G31 | Shield bypass visibility (DoH / pinned IP) | S | **done + metal** rule 126 SNI-vs-Shield (`d6a62268`); **enforcement per the operator (2026-11-10) done** (`[P-sni-block]`): the bypass is always only observed; a ClientHello whose SNI the device's Shield decision blocks is dropped and logged in the Shield log with its category; an allowed name, a Shield-off device and a non-LAN source always pass — metal next |
| G32 | Device discovery parity (Fingerbank opt 55/60, OUI, pinned OUI, private-MAC linking) | M | **D1 done + metal** (`49cd473e`), **D2 done + metal** passive mDNS/SSDP names (`5752ba63`); D3 full IEEE registry (40 455 MA-L, `os/build/fpgen/gen_oui.py` from the IEEE oui.csv) as signed OUI.TXT on the boot partition, curated vendors first (found on the bench: the Pi's 2025 TP-Link dongle prefix is in neither the legacy table nor nmap's 2024 list). **JA4 identity signal built** (2026-11-10, `[P-ja4id]`): distinct TLS fingerprints per MAC; a private MAC that appears after an earlier MAC went quiet and shares ≥ 2 fingerprints at ≥ 50 % Jaccard gets `likely_same_as` in `/api/devices` (a hint for the owner, never a merge or an enforcement key; concurrent or ambiguous matches give no hint) — **metal PASS** (batch 53: rotation A→B linked, `docs/design/metal-evidence/20261110-batch52-53.md`) |
| G33 | Real LAN-client test path | S | **done** Pi 4 on the CM5 AP, `tools/diagnostics/cm5-lan-client.sh` 10/10 |
| G34 | Parse each packet once (≈ −30 % IDS CPU) | S | step 1 (no per-packet 2 KB zeroing) **metal**: IDS-BENCH mix 802 → 536 ns/pkt (`fe507d6e`); 1b uplink buffers (`71544bb5`) + 2 one `net::parse` per verdict **metal**: mix 511 ns/pkt, 1.96 Mpps/core (−36 % vs 802) |
| G35 | IPv6 detection coverage: JA4 / rules 125-126 saw IPv4 TLS only (found on the bench: `openssl s_client` over v6 was invisible) | S | **done + metal** JA4 on the AP's IPv6 LAN path, attributed to the device's IPv4 lease; `/api/tls` `lease` field |
| G36 | IPv6 behavioural rules: brute force (124), beaconing, lateral are IPv4-keyed; v6 has scan shape only (G24a) | M | **brute force + beacon done, 124-over-v6 metal**: a dual-stack device's v6 connections feed the v4 tables under its lease, the peer folded into 240/4. Lateral v6 **done** (`lateral_observe6`); **IPv6-only devices done** (2026-11-10, `[P-v6only]`): a device with no IPv4 lease keys on a stable 248.0.0.0/5 identity (peers moved to 240/5, disjoint) instead of being skipped; detections carry `src_device` (MAC) — **metal PASS** (batch 53: rule 124 from an IPv6-only device attributed to its MAC) |
| G37 | `/api/tls` not surfaced in Mission Control | S | **done** (build + e2e) My Network shows per-device TLS programs + names, known-bad TLS client (125) and Shield-bypass (126) flags |
| G38 | Shield page showed sample controls (relaxed/balanced/strict) on a real device after 3 slow reads, then they vanished (operator report) | S | **done** (build + e2e) device builds never fall back to the sample layout; "still waiting" status instead |
| G39 | Beaconing invisible on any busy host: beacon table direct-mapped by `key % 256`, whose low 8 bits were the source's last octet — every (dst, port) of a host shared one slot | S | **fixed** 4096 slots, hashed 2-way sets, evict the shorter history; `[P-beacon-busy]` (old code: detected=false) |
| G40 | Per-source SYN limiter never tripped on a busy LAN: slot = first octet of the LE-loaded source (all 10.x shared a slot, each other client's SYN reset the count); flow/scan/corroboration tables 16 slots | S | **fixed + metal** (`ae5c9ad9`) hashed `ratelimit::slot`, 64-slot per-source tables; busy-LAN flooder regression |
| G41 | Flow tier interpreted (JIT refused BPF CALL) | M | **done + metal** (`ae5c9ad9`) CALL in the JIT for scalar helpers: flow 140 -> 58 ns, mix 419 ns/pkt (802 at the start of G34) |
| G42 | Shipping ML-KEM 0.2.3 had a secret-indexed table lookup (SamplePolyCBD) | S | **done + metal** (`efa098f3`) ml-kem 0.3.4 (upstream fix #386), ctgrind 0 errors, Chromium X25519MLKEM768 on the CM5 |
