# heqk ↔ legacy parity — gap inventory and fix loop (2026-11-07)

Source: a read-only, code-verified audit of `os/kernel` against `legacy/v1` and `legacy/linux-tier` (this
branch = main + Shield v2). Every heqk claim was checked in code; phase tags are `validate.sh` phases.
**Status** is updated as the fix loop closes items (each closure = code + QEMU phase + `validate.sh` +
`mc-e2e.sh` green + commit). Items needing the CM5 move to `heqk-metal-test-plan.md`.

## Cross-cutting findings

1. **The shipping AP image (`apmc`) cannot include `prod-full`** (snapshot persistence, enrollment, M6
   export, OTA orchestrator): `compile_error!` at `kernel/src/main.rs:13`, justified by a stale comment
   ("AP NATs without packet::verdict" — it calls it at six places).
2. **The AP loop (~1,400 lines inside `main.rs`, `cm5`-only) has no QEMU coverage.** Only logic already
   extracted into pure modules (apparse, ip6lan, shield, hal::policy, nat) is regression-tested.
3. No cargo unit tests: proof = QEMU phase markers + host harnesses.

## Gaps closable without the board (priority order)

| ID | Gap | Size | Status |
|---|---|---|---|
| G2 | DHCP server: leases never expire/reclaim (17th distinct MAC refused until reboot), 16-lease pool, `clients` = cumulative, no options 15/119 | S/M | open |
| G1 | `/api/devices` empty on the AP image (`note_host` never called there); leases hold MAC↔IP but no hostname/fingerprint (opt 12/55/60/61), no OUI | S/M | open |
| G4 | Beacon detector fed every TCP packet both ways, no refire cooldown → keep-alive FPs + alert storm evicting the 256-row ring; 16-entry tables | S | open |
| G3 | Exfil detector not wired (only the selftest calls it); NAT already counts bytes per flow | S | open |
| G11 | AP image has no wall clock (`set_clock(0)` + `disable_sntp`) → every AP timestamp is boot-relative | S | open |
| G13 | Investigate calls `/api/reports`, `/api/evidence/graph`, `/api/evidence/stats` → 404 on heqk; `/api/engines` always `[]`; no `/api/manifest`, `/api/verdicts/dns`; SampleDataNotice marks Investigate fully live | S each | open |
| G5 | QSECBIT only scores wire-DROPPED detections → observe-only threats (beacon, lateral, IOC, ARP spoof) leave it GREEN | M | open |
| G0 | Extract the AP loop into a pure `apcore` (NIC trait) + QEMU harness | L | open |
| G7 | Threat intel = 4 hard-coded CIDRs; need a signed IOC pack (CIDR v4/v6, domains), LPM, per-entry expiry | M | open |
| G8 | No DGA/lookalike scoring on Shield queries (detect-only; score the registrable label — V1's `parts[0]` bug) | S/M | open |
| G9 | Local NAC: signed DEVICES.TXT (MAC → full/internet_only/lan_only/quarantine) arming `segment` without enrollment | M | open |
| G23 | Read-only `/api/enforcement` (rate-limited / quarantined sources + time left) | S | open |
| G6 | Signed dynamic rule pack (RULES.BIN via the DET-2 gate) + NAPSE rule port; `MAX_RULES` 16 → 256 | M/L | open |
| G14 | Operator write APIs (logout, incident ack, quarantine/release, Shield allow/pause) + Origin check + audit ring | M | open — needs operator ADR on authority |
| G15 | Local SIEM export (RFC 5424 syslog / OCSF JSON) — beats both legacy tiers | M | open |
| G12 | Converge AP + prod-full into one shippable image | L | open (after G0) |
| G16 | WAN health probes (ICMP/DNS) with hysteresis | M | open |
| G17 | IPv6 (RS + DHCPv6-PD) on DHCP/static WAN, not only PPPoE | M | open |
| G24a/G18 | ADR 0049 D2 IPv6 source identity → IPv6 scan/behaviour/IOC detection | M/L | open |
| G13e | Deterministic incident reports | M | open |
| G20 | Signed WIFI.TXT (SSID, PSK, channel, guest) instead of build-time env | S | open |
| G22 | Shield per-client profiles, pause, list refresh | M | open (after G14) |
| G24b | ADR 0050 D4 EL0 steps 1-4 (HTTP, DHCP/DNS, PPPoE/DHCP clients, Noise) | L each | open |
| G24c, G28 | crypto audit / libcrux ML-KEM; logout / session list / owner-key rotation | M / S | open |
| G19 | HTP/SASE tunnel over the Noise channel | L | open |
| docs | `heqk-remaining-gaps.md` cites the removed `[P-dnsblock]`; `GAP_REGISTER.md` stale (July) | S | open |

## Needs the board

G10 intra-BSS bridging / `ap_isolate`; Shield on a non-Relay client; `/api/flows` + drill-down on metal;
eth1 traffic; Wi-Fi TX-stall root cause; WPA3-SAE/PMF + guest SSID; LTE/USB WAN; native-IPv6 ISP (G17);
RPMB floor (G24d, operator decision, irreversible); P-256 dudect run; WPA2 authenticator → EL0; G12 final
acceptance (persistence across power cycle, OTA tryboot); re-flash validation of every AP-side fix.

## Legacy lessons carried into every fix

V1 "lateral on one SYN" was an FP factory · V1 `pps` was per-60 s · never ship a model with random weights ·
rule-ID collisions → `rulecat.rs` is the single catalogue · HYDRA never deleted expired IOCs · V1 NAC took
unvalidated MACs into SQL/OVS · Guardian write routes had no CSRF and a shell `/execute` · dnsXai's Bloom fast
path broke subdomain matching · V1 HTP VPN fell back to an all-zero Kyber key — never fall back silently.
