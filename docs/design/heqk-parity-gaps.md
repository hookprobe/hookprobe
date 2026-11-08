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
| G2 | DHCP server: leases never expire/reclaim (17th distinct MAC refused until reboot), 16-lease pool, `clients` = cumulative, no options 15/119 | S/M | **closed** `fb417999` [P-dhcpd] |
| G1 | `/api/devices` empty on the AP image (`note_host` never called there); leases hold MAC↔IP but no hostname/fingerprint (opt 12/55/60/61), no OUI | S/M | **closed** `fb417999` (+ policy/label `4b23f618`) |
| G4 | Beacon detector fed every TCP packet both ways, no refire cooldown → keep-alive FPs + alert storm evicting the 256-row ring; 16-entry tables | S | **closed** `fb417999` (SYN-only + refire cooldown) |
| G3 | Exfil detector not wired (only the selftest calls it); NAT already counts bytes per flow | S | **closed** `fb417999` |
| G11 | AP image has no wall clock (`set_clock(0)` + `disable_sntp`) → every AP timestamp is boot-relative | S | **closed** `fb417999` [P-wanntp] |
| G13 | Investigate calls `/api/reports`, `/api/evidence/graph`, `/api/evidence/stats` → 404 on heqk; `/api/engines` always `[]`; no `/api/manifest`, `/api/verdicts/dns`; SampleDataNotice marks Investigate fully live | S each | open |
| G5 | QSECBIT only scores wire-DROPPED detections → observe-only threats (beacon, lateral, IOC, ARP spoof) leave it GREEN | M | **closed** `fb417999` (severity scoring + 5-min decay) |
| G0 | Extract the AP loop into a pure `apcore` (NIC trait) + QEMU harness | L | open |
| G7 | Threat intel = 4 hard-coded CIDRs; need a signed IOC pack (CIDR v4/v6, domains), LPM, per-entry expiry | M | **closed** `4b23f618` [P-ioc] |
| G8 | No DGA/lookalike scoring on Shield queries (detect-only; score the registrable label — V1's `parts[0]` bug) | S/M | **closed** `fb417999` [P-dga] |
| G9 | Local NAC: signed DEVICES.TXT (MAC → full/internet_only/lan_only/quarantine) arming `segment` without enrollment | M | **closed** `4b23f618` [P-devpolicy] |
| G23 | Read-only `/api/enforcement` (rate-limited / quarantined sources + time left) | S | **closed** `fb417999` (/api/enforcement) |
| G6 | Signed dynamic rule pack (RULES.BIN via the DET-2 gate) + NAPSE rule port; `MAX_RULES` 16 → 256 | M/L | **closed** (batch 5) [P-rulepack] — signed RULES.BIN + tools/rulepack.py + NAPSE-derived starter pack; heap-safe loader |
| G14 | Operator write APIs (logout, incident ack, quarantine/release, Shield allow/pause) + Origin check + audit ring | M | **decision** — ADR 0053 proposed (option C recommended) |
| G15 | Local SIEM export (RFC 5424 syslog / OCSF JSON) — beats both legacy tiers | M | **closed** (batch 4) [P-siem] |
| G12 | Converge AP + prod-full into one shippable image | L | **decision** — the AP is a bench-only mode by rule (ADR 0023/0045); G20 removed the credential blocker; making the AP a shipping mode needs an ADR |
| G16 | WAN health probes (ICMP/DNS) with hysteresis | M | **closed** (batch 4) [P-wanhealth] |
| G17 | IPv6 (RS + DHCPv6-PD) on DHCP/static WAN, not only PPPoE | M | open |
| G24a/G18 | ADR 0049 D2 IPv6 source identity → IPv6 scan/behaviour/IOC detection | M/L | open |
| G13e | Deterministic incident reports | M | **closed** `fb417999` (deterministic reports) |
| G20 | Signed WIFI.TXT (SSID, PSK, channel, guest) instead of build-time env | S | **closed** (batch 4) [P-wificfg] — AP builds without a build-time PSK |
| G22 | Shield per-client profiles, pause, list refresh | M | open (after G14) |
| G24b | ADR 0050 D4 EL0 steps 1-4 (HTTP, DHCP/DNS, PPPoE/DHCP clients, Noise) | L each | open |
| G24c, G28 | crypto audit / libcrux ML-KEM; logout / session list / owner-key rotation | M / S | G28 logout **closed** (batch 5); key rotation needs G14; G24c **decision** |
| G19 | HTP/SASE tunnel over the Noise channel | L | open |
| docs | `heqk-remaining-gaps.md` cites the removed `[P-dnsblock]`; `GAP_REGISTER.md` stale (July) | S | **closed** (batch 4) |

## Needs the board

G10 intra-BSS bridging (`ap_isolate`=1 now set at AP start, batch 5 — the board shows whether the firmware honours it); Shield on a non-Relay client; `/api/flows` + drill-down on metal;
eth1 traffic; Wi-Fi TX-stall root cause; WPA3-SAE/PMF + guest SSID; LTE/USB WAN; native-IPv6 ISP (G17);
RPMB floor (G24d, operator decision, irreversible); P-256 dudect run; WPA2 authenticator → EL0; G12 final
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
