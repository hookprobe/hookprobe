# heqk product-completion plan — gaps by user experience, with the CI that closes them (2026-10-09)

> Owner: this plan ranks what is left for heqk to be a **plug-and-play edge product** the way a
> customer experiences it — *accessibility* (can I get on and get help), *function* (does it do
> the job: connect, protect, show me), *form* (does it feel finished: no power-cycles, honest
> status, nothing flaky). Every gap carries the CI gate that proves it WITHOUT a flash, and the
> metal check that proves it WITH one. Flashes are batched: build everything QEMU/host can prove,
> flash once, read the serial evidence, repeat. Canon: ADR 0047 (heqk everywhere, Mission Control
> served on-device), `docs/design/e2e-gap-audit-2026-10-08.md` (Stages 1–4),
> `kernel/heqk/docs/design/heqk-gap-plan.md` (kernel ledger).

## 1. Where the product stands on metal (2026-10-09, apmode image on HEAD)

| Capability | Metal state | Evidence |
|---|---|---|
| Boot, attestation, A/B, sealed store, signed rules, inline IPS self-test | PASS every boot | `[P7*]`, `[P8] PASS — inline IPS`, `[P15-*]` |
| Wi-Fi AP: beacon, WPA2 4-way (host authenticator), DHCP, reconnect | PASS — 2 joins first try, reconnect 3/3 | `[P11-AP3 auth] m1_sends=1 … m4_mic=true`, `[P11-AP3] PASS — client leased` |
| WAN (end0) lease from the upstream router | PASS — `10.200.0.14/28`, two-sided (dnsmasq lease + neighbour REACHABLE) | `[M-NAT0] PASS(uplink)` |
| NAT / masquerade of a phone's traffic | PASS on the wire — `10.200.0.14:4000x → 8.8.8.8:53` captured on the upstream port | tcpdump `enp4s0` |
| Internet from the phone | **BLOCKED upstream**: the fortress NAC quarantines the unknown MAC (DHCP + DNS-to-gateway only) | `fts-nac: Applied QUARANTINE policy for 02:00:00:00:00:02` |
| Plug-and-play (cable after boot) | **Built, unflashed** (`9a76405`): lease retried on link-up, no power-cycle | next flash |
| IDS/IPS on AP traffic, (MAC,IP) binding, eth1 LAN, lease renewal | **Built, unflashed** (`68ab65c`) | next flash |
| Mission Control served by heqk (ADR 0047) | QEMU/browser-proven by the peer session (`bd3c838`), not yet on CM5 | `tools/mc-e2e.sh` |

## 2. The gaps, ranked by what a user feels first

Legend — **A** accessibility (can the user get on / get help), **F** function, **Fo** form/polish.
CI column = what proves it before a flash. Metal column = the one check after.

| # | Gap (user-visible symptom) | Lens | Fix | CI gate (no flash) | Metal check |
|---|---|---|---|---|---|
| 1 | "I'm connected but there's no internet" (upstream NAC/firewall quarantines heqk) | A/F | **Onboarding story**: heqk announces itself honestly (DHCP hostname/vendor-class `heqk`, mDNS name) so the upstream admin can admit it; on the fortress, an `internet_only` policy for the heqk MAC. Product-side: the status page must SAY "upstream blocks us" (ICMP/DNS probe failed after lease) instead of silence | host test: DHCP option 12/60 present in the DISCOVER builder; QEMU `[P18-netcfg]` row | `fortress-ctl device set-policy <mac> internet_only` → phone loads a page; `[M-NAT1] PASS` |
| 2 | "I had to power-cycle after plugging the cable" | Fo | DONE in `9a76405` (10 s link-up retry); extend to Wi-Fi radio re-init and eth1 link flaps | QEMU: a `[P-uplink-retry]` phase driving `bringup` through a fake link-down→up on virtio-net | plug cable after boot → `[M-NAT0] WAN came up after boot` |
| 3 | "The AP sometimes doesn't accept my password" | A | DONE (zero-BSSID root cause, replay-correct 4-way, pump drain) — **keep it proven**: add the handshake as a host KAT (hostapd-recorded M1–M4 vectors) so no refactor can regress it silently | `tools/wifi-crypto-kat.rs` grows an EAPOL-frame KAT (MIC over recorded M2/M4) | 5 joins + 5 reconnects, zero `4-way incomplete` |
| 4 | "Video/QUIC apps stall" (UDP > ~480 B dropped on the Wi-Fi leg) | F | **M-NAT4 block-mode SDIO**: multi-block CMD53 on F2 (block size 512 already set; F1 multi-block pattern exists) → full-MTU Wi-Fi frames; until then advertise DHCP option 26 MTU 482 and strip EDNS0 size so DNS falls back to TCP | host unit: SDPCM frame assembly for 1514 B across 3 blocks; QEMU can't run SDIO — mark metal-only | iPhone speed test; `in_too_big=0` in the heartbeat |
| 5 | "I can't see what the box is doing" | A | Mission Control on-device (ADR 0047): serve the status page from heqk on 10.99.0.1 (AP) and the WAN lease; first screen = *connectivity + protection + evidence*; WCAG: text alternatives for every state icon, keyboard-only navigation, 4.5:1 contrast, no colour-only status | `tools/mc-e2e.sh` (browser e2e) + an axe-core pass in CI on the served HTML | open `http://10.99.0.1` from the phone |
| 6 | "Is it protecting me?" | F | IDS/IPS on both NAT legs DONE in `68ab65c` (`packet::verdict`); next: give the Wi-Fi leg an **Access** port role ONLY after the A9 embargo conditions (manifest-declared role, authority-gated writer) — never a silent default | QEMU `[P8-raflood]`, `[P8-l2struct]`; new `[P-nat-ids]` phase: a rule-1 (port 4444) frame on the inside leg is DROPped before NAT, a legit frame is forwarded | heartbeat `ids_drop out>0` after `nc 10.0.0.1 4444` from the phone, `bind_drop=0` for legit clients |
| 7 | "My second phone gets the first phone's address" | F | DONE in `68ab65c` (MAC-bound 16-lease pool, NAK on foreign REQUEST) | host unit on `ApDhcp::alloc_for/binding_ok` (two MACs → two IPs, same MAC → same IP, pool exhaustion silent) | two phones, two leases, both browse |
| 8 | "The LAN port does nothing" | F | DONE in `68ab65c` (eth1 DHCP/ARP + NAT, `rtl8111::tx_frame` first exercise) | — (RTL has no QEMU model) | laptop on eth1 → `[M-NAT2] … PROVEN`, browses |
| 9 | "It got hot" | Fo | DONE (event stream + `wfe` on the AP path) — add a **thermal readout** to the status page (SoC temp via the mailbox proxy tag, if whitelisted) | — | hand test + status page |
| 10 | "It just hangs" (no watchdog after boot-commit) | Fo | DONE: exception → `hvc #0` reset. Add a *liveness* watchdog: the AP pump re-arms the PM watchdog via an EL2 tag every heartbeat (hboot owns the PM block) | QEMU: a phase proving the heartbeat path calls the re-arm | yank the SDIO firmware (simulated hang) → reset within 16 s |
| 11 | "Did the update work?" (A/B on-device, OTA trial on metal) | Fo | the firmware tryboot flip + PM-watchdog trial on metal (`[P15-ota]` is QEMU-only) | `[P15-ota]`, `[P15-otafat]` (already green) | one slot-B trial boot, fallback proven |
| 12 | "Set it up without a laptop" | A | captive onboarding: first boot = open setup SSID → status page asks for the AP name/PSK + upstream admission hint → stores sealed (`[P15-sealfs]`) → reboots into the configured AP. Replaces the build-time `HEQK_AP_PSK` | host test on the sealed-config record round-trip; QEMU phase for the config state machine | phone-only first boot |
| 13 | IPv6 on the AP side (phones prefer v6; today silently dropped) | F | observe-only RA/ND passthrough is NOT enough: either run NDP proxy + NAT66-free v6 (prefix from upstream DHCPv6-PD/RA) or honestly advertise v4-only (no RA) so phones don't wait | host unit on the v6 parse (`net.rs`) | phone shows no v6 stall |
| 14 | Fleet: evidence leaves the device (M6 export, `prod-export`) | F | the peer's Stage 2 — metal-run pending (`responder-sim --live --dev-pk`) | `[P-m6-export]`, `[P19-controlplane]` (green) | `[M6-EXPORT] ENROLLED`, sim shows frames |

## 3. The CI that makes every flash count

Principle: **a flash only tests what QEMU/host cannot.** Everything else must be a gate.

1. **`validate.sh` (QEMU, every commit)** — the 93-phase ladder; new phases per gap above:
   `[P-uplink-retry]`, `[P-nat-ids]`, `[P-ap-config]` (gap 12), `[P-watchdog-beat]` (gap 10).
2. **Host harnesses (every commit, seconds):** `tools/wifi-crypto-kat.rs` (+ EAPOL KAT, gap 3),
   `tools/verifier-harness.rs`, unit tests for `ApDhcp` (gap 7), `nat.rs` (checksum/MSS/TTL
   vectors from a recorded pcap), `net.rs` v6 parse (gap 13).
3. **Docs gate** (`validate.sh` Stage-1d): every cited `docs/design/heqk-*.md` exists.
4. **Browser e2e** (`tools/mc-e2e.sh`) + **accessibility** (axe-core on the served pages; fail on
   any *serious* finding) — gap 5.
5. **Build matrix** (`build-heqk.yml`): `prod`, `prod-export`, `apmode` (+`HEQK_AP_PSK`),
   `stajoin`; `prod`+`apmode` must fail to compile (it does).
6. **Metal matrix (per flash, attended):** a single serial-log parser (`tools/gate-r-run.py`
   grown to cover `[M-NAT0/1/2]`, `[P11-AP*]`, `[M6-EXPORT]`) emits one `METAL: PASS/FAIL` table
   per boot — so a flash yields a *record*, not a scroll of lines.

## 4. Flash batching — what goes into the next images

- **Next flash (ready now, `4266ff44`):** plug-and-play WAN retry, upstream DNS, IDS/IPS on NAT
  legs, lease pool + binding, eth1 LAN, lease renewal. Needs the fortress admission (gap 1) to
  show internet; everything else is observable in the heartbeat without it.
- **Flash +1:** onboarding identity (gap 1 product side), liveness watchdog (10), DHCP option 26 +
  EDNS0 clamp (4-interim), v4-only honesty (13-interim), status page served on 10.99.0.1 (5).
- **Flash +2:** block-mode SDIO (4), captive setup (12), OTA trial on metal (11), M6 export live (14).

## 5. Definition of done (product)

A customer plugs the box into their router, joins the Wi-Fi printed on the box, and (a) is online
within 30 s with no power-cycle, (b) sees the status page on their phone saying what is protected
and whether the upstream admitted the device, (c) a port-4444 probe from their phone is dropped
and shows up as evidence, (d) the box survives a cable yank, a Wi-Fi reconnect, and an hour of
video without a reboot, (e) updates land through A/B with rollback, (f) nothing in the flow
required a laptop, a serial cable, or a build-time secret.
