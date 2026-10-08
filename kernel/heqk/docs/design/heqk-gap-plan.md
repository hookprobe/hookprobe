# heqk gap plan — the live remaining-gaps ledger

> **Status: reconstructed 2026-09-11.** This is the *current, ranked* ledger of what is
> still open on heqk (Track C). The historical, per-ID audit register (CORE/SEC/DRV/
> DSN/XC/DET, with the surgical/medium closing rounds) is `GAP_REGISTER.md`; the
> remediation sequencing is `HEQK_REMEDIATION_PLAN.md`; production-readiness gates
> are `PRODUCTION_READINESS.md`; the metal-proof evidence lives in
> `~/heqk-metal-logs/`. Cited by `LIFECYCLE.md` (§"Beyond P7") before it existed.
> Update this table when a gap closes; the commit history is the audit trail.

## Method (the standing directive)

Close each gap step-by-step: **build → QEMU-validate (`validate.sh`) → flash slot A
only (slot B = the known-good brick net) → metal-validate attended over serial → update
this ledger + memory + evidence.** Never fake a metal result; anything the board
can't prove is marked *metal-deferred*, not closed.

## Closed milestones (do not re-verify — all metal-proven)

| Milestone | Proof |
|-----------|-------|
| M1 CI/CD + hybrid signing (Ed25519 + SLH-DSA), A/B tryboot | `build-heqk.yml`, `[HBoot-AB]`, metal boots |
| M2 Gate-R 33-row separation matrix — CONDITIONAL-GO (§6) | `heqk-detection-parity.md`; 31/31 heqk-owned rows metal-proven |
| M3 persistence — sealed store, crash-safe fslog, A/B OTA; real eMMC write survives power-cycle | `heqk-persistence.md` |
| M4 control plane — PQ-hybrid Noise, enrollment, secure-edge envelope, segmentation authority (armed on metal 2026-09-09) | `heqk-control-plane.md` |
| M5 module runtime — real wasmi + WASI-p1 in isolated EL0 hosts, detection at parity on metal | `heqk-module-runtime.md` |
| SEC-2 / V3 OTP carve-out — EL1 cannot read OTP; SRK HW-derived at EL2 | metal 2026-09-10 |
| CORE-1/CORE-2 capability keystones on the CM5 MMU backend | `[P-cm5-cap]`, `[P-cm5-cspace-iso]` metal |
| WiFi **STA** (P10) — scan→assoc→host 4-way→PTK+GTK→DHCP→NAT→internet→DNS→TCP, on the production AP | metal 2026-09-10 |
| WiFi **AP** (P11) — heqk as WPA2 authenticator+AP: 4-way, DHCP lease, reconnect-reliable persistent loop | metal 2026-09-10/11 |
| Both wired NICs (RP1 GEM `end0`, RTL8111 `eth1`) up at 1000M, link LEDs correct | metal 2026-09-10 |

## Open gaps — ranked

| # | Gap | Track | Type | Status / next action |
|---|-----|-------|------|----------------------|
| 1 | **M-AP-NAT** — route/NAT WiFi-AP + eth1-LAN clients → internet via the **end0 (GEM) WAN** uplink (operator topology 2026-09-11: end0 = WAN always, eth1 = LAN) | WiFi AP | metal | M-NAT0 (`uplink.rs`, GEM) + **M-NAT1 SNAT engine (`nat.rs`, `fc18f43`) BUILT**; blocked on metal by a GEM `tx_frame` timeout on the first frame after P8 (P8's own diag frames pass; prod re-inits the ring — mirrored in `0dd2424`, TSR captured if it recurs). Phone ↔ internet unproven. Then M-NAT2/3 (eth1 LAN DHCP server + forwarding), M-NAT4 block-mode SDIO (UDP > ~480 B dropped today) |
| 4b | **A9 arming conditions** A9-1..A9-9 (`heqk-detection-parity.md` §5) — must land before C-2 arms any Access-port RA drop | Security | no-metal (QEMU) | A9-3 flood arm + A9-5 attribution + A9-7 evasion visibility BUILT, `[P8-raflood]` GREEN (2026-09-11); open: tri-state remap, IPv6 mgmt floor, A9-1/2/4/9 (with C-2) |
| 2 | AP **bring-up intermittent** / "incorrect password on some boots" | WiFi AP | metal | **ROOT-CAUSED + FIXED + metal-proven 2026-09-11**: `ap_start`'s live `cur_etheraddr` GET returned zero after the scan had established the OTP MAC → `bssid 00:00:…` → zero-sourced M1 → no M2. Now the AP MAC is the scan's established MAC (fail-closed LAA), SETs recorded, `WLC_GET_BSSID` verified (`verified=true` on metal), `serve_ready()` gates the loop. Authenticator rewritten bounded/replay-correct/event-aware (first-try join `m1_sends=1 … m4_mic=true`); one event-driven pump serves ARP/DHCP forever; **reconnect 3/3 operator-confirmed on `ca5df30b`** (after my own peek-stall regression on `aeec0677`: fixed by drain-until-dry + a 250 ms liveness read) |
| 3 | AP: concurrent multi-station event loop; GTK-broadcast TX path; multi-client DHCP pool | WiFi AP | metal | follow-ups (unicast sidesteps GTK for now) |
| 4 | **Gate-R sign-off leftovers** — A9 posture ruling RECORDED (§5 CONDITIONAL-GO, 2026-09-11); one unified adversarial metal pass emitting a single `GATE-R: PASS` (`tools/gate-r-run.py` is the parser); a REAL Access-port manifest role (C-2, needs the second datapath) | Security | governance + metal | → unlocks **U2** (retire the Linux dataplane) via a U2a/U2b split-ADR |
| 5 | eMMC: dedicated DataVolume partition; firmware tryboot flip + PM-watchdog on metal; InactiveSlot write arming | Persistence | factory + metal | see `heqk-persistence.md` §4 |
| 6 | Wire the prod excursion driver onto per-TCB CSpaces (bare `enter_user` today) | Caps | design | distinct design, deferred |
| 7 | M4 bridge: ICMP/DHCP/enroll/Noise over the GEM wired datapath on the wire (host MSSP-sim) | Bridge | metal | Gate R |
| 8 | DET-2 dynamic signed-rule load (RState table + storage/HYDRA transport) | Detection | no-metal (QEMU) | `[P8-det2]` gate exists; wiring is the follow-on |
| 9 | RP1 GEM RX-IRQ / MSI-X emission (RP1-internal; polled RX works, drop=0) | Driver | hardware | characterized; not an M2 gate |
| 10 | Production signing-key custody (HSM / ceremony / KMS) + co-rooting; SVN-floor fuse burn | Governance | operator decision | `heqk-signing-identity.md` — never autonomous |

## M-AP-NAT — the current build (scoped 2026-09-11)

Route + masquerade the WiFi-AP subnet to `eth1`. Reuses every packet helper
(`build_dhcp`/`parse_dhcp_reply`/`build_arp`/`inet_csum`/`fill_eth_ip`) and the proven
WiFi unicast-TX (PTK) path. New: eth1 DHCP client + gateway ARP over `rtl8111::tx_frame`
/`poll_rx`; a bounded no-alloc NAT table (ICMP id / UDP / TCP ports); one dual-interface
poll loop. **Two make-or-break facts:** RTL8111 `tx_frame` has never transmitted on
metal (M-NAT0 exists to prove it first), and WiFi SDIO transfers are hard-capped at
512 B (`cmd53_read`/`cmd53_write`), so full-MTU frames can't cross → v1 needs a TCP
MSS clamp (+ DHCP option-26 MTU); block-mode SDIO is a later throughput milestone.
Stages: M-NAT0 eth1 IP+gw-ARP → M-NAT1 one-way ICMP SNAT → M-NAT2 reverse path (phone
pings 8.8.8.8) → M-NAT3 UDP+TCP + MSS clamp (phone loads a web page) → M-NAT4
block-mode SDIO.

## Recurring lessons (bank these)

- **"Slow, not stuck"**: every apparent hang in the WiFi bring-up was a bounded loop of
  dry `read_sdpcm_frame` polls (~1.5 s each). Bound the loop, wait the worst-case
  budget, *then* diagnose.
- A client's generic "incorrect password" is a **post-handshake data failure** when
  the MIC checks passed — look at the data path (port authorize, chanspec, GTK vs PTK
  encryption of replies), not the PSK.
- A stale `cat /dev/ttyUSB2` surviving a task stop garbles the serial capture — check
  `pgrep -af "cat /dev/ttyUSB2"` before trusting a log.
- Schematic LED-pin notes were wrong for BOTH NICs; the register read-back + the
  operator's eyes were the truth.
