# heqk / HookProbe OS — aligned status, 2026-11-05

> One page that reconciles everything proven, built and decided since the 2026-10-09 product
> plan (`heqk-ux-ci-gap-plan-2026-10-09.md`). Every row cites the commit or the metal evidence.
> This is the source the shared status artifact is rendered from; update here first.
> Canon: ADR 0047 (heqk everywhere, Mission Control on-device), ADR 0023, ADR 0014, ADR 0038.

## 1. Milestones reached (metal-proven unless marked)

| Date | Milestone | Evidence |
|---|---|---|
| 2026-11-04 | 🏁 **Zero-Linux factory image passes full acceptance on CM5** (`prod-mc`): Mission Control served by heqk, attack → IPS drop → detection → shown in a real browser | `tools/mc-e2e-metal.sh` MC-METAL: PASS, img `e690e4d`; `~/heqk-metal-logs/20261104-192412-prod-mc-metal-acceptance.txt` |
| 2026-11-04 | **A/B commit on metal**: content-pinned a↔b flip survives two power cycles; boot-config writes admitted one-shot by the driver | `c748cf0`, `[P15-abcommit]`, `20261104-abcommit-metal-PASS-c748cf0.log` |
| 2026-11-04 | **iPhone browses through heqk Wi-Fi AP + NAT** — root cause of "connected, no internet" was half-read SDPCM frames; fixed by porting brcmfmac `rxfail` | `4a57a46`, 7–8 Mbps |
| 2026-11-04 | **Large-frame SDIO solved from a Linux v8 mmc trace on this CM5** (blocks + byte tail; fixed-address F2 reads) — YouTube/Facebook on the iPhone | `57ff6d1`, ~11 Mbps, `big_tx 1773/0` |
| 2026-11-04 | **Firmware RX superframes** (port of `brcmf_sdio_rxglom`) — 0 drops | `4a1a996`, 22 Mbps steady, `[P11-glom]` |
| 2026-11-04 | **IDS/IPS proven on the AP path**: iPhone SYNs to :4444 dropped by rule 1, zero on the wire | `779121d`, 43 drops |
| 2026-11-05 | **Real VHT80 + SDIO High-Speed**: chanspec as a 4-byte int (the AP had never been 80 MHz), SDCLK 50 MHz verified, regdomain-checked ACS preferring 5 GHz | `eacc4cc`, `89138e5`, ~45 Mbps |
| 2026-11-05 | **WAN modes**: operator-selectable via `WAN.TXT` — DHCP / static / **PPPoE client** (RFC 2516 + LCP/PAP/CHAP-MD5/IPCP, keepalive, re-dial) on the ISP line | `395ccd0`, `26e6ac5`, `7de8ccc` |
| 2026-11-05 | **DNS on the AP address, forwarded upstream**; 128-deep delivery queue; firmware flow-control (XOFF) honoured; GEM TX ring re-sync after timeout | `2146169`, `2e8bc7a`, `cdc5394` |
| 2026-11-05 | **Firmware TX-stall mitigation** found by elimination (bus clock, glom, tlv ruled out): one control frame restarts it in ~5 ms → 2 reserved control credits + 100 ms kick, 62/62 in a heavy session | `825b073`, `6ed4833`, `1c1594c` |
| 2026-11-05 | 🏁 **120–160 Mbps through heqk AP + NAT = Linux parity**, on ISP PPPoE. Speed cap root-caused by a per-beat profiler (loop ~80 % asleep in 1-ms dry-poll sleeps), not by guessing | `31e5466`, `f9982c6`, `54ea7b5` |
| 2026-11-05 | **BOI / HookProbe Behavioural Genome**: deep alignment + adversarial architecture review (7 questions, 60+ acceptance/failure criteria, 9 corrections) + the graduated-response ladder and root-cause UI contract — design only, no implementation | `39c2fbf`, `0ae5ac0`, `78c42de` |

Earlier (Sept–Oct) milestones remain as recorded: WPA2 AP with host authenticator and
reconnect-reliable pump, plug-and-play WAN, MAC-bound leases, M-NAT SNAT engine, Gate-R
CONDITIONAL-GO, M6 export plane, SRK-derived device identity, prod-mc on CM5, ADR 0047.

## 2. The 2026-10-09 gap list — where each one stands

| # | Gap (user symptom) | 10-09 state | 11-05 state |
|---|---|---|---|
| 1 | "Connected but no internet" (upstream NAC quarantine) | fix = onboarding story + operator admission | **still operator-admitted** (`fortress-ctl device set-policy <mac> …`); the SRK-derived MAC is new per image — the status page must say "upstream blocks us" (open) |
| 2 | Power-cycle after plugging the cable | DONE | DONE (WAN retry on link-up; now also PPPoE re-dial) |
| 3 | AP rejects the password sometimes | DONE | DONE + AP brought up exactly as Linux brcmfmac does on this chip (`9a47b83`) |
| 4 | Video/QUIC stalls (UDP > ~480 B) | **open** — M-NAT4 block-mode SDIO | **CLOSED** — Linux-traced block TX + fixed-address reads + glom; MSS 1460; Linux-parity throughput |
| 5 | "Can't see what the box is doing" | MC on-device, QEMU only | **CLOSED on metal** (`prod-mc` MC-METAL PASS; owner auth) — thermal/upstream-blocked widgets still open |
| 6 | "Is it protecting me?" | IDS on NAT legs built | **proven on metal** (rule 1 drops on the AP path); Access port role for Wi-Fi still gated by the A9 embargo conditions |
| 7 | Second phone gets the first one's address | DONE | DONE |
| 8 | LAN port (eth1) does nothing | built, unproven | **still unproven on metal** (no LAN client exercised) |
| 9 | "It got hot" | DONE | DONE; thermal readout on the status page open |
| 10 | "It just hangs" | reset on exception | DONE + firmware TX-stall kick; liveness watchdog re-arm still open |
| 11 | "Did the update work?" (A/B on metal) | open | **CLOSED** — A/B commit metal-proven (`c748cf0`); late-confirm stays opt-in (prod loop at +70 s vs the 15 s trial watchdog) |
| 12 | Set it up without a laptop | open | **in progress** — browser flasher (WebUSB rpiboot + owner-key patch) is the other session's next item; `WAN.TXT`/`OWNER.TXT` are the config seams |
| 13 | IPv6 on the AP side | open | open |
| 14 | Evidence leaves the device (M6 export live) | metal-run pending | **still pending** (`responder-sim --live --dev-pk`); receiver must bind `device_fp` to the authenticated static key first (review Q2-H1) |

## 3. Decided (design, no code)

- **BOI/HBG** = optional, isolated, observe-only behavioural intelligence; the genome is
  **on-device state, never on-device policy** (ADR 0014 boundary: θ signed logic vs S fold over
  the entity's own observations; empirical Bayes / adaptive thresholds / on-device calibration
  are training and forbidden).
- **Remote evidence is inert**: authority ≠ truth — operator-signed pattern for priors/thresholds
  /allowlists; channel-authenticated node evidence has no code path into local state; three trust
  levels (Authenticated / Validated / Corroborated).
- **Pattern-break ladder**: see it → step-up (credential anchor) → corroborated containment through
  the operator-signed reach plane (TTL, self-reverting) → automatic drop **only** when the break
  coincides with one of ADR 0023's four classes. "Pattern break ⇒ drop" is forbidden, not deferred
  (entity identity is attacker-assertable on any LAN without 802.1X).
- **Root-cause UI contract**: the explanation envelope gains `pattern` (the entity's established
  neighbourhood as a small graph), `break` (the deviating edge/context/sequence with its active-day
  history), `ladder_rung` — rendering evidence that exists, never a narrative; `model: null` until a
  signed model is in play.
- **Next ADR = 0048**; the product-steward cuts it from the alignment doc §7 + §3.8 and the review's
  criteria. Privacy/profiling stance, licensing boundary and the first real entity-identity design
  are decided there.

## 4. Open defects and risks (owned, not hidden)

| Item | Severity | Owner / state |
|---|---|---|
| `prod-mc` sealed snapshot **never restores across reboot** (sepdiag blob and snapshot both at LBA 2016; `boots=1` every boot in the 11-04 log) | HIGH | prod-mc session — logged, fix after the current metal run |
| `SealedStore::store` multi-sector write not crash-consistent (power loss destroys the *previous* state) | HIGH | same task; `[P15-abcommit]` pattern is the fix shape |
| sepdiag DataVolume self-test writes outside every partition on the factory layout | MED | same task |
| GEM ring overflow (`rsr=0x7`) invisible to `faults=0` — needs an `rx_overrun` counter on prod-mc (the AP-loop drain cause is fixed, `1c1594c`) | MED | same task |
| Firmware TX stall: trigger still unknown; the 100 ms control-frame kick is a mitigation, not a root cause | MED | AP session |
| `kernel/heqk/SECURITY.md:393-515` publishes stale GDPR / "no behavioral profiling" claims; ADR 0007 says Apache-2.0 vs AGPL | docs | to reconcile in/with ADR 0048 |
| `responder-sim` trusts the device's self-claimed `device_fp`; `src_mac_hash` is the raw first 4 MAC octets; evidence `dev:` ids are unkeyed FNV over raw IP | MED | before any multi-device receiver / BOI Phase 1 |
| Upstream NAC admission of heqk's WAN MAC remains a manual operator step | UX | gap 1 |
| Late boot-confirm stays opt-in: prod loop reached at +70 s vs hboot's 15 s trial watchdog | design | shorten boot or keep opt-in |

## 5. Method lessons banked (apply before the next change)

- **Stop guessing on SDIO/Wi-Fi**: state measured facts, read brcmfmac, or take a Linux trace on
  the same hardware (`tracefs mmc_request_start`, `cmd_opcode==53`); one pre-decided image per
  hypothesis. Every real fix this week came from a trace or a profiler, not a theory.
- **Build everything the host/QEMU can prove, flash once**; snapshot the image to a job-private
  path (the shared `cm5-boot/heqk8.img` was overwritten by a concurrent build once).
- **Read the serial log in order** before narrating a boot; `faults=0` is not "no loss".
- **An attacker may influence what heqk observes, never what heqk trusts** — the test every BOI
  decision was held to.

## 6. Next

1. Fix the prod-mc persistence defects (A3.3 criterion: `boots=N+1` across a real power cycle).
2. Browser flasher (laptop-free first boot) → gap 12.
3. M6 export live run with the receiver binding `device_fp` to the static key → gap 14.
4. eth1 LAN client on the bench → gap 8.
5. ADR 0048 (BOI/HBG) — then Phase 1 (observation contract), host/QEMU-gated only.
