# Moving the CYW43455 driver's control plane to EL0 (SEC-01 follow-up, ADR 0050 D4 step 5 remainder)

**Status:** design for operator review. Nothing here is built. ADR 0050 is not changed by this document; if the
operator accepts a plan below, the ADR's D4 step 5 status line is updated in a separate PR.

## Where SEC-01 stands

ADR 0050 D4 step 5 says the WPA authenticator "moves with the driver". Steps 5a–5c moved every walk over a
station's frames into `el0-lansvc`. Metal proof: `sae_frames_el0 = 8`, `in_kernel_messages = 0`
(`docs/design/metal-evidence/20261114-evening.md` §2).

These parts are still in EL1:

| Part | Where | What it holds |
|---|---|---|
| SDHCI host + SDIO bus (CMD52/CMD53, F1 backplane, F2 frames) | `arch-aarch64/src/cyw43.rs` | MMIO at `0x10_0110_0000`; **polled PIO, no host DMA, no IRQ line** |
| SDPCM framing, credit / flow control, BCDC ioctl / iovar | same | sequence numbers, credit window |
| Firmware download, NVRAM, CLM, regdomain | same | the Infineon blob (read-only input) |
| Event decoding (`apparse::parse_ap_event`) | `apparse.rs` (already fuzzed) | fixed-offset reads |
| 4-way handshake state machine, M1 / M3 building, replay counters | `cyw43::ap_authenticate` | PMK, PTK, GTK, IGTK, ANonce |
| SAE engine (PWE / PT, rand / mask, K / KCK / PMK, confirm) | `cyw43::ap_sae_rx` + `sae` crate | passphrase-derived secrets |
| `WLC_SET_KEY` installs | `cyw43::wlc_set_key` | PTK / GTK into the firmware |
| Self-heal, DFS watch, ACS | `wifiheal`, `hal::DfsWatch`, `cyw43::wifi_scan` | state only |

The driver is 6,438 lines with 227 `unsafe` sites. Most of them are MMIO accessors.

## What the move buys, and what it does not

- **It buys:** a memory-safety bug in the bus, SDPCM or BCDC code no longer runs with kernel privileges. The
  input is the firmware's output, so the realistic attacker is a compromised or buggy CYW43455 firmware. REL-08
  (the PMKID use-after-free) shows the firmware itself can misbehave.
- **It does not remove the firmware from the trust picture.** The radio can still corrupt any frame it delivers.
  The kernel's parsers already treat those frames as hostile.
- **Over-the-air attackers already hit EL0 first.** Every walk over a station's frame (EAPOL, RSNE, SAE, DHCP,
  DNS) is in `el0-lansvc` today. What remains in EL1 for them is fixed-offset header reads.

So the gain from moving the bus code is containment of a misbehaving firmware, not of an over-the-air
attacker. That shapes the order below.

## Findings that constrain the design

1. **The 4-way handshake is blocking.** `ap_authenticate` runs M1 → wait for M2 → M3 → wait for M4 inside one
   call from the AP loop (`main.rs`, the keying arm). It reads SDPCM frames itself, with up to 3 sends ~3 s apart
   per message. While a station keys, the loop does not forward, answer DNS or pet the watchdog from the main path.
   - This must become an event-driven state machine **before** it can move anywhere. In EL0 the synchronous-
     excursion model (no scheduler; cm5 prod runs IRQs-off) cannot block for seconds.
   - It is worth doing in EL1 on its own: one slow station would no longer stall every other client.
   - **To measure first:** `[WDOG] worst_loop_gap_ms` across a keying with a retransmit (bench: the Pi joins
     while the CM5 drops its first M2).
2. **No DMA, no interrupt.** An EL0 bus driver needs one 4 KiB device mapping (SDHCI) and nothing else. No IOMMU
   programming is needed, and no IRQ routing. This is the cheapest possible case for a user-mode driver.
3. **The hot path crosses the driver per frame.** `ap_tx` and `ap_poll` run for every forwarded frame. Today an
   EL0 call is one synchronous excursion: `enter_user`, the server runs, `SYS_DRIVER_REPORT` back. The
   throughput floor is the 2026-11-07 baseline, 80–160 Mbps; parity measured since is 120–160 Mbps.
   - At ~12,000 frames/s per direction, even 5 µs per excursion is 6–12 % of a core.
   - **To measure first:** the excursion cost on metal (`el0_messages` against a cycle counter around
     `lansvc::call`). This document assumes nothing about it.
4. **The keys.** The operator's 2A decision (2026-11-11) lets the PMK enter EL0 through one call
   (`CMD_STA_M2`), wiped after use.
   - Moving the state machine or the SAE engine to EL0 widens that capability: the GTK / IGTK and the SAE
     secrets would also live there, across calls.
   - The device identity key and Noise stay in EL1 (operator 2026-11-11). They are unaffected.

## Options

### A. Whole driver to EL0 (bus + SDPCM + control)

- The kernel maps the SDHCI page into a new `el0-wifi` server and exchanges frames through shared rings, one
  excursion per loop iteration (batching RX and TX).
- **For:** the largest TCB cut (≈6 k lines, most of the `unsafe`).
- **Against:**
  - The hot path depends on the excursion cost (finding 3).
  - Firmware download and self-heal (reload, bus wake, trap dump) would need to run in EL0 too.
  - The crash-record path (`fw_trap_dump`, written before a reset) would cross the boundary.
  - The server would own the device for the whole boot. `el0-tlshost` already keeps session state across calls,
    but it owns no hardware; `el0-lansvc` keeps no state between commands (ADR 0050 placement note).

### B. Control plane to EL0, bus stays in EL1 (recommended as the next step)

- **Stays in EL1:** SDHCI, SDPCM framing and credit, `ap_tx` / `ap_poll`, and the firmware download. These are
  the hot path and the reset path.
- **Moves to a new stateful EL0 server, `el0-wpa`:**
  - the authenticator state machine, made event-driven per finding 1;
  - M1 / M3 building and the replay counters;
  - the SAE engine;
  - the PMKSA cache.
- **The kernel:**
  - hands the server each EAPOL / SAE event record;
  - sends the frames it returns;
  - performs the `WLC_SET_KEY` install the server requests. The request carries a key handle, not the key.
    The key bytes go from the server's IO page straight into the ioctl buffer, then both are wiped.
- **For:**
  - Per-frame cost is unchanged; only management frames (a handful per join) cross.
  - It finishes ADR 0050 D4 step 5 as written ("the key state machine … stay[s] with the driver"). The driver's
    *keying* is what moves.
- **Against:** it widens 2A. GTK / IGTK and the SAE secrets would live in EL0 between calls.
  - **Mitigation:** a dedicated server holding nothing else, not the shared `el0-lansvc`. Plus the same wipe
    discipline, `[P-lansvc]`-style "IO page holds no key after the call" checks, and no logging of keys.
- **Needs an operator decision:** this is a new key-handling capability, beyond 2A.

### C. Keep the driver in EL1, harden in place

- Event-driven 4-way (finding 1) and fuzzing the SDPCM / BCDC / event decoders with firmware-shaped input. The
  event decoder is already fuzzed; SDPCM header and credit handling are not.
- **For:** no new key capability, no hot-path risk.
- **Against:** SEC-01 step 5 stays "not moved, by decision", like D4 step 4 (Noise).

## Recommendation

1. **Now, in EL1 (no decision needed):**
   - make the 4-way event-driven;
   - add a libFuzzer target for the SDPCM header / credit / BCDC response parsers, with firmware-shaped input.
2. **Measure:**
   - the excursion cost on metal (finding 3);
   - the loop gap during keying (finding 1).
3. **Operator decision:** B (widen 2A for a dedicated `el0-wpa` server) or C (close step 5 as "not moved, by
   decision"). A is not recommended until the excursion cost is known. Even then, its gain over B is containing
   the firmware, which REL-08 shows is real but rare.

## Tests each step must pass

- The ADR 0050 D4 rule: AP throughput ≥ the 2026-11-07 baseline, the separation matrix, `mc-e2e`.
- `cm5-wpa3-check` and `cm5-lan-client` green: WPA3 transition, SAE and WPA2-only stations keyed and authorized.
- No REL-08b regression on an SAE soak.
- For B: an `[P-wpa-el0]` row showing that the IO page holds no PMK / PTK / GTK after each call, and that a
  server fault forgets only that station's handshake. The station retries; the AP's security mode never changes.
