# Pre-soak code review: long-runtime defects (2026-11-22)

**Scope:** `origin/main` `ed7a35aab`, the AP image's kernel (`os/kernel/kernel`, `hal`, `arch-aarch64`, EL0 servers'
long-lived state).
**Question:** what breaks only after hours or days of uptime, ahead of the REL-05 72 h soak?
**Method:** a read-only review, then each finding re-checked against the code (and smoltcp 0.13.1's source) before
it was accepted. Nothing was run on hardware for this review.
**Release profile note:** `overflow-checks` is off, so integer overflow wraps silently and never panics. Panics can
only come from indexing or `unwrap`.

## Findings

| # | Finding | Severity | Verified | Status |
|---|---|---|---|---|
| 1 | **Mission Control TCP slots never time out.** No MC socket sets `set_timeout` or `set_keep_alive`. smoltcp never gives up retransmitting without a timeout. An SSE stream whose peer vanishes stays ESTABLISHED (`may_send()` stays true), and a closed plain-HTTP slot stays in FIN-WAIT-1/2. A laptop sleeping with the dashboard open, or a phone leaving Wi-Fi, pins an HTTPS slot until reboot. After 8, HTTPS MC refuses everyone. | soak-blocker (MC availability) | yes: `mcserve.rs` has no timeout anywhere; smoltcp `timed_out()` needs `timeout`, and `reset()` keeps it | **fixed, metal-proven** (`metal-evidence/20261122-presoak-mc-deadpeer.md`: before, a 9th client is never served; after, from t = 66 s): `reap_dead_peers()` sets a 60 s silence timeout and 15 s keep-alive on every MC socket at creation. A dead peer is aborted in any state and its slot returns to Listen through the existing `!is_open()` path |
| 2 | **Evidence log silently drops every detection after the 20th per heartbeat.** `EvLog::push` ignored a push into a full batch. The AP loop ignored the "full" return, and the flush ran only on the 5 s heartbeat, so a burst (scan, flood, DGA) lost detections 21+ of every 5 s with no counter. | should-fix (evidence integrity) | yes: `evlog.rs` `push`, `main.rs` push site, and the heartbeat flush | **fixed**: a full batch is written at once (`flush_full`), at most every 250 ms (≤ 80 detections/s kept). Anything beyond is counted in `EvLog::dropped` and printed in the `[AP-EVLOG]` heartbeat line. `[P-evlog]` checks the count, the immediate write and the pacing |
| 3 | **Stations the firmware deauths itself may stay in the AP's station set.** `ap_poll` maps only `WLC_E_DEAUTH_IND` / `WLC_E_DISASSOC_IND` to Leave. The firmware's own `WLC_E_DEAUTH` / `WLC_E_DISASSOC` (enabled under `wpa3`) go only to the SAE watch. If the firmware ages out a station that way, the Leave cleanup never runs (StaSet, key abort, SAE forget, SAVI). Ghosts then defeat wifiheal's "nobody to deliver to" guard. | should-fix if the firmware does this | **plausible, not proven**: the code path is as described, but no bench log records whether CYW43455 AP-mode inactivity ageing emits `WLC_E_DEAUTH` | **open**: needs a metal check (a station leaves range with no deauth from it; log the AP's own deauth events). Not changed before the soak: remapping those events would take them away from the WPA3 SAE watch |
| 4 | 32-bit NAT forward counters (`NatStats.out_fwd/in_fwd`) wrap after about 40 h at 30 kpps | minor (display only) | yes | open (display-only; no logic depends on them) |
| 5 | Qsecbit risk reads 0 once the lifetime `telemetry::SCORE` saturates at `u32::MAX` | minor (needs about 4×10⁸ severity points) | yes | open |
| 6 | IOC expiry clock advances only on SNTP replies, and is set before `sync_clock` may refuse the step | minor | yes | open |

## eMMC writes over 72 h (bounded)

- **Evidence ring:**
  - Before: at most 1 sector per 5 s heartbeat, about 52k sectors (about 26 MB) worst case.
  - After fix 2: at most 4 sectors/s during a sustained flood. The ring is 4,096 slots and wraps under sustained
    load, which the boot scan already reports as honest retention.
- **Sealed snapshot:** at most every 300 s (864 A/B writes of about 3 sectors).
- **Recovery journal:** goes to the DRAM crash page, not eMMC.

## Checked and sound

- **Time base:** u64 `cntpct`, `wrapping_sub`/`saturating_sub`.
- **Watchdog:** pet and gap tracking.
- **Supervisor:** backoff, `stable_ms`, CPU windows, probe clock.
- **wifiheal:** reload budget and episode bounding.
- **NAT:** idle expiry, LRU sweep, port range.
- **DHCP server and client:** lease expiry, renew, T1/T2.
- **IPv6:** neighbour/flow expiry.
- **Bounded tables:** ratelimit, conntrack, scan, discovery, ja4id.
- **Rings:** events, mcstate, mcauth sessions (12 h TTL).
- **Other:** WAN-health hysteresis, OTA trial gate, PMKSA and SAE peer lifetimes, heap use (no per-request
  allocation on the AP loop path).

## Not covered

- An exhaustive index-panic audit of every network parser (spot-checked only).
- G19 tunnel rekey limits (only runs when a policy enables it).
