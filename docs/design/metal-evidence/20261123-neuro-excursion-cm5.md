<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Neuro N0 per-excursion timing on CM5 (2026-11-23)

**Class: CM5 metal.** Status register `cm5-metal` open item "per-excursion timing". Image `nxt-fa54e26a` =
`feat/neuro-excursion-timing` (#1506) on main `7f6bc8ba`: shipping features + `neuro`, bench dev keys and config. Run:
OTA install, then `tools/diagnostics/cm5-soak.sh` 2 h with the Pi browsing, then OTA back to am35B.

`Server::call` times each excursion (EL1 → el0-neuro → EL1, including the address-space switch) with the generic
counter (`cntpct_el0`, 54 MHz on the CM5), per command class.

```
[NEURO exc] events n=926 avg=0us max=3us | close_hour n=2 avg=4us max=4us | other n=1 avg=0us max=0us
PASS — SOAK: 2 h, 12 samples — reboots/faults=0, failed samples=0, throughput median 95.4 Mbps (worst 89.4)
[NEURO beat] fed=5847 dropped=0 batches=926 hours=2 failed=0 results=2 deviant=2 resets=0
[WDOG] armed=true worst_loop_gap_ms=470
```

| command | calls in 2 h | average | worst |
|---|---|---|---|
| EVENTS (a batch, ~6 events) | 926 | < 1 µs (integer µs printed 0) | 3 µs |
| CLOSE_HOUR (score the hour, ≤ 64 devices) | 2 | 4 µs | 4 µs |
| other (INFO / HEALTH) | 1 | < 1 µs | < 1 µs |

**Reading.**
- Neuro costs the AP loop a few microseconds per minute. Against the 2,000 ms loop-gap gate and a 470 ms worst gap,
  that is negligible.
- The figures match the ADR 0065 metal measurement of an EL0 round trip (388 ns empty, 1.2 µs with a frame, #1206):
  the reference engine is small integer code.
- The averages printed as `0us` because the line used whole microseconds. The follow-up in this PR prints
  nanoseconds (u128 arithmetic for the running total).
- Only one client device, so CLOSE_HOUR scored one device. The 64-device slot pressure item stays open.
