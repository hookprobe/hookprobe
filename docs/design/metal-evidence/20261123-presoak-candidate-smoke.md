<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Pre-soak item 3: candidate-shaped image, 1 h smoke on CM5 (2026-11-22/23)

**Class: CM5 metal. NOT the 72 h soak (REL-05) and NOT the operator's candidate approval.** The image has the
shape of a soak candidate: main `7f6bc8ba` (includes #1468 dead-peer/evlog, #1496 MC seed fail-closed), the
shipping features from `tools/ci/shipping-features.txt` (`hboot,apmc,wifi-bigtx,appersist,wpa3`), and a fresh UI
build. It is signed with the **bench dev keys and bench config**, so it is not a release artifact. Build id
`cand-7f6bc8ba`.

Run: OTA install (trial → COMMITTED), then `tools/diagnostics/cm5-soak.sh` for 1 h at a 300 s interval with the Pi
browsing through the AP, then OTA back to am35B (COMMITTED).

```
PASS — SOAK: 1 h, 12 samples — reboots/faults=0, failed samples=0, firmware-trap events=0, throughput median 95.3 Mbps (worst 92.8)
[WDOG] armed=true pets=3798 worst_loop_gap_ms=449 prev_reset_was_watchdog=false
```

| t (s) | seen | detections | Mbps | DNS ms |
|---|---|---|---|---|
| 0 | 44 | 135 | 92.8 | 83 |
| 920 | 21,710 | 136 | 94.4 | 7 |
| 1839 | 43,672 | 136 | 95.3 | 7 |
| 2759 | 65,203 | 137 | 98.7 | 343 |
| 3372 | 79,603 | 137 | 96.8 | 7 |

The counters only grow (no silent reboot). No panic, crash, self-heal or `[AP-MC] TRNG` line in the serial, and no
evidence-log drops. The worst AP-loop gap was 449 ms. DNS shows occasional 287–343 ms samples (cold lookups) against
a 3–7 ms steady state.

Not covered by 1 h: slow leaks, the 24 h session rekey, the REL-08 firmware trap (~10 h), and DHCP lease expiry over
days. Those are what REL-05 is for.
