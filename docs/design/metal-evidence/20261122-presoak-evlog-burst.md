<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Pre-soak finding 2 on CM5: evidence log under a detection burst (2026-11-22)

**Class: CM5 metal.** Bench image `evb-f51d4ae9` = main `19034148` (includes the #1468 `flush_full` fix) + the bench-only
`evlog-burst-N` injector (`wifi-inject` feature, never in the shipping flavour). Script:
`tools/diagnostics/cm5-evlog-burst-check.sh`.

The injector pushes N synthetic detections (rule 199, sources in 192.0.2.0/24 TEST-NET-1) into the event ring in one
go, so the whole burst is drained in ONE AP-loop pass, which is the worst case for the 250 ms fill-flush pacing.
The detections take the real path: the event ring, then `ProdFull::image_of`, then `EvLog::push` and `flush_full` /
the heartbeat flush, then a sealed record on the eMMC.

| Check | Result |
|---|---|
| 40 in one burst (two full batches): batch 1 written at once, batch 2 by the heartbeat | **ok**: written +40, dropped +0 |
| 60 in one burst (third batch inside the 250 ms pacing window) | **ok**: written +40, dropped +20, every one written or counted (`[AP-EVLOG] … 20 not kept: over the paced write rate`) |
| AP loop during the bursts | **ok**: worst loop gap 431 ms (< 2 s) |
| No panic / crash | **ok** |
| Reboot (OTA back to am35B): the sealed log reopens with every burst record | **ok**: 57 records before, 57 after |

`EVLOG-BURST-METAL: PASS (7/7)`

Serial excerpts:
```
 [BENCH] evlog-burst: 40 synthetic detections pushed (rule 199)
 [AP-EVLOG] 20 detections sealed to the evidence log (41 total this boot, ring 55 records, 0 not kept: over the paced write rate)
 [BENCH] evlog-burst: 60 synthetic detections pushed (rule 199)
 [AP-EVLOG] 20 detections sealed to the evidence log (81 total this boot, ring 57 records, 20 not kept: over the paced write rate)
```

**Behaviour to note:** within one instant the log keeps 40 (one immediate write plus one full pending batch).
Detections spread over ≥ 250 ms get the designed ≤ 80/s. Anything beyond is counted, not silently lost, which is the
finding-2 requirement. The bench evidence log now contains 80 synthetic rule-199 records from this run.
