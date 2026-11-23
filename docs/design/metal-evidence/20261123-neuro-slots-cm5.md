<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Neuro N0: 64-device slot pressure on CM5 (2026-11-23)

**Class: CM5 metal, synthetic stations.** Status register `cm5-metal` open item "64-device slot pressure". The bench
has one real Wi-Fi client, so the bench-only `neuro-slots-N[-BASE]` injector (`wifi-inject`, never in the shipping
flavour) feeds N synthetic devices (locally administered MACs `02:4e:00:00:xx:xx`, three flow events each) through the
real host path on the CM5: slot assignment, batching, the hour close and eviction. The Pi browses through the AP
the whole time (one real slot). Image `slots-a02d570d` = main + the injector, built with the shipping set + `neuro` +
`wifi-inject`. Script: `tools/diagnostics/cm5-neuro-slots-check.sh`.

```
[NEURO] bench slots: 70 synthetic devices from 0x0000: tracked 1 -> 64 (of 64), events fed +189 dropped +21, evictions +0, resets +0
[NEURO beat] fed=2330 dropped=21 batches=530 hours=1 failed=0 results=64 deviant=64 resets=0 evictions=0
[NEURO exc] events n=530 avg=713ns max=44907ns | close_hour n=1 avg=39962ns max=39962ns | other n=1 avg=833ns max=833ns
[NEURO] bench slots: 10 synthetic devices from 0x03e8: tracked 64 -> 64 (of 64), events fed +30 dropped +0, evictions +10, resets +0
NEURO-SLOTS-METAL: PASS (8/8)
```

| Check | Result |
|---|---|
| A: 70 devices in one open hour | **ok**: all 64 slots used (63 synthetic + the Pi). The other 7 devices' 21 events are dropped and counted. 0 evictions: a device with an open hour is never evicted |
| B: the hour closes with 64 devices | **ok**: 64 results, 0 failed. CLOSE_HOUR for 64 devices takes **40 µs**; the worst EVENTS batch, the full burst, 45 µs |
| C: next hour, 10 fresh devices | **ok**: exactly 10 evictions (least recently seen → `RESET_DEV`), 0 dropped |
| D: `/api/neuro` | **ok**: `devices_tracked` 64, 10 evictions, 0 failed hours, 64 evidence records |
| D: AP loop | **ok**: worst gap 467 ms (< 2 s), no panic, bench restored to am35B |

**Reading.**
- At capacity the host behaves as designed: it drops and counts rather than evicting an active device, and evicts
  only idle ones.
- The cost stays in microseconds: the full 64-device hour close is 40 µs against the 2 s loop-gap gate.
- `deviant=64` is the cold-start rule (every synthetic device is brand new). The API marks all of them `learning`
  and not ranked (research `n0-cold-start.md`).

With this, every `cm5-metal` open item in the Neuro status register is closed.
