# N0 cold start on real devices, and a warm-up policy for surfacing evidence (2026-11-23)

**Responds to** heqk's 6 h CM5 run (`docs/design/metal-evidence/20261123-neuro-6h-cm5.md`): a fresh device's first
6 hours were all scored deviant. Also see the status register, `api-evidence` inputs.

**Method.**
- `tools/neuro-research/cold_start.py` runs the bit-exact reference engine (`dna_fixed.DNAFixed` = `neuro-core`)
  from each UNSW device's **first** hour, fed as in D1.
- It reports the share of active hours flagged deviant (score ≥ 1.0) by hours since the device was first seen.
- This is descriptive; the engine is unchanged.

```
devices 27 (UNSW-IoTraffic, D1 records, engine = dna_fixed.DNAFixed)
| hours since first seen | active device-hours | deviant share |
|---|---|---|
| 0–6 | 137 | 0.547 |
| 6–24 | 387 | 0.269 |
| 24–72 | 930 | 0.117 |
| 72–168 | 1574 | 0.234 |
| 168–336 | 2522 | 0.232 |
| 336–672 | 4326 | 0.307 |
| 672–end | 27670 | 0.483 |

first deviant hour per device: median 0 h, all within the first 6 h: 27 of 27 devices
```

## Reading

1. **The first hours are noisy, as heqk saw.** 0.55 of a device's first 6 active hours are deviant, and every one of
   the 27 devices has a deviant hour in its first 6 hours.
   - The CM5 client was a browser on CDN-backed sites. Its peers keep rotating, so every hour stays novel until each
     peer is admitted (`PERSIST_K` = 6 hours seen). That gives 6/6.
   - IoT devices with a few fixed clouds settle faster.
2. **Then a quiet stretch, then the steady state.**
   - 0.12–0.27 deviant from 6 h to 2 weeks. The cold-slot widening raises thresholds while each hour-of-day slot has
     fewer than `SLOT_MIN` samples.
   - Then it climbs to the steady **0.48**. That is D1's known nuisance level (about 72 deviations per device per
     week), and it is why N0 output is evidence only (docs 17–20).
3. **So the burst at the start is small next to the steady state.** Suppressing the first hours alone would not make
   N0 quiet, and nothing about N0's role changes.

## Proposal: presentation only, no engine or ABI change; the host and UI owner decide

| Device state | Shown as | Rule |
|---|---|---|
| **learning** | evidence kept, marked "learning, first seen ⟨time⟩"; not ranked into incidents | first **24 h** after first seen (covers the 0–6 h burst and the 6–24 h tail) |
| **relearning** | as above, "relearning since ⟨reset time⟩" | first **14 days** after an el0-neuro reset (doc 34 §3: sensitivity gap, fewer flags) |
| **warm** | doc 20 wording unchanged | otherwise |

- The host already knows both times. First-seen is when a device slot was created; relearning starts at the last
  `server_resets` increment.
- An engine-side novelty discount while slots are cold would change the bit-exact engine. It would need new golden
  vectors, a new el0-neuro image and a D1-style re-measurement of detection. That is not proposed now: the
  presentation rule removes the visible symptom at no detection cost.
