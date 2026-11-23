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

## Addendum, 2026-11-23: alignment with the shipped API (#1517, #1522)

heqk implemented this proposal as written: `GET /api/neuro` labels every evidence record `learning` (first 24 h after
the device's slot was assigned), `relearning` (14 d after an el0-neuro reset the device predates) or `warm`, and only
`warm` records are ranked. Metal check: `docs/design/metal-evidence/20261123-neuro-api-cm5.md`. Slot eviction resets
the slot in the server (RESET_DEV) and restarts `first_seen`, so an evicted device that returns is `learning` again,
which matches the engine.

**One correction to this note, from the measurements already in it.** A device's first sighting and an el0-neuro reset
leave the engine in the same place: no history. The two curves agree:

| Hours since history started | first sighting (this note) | after a reset at k = 7 / 14 / 21 days (`conn-rule-and-reset.md` §2) |
|---|---|---|
| 0–24 | 0.34 (0–6 h 0.547, 6–24 h 0.269, weighted) | 0.295 / 0.290 / 0.327 |
| 24–72 | 0.117 | 0.081 / 0.127 / 0.098 |
| 72–168 | 0.234 | 0.187 / 0.255 / 0.367 |
| 168–336 | 0.232 | 0.275 / 0.375 / 0.456 |
| steady state | 0.483 | about 0.48–0.52 |

So the sensitivity gap that `relearning` describes also follows every first sighting. Under the shipped rule a new
device turns `warm` after 24 h, although for the next ~2 weeks it flags fewer hours for the same reason a reset device
does. The same holds after every reboot or OTA: the host's memory is not persisted (D4), so every device restarts as
new (`learning` for 24 h, then `warm`, `relearning_since` null).

**What it means.** Nothing unsafe: N0 is evidence only, and fewer flags is not a false-alarm risk. It only matters
for how much "no evidence" means. A quiet device 3 days after first sighting is less informative than a quiet
device after a month.

**Suggested refinement (presentation only, the host's and UI owner's call).** One rule on one clock,
`history_start = max(first_seen, reset_at)`:

| state | rule | ranked |
|---|---|---|
| `learning` | < 24 h since `history_start` | no |
| `settling` (or keep the name `relearning`) | 24 h – 14 d since `history_start` | as today's `relearning` |
| `warm` | otherwise | yes |

This needs no engine or ABI change and no new measurement: the 24 h and 14 d bounds are the ones above. Whether
`settling` records are ranked is a product choice; the data only says they are fewer, not worse. Until then the API
already carries `first_seen` and `hours_since_first_seen` on every record, so the UI can show the history age itself.
