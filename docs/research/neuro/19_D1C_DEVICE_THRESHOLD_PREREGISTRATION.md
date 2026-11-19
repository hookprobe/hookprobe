# 19 — D1c pre-registration: service-keyed peers plus a per-device alarm threshold

> 2026-11-19. **Committed before any code for this rule exists and before any number under it was
> computed.**
> - It follows `18` (D1b): rejected on dev. The service key cut novel-peer alarms by 79% and raised AUC to
>   0.995, but the fixed threshold of 1.0 still left a median of 29 alarms per device per week.
> - **The Deakin captures (`18`, primary dataset) are downloaded and MD5-verified but have not been
>   converted or read.** They are this pre-registration's confirmation set.

## Hypothesis

**H:** with V2 service keys, the DNA's scores rank attack hours well, but one absolute cut-off does not fit
every device. A threshold calibrated **per device, on that device's own learning period**, meets the D1
nuisance gate on **unseen time** while keeping detection.

## Fixed from earlier work

- **Peer key: V2 /24** (`18`).
  - /24 and /16 were identical on dev: the prefix fallback is 0.2% of public flows.
  - `18`'s tie-break picks /24.
- **The engine does not change.** `DNAFixed` / `el0-neuro` scoring, and learning gated at 1.0, stay exactly
  as they are.
- **Only the alarm decision changes:** an hour alarms when its score is at least the device's threshold
  `T_d`.

## The threshold rule (fixed now; only `b` and `m` are chosen on dev)

**Calibration window.** The last 50% of the hours the engine streams **before** the scored period, after
its first half has warmed up. Scores are computed exactly as on the device.

**`T_d = max(1.0, m × S_d[k])`**, where:
- `S_d` is the device's calibration-window scores, sorted in descending order (`S_d[0]` is the largest);
- `k = min(15, floor(b × calibration weeks))`, with calibration weeks = active calibration days ÷ 7;
- `b` is the alarm budget per calibration week, in {0.5, 1};
- `m` is the margin, in {1.0, 1.25, 1.5, 2.0}.

So the device would have alarmed at most `k` times in its own calibration window, before the margin is
applied. The floor of 1.0 means a threshold can only rise above D1's.

**On the device:** this is a top-16 buffer of `u32` scores, kept while the window runs, then one
multiplication: integer and bounded.

**The threshold is frozen at the end of the window. It is not re-calibrated during the scored period.**
Periodic re-calibration is a possible follow-up, and is not tested here.

## Selection (UNSW dev, D1 split unchanged)

There are 8 configurations `(b, m)`. A configuration qualifies only when **all** of these hold:
1. median benign alarms per device per week ≤ 1 (devices with ≥ 7 active days in the period, as in D1, A6);
2. detection ≥ 0.9 for **each** of the four D1 attack classes;
3. **no muting:** ≥ 90% of the counted devices have detection ≥ 0.8, with all classes pooled.

**Choice:** the qualifying configuration with the smallest `m`, then the larger `b`: the most sensitive
one. If none qualifies, the hypothesis is **rejected on dev**, and Deakin stays unopened.

**Disclosure:** UNSW dev has been inspected under D1 and D1b, so it serves only to choose.

## Confirmation (the gate): Deakin IoT Traffic v2, once

**Conversion.**
- The 119 unique `IoT_*.pcap` files, MD5-verified against `data/d1b-deakin-manifest.tsv`.
- Device identity from `macAddresses.csv`.
- Peer key V2 /24.

**Split per device:**
- the first 50% of active days are learning (the second half of those days is the calibration window);
- the last 50% are scored.

**Attacks:** the same overlays as D1/D1b, with IoT-23 malicious hours taken from its test split.

**Gate:** the same three conditions as selection, on the scored half.
- Both readings of the nuisance gate are reported: the median, and per device.
- Also reported: the per-device `T_d` distribution, and alarms that fall inside `setupTimes.csv` windows
  (descriptive only).

**Secondary:** UNSW test is run once with the frozen configuration and reported, but it **cannot pass the
gate on its own**: it has been seen.

## Decisions

- **The Deakin gate passes:** V2 service keys plus a per-device threshold become the P5 integration
  candidate for the temporal tier as an alarm source. It still sits behind the field pilot (P7), which must
  show it in a lived-in home. Deakin and UNSW are lab testbeds.
- **The gate fails on Deakin:** the temporal tier stays evidence-only (`17`). Deakin is then spent, and any
  further rule needs a new fresh dataset.
- **Rejected on dev:** as above. Deakin stays unopened.

## Implementation (committed before any D1c number was computed)

`d1_analysis.py --phase calib --period {dev, test} --split {d1, half} --peer-key v2-24 [--b B --m M]`.
- It records each device's scores over the calibration window (the last 50% of the warm-up hours).
- It applies `T_d` per device, and evaluates the three conditions with per-device detection for the
  muting check.
- Without `--b`/`--m` it evaluates the 8-configuration grid and prints the rule's choice. With them, it
  evaluates only the frozen configuration (confirmation).
- The engine's scores do not depend on the threshold, so one engine run serves the whole grid.
- Smoke-tested on synthetic data. The existing `--phase dna` output is unchanged.
