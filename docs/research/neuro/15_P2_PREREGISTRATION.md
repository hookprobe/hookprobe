# 15 — P2 pre-registration: does a learned state-space cell beat the statistical memory? (IoT-23, preliminary)

> 2026-11-18. **Committed before any test-split result was computed.** Plan: `14` P2.
>
> This run uses IoT-23 only, so it is **preliminary**: no DNS, short benign captures, and no
> multi-day benign traffic. A final P2 verdict needs D1 (real multi-day traffic with DNS).

## Data (IoT-23, CC BY 4.0, MD5-verified, not committed)

- **Split:** by scenario, `sha256(name) % 3 == 0` → dev, else test. This is the same split as Phase 0
  E-SC2/E-BM2a, fixed before any result. Test scenarios are not opened until the design is frozen.
- **Benign timelines.** For each scenario's main internal host, an hourly series built from the flows
  **labelled benign** only (the device's own normal traffic). Honeypot captures are all benign.
  A timeline is kept if it has ≥ 12 non-empty hours.
- **Infected segments.** In each malware scenario, the hours with malicious-labelled flows, using all
  flows of the host (full view).
- **Episodes (semi-synthetic, as in E-BM2a).** For every benign timeline B and infected scenario I in the
  **same split**:
  1. learn on B's first half;
  2. score B's second half (negatives);
  3. splice k = 4 consecutive real infected hours from I at a seeded position (positives).

  Both sides are real traffic; the join is artificial and labelled as such.
- **Training data** for learned parameters: benign hours of **dev-split** timelines only.

## Candidates

All see the same hourly inputs: bytes out, connections, distinct peers, novel peers (against the same
1,024-bit aging Bloom filter), and hour of day. Novelty needs set memory, which no small recurrent state
can replace at this size, so every candidate keeps the Bloom filter.

| Id | Candidate | Per-device state |
|---|---|---|
| **A** | Integer DNA (`dna_fixed.py`, the engine shipped in `el0-neuro`), unchanged | 1,296 B |
| **B** | **Diagonal state-space cell:** <ul><li>fixed multi-timescale decays λ ∈ {0.5, 0.8, 0.95, 0.99} on the six features gives 24 state values;</li><li>a linear readout learned by ridge regression on dev benign hours predicts the next hour's four volume/novelty features;</li><li>anomaly = sum of absolute prediction errors, each normalised by a per-device running mean absolute error.</li></ul> | 24 × int16 + 4 scales + Bloom ≈ 0.7 KB |
| **C** | Hybrid: max(A score, B score), with B rescaled so that both have the same dev-split FPR | A + B |

**The ridge penalty is the only tuned parameter, chosen on dev.** The λ set and the feature set are
fixed above. A GRU is **not** run in this pre-registration; if B and C fail, a GRU is a new
pre-registration.

## Metrics (test split, computed once)

1. Hour-level ROC AUC: spliced infected hours vs benign second-half hours.
2. Incident detection within 4 h at the threshold that gives **1 alarm per device per week** (≈ 0.6% of
   benign hours) on the **dev** split.
3. Benign alarms per device per day on test negatives at that threshold.
4. Bytes per device.

## Decision rule

- **A learned candidate (B or C) wins** only if it beats A by **≥ 0.02 AUC** at ≤ equal bytes per
  device **and** does not raise benign alarms per device per day.
- **Otherwise** A (the statistical DNA) stays in `el0-neuro`, and the result is reported as is.
- **Either way the result is preliminary** until D1.

## Results (2026-11-19), recorded after the pre-registration commit `7c56f1bc`

**Data.** IoT-23 re-downloaded; MD5 `7132e603…` matches; 23 conn logs, the same as Phase 0.

**Dev (design choices only).**
- 3 benign timelines × 9 infected scenarios = 27 episodes; 168 training pairs.
- The ridge penalty was chosen as **10** (dev AUC of B: 0.931 / 0.952 / 0.952 / 0.945 for 0.1 / 1 / 10 / 100).
- Thresholds were calibrated to 1 alarm per device per week on dev negatives.

| Dev | AUC | Incident detection | Benign alarms / device / day | Bytes / device |
|---|---|---|---|---|
| A — integer DNA | 0.949 | 0.52 | 0.000 | 1,214 |
| B — learned SSM cell | 0.952 | 0.37 | 0.093 | 568 |
| C — hybrid | 0.977 | 0.67 | 0.093 | 1,782 |

**Test (run once, everything frozen from dev).** 5 benign timelines × 11 infected scenarios = 55 episodes.

| Test | AUC | Incident detection @ 1 alarm/week (dev threshold) | Benign alarms / device / day | Bytes / device |
|---|---|---|---|---|
| **A — integer DNA** | **0.927** | **0.87** | 0.33 | 1,214 |
| B — learned SSM cell | 0.886 | 0.09 | 0.00 | 568 |
| C — hybrid | 0.907 | 0.87 | 0.33 | 1,782 |

**Decision under the pre-registered rule: A stays.**
- **B fails.** It is 0.041 AUC *below* A on test. Its dev-calibrated threshold transfers so poorly
  that it catches 9% of incidents.
- **C fails.** It uses more bytes than A by construction, and is 0.02 AUC below it on test.
- **The learned cell is rejected for now** and `el0-neuro` keeps the statistical DNA.

**Honest reading.**
- **The samples are tiny.** Dev has 3 benign timelines and test has 5. Dev looked favourable to B
  (+0.003 AUC) and test reversed it (−0.041): the variance of an 8-timeline study.
- **The learned readout has nothing to stand on.** 168 benign training hours cannot learn device
  behaviour that transfers.
- **Thresholds do not transfer between splits at this size** for B or C. A's statistics need no
  training, so its threshold moved less.
- **This result says "not on IoT-23", not "never".** The question reopens only with D1 (≥ 14 days,
  ≥ 20 devices, DNS) and a new pre-registration (e.g. a GRU, or more training hours).
- **A's test nuisance rate (0.33 alarms/device/day, about 2.3 per week) is above the ≤ 1/week ship
  gate.** That gate remains open and needs D1 to measure properly.

Files: `data/p2-dev.*`, `data/p2-test.*` (readout weights omitted; reproducible from the script).
