# 31: M3, sealed confirmation of the protection decision rules (pre-registration, 2026-11-22)

Written **before** any sealed data is exported or looked at. It fixes the systems, the training data, the
thresholds, the metrics and the pass criteria. Dev evidence: doc 28 v1.2. Architecture: doc 30.

## Sealed data (one look)

| Set | What | Status before M3 |
|---|---|---|
| IoT-23 **test** split | 13 captures by `neuro-sha256-mod3` (intel-data registry: `split:test`) | sealed, never exported |
| CTU-13 **test** split | scenarios 2, 3, 4, 6, 7, 9, 11, 12, 13 (doc 22) | sealed (`registry/sealed.json`) |
| UNSW-IoTraffic **second half** | each device's later 50% of active days (`unsw_to_dna.py` keeps only the first half for dev) | never converted |

**Excluded:**
- **Deakin IoT v2** stays sealed for the temporal-engine question (doc 20).
- **The CIC datasets** are evaluation-only and are not used here.

## Systems (frozen now; code at the commit that adds this document)

Features: DNA v1 (doc 27), exactly as in `bench/dna_features.py` and `bench/unsw_to_dna.py`.

| System | Definition | Role |
|---|---|---|
| **S1 notify** | logistic regression (`bench.logreg`, l2 = 1.0, 400 iterations, class-balanced) on the **28 non-context DNA features**, trained on **all IoT-23 + CTU-13 dev windows**; threshold = training-benign FPR ≤ 1% | owner notification tier |
| **S2 L0-gated** | kernel-style rules (`bench.rules`, doc 28 thresholds) with the **gated beacon** (periodic peer counts only if `novel_pair_frac > 0.5` and `warninglist_frac < 0.5`); alert when any detector fires | kernel candidate (request R-D1) |
| **S3 act** | S2 **AND** S1 | enforcement-proposal tier (doc 29 decision shape) |

**Reported, not gated:** the ungated any-detector rules, LightGBM, and Isolation Forest, trained and thresholded the
same way.

**Why S1 drops the 4 context features** (`warninglist_frac`, `unrouted_frac`, `log_countries`, `log_asns`):
- The context is computed with **today's** ASN and warninglist tables on 2011 (CTU-13) and 2018 (IoT-23) captures.
  It is therefore not deployment-faithful: for example, 2011 C2 servers are unrouted today.
- Dev ablation (leave-one-capture-out, before this pre-registration):
  - all 32 features: recall 0.983, home 0.031 false alerts per device-day;
  - **28 features: recall 0.975 (CTU-13 0.815), home 0.002 per device-day.**
- The 32-feature variant is reported as an extra.

**Expectation recorded before the run.** S2's gated beacon misses established C2: on the dev dry run, trained on
IoT-23 and tested on CTU-13 dev, its recall was 0.037. The gate requires a novel peer, and a daily C2 server stops
being novel after 24 h. **S2 is therefore expected to have low recall on CTU-13-like botnets.** It is kept as
pre-registered, to measure exactly that. Per-dataset recall is reported.

## Metrics

- **Recall and precision** on the IoT-23 test plus CTU-13 test windows (pooled for the criteria; per-dataset and
  per-capture recall also reported). These captures are unseen, so no leave-one-out is needed.
- **False alerts per device-day** on the UNSW second half, with every device scored. No model sees any UNSW data in
  training.
- Per-capture recall, per-device false-alert rate, and the worst device.
- **The source-confound AUC** between the test sets is reported. It is expected to stay high (doc 28 v1.2), and the
  design does not depend on it.

## Pass criteria (each system judged separately)

| System | Recall | Home false alerts / device-day |
|---|---|---|
| **S1 notify** | ≥ 0.90 | ≤ 0.14 (about one per device-week) |
| **S2 L0-gated** | ≥ 0.80 | ≤ 0.14 |
| **S3 act** | ≥ 0.80 | ≤ 0.02 (about one per device per 7 weeks) |

**Recall uncertainty.** The exact binomial 95% CI is reported. A pass needs the **point estimate** to meet the
criterion, and the CI is shown alongside.

## Stop rules

- **One run.** Results are reported as they are. Nothing is tuned on sealed data afterwards.
- **If S3 passes:** the decision rule goes into the doc 29 rule table as `rules_ver = 2`, and R-D1 (beacon gating) is
  recommended to HomePods with the measured numbers.
- **If a system fails:** it is not deployed in that role. A new attempt needs new sealed data. Candidates include a
  new UNSW-like home capture, or a field study (M6).

## Process

1. Push this pre-registration.
2. Operator approves unsealing. The test splits are spent by this run.
3. intel-data exports the IoT-23 and CTU-13 test windows as new immutable build ids, with manifests verified and
   pinned here. Neuro converts the UNSW second half with the frozen converter.
4. One scripted run (`bench/m3_run.py`, committed before step 3) writes the results.
5. Results and per-device tables are published in `data/m3-results.md`.
