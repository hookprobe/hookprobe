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

## Addendum A: corrections and pins before the run (2026-11-22)

Written after the operator approved unsealing and **before any test window is scored**.

**Correction: the IoT-23 test split is not virgin.**
- The table above says "sealed, never exported". That is wrong.
- The intel-data registry's seal reason reads "Neuro P2 test side (spent)": the IoT-23 test split was looked at
  once in P2, for the temporal-engine evidence.
- **None of the M3 systems, features or thresholds was fitted or tuned on it.** DNA v1, the doc 28 benchmark and
  this pre-registration used only the dev split.
- So IoT-23 test is a second look for the dataset, but a first look for these systems. CTU-13 test and the UNSW
  second half are first looks.

**Test split contents (intel-data registry):**
- **CTU-13:** Dataset-43, 44, 45, 47, 48, 50, 52, 53, 54, which are scenarios 2, 3, 4, 6, 7, 9, 11, 12, 13. This
  matches doc 22. Scenario 10 (Dataset-51) was never acquired; it is absent, not skipped.
- **IoT-23:** 13 captures: Honeypot 4-1, 5-1; Malware 8-1, 9-1, 17-1, 20-1, 21-1, 33-1, 34-1, 35-1, 36-1, 39-1,
  43-1.

**Export format.** The test builds are made at the dev builds' code (intel-data commit `d9f0aaaf`), in a
throwaway worktree. Intel-data first proves this by rebuilding CTU-13 dev byte-for-byte. The context snapshot is
the same as dev: iptoasn `1634a0e4…`, warninglists `8a171664…`. The test windows therefore have the same format as
dev. Build ids and manifest hashes will be pinned in Addendum B.

**UNSW second half (converted with the frozen converter at commit `128b2520`):**
- `unsw_m3_second.jsonl`, SHA-256 `c8adabb1d18964ca8c52d91c525b11d83d04909a19a44791f9d259038d81799c`;
- 27 devices, 15,413 windows (15,299 unique device-hours), all benign;
- 0 window ids shared with the dev half.

**A converter artefact present in dev too.** 114 window ids occur twice: an hour split across two pcap files. The
dev half has 66. `m3_run.py` is frozen and counts lines, as it did on dev, so this is reported, not changed.

## Addendum B: pinned test builds (2026-11-22)

Written **before the single M3 run**. No test window has been scored and no label has been looked at. Features
are extracted with the frozen `bench/dna_features.py`, which is unchanged since `128b2520`.

**CTU-13 test** (intel-data, built at `d9f0aaaf`, purpose `evaluation`):
- build id `windows-3a93dfd92bed`;
- manifest SHA-256 `c3d04c2ae56588cfa4ebbbbfe317f7acc7bd76807bc52e278abd29c20f77dd43`;
- unsealed: Dataset-43, 44, 45, 47, 48, 50, 52, 53, 54. Dev 42, 46, 49 are skipped. All 9 file SHA-256s were
  re-checked against the manifest here: 0 mismatches;
- DNA v1 features: `ctu13_test.jsonl`, 675 windows, SHA-256
  `96741d0440e2509e16b5ff0051c96d216d460ca4ac122e48b7f9c79c86f1ce0e`.

**IoT-23 test:** still building at intel-data. It will be pinned here before the run.

**Intel-data's reproducibility proof.** Rebuilding CTU-13 dev at `d9f0aaaf` reproduced dev build
`windows-8ada671b2e1e`'s 3 window files byte-for-byte.

**Warninglists: 196 kept, where dev kept 203.** The manifests differ in one field. `d9f0aaaf` drops 35
warninglists for licence terms, where dev dropped 28. The 7 extra are:
- netapi-top1k, netapi-top10k, netapi-top1m;
- moz-top500;
- covid-19-cyber-threat-coalition-whitelist, covid-19-krassi-whitelist;
- digitalside.

None of them appears in any IoT-23 or CTU-13 dev window (per intel-data). The effect on `warninglist_frac` is
therefore expected to be nil. In any case, S1 does not use that feature (it is one of the 4 context features
dropped above); only S2's beacon gate uses warninglists.

One raw address, 239.255.255.250 (SSDP multicast), is kept by design, as in the dev code.
