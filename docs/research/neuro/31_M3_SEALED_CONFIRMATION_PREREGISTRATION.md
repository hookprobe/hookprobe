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

**IoT-23 test** (intel-data, purpose `evaluation`, finished 2026-11-23 04:02):
- build id `windows-f1677e2e31b2`;
- manifest SHA-256 `5a26578dbbb6546deb2cda7b86a366ce4dfa264dbefae5e61c9671463f394226`;
- **code:** `d9f0aaaf` + `cb58dc7b`. The patch changes only the plain-file size cap: a plain file is bounded by its own
  size, and gzip keeps the 8 GiB cap;
- unsealed: all 13 test captures. The 10 dev captures are skipped. All 13 file SHA-256s were re-checked here
  against the manifest: 0 mismatches;
- context is the same acquisitions as dev and as CTU-13 test: iptoasn `1634a0e4…`, warninglists `8a171664…`, 196
  kept;
- DNA v1 features: `iot23_test.jsonl`, 313 windows, SHA-256 `2abcb0d2c61601b4081d263083e128615d26c846b79a9ca2da65719e6ba9ab00`.

**Why the patch cannot change any dev or CTU-13 window** (intel-data):
- the cap is 8,589,934,592 B;
- the only plain inputs above it are IoT-23 test 39-1 (10,885,361,439 B) and 43-1 (9,363,261,631 B). Before the
  patch, the first build attempt stopped at 39-1;
- every IoT-23 dev file is ≤ 3,070,319,722 B and every CTU-13 file is < 1 GB. All are ASCII, with no gzip.

**Determinism.** The failed attempt finished 9 files: 4-1, 5-1, 17-1, 20-1, 21-1, 33-1, 34-1, 35-1, 36-1. All 9 are
byte-identical to this build. (Intel-data first said 11; corrected to 9.)

**Pseudonymisation scan** (intel-data, first 2 GB of each file). The only addresses outside the documentation and
benchmark ranges are:
- the documented 240.0.0.0/4 overflow remote pool, which dev uses too;
- multicast 224.0.0.251, kept by design.

| Capture | Windows | Events | File SHA-256 |
|---|---|---|---|
| Honeypot-Capture-4-1 | 22 | 452 | `9381ff8add3e855d16d00124bd29847dc6362afb8fe936a8a699d10cefc41fd9` |
| Honeypot-Capture-5-1 | 39 | 1,164 | `a0b21c00d2d2e13ba5146128c34d7fe70af8940aa3bab0a35ef8e8187e102e24` |
| IoT-Malware-Capture-8-1 | 27 | 10,403 | `883aad56c704bbafb106dd691b0d8bc9fa030075f9bb1cdc403cb7bb85661b76` |
| IoT-Malware-Capture-9-1 | 26 | 6,378,293 | `256c4f7f3b9d3db2f046c2fb08244fcf50200e639b275397532f715218f73a7d` |
| IoT-Malware-Capture-17-1 | 26 | 54,659,855 | `88af082d2219998ee4e0d152557be232b464e2e7780be989bce78dc564221c97` |
| IoT-Malware-Capture-20-1 | 26 | 3,209 | `a5c22e6173dc528d14dbde24165e091596e64c373ece58c2e2159c631150c349` |
| IoT-Malware-Capture-21-1 | 27 | 3,286 | `faf959cb17c35571144e7897e35c6a5f8210d8600cfc6b064a982b971f30df0f` |
| IoT-Malware-Capture-33-1 | 28 | 54,454,591 | `749abbfa5b1e90e43c45fee0fcc0d1ba2c9544537cad2a92a91f4d4829801cea` |
| IoT-Malware-Capture-34-1 | 26 | 23,145 | `f3c63ce4e7ae7614ba8a6682f98a2740b84fa42852ce24aa0e4abfd41813a649` |
| IoT-Malware-Capture-35-1 | 26 | 10,447,787 | `e47563440028e4f5907b17e5f450de405fa8d5b9833e649589682db7e8b79a55` |
| IoT-Malware-Capture-36-1 | 27 | 13,645,098 | `03b7586c06bf5e4a1ea9ab01c858a9af4fb6019d0ddd4296b220b21e8d0753c8` |
| IoT-Malware-Capture-39-1 | 10 | 73,568,981 | `18acde74804d0786e585e623d36c62415c418d4f30d08b204eb5c4f03514dcce` |
| IoT-Malware-Capture-43-1 | 3 | 67,321,809 | `a011b2e792d601b61b745c7a48391e000fc9e794543cb0617bf36b76c7319825` |

**Home set:** `unsw_m3_second.jsonl` (Addendum A, `c8adabb1…`). Intel-data has marked both test splits spent in `sealed.json` (PR #1503).

**The run** uses `bench/m3_run.py` and `dna_features.py`, both unchanged since `128b2520`, once, with `venv-bench`:
`m3_run.py --dev iot23_dev.jsonl,ctu13_dev.jsonl --test iot23_test.jsonl,ctu13_test.jsonl --home unsw_m3_second.jsonl`.

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

## Result (2026-11-23): all three systems FAIL; stop rules applied

| System | Recall | Home false alerts / device-day | Verdict |
|---|---|---|---|
| S1 | 0.680 [0.621, 0.735] | 0.003 | FAIL (recall) |
| S2 | 0.425 | 0.042 | FAIL (recall) |
| S3 | 0.404 | 0.002 | FAIL (recall) |

- IoT-23 test S1 recall is 0.993; CTU-13 test is 0.320. The models do not generalise from 27 dev CTU-13 windows to
  the other C2 scenarios.
- Nothing is deployed in these roles. There is no `rules_ver = 2`, R-D1 is not recommended, and heqk P5 stays
  gated.
- A next attempt needs new sealed data.
- Full output: `data/m3-results.md`.
