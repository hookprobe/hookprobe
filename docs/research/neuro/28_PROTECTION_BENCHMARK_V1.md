# 28: Behavioural protection benchmark v1 (dev results, 2026-11-22)

**Status: dev results.**
- IoT-23 and CTU-13 **dev splits only**. Their test splits stay sealed (intel-data registry, docs 17 and 22) for
  one pre-registered confirmation run (milestone M3, doc 30).
- Reproduce: `tools/neuro-research/bench/dna_features.py` (DNA v1 vectors, doc 27), then
  `tools/neuro-research/bench/bench.py`.
- Inputs: `windows-00af0005d9b1` (IoT-23 dev) and `windows-8ada671b2e1e` (CTU-13 dev).

## Protocol (fixed in code before results)

- **Unit:** a host-hour window with at least 3 flows. Label = malicious if ≥ 50% of its labelled events are
  malicious.
- **Leave-one-capture-out:** 13 folds. Each test fold is a whole capture or scenario, so the test family was never
  seen and capture identity cannot leak (Arp et al. 2022 pitfalls; TESSERACT). Captures without malicious windows
  serve as benign test folds.
- **Threshold** for each method: set on the **training folds only**, at training-benign FPR ≤ 1%.
- **Reported:** pooled precision, recall, FPR, **false alerts per device-day** (FPR × 24) and AUC.
- **Data:** 544 windows, 242 malicious. The test pool is **44% malicious**, far above a real home, so precision is
  optimistic. FPR and alerts per device-day are the deployment-relevant numbers.

## Results

| Method | Precision | Recall | FPR | False alerts / device-day | AUC |
|---|---|---|---|---|---|
| Kernel-style L0 rules, any detector fires | 0.840 | 0.955 | 14.6% | 3.50 | — |
| Kernel-style L0 rules, 1% threshold | 0.990 | 0.798 | 0.66% | 0.16 | 0.969 |
| Robust per-feature quantiles (Arp-style) | 0.969 | 0.260 | 0.66% | 0.16 | 0.943 |
| Logistic regression | 0.922 | 0.983 | 6.6% | 1.59 | 0.985 |
| Mahalanobis, benign-only | 0.863 | 0.967 | 12.3% | 2.94 | 0.984 |
| LightGBM | 0.882 | **0.988** | 10.6% | 2.54 | **0.993** |
| Isolation Forest, benign-only | 0.985 | 0.822 | 0.99% | 0.24 | 0.918 |
| **Kernel rules AND LightGBM** (doc 29 §5 shape) | **0.963** | **0.955** | **3.0%** | **0.72** | 0.980 |

"Kernel-style" means the thresholds from `os/kernel/kernel/src/behavioral.rs` and `ratelimit.rs`, approximated on
host-hour windows. **It is not a measurement of heqk itself.** That needs the kernel's own detector output
replayed on these captures (milestone M1).

## Findings

1. **Learned models rank best but do not hold their false-positive rate on unseen captures.** Thresholds tuned to 1%
   on training benign give 6–12% on held-out benign, because benign behaviour differs between captures. This is the
   generalisation gap the literature warns about (Layeghy and Portmann 2022).
2. **The kernel's any-detector behaviour is too noisy** (14.6% FPR, 3.5 false alerts per device-day). That is
   consistent with DET-01: 768 alerts in 24 h of a real household, all false positives.
3. **Requiring an L0 detector AND classifier agreement** gives the best balance: 0.72 false alerts per device-day at
   0.955 recall. This supports the hybrid architecture in doc 30.
4. **None reaches about one false alert per device-week (0.14/day) at high recall.** Closing that gap is the next
   milestone: per-device baselines from DNA (doc 27), alert aggregation per incident rather than per window, and
   10-minute windows.
5. **The anomaly detectors** (Isolation Forest, robust quantiles) are quiet but miss whole families (e.g. IoT-60,
   IoT-1-1). They fit as **evidence** (doc 20), not as alarms.

## Limitations

- **Small:** 13 captures and 544 windows. IoT-23 malicious windows come from lab captures.
- **No DNS events** in these exports, so DNA v2's DGA and tunnel features are not exercised.
- **Window labels** come from the dataset's per-flow labels (IoT-23 / CTU-13 labelling quality applies).
- **No temporal split within a capture.** The split is by capture: stronger against family leakage, but not a
  time-ordered deployment simulation.
- **Not yet compared:** a temporal model or a combined behavioural-and-graph model. The literature review
  recommends not building those before this hybrid is validated (doc 30).
