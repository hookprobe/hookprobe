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

---

## v1.2 (same day): real home-IoT false alarms, a source-confound check, and the beacon finding

### Home-IoT benign data

- UNSW-IoTraffic (**CC0-1.0**, verified in the intel-data registry): 27 home IoT devices.
- Converted by `bench/unsw_to_dna.py`, with Zeek-like connections (new connection at SYN after FIN/RST; 300 s TCP
  / 60 s UDP idle; ICMP included; each connection assigned to the hour it starts).
- Remote context comes from the same verified lookup build as the exports.
- **Only the first half of each device's active days** is used: 15,521 device-hours. The second half is reserved
  for M3.

### Source-confound check (now a standing step: `bench/confound.py`)

A leave-one-capture-out classifier separates **benign** windows by source:

| Pair | AUC |
|---|---|
| UNSW vs IoT-23 + CTU-13, first converter (whole-hour 4-tuples) | 0.988 |
| Same pair, Zeek-like converter | 0.981 |
| **IoT-23 vs CTU-13** (both intel-data exports) | **0.950** |

**Conclusion.** These datasets come from genuinely different populations and are intrinsically separable. Pooling
benign windows from one source with malicious windows from another **inflates any learned model**.
- A first pooled run gave LightGBM AUC 1.000. **That number is discarded.**
- The protocol is therefore:
  - recall and precision by leave-one-capture-out **within** IoT-23 + CTU-13 (the table above);
  - **false alarms measured on a benign source the models never saw** (below).

### False alarms on 27 unseen home devices

Methods are trained on IoT-23 + CTU-13, thresholded at training-benign FPR ≤ 1%, and never shown UNSW.

| Method | Recall (LOCO, table above) | Home false alerts / device-day | Devices with any false alert | Worst device |
|---|---|---|---|---|
| Kernel-style rules, any detector | 0.955 | **5.43** | 15/27 | Belkin Wemo switch, 23.4/day |
| LightGBM | 0.988 | 6.35 | 14/27 | 23.3/day |
| Mahalanobis | 0.967 | 6.35 | 19/27 | 24.0/day |
| Rules AND LightGBM | 0.955 | 1.95 | 8/27 | 21.2/day |
| Isolation Forest | 0.822 | 0.20 | 10/27 | 4.6/day |
| Robust quantiles | 0.260 | 0.135 | 3/27 | 11.5/day |
| **Logistic regression** | **0.983** | **0.031** | 2/27 | 0.46/day |
| **Rules, 2+ detectors** | 0.798 | **0.005** | 1/27 | 0.47/day |

### Which kernel-style detector fires on home IoT

| Detector | Home IoT (15,521 h) | Labelled benign | Labelled malicious |
|---|---|---|---|
| port scan (≥ 50 ports) | 0.2% | 1.7% | 46.7% |
| horizontal scan | 0.0% | 0.0% | 86.8% |
| lateral movement | 0.0% | 0.0% | 0.0% |
| **beacon (CV ≤ 0.15, ≥ 6 connections)** | **22.4%** | 10.9% | 49.6% |
| exfil (≥ 50 MB) | 0.1% | 2.6% | 0.0% |
| brute force | 0.0% | 0.0% | 72.7% |

**The beacon detector causes essentially all home false alarms.** IoT devices heartbeat to their vendor cloud on a
fixed period. **Gating it** (a periodic peer counts only if it is new to the device, `novel_pair_frac > 0.5`, and
not on a warninglist):

| | Recall | Labelled-benign FPR | Home false alerts / device-day | Devices |
|---|---|---|---|---|
| Any detector, ungated | 0.955 | 14.6% | 5.43 | 15/27 |
| **Any detector, gated beacon** | 0.876 | 5.0% | **0.071** | 7/27 |

### Reading (dev; the decision rule must be pre-registered before M3)

1. **LightGBM does not transfer to unseen homes.** It learns training captures too specifically. Simple
   **logistic regression transfers best**: recall 0.983 at 0.031 false alerts per device-day, about one every 32
   days per device.
2. **The kernel's beacon detector is the false-alarm source on home IoT.** A novelty and known-service gate cuts home
   false alarms 76-fold at a cost of 8 recall points. This is a candidate request for HomePods (**R-D1**, doc 30).
   It needs the sealed-test confirmation before anyone acts on it.
3. **M2's target** (≤ 0.14 false alerts per device-day at recall ≥ 0.9) is met on dev by logistic regression. The
   gated rules come close (recall 0.876). Next step: pre-register the decision rule and run M3 once.
