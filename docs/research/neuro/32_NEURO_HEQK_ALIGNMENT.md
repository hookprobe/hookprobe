# 32: Neuro ↔ heqk alignment notes on the integration design (2026-11-22)

**Responds to** `docs/design/heqk-neuro-integration.md` (PR #1469, HomePods). This is written from the Neuro side and
changes no kernel code or decision. **Agreed in full:** §1 (the rule), §4 (no recommendations in ABI v1), §6 (the
model never judges) and §7 (compiler → HQPROP1 → owner → ADR 0053 is the only path). Below are corrections, new
evidence for the §10 decisions, and contract points for P2 and P5.

## 1. New evidence for §10 D2 (FP/SIMD in EL0): the L1 classifier does not need the FP lease

**The L1 candidate** (doc 31 S1, a logistic regression on 28 DNA v1 features) was run **integer-only**:
- features: u8, per feature `q = clip(round(255·(x − lo)/(hi − lo)))`;
- weights: i16, with standardisation folded in;
- accumulator: i32, compared against an integer threshold.

**It makes the same decisions as the float model** (dev data only, never M3 sealed data;
`tools/neuro-research/bench/quant_check.py`):

| Set | Windows | Float alerts | Integer alerts | Decisions that differ |
|---|---|---|---|---|
| IoT-23 + CTU-13 dev (training) | 544 | 243 | 242 | 1 |
| UNSW home, first half | 15,521 | 1 | 1 | 0 |

- Recall on training malicious windows is 0.9876 for both.
- The largest accumulator value is 7.6e7, far below i32's 2.1e9.
- The model is about **288 B**: 28 × i16 weights, bias, threshold, and 28 × (lo, scale).

**Implication:** L1 can run as an integer-only engine like N0. D2 option (a), "never", stays viable through L1, and
the lease is needed only for L2 models.

**Caveat:** this covers the scorer only. The DNA v1 extractor uses log1p, entropy and coefficient of variation. An
EL0 port needs fixed-point versions (lookup tables), and those must be checked bit-for-bit against the reference, as
`neuro-core` was.

## 2. Contract for P2 (data-plane hooks): one connection rule for kernel and benchmark

- **DNA v1 numbers are measured on Zeek-like connections** (`bench/unsw_to_dna.py`): a new connection on a TCP SYN
  after FIN/RST, or after **300 s idle (TCP) / 60 s (UDP)**, attributed to the hour it starts.
- **P2 proposes** SYN, or UDP idle ≥ 120 s.
- **Ask:** pick one rule and record it in the ABI or design doc.
  - If it is ≠ 300/60, Neuro re-runs the doc 28 benchmark with the kernel rule before L1 thresholds are set.
  - The cleanest path is that the kernel adopts 300/60 for the flow-start event that feeds DNA.
- **N0's peer key** (`peer_fp` V2/24) is unaffected. This concerns flow counting for the L1 features only.

## 3. Corrections to the design doc

**§6 L1.** "0.031 false alerts per device-day" is the 32-feature dev figure. The pre-registered L1 candidate (doc 31
S1) uses **28 features** and measured **0.002 per device-day** on dev:
- the 4 context features were dropped because they are not deployment-faithful on old captures;
- S1 needs no remote-context lookup in the kernel.

**§7 HQPROP1.** "TTL ≤ 30 min" mixes up two fields:
- **`expires_at`** (default 30 min) is how long an unapproved proposal stays valid;
- **`ttl_s`** is the lifetime of the applied action: session 60 s–24 h, durable ≤ 7 days (doc 29 §3).

**§2, row "Protection model".** Doc 31 M3 is **approved for unsealing and in progress**:
- the UNSW second half is converted and pinned;
- the IoT-23 / CTU-13 test exports are being built by intel-data at the dev builds' code.

The result goes to `data/m3-results.md`. It gates P5, and L1 thresholds must not be baked in before it.

## 4. A finding for L0 (request R-D1, pending M3)

**The kernel-style beacon rule fires on 22.4% of home device-hours** (doc 28 v1.2, 27 unseen UNSW devices). The
rule is ≥ 6 connections with MAD ≤ 15%. IoT devices heartbeat to their vendor clouds.

**A gate cuts home false alarms 76-fold but misses established C2.** The gate is: periodic only if
`novel_pair_frac > 0.5` and the peer is not on a warninglist. On dev, CTU-13 recall fell to 0.037.

**M3 S2 measures exactly this on sealed data.** No kernel change is asked until that result exists. This is relevant
to DET-01's 768/768 false positives.

## 5. L3 explainer status (for §6 L3)

- **The guarded explainer** (ftFg, Qwen3-1.7B LoRA, Q8_0, with default-deny guard A plus echo filter E) **passed the
  full blind v6 gate** (doc 26):
  - explanation 0.552 vs base 0.472, p = 0.035;
  - 70/70 injections neutralised;
  - hallucination 0.012.
- A known regression is on thin-evidence windows.
- It stays **off the protection path**: the ≥ 4 GB SKU or off-device (ADR 0025).
- Its input is evidence text with every quoted attacker value withheld (guard A), which matches §1: "every byte is
  untrusted".

## 6. Proposed next joint steps

| Step | Who | Gate |
|---|---|---|
| Fix the P2 connection rule (§2 here) | HomePods, with Neuro re-benchmarking if ≠ 300/60 | before P2 hooks land |
| M3 result → L1 go/no-go, and R-D1 recommendation | Neuro | running |
| Fixed-point DNA v1 extractor + integer S1 scorer, host golden tests against the Python reference | Neuro (`os/neuro`, outside the kernel) | after M3 passes |
| An EL0 L1 server, or extend el0-neuro behind a `caps` bit | HomePods | after D1–D3, M3, golden tests |
