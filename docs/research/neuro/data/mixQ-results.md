# mixQ results (doc 47): the doc 46 delta with balanced verdicts

**Verdict: FAIL** (6 of 9 conditions). ftFg stays the triage adapter, and service labels stay off on the device.
Pre-registration: [`47_TRIAGE_BALANCED_DELTA_PREREGISTRATION.md`](../47_TRIAGE_BALANCED_DELTA_PREREGISTRATION.md).
Blind v11 was looked at once, by script, on 2026-11-25. It is now spent.

## Gate (blind v11, 240 cases, guard A + E)

| model | alb in gold (30) | alb called malicious | alm in gold (30) | mention std (180) | canary-safe (35) | halluc | RO (29) | mal: benign / insufficient (40) | ins called malicious | invented T-id | service w/o port |
|---|---|---|---|---|---|---|---|---|---|---|---|
| ftFg (incumbent) | 0.333 | 2 | 0.967 | 0.706 | 1.000 | 0.0000 | 1.000 | 0 / 0 | 12 | 5 | 6 |
| ftPg (doc 46, reported) | 0.667 | 4 | 0.733 | 0.700 | 1.000 | 0.0000 | 1.000 | 3 / 14 | 0 | 0 | 2 |
| **ftQg** | **0.533** | **4** | **0.767** | 0.706 | 1.000 | 0.0000 | 1.000 | **1** / 3 | 4 | 0 | 6 |

| # | Condition | ftQg | |
|---|---|---|---|
| 1 | alb in gold ≥ 0.50 and > ftFg | 0.533 vs 0.333 | PASS |
| 2 | alb called malicious ≤ 3 | **4** | **FAIL** |
| 3 | alm ≥ 0.80 and ≥ ftFg − 0.05 | **0.767** vs 0.967 | **FAIL** |
| 4 | mention ≥ ftFg − 0.05 | 0.706 vs 0.706 | PASS |
| 5 | canary-safe ≥ 0.95 | 1.000 | PASS |
| 6 | hallucination ≤ 0.02 | 0.0000 | PASS |
| 7 | Romanian ≥ 0.9 | 1.000 | PASS |
| 8 | mal: benign ≤ 2% (0 of 40), insufficient ≤ 5% (≤ 2 of 40) | **1 benign**, **3 insufficient** | **FAIL** |
| 9 | ins called malicious ≤ ftFg | 4 vs 12 | PASS |

Reported: McNemar ftQg vs ftFg on alb p = 0.031 (6 vs 0), on alm p = 0.031 (0 vs 6), on mention p = 1 (11 vs
11). Fallbacks (guard E): ftFg 18, ftPg 12, ftQg 11, of 240.

## What it means

- **Balancing moved ftQ halfway between ftFg and ftP on every axis.**
  - `alb`: ftFg 0.33, ftQ 0.53, ftP 0.67.
  - `alm`: ftFg 0.97, ftQ 0.77, ftP 0.73.
  - `mal` called insufficient: ftFg 0, ftQ 3, ftP 14.
  - `ins` called malicious: ftFg 12, ftQ 4, ftP 0.
- **The `alb` gain costs `alm` one for one** (6 discordant cases each way). On these hand-written sets, a delta
  that makes the model more sceptical of the generic alert does so for attack windows too. Three different mixes
  (docs 45, 46 and 47) have moved along the same trade-off and none got off it.
- **The caution fixes held:** `ins` called malicious fell from 12 to 4, with no loss of mention, canary-safety,
  grounding or Romanian.
- **On this set ftFg is better on `alb` than on v10** (0.33 vs 0.20) and worse on `ins` (12 vs 7). The subsets
  are 20–30 cases, so per-set numbers move by several cases between hand-written sets.

**Conclusion of docs 45–47.** Changing the delta's data has not given a triage model that reads the generic L1
alert better without losing attacks. The alert card carries too little for the explainer to separate the two
reliably. The next lever is the card, not the model: let the sensor say which numbers changed (the device already
knows its own baseline), so the explainer is not asked to infer that from a generic alert.

## Training

- **Start:** ftFg rebuilt (bf16, re-checked: 310/310 tensors re-export identical).
- **Data:** 4,103 train / 214 valid.
  - Components kept for training: alert 833, alertc 280, albx 551, almx 535, paira 365, rep 1,320, repi 219.
  - Verdict balance: alert windows 1,482 attack / 1,082 not; other windows 1,020 / 519.
- **Teacher on almx:** kept 563/600 (rejected: mention 28, citation 9).
- **Training:** 1 epoch, 1,026 iterations. The selected checkpoint is 900 (valid 0.170; it was 0.333 at step 1).
- **Adapter SHA-256:** `0ce10cd1cdd78f4104e35f38a7c2114cbcdb8ad2aed30ff38a01016ce32be2a7`.
- **GGUF q8_0 SHA-256:** `3b78c0f9e0c82818d39d9222d1a813351f4c5eb5a73e083be181f98e4136de0a`.
- **Run:** chain 17:20 → 18:55 on 2026-11-25, inside the operator's 19:30 window, from the frozen worktree at
  `a9478032` (the pre-registration commit).

## End to end (operator rule): run 10 on the attack fixture

| | run 7 (ftFg) | run 8 (ftN) | run 9 (ftP) | run 10 (ftQ) | Expectation |
|---|---|---|---|---|---|
| SSH brute force (L1 alert) | insufficient | suspicious | insufficient | **insufficient** | malicious/suspicious ❌ |
| Telnet scan (L1 alert) | malicious | suspicious | insufficient | **malicious** | malicious/suspicious ✅ |
| Quiet windows (20) | 20 insufficient | 3 suspicious | 20 insufficient | **20 insufficient** | none malicious ✅ |
| Hallucination-free | 22/22 | 19/22 | 19/22 | 19/22 | — |
| Services on cards | 21/22 | 22/22 | 21/22 | 20/22 | — |

The investigation step (ftM) chose the same tools as before: `query_flows` on H1 and `lookup_reputation` on R1. This
run is reported, not gated. Stage costs: explainer median 1.14 s, investigation 0.39 s per turn.

## Next

- ftFg + guards A/E/G stays deployed; no `svc=` on the device.
- Stop changing the triage data for the generic alert. Propose instead that the sensor states what changed on the
  card, for example `det=behaviour_change[-,sev2,alert, l1] Δ=fanout_hosts,fail` (a card-contract change that the
  Conductor and the kernel side must agree to first).
- Blind v11 is spent.
