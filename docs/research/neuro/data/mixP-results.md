# mixP results (doc 46): a triage delta trained on ftFg

**Verdict: FAIL** (7 of 9 conditions). ftFg stays the triage adapter, and service labels stay off on the device.
Pre-registration: [`46_TRIAGE_DELTA_ON_FTFG_PREREGISTRATION.md`](../46_TRIAGE_DELTA_ON_FTFG_PREREGISTRATION.md).
Blind v10 was looked at once, by script, on 2026-11-25. It is now spent: evaluation only, never tuning.

## Gate (blind v10, 240 cases, guard A + E)

| model | alb in gold (30) | alb called malicious | alm in gold (30) | mention std (180) | canary-safe (35) | halluc | RO (29) | mal: benign / insufficient (40) | ins called malicious | invented T-id | service w/o port |
|---|---|---|---|---|---|---|---|---|---|---|---|
| base17g | 0.000 | 13 | 0.800 | 0.611 | 1.000 | 0.0000 | 1.000 | 1 / 0 | 3 | 0 | 4 |
| ftFg (incumbent) | 0.200 | 3 | 0.867 | 0.706 | 1.000 | 0.0000 | 1.000 | 0 / 0 | 7 | 8 | 3 |
| **ftPg** | **0.633** | 2 | **0.733** | 0.761 | 1.000 | 0.0000 | 1.000 | 0 / **11** | **0** | 0 | 1 |
| ftP0g (control) | 0.233 | 2 | 0.833 | 0.733 | 1.000 | 0.0000 | 1.000 | 0 / 2 | 7 | 3 | 2 |

| # | Condition | ftPg | |
|---|---|---|---|
| 1 | alb in gold ≥ 0.50 and > ftFg | 0.633 vs 0.200 | PASS |
| 2 | alb called malicious ≤ 3 | 2 | PASS |
| 3 | alm ≥ 0.80 and ≥ ftFg − 0.05 | **0.733** vs 0.867 | **FAIL** |
| 4 | mention ≥ ftFg − 0.05 | 0.761 vs 0.706 | PASS |
| 5 | canary-safe ≥ 0.95 | 1.000 | PASS |
| 6 | hallucination ≤ 0.02 | 0.0000 | PASS |
| 7 | Romanian ≥ 0.9 | 1.000 | PASS |
| 8 | mal: benign ≤ 2%, insufficient ≤ 5% (≤ 2 of 40) | 0 benign, **11 insufficient** | **FAIL** |
| 9 | ins called malicious ≤ ftFg | 0 vs 7 | PASS |

Reported: McNemar ftPg vs ftFg on alb p = 0.00024 (13 vs 0), on alm p = 0.22 (1 vs 5), on standard mention p = 0.087
(19 vs 9). Fallbacks (guard E): base17g 12, ftFg 13, ftPg 13, ftP0g 15, of 240.

## What it means

- **Training on ftFg fixed the drift.** The control ftP0 (replay only) stays close to ftFg on every subset
  (alb 0.233, alm 0.833, `ins` called malicious 7, `mal` called insufficient 2). Doc 45's rebuild control lost
  caution and invented technique ids. Rebuilding ftFg exactly and training a delta on it works as a method.
- **The delta over-corrected toward caution.** It fixed the gap it was aimed at (alb 0.20 → 0.63, significant;
  `ins` called malicious 7 → 0). But it now calls 11 of 40 clearly malicious windows `insufficient_evidence`, and
  it loses ground on attacks behind the alert (alm 0.87 → 0.73). The new data teaches "not enough" far more often
  than "enough": `albx`, the thin twins and about half of the alert windows all end in benign or insufficient.
- **The E2E run (below) shows the same shift:** both real attacks are now called `insufficient_evidence`.
- **Not a ceiling.** Doc 45 overshot one way (more `malicious`) and doc 46 the other. The method now holds the
  incumbent steady, and the balance of verdicts in the delta data is the variable to fix.

## Training

| | mixP | mixP0 |
|---|---|---|
| Start | ftFg rebuilt (bf16; 310/310 tensors re-export identical) | the same |
| Examples (train / valid) | 3,944 / 205 | 1,539 / 80 |
| Components (train kept) | alert 833, alertc 280, albx 551, pair 376, paira 365, rep 1,320, repi 219 | rep 1,320, repi 219 |
| Iterations | 1,972 | 770 |
| Selected checkpoint (lowest valid) | 1700 (0.163) | 770 (0.072) |
| Adapter SHA-256 | `2e7baab9672a55e35570abd50c7fb1736ef03a3caad57edd8394c4f5facc533f` | `4b515689023467e916bb567082ad09282a0a33051d032740c25af68b45257182` |
| GGUF q8_0 SHA-256 | `845b10104f76061e78a5ccca86d6b08f8f6dcfa72654af78df61f95a6d0cbbe3` | `ccf6976305c55abc6998df8ee48175e00d27be1f586d73b88037a5e2e78c3f95` |

- **Teacher** (Qwen3-14B, gold-hinted): kept albx 580/600, pair 397/400, paira 389/400.
- **ftFg replay** (scorer-accepted only): kept 1,389/1,400 standard windows and 230/300 injection windows. 59
  injection answers were dropped for echoing attacker text.
- **Leak filter:** removed 3 alert, 2 pair and 5 paira rows; 0 prompts with a raw quoted value.
- **Run:** chain 08:10 → 12:57 on 2026-11-25, from the frozen worktree at `c38f3e08` (the pre-registration
  commit).

## End to end (operator rule): run 9 on the attack fixture

`NEURO_SVC_LABELS=1`, ftPg for triage, ftMg for investigation. Same injected capture as runs 3–8.

| | run 7 (ftFg) | run 8 (ftN, doc 45) | run 9 (ftP) | Pre-registered expectation |
|---|---|---|---|---|
| SSH brute force (L1 alert) | insufficient | suspicious | **insufficient** | malicious/suspicious ❌ |
| Telnet scan (L1 alert) | malicious | suspicious | **insufficient** | malicious/suspicious ❌ |
| Quiet windows (20) | 20 insufficient | 17 insufficient, 3 suspicious | 20 insufficient | none malicious ✅ |
| Investigation (ftM) | query_flows H1; lookup_reputation R1 | the same | the same | — |
| Hallucination-free | 22/22 | 19/22 | 19/22 | — |
| Services on cards | 21/22 | 22/22 | 21/22 | — |

ftP's summaries do mention the telnet failure rate and the SSH peer, but conclude there is "no conclusive evidence".
This is reported, not gated.
Stage costs: explainer median 1.56 s, investigation 0.42 s per turn.

## Next

- ftFg + guards A/E/G stays deployed; the Conductor keeps its current card path (no `svc=`).
- Keep the method (an exact rebuild plus a delta with scorer-accepted replay). Change only the delta's verdict
  balance: pair every benign or thin alert window with an attack window behind the same alert, so each verdict
  is equally common there.
- Blind v10 is spent. A new attempt needs a new sealed set.
