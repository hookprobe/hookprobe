# mixR results (doc 49): restoring the investigation multi-step targets

**Verdict: FAIL** (condition 1). ftM stays the investigation adapter. Pre-registration:
[`49_INVESTIGATION_MULTISTEP_FIX_PREREGISTRATION.md`](../49_INVESTIGATION_MULTISTEP_FIX_PREREGISTRATION.md).
Inv-blind v4 was looked at once, by script, on 2026-11-25. It is now spent.

## Gate (inv-blind v4, 175 cases, guard A)

| model | next+multi (80) | next (45) | multi (35) | alert (25) | decoy exact (25) | invisible (15) | unreturned CVE | invented T-id | policy on decoy | tool calls |
|---|---|---|---|---|---|---|---|---|---|---|
| base17g | 0.125 | 0.156 | 0.086 | 0.120 | 0.440 | 0.867 | 0 | 0 | 0 | 110 |
| ftMg (incumbent) | 0.362 | 0.556 | 0.114 | 0.680 | 0.920 | 1.000 | 0 | 0 | 0 | 87 |
| **ftRg** | **0.325** | **0.400** | **0.229** | 0.680 | 0.960 | 1.000 | 0 | 0 | 0 | 84 |

| # | Condition | ftRg | |
|---|---|---|---|
| 1 | next+multi ≥ 0.60 and > ftMg | 0.325 vs 0.362 | **FAIL** |
| 2 | alert ≥ ftMg − 0.05 | 0.680 vs 0.680 | PASS |
| 3 | decoy ≥ ftMg − 0.05 | 0.960 vs 0.920 | PASS |
| 4 | invisible ≥ 0.80 | 1.000 | PASS |
| 5 | grounding / policy on decoy | 0 / 0 / 0 | PASS |

McNemar ftRg vs ftMg on next+multi (reported): p = 0.63 (7 vs 10).

## What it means

> **Note added 2026-11-28 (doc 54):** this run's training data had a generator defect. "Move on" golds named the
> first step's target instead of the new step's (68 of 73 in gen v5, 154 of 162 in gen v6). The conclusion below
> that multi-step training *itself* costs the first check is therefore confounded. Doc 54 re-runs doc 51 with only
> that fixed.

- **The fix did what it targeted, at a cost elsewhere.** Multi-step accuracy doubled (0.114 → 0.229), but the first
  check fell (0.556 → 0.400). Neither change is significant on its own; the sum is slightly worse.
- **Inv-blind v4 is harder than v3 for every model.** ftM scored 0.556 on next and 0.114 on multi, against 0.733
  and 0.257 on v3. Even the gate's 0.60 floor was out of reach for both models.
- **Multi-step stays weak even with the right targets:** 0.23 on 35 hand-written cases. The synthetic RESULT lines
  (four fixed phrases per tool) may be too narrow for the author's wording of real tool results.
- **E2E run 11 regressed** (below). On both real alerts ftR made no tool call, where ftM chose the pre-registered
  checks. That matches its lower first-check score.

## Training

- ftM's adapter (`5cc933ba…`, re-export checked: 310/310 tensors identical to ftMg) continued on 900 gen v5 cases
  (seed 4901): 855 train / 45 valid, 546 tool calls and 354 stops. 1 epoch, 214 iterations, learning rate 5e-5.
- Selected checkpoint: 200 (valid 0.010; 0.408 at step 1).
- Adapter SHA-256 `76fdeffa19288dc1c52277f5cb17ee878a8c683e1eba5c9875e4600a213173a7`; GGUF q8_0
  `3da86e16a9e917517786c7d68aab3483136142275593c711ce263d990740cd5f`.
- Run: 19:48 → 20:01 on 2026-11-25, from the frozen worktree at `88fea981` (pre-registration plus the §7 addendum).

## End to end (operator rule): run 11 on the attack fixture

Triage ftFg (guards A/E/G); investigation ftRg.

| Alert | run 7 (ftM) | run 11 (ftR) | Expected (doc 44) |
|---|---|---|---|
| Telnet scan | `query_flows` H1 | **no call** | `query_flows` on the camera ❌ |
| SSH brute force | `lookup_reputation` R1 | **no call** | `lookup_reputation` on R1 ❌ |

The investigation turn's median is 0.30 s. This is reported, not gated.

## Next

- ftM stays; nothing changes for the Conductor (GGUF and `inv_contract*.json` unchanged).
- Generator v5 stays in the tree as the correct multi-step generator; v4 is unchanged.
- A further attempt should make the RESULT wording varied, as real tool output would be, before training again. It
  should also keep the first-check data unchanged, so the first check cannot regress.
