# mixS results (doc 51): varied tool results, unchanged first-check data

**Verdict: FAIL** (conditions 1 and 2). ftM stays the investigation adapter. Pre-registration:
[`51_INVESTIGATION_VARIED_RESULTS_PREREGISTRATION.md`](../51_INVESTIGATION_VARIED_RESULTS_PREREGISTRATION.md).
Inv-blind v5 was looked at once, by script, on 2026-11-25. It is now spent.

## Gate (inv-blind v5, 175 cases, guard A)

| model | next+multi (80) | next (45) | multi (35) | alert (25) | decoy exact (25) | invisible (15) | grounding | policy on decoy | tool calls |
|---|---|---|---|---|---|---|---|---|---|
| base17g | 0.150 | 0.244 | 0.029 | 0.000 | 0.680 | 0.800 | clean | 0 | 89 |
| ftMg (incumbent) | 0.512 | 0.733 | 0.229 | 0.800 | 0.800 | 1.000 | clean | 0 | 102 |
| **ftSg** | **0.450** | **0.578** | **0.286** | 0.800 | 0.880 | 0.933 | clean | 0 | 108 |

| # | Condition | ftSg | |
|---|---|---|---|
| 1 | multi > ftM **and** next+multi > ftM | multi 0.286 > 0.229, but next+multi 0.450 < 0.512 | **FAIL** |
| 2 | next ≥ ftM − 0.05 | 0.578 vs 0.733 | **FAIL** |
| 3 | alert ≥ ftM − 0.05 | 0.800 vs 0.800 | PASS |
| 4 | decoy ≥ ftM − 0.05 | 0.880 vs 0.800 | PASS |
| 5 | invisible ≥ 0.80 | 0.933 | PASS |
| 6 | grounding / policy on decoy | 0 / 0 / 0 | PASS |

McNemar ftSg vs ftMg on next+multi (reported): p = 0.33 (6 vs 11).

## What it means

- **Keeping the first-check data byte-identical did not protect the first check.** ftS trained on exactly ftM's
  `next`, `alert`, `decoy` and `invisible` rows, and still lost 7 of 45 first checks (0.733 → 0.578).
- **Together, docs 49 and 51 show the cause is the multi-step training itself.** Teaching the model to move on after a
  result, or to propose a policy, also makes it switch tools or stop on windows that have no result. It is the same
  kind of trade-off as docs 45–47 on triage.
- **The multi-step gain is small:** 0.229 → 0.286, which is 2 of 35 cases.
- **E2E run 12 is correct.** ftS chose `query_flows` on the camera for the scan and `lookup_reputation` on R1 for the
  SSH brute force, as ftM does (run 11 with ftR made no call).

## Training

- **Data:** ftM's adapter (`5cc933ba…`, re-export checked) continued on 1,165 train / 62 valid rows.
  - 595 + 32 of those are ftM's own rows without a RESULT line, byte for byte.
  - 570 + 30 are gen v6 multi/clears rows (seed 5101; 38 RESULT phrasings).
- **Training:** 1 epoch, 292 iterations, learning rate 5e-5. Selected checkpoint: 292 (valid 0.014; 0.336 at step
  1).
- **Artefacts:** adapter SHA-256 `85f2690719ce039c80ca184af7ed92c452a7f7638eb5d976c9def966af2a2a11`; GGUF q8_0
  `b973cf06024b28fa466ded6ca7b5ecd55b86864abf9ecf578f6d0c57ebdbb94d`.
- **Run:** 20:07 → 20:25 on 2026-11-25, from the frozen worktree at `3df7db1d` (the pre-registration commit).

## End to end: run 12 (ftFg triage, ftSg investigation)

| Alert | run 7 (ftM) | run 11 (ftR) | run 12 (ftS) | Expected |
|---|---|---|---|---|
| Telnet scan | `query_flows` H1 | no call | **`query_flows` H1** | ✅ |
| SSH brute force | `lookup_reputation` R1 | no call | **`lookup_reputation` R1** | ✅ |

The investigation turn's median is 0.38 s. This is reported, not gated.

## Next

- ftM stays. Nothing changes for the Conductor.
- **Stop retraining ftM for multi-step.** A better route is structural, mirroring doc 40's rule T for triage:
  - the first check stays with ftM;
  - after a result, a deterministic rule decides "conclusive → propose a policy" from the playbook, which already
    lists each technique's steps and clears condition;
  - the model only chooses among the playbook's remaining steps.
- That is a design for a later doc, and it needs the Conductor's harness turn (#1615) to carry the playbook step.
