# mixN results (doc 45): triage on the generic L1 alert, with service labels

**Verdict: FAIL** (6 of 8 conditions). ftFg stays the triage adapter, and service labels stay off on the device.
Pre-registration: [`45_TRIAGE_L1_ALERT_PREREGISTRATION.md`](../45_TRIAGE_L1_ALERT_PREREGISTRATION.md). Blind v9 was
looked at once, by script, on 2026-11-25. It is now spent: evaluation only, never tuning.

## Gate (blind v9, 240 cases, guard A + E)

| model | alm in gold (30) | alb in gold (30) | alb called malicious | mention std (180) | canary-safe (35) | halluc | RO (29) | mal: benign / insufficient (40) | ins called malicious | invented T-id | service w/o port |
|---|---|---|---|---|---|---|---|---|---|---|---|
| base17g | 0.833 | 0.000 | 1 | 0.467 | 1.000 | 0.0000 | 1.000 | 6 / 0 | 8 | 0 | 2 |
| ftFg (incumbent) | 0.967 | 0.133 | 0 | 0.489 | 1.000 | 0.0000 | 1.000 | 0 / 0 | 10 | 0 | 2 |
| **ftNg** | **1.000** | **0.367** | 3 | 0.511 | 1.000 | 0.0000 | 1.000 | 0 / **3** | **11** | 0 | 1 |
| ftN0g (control) | 0.967 | 0.133 | 15 | 0.567 | 1.000 | 0.0000 | 1.000 | 1 / 4 | 15 | 10 | 0 |

| # | Condition | ftNg | |
|---|---|---|---|
| 1 | alm ≥ 0.70 and > ftFg | 1.000 vs 0.967 | PASS |
| 2 | alb called malicious ≤ 3, in gold ≥ ftFg − 0.05 | 3; 0.367 vs 0.133 | PASS |
| 3 | mention ≥ ftFg − 0.05 | 0.511 vs 0.489 | PASS |
| 4 | canary-safe ≥ 0.95 | 1.000 | PASS |
| 5 | hallucination ≤ 0.02 | 0.0000 | PASS |
| 6 | Romanian ≥ 0.9 | 1.000 | PASS |
| 7 | mal: benign ≤ 2%, insufficient ≤ 5% (≤ 2 of 40) | 0 benign, **3 insufficient** | **FAIL** |
| 8 | ins called malicious ≤ ftFg | **11** vs 10 | **FAIL** |

Reported: McNemar ftNg vs ftFg on alm p = 1 (1 vs 0), on standard mention p = 0.597 (18 vs 14). Fallbacks (guard
E): base17g 7, ftFg 13, ftNg 10, ftN0g 7, of 240.

## What it means

- **The premise was weaker than measured on the E2E fixture.** On blind v9, ftFg already reads a generic L1 alert on
  malicious windows (alm 0.967). The real gap is the benign side: ftFg gets only 0.133 of `alb` (alert on a benign
  window) right. ftN more than doubles that (0.367) but still gets most of them wrong.
- **ftN fails narrowly, on caution.** One extra `insufficient_evidence` on a malicious window (3 vs a cap of 2) and
  one extra `malicious` on an insufficient window (11 vs 10). Neither difference is significant on its own; the
  pre-registered rule says a fail is a fail.
- **The rebuild drifted.** The control ftN0 (same recipe, no alert data) is not ftFg: 15 `alb` called malicious,
  15 `ins` called malicious, and 10 invented technique ids. The alert components mostly repair that. So part of
  what ftN fixes is damage from re-implementing ftFg's uncommitted recipe, not only the L1-alert gap.
- **Service labels did not hurt.** Mention, canary-safety, hallucination and Romanian held for ftN and ftN0.

## Training

| | mixN | mixN0 |
|---|---|---|
| Examples (train / valid) | 4,945 / 257 | 3,832 / 199 |
| Components | main, inj, con, alert, alertc | main, inj, con |
| Iterations | 2,473 | 1,916 |
| Selected checkpoint (lowest valid) | 2473 (0.206) | 1400 (0.203) |
| Adapter SHA-256 | `04a4e444be45a243e313bda4eac6429155bd725b912b23c2d247ee1856ba872f` | `e6340f473a9770ca4314187789ec6fe13ddc427a710b454b0be649db5036f1b2` |
| GGUF q8_0 SHA-256 | `be2fbb3ce3014bcb054961fe67ef378e05f1558f39472a6064645ea17d79a4e6` | `2fc0eda2199c38fb471681d2e8946271ca8d7519945c75553fe9fe40f780e92f` |

Teacher Qwen3-14B-Q4_K_M (guard A, gold-verdict hints, teacher-side only). Leak filter kept 2,766/2,774 main,
221/221 inj, 845/845 con, 833/836 alert, 280/280 alertc; 0 prompts with a raw quoted value. Chain run 2026-11-24
17:00 → 2026-11-25 01:33 from the frozen worktree at `6632ba76` plus the §8 labeller fix.

## End to end (operator rule): run 8 on the attack fixture

`NEURO_SVC_LABELS=1`, ftNg for triage, ftMg for investigation. Same injected capture as runs 3–7
([`e2e-attack-2026-11-24.md`](e2e-attack-2026-11-24.md)).

| | run 7 (ftFg, no labels) | run 8 (ftNg, labels) | Pre-registered expectation |
|---|---|---|---|
| SSH brute force (L1 alert) | `insufficient_evidence` | `suspicious`, "port 22 (SSH)" | malicious/suspicious, not NTP or "no detection" ✅ |
| Telnet scan (L1 alert) | `malicious` | `suspicious`, "port 23 (telnet)" | malicious/suspicious ✅ |
| Quiet windows (20) | 20 insufficient | 17 insufficient, 3 suspicious | none malicious ✅ |
| Investigation (ftM) | `query_flows` H1; `lookup_reputation` R1 | the same | — |
| Schema / citations | 22/22 / 19/22 | 22/22 / 19/22 | — |
| Hallucination-free | 22/22 | **19/22** | — |
| Services on cards | 21/22 | 22/22 | — |

All three expectations hold, but this is reported, not gated, and it is two alerts. Two warnings for the next
attempt: ftN called 3 quiet windows suspicious (ftFg: 0), and 3 answers named an entity not on the card (ftFg: 0).
Stage costs: capture→DNA 11.8 ms/window, S1 1.6 µs/window, explainer median 1.25 s, investigation 0.36 s per turn.

## Next

- ftFg + guards A/E/G stays deployed; the Conductor keeps its current card path (no `svc=`).
- The `alb` gap is real and measured. A next attempt should commit its data recipe and seeds first, so the control
  matches the incumbent, and should add benign-alert contrast without lowering caution on `ins`.
- Blind v9 is spent. A new attempt needs a new sealed set.
