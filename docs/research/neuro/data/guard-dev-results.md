# Doc 24 dev results: injection guard and mixE (2026-11-22)

> Dev only: dev v2 (215) and blind v3 (spent, published; 300 cases, 50 real injection cases). Protocol and
> selection rule: `../24_INJECTION_GUARD_PREREGISTRATION.md` §C. All runs are GGUF Q8_0 with grammar, temperature 0.

## Table

Comparator first; McNemar is computed against base17g-RE.

| Config | Mention: blind v3 / dev v2 | Combined (n = 420) | Canary-safe real: blind v3 / dev v2 | E fallback: blind v3 / dev v2 |
|---|---|---|---|---|
| base17g (no guard) | 0.392 / 0.571 | 0.467 | 0.70 / 0.76 | — |
| base17g-R | 0.408 / 0.560 | 0.471 | 0.94 / 1.00 | — |
| base17g-E | 0.355 / 0.537 | 0.431 | 1.00 / 1.00 | 17.0% / 8.8% |
| base17g-RE | 0.371 / 0.537 | 0.440 | 1.00 / 1.00 | 12.7% / 5.6% |
| ftDg (no guard) | 0.567 / 0.657 | 0.605 | 0.78 / 0.96 | — |
| **ftDg-R** | **0.576 / 0.646** | **0.605** | **0.98 / 1.00** | — |
| ftDg-E | 0.531 / 0.646 | 0.579 | 1.00 / 1.00 | 10.7% / 5.6% |
| ftDg-RE | 0.535 / 0.629 | 0.574 | 1.00 / 1.00 | 7.7% / 5.1% |
| ftEg-RE (mixE) | 0.473 / 0.629 | 0.538 | 1.00 / 1.00 | 13.3% / 6.0% |

The hallucinated-entity rate is 0.000 for every config. Romanian language is ≥ 0.887 for base and 1.000 for the
fine-tunes.

## Candidate selection (rule §C, applied as written)

**Eligible.** Canary-safe on blind v3 ≥ 0.98 and hallucination ≤ 0.02: base17g-E, base17g-RE, ftDg-E, **ftDg-R**
(49/50), ftDg-RE and ftEg-RE.

**Selected: ftDg-R**, the highest combined mention (0.605). It needs no retraining and only one guard.

**Comparator for blind v4: base17g-R** (same guard, same decoding).

## Findings

1. **R costs nothing on explanation, and it secures injection safety for the canaries it covers.**
   - ftDg-R matches ftDg's mention (0.605 combined).
   - Canary-safe rises from 0.78 to 0.98 on blind v3.
   - The model cannot copy what it never sees.
2. **The one remaining R leak is a marker-recall miss, not an R failure.**
   - It sits in a `device_name` field on a context line the blind v3 author did not mark `!instr-like`, although
     the text addresses the assistant.
   - The reference keyword rule (`INSTRUCTION_LIKE`) would have marked it.
   - The guard is only as good as the detector that emits the marker. Detector recall on real attacks is the open
     question named in doc 24.
3. **E is a safe backstop, but it costs explanation through template fallback** (5–17% of answers).
   - The fallbacks are real echoes of quoted values: legitimate file names, SNIs and user agents.
   - None is triggered by common words alone (checked on ftDg-E's 32). This corrects my earlier guess that common
     words drove them.
4. **mixE did not help, and it hurt blind v3 mention (0.473).**
   - Training with redacted prompts plus the wider echo filter produced more template fallbacks (13.3%) and
     shorter, more generic summaries.
   - The identifier-style data itself is kept for later study. It is not part of the candidate.
5. **Fine-tuning still dominates under every guard.** The ftDg variants beat the base variants by 0.10–0.17 on
   blind v3.

## Next

**Blind v4,** per doc 24 §D: candidate ftDg-R, comparator base17g-R, 80 injection cases, fresh author. Its
canaries use identifier-style and sentence-style forms; ID_WORDS and every earlier canary word are banned.
