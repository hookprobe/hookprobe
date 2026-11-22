# Doc 26 dev result: mixF / ftFg (2026-11-22)

This applies the doc 26 §B selection rule, fixed before any data existed, on the four **spent** sets: dev v2,
blind v3, blind v4 and blind v5. That is 920 triage + injection cases, 211 of them with real injections in quoted
fields. Every configuration ran GGUF + grammar, temperature 0, with guard A + E.

| config | mention (920) | per set d2 / b3 / b4 / b5 | McNemar vs base17g-AE | canary-safe, quoted (211) | hallucination | benign verdict on malicious | E fallback |
|---|---|---|---|---|---|---|---|
| base17g-AE | 0.489 | 0.537 / 0.392 / 0.436 / 0.604 | — | 1.000 | 0.000 | 5.8% | 4.4% |
| ftDg-AE | 0.579 | 0.651 / 0.543 / 0.524 / 0.620 | p = 7.4e-08 (160 vs 77) | 1.000 | 0.000 | 12.9% | 6.3% |
| **ftFg-AE** | **0.590** | 0.634 / 0.478 / 0.584 / 0.676 | p = 1e-09 (163 vs 70) | 1.000 | 0.000 | **0.6%** | 5.8% |

**Eligible:** ftFg-AE and ftDg-AE. **Selected: ftFg-AE** (higher combined mention), so blind v6 proceeds per doc 26 §C.

## What changed

- **The over-benign shortcut is gone on dev.** On malicious cases, ftFg gives a benign verdict 0.6% of the time,
  against 12.9% for ftDg and 5.8% for the base model. This is the metric doc 26 targeted (reported, not selected on).
- **Mention rose on blind v4 and v5** (+0.060, +0.056 over ftDg) and **fell on blind v3** (−0.065). The pooled gain
  over ftDg is small (+0.011). The real test is blind v6.
- Injection safety is unchanged at 211/211.

## Caveats

- These four sets are dev material. Blind v3, v4 and v5 were spent before doc 26 and were used for diagnosis, so this
  is not a held-out result.
- **What came out of building the training data:**
  - teacher kept 894 of the 900 contrast windows;
  - mixF has 4,448 train and 224 valid examples;
  - prompts with a quoted value left raw: 0;
  - the injection component lost 151 of 700 teacher answers to the echo filter.
- **Training:** the checkpoint at 2,200 iterations had the lowest T0-valid loss, 0.230.

## Reproducibility

| Artefact | SHA-256 |
|---|---|
| `gguf-mixF-q8_0.gguf` (ftFg) | `0b0d276ed5a9f0a5b6597830c3f751411db6d62f3d962ec58e1f12d19f3161ed` |
| `ft-mixF/adapters.safetensors` | `142c5a78e25b7f9f1272424f448b4a612612054ee4f542eddb5006acc1c6c381` |
| `mixF/train.jsonl` | `e39cae9eb0d5c34109bc78be4554094e8c1468340ead73a51ef4fe411a26500a` |
| `mixF/valid.jsonl` | `806ee63edc21b4294d1beef94c8e59df15a3f625a1bada251bd0fe1591ff285c` |
| `t0v3c_cases.jsonl` (contrast) | `78572160e904d80d3d1414af6abcfe17592c6b701b1ce4c5e6e853c68be47ba1` |
| `teacher-c.json` | `22dc7abaf6ddc6d6d24704a7967540299de4e7959f587fe1f35346805fecfb1f` |

**Pipeline:** `tools/neuro-research/mixF_chain.sh` and `mixF_select.py`. Code changes: `gen_t0_v3.py`
(`f_contrast`) and `build_sft.py` (`--redact-all`).
