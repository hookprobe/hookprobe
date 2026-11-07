# dga-lm — model card (SEED / BASELINE, not a trained model)

**Status:** seed placeholder. This is NOT a trained classifier. Per ADR 0014, the real
dga-lm model is trained OFF-DEVICE on a labelled DGA/benign domain corpus and quantized
by this same script (`--from-checkpoint`, not yet implemented — see the script's
docstring). This checked-in blob exists so the int8 embed -> conv -> pool -> dense
compute graph, the int8 dot-product kernels (`dot.rs`: relaxed-dot / simd128-widening /
scalar), the two-stage SDOT gate, and QSECBIT's `p_attack` wiring can all be exercised
and tested end to end before a real model exists.

## What it actually computes

Two hand-derived, well-known coarse lexical heuristics, implemented as int8 conv
channels 0 and 1 (channels 2-31 are inert zero-weight headroom for real trained
features):

1. **Digit density vs vowel density** per 4-character window — DGA domains skew
   digit-heavy and vowel-sparse more often than dictionary-word domains.
2. **4-consecutive-consonant runs** — a classic "unpronounceable string" tell.

Score = softmax(dense(maxpool(relu(conv(embed(domain)))))) — see `../src/model.rs`.

## What it is NOT

- Not trained on any real DGA or benign corpus.
- Not validated against a held-out test set, ROC/AUC, precision/recall, or any of the
  metrics a real model card would report — there are none to report yet.
- Not a substitute for HYDRA's IOC/threat-intel DGA feeds — this is a fast, local,
  CPU-only, advisory/observe-only signal (C9), not the platform's DGA detector of record.

## Shape / footprint

- Vocabulary: 40 symbols, 16-dim int8 embedding.
- Input: 24 characters (truncate/left-pad).
- Conv: kernel=4, 32 output channels (2 active, 30 inert headroom).
- Dense: 32 -> 2 logits (benign, dga).
- Blob size: 2900 bytes (2.83 KiB) — budget is 256 KiB (L2-resident,
  base-tier-build-ticket.md Phase 4 A76 budget row). This seed uses well under 1% of
  that budget; a real trained model has ~250x headroom to grow within the same budget.

## Regeneration

`python3 ci/quantize.py` regenerates `dga_seed.bin` + this file deterministically (no
randomness, no external inputs) — the seed weights are hand-derived constants in this
script, not sampled. `python3 ci/quantize.py --check` verifies the checked-in blob is
byte-identical to what this script generates (CI drift gate).
