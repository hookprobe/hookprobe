# 16 — Our own small model for heqk: plan (start on the M5 Pro)

> 2026-11-18. **A plan.** Larger compute (2× DGX Spark, 256 GB total, or rented cloud GPUs) is used
> only when a stage has proven it needs it.

## 1. What the model is for

Phase 0 decided this, and it shapes everything that follows:
- **It explains; it does not judge.**
  - On the blind set, small models scored 0.37–0.50 on verdicts, about what a constant answer scores
    (0.41–0.43). The rules core (L0) scored 0.59.
  - As explainers on top of the L0 verdict they nearly tripled coverage, from 0.27 to 0.56–0.73.
- **Its task is narrow.**
  - Input: evidence cards, the L0 verdict and next step, the owner's language.
  - Output: a short explanation that cites fact IDs and names entity aliases, inside the closed schema.
  - It must ignore instructions embedded in telemetry.
- **It must fit heqk** (`00`, `07`, `12`):
  - a few hundred MB at most on 4 GB SKUs; ideally ≤ 150 MB;
  - low-bit (4-bit or ternary);
  - integer-friendly operations;
  - short contexts (evidence cards are about 500 tokens per hour);
  - a small vocabulary. The output head is 25–40% of per-token bytes in off-the-shelf small models.

Narrow and small is achievable. A general-purpose model of the same size is not useful here.

## 2. Stages

| Stage | What | Where | Gate to the next stage |
|---|---|---|---|
| **T0 Data** | Generate training inputs (contexts in the evidence-card format) from synthetic telemetry, IoT-23 replays and templated case families: incidents, false positives, insufficient evidence, injection inside telemetry, EN + RO. **Never from the blind set.** An **Apache-2.0 open-weight teacher** run locally writes reference explanations. Each one is auto-checked (schema, citations, no invented entities, canary refusal, language) before entering the set. | M5 Pro | ≥ 3K checked examples; no blind-set overlap (hash check) |
| **T1 Specialise an existing small model** | Fine-tune **Qwen3-0.6B** (Apache-2.0) on T0 with MLX, full fine-tune or LoRA. Evaluate on the blind set in the Phase 0 hybrid mode (L0 verdict + model explanation, closed decoding), against the same model unmodified. | M5 Pro (hours) | **fine-tuned 0.6B ≥ base Qwen3-1.7B (0.73 mention)** at ≤ 40% of its bytes, canary-safe ≥ 0.96, RO language ≥ 0.9 |
| **T2 Shrink** | Trim the vocabulary to EN/RO/security tokens; then quantisation-aware fine-tuning to 4-bit, then ternary (route 3 in `03`). Re-evaluate after each step. | M5 Pro; DGX Spark if QAT needs it | each step loses ≤ 0.02 mention and keeps canary safety |
| **T3 Our own architecture** | A 50–150M-parameter model designed for heqk: recurrent (RWKV-7-style) or few-attention-layer; ReLU²; an 8–16K vocabulary; trained **by distillation from T1/T2** (logits, not just text) on T0 + more generated data. | **2× DGX Spark** (≈ 1 week per run at 0.5B × 20B tokens; smaller is faster); cloud only if T3 needs more tokens | beats the T2 model at ≤ half its bytes, or stop and ship T2 |
| **T4 Ship** | HNX package (`06`), signed, eval report in provenance; runs on the heqk engine | heqk | needs HomePods R2 (FP/SIMD) and R3 (model region) — `12` |

## 3. Rules that keep it honest

- **Evaluation stays fixed:** the 215-case blind set, Phase 0 scorer, closed decoding, the L0-hybrid
  mode, constant-answer baselines printed alongside, McNemar for paired comparisons. The blind set is
  never used for training or prompt tuning.
- **The teacher licence must permit training on its outputs.** Use local Apache-2.0 open-weight models
  only (Qwen3 family).
  - **No commercial API outputs** (including Anthropic's) go into training data without a licence
    review. Several providers' terms restrict that use.
- **Provenance:** every model file is SHA-256-verified against its publisher's record, as in Phase 0.

## 4. First steps on the M5 Pro (24 GiB unified memory)

| Item | Source | Size | Licence |
|---|---|---|---|
| `mlx`, `mlx-lm` (+ deps) into the isolated scratch venv | PyPI | ~0.3 GB | MIT |
| llama.cpp `b12477` macOS arm64 (the Phase 0 build, sha256-verified) | github.com/ggml-org/llama.cpp | ~30 MB | MIT |
| **Teacher:** `Qwen/Qwen3-14B-GGUF`, Q4_K_M, the publisher's own repo | huggingface.co | ~9 GB | Apache-2.0 |
| **Student:** `Qwen/Qwen3-0.6B` safetensors, the publisher's own repo | huggingface.co | ~1.5 GB | Apache-2.0 |

**Expected costs on this machine:**
- teacher generation of 3K examples: a few hours (14B at 4-bit through Metal);
- T1 full fine-tune of 0.6B: about 1–2 hours per epoch at this data size.

These are estimates; they are measured in T1.
