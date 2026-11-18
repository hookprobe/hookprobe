# 03 — Model representations beyond GGUF (Gate 3)

> Native Inference Research Programme, 2026-11-18. Primary sources:
> - GGUF spec (`ggml/docs/gguf.md`), `ggml-common.h`, `repack.cpp`;
> - bitnet.cpp paper (arXiv 2502.11880) and repo;
> - BitNet b1.58 2B4T report (arXiv 2504.12285);
> - T-MAC (EuroSys '25);
> - earlier references in `NEURO_LITERATURE_REVIEW.md` §1–2 and `10` §5.
>
> Kernel costs come from `01`/`02`.

## 1. Representations, with cost on the A76

| Representation | Bits/weight (incl. scales) | Inner-loop cost on A76 (`02` §3) | Quality risk at ≤ 3B | Where it comes from |
|---|---|---|---|---|
| FP32 / FP16 / BF16 | 32 / 16 / 16 | FMLA: 8 MAC/cycle (fp32); **BF16 absent**; FP16 arithmetic present but 4× the bytes of Q4 | none | training formats; never for decode on CM5 |
| INT8 per-block (Q8_0) | 8.5 | 0.38 V-instr/weight; **bus-bound on one core** | negligible | post-training |
| INT4 per-block (Q4_0, ggml `4x4` repack on A76) | 4.5 | 0.47; near balance | small for ≥ 1B; measurable for 0.6B (not measured here) | post-training |
| K-quants (Q4_K, Q5_K, Q6_K) | 4.5–6.6 | super-blocks with 6-bit sub-scales; more decode work per weight | smaller than Q4_0 | post-training |
| Ternary, unpack to int8 + SDOT (bitnet.cpp I2_S) | 2 | 0.63; compute-bound | **only for models trained ternary** | QAT / native |
| **Ternary via LUT (T-MAC; bitnet.cpp TL1 on Arm)** | 2 | **0.34; no multiplies, no per-block convert** | same | QAT / native |
| Ternary TL2 (3 weights per 5 bits) | 1.67 | x86 only in the bitnet.cpp repo (`setup_env.py`: arm64 = i2_s, tl1) | same | native |
| Activation quantisation (int8 per block or per token) | — | needed for SDOT and for LUT tables | small | runtime |
| KV-cache quantisation (q8_0 KV) | — | halves the KV read (`07`) | small, to verify | runtime |
| Weight clustering / product quantisation | 2–4 + codebooks | table lookups (TBL) per sub-vector; codebook must fit 1–2 registers | moderate | post-training |
| Structured sparsity (2:4, N:M) | ~50% + metadata | **no sparse-dot instruction on A76**: gather costs exceed savings at 50% | moderate | training |
| Unstructured sparsity | variable | irregular gathers; poor on SIMD | — | reject for CPU decode |
| Low-rank decomposition | depends on rank | two smaller GEMVs; helps only if rank ≪ d | moderate–high | post-training + fine-tune |
| Weight sharing / tied embeddings | — | already common (Qwen3 ties the head) | none | architecture |
| **Vocabulary trimming** | — | cuts head size: 25–40% of per-token bytes in small models (`07`) | small if the target languages are kept [R165] | post-training |

## 2. The four routes to a low-bit model

| Route | Example | Quality at 2 bits | Cost to produce | Fit for HookProbe |
|---|---|---|---|---|
| 1. Trained in low bit from scratch | BitNet b1.58 2B4T (MIT, 4T tokens; average 54.19 vs Qwen2.5-1.5B 55.23 on its benchmark set) | **competitive** at 2B | enormous (4T tokens), not reproducible by HookProbe | use released checkpoints only |
| 2. Conventional model quantised after training | Qwen3 Q4_0 (Phase 0) | good at 4 bits; **collapses at ternary** (naive ternary PTQ of Mamba-2 → perplexity ~13M [R110]) | minutes | 4–8 bits only |
| 3. Quantisation-aware fine-tuning of a pretrained model | Ternary Mamba: Mamba-2-1.3B → W1.58A16 in ~4 H100-hours, 102M tokens, 48.1% zero-shot vs 48.4% for the scratch-trained Bi-Mamba [R110] | close to route 1, at a fraction of the cost (one paper, one architecture) | GPU-hours to GPU-days | **the realistic route to a ternary HookProbe specialist or a ternary RWKV**, which does not exist yet |
| 4. Architecture and kernels designed together | BitNet (BitLinear + subln + ReLU² + bitnet.cpp TL/I2_S); T-MAC | best per byte | research programme | long-term (`13` "later") |

**Strongest trade-off today:**
- **4-bit post-training** for general language models;
- **trained-ternary checkpoints (BitNet 2B4T)** where bandwidth matters most;
- **QAT ternary (route 3) as the research bet** for HookProbe-specific models. Specialists are small
  enough to train on modest hardware.

## 3. Can heqk consume packed ternary directly, without unpacking?

**Yes. This is already what the LUT kernel does.** `01` §4 and `02` §3 show the bit-plane LUT
kernel:
- reads packed 2-bit weights straight from memory;
- uses them **as table indices** (`tbl`);
- never forms an int8 weight vector;
- never multiplies.

The costs measured in instructions:

| Cost | Where | Amortisation |
|---|---|---|
| Table build: 16 subset sums per 4 activations | once per input vector per layer | over every row of the layer (thousands) |
| Index split: packed nibbles → lanes (`and`, `ushr`, combine) | per 16 rows × 4 weights | 6 of 29 instructions; avoidable by storing one row-group per register-width |
| Lo/hi byte tables for int16 sums (`zip1`/`zip2`) | per lookup | bitnet.cpp TL1_0 uses int8 tables (lossy) to avoid it; TL1_1 keeps int16 (lossless) |
| Scaling | **per tensor** (BitNet trains with absmean per-tensor scales) | once per row, outside the loop: no `scvtf` per block |
| Accumulation | int16 lanes, widened to int32 every 32 groups | 4 `saddw` per 32 groups |

**What remains unproven:** speed on the real A76 (E-N1). The model in `02` predicts ~17 Gweights/s
per core for packed LUT against ~15 for Q4_0.

## 4. Implications for the HNX format (`06`)

1. **Layout is part of the model, not the runtime.** ggml decides `q4_0_4x4` repacking *at load*
   ("online repacking"). On heqk the offline compiler should store the A76 layout directly:
   - interleaved rows for SDOT;
   - row-group bit-planes for the LUT.

   This removes a load-time pass and a second copy in RAM.
2. **Scale granularity is a kernel choice.** The format must record per-block, per-row or per-tensor
   scales, so the engine picks the kernel id without branching in the loop.
3. **No sparse formats in v1.** The A76 has nothing that makes them pay.
4. **Vocabulary trimming and the constraint tables for grammar-sparse logits belong in the package**,
   because they change the head's layout (`10` §3, rank 1).
