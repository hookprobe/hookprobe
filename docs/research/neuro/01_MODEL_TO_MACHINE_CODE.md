# 01 — From model to machine code (Gate 1)

> Native Inference Research Programme, 2026-11-18. Operation counts are **computed** from the
> architecture fields of the Phase 0 GGUF files (Qwen3-0.6B: 28 layers, d = 1,024, FFN 3,072,
> 16 query heads, 8 KV heads, head dim 128, vocab 151,936, tied embedding). Assembly is **real
> compiler output** (Apple clang 17, `-O3 -mcpu=cortex-a76`) of
> `tools/neuro-research/kernels/dot_kernels.c`, saved as `dot_kernels.a76.s`. Cycle estimates use
> the Cortex-A76 pipe data in `02` and are **theoretical**.

## 1. The execution path of one generated token (decoder transformer)

```
token id
  → embedding row lookup (1 row of vocab × d)                    memory: 1 row; trivial
  → for each of L layers:
       RMSNorm(x)                                                 d FLOPs ×~4, needs 1/sqrt
       quantise activation to int8 (per 32-block scale)           d ops; fusable into the norm
       q = Wq·x, k = Wk·x, v = Wv·x   (3 GEMVs)                   ← weight-bandwidth bound
       q/k RMSNorm per head (Qwen3), RoPE on q and k               ~ (Hq+Hkv)·hd ops, sin/cos table
       append k, v to the KV cache                                 write 2·Hkv·hd values
       scores = q·Kᵀ over ctx, softmax, out = scores·V             ← KV-bandwidth bound at long ctx
       o = Wo·out   (GEMV)                                         ← weight bound
       x += o                                                      in place
       RMSNorm, quantise
       g = Wg·x, u = Wu·x  (2 GEMVs), h = SiLU(g)⊙u               ← weight bound; SiLU needs exp
       x += Wd·h   (GEMV)                                          ← weight bound
  → final RMSNorm
  → logits = E·x  (vocab × d GEMV with the tied embedding)         ← the largest single GEMV
  → sampling: argmax, or masked by the grammar (closed decoding)
```

## 2. Where the work and the bytes are (Qwen3-0.6B, per token)

| Operation | MACs per token | Weight/KV bytes per token at Q4_0, f16 KV | Bound on A76 | Fusable with | Needs scratch | In place | Fixed-point possible | SIMD |
|---|---|---|---|---|---|---|---|---|
| Q, K, V, O projections | 28 × 6.3 M = 176 M | 93 MiB | bandwidth (Q4/Q8); compute (ternary) | quantise → GEMV | q, k, v (17 KB) | no | yes (int8 × int4 → int32) | SDOT |
| FFN gate, up, down | 28 × 9.4 M = 264 M | 140 MiB | as above | gate·up + SiLU + multiply in one pass | gate, up (24 KB) | down writes into residual | yes, except SiLU | SDOT |
| Output head (tied embedding) | 155.6 M | **158 MiB at Q8_0** (Q6_K in the file) | bandwidth | argmax / grammar mask | logits (594 KB f32) | — | yes | SDOT |
| Attention QKᵀ and ·V | 28 × 2 × 16 × 128 × ctx: **59 M at ctx 512, 235 M at 2,048** | KV: 56 MiB at 512, 224 MiB at 2,048 | bandwidth at long ctx | softmax online (one pass, no score buffer) | scores 16 × ctx f32 | — | partly (int8 KV + f32 softmax) | dot products on f16/int8 |
| RMSNorm (2 per layer + 2 per head-norm) | ~0.3 M | none | compute, tiny | quantise | none | yes | yes: integer rsqrt (Newton) | yes |
| RoPE | ~0.1 M | none | compute, tiny | QK kernel | sin/cos table (ctx × 64 × 2) | yes | yes: Q15 rotation | yes |
| Softmax | ctx × 16 × 28 exp | none | compute | QKᵀ kernel (online softmax) | none if online | yes | yes: exp LUT / polynomial (I-BERT-style) | yes |
| SiLU | 3,072 × 28 exp | none | compute | FFN kernel | none | yes | yes: LUT | yes |
| Embedding lookup | 0 | 1 row | — | — | — | — | — | — |
| Sampling | argmax over allowed tokens | — | — | output head | none | — | yes | yes |

**Totals at ctx 512:** ~655 M MACs, ~450 MiB moved per token. At 11.8 GB/s the bytes alone take
≈ 40 ms; at the A76's dot-product rate (`02`) the MACs take ≈ 30–60 ms on one core. **Decode on
CM5 is bandwidth-bound for 8-bit weights and near the balance point for 4-bit weights on one core.**
Ternary moves the bound to compute (§4).

What the table says to optimise, in order:
1. **bytes per weight** (format, `03`);
2. **the output head** (vocabulary size, sparse logits under a grammar: `07` §3, `10`);
3. **the KV cache** at contexts above ~1K (KV quantisation, or recurrence: `04`);
4. **fusion** of the small ops so that none of them adds a pass over memory.

Norms, RoPE, softmax and SiLU are < 1% of the work. Their only real cost is **floating point**,
which heqk traps today (`00`). All four have integer or fixed-point formulations with published
precedent (I-BERT, Kim et al., ICML 2021: integer-only GELU/softmax/LayerNorm). That makes an
**integer-only decode path** possible, apart from scale factors that can be fixed-point. It does not
remove the need for **NEON**, which heqk traps as well: SIMD integer instructions use the same
FP/SIMD register file (`02` §1).

## 3. Recurrent alternative (RWKV-7) — the same exercise

Per token per layer, RWKV-7 replaces attention with:
- token-shift interpolations (elementwise);
- r, k, v, o projections (4 GEMVs, d × d) plus small low-rank adapters for decay/in-context learning rate;
- a **state update** S ← S·(diag(w) + aᵀb) + vᵀk per head (64 × 64 per head; elementwise and outer products);
- a read-out r·S.

Channel-mix is 2 GEMVs (d × 4d and 4d × d) with squared ReLU, which is cheaper than SiLU and
integer-friendly. Differences that matter on a CM5:
- **no score buffer, no KV growth.** State is fixed: d × 64 values per layer (f32: 256 KiB per layer
  at d = 1,024).
- **the state is read and written every token.** At 24 layers, 6 MiB of state traffic per token is
  < 3% of the weight traffic. It sits in DRAM, but is small enough to be L3-warm per layer.
- **the state recurrence is sequential.** Prefill cannot use the parallel-scan trick on a CPU as
  effectively as attention uses matrix-matrix products. Prompt processing will be relatively slower;
  decode is not.
- **numerics:** the decay terms need exp, and the state is f32 in reference code. Fixed-point state
  is an open question with no precedent found yet (`10`).

## 4. The innermost loop in four representations (real A76 assembly)

All four compute a 2,048-element dot product. They were checked against a scalar reference on
the 32,768-row matrix used in `02` (0 mismatches).

**Q8_0 × Q8_0, per 32 weights** — 14 instructions, 4 × 128-bit loads, 2 SDOT:
```
ldur q1,[x0,#4] ; ldur q2,[x0,#20] ; ldur q3,[x1,#4] ; ldur q4,[x1,#20]
movi v5.2d,#0
sdot v5.4s,v1.16b,v3.16b ; sdot v5.4s,v2.16b,v4.16b      ← 32 MACs in 2 instructions
scvtf v1.4s,v5.4s ; ldr s2,[x0],#36 ; ldr s3,[x1],#36 ; fmul s2,s2,s3
fmla v0.4s,v1.4s,v2.s[0] ; subs x8,x8,#1 ; b.ne
```
The SDOTs are 2 of 14 instructions. The rest is per-block scaling (`scvtf`, `fmul`, `fmla`) and
loads. Larger blocks or a per-row scale would cut that overhead; that trade is a format decision
(`06`).

**Q4_0 × Q8_0** — 18 instructions; unpacking costs 4 (`and`, `add`, `movi`, `usra`). The compiler
folded "subtract 8" into a `usra` with a −8 bias, a neat trick.

**Ternary 2-bit, unpack then SDOT** — 23 instructions. Unpacking costs 9, and the compiler lost
efficiency on lane inserts (`mov v6.d[1], v5.d[0]`). **This is where hand-written assembly beats
the compiler.** A layout that stores the four 2-bit planes contiguously would let each plane decode
with one `ushr` + `and`.

**Ternary as bit-planes + lookup table (T-MAC/TL-style), per 16 rows × 4 weights** — 21–29
instructions for 64 weights, 4 `tbl`, no multiply at all:
```
ldr q6,[x2,x10] ; ldr q7,[x3,x10]         ← table (lo/hi bytes) for this activation group
ldr q16,[x0,x10] ; ldr q17,[x1,x10]       ← +1 and −1 masks of 16 rows
tbl v18.16b,{v6.16b},v16.16b ; tbl v16.16b,{v7.16b},v16.16b
tbl v6.16b,{v6.16b},v17.16b ; tbl v7.16b,{v7.16b},v17.16b
zip1/zip2 ×4                              ← reassemble int16 sums from byte tables
sub/add ×4                                ← (+ sums) − (− sums), accumulate
```

| Kernel | Instr. / weight | SIMD instr. / weight | Bytes / weight streamed (ggml-style f16 scales) |
|---|---|---|---|
| Q8_0 | 0.44 | 0.38 | 1.06 |
| Q4_0 | 0.56 | 0.47 | 0.56 |
| Ternary unpack + SDOT | 0.72 | 0.63 | 0.25–0.38 |
| Ternary LUT, unpacked indices | 0.36 | 0.25 | 0.50 |
| **Ternary LUT, packed (2 bits/weight)** | **0.45** | **0.34** | **0.25** |

**The lookup-table kernel needs no multiplier, no unpack-to-int8 and no per-block scaling.** Its
activation tables are rebuilt once per input vector: 16 entries per 4 activations, amortised over
every row of the layer. On A76 it is the cheapest ternary kernel per weight, and cheaper than Q4_0.
`02` turns these counts into cycles.

## 5. What can be eliminated by restructuring the model, not the code

| Cost | Restructuring | Status |
|---|---|---|
| Output head over 152K–248K tokens | trimmed vocabulary; sparse logits under grammar | hypothesis (`10`) |
| KV growth | recurrent layers (RWKV-7), or hybrid with few attention layers (Qwen3.5: 6 of 24) | measured memory (`07`); quality unknown |
| Per-block scales in the inner loop | per-row or per-tensor scales (BitNet trains with per-tensor absmean) | format choice (`03`) |
| Floating point in norms/activations | integer-only formulations (I-BERT); squared ReLU (RWKV channel-mix) | published precedent; untested here |
| Long prompts | evidence cards (P1) | **measured**: ~500 tokens per hour of telemetry (synthetic); 0.88/0.65 recall on real held-out traffic |
| Most of the language model, for most events | specialists + rules decide; the LM explains only on request | **measured**: models are worse judges than L0 (Phase 0) |
