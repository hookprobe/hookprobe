# 04 — Neural architecture comparison for HookProbe on CM5 (Gate 4)

> Native Inference Research Programme, 2026-11-18. Memory figures come from
> `tools/neuro-research/memory_model.py` (theoretical, `07`). Model facts and licences are from `10`
> §5. No architecture below has been measured on a CM5 or an A76 by anyone in this study.

## 1. The question behind the comparison

A security gateway sees a **continuous stream** (flows, DNS, detections, device events) and must
answer three different kinds of question:
1. Is this device behaving differently from its own past? This is *temporal and per-device*.
2. What is this traffic or device? This is *classification, per event or window*.
3. What happened, and what should the owner do? This is *language*.

A transformer that re-reads a long textual context serves (3) and serves (1) badly: memory grows
with context and every question re-processes the history. A recurrent model keeps a fixed state, which
looks like a natural fit for (1). **This is a hypothesis, not a result.** `11` E-N2/E-N3 test it.

## 2. Comparison (language-capable architectures, ≤ 3B, CPU)

| Architecture | Example (licence) | Weights @Q4_0 | Context state | Per-token work | Operators beyond GEMV | A76 suitability | Training / fine-tune need | Security-task quality |
|---|---|---|---|---|---|---|---|---|
| Transformer + GQA | Qwen3-0.6B / 1.7B (Apache-2.0) | 236 / 756 MiB + head | **KV grows**: 56 MiB at 512, 224 MiB at 2K (f16) | weights + full KV read | RoPE, softmax, SiLU | good (SDOT GEMV); KV traffic hurts at long ctx | fine-tune well supported | **measured (Phase 0)**: worse than L0 at verdicts, best explainer (Qwen3-1.7B) |
| Multi-head latent attention | DeepSeek-style MLA, no ≤ 3B permissive checkpoint found | — | KV compressed to a latent | extra up-projections | latent projections | neutral | — | — |
| **Gated DeltaNet hybrid** (3 recurrent : 1 attention) | Qwen3.5-0.8B / 2B (Apache-2.0) | 267 MiB + **254 M-param head** | 18 MiB GDN state + 12 KiB/token KV (DERIVED) → 43 MiB at 2K | weights + state + small KV | delta-rule recurrence, conv1d, gating | good decode; **lost prompt-cache reuse in llama.cpp (Phase 0)** | supported | measured: Qwen3.5-0.8B best fast-tier explainer, perfect RO language check |
| **RWKV-7** | 0.19 / 0.4 / 1.5 / 2.9B (Apache-2.0) | 163 MiB (0.4B) / 653 MiB (1.5B) | **6.2 / 12.4 MiB, constant** (DERIVED) | weights + state | token shift, low-rank adapters, WKV7 state update, sigmoid, squared ReLU | good: squared ReLU and state update are integer-friendly; no attention scores | community tooling; less mature | **unmeasured**; paper: 1.5B ≈ Qwen2.5-1.5B on English LM-eval, better multilingual |
| RWKV-6 | Finch 1.6/3.1B (Apache-2.0) | similar | constant | similar | WKV6 | good | — | superseded by RWKV-7 |
| Mamba-2 | 130M–2.7B (Apache-2.0) | ~0.7 GiB (1.3B) | **≈ 98 MiB at 1.3B** (DERIVED, defaults assumed) | weights + state | selective scan, conv1d | fair (scan is sequential) | base models only (Pile, 300B tokens) | no instruct checkpoints; weak |
| xLSTM | 7B only (NXAI licence, €100M cap) | — | matrix memory | — | mLSTM/sLSTM | — | — | excluded (size, licence) |
| Griffin / RecurrentGemma | 2B (Gemma terms) | — | RG-LRU + local-attention window | — | RG-LRU | — | — | excluded (licence) |
| LFM2 | 0.35–2.6B (LFM licence, US$10M cap) | — | short-conv + few GQA | — | double-gated conv | very good on ARM (published) | — | excluded (licence) |
| Mixture of Experts | OLMoE-1B-7B; Granite 1B-A400M (Apache-2.0) | **must hold all experts**: ~3.9 GB for OLMoE | KV | active experts only | router, top-k | reads few bytes per token but needs big RAM | supported | Granite 1B-A400M: MMLU at chance |
| Early-exit / layer-skip | method; released checkpoints non-commercial | — | KV for skipped layers | (exit layer / L) of weights | exit heads | good on bandwidth-bound CPU | needs training | — |
| **Native ternary transformer** | BitNet b1.58 2B4T (MIT; config UNVERIFIED) | **≈ 0.5 GiB at 2 bits** for 2B | KV (5 KV heads) 150 MiB at 2K | compute-bound on A76 (`02`) | BitLinear, ReLU², subln | LUT kernel fits A76 well (`01`) | **must be trained ternary**; post-hoc ternarisation destroys quality [R110] | unmeasured on HookProbe tasks |

## 3. Non-language architectures (questions 1 and 2)

| Architecture | Example | Size | State per device | Per event | Fits heqk today? | Evidence |
|---|---|---|---|---|---|---|
| Damped statistics + aging Bloom filters ("Neural DNA") | `behavioural_memory.py` | code only | **672 B** | µs | **yes** (integer port of `log2`/`sqrt` needed) | simulated AUC 0.999; real Hue device 2 alarms/day after the Phase 0b fix |
| Tiny recurrent cell (GRU / minimal RNN), int8 | to be trained (E-N2) | 10–100 K params | 64–256 B | µs | yes (scalar int8; no SIMD needed at this size) | none yet; must beat DNA by ≥ 0.02 AUC at equal bytes |
| Autoencoder ensemble (Kitsune) | literature | ~100 K | statistics per channel | µs | yes | NDSS 2018 |
| Gradient-boosted trees / logistic heads on flow features | NAPSE seeds (Track E-DS1) | KB | none | µs | yes | in the earlier experiment design |
| int8 char-CNN (DGA) | E-DS1 | ~100 KB | none | µs | yes | planned |
| LM-scale recurrent state per device (RWKV-7 0.1B) | — | 0.19B | **2.3 MiB** per device | ms | **no**: 1,000 devices = 2.3 GiB | DERIVED |

## 4. Findings

1. **Weight bandwidth, not architecture, sets decode speed.** Every architecture reads all active
   weights per token. Recurrence saves *context memory* (constant 6–12 MiB versus a 224 MiB KV cache
   at 2K), not weight traffic.
2. **For per-device temporal intelligence, LM-scale recurrent states are the wrong size.** One
   RWKV-7 0.1B state is 2.3 MiB, against 672 B for the measured statistical DNA. "Recurrent
   security intelligence" therefore has two different scales:
   - a **tiny learned recurrent cell per device** (bytes, integer);
   - at most **one LM-scale recurrent state per conversation or incident** (MiB).
   They must not be conflated.
3. **RWKV-7 is the best-fitting language architecture *on paper*** for heqk:
   - constant small state;
   - integer-friendly channel-mix;
   - no softmax over context;
   - Apache-2.0, with 0.4B and 1.5B sizes inside the 4 GB SKU budget.

   It is **unmeasured** on HookProbe tasks, and Phase 0 showed paper benchmarks do not predict
   security-task quality. It enters as a candidate in E-N3, not as a decision.
4. **Ternary is the best-fitting *format*, but only for models trained ternary.** BitNet b1.58 2B4T
   is the only permissive, competent one found. No ternary RWKV exists. Training one is research,
   not engineering (`13` "not now").
5. **The Qwen3.5 hybrid, measured as the best fast explainer in Phase 0, sits between the two**: an
   18 MiB recurrent state plus a small KV. Its practical problem is the oversized 248K-token head,
   which vocabulary trimming and grammar-sparse logits address (`10` §3).
6. **Mixture-of-experts and layer-skip do not fit CM5 now.** MoE needs RAM for all experts. The
   released layer-skip checkpoints are non-commercial.
