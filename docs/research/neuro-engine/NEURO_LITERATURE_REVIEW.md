# NEURO_LITERATURE_REVIEW — Gate 1: what science and software already show

> HookProbe Neuro Engine, Research Gate 001 (2026-11-17). Sources were checked against primary
> material (arXiv / ACL Anthology / PMLR / NeurIPS / USENIX pages, official repositories and model
> cards) during this study. **UNVERIFIED** marks anything not confirmed from a primary source.
> Venue labels distinguish peer-reviewed work from preprints. Every quoted number keeps its stated
> conditions; most are **GPU or Apple-silicon** results and say nothing about a Cortex-A76 until
> measured there.
>
> Evidence classes used throughout the package: **SD** scientifically demonstrated (peer-reviewed) ·
> **IMPL** demonstrated in an existing implementation · **ARM** verified on ARM64 (published) ·
> **CM5** verified on actual CM5 (none yet) · **TH** theoretical but plausible · **HYP** original
> hypothesis of this study.

## 0. The one fact that organises everything

On a Cortex-A76 with a 32-bit LPDDR4X bus, **decode is bandwidth-bound and prefill is
compute-bound** [ARM: Arm Learning Path, Pi 5; decode peaks at 2 threads at ~84–86% of measured
bandwidth, prefill scales to 4 threads, ref 1]. Any technique is therefore judged by one question:
*does it reduce the bytes moved per generated token, or the number of tokens/requests that need a
model at all?* Techniques that add compute to save bandwidth can win here; techniques that add
bandwidth (separate draft models, larger state) usually lose.

## 1. Native low-bit networks

| Work | What it shows | Status | CM5 relevance |
|---|---|---|---|
| **BitNet b1.58 2B4T** (Microsoft, 2025) [2][3] | Native ternary weights trained from scratch on 4T tokens; 0.4 GB non-embedding memory vs 1.4–2.6 GB for comparable 1–1.5B models; average 54.19 vs 55.23 (Qwen2.5-1.5B); weaker on MMLU (53.2 vs 60.3) and HumanEval+. MIT licence. Model card's "29 ms/token, 0.028 J/token" names **no hardware**. | IMPL (tech report, arXiv 2504.12285) | **The strongest bandwidth story**: ~753 MiB read per token incl. a Q6_K embedding/head (E-RF1) vs ~1.1 GiB for Qwen3-1.7B Q4_0. Context only 4K; no Romanian claim; general-purpose quality below Qwen-class. |
| **bitnet.cpp** (ACL 2025) [4][5] | LUT kernels built on T-MAC: **TL1 = ARM** (NEON `vqtbl1q_s8`, per-model codegen), TL2 = x86 only, I2_S both (uses `vdotq_s32` when dotprod exists). 1.37–5.07× over llama.cpp **FP16** on ARM, 55–70% less energy — measured on **Apple M2 Ultra**. Output matched FP32 on 100% of 1,000 prompts vs 1.4% for llama.cpp TQ1_0/TQ2_0. | SD + IMPL; **no Cortex-A numbers** | Kernels are A76-compatible by instruction set (dotprod, TBL). Speedup baseline is FP16, not Q4 — the relevant comparison (ternary vs Q4_0 on A76) is **unmeasured**. |
| **T-MAC** (EuroSys 2025) [6] | Lookup-table mixed-precision GEMM. **Raspberry Pi 5 results in the paper**: single-thread end-to-end 2.8× (Llama-2-7B 4-bit), 6.7× (2-bit), 5.8× (BitNet-3B) vs llama.cpp **b2794**; **BitNet-b1.58-3B at ~11 tok/s on Pi 5**. Paper notes multi-thread GEMV is bandwidth-limited. | SD + **ARM (Pi 5)** | The only peer-reviewed low-bit result on our SoC family. Baseline llama.cpp is 2024-era (before Q4_0 repacking / KleidiAI), so the gap to *today's* llama.cpp must be re-measured. |
| llama.cpp **TQ1_0 / TQ2_0** (PR #8151) [7] | 1.69 / 2.06 bpw ternary types without LUTs; kernel throughput on Neoverse-N1 (dotprod): TQ2_0 65.8 GB/s vs Q4_K 45.4 vs Q8_0 42.6 (dot-product kernel, not tok/s); on Pi 4 (A72) TQ2_0 15.8 vs Q4_K 9.3 GB/s. | IMPL + ARM (kernel level) | Works today in upstream. Fidelity vs FP32 much lower than bitnet.cpp's [4]. |
| PrismML **Bonsai** 1-bit (Q1_0) and **Ternary Bonsai** (Apr 2026) [8] | 8B at 1.15 GB (1-bit) / 1.75 GB (ternary); averages 70.5 / 75.5 vs 79.3 for Qwen3-8B. Apache-2.0. Speeds only on M4 Pro / iPhone. Q1_0 is upstream with an A76 repack path; ternary Q2_0 needs PrismML's fork. | IMPL; base model UNVERIFIED | A real "8B-class in < 2 GB" option for 4 GB SKUs — but decode is still ~1.15–1.75 GB/token → ~7–10 tok/s bound [TH]. |
| Falcon-Edge / Falcon3 1.58-bit [9] | 1B / 3B native ternary, bitnet.cpp I2_S + TL1. Falcon-LLM licence (custom, AUP). | IMPL | Licence friction (see §8). |
| **Post-training** 2–3-bit on small models (Qwen3 quantisation study, arXiv 2505.02214) [10] | Qwen3-1.7B: FP16 MMLU 60.0 → 4-bit GPTQ 55.7 → 3-bit AWQ 26.7 → 2-bit GPTQ 25.6 (chance). Qwen3-0.6B collapses already at 3-bit. | preprint, consistent with llama.cpp perplexity table [11] (Llama-3-8B: iq2_XXS PPL 14.1 vs 6.23 f16; iq1_S ~60) | **Below 4 bits, post-training quantisation of a small model destroys it.** Low bits are only viable for models *trained* low-bit. |

**Answers to the Gate-1 questions.** *Do ternary weights cut bandwidth as well as storage?* Yes, by
construction — decode reads ~2 bits/weight instead of ~4.5 [TH, follows from §0]. *Unpacking cost?*
LUT kernels trade it for table lookups; T-MAC shows this is a net win on Pi 5 single-thread [SD+ARM].
*Can native ternary beat INT4 on A76?* Plausible but **unmeasured against today's repacked Q4_0** —
experiment E-LB1. *Smaller native-low-bit vs larger PTQ?* At ≤3 bits, native wins decisively
[SD, ref 10]; at 4 bits, a PTQ model of the same size is the stronger general model today.

## 2. Calibration and compression

| Technique | Finding | GGUF/llama.cpp path |
|---|---|---|
| **importance matrix (imatrix)** [11] | Llama-3-8B: q4_K_M+imatrix PPL 6.383 (KLD 0.028) vs plain q4_0 6.700 (KLD 0.072). Required for IQ2/Q2_K_S. | native (`llama-imatrix`) — **this is where HookProbe-specific calibration data plugs in today** |
| GPTQ [12] | Hessian-based PTQ (ICLR 2023). | converted by **dequantising** → re-quantised; GPTQ rounding not preserved |
| AWQ [13] | activation-aware scaling (MLSys 2024). | packed AWQ checkpoints rejected; route via AutoAWQ `export_compatible=True` then quantise |
| SmoothQuant [14] | W8A8 by migrating activation outliers into weights (ICML 2023). | not applicable (llama.cpp is weight-only on CPU) |
| SpinQuant / QuaRot [15][16] | rotations remove outliers for W4A4KV4. | folded rotations convert; activation/KV 4-bit not in llama.cpp. llama.cpp merged its own **Hadamard rotation of Q/K/V** (PR #21038, 2026-04-01) which greatly improves q4_0 KV [17] |
| SparseGPT [18] / Wanda [19] | 50–60% unstructured sparsity (ICML 2023 / ICLR 2024). | **no gain on CPU**: GGUF is dense; no sparse kernels |
| Minitron / Sheared-LLaMA [20][21] | structured pruning + distillation; up to 40× fewer training tokens than from scratch (NeurIPS 2024). | **yes** — output is a smaller standard model |
| Low-rank (SVD-LLM, ICLR 2025; ASVD; LoSparse ICML 2023) [22][23] | 10–30% compression training-free (ASVD, venue UNVERIFIED). | converts as a standard model if refolded |
| **Ordering study** (arXiv 2511.19495, preprint) [24] | On Qwen2.5-3B, **prune → distill → quantise** gave the best trade-off (~3.68×); quantising early degraded badly. | — |

**CALIBRE.** The only ML artefact with that name is *Calibre: Towards Fair and Accurate Personalized
Federated Learning with Self-Supervised Learning* (Chen, Su, Li; arXiv 2412.20020; ICDCS) — a
**personalised federated-learning** method (prototype loss + prototype-guided aggregation), code in
the Plato framework [25]. No compression, quantisation or calibration framework named CALIBRE was
found (arXiv title search; GitHub "calibre quantization" → 0). Easily confused: *Caliber* (output
calibration toolkit), calibration-data studies for compression (arXiv 2311.09755, 2405.20835).
**We therefore treat "calibre" as two separate, real ideas:** (a) calibration data for quantisation
(imatrix/AWQ) — §2; (b) Calibre-style personalised FL — §7.

## 3. Alternative architectures (runtime reality, not theory)

| Family | Representative small models | llama.cpp | State per sequence (E-RF1, fp32 state, f16 KV) | Published CPU evidence |
|---|---|---|---|---|
| Mamba / Mamba-2 [26][27] | (pure SSM small instruct models are rare) | `mamba`, `mamba2` ✅ | constant | — |
| **RWKV-7 "Goose"** [28][29] | 0.19–2.9B, Apache-2.0 | `rwkv7` ✅; rwkv.cpp | **~12 MiB constant** for 1.5B | none on A76 |
| **Hybrid Mamba-2 + attention** — IBM Granite 4.0-H [30] | H-1B (36 Mamba-2 + 4 attn), H-350M, Micro; Apache-2.0 | `granitehybrid` ✅ | **~54 MiB constant + 8 KiB/token** — larger than a transformer's KV at < 4K context | none on A76 |
| **Gated conv + attention** — Liquid LFM2 / LFM2.5 / LFM3 [31][32] | 350M–2.6B, 8B-A1B MoE | `lfm2`, `lfm3` ✅ | tiny conv state + ~12 KiB/token (6 attn layers) | LFM2 tech report: on Galaxy S25 (llama.cpp Q4_0, CPU) LFM2-1.2B **69.8 tok/s decode vs 39.7 for Qwen3-1.7B**, and decode falls only 21% from 1K→4K context vs 32% for Qwen3 [31] — **ARM (Snapdragon), not A76** |
| **Gated DeltaNet + attention** — Qwen3.5 [33] | 0.8B / 2B / 4B / 9B, 262K ctx, Apache-2.0 | `qwen35` ✅ | ~18 MiB constant + 12 KiB/token | none on A76 |
| Falcon-H1 (attention + Mamba) [34] | 0.5–7B; Falcon licence | `falcon-h1` ✅ | KV + SSM | — |
| Sliding-window transformer — Gemma 3 (5 local : 1 global, window 512 for 1B) [35] | 1B; Gemma Terms | ✅ | **~43 MiB at 8K** (vs ~896 MiB Qwen3-1.7B) | — |
| Zamba2 | — | ❌ no arch upstream | — | — |

**Reading.** Bounded-state architectures do not cut *weight* bandwidth — a 1.5B RWKV still reads
~1.5B weights per token. They cut **state** memory and keep decode flat as context grows. For
HookProbe, where semantic compression keeps contexts at ~0.5–2K tokens (E-SC1), the state advantage
is modest at single-sequence scale and becomes real only for **long-lived or many concurrent
sequences** — e.g. a persistent per-device recurrent behavioural state (§ Neural DNA). *Do not assume
architectural novelty translates into practical speed* — no recurrent model has a published A76
measurement.

## 4. Memory-efficient inference

| Topic | Evidence | Practical status (llama.cpp master 9048bad, 2026-11-17) |
|---|---|---|
| **KIVI** (ICML 2024) [36] | tuning-free 2-bit KV (keys per-channel, values per-token); ~2.6× lower peak memory on Llama-2-7B, "little to no" accuracy loss — **GPU**. | not implemented as such |
| KVQuant (NeurIPS 2024), Coupled Quantization (NeurIPS 2024), KVTuner (ICML 2025), RotateKV (IJCAI 2025) [37–40] | 3-bit KV < 0.1 PPL loss (KVQuant); keys more sensitive than values (KVTuner). | — |
| llama.cpp KV types | `-ctk/-ctv` f16, q8_0, q4_0, …; quantised V needs flash attention (auto). Closed demo PR #7412: q8_0 K/V +0.0046 PPL; q4_0 K/V +0.209 [41]. Post-rotation (PR #21038): Qwen3-0.6B q4_0-KV PPL 62.0 → 46.3 (f16: 13.7) [17]. | **q8_0 KV is safe; q4_0 KV still hurts small models** |
| Sliding window / StreamingLLM sinks [42] | SWA cache default for SWA models; `--context-shift` + `--keep N` ≈ attention sinks | available |
| H2O / SnapKV eviction [43][44] | NeurIPS 2023 / 2024 | **not in llama.cpp** |
| Prefix caching / slot save-restore | `cache_prompt`, `--cache-reuse`, `POST /slots/{id}?action=save|restore`; example restored 1,745 tokens in 43 ms | available — the basis of **fast reactivation** (P5) |
| mmap / page cache | `--load-mode auto|mmap|mlock|dio`, `--lazy-mode`. **Repacked Q4_0 weights are copied to anonymous RAM** (not evictable page cache); `--no-repack` keeps them evictable | trade-off to measure (E-MEM2). **heqk has no page cache at all.** |
| LLM in a flash (Apple) [45], PowerInfer / PowerInfer-2 [46][47], AirLLM [48] | Weights > DRAM work only with **activation sparsity** (ReLU-family models) or at seconds-per-token | not applicable to SwiGLU models; E-RF1 shows dense flash-backed decode = 3–11 s/token on CM5 |

## 5. Adaptive and conditional computation

| Work | Finding | CM5 relevance |
|---|---|---|
| **Mainardi, Sandikci, Vanschoren, "An Empirical Study of Speculative Decoding for Small Language Models", EACL 2026** [49] | GPU (A5500), greedy, batch 1: separate-drafter speculative sampling **slowed** small targets: **0.83×** Qwen2.5-1.5B, **0.67×** SmolLM2-1.7B (vs 1.69× on Vicuna-7B). Drafting overhead, not draft quality, dominates. EAGLE-2 1.44–1.81×; **prompt-lookup decoding** best training-free method, 1.28–2.52× on summarisation, 1.51–1.60× on RAG. | Confirms the research-gate caution. On a bandwidth-bound A76 a separate drafter adds its own weight traffic → expect equal or worse [TH]. **Prompt-lookup / n-gram drafting** costs no extra weights and fits input-grounded outputs (JSON that copies entity aliases) → E-AD2. |
| Leviathan et al. (ICML 2023), Medusa (ICML 2024), EAGLE-2 (EMNLP 2024), EAGLE-3 (NeurIPS 2025) [50–53] | GPU speedups 2–6.5× on large models | llama.cpp has `draft-eagle3` (heads exist for Qwen3-1.7B/4B), `draft-mtp` (Qwen3.5 trained with MTP heads), `ngram-*` |
| LayerSkip (ACL 2024) [54], CALM (NeurIPS 2022) [55], Mixture-of-Depths (preprint) [56], ACT (preprint) [57] | Early exit / dynamic depth: up to ~2–3× on T5 / Llama with special training | **none in llama.cpp**; needs checkpoints trained for it |
| **FrugalGPT** (TMLR 2024) [58], **RouteLLM** (ICLR 2025) [59], **IDK cascades** (UAI 2018) [60] | Cascades/routers: matched GPT-4 at up to 98% lower cost (FrugalGPT); >2× cost reduction (RouteLLM); confidence-gated classifier cascades | **The most transferable adaptive-compute evidence** — model-level routing needs no special checkpoints. Basis of the Neuro Engine's level router. |

## 6. Distillation and specialised intelligence

- **Logit distillation** (Hinton et al., 2015) [61]; **MiniLLM** reverse-KL (ICLR 2024, UNVERIFIED on
  proceedings page) [62]; **DistiLLM** (ICML 2024) [63].
- **Distilling step-by-step** (Findings of ACL 2023) [64]: LLM rationales as multi-task supervision —
  a 770M T5 beat 540B few-shot PaLM on one benchmark with 80% of the data. **Most relevant recipe for
  HookProbe specialists.**
- **Gemma 2 / Gemma 3** were trained with distillation in pretraining (256 teacher logits per token
  in Gemma 3) [65][66] — distillation is how today's best small models are already made.
- Prune + distill: **Minitron** (NeurIPS 2024) [20].
- Security/logs: FusionLog (LLM pseudo-labels → small model, >90% F1 zero-label on 3 log datasets,
  preprint) [67]; a 3B → 0.5B log-detector distillation (preprint) [68]. **No peer-reviewed LLM →
  NIDS-on-flows distillation found.**
- **HookProbe's own Level-1 models are untrained.** `legacy/linux-tier/modules/napse/MODEL_CARD-tabular.md`
  states the NAPSE tabular model is "a seed placeholder… NOT a trained classifier" with hand-derived
  weights, and `dga-lm` is scoped (int8 char-CNN) but awaits a labelled corpus. Teacher-labelled
  distillation is the missing pipeline.
- **Licence pitfalls for teacher outputs**: Gemma Terms make a model distilled from Gemma (or trained
  on Gemma synthetic data) a *Model Derivative* bound by Gemma's restrictions; Llama 3.2 requires a
  derived model's name to start with "Llama" + "Built with Llama"; OpenAI and Anthropic commercial
  terms prohibit using outputs to train competing models [69–72]. **Apache-2.0 teachers (Qwen3/3.5,
  Granite, Mistral 3, OLMo) are the clean choice.**

## 7. Behavioural state, sketches and federated intelligence

- **Kitsune** (NDSS 2018) [73]: damped incremental statistics + small autoencoder ensemble, fully
  online, **ran on a Raspberry Pi** — the closest published precedent for "Neural DNA".
- **DeepLog** (CCS 2017) [74]: LSTM over log keys — recurrent behavioural modelling for anomalies.
- Sketches: k-ary sketch change detection (IMC 2003) [75], UnivMon (SIGCOMM 2016) [76], Count-Min,
  HyperLogLog — fixed-size summaries of unbounded streams.
- Federated: FedAvg [77], secure aggregation (CCS 2017) [78], DP-FedAvg [79], open problems [80];
  NIDS-specific surveys stress non-IID data and weak evaluation standards [81][82]; **Calibre**
  personalised FL [25]; Flower framework [83]. Practical consensus: federate **small heads**, never
  the LLM; secure aggregation + clipping + DP noise + robust aggregation against poisoning.

## 8. Runtimes, accelerators, licences (summary — details in the companion documents)

- **llama.cpp** (MIT, v1.0.0 2026-11-13): online Q4_0 repack on by default; KleidiAI optional (A76
  uses only its dotprod kernels); OpenAI-compatible server with `json_schema` / GBNF constrained
  output, tools via Jinja, slots + save/restore, KV quantisation, `/health`, `/metrics` [84].
  Ollama adds overhead (secondary report: 8.2 → 5.7 tok/s TinyLlama on Pi 5) [85].
- ExecuTorch (BSD-3), ONNX Runtime GenAI (MIT), MNN (Apache-2.0), MLC-LLM (Apache-2.0): no primary
  A76 LLM numbers; **LiteRT-LM** (Google) reported Gemma 4 E2B at 9 tok/s decode vs 4 tok/s for
  llama.cpp Q4_0 on Pi 5 in a Raspberry Pi blog post whose figures are internally inconsistent
  (appendix says 58/7) [86] — worth an independent re-measurement.
- **Licences** (verified, model cards): Apache-2.0 — Qwen3, **Qwen3.5**, **Gemma 4**, Granite 4.x,
  Ministral 3, SmolLM3, OLMo 3, EuroLLM, ERNIE 4.5; MIT — Phi-4-mini, BitNet b1.58; custom — Gemma 3
  Terms, Llama 3.2 Community, **LFM Open v1.0 (no commercial use at ≥ US$10M revenue)**, Falcon
  (AUP), Hunyuan (**excludes EU/UK/KR**), OpenLLM-Ro (**CC BY-NC**). Romanian is explicitly named only
  for Qwen3, Falcon-H1, EuroLLM/EuroMoE (and non-commercial OpenLLM-Ro).

## References

1. Arm Learning Path, LLM decode roofline (Pi 5) — https://learn.arm.com/learning-paths/cross-platform/llm-decode-roofline/
2. BitNet b1.58 2B4T model card — https://huggingface.co/microsoft/bitnet-b1.58-2B-4T ; tech report https://arxiv.org/abs/2504.12285
3. Microsoft BitNet repository — https://github.com/microsoft/BitNet
4. Wang et al., bitnet.cpp, ACL 2025 — https://aclanthology.org/2025.acl-long.457 ; https://arxiv.org/abs/2502.11880
5. "1-bit AI Infra" (bitnet.cpp CPU results) — https://arxiv.org/abs/2410.16144
6. Wei et al., T-MAC, EuroSys 2025 — https://arxiv.org/abs/2407.00088 ; https://github.com/microsoft/T-MAC
7. llama.cpp PR #8151 (TQ1_0/TQ2_0) — https://github.com/ggml-org/llama.cpp/pull/8151
8. PrismML Bonsai — https://prismml.com/news/bonsai-8b ; https://prismml.com/news/ternary-bonsai
9. Falcon-Edge — https://huggingface.co/blog/tiiuae/falcon-edge
10. Qwen3 quantisation study — https://arxiv.org/abs/2505.02214
11. llama.cpp perplexity scoreboard — https://github.com/ggml-org/llama.cpp/blob/master/tools/perplexity/README.md
12. GPTQ — https://arxiv.org/abs/2210.17323
13. AWQ — https://arxiv.org/abs/2306.00978
14. SmoothQuant, ICML 2023 — https://proceedings.mlr.press/v202/xiao23c.html
15. SpinQuant — https://arxiv.org/abs/2405.16406
16. QuaRot — https://arxiv.org/abs/2404.00456
17. llama.cpp PR #21038 (rotated Q/K/V) — https://github.com/ggml-org/llama.cpp/pull/21038
18. SparseGPT, ICML 2023 — https://proceedings.mlr.press/v202/frantar23a.html
19. Wanda — https://arxiv.org/abs/2306.11695
20. Minitron, NeurIPS 2024 — https://arxiv.org/abs/2407.14679
21. Sheared-LLaMA — https://arxiv.org/abs/2310.06694
22. SVD-LLM, ICLR 2025 — https://proceedings.iclr.cc/paper_files/paper/2025/hash/3104e1ab39875cf54fe1eb4473e7c5a1-Abstract-Conference.html
23. LoSparse, ICML 2023 — https://proceedings.mlr.press/v202/li23ap.html
24. Compression ordering study — https://arxiv.org/abs/2511.19495
25. Calibre (personalised FL) — https://arxiv.org/abs/2412.20020 ; https://github.com/TL-System/plato/tree/main/examples/ssl/calibre
26. Mamba — https://arxiv.org/abs/2312.00752
27. Mamba-2 — https://arxiv.org/abs/2405.21060
28. RWKV-7 "Goose" — https://arxiv.org/abs/2503.14456
29. rwkv.cpp — https://github.com/RWKV/rwkv.cpp
30. IBM Granite 4.0-H-1B — https://huggingface.co/ibm-granite/granite-4.0-h-1b
31. LFM2 technical report — https://arxiv.org/abs/2511.23404
32. LFM2.5-1.2B-Instruct — https://huggingface.co/LiquidAI/LFM2.5-1.2B-Instruct
33. Qwen3.5-0.8B — https://huggingface.co/Qwen/Qwen3.5-0.8B
34. Falcon-H1 — https://huggingface.co/tiiuae/Falcon-H1-0.5B-Instruct
35. Gemma 3 technical report — https://arxiv.org/abs/2503.19786
36. Liu et al., KIVI, ICML 2024 — https://proceedings.mlr.press/v235/liu24bz.html
37. Hooper et al., KVQuant, NeurIPS 2024 — https://proceedings.neurips.cc/paper_files/paper/2024/hash/028fcbcf85435d39a40c4d61b42c99a4-Abstract.html
38. Coupled Quantization, NeurIPS 2024 — https://arxiv.org/abs/2405.03917
39. KVTuner, ICML 2025 — https://proceedings.mlr.press/v267/li25dd.html
40. RotateKV, IJCAI 2025 — https://www.ijcai.org/proceedings/2025/690
41. llama.cpp PR #7412 (KV quantisation demo) — https://github.com/ggml-org/llama.cpp/pull/7412
42. StreamingLLM — https://arxiv.org/abs/2309.17453
43. H2O — https://arxiv.org/abs/2306.14048
44. SnapKV — https://arxiv.org/abs/2404.14469
45. LLM in a flash — https://arxiv.org/abs/2312.11514
46. PowerInfer — https://arxiv.org/abs/2312.12456
47. PowerInfer-2 — https://arxiv.org/abs/2406.06282
48. AirLLM — https://github.com/lyogavin/airllm
49. Mainardi, Sandikci, Vanschoren, EACL 2026 — https://aclanthology.org/2026.eacl-long.255/
50. Leviathan et al., ICML 2023 — https://proceedings.mlr.press/v202/leviathan23a.html
51. Medusa, ICML 2024 — https://proceedings.mlr.press/v235/cai24b.html
52. EAGLE-2 — https://arxiv.org/abs/2406.16858
53. EAGLE-3, NeurIPS 2025 — https://proceedings.neurips.cc/paper_files/paper/2025/hash/c7b5a35ea98b62512a869c19ea7b03cb-Abstract-Conference.html
54. LayerSkip, ACL 2024 — https://aclanthology.org/2024.acl-long.681
55. CALM, NeurIPS 2022 — https://proceedings.neurips.cc/paper_files/paper/2022/hash/6fac9e316a4ae75ea244ddcef1982c71-Abstract.html
56. Mixture-of-Depths — https://arxiv.org/abs/2404.02258
57. Adaptive Computation Time — https://arxiv.org/abs/1603.08983
58. FrugalGPT, TMLR 2024 — https://mlanthology.org/tmlr/2024/chen2024tmlr-frugalgpt
59. RouteLLM, ICLR 2025 — https://proceedings.iclr.cc/paper_files/paper/2025/hash/5503a7c69d48a2f86fc00b3dc09de686-Abstract-Conference.html
60. IDK Cascades, UAI 2018 — https://proceedings.mlr.press/r16/wang18c.html
61. Hinton, Vinyals, Dean — https://arxiv.org/abs/1503.02531
62. MiniLLM — https://arxiv.org/abs/2306.08543
63. DistiLLM, ICML 2024 — https://arxiv.org/abs/2402.03898
64. Hsieh et al., Distilling step-by-step, Findings of ACL 2023 — https://aclanthology.org/2023.findings-acl.507
65. Gemma 2 — https://arxiv.org/abs/2408.00118
66. Gemma 3 — https://arxiv.org/abs/2503.19786
67. FusionLog — https://arxiv.org/abs/2511.05878
68. Distilled heterogeneous-log detector — https://arxiv.org/abs/2602.06777
69. Gemma Terms of Use (modified 2026-04-01) — https://gemma.ai/resources/terms/
70. Llama 3.2 Community License — https://github.com/meta-llama/llama-models/blob/main/models/llama3_2/LICENSE
71. OpenAI Terms of Use — https://openai.com/policies/terms-of-use/
72. Anthropic Commercial Terms — https://www.anthropic.com/legal/commercial-terms
73. Mirsky et al., Kitsune, NDSS 2018 — https://arxiv.org/abs/1802.09089
74. Du et al., DeepLog, CCS 2017 — https://users.cs.utah.edu/~lifeifei/papers/deeplog.pdf
75. Krishnamurthy et al., sketch-based change detection, IMC 2003 — https://www.cs.utexas.edu/~yzhang/papers/nad-imc03.pdf
76. UnivMon, SIGCOMM 2016 — https://www.cs.princeton.edu/courses/archive/fall18/cos561/papers/Univmon16.pdf
77. FedAvg — https://arxiv.org/abs/1602.05629
78. Bonawitz et al., secure aggregation, CCS 2017 — https://eprint.iacr.org/2017/281
79. DP-FedAvg — https://arxiv.org/abs/1710.06963
80. Advances and open problems in FL — https://arxiv.org/abs/1912.04977
81. FL for NIDS survey — https://arxiv.org/abs/2509.21389
82. FL for NIDS survey — https://arxiv.org/abs/2204.12443
83. Flower — https://arxiv.org/abs/2007.14390
84. llama.cpp server README — https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md
85. llama.cpp vs Ollama on Pi (secondary) — https://dev.to/baretensor/llamacpp-vs-ollama-on-raspberry-pi-the-performance-trade-off-nobody-talks-about-4hg0
86. Raspberry Pi, LiteRT + Gemma — https://raspberrypi.com/news/mastering-edge-ai-on-raspberry-pi-with-litert-and-gemma
