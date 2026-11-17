# NEURO_TECHNIQUE_MATRIX — Gate 3: 18 approaches, ranked for CM5

> HookProbe Neuro Engine, Research Gate 001 (2026-11-17). Ranking is by **expected practical benefit
> on CM5 for HookProbe's workloads**, not by novelty or marketing claims. Evidence classes: SD
> scientifically demonstrated · IMPL existing implementation · ARM verified on ARM64 (published) ·
> CM5 verified on CM5 (none yet) · TH theoretical · HYP hypothesis · MS measured here on synthetic
> data. Sources are numbered in `NEURO_LITERATURE_REVIEW.md` (L#) or are this study's experiments
> (E-…, `NEURO_EXPERIMENT_DESIGN.md`).

## A. What each approach is, and where it stands

| # | Approach | Principle | Implementations | Key sources | Model compatibility | ARM64 / A76 | Evidence |
|---|---|---|---|---|---|---|---|
| 1 | **Evidence cards (semantic compression)** | Information bottleneck before inference: aggregate, rank by surprisal, never drop silently | this study (`semantic_compression.py`) | E-SC1; sketches L75–76 | any model | integer-only, runs on heqk | MS |
| 2 | **Model cascade / level router** | Answer at the cheapest level that can ground the answer | FrugalGPT, RouteLLM, IDK cascades | L58–60 | any | n/a (control logic) | SD |
| 3 | **Behavioural memory ("Neural DNA")** | Damped incremental statistics + aging Bloom sets, guarded updates | Kitsune; this study | L73, L75; E-BM1 | none needed (no model) | integer/fixed-point, runs on heqk | SD (Kitsune on Pi) + MS |
| 4 | **Evidence-closed constrained decoding** | Per-request grammar with closed fact/entity vocabularies | llama.cpp json_schema/GBNF; this study's schema builder | L84; P2 | any llama.cpp model | yes | IMPL + HYP (quality impact) |
| 5 | **Event-driven residency + KV prefix snapshot** | Lease RAM on demand; restore pre-computed prefix KV | llama-server slots save/restore; ADR 0061 budgets | L84 | any | yes (Linux); heqk needs copy-in loader | IMPL + TH |
| 6 | **Bandwidth-budgeted decoding** | Pace tok/s × bytes/token to a DRAM share | MemGuard (PMU), Sereno (yield points) | L10–12 (budget doc), P4 | dense models (bytes/token known) | no MPAM → software pacing | SD (interference) + TH |
| 7 | **4-bit weight PTQ + imatrix calibration** | Importance-weighted rounding with domain calibration data | llama.cpp Q4_0 (+ A76 repack), Q4_K_M, imatrix | L11 | nearly all GGUF archs | **ARM verified** (Pi 5, Arm LP) | ARM |
| 8 | **Task-specific distillation to tiny specialists** | Teacher labels + rationales → small student | Distilling step-by-step, FusionLog | L64, L67 | students: logistic/GBDT/char-CNN/encoders | trivially | SD (method) + HYP (NIDS) |
| 9 | **Native ternary / 1-bit models + LUT kernels** | Train at ≤ 2 bits; table-lookup GEMV | bitnet.cpp (TL1 ARM), T-MAC, llama.cpp TQ*, Q1_0 | L2–8 | BitNet, Falcon-E, Bonsai only | **ARM verified on Pi 5** (T-MAC) | SD + ARM |
| 10 | **Hybrid / linear-attention architectures** | Bounded recurrent state + few attention layers | Qwen3.5 (DeltaNet), LFM2/2.5/3, Granite 4.0-H, Falcon-H1 | L30–34 | those models | ARM (Snapdragon, LFM2); A76 unmeasured | IMPL + ARM(other) |
| 11 | **Pure recurrent LMs (RWKV-7, Mamba)** | Constant state, no KV | llama.cpp rwkv7/mamba2, rwkv.cpp | L26–29 | those models | supported; unmeasured | IMPL |
| 12 | **KV-cache quantisation (q8_0 / KIVI-class)** | Low-bit K/V, keys per-channel | llama.cpp -ctk/-ctv (+ Hadamard rotation, PR #21038); KIVI, KVQuant | L36–41, L17 | attention models | yes | SD (GPU) + IMPL |
| 13 | **Sliding-window / MQA attention models** | Bound KV by window and KV-head count | Gemma 3/4 SWA, MQA | L35 | Gemma family (licence!) | yes | IMPL |
| 14 | **Prompt-lookup / n-gram self-drafting** | Draft tokens from the input, verify in one pass | llama.cpp `ngram-*` | L49 (best training-free on input-grounded tasks) | any | yes; gain on CPU unmeasured | SD (GPU) + TH |
| 15 | **Small embedding models for retrieval / similarity** | Encode events / KB once, nearest-neighbour at query time | model2vec potion (static), granite-embedding-small-r2, EmbeddingGemma, Qwen3-Embedding-0.6B | L-F (lit. §F) | bert / modern-bert / gemma-embedding | yes | IMPL |
| 16 | **Federated learning of L1 heads** | FedAvg + secure aggregation + DP; Calibre-style personalisation | Flower, Plato (Calibre) | L25, L77–83 | small heads only | yes | SD |
| 17 | **AOT-compiled model-specific executor** | Static arena, fused kernels, no runtime allocation | ExecuTorch, TVM/MLC, IREE | L-§8 | per model | unmeasured on A76 | HYP for heqk |
| 18 | **NPU offload (Hailo-10H; RK3588 NPU later)** | Separate silicon + DRAM for inference | HailoRT, hailo-ollama | budget doc §3 | Hailo zoo models only (≤ ~6B, 2K ctx) | Pi 5: prefill 6× faster, decode slower than CPU | ARM (Pi 5, vendor + review) |

Also evaluated and **rejected** (see `NEURO_INNOVATION_PROPOSALS.md` § Rejected): separate-drafter
speculative decoding, storage-backed decode, ≤ 3-bit PTQ of small models, unstructured sparsity on
CPU, VideoCore GPU, early exit without trained checkpoints.

## B. Expected impact on CM5 and ranking

Scores are judgements from the evidence above, 0 (none) – 3 (large). "Avail." = protection of the
packet path. Latency/quality: + better, − worse, 0 neutral. Licence column flags friction for a
commercial AGPL + dual-licence product.

| Rank | # | Approach | RAM ↓ | Storage ↓ | CPU / BW ↓ | Avail. | Latency | Quality | Dev. cost | Licence | Main limitation |
|---|---|---|---|---|---|---|---|---|---|---|---|
| **1** | 1 | Evidence cards | 3 (KV) | 0 | **3** (prefill ÷ ~600) | 3 | + + | + (no noise) / − if lossy | low | own (AGPL) | synthetic validation only; must not drop the needle |
| **2** | 2 | Level router / cascade | 3 | 2 | **3** (most requests never reach a model) | 3 | + + | ± (depends on L0/L1 quality) | low | own | needs good escalation signals |
| **3** | 3 | Neural DNA | 3 (KB/device) | 3 (vs raw history) | 3 | 3 | + + | n/a (detector) | medium | own | drift vs poisoning trade-off; synthetic only |
| **4** | 4 | Evidence-closed decoding | 0 | 0 | 0 | 0 | 0 / slight − | **+ (no entity hallucination)** | low | llama.cpp MIT | possible reasoning-quality cost on small models (E-EV1) |
| **5** | 5 | Event-driven residency | **3** (idle = 0) | 0 | 1 | 2 | − (cold start s) | 0 | medium | own | heqk has no page cache; eMMC rate unmeasured |
| **6** | 6 | Bandwidth-budgeted decoding | 0 | 0 | 0 (caps it) | **3** | − (paced) | 0 | low | own | value depends on measured interference (E-INT1) |
| **7** | 7 | Q4_0 + imatrix | 2 | 2 | 2 | 1 | + | − small | low | MIT | ≤ 3-bit collapses on small models |
| **8** | 8 | Distilled specialists (L1) | 3 | 3 | 3 | 3 | + + + | + on narrow tasks | medium–high | **teacher licence** (Apache teachers only) | needs labelled corpus + blind eval |
| **9** | 9 | Native ternary + LUT | 2 | 2 | **2–3** (bytes/token ÷ ~2) | 2 | + | − (BitNet < Qwen class), no RO claim | medium | MIT (BitNet) / Falcon / Apache (Bonsai) | few models; Q4_0 comparison on A76 unmeasured |
| 10 | 12 | KV q8_0 | 1–2 | 0 | 1 | 1 | 0 | ≈0 at q8_0; − at q4_0 | none | MIT | small benefit when contexts are short (P1) |
| 11 | 10 | Hybrid / linear attention | 1–2 (state) | 0 | 1 (flat decode with ctx) | 1 | + at long ctx | model-dependent | none (use) | Apache (Qwen3.5/Granite) / LFM revenue cap | state can exceed KV at short ctx (Granite-H ~54 MiB) |
| 12 | 13 | SWA / MQA models | 2 | 0 | 1 | 1 | 0 | model-dependent | none | Gemma 3 Terms ✗ / Gemma 4 Apache ✓ | family-specific |
| 13 | 15 | Embeddings / retrieval | 1 | 1 | 2 (replaces generation for lookup) | 2 | + | + for KB answers | low | mostly Apache/MIT; EmbeddingGemma = Gemma Terms | not a generator |
| 14 | 18 | NPU (Hailo-10H) | 2 (own DRAM) | 0 | **3 (off the bus)** | **3** | + prefill, − decode | Hailo-zoo models only | high (no heqk driver) | HailoRT MIT; driver GPL-2.0 | CM5-on-heqk: no driver; RK3588 era |
| 15 | 11 | Pure recurrent (RWKV-7) | 2 (12 MiB state) | 0 | 0 | 1 | 0 | weaker instruction-following ecosystem | none (use) | Apache | unmeasured; tooling/tool-calling weaker |
| 16 | 14 | Prompt-lookup drafting | 0 | 0 | 1 | 0 | + maybe | 0 | none | MIT | unproven on CPU |
| 17 | 16 | Federated L1 heads | 0 | 0 | 0 | 0 | 0 | + over time | high | own | governance, poisoning, non-IID |
| 18 | 17 | AOT executor for heqk | 1 (exact arena) | 0 | 0–1 | 2 (exact budget) | 0 | 0 | **very high** | own | only after heqk SMP + FP/SIMD |

**How to read the ranking.** The top six are *system* techniques — they decide **whether, how much and
when** to infer. They dominate because on CM5 the cheapest token is the one never generated and the
cheapest prompt token is the one compiled away. Model-level techniques (7, 9–13) decide **how cheaply a
necessary token is produced** and matter second. The ranking would change on the RK3588 board, where
an NPU (18) moves inference off the shared DRAM bus and rises sharply.

## C. Combinations

| Combination | Effect | Verdict |
|---|---|---|
| Evidence cards (1) + closed decoding (4) | Cards define the closed vocabulary; decoding cannot leave it; citations become type-checked | **strongly synergistic — core of the engine** |
| Neural DNA (3) + evidence cards (1) | DNA supplies the "novel" and surprisal ranking signals; cards carry DNA change signals to L2 | **synergistic** |
| Neural DNA (3) + router (2) + residency (5) — "explain-to-learn" | DNA flags a change → one L2 explanation → owner confirms → signed DNA update; model woken rarely | **synergistic; the main differentiator** |
| Router (2) + distilled specialists (8) | Specialists absorb the high-volume classification traffic; LLM only for residue | **synergistic** (FrugalGPT pattern) |
| Native ternary (9) + LUT kernels | Required pairing: ternary weights in Q4 kernels gain nothing; bitnet.cpp fidelity ≫ llama.cpp TQ types | **mandatory pairing** |
| Bandwidth pacing (6) + any decode | Bounds the availability damage of any model choice | **always on** |
| KV q8_0 (12) + evidence cards (1) | Cards already make contexts short → KV quantisation saves little | **redundant at ≤ 2K ctx** — keep q8_0 as a free default, don't invest further |
| Hybrid/recurrent (10/11) + evidence cards (1) | State advantage shows at long contexts, which cards eliminate | **weak** — choose hybrids for quality/licence, not for memory |
| Separate-draft speculative decoding + small target on CPU | Drafter adds weight traffic on a bandwidth-bound core | **incompatible** (EACL 2026 + TH) |
| Storage-backed weights + interactive decode | seconds per token | **incompatible** |
| Q4_0 online repack + event-driven residency on Linux | Repacked weights are anonymous RAM, not evictable cache → idle model can't be reclaimed by the kernel | **tension — measure (E-MEM2)**; prefer explicit unload |
| Unstructured sparsity + GGUF | Dense storage, no sparse kernels | **no effect** |
| Gemma teacher + distilled specialists | Students become Gemma "Model Derivatives" | **licence-incompatible** with an AGPL product line |
