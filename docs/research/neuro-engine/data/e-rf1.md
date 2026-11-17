# E-RF1 theoretical resource model (ESTIMATES, not measurements)

## Calibration against published Pi 5 measurements (Arm Learning Path, llama.cpp Q4_0, best thread count)

| model | weights read / token | predicted tg bound @ 11.8 GB/s | published tg | ratio |
|---|---|---|---|---|
| Qwen2.5-0.5B Q4_0 | 403 MiB (file) | 27.9 tok/s | 33.8 tok/s | 1.21 |
| Qwen2.5-1.5B Q4_0 | 1011 MiB (file) | 11.1 tok/s | 12.4 tok/s | 1.11 |

(Qwen2.5-1.5B Q4_0 file size is the ggml-org/bartowski GGUF size, ~1011 MiB, UNVERIFIED to the MiB.)

## Decode upper bound on CM5 by weight format (tok/s, weights only, short context)

| model | params | Q8_0 | Q4_K_M | Q4_0 | Q3_K_M | Q2_K | IQ2_XXS | TQ2_0 / I2_S (ternary) | TQ1_0 (ternary) |
|---|---|---|---|---|---|---|---|---|---|
| Qwen3-0.6B | 0.60B | 18.6 | 32.7 | 35.2 | 40.6 | 60.3 | 76.9 | 76.8 | 93.9 |
| Qwen3-1.7B | 2.03B | 5.5 | 9.6 | 10.3 | 11.9 | 17.7 | 22.6 | 22.5 | 27.6 |
| Qwen3-4B-Instruct-2507 | 4.02B | 2.8 | 4.8 | 5.2 | 6.0 | 8.9 | 11.4 | 11.4 | 13.9 |
| Llama-3.2-1B-Instruct | 1.24B | 9.0 | 15.7 | 17.0 | 19.6 | 29.1 | 37.1 | 37.0 | 45.3 |
| Gemma-3-1B-it | 1.00B | 11.1 | 19.5 | 21.0 | 24.2 | 36.0 | 45.8 | 45.8 | 55.9 |
| EuroLLM-1.7B-Instruct | 1.70B | 7.7 | 13.5 | 14.6 | 16.8 | 25.0 | 31.9 | 31.8 | 38.9 |
| Qwen3.5-0.8B (18 DeltaNet + 6 attn) | 0.80B | 13.9 | 24.3 | 26.2 | 30.3 | 45.0 | 57.3 | 57.2 | 69.9 |
| Qwen3.5-2B (18 DeltaNet + 6 attn) | 2.00B | 5.6 | 9.7 | 10.5 | 12.1 | 18.0 | 22.9 | 22.9 | 28.0 |
| LFM2.5-1.2B (10 conv + 6 attn) | 1.17B | 9.5 | 16.6 | 17.9 | 20.7 | 30.7 | 39.2 | 39.1 | 47.8 |
| Granite-4.0-H-1B (36 Mamba2 + 4 attn) | 1.50B | 7.4 | 13.0 | 14.0 | 16.1 | 24.0 | 30.6 | 30.5 | 37.3 |
| RWKV-7 1.5B (24 layers, no attention) | 1.50B | 8.1 | 14.3 | 15.4 | 17.7 | 26.3 | 33.6 | 33.5 | 41.0 |
| BitNet b1.58 2B4T (ternary) | 2.41B | - | - | - | - | - | - | 14.9 (753 MiB) | - |

Ternary formats only make sense for NATIVELY ternary models (BitNet); post-training ternarisation of a normal model destroys it (see the IQ1/IQ2 perplexity table in NEURO_LITERATURE_REVIEW.md).

## Per-sequence state memory vs context (f16 KV unless noted; recurrent state fp32)

| model | KV / token (f16) | ctx 512 | ctx 2048 | ctx 8192 | ctx 32768 | ctx 8192 @ q8_0 KV |
|---|---|---|---|---|---|---|
| Qwen3-0.6B | 112 KiB | 56 MiB | 224 MiB | 896 MiB | 3584 MiB | 476 MiB |
| Qwen3-1.7B | 112 KiB | 56 MiB | 224 MiB | 896 MiB | 3584 MiB | 476 MiB |
| Qwen3-4B-Instruct-2507 | 144 KiB | 72 MiB | 288 MiB | 1152 MiB | 4608 MiB | 612 MiB |
| Llama-3.2-1B-Instruct | 32 KiB | 16 MiB | 64 MiB | 256 MiB | 1024 MiB | 136 MiB |
| Gemma-3-1B-it | 26 KiB | 13 MiB | 19 MiB | 43 MiB | 139 MiB | 23 MiB |
| EuroLLM-1.7B-Instruct | 96 KiB | 48 MiB | 192 MiB | 768 MiB | 3072 MiB | 408 MiB |
| Qwen3.5-0.8B (18 DeltaNet + 6 attn) | 12 KiB | 24 MiB | 42 MiB | 114 MiB | 402 MiB | 69 MiB |
| Qwen3.5-2B (18 DeltaNet + 6 attn) | 12 KiB | 24 MiB | 42 MiB | 114 MiB | 402 MiB | 69 MiB |
| LFM2.5-1.2B (10 conv + 6 attn) | 12 KiB | 6 MiB | 24 MiB | 96 MiB | 384 MiB | 51 MiB |
| Granite-4.0-H-1B (36 Mamba2 + 4 attn) | 8 KiB | 58 MiB | 70 MiB | 118 MiB | 310 MiB | 88 MiB |
| RWKV-7 1.5B (24 layers, no attention) | 0 | 12 MiB | 12 MiB | 12 MiB | 12 MiB | 12 MiB |
| BitNet b1.58 2B4T (ternary) | 75 KiB | 38 MiB | 150 MiB | 600 MiB | 2400 MiB | 319 MiB |

Reading: recurrent/hybrid models trade a context-proportional KV cache for a CONSTANT state that can be LARGER than a transformer's KV at short context (Granite-4.0-H-1B ~54 MiB). They win only when context is long or many sequences are kept alive.

## Bandwidth-budgeted decoding: max tok/s if AI may use at most X% of CM5 DRAM bandwidth

| model @ Q4_0 (BitNet @ I2_S) | bytes / token | 10% | 25% | 50% |
|---|---|---|---|---|
| Qwen3-0.6B | 320 MiB | 3.5 | 8.8 | 17.6 |
| Qwen3-1.7B | 1089 MiB | 1.0 | 2.6 | 5.2 |
| Qwen3-4B-Instruct-2507 | 2156 MiB | 0.5 | 1.3 | 2.6 |
| Llama-3.2-1B-Instruct | 663 MiB | 1.7 | 4.2 | 8.5 |
| Gemma-3-1B-it | 536 MiB | 2.1 | 5.2 | 10.5 |
| EuroLLM-1.7B-Instruct | 771 MiB | 1.5 | 3.6 | 7.3 |
| Qwen3.5-0.8B (18 DeltaNet + 6 attn) | 429 MiB | 2.6 | 6.6 | 13.1 |
| Qwen3.5-2B (18 DeltaNet + 6 attn) | 1073 MiB | 1.0 | 2.6 | 5.2 |
| LFM2.5-1.2B (10 conv + 6 attn) | 628 MiB | 1.8 | 4.5 | 9.0 |
| Granite-4.0-H-1B (36 Mamba2 + 4 attn) | 805 MiB | 1.4 | 3.5 | 7.0 |
| RWKV-7 1.5B (24 layers, no attention) | 733 MiB | 1.5 | 3.8 | 7.7 |
| BitNet b1.58 2B4T (ternary) | 753 MiB | 1.5 | 3.7 | 7.5 |

A decode at the full bound saturates DRAM for its whole duration; the packet path shares that DRAM (literature: ResQ NSDI'18, Sereno OSDI'26). Pacing tokens to a bandwidth share is a scheduler decision the Neuro Engine can make from bytes/token alone (proposal P4).

## Prefill compute bound on CM5 (int8 SDOT peak, all 4 cores) vs bandwidth

| model | MAC / token | compute-bound pp (tok/s) at 100% / 40% SIMD efficiency |
|---|---|---|
| Qwen3-0.6B | 0.60 G | 515 / 206 |
| Qwen3-1.7B | 2.03 G | 151 / 61 |
| Qwen3-4B-Instruct-2507 | 4.02 G | 76 / 31 |
| Llama-3.2-1B-Instruct | 1.24 G | 249 / 99 |
| Gemma-3-1B-it | 1.00 G | 307 / 123 |
| EuroLLM-1.7B-Instruct | 1.70 G | 181 / 72 |
| Qwen3.5-0.8B (18 DeltaNet + 6 attn) | 0.80 G | 384 / 154 |
| Qwen3.5-2B (18 DeltaNet + 6 attn) | 2.00 G | 154 / 61 |
| LFM2.5-1.2B (10 conv + 6 attn) | 1.17 G | 263 / 105 |
| Granite-4.0-H-1B (36 Mamba2 + 4 attn) | 1.50 G | 205 / 82 |
| RWKV-7 1.5B (24 layers, no attention) | 1.50 G | 205 / 82 |
| BitNet b1.58 2B4T (ternary) | 2.41 G | 127 / 51 |

Published: Qwen2.5-0.5B Q4_0 pp512 = 289.9 tok/s at 4 threads on Pi 5 (Arm LP) vs a 100% bound of ~622 -> ~47% of peak. Prefill is compute-bound, decode is bandwidth-bound: they want different thread counts (published: decode peaks at 2 threads).

## Storage as a memory tier (dense model, weights NOT resident: every token re-reads them)

| model @ Q4_0 | bytes / token | eMMC (HS400, up to ~400 MB/s per CM5 brief; 100-300 sustained typical) | NVMe on PCIe Gen2 x1 (5 GT/s, 8b/10b -> 500 MB/s link; ~400 MB/s practical) |
|---|---|---|---|
| Qwen3-0.6B | 320 MiB | 1.1-3.4 s/token | 0.8-1.0 s/token |
| Qwen3-1.7B | 1089 MiB | 3.8-11.4 s/token | 2.9-3.3 s/token |
| Qwen3-4B-Instruct-2507 | 2156 MiB | 7.5-22.6 s/token | 5.7-6.5 s/token |
| Llama-3.2-1B-Instruct | 663 MiB | 2.3-7.0 s/token | 1.7-2.0 s/token |

=> Storage cannot substitute for RAM in decode. Its legitimate role is the COLD tier: activation (load once, then decode from RAM).

## Cold activation (event-driven residency): time to page a model in once

| model @ Q4_0 | file | eMMC 100 MB/s | eMMC 300 MB/s | NVMe 400 MB/s |
|---|---|---|---|---|
| Qwen3-0.6B | 320 MiB | 3.4 s | 1.1 s | 0.8 s |
| Qwen3-1.7B | 1089 MiB | 11.4 s | 3.8 s | 2.9 s |
| Qwen3-4B-Instruct-2507 | 2156 MiB | 22.6 s | 7.5 s | 5.7 s |
| Llama-3.2-1B-Instruct | 663 MiB | 7.0 s | 2.3 s | 1.7 s |
| Gemma-3-1B-it | 536 MiB | 5.6 s | 1.9 s | 1.4 s |
| EuroLLM-1.7B-Instruct | 912 MiB | 9.6 s | 3.2 s | 2.4 s |
| Qwen3.5-0.8B (18 DeltaNet + 6 attn) | 429 MiB | 4.5 s | 1.5 s | 1.1 s |
| Qwen3.5-2B (18 DeltaNet + 6 attn) | 1073 MiB | 11.2 s | 3.8 s | 2.8 s |
| LFM2.5-1.2B (10 conv + 6 attn) | 628 MiB | 6.6 s | 2.2 s | 1.6 s |
| Granite-4.0-H-1B (36 Mamba2 + 4 attn) | 805 MiB | 8.4 s | 2.8 s | 2.1 s |
| RWKV-7 1.5B (24 layers, no attention) | 805 MiB | 8.4 s | 2.8 s | 2.1 s |
| BitNet b1.58 2B4T (ternary) | 753 MiB | 7.9 s | 2.6 s | 2.0 s |

On heqk there is no page cache or demand paging: activation = copy into an admitted budget (ADR 0061). The heqk eMMC driver's sustained read rate is UNMEASURED.

## Sources

- CM5: 32-bit LPDDR4X-4267 = 17.07 GB/s theoretical (raspberrypi.com processors docs). Effective 11.8 GB/s: Arm Learning Path llm-decode-roofline measured 11.82 GB/s on Pi 5 (13.78 GB/s single-thread max kernel, 10.7 GB/s at 4 threads). MEASURED BY ARM ON PI 5, NOT BY US ON CM5.
- N100: single-channel DDR5-4800 = 38.4 GB/s theoretical (Intel ARK lists DDR5-4800 / LPDDR5-4800, 1 channel). Effective 26.9 GB/s is an ASSUMPTION (70% of theoretical), UNMEASURED.
- A76 SIMD peak: 2x128-bit ASIMD pipes, SDOT 16 int8 MAC/instr (Arm Cortex-A76 SWOG); 2.4 GHz (CM5 brief).
- Model architectures: config.json of Qwen/Qwen3-0.6B, Qwen/Qwen3-1.7B, Qwen/Qwen3-4B-Instruct-2507, meta-llama/Llama-3.2-1B-Instruct, google/gemma-3-1b-it (5 local:1 global, window 512), utter-project/EuroLLM-1.7B-Instruct, Qwen/Qwen3.5-0.8B, Qwen/Qwen3.5-2B, LiquidAI/LFM2.5-1.2B-Instruct (conv_L_cache=3), ibm-granite/granite-4.0-h-1b, fla-hub/rwkv7-1.5B-world, microsoft/bitnet-b1.58-2B-4T.
