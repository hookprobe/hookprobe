# 07 — Memory and storage model (Gate 7)

> Native Inference Research Programme, 2026-11-18. **Theoretical** unless marked. Nothing here was
> measured on a CM5 or on heqk. Script: `tools/neuro-research/memory_model.py`; outputs:
> [`data/memory-model.md`](data/memory-model.md) (512/2,048-token context) and
> [`data/memory-model-shortctx.md`](data/memory-model-shortctx.md) (256/512).

## 1. What "memory" means for one inference

Resident bytes for one model instance are the sum of the following rows. They are listed in the
order they matter on a CM5.

| Component | What it is | Size driver | Read per generated token? |
|---|---|---|---|
| Layer weights | quantised matrices (attention or time-mix, FFN or channel-mix) | params × bits/weight | **all of them** (decode is a GEMV per matrix) |
| Embedding / output head | vocab × d table; tied models use it twice (input row lookup + output logits) | vocab × d × 8.5 bits | **all of it** for the logits; one row for the input |
| KV cache (attention) or recurrent state | per-layer keys/values for every past token, or a fixed per-layer state | ctx × layers × 2 × kv_heads × head_dim × bytes; or constant | all of it (attention reads every past key/value) |
| Scratch arena | activations live during one token: residual, normed input, q/k/v, attention scores, FFN gate+up, logits | d, ff, heads × ctx, vocab | written and read, cache-resident if small |
| Tokenizer | vocab strings + merges in a binary table | vocab | no (once per request) |
| Runtime code | engine + kernels | — | instruction cache only |

Plus what is **not** the AI's to take (NEURO_CM5_RESOURCE_BUDGET §5): kernel, data plane, flow
tables, Mission Control, the ADR 0061 management reserve (≥ 64 MiB, D9) and a headroom reserve.

## 2. Results (bus share 100% / 25% of the 11.8 GB/s measured on a Pi 5; f16 KV)

| Model, format | Weights + head MiB | Context state @2K | **Total @2K MiB** | Read per token MiB | Decode ceiling tok/s (100% / 25% bus) | Cold load s (100 / 250 MB/s eMMC) | Fits AI budget of |
|---|---|---|---|---|---|---|---|
| Qwen3-0.6B Q4_0 | 236 + 158 | 224 MiB (KV) | 624 | 618 | 18 / 5 | 4.1 / 1.7 | 4, 8, 16 GB |
| Qwen3-1.7B Q4_0 | 756 + 315 | 224 MiB | 1,301 | 1,295 | 9 / 2 | 11.2 / 4.5 | 8, 16 GB |
| Qwen3.5-0.8B Q4_0 (hybrid) | 267 + 258 | 43 MiB (6 attn layers KV + 18 GDN states) | 576 | 568 | 20 / 5 | 5.5 / 2.2 | 4, 8, 16 GB |
| BitNet b1.58 2B4T, ternary 2-bit* | 497 + 333 | 150 MiB | 985 | 980 | 11 / 3 | 8.7 / 3.5 | 4, 8, 16 GB |
| BitNet b1.58 2B4T, 1.67-bit (TL2-like)* | 414 + 333 | 150 MiB | 902 | 897 | 13 / 3 | 7.8 / 3.1 | 4, 8, 16 GB |
| RWKV-7 0.4B Q4_0* | 163 + 136 | **6.2 MiB, constant** | 308 | 238 | 47 / 12 | 3.1 / 1.3 | 4, 8, 16 GB |
| RWKV-7 1.5B Q4_0* | 653 + 272 | **12.4 MiB, constant** | 940 | 802 | 14 / 4 | 9.7 / 3.9 | 4, 8, 16 GB |
| Security specialist (proposed, 2 M params int8) | 1.9 | 256 B per device (0.24 MiB per 1,000 devices) | 2.5 | — (per event) | — | < 0.1 | **all, incl. 2 GB** |

* RWKV-7 configs checked against arXiv 2503.14456; BitNet configs recalled from the model card, **UNVERIFIED** until checked against the primary
source (see `05`/`10` for the checked values; the script is updated when they differ).

The tok/s ceilings are **bandwidth ceilings**. They assume the bus is the only limit; `02` shows
that ternary kernels are compute-bound on one A76 core, so their real ceiling is lower than the
bandwidth figure until more cores are leased.

## 3. Findings

1. **No model fits the 2 GB SKU's 256 MiB AI budget except specialists.** Even RWKV-7 0.4B at Q4_0
   needs about 300 MiB. On 2 GB the generative tier stays off-device; the temporal and specialist
   tier fits easily.
2. **For small models, the output head is the largest single read.** Qwen3-0.6B's tied 151,936 × 1,024
   embedding is 158 MiB at 8.5 bits. That is 40% of the per-token weight traffic at Q4_0. Two levers
   follow (both hypotheses, see `10`):
   - **vocabulary trimming** to the EN/RO/security subset, which shrinks memory and every token's read;
   - **constraint-aware sparse logits**: under evidence-closed decoding, compute logits only for the
     tokens the grammar allows.
3. **At useful contexts the KV cache rivals the weights.** At 2,048 tokens Qwen3's f16 KV (224 MiB)
   equals its Q4_0 layer weights. It is also read in full on every token. RWKV-7's state is constant
   (6–12 MiB), and the Qwen3.5 hybrid holds a 43 MiB mixed state. This is the strongest *memory*
   argument for recurrent models on this device. It is independent of the quality question, which
   `04` and `11` treat separately.
4. **On heqk today, storage is far slower than this table assumes.** The eMMC driver uses PIO at
   ≤ 25 MHz and never issues CMD6, so it stays in default-speed mode with the power-on bus width
   (`00` §3.6). The arithmetic ceiling is ≈ 3.1 MB/s on 1 data line, ≈ 12.5 MB/s on 4. A 300 MiB
   model then takes **25–100 s** to load, not 1–3 s. There is also no EL0 path to read it at all.
   Re-run the script with `--emmc 3,12` for heqk figures.

   **Storage is a loading tier, never a decode tier.** Streaming the weights from eMMC costs 1–11 s
   **per token** at 250 MB/s, against 0.05–0.5 s from DRAM. Block-wise or layer-wise streaming does
   not change the arithmetic: every token touches every layer. Storage-backed inference is rejected
   for decode. It remains valid for:
   - cold load (2–11 s);
   - **mixture-of-experts** routing, where only the selected experts must be resident. This is
     unproven for security models (`04`).
5. **Cold activation is seconds on Linux-class storage and minutes on heqk's current eMMC path** ([`data/memory-model-heqk-emmc.md`](data/memory-model-heqk-emmc.md): RWKV-7 0.4B Q4_0 ≈ 25–101 s, Qwen3-0.6B Q4_0 ≈ 33–133 s). Seconds would be acceptable for event-driven explanation (one
   activation per incident burst). It argues for keeping the model resident only on SKUs with room
   and loading on demand elsewhere. Two eMMC facts are unknown on heqk (`00`):
   - whether eMMC read throughput on heqk reaches the assumed range;
   - whether eMMC can be read at all into an EL0-visible region.
6. **Scratch arenas are small** (under 1.2 MiB at 2K context) and statically plannable. One
   decode-step arena per model instance fits in L2/L3-adjacent memory, so dynamic allocation during
   inference is unnecessary (`05`).

## 4. Budget per SKU (planning, extends NEURO_CM5_RESOURCE_BUDGET §5)

| SKU | AI budget (assumed) | What fits | Recommendation |
|---|---|---|---|
| 2 GB | ≤ 256 MiB | specialists + per-device state for thousands of devices | temporal/specialist tier only; language tier off-device |
| 4 GB | ≤ 1 GiB | one ≤ 1B model *or* RWKV-7 ≤ 1.5B Q4_0 *or* BitNet 2B ternary, on demand | one language model, leased |
| 8 GB | ≤ 2.5 GiB | a ≤ 2B model resident, or two small ones | language model resident if bus pacing passes E-INT |
| 16 GB | ≤ 6 GiB | several models; larger contexts | capacity is not the limit; bandwidth is |

## 5. Memory techniques, with a verdict for heqk

| Technique | Verdict | Why |
|---|---|---|
| Static arenas, buffer reuse, in-place ops | **adopt** | sizes are known at compile time (`06` execution plan); removes allocator from the hot path |
| Operator fusion (norm+quantise, gate·up+SiLU, RoPE in the QK kernel) | **adopt** | removes scratch round-trips; see `01` |
| Read-only, shareable weight region | **adopt** (needs kernel support, `12`) | integrity (W^X-like for data) and one copy across instances |
| KV-cache quantisation (q8_0 KV) | adopt for transformers | halves the dominant context cost; small quality risk to verify |
| Context compression (evidence cards, P1) | **adopt — already validated** | the largest lever measured so far: ~500 tokens per hour on synthetic data; real-traffic results in Phase 0 |
| Recurrent state instead of KV | **experiment** (`11` E-N2) | constant memory; quality on security tasks unknown |
| Weight streaming from storage during decode | **reject** | 1–11 s per token |
| Layer-wise loading | reject for decode; fine for cold start | same arithmetic |
| Demand-paged weights | **reject on heqk** | no page cache; non-deterministic latency; violates ADR 0061 "no overcommit" |
