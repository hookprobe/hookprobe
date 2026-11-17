#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Experiment E-RF1: THEORETICAL resource model for CM5 (and N100) -- decode/prefill bounds, KV-vs-
recurrent state memory, bandwidth-budgeted decoding, storage-tier cost, cold activation.

EVERYTHING this prints is a THEORETICAL ESTIMATE from published hardware figures and model configs.
It is not a measurement. It is calibrated once against two PUBLISHED Pi 5 measurements (Arm Learning
Path, same BCM2712 + LPDDR4X as CM5) so the reader can see how far the model is from reality.

Architecture numbers come from each model's config.json on Hugging Face (fetched 2026-11-17; repo ids in
MODELS). Hardware numbers and their sources are in HW. Quantisation bits-per-weight are llama.cpp's
block formats (ggml-common.h): Q8_0 = 34 B / 32 w, Q4_0 = 18 B / 32 w, Q4_K ~4.5 bpw, Q2_K ~2.625 bpw,
TQ2_0 = 66 B / 256 w, TQ1_0 = 54 B / 256 w, IQ2_XXS ~2.06 bpw; bitnet.cpp I2_S = 2 bpw (+ scale).

Usage: python3 -I roofline.py [--markdown]
"""
import argparse

GB = 1e9
MiB = 1024 * 1024

HW = {
    # name: (theoretical GB/s, effective GB/s used for bounds, source / status)
    "CM5": (17.07, 11.8,
            "32-bit LPDDR4X-4267 = 17.07 GB/s theoretical (raspberrypi.com processors docs). Effective 11.8 GB/s: "
            "Arm Learning Path llm-decode-roofline measured 11.82 GB/s on Pi 5 (13.78 GB/s single-thread max "
            "kernel, 10.7 GB/s at 4 threads). MEASURED BY ARM ON PI 5, NOT BY US ON CM5."),
    "N100": (38.4, 26.9,
             "single-channel DDR5-4800 = 38.4 GB/s theoretical (Intel ARK lists DDR5-4800 / LPDDR5-4800, 1 channel). "
             "Effective 26.9 GB/s is an ASSUMPTION (70% of theoretical), UNMEASURED."),
}
# Cortex-A76: 2 x 128-bit ASIMD pipes; SDOT = 16 int8 MAC per instruction -> 32 MAC/cycle/core.
A76_MAC_PER_S = 4 * 2.4e9 * 32
STORAGE = {"eMMC (HS400, up to ~400 MB/s per CM5 brief; 100-300 sustained typical)": (0.1e9, 0.3e9),
           "NVMe on PCIe Gen2 x1 (5 GT/s, 8b/10b -> 500 MB/s link; ~400 MB/s practical)": (0.35e9, 0.4e9)}

BPW = {"Q8_0": 8.5, "Q4_K_M": 4.85, "Q4_0": 4.5, "Q3_K_M": 3.9, "Q2_K": 2.625, "IQ2_XXS": 2.06,
       "TQ2_0 / I2_S (ternary)": 2.0625, "TQ1_0 (ternary)": 1.6875}

# name: dict(params total (B), vocab, hidden, tied, attn layers, kv heads, head_dim, window (None=full),
#            n_window_layers, recurrent state floats per sequence, hf)
MODELS = [
    dict(name="Qwen3-0.6B", p=0.596, vocab=151936, hidden=1024, tied=True, attn=28, kvh=8, hd=128,
         rec=0, hf="Qwen/Qwen3-0.6B"),
    dict(name="Qwen3-1.7B", p=2.03, vocab=151936, hidden=2048, tied=True, attn=28, kvh=8, hd=128,
         rec=0, hf="Qwen/Qwen3-1.7B"),
    dict(name="Qwen3-4B-Instruct-2507", p=4.02, vocab=151936, hidden=2560, tied=True, attn=36, kvh=8, hd=128,
         rec=0, hf="Qwen/Qwen3-4B-Instruct-2507"),
    dict(name="Llama-3.2-1B-Instruct", p=1.236, vocab=128256, hidden=2048, tied=True, attn=16, kvh=8, hd=64,
         rec=0, hf="meta-llama/Llama-3.2-1B-Instruct"),
    dict(name="Gemma-3-1B-it", p=1.0, vocab=262144, hidden=1152, tied=True, attn=26, kvh=1, hd=256,
         window=512, wl=26 - 26 // 6, rec=0, hf="google/gemma-3-1b-it (5 local:1 global, window 512)"),
    dict(name="EuroLLM-1.7B-Instruct", p=1.7, vocab=128000, hidden=2048, tied=False, attn=24, kvh=8, hd=128,
         rec=0, hf="utter-project/EuroLLM-1.7B-Instruct"),
    # hybrids / recurrent: state floats per sequence computed from config (fp32 state assumed)
    dict(name="Qwen3.5-0.8B (18 DeltaNet + 6 attn)", p=0.8, vocab=248320, hidden=1024, tied=True, attn=6, kvh=2,
         hd=256, rec=18 * 16 * 128 * 128, hf="Qwen/Qwen3.5-0.8B"),
    dict(name="Qwen3.5-2B (18 DeltaNet + 6 attn)", p=2.0, vocab=248320, hidden=2048, tied=True, attn=6, kvh=2,
         hd=256, rec=18 * 16 * 128 * 128, hf="Qwen/Qwen3.5-2B"),
    dict(name="LFM2.5-1.2B (10 conv + 6 attn)", p=1.17, vocab=65536, hidden=2048, tied=True, attn=6, kvh=8,
         hd=64, rec=10 * 2048 * 2, hf="LiquidAI/LFM2.5-1.2B-Instruct (conv_L_cache=3)"),
    dict(name="Granite-4.0-H-1B (36 Mamba2 + 4 attn)", p=1.5, vocab=100352, hidden=1536, tied=True, attn=4,
         kvh=4, hd=128, rec=36 * 48 * 64 * 128, hf="ibm-granite/granite-4.0-h-1b"),
    dict(name="RWKV-7 1.5B (24 layers, no attention)", p=1.5, vocab=65536, hidden=2048, tied=False, attn=0,
         kvh=0, hd=0, rec=24 * (2048 // 64) * 64 * 64, hf="fla-hub/rwkv7-1.5B-world"),
    dict(name="BitNet b1.58 2B4T (ternary)", p=2.41, vocab=128256, hidden=2560, tied=True, attn=30, kvh=5,
         hd=128, rec=0, native_bpw=2.0, emb_bpw=6.5625, hf="microsoft/bitnet-b1.58-2B-4T"),
]


def kv_bytes_per_token(m, kv_bytes_per_elem):
    return 2 * m["attn"] * m["kvh"] * m["hd"] * kv_bytes_per_elem


def state_bytes(m, ctx, kv_bpe=2.0, rec_bpe=4.0):
    """KV cache (sliding-window layers capped at the window) + constant recurrent state."""
    per_layer_tok = 2 * m["kvh"] * m["hd"] * kv_bpe
    w, wl = m.get("window"), m.get("wl", 0)
    full_layers = m["attn"] - wl
    kv = full_layers * per_layer_tok * ctx + wl * per_layer_tok * min(ctx, w or ctx)
    return kv + m["rec"] * rec_bpe


def weight_bytes_read_per_token(m, bpw):
    """Decode reads every weight once per token, EXCEPT the input embedding table of an UNTIED model
    (one row is gathered). A tied table is read in full as the output head."""
    emb = m["vocab"] * m["hidden"]
    if "native_bpw" in m:  # ternary linear layers + higher-precision embedding/head
        return (m["p"] * 1e9 - emb) * m["native_bpw"] / 8 + emb * m["emb_bpw"] / 8
    readable = m["p"] * 1e9 - (0 if m["tied"] else emb)
    return readable * bpw / 8


def fmt_mib(b):
    return "%.0f MiB" % (b / MiB) if b >= MiB else "%.0f KiB" % (b / 1024)


def main():
    ap = argparse.ArgumentParser()
    ap.parse_args()
    cm5_bw = HW["CM5"][1] * GB

    print("# E-RF1 theoretical resource model (ESTIMATES, not measurements)\n")
    print("## Calibration against published Pi 5 measurements (Arm Learning Path, llama.cpp Q4_0, best thread count)\n")
    print("| model | weights read / token | predicted tg bound @ 11.8 GB/s | published tg | ratio |")
    print("|---|---|---|---|---|")
    for name, mib, meas in (("Qwen2.5-0.5B Q4_0", 403, 33.8), ("Qwen2.5-1.5B Q4_0", 1011, 12.4)):
        pred = cm5_bw / (mib * MiB)
        print("| %s | %d MiB (file) | %.1f tok/s | %.1f tok/s | %.2f |" % (name, mib, pred, meas, meas / pred))
    print("\n(Qwen2.5-1.5B Q4_0 file size is the ggml-org/bartowski GGUF size, ~1011 MiB, UNVERIFIED to the MiB.)\n")

    print("## Decode upper bound on CM5 by weight format (tok/s, weights only, short context)\n")
    hdr = list(BPW)
    print("| model | params | " + " | ".join(hdr) + " |")
    print("|---" * (len(hdr) + 2) + "|")
    for m in MODELS:
        if "native_bpw" in m:
            b = weight_bytes_read_per_token(m, 0)
            cells = ["-"] * (len(hdr) - 2) + ["%.1f (%.0f MiB)" % (cm5_bw / b, b / MiB), "-"]
        else:
            cells = []
            for f, bpw in BPW.items():
                b = weight_bytes_read_per_token(m, bpw)
                cells.append("%.1f" % (cm5_bw / b))
        print("| %s | %.2fB | %s |" % (m["name"], m["p"], " | ".join(cells)))
    print("\nTernary formats only make sense for NATIVELY ternary models (BitNet); post-training ternarisation of a "
          "normal model destroys it (see the IQ1/IQ2 perplexity table in NEURO_LITERATURE_REVIEW.md).\n")

    print("## Per-sequence state memory vs context (f16 KV unless noted; recurrent state fp32)\n")
    ctxs = [512, 2048, 8192, 32768]
    print("| model | KV / token (f16) | " + " | ".join("ctx %d" % c for c in ctxs) + " | ctx 8192 @ q8_0 KV |")
    print("|---" * (len(ctxs) + 3) + "|")
    for m in MODELS:
        kvt = kv_bytes_per_token(m, 2.0)
        cells = [fmt_mib(state_bytes(m, c)) for c in ctxs]
        print("| %s | %s | %s | %s |" % (m["name"], fmt_mib(kvt) if kvt else "0", " | ".join(cells),
                                         fmt_mib(state_bytes(m, 8192, kv_bpe=1.0625))))
    print("\nReading: recurrent/hybrid models trade a context-proportional KV cache for a CONSTANT state that can "
          "be LARGER than a transformer's KV at short context (Granite-4.0-H-1B ~54 MiB). They win only when "
          "context is long or many sequences are kept alive.\n")

    print("## Bandwidth-budgeted decoding: max tok/s if AI may use at most X% of CM5 DRAM bandwidth\n")
    shares = [0.10, 0.25, 0.50]
    print("| model @ Q4_0 (BitNet @ I2_S) | bytes / token | " + " | ".join("%d%%" % (s * 100) for s in shares) + " |")
    print("|---" * (len(shares) + 2) + "|")
    for m in MODELS:
        b = weight_bytes_read_per_token(m, BPW["Q4_0"])
        print("| %s | %s | %s |" % (m["name"], fmt_mib(b), " | ".join("%.1f" % (cm5_bw * s / b) for s in shares)))
    print("\nA decode at the full bound saturates DRAM for its whole duration; the packet path shares that DRAM "
          "(literature: ResQ NSDI'18, Sereno OSDI'26). Pacing tokens to a bandwidth share is a scheduler decision "
          "the Neuro Engine can make from bytes/token alone (proposal P4).\n")

    print("## Prefill compute bound on CM5 (int8 SDOT peak, all 4 cores) vs bandwidth\n")
    print("| model | MAC / token | compute-bound pp (tok/s) at 100% / 40% SIMD efficiency |")
    print("|---|---|---|")
    for m in MODELS:
        macs = m["p"] * 1e9
        print("| %s | %.2f G | %.0f / %.0f |" % (m["name"], macs / 1e9, A76_MAC_PER_S / macs, 0.4 * A76_MAC_PER_S / macs))
    print("\nPublished: Qwen2.5-0.5B Q4_0 pp512 = 289.9 tok/s at 4 threads on Pi 5 (Arm LP) vs a 100%% bound of "
          "~%.0f -> ~47%% of peak. Prefill is compute-bound, decode is bandwidth-bound: they want different "
          "thread counts (published: decode peaks at 2 threads).\n" % (A76_MAC_PER_S / 0.494e9))

    print("## Storage as a memory tier (dense model, weights NOT resident: every token re-reads them)\n")
    print("| model @ Q4_0 | bytes / token | " + " | ".join(STORAGE) + " |")
    print("|---" * (len(STORAGE) + 2) + "|")
    for m in MODELS[:4]:
        b = weight_bytes_read_per_token(m, BPW["Q4_0"])
        cells = ["%.1f-%.1f s/token" % (b / hi, b / lo) for lo, hi in STORAGE.values()]
        print("| %s | %s | %s |" % (m["name"], fmt_mib(b), " | ".join(cells)))
    print("\n=> Storage cannot substitute for RAM in decode. Its legitimate role is the COLD tier: activation "
          "(load once, then decode from RAM).\n")

    print("## Cold activation (event-driven residency): time to page a model in once\n")
    print("| model @ Q4_0 | file | eMMC 100 MB/s | eMMC 300 MB/s | NVMe 400 MB/s |")
    print("|---|---|---|---|---|")
    for m in MODELS:
        if "native_bpw" in m:
            b = weight_bytes_read_per_token(m, 0)
        else:
            emb = m["vocab"] * m["hidden"]
            b = (m["p"] * 1e9 + (0 if m["tied"] else emb) * 0) * BPW["Q4_0"] / 8
        print("| %s | %s | %.1f s | %.1f s | %.1f s |" % (m["name"], fmt_mib(b), b / 0.1e9, b / 0.3e9, b / 0.4e9))
    print("\nOn heqk there is no page cache or demand paging: activation = copy into an admitted budget "
          "(ADR 0061). The heqk eMMC driver's sustained read rate is UNMEASURED.\n")

    print("## Sources\n")
    for k, v in HW.items():
        print("- %s: %s" % (k, v[2]))
    print("- A76 SIMD peak: 2x128-bit ASIMD pipes, SDOT 16 int8 MAC/instr (Arm Cortex-A76 SWOG); 2.4 GHz (CM5 brief).")
    print("- Model architectures: config.json of " + ", ".join(m["hf"] for m in MODELS) + ".")


if __name__ == "__main__":
    main()
