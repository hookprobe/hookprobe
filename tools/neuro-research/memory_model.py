#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Gate 7 memory and storage model for native inference on CM5 (theoretical; no device measured).

For each candidate model and weight representation: resident bytes split into weights, embedding,
KV cache or recurrent state, static scratch arena, tokenizer and runtime code; the bytes that must
cross the DRAM bus per generated token; a bandwidth-bound decode ceiling at a given share of the
CM5's measured-on-Pi-5 DRAM bandwidth; cold-load time from eMMC; and whether "streaming weights
from storage" is viable. Then the fit against the per-SKU AI budgets from NEURO_CM5_RESOURCE_BUDGET §5.

Config sources: Qwen3/Qwen3.5 values are read from the GGUF headers of the files evaluated in Phase 0
(tools: scratchpad gguf reader; values copied here). Others are marked with their source; any marked
UNVERIFIED must be checked against the model card before use.

Usage: python3 -I memory_model.py [--bw 11.8] [--share 1.0,0.25] [--emmc 100,250] [--ctx 512,2048]
"""
import argparse

MiB = 1024 ** 2
GiB = 1024 ** 3

# bits per weight INCLUDING block scales
FORMATS = {
    "Q8_0": 8.5,          # 32 int8 + f16 scale
    "Q4_0": 4.5,          # 32 x 4-bit + f16 scale
    "T2 (ternary 2-bit, per-tensor scale)": 2.0,
    "T1.67 (ternary 3 weights / 5 bits, TL2-like)": 5 / 3,
}

# name: dict(kind, layers, d, ff, heads, kv_heads, head_dim, vocab, tied, extra)
MODELS = {
    "Qwen3-0.6B (GGUF header)": dict(kind="transformer", layers=28, d=1024, ff=3072, heads=16, kv=8, hd=128,
                                     vocab=151936, tied=True, src="GGUF header, Phase 0 file"),
    "Qwen3-1.7B (GGUF header)": dict(kind="transformer", layers=28, d=2048, ff=6144, heads=16, kv=8, hd=128,
                                     vocab=151936, tied=True, src="GGUF header, Phase 0 file"),
    "Qwen3.5-0.8B (GGUF header)": dict(kind="hybrid-gdn", layers=24, attn_every=4, d=1024, ff=3584, heads=8, kv=2,
                                       hd=256, vocab=248320, tied=True, ssm_heads=16, ssm_k=128, ssm_v=128,
                                       ssm_inner=2048, conv=4, src="GGUF header (vocab from embedding tensor 254279680/1024)"),
    "BitNet b1.58 2B4T": dict(kind="transformer", layers=30, d=2560, ff=6912, heads=20, kv=5, hd=128, vocab=128256,
                              tied=True, native_ternary=True, src="model card values recalled -- UNVERIFIED"),
    "RWKV-7 0.4B": dict(kind="rwkv7", layers=24, d=1024, ff=4096, head=64, vocab=65536, tied=False,
                        src="RWKV-7 paper arXiv 2503.14456 (L24, D1024); state derived, matches the research pass (6.2 MiB)"),
    "RWKV-7 1.5B": dict(kind="rwkv7", layers=24, d=2048, ff=8192, head=64, vocab=65536, tied=False,
                        src="RWKV-7 paper arXiv 2503.14456 (L24, D2048); FFN 4D assumed"),
    "Security specialist (proposed)": dict(kind="specialist", params=2_000_000, state_per_device=256,
                                           src="design target, not a model"),
}

SKU_AI_BUDGET = {"2 GB": 256 * MiB, "4 GB": 1 * GiB, "8 GB": int(2.5 * GiB), "16 GB": 6 * GiB}
TOKENIZER = {151936: 4 * MiB, 248320: 6 * MiB, 128256: 3.5 * MiB, 65536: 1 * MiB}  # ESTIMATES (binary vocab+merges)
RUNTIME_CODE = 1 * MiB  # ESTIMATE: target for a no_std engine incl. kernels


def matrix_params(m):
    """Parameters in the per-layer weight matrices (the part that is quantised and read every token)."""
    d, L = m["d"], m["layers"]
    if m["kind"] == "transformer":
        attn = d * m["heads"] * m["hd"] + 2 * d * m["kv"] * m["hd"] + m["heads"] * m["hd"] * d
        return L * (attn + 3 * d * m["ff"])
    if m["kind"] == "hybrid-gdn":
        n_attn = L // m["attn_every"]
        attn = d * m["heads"] * m["hd"] * 2 + 2 * d * m["kv"] * m["hd"] + m["heads"] * m["hd"] * d  # q has a gate half
        gdn = d * (2 * m["ssm_heads"] * m["ssm_k"] + 2 * m["ssm_inner"]) + m["ssm_inner"] * d + d * 2 * m["ssm_heads"]
        return n_attn * (attn + 3 * d * m["ff"]) + (L - n_attn) * (gdn + 3 * d * m["ff"])
    if m["kind"] == "rwkv7":
        # time-mix: r,k,v,o (4 d^2) + low-rank adapters (~0.1 d^2, approx); channel-mix: d*ff*2
        return L * (4 * d * d + int(0.1 * d * d) + 2 * d * m["ff"])
    raise ValueError


def ctx_state_bytes(m, ctx, kv_bytes=2.0):
    if m["kind"] == "transformer":
        return m["layers"] * 2 * m["kv"] * m["hd"] * ctx * kv_bytes
    if m["kind"] == "hybrid-gdn":
        n_attn = m["layers"] // m["attn_every"]
        kv = n_attn * 2 * m["kv"] * m["hd"] * ctx * kv_bytes
        st = (m["layers"] - n_attn) * (m["ssm_heads"] * m["ssm_k"] * m["ssm_v"] * 4 + (m["conv"] - 1) * (2 * m["ssm_heads"] * m["ssm_k"] + m["ssm_inner"]) * 4)
        return kv + st
    if m["kind"] == "rwkv7":
        heads = m["d"] // m["head"]
        return m["layers"] * (heads * m["head"] * m["head"] * 4 + 2 * m["d"] * 4)  # f32 WKV state + 2 token shifts
    return 0


def scratch_bytes(m, ctx):
    """Static arena: the largest set of simultaneously live activations for ONE token (decode), f32,
    plus int8 copies of the activation for quantised matmuls, plus the logits."""
    if m["kind"] == "specialist":
        return 64 * 1024
    d = m["d"]
    ff = m.get("ff", 4 * d)
    heads = m.get("heads", d // m.get("head", 64))
    live = 3 * d + 2 * ff + heads * ctx  # residual, normed x, attn out | gate+up | attention scores
    return live * 4 + (d + ff) + m["vocab"] * 4


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bw", type=float, default=11.8, help="GB/s DRAM, Pi 5 measured overall (Arm Learning Path)")
    ap.add_argument("--share", default="1.0,0.25", help="fractions of bandwidth the AI lease may use")
    ap.add_argument("--emmc", default="100,250", help="MB/s eMMC sequential read range (UNMEASURED on heqk)")
    ap.add_argument("--ctx", default="512,2048")
    a = ap.parse_args()
    shares = [float(x) for x in a.share.split(",")]
    emmc = [float(x) for x in a.emmc.split(",")]
    ctxs = [int(x) for x in a.ctx.split(",")]
    print("THEORETICAL. DRAM %.1f GB/s (Pi 5 measured, same SoC); eMMC %s MB/s (assumed range); KV f16." % (a.bw, a.emmc))
    print("decode ceiling = bus share x bandwidth / bytes read per token; real decode is lower (compute, cache, scheduling)\n")
    hdr = "| model | format | weights MiB | embed MiB | state @%s | scratch MiB | tokenizer+code MiB | total @%d MiB | bytes/token MiB | tok/s ceiling @%s share | cold load s @%s MB/s | stream-from-eMMC s/token | fits SKU (AI budget) |" % (
        "/".join(map(str, ctxs)), ctxs[-1], "/".join("%d%%" % (s * 100) for s in shares), "/".join("%g" % e for e in emmc))
    print(hdr)
    print("|" + "---|" * hdr.count("|")[:-1] if False else "|---" * (hdr.count("|") - 1) + "|")
    for name, m in MODELS.items():
        if m["kind"] == "specialist":
            w = m["params"] * 1.0
            st = m["state_per_device"] * 1000
            tot = w + st + scratch_bytes(m, 0) + 256 * 1024
            fits = ", ".join(k for k, v in SKU_AI_BUDGET.items() if tot <= v)
            print("| %s | int8 | %.1f | - | %.2f (1,000 devices) | 0.06 | 0.25 | %.1f | %.1f | n/a (per event, not per token) | <0.1 | n/a | %s |" % (
                name, w / MiB, st / MiB, tot / MiB, w / MiB, fits))
            continue
        mp = matrix_params(m)
        emb = m["vocab"] * m["d"]
        for fmt, bits in FORMATS.items():
            if fmt.startswith("T") and not m.get("native_ternary") and m["kind"] != "rwkv7":
                continue  # ternary only for models TRAINED ternary (post-hoc ternarisation of others destroys quality)
            if fmt.startswith("T") and m["kind"] == "rwkv7":
                continue
            wb = mp * bits / 8
            eb = emb * 8.5 / 8 * (1 if m["tied"] else 2)
            sts = [ctx_state_bytes(m, c) for c in ctxs]
            sc = scratch_bytes(m, ctxs[-1])
            tk = TOKENIZER.get(m["vocab"], 4 * MiB) + RUNTIME_CODE
            tot = wb + eb + sts[-1] + sc + tk
            # per token: all matrices + output head (tied embedding read fully for logits) + state/KV read
            per_tok = wb + emb * 8.5 / 8 + sts[-1]
            ceil = [s * a.bw * 1e9 / per_tok for s in shares]
            cold = [(wb + eb) / (e * 1e6) for e in emmc]
            stream = per_tok / (emmc[-1] * 1e6)
            fits = ", ".join(k for k, v in SKU_AI_BUDGET.items() if tot <= v) or "none"
            print("| %s | %s | %.0f | %.0f | %s | %.1f | %.1f | %.0f | %.0f | %s | %s | %.1f | %s |" % (
                name, fmt, wb / MiB, eb / MiB, " / ".join("%.1f" % (s / MiB) for s in sts), sc / MiB, tk / MiB,
                tot / MiB, per_tok / MiB, " / ".join("%.0f" % c for c in ceil), " / ".join("%.1f" % c for c in cold),
                stream, fits))
    print("\nSources: " + "; ".join("%s: %s" % (k, v["src"]) for k, v in MODELS.items()))
    print("SKU AI budgets (planning assumptions, NEURO_CM5_RESOURCE_BUDGET §5): " +
          ", ".join("%s <= %d MiB" % (k, v // MiB) for k, v in SKU_AI_BUDGET.items()))


if __name__ == "__main__":
    main()
