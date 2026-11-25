#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Doc 46: rebuild HF safetensors (float32) from a merged Qwen3 GGUF, so a new LoRA can be trained ON an adapter that
only survives as a merged GGUF (ftFg: its LoRA weights were lost on 2026-11-24).

Q8_0 dequantizes exactly to q * d. Stored as float32 (bf16 would round it), the result re-quantizes to the same
Q8_0 blocks; `verify` checks that tensor by tensor against the source GGUF.
Config and tokenizer files come from the base model directory (a merge never changes them).

Usage: gguf_to_hf.py build  <in.gguf> <base hf dir> <out dir>
       gguf_to_hf.py verify <a.gguf> <b.gguf>        (every tensor: same type, shape and bytes)
Needs llama.cpp's gguf-py (venv-convert) and numpy + safetensors.
"""
import json, os, re, shutil, sys
import numpy as np
from gguf import GGUFReader
from gguf.quants import dequantize

MAP = {"token_embd.weight": "model.embed_tokens.weight", "output_norm.weight": "model.norm.weight",
       "output.weight": "lm_head.weight"}
BLK = {"attn_q": "self_attn.q_proj", "attn_k": "self_attn.k_proj", "attn_v": "self_attn.v_proj",
       "attn_output": "self_attn.o_proj", "attn_q_norm": "self_attn.q_norm", "attn_k_norm": "self_attn.k_norm",
       "attn_norm": "input_layernorm", "ffn_norm": "post_attention_layernorm", "ffn_gate": "mlp.gate_proj",
       "ffn_up": "mlp.up_proj", "ffn_down": "mlp.down_proj"}


def hf_name(n):
    if n in MAP:
        return MAP[n]
    m = re.match(r"blk\.(\d+)\.(\w+)\.(weight|bias)$", n)
    if not m or m.group(2) not in BLK:
        raise SystemExit("unmapped tensor %s" % n)
    return "model.layers.%s.%s.%s" % (m.group(1), BLK[m.group(2)], m.group(3))


def build(src, base, out):
    from safetensors.numpy import save_file
    r = GGUFReader(src)
    arch = r.fields["general.architecture"]
    if bytes(arch.parts[arch.data[0]]).decode() != "qwen3":
        raise SystemExit("not a qwen3 gguf")
    want = json.load(open(os.path.join(base, "model.safetensors.index.json")))["weight_map"]
    ts = {}
    for t in r.tensors:
        a = dequantize(t.data, t.tensor_type).astype(np.float32)
        ts[hf_name(t.name)] = np.ascontiguousarray(a.reshape(tuple(int(x) for x in reversed(t.shape))))
    if "lm_head.weight" in want and "lm_head.weight" not in ts:
        cfg = json.load(open(os.path.join(base, "config.json")))
        if not cfg.get("tie_word_embeddings"):
            raise SystemExit("no output tensor and embeddings are not tied")
        want = {k: v for k, v in want.items() if k != "lm_head.weight"}  # tied: no separate head, as in a fused model
    if set(ts) != set(want):
        raise SystemExit("tensor set differs from base: missing %s extra %s" % (sorted(set(want) - set(ts))[:5],
                                                                               sorted(set(ts) - set(want))[:5]))
    os.makedirs(out, exist_ok=True)
    save_file(ts, os.path.join(out, "model.safetensors"), metadata={"format": "pt"})
    for f in os.listdir(base):
        if f.endswith(".json") and f != "model.safetensors.index.json" or f in ("merges.txt", "LICENSE"):
            shutil.copy(os.path.join(base, f), out)
    cfg = json.load(open(os.path.join(out, "config.json")))
    cfg["torch_dtype"] = "float32"; cfg.pop("dtype", None)
    json.dump(cfg, open(os.path.join(out, "config.json"), "w"), indent=2)
    json.dump({"source_gguf": os.path.basename(src), "tensors": len(ts), "dtype": "float32"},
              open(os.path.join(out, "provenance-gguf.json"), "w"), indent=1)
    print("wrote %d tensors to %s" % (len(ts), out))


def verify(a, b):
    ra, rb = GGUFReader(a), GGUFReader(b)
    ta, tb = {t.name: t for t in ra.tensors}, {t.name: t for t in rb.tensors}
    if set(ta) != set(tb):
        raise SystemExit("tensor names differ")
    bad = [n for n in ta if ta[n].tensor_type != tb[n].tensor_type or list(ta[n].shape) != list(tb[n].shape)
           or not np.array_equal(np.asarray(ta[n].data), np.asarray(tb[n].data))]
    print("tensors %d, identical %d, differ %d %s" % (len(ta), len(ta) - len(bad), len(bad), bad[:5]))
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    {"build": lambda: build(*sys.argv[2:5]), "verify": lambda: verify(*sys.argv[2:4])}[sys.argv[1]]()
