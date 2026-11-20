#!/usr/bin/env bash
# MLX model (+ adapter) -> fused HF weights -> GGUF (llama.cpp b12477 converter, separate venv) -> quantized.
# mlx-lm's own GGUF export does not support qwen3; mlx-lm writes a tokenizer_config that transformers 4.57
# cannot read, so the ORIGINAL HF tokenizer files are used (fine-tuning never changes the tokenizer).
# Usage: export_gguf.sh <work dir> <base model dir> <adapter dir|-> <out prefix> [quant=Q8_0]
set -euo pipefail
W=$1; BASE=$2; AD=$3; OUTP=$4; Q=${5:-Q8_0}
L=$W/llamacpp-src/llama.cpp-b12477
F=$OUTP-fused
rm -rf "$F"
if [ "$AD" = "-" ]; then cp -R "$BASE" "$F"; else
  HF_HUB_OFFLINE=1 "$W/venv/bin/mlx_lm.fuse" --model "$BASE" --adapter-path "$AD" --save-path "$F" >/dev/null; fi
for f in tokenizer.json tokenizer_config.json vocab.json merges.txt; do cp "$BASE/$f" "$F/"; done
rm -f "$F/chat_template.jinja"
"$W/venv-convert/bin/python" "$L/convert_hf_to_gguf.py" "$F" --outtype bf16 --outfile "$OUTP-bf16.gguf" 2>&1 | grep -E "successfully|Error" || true
"$W/llamacpp/llama-b12477/llama-quantize" "$OUTP-bf16.gguf" "$OUTP-$(echo $Q | tr A-Z a-z).gguf" "$Q" >/dev/null 2>&1
ls -la "$OUTP"-*.gguf
