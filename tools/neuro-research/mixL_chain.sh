#!/usr/bin/env bash
# Doc 43: investigation-ONLY adapter (ftL) on the base student; ftFg's triage weights are not touched.
# gen v3 (720, seed 43) -> tool-call SFT (no teacher) -> LoRA on base Qwen3-1.7B (doc 26 settings, 2 epochs, checkpoint
# every 50 steps, lowest valid loss) -> export ftLg -> wait for the sealed inv-blind v2 -> base17g and ftLg with tools
# (guard A) -> mixL_gate.py. Stops on any missing output or hash mismatch.
# Usage: mixL_chain.sh <work dir> <repo tools/neuro-research dir>
set -uo pipefail
S=$1; T=$2; O=$S/t0v3; D=$S/invblind2; E=$S/mixL-eval; M=$HOME/.cache/hookprobe-neuro/models; mkdir -p "$E"
log() { echo "[$(date '+%F %T')] $*"; }
need() { [ -s "$1" ] || { log "STOP: missing $1"; exit 3; }; }
"$S/venv/bin/python" -c "import mlx_lm" || { log "STOP: mlx_lm missing"; exit 3; }
need "$S/models/student17/config.json"; need "$M/base17-q8_0.gguf"
log "investigation cases (gen v3, 720, seed 43)"
python3 -I "$T/gen_investigate.py" --playbooks "$T/../../docs/research/neuro/data/playbooks.json" --n 720 --seed 43 --version 3 --out "$O/inv3_cases.jsonl" || exit 3
need "$O/inv3_cases.jsonl"
"$S/venv/bin/python" -I "$T/build_inv_sft.py" "$O/inv3_cases.jsonl" "$O/mixL" --valid 0.05 --seed 43 || exit 3
need "$O/mixL/train.jsonl"
N=$(wc -l < "$O/mixL/train.jsonl"); IT=$(( (N * 2 + 3) / 4 ))
log "train ftL (investigation only, base student): $N examples, $IT iterations"
printf 'lora_parameters:\n  rank: 16\n  dropout: 0.0\n  scale: 20.0\n' > "$O/mixL.yaml"
"$S/venv/bin/mlx_lm.lora" -c "$O/mixL.yaml" --model "$S/models/student17" --train --data "$O/mixL" --fine-tune-type lora \
  --num-layers -1 --mask-prompt --grad-checkpoint --batch-size 4 --iters "$IT" --learning-rate 1e-4 --max-seq-length 2048 \
  --steps-per-report 25 --steps-per-eval 50 --val-batches 25 --save-every 50 --adapter-path "$O/ft-mixL" > "$O/train-mixL.log" 2>&1
need "$O/ft-mixL/adapters.safetensors"
python3 -I - "$O/train-mixL.log" "$O/ft-mixL" "$IT" <<'PY' || exit 3
import re, sys, os, shutil
log, d, it = sys.argv[1], sys.argv[2], int(sys.argv[3])
fin = os.path.join(d, "%07d_adapters.safetensors" % it)
if not os.path.exists(fin): shutil.copy(os.path.join(d, "adapters.safetensors"), fin)
vals = {}
for l in open(log):
    m = re.match(r"\s*(\d+)\s+val ([0-9.]+)", re.sub(r"\x1b\[[0-9;]*m", "", l))
    if m: vals[int(m.group(1))] = float(m.group(2))
saved = {k: v for k, v in vals.items() if os.path.exists(os.path.join(d, "%07d_adapters.safetensors" % k))}
best = min(saved, key=lambda k: (saved[k], k))
shutil.copy(os.path.join(d, "%07d_adapters.safetensors" % best), os.path.join(d, "adapters.safetensors"))
print("  ft-mixL: checkpoint %d (valid %.3f) of %s" % (best, saved[best], sorted(saved.items())))
PY
bash "$S/tools/export_gguf.sh" "$S" "$S/models/student17" "$O/ft-mixL" "$O/gguf-mixL" Q8_0 > "$O/export-mixL.log" 2>&1
need "$O/gguf-mixL-q8_0.gguf"
cp "$O/gguf-mixL-q8_0.gguf" "$M/"; shasum -a 256 "$O/gguf-mixL-q8_0.gguf" "$O/ft-mixL/adapters.safetensors"
log "waiting for the sealed inv-blind v2 ($D/SEALED)"
until [ -s "$D/SEALED" ]; do sleep 60; done
want=$(cat "$D/SEALED"); got=$(shasum -a 256 "$D/blind_cases.jsonl" | cut -c1-64)
[ "$want" = "$got" ] || { log "STOP: inv-blind v2 hash $got != sealed $want"; exit 4; }
python3 -I "$T/inv_seal.py" check "$D/blind_cases.jsonl" "$O/inv3_cases.jsonl" | grep -q "/inv3_cases.jsonl': 0" \
  || { log "STOP: training cases collide with inv-blind v2"; exit 4; }
port=18990
for m in base17g:$M/base17-q8_0.gguf ftLg:$O/gguf-mixL-q8_0.gguf; do
  n=${m%%:*}; g=${m#*:}
  "$S/llamacpp/llama-b12477/llama-server" -m "$g" --port $port -c 8192 -np 1 -ngl 99 --reasoning off --no-webui --jinja > "$E/srv-$n.log" 2>&1 & sp=$!
  for _ in $(seq 1 180); do curl -sf http://127.0.0.1:$port/health >/dev/null && break; sleep 1; done
  python3 -I "$T/inv_eval.py" --cases "$D/blind_cases.jsonl" --url http://127.0.0.1:$port/v1 --guard A --json "$E/$n-inv.json" > "$E/$n-inv.txt" 2>&1
  kill $sp; wait $sp 2>/dev/null
  need "$E/$n-inv.json"
  log "inv-blind v2 $n done"
done
python3 -I "$T/mixL_gate.py" "$D/blind_cases.jsonl" "$E/base17g-inv.json" "$E/ftLg-inv.json" "$T" | tee "$E/GATE.md"
log "MIXL DONE"
