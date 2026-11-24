#!/usr/bin/env bash
# Doc 44: investigation adapter v2 (ftM) on the base student, from generator v4 (L1-alert cards, more decoy and
# invisible cases) -> LoRA (doc 26 settings, 2 epochs, checkpoint every 50 steps, lowest valid loss) -> export ftMg ->
# wait for the sealed inv-blind v3 -> base17g, ftLg (incumbent) and ftMg with tools (guard A) -> mixM_gate.py.
# Everything lives under ~/.cache/hookprobe-neuro (durable; the session scratchpad is not). Stops on any missing output.
# Usage: mixM_chain.sh <repo tools/neuro-research dir>
set -uo pipefail
T=$1; C=$HOME/.cache/hookprobe-neuro; W=$C/w; O=$W/mixM; D=$C/invblind3; E=$C/mixM-eval; M=$C/models
mkdir -p "$O" "$E"
log() { echo "[$(date '+%F %T')] $*"; }
need() { [ -s "$1" ] || { log "STOP: missing $1"; exit 3; }; }
"$W/venv/bin/python" -c "import mlx_lm" || { log "STOP: mlx_lm missing"; exit 3; }
need "$W/models/student17/config.json"; need "$M/base17-q8_0.gguf"; need "$M/gguf-mixL-q8_0.gguf"; need "$W/llamacpp/llama-b12477/llama-server"
log "investigation cases (gen v4, 900, seed 44)"
python3 -I "$T/gen_investigate.py" --playbooks "$T/../../docs/research/neuro/data/playbooks.json" --n 900 --seed 44 --version 4 --out "$O/inv4_cases.jsonl" || exit 3
need "$O/inv4_cases.jsonl"
"$W/venv/bin/python" -I "$T/build_inv_sft.py" "$O/inv4_cases.jsonl" "$O/data" --valid 0.05 --seed 44 || exit 3
need "$O/data/train.jsonl"
N=$(wc -l < "$O/data/train.jsonl"); IT=$(( (N * 2 + 3) / 4 ))
log "train ftM (investigation only, base student): $N examples, $IT iterations"
printf 'lora_parameters:\n  rank: 16\n  dropout: 0.0\n  scale: 20.0\n' > "$O/lora.yaml"
"$W/venv/bin/mlx_lm.lora" -c "$O/lora.yaml" --model "$W/models/student17" --train --data "$O/data" --fine-tune-type lora \
  --num-layers -1 --mask-prompt --grad-checkpoint --batch-size 4 --iters "$IT" --learning-rate 1e-4 --max-seq-length 2048 \
  --steps-per-report 25 --steps-per-eval 50 --val-batches 25 --save-every 50 --adapter-path "$O/ft" > "$O/train.log" 2>&1
need "$O/ft/adapters.safetensors"
python3 -I - "$O/train.log" "$O/ft" "$IT" <<'PY' || exit 3
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
print("  ftM: checkpoint %d (valid %.3f) of %s" % (best, saved[best], sorted(saved.items())))
PY
bash "$T/export_gguf.sh" "$W" "$W/models/student17" "$O/ft" "$O/gguf-mixM" Q8_0 > "$O/export.log" 2>&1
need "$O/gguf-mixM-q8_0.gguf"
cp "$O/gguf-mixM-q8_0.gguf" "$M/"; shasum -a 256 "$O/gguf-mixM-q8_0.gguf" "$O/ft/adapters.safetensors"
log "waiting for the sealed inv-blind v3 ($D/SEALED)"
until [ -s "$D/SEALED" ]; do sleep 60; done
want=$(cat "$D/SEALED"); got=$(shasum -a 256 "$D/blind_cases.jsonl" | cut -c1-64)
[ "$want" = "$got" ] || { log "STOP: inv-blind v3 hash $got != sealed $want"; exit 4; }
INV_SET=v3 python3 -I "$T/inv_seal.py" check "$D/blind_cases.jsonl" "$O/inv4_cases.jsonl" | grep -q "/inv4_cases.jsonl': 0" \
  || { log "STOP: training cases collide with inv-blind v3"; exit 4; }
port=18988
for m in base17g:$M/base17-q8_0.gguf ftLg:$M/gguf-mixL-q8_0.gguf ftMg:$M/gguf-mixM-q8_0.gguf; do
  n=${m%%:*}; g=${m#*:}
  "$W/llamacpp/llama-b12477/llama-server" -m "$g" --port $port -c 8192 -np 1 -ngl 99 --reasoning off --no-webui --jinja > "$E/srv-$n.log" 2>&1 & sp=$!
  for _ in $(seq 1 180); do curl -sf http://127.0.0.1:$port/health >/dev/null && break; sleep 1; done
  python3 -I "$T/inv_eval.py" --cases "$D/blind_cases.jsonl" --url http://127.0.0.1:$port/v1 --guard A --json "$E/$n-inv.json" > "$E/$n-inv.txt" 2>&1
  kill $sp; wait $sp 2>/dev/null
  need "$E/$n-inv.json"
  log "inv-blind v3 $n done"
done
python3 -I "$T/mixM_gate.py" "$D/blind_cases.jsonl" "$E/base17g-inv.json" "$E/ftLg-inv.json" "$E/ftMg-inv.json" "$T" | tee "$E/GATE.md"
log "MIXM DONE"
