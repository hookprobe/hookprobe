#!/usr/bin/env bash
# Doc 42: investigation cases (gen v2, 720, seed 42) -> tool-call SFT (no teacher) -> mixK = mixF + investigation ->
# train (doc 26 recipe) -> export ftKg -> one look: inv-blind v1 (sealed) + triage no-regression on blind v7 and dev v8
# -> mixK_gate.py. Stops if any step's output is missing, or if the sealed set's hash changed.
# Usage: mixK_chain.sh <work dir> <repo tools/neuro-research dir>
set -uo pipefail
S=$1; T=$2; O=$S/t0v3; E=$S/mixK-eval; M=$HOME/.cache/hookprobe-neuro/models; mkdir -p "$E" "$O/mixK"
log() { echo "[$(date '+%F %T')] $*"; }
need() { [ -s "$1" ] || { log "STOP: missing $1"; exit 3; }; }
"$S/venv/bin/python" -c "import mlx_lm" || { log "STOP: mlx_lm missing"; exit 3; }
need "$O/mixF/train.jsonl"; need "$S/models/student17/config.json"; need "$S/invblind/blind_cases.jsonl"
INV=c49f06c94f75b74e453d6943d6605ede8cd5b0ae6e79d41317cc156d8cb68ade
[ "$(shasum -a 256 "$S/invblind/blind_cases.jsonl" | cut -c1-64)" = "$INV" ] || { log "STOP: inv-blind hash changed"; exit 4; }
log "investigation cases (gen v2, 720, seed 42)"
python3 -I "$T/gen_investigate.py" --playbooks "$T/../../docs/research/neuro/data/playbooks.json" --n 720 --seed 42 --out "$O/inv_cases.jsonl" || exit 3
need "$O/inv_cases.jsonl"
python3 -I "$T/inv_seal.py" check "$S/invblind/blind_cases.jsonl" "$O/inv_cases.jsonl" | grep -q "/inv_cases.jsonl': 0" \
  || { log "STOP: training cases collide with inv-blind"; exit 4; }
"$S/venv/bin/python" -I "$T/build_inv_sft.py" "$O/inv_cases.jsonl" "$O/sftK-inv" --valid 0.05 --seed 42 || exit 3
need "$O/sftK-inv/train.jsonl"
python3 -I - "$O" <<'PY'
import json, random, sys
O = sys.argv[1]
rd = lambda p: [json.loads(l) for l in open(p)]
it, iv = rd(O + "/sftK-inv/train.jsonl"), rd(O + "/sftK-inv/valid.jsonl")
tr = rd(O + "/mixF/train.jsonl") + it; va = rd(O + "/mixF/valid.jsonl") + iv
random.Random(7).shuffle(tr)
for n, rows in (("train", tr), ("valid", va)):
    open("%s/mixK/%s.jsonl" % (O, n), "w").write("".join(json.dumps(x, ensure_ascii=False) + "\n" for x in rows))
print("mixK: %d train (%d investigation) / %d valid (%d investigation)" % (len(tr), len(it), len(va), len(iv)))
PY
N=$(wc -l < "$O/mixK/train.jsonl"); IT=$(( (N * 2 + 3) / 4 ))
log "train mixK: $N examples, $IT iterations"
printf 'lora_parameters:\n  rank: 16\n  dropout: 0.0\n  scale: 20.0\n' > "$O/mixK.yaml"
"$S/venv/bin/mlx_lm.lora" -c "$O/mixK.yaml" --model "$S/models/student17" --train --data "$O/mixK" --fine-tune-type lora \
  --num-layers -1 --mask-prompt --grad-checkpoint --batch-size 4 --iters "$IT" --learning-rate 1e-4 --max-seq-length 2048 \
  --steps-per-report 50 --steps-per-eval 200 --val-batches 25 --save-every 200 --adapter-path "$O/ft-mixK" > "$O/train-mixK.log" 2>&1
need "$O/ft-mixK/adapters.safetensors"
python3 -I - "$O/train-mixK.log" "$O/ft-mixK" "$IT" <<'PY' || exit 3
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
print("  ft-mixK: checkpoint %d (valid %.3f) of %s" % (best, saved[best], sorted(saved.items())))
PY
bash "$S/tools/export_gguf.sh" "$S" "$S/models/student17" "$O/ft-mixK" "$O/gguf-mixK" Q8_0 > "$O/export-mixK.log" 2>&1
need "$O/gguf-mixK-q8_0.gguf"
cp "$O/gguf-mixK-q8_0.gguf" "$M/" ; shasum -a 256 "$O/gguf-mixK-q8_0.gguf" "$O/ft-mixK/adapters.safetensors"
port=18991
"$S/llamacpp/llama-b12477/llama-server" -m "$O/gguf-mixK-q8_0.gguf" --port $port -c 8192 -np 1 -ngl 99 --reasoning off --no-webui --jinja > "$E/srv.log" 2>&1 & sp=$!
for _ in $(seq 1 180); do curl -sf http://127.0.0.1:$port/health >/dev/null && break; sleep 1; done
log "ftKg on inv-blind v1"
python3 -I "$T/inv_eval.py" --cases "$S/invblind/blind_cases.jsonl" --url http://127.0.0.1:$port/v1 --guard A --json "$E/ftKg-inv.json" > "$E/ftKg-inv.txt" 2>&1
need "$E/ftKg-inv.json"
for set in blind7 dev8; do
  python3 -I "$T/eval/run_eval.py" --backend openai --url http://127.0.0.1:$port/v1 --model x --mode closed --guard A \
    --cases "$S/$set/blind_cases.jsonl" --max-tokens 700 --workers 1 --json "$E/$set-ftKg-A.json" > "$E/$set-ftKg-A.txt" 2>&1
  need "$E/$set-ftKg-A.json"
  python3 -I "$T/guard_offline.py" "$S/$set/blind_cases.jsonl" "$E/$set-ftKg-A.json" "$E/$set-ftKg-AE.json"
  log "ftKg triage on $set done"
done
kill $sp; wait $sp 2>/dev/null
python3 -I "$T/mixK_gate.py" "$S/invblind/blind_cases.jsonl" "$HOME/.cache/hookprobe-neuro/invblind-floor/base17g.json" "$E/ftKg-inv.json" \
  "$S/blind7/blind_cases.jsonl" "$E/blind7-ftKg-AE.json" "$S/dev8/blind_cases.jsonl" "$E/dev8-ftKg-AE.json" "$T" | tee "$E/GATE.md"
log "MIXK DONE"
