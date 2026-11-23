#!/usr/bin/env bash
# Doc 36: mixH = mixF + a quarter of the doc 33 thin-evidence SFT (same teacher outputs; no new teacher run) -> train
# (doc 26 recipe) -> export ftHg -> dev eval AE on the 5 spent sets -> mixH_select.py (doc 36 rule).
# Usage: mixH_chain.sh <work dir> <repo tools/neuro-research dir>
set -uo pipefail
S=$1; T=$2; O=$S/t0v3; G=$S/mixH-dev; mkdir -p "$G" "$O/mixH"
log() { echo "[$(date '+%F %T')] $*"; }
python3 -I - "$O" <<'PY'
import json, random, re, sys
O = sys.argv[1]
LEAK = re.compile(r"\bL0\b|deterministic|engine|for the analyst|analyst note|as instructed", re.I)
rd = lambda p: [json.loads(l) for l in open(p)]
ok = lambda x: not LEAK.search(json.loads(x["messages"][-1]["content"]).get("summary", ""))
t_ = [x for x in rd(O + "/sftA-t/train.jsonl") if ok(x)]; v_ = [x for x in rd(O + "/sftA-t/valid.jsonl") if ok(x)]
r = random.Random(36); r.shuffle(t_); r.shuffle(v_)
kt, kv = t_[: len(t_) // 4], v_[: max(1, len(v_) // 4)]
tr = rd(O + "/mixF/train.jsonl") + kt; va = rd(O + "/mixF/valid.jsonl") + kv
random.Random(7).shuffle(tr)
for n, rows in (("train", tr), ("valid", va)):
    open("%s/mixH/%s.jsonl" % (O, n), "w").write("".join(json.dumps(x, ensure_ascii=False) + "\n" for x in rows))
print("thin kept: %d train, %d valid (a quarter); mixH: %d train / %d valid" % (len(kt), len(kv), len(tr), len(va)))
PY
N=$(wc -l < "$O/mixH/train.jsonl"); IT=$(( (N * 2 + 3) / 4 ))
log "train mixH: $N examples, $IT iterations"
printf 'lora_parameters:\n  rank: 16\n  dropout: 0.0\n  scale: 20.0\n' > "$O/mixH.yaml"
"$S/venv/bin/mlx_lm.lora" -c "$O/mixH.yaml" --model "$S/models/student17" --train --data "$O/mixH" --fine-tune-type lora \
  --num-layers -1 --mask-prompt --grad-checkpoint --batch-size 4 --iters "$IT" --learning-rate 1e-4 --max-seq-length 2048 \
  --steps-per-report 50 --steps-per-eval 200 --val-batches 25 --save-every 200 --adapter-path "$O/ft-mixH" > "$O/train-mixH.log" 2>&1
python3 -I - "$O/train-mixH.log" "$O/ft-mixH" "$IT" <<'PY'
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
print("  ft-mixH: checkpoint %d (valid %.3f) of %s" % (best, saved[best], sorted(saved.items())))
PY
bash "$S/tools/export_gguf.sh" "$S" "$S/models/student17" "$O/ft-mixH" "$O/gguf-mixH" Q8_0 > "$O/export-mixH.log" 2>&1
rm -f "$O/gguf-mixH-bf16.gguf"
log "dev eval ftHg with guard A on 5 spent sets"
port=18997
"$S/llamacpp/llama-b12477/llama-server" -m "$O/gguf-mixH-q8_0.gguf" --port $port -c 8192 -np 1 -ngl 99 --reasoning off --no-webui > "$G/srv-ftHg.log" 2>&1 & sp=$!
for _ in $(seq 1 180); do curl -sf http://127.0.0.1:$port/health >/dev/null && break; sleep 1; done
for set in dev2 blind3 blind4 blind5 blind6; do
  python3 -I "$T/eval/run_eval.py" --backend openai --url http://127.0.0.1:$port/v1 --model x --mode closed --guard A \
    --cases "$S/$set/blind_cases.jsonl" --max-tokens 700 --workers 1 --json "$G/$set-ftHg-A.json" > "$G/$set-ftHg-A.txt" 2>&1
  python3 -I "$T/guard_offline.py" "$S/$set/blind_cases.jsonl" "$G/$set-ftHg-A.json" "$G/$set-ftHg-AE.json"
  log "$set ftHg done"
done
kill $sp; wait $sp 2>/dev/null
python3 -I "$T/mixH_select.py" "$S" "$T" | tee "$G/SELECT.md"
log "MIXH DONE"
