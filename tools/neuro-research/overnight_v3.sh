#!/usr/bin/env bash
# After T0 v3 labelling: build two SFT mixes, train 1.7B LoRA (same recipe as T1-1.7B), score on the DEV set.
set -uo pipefail
S=$1; O=$S/t0v3; T=$(cd "$(dirname "$0")" && pwd)
log() { echo "[$(date '+%F %T')] $*"; }
until grep -qE 'REDO DONE' "$O/redo.log" 2>/dev/null; do sleep 60; done
log "T0 v3 filtered: $(wc -l < $O/sft/train.jsonl) train / $(wc -l < $O/sft/valid.jsonl) valid"
mkdir -p "$O/mixA" "$O/mixB"
cp "$O/sft/train.jsonl" "$O/sft/valid.jsonl" "$O/mixA/"
python3 -I - "$S" <<'PY'
import json, random, sys
S = sys.argv[1]; O = S + "/t0v3"
v2 = [json.loads(l) for l in open(S + "/t0v2/sft/train.jsonl")]
inj = [r for r in v2 if "!instr-like" in r["messages"][-2]["content"] or "instruction-like" in r["messages"][-1]["content"]]
tr = [json.loads(l) for l in open(O + "/sft/train.jsonl")] + inj
random.Random(7).shuffle(tr)
open(O + "/mixB/train.jsonl", "w").write("".join(json.dumps(x, ensure_ascii=False) + "\n" for x in tr))
open(O + "/mixB/valid.jsonl", "w").write(open(O + "/sft/valid.jsonl").read())
print("mixB: %d train (%d v2 injection examples added)" % (len(tr), len(inj)))
PY
for mix in mixA mixB; do
  N=$(wc -l < "$O/$mix/train.jsonl"); IT=$(( (N * 2 + 3) / 4 ))
  log "train $mix: $N examples, $IT iterations"
  printf 'lora_parameters:\n  rank: 16\n  dropout: 0.0\n  scale: 20.0\n' > "$O/$mix.yaml"
  "$S/venv/bin/mlx_lm.lora" -c "$O/$mix.yaml" --model "$S/models/student17" --train --data "$O/$mix" --fine-tune-type lora \
    --num-layers -1 --mask-prompt --grad-checkpoint --batch-size 4 --iters "$IT" --learning-rate 1e-4 --max-seq-length 2048 \
    --steps-per-report 50 --steps-per-eval 200 --val-batches 25 --save-every 200 --adapter-path "$O/ft-$mix" > "$O/train-$mix.log" 2>&1
  python3 -I - "$O/train-$mix.log" "$O/ft-$mix" "$IT" <<'PY'
import re, sys, os, shutil
fin = os.path.join(sys.argv[2], "%07d_adapters.safetensors" % int(sys.argv[3]))
if not os.path.exists(fin):                       # keep the FINAL adapter as a candidate too
    shutil.copy(os.path.join(sys.argv[2], "adapters.safetensors"), fin)
vals = {}
for l in open(sys.argv[1]):
    m = re.match(r"\s*(\d+)\s+val ([0-9.]+)", re.sub(r"\x1b\[[0-9;]*m", "", l))
    if m: vals[int(m.group(1))] = float(m.group(2))
saved = {k: v for k, v in vals.items() if os.path.exists(os.path.join(sys.argv[2], "%07d_adapters.safetensors" % k))}
best = min(saved, key=lambda k: (saved[k], k))
shutil.copy(os.path.join(sys.argv[2], "%07d_adapters.safetensors" % best), os.path.join(sys.argv[2], "adapters.safetensors"))
print("  %s: checkpoint %d (valid %.3f) of %s" % (os.path.basename(sys.argv[2]), best, saved[best], sorted(saved.items())))
PY
  bash "$T/export_gguf.sh" "$S" "$S/models/student17" "$O/ft-$mix" "$O/gguf-$mix" Q8_0 > "$O/export-$mix.log" 2>&1
done
log "dev evaluation"
bash "$T/dev_eval.sh" "$S" "$S/dev-eval-v3" \
  ftA=mlx:$S/models/student17:$O/ft-mixA ftAg=gguf:$O/gguf-mixA-q8_0.gguf \
  ftB=mlx:$S/models/student17:$O/ft-mixB ftBg=gguf:$O/gguf-mixB-q8_0.gguf
python3 -I "$T/t1_compare.py" "$S/dev2/blind_cases.jsonl" base17=$S/dev-eval/base17.json ft17=$S/dev-eval/ft17.json \
  ftA=$S/dev-eval-v3/ftA.json ftAg=$S/dev-eval-v3/ftAg.json ftB=$S/dev-eval-v3/ftB.json ftBg=$S/dev-eval-v3/ftBg.json | tee "$S/dev-eval-v3/COMPARE.md"
log "OVERNIGHT DONE"
