#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# T1-1.7B (docs/research/neuro/21): Qwen3-1.7B LoRA on the FROZEN T0 v2 SFT set, then ONE blind-v2 session.
#   smoke : 50 iterations, no evaluation (memory and speed). ITERS / MAXSEQ / BATCH / ACCUM / RANK override
#           (only along doc 21's out-of-memory ladder).
#   train : the frozen recipe; checkpoint chosen by the lowest T0-valid loss only.
#   eval  : refuses unless blind v2's SHA-256 equals the seal (BLIND2_SHA); five runs; hybrid comparison.
# Usage: t1_17b_pipeline.sh <smoke|train|eval> <work dir with venv/ models/ t0v2/ t1/>
set -uo pipefail
MODE=$1; W=$2
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=${OUT:-$W/t1-17b}; mkdir -p "$OUT"
log() { echo "[$(date '+%F %T')] $*" | tee -a "$OUT/pipeline.log"; }
DATA=$W/t0v2/sft
STUDENT=$W/models/student17
ITERS=${ITERS:-1631}; MAXSEQ=${MAXSEQ:-2048}; BATCH=${BATCH:-4}; ACCUM=${ACCUM:-1}; RANK=${RANK:-16}

check_data() {  # doc 21: the training set is frozen by hash
  local a b
  a=$(shasum -a 256 "$DATA/train.jsonl" | cut -d' ' -f1); b=$(shasum -a 256 "$DATA/valid.jsonl" | cut -d' ' -f1)
  [ "$a" = cd7b173248bbd0f82b49954a52a73a633f8ad17ea97549449bbeecdf406b6d26 ] && \
  [ "$b" = c80dd6a34bd8f45ca004d7cd6e939ff1bce9d6416174bc1c0af55103e3d2598f ] || { log "STOP: training data hash changed"; exit 3; }
}

train() {  # $1 adapter dir, $2 iterations
  printf 'lora_parameters:\n  rank: %s\n  dropout: 0.0\n  scale: 20.0\n' "$RANK" > "$1.yaml"
  mkdir -p "$1"
  /usr/bin/time -l "$W/venv/bin/mlx_lm.lora" -c "$1.yaml" --model "$STUDENT" --train --data "$DATA" --fine-tune-type lora --num-layers -1 \
    --mask-prompt --grad-checkpoint --batch-size "$BATCH" --grad-accumulation-steps "$ACCUM" --iters "$2" \
    --learning-rate 1e-4 --max-seq-length "$MAXSEQ" --steps-per-report 25 --steps-per-eval 200 --val-batches 25 \
    --save-every 200 --adapter-path "$1" > "$1.log" 2>&1
  local rc=$?
  grep -E "peak memory footprint|maximum resident" "$1.log" | tee -a "$OUT/pipeline.log"
  return $rc
}

case "$MODE" in
smoke)
  check_data
  log "smoke: 50 iterations rank=$RANK batch=$BATCH accum=$ACCUM maxseq=$MAXSEQ"
  ITERS=50; train "$OUT/smoke" 50; rc=$?
  sed 's/\x1b\[[0-9;]*m//g' "$OUT/smoke.log" | grep -E "^ +(1|25|50) |Error|error" | tail -5 | tee -a "$OUT/pipeline.log"
  log "smoke exit=$rc"; exit $rc ;;
train)
  check_data
  log "train: $ITERS iterations rank=$RANK batch=$BATCH accum=$ACCUM maxseq=$MAXSEQ lr=1e-4"
  train "$OUT/ft" "$ITERS"; rc=$?
  sed 's/\x1b\[[0-9;]*m//g' "$OUT/ft.log" | grep -E "^ +[0-9]+ +val " | tee "$OUT/val.txt" | tee -a "$OUT/pipeline.log"
  [ $rc = 0 ] || { log "STOP: training exit $rc"; exit $rc; }
  # divergence stop (doc 21): val loss at iteration 400 above its iteration-1 value
  python3 -I - "$OUT/val.txt" "$OUT/ft" <<'EOF' | tee -a "$OUT/pipeline.log"
import re, sys, shutil, os
vals = {int(m.group(1)): float(m.group(2)) for l in open(sys.argv[1]) for m in [re.match(r"\s*(\d+)\s+val ([0-9.]+)", l)] if m}
if 400 in vals and 1 in vals and vals[400] > vals[1]:
    print("STOP: diverged (val@400 %.3f > val@1 %.3f)" % (vals[400], vals[1])); sys.exit(4)
saved = {k: v for k, v in vals.items() if k > 1 and os.path.exists(os.path.join(sys.argv[2], "%07d_adapters.safetensors" % k))}
best = min(saved, key=lambda k: (saved[k], k))
shutil.copy(os.path.join(sys.argv[2], "%07d_adapters.safetensors" % best), os.path.join(sys.argv[2], "adapters.safetensors"))
print("selected checkpoint: iteration %d, T0-valid loss %.3f (of %s)" % (best, saved[best], sorted(saved.items())))
EOF
  exit ${PIPESTATUS[0]} ;;
eval)
  B=${BLIND2:?BLIND2=<blind_cases.jsonl>}; WANT=${BLIND2_SHA:?BLIND2_SHA=<sealed sha256>}
  [ "$(shasum -a 256 "$B" | cut -d' ' -f1)" = "$WANT" ] || { log "STOP: blind v2 does not match the seal"; exit 5; }
  [ -f "$OUT/ft/adapters.safetensors" ] || { log "STOP: no selected 1.7B adapter"; exit 6; }
  log "eval: blind v2 matches the seal; one session, five runs"
  port=18484
  run() {  # $1 name, $2 model, $3 adapter or ""
    HF_HUB_OFFLINE=1 "$W/venv/bin/mlx_lm.server" --model "$2" ${3:+--adapter-path "$3"} --port $port \
      --chat-template-args '{"enable_thinking":false}' --temp 0 > "$OUT/server-$1.log" 2>&1 &
    local sp=$!
    for _ in $(seq 1 180); do curl -sf http://127.0.0.1:$port/v1/models >/dev/null && break; sleep 1; done
    python3 -I "$HERE/eval/run_eval.py" --backend openai --url http://127.0.0.1:$port/v1 --model default_model --mode closed \
      --cases "$B" --max-tokens 700 --json "$OUT/$1.json" > "$OUT/$1.txt" 2>&1
    kill $sp 2>/dev/null; wait $sp 2>/dev/null
    log "  $1 done"
  }
  run base17 "$STUDENT" ""
  run ft17 "$STUDENT" "$OUT/ft"
  run base06 "$W/models/student" ""
  run ft1 "$W/models/student" "$W/t1/ft"
  run ft2 "$W/models/student" "$W/t0v2/ft"
  python3 -I "$HERE/t1_compare.py" "$B" base17="$OUT/base17.json" ft17="$OUT/ft17.json" base06="$OUT/base06.json" \
    ft1="$OUT/ft1.json" ft2="$OUT/ft2.json" | tee "$OUT/RESULTS.md" | tee -a "$OUT/pipeline.log"
  log "DONE" ;;
*) echo "mode: smoke | train | eval"; exit 2 ;;
esac
