#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Phase 0: run the eval set against each candidate model through llama-server, closed and free decoding.
# QUALITY and TOKEN COUNTS are the outputs that transfer to CM5; wall-clock times on the host do NOT.
# Usage: ./eval_models.sh <llama.cpp bin dir> <models dir> <cases.jsonl> <outdir> [repeat] [extra llama-server args...]
# MODES="closed free freeex" selects modes (default "closed free"); freeex = free + one fixed example answer.
set -euo pipefail
BIN=$1; MODELS=$2; CASES=$3; OUT=$4; REPEAT=${5:-1}; shift 5 || true
EXTRA=("$@")
HERE=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$OUT"
port=18181
for m in "$MODELS"/*.gguf; do
  base=$(basename "$m" .gguf)
  "$BIN/llama-server" -m "$m" --port $port -c 8192 -np 1 -ngl 0 -t 8 --reasoning off --no-webui \
     ${EXTRA[@]+"${EXTRA[@]}"} > "$OUT/server-$base.log" 2>&1 & pid=$!
  for _ in $(seq 1 300); do curl -sf "http://127.0.0.1:$port/health" >/dev/null && break; sleep 0.5; done
  for mode in ${MODES:-closed free}; do
    flags=(--mode "$mode"); [ "$mode" = freeex ] && flags=(--mode free --example)
    python3 -I "$HERE/eval/run_eval.py" --backend openai --url "http://127.0.0.1:$port/v1" --model "$base" \
       "${flags[@]}" --cases "$CASES" --repeat "$REPEAT" --json "$OUT/$base-$mode.json" > "$OUT/$base-$mode.txt" 2>&1 || true
    echo "$base $mode: $(grep -E 'verdict_ok' "$OUT/$base-$mode.txt" | grep -E '^  (triage|injection)' | tr -s ' ' | tr '\n' ' ')"
  done
  kill $pid 2>/dev/null || true; wait $pid 2>/dev/null || true
done
