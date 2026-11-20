#!/usr/bin/env bash
# Score models on the DEV set (tunable; never the blind set). MLX runs (no grammar) and llama.cpp GGUF runs
# (closed mode = json_schema grammar). Usage: dev_eval.sh <work dir> <out dir> <name=mlx:model[:adapter] | name=gguf:file> ...
set -uo pipefail
W=$1; OUT=$2; shift 2
T=$(cd "$(dirname "$0")" && pwd); D=$W/dev2/blind_cases.jsonl
mkdir -p "$OUT"; port=18686; runs=()
for spec in "$@"; do
  name=${spec%%=*}; rest=${spec#*=}; kind=${rest%%:*}; arg=${rest#*:}
  if [ "$kind" = mlx ]; then
    model=${arg%%:*}; ad=""; [ "$arg" != "$model" ] && ad=${arg#*:}
    HF_HUB_OFFLINE=1 "$W/venv/bin/mlx_lm.server" --model "$model" ${ad:+--adapter-path "$ad"} --port $port \
      --chat-template-args '{"enable_thinking":false}' --temp 0 > "$OUT/srv-$name.log" 2>&1 & sp=$!; mname=default_model
    for _ in $(seq 1 180); do curl -sf http://127.0.0.1:$port/v1/models >/dev/null && break; sleep 1; done
  else
    "$W/llamacpp/llama-b12477/llama-server" -m "$arg" --port $port -c 8192 -np 1 -ngl 99 --reasoning off --no-webui > "$OUT/srv-$name.log" 2>&1 & sp=$!; mname=x
    for _ in $(seq 1 180); do curl -sf http://127.0.0.1:$port/health >/dev/null && break; sleep 1; done
  fi
  python3 -I "$T/eval/run_eval.py" --backend openai --url http://127.0.0.1:$port/v1 --model $mname --mode closed \
    --cases "$D" --max-tokens 700 --json "$OUT/$name.json" > "$OUT/$name.txt" 2>&1
  kill $sp 2>/dev/null; wait $sp 2>/dev/null
  echo "[$(date '+%T')] dev: $name done"; runs+=("$name=$OUT/$name.json")
done
python3 -I "$T/t1_compare.py" "$D" "${runs[@]}" | tee "$OUT/DEV-RESULTS.md"
