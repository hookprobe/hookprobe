#!/usr/bin/env bash
# Doc 24 dev: guard R runs (GGUF + grammar) for base17g and ftDg on blind v3 (spent = dev) and dev v2.
set -uo pipefail
S=$1; T="$(cd "$(dirname "$0")" && pwd)"; OUT=$S/guard-dev; port=18888
for m in "base17g=$S/gguf17/base17-q8_0.gguf" "ftDg=$S/t0v3/gguf-mixD-q8_0.gguf"; do
  name=${m%%=*}; g=${m#*=}
  "$S/llamacpp/llama-b12477/llama-server" -m "$g" --port $port -c 8192 -np 1 -ngl 99 --reasoning off --no-webui > "$OUT/srv-$name-R.log" 2>&1 & sp=$!
  for _ in $(seq 1 180); do curl -sf http://127.0.0.1:$port/health >/dev/null && break; sleep 1; done
  for set in blind3 dev2; do
    C=$S/$set/blind_cases.jsonl
    python3 -I "$T/eval/run_eval.py" --backend openai --url http://127.0.0.1:$port/v1 --model x --mode closed --guard R \
      --cases "$C" --max-tokens 700 --workers 1 --json "$OUT/$set-$name-R.json" > "$OUT/$set-$name-R.txt" 2>&1
    python3 -I "$T/guard_offline.py" "$C" "$OUT/$set-$name-R.json" "$OUT/$set-$name-RE.json"
    echo "[$(date '+%T')] $set $name R done"
  done
  kill $sp; wait $sp 2>/dev/null
done
echo "GUARD R DONE"
