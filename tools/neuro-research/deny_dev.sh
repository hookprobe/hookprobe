#!/usr/bin/env bash
# Doc 25 dev: guard A runs (GGUF + grammar) for base17g and ftDg on dev v2, blind v3, blind v4; AE offline.
set -uo pipefail
S=$1; T="$(cd "$(dirname "$0")" && pwd)"; OUT=$S/deny-dev; port=18999
for m in "base17g=$S/gguf17/base17-q8_0.gguf" "ftDg=$S/t0v3/gguf-mixD-q8_0.gguf"; do
  name=${m%%=*}; g=${m#*=}
  "$S/llamacpp/llama-b12477/llama-server" -m "$g" --port $port -c 8192 -np 1 -ngl 99 --reasoning off --no-webui > "$OUT/srv-$name.log" 2>&1 & sp=$!
  for _ in $(seq 1 180); do curl -sf http://127.0.0.1:$port/health >/dev/null && break; sleep 1; done
  for set in dev2 blind3 blind4; do
    C=$S/$set/blind_cases.jsonl
    python3 -I "$T/eval/run_eval.py" --backend openai --url http://127.0.0.1:$port/v1 --model x --mode closed --guard A \
      --cases "$C" --max-tokens 700 --workers 1 --json "$OUT/$set-$name-A.json" > "$OUT/$set-$name-A.txt" 2>&1
    python3 -I "$T/guard_offline.py" "$C" "$OUT/$set-$name-A.json" "$OUT/$set-$name-AE.json"
    echo "[$(date '+%T')] $set $name A done"
  done
  kill $sp; wait $sp 2>/dev/null
done
echo "DENY DEV DONE"
