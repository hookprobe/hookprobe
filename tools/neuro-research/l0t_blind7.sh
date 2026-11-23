#!/usr/bin/env bash
# Doc 40 §4: the one look. Waits for the sealed blind v7, checks its hash, evaluates base17g and ftFg with guard A + E
# (as every earlier set), then applies rule T offline (l0_thin.compose) and the gate (l0_thin_select.py --blind).
# Stops if any model file or output is missing.
# Usage: l0t_blind7.sh <work dir> <repo tools/neuro-research dir>
set -uo pipefail
S=$1; T=$2; B=$S/blind7; E=$S/blind7-eval; mkdir -p "$E"
log() { echo "[$(date '+%F %T')] $*"; }
need() { [ -s "$1" ] || { log "STOP: missing $1"; exit 3; }; }
need "$S/gguf17/base17-q8_0.gguf"; need "$S/t0v3/gguf-mixF-q8_0.gguf"
log "waiting for the sealed blind v7 ($B/SEALED)"
until [ -s "$B/SEALED" ]; do sleep 60; done
want=$(cat "$B/SEALED"); got=$(shasum -a 256 "$B/blind_cases.jsonl" | cut -c1-64)
[ "$want" = "$got" ] || { log "STOP: blind v7 hash $got != sealed $want"; exit 4; }
port=18994
for m in base17g:$S/gguf17/base17-q8_0.gguf ftFg:$S/t0v3/gguf-mixF-q8_0.gguf; do
  n=${m%%:*}; g=${m#*:}
  "$S/llamacpp/llama-b12477/llama-server" -m "$g" --port $port -c 8192 -np 1 -ngl 99 --reasoning off --no-webui > "$E/srv-$n.log" 2>&1 & sp=$!
  for _ in $(seq 1 180); do curl -sf http://127.0.0.1:$port/health >/dev/null && break; sleep 1; done
  python3 -I "$T/eval/run_eval.py" --backend openai --url http://127.0.0.1:$port/v1 --model x --mode closed --guard A \
    --cases "$B/blind_cases.jsonl" --max-tokens 700 --workers 1 --json "$E/$n-A.json" > "$E/$n-A.txt" 2>&1
  kill $sp; wait $sp 2>/dev/null
  need "$E/$n-A.json"
  python3 -I "$T/guard_offline.py" "$B/blind_cases.jsonl" "$E/$n-A.json" "$E/$n-AE.json"
  need "$E/$n-AE.json"
  log "blind v7 $n done"
done
python3 -I "$T/l0_thin_select.py" "$B/blind_cases.jsonl" "$E/base17g-AE.json" "$E/ftFg-AE.json" "$T" --blind | tee "$E/GATE.md"
log "L0T BLIND7 DONE"
