#!/usr/bin/env bash
# Neuro end to end (operator rule, 2026-11-24): capture -> DNA -> S1 -> cards -> explainer -> answer, with cost per stage.
# Usage: e2e_neuro.sh <out dir> <explainer gguf> <llama-server binary> <python with deps> <pcap>...
# Stops on any missing output. Nothing here reads a sealed set.
set -uo pipefail
O=$1; G=$2; LS=$3; PY=$4; shift 4
T=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$O"
log() { echo "[$(date '+%F %T')] $*"; }
need() { [ -s "$1" ] || { log "STOP: missing $1"; exit 3; }; }
need "$G"; need "$LS"
log "stages A-C, E (capture -> DNA -> S1 -> cards; exposure lookup)"
"$PY" -I "$T/e2e_neuro.py" build "$O" "$@" --sample 20 > "$O/build.log" 2>&1 || { tail -5 "$O/build.log"; exit 4; }
need "$O/cases.jsonl"
log "stage D (explainer: llama-server, guard A, then guard E and rule T)"
port=18993; t0=$(date +%s)
"$LS" -m "$G" --port $port -c 8192 -np 1 -ngl 99 --reasoning off --no-webui > "$O/server.log" 2>&1 & sp=$!
for _ in $(seq 1 180); do curl -sf http://127.0.0.1:$port/health >/dev/null && break; sleep 1; done
t1=$(date +%s)
python3 -I "$T/eval/run_eval.py" --backend openai --url http://127.0.0.1:$port/v1 --model x --mode closed --guard A \
  --cases "$O/cases.jsonl" --max-tokens 700 --workers 1 --json "$O/explainer-A.json" > "$O/explainer-A.txt" 2>&1
srss=$(ps -o rss= -p $sp 2>/dev/null | tr -d ' ')
kill $sp; wait $sp 2>/dev/null
need "$O/explainer-A.json"
python3 -I "$T/guard_offline.py" "$O/cases.jsonl" "$O/explainer-A.json" "$O/explainer-AE.json"
"$PY" -I "$T/e2e_neuro.py" score "$O" "$O/explainer-AE.json" > "$O/score.log" 2>&1 || { tail -5 "$O/score.log"; exit 5; }
echo "{\"model_load_s\": $((t1 - t0)), \"server_rss_mb\": $(( ${srss:-0} / 1024 )), \"gguf\": \"$(basename "$G")\", \"gguf_mb\": $(( $(stat -f %z "$G") / 1048576 ))}" > "$O/stage_D_server.json"
log "E2E DONE"
cat "$O/stages_ABCE.json" "$O/stage_D.json" "$O/stage_D_server.json"
