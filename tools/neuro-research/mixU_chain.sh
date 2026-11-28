#!/usr/bin/env bash
# Doc 55: routing by turn, no new model. ftM answers contexts without a RESULT line, and ftT (doc 54) answers contexts
# with one. Wait for the sealed inv-blind v7 -> base17g, ftMg, ftTg with tools (guard A) -> mixU_gate.py (router).
# Usage: mixU_chain.sh <repo tools/neuro-research dir>
set -uo pipefail
T=$1; C=$HOME/.cache/hookprobe-neuro; W=$C/w; D=$C/invblind7; E=$C/mixU-eval; M=$C/models
mkdir -p "$E"
log() { echo "[$(date '+%F %T')] $*"; }
need() { [ -s "$1" ] || { log "STOP: missing $1"; exit 3; }; }
sha() { shasum -a 256 "$1" | cut -c1-64; }
need "$M/base17-q8_0.gguf"; need "$W/llamacpp/llama-b12477/llama-server"
[ "$(sha "$M/gguf-mixM-q8_0.gguf")" = 9576cfacef5ad23728e171f157321aedf8ab12c4aba926f89fd0527d5d23dcc9 ] || { log "STOP: ftMg hash"; exit 3; }
[ "$(sha "$M/gguf-mixT-q8_0.gguf")" = 40fd46d4730a4c63defb8dbb90e445b6cb4374eb307d3ef15490428d06b765ea ] || { log "STOP: ftTg hash"; exit 3; }
log "waiting for the sealed inv-blind v7 ($D/SEALED)"
until [ -s "$D/SEALED" ]; do sleep 60; done
want=$(cat "$D/SEALED"); got=$(sha "$D/blind_cases.jsonl")
[ "$want" = "$got" ] || { log "STOP: inv-blind v7 hash $got != sealed $want"; exit 4; }
INV_SET=v3 python3 -I "$T/inv_seal.py" check "$D/blind_cases.jsonl" "$W/mixT/inv7_cases.jsonl" "$W/mixS/inv6_cases.jsonl" "$W/mixR/inv5_cases.jsonl" \
  "$W/mixM/inv4_cases.jsonl" "$C/invblind/blind_cases.jsonl" "$C/invblind2/blind_cases.jsonl" "$C/invblind3/blind_cases.jsonl" \
  "$C/invblind4/blind_cases.jsonl" "$C/invblind5/blind_cases.jsonl" "$C/invblind6/blind_cases.jsonl" > "$E/seal-recheck.txt" 2>&1 \
  || { log "STOP: inv-blind v7 seal re-check failed (see $E/seal-recheck.txt)"; exit 4; }
port=18988
for m in base17g:$M/base17-q8_0.gguf ftMg:$M/gguf-mixM-q8_0.gguf ftTg:$M/gguf-mixT-q8_0.gguf; do
  n=${m%%:*}; g=${m#*:}
  "$W/llamacpp/llama-b12477/llama-server" -m "$g" --port $port -c 8192 -np 1 -ngl 99 --reasoning off --no-webui --jinja > "$E/srv-$n.log" 2>&1 & sp=$!
  for _ in $(seq 1 180); do curl -sf http://127.0.0.1:$port/health >/dev/null && break; sleep 1; done
  python3 -I "$T/inv_eval.py" --cases "$D/blind_cases.jsonl" --url http://127.0.0.1:$port/v1 --guard A --json "$E/$n-inv.json" > "$E/$n-inv.txt" 2>&1
  kill $sp; wait $sp 2>/dev/null
  need "$E/$n-inv.json"; log "inv-blind v7 $n done"
done
python3 -I "$T/mixU_gate.py" "$D/blind_cases.jsonl" "$E/base17g-inv.json" "$E/ftMg-inv.json" "$E/ftTg-inv.json" "$T" | tee "$E/GATE.md"
log "MIXU DONE"
