#!/usr/bin/env bash
# Doc 25 §C: the ONE evaluation session on blind v5. Refuses to run unless the file matches the seal in doc 25.
# Usage: blind5_eval.sh <work dir> <blind4 cases> <out dir>
set -uo pipefail
W=$1; B=$2; OUT=$3; T="$(cd "$(dirname "$0")" && pwd)"; DOC="$T/../../docs/research/neuro/25_DEFAULT_DENY_PREREGISTRATION.md"
H=$(shasum -a 256 "$B" | awk '{print $1}')
grep -q "SHA-256 \`$H\`" "$DOC" || { echo "SEAL MISMATCH: $H is not the sealed hash in doc 25. Stop."; exit 2; }
for g in "$W/gguf17/base17-q8_0.gguf" "$W/t0v3/gguf-mixD-q8_0.gguf"; do
  gh=$(shasum -a 256 "$g" | awk '{print $1}'); grep -q "$gh" "$DOC" || { echo "GGUF MISMATCH: $g ($gh) not in the seal. Stop."; exit 2; }
done
echo "[$(date '+%F %T')] seal verified: $H"
mkdir -p "$OUT"; port=18990; runs=()
for spec in "base17g-A=$W/gguf17/base17-q8_0.gguf=A" "ftDg-A=$W/t0v3/gguf-mixD-q8_0.gguf=A"; do
  name=${spec%%=*}; rest=${spec#*=}; g=${rest%=*}; guard=${rest##*=}
  "$W/llamacpp/llama-b12477/llama-server" -m "$g" --port $port -c 8192 -np 1 -ngl 99 --reasoning off --no-webui > "$OUT/srv-$name.log" 2>&1 & sp=$!
  for _ in $(seq 1 180); do curl -sf http://127.0.0.1:$port/health >/dev/null && break; sleep 1; done
  python3 -I "$T/eval/run_eval.py" --backend openai --url http://127.0.0.1:$port/v1 --model x --mode closed --guard $guard \
    --cases "$B" --max-tokens 700 --workers 1 --json "$OUT/$name.json" > "$OUT/$name.txt" 2>&1
  kill $sp 2>/dev/null; wait $sp 2>/dev/null
  echo "[$(date '+%T')] blind5: $name done"
done
python3 -I "$T/guard_offline.py" "$B" "$OUT/base17g-A.json" "$OUT/base17g-AE.json"
python3 -I "$T/guard_offline.py" "$B" "$OUT/ftDg-A.json" "$OUT/ftDg-AE.json"
python3 -I "$T/guard_compare.py" "$B" base17g-AE=$OUT/base17g-AE.json ftDg-AE=$OUT/ftDg-AE.json base17g-A=$OUT/base17g-A.json ftDg-A=$OUT/ftDg-A.json | tee "$OUT/COMPARE.md"
python3 -I "$T/blind3_gate.py" "$B" "$OUT/base17g-AE.json" "$OUT/ftDg-AE.json" | sed 's/base17g /base17g-AE /; s/ftDg /ftDg-AE /' | tee "$OUT/GATE.txt"
echo "[$(date '+%F %T')] BLIND5 DONE"
