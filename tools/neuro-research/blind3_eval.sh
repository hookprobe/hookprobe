#!/usr/bin/env bash
# Doc 23: the ONE evaluation session on blind v3. Refuses to run unless the file matches the seal in doc 23.
# Usage: blind3_eval.sh <work dir> <blind3 cases> <out dir>
set -uo pipefail
W=$1; B=$2; OUT=$3; T="$(cd "$(dirname "$0")" && pwd)"; DOC="$T/../../docs/research/neuro/23_BLIND3_PREREGISTRATION.md"
H=$(shasum -a 256 "$B" | awk '{print $1}')
grep -q "SHA-256 \`$H\`" "$DOC" || { echo "SEAL MISMATCH: $H is not the sealed hash in doc 23. Stop."; exit 2; }
for g in "$W/gguf17/base17-q8_0.gguf" "$W/t0v3/gguf-mixD-q8_0.gguf"; do
  gh=$(shasum -a 256 "$g" | awk '{print $1}'); grep -q "$gh" "$DOC" || { echo "GGUF MISMATCH: $g ($gh) not in the seal. Stop."; exit 2; }
done
echo "[$(date '+%F %T')] seal verified: $H"
mkdir -p "$OUT"; port=18787; runs=()
for spec in "base17g=gguf:$W/gguf17/base17-q8_0.gguf" "ftDg=gguf:$W/t0v3/gguf-mixD-q8_0.gguf" \
            "ftD=mlx:$W/models/student17:$W/t0v3/ft-mixD" "base17=mlx:$W/models/student17"; do
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
    --cases "$B" --max-tokens 700 --workers 1 --json "$OUT/$name.json" > "$OUT/$name.txt" 2>&1
  kill $sp 2>/dev/null; wait $sp 2>/dev/null
  echo "[$(date '+%T')] blind3: $name done"; runs+=("$name=$OUT/$name.json")
done
python3 -I "$T/t1_compare.py" "$B" "${runs[@]}" | tee "$OUT/COMPARE.md"
python3 -I "$T/blind3_gate.py" "$B" "$OUT/base17g.json" "$OUT/ftDg.json" | tee "$OUT/GATE.txt"
echo "[$(date '+%F %T')] BLIND3 DONE"
