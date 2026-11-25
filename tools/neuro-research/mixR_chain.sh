#!/usr/bin/env bash
# Doc 49: investigation adapter v3 (ftR) = ftM's own LoRA adapter trained further on generator v5 (v4's mix with doc
# 43's multi-step targets restored), one epoch at half the learning rate. Check first that ftM's adapter still exports
# to ftMg exactly. Wait for the sealed inv-blind v4 -> base17g, ftMg (incumbent), ftRg with tools (guard A) -> gate.
# Usage: mixR_chain.sh <repo tools/neuro-research dir>
set -uo pipefail
T=$1; C=$HOME/.cache/hookprobe-neuro; W=$C/w; O=$W/mixR; D=$C/invblind4; E=$C/mixR-eval; M=$C/models; FTM=$W/mixM/ft
mkdir -p "$O" "$E"
log() { echo "[$(date '+%F %T')] $*"; }
need() { [ -s "$1" ] || { log "STOP: missing $1"; exit 3; }; }
sha() { shasum -a 256 "$1" | cut -c1-64; }
need "$W/models/student17/config.json"; need "$M/base17-q8_0.gguf"; need "$M/gguf-mixM-q8_0.gguf"; need "$W/llamacpp/llama-b12477/llama-server"
[ "$(sha "$FTM/adapters.safetensors")" = 5cc933ba6222729d0a78b420cb41548877accce577282f10d8815fc4c851548b ] || { log "STOP: ftM adapter hash"; exit 3; }
[ "$(sha "$M/gguf-mixM-q8_0.gguf")" = 9576cfacef5ad23728e171f157321aedf8ab12c4aba926f89fd0527d5d23dcc9 ] || { log "STOP: ftMg hash"; exit 3; }
log "ftM's adapter must re-export to ftMg exactly"
bash "$T/export_gguf.sh" "$W" "$W/models/student17" "$FTM" "$O/rt-ftM" Q8_0 > "$O/export-rt.log" 2>&1
# tensors, not file bytes: the GGUF header's general.name comes from the export directory name (doc 49 §7)
"$W/venv-convert/bin/python" -I "$T/gguf_to_hf.py" verify "$M/gguf-mixM-q8_0.gguf" "$O/rt-ftM-q8_0.gguf" || { log "STOP: ftM adapter does not re-export to ftMg's tensors"; exit 3; }
rm -rf "$O"/rt-ftM*
log "investigation cases (gen v5, 900, seed 4901)"
python3 -I "$T/gen_investigate.py" --playbooks "$T/../../docs/research/neuro/data/playbooks.json" --n 900 --seed 4901 --version 5 --out "$O/inv5_cases.jsonl" || exit 3
"$W/venv/bin/python" -I "$T/build_inv_sft.py" "$O/inv5_cases.jsonl" "$O/data" --valid 0.05 --seed 49 || exit 3
need "$O/data/train.jsonl"
N=$(wc -l < "$O/data/train.jsonl"); IT=$(( (N + 3) / 4 ))
log "train ftR (resume ftM's adapter): $N examples, $IT iterations (1 epoch)"
printf 'lora_parameters:\n  rank: 16\n  dropout: 0.0\n  scale: 20.0\n' > "$O/lora.yaml"
"$W/venv/bin/mlx_lm.lora" -c "$O/lora.yaml" --model "$W/models/student17" --train --data "$O/data" --fine-tune-type lora \
  --resume-adapter-file "$FTM/adapters.safetensors" \
  --num-layers -1 --mask-prompt --grad-checkpoint --batch-size 4 --iters "$IT" --learning-rate 5e-5 --max-seq-length 2048 \
  --steps-per-report 25 --steps-per-eval 50 --val-batches 25 --save-every 50 --adapter-path "$O/ft" > "$O/train.log" 2>&1
need "$O/ft/adapters.safetensors"
python3 -I - "$O/train.log" "$O/ft" "$IT" <<'PY' || exit 3
import re, sys, os, shutil
log, d, it = sys.argv[1], sys.argv[2], int(sys.argv[3])
fin = os.path.join(d, "%07d_adapters.safetensors" % it)
if not os.path.exists(fin): shutil.copy(os.path.join(d, "adapters.safetensors"), fin)
vals = {}
for l in open(log):
    m = re.match(r"\s*(\d+)\s+val ([0-9.]+)", re.sub(r"\x1b\[[0-9;]*m", "", l))
    if m: vals[int(m.group(1))] = float(m.group(2))
saved = {k: v for k, v in vals.items() if os.path.exists(os.path.join(d, "%07d_adapters.safetensors" % k))}
best = min(saved, key=lambda k: (saved[k], k))
shutil.copy(os.path.join(d, "%07d_adapters.safetensors" % best), os.path.join(d, "adapters.safetensors"))
print("  ftR: checkpoint %d (valid %.3f) of %s; step-1 valid %s" % (best, saved[best], sorted(saved.items()), vals.get(1)))
PY
bash "$T/export_gguf.sh" "$W" "$W/models/student17" "$O/ft" "$O/gguf-mixR" Q8_0 > "$O/export.log" 2>&1
need "$O/gguf-mixR-q8_0.gguf"; cp "$O/gguf-mixR-q8_0.gguf" "$M/"
shasum -a 256 "$O/gguf-mixR-q8_0.gguf" "$O/ft/adapters.safetensors"
log "waiting for the sealed inv-blind v4 ($D/SEALED)"
until [ -s "$D/SEALED" ]; do sleep 60; done
want=$(cat "$D/SEALED"); got=$(sha "$D/blind_cases.jsonl")
[ "$want" = "$got" ] || { log "STOP: inv-blind v4 hash $got != sealed $want"; exit 4; }
INV_SET=v3 python3 -I "$T/inv_seal.py" check "$D/blind_cases.jsonl" "$O/inv5_cases.jsonl" "$W/mixM/inv4_cases.jsonl" \
  "$C/invblind/blind_cases.jsonl" "$C/invblind2/blind_cases.jsonl" "$C/invblind3/blind_cases.jsonl" > "$E/seal-recheck.txt" 2>&1 \
  || { log "STOP: inv-blind v4 seal re-check failed (see $E/seal-recheck.txt)"; exit 4; }
port=18988
for m in base17g:$M/base17-q8_0.gguf ftMg:$M/gguf-mixM-q8_0.gguf ftRg:$M/gguf-mixR-q8_0.gguf; do
  n=${m%%:*}; g=${m#*:}
  "$W/llamacpp/llama-b12477/llama-server" -m "$g" --port $port -c 8192 -np 1 -ngl 99 --reasoning off --no-webui --jinja > "$E/srv-$n.log" 2>&1 & sp=$!
  for _ in $(seq 1 180); do curl -sf http://127.0.0.1:$port/health >/dev/null && break; sleep 1; done
  python3 -I "$T/inv_eval.py" --cases "$D/blind_cases.jsonl" --url http://127.0.0.1:$port/v1 --guard A --json "$E/$n-inv.json" > "$E/$n-inv.txt" 2>&1
  kill $sp; wait $sp 2>/dev/null
  need "$E/$n-inv.json"; log "inv-blind v4 $n done"
done
python3 -I "$T/mixR_gate.py" "$D/blind_cases.jsonl" "$E/base17g-inv.json" "$E/ftMg-inv.json" "$E/ftRg-inv.json" "$T" | tee "$E/GATE.md"
log "MIXR DONE"
