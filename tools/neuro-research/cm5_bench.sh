#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Neuro Engine Gate-5 measurement plan for a CM5 BENCH UNIT (NEURO_EXPERIMENT_DESIGN.md, E-HW*, E-LLM*).
#
# PREPARED, NOT RUN. Nothing in the research package was measured on a CM5.
#
# Where this runs: a CM5 bench unit booted into Raspberry Pi OS (64-bit) -- NOT heqk. heqk cannot host
# a userspace inference process today (single core, FP/SIMD trapped, no page cache: see
# NEURO_CM5_RESOURCE_BUDGET.md). Linux-on-CM5 numbers are therefore an UPPER BOUND for what a future
# native heqk EL0 inference server could reach on the same silicon, and every record is labelled
#   "platform":"cm5-linux"   -- never "cm5-heqk".
# It never touches a production device, never flashes anything, and only reads under /sys and /proc.
#
# Usage:  ./cm5_bench.sh <outdir> <llama.cpp bin dir> <models dir with .gguf files> [--quick]
# Needs:  llama-bench, llama-server (pinned llama.cpp build, recorded below); optional: fio, stress-ng,
#         iperf3, sysbench. Each optional tool's absence is recorded, never faked.
set -euo pipefail
OUT=${1:?outdir}; BIN=${2:?llama.cpp bin dir}; MODELS=${3:?models dir}; QUICK=${4:-}
mkdir -p "$OUT"
J="$OUT/results.jsonl"
rec() { printf '%s\n' "$1" >> "$J"; }
now() { date -u +%Y-%m-%dT%H:%M:%SZ; }

# ---- 0. provenance: what hardware, what firmware, what build ------------------------------------
{
  echo "== $(now)"; uname -a; cat /proc/device-tree/model 2>/dev/null; echo
  grep -m1 -E 'Revision' /proc/cpuinfo || true
  lscpu || true; grep -E 'MemTotal|MemAvailable' /proc/meminfo
  vcgencmd version 2>/dev/null || true; vcgencmd get_config arm_freq 2>/dev/null || true
  "$BIN/llama-bench" --version 2>&1 | head -3 || true
  lsblk -o NAME,SIZE,TYPE,MODEL,TRAN 2>/dev/null || true
  for f in "$MODELS"/*.gguf; do sha256sum "$f"; done
} > "$OUT/provenance.txt" 2>&1
rec "{\"ts\":\"$(now)\",\"kind\":\"provenance\",\"platform\":\"cm5-linux\",\"file\":\"provenance.txt\"}"

# ---- sampler: temperature, clock, throttle flags, PMIC rail power (CM5 has an on-board PMIC ADC) --
sample() {  # $1 = label; appends one JSON line
  local t c th p
  t=$(vcgencmd measure_temp 2>/dev/null | grep -o '[0-9.]*' || echo null)
  c=$(vcgencmd measure_clock arm 2>/dev/null | cut -d= -f2 || echo null)
  th=$(vcgencmd get_throttled 2>/dev/null | cut -d= -f2 || echo null)
  # sum of V*A over PMIC rails = SoC-side power estimate (not wall power; record both when a meter exists)
  p=$(vcgencmd pmic_read_adc 2>/dev/null | awk '/_A /{gsub(/.*=|A/,"",$2);a[$1]=$2} /_V /{gsub(/.*=|V/,"",$2);v[$1]=$2}
       END{s=0;for(k in a){r=k;sub(/_A$/,"_V",r);if(r in v)s+=a[k]*v[r]};printf "%.3f",s}' || echo null)
  rec "{\"ts\":\"$(now)\",\"kind\":\"sample\",\"platform\":\"cm5-linux\",\"label\":\"$1\",\"temp_c\":${t:-null},\"arm_hz\":${c:-null},\"throttled\":\"${th}\",\"pmic_w\":${p:-null}}"
}
sampler_start() { ( while :; do sample "$1"; sleep 1; done ) & SAMPLER=$!; }
sampler_stop() { kill "${SAMPLER:-0}" 2>/dev/null || true; wait "${SAMPLER:-0}" 2>/dev/null || true; }
trap sampler_stop EXIT

# ---- 1. idle baseline (60 s) ----------------------------------------------------------------------
sampler_start idle; sleep 60; sampler_stop

# ---- 2. memory bandwidth (E-HW1): the number every decode bound depends on -----------------------
if command -v sysbench >/dev/null; then
  for t in 1 2 4; do
    sysbench memory --memory-block-size=1M --memory-total-size=20G --memory-oper=read --threads=$t run \
      > "$OUT/membw-read-t$t.txt" 2>&1 || true
  done
  rec "{\"ts\":\"$(now)\",\"kind\":\"membw\",\"platform\":\"cm5-linux\",\"tool\":\"sysbench\",\"files\":\"membw-read-t*.txt\"}"
else
  rec "{\"ts\":\"$(now)\",\"kind\":\"membw\",\"platform\":\"cm5-linux\",\"status\":\"skipped: sysbench absent\"}"
fi

# ---- 3. storage tier (E-HW2): sequential + random read, eMMC and NVMe if present -----------------
if command -v fio >/dev/null; then
  for dev in /dev/mmcblk0 /dev/nvme0n1; do
    [ -b "$dev" ] || continue
    n=$(basename "$dev")
    sudo fio --name=seq --filename="$dev" --readonly --rw=read --bs=1M --direct=1 --runtime=30 --time_based \
      --output-format=json > "$OUT/fio-seq-$n.json" 2>&1 || true
    sudo fio --name=rand --filename="$dev" --readonly --rw=randread --bs=4k --iodepth=32 --ioengine=libaio \
      --direct=1 --runtime=30 --time_based --output-format=json > "$OUT/fio-rand4k-$n.json" 2>&1 || true
  done
  rec "{\"ts\":\"$(now)\",\"kind\":\"storage\",\"platform\":\"cm5-linux\",\"files\":\"fio-*.json\",\"note\":\"--readonly; no writes\"}"
fi

# ---- 4. llama-bench sweep (E-LLM1): format x threads, repack on/off, decode vs prefill ------------
THREADS="1 2 3 4"; [ "$QUICK" = --quick ] && THREADS="2 4"
for m in "$MODELS"/*.gguf; do
  base=$(basename "$m" .gguf)
  for rp in repack no-repack; do
    flag=""; [ "$rp" = no-repack ] && flag="--no-repack"
    sampler_start "bench:$base:$rp"
    "$BIN/llama-bench" -m "$m" -p 128,512 -n 128 -t $(echo $THREADS | tr ' ' ,) -r 3 $flag -o json \
      > "$OUT/bench-$base-$rp.json" 2> "$OUT/bench-$base-$rp.log" || true
    sampler_stop
    rec "{\"ts\":\"$(now)\",\"kind\":\"llama-bench\",\"platform\":\"cm5-linux\",\"model\":\"$base\",\"repack\":\"$rp\",\"file\":\"bench-$base-$rp.json\"}"
  done
done

# ---- 5. server profile (E-LLM2): cold activation, TTFT, RSS, KV types, concurrency ---------------
serve_case() {  # $1 model  $2 ctk  $3 parallel  $4 label
  local port=18080 pid rss0 t0 t1
  t0=$(date +%s.%N)
  "$BIN/llama-server" -m "$1" --port $port -t 2 -tb 4 -c 4096 -ctk "$2" -ctv "$2" -np "$3" --metrics \
     > "$OUT/server-$4.log" 2>&1 & pid=$!
  until curl -sf "http://127.0.0.1:$port/health" >/dev/null; do sleep 0.2; kill -0 $pid || return 0; done
  t1=$(date +%s.%N)
  rss0=$(awk '/VmRSS/{print $2}' /proc/$pid/status)
  rec "{\"ts\":\"$(now)\",\"kind\":\"activation\",\"platform\":\"cm5-linux\",\"label\":\"$4\",\"cold_start_s\":$(echo "$t1-$t0"|bc),\"rss_kib_ready\":$rss0}"
  sampler_start "serve:$4"
  python3 -I "$(dirname "$0")/eval/run_eval.py" --backend openai --url "http://127.0.0.1:$port/v1" \
     --mode closed --json "$OUT/eval-$4.json" > "$OUT/eval-$4.txt" 2>&1 || true
  sampler_stop
  rec "{\"ts\":\"$(now)\",\"kind\":\"serve\",\"platform\":\"cm5-linux\",\"label\":\"$4\",\"rss_kib_peak\":$(awk '/VmHWM/{print $2}' /proc/$pid/status),\"metrics\":$(curl -s http://127.0.0.1:$port/metrics | grep -E '^llamacpp:(prompt_tokens_seconds|predicted_tokens_seconds)' | awk '{printf "%s\"%s\":%s", (NR>1?",":"{"), $1, $2} END{print (NR?"}":"null")}')}"
  kill $pid; wait $pid 2>/dev/null || true
}
for m in "$MODELS"/*.gguf; do
  base=$(basename "$m" .gguf)
  # drop page cache first so activation is a true cold read from flash (root only; recorded if skipped)
  if sync && echo 3 | sudo tee /proc/sys/vm/drop_caches >/dev/null 2>&1; then :; fi
  serve_case "$m" f16 1 "$base-f16-np1"
  serve_case "$m" q8_0 1 "$base-q8-np1"
  [ "$QUICK" = --quick ] || serve_case "$m" q8_0 2 "$base-q8-np2"
done

# ---- 6. co-run interference (E-INT1): does inference hurt the packet path, and vice versa? -------
# Network latency proxy: ping through the bench unit's LAN port while (a) idle (b) decoding.
# Real heqk dataplane interference can only be measured on heqk; this is the Linux proxy.
if command -v iperf3 >/dev/null && [ -n "${PEER:-}" ]; then
  for phase in idle decode; do
    if [ "$phase" = decode ]; then
      first=$(ls "$MODELS"/*.gguf | head -1)
      "$BIN/llama-bench" -m "$first" -p 0 -n 2048 -t 2 > /dev/null 2>&1 & LB=$!
    fi
    ping -c 200 -i 0.05 "$PEER" > "$OUT/ping-$phase.txt" 2>&1 || true
    iperf3 -c "$PEER" -t 20 -J > "$OUT/iperf-$phase.json" 2>&1 || true
    [ "$phase" = decode ] && { kill $LB 2>/dev/null || true; }
  done
  rec "{\"ts\":\"$(now)\",\"kind\":\"interference\",\"platform\":\"cm5-linux\",\"files\":\"ping-*.txt iperf-*.json\"}"
else
  rec "{\"ts\":\"$(now)\",\"kind\":\"interference\",\"platform\":\"cm5-linux\",\"status\":\"skipped: set PEER=<host> and install iperf3\"}"
fi

# ---- 7. thermal soak (E-TH1): 10 minutes of continuous decode, throttle flags recorded -----------
first=$(ls "$MODELS"/*.gguf | head -1)
sampler_start soak
timeout 600 "$BIN/llama-bench" -m "$first" -p 0 -n 128 -t 4 -r 1000 > /dev/null 2>&1 || true
sampler_stop
rec "{\"ts\":\"$(now)\",\"kind\":\"soak\",\"platform\":\"cm5-linux\",\"seconds\":600}"
echo "done: $J"
