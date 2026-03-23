#!/bin/bash
#
# HookProbe Benchmark Suite
# Measures detection latency, throughput, memory, and classification accuracy.
# Outputs JSON for automated comparison page generation.
#
# Usage:
#   ./run-benchmark.sh                    # Full suite
#   ./run-benchmark.sh --quick            # Quick (100 iterations)
#   ./run-benchmark.sh --json             # JSON only (no human output)
#   ./run-benchmark.sh --output results.json
#
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
ITERATIONS=1000
OUTPUT_FILE=""
JSON_ONLY=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --quick)    ITERATIONS=100; shift ;;
        --json)     JSON_ONLY=true; shift ;;
        --output)   OUTPUT_FILE="$2"; shift 2 ;;
        *)          shift ;;
    esac
done

[[ -z "$OUTPUT_FILE" ]] && OUTPUT_FILE="$ROOT_DIR/reports/benchmark-$(date +%Y%m%d-%H%M%S).json"
mkdir -p "$(dirname "$OUTPUT_FILE")"

log() { $JSON_ONLY || echo "[BENCH] $1"; }

log "HookProbe Benchmark Suite"
log "Iterations: $ITERATIONS"
log "Output: $OUTPUT_FILE"
log "=========================================="

# Run the Python benchmark
cd "$ROOT_DIR"
PYTHONPATH="$ROOT_DIR" python3 -c "
import json
import time
import os
import sys
import numpy as np

sys.path.insert(0, '$ROOT_DIR')

from core.brain.hw_detect import detect_hardware
from core.brain.inference_bridge import InferenceBridge, HYDRA_FEATURE_DIMS

ITERATIONS = $ITERATIONS

# --- Hardware Detection ---
hw = detect_hardware()

# --- Initialize Bridge ---
bridge = InferenceBridge(tier='auto', hw_profile=hw)

# --- Benchmark: Classification Latency ---
features = np.random.rand(HYDRA_FEATURE_DIMS).astype(np.float32)
latencies = []
for _ in range(ITERATIONS):
    start = time.monotonic()
    result = bridge.classify(features)
    elapsed = (time.monotonic() - start) * 1000  # ms
    latencies.append(elapsed)

latencies.sort()
avg_latency = sum(latencies) / len(latencies)
median_latency = latencies[len(latencies) // 2]
p99_latency = latencies[int(len(latencies) * 0.99)]
min_latency = latencies[0]
max_latency = latencies[-1]

# --- Benchmark: Batch Throughput ---
batch_size = 100
batch_features = np.random.rand(batch_size, HYDRA_FEATURE_DIMS).astype(np.float32)
start = time.monotonic()
for i in range(batch_size):
    bridge.classify(batch_features[i])
batch_elapsed = time.monotonic() - start
throughput_per_sec = batch_size / batch_elapsed if batch_elapsed > 0 else 0

# --- System Metrics ---
import resource
mem_usage_mb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024  # KB to MB on Linux

# --- Build Results ---
results = {
    'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
    'hookprobe_version': '5.5.0',
    'hardware': hw.to_dict(),
    'benchmark': {
        'iterations': ITERATIONS,
        'classification': {
            'avg_latency_ms': round(avg_latency, 4),
            'median_latency_ms': round(median_latency, 4),
            'p99_latency_ms': round(p99_latency, 4),
            'min_latency_ms': round(min_latency, 4),
            'max_latency_ms': round(max_latency, 4),
        },
        'throughput': {
            'classifications_per_sec': round(throughput_per_sec, 1),
            'batch_size': batch_size,
            'batch_elapsed_ms': round(batch_elapsed * 1000, 2),
        },
        'memory': {
            'peak_rss_mb': round(mem_usage_mb, 1),
        },
        'engine': {
            'classify_backend': bridge.device_info()['classify_engine'],
            'llm_backend': bridge.device_info()['llm_engine'],
        },
    },
}

# Write JSON
with open('$OUTPUT_FILE', 'w') as f:
    json.dump(results, f, indent=2)

# Print summary
if '$JSON_ONLY' != 'true':
    print()
    print('=' * 50)
    print('  BENCHMARK RESULTS')
    print('=' * 50)
    print(f'  Hardware:     {hw.accelerator.value} ({hw.cpu_arch})')
    print(f'  Engine:       {results[\"benchmark\"][\"engine\"][\"classify_backend\"]}')
    print(f'  Iterations:   {ITERATIONS}')
    print(f'  ─────────────────────────────────────')
    print(f'  Avg Latency:  {avg_latency:.4f} ms')
    print(f'  Median:       {median_latency:.4f} ms')
    print(f'  P99:          {p99_latency:.4f} ms')
    print(f'  Throughput:   {throughput_per_sec:.0f} classifications/sec')
    print(f'  Peak Memory:  {mem_usage_mb:.1f} MB')
    print(f'  ─────────────────────────────────────')
    print(f'  Output:       $OUTPUT_FILE')
    print('=' * 50)
else:
    print(json.dumps(results, indent=2))
"

log "Benchmark complete."
