#!/usr/bin/env bash
# sdot-gate.sh — the two-stage SDOT verification gate for dga-lm (base-tier-build-ticket.md
# Phase 4, MUST-FIX #2; ADR 0021 D7).
#
# The A76 acceleration claim ("dga-lm's int8 dot lowers to a single SDOT on Cortex-A76") is
# NOT asserted anywhere in the tree — it is VERIFIED here, or the claim is dropped. This gate
# never fabricates green: if a disassembler is unavailable, the relevant stage is reported
# SKIPPED (exit 0 with a loud note), not PASSED. A hard FAIL (exit 1) happens only when a tool
# IS present and the expected opcode/instruction is provably ABSENT.
#
# Stage (a): Rust -> Wasm. Build the `relaxed-dot` tier with the required target-features and
#            confirm the emitted .wat carries `i32x4.relaxed_dot_i8x16_i7x16_add_s`. This proves
#            the crate routes the hot loop through the EXPLICIT core::arch::wasm32 intrinsic
#            (must-fix #2 — plain core::simd emits nothing).
# Stage (b): Wasm -> native AOT. Precompile the relaxed .wasm to an aarch64 `.a76.cwasm` with a
#            cortex-a76 (+dotprod) target and confirm the native disassembly carries `sdot`.
#            This proves Cranelift actually lowered the op to SDOT (the part ADR 0021 D7 says
#            must be seen, not assumed).
#
# Usage:  modules/dga-lm/tools/sdot-gate/sdot-gate.sh
# Env:    SUPERVISOR=<path to hookprobe-supervisor>   (for stage b; else stage b SKIPs)
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
cd "$REPO"
export PATH="$HOME/.cargo/bin:$PATH"

OP_WASM='relaxed_dot'          # substring of i32x4.relaxed_dot_i8x16_i7x16_add_s in .wat
OP_NATIVE='sdot'               # aarch64 SDOT mnemonic (case-insensitive)
OUT="target/wasm32-wasip1/release/dga-lm.relaxed.wasm"
WAT="target/dga-lm.relaxed.wat"
CWASM="target/dga-lm.a76.cwasm"

log(){ printf '  %s\n' "$*"; }
have(){ command -v "$1" >/dev/null 2>&1; }

echo "== sdot-gate: dga-lm A76 relaxed-dot / SDOT verification =="

# ---- build the relaxed tier with the REQUIRED target-features ---------------------------
log "building dga-lm --features relaxed-dot with -C target-feature=+simd128,+relaxed-simd"
RUSTFLAGS="-C target-feature=+simd128,+relaxed-simd" \
  cargo build -p dga-lm --release --target wasm32-wasip1 --features relaxed-dot >/dev/null
# the built artifact is the same dga-lm.wasm name; copy it aside so the baseline (no-feature)
# build is never confused with the relaxed one.
cp -f target/wasm32-wasip1/release/dga-lm.wasm "$OUT"
log "built: $OUT ($(stat -c%s "$OUT" 2>/dev/null || echo '?') bytes)"

# ---- stage (a): Rust -> Wasm, expect the relaxed-dot opcode in the .wat ------------------
STAGE_A="SKIP"
if have wasm-tools; then
  wasm-tools print "$OUT" > "$WAT"
elif have wasm2wat; then
  wasm2wat "$OUT" -o "$WAT"
else
  WAT=""
fi
if [ -n "$WAT" ] && [ -f "$WAT" ]; then
  if grep -qi "$OP_WASM" "$WAT"; then
    STAGE_A="PASS"; log "stage (a) PASS: '$OP_WASM' opcode present in .wat"
  else
    STAGE_A="FAIL"; log "stage (a) FAIL: '$OP_WASM' opcode ABSENT — the intrinsic did not survive to Wasm"
  fi
else
  log "stage (a) SKIP: no wasm-tools/wasm2wat disassembler on PATH (never fabricating green)"
fi

# ---- stage (b): Wasm -> aarch64 AOT, expect SDOT in the native disassembly ---------------
STAGE_B="SKIP"
SUP="${SUPERVISOR:-}"
[ -z "$SUP" ] && for c in target/release/hookprobe-supervisor target/debug/hookprobe-supervisor; do
  [ -x "$c" ] && SUP="$c" && break
done
DISASM=""
for d in aarch64-linux-gnu-objdump objdump llvm-objdump; do have "$d" && DISASM="$d" && break; done
if [ -n "$SUP" ] && [ -n "$DISASM" ]; then
  # precompile the relaxed wasm to a cortex-a76 (+dotprod) native cwasm, then disassemble.
  if "$SUP" --precompile-file "$OUT" --precompile-cpu cortex-a76 --precompile-out "$CWASM" 2>/dev/null \
     || "$SUP" --precompile "$OUT" >/dev/null 2>&1; then
    [ -f "$CWASM" ] || CWASM="$(ls -1 target/*a76*.cwasm 2>/dev/null | head -1)"
  fi
  if [ -n "${CWASM:-}" ] && [ -f "$CWASM" ]; then
    if "$DISASM" -d "$CWASM" 2>/dev/null | grep -qi "\\b${OP_NATIVE}\\b"; then
      STAGE_B="PASS"; log "stage (b) PASS: '$OP_NATIVE' instruction present in a76 .cwasm disassembly"
    else
      STAGE_B="CLAIM-DROPPED"
      log "stage (b): '$OP_NATIVE' NOT found in the a76 disassembly — Cranelift did not lower to SDOT"
      log "           -> ship the module, but DROP the 'full SDOT throughput' claim (ADR 0021 D7)"
    fi
  else
    log "stage (b) SKIP: could not produce an a76 .cwasm (supervisor precompile flags may differ)"
  fi
else
  log "stage (b) SKIP: need a hookprobe-supervisor + an aarch64 objdump; set SUPERVISOR=<path>"
fi

echo "== sdot-gate result: stage(a)=$STAGE_A  stage(b)=$STAGE_B =="
# Only a *proven* stage-(a) FAIL is a hard failure — the explicit intrinsic must reach Wasm.
# stage (b) never hard-fails: a missing SDOT lowering only drops the throughput claim, and a
# missing tool only SKIPs — the portable-SIMD module still ships and is correct.
[ "$STAGE_A" = "FAIL" ] && exit 1
exit 0
