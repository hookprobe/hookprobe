#!/usr/bin/env bash
# ap-size-gate — the kernel payload must fit HBoot's load window (audit A3). The signed heqk8.img is
#   HBoot padded to 0x200000 + the 7,992-byte hybrid header + the flat kernel payload, and it must end at or
#   below 0x700000 (HBoot's EL2 stack reserve) — so the payload ceiling is 3,137,736 bytes. This catches a
#   growing kernel in CI, long before the (offline) signing step refuses it.
#   tools/ci/ap-size-gate.sh <kernel.elf>
set -euo pipefail
ELF="${1:?kernel ELF}"
OC=$(command -v llvm-objcopy || true)
[ -n "$OC" ] || OC=$(ls "$(rustc --print sysroot)"/lib/rustlib/*/bin/llvm-objcopy 2>/dev/null | head -1)
[ -x "$OC" ] || { echo "ap-size-gate: llvm-objcopy not found (rustup component llvm-tools)"; exit 2; }
T=$(mktemp); trap 'rm -f "$T"' EXIT
"$OC" -O binary "$ELF" "$T"
N=$(stat -c %s "$T"); MAX=$(( 0x700000 - 0x200000 - 0x200000 - 7992 ))
echo "ap-size-gate: payload $N / $MAX bytes (headroom $((MAX - N)))"
[ "$N" -le "$MAX" ] || { echo "FATAL: the kernel payload no longer fits the HBoot load window"; exit 1; }
