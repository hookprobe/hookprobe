#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# m5-probe-build — build the NanoPi M5 bring-up probe (os/kernel/m5probe) as a flat arm64 Image for booti.
#   tools/diagnostics/m5-probe-build.sh [--out DIR]       (default ~/heqk-m5-bench/probe)
# Then stage it: cp DIR/m5probe.img ~/heqk-m5-bench/tftp/heqk-m5/heqk-m5.img  (or m5-metal-loop.sh --image).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
OUT="$HOME/heqk-m5-bench/probe"
[ "${1:-}" = "--out" ] && OUT="$2"
mkdir -p "$OUT"
( cd "$ROOT/os/kernel" && cargo build -q -p m5probe --release )
ELF="$ROOT/os/kernel/target/aarch64-unknown-none-softfloat/release/m5probe"
# Only R_AARCH64_RELATIVE relocations are handled by the entry code: refuse anything else.
bad=$(aarch64-linux-gnu-readelf -rW "$ELF" | awk 'NR>2 && $3 ~ /^R_/ && $3 != "R_AARCH64_RELATIVE"' | wc -l)
[ "$bad" -eq 0 ] || { echo "m5probe has non-RELATIVE dynamic relocations — entry.s cannot apply them" >&2; exit 1; }
aarch64-linux-gnu-objcopy -O binary "$ELF" "$OUT/m5probe.img"
[ "$(xxd -s 0x38 -l 4 -p "$OUT/m5probe.img")" = "41524d64" ] || { echo "bad Image header magic" >&2; exit 1; }
echo "m5probe.img $(stat -c %s "$OUT/m5probe.img") B sha256 $(sha256sum "$OUT/m5probe.img" | cut -c1-16)… -> $OUT"
