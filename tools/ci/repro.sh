#!/usr/bin/env bash
# =============================================================================
# tools/ci/repro.sh — G4r: reproducible-build check for the SHIPPED heqk flavour
# (ADR 0036 Rung 1, ADR 0048). Builds `--features prod --release` twice into two
# FRESH target dirs at two different absolute paths and requires byte-identical
# kernel ELFs. A mismatch means something non-deterministic (timestamps, absolute
# paths, HashMap order, build-script randomness) leaked into the image — which
# would make the signed artifact unverifiable by a third party.
#
#   tools/ci/repro.sh            (writes $CI_OUT/repro.json)
# =============================================================================
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CI_OUT="${CI_OUT:-$ROOT/out/ci}"
FEATURES="${REPRO_FEATURES:-prod}"
mkdir -p "$CI_OUT"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/heqk-repro.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

# Remap absolute source/toolchain paths so the two build locations cannot leak in.
export RUSTFLAGS="${RUSTFLAGS:-} --remap-path-prefix=$ROOT=/src --remap-path-prefix=$HOME=/home"
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git -C "$ROOT" log -1 --format=%ct 2>/dev/null || echo 0)}"

build() {  # build <n>
  local td="$WORK/t$1"
  (cd "$ROOT/os/kernel" && CARGO_TARGET_DIR="$td" cargo build -p kernel --features "$FEATURES" --release -q)
  sha256sum "$td/aarch64-unknown-none-softfloat/release/kernel" | cut -d' ' -f1
}

# The shipped flavours embed the licensed CYW43455 firmware (gitignored) — stage the pinned blob.
"$ROOT/tools/ci/stage-firmware.sh"

echo "[repro] build 1/2 (features=$FEATURES)"; H1=$(build 1)
echo "[repro] build 2/2 (features=$FEATURES)"; H2=$(build 2)
echo "[repro] sha256 #1 $H1"
echo "[repro] sha256 #2 $H2"
RESULT=$([ "$H1" = "$H2" ] && echo reproducible || echo NOT-reproducible)
printf '{"features":"%s","sha256_1":"%s","sha256_2":"%s","result":"%s"}\n' "$FEATURES" "$H1" "$H2" "$RESULT" > "$CI_OUT/repro.json"
echo "[repro] $RESULT"
[ "$H1" = "$H2" ]
