#!/usr/bin/env bash
# builder/build-glibc-pin-amd64.sh — build the NATIVE amd64 `--features bpf` loader binaries
# (hookprobe-execsnoop, napse-quarantine, napse-l2guard) inside the pinned-glibc-2.35 Ubuntu
# 22.04 container (builder/glibc-pin-amd64/Containerfile), so a from-scratch amd64 build never
# again picks up too-new GLIBC symbols the way a plain native `cargo build` on a newer-glibc dev
# box does (2026-07 finding: GLIBC_2.38 symbols crash-looping `hookprobe-execsnoop` on the
# bookworm/glibc-2.36 image — see the Containerfile's own header for the full story).
#
# Mirrors the arm64 leg's discipline (an exact-glibc sysroot, `modules/napse-quarantine/
# README.md`'s "Cross-compile trail") for the amd64 leg — but SIMPLER, because amd64-on-amd64 is
# native, not cross: pinning the container's OWN base distro (Ubuntu 22.04, glibc 2.35) is
# enough; no `--sysroot`/`-isystem` wrapper needed.
#
# WHAT IT DOES NOT NEED FROM THE NETWORK: this box's egress resets connections to
# static.rust-lang.org specifically (rustup's channel — see Containerfile header), so this
# script reuses the CALLING HOST's own already-installed rustc/cargo (bind-mounted read-only
# into the container from `rustc --print sysroot`) instead of installing a fresh toolchain in
# the image. `cargo`'s own crates.io dependency fetches (a DIFFERENT host, confirmed reachable)
# still work normally. On a CI runner with full internet access this is equally valid — install
# the runner's pinned rustc as usual (`dtolnay/rust-toolchain@1.96.0`), then run this script,
# which mounts THAT runner's sysroot in exactly the same way.
#
# Usage:
#   builder/build-glibc-pin-amd64.sh                          # build all 3 loaders
#   builder/build-glibc-pin-amd64.sh hookprobe-execsnoop      # build just one
#   builder/build-glibc-pin-amd64.sh --rebuild-image ...      # force-rebuild the container image
#   builder/build-glibc-pin-amd64.sh --check                  # objdump -T proof only, no rebuild
#
# OUTPUT: writes each binary DIRECTLY to the exact path `builder/mkosi/build-vm.sh`'s
# `GNU_BIN`/`gen-staging.sh`'s `{gnu_bin}` placeholder already expects —
# `target/x86_64-unknown-linux-gnu/release/<crate>` — so build-vm.sh needs NO changes to consume
# it; it just always gets the glibc-pinned binary now instead of whatever the dev box's own
# native toolchain would have produced there.
set -euo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"
IMAGE="hookprobe-glibc-pin-amd64:22.04"
DOCKERFILE_DIR="$REPO/builder/glibc-pin-amd64"
# Max acceptable GLIBC symbol version — anything higher than this on the shipped bookworm image
# (glibc 2.36-9+deb12u14) risks the "version 'GLIBC_2.3x' not found" crash-loop this recipe
# exists to prevent. Kept at 2.34 (not 2.35/2.36) to match the Verify checklist's own bar and
# leave a one-point safety margin under Ubuntu 22.04's own glibc 2.35 (glibc symbol versions are
# typically a step or two behind the distro's shipped glibc.so itself).
MAX_GLIBC="2.34"

# The three module.yaml-declared `--features bpf` native amd64 loaders (grep
# 'features: \[bpf\]' modules/*/module.yaml — host-telemetry/napse-quarantine/napse-l2guard).
# crate name == bin name for all three (verified against each loader's Cargo.toml).
ALL_CRATES=(hookprobe-execsnoop napse-quarantine napse-l2guard)

REBUILD_IMAGE=0
CHECK_ONLY=0
CRATES=()
while [ $# -gt 0 ]; do
  case "$1" in
    --rebuild-image) REBUILD_IMAGE=1; shift ;;
    --check)         CHECK_ONLY=1; shift ;;
    -h|--help)
      echo "usage: $0 [--rebuild-image] [--check] [crate ...]"; exit 0 ;;
    -*) echo "$0: unknown flag $1" >&2; exit 1 ;;
    *) CRATES+=("$1"); shift ;;
  esac
done
[ ${#CRATES[@]} -gt 0 ] || CRATES=("${ALL_CRATES[@]}")

OUT_DIR="$REPO/target/x86_64-unknown-linux-gnu/release"
mkdir -p "$OUT_DIR"

check_glibc() {
  local bin="$1" max="$2"
  command -v objdump >/dev/null 2>&1 || { echo "$0: objdump not found on host -- cannot verify $bin" >&2; return 1; }
  local worst
  worst="$(objdump -T "$bin" 2>/dev/null | grep -oE 'GLIBC_[0-9]+\.[0-9]+' | sort -V -u | tail -1 || true)"
  if [ -z "$worst" ]; then
    echo "  $bin: no GLIBC_x.y symbol versions found (statically linked, or objdump couldn't read it)"
    return 0
  fi
  local worst_num="${worst#GLIBC_}"
  echo "  $bin: highest referenced symbol version = $worst"
  # Numeric compare via sort -V (handles 2.34 vs 2.5 etc. correctly, unlike a naive string compare).
  local top
  top="$(printf '%s\n%s\n' "$worst_num" "$max" | sort -V | tail -1)"
  if [ "$top" != "$max" ]; then
    echo "  FAIL: $bin references GLIBC_$worst_num > the $max ceiling -- would crash-loop on the" >&2
    echo "        bookworm/glibc-2.36 image (\"version 'GLIBC_$worst_num' not found\")" >&2
    return 1
  fi
  echo "  PASS: $bin tops out at GLIBC_$worst_num (<= $max ceiling)"
}

if [ "$CHECK_ONLY" = 1 ]; then
  echo "== builder/build-glibc-pin-amd64.sh --check: verifying already-built binaries =="
  fail=0
  for c in "${CRATES[@]}"; do
    bin="$OUT_DIR/$c"
    [ -x "$bin" ] || { echo "  SKIP: $bin not built yet -- run without --check first" >&2; continue; }
    check_glibc "$bin" "$MAX_GLIBC" || fail=1
  done
  exit "$fail"
fi

have() { command -v "$1" >/dev/null 2>&1; }
have podman || { echo "$0: podman not found -- this is a build-host step" >&2; exit 1; }

if [ "$REBUILD_IMAGE" = 1 ] || ! podman image exists "$IMAGE" 2>/dev/null; then
  echo "== building $IMAGE from $DOCKERFILE_DIR =="
  podman build -f "$DOCKERFILE_DIR/Containerfile" -t "$IMAGE" "$DOCKERFILE_DIR"
fi

# Bind-mount the CALLING HOST's own rustc/cargo sysroot (see the doc header for why: this
# recipe's glibc pin comes from the CONTAINER's system cc/headers, not from the Rust toolchain
# itself, so reusing the host's already-pinned rustc avoids both a network dependency on
# static.rust-lang.org AND a second, independently-drifting toolchain-version pin).
have rustc || { echo "$0: rustc not found on the host -- install the repo's pinned toolchain first" >&2; exit 1; }
SYSROOT="$(rustc --print sysroot)"
[ -d "$SYSROOT" ] || { echo "$0: rustc sysroot not found: $SYSROOT" >&2; exit 1; }
CARGO_BIN_HOST="$(dirname "$(command -v cargo)")"

# Isolated, ephemeral cargo home + target dir -- NEVER the host's own `target/x86_64-unknown-
# linux-gnu` cache (that dir holds artifacts built by the HOST's own (newer-glibc) system cc;
# reusing its build-script cache/fingerprints from inside this container risks silently reusing
# a stale, wrong-glibc-linked libbpf-sys .o instead of genuinely recompiling under the pin). Only
# the FINAL binary is ever copied into that shared location, never cargo's own cache dirs. Lives
# under `target/` (already `.gitignore`d, unlike `builder/generated/`) since this is exactly what
# it is: a second, isolated build-artifact cache, not a small generated-config file.
CARGO_HOME_PIN="$REPO/target/glibc-pin-amd64/cargo-home"
TARGET_PIN="$REPO/target/glibc-pin-amd64/target"
mkdir -p "$CARGO_HOME_PIN" "$TARGET_PIN"

echo "== building [${CRATES[*]}] natively inside $IMAGE (glibc <= $MAX_GLIBC pin) =="
BUILD_CMD="set -e; export PATH=\"$SYSROOT/bin:$CARGO_BIN_HOST:\$PATH\"; cd /src; "
for c in "${CRATES[@]}"; do
  BUILD_CMD+="cargo build --release --target x86_64-unknown-linux-gnu --features bpf -p '$c'; "
done

podman run --rm \
  -v "$REPO:/src:Z" \
  -v "$SYSROOT:$SYSROOT:ro,Z" \
  -v "$CARGO_HOME_PIN:/cargo-home:Z" \
  -v "$TARGET_PIN:/cargo-target:Z" \
  -e "CARGO_HOME=/cargo-home" \
  -e "CARGO_TARGET_DIR=/cargo-target" \
  -w /src \
  "$IMAGE" \
  bash -c "$BUILD_CMD"

fail=0
for c in "${CRATES[@]}"; do
  src="$TARGET_PIN/x86_64-unknown-linux-gnu/release/$c"
  [ -x "$src" ] || { echo "$0: expected binary not produced: $src" >&2; fail=1; continue; }
  cp -f "$src" "$OUT_DIR/$c"
  echo "== $c -> $OUT_DIR/$c =="
  check_glibc "$OUT_DIR/$c" "$MAX_GLIBC" || fail=1
done

exit "$fail"
