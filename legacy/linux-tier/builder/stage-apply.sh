#!/usr/bin/env bash
# builder/stage-apply.sh — ADR 0015 D1 applier. Executes a staging-plan.json's actions
# against a destination root. Parses NO YAML (only the plan's JSON) — this is the "dumb,
# shared" half of the generator/applier split, so all three build paths (base/Containerfile
# stage `build`, builder/mkosi-arm64/build-arm64.sh, builder/mkosi/build-vm.sh) converge on
# identical staging semantics. Adding a module changes only the generated plan; this script
# never changes.
#
# Usage:
#   builder/stage-apply.sh <plan.json> <DEST_ROOT> [--relaxed]
#
# Path placeholders in the plan ({repo} {wasm} {bin} {gnu_bin}) are resolved from env:
#   REPO=...       repo root                         (default: this script's ../..)
#   WASM=...       wasm32-wasip1 release dir          (default: $REPO/target/wasm32-wasip1/release)
#   BIN=...        musl release dir for the plan arch (default: derived from plan.arch)
#   GNU_BIN=...    gnu release dir for the plan arch  (default: derived from plan.arch)
#
# --relaxed (dev box, incomplete cross-toolchains): a missing SOURCE file is a WARNING, the
# action is skipped, and the run continues — mirrors today's build-arm64.sh "note: X not
# staged" tolerance for artifacts nobody cross-built locally yet. Without --relaxed (CI /
# release builds) a missing source, OR a `requires_sig` action whose file is absent, is a
# HARD FAILURE — "trust nothing unsigned" + a release you can't reproduce is a liability.
#
# `optional: true` (ADR 0017 D3 — the build-time AOT `.cwasm`): a missing source is ALWAYS a
# WARNING, regardless of --relaxed/CI — a signed wasm module that ships no AOT blob for the
# built arch is a normal, safe condition (it falls back to the verified-JIT floor at runtime),
# never a reason to fail the whole image build.
set -euo pipefail

PLAN="${1:?usage: stage-apply.sh <plan.json> <DEST_ROOT> [--relaxed]}"
DEST="${2:?usage: stage-apply.sh <plan.json> <DEST_ROOT> [--relaxed]}"
RELAXED=0
[ "${3:-}" = "--relaxed" ] && RELAXED=1

HERE=$(cd "$(dirname "$0")" && pwd)
REPO="${REPO:-$(cd "$HERE/.." && pwd)}"

ARCH="$(jq -r '.arch' "$PLAN")"
case "$ARCH" in
  arm64)   TRIPLE=aarch64 ;;
  amd64)   TRIPLE=x86_64 ;;
  riscv64) TRIPLE=riscv64gc ;;
  *) echo "stage-apply.sh: unknown arch '$ARCH' in $PLAN" >&2; exit 1 ;;
esac

WASM="${WASM:-$REPO/target/wasm32-wasip1/release}"
BIN="${BIN:-$REPO/target/${TRIPLE}-unknown-linux-musl/release}"
GNU_BIN="${GNU_BIN:-$REPO/target/${TRIPLE}-unknown-linux-gnu/release}"

mkdir -p "$DEST"

resolve() {
  # Substitute the four placeholder tokens; ADR 0015 D1's stated set.
  local s="$1"
  s="${s//\{repo\}/$REPO}"
  s="${s//\{wasm\}/$WASM}"
  s="${s//\{bin\}/$BIN}"
  s="${s//\{gnu_bin\}/$GNU_BIN}"
  s="${s//\{dest\}/$DEST}"
  printf '%s' "$s"
}

FAIL=0
N_OK=0
N_SKIP=0

apply_action() {
  local op="$1" src="$2" dest="$3" mode="$4" requires_sig="$5" mod_id="$6" optional="$7"
  local rsrc rdest
  rsrc="$(resolve "$src")"
  rdest="$DEST$(resolve "$dest")"

  if [ ! -e "$rsrc" ]; then
    if [ "$optional" = "true" ]; then
      # ADR 0017 D3: a missing AOT `.cwasm` for this arch is ALWAYS a warning, never a failure —
      # unconditionally (not gated on --relaxed): the module falls back to verified JIT at runtime.
      echo "stage-apply.sh: note: optional artifact not staged for '$mod_id' (ADR 0017 D3 — falls back to verified JIT): $rsrc" >&2
      N_SKIP=$((N_SKIP+1))
      return
    fi
    if [ "$requires_sig" = "true" ]; then
      echo "stage-apply.sh: SIGNATURE MISSING for module '$mod_id': $rsrc (dest ${dest})" >&2
      if [ "$RELAXED" = "1" ]; then
        echo "  --relaxed: WARNING only, skipping (this build CANNOT ship — CI must hard-fail here)" >&2
        N_SKIP=$((N_SKIP+1))
        return
      fi
      FAIL=1
      return
    fi
    if [ "$RELAXED" = "1" ]; then
      echo "stage-apply.sh: note: source not staged for '$mod_id' (relaxed): $rsrc" >&2
      N_SKIP=$((N_SKIP+1))
      return
    fi
    echo "stage-apply.sh: ERROR: missing source for module '$mod_id': $rsrc (dest ${dest})" >&2
    FAIL=1
    return
  fi

  mkdir -p "$(dirname "$rdest")"
  case "$op" in
    install)
      install -D -m"$mode" "$rsrc" "$rdest"
      ;;
    copy)
      cp -f "$rsrc" "$rdest"
      chmod "$mode" "$rdest"
      ;;
    symlink)
      ln -sf "$rsrc" "$rdest"
      ;;
    *)
      echo "stage-apply.sh: unknown op '$op'" >&2
      FAIL=1
      return
      ;;
  esac
  N_OK=$((N_OK+1))
}

# Iterate modules[].actions via jq, emitting TSV rows (op, src, dest, mode, requires_sig, id, optional).
while IFS=$'\t' read -r op src dest mode requires_sig mod_id optional; do
  apply_action "$op" "$src" "$dest" "$mode" "$requires_sig" "$mod_id" "$optional"
done < <(jq -r '
  .modules[]
  | .id as $id
  | .actions[]
  | [ .op, .src, .dest, (.mode // "0644"), ((.requires_sig // false) | tostring), $id, ((.optional // false) | tostring) ]
  | @tsv
' "$PLAN")

echo "stage-apply.sh: $N_OK action(s) applied, $N_SKIP skipped (relaxed=$RELAXED), dest=$DEST" >&2
[ "$FAIL" -eq 0 ] || { echo "stage-apply.sh: FAILED — see errors above" >&2; exit 1; }
