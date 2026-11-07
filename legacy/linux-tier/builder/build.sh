#!/usr/bin/env bash
# =============================================================================
# builder/build.sh — compose the signed bootc OS image and turn it into
# per-platform installable artifacts (.raw/.iso/.qcow2/.ami) via bootc-image-builder.
# =============================================================================
#
# Reads base/profiles/<PROFILE>.yaml (build_args + bib.variants + bib.filesystem)
# so "add a platform = one profile file" (the design test). The SAME OCI image
# self-detects hardware at first boot (bootstrap → Platform Manifest); a profile
# only tunes optional packages + which disk artifacts to emit.
#
# Pipeline per (profile, arch):
#   1. release-sign modules + bake the trust store        (builder/sign-release.sh)
#   2. podman build base/Containerfile  → signed OCI image (cosign)
#   3. bootc-image-builder per type     → .raw / .iso / .qcow2 / .ami
#
# REQUIRES a BUILD HOST with: podman (rootful or rootless+privileged), the
# bootc-image-builder container, cosign. It CANNOT run on a box without podman —
# use `--plan` to print the exact plan anywhere (validated on the dev box).
# =============================================================================
set -euo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"

PROFILE=""; PLAN=0; ARCH_FILTER=""; TYPE_FILTER=""
IMAGE_BASE="${IMAGE_BASE:-localhost/hookprobe-os}"
OUT="${OUT:-$REPO/builder/out}"
BIB="${BIB:-quay.io/centos-bootc/bootc-image-builder:latest}"
COSIGN_KEY="${COSIGN_KEY:-}"          # off-device in production (HSM); optional here

usage() { echo "usage: build.sh --profile <name> [--plan] [--arch x86_64|aarch64] [--type raw|iso|qcow2|ami]"; exit 2; }
while [ $# -gt 0 ]; do case "$1" in
  --profile) PROFILE="${2:-}"; shift 2;;
  --plan|--check) PLAN=1; shift;;
  --arch) ARCH_FILTER="${2:-}"; shift 2;;
  --type) TYPE_FILTER="${2:-}"; shift 2;;
  -h|--help) usage;;
  *) echo "unknown arg: $1" >&2; usage;;
esac; done
[ -n "$PROFILE" ] || usage
PROF="$REPO/base/profiles/$PROFILE.yaml"
[ -f "$PROF" ] || { echo "no such profile: $PROF" >&2; exit 1; }

have() { command -v "$1" >/dev/null 2>&1; }

# Expand the profile's bib.variants into TSV rows: arch <tab> targetarch <tab> type
plan_rows() {
  python3 - "$PROF" "$ARCH_FILTER" "$TYPE_FILTER" <<'PY'
import sys, yaml
prof = yaml.safe_load(open(sys.argv[1])) or {}
arch_f, type_f = sys.argv[2], sys.argv[3]
TA = {"x86_64": "amd64", "aarch64": "arm64"}
for v in prof.get("bib", {}).get("variants", []):
    arch = v.get("arch")
    if arch_f and arch != arch_f:
        continue
    for t in v.get("types", ["raw"]):
        if type_f and t != type_f:
            continue
        print(f"{arch}\t{TA.get(arch, arch)}\t{t}")
PY
}

echo "== HookProbe OS image build · profile=$PROFILE =="
ROWS="$(plan_rows)"
[ -n "$ROWS" ] || { echo "no matching variants in $PROF (check --arch/--type)"; exit 1; }

if [ "$PLAN" = 1 ]; then
  echo "PLAN (dry-run — no build performed):"
  while IFS=$'\t' read -r arch ta type; do
    img="$IMAGE_BASE:$PROFILE-$ta"
    echo "  1. podman build -f base/Containerfile --build-arg PROFILE=$PROFILE --build-arg TARGETARCH=$ta -t $img ."
    echo "     cosign sign $img"
    echo "     podman run --privileged --rm -v $OUT:/output $BIB --type $type --target-arch $arch $img"
    echo "     → $OUT/$PROFILE-$arch.$type"
  done <<< "$ROWS"
  echo "tools present: podman=$(have podman && echo yes || echo MISSING)  cosign=$(have cosign && echo yes || echo MISSING)  python3=$(have python3 && echo yes || echo MISSING)"
  [ "$(have podman && echo y)" = "y" ] || echo "NOTE: podman missing → real build must run on a build host. This --plan is the dry-run."
  exit 0
fi

# ---- real build (build host only) ----
have podman || { echo "ERROR: podman not found. This is a build-host step; run with --plan to preview, or run on a host with podman + $BIB." >&2; exit 1; }
mkdir -p "$OUT"

echo "[1/3] release-sign modules + bake trust store"
"$REPO/builder/sign-release.sh"

while IFS=$'\t' read -r arch ta type; do
  img="$IMAGE_BASE:$PROFILE-$ta"
  echo "[2/3] podman build $img ($ta)"
  podman build -f "$REPO/base/Containerfile" --build-arg "PROFILE=$PROFILE" --build-arg "TARGETARCH=$ta" -t "$img" "$REPO"
  if [ -n "$COSIGN_KEY" ] && have cosign; then
    echo "      cosign sign $img"
    cosign sign --key "$COSIGN_KEY" "$img"
  else
    echo "      (skip cosign — set COSIGN_KEY; production signs off-device)"
  fi
  echo "[3/3] bootc-image-builder --type $type --target-arch $arch"
  podman run --rm --privileged \
    -v "$OUT:/output" \
    -v /var/lib/containers/storage:/var/lib/containers/storage \
    "$BIB" --type "$type" --target-arch "$arch" "$img"
  echo "      → $OUT (artifact: $PROFILE-$arch.$type)"
done <<< "$ROWS"

echo "done. artifacts in $OUT"
