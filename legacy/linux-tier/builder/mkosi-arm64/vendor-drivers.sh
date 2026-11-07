#!/usr/bin/env bash
# vendor-drivers.sh — VENDOR + PIN the out-of-tree USB-Wi-Fi dongle driver sources into the
# repo (base/drivers/<name>), ONCE, at a recorded commit. After this, the image build compiles
# ONLY from the committed local tree (no live external repos) — reproducible + auditable, in
# keeping with the OS's "trust nothing unsigned · SBOM/CBOM" posture. Records each source URL
# + pinned commit SHA in base/drivers/SOURCES.md for the CBOM/provenance trail.
#
# Run once (network needed); commit base/drivers/ ; thereafter build-dongle-drivers.sh is offline.
#   builder/mkosi-arm64/vendor-drivers.sh
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
DST="$REPO/base/drivers"
SRC="$DST/SOURCES.md"

# (name, git url) — the de-facto community sources for the operator-selected chipsets.
# Pinned to whatever HEAD resolves at vendor time; the SHA is recorded below and the TREE is
# committed, so the build is reproducible regardless of upstream moving.
REPOS=(
  "rtl8812au|https://github.com/aircrack-ng/rtl8812au.git"
  "rtl8821cu|https://github.com/morrownr/8821cu-20210916.git"
  "rtl8821au|https://github.com/morrownr/8821au-20210708.git"
  "rtl88x2bu|https://github.com/morrownr/88x2bu-20210702.git"
  "rtl8852au|https://github.com/lwfinger/rtl8852au.git"
  "rtl8188eu|https://github.com/aircrack-ng/rtl8188eus.git"
  "rtl8192eu|https://github.com/clnhub/rtl8192eu-linux.git"
)

mkdir -p "$DST"
{
  echo "# Vendored out-of-tree USB-Wi-Fi dongle drivers — sources & pinned commits"
  echo
  echo "> Vendored by \`builder/mkosi-arm64/vendor-drivers.sh\`. Built into the arm64/Pi 4 image"
  echo "> by \`build-dongle-drivers.sh\` from these LOCAL trees only (no live external repos)."
  echo "> Chipsets operator-selected; sources are the de-facto community repos for each."
  echo
  echo "| Driver | Upstream | Pinned commit |"
  echo "|---|---|---|"
} > "$SRC"

clone_retry() { # url dest — shallow clone with retries against transient resets
  local url=$1 dest=$2 n=0
  until [ "$n" -ge 5 ]; do
    rm -rf "$dest"
    git clone --depth 1 "$url" "$dest" && return 0
    n=$((n+1)); echo "  clone failed ($n/5), retrying…"; sleep 4
  done
  return 1
}

for entry in "${REPOS[@]}"; do
  name=${entry%%|*}; url=${entry#*|}
  if [ -d "$DST/$name" ] && [ ! -d "$DST/$name/.git" ] && grep -q "\`$name\`" "$SRC" 2>/dev/null; then
    echo "=== $name already vendored — skipping ==="; continue
  fi
  echo "=== vendoring $name from $url ==="
  clone_retry "$url" "$DST/$name" || { echo "  GIVING UP on $name (network); re-run to resume"; continue; }
  sha=$(git -C "$DST/$name" rev-parse HEAD)
  rm -rf "$DST/$name/.git"
  echo "| \`$name\` | $url | \`$sha\` |" >> "$SRC"
  echo "  pinned $name @ $sha"
done

echo "=== vendored $(ls -d "$DST"/*/ | wc -l) driver trees into $DST ==="
cat "$SRC"
echo "next: commit base/drivers/, then build-dongle-drivers.sh builds from the local trees"
