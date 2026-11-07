#!/usr/bin/env bash
# =============================================================================
# tools/ci/stage-firmware.sh — reproducibly stage the CYW43455 Wi-Fi firmware that the
# SHIPPED heqk flavours (`prod`, `prod-mc`) embed via include_bytes! (ADR 0048).
#
# Why: the blobs are licensed (redistributable via linux-firmware) and gitignored, so a
# fresh checkout — and therefore every CI runner — could not build the shipped kernel at
# all (found by G4r on 2026-11-08). This fetches the exact package the staging script's
# header names, verifies BOTH the .deb and the extracted .bin against pinned sha256s, and
# hands the blob to os/kernel/cm5-boot/stage-wifi-firmware.sh (which adds the CM5 NVRAM,
# the CLM blob and the baked regdomain, and enforces firmware >= 7.45.265).
#
#   tools/ci/stage-firmware.sh          # no-op if already staged
#   FORCE=1 tools/ci/stage-firmware.sh  # restage
# =============================================================================
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT="$ROOT/os/kernel/firmware/brcm"

# Pinned: RPi firmware-nonfree 20260519 → cyfmac43455-sdio-standard.bin 7.45.265 (metal-proven
# on CM5, ADR 0034). Bumping these is a reviewed change (tools/ci/ is a protected path).
DEB_URL="http://archive.raspberrypi.com/debian/pool/main/f/firmware-nonfree/firmware-brcm80211_20260519-1~bpo13+1+rpt1_all.deb"
DEB_SHA256="c25e13e84be8dbf58b6b3381b4a10ad7e9dbeae101579376f457e0f17e60d902"
BIN_SHA256="d608f866582519c0a28d86db43040f4f1b98dd1d153e72e9752586546b4a36c3"

if [ -z "${FORCE:-}" ] && [ -s "$OUT/cyw43455-sdio.bin" ] && [ -s "$OUT/cyw43455-sdio.clm_blob" ] \
   && [ -s "$OUT/cyw43455-sdio-cm5.nvram.txt" ]; then
  if echo "$BIN_SHA256  $OUT/cyw43455-sdio.bin" | sha256sum -c --quiet 2>/dev/null; then
    echo "[stage-firmware] already staged (pinned 7.45.265 blob)"; exit 0
  fi
  echo "[stage-firmware] staged blob is NOT the pinned one — restaging"
fi

WORK="$(mktemp -d "${TMPDIR:-/tmp}/heqk-fw.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
echo "[stage-firmware] fetching $(basename "$DEB_URL")"
curl -sSfL --retry 3 -o "$WORK/fw.deb" "$DEB_URL"
echo "$DEB_SHA256  $WORK/fw.deb" | sha256sum -c --quiet || { echo "ABORT: .deb sha256 mismatch"; exit 1; }
# The .deb is an `ar` archive; extract with dpkg-deb when present, else ar + tar (any Linux).
if command -v dpkg-deb >/dev/null; then
  dpkg-deb -x "$WORK/fw.deb" "$WORK/x"
else
  (cd "$WORK" && ar x fw.deb && mkdir -p x && tar -xf data.tar.* -C x)
fi
BIN="$WORK/x/usr/lib/firmware/cypress/cyfmac43455-sdio-standard.bin"
echo "$BIN_SHA256  $BIN" | sha256sum -c --quiet || { echo "ABORT: firmware .bin sha256 mismatch"; exit 1; }
FW_BIN_SRC="$BIN" "$ROOT/os/kernel/cm5-boot/stage-wifi-firmware.sh"
