#!/usr/bin/env bash
# Stage the CYW43455 (BCM4345/6) WiFi firmware blobs into firmware/brcm/ so the
# HEQK kernel can `include_bytes!` them into the self-contained image (P10). These
# are LICENSED Cypress/Broadcom blobs (redistributable via linux-firmware) and are
# gitignored — not committed to this public repo. Run once before a P10 build.
#
#   ./cm5-boot/stage-wifi-firmware.sh
set -euo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$HERE/firmware/brcm"; mkdir -p "$OUT"

# Firmware .bin — Cypress cyfmac43455 (linux-firmware ships it, possibly .zst).
BIN_SRC=""
for c in /lib/firmware/cypress/cyfmac43455-sdio.bin \
         /lib/firmware/cypress/cyfmac43455-sdio.bin.zst \
         /lib/firmware/brcm/brcmfmac43455-sdio.bin \
         "$HOME/hookprobe-os/base/drivers/brcm-firmware-rpt/brcmfmac43455-sdio.bin"; do
  [ -e "$c" ] && { BIN_SRC="$c"; break; }
done
[ -n "$BIN_SRC" ] || { echo "ABORT: cyw43455 firmware .bin not found (install linux-firmware / firmware-cypress)"; exit 1; }
case "$BIN_SRC" in
  *.zst) zstd -f -dc "$BIN_SRC" > "$OUT/cyw43455-sdio.bin" ;;
  *)     cp -f "$BIN_SRC" "$OUT/cyw43455-sdio.bin" ;;
esac

# CLM blob + CM5 NVRAM (RF calibration; the CM5 board variant).
CLM="$HOME/hookprobe-os/base/drivers/brcm-firmware-rpt/brcmfmac43455-sdio.clm_blob"
[ -e "$CLM" ] || CLM=/lib/firmware/brcm/brcmfmac43455-sdio.clm_blob
[ -e "$CLM.zst" ] && zstd -f -dc "$CLM.zst" > "$OUT/cyw43455-sdio.clm_blob" || cp -f "$CLM" "$OUT/cyw43455-sdio.clm_blob"
NV="$HOME/hookprobe-os/base/drivers/brcm-firmware-rpt/brcmfmac43455-sdio.raspberrypi,5-compute-module.txt"
cp -f "$NV" "$OUT/cyw43455-sdio-cm5.nvram.txt"

echo "== staged:"; ls -la "$OUT"
echo "== now build P10: cargo build -p kernel --features hboot --release"
