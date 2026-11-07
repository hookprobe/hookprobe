#!/usr/bin/env bash
# Stage the CYW43455 (BCM4345/6) WiFi firmware blobs into firmware/brcm/ so the
# HEQK kernel can `include_bytes!` them into the self-contained image (P10). These
# are LICENSED Cypress/Broadcom blobs (redistributable via linux-firmware) and are
# gitignored — not committed to this public repo. Run once before a P10 build.
#
#   ./cm5-boot/stage-wifi-firmware.sh            # bakes REGDOMAIN=RO (default)
#   REGDOMAIN=DE ./cm5-boot/stage-wifi-firmware.sh
#
# REGDOMAIN + THE FIRMWARE VERSION ARE THE REGDOMAIN FIX (metal-proven 2026-07-23):
#   * The CYW43455 firmware is the regulatory AUTHORITY (it enforces channels/power
#     from its CLM blob). Firmware **7.45.234 (2021) SILENTLY IGNORES the country** —
#     phy stays world/99, ch12/13 + full ETSI 5 GHz stay blocked. Firmware
#     **>= 7.45.265** (RPi firmware-nonfree 2026-05) actually applies it. So we
#     REQUIRE >= 7.45.265 and abort loudly on an older blob.
#   * Unlike the RPi downstream kernel (which intercepts NVRAM `ccode=` and only
#     uses it as a "00" fallback), HEQK's own loader uploads the NVRAM verbatim, so
#     baking `ccode=<CC>`/`regrev=0` here sets the firmware's POWER-ON regulatory
#     domain DETERMINISTICALLY — no userspace `iw reg set`, no runtime negotiation.
#   * The country must exist in the CLM blob (RO/ETSI does). rev 0 = the driver's
#     ISO3166 fallback (correct for a current CLM).
# Get a current blob:  http://archive.raspberrypi.com/debian/pool/main/f/firmware-nonfree/
#   firmware-brcm80211_20260519-*.deb  ->  usr/lib/firmware/cypress/cyfmac43455-sdio-standard.bin (7.45.265)
set -euo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$HERE/firmware/brcm"; mkdir -p "$OUT"
REGDOMAIN="${REGDOMAIN:-RO}"       # ISO-3166 alpha-2 baked as the boot country
REGREV="${REGREV:-0}"
MIN_FW="7.45.265"                  # older silently ignores the country (metal-proven)

# Firmware .bin — Cypress cyfmac43455 (7.45.265 standard build preferred).
BIN_SRC=""
# FW_BIN_SRC (optional) wins: tools/ci/stage-firmware.sh passes the sha256-pinned blob it extracted
# from the RPi firmware-nonfree .deb, so CI / fresh checkouts stage the SAME bytes as a dev box.
for c in ${FW_BIN_SRC:+"$FW_BIN_SRC"} \
         /lib/firmware/cypress/cyfmac43455-sdio-standard.bin \
         /lib/firmware/cypress/cyfmac43455-sdio.bin \
         /lib/firmware/cypress/cyfmac43455-sdio.bin.zst \
         /lib/firmware/brcm/brcmfmac43455-sdio.bin \
         "$HERE/../drivers/firmware/brcm-firmware-rpt/brcmfmac43455-sdio.bin"; do
  [ -e "$c" ] && { BIN_SRC="$c"; break; }
done
[ -n "$BIN_SRC" ] || { echo "ABORT: cyw43455 firmware .bin not found (install linux-firmware / firmware-cypress)"; exit 1; }
case "$BIN_SRC" in
  *.zst) zstd -f -dc "$BIN_SRC" > "$OUT/cyw43455-sdio.bin" ;;
  *)     cp -f "$BIN_SRC" "$OUT/cyw43455-sdio.bin" ;;
esac

# Gate on firmware version — an older blob makes the regdomain a silent no-op.
FWVER="$(strings "$OUT/cyw43455-sdio.bin" | grep -oE 'Version: 7\.45\.[0-9]+' | head -1 | grep -oE '7\.45\.[0-9]+' || true)"
if [ -z "$FWVER" ]; then
  echo "WARN: could not read firmware version from $BIN_SRC — cannot verify >= $MIN_FW"
elif [ "$(printf '%s\n%s\n' "$MIN_FW" "$FWVER" | sort -V | head -1)" != "$MIN_FW" ]; then
  echo "ABORT: firmware $FWVER < $MIN_FW — it SILENTLY IGNORES the country (regdomain would stay world/99)."
  echo "       Fetch firmware-brcm80211_20260519+ .deb (7.45.265) — see the header of this script."
  exit 1
else
  echo "== firmware $FWVER OK (>= $MIN_FW — honors the country iovar)"
fi

# CLM blob (must contain $REGDOMAIN) + CM5 NVRAM (RF calibration; CM5 board variant).
CLM="$HERE/../drivers/firmware/brcm-firmware-rpt/brcmfmac43455-sdio.clm_blob"
[ -e "$CLM" ] || CLM=/lib/firmware/cypress/cyfmac43455-sdio.clm_blob
[ -e "$CLM" ] || CLM=/lib/firmware/brcm/brcmfmac43455-sdio.clm_blob
[ -e "$CLM.zst" ] && zstd -f -dc "$CLM.zst" > "$OUT/cyw43455-sdio.clm_blob" || cp -f "$CLM" "$OUT/cyw43455-sdio.clm_blob"
NV="$HERE/../drivers/firmware/brcm-firmware-rpt/brcmfmac43455-sdio.raspberrypi,5-compute-module.txt"
[ -e "$NV" ] || NV=/lib/firmware/brcm/brcmfmac43455-sdio.raspberrypi,5-compute-module.txt
cp -f "$NV" "$OUT/cyw43455-sdio-cm5.nvram.txt"

# Bake the regdomain into the NVRAM (idempotent): strip any existing ccode/regrev,
# then append ours. On HEQK's verbatim loader this is the firmware boot country.
sed -i -E '/^[[:space:]]*(ccode|regrev)=/d' "$OUT/cyw43455-sdio-cm5.nvram.txt"
{ echo ""; echo "# HEQK regdomain (staged by stage-wifi-firmware.sh) — boot country"; \
  echo "ccode=${REGDOMAIN}"; echo "regrev=${REGREV}"; } >> "$OUT/cyw43455-sdio-cm5.nvram.txt"
echo "== baked regdomain ccode=${REGDOMAIN} regrev=${REGREV} into NVRAM"

echo "== staged:"; ls -la "$OUT"
echo "== now build P10: cargo build -p kernel --features hboot --release"
