#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# m5-spi-flash — write the first-stage loader (u-boot-rockchip-spi.bin from tools/build/m5-firmware-build.sh)
# to the NanoPi M5's 16 MiB SPI-NOR through the Rockchip boot ROM (maskrom), then read it back.
# This is the RECOVERY path; normal loader updates go through U-Boot itself (runbook §6).
#
#   tools/diagnostics/m5-spi-flash.sh [--fw DIR] [--relay-dev DEV] [--in-maskrom] [--dry-run]
#
# Needs: the OTG port (top USB-A) cabled to the host, the MASK relay wired (or --in-maskrom after
# entering maskrom by hand: hold MASK, power on, release after ~3 s), the BOOT switch on FSPI for the
# boot after the flash. rkdeveloptool is the one built by m5-firmware-build.sh (no root with the udev rule).
set -u -o pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
FW="$HOME/heqk-m5-bench/fw"
RDEV="${M5_RELAY:-}"
INMASK=0 DRY=0
while [ $# -gt 0 ]; do
  case "$1" in
    --fw) FW="$2"; shift ;;
    --relay-dev) RDEV="$2"; shift ;;
    --in-maskrom) INMASK=1 ;;
    --dry-run) DRY=1 ;;
    *) echo "unknown argument $1" >&2; exit 2 ;;
  esac
  shift
done
RKD="$FW/rkdeveloptool"
SPI="$FW/u-boot-rockchip-spi.bin"
PLUG="$FW/rk3576_usbplug_fspi1_v1.03.bin"
for f in "$RKD" "$SPI" "$PLUG"; do [ -e "$f" ] || { echo "missing $f (run tools/build/m5-firmware-build.sh)" >&2; exit 1; }; done
size=$(stat -c %s "$SPI")
[ "$size" -le $((16 * 1024 * 1024)) ] || { echo "$SPI is $size B, larger than the 16 MiB SPI-NOR" >&2; exit 1; }
grep -q "u-boot-rockchip-spi.bin" "$FW/MANIFEST.txt" 2>/dev/null && \
  (cd "$FW" && grep "u-boot-rockchip-spi.bin" MANIFEST.txt | sha256sum -c --quiet) || { echo "$SPI does not match $FW/MANIFEST.txt" >&2; exit 1; }
sectors=$(( (size + 511) / 512 ))
run() { echo "+ $*"; [ "$DRY" = 1 ] || "$@"; }

echo "== m5-spi-flash $(date -Is) $(sha256sum "$SPI" | cut -c1-16)… ($size B, $sectors sectors)"
if [ "$INMASK" = 0 ]; then
  if [ "$DRY" = 1 ]; then python3 "$HERE/m5-relay.py" --dry-run maskrom
  else python3 "$HERE/m5-relay.py" --dev "$RDEV" maskrom || exit 1; fi
fi
[ "$DRY" = 1 ] || "$RKD" ld | grep -qi maskrom || { echo "rkdeveloptool sees no Maskrom device" >&2; "$RKD" ld; exit 1; }
run "$RKD" db "$PLUG"                 # download the FSPI1 usbplug stub into SRAM/DRAM
sleep 1
run "$RKD" wl 0 "$SPI"                # write at sector 0 of the SPI-NOR (idbloader @0x8000, itb @0x60000 inside)
TMP=$(mktemp)
trap 'rm -f "$TMP"' EXIT
run "$RKD" rl 0 "$sectors" "$TMP"     # read back and compare
if [ "$DRY" = 0 ]; then
  cmp -n "$size" "$SPI" "$TMP" && echo "read-back OK" || { echo "READ-BACK MISMATCH — do not reboot into it; flash again" >&2; exit 1; }
fi
run "$RKD" rd                          # reset: boots the new loader if the BOOT switch is on FSPI
echo "done. Expect U-Boot $(grep -m1 '^u-boot' "$FW/MANIFEST.txt" 2>/dev/null) on the console."
