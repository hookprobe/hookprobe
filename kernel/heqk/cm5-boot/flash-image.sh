#!/usr/bin/env bash
# flash-image.sh — write a WHOLE factory disk image (builder/make-cm5-heqk-disk.sh) to the CM5 eMMC.
# OPERATOR-ONLY (Red): this REPLACES the entire eMMC — partition table, boot partition, any
# remaining Linux recovery partitions. Interim path until the browser flasher (WebUSB rpiboot +
# heqk-flasher) exists; note the mass-storage gadget below briefly boots a Linux initramfs ON THE
# CM5 for the duration of the flash (the browser flasher removes that).
#
#   sudo kernel/heqk/cm5-boot/flash-image.sh <image.img> [--backup <file>] [--confirm-erase]
#
# --confirm-erase  non-interactive: the explicit flag replaces typing FLASH (for runs where stdin
#                  is not a terminal). If the CM5 is already in rpiboot mode (0a5c:2712 on USB) the
#                  "fit the jumper" prompt is skipped.
#
# Guards: only a Raspberry Pi USB mass-storage device (by-id) is accepted — never a host disk; the
# device + size are shown and you must type FLASH; the written image is read back and its sha256
# compared. --backup copies the CURRENT eMMC to <file> first (recommended: the old layout is gone
# after this).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
IMG="${1:-}"; BACKUP=""; CONFIRM=0
shift || true
while [ $# -gt 0 ]; do
  case "$1" in
    --backup) BACKUP="${2:-}"; shift ;;
    --confirm-erase) CONFIRM=1 ;;
    *) echo "unknown option $1"; exit 2 ;;
  esac
  shift
done
[ -f "$IMG" ] || { echo "usage: sudo $0 <image.img> [--backup <file>]"; exit 2; }
[ "$(id -u)" = 0 ] || { echo "run with sudo (raw block-device write)"; exit 2; }
SHA_IMG="$(sha256sum "$IMG" | cut -d' ' -f1)"
if [ -f "$IMG.sha256" ] && ! grep -q "$SHA_IMG" "$IMG.sha256"; then
  echo "ABORT: $IMG does not match its .sha256 — rebuild it"; exit 1
fi

USBBOOT="$HERE/../tools/usbboot"
# The VENDORED rpiboot first: distro builds can predate BCM2712 and cannot parse the gadget's
# bootfiles.bin ("No 'bootcode' files found").
if [ -x "$USBBOOT/rpiboot" ]; then RPIBOOT="$USBBOOT/rpiboot"; else RPIBOOT="$(command -v rpiboot)"; fi
if lsusb -d 0a5c:2712 >/dev/null 2>&1; then
  echo "== 1/4 rpiboot: CM5 already in USB-boot mode (0a5c:2712)"
else
  echo "== 1/4 rpiboot: fit the nRPIBOOT jumper (EMMC-DISABLE), power-cycle the CM5, then press Enter"
  read -r _
fi
"$RPIBOOT" -d "$USBBOOT/mass-storage-gadget64"

echo "== 2/4 waiting for the CM5 eMMC to appear as a USB disk..."
DEV=""
for _ in $(seq 1 30); do
  DEV="$(ls /dev/disk/by-id/usb-*Raspberry_Pi* /dev/disk/by-id/usb-RPi*MSD* 2>/dev/null | grep -v -- '-part[0-9]*$' | head -1 || true)"
  [ -n "$DEV" ] && break; sleep 1
done
[ -n "$DEV" ] || { echo "ABORT: no Raspberry Pi mass-storage disk appeared. lsblk:"; lsblk -o NAME,SIZE,MODEL,TRAN; exit 1; }
REAL="$(readlink -f "$DEV")"
SIZE="$(blockdev --getsize64 "$REAL")"
IMGSZ="$(stat -c %s "$IMG")"
[ "$IMGSZ" -le "$SIZE" ] || { echo "ABORT: image ($IMGSZ B) larger than the eMMC ($SIZE B)"; exit 1; }
echo "   target : $DEV -> $REAL ($((SIZE / 1024 / 1024)) MiB, $(lsblk -dno MODEL,TRAN "$REAL" | xargs))"
echo "   image  : $IMG ($((IMGSZ / 1024 / 1024)) MiB, sha256 $SHA_IMG)"
for m in $(lsblk -nro MOUNTPOINT "$REAL" | grep -v '^$' || true); do umount "$m"; done

if [ -n "$BACKUP" ]; then
  echo "== backup: copying the current eMMC to $BACKUP (this takes a while)..."
  dd if="$REAL" of="$BACKUP" bs=4M status=progress conv=fsync
fi

echo "== 3/4 THIS ERASES THE WHOLE eMMC on $REAL."
if [ "$CONFIRM" != 1 ]; then
  echo "   Type FLASH to continue:"
  read -r ans
  [ "$ans" = FLASH ] || { echo "aborted, nothing written"; exit 1; }
else
  echo "   (--confirm-erase given)"
fi
dd if="$IMG" of="$REAL" bs=4M status=progress conv=fsync
sync

echo "== 4/4 verify: reading back $IMGSZ bytes..."
SHA_DEV="$(head -c "$IMGSZ" "$REAL" | sha256sum | cut -d' ' -f1)"
if [ "$SHA_DEV" = "$SHA_IMG" ]; then
  echo "VERIFIED: eMMC content == image (sha256 $SHA_IMG)"
  echo "NEXT: remove the nRPIBOOT jumper, start the serial capture, then power-cycle the CM5."
else
  echo "VERIFY FAILED: device sha256 $SHA_DEV != image $SHA_IMG — do NOT boot; reflash"; exit 1
fi
