#!/usr/bin/env bash
# Restore the ORIGINAL Linux boot on the CM5 eMMC: rpiboot the board as a USB
# mass-storage disk, then rename config.txt.heqk-backup -> config.txt (undoing
# the HEQK swap). Non-destructive: the Linux rootfs on parts 2/3 was never
# touched; only the FAT boot partition's config.txt was swapped. Leaves the HEQK
# artifacts in place (config.txt.heqk-backup is re-created from the current
# config.txt so you can flip back to HEQK later with flash-now.sh).
#
# Purpose: boot Linux to reverse-engineer the RP1 GEM RX descriptor (the "w1=0"
# question) against the working mainline macb/rp1-gem driver on this exact silicon.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
USBBOOT="$HERE/../tools/usbboot"

[ "$(id -u)" = 0 ] || { echo "ABORT: run with sudo." >&2; exit 1; }

echo "== rpiboot: loading mass-storage gadget (BCM2712)..."
"$USBBOOT/rpiboot" -d "$USBBOOT/mass-storage-gadget64"

echo "== waiting for the eMMC to enumerate as a USB mass-storage disk..."
PART=""
for _ in $(seq 1 30); do
  PART="$(ls /dev/disk/by-id/usb-*Raspberry_Pi*-part1 /dev/disk/by-id/usb-RPi*MSD*-part1 2>/dev/null | head -1 || true)"
  [ -n "$PART" ] && break
  sleep 1
done
[ -n "$PART" ] || { echo "ABORT: no RPi mass-storage partition appeared in 30s. lsblk:"; lsblk -o NAME,SIZE,MODEL,TRAN; exit 1; }
DEV="$(readlink -f "$PART")"
echo "== eMMC boot partition: $PART -> $DEV"

MNT="$(mktemp -d)"
mount "$DEV" "$MNT"
echo "== mounted; files:"; ls "$MNT" | head -20
if [ ! -f "$MNT/config.txt.heqk-backup" ]; then
  echo "ABORT: no config.txt.heqk-backup found — nothing to restore." >&2
  umount "$MNT"; rmdir "$MNT"; exit 1
fi
# Keep a HEQK config copy so we can flip back later without rebuilding.
[ -f "$MNT/config.txt" ] && cp -f "$MNT/config.txt" "$MNT/config.txt.heqk"
cp -f "$MNT/config.txt.heqk-backup" "$MNT/config.txt"
sync
echo "== restored ORIGINAL Linux config.txt:"; grep -E 'kernel=|pciex4|arm_64bit|auto_initramfs' "$MNT/config.txt" | head
umount "$MNT"; rmdir "$MNT"
echo "== DONE. Flip the BOOT switch back to eMMC and power-cycle -> Linux boots."
echo "   To go back to HEQK later: sudo cm5-boot/flash-now.sh (or restore config.txt.heqk)."
