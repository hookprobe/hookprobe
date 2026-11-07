#!/usr/bin/env bash
# One-shot: rpiboot (mass-storage-gadget64) -> wait for the CM5 eMMC ->
# copy HEQK config.txt + heqk8.img onto the FAT boot partition (backs up
# the existing config.txt). Targets ONLY a USB disk whose ID matches the
# RPi mass-storage gadget — never the host's disks.
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
lsblk -o NAME,SIZE,MODEL,TRAN "$(echo "$DEV" | sed 's/[0-9]*$//')"

MNT="$(mktemp -d)"
mount "$DEV" "$MNT"
echo "== mounted; existing files:"; ls "$MNT" | head
[ -f "$MNT/config.txt" ] && cp -f "$MNT/config.txt" "$MNT/config.txt.heqk-backup" && echo "== backed up config.txt -> config.txt.heqk-backup"
cp -f "$HERE/config.txt" "$MNT/config.txt"
cp -f "$HERE/heqk8.img" "$MNT/heqk8.img"
# A/B: also stage SLOT B (candidate config + image) so future updates need no
# extra rpiboot cycle. tryboot.txt boots heqk8-b.img for one `tryboot` boot.
[ -f "$HERE/tryboot.txt" ]  && cp -f "$HERE/tryboot.txt"  "$MNT/tryboot.txt"
[ -f "$HERE/heqk8-b.img" ]  && cp -f "$HERE/heqk8-b.img"  "$MNT/heqk8-b.img"
sync
echo "== wrote:"; ls -la "$MNT/config.txt" "$MNT/heqk8.img" "$MNT/heqk8-b.img" 2>/dev/null
echo "== verify kernel line:"; grep -E 'kernel=|pciex4' "$MNT/config.txt"
umount "$MNT"; rmdir "$MNT"
echo "== DONE. Flip the BOOT switch back to eMMC and power-cycle."
echo "   Watch the FTDI @115200 for: HK2 + the HEQK banner."
echo "   Restore Linux later: rename config.txt.heqk-backup -> config.txt."
