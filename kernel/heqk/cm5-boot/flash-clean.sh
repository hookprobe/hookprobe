#!/usr/bin/env bash
# flash-clean.sh — ZERO-LINUX CM5 flash: archive the Linux reference to the HOST,
# then write a boot partition that contains ONLY heqk artifacts.
#
# Difference from flash-now.sh: that script only ADDS heqk files and leaves every
# Linux file in place (kernels, initramfs, dtbs, overlays, the config.txt backup) —
# ~102 MB of Linux boot artifacts stay resident, plus the whole Debian rootfs on
# part2. This script removes them from the BOARD, having first copied them to the
# host so they remain available as a working reference.
#
# ORDER IS DELIBERATE — archive, verify the archive, THEN destroy. Nothing is
# removed from the eMMC until its copy on the host has been read back.
#
# ── Recovery, if heqk does not boot ──────────────────────────────────────────────
# The CM5's boot firmware lives in SPI EEPROM, NOT on the FAT partition, so wiping
# part1 cannot brick the board: rpiboot always re-enumerates the eMMC.
#   1. Fit the nRPIBOOT jumper, power-cycle.
#   2. sudo ./flash-clean.sh --restore <archive-dir>     # puts Linux back
# The archive written by this script is exactly what --restore consumes.
#
# ⚠️ This removes the one-rename Linux revert path FROM THE DEVICE. Until the M1
# gate is green on metal (cm5 W^X executes on silicon for the FIRST time here), the
# fallback is an rpiboot cycle + --restore, not a config.txt rename. That is a
# deliberate operator choice: a genuinely zero-Linux board for the first metal test.
#
# Usage:
#   sudo ./flash-clean.sh                    # keep the ONE .dtb (default; eth1 works)
#   sudo ./flash-clean.sh --no-dtb           # TRUE zero-Linux; costs RTL8111 training
#   sudo ./flash-clean.sh --with-rootfs      # also image part2 (Debian rootfs, ~GB)
#   sudo ./flash-clean.sh --restore <dir>    # put the archived Linux back
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
USBBOOT="$HERE/../tools/usbboot"
ARCHIVE_ROOT="${HEQK_ARCHIVE_ROOT:-$HOME/heqk-linux-reference}"

KEEP_DTB=1
WITH_ROOTFS=0
RESTORE_DIR=""
while [ $# -gt 0 ]; do
  case "$1" in
    --no-dtb)      KEEP_DTB=0 ;;
    --with-rootfs) WITH_ROOTFS=1 ;;
    --restore)     RESTORE_DIR="${2:-}"; shift ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
  shift
done

[ "$(id -u)" = 0 ] || { echo "ABORT: run with sudo." >&2; exit 1; }

# ── Bring the eMMC up as a USB mass-storage device ──────────────────────────────
echo "== rpiboot: loading mass-storage gadget (BCM2712)..."
"$USBBOOT/rpiboot" -d "$USBBOOT/mass-storage-gadget64"

echo "== waiting for the eMMC to enumerate as a USB mass-storage disk..."
P1=""
for _ in $(seq 1 30); do
  # Same strict glob as flash-now.sh: ONLY a disk whose ID says Raspberry Pi.
  # Never the host's disks.
  P1="$(ls /dev/disk/by-id/usb-*Raspberry_Pi*-part1 /dev/disk/by-id/usb-RPi*MSD*-part1 2>/dev/null | head -1 || true)"
  [ -n "$P1" ] && break
  sleep 1
done
[ -n "$P1" ] || { echo "ABORT: no RPi mass-storage partition appeared in 30s. lsblk:"; lsblk -o NAME,SIZE,MODEL,TRAN; exit 1; }
D1="$(readlink -f "$P1")"
P2="${P1%-part1}-part2"; D2=""
[ -e "$P2" ] && D2="$(readlink -f "$P2")"
echo "== eMMC boot partition: $P1 -> $D1"
[ -n "$D2" ] && echo "== eMMC root partition: $P2 -> $D2"
lsblk -o NAME,SIZE,MODEL,TRAN "$(echo "$D1" | sed 's/[0-9]*$//')"

MNT="$(mktemp -d)"
cleanup() { mountpoint -q "$MNT" && umount "$MNT" || true; rmdir "$MNT" 2>/dev/null || true; }
trap cleanup EXIT

# ── RESTORE mode ────────────────────────────────────────────────────────────────
if [ -n "$RESTORE_DIR" ]; then
  [ -f "$RESTORE_DIR/bootpart.tar" ] || { echo "ABORT: $RESTORE_DIR/bootpart.tar missing" >&2; exit 1; }
  echo "== RESTORE: repopulating the boot partition from $RESTORE_DIR"
  mount "$D1" "$MNT"
  find "$MNT" -mindepth 1 -maxdepth 1 -exec rm -rf {} +
  tar -xf "$RESTORE_DIR/bootpart.tar" -C "$MNT"
  # The archived tree carries config.txt.heqk-backup (the pre-heqk Linux config);
  # promote it back so the board boots Linux again.
  if [ -f "$MNT/config.txt.heqk-backup" ]; then
    cp -f "$MNT/config.txt.heqk-backup" "$MNT/config.txt"
    echo "   promoted config.txt.heqk-backup -> config.txt (Linux boots)"
  elif [ -f "$MNT/config.txt.linux" ]; then
    cp -f "$MNT/config.txt.linux" "$MNT/config.txt"
    echo "   promoted config.txt.linux -> config.txt (Linux boots)"
  fi
  sync; umount "$MNT"
  echo "== RESTORE DONE. Remove the nRPIBOOT jumper and power-cycle."
  exit 0
fi

# ── 1. ARCHIVE FIRST (the 'reference to learn from', and the recovery path) ─────
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
ARCH="$ARCHIVE_ROOT/$STAMP"
mkdir -p "$ARCH"
echo "== archiving the Linux reference -> $ARCH"

mount "$D1" "$MNT"
echo "== boot partition currently holds:"
ls -la "$MNT" | sed 's/^/     /'
du -sh "$MNT" | sed 's/^/     total: /'

tar -cf "$ARCH/bootpart.tar" -C "$MNT" .
# Read the archive back before anything is destroyed — an unverified backup is not
# a backup. `tar -tf` walks the whole archive and fails loudly on a truncated write.
tar -tf "$ARCH/bootpart.tar" >"$ARCH/bootpart.list" 2>/dev/null \
  || { echo "ABORT: boot-partition archive did not read back — NOTHING removed." >&2; exit 1; }
echo "   bootpart.tar OK ($(wc -l <"$ARCH/bootpart.list") entries, $(du -h "$ARCH/bootpart.tar" | cut -f1))"

# Record the partition table + the exact DTB the current config references, so the
# layout is reproducible from the archive alone.
sfdisk -d "$(echo "$D1" | sed 's/[0-9]*$//')" >"$ARCH/partition-table.sfdisk" 2>/dev/null || true
DTB_NAME="$(grep -hoP '^\s*device_tree=\K\S+' "$MNT/config.txt" 2>/dev/null | head -1 || true)"
[ -n "$DTB_NAME" ] && echo "$DTB_NAME" >"$ARCH/referenced-dtb.txt"
umount "$MNT"

if [ "$WITH_ROOTFS" = 1 ] && [ -n "$D2" ]; then
  echo "== imaging the Debian rootfs (part2) — this is GB-scale, be patient"
  dd if="$D2" bs=4M conv=sparse status=progress | gzip -1 >"$ARCH/rootfs.img.gz"
  echo "   rootfs.img.gz $(du -h "$ARCH/rootfs.img.gz" | cut -f1)"
else
  [ -n "$D2" ] && echo "== NOTE: part2 (Debian rootfs) left INTACT on the eMMC (pass --with-rootfs to image it)."
fi

# ── 2. WIPE the boot partition, then write ONLY heqk ────────────────────────────
echo "== wiping the boot partition (firmware lives in SPI EEPROM, not here)"
mount "$D1" "$MNT"
find "$MNT" -mindepth 1 -maxdepth 1 -exec rm -rf {} +

if [ "$KEEP_DTB" = 1 ]; then
  cp -f "$HERE/config.txt" "$MNT/config.txt"
  if [ -n "$DTB_NAME" ]; then
    # Restore exactly ONE Linux artifact: the .dtb config.txt names. heqk never
    # parses it, but the firmware needs it to apply the dtparam= PCIe lines that
    # train RC1 for the RTL8111 (eth1).
    if tar -xf "$ARCH/bootpart.tar" -C "$MNT" "./$DTB_NAME" 2>/dev/null; then
      echo "   kept ONE Linux artifact: $DTB_NAME (firmware needs it for dtparam=)"
    else
      echo "   WARN: $DTB_NAME not found in the archive — dtparam= lines will not apply" >&2
    fi
  fi
else
  cp -f "$HERE/config-nolinux.txt" "$MNT/config.txt"
  echo "   TRUE zero-Linux: no .dtb, no dtparam= (RTL8111/eth1 will NOT be trained)"
fi

cp -f "$HERE/heqk8.img" "$MNT/heqk8.img"
[ -f "$HERE/heqk8-b.img" ] && cp -f "$HERE/heqk8-b.img" "$MNT/heqk8-b.img"
[ -f "$HERE/tryboot.txt" ] && cp -f "$HERE/tryboot.txt" "$MNT/tryboot.txt"
sync

echo "== boot partition now contains ONLY:"
ls -la "$MNT" | sed 's/^/     /'
echo "== kernel line:"; grep -E 'kernel=|pciex4|device_tree' "$MNT/config.txt" | sed 's/^/     /'
LEFTOVER="$(find "$MNT" -maxdepth 1 -type f \( -name 'kernel*.img' -o -name 'initramfs*' -o -name 'cmdline.txt' \) | grep -v heqk8 || true)"
[ -z "$LEFTOVER" ] && echo "     (no Linux kernel/initramfs/cmdline present)" || { echo "WARN: Linux artifacts remain:"; echo "$LEFTOVER"; }
umount "$MNT"

echo ""
echo "== DONE. Linux reference archived at: $ARCH"
echo "   Flip the BOOT switch back to eMMC and power-cycle."
echo "   Watch the FTDI @115200 for: HK2 + the HEQK banner, then [P7b] W^X PASS."
echo "   If it does not boot: nRPIBOOT jumper + sudo $0 --restore $ARCH"
