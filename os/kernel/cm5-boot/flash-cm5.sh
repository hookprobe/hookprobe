#!/usr/bin/env bash
# Flash HEQK Core's boot files onto a CM5 eMMC exposed via rpiboot.
#
# Prereq: CM5 in rpiboot/USB-boot mode, USB cable to this host; `rpiboot` has
# already run and the eMMC now shows as a block device. This script mounts the
# FAT boot partition (partition 1), backs up its config.txt, and copies HEQK's
# config.txt + kernel8.img onto it. Non-destructive to other files.
#
#   sudo ./flash-cm5.sh /dev/sdX     (pass the eMMC device; partition 1 = boot)
set -euo pipefail
DEV="${1:?usage: sudo ./flash-cm5.sh <eMMC block device, e.g. /dev/sdb>}"
HERE="$(cd "$(dirname "$0")" && pwd)"
BOOTP="${DEV}1"   # first partition = FAT boot partition

[ "$(id -u)" = 0 ] || { echo "ABORT: run with sudo." >&2; exit 1; }
[ -b "$BOOTP" ] || { echo "ABORT: $BOOTP is not a block device (is the CM5 in rpiboot? did rpiboot run?)." >&2; exit 1; }
# Safety: never touch the host's own disks.
case "$(readlink -f "$DEV")" in
  *nvme*|*/dev/sda) echo "ABORT: $DEV looks like a host disk — refusing." >&2; exit 1;;
esac

MNT="$(mktemp -d)"
mount "$BOOTP" "$MNT"
echo "== boot partition mounted at $MNT; existing files:"; ls "$MNT" | head
# Back up the existing config.txt (so the prior OS can be restored).
[ -f "$MNT/config.txt" ] && cp -f "$MNT/config.txt" "$MNT/config.txt.heqk-backup" && echo "== backed up config.txt -> config.txt.heqk-backup"
cp -f "$HERE/config.txt" "$MNT/config.txt"
cp -f "$HERE/heqk8.img" "$MNT/heqk8.img"   # HEQK-specific name — never clobbers an existing kernel
sync
echo "== wrote HEQK config.txt + heqk8.img"; ls -la "$MNT/config.txt" "$MNT/heqk8.img"
umount "$MNT"; rmdir "$MNT"
echo "== DONE. Power-cycle the CM5 out of rpiboot; watch the FTDI serial @115200."
echo "   To restore the previous OS: rename config.txt.heqk-backup -> config.txt."
