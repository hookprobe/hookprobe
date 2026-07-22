#!/usr/bin/env bash
# Read back the RC1 register dump after the CM5 booted Linux, and restore the
# HEQK boot config. Run with the CM5 in rpiboot (eMMC exposed).
#   sudo ./readback.sh <eMMC-disk, e.g. /dev/sda>
set -euo pipefail
DEV="${1:?usage: sudo ./readback.sh <eMMC block device>}"
[ "$(id -u)" = 0 ] || { echo "run with sudo" >&2; exit 1; }
MB="$(mktemp -d)"; MR="$(mktemp -d)"
mount "${DEV}1" "$MB"; mount "${DEV}2" "$MR"
trap 'umount "$MB" "$MR" 2>/dev/null; rmdir "$MB" "$MR"' EXIT

echo "===== /rc1dump.txt ====="
cat "$MR/rc1dump.txt" 2>/dev/null || echo "(no dump — did Linux boot + the service run?)"

# Restore the HEQK boot config so the next power-cycle boots HEQK again.
if [ -f "$MB/config.txt.heqk-live" ]; then
  cp -f "$MB/config.txt.heqk-live" "$MB/config.txt"
  echo "== restored HEQK config.txt"
fi
sync
