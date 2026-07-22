#!/usr/bin/env bash
# Install the HEQK Linux-observe harness onto the CM5 eMMC (exposed via rpiboot
# mass-storage-gadget). Restores a Linux boot (edge kernel) + installs a boot-time
# RC1 register dumper, so Linux's pcie-brcmstb trains the external PCIe and we can
# read the trained register state to mirror it in bare-metal rc1_train().
#
#   sudo ./install.sh <eMMC-disk, e.g. /dev/sda>
# Then: power-cycle the CM5 to eMMC (Linux boots, dumps to /rc1dump.txt on the
# rootfs and to the FTDI console), and afterwards run ./readback.sh <disk>.
set -euo pipefail
DEV="${1:?usage: sudo ./install.sh <eMMC block device>}"
HERE="$(cd "$(dirname "$0")" && pwd)"
[ "$(id -u)" = 0 ] || { echo "run with sudo" >&2; exit 1; }
case "$(readlink -f "$DEV")" in *nvme*) echo "refusing host disk" >&2; exit 1;; esac

MB="$(mktemp -d)"; MR="$(mktemp -d)"
mount "${DEV}1" "$MB"; mount "${DEV}2" "$MR"
trap 'umount "$MB" "$MR" 2>/dev/null; rmdir "$MB" "$MR"' EXIT

# 1. Preserve the HEQK config, swap in the Linux boot config.
[ -f "$MB/config.txt" ] && cp -f "$MB/config.txt" "$MB/config.txt.heqk-live"
cp -f "$HERE/config-linux.txt" "$MB/config.txt"
echo "== config.txt -> Linux (edge kernel); HEQK saved as config.txt.heqk-live"

# 2. Relax /dev/mem so the dumper can read the RC1 controller MMIO.
if ! grep -q 'iomem=relaxed' "$MB/cmdline.txt"; then
  sed -i 's/$/ iomem=relaxed/' "$MB/cmdline.txt"
fi
echo "== cmdline: $(cat "$MB/cmdline.txt")"

# 3. Install the dumper + a oneshot service that runs it after boot.
cp -f "$HERE/rc1-dump.py" "$MR/rc1-dump.py"; chmod +x "$MR/rc1-dump.py"
cp -f "$HERE/rc1-observe.service" "$MR/etc/systemd/system/rc1-observe.service"
mkdir -p "$MR/etc/systemd/system/multi-user.target.wants"
ln -sf ../rc1-observe.service \
  "$MR/etc/systemd/system/multi-user.target.wants/rc1-observe.service"
echo "== installed /rc1-dump.py + rc1-observe.service (enabled)"

sync
echo "== DONE. Power-cycle the CM5 to eMMC; watch the FTDI for the pcie-brcmstb"
echo "   link-up + the '===== HEQK RC1 OBSERVE =====' dump, then run ./readback.sh $DEV"
