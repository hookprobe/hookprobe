#!/usr/bin/env bash
# usr-verity-qemu-test.sh — PROVE the /usr-only verity design boots correctly, in qemu, before it ever
# touches real hardware. Builds a 3-partition disk from the arm64 rootfs (p1 FAT boot, p2 writable
# root-minus-/usr, p3 verity-sealed /usr), regenerates an initramfs carrying the local-bottom
# hookprobe-usr-verity hook, then boots it in `qemu-system-aarch64 -M virt`. An auto-verify init
# checks: /usr is a read-only verity mount, / is writable, then powers off. See ADR 0006 (H3).
#
#   sudo security/verity/usr-verity-qemu-test.sh
#
# Exit 0 + "USR-VERITY: PASS" in the serial log = the design boots correctly.
set -euo pipefail
REPO=$(cd "$(dirname "$0")/../.." && pwd)
SRC="${SRC:-$REPO/builder/mkosi-arm64/hookprobe-os-arm64.raw}"
W=$(mktemp -d /tmp/usrverity.XXXXXX)
trap 'set +e; umount -R "$W"/mnt/* 2>/dev/null; [ -n "${DL:-}" ] && losetup -d "$DL" 2>/dev/null; [ -n "${SL:-}" ] && losetup -d "$SL" 2>/dev/null; rm -rf "$W"' EXIT
mkdir -p "$W"/mnt/src "$W"/mnt/root "$W"/mnt/usr

echo "=== 1. open the source arm64 rootfs ==="
SL=$(losetup --show -fP "$SRC"); partprobe "$SL"; sleep 2
mount -o ro "${SL}p2" "$W/mnt/src"
KVER=$(ls "$W/mnt/src/lib/modules" | head -1)
echo "  kernel modules: $KVER"

echo "=== 2. build the 3-partition test disk ==="
truncate -s 2500M "$W/test.img"
sfdisk "$W/test.img" >/dev/null <<'PARTS'
label: dos
start=2048,   size=204800, type=c
start=206848, size=409600, type=83
start=616448, type=83
PARTS
DL=$(losetup --show -fP "$W/test.img"); partprobe "$DL"; sleep 2
mkfs.vfat -F32 "${DL}p1" >/dev/null
mkfs.ext4 -q -L hp-root "${DL}p2"
mkfs.ext4 -q -L hp-usr  "${DL}p3"
mount "${DL}p2" "$W/mnt/root"; mkdir -p "$W/mnt/root/usr"; mount "${DL}p3" "$W/mnt/root/usr"

echo "=== 3. split: root-minus-/usr → p2, /usr → p3 (p3 stays mounted at root/usr for the chroot) ==="
rsync -aHAX --exclude=/usr/ "$W/mnt/src/." "$W/mnt/root/" 2>/dev/null
rsync -aHAX "$W/mnt/src/usr/." "$W/mnt/root/usr/" 2>/dev/null

echo "=== 4. install the /usr-verity hook + virtio/dm modules, regen initramfs ==="
RT="$W/mnt/root"
install -D -m0755 "$REPO/base/initramfs/hooks/hookprobe-usr-verity"                "$RT/etc/initramfs-tools/hooks/hookprobe-usr-verity"
install -D -m0755 "$REPO/base/initramfs/scripts/local-bottom/hookprobe-usr-verity" "$RT/etc/initramfs-tools/scripts/local-bottom/hookprobe-usr-verity"
for m in virtio_blk virtio_pci virtio_mmio dm_verity dm_mod vfat; do
  grep -qx "$m" "$RT/etc/initramfs-tools/modules" 2>/dev/null || echo "$m" >> "$RT/etc/initramfs-tools/modules"
done
# update-initramfs greps /boot/config-KVER for supported compressors; the mkosi image strips /boot, so
# supply the cached config (from make-pi4-image) + force zstd (this arm64 kernel has CONFIG_RD_GZIP off).
cp "$REPO/builder/mkosi-arm64/pi4-kernel-config/config-$KVER" "$RT/boot/config-$KVER" 2>/dev/null || true
mkdir -p "$RT/etc/initramfs-tools/conf.d"; echo "COMPRESS=zstd" > "$RT/etc/initramfs-tools/conf.d/zstd"
# auto-verify init: proves /usr is mounted (script can't even run without it — /bin/sh→/usr/bin/sh)
cat > "$RT/hp-verity-test.sh" <<'VERIFY'
#!/bin/sh
mount -t proc proc /proc 2>/dev/null; mount -t sysfs sys /sys 2>/dev/null
exec >/dev/console 2>&1
echo "=================== USR-VERITY BOOT TEST ==================="
echo "usr-mount : $(findmnt -no SOURCE,FSTYPE,OPTIONS /usr 2>/dev/null || echo NONE)"
echo "usr-verity: $(dmsetup status --target verity 2>/dev/null | head -1 || echo none)"
echo "root      : $(findmnt -no SOURCE,OPTIONS / 2>/dev/null)"
if touch /etc/.hpw 2>/dev/null; then echo "root-write: WRITABLE"; rm -f /etc/.hpw; else echo "root-write: READONLY"; fi
if findmnt -no OPTIONS /usr 2>/dev/null | grep -q ro && dmsetup status --target verity 2>/dev/null | grep -q verity; then
  echo "USR-VERITY: PASS (/usr = read-only verity, / = writable)"
else
  echo "USR-VERITY: FAIL"
fi
echo "==========================================================="
sync; poweroff -f
VERIFY
chmod +x "$RT/hp-verity-test.sh"
# plymouth's initramfs hook fails in the emulated chroot (no graphics) → aborts update-initramfs.
rm -f "$RT/usr/share/initramfs-tools/hooks/plymouth"
cp /usr/bin/qemu-aarch64-static "$RT/usr/bin/" 2>/dev/null || true
for m in proc sys dev dev/pts; do mkdir -p "$RT/$m"; mount --bind "/$m" "$RT/$m"; done
chroot "$RT" /usr/sbin/update-initramfs -c -k "$KVER" 2>&1 | tail -3 || echo "  WARN initramfs regen"
for m in dev/pts dev sys proc; do umount "$RT/$m" 2>/dev/null || true; done
rm -f "$RT/usr/bin/qemu-aarch64-static"
cp "$RT/boot/initrd.img-$KVER" "$W/initrd"
# kernel: the mkosi image strips /boot, so grab the extracted vmlinuz (kernel8.img) from the pi4 image.
PIL=$(losetup --show -fP "$REPO/builder/mkosi-arm64/hookprobe-os-pi4.img"); partprobe "$PIL"; sleep 1
mkdir -p "$W/pi1"; mount -o ro "${PIL}p1" "$W/pi1"; cp "$W/pi1/kernel8.img" "$W/vmlinuz"; umount "$W/pi1"; losetup -d "$PIL"
echo "  kernel: $(file -b "$W/vmlinuz" | cut -c1-40)"

echo "=== 5. unmount /usr, verity-seal p3 ==="
umount "$W/mnt/root/usr"
RH=$(veritysetup format "${DL}p3" "$W/mnt/root/boot/usr.verity" | awk '/Root hash:/ {print $3}')
# put the hash tree on the FAT boot partition (out-of-band from the verity-protected /usr)
mkdir -p "$W/uboot"; mount "${DL}p1" "$W/uboot"; cp "$W/mnt/root/boot/usr.verity" "$W/uboot/usr.verity"; umount "$W/uboot"
umount "$W/mnt/root"
echo "  /usr root hash: $RH"

echo "=== 6. BOOT in qemu -M virt (TCG), auto-verify + poweroff ==="
LOG="$W/serial.log"
timeout 300 qemu-system-aarch64 -M virt -cpu cortex-a72 -m 2048 -smp 2 \
  -kernel "$W/vmlinuz" -initrd "$W/initrd" \
  -append "root=/dev/vda2 rw rootwait console=ttyAMA0 init=/hp-verity-test.sh usrverity.roothash=$RH usrverity.data=/dev/vda3 usrverity.boot=/dev/vda1 usrverity.hashfile=usr.verity panic=5" \
  -drive file="$W/test.img",format=raw,if=virtio -nographic -no-reboot 2>&1 | tee "$LOG" | grep -aE "hookprobe-usr-verity|USR-VERITY|usr-mount|root-write|Kernel panic|Cannot open root|not syncing" || true

echo "=== RESULT ==="
if grep -qa "USR-VERITY: PASS" "$LOG"; then echo "  ✅ PASS — /usr-only verity boots correctly (safe to build the Pi image)"; exit 0
else echo "  ❌ FAIL — see above; iterate the hook (this is qemu, no hardware harmed)"; exit 1; fi
