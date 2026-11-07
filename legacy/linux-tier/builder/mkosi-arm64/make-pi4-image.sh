#!/usr/bin/env bash
# *** SUPERSEDED by make-pi-image.sh (ADR 0029 — unified Pi4/CM4/Pi5/CM5 fat-boot image) ***
# Kept for now (single-board slim builds / historical reference), NOT deleted, per ADR 0029 D4.
# New work targets make-pi-image.sh, which produces ONE image booting all four Raspberry Pi
# boards via the Raspberry-Pi-repo dual kernel (linux-image-rpi-v8 + linux-image-rpi-2712) —
# this script's Debian-kernel-only path has no CM5/Pi5 network path (RP1 needs the RPi kernel).
# See docs/adr/0029-unified-pi-fatboot-dual-kernel.md.
#
# make-pi4-image.sh — assemble a REAL Raspberry Pi 4 bootable SD image from the proven arm64
# rootfs, using the Debian-native raspi-firmware boot path (config.txt loads the kernel directly;
# no UEFI/systemd-boot). The rootfs is byte-for-byte the one validated in Gate 3b; only the boot
# substrate differs. Output: a flashable .img (p1 vfat boot + p2 ext4 root).
#
# Pi 4 boot chain this produces:
#   SoC bootloader (SPI EEPROM) → reads p1 vfat → start4.elf + config.txt → loads the arm64
#   kernel (kernel8.img) + bcm2711-rpi-4-b.dtb + initramfs → kernel → systemd → HookProbe chain.
#
# Needs sudo (loop/mkfs/mount). NOT boot-testable here (this qemu has no raspi4b machine) — the
# Pi 4 boot path validates on real hardware (Gate 4/5). This script verifies the boot partition
# is correctly assembled. Firmware blobs come from the Debian-signed raspi-firmware package.
#
#   sudo builder/mkosi-arm64/make-pi4-image.sh [SRC.raw] [OUT.img] [SIZE_GB]
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
SRC=${1:-$HERE/hookprobe-os-arm64.raw}
OUT=${2:-$HERE/hookprobe-os-pi4.img}
SIZE_GB=${3:-2}
# Boot splash toggle (ADR 0006 H1b): HOOKPROBE_SPLASH=1 adds `quiet splash` so Plymouth takes over the
# HDMI framebuffer with the HookProbe appliance theme. Kept OFF by default during bring-up/debug so the
# console stays readable; `plymouth.ignore-serial-consoles` keeps the serial console (ttyAMA0) getting
# messages for remote debug, and ESC toggles Plymouth's detail view. Enable once boot is validated.
SPLASH_ARGS=""
[ "${HOOKPROBE_SPLASH:-0}" = 1 ] && SPLASH_ARGS="quiet splash loglevel=3 vt.global_cursor_default=0 plymouth.ignore-serial-consoles"
KVER=${KVER:-}  # empty ⇒ auto-detect from the built image after the rootfs is mounted. Never hardcode: the Debian 6.1.0-49→-50 point-release bump silently broke the old hardcoded default. Override via KVER=… env.
FWCACHE="$HERE/pi4-firmware-cache"
WORK=$(mktemp -d /tmp/hp-pi4.XXXXXX)
[ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 1; }
[ -f "$SRC" ] || { echo "source image $SRC not found (build the arm64 image first)"; exit 1; }

cleanup() {
  set +e
  # chroot bind mounts (initrd regen) must come off before their parent p2
  for m in dev/pts dev sys proc; do umount "$WORK/p2/$m" 2>/dev/null; done
  for m in "$WORK"/srcboot "$WORK"/srcroot "$WORK"/p1 "$WORK"/p2; do mountpoint -q "$m" && umount "$m"; done
  [ -n "${SRCLOOP:-}" ] && losetup -d "$SRCLOOP" 2>/dev/null
  [ -n "${OUTLOOP:-}" ] && losetup -d "$OUTLOOP" 2>/dev/null
  rm -rf "$WORK"
}
trap cleanup EXIT
mkdir -p "$WORK"/{srcboot,srcroot,p1,p2}

# Wait for a loop device's partition nodes to appear (losetup -fP + partprobe are async; mkfs
# can otherwise race ahead of /dev/loopNpX creation).
wait_parts() { # loopdev
  udevadm settle 2>/dev/null || true
  for _ in $(seq 1 30); do
    [ -b "${1}p1" ] && [ -b "${1}p2" ] && return 0
    partprobe "$1" 2>/dev/null || true; sleep 0.5
  done
  [ -b "${1}p1" ] || { echo "partition nodes for $1 never appeared"; return 1; }
}

# 1. Raspberry Pi GPU firmware blobs (start4.elf/fixup4.dat/bootcode.bin) — from the Debian
#    raspi-firmware package, cached locally so repeat runs are offline. Debian-signed source.
if [ ! -f "$FWCACHE/start4.elf" ]; then
  echo "=== fetching rpi firmware blobs from Debian raspi-firmware (cached → $FWCACHE) ==="
  mkdir -p "$FWCACHE"
  podman run --rm -v "$FWCACHE:/fw:Z" --arch arm64 docker.io/arm64v8/debian:bookworm bash -c '
    echo "deb http://deb.debian.org/debian bookworm non-free-firmware" > /etc/apt/sources.list.d/nf.list
    apt-get update -q >/dev/null 2>&1
    cd /tmp && apt-get download raspi-firmware >/dev/null 2>&1
    dpkg-deb -x raspi-firmware_*.deb x
    cp x/usr/lib/raspi-firmware/start4.elf x/usr/lib/raspi-firmware/fixup4.dat \
       x/usr/lib/raspi-firmware/bootcode.bin /fw/
    cp -r x/usr/lib/raspi-firmware/overlays /fw/ 2>/dev/null || true
  '
fi
ls "$FWCACHE/start4.elf" "$FWCACHE/fixup4.dat" >/dev/null || { echo "firmware blob fetch failed"; exit 1; }

# 2. Pull kernel + initrd + DTB + rootfs out of the proven arm64 image.
echo "=== extracting kernel/initrd/DTB/rootfs from $SRC ==="
SRCLOOP=$(losetup --show -fP "$SRC"); wait_parts "$SRCLOOP"
mount -o ro "${SRCLOOP}p1" "$WORK/srcboot"
mount -o ro "${SRCLOOP}p2" "$WORK/srcroot"

# Precheck the base rootfs payload before consuming it (field defect 006, 2026-07-09): a base
# rootfs baked from a half-staged mkosi.extra has an EMPTY platforms/ and boot-loops (bootstrap
# no fallback → no manifest → supervisor restart-loop). Fail loud/early instead of shipping it.
SR="$WORK/srcroot"; SRC_BAD=0
for f in usr/share/hookprobe/platforms/generic.yaml usr/lib/hookprobe/hookprobe-bootstrap usr/lib/hookprobe/hookprobe-supervisor; do
  [ -e "$SR/$f" ] || { echo "  base-rootfs MISSING: /$f"; SRC_BAD=1; }
done
for d in usr/share/hookprobe/trust usr/lib/hookprobe/modules; do
  [ -d "$SR/$d" ] && [ -n "$(ls -A "$SR/$d" 2>/dev/null)" ] || { echo "  base-rootfs EMPTY/MISSING dir: /$d"; SRC_BAD=1; }
done
[ "$SRC_BAD" -eq 0 ] || { echo "FATAL: base rootfs $SRC is INCOMPLETE (payload dropped — cf. 006). Rebuild it (build-arm64.sh must print 'staging complete', then 'sudo mkosi --force build') before re-running." >&2; exit 1; }
echo "  base rootfs payload precheck OK"
# Kernel version — auto-detect from the image the build actually produced (Debian bumps the
# point release: 6.1.0-49 → -50 → …). Hardcoding it silently breaks the bake on every kernel
# update; derive it from the vmlinuz that shipped on the ESP. Override with KVER=… if needed.
if [ -z "$KVER" ]; then
  KVER=$(ls "$WORK/srcboot"/vmlinuz-* 2>/dev/null | head -1 | sed 's#.*/vmlinuz-##')
  [ -n "$KVER" ] || { echo "could not auto-detect kernel version from $WORK/srcboot/vmlinuz-*"; exit 1; }
  echo "  auto-detected kernel: $KVER"
fi
# kernel: plain vmlinuz on the ESP; initrd: the .initrd section of the UKI; DTB: from kernel pkg.
cp "$WORK/srcboot/vmlinuz-$KVER" "$WORK/kernel8.img"
UKI=$(ls "$WORK"/srcboot/EFI/Linux/*.efi | head -1)
# The UKI is an aarch64 PE — host (x86) objcopy can't parse it; the arm64 cross-binutils can.
OBJCOPY=$(command -v aarch64-linux-gnu-objcopy || command -v llvm-objcopy || command -v objcopy)
"$OBJCOPY" -O binary --only-section=.initrd "$UKI" "$WORK/initramfs8"
[ -s "$WORK/initramfs8" ] || { echo "could not extract initrd from UKI $UKI (objcopy=$OBJCOPY)"; exit 1; }
DTB="$WORK/srcroot/usr/lib/linux-image-$KVER/broadcom/bcm2711-rpi-4-b.dtb"
cp "$DTB" "$WORK/bcm2711-rpi-4-b.dtb"
echo "  kernel $(du -h "$WORK/kernel8.img"|cut -f1) · initrd $(du -h "$WORK/initramfs8"|cut -f1) · dtb ok"

# 3. Build the SD image: p1 vfat boot (256M) + p2 ext4 root (rest).
echo "=== building $OUT (${SIZE_GB}G: vfat boot + ext4 root) ==="
rm -f "$OUT"; truncate -s "${SIZE_GB}G" "$OUT"
# MBR (msdos) table — the CANONICAL Raspberry Pi layout. The Pi firmware reliably reads MBR +
# a FAT32 (type 0c) boot partition; a GPT table can leave it stuck on the rainbow splash
# (kernel never loaded). p1 = FAT32 boot (256M, bootable), p2 = Linux root (rest).
if [ "${HOOKPROBE_USR_VERITY:-0}" = 1 ]; then
  # /usr-only verity (ADR 0006 H3, the CORRECT design): p1 boot + p2 root (1.5G — holds the FULL
  # rootfs during the initramfs regen, then /usr is emptied out) + p3 /usr (verity-sealed, RO-mounted,
  # never written → cannot self-poison like whole-root verity did). Requires SIZE_GB >= 4.
  sfdisk "$OUT" >/dev/null <<'PARTS'
label: dos
unit: sectors
start=2048, size=524288, type=c, bootable
start=526336, size=3145728, type=83
start=3672064, type=83
PARTS
else
  sfdisk "$OUT" >/dev/null <<'PARTS'
label: dos
unit: sectors
start=2048, size=524288, type=c, bootable
start=526336, type=83
PARTS
fi
OUTLOOP=$(losetup --show -fP "$OUT"); wait_parts "$OUTLOOP"
mkfs.vfat -F32 -n BOOTFS "${OUTLOOP}p1" >/dev/null
mkfs.ext4 -q -L hookprobe-root "${OUTLOOP}p2"
[ "${HOOKPROBE_USR_VERITY:-0}" = 1 ] && mkfs.ext4 -q -L hp-usr "${OUTLOOP}p3"
mkdir -p "$WORK/p1" "$WORK/p2" "$WORK/p3"
mount "${OUTLOOP}p1" "$WORK/p1"
mount "${OUTLOOP}p2" "$WORK/p2"

# 4. Populate the boot (vfat) partition: firmware + kernel + dtb + initrd + config/cmdline.
echo "=== populating boot partition ==="
cp "$FWCACHE"/start4.elf "$FWCACHE"/fixup4.dat "$FWCACHE"/bootcode.bin "$WORK/p1/"
[ -d "$FWCACHE/overlays" ] && cp -r "$FWCACHE/overlays" "$WORK/p1/" || true
cp "$WORK/kernel8.img" "$WORK/initramfs8" "$WORK/bcm2711-rpi-4-b.dtb" "$WORK/p1/"
cat > "$WORK/p1/config.txt" <<'CFG'
# HookProbe OS — Raspberry Pi 4 boot config (Debian arm64 kernel via raspi-firmware path).
arm_64bit=1
enable_uart=1
kernel=kernel8.img
initramfs initramfs8 followkernel
device_tree=bcm2711-rpi-4-b.dtb
disable_overscan=1
# Pi 4 specific
[pi4]
max_framebuffers=2
arm_boost=1
[all]
CFG
# console on both the Pi UART (ttyAMA0 = GPIO serial) and HDMI; root by label; firstboot off
# (headless — same lesson as the VM); rootwait for the SD; firstboot-data grows the data part.
cat > "$WORK/p1/cmdline.txt" <<CMD
console=ttyAMA0,115200 console=tty1 root=LABEL=hookprobe-root rootfstype=ext4 fsck.repair=yes rootwait rw systemd.firstboot=off systemd.journald.forward_to_console=1 ${SPLASH_ARGS}
CMD

# 5. Populate the root (ext4) partition from the proven rootfs.
echo "=== copying rootfs (this takes a moment) ==="
rsync -aHAX --numeric-ids "$WORK/srcroot/." "$WORK/p2/"
# Overlay the latest repo HookProbe scripts so script fixes (e.g. firstboot-provision-data.sh's
# MBR support) apply WITHOUT a full mkosi rebuild — this step runs after mkosi, on the final rootfs.
install -m0755 "$REPO"/base/scripts/*.sh "$WORK/p2/usr/lib/hookprobe/" 2>/dev/null \
  && echo "  overlaid $(ls "$REPO"/base/scripts/*.sh | wc -l) repo scripts onto the rootfs" || true
# Overlay the latest units too (e.g. the hookprobe-ovs ConditionPathExists gate) so unit fixes
# also skip the mkosi rebuild, and ensure /etc/hostapd exists so network-apply can stage the
# hostapd AP config under ProtectSystem=strict (its optional -/etc/hostapd RW path needs the
# dir to pre-exist). Both keep the first boot's reconcile clean (zero failed units).
cp "$REPO"/base/units/* "$REPO"/modules/ovs/units/* "$WORK/p2/usr/lib/systemd/system/" 2>/dev/null || true
mkdir -p "$WORK/p2/etc/hostapd"
echo "  overlaid units + ensured /etc/hostapd"
# Pi 4 fstab: root by label + the vfat boot at /boot/firmware (raspi convention).
cat > "$WORK/p2/etc/fstab" <<FSTAB
# HookProbe OS — Pi 4. Persistent data partition is provisioned + mounted by firstboot-data.
LABEL=hookprobe-root  /              ext4  defaults,noatime  0 1
LABEL=BOOTFS          /boot/firmware vfat  defaults,nofail   0 2
FSTAB
mkdir -p "$WORK/p2/boot/firmware"

# ---- ADMIN ACCESS — GATED (ADR 0008; security-audit F1; credentials neutralized to the
# default hookprobe/hookprobe login per ADR 0045, 2026-07-25) ------------------------------
# Release images ship NO password auth, NO root login, and NO login-capable account — access is
# via an enrolled SSH key (dashboard-first). The bring-up debug login (hookprobe/root passwords)
# is opt-in ONLY: set HOOKPROBE_DEBUG_ACCESS=1. Default OFF so a shipped image is never trivially
# cracked (hydra cracked root:hookprobe when this block was unconditional). Debug mode elevates
# the existing hookprobe SERVICE account (created by mkosi.postinst, normally nologin) into a
# login admin instead of creating a second account.
#   debug build:  HOOKPROBE_DEBUG_ACCESS=1  →  ssh hookprobe@<ip> pw hookprobe · ssh root@<ip> pw hookprobe
RT="$WORK/p2"
mkdir -p "$RT/etc/ssh/sshd_config.d" "$RT/etc/systemd/system/multi-user.target.wants"
if [ "${HOOKPROBE_DEBUG_ACCESS:-0}" = 1 ]; then
  # DEBUG-ONLY: cracked-by-design credentials. NEVER set this flag for a release build.
  R_HASH='$6$qEkJ33cMtCvXHNnx$n8xTd2YDLffJ9efYmRlXqD72fuTvPwH5VXvFWMfOXKrI/ebwPtK7m8C1TW25nJCwegHnIashhrvPhXMsl7Nw60'
  if grep -q '^hookprobe:' "$RT/etc/passwd"; then
    awk -F: 'BEGIN{OFS=":"} $1=="hookprobe"{$7="/bin/bash"} 1' "$RT/etc/passwd" > "$RT/etc/passwd.new" && mv "$RT/etc/passwd.new" "$RT/etc/passwd"
  fi
  sed -i "s|^hookprobe:[^:]*:|hookprobe:${R_HASH}:|" "$RT/etc/shadow"
  awk -F: 'BEGIN{OFS=":"} $1=="sudo"{ if($4=="") $4="hookprobe"; else if($4 !~ /(^|,)hookprobe(,|$)/) $4=$4",hookprobe" } 1' \
    "$RT/etc/group" > "$RT/etc/group.new" && mv "$RT/etc/group.new" "$RT/etc/group"
  sed -i "s|^root:[^:]*:|root:${R_HASH}:|" "$RT/etc/shadow"
  rm -f "$RT/etc/ssh/sshd_config.d/10-hookprobe-hardened.conf" 2>/dev/null || true
  printf 'PermitRootLogin yes\nPasswordAuthentication yes\n' > "$RT/etc/ssh/sshd_config.d/10-hookprobe-debug.conf"
  mkdir -p "$RT/etc/hookprobe"; echo "debug" > "$RT/etc/hookprobe/build-mode"
  echo "  ADMIN ACCESS: DEBUG (hookprobe sudo + root, password SSH) — HOOKPROBE_DEBUG_ACCESS=1"
else
  # RELEASE: lock root, revert the hookprobe account to no-login, harden sshd (key-only, no root
  # login). Defense-in-depth (2026-07-07 backend audit F2): mkosi.postinst now gates account
  # elevation at the SOURCE, so a fresh release-mode base rootfs never carries a login-capable
  # hookprobe account — but this branch must not assume that: strip it explicitly here too, in
  # case $SRC was built with HOOKPROBE_DEBUG_ACCESS=1 and fed into a "release" make-pi4-image.sh
  # run by mistake. A release .img must have ZERO default-credential sudo accounts, full stop.
  # Also strips a leftover legacy 'andrei' entry (pre-ADR-0045 rootfs).
  if grep -q '^hookprobe:' "$RT/etc/passwd" 2>/dev/null; then
    awk -F: 'BEGIN{OFS=":"} $1=="hookprobe"{$7="/usr/sbin/nologin"} 1' "$RT/etc/passwd" > "$RT/etc/passwd.new" && mv "$RT/etc/passwd.new" "$RT/etc/passwd"
  fi
  sed -i 's|^hookprobe:[^:]*:|hookprobe:!:|' "$RT/etc/shadow" 2>/dev/null || true
  if grep -q '^andrei:' "$RT/etc/passwd" 2>/dev/null; then
    sed -i '/^andrei:/d' "$RT/etc/passwd"
    sed -i '/^andrei:/d' "$RT/etc/shadow"
    sed -i '/^andrei:/d' "$RT/etc/group"
    rm -rf "$RT/home/andrei"
    echo "  defense-in-depth: stripped leftover legacy 'andrei' debug account from the release rootfs"
  fi
  if grep -q '^sudo:' "$RT/etc/group" 2>/dev/null; then
    awk -F: 'BEGIN{OFS=":"} $1=="sudo"{c=split($4,a,","); out=""; for(i=1;i<=c;i++) if(a[i]!="" && a[i]!="hookprobe" && a[i]!="andrei") out=(out==""?a[i]:out","a[i]); $4=out} 1' \
      "$RT/etc/group" > "$RT/etc/group.new" && mv "$RT/etc/group.new" "$RT/etc/group"
  fi
  sed -i 's|^root:[^:]*:|root:!:|' "$RT/etc/shadow" 2>/dev/null || true
  rm -f "$RT/etc/ssh/sshd_config.d/10-hookprobe-debug.conf" 2>/dev/null || true
  printf 'PermitRootLogin no\nPasswordAuthentication no\nKbdInteractiveAuthentication no\n' \
    > "$RT/etc/ssh/sshd_config.d/10-hookprobe-hardened.conf"
  mkdir -p "$RT/etc/hookprobe"; echo "release" > "$RT/etc/hookprobe/build-mode"
  echo "  ADMIN ACCESS: RELEASE (root locked, no login account, key-only SSH) — set HOOKPROBE_DEBUG_ACCESS=1 for a debug image"
fi
# ssh service + the E1/E2/flow-fix operational services (make-pi4-only builds don't re-run preset-all)
# GAP-1 (2026-07-16): only a DEBUG image runs sshd. Release has no login user + root locked, so a
# live sshd is pure pre-auth WAN attack surface — mask it (symlink→/dev/null) on release.
if [ "${HOOKPROBE_DEBUG_ACCESS:-0}" = "1" ]; then
  ln -sf /lib/systemd/system/ssh.service "$RT/etc/systemd/system/multi-user.target.wants/ssh.service"
else
  rm -f "$RT/etc/systemd/system/multi-user.target.wants/ssh.service"
  ln -sf /dev/null "$RT/etc/systemd/system/ssh.service"
  # also mask ssh.SOCKET (audit MEDIUM): socket-activation would bypass a masked service.
  rm -f "$RT/etc/systemd/system/sockets.target.wants/ssh.socket"
  ln -sf /dev/null "$RT/etc/systemd/system/ssh.socket"
fi
mkdir -p "$RT/etc/systemd/system/local-fs.target.wants"
for svc in hookprobe-unlock-data hookprobe-data-guard; do
  ln -sf "/usr/lib/systemd/system/$svc.service" "$RT/etc/systemd/system/local-fs.target.wants/$svc.service"
done
ln -sf /usr/lib/systemd/system/hookprobe-secrets.service "$RT/etc/systemd/system/multi-user.target.wants/hookprobe-secrets.service"
ln -sf /usr/lib/systemd/system/hookprobe-rbac-check.service "$RT/etc/systemd/system/multi-user.target.wants/hookprobe-rbac-check.service"

# ---- Regenerate the initrd WITH the Pi's storage drivers (THE fix for SD-root boot) -------
# mkosi's UKI initrd has NO kernel modules. The Pi 4 SD host controller (sdhci-iproc) is a
# MODULAR driver, so the kernel can't mount root from the SD without it → boot stalls before
# networking. Rebuild a proper MODULES=most initrd using the rootfs's own initramfs-tools via
# a qemu-user (binfmt 'F' flag) chroot, then use it as initramfs8 on the boot partition.
echo "=== regenerating initrd with Pi storage drivers (chroot + update-initramfs) ==="
# update-initramfs greps /boot/config-<ver> to learn which initrd compressors the kernel
# supports; mkosi strips /boot, so without it update-initramfs can't confirm zstd and aborts.
# Supply the real config from the linux-image .deb (cached, Debian-signed).
CFGCACHE="$HERE/pi4-kernel-config"
if [ ! -f "$CFGCACHE/config-$KVER" ]; then
  echo "  fetching kernel config-$KVER from linux-image .deb (cached → $CFGCACHE)"
  mkdir -p "$CFGCACHE"
  podman run --rm -v "$CFGCACHE:/c:Z" --arch arm64 docker.io/arm64v8/debian:bookworm bash -c "
    apt-get update -q >/dev/null 2>&1
    cd /tmp && apt-get download linux-image-$KVER >/dev/null 2>&1
    dpkg-deb -x linux-image-${KVER}_*.deb x
    cp x/boot/config-$KVER /c/ 2>/dev/null || true
  " 2>/dev/null || true
fi
[ -f "$CFGCACHE/config-$KVER" ] && cp "$CFGCACHE/config-$KVER" "$RT/boot/config-$KVER" \
  && echo "  placed /boot/config-$KVER ($(grep -c '^CONFIG_RD_' "$CFGCACHE/config-$KVER") CONFIG_RD_ options)" \
  || echo "  WARN: could not obtain kernel config — update-initramfs may still fall back"
# Force-include the Pi 4 SD/MMC stack so the initrd can mount root from the SD regardless of
# what MODULES=most happens to pull in (sdhci-iproc is the Pi4's SD host controller).
for mod in sdhci-iproc sdhci-of-arasan sdhci-pltfm mmc_block bcm2835 dwc2; do
  grep -qx "$mod" "$RT/etc/initramfs-tools/modules" 2>/dev/null || echo "$mod" >> "$RT/etc/initramfs-tools/modules"
done
# H3b: install the dm-verity initramfs hooks so the regenerated initrd can set up a read-only,
# hash-verified root (with a fallback-safe plain-root path). Only engages when cmdline carries
# verity.roothash= (written after the rootfs is sealed, below). Needs veritysetup+dmsetup in the
# rootfs (cryptsetup pkg — added to mkosi.conf). See docs/adr/0006 (H3b).
if [ "${HOOKPROBE_VERITY:-0}" = 1 ]; then
  install -D -m0755 "$REPO"/base/initramfs/hooks/hookprobe-verity             "$RT/etc/initramfs-tools/hooks/hookprobe-verity"
  install -D -m0755 "$REPO"/base/initramfs/scripts/local-top/hookprobe-verity "$RT/etc/initramfs-tools/scripts/local-top/hookprobe-verity"
  install -D -m0755 "$REPO"/base/initramfs/scripts/local-premount/hookprobe-overlay "$RT/etc/initramfs-tools/scripts/local-premount/hookprobe-overlay"
  echo "  H3b: dm-verity initramfs hooks installed (root will be RO-verified, fallback-safe)"
fi
if [ "${HOOKPROBE_USR_VERITY:-0}" = 1 ]; then
  # /usr-only verity (the correct design): local-bottom hook mounts a RO-verity /usr; / stays writable.
  install -D -m0755 "$REPO"/base/initramfs/hooks/hookprobe-usr-verity                "$RT/etc/initramfs-tools/hooks/hookprobe-usr-verity"
  install -D -m0755 "$REPO"/base/initramfs/scripts/local-bottom/hookprobe-usr-verity "$RT/etc/initramfs-tools/scripts/local-bottom/hookprobe-usr-verity"
  echo "  H3: /usr-verity initramfs hooks installed (/usr = RO-verity, / = writable — no self-poison)"
fi
# plymouth's initramfs hook fails inside the emulated arm64 chroot (no graphics stack) and ABORTS
# update-initramfs — which would drop the Pi SD drivers AND the verity hooks, leaving an unbootable
# image. Remove it: the boot splash still runs from the real root once plymouthd starts; it does not
# need to be in the initrd. (Root-cause of the first H3b build failure — ADR 0006.)
rm -f "$RT/usr/share/initramfs-tools/hooks/plymouth"
cp /usr/bin/qemu-aarch64-static "$RT/usr/bin/" 2>/dev/null || true   # fallback if binfmt lacks F
# Force the Pi 4 microSD stack into the initrd: update-initramfs in the emulated chroot can't detect the
# SD hardware (MODULES=dep sees nothing), so without this the regenerated initrd lacks sdhci-iproc and
# the SD root never mounts → unbootable. The Pi 4 microSD is the BCM2711 emmc2 controller = sdhci-iproc.
for mod in sdhci sdhci-pltfm sdhci-iproc mmc_block; do
  grep -qxF "$mod" "$RT/etc/initramfs-tools/modules" 2>/dev/null || echo "$mod" >> "$RT/etc/initramfs-tools/modules"
done
for m in proc sys dev dev/pts; do mkdir -p "$RT/$m"; mount --bind "/$m" "$RT/$m" 2>/dev/null || true; done
chroot "$RT" /usr/sbin/update-initramfs -c -k "$KVER" 2>&1 | tail -8 || echo "  WARN update-initramfs failed"
for m in dev/pts dev sys proc; do umount "$RT/$m" 2>/dev/null || true; done
rm -f "$RT/usr/bin/qemu-aarch64-static"
NEWINITRD="$RT/boot/initrd.img-$KVER"
if [ -s "$NEWINITRD" ]; then
  cp "$NEWINITRD" "$WORK/p1/initramfs8"
  echo "  initramfs8 regenerated: $(du -h "$WORK/p1/initramfs8" | cut -f1) (replaces module-less UKI initrd)"
  # Debian initrds are multi-segment cpio (early microcode + main archive) — a bare zstdcat|cpio
  # only reads the FIRST segment and false-negatives (bit us 2026-07-03: iproc WAS in the initrd,
  # verified by unmkinitramfs + CONFIG_MMC_BLOCK=y built-in). Use unmkinitramfs when available.
  IVER=$(mktemp -d)
  if command -v unmkinitramfs >/dev/null 2>&1 && unmkinitramfs "$WORK/p1/initramfs8" "$IVER" 2>/dev/null \
     && find "$IVER" -name 'sdhci-iproc.ko' | grep -q .; then
    echo "  ✓ sdhci-iproc present (unmkinitramfs) — SD root will mount on the Pi 4"
  elif zstdcat "$WORK/p1/initramfs8" 2>/dev/null | cpio -t 2>/dev/null | grep -qi "sdhci.iproc"; then
    echo "  ✓ sdhci-iproc present — SD root will mount on the Pi 4"
  else
    echo "  ⚠ sdhci-iproc NOT found by either check — investigate before flashing"
  fi
  rm -rf "$IVER"
else
  echo "  ⚠ WARN: initrd regen produced nothing; boot partition still has the module-less initrd"
fi

# --- H3a: dm-verity rootfs integrity (ADR 0006). Opt-in (HOOKPROBE_VERITY=1) until Pi-boot-validated,
#     so the proven image build is unchanged by default. Computes the hash tree + root hash over the
#     FINAL rootfs and stores the anchor on p1 (FAT boot) — out-of-band from the p2 it protects. The
#     integrity-check service verifies against it on-device. Full read-only verity-BOOT (initramfs
#     veritysetup hook + root=/dev/mapper/hookprobe-verity + the root hash on cmdline) is H3b. ---
if [ "${HOOKPROBE_VERITY:-0}" = 1 ] && command -v veritysetup >/dev/null; then
  echo "=== H3b: sealing the rootfs with dm-verity (read-only verified boot) ==="
  sync; umount "$WORK/p2"           # p2 must be quiescent + UNMOUNTED to hash it (and stay so after)
  "$REPO"/security/verity/build-verity.sh "${OUTLOOP}p2" "$WORK/p1/rootfs.verity" "$WORK/p1/verity.roothash" >/dev/null
  RH=$(cat "$WORK/p1/verity.roothash")
  # Repoint root at the verity device. root MUST be `ro` (verity is read-only); the initramfs
  # local-premount hook lays a writable tmpfs overlay on top so services can still write /etc,/var.
  cat > "$WORK/p1/cmdline.txt" <<CMD
console=ttyAMA0,115200 console=tty1 root=/dev/mapper/hpverity rootwait ro verity.roothash=$RH verity.data=/dev/mmcblk0p2 verity.boot=/dev/mmcblk0p1 verity.hashfile=rootfs.verity fsck.mode=skip systemd.firstboot=off systemd.journald.forward_to_console=1
CMD
  echo "  ✓ dm-verity sealed: root hash $RH"
  echo "    cmdline → root=/dev/mapper/hpverity ro (p2 left UNTOUCHED — any write would break the hash)"
  # p2 intentionally NOT remounted from here.
fi

# --- H3 (CORRECT design): /usr-only verity. The initramfs already regenerated with /usr in place, so
#     now split /usr → p3 + verity-seal it. / stays LABEL rw (proven boot); /usr is mounted READ-ONLY
#     via dm-verity by the local-bottom hook → the /usr device is NEVER written → cannot self-poison
#     (the flaw that killed whole-root verity). AEGIS writes /etc,/var on the writable / freely. ---
if [ "${HOOKPROBE_USR_VERITY:-0}" = 1 ] && command -v veritysetup >/dev/null; then
  echo "=== H3: /usr-only verity — split /usr → p3, verity-seal (/ stays writable) ==="
  mount "${OUTLOOP}p3" "$WORK/p3"
  rsync -aHAX "$WORK/p2/usr/." "$WORK/p3/"
  sync; umount "$WORK/p3"
  rm -rf "$WORK/p2/usr"; mkdir -p "$WORK/p2/usr"     # empty /usr mountpoint on the writable root
  sync
  # hash tree on the EXT4 root /boot (already mounted at boot before local-bottom) — NOT the FAT boot
  # partition, so the initramfs needs no vfat/nls codepage to read it (that was the 2nd boot failure).
  mkdir -p "$WORK/p2/boot"
  "$REPO"/security/verity/build-verity.sh "${OUTLOOP}p3" "$WORK/p2/boot/usr.verity" "$WORK/p2/boot/usr.roothash" >/dev/null
  RH=$(cat "$WORK/p2/boot/usr.roothash")
  cat > "$WORK/p1/cmdline.txt" <<CMD
console=ttyAMA0,115200 console=tty1 root=LABEL=hookprobe-root rootfstype=ext4 fsck.repair=yes rootwait rw usrverity.roothash=$RH usrverity.data=LABEL=hp-usr usrverity.hashfile=usr.verity systemd.firstboot=off systemd.journald.forward_to_console=1 ${SPLASH_ARGS}
CMD
  echo "  ✓ /usr verity-sealed: usr root hash $RH"
  echo "    cmdline → root=LABEL=hookprobe-root rw + usrverity.data=/dev/mmcblk0p3 (/usr = RO verity)"
fi

sync
echo "=== verifying boot partition ==="
ls -la "$WORK/p1" | sed 's/^/  /'
echo "=== DONE: $OUT ==="
echo "  flash to SD with:  sudo dd if=$OUT of=/dev/sdX bs=4M conv=fsync status=progress"
echo "  (or Raspberry Pi Imager → Use Custom)"
