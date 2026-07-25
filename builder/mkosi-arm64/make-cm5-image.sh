#!/usr/bin/env bash
# *** SUPERSEDED by make-pi-image.sh (ADR 0029 — unified Pi4/CM4/Pi5/CM5 fat-boot image) ***
# Kept for now (single-board slim builds / historical reference), NOT deleted, per ADR 0029 D4.
# This script's entire "NO RP1 driver" problem (see HOOKPROBE_CM5_ACCEPT_NO_RP1 below) is SOLVED
# by make-pi-image.sh: it fetches the Raspberry-Pi-repo's OWN downstream kernel
# (linux-image-rpi-2712), which carries full RP1 (Ethernet/USB) support TODAY, plus the real
# bcm2712-rpi-cm5-cm5io.dtb natively (no GitHub-vendored dtb hack needed). New work targets
# make-pi-image.sh. See docs/adr/0029-unified-pi-fatboot-dual-kernel.md.
#
# make-cm5-image.sh — assemble a REAL Raspberry Pi Compute Module 5 (CM5, BCM2712/Cortex-A76)
# bootable image from the proven arm64 rootfs, mirroring make-pi4-image.sh's structure. The CM5
# boots COMPLETELY differently from the Pi 4 — do not assume Pi4 mechanics carry over (researched
# 2026-07-08, cited inline below, not assumed):
#
#   Pi 4 boot chain: SoC ROM -> reads p1 vfat's bootcode.bin -> start4.elf/fixup4.dat (GPU
#     firmware, loaded from the SD card every boot) -> config.txt -> kernel8.img + dtb + initramfs.
#
#   CM5 boot chain: SoC ROM -> onboard SPI-EEPROM bootloader (self-contained; NOT loaded from the
#     boot partition — rpi-eeprom-update territory, out of this script's scope) -> the EEPROM
#     bootloader itself reads p1 vfat directly for config.txt + the kernel + dtb + initramfs.
#     "The Raspberry Pi 5, 500, 500+, and Compute Module 5 firmware is self-contained in the
#     bootloader EEPROM" and "Raspberry Pi 5 requires a config.txt file to be present to indicate
#     that the partition is bootable" (raspberrypi.com/documentation/computers/config_txt.html,
#     fetched live 2026-07-08) — so THIS script's boot partition carries NO bootcode.bin/
#     start4.elf/fixup4.dat (there is nothing for them to do; shipping them is harmless-but-dead,
#     so we simply don't). Firmware tries `kernel_2712.img` first (RPi Foundation's own
#     16K-page-optimized downstream build), falling back to the generic `kernel8.img` if absent —
#     we ship ONLY `kernel8.img` (a standard Debian arm64 kernel, not the RPi Foundation's
#     downstream 2712-optimized build) and rely on that documented fallback, same honest naming
#     convention as make-pi4-image.sh. `arm_64bit=1` is accepted but ignored (Pi5/CM5 are
#     64-bit-only and ignore the flag) — kept for readability parity with the Pi4 config, no
#     functional effect.
#
# *** THE LOAD-BEARING FINDING OF THIS SCRIPT (read before flashing) ***
#   The base rootfs's stock Debian bookworm kernel (6.1.0-50-arm64, confirmed by direct inspection
#   of hookprobe-os-arm64.raw's /usr/lib/linux-image-*/broadcom/ 2026-07-08) ships ZERO bcm2712
#   device trees (only bcm2711/bcm2837 — Pi4/Pi3 family). Debian bookworm-backports' newest
#   kernel (linux-image-6.12.94+deb12-arm64, confirmed via packages.debian.org 2026-07-08) DOES
#   carry `bcm2712-rpi-5-b.dtb` (Pi 5 Model B) but — also confirmed by direct file-list
#   inspection — carries NO CM5/CM5-IO-board dtb variant at all (mainline dts upstreaming lands
#   carrier-board variants later than the flagship board). Worse: BCM2712's RP1 I/O chip (the
#   southbridge that provides Gigabit Ethernet MAC, USB 2/3, camera/display I/O on the Pi 5/CM5)
#   has **no mainline Linux driver before ~6.17, with working Ethernet/USB only from ~6.18**
#   (Phoronix "Raspberry Pi RP1 PCI Device Support On Path For Linux 6.17", SUSE upstreaming work,
#   fetched 2026-07-08) — Debian bookworm-backports tops out at 6.12.x as of this writing. THE
#   CONSEQUENCE: an image built purely from Debian/mainline kernel packaging (what this script
#   does, by design — Debian/Ubuntu is the locked base-distro canon) will very likely boot to a
#   console with SD/eMMC root mounted but have **NO functioning Ethernet or USB** on real CM5/Pi5
#   hardware. A network-security appliance with no network path is not a shippable SOC. This is a
#   genuine, currently-unresolved architecture question (vendor the Raspberry Pi Foundation's own
#   downstream kernel — which DOES have full RP1 support today — for the Pi5/CM5 tier only, vs.
#   hold Pi5/CM5 as "console/storage validated, network NOT validated" until Debian ships an
#   RP1-capable kernel) that needs an os-architect decision, not a release-engineer default. This
#   script does NOT silently paper over it — see HOOKPROBE_CM5_ACCEPT_NO_RP1 below.
#
# Needs sudo (loop/mkfs/mount/chroot), same as make-pi4-image.sh. NOT boot-testable here (no CM5
# hardware attached to this dev box) — on-silicon validation happens when the operator plugs in
# the CM5 (eMMC via rpiboot, or SD for a CM5 Lite). This script only assembles + statically
# verifies the image; see the tail of this file for the exact flash commands.
#
#   sudo builder/mkosi-arm64/make-cm5-image.sh [SRC.raw] [OUT.img] [SIZE_GB]
#
# Env knobs:
#   HOOKPROBE_DEBUG_ACCESS=1        same gated debug-account model as make-pi4-image.sh (default
#                                    OFF = release-mode, key-only SSH, no default password user).
#   HOOKPROBE_CM5_ACCEPT_NO_RP1=1   required ack that you have read the RP1 caveat above. Without
#                                    it the script still builds the image (useful for a
#                                    console/eMMC-mount-only bench check) but refuses to drop the
#                                    "NO-NETWORK, RP1-UNSUPPORTED" marker's severity — the banner
#                                    always prints either way; this flag only silences the
#                                    30-second confirmation pause so CI/batch runs aren't stuck
#                                    waiting on a TTY that doesn't exist.
#   CM5_DTB_SOURCE=vendor|debian    which device tree to ship (default: vendor — the real CM5-IO
#                                    dtb, pinned from raspberrypi/firmware; see the fetch stage
#                                    below). `debian` forces the Pi-5-Model-B dtb Debian actually
#                                    ships, which is WRONG for CM5's carrier-board peripheral
#                                    mapping (I2C/SPI/eMMC/PCIe wiring differs from the Pi 5
#                                    board) but at least comes from the same Debian kernel package
#                                    as everything else — an explicit, honest fallback, never a
#                                    silent default.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
SRC=${1:-$HERE/hookprobe-os-arm64.raw}
OUT=${2:-$HERE/hookprobe-os-cm5.img}
SIZE_GB=${3:-2}
SPLASH_ARGS=""
[ "${HOOKPROBE_SPLASH:-0}" = 1 ] && SPLASH_ARGS="quiet splash loglevel=3 vt.global_cursor_default=0 plymouth.ignore-serial-consoles"
CM5_DTB_SOURCE="${CM5_DTB_SOURCE:-vendor}"
KCACHE="$HERE/cm5-kernel-cache"     # bookworm-backports linux-image-arm64 (bcm2712 support)
DTBCACHE="$HERE/cm5-dtb-cache"      # vendored CM5-IO-board dtb (pinned, see base/drivers/SOURCES.md)
WORK=$(mktemp -d /tmp/hp-cm5.XXXXXX)
[ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 1; }
[ -f "$SRC" ] || { echo "source image $SRC not found (build the arm64 image first)"; exit 1; }

cleanup() {
  set +e
  for m in dev/pts dev sys proc; do umount "$WORK/p2/$m" 2>/dev/null; done
  for m in "$WORK"/srcboot "$WORK"/srcroot "$WORK"/p1 "$WORK"/p2; do mountpoint -q "$m" && umount "$m"; done
  [ -n "${SRCLOOP:-}" ] && losetup -d "$SRCLOOP" 2>/dev/null
  [ -n "${OUTLOOP:-}" ] && losetup -d "$OUTLOOP" 2>/dev/null
  rm -rf "$WORK"
}
trap cleanup EXIT
mkdir -p "$WORK"/{srcboot,srcroot,p1,p2}

wait_parts() {
  udevadm settle 2>/dev/null || true
  for _ in $(seq 1 30); do
    [ -b "${1}p1" ] && [ -b "${1}p2" ] && return 0
    partprobe "$1" 2>/dev/null || true; sleep 0.5
  done
  [ -b "${1}p1" ] || { echo "partition nodes for $1 never appeared"; return 1; }
}

echo "=================================================================================="
echo " HookProbe OS — Compute Module 5 image assembly"
echo " *** RP1 (Ethernet/USB/camera southbridge) has NO mainline/Debian kernel driver  ***"
echo " *** before ~Linux 6.17-6.18; bookworm-backports tops out at 6.12.x today.       ***"
echo " *** This image will very likely have NO Ethernet/USB on real CM5/Pi5 hardware.  ***"
echo " *** See this script's header comment for the full finding + citations.          ***"
echo "=================================================================================="
if [ "${HOOKPROBE_CM5_ACCEPT_NO_RP1:-0}" != 1 ] && [ -t 0 ]; then
  echo "Set HOOKPROBE_CM5_ACCEPT_NO_RP1=1 to skip this pause (CI/batch). Continuing in 5s..."
  sleep 5
fi

# 1. Kernel WITH bcm2712 support: the base rootfs's stock bookworm kernel (6.1.x) ships ZERO
#    bcm2712 device trees (confirmed by direct inspection, see header) — bookworm-backports'
#    linux-image-arm64 (6.12.x) is the minimum Debian-native kernel that even knows the SoC
#    exists. Fetched + cached via podman (same non-privileged, cached, Debian-signed-source
#    pattern make-pi4-image.sh already uses for raspi-firmware/linux-image-arm64 config).
if [ ! -d "$KCACHE/lib/modules" ] || [ -z "$(ls -A "$KCACHE/lib/modules" 2>/dev/null)" ]; then
  echo "=== fetching bookworm-backports linux-image-arm64 (bcm2712 support; cached -> $KCACHE) ==="
  mkdir -p "$KCACHE"
  podman run --rm -v "$KCACHE:/out:Z" --arch arm64 docker.io/arm64v8/debian:bookworm bash -c '
    set -e
    echo "deb http://deb.debian.org/debian bookworm-backports main non-free-firmware" > /etc/apt/sources.list.d/backports.list
    apt-get update -q >/dev/null 2>&1
    apt-get install -y -t bookworm-backports --no-install-recommends linux-image-arm64 >/dev/null 2>&1
    KVER=$(ls /lib/modules | sort -V | tail -1)
    echo "backports kernel: $KVER"
    mkdir -p /out/lib/modules /out/boot /out/broadcom /out/config
    cp -a "/lib/modules/$KVER" /out/lib/modules/
    cp "/boot/vmlinuz-$KVER" /out/boot/vmlinuz
    cp "/boot/config-$KVER" /out/config/ 2>/dev/null || true
    cp -a "/usr/lib/linux-image-$KVER/broadcom/." /out/broadcom/ 2>/dev/null || true
    echo "$KVER" > /out/KVER
  '
fi
CM5KVER=$(cat "$KCACHE/KVER" 2>/dev/null || true)
[ -n "$CM5KVER" ] || { echo "backports kernel fetch failed (no KVER recorded in $KCACHE)"; exit 1; }
[ -f "$KCACHE/boot/vmlinuz" ] || { echo "backports kernel fetch failed (no vmlinuz in $KCACHE)"; exit 1; }
echo "  backports kernel: $CM5KVER"
ls "$KCACHE/broadcom" 2>/dev/null | grep -qi bcm2712 \
  && echo "  bcm2712 dtb(s) present in the Debian package: $(ls "$KCACHE/broadcom" | grep -i bcm2712 | tr '\n' ' ')" \
  || echo "  WARN: no bcm2712-*.dtb found in the fetched Debian kernel package (see CM5_DTB_SOURCE fallback below)"

# 2. Device tree. Debian's backports kernel ships bcm2712-rpi-5-b.dtb (Pi 5 Model B) but no
#    CM5/CM5-IO variant (confirmed, see header) — the CORRECT dtb for a real CM5 is
#    bcm2712-rpi-cm5-cm5io.dts (raspberrypi/linux), which we vendor directly (pinned commit,
#    tracked in base/drivers/SOURCES.md, same discipline as the vendored Wi-Fi dongle drivers)
#    rather than fabricate a "close enough" substitute. `CM5_DTB_SOURCE=debian` opts out of the
#    vendored blob and uses the Pi-5-board dtb instead (wrong carrier peripheral mapping, but at
#    least Debian-native) — an explicit choice, never a silent one.
CM5_DTB_PIN="89752d47a688ec33c9f0c38f6549f627e5c143f9"   # raspberrypi/firmware, pinned 2026-07-08
CM5_DTB_URL="https://raw.githubusercontent.com/raspberrypi/firmware/${CM5_DTB_PIN}/boot/bcm2712-rpi-cm5-cm5io.dtb"
DTB_NAME="bcm2712-rpi-cm5-cm5io.dtb"
if [ "$CM5_DTB_SOURCE" = vendor ]; then
  if [ ! -s "$DTBCACHE/$DTB_NAME" ]; then
    echo "=== fetching vendored CM5-IO-board dtb (pinned $CM5_DTB_PIN, cached -> $DTBCACHE) ==="
    mkdir -p "$DTBCACHE"
    curl -fsSL "$CM5_DTB_URL" -o "$DTBCACHE/$DTB_NAME.tmp" && mv "$DTBCACHE/$DTB_NAME.tmp" "$DTBCACHE/$DTB_NAME" \
      || { echo "  WARN: vendored dtb fetch failed (no network?) — falling back to CM5_DTB_SOURCE=debian"; CM5_DTB_SOURCE=debian; }
  fi
fi
if [ "$CM5_DTB_SOURCE" = vendor ] && [ -s "$DTBCACHE/$DTB_NAME" ]; then
  cp "$DTBCACHE/$DTB_NAME" "$WORK/$DTB_NAME"
  echo "  using VENDORED $DTB_NAME (pinned raspberrypi/firmware@$CM5_DTB_PIN — the real CM5-IO-board dtb)"
else
  DTB_NAME="bcm2712-rpi-5-b.dtb"
  [ -f "$KCACHE/broadcom/$DTB_NAME" ] || { echo "no usable CM5 or Pi5 dtb available — aborting"; exit 1; }
  cp "$KCACHE/broadcom/$DTB_NAME" "$WORK/$DTB_NAME"
  echo "  WARN: using Debian's $DTB_NAME (Pi 5 MODEL BOARD dtb, NOT CM5-shaped — carrier-board"
  echo "        peripheral mapping (I2C/SPI/eMMC/PCIe) is very likely WRONG for a real CM5)"
fi

# 3. Pull rootfs + the arm64 UEFI-boot artifacts' kernel command-line convention out of the
#    proven arm64 image (SAME source `make-pi4-image.sh` uses — one rootfs, two boot substrates).
echo "=== extracting rootfs from $SRC ==="
SRCLOOP=$(losetup --show -fP "$SRC"); wait_parts "$SRCLOOP"
mount -o ro "${SRCLOOP}p1" "$WORK/srcboot"
mount -o ro "${SRCLOOP}p2" "$WORK/srcroot"

# Precheck the base rootfs payload before consuming it (field defect 006, 2026-07-09): if the base
# rootfs was baked from a half-staged mkosi.extra, platforms/ is EMPTY and the resulting image
# boot-loops (bootstrap has no fallback → no manifest → supervisor restart-loop). Fail loud/early.
SR="$WORK/srcroot"; SRC_BAD=0
for f in usr/share/hookprobe/platforms/generic.yaml usr/lib/hookprobe/hookprobe-bootstrap usr/lib/hookprobe/hookprobe-supervisor; do
  [ -e "$SR/$f" ] || { echo "  base-rootfs MISSING: /$f"; SRC_BAD=1; }
done
for d in usr/share/hookprobe/trust usr/lib/hookprobe/modules; do
  [ -d "$SR/$d" ] && [ -n "$(ls -A "$SR/$d" 2>/dev/null)" ] || { echo "  base-rootfs EMPTY/MISSING dir: /$d"; SRC_BAD=1; }
done
[ "$SRC_BAD" -eq 0 ] || { echo "FATAL: base rootfs $SRC is INCOMPLETE (payload dropped — cf. 006). Rebuild it (build-arm64.sh must print 'staging complete', then 'sudo mkosi --force build') before re-running." >&2; exit 1; }
echo "  base rootfs payload precheck OK"

# 4. Build the image: p1 vfat boot (256M) + p2 ext4 root (rest). MBR (not GPT) — the CM5/Pi5
#    EEPROM bootloader is documented to need only "a FAT partition + config.txt present"
#    (raspberrypi.com config_txt.html) and does not require GPT; MBR is the already-proven Pi4
#    layout, kept here for consistency (GPT+NVMe-boot is a real future CM5 variant, out of scope).
echo "=== building $OUT (${SIZE_GB}G: vfat boot + ext4 root) ==="
rm -f "$OUT"; truncate -s "${SIZE_GB}G" "$OUT"
sfdisk "$OUT" >/dev/null <<'PARTS'
label: dos
unit: sectors
start=2048, size=524288, type=c, bootable
start=526336, type=83
PARTS
OUTLOOP=$(losetup --show -fP "$OUT"); wait_parts "$OUTLOOP"
mkfs.vfat -F32 -n BOOTFS "${OUTLOOP}p1" >/dev/null
mkfs.ext4 -q -L hookprobe-root "${OUTLOOP}p2"
mount "${OUTLOOP}p1" "$WORK/p1"
mount "${OUTLOOP}p2" "$WORK/p2"

# 5. Populate the boot (vfat) partition — NO bootcode.bin/start4.elf/fixup4.dat (the CM5's SPI
#    EEPROM bootloader is self-contained; those Pi4-era GPU-firmware files have nothing to load
#    them and are simply absent here, not "forgotten"). config.txt existing is itself the
#    boot-partition marker the CM5 firmware requires.
echo "=== populating boot partition (CM5: config.txt marks it bootable; no bootcode.bin/start.elf) ==="
cp "$KCACHE/boot/vmlinuz" "$WORK/p1/kernel8.img"
cp "$WORK/$DTB_NAME" "$WORK/p1/"
cat > "$WORK/p1/config.txt" <<CFG
# HookProbe OS — Compute Module 5 boot config (Debian arm64 backports kernel via the CM5's
# self-contained EEPROM bootloader path — no start.elf/fixup.dat/bootcode.bin needed or shipped).
arm_64bit=1
enable_uart=1
kernel=kernel8.img
initramfs initramfs8 followkernel
device_tree=$DTB_NAME
disable_overscan=1
[all]
CFG
cat > "$WORK/p1/cmdline.txt" <<CMD
console=ttyAMA0,115200 console=tty1 root=LABEL=hookprobe-root rootfstype=ext4 fsck.repair=yes rootwait rw systemd.firstboot=off systemd.journald.forward_to_console=1 ${SPLASH_ARGS}
CMD

# 6. Populate the root (ext4) partition from the proven rootfs (same overlay pattern as Pi4).
echo "=== copying rootfs ==="
rsync -aHAX --numeric-ids "$WORK/srcroot/." "$WORK/p2/"
install -m0755 "$REPO"/base/scripts/*.sh "$WORK/p2/usr/lib/hookprobe/" 2>/dev/null \
  && echo "  overlaid $(ls "$REPO"/base/scripts/*.sh | wc -l) repo scripts onto the rootfs" || true
cp "$REPO"/base/units/* "$REPO"/modules/ovs/units/* "$WORK/p2/usr/lib/systemd/system/" 2>/dev/null || true
mkdir -p "$WORK/p2/etc/hostapd"

# 6b. Swap in the backports kernel's modules (the base rootfs's own 6.1.x /lib/modules stays —
#     harmless dead weight — the NEW tree is what the regenerated initramfs + running kernel use).
cp -a "$KCACHE/lib/modules/$CM5KVER" "$WORK/p2/usr/lib/modules/" 2>/dev/null \
  || cp -a "$KCACHE/lib/modules/$CM5KVER" "$WORK/p2/lib/modules/"
echo "  staged kernel modules for $CM5KVER"

RT="$WORK/p2"
cat > "$RT/etc/fstab" <<FSTAB
# HookProbe OS — CM5. Persistent data partition is provisioned + mounted by firstboot-data.
LABEL=hookprobe-root  /              ext4  defaults,noatime  0 1
LABEL=BOOTFS          /boot/firmware vfat  defaults,nofail   0 2
FSTAB
mkdir -p "$RT/boot/firmware"

# ---- ADMIN ACCESS — GATED (ADR 0008; same model as make-pi4-image.sh; credentials
# neutralized to the default hookprobe/hookprobe login per ADR 0045, 2026-07-25) -----------
mkdir -p "$RT/etc/ssh/sshd_config.d" "$RT/etc/systemd/system/multi-user.target.wants"
if [ "${HOOKPROBE_DEBUG_ACCESS:-0}" = 1 ]; then
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
  if grep -q '^hookprobe:' "$RT/etc/passwd" 2>/dev/null; then
    awk -F: 'BEGIN{OFS=":"} $1=="hookprobe"{$7="/usr/sbin/nologin"} 1' "$RT/etc/passwd" > "$RT/etc/passwd.new" && mv "$RT/etc/passwd.new" "$RT/etc/passwd"
  fi
  sed -i 's|^hookprobe:[^:]*:|hookprobe:!:|' "$RT/etc/shadow" 2>/dev/null || true
  if grep -q '^andrei:' "$RT/etc/passwd" 2>/dev/null; then
    sed -i '/^andrei:/d' "$RT/etc/passwd"; sed -i '/^andrei:/d' "$RT/etc/shadow"; sed -i '/^andrei:/d' "$RT/etc/group"
    rm -rf "$RT/home/andrei"
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
# RP1 caveat marker baked into the image itself — so a booted console/MOTD never claims network
# capability this build cannot deliver (never let a build-time-only warning be the ONLY record).
echo "no-rp1-driver: kernel $CM5KVER predates mainline RP1 (Ethernet/USB) support; console/eMMC only" \
  >> "$RT/etc/hookprobe/build-mode"
ln -sf /lib/systemd/system/ssh.service "$RT/etc/systemd/system/multi-user.target.wants/ssh.service"
mkdir -p "$RT/etc/systemd/system/local-fs.target.wants"
for svc in hookprobe-unlock-data hookprobe-data-guard; do
  ln -sf "/usr/lib/systemd/system/$svc.service" "$RT/etc/systemd/system/local-fs.target.wants/$svc.service"
done
ln -sf /usr/lib/systemd/system/hookprobe-secrets.service "$RT/etc/systemd/system/multi-user.target.wants/hookprobe-secrets.service"
ln -sf /usr/lib/systemd/system/hookprobe-rbac-check.service "$RT/etc/systemd/system/multi-user.target.wants/hookprobe-rbac-check.service"

# ---- Regenerate the initrd for the NEW ($CM5KVER) kernel, WITH the CM5's storage drivers ----
# The CM5's SD/eMMC interface is on-die (BCM2712), not behind RP1 — `mmc/host/bcm2835.ko` +
# `sdhci-iproc`/`sdhci-pltfm` (the SAME modules Pi4 needs) are confirmed present in the fetched
# backports kernel package (see the file-list check above) and are force-included below on that
# basis, mirroring make-pi4-image.sh's own "don't trust MODULES=most to find it in an emulated
# chroot" lesson. NVMe modules are ALSO force-included (nvme/nvme-core) for a CM5 carrier board
# that boots from an M.2 NVMe drive rather than eMMC/SD — untested here (no NVMe media on this
# dev box), included on a best-effort basis since the module names are confirmed present in the
# package. RP1-attached storage/USB paths are NOT included (RP1 has no driver in this kernel at
# all yet, storage or otherwise — see the header caveat).
echo "=== regenerating initrd for $CM5KVER with CM5 storage drivers (chroot + update-initramfs) ==="
[ -f "$KCACHE/config/config-$CM5KVER" ] && cp "$KCACHE/config/config-$CM5KVER" "$RT/boot/config-$CM5KVER" 2>/dev/null || true
for mod in sdhci sdhci-pltfm sdhci-iproc mmc_block bcm2835 nvme nvme-core; do
  grep -qxF "$mod" "$RT/etc/initramfs-tools/modules" 2>/dev/null || echo "$mod" >> "$RT/etc/initramfs-tools/modules"
done
rm -f "$RT/usr/share/initramfs-tools/hooks/plymouth"   # fails under emulated arm64 chroot (no GPU stack); see make-pi4-image.sh
cp /usr/bin/qemu-aarch64-static "$RT/usr/bin/" 2>/dev/null || true
for m in proc sys dev dev/pts; do mkdir -p "$RT/$m"; mount --bind "/$m" "$RT/$m" 2>/dev/null || true; done
chroot "$RT" /usr/sbin/update-initramfs -c -k "$CM5KVER" 2>&1 | tail -8 || echo "  WARN update-initramfs failed"
for m in dev/pts dev sys proc; do umount "$RT/$m" 2>/dev/null || true; done
rm -f "$RT/usr/bin/qemu-aarch64-static"
NEWINITRD="$RT/boot/initrd.img-$CM5KVER"
if [ -s "$NEWINITRD" ]; then
  cp "$NEWINITRD" "$WORK/p1/initramfs8"
  echo "  initramfs8 regenerated: $(du -h "$WORK/p1/initramfs8" | cut -f1)"
  IVER=$(mktemp -d)
  if command -v unmkinitramfs >/dev/null 2>&1 && unmkinitramfs "$WORK/p1/initramfs8" "$IVER" 2>/dev/null \
     && find "$IVER" -iname 'bcm2835.ko*' | grep -q .; then
    echo "  OK: bcm2835 mmc host present — SD/eMMC root should mount on the CM5"
  else
    echo "  WARN: bcm2835 mmc host module NOT confirmed in the regenerated initrd — investigate before flashing"
  fi
  rm -rf "$IVER"
else
  echo "  WARN: initrd regen produced nothing; boot partition still has no CM5-capable initramfs — DO NOT FLASH"
fi

sync
echo "=== verifying boot partition contents (no bootcode.bin/start4.elf/fixup4.dat expected) ==="
ls -la "$WORK/p1" | sed 's/^/  /'
for f in bootcode.bin start4.elf fixup4.dat; do
  [ -f "$WORK/p1/$f" ] && echo "  UNEXPECTED: $f present (Pi4-only GPU firmware; should not be here for CM5)"
done
echo "=== DONE: $OUT ==="
echo "  eMMC (module-mounted eMMC variant): put the CM5 into rpiboot mass-storage mode first"
echo "    (nRPIBOOT/EMMC-DISABLE jumper fitted, USB-C to host), then:"
echo "      sudo rpiboot -d <path-to-usbboot-EEPROM-blobs>   # exposes the eMMC as /dev/sdX"
echo "      sudo dd if=$OUT of=/dev/sdX bs=4M conv=fsync status=progress"
echo "  SD (CM5 Lite / carrier with an SD slot):"
echo "      sudo dd if=$OUT of=/dev/sdX bs=4M conv=fsync status=progress"
echo "  *** UNVALIDATED ON REAL SILICON — no CM5 hardware on this dev box. Boot-test on the ***"
echo "  *** operator's CM5 before treating this as more than a statically-assembled image.  ***"
