#!/usr/bin/env bash
# make-pi-image.sh — THE unified Raspberry Pi fat-boot factory (ADR 0029). Assembles ONE arm64
# image that boots Pi 4, CM4, Pi 5 AND CM5 from the SAME proven HookProbe rootfs, by installing
# BOTH Raspberry-Pi-repo downstream kernels + all four boards' DTBs + both regenerated initrds
# onto one FAT32 boot partition, with the on-board SoC firmware/EEPROM selecting kernel+DTB per
# board via `config.txt` conditional filters ([pi4]/[cm4]/[pi5]/[cm5]/[all]) — the same mechanism
# Raspberry Pi OS itself uses to ship one image across all four boards.
#
# Replaces make-pi4-image.sh + make-cm5-image.sh (kept for now as thin, superseded scripts — see
# their headers). Read docs/adr/0029-unified-pi-fatboot-dual-kernel.md before touching this file;
# it is the accepted design this script implements verbatim.
#
# *** WHY A NON-DEBIAN KERNEL (the ADR 0029 D3 tradeoff, stated here too) ***
#   BCM2712's RP1 southbridge (Gigabit Ethernet MAC + USB 2/3) has NO mainline Linux driver
#   before ~6.17, working Ethernet/USB only ~6.18 (Phoronix/SUSE upstreaming, raspberrypi/linux
#   issue tracking, confirmed 2026-07-08); Debian bookworm-backports tops out at 6.12.x. The
#   Raspberry Pi Foundation's OWN downstream kernel (archive.raspberrypi.com/debian) has carried
#   full RP1 support + every Pi DTB (Pi4/CM4/Pi5/CM5) for over a year. This script therefore
#   fetches TWO Raspberry-Pi-repo kernel packages (`linux-image-rpi-v8` for BCM2711 Pi4/CM4,
#   `linux-image-rpi-2712` for BCM2712 Pi5/CM5) instead of Debian's — a real supply-chain cost
#   (vendor fork, not the Debian archive), pinned + GPG-verified + SBOM-tracked (base/drivers/
#   SOURCES.md), CONFINED to this one factory script (mkosi.conf / the arm64-UEFI/virt rootfs
#   stay 100% Debian-canon — ADR 0029 D2). The rootfs — bootstrap, supervisor, Wasm/.cwasm
#   modules, trust store, manifest schema — is untouched and shared with every other platform;
#   only the kernel + boot wrapper (which the "Base" abstraction is meant to absorb) differs.
#
# *** VERIFIED GROUND TRUTH (2026-07-08, direct `dpkg-deb -c`/`grep config-<kver>` inspection of
#     the REAL pinned .deb files — not assumed; see base/drivers/SOURCES.md for the full record)
#     THAT REFINES ADR 0029 D2's initramfs-union assumption: ***
#   The RPi downstream kernels build their ENTIRE storage stack in (CONFIG_MMC_BLOCK=y,
#   CONFIG_MMC_BCM2835[_MMC]=y, CONFIG_MMC_SDHCI_IPROC=y, CONFIG_USB_DWC2=y,
#   CONFIG_NVME_CORE=y, CONFIG_BLK_DEV_NVME=y — confirmed in BOTH kernels' shipped
#   /boot/config-<kver>), NOT as loadable modules. Unlike Debian's modular kernel (which is why
#   make-pi4-image.sh had to force sdhci-iproc et al into the regenerated initrd), these RPi
#   kernels do not need ANY storage driver in the initramfs to mount root — it is already linked
#   into vmlinuz. This script still force-lists the ADR 0029 D2 module-name union into
#   /etc/initramfs-tools/modules (defense-in-depth: harmless no-op today, a real safety net if a
#   future RPi kernel bump ever demotes one of these to modular without this script being
#   updated) and records the config-<kver> CONFIG_*=y evidence into the kernel-config cache so
#   the boot-partition gate (verify-pi-bootpart.sh) can assert storage support from authoritative
#   kernel config, not a fragile "grep the initrd for a .ko that was never going to be there"
#   check. sdhci-of-arasan and sdhci-pltfm are NOT set in either kernel (the RPi boards use the
#   iproc/bcm2835 controllers, not the arasan/generic-platform ones) — kept in the force-list
#   for documentation parity with the ADR matrix and as a no-op safety net only.
#
# Needs sudo (loop/mkfs/mount/chroot), same privilege model as make-pi4-image.sh. NOT
# boot-testable here (no Pi5/CM5/CM4 hardware on this dev box) — this script assembles +
# statically verifies the image; on-silicon validation (RP1 Ethernet/USB actually coming up on
# real CM5/Pi5, and re-proving Pi4 is not regressed) happens on the operator's hardware.
#
#   sudo builder/mkosi-arm64/make-pi-image.sh [SRC.raw] [OUT.img] [SIZE_GB]
#
# Env knobs (same gated model as make-pi4-image.sh):
#   HOOKPROBE_DEBUG_ACCESS=1   opt-in debug login (hookprobe/root passwords, password SSH).
#                              Default OFF = release-mode, key-only SSH, no default password user.
#   HOOKPROBE_SPLASH=1         Plymouth boot splash (kept off during bring-up/debug).
#   HOOKPROBE_VERITY=1         H3b whole-root dm-verity seal (opt-in).
#   HOOKPROBE_USR_VERITY=1     H3 /usr-only dm-verity seal (opt-in, the CORRECT design).
#   --board pi4|cm4|pi5|cm5    build a SLIMMER single-board image (one kernel, one DTB set) for
#                              a constrained SD — the default (no flag) always produces the ONE
#                              unified image that boots all four boards (ADR 0029 D4).
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)

BOARD_FILTER="all"
POSITIONAL=()
while [ $# -gt 0 ]; do
  case "$1" in
    --board) BOARD_FILTER="$2"; shift 2 ;;
    --board=*) BOARD_FILTER="${1#--board=}"; shift ;;
    *) POSITIONAL+=("$1"); shift ;;
  esac
done
set -- "${POSITIONAL[@]+"${POSITIONAL[@]}"}"

SRC=${1:-$HERE/hookprobe-os-arm64.raw}
OUT=${2:-$HERE/hookprobe-os-pi.img}
SIZE_GB=${3:-8}   # default 8G: the base rootfs (~1.7G) + BOTH RPi kernel module trees (~106M each)
                  # + 2 initrds + 2 BTF blobs overflow a 2G image; 8G is safe for every documented
                  # CM5 eMMC variant (16/32/64/128G) and clears the HOOKPROBE_USR_VERITY floor.
                  # (2026-07-09: default was 2G — undersized, fails late via mkfs/rsync ENOSPC.)
# GUARD (2026-07-09): this script's fixed MBR layout is p1=512MiB (boot, TWO kernels) + p2=1.5GiB
# (root, fixed) when HOOKPROBE_USR_VERITY=1 — that is EXACTLY 2GiB before p3 (/usr, verity-sealed)
# gets a single byte. The default/positional SIZE_GB=2 therefore makes sfdisk try to start p3 past
# the end of the truncated device and FAILS outright. This unified image also carries BOTH RPi
# kernels' module trees in /usr (unlike the single-kernel make-pi4-image.sh, whose own header notes
# "Requires SIZE_GB >= 4" for the same p1/p2 split) — so the safe floor here is higher. Fail fast
# with a clear message instead of a cryptic sfdisk error.
if [ "${HOOKPROBE_USR_VERITY:-0}" = 1 ] && [ "$SIZE_GB" -lt 6 ]; then
  echo "ABORT: HOOKPROBE_USR_VERITY=1 needs SIZE_GB >= 6 on this dual-kernel unified image" >&2
  echo "       (p1 512MiB boot + p2 1.5GiB fixed root == 2GiB already, before /usr's p3 gets any" >&2
  echo "       space at all; this image also carries BOTH v8+2712 kernel module trees in /usr)." >&2
  echo "       Pass a larger SIZE_GB as the 3rd positional arg, e.g.:" >&2
  echo "         sudo $0 $SRC $OUT 8" >&2
  exit 1
fi
# Non-verity path floor (2026-07-09): even without the /usr split, p1 512MiB boot + the base rootfs
# (~1.7GiB) + BOTH kernel module trees leave a 2GiB image with a negative p2 — it fails late via
# mkfs/rsync ENOSPC instead of up front. Fail fast with the same clear guidance as the verity path.
if [ "${HOOKPROBE_USR_VERITY:-0}" != 1 ] && [ "$SIZE_GB" -lt 4 ]; then
  echo "ABORT: this dual-kernel unified image needs SIZE_GB >= 4 (p1 512MiB boot + ~1.7GiB rootfs +" >&2
  echo "       two RPi kernel module trees). Pass e.g.:  sudo $0 $SRC $OUT 8" >&2
  exit 1
fi
SPLASH_ARGS=""
[ "${HOOKPROBE_SPLASH:-0}" = 1 ] && SPLASH_ARGS="quiet splash loglevel=3 vt.global_cursor_default=0 plymouth.ignore-serial-consoles"

# ---- Pinned Raspberry Pi repo inputs (base/drivers/SOURCES.md is the single source of truth for
#      these — DO NOT hand-edit a version/digest here without updating that file too). The
#      *_SHA values are re-verified against the actual fetched .deb bytes below (defense-in-depth
#      ON TOP of apt's own Release-file hash check — never trust one layer alone). ----
RPI_REPO_URL="https://archive.raspberrypi.com/debian"
RPI_KEYRING="$HERE/rpi-keyring/raspberrypi-archive-keyring.gpg"
RPI_SOURCES="$HERE/raspberrypi.sources"
V8_META_VER="6.12.93-1+rpt1";    V8_META_SHA="08fb6d6f03f67e8f0b8a887d1dd7260166cf62b6434d902858f1b8f0010ed25e"
V8_KVER="6.12.93+rpt-rpi-v8";    V8_KVER_SHA="ab27b24177b6ccd247e385b88a5bf80159acd6fce84e6b602b5a8c21b4869362"
K2712_META_VER="6.12.93-1+rpt1"; K2712_META_SHA="3197526321f3b81e74d3f58fb454a5345e0a6c854851180a23525c29c772c6ec"
K2712_KVER="6.12.93+rpt-rpi-2712"; K2712_KVER_SHA="82bedbb36f23dfa0f164df1f805f6d84e70964c47e6e49b014b0b9c8578a83cd"
# CO-RE BTF (ADR 0029/0030): the RPi Foundation kernels do NOT set CONFIG_DEBUG_INFO_BTF, so
# /sys/kernel/btf/vmlinux is absent at runtime and every CO-RE eBPF loader (napse-quarantine,
# napse-l2guard) fails `libbpf: kernel BTF is missing ... -ESRCH`. Fix: fetch the matching `-dbg`
# packages (same 1:-epoch handling as the kernels above), extract each debug vmlinux, run pahole to
# emit a detached BTF blob, and stage it at /usr/lib/hookprobe/btf/vmlinux-<uname -r>.btf — the
# loaders point libbpf's btf_custom_path at it (hookprobe-manifest::xdp::apply_btf_custom_path).
# The `-dbg` .deb SHA-256s below are PENDING first real fetch: the coordinator's arm64 build host
# (with archive.raspberrypi.com egress) fills them from the digest re-check the script prints, same
# discipline as every other pin. Both are version 1:6.12.93-1+rpt1 (same source as the kernels).
V8_DBG_VER="6.12.93-1+rpt1";     V8_DBG_SHA="PENDING-FILL-ON-FIRST-FETCH"
K2712_DBG_VER="6.12.93-1+rpt1";  K2712_DBG_SHA="PENDING-FILL-ON-FIRST-FETCH"
FW_VER="1.20260521-1~bookworm"; FW_SHA="c660bb5a40e1d48a5e2f8306b87ceaa013f870d2be4139195920898f3ac8713d"
KEYRING_VER="2021.1.1+rpt1"; KEYRING_SHA="df027ffdd7c400a7e3fc806a681a2db079eccefc7043f23a751fddebffe49e48"

# ADR 0032 — opt-in BTF-enabled edge kernel (downstream RPi kernel RE-COMPILED with
# CONFIG_DEBUG_INFO_BTF=y). It IS the downstream kernel, so DTBs + config.txt are UNCHANGED;
# only the kernel binary + its modules are substituted (native /sys/kernel/btf/vmlinux -> CO-RE
# eBPF loads with no sideload, on ALL RPi boards). Default 0 = ship the stock -rpt kernel
# unchanged (metal-proven path). Set HOOKPROBE_EDGE_KERNEL=1 + EDGE_DEB_2712 (and optionally
# EDGE_DEB_V8) pointing at builder/kernel-build/out/linux-image-*-hookprobe-edge_*_arm64.deb.
# Build them with builder/build-edge-kernel.sh (FLAVOUR=2712 / FLAVOUR=v8). Not metal-confirmed yet.
HOOKPROBE_EDGE_KERNEL="${HOOKPROBE_EDGE_KERNEL:-0}"
# Auto-discover the real edge debs by glob (build-edge-kernel.sh writes them directly under
# builder/kernel-build/ as linux-image-<KREL>_<ver>-hookprobe1_arm64.deb — NOT under out/, and the
# 2712 flavour's KREL contains "2712" while the Pi4/CM4 flavour's contains "v8"). FIX (2026-07-09,
# defect-006 follow-up): the old hardcoded default `out/linux-image-2712-hookprobe.deb` never
# existed, so HOOKPROBE_EDGE_KERNEL=1 silently fell back to the stock no-BTF kernel. Pick the
# NEWEST match per flavour; an explicit EDGE_DEB_* env still overrides.
# NAMING NOTE: build-edge-kernel.sh's RPi 2712 flavour (bcm2712_defconfig, Pi5/CM5, 16K page)
# localversions its KREL as "-v8-16k" (NOT "-2712"); the Pi4/CM4 flavour (bcm2711_defconfig, 4K)
# is plain "-v8". So the KCACHE/2712 (Pi5/CM5) slot takes the *-v8-16k-* deb and KCACHE/v8
# (Pi4/CM4) takes the *-v8-* (non-16k) deb. Both carry CONFIG_DEBUG_INFO_BTF=y + the CM5 DTBs.
_kb="$HERE/../kernel-build"
EDGE_DEB_2712="${EDGE_DEB_2712:-$(ls -t "$_kb"/linux-image-*-v8-16k-hookprobe-edge_*_arm64.deb 2>/dev/null | head -1)}"
EDGE_DEB_V8="${EDGE_DEB_V8:-$(ls -t "$_kb"/linux-image-*-v8-hookprobe-edge_*_arm64.deb 2>/dev/null | grep -v -- '-v8-16k-' | head -1)}"

KCACHE="$HERE/pi-kernel-cache"      # both RPi kernel trees + configs (cached, offline-repeatable)
FWCACHE="$HERE/pi-firmware-cache"   # raspi-firmware blobs (start4.elf etc + overlays)
WORK=$(mktemp -d /tmp/hp-pi.XXXXXX)
[ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 1; }
[ -f "$SRC" ] || { echo "source image $SRC not found (build the arm64 image first)"; exit 1; }
[ -s "$RPI_KEYRING" ] || { echo "missing vendored keyring: $RPI_KEYRING"; exit 1; }

cleanup() {
  set +e
  for m in dev/pts dev sys proc; do umount "$WORK/p2/$m" 2>/dev/null; done
  for m in "$WORK"/srcroot "$WORK"/p1 "$WORK"/p2 "$WORK"/p3; do mountpoint -q "$m" && umount "$m"; done
  [ -n "${SRCLOOP:-}" ] && losetup -d "$SRCLOOP" 2>/dev/null
  [ -n "${OUTLOOP:-}" ] && losetup -d "$OUTLOOP" 2>/dev/null
  rm -rf "$WORK"
}
trap cleanup EXIT
mkdir -p "$WORK"/{srcroot,p1,p2,p3}

wait_parts() { # loopdev
  udevadm settle 2>/dev/null || true
  for _ in $(seq 1 30); do
    [ -b "${1}p1" ] && [ -b "${1}p2" ] && return 0
    partprobe "$1" 2>/dev/null || true; sleep 0.5
  done
  [ -b "${1}p1" ] || { echo "partition nodes for $1 never appeared"; return 1; }
}

# 1. Fetch BOTH Raspberry Pi kernels + raspi-firmware from the RPi repo (pinned, GPG-verified via
#    the scoped keyring — Signed-By confined to raspberrypi.sources, never a system-wide anchor;
#    ADR 0029 D3.2). Cached so repeat runs are offline. Non-privileged podman fetch, same pattern
#    make-pi4-image.sh already used for Debian's raspi-firmware.
# The -dbg (DWARF) fetch + pahole BTF-sideload exists ONLY to give the STOCK RPi kernels CO-RE BTF
# (they ship CONFIG_DEBUG_INFO_BTF=n). With HOOKPROBE_EDGE_KERNEL=1 the edge kernels carry NATIVE
# BTF (built CONFIG_DEBUG_INFO_BTF=y — ADR 0032), so /sys/kernel/btf/vmlinux is populated at boot
# and NO sideload blob is needed. Skip the whole -dbg/pahole path in that case (2026-07-09).
NEED_DBG_BTF=1; [ "$HOOKPROBE_EDGE_KERNEL" = 1 ] && NEED_DBG_BTF=0
if [ ! -d "$KCACHE/v8/lib/modules" ] || [ ! -d "$KCACHE/2712/lib/modules" ] || [ ! -f "$FWCACHE/start4.elf" ] \
   || { [ "$NEED_DBG_BTF" = 1 ] && { [ ! -f "$KCACHE/v8/vmlinux-dbg" ] || [ ! -f "$KCACHE/2712/vmlinux-dbg" ]; }; }; then
  echo "=== fetching pinned Raspberry Pi kernels + firmware ($RPI_REPO_URL; cached) ==="
  mkdir -p "$KCACHE"/{v8,2712,debs} "$FWCACHE"
  podman run --rm \
    -v "$KCACHE:/out:Z" -v "$FWCACHE:/fw:Z" -v "$RPI_KEYRING:/rpi-keyring/raspberrypi-archive-keyring.gpg:ro,Z" \
    -v "$RPI_SOURCES:/etc/apt/sources.list.d/raspberrypi.sources:ro,Z" \
    --arch arm64 docker.io/arm64v8/debian:bookworm bash -c "
    set -e
    # The minimal debian:bookworm image has NO ca-certificates, so Debian's repo works (http)
    # but the RPi repo (https://archive.raspberrypi.com) fails TLS verification and its packages
    # go 'unlocatable'. Install certs from Debian first (this update ignores the not-yet-trusted
    # RPi repo), then re-update so the RPi HTTPS cert verifies and its packages resolve.
    apt-get update -q || true
    apt-get install -y -q --no-install-recommends ca-certificates >/dev/null
    apt-get update -q
    cd /tmp
    # Pin exact versions — never 'latest' (ADR 0029 D3.1). apt-get download refuses a version
    # mismatch outright, which is itself a live check that the pinned version still exists.
    # RPi linux-image + raspi-firmware carry apt epoch '1:'; the .deb FILENAMES drop it, so the
    # version vars stay epoch-less for the filename paths below and the epoch is added ONLY here
    # in the download spec (keyring has no epoch).
    # The two '-dbg' packages carry the DWARF debug vmlinux we pahole into a detached BTF blob on
    # the host (CO-RE BTF for the BSP kernels — see the SOURCES.md/header note). Same 1:-epoch.
    apt-get download raspberrypi-archive-keyring=${KEYRING_VER} raspi-firmware=1:${FW_VER} \
      linux-image-rpi-v8=1:${V8_META_VER} 'linux-image-${V8_KVER}=1:${V8_META_VER}' \
      linux-image-rpi-2712=1:${K2712_META_VER} 'linux-image-${K2712_KVER}=1:${K2712_META_VER}' \
      'linux-image-${V8_KVER}-dbg=1:${V8_DBG_VER}' 'linux-image-${K2712_KVER}-dbg=1:${K2712_DBG_VER}' >/dev/null
    # apt-get download URL-encodes the epoch ':' as '%3a' in .deb filenames (e.g.
    # linux-image-..._1%3a6.12.93-1+rpt1_arm64.deb). Strip it so the epoch-less path
    # constructions below (and verify_deb) match -- the epoch lives only in the apt version spec.
    for f in *1%3a*.deb; do mv \"\$f\" \"\${f/1%3a/}\"; done
    for f in *.deb; do dpkg-deb -x \"\$f\" \"x-\$f.d\"; done
    cp -a *.deb /out/debs/
    mkdir -p /out/v8/lib/modules /out/v8/boot /out/v8/broadcom /out/v8/overlays
    mkdir -p /out/2712/lib/modules /out/2712/boot /out/2712/broadcom /out/2712/overlays
    cp -a \"x-linux-image-${V8_KVER}_${V8_META_VER}_arm64.deb.d/lib/modules/${V8_KVER}\" /out/v8/lib/modules/
    cp \"x-linux-image-${V8_KVER}_${V8_META_VER}_arm64.deb.d/boot/vmlinuz-${V8_KVER}\" /out/v8/boot/vmlinuz
    cp \"x-linux-image-${V8_KVER}_${V8_META_VER}_arm64.deb.d/boot/config-${V8_KVER}\" /out/v8/config
    cp -a \"x-linux-image-${V8_KVER}_${V8_META_VER}_arm64.deb.d/usr/lib/linux-image-${V8_KVER}/broadcom/.\" /out/v8/broadcom/
    cp -a \"x-linux-image-${V8_KVER}_${V8_META_VER}_arm64.deb.d/usr/lib/linux-image-${V8_KVER}/overlays/.\" /out/v8/overlays/ 2>/dev/null || true
    cp -a \"x-linux-image-${K2712_KVER}_${K2712_META_VER}_arm64.deb.d/lib/modules/${K2712_KVER}\" /out/2712/lib/modules/
    cp \"x-linux-image-${K2712_KVER}_${K2712_META_VER}_arm64.deb.d/boot/vmlinuz-${K2712_KVER}\" /out/2712/boot/vmlinuz
    cp \"x-linux-image-${K2712_KVER}_${K2712_META_VER}_arm64.deb.d/boot/config-${K2712_KVER}\" /out/2712/config
    cp -a \"x-linux-image-${K2712_KVER}_${K2712_META_VER}_arm64.deb.d/usr/lib/linux-image-${K2712_KVER}/broadcom/.\" /out/2712/broadcom/
    cp -a \"x-linux-image-${K2712_KVER}_${K2712_META_VER}_arm64.deb.d/usr/lib/linux-image-${K2712_KVER}/overlays/.\" /out/2712/overlays/ 2>/dev/null || true
    dpkg-deb -x \"raspi-firmware_${FW_VER}_all.deb\" x-fw
    cp x-fw/usr/lib/raspi-firmware/start4.elf x-fw/usr/lib/raspi-firmware/fixup4.dat \
       x-fw/usr/lib/raspi-firmware/bootcode.bin /fw/
    cp -r x-fw/usr/lib/raspi-firmware/overlays /fw/ 2>/dev/null || true
    # Cache each -dbg package's DWARF debug vmlinux (the 'for f in *.deb' loop above already
    # dpkg-deb -x'd every deb, -dbg included). RPi/Debian packaging puts it under
    # /usr/lib/debug/{boot,lib/modules/<kver>}/vmlinux* — use find so either layout works; pahole
    # runs on the HOST outside this emulated container (see the BTF-gen step below).
    cp -a \"\$(find \"x-linux-image-${V8_KVER}-dbg_${V8_DBG_VER}_arm64.deb.d\" -name 'vmlinux*' -type f | head -1)\"    /out/v8/vmlinux-dbg
    cp -a \"\$(find \"x-linux-image-${K2712_KVER}-dbg_${K2712_DBG_VER}_arm64.deb.d\" -name 'vmlinux*' -type f | head -1)\" /out/2712/vmlinux-dbg
    echo '${V8_KVER}'    > /out/v8/KVER
    echo '${K2712_KVER}' > /out/2712/KVER
  "
  # Defense-in-depth digest re-check on the HOST (outside the container, no network) against the
  # pinned SHA-256 table above / base/drivers/SOURCES.md — on TOP of apt's own Release-signature
  # hash check inside the container. A mismatch here means the archive served something other
  # than what SOURCES.md pinned, and this script refuses to use it.
  echo "=== re-verifying fetched .deb digests against base/drivers/SOURCES.md pins ==="
  verify_deb() { # glob-prefix sha
    local f; f=$(ls "$KCACHE"/debs/"$1"*.deb 2>/dev/null | head -1)
    [ -n "$f" ] || { echo "ABORT: expected .deb matching $1*.deb not found in $KCACHE/debs"; exit 1; }
    local got; got=$(sha256sum "$f" | cut -d' ' -f1)
    [ "$got" = "$2" ] || { echo "ABORT: $f SHA-256 mismatch (got=$got want=$2)"; exit 1; }
    echo "  OK  $(basename "$f")"
  }
  verify_deb "raspberrypi-archive-keyring_${KEYRING_VER}"      "$KEYRING_SHA"
  verify_deb "raspi-firmware_${FW_VER}"                        "$FW_SHA"
  verify_deb "linux-image-rpi-v8_${V8_META_VER}"                "$V8_META_SHA"
  verify_deb "linux-image-${V8_KVER}_${V8_META_VER}"            "$V8_KVER_SHA"
  verify_deb "linux-image-rpi-2712_${K2712_META_VER}"           "$K2712_META_SHA"
  verify_deb "linux-image-${K2712_KVER}_${K2712_META_VER}"      "$K2712_KVER_SHA"
  # The two -dbg debs. Until their SHAs are pinned (PENDING first fetch), print the observed digest
  # loudly so the coordinator can drop it into SOURCES.md / the *_DBG_SHA vars, but do NOT hard-fail
  # the very first fetch on a placeholder. Once pinned, this is a strict re-check like the rest.
  verify_dbg() { # glob-prefix pinned-sha kver-label
    local f; f=$(ls "$KCACHE"/debs/"$1"*.deb 2>/dev/null | head -1)
    [ -n "$f" ] || { echo "ABORT: expected -dbg .deb matching $1*.deb not found in $KCACHE/debs"; exit 1; }
    local got; got=$(sha256sum "$f" | cut -d' ' -f1)
    if [ "$2" = "PENDING-FILL-ON-FIRST-FETCH" ]; then
      echo "  PIN-ME  $(basename "$f")  SHA256=$got  (set $3 in make-pi-image.sh + SOURCES.md)"
    elif [ "$got" = "$2" ]; then
      echo "  OK  $(basename "$f")"
    else
      echo "ABORT: $f SHA-256 mismatch (got=$got want=$2)"; exit 1
    fi
  }
  verify_dbg "linux-image-${V8_KVER}-dbg_${V8_DBG_VER}"        "$V8_DBG_SHA"    "V8_DBG_SHA"
  verify_dbg "linux-image-${K2712_KVER}-dbg_${K2712_DBG_VER}"  "$K2712_DBG_SHA" "K2712_DBG_SHA"
fi
if [ "$NEED_DBG_BTF" = 1 ]; then
  [ -s "$KCACHE/v8/vmlinux-dbg" ] && [ -s "$KCACHE/2712/vmlinux-dbg" ] || { echo "debug vmlinux extraction failed (need the -dbg packages for CO-RE BTF)"; exit 1; }
fi

# 1b. Generate a detached CO-RE BTF blob per RPi kernel on the BUILD HOST (pahole reads the DWARF
#     debug vmlinux — cross-arch is fine, BTF is arch-neutral). Cached alongside the kernels so
#     repeat runs are offline. Validated with bpftool before it is trusted. (ADR 0029/0030: shipped
#     BTF blob until the single-kernel convergence gives us a CONFIG_DEBUG_INFO_BTF=y kernel.)
#     SKIPPED entirely under HOOKPROBE_EDGE_KERNEL=1 — the edge kernel has native BTF (ADR 0032).
if [ "$NEED_DBG_BTF" = 1 ] && { [ ! -s "$KCACHE/v8/vmlinux.btf" ] || [ ! -s "$KCACHE/2712/vmlinux.btf" ]; }; then
  command -v pahole >/dev/null || { echo "ABORT: pahole not on build host — needed to encode CO-RE BTF for the RPi kernels (apt install dwarves)"; exit 1; }
  echo "=== generating detached CO-RE BTF blobs (pahole) for the RPi kernels ==="
  gen_btf() { # dbg-vmlinux out.btf
    pahole --btf_encode_detached="$2" "$1" \
      || { echo "ABORT: pahole failed to encode BTF from $1"; exit 1; }
    # Validate the blob is well-formed BTF before we ship it. bpftool's per-kernel wrapper often
    # can't self-locate; fall back to the real binary under /usr/lib/linux-tools/*/bpftool.
    local bt; bt=$(command -v bpftool || true)
    "$bt" btf dump file "$2" format raw >/dev/null 2>&1 \
      || bt=$(ls /usr/lib/linux-tools/*/bpftool 2>/dev/null | head -1)
    if [ -n "$bt" ] && "$bt" btf dump file "$2" format raw >/dev/null 2>&1; then
      echo "  OK  $(basename "$2")  $(stat -c%s "$2") bytes  (bpftool-validated well-formed BTF)"
    else
      echo "  WARN no working bpftool to validate $(basename "$2") — shipping unvalidated ($(stat -c%s "$2") bytes)"
    fi
  }
  gen_btf "$KCACHE/v8/vmlinux-dbg"   "$KCACHE/v8/vmlinux.btf"
  gen_btf "$KCACHE/2712/vmlinux-dbg" "$KCACHE/2712/vmlinux.btf"
fi
if [ "$NEED_DBG_BTF" = 1 ]; then
  [ -s "$KCACHE/v8/vmlinux.btf" ] && [ -s "$KCACHE/2712/vmlinux.btf" ] || { echo "CO-RE BTF blob generation failed"; exit 1; }
fi
[ -f "$KCACHE/v8/KVER" ] && [ -f "$KCACHE/2712/KVER" ] || { echo "RPi kernel fetch failed"; exit 1; }
V8=$(cat "$KCACHE/v8/KVER"); K2712=$(cat "$KCACHE/2712/KVER")
echo "  linux-image-rpi-v8:   $V8"
echo "  linux-image-rpi-2712: $K2712"
[ -f "$KCACHE/v8/broadcom/bcm2711-rpi-4-b.dtb" ]        || { echo "missing bcm2711-rpi-4-b.dtb in v8 package"; exit 1; }
[ -f "$KCACHE/v8/broadcom/bcm2711-rpi-cm4.dtb" ]        || { echo "missing bcm2711-rpi-cm4.dtb in v8 package"; exit 1; }
[ -f "$KCACHE/2712/broadcom/bcm2712-rpi-5-b.dtb" ]      || { echo "missing bcm2712-rpi-5-b.dtb in 2712 package"; exit 1; }
[ -f "$KCACHE/2712/broadcom/bcm2712-rpi-cm5-cm5io.dtb" ] || { echo "missing bcm2712-rpi-cm5-cm5io.dtb in 2712 package"; exit 1; }
echo "  all four DTBs confirmed present in the pinned RPi kernel packages"

# ADR 0032 — substitute the BTF-enabled edge kernel over the stock -rpt kernel in KCACHE.
# The edge deb IS the downstream kernel recompiled with BTF, so its layout matches the stock
# deb exactly (boot/vmlinuz-*, lib/modules/<rel>/, usr/lib/linux-image-<rel>/broadcom/*.dtb):
# we overlay vmlinuz + modules + DTBs and update the KVER marker; DTBs/config.txt/initrd flow
# downstream are byte-identical. Native BTF makes the -dbg sideload blob (gen_btf) redundant but
# harmless — apply_btf_custom_path finds /sys/kernel/btf/vmlinux at runtime regardless.
substitute_edge() {  # $1=flavour(v8|2712)  $2=edge deb path
  local fl="$1" deb="$2" tmp rel
  # FAIL LOUD (2026-07-09): HOOKPROBE_EDGE_KERNEL=1 is an explicit operator request for the BTF
  # kernel (the ONLY working CO-RE path — the stock -rpt/-dbg sideload is dead, ADR 0032). Silently
  # falling back to the stock no-BTF kernel here is exactly how a "detecting" image ships with
  # napse-* crash-looping -ESRCH on metal. If the flag is set and the deb is missing, ABORT.
  [ -f "$deb" ] || { echo "FATAL: HOOKPROBE_EDGE_KERNEL=1 but the $fl edge deb is absent ('$deb'). Build it (builder/build-edge-kernel.sh FLAVOUR=$([ "$fl" = 2712 ] && echo 2712 || echo v8)) or pass EDGE_DEB_${fl^^}=. Refusing to ship a stock no-BTF kernel as an 'edge' image." >&2; exit 1; }
  tmp=$(mktemp -d); dpkg-deb -x "$deb" "$tmp"
  rel=$(ls "$tmp/lib/modules" | head -1)
  [ -n "$rel" ] || { echo "  ADR 0032: edge deb $deb has no /lib/modules — skipping"; rm -rf "$tmp"; return; }
  echo "  ADR 0032: substituting BTF edge kernel $rel over stock $fl"
  cp "$tmp/boot/vmlinuz-$rel" "$KCACHE/$fl/boot/vmlinuz"
  rm -rf "$KCACHE/$fl/lib/modules"; mkdir -p "$KCACHE/$fl/lib/modules"
  cp -a "$tmp/lib/modules/$rel" "$KCACHE/$fl/lib/modules/"
  cp "$tmp/usr/lib/linux-image-$rel/broadcom/"*.dtb "$KCACHE/$fl/broadcom/" 2>/dev/null || true
  # FIX (2026-07-09): also substitute the REAL edge-kernel .config over the stock one. Without this,
  # $KCACHE/$fl/config stays the STOCK RPi kernel's .config (no CONFIG_DEBUG_INFO_BTF=y) while it
  # gets shipped into the rootfs as /boot/config-$rel (rel = the EDGE kernel's release string) —
  # a false-provenance mismatch: the on-disk config would not match the kernel actually booted/
  # installed. The edge .deb carries its own config at boot/config-<rel>; use that instead.
  if [ -f "$tmp/boot/config-$rel" ]; then
    cp "$tmp/boot/config-$rel" "$KCACHE/$fl/config"
  else
    echo "  ADR 0032 WARN: edge deb $deb has no boot/config-$rel — leaving stock config in KCACHE (provenance mismatch risk)"
  fi
  echo "$rel" > "$KCACHE/$fl/KVER"
  rm -rf "$tmp"
}
if [ "$HOOKPROBE_EDGE_KERNEL" = 1 ]; then
  substitute_edge 2712 "$EDGE_DEB_2712"
  [ -n "$EDGE_DEB_V8" ] && substitute_edge v8 "$EDGE_DEB_V8"
  V8=$(cat "$KCACHE/v8/KVER"); K2712=$(cat "$KCACHE/2712/KVER")
fi

ls "$FWCACHE/start4.elf" "$FWCACHE/fixup4.dat" "$FWCACHE/bootcode.bin" >/dev/null || { echo "firmware blob fetch failed"; exit 1; }

# 2. Pull the ROOTFS out of the proven arm64 image (SAME source as make-pi4-image.sh — one
#    rootfs, three boot substrates, ADR 0019/0029 D2). The Debian kernel + UKI on the source
#    image's p1 (ESP) is NOT used here at all — the RPi kernels above replace it entirely; the
#    source rootfs's own /lib/modules/<debian-kver> tree stays as harmless dead weight (same
#    lesson make-cm5-image.sh already recorded).
echo "=== extracting rootfs from $SRC ==="
SRCLOOP=$(losetup --show -fP "$SRC"); wait_parts "$SRCLOOP"
mount -o ro "${SRCLOOP}p2" "$WORK/srcroot"

# 2b. Precheck the base rootfs BEFORE consuming it (field defect 006, 2026-07-09). This script is
#     a BOOT-layer transform only — it TRUSTS the base rootfs to already carry the hookprobe
#     payload (modules/trust/schema/platforms; see this file's header). When the base rootfs was
#     baked from a half-staged mkosi.extra (build-arm64.sh aborted before stage-apply), that trust
#     is misplaced: platforms/ is EMPTY → bootstrap has no fallback → the manifest is never written
#     → supervisor crash-loops. Fail LOUD and EARLY here instead of silently assembling a
#     boot-broken image. (verify-image-payload.sh re-checks the finished image as suspenders.)
SR="$WORK/srcroot"; SRC_BAD=0
for f in usr/share/hookprobe/platforms/generic.yaml usr/share/hookprobe/schema/manifest.schema.json \
         usr/lib/hookprobe/hookprobe-bootstrap usr/lib/hookprobe/hookprobe-supervisor; do
  [ -e "$SR/$f" ] || { echo "  base-rootfs MISSING: /$f"; SRC_BAD=1; }
done
for d in usr/share/hookprobe/trust usr/lib/hookprobe/modules; do
  [ -d "$SR/$d" ] && [ -n "$(ls -A "$SR/$d" 2>/dev/null)" ] || { echo "  base-rootfs EMPTY/MISSING dir: /$d"; SRC_BAD=1; }
done
if [ "$SRC_BAD" -ne 0 ]; then
  echo "FATAL: base rootfs $SRC is INCOMPLETE (payload dropped — cf. field defect 006). Rebuild it:" >&2
  echo "       builder/mkosi-arm64/build-arm64.sh   # must succeed AND print 'staging complete'" >&2
  echo "       sudo mkosi --force build             # regenerates hookprobe-os-arm64.raw" >&2
  echo "  then re-run this script. Refusing to assemble a boot-broken image." >&2
  exit 1
fi
echo "  base rootfs payload precheck OK (platforms + schema + trust + modules + binaries present)"

# 3. Build the SD/eMMC image: p1 vfat boot (512M — TWO kernels + TWO initrds + FOUR DTBs +
#    overlays + Pi4 GPU firmware no longer fit 256M, ADR 0029 "bigger boot partition") + p2 ext4
#    root (rest). MBR (dos) — the canonical Pi layout; CM5/Pi5's EEPROM bootloader is documented
#    to need only "a FAT partition + config.txt present", same as Pi4's start4.elf path.
echo "=== building $OUT (${SIZE_GB}G: 512M vfat boot + ext4 root) ==="
rm -f "$OUT"; truncate -s "${SIZE_GB}G" "$OUT"
if [ "${HOOKPROBE_USR_VERITY:-0}" = 1 ]; then
  sfdisk "$OUT" >/dev/null <<'PARTS'
label: dos
unit: sectors
start=2048, size=1048576, type=c, bootable
start=1050624, size=3145728, type=83
start=4196352, type=83
PARTS
else
  sfdisk "$OUT" >/dev/null <<'PARTS'
label: dos
unit: sectors
start=2048, size=1048576, type=c, bootable
start=1050624, type=83
PARTS
fi
OUTLOOP=$(losetup --show -fP "$OUT"); wait_parts "$OUTLOOP"
mkfs.vfat -F32 -n BOOTFS "${OUTLOOP}p1" >/dev/null
mkfs.ext4 -q -L hookprobe-root "${OUTLOOP}p2"
[ "${HOOKPROBE_USR_VERITY:-0}" = 1 ] && mkfs.ext4 -q -L hp-usr "${OUTLOOP}p3"
mount "${OUTLOOP}p1" "$WORK/p1"
mount "${OUTLOOP}p2" "$WORK/p2"

# 4. Populate the boot (vfat) partition: Pi4 GPU firmware (harmless-but-unused on Pi5/CM5, which
#    ignore it — their EEPROM is self-contained) + BOTH kernels + all FOUR DTBs + overlays +
#    the unified config.txt (D1) + one board-agnostic cmdline.txt.
echo "=== populating boot partition (both kernels, 4 DTBs, Pi4 GPU firmware) ==="
cp "$FWCACHE"/start4.elf "$FWCACHE"/fixup4.dat "$FWCACHE"/bootcode.bin "$WORK/p1/"
mkdir -p "$WORK/p1/overlays"
[ -d "$FWCACHE/overlays" ] && cp -r "$FWCACHE"/overlays/. "$WORK/p1/overlays/" || true
[ -d "$KCACHE/v8/overlays" ] && cp -r "$KCACHE"/v8/overlays/. "$WORK/p1/overlays/" || true
[ -d "$KCACHE/2712/overlays" ] && cp -r "$KCACHE"/2712/overlays/. "$WORK/p1/overlays/" || true
cp "$KCACHE/v8/boot/vmlinuz" "$WORK/p1/kernel8.img"
cp "$KCACHE/2712/boot/vmlinuz" "$WORK/p1/kernel_2712.img"
cp "$KCACHE/v8/broadcom/bcm2711-rpi-4-b.dtb"       "$WORK/p1/"
cp "$KCACHE/v8/broadcom/bcm2711-rpi-cm4.dtb"       "$WORK/p1/"
cp "$KCACHE/2712/broadcom/bcm2712-rpi-5-b.dtb"     "$WORK/p1/"
cp "$KCACHE/2712/broadcom/bcm2712-rpi-cm5-cm5io.dtb" "$WORK/p1/"
echo "  kernel8.img $(du -h "$WORK/p1/kernel8.img"|cut -f1) · kernel_2712.img $(du -h "$WORK/p1/kernel_2712.img"|cut -f1) · 4 DTBs staged"

# config.txt — ADR 0029 D1's explicit-filter form verbatim (deterministic boot over firmware
# auto-detect heuristics on a security appliance). `--board` builds a slimmer single-filter image
# for a constrained SD; the default (no flag) ships every filter block — ONE image, all boards.
{
cat <<'CFG'
# HookProbe OS — unified Raspberry Pi boot config (Pi4/CM4/Pi5/CM5).
# The on-board SoC firmware/EEPROM evaluates these [..] filters BEFORE Linux loads and
# routes to the matching kernel + DTB. All kernels/DTBs/initrds below are present on the
# boot partition; each board consumes only its own. See docs/adr/0029.
[all]
arm_64bit=1              # accepted+ignored on Pi5/CM5 (64-bit-only); load-bearing on Pi4/CM4
enable_uart=1
disable_overscan=1
CFG
if [ "$BOARD_FILTER" = "all" ] || [ "$BOARD_FILTER" = "pi4" ]; then
cat <<'CFG'

[pi4]
kernel=kernel8.img
initramfs initramfs8 followkernel
device_tree=bcm2711-rpi-4-b.dtb
max_framebuffers=2
arm_boost=1
CFG
fi
if [ "$BOARD_FILTER" = "all" ] || [ "$BOARD_FILTER" = "cm4" ]; then
cat <<'CFG'

[cm4]
kernel=kernel8.img
initramfs initramfs8 followkernel
device_tree=bcm2711-rpi-cm4.dtb
CFG
fi
if [ "$BOARD_FILTER" = "all" ] || [ "$BOARD_FILTER" = "pi5" ]; then
cat <<'CFG'

[pi5]
kernel=kernel_2712.img
initramfs initramfs_2712 followkernel
device_tree=bcm2712-rpi-5-b.dtb
CFG
fi
if [ "$BOARD_FILTER" = "all" ] || [ "$BOARD_FILTER" = "cm5" ]; then
cat <<'CFG'

[cm5]
kernel=kernel_2712.img
initramfs initramfs_2712 followkernel
device_tree=bcm2712-rpi-cm5-cm5io.dtb
CFG
fi
echo
echo "[all]"
} > "$WORK/p1/config.txt"

# cmdline.txt — board-agnostic: root found by LABEL, not device path, so ONE line serves all
# four boards (ADR 0029 D1).
# GAP-2/GAP-8 (2026-07-16 hardening): the Pi does NOT read bootc kargs.d, so the KSPP runtime
# hardening + Lockdown LSM enforcement must be on the cmdline here too. lockdown=integrity enforces
# signed-module-load (the edge kernel's Delta-5 MODULE_SIG) + blocks kexec/hibernate/devmem-writes
# while permitting the eBPF stack's kernel reads (NOT confidentiality). All inert on a kernel without
# the LSM/sig, so safe before the GAP-2 kernel rebuild lands; active with it.
HARDEN_KARGS="init_on_alloc=1 init_on_free=1 slab_nomerge randomize_kstack_offset=1 page_alloc.shuffle=1 lockdown=integrity"
cat > "$WORK/p1/cmdline.txt" <<CMD
console=ttyAMA0,115200 console=tty1 root=LABEL=hookprobe-root rootfstype=ext4 fsck.repair=yes rootwait rw systemd.firstboot=off systemd.journald.forward_to_console=1 ${HARDEN_KARGS} ${SPLASH_ARGS}
CMD

# 5. Populate the root (ext4) partition from the proven rootfs (unchanged from make-pi4-image.sh
#    — this is a BOOT-layer change only, the rootfs contents are the proven ones: sigma-19-rules/
#    hydra/planner/exploit/yara + the signed manifest).
echo "=== copying rootfs (this takes a moment) ==="
rsync -aHAX --numeric-ids "$WORK/srcroot/." "$WORK/p2/"
install -m0755 "$REPO"/base/scripts/*.sh "$WORK/p2/usr/lib/hookprobe/" 2>/dev/null \
  && echo "  overlaid $(ls "$REPO"/base/scripts/*.sh | wc -l) repo scripts onto the rootfs" || true
cp "$REPO"/base/units/* "$REPO"/modules/ovs/units/* "$WORK/p2/usr/lib/systemd/system/" 2>/dev/null || true
mkdir -p "$WORK/p2/etc/hostapd"
echo "  overlaid units + ensured /etc/hostapd"

# CM5/CM4 Broadcom Wi-Fi NVRAM (2026-07-09 CM5 first-boot: no SSID). Debian's firmware-brcm80211
# predates the CM5, so `brcmfmac43455-sdio.txt` (the NVRAM the driver falls back to) is absent →
# `brcmf: firmware load ... error -2` → the radio never inits → no wlan0/AP. These files (from
# RaspberryPi's rpt4 firmware, provenance in base/drivers/SOURCES.md) overlay onto the base
# firmware BEFORE the verity seal. PROVEN on the CM5 (brcmfmac 7.45.234 loads, wlan0 appears).
if [ -d "$REPO/../../os/drivers/firmware/brcm-firmware-rpt" ] && ls "$REPO"/../../os/drivers/firmware/brcm-firmware-rpt/* >/dev/null 2>&1; then
  install -d -m0755 "$WORK/p2/usr/lib/firmware/brcm"
  install -m0644 "$REPO"/../../os/drivers/firmware/brcm-firmware-rpt/* "$WORK/p2/usr/lib/firmware/brcm/" 2>/dev/null \
    && echo "  overlaid $(ls "$REPO"/../../os/drivers/firmware/brcm-firmware-rpt/ | wc -l) CM5/Pi Broadcom Wi-Fi NVRAM/firmware files"
fi
cat > "$WORK/p2/etc/fstab" <<FSTAB
# HookProbe OS — unified Pi image (Pi4/CM4/Pi5/CM5). Persistent data partition is provisioned
# + mounted by firstboot-data.
LABEL=hookprobe-root  /              ext4  defaults,noatime  0 1
LABEL=BOOTFS          /boot/firmware vfat  defaults,nofail   0 2
FSTAB
mkdir -p "$WORK/p2/boot/firmware"

# 5b. Stage BOTH kernels' module trees into the rootfs (board-agnostic manifest classification
#     picks the right profile at first boot; the running kernel's OWN /lib/modules/<kver> tree
#     is what matters post-boot, so both must be present — mirrors make-cm5-image.sh's pattern).
MODDST="$WORK/p2/usr/lib/modules"; [ -d "$MODDST" ] || MODDST="$WORK/p2/lib/modules"
mkdir -p "$MODDST"
cp -a "$KCACHE/v8/lib/modules/$V8" "$MODDST/"
cp -a "$KCACHE/2712/lib/modules/$K2712" "$MODDST/"
echo "  staged kernel modules for $V8 and $K2712 into $MODDST"

# 5c. Stage the detached CO-RE BTF blobs, named by `uname -r` so the loaders' shared
#     hookprobe-manifest::xdp::apply_btf_custom_path can resolve
#     /usr/lib/hookprobe/btf/vmlinux-$(uname -r).btf for whichever RPi kernel actually booted.
#     Without these, napse-quarantine/napse-l2guard crash-loop on `kernel BTF is missing -ESRCH`
#     because the RPi kernels lack CONFIG_DEBUG_INFO_BTF (ADR 0029/0030).
#     With HOOKPROBE_EDGE_KERNEL=1 the edge kernels carry NATIVE BTF (CONFIG_DEBUG_INFO_BTF=y,
#     ADR 0032) — /sys/kernel/btf/vmlinux is populated at boot and resolve_btf_source() prefers it
#     (KernelNative), so no staged blob is needed. Skip staging in that case.
if [ "$NEED_DBG_BTF" = 1 ]; then
  BTFDST="$WORK/p2/usr/lib/hookprobe/btf"; mkdir -p "$BTFDST"
  cp -a "$KCACHE/v8/vmlinux.btf"   "$BTFDST/vmlinux-$V8.btf"
  cp -a "$KCACHE/2712/vmlinux.btf" "$BTFDST/vmlinux-$K2712.btf"
  echo "  staged CO-RE BTF blobs: vmlinux-$V8.btf ($(du -h "$BTFDST/vmlinux-$V8.btf"|cut -f1)) · vmlinux-$K2712.btf ($(du -h "$BTFDST/vmlinux-$K2712.btf"|cut -f1))"
else
  echo "  edge kernel: native BTF (CONFIG_DEBUG_INFO_BTF=y) — no sideload blob staged (ADR 0032)"
fi

# ---- ADMIN ACCESS — GATED (ADR 0008; security-audit F1; credentials neutralized to the
# default hookprobe/hookprobe login per ADR 0045, 2026-07-25) — identical model to
# make-pi4-image.sh: debug mode elevates the existing hookprobe SERVICE account into a login
# admin instead of creating a second account.
RT="$WORK/p2"
mkdir -p "$RT/etc/ssh/sshd_config.d" "$RT/etc/systemd/system/multi-user.target.wants"
if [ "${HOOKPROBE_DEBUG_ACCESS:-0}" = 1 ]; then
  R_HASH="$(openssl passwd -6 -salt qEkJ33cMtCvXHNnx hookprobe)"  # ADR 0045 public dev login hookprobe/hookprobe, DERIVED (no literal hash in the tree)
  case "$R_HASH" in '$6$'*) ;; *) echo "FATAL: openssl passwd failed; refusing to bake an empty debug password" >&2; exit 1 ;; esac
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
# GAP-1 (2026-07-16): only a DEBUG image runs sshd. A release image has no login user and root is
# locked, so a live sshd is pure pre-auth WAN attack surface with zero function — mask it (symlink
# to /dev/null = the offline systemd mask) so nothing can start it on the internet-facing uplink.
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

# ---- Regenerate BOTH initrds WITH the storage-driver union (ADR 0029 D2) -------------------
# See the header note: BOTH RPi kernels build MMC/SDHCI-IPROC/BCM2835/DWC2/NVMe support IN
# (CONFIG_*=y, confirmed via each kernel's own /boot/config-<kver>) — this force-list is
# defense-in-depth (a no-op today) for exactly the failure mode that bit make-pi4-image.sh with
# Debian's MODULAR kernel: never trust an emulated qemu-user chroot's MODULES=most to find
# storage drivers on its own. RP1 (Ethernet/USB) is NOT listed — it is network, not storage, and
# loads from the real rootfs after pivot (ADR 0029 D2).
STORAGE_MODULES="sdhci-iproc sdhci-of-arasan sdhci-pltfm mmc_block bcm2835 dwc2 nvme nvme-core"
for mod in $STORAGE_MODULES; do
  grep -qxF "$mod" "$RT/etc/initramfs-tools/modules" 2>/dev/null || echo "$mod" >> "$RT/etc/initramfs-tools/modules"
done
rm -f "$RT/usr/share/initramfs-tools/hooks/plymouth"   # fails under emulated arm64 chroot (no GPU stack)
cp "$KCACHE/v8/config"    "$RT/boot/config-$V8"
cp "$KCACHE/2712/config"  "$RT/boot/config-$K2712"
cp /usr/bin/qemu-aarch64-static "$RT/usr/bin/" 2>/dev/null || true
for m in proc sys dev dev/pts; do mkdir -p "$RT/$m"; mount --bind "/$m" "$RT/$m" 2>/dev/null || true; done

# H3b/H3 verity hooks (opt-in, same as make-pi4-image.sh) must be installed BEFORE the initrd
# regen so both regenerated initrds pick them up.
if [ "${HOOKPROBE_VERITY:-0}" = 1 ]; then
  install -D -m0755 "$REPO"/base/initramfs/hooks/hookprobe-verity             "$RT/etc/initramfs-tools/hooks/hookprobe-verity"
  install -D -m0755 "$REPO"/base/initramfs/scripts/local-top/hookprobe-verity "$RT/etc/initramfs-tools/scripts/local-top/hookprobe-verity"
  install -D -m0755 "$REPO"/base/initramfs/scripts/local-premount/hookprobe-overlay "$RT/etc/initramfs-tools/scripts/local-premount/hookprobe-overlay"
  echo "  H3b: dm-verity initramfs hooks installed (root will be RO-verified, fallback-safe)"
fi
if [ "${HOOKPROBE_USR_VERITY:-0}" = 1 ]; then
  install -D -m0755 "$REPO"/base/initramfs/hooks/hookprobe-usr-verity                "$RT/etc/initramfs-tools/hooks/hookprobe-usr-verity"
  install -D -m0755 "$REPO"/base/initramfs/scripts/local-bottom/hookprobe-usr-verity "$RT/etc/initramfs-tools/scripts/local-bottom/hookprobe-usr-verity"
  echo "  H3: /usr-verity initramfs hooks installed (/usr = RO-verity, / = writable — no self-poison)"
fi

echo "=== depmod + regenerating BOTH initrds (chroot + update-initramfs) ==="
chroot "$RT" /sbin/depmod -a "$V8"    2>&1 | tail -4 || echo "  WARN depmod $V8 failed"
chroot "$RT" /sbin/depmod -a "$K2712" 2>&1 | tail -4 || echo "  WARN depmod $K2712 failed"
chroot "$RT" /usr/sbin/update-initramfs -c -k "$V8"    2>&1 | tail -8 || echo "  WARN update-initramfs $V8 failed"
chroot "$RT" /usr/sbin/update-initramfs -c -k "$K2712" 2>&1 | tail -8 || echo "  WARN update-initramfs $K2712 failed"
for m in dev/pts dev sys proc; do umount "$RT/$m" 2>/dev/null || true; done
rm -f "$RT/usr/bin/qemu-aarch64-static"

stage_initrd() { # kver dest-name
  local kver="$1" dest="$2"
  local src="$RT/boot/initrd.img-$kver"
  if [ -s "$src" ]; then
    cp "$src" "$WORK/p1/$dest"
    echo "  $dest regenerated: $(du -h "$WORK/p1/$dest" | cut -f1) (kernel $kver)"
    local iver; iver=$(mktemp -d)
    if command -v unmkinitramfs >/dev/null 2>&1 && unmkinitramfs "$WORK/p1/$dest" "$iver" 2>/dev/null; then
      echo "  ✓ $dest is a well-formed multi-segment cpio (unmkinitramfs OK)"
    else
      echo "  ⚠ $dest could not be unpacked by unmkinitramfs — investigate before flashing"
    fi
    rm -rf "$iver"
  else
    echo "  ⚠ WARN: initrd regen for $kver produced nothing — boot partition lacks $dest, DO NOT FLASH"
  fi
}
stage_initrd "$V8"    "initramfs8"
stage_initrd "$K2712" "initramfs_2712"

# --- H3a whole-root verity (opt-in, ADR 0006, ported verbatim from make-pi4-image.sh) ---------
if [ "${HOOKPROBE_VERITY:-0}" = 1 ] && command -v veritysetup >/dev/null; then
  echo "=== H3b: sealing the rootfs with dm-verity (read-only verified boot) ==="
  sync; umount "$WORK/p2"
  "$REPO"/security/verity/build-verity.sh "${OUTLOOP}p2" "$WORK/p1/rootfs.verity" "$WORK/p1/verity.roothash" >/dev/null
  RH=$(cat "$WORK/p1/verity.roothash")
  cat > "$WORK/p1/cmdline.txt" <<CMD
console=ttyAMA0,115200 console=tty1 root=/dev/mapper/hpverity rootwait ro verity.roothash=$RH verity.data=/dev/mmcblk0p2 verity.boot=/dev/mmcblk0p1 verity.hashfile=rootfs.verity fsck.mode=skip systemd.firstboot=off systemd.journald.forward_to_console=1
CMD
  echo "  ✓ dm-verity sealed: root hash $RH"
fi

# --- H3 /usr-only verity (opt-in, the CORRECT design, ported verbatim) -------------------------
if [ "${HOOKPROBE_USR_VERITY:-0}" = 1 ] && command -v veritysetup >/dev/null; then
  echo "=== H3: /usr-only verity — split /usr → p3, verity-seal (/ stays writable) ==="
  mount "${OUTLOOP}p3" "$WORK/p3"
  rsync -aHAX "$WORK/p2/usr/." "$WORK/p3/"
  sync; umount "$WORK/p3"
  rm -rf "$WORK/p2/usr"; mkdir -p "$WORK/p2/usr"
  sync
  mkdir -p "$WORK/p2/boot"
  "$REPO"/security/verity/build-verity.sh "${OUTLOOP}p3" "$WORK/p2/boot/usr.verity" "$WORK/p2/boot/usr.roothash" >/dev/null
  RH=$(cat "$WORK/p2/boot/usr.roothash")
  cat > "$WORK/p1/cmdline.txt" <<CMD
console=ttyAMA0,115200 console=tty1 root=LABEL=hookprobe-root rootfstype=ext4 fsck.repair=yes rootwait rw usrverity.roothash=$RH usrverity.data=LABEL=hp-usr usrverity.hashfile=usr.verity systemd.firstboot=off systemd.journald.forward_to_console=1 ${SPLASH_ARGS}
CMD
  echo "  ✓ /usr verity-sealed: usr root hash $RH"
fi

sync
echo "=== verifying boot partition ==="
ls -la "$WORK/p1" | sed 's/^/  /'
echo "=== DONE: $OUT ==="
echo "  static gates (run BOTH before flashing — release-blocking):"
echo "    boot part:  builder/mkosi-arm64/verify-pi-bootpart.sh $OUT"
echo "    payload:    builder/mkosi-arm64/verify-image-payload.sh $OUT   # catches the 006 empty-platforms class"
echo "  flash Pi4/CM4/Pi5-SD/CM5-Lite-SD:  sudo dd if=$OUT of=/dev/sdX bs=4M conv=fsync status=progress"
echo "  flash CM5 eMMC: put CM5 in rpiboot mass-storage mode, then"
echo "    sudo rpiboot -d <usbboot-EEPROM-blobs-path>   # exposes eMMC as /dev/sdX"
echo "    sudo dd if=$OUT of=/dev/sdX bs=4M conv=fsync status=progress"
echo "  *** Pi5/CM5 RP1 Ethernet+USB is UNVALIDATED ON REAL SILICON from this dev box — the ***"
echo "  *** whole point of this image; boot-test on real hardware before any Pi5/CM5 claim.  ***"
echo "  *** Also re-prove Pi4 (10.200.0.4) is not regressed by the unified image.            ***"
