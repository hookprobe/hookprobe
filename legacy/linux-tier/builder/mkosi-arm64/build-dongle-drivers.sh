#!/usr/bin/env bash
# build-dongle-drivers.sh — build the out-of-tree (Tier-2) USB Wi-Fi dongle kernel modules
# for the arm64 image and stage them as prebuilt .ko, so they are BAKED INTO the immutable
# image (no on-device DKMS/compiler). Modules are built against the SAME kernel version the
# arm64 image ships, inside an emulated arm64 Debian container (binfmt qemu-aarch64), FROM THE
# VENDORED+PINNED LOCAL SOURCES in base/drivers/ — no live external repos (run vendor-drivers.sh
# once first). Only Debian-signed packages (linux-headers, build-essential) come from the net.
#
# Run AFTER the first `sudo mkosi --force build` (we read the kernel version from the image),
# then re-run build-arm64.sh + mkosi build to fold the drivers in:
#   builder/mkosi-arm64/vendor-drivers.sh           # once
#   builder/mkosi-arm64/build-dongle-drivers.sh
#   builder/mkosi-arm64/build-arm64.sh && (cd builder/mkosi-arm64 && sudo mkosi --force build)
#
# Chipsets (operator-selected, all Realtek out-of-tree): 8812au/8814au, 8821au/8821cu,
# 8188eu/8192eu, 8852au/8832bu. See docs/architecture/driver-strategy.md supported-hardware matrix.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
RAW="$HERE/hookprobe-os-arm64.raw"
WORK="$HERE/drivers-build"
STAGE="$WORK/staged"
VENDORED="$REPO/base/drivers"

command -v podman >/dev/null || { echo "podman required (emulated arm64 build)"; exit 1; }
[ -d "$VENDORED" ] && ls "$VENDORED"/*/Makefile >/dev/null 2>&1 || { echo "vendor the drivers first: builder/mkosi-arm64/vendor-drivers.sh"; exit 1; }

# 1. Kernel version the image ships. Pass it in (KVER=… or $1) to avoid a privileged
#    loop-mount; otherwise read it from the built rootfs (needs sudo for losetup).
KVER="${KVER:-${1:-}}"
if [ -z "$KVER" ]; then
  [ -f "$RAW" ] || { echo "build the arm64 image first, or pass KVER=<ver> (e.g. 6.1.0-49-arm64)"; exit 1; }
  echo "=== reading kernel version from $RAW (loop-mount, needs sudo) ==="
  LOOP=$(sudo losetup --show -fP "$RAW")
  trap 'sudo umount /mnt/hp-arm64 2>/dev/null || true; sudo losetup -d "$LOOP" 2>/dev/null || true' EXIT
  sudo mkdir -p /mnt/hp-arm64
  ROOTPART=$(lsblk -rno NAME,FSTYPE "$LOOP" | awk '$2=="ext4"||$2=="ext2"{print "/dev/"$1; exit}')
  sudo mount -o ro "$ROOTPART" /mnt/hp-arm64
  KVER=$(ls /mnt/hp-arm64/usr/lib/modules | grep -E 'arm64|aarch64' | head -1)
  sudo umount /mnt/hp-arm64; sudo losetup -d "$LOOP"; trap - EXIT
fi
[ -n "$KVER" ] || { echo "could not determine kernel version"; exit 1; }
echo "image kernel: $KVER"

# 2. Build all vendored drivers in an emulated arm64 Debian bookworm container, against the
#    matching linux-headers, FROM the read-only vendored source mount, then copy .ko out.
rm -rf "$WORK"; mkdir -p "$STAGE/usr/lib/modules/$KVER/updates/hookprobe"
echo "=== building dongle drivers from $VENDORED (emulated arm64 — minutes) ==="
podman run --rm -e KVER="$KVER" \
  -v "$VENDORED:/src:ro" \
  -v "$STAGE/usr/lib/modules/$KVER/updates/hookprobe:/out:Z" \
  --arch arm64 docker.io/arm64v8/debian:bookworm bash -euo pipefail -c '
    sed -i "s/ main$/ main contrib non-free non-free-firmware/" /etc/apt/sources.list || true
    apt-get update -q
    apt-get install -y -q --no-install-recommends \
        ca-certificates build-essential bc kmod "linux-headers-$KVER" || \
      apt-get install -y -q --no-install-recommends ca-certificates build-essential bc kmod linux-headers-arm64
    KDIR=/usr/src/linux-headers-$KVER
    [ -d "$KDIR" ] || KDIR=$(ls -d /usr/src/linux-headers-*-arm64 | head -1)
    echo "building against $KDIR"
    # These Realtek Makefiles hardcode CONFIG_PLATFORM_I386_PC=y (x86) and gate the build ARCH
    # on it. For an arm64 build, flip it off and enable the driver-specific arm64 platform var.
    # (morrownr trees use CONFIG_PLATFORM_AUTODETECT=y → leave them alone.) Applied to the build
    # COPY in /b only; the vendored /src tree is never mutated.
    arm64ify() { # build-dir
      local mk="$1/Makefile"
      grep -q "^CONFIG_PLATFORM_AUTODETECT = y" "$mk" && return 0          # autodetect: leave
      sed -i "s/^CONFIG_PLATFORM_I386_PC = y/CONFIG_PLATFORM_I386_PC = n/" "$mk"
      for v in CONFIG_PLATFORM_ARM64_RPI CONFIG_PLATFORM_ARM_AARCH64 CONFIG_PLATFORM_ARM_RPI; do
        sed -i "s/^$v = n/$v = y/" "$mk"
      done
    }
    build() { # name (dir under /src)
      echo "--- $1 ---"
      [ -d "/src/$1" ] || { echo "  MISSING vendored /src/$1"; return 0; }
      cp -r "/src/$1" "/b/$1"            # copy out of the RO mount so make can write objects
      arm64ify "/b/$1"
      make -C "$KDIR" M="/b/$1" ARCH=arm64 modules 2>&1 | tail -4 || { echo "  build FAILED $1"; return 0; }
      find "/b/$1" -name "*.ko" -exec cp -v {} /out/ \; || true
    }
    mkdir -p /b
    for d in rtl8812au rtl8821cu rtl8821au rtl88x2bu rtl8852au rtl8188eu rtl8192eu; do build "$d"; done
    echo "=== built modules ==="; ls -la /out/
  '

N=$(find "$STAGE" -name '*.ko' | wc -l)
echo "=== staged $N driver module(s) under $STAGE ==="
find "$STAGE" -name '*.ko' -printf '  %f\n' | sort
[ "$N" -gt 0 ] || { echo "WARNING: no modules built — check output above"; exit 1; }

# ---- module signing (audit MEDIUM, 2026-07-16) --------------------------------------------------
# The hardened edge kernel sets CONFIG_MODULE_SIG + boots lockdown=integrity, so an UNSIGNED
# out-of-tree .ko is REFUSED at load — the USB-Wi-Fi STATION path would silently die. MODULE_SIG_ALL
# only signs the kernel's OWN in-tree modules; these must be signed with the SAME edge-kernel build's
# (ephemeral, per-build) key. Point EDGE_BUILD at that kernel's build tree (default: the 2712 tree;
# set EDGE_BUILD=…/build-v8 for the Pi4/CM4 flavour, matching the $KVER these .ko were built for).
EDGE_BUILD="${EDGE_BUILD:-$(cd "$(dirname "$0")/../kernel-build/build-2712" 2>/dev/null && pwd)}"
SIGN_KEY="$EDGE_BUILD/certs/signing_key.pem"
SIGN_X509="$EDGE_BUILD/certs/signing_key.x509"
SIGN_TOOL="$EDGE_BUILD/scripts/sign-file"
if [ -f "$SIGN_KEY" ] && [ -f "$SIGN_X509" ] && [ -x "$SIGN_TOOL" ]; then
  echo "=== signing $N dongle .ko with the edge-kernel key ($EDGE_BUILD) ==="
  find "$STAGE" -name '*.ko' -print0 | while IFS= read -r -d '' ko; do
    "$SIGN_TOOL" sha256 "$SIGN_KEY" "$SIGN_X509" "$ko" && echo "  signed $(basename "$ko")" \
      || { echo "ERROR: sign-file failed on $ko"; exit 1; }
  done
else
  echo "!!! WARNING: edge-kernel signing key not found under $EDGE_BUILD/certs — dongle .ko are UNSIGNED."
  echo "!!! Under lockdown=integrity (the hardened default) they WILL FAIL TO LOAD. Set EDGE_BUILD to"
  echo "!!! the matching kernel build tree (with certs/signing_key.pem) and re-run to sign them."
fi

echo "now: build-arm64.sh && (cd builder/mkosi-arm64 && sudo mkosi --force build)   # bakes them in"
