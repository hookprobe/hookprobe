#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# m5-firmware-build — build the NanoPi M5 (RK3576) first-stage firmware for the heqk bench:
#   rkbin DDR init blob (closed, pinned by sha256) + mainline U-Boot SPL/proper + upstream TF-A BL31,
#   packaged as u-boot-rockchip-spi.bin (SPI-NOR) and u-boot-rockchip.bin (SD/UFS),
#   plus rkdeveloptool (host, maskrom flashing) and U-Boot's mkimage (boot.scr).
#
#   tools/build/m5-firmware-build.sh [--out DIR] [--work DIR] [--pin]
#
# Everything is fetched as release tarballs / single files at pinned versions and checked against
# tools/build/m5-firmware.sha256. --pin (first run only) writes that file instead of checking it:
# review the diff before committing it. Nothing here needs root. Third-party sources are built
# outside the repo (default ~/heqk-m5-bench) and never committed (licences: U-Boot GPL-2.0,
# TF-A BSD-3, rkbin Rockchip binary licence -> recorded as a vendor blob in the SBOM/CBOM).
# See docs/design/heqk-nanopi-m5-bench-runbook-2026-11-26.md.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
LOCK="$HERE/m5-firmware.sha256"
WORK="$HOME/heqk-m5-bench/fw-build"
OUT="$HOME/heqk-m5-bench/fw"
PIN=0
while [ $# -gt 0 ]; do
  case "$1" in
    --out) OUT="$2"; shift ;;
    --work) WORK="$2"; shift ;;
    --pin) PIN=1 ;;
    *) echo "unknown argument $1" >&2; exit 2 ;;
  esac
  shift
done

# ---- pinned inputs (docs/design/heqk-nanopi-m5-hw-datapack-2026-11-26.md §4) ----
UBOOT_TAG=v2026.10          # nanopi-m5-rk3576_defconfig since v2026.01; SPL UFS boot since v2026.07
TFA_TAG=v2.15.0             # plat/rockchip/rk3576 since v2.13.0 (PSCI + SCMI clock server)
RKBIN_REV=master            # replaced by a commit id when pinned; the blob itself is pinned by sha256
DDR_BLOB=rk3576_ddr_lp4_2112MHz_lp5_2736MHz_v1.13.bin   # one blob for LPDDR4/4X/5 (both M5 variants)
USBPLUG=rk3576_usbplug_fspi1_v1.03.bin                  # maskrom download stub for the SPI-NOR (FSPI1) path
RKDEV_REV=304f073752fd25c854e1bcf05d8e7f925b1f4e14      # rkdeveloptool master 2025-03-07
CROSS=${CROSS_COMPILE:-aarch64-linux-gnu-}

URL_UBOOT="https://github.com/u-boot/u-boot/archive/refs/tags/$UBOOT_TAG.tar.gz"
URL_TFA="https://github.com/ARM-software/arm-trusted-firmware/archive/refs/tags/$TFA_TAG.tar.gz"
URL_DDR="https://raw.githubusercontent.com/rockchip-linux/rkbin/$RKBIN_REV/bin/rk35/$DDR_BLOB"
URL_USBPLUG="https://raw.githubusercontent.com/rockchip-linux/rkbin/$RKBIN_REV/bin/rk35/$USBPLUG"
URL_RKDEV="https://github.com/rockchip-linux/rkdeveloptool/archive/$RKDEV_REV.tar.gz"

command -v "${CROSS}gcc" >/dev/null || { echo "missing ${CROSS}gcc (apt install gcc-aarch64-linux-gnu)" >&2; exit 1; }
for t in make bison flex dtc python3 curl sha256sum autoreconf pkg-config; do
  command -v "$t" >/dev/null || { echo "missing host tool: $t" >&2; exit 1; }
done
pkg-config --exists libusb-1.0 || { echo "missing libusb-1.0 dev headers (apt install libusb-1.0-0-dev)" >&2; exit 1; }

mkdir -p "$WORK/dl" "$OUT"
cd "$WORK"
[ "$PIN" = 1 ] && : > "$LOCK.new"

fetch() { # name url
  local f="dl/$1"
  [ -s "$f" ] || curl -sfL --retry 3 -o "$f.part" "$2" && { [ -s "$f" ] || mv "$f.part" "$f"; }
  [ -s "$f" ] || { echo "download failed: $2" >&2; exit 1; }
  local h; h=$(sha256sum "$f" | cut -d' ' -f1)
  if [ "$PIN" = 1 ]; then
    echo "$h  $1" >> "$LOCK.new"
  else
    [ -f "$LOCK" ] || { echo "no $LOCK: run once with --pin, review, commit" >&2; exit 1; }
    grep -q "^$h  $1\$" "$LOCK" || { echo "SHA-256 MISMATCH for $1 ($h) — refusing to build" >&2; exit 1; }
  fi
  echo "ok $1 ${h:0:16}…"
}
fetch "u-boot-$UBOOT_TAG.tar.gz" "$URL_UBOOT"
fetch "tf-a-$TFA_TAG.tar.gz" "$URL_TFA"
fetch "$DDR_BLOB" "$URL_DDR"
fetch "$USBPLUG" "$URL_USBPLUG"
fetch "rkdeveloptool-$RKDEV_REV.tar.gz" "$URL_RKDEV"
if [ "$PIN" = 1 ]; then mv "$LOCK.new" "$LOCK"; echo "pinned -> $LOCK (review + commit)"; fi

# Python for binman: pyelftools + swig (to build U-Boot's own pylibfdt). Private venv, no root.
if [ ! -x venv/bin/python3 ]; then
  python3 -m venv venv
  venv/bin/pip install -q 'pyelftools==0.31' 'swig==4.3.1' 'setuptools>=70'
fi
export PATH="$WORK/venv/bin:$PATH"

# ---- TF-A BL31 ----
rm -rf tf-a && mkdir tf-a && tar -xzf "dl/tf-a-$TFA_TAG.tar.gz" -C tf-a --strip-components=1
make -C tf-a CROSS_COMPILE="$CROSS" PLAT=rk3576 DEBUG=0 bl31 -j"$(nproc)" >tf-a.log 2>&1 || { tail -30 tf-a.log; exit 1; }
BL31="$WORK/tf-a/build/rk3576/release/bl31/bl31.elf"
[ -f "$BL31" ] || { echo "no bl31.elf" >&2; exit 1; }

# ---- U-Boot ----
rm -rf u-boot && mkdir u-boot && tar -xzf "dl/u-boot-$UBOOT_TAG.tar.gz" -C u-boot --strip-components=1
make -C u-boot CROSS_COMPILE="$CROSS" nanopi-m5-rk3576_defconfig >u-boot.log 2>&1
# not needed on the bench and they pull gnutls/uuid dev headers
u-boot/scripts/config --file u-boot/.config -d TOOLS_MKEFICAPSULE -d TOOLS_MKFWUMDATA
make -C u-boot CROSS_COMPILE="$CROSS" olddefconfig >>u-boot.log 2>&1
make -C u-boot CROSS_COMPILE="$CROSS" BL31="$BL31" ROCKCHIP_TPL="$WORK/dl/$DDR_BLOB" -j"$(nproc)" >>u-boot.log 2>&1 \
  || { tail -40 u-boot.log; exit 1; }
for f in u-boot-rockchip-spi.bin u-boot-rockchip.bin; do
  [ -f "u-boot/$f" ] || { echo "U-Boot did not produce $f" >&2; exit 1; }
  cp "u-boot/$f" "$OUT/"
done
cp u-boot/tools/mkimage "$OUT/mkimage"
cp u-boot/.config "$OUT/u-boot.config"

# ---- rkdeveloptool (host) ----
rm -rf rkdeveloptool && mkdir rkdeveloptool && tar -xzf "dl/rkdeveloptool-$RKDEV_REV.tar.gz" -C rkdeveloptool --strip-components=1
( cd rkdeveloptool && autoreconf -i >/dev/null 2>&1 && ./configure >/dev/null && make -j"$(nproc)" CXXFLAGS="-O2 -Wno-format-truncation -Wno-stringop-truncation" >../rkdev.log 2>&1 ) \
  || { tail -30 rkdev.log; exit 1; }
cp rkdeveloptool/rkdeveloptool "$OUT/"
cp "dl/$USBPLUG" "$OUT/"

# ---- manifest (what the SBOM/CBOM must say) ----
{
  echo "# NanoPi M5 bench firmware, built $(date -Is) on $(uname -m)"
  echo "u-boot $UBOOT_TAG (GPL-2.0, open) defconfig nanopi-m5-rk3576_defconfig"
  echo "tf-a   $TFA_TAG (BSD-3-Clause, open) PLAT=rk3576 bl31"
  echo "ddr    $DDR_BLOB (Rockchip binary, CLOSED vendor blob — unverifiable)"
  echo "usbplug $USBPLUG (Rockchip binary, CLOSED, host-side maskrom stub only)"
  echo "rkdeveloptool $RKDEV_REV (GPL-2.0, host tool)"
  ( cd "$OUT" && sha256sum u-boot-rockchip-spi.bin u-boot-rockchip.bin mkimage rkdeveloptool "$USBPLUG" )
} > "$OUT/MANIFEST.txt"
cat "$OUT/MANIFEST.txt"
echo "done -> $OUT"
