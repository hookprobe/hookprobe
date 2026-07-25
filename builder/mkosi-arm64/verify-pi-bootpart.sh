#!/usr/bin/env bash
# verify-pi-bootpart.sh — the ADR 0029 (step 4) boot-partition STATIC gate for the unified Pi
# fat-boot image. Proves the assembled image's FAT32 boot partition carries BOTH Raspberry Pi
# kernels, all FOUR board DTBs, BOTH regenerated initrds, the storage-driver union, and the
# config.txt [pi4]/[cm4]/[pi5]/[cm5]/[all] filter matrix — the honest ceiling of what can be
# proven at build time without booting real Pi4/CM4/Pi5/CM5 silicon (see ADR 0029 §"needs
# physical silicon").
#
# Reads the FAT boot partition directly via mtools (`mdir`/`mcopy` with the `img@@offset` form)
# — NO loop device, NO mount, NO root required, so this gate runs on a plain dev box exactly like
# every other gate-ladder.sh check.
#
#   builder/mkosi-arm64/verify-pi-bootpart.sh [IMG] [--kcache DIR]
#     IMG      default: builder/mkosi-arm64/hookprobe-os-pi.img
#     --kcache default: builder/mkosi-arm64/pi-kernel-cache (make-pi-image.sh's own cache; used
#              to cross-check the storage-driver union against each kernel's ACTUAL /boot/config-
#              <kver> — see the "built-in, not modular" finding below). Absent kcache = the
#              storage-union check runs off initrd contents alone and WARNS (does not fail) for
#              anything it cannot find as a .ko, since these RPi kernels build most of the
#              storage stack IN rather than as loadable modules (confirmed 2026-07-08, see
#              base/drivers/SOURCES.md) — a bare initrd-only check cannot distinguish
#              "absent-because-built-in" from "absent-because-genuinely-missing" without the
#              kernel config as ground truth.
#
# Exit codes: 0 = PASS, 1 = FAIL (a real defect), 2 = SKIP (no image to check — e.g. this dev box
# has never run the privileged build; NOT a check failure).
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
IMG="${HERE}/hookprobe-os-pi.img"
KCACHE="${HERE}/pi-kernel-cache"
POSITIONAL=()
while [ $# -gt 0 ]; do
  case "$1" in
    --kcache) KCACHE="$2"; shift 2 ;;
    --kcache=*) KCACHE="${1#--kcache=}"; shift ;;
    *) POSITIONAL+=("$1"); shift ;;
  esac
done
if [ "${#POSITIONAL[@]}" -gt 0 ]; then IMG="${POSITIONAL[0]}"; fi

FAIL=0
WARN=0
note()  { echo "  .. $*"; }
ok()    { echo "  OK  $*"; }
warn()  { echo "  WARN $*"; WARN=$((WARN+1)); }
bad()   { echo "  FAIL $*"; FAIL=$((FAIL+1)); }

if [ ! -f "$IMG" ]; then
  echo "SKIP: no image at $IMG — this dev box has not run the privileged build (make-pi-image.sh needs sudo/loop/mkfs/mount, which the sandbox here refuses). Not a check failure."
  exit 2
fi
command -v mdir  >/dev/null 2>&1 || { echo "ABORT: mtools (mdir/mcopy) not installed"; exit 1; }
command -v mcopy >/dev/null 2>&1 || { echo "ABORT: mtools (mdir/mcopy) not installed"; exit 1; }

echo "=== locating the FAT32 boot partition in $IMG ==="
OFFSET=0
if command -v sfdisk >/dev/null 2>&1 && sfdisk -J "$IMG" >/tmp/hp-bootpart-sfdisk.$$.json 2>/dev/null; then
  # Partitioned image (the real make-pi-image.sh output): p1 is the FAT32 (dos type 0x0c) /
  # bootable partition. sfdisk reads a plain file without root/loop — no privilege needed.
  OFFSET=$(python3 -c "
import json
with open('/tmp/hp-bootpart-sfdisk.$$.json') as f:
    d = json.load(f)
parts = d['partitiontable']['partitions']
ss = d['partitiontable'].get('sectorsize', 512)
# prefer the bootable / type 'c' (FAT32 LBA) partition; fall back to the first partition.
p1 = next((p for p in parts if p.get('bootable') or p.get('type') == 'c'), parts[0])
print(p1['start'] * ss)
")
  rm -f "/tmp/hp-bootpart-sfdisk.$$.json"
  note "MBR partition table found — boot (FAT32) partition offset = $OFFSET bytes"
else
  note "no MBR partition table detected — treating $IMG as a standalone FAT image at offset 0 (self-test fixture mode)"
fi
MT="$IMG@@$OFFSET"

echo "=== listing boot partition contents ==="
mdir -i "$MT" :: 2>/dev/null | sed 's/^/  /' || { echo "FAIL: mdir could not read the FAT partition at offset $OFFSET"; exit 1; }
# `-b` (bare/brief) gives clean one-path-per-line output using the REAL long filename — the
# default `mdir` columnar listing splits short (8.3) names as "base  ext" with no long-name
# column when the name already fits 8.3 (e.g. kernel8.img, config.txt), which breaks a naive
# substring/anchor match. `-b` is the only reliable way to test "is this exact filename present".
LISTING=$(mdir -i "$MT" -b :: 2>/dev/null) || { echo "FAIL: mdir -b could not read the FAT partition at offset $OFFSET"; exit 1; }

has_file() { echo "$LISTING" | grep -qiE "(^|/)${1//./\\.}\$"; }

echo "=== D1 matrix: both kernels + all four DTBs + both initrds ==="
for f in kernel8.img kernel_2712.img \
         bcm2711-rpi-4-b.dtb bcm2711-rpi-cm4.dtb bcm2712-rpi-5-b.dtb bcm2712-rpi-cm5-cm5io.dtb \
         initramfs8 initramfs_2712 config.txt cmdline.txt; do
  if has_file "$f"; then ok "$f present"; else bad "$f MISSING from boot partition"; fi
done
for f in start4.elf fixup4.dat bootcode.bin; do
  if has_file "$f"; then ok "$f present (Pi4/CM4 GPU firmware — harmless-unused on Pi5/CM5)"; else warn "$f missing (Pi4/CM4 boot needs this; only fatal if targeting those boards)"; fi
done

echo "=== config.txt filter-block check (ADR 0029 D1) ==="
CFGTMP=$(mktemp)
if mcopy -i "$MT" -n ::config.txt "$CFGTMP" 2>/dev/null; then
  check_cfg() { grep -qF "$1" "$CFGTMP" && ok "config.txt: '$1'" || bad "config.txt missing '$1'"; }
  check_cfg "[pi4]"
  check_cfg "[cm4]"
  check_cfg "[pi5]"
  check_cfg "[cm5]"
  check_cfg "[all]"
  check_cfg "kernel=kernel8.img"
  check_cfg "kernel=kernel_2712.img"
  check_cfg "device_tree=bcm2711-rpi-4-b.dtb"
  check_cfg "device_tree=bcm2711-rpi-cm4.dtb"
  check_cfg "device_tree=bcm2712-rpi-5-b.dtb"
  check_cfg "device_tree=bcm2712-rpi-cm5-cm5io.dtb"
else
  bad "could not extract config.txt from the boot partition"
fi

echo "=== cmdline.txt board-agnostic check ==="
CMDTMP=$(mktemp)
if mcopy -i "$MT" -n ::cmdline.txt "$CMDTMP" 2>/dev/null; then
  grep -qF "root=LABEL=hookprobe-root" "$CMDTMP" && ok "cmdline.txt: root=LABEL=hookprobe-root (board-agnostic)" \
    || bad "cmdline.txt does not use root=LABEL=hookprobe-root"
else
  bad "could not extract cmdline.txt from the boot partition"
fi

echo "=== initrd well-formedness + storage-driver union (ADR 0029 D2) ==="
# Ground truth (2026-07-08, direct kernel-config inspection, see base/drivers/SOURCES.md): BOTH
# RPi kernels build MMC_BLOCK/MMC_BCM2835/MMC_SDHCI_IPROC/USB_DWC2/NVME_CORE/BLK_DEV_NVME IN
# (CONFIG_*=y), NOT as modules — so their absence as a .ko in the initrd is EXPECTED, not a
# defect, and this check treats "confirmed built-in via the kernel's own /boot/config-<kver>" as
# an equally valid PASS to "found as a .ko in the initrd". sdhci-of-arasan/sdhci-pltfm are kept
# for ADR-matrix documentation parity only (neither BCM2711 nor BCM2712 uses the arasan/generic
# controller) — their absence is WARN, never FAIL.
declare -A CFG_SYMBOL=(
  [sdhci-iproc]="CONFIG_MMC_SDHCI_IPROC"
  [mmc_block]="CONFIG_MMC_BLOCK"
  [bcm2835]="CONFIG_MMC_BCM2835"
  [dwc2]="CONFIG_USB_DWC2"
  [nvme]="CONFIG_BLK_DEV_NVME"
  [nvme-core]="CONFIG_NVME_CORE"
)
REQUIRED_MODULES="sdhci-iproc mmc_block bcm2835 dwc2 nvme nvme-core"
OPTIONAL_MODULES="sdhci-of-arasan sdhci-pltfm"

check_initrd() { # dest-name kver-config-file
  local dest="$1" cfg="$2" tmp
  if ! mcopy -i "$MT" -n "::$dest" "/tmp/hp-bootpart-$dest.$$" 2>/dev/null; then
    bad "$dest could not be extracted from the boot partition"
    return
  fi
  tmp=$(mktemp -d)
  if command -v unmkinitramfs >/dev/null 2>&1 && unmkinitramfs "/tmp/hp-bootpart-$dest.$$" "$tmp" 2>/dev/null; then
    ok "$dest is a well-formed cpio archive (unmkinitramfs OK)"
  else
    bad "$dest could not be unpacked by unmkinitramfs — corrupt/malformed initrd"
    rm -rf "$tmp" "/tmp/hp-bootpart-$dest.$$"
    return
  fi
  for mod in $REQUIRED_MODULES; do
    if find "$tmp" -iname "${mod}.ko*" 2>/dev/null | grep -q .; then
      ok "$dest: $mod present as a module"
    elif [ -n "$cfg" ] && [ -f "$cfg" ] && grep -qE "^${CFG_SYMBOL[$mod]}(_MMC)?=y" "$cfg"; then
      ok "$dest: $mod confirmed BUILT-IN via $(basename "$cfg") (${CFG_SYMBOL[$mod]}=y — not modular, expected for the RPi kernel)"
    elif [ -z "$cfg" ] || [ ! -f "$cfg" ]; then
      warn "$dest: $mod not found as a module and no kernel config available to confirm built-in (pass --kcache DIR, or this is a self-test fixture)"
    else
      bad "$dest: $mod is NEITHER a module NOR built-in per $(basename "$cfg") — real storage-support gap"
    fi
  done
  for mod in $OPTIONAL_MODULES; do
    find "$tmp" -iname "${mod}.ko*" 2>/dev/null | grep -q . \
      && ok "$dest: $mod present (bonus — not required on RPi's iproc/bcm2835 controllers)" \
      || warn "$dest: $mod absent (expected — BCM2711/BCM2712 don't use this controller)"
  done
  rm -rf "$tmp" "/tmp/hp-bootpart-$dest.$$"
}

V8_CFG=""; K2712_CFG=""
if [ -d "$KCACHE" ]; then
  V8_CFG=$(ls "$KCACHE"/v8/config 2>/dev/null | head -1)
  K2712_CFG=$(ls "$KCACHE"/2712/config 2>/dev/null | head -1)
fi
check_initrd "initramfs8"    "$V8_CFG"
check_initrd "initramfs_2712" "$K2712_CFG"

rm -f "$CFGTMP" "$CMDTMP"

echo
echo "=== SUMMARY ==="
echo "  FAIL count: $FAIL"
echo "  WARN count: $WARN"
if [ "$FAIL" -gt 0 ]; then
  echo "RESULT: FAIL — boot partition is NOT correctly assembled for the ADR 0029 unified image."
  exit 1
fi
echo "RESULT: PASS — boot partition carries both kernels, all four DTBs, both initrds, the"
echo "        config.txt filter matrix, and the storage-driver union (module-or-built-in)."
echo "        Reminder: this proves the image is ASSEMBLED correctly. RP1 Ethernet/USB actually"
echo "        coming up on real Pi5/CM5 silicon still needs physical hardware (ADR 0029)."
exit 0
