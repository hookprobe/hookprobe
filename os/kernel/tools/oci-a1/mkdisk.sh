#!/usr/bin/env bash
# Build an OCI-importable boot disk: GPT + one EFI System Partition (FAT32) holding
# EFI/BOOT/BOOTAA64.EFI (+ optional extra files at the ESP root). Emits <out>.img (raw, for
# QEMU) and, with MKDISK_QCOW2=1, <out>.qcow2 (OCI custom-image import format).
# Usage: mkdisk.sh <out-basename> <BOOTAA64.EFI> [extra-file...]
set -euo pipefail
OUT=${1:?usage: mkdisk.sh <out> <BOOTAA64.EFI> [extra...]}
EFI=${2:?usage: mkdisk.sh <out> <BOOTAA64.EFI> [extra...]}
shift 2
IMG="$OUT.img"
SIZE_MB=${MKDISK_SIZE_MB:-64}
rm -f "$IMG"
truncate -s "${SIZE_MB}M" "$IMG"
# (no -q: with -q this sgdisk silently skipped -n on a fresh image)
sgdisk -o -n 1:2048:0 -t 1:ef00 -c 1:"EFI System" "$IMG" >/dev/null 2>&1
sgdisk -i 1 "$IMG" | grep -q 'First sector' || { echo "mkdisk: ESP partition not created" >&2; exit 1; }
FIRST=$(sgdisk -i 1 "$IMG" | awk '/First sector/{print $3}')
LAST=$(sgdisk -i 1 "$IMG" | awk '/Last sector/{print $3}')
ESP=$(mktemp)
trap 'rm -f "$ESP"' EXIT
truncate -s $(( (LAST - FIRST + 1) * 512 )) "$ESP"
mkfs.vfat -F 32 -n HEQK "$ESP" >/dev/null
mmd -i "$ESP" ::/EFI ::/EFI/BOOT
mcopy -i "$ESP" "$EFI" ::/EFI/BOOT/BOOTAA64.EFI
for f in "$@"; do mcopy -i "$ESP" "$f" ::/"$(basename "$f")"; done
dd if="$ESP" of="$IMG" bs=512 seek="$FIRST" conv=notrunc status=none
if [ "${MKDISK_QCOW2:-0}" = 1 ]; then qemu-img convert -f raw -O qcow2 "$IMG" "$OUT.qcow2"; fi
echo "$IMG"
