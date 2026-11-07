#!/usr/bin/env bash
# boot-vm.sh — boot the mkosi image in qemu-kvm (UEFI/OVMF), headless, serial → a log.
# Operates on a COPY so the source image stays clean. Pair with `timeout`:
#   sudo timeout 150 builder/mkosi/boot-vm.sh [IMAGE.raw] [SERIAL.log] [EXTRA_GB]
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
RAW=${1:-$HERE/hookprobe-os.raw}
SER=${2:-/tmp/hp-serial.log}
EXTRA_GB=${3:-4}                       # free space appended so firstboot-data can provision

WORK=$(mktemp --suffix=.raw /tmp/hpvm.XXXXXX)
cp "$RAW" "$WORK"
# Append free space at the end of the disk (firstboot-data grows a hookprobe-data
# partition into it; it relocates the GPT backup header itself).
truncate -s "+${EXTRA_GB}G" "$WORK"
VARS=$(mktemp --suffix=.fd /tmp/ovmf-vars.XXXXXX)
cp /usr/share/OVMF/OVMF_VARS_4M.fd "$VARS"

: > "$SER"
qemu-system-x86_64 \
  -machine q35,accel=kvm -cpu host -m 2048 -smp 2 \
  -drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd \
  -drive if=pflash,format=raw,file="$VARS" \
  -drive file="$WORK",format=raw,if=virtio,cache=unsafe \
  -netdev user,id=n0 -device virtio-net-pci,netdev=n0 \
  -display none -serial "file:$SER" -no-reboot || true
rm -f "$WORK" "$VARS"
