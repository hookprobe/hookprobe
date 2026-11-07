#!/usr/bin/env bash
# boot-arm64.sh — boot the arm64 mkosi image in qemu-system-aarch64 (UEFI/AAVMF, -M virt),
# headless, serial → a log. TCG emulation (host is x86), so slower than the amd64 KVM boot.
# This proves the arm64 HookProbe userspace + the first-boot self-provision chain; the real
# Pi 4 reuses the SAME rootfs under the rpi UEFI firmware. Operates on a COPY. Pair with timeout:
#   sudo timeout 600 builder/mkosi-arm64/boot-arm64.sh [IMAGE.raw] [SERIAL.log] [EXTRA_GB]
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
RAW=${1:-$HERE/hookprobe-os-arm64.raw}
SER=${2:-/tmp/hp-arm64-serial.log}
EXTRA_GB=${3:-4}                       # free space for firstboot-data to provision into

WORK=$(mktemp --suffix=.raw /tmp/hparm.XXXXXX)
cp "$RAW" "$WORK"
truncate -s "+${EXTRA_GB}G" "$WORK"

# AAVMF (arm64 UEFI) pflash needs 64MiB images; the packaged _CODE/_VARS are smaller, so pad
# copies to 64MiB. CODE is read-only; VARS is the writable per-boot NVRAM.
CODE=$(mktemp --suffix=.fd /tmp/aavmf-code.XXXXXX)
VARS=$(mktemp --suffix=.fd /tmp/aavmf-vars.XXXXXX)
cp /usr/share/AAVMF/AAVMF_CODE.fd "$CODE"; truncate -s 64M "$CODE"
cp /usr/share/AAVMF/AAVMF_VARS.fd "$VARS"; truncate -s 64M "$VARS"

: > "$SER"
qemu-system-aarch64 \
  -machine virt -cpu cortex-a72 -m 2048 -smp 2 \
  -drive if=pflash,format=raw,readonly=on,file="$CODE" \
  -drive if=pflash,format=raw,file="$VARS" \
  -drive file="$WORK",format=raw,if=virtio,cache=unsafe \
  -netdev user,id=n0 -device virtio-net-pci,netdev=n0 \
  -display none -serial "file:$SER" -no-reboot || true
rm -f "$WORK" "$VARS" "$CODE"
