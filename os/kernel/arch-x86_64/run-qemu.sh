#!/usr/bin/env bash
# run-qemu.sh — build the X1 x86_64 skeleton and boot it under qemu-system-x86_64 (q35 + OVMF UEFI).
#   ./run-qemu.sh            KVM (-cpu host) when /dev/kvm is usable, else TCG (-cpu max)
#   X1_ACCEL=tcg ./run-qemu.sh   force TCG;  X1_CPU=<model,flags> overrides the CPU model
#   X1_CRATE=<dir>               build and boot another copy of the crate (tests/negative.sh uses it)
# PASS = QEMU exit status 33 (isa-debug-exit 0x10) AND every stage marker present. Unprivileged; touches nothing
# outside a temp dir (the ESP is a QEMU vvfat view of a throwaway dir; the OVMF VARS store is a throwaway copy).
set -euo pipefail
HERE="$(cd "${X1_CRATE:-$(dirname "$0")}" && pwd)"
OVMF_CODE="${OVMF_CODE:-/usr/share/OVMF/OVMF_CODE_4M.fd}"
OVMF_VARS="${OVMF_VARS:-/usr/share/OVMF/OVMF_VARS_4M.fd}"
[ -r "$OVMF_CODE" ] && [ -r "$OVMF_VARS" ] || { echo "run-qemu: OVMF not found (set OVMF_CODE/OVMF_VARS; Debian/Ubuntu: apt install ovmf)" >&2; exit 2; }

(cd "$HERE" && cargo build --release --quiet)
EFI="$HERE/target/x86_64-unknown-uefi/release/heqk-x86.efi"

T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
mkdir -p "$T/esp/EFI/BOOT"; cp "$EFI" "$T/esp/EFI/BOOT/BOOTX64.EFI"; cp "$OVMF_VARS" "$T/vars.fd"

ACCEL="${X1_ACCEL:-auto}"
if [ "$ACCEL" = auto ]; then [ -r /dev/kvm ] && [ -w /dev/kvm ] && ACCEL=kvm || ACCEL=tcg; fi
if [ "$ACCEL" = kvm ]; then CPU=(-enable-kvm -cpu "${X1_CPU:-host}"); else CPU=(-accel tcg -cpu "${X1_CPU:-max}"); fi

set +e
timeout "${X1_TIMEOUT:-120}" qemu-system-x86_64 -M q35 -m 512M "${CPU[@]}" -nodefaults -display none -no-reboot \
  -serial "file:$T/serial.log" \
  -drive if=pflash,format=raw,readonly=on,file="$OVMF_CODE" \
  -drive if=pflash,format=raw,file="$T/vars.fd" \
  -drive format=raw,file=fat:rw:"$T/esp" \
  -device isa-debug-exit,iobase=0xf4,iosize=0x04
RC=$?
set -e

grep -a '^\[X1' "$T/serial.log" || true
MISSING=0
for m in '\[X1\] heqk x86_64 entered' '\[X1-ebs\]' '\[X1-gdt\]' '\[X1-idt\]' '\[X1-paging\]' '\[X1-rng\] PASS' \
         '\[X1-apic\]' '\[X1-ring3\]' '\[X1-ring3-iso\] CPL3 read' '\[X1\] PASS'; do
  grep -aq "$m" "$T/serial.log" || { echo "run-qemu: missing marker: $m"; MISSING=1; }
done
echo "run-qemu: accel=$ACCEL qemu-exit=$RC (33 = PASS)"
[ "$RC" = 33 ] && [ "$MISSING" = 0 ] && { echo "run-qemu: X1 PASS"; exit 0; }
echo "run-qemu: X1 FAIL"; exit 1
