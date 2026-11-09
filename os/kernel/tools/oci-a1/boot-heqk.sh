#!/usr/bin/env bash
# Build heqk (cloud tier) -> embed in efiboot (UEFI) -> GPT/ESP disk -> boot on the OCI A1
# QEMU model. With MKDISK_QCOW2=1 also writes <out>.qcow2 for OCI custom-image import.
#
# Usage: boot-heqk.sh [out-dir]           env: HEQK_FEATURES (default "cloud"),
#        BOOT=0 to only build the disk,   OCI_TIMEOUT (default 120), PROBE_ONLY=1 (no kernel)
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd) # os/kernel
OUT=${1:-$ROOT/target/oci-a1}
mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd) # absolute: the builds below cd into sub-crates
[ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"
SYSROOT=$(rustc --print sysroot)
OBJCOPY=$(find "$SYSROOT" -name llvm-objcopy -type f | head -1)
[ -x "$OBJCOPY" ] || { echo "llvm-objcopy not found (rustup component add llvm-tools)" >&2; exit 2; }

if [ "${PROBE_ONLY:-0}" = 1 ]; then
  (cd "$ROOT/efiboot" && env -u HEQK_IMAGE CARGO_TARGET_DIR="$OUT/efiboot-probe" cargo build --release -q)
  EFI="$OUT/efiboot-probe/aarch64-unknown-uefi/release/efiboot.efi"
else
  echo "[oci-a1] building heqk --features ${HEQK_FEATURES:-cloud}"
  (cd "$ROOT" && CARGO_TARGET_DIR="$OUT/kernel" cargo build -q -p kernel --features "${HEQK_FEATURES:-cloud}")
  "$OBJCOPY" --strip-all "$OUT/kernel/aarch64-unknown-none-softfloat/debug/kernel" "$OUT/heqk.elf"
  echo "[oci-a1] building efiboot with embedded heqk"
  (cd "$ROOT/efiboot" && HEQK_IMAGE="$OUT/heqk.elf" CARGO_TARGET_DIR="$OUT/efiboot" cargo build --release -q)
  EFI="$OUT/efiboot/aarch64-unknown-uefi/release/efiboot.efi"
fi
"$HERE/mkdisk.sh" "$OUT/disk" "$EFI" >/dev/null
echo "[oci-a1] disk: $OUT/disk.img$([ "${MKDISK_QCOW2:-0}" = 1 ] && echo " + $OUT/disk.qcow2")"
[ "${BOOT:-1}" = 1 ] || exit 0
OCI_SEMIHOST=1 OCI_TIMEOUT=${OCI_TIMEOUT:-120} "$HERE/run-oci-a1.sh" "$OUT/disk.img"
