#!/usr/bin/env bash
# make-cm5-heqk-image.sh — Track C (ADR 0043 / MIGRATION-heqk.md Phase M1) build seam.
#
# Builds the heqk MICROKERNEL substrate image for the CM5 rpi-native tier and stages the
# CM5 boot-partition contents. This is the Amber (operator-reviewed) BUILD step; the FLASH
# is a separate Red step performed by the operator via kernel/heqk/cm5-boot/flash-now.sh
# (rpiboot mass-storage) — never automated here.
#
# heqk lives at kernel/heqk as its OWN nightly no_std / build-std / aarch64-none-softfloat
# Cargo workspace (rust-toolchain.toml + .cargo/config scoped to that dir; the root Wasm
# workspace excludes it — see the repo Cargo.toml). We invoke heqk's own proven build+sign
# chain by-reference; nothing about heqk's toolchain leaks into the hookprobe-os workspace.
#
# Scope discipline (ADR 0043): this is a PARALLEL CM5 substrate variant. It does NOT replace
# the shipping Linux rpi-native image (make-pi-image.sh) and must not be wired into the
# default Pi build until the M2 gates (P8 rule-parity + the 0.7 enforcement-separation
# matrix + Gate R) pass on heqk metal.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
HEQK="$ROOT/kernel/heqk"
OUT="${OUT:-$ROOT/builder/generated/cm5-heqk}"

# Feature set: hboot (attested EL2 boot) + prod (the running IDS/IPS sensor loop). Add p10bt
# for the Bluetooth LE-scan sensor path; omit for a faster boot.
FEATURES="${FEATURES:-prod}"
SVN="${SVN:-1}"

[ -d "$HEQK/.git" ] || { echo "FATAL: $HEQK not found (run make-pi-image.sh for the Linux tier)"; exit 1; }
command -v llvm-objcopy >/dev/null || { echo "FATAL: llvm-objcopy not on PATH"; exit 1; }

echo "== [M1] building heqk substrate (features=$FEATURES svn=$SVN) at $HEQK"
cd "$HEQK"

# Pre-flight assurance gate (heqk's own always-on V&V): the verifier soundness harness must
# pass before we sign an image (mirrors heqk BUILD_FLASH_PLAN.md §1).
if [ -f tools/verifier-harness.rs ]; then
  rustc --edition 2021 -O tools/verifier-harness.rs -o "$OUT.vh" 2>/dev/null && "$OUT.vh" >/dev/null \
    && echo "== [M1] verifier soundness harness PASS" || { echo "FATAL: verifier harness failed"; exit 1; }
  rm -f "$OUT.vh"
fi

cargo build -p hboot --release
cargo build -p kernel --features "$FEATURES" --release

KBIN="$(mktemp -d)/kernel.bin"
llvm-objcopy -O binary target/aarch64-unknown-none-softfloat/release/kernel "$KBIN"

# Hybrid-sign (ed25519 + SLH-DSA) + assemble the combined hboot image = the CM5 kernel8 drop-in.
SVN="$SVN" ./cm5-boot/mkimage-hboot.sh \
  target/aarch64-unknown-none-softfloat/release/hboot "$KBIN" cm5-boot/heqk8.img

# Stage the CM5 boot-partition contents (what flash-now.sh copies onto the FAT boot part).
mkdir -p "$OUT"
cp -f cm5-boot/heqk8.img "$OUT/"
[ -f cm5-boot/heqk8-b.img ] && cp -f cm5-boot/heqk8-b.img "$OUT/"       # A/B slot B
[ -f cm5-boot/config.txt ] && cp -f cm5-boot/config.txt "$OUT/"          # kernel=heqk8.img + pciex4_reset=0
[ -f cm5-boot/tryboot.txt ] && cp -f cm5-boot/tryboot.txt "$OUT/"        # A/B tryboot
SHA="$(sha256sum cm5-boot/heqk8.img | cut -d' ' -f1)"

echo "== [M1] staged CM5 heqk boot set -> $OUT"
ls -la "$OUT" | sed 's/^/     /'
echo "== [M1] heqk8.img sha256=$SHA"
echo "== NEXT (Red / operator): put the CM5 in rpiboot, then run:"
echo "     sudo $HEQK/cm5-boot/flash-now.sh"
echo "   (device_tree=bcm2712-rpi-cm5-cm5io.dtb + the CYW43455 firmware must be present on the"
echo "    boot partition; the WiFi/BT blobs are staged by $HEQK/cm5-boot/stage-wifi-firmware.sh)"
