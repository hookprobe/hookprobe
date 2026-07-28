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

# heqk is flattened into the monorepo (its history was inherited via -s ours merge,
# ADR 0046) — it is a subdir, not a nested repo, so probe for the workspace markers,
# not a $HEQK/.git that no longer exists.
[ -f "$HEQK/Cargo.toml" ] && [ -f "$HEQK/rust-toolchain.toml" ] && [ -d "$HEQK/kernel" ] || {
  echo "FATAL: heqk workspace not found at $HEQK (expected Cargo.toml + rust-toolchain.toml + kernel/)"; exit 1; }
command -v llvm-objcopy >/dev/null || { echo "FATAL: llvm-objcopy not on PATH"; exit 1; }

# ── Fail-closed boot-signing keydir (ADR 0046 / docs/design/heqk-signing-identity.md) ──────
# mkimage-hboot.sh otherwise SILENTLY defaults KEYDIR/SIGNER to ~/heqk-sign — i.e. it would sign
# the CM5 boot ROOT-OF-TRUST with whatever dev key sits in one operator's $HOME, with no
# indication. Require the keydir to be chosen EXPLICITLY; never fall through to $HOME. (The rest
# of the plumbing — an in-tree vendored heqk-sign, builder/gen-heqk-dev-keys.sh, and the
# release-BLOCKING dev-key-in-prod fingerprint gate — is tracked in the design note.)
if [ -z "${HEQK_KEYDIR:-}" ]; then
  echo "FATAL: HEQK_KEYDIR is unset — refusing to silently sign the CM5 boot root-of-trust" >&2
  echo "       with the dev key in ~/heqk-sign. Set HEQK_KEYDIR to a keydir holding the" >&2
  echo "       ed25519 + slh-dsa-sha2-128s signing keys (dev/CI: a generated dev keydir;" >&2
  echo "       production: an HSM-backed keydir). See docs/design/heqk-signing-identity.md." >&2
  exit 1
fi
[ -d "$HEQK_KEYDIR" ] || { echo "FATAL: HEQK_KEYDIR=$HEQK_KEYDIR is not a directory" >&2; exit 1; }
HEQK_SIGNER="${HEQK_SIGNER:-$HOME/heqk-sign/target/release/heqk-sign}"
[ -x "$HEQK_SIGNER" ] || { echo "FATAL: heqk-sign not executable at $HEQK_SIGNER — set HEQK_SIGNER (in-tree vendoring tracked in docs/design/heqk-signing-identity.md)" >&2; exit 1; }

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
SVN="$SVN" KEYDIR="$HEQK_KEYDIR" SIGNER="$HEQK_SIGNER" ./cm5-boot/mkimage-hboot.sh \
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
