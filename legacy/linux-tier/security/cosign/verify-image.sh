#!/usr/bin/env bash
# =============================================================================
# verify-image.sh — FLASH-TIME verification of a HookProbe release disk image.
# =============================================================================
# "Trust nothing unsigned" (Readme / ADR 0002): OFFICIAL disk artifacts (.img/.img.xz/.iso/.qcow2)
# are `cosign sign-blob`'d + checksummed in build-os.yml. This verifies the detached signature +
# digest BEFORE flashing. Invalid/missing signature → NON-ZERO exit → the flash gate aborts.
#
# SELF-BUILT images are unsigned by design (you built them, you trust them) — pass --allow-unsigned.
# This is the counterpart to verify.sh (which verifies REGISTRY/OCI refs for the bootc path).
#
#   verify-image.sh <image.img[.xz]> [--allow-unsigned]
#   env: COSIGN_PUBLIC_KEY (key mode) | COSIGN_CERT_IDENTITY_REGEXP + COSIGN_CERT_OIDC_ISSUER (keyless)
# =============================================================================
set -euo pipefail
IMG="${1:?usage: verify-image.sh <image.img[.xz]> [--allow-unsigned]}"
ALLOW_UNSIGNED=0; [ "${2:-}" = "--allow-unsigned" ] && ALLOW_UNSIGNED=1
SIG="${IMG}.sig"; SUM="${IMG}.sha256"
# certificate name: build-os.yml emits <img>.pem; accept .cert as a fallback.
CERT="${IMG}.pem"; [ -f "$CERT" ] || CERT="${IMG}.cert"
IDENTITY="${COSIGN_CERT_IDENTITY_REGEXP:-https://github.com/hookprobe/hookprobe-os/.github/workflows/.+@refs/tags/v.+}"
ISSUER="${COSIGN_CERT_OIDC_ISSUER:-https://token.actions.githubusercontent.com}"
PUBKEY="${COSIGN_PUBLIC_KEY:-}"

[ -f "$IMG" ] || { echo "ABORT: image not found: $IMG" >&2; exit 1; }

# 1) Checksum (integrity) — always when present.
if [ -f "$SUM" ]; then
  echo "== checksum"
  ( cd "$(dirname "$IMG")" && sha256sum -c "$(basename "$SUM")" ) \
    || { echo "ABORT: checksum mismatch — image is corrupt or tampered." >&2; exit 2; }
fi

# 2) Signature (authenticity).
if [ ! -f "$SIG" ]; then
  if [ "$ALLOW_UNSIGNED" = 1 ]; then
    echo "WARN: no signature ($SIG) — proceeding (self-built, --allow-unsigned)."
    exit 0
  fi
  echo "ABORT: no signature for $IMG." >&2
  echo "       Official HookProbe images are signed. If you built this yourself, re-run with --allow-unsigned." >&2
  exit 3
fi
command -v cosign >/dev/null 2>&1 || { echo "ABORT: cosign not installed (needed to verify the signature)." >&2; exit 4; }

echo "== cosign verify-blob"
if [ -n "$PUBKEY" ]; then
  # Counterpart to sign-image.sh's `--tlog-upload=false` (offline/local-key signing, e.g. a
  # secret build with no Rekor entry to look up): without this, verify-blob may try to
  # fall back to a Rekor lookup for a signature that was deliberately never uploaded, and
  # fail or hang. Set COSIGN_REQUIRE_TLOG=1 to instead REQUIRE a tlog entry (for a key that
  # intentionally publishes to Rekor — see sign-image.sh's COSIGN_TLOG_UPLOAD=1 counterpart).
  # VERIFIED 2026-07-16 against cosign v2.4.1: `cosign verify-blob --help` lists
  # `--insecure-ignore-tlog=false`, so passing `--insecure-ignore-tlog` here is correct.
  TLOG_FLAG="--insecure-ignore-tlog"
  [ "${COSIGN_REQUIRE_TLOG:-0}" = "1" ] && TLOG_FLAG=""
  cosign verify-blob --key "$PUBKEY" $TLOG_FLAG --signature "$SIG" "$IMG"
else
  [ -f "$CERT" ] || { echo "ABORT: keyless verify needs $CERT (set COSIGN_PUBLIC_KEY for key mode)." >&2; exit 5; }
  cosign verify-blob --certificate "$CERT" --signature "$SIG" \
    --certificate-identity-regexp "$IDENTITY" --certificate-oidc-issuer "$ISSUER" "$IMG"
fi
echo "OK: $IMG verified (signature$( [ -f "$SUM" ] && echo ' + checksum' ))."
