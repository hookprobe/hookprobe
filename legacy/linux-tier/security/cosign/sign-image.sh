#!/usr/bin/env bash
# =============================================================================
# sign-image.sh — sign a HookProbe release disk image (cosign sign-blob) + checksum.
# =============================================================================
# Runs in build-os.yml on release (keyless Fulcio/Rekor OIDC — recommended for the open-core image),
# or locally with a key (COSIGN_KEY=...). Produces the artifacts verify-image.sh checks at flash time:
#   <img>.sha256   sha256 checksum (integrity)
#   <img>.sig      cosign detached signature (authenticity)
#   <img>.pem      signing certificate (keyless mode only; matches build-os.yml)
# The device/operator only VERIFIES; the signing key never ships (ADR 0002).
#
#   sign-image.sh <image.img[.xz]>
#   env: COSIGN_KEY (key mode) | none (keyless — needs id-token in CI)
# =============================================================================
set -euo pipefail
IMG="${1:?usage: sign-image.sh <image.img[.xz]>}"
KEY="${COSIGN_KEY:-}"
[ -f "$IMG" ] || { echo "ERROR: image not found: $IMG" >&2; exit 1; }
command -v cosign >/dev/null 2>&1 || { echo "ERROR: cosign not installed" >&2; exit 1; }

( cd "$(dirname "$IMG")" && sha256sum "$(basename "$IMG")" > "$(basename "$IMG").sha256" )
if [ -n "$KEY" ]; then
  # FIX (2026-07-16): `cosign sign-blob` uploads to the PUBLIC Rekor transparency log by
  # DEFAULT for BOTH keyless AND key-based signing -- an unqualified `--key "$KEY"` call
  # here would publish this artifact's hash (and the fact that it was signed, when, by
  # what OIDC-less key fingerprint) to the world even though a private key was used. That
  # is correct/desired for Option A (keyless, the public open-core image, transparency IS
  # the point) but actively WRONG for Option B / any local-secret build (KEY-CUSTODY.md
  # "offline release HSM/KMS" model, or a local dev key for a build that hasn't been
  # announced yet) — this branch is exactly the one a secret/local release uses, so it
  # must default closed. `--tlog-upload=false` keeps this call fully offline; the
  # matching verify-time flag is `--insecure-ignore-tlog` (see verify-image.sh).
  # VERIFIED 2026-07-16 against cosign v2.4.1 (the base/Containerfile pin, run here via the
  # containerized `cosign` wrapper): `cosign sign-blob --help` lists `--tlog-upload=true` as
  # the real flag, so `--tlog-upload=false` below is correct for this version.
  # Set COSIGN_TLOG_UPLOAD=1 to opt back INTO tlog upload for a key that intentionally
  # wants public transparency (e.g. a KMS/HSM production key, Option B, where publishing
  # to Rekor is a deliberate auditability choice, not a leak).
  TLOG_FLAG="--tlog-upload=false"
  [ "${COSIGN_TLOG_UPLOAD:-0}" = "1" ] && TLOG_FLAG="--tlog-upload=true"
  cosign sign-blob --yes --key "$KEY" $TLOG_FLAG --output-signature "${IMG}.sig" "$IMG"
else
  cosign sign-blob --yes --output-signature "${IMG}.sig" --output-certificate "${IMG}.pem" "$IMG"
fi
echo "signed: ${IMG}.sig $( [ -f "${IMG}.pem" ] && echo "${IMG}.pem ")${IMG}.sha256"
