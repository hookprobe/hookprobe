#!/usr/bin/env bash
# security/cosign/verify.sh — verify a HookProbe OS image OR module against the release
# identity, and confirm its SBOM + CBOM attestations are present.
#
# This is the COUNTERPART to the signing done in .github/workflows/*. On-device, the
# equivalent trust decision is enforced by /etc/containers/policy.json (default-reject;
# base/config/containers/policy.json) — this script is for CI/operators/auditors to
# verify out-of-band, and to gate the boot smoke-test / fleet promotion.
#
# ADR 0002 §3: image & module signing = composite ML-DSA-65 + Ed25519. cosign/sigstore
# PQC signing is still maturing (ADR 0002 consequences), so the INTERIM path is
# dual/composite signing. This script verifies whatever the active identity model is —
# pick ONE of the two blocks below (keyless OIDC vs key/KMS) to match the workflow.
set -euo pipefail

REF="${1:?usage: verify.sh <image-or-module-ref@sha256:...>}"

# --- Identity model (MUST match build-os.yml / build-modules.yml) -------------
# Option A — keyless (Fulcio/Rekor, recommended for OSS): verify by OIDC identity.
#   TODO: set these to the real release workflow identity once the repo is on GitHub.
COSIGN_CERT_IDENTITY_REGEXP="${COSIGN_CERT_IDENTITY_REGEXP:-https://github.com/hookprobe/hookprobe-os/.github/workflows/.+@refs/tags/v.+}"
COSIGN_CERT_OIDC_ISSUER="${COSIGN_CERT_OIDC_ISSUER:-https://token.actions.githubusercontent.com}"

# Option B — key/KMS (regulated/offline): verify against the published public key.
#   COSIGN_PUBLIC_KEY=security/cosign/keys/cosign.pub   # public material ONLY (ADR 0002 §5)
COSIGN_PUBLIC_KEY="${COSIGN_PUBLIC_KEY:-}"

echo "== verifying signature: ${REF}"
if [[ -n "${COSIGN_PUBLIC_KEY}" ]]; then
  cosign verify --key "${COSIGN_PUBLIC_KEY}" "${REF}"
else
  cosign verify \
    --certificate-identity-regexp "${COSIGN_CERT_IDENTITY_REGEXP}" \
    --certificate-oidc-issuer "${COSIGN_CERT_OIDC_ISSUER}" \
    "${REF}"
fi

echo "== verifying SBOM attestation (CycloneDX)"
cosign verify-attestation --type cyclonedx \
  ${COSIGN_PUBLIC_KEY:+--key "${COSIGN_PUBLIC_KEY}"} \
  ${COSIGN_PUBLIC_KEY:--certificate-identity-regexp "${COSIGN_CERT_IDENTITY_REGEXP}" --certificate-oidc-issuer "${COSIGN_CERT_OIDC_ISSUER}"} \
  "${REF}" >/dev/null

# CBOM is also a CycloneDX document; we tag the predicate so verifiers can tell them
# apart. TODO: confirm whether to use a custom predicateType for the CBOM or rely on the
# in-document `cryptoProperties` to distinguish it from the SBOM (both are cyclonedx/bom).
echo "== verifying CBOM attestation (CycloneDX cryptographic-assets)"
cosign verify-attestation --type "https://cyclonedx.org/bom" \
  ${COSIGN_PUBLIC_KEY:+--key "${COSIGN_PUBLIC_KEY}"} \
  ${COSIGN_PUBLIC_KEY:--certificate-identity-regexp "${COSIGN_CERT_IDENTITY_REGEXP}" --certificate-oidc-issuer "${COSIGN_CERT_OIDC_ISSUER}"} \
  "${REF}" >/dev/null || echo "WARN: CBOM attestation not found / predicate mismatch (TODO: finalize CBOM predicateType)"

echo "OK: ${REF} verified (signature + SBOM; CBOM best-effort)."
