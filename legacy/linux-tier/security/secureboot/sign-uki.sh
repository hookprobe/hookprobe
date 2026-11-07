#!/usr/bin/env bash
# sign-uki.sh — sign a Unified Kernel Image (the mkosi .efi) with the HookProbe `db` key so UEFI Secure
# Boot accepts it, then verify. Idempotent + safe to re-run (sbsign refuses to double-sign; we detect).
# Called from build-arm64.sh after mkosi produces the UKI. See docs/adr/0006-os-hardening.md (H2).
#
#   ./sign-uki.sh <uki.efi> [output.efi]
#
# If the db key is absent (no HOOKPROBE_SB_KEYS / ./keys), this is a NON-FATAL skip — an unsigned image
# still boots on platforms with Secure Boot OFF (dev/Pi), and CI signs via KMS in production.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
KEYS="${HOOKPROBE_SB_KEYS:-$HERE/keys}"
IN="${1:?usage: sign-uki.sh <uki.efi> [out.efi]}"
OUT="${2:-$IN}"

[ -f "$KEYS/db.key" ] || { echo "sign-uki: no db key at $KEYS — SKIP (unsigned; enroll+sign in prod/CI)"; exit 0; }
command -v sbsign >/dev/null || { echo "sign-uki: sbsign not found (apt: sbsigntool) — SKIP"; exit 0; }

if sbverify --cert "$KEYS/db.crt" "$IN" >/dev/null 2>&1; then
  echo "sign-uki: $IN already signed by our db — OK"; exit 0
fi
tmp=$(mktemp)
sbsign --key "$KEYS/db.key" --cert "$KEYS/db.crt" --output "$tmp" "$IN"
mv "$tmp" "$OUT"
sbverify --cert "$KEYS/db.crt" "$OUT" >/dev/null
echo "sign-uki: ✓ signed + verified $OUT (db: $(openssl x509 -in "$KEYS/db.crt" -noout -subject | sed 's/.*CN=//;s/,.*//'))"
