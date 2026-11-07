#!/usr/bin/env bash
# generate-keys.sh — mint the HookProbe OS Secure Boot key hierarchy (PK → KEK → db) + the UKI signing
# key. This is the ROOT OF TRUST for UEFI Secure Boot on UEFI targets (N100, arm64/x86 UEFI boards,
# VMs, HP appliances). The Pi boots via GPU/u-boot firmware, NOT UEFI SB — there boot integrity comes
# from dm-verity/composefs (ADR 0006 H3) + the software-PUF identity; signing the UKI is still done
# (harmless, and enforced anywhere the platform checks). See docs/adr/0006-os-hardening.md (H2).
#
#   PK  (Platform Key)      — owns the platform; self-signed root.
#   KEK (Key Exchange Key)  — authorizes db/dbx updates; signed under PK.
#   db  (signature db)      — the key that signs UKIs/bootloaders; what firmware checks at boot.
#
# PRIVATE KEYS NEVER ENTER THE REPO OR AN IMAGE. In production these live in a KMS/HSM (crypto-agility,
# ADR 0002) and CI signs via the KMS. This script is the reference/dev path; keys land in ./keys
# (gitignored). Crypto-agile: swap `-newkey rsa:4096` for an ML-DSA hybrid when the toolchain lands.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
KEYS="${HOOKPROBE_SB_KEYS:-$HERE/keys}"
DAYS="${HOOKPROBE_SB_DAYS:-7300}"   # 20y — field firmware outlives classical RSA; see CNSA 2.0 / PQC note
mkdir -p "$KEYS"; chmod 700 "$KEYS"

gen() { # name  CN
  local n=$1 cn=$2
  [ -f "$KEYS/$n.key" ] && { echo "  $n exists — keeping (delete to rotate)"; return; }
  openssl req -new -x509 -newkey rsa:4096 -nodes -sha256 -days "$DAYS" \
    -subj "/CN=HookProbe OS $cn/O=HookProbe/C=EU" \
    -keyout "$KEYS/$n.key" -out "$KEYS/$n.crt" 2>/dev/null
  openssl x509 -in "$KEYS/$n.crt" -outform DER -out "$KEYS/$n.der" 2>/dev/null
  chmod 600 "$KEYS/$n.key"
  echo "  ✓ $n  ($(openssl x509 -in "$KEYS/$n.crt" -noout -fingerprint -sha256 | cut -d= -f2 | cut -c1-23)…)"
}

echo "HookProbe OS Secure Boot key hierarchy → $KEYS"
gen PK  "Platform Key"
gen KEK "Key Exchange Key"
gen db  "Signature Database (UKI signer)"
# GUID for owner identity in EFI signature lists (stable per key-set).
[ -f "$KEYS/GUID" ] || openssl rand -hex 16 | sed 's/\(........\)\(....\)\(....\)\(....\)\(............\)/\1-\2-\3-\4-\5/' > "$KEYS/GUID"
echo "owner GUID: $(cat "$KEYS/GUID")"
echo
echo "NEXT: sign the UKI with ./sign-uki.sh <path-to.efi>; enroll PK/KEK/db per docs/adr/0006 (H2)."
echo "GUARD: keep $KEYS/*.key OFF the repo + out of every image (gitignored). Production → KMS/HSM."
