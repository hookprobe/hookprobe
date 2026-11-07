#!/usr/bin/env bash
# enroll-keys.sh — enroll the HookProbe PK/KEK/db into a UEFI platform's Secure Boot variables so the
# firmware will only run our-signed UKIs. H2 follow-on; UEFI targets only (the Pi has no UEFI SB). Two
# paths — pick per platform. Run from generate-keys.sh's key dir. See docs/adr/0006-os-hardening.md.
#
#   MODE A — factory/setup-mode (own the platform): firmware in "Setup Mode" (custom keys), we install
#            db → KEK → PK (PK last; installing PK LOCKS the platform into User Mode = SB enforcing).
#            Needs efitools (efi-updatevar) or `sbkeysync`, run as root with efivarfs writable.
#   MODE B — shim + MOK (co-exist with Microsoft/OEM keys, e.g. generic N100): keep the OEM db, enroll
#            our db cert into the Machine Owner Key list via `mokutil --import db.der` (a reboot +
#            MokManager confirmation enrolls it). Best for hardware we don't fully own the PK on.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
KEYS="${HOOKPROBE_SB_KEYS:-$HERE/keys}"
MODE="${1:-mok}"
GUID=$(cat "$KEYS/GUID" 2>/dev/null || echo "00000000-0000-0000-0000-000000000000")
[ -f "$KEYS/db.crt" ] || { echo "no keys at $KEYS — run ./generate-keys.sh first"; exit 1; }
[ "$(id -u)" = 0 ] || { echo "must run as root (writes UEFI vars)"; exit 1; }

case "$MODE" in
  mok)  # MODE B — shim + MOK (safest on generic hardware)
    command -v mokutil >/dev/null || { echo "install mokutil (apt: mokutil)"; exit 1; }
    echo "enrolling db.der into the MOK list (reboot → MokManager will prompt to confirm)…"
    mokutil --import "$KEYS/db.der"
    echo "✓ queued. Reboot, choose 'Enroll MOK' → 'Continue', enter the password you just set." ;;
  setup)  # MODE A — custom PK/KEK/db, platform in Setup Mode
    command -v efi-updatevar >/dev/null || { echo "install efitools (apt: efitools)"; exit 1; }
    echo "installing db → KEK → PK (PK LAST locks SB into enforcing). Platform must be in Setup Mode."
    efi-updatevar -c "$KEYS/db.crt"  -k "$KEYS/KEK.key" db
    efi-updatevar -c "$KEYS/KEK.crt" -k "$KEYS/PK.key"  KEK
    efi-updatevar -c "$KEYS/PK.crt"  -k "$KEYS/PK.key"  PK
    echo "✓ enrolled. Platform now enforces HookProbe-signed boot (owner GUID $GUID)." ;;
  *) echo "usage: enroll-keys.sh [mok|setup]"; exit 1 ;;
esac
