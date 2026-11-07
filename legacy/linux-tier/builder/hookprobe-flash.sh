#!/usr/bin/env bash
# =============================================================================
# hookprobe-flash.sh — the INSTALL GATE: verify-then-flash a HookProbe image.
# =============================================================================
# "otherwise, installation aborted" (operator's E4 requirement): an OFFICIAL image with a
# missing/invalid signature is REFUSED before any bytes touch the device. Self-built images
# (no signature) require an explicit --allow-unsigned — you built it, you vouch for it.
#
#   hookprobe-flash.sh <image.img[.xz]> <device> [--allow-unsigned]
#   e.g.  sudo hookprobe-flash.sh hookprobe-os-pi4.img.xz /dev/sda
# =============================================================================
set -euo pipefail
IMG="${1:?usage: hookprobe-flash.sh <image.img[.xz]> <device> [--allow-unsigned]}"
DEV="${2:?usage: hookprobe-flash.sh <image.img[.xz]> <device> [--allow-unsigned]}"
ALLOW="${3:-}"
HERE="$(cd "$(dirname "$0")" && pwd)"
VERIFY="$HERE/../security/cosign/verify-image.sh"

echo "== GATE: verifying $IMG before flashing"
if ! "$VERIFY" "$IMG" ${ALLOW:+"$ALLOW"}; then
  echo "ABORT: verification failed — NOT flashing. (If you built this image yourself, re-run with --allow-unsigned.)" >&2
  exit 1
fi

[ -b "$DEV" ] || { echo "ABORT: $DEV is not a block device." >&2; exit 1; }
echo "== flashing $IMG → $DEV  (THIS ERASES $DEV)"
umount "${DEV}"* 2>/dev/null || true; sync
case "$IMG" in
  *.xz) xzcat "$IMG" | dd of="$DEV" bs=4M conv=fsync status=progress ;;
  *)    dd if="$IMG" of="$DEV" bs=4M conv=fsync status=progress ;;
esac
sync
echo "OK: flashed $IMG → $DEV (signature-verified)."
