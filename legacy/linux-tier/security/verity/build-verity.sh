#!/usr/bin/env bash
# build-verity.sh — compute a dm-verity hash tree + root hash over a rootfs image/partition so the
# rootfs becomes read-only + cryptographically tamper-EVIDENT: any single block change → an I/O error
# at read time (fail-closed). For the Pi (no TPM, no UEFI Secure Boot) this is THE rootfs-integrity
# mechanism — the equivalent of Bottlerocket's dm-verity root (ADR 0006 H3). It also matches our
# immutable-OS design: the rootfs is RO, writable state lives on /var/lib/hookprobe.
#
#   ./build-verity.sh <rootfs.img-or-dev> <hashtree-out> [roothash-out]
#
# The root hash is the trust anchor: whoever controls it controls what the rootfs is allowed to be.
# It is put on the (integrity-protected) boot cmdline; the hash tree ships in its own partition/blob.
# At boot the initramfs runs `veritysetup open <root> hookprobe-verity <hashtree> <roothash>` →
# /dev/mapper/hookprobe-verity (read-only, verified). rootfs-integrity-check.sh re-verifies online.
set -euo pipefail
ROOT="${1:?usage: build-verity.sh <rootfs> <hashtree-out> [roothash-out]}"
HASH="${2:?hashtree output path}"
RHOUT="${3:-$HASH.roothash}"

command -v veritysetup >/dev/null || { echo "veritysetup missing (apt: cryptsetup-bin)"; exit 1; }
out=$(veritysetup format "$ROOT" "$HASH")
printf '%s\n' "$out"
rh=$(printf '%s\n' "$out" | awk '/Root hash:/ {print $3}')
[ -n "$rh" ] || { echo "failed to parse root hash"; exit 1; }
printf '%s\n' "$rh" > "$RHOUT"
echo "verity: root hash $rh → $RHOUT   (hash tree → $HASH)"
