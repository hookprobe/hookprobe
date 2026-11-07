#!/bin/sh
# unlock-data.sh — open the plain-dm-crypt data volume at boot (ADR 0007 E1+E3), BEFORE
# var-lib-hookprobe.mount. The master key is unwrapped via the SELF-DETECTED platform anchor
# (TPM / CM5-OTP / passphrase / Tang / software — key-anchor.sh) and piped straight to cryptsetup, so
# for the hardware/passphrase anchors it never touches disk. Plain mode: no header; the raw partition
# is found by PARTUUID recorded at provisioning. Idempotent + non-fatal (data-guard tmpfs-falls-closed).
set -u
MAP=hookprobe-data-crypt
ANCHOR=/etc/hookprobe/keys/anchor

[ -b "/dev/mapper/$MAP" ] && exit 0          # already open (e.g. first boot opened it) — no-op
[ -f "$ANCHOR" ] || { echo "unlock-data: not provisioned (no anchor state) — mount is nofail"; exit 0; }

DEV=""
PU=$(cat /etc/hookprobe/data-partuuid 2>/dev/null)
[ -n "$PU" ] && [ -b "/dev/disk/by-partuuid/$PU" ] && DEV="/dev/disk/by-partuuid/$PU"
[ -b "$DEV" ] || DEV=$(cat /etc/hookprobe/data-partdev 2>/dev/null)
[ -b "$DEV" ] || { echo "unlock-data: data partition not found (pre-provision) — mount is nofail"; exit 0; }

modprobe dm_crypt 2>/dev/null || true
# Unwrap the master key to a PRIVATE tmpfs keyfile, then open with --key-file <file>.
# CRITICAL: in plain mode, cryptsetup derives a DIFFERENT key from stdin ('--key-file -') than from a
# regular file — even for identical bytes — so piping the key produces a garbage mapper (no filesystem).
# We MUST match firstboot's file-based read (that's the key the volume was mkfs'd with). /run is tmpfs
# (RAM), so the plaintext key never lands on disk; it's shredded immediately after the open.
KT="$(mktemp /run/hp-datakey.XXXXXX 2>/dev/null || echo /run/hp-datakey)"
( umask 077; /usr/lib/hookprobe/key-anchor.sh unwrap > "$KT" )
if cryptsetup --type plain --cipher aes-xts-plain64 --key-size 512 --key-file "$KT" open "$DEV" "$MAP"; then
  shred -u "$KT" 2>/dev/null || rm -f "$KT"
  udevadm settle 2>/dev/null || true   # let udev create the /dev/mapper node + by-label before mount/data-guard
  echo "unlock-data: opened $DEV → /dev/mapper/$MAP (anchor=$(cat "$ANCHOR"))"
else
  shred -u "$KT" 2>/dev/null || rm -f "$KT"
  echo "unlock-data: open FAILED on $DEV (anchor=$(cat "$ANCHOR" 2>/dev/null)) — leaving locked; data-guard will fail-closed to tmpfs"
fi
