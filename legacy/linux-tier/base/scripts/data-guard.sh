#!/bin/sh
# data-guard.sh — FAIL-CLOSED confidentiality guard (ADR 0007, closes flow-analysis gap #1).
# Guarantees /var/lib/hookprobe is EITHER the encrypted dm-crypt mount OR a volatile tmpfs — NEVER a
# plain directory on the unencrypted root. Without this, a failed unlock (wrong/missing key, corrupt
# partition) leaves the `nofail` mount inactive, and bootstrap/supervisor/SOC would then write the
# manifest, DEVICE KEYS, captures, events and secrets in PLAINTEXT onto the SD — silently defeating E1.
# Runs AFTER var-lib-hookprobe.mount and BEFORE any writer (bootstrap/supervisor/reconcile/SOC).
set -u
TARGET=/var/lib/hookprobe
MAP=/dev/mapper/hookprobe-data-crypt
src=$(findmnt -no SOURCE "$TARGET" 2>/dev/null || true)

case "$src" in
  /dev/mapper/*)
    echo "data-guard: $TARGET is on encrypted $src — OK"
    exit 0 ;;
esac

# SELF-HEAL the udev race: `cryptsetup open` returns success and the dm device is visible to `dmsetup`
# SYNCHRONOUSLY, but the /dev/mapper NODE is created by udev a few ms later — so `[ -b $MAP ]` can be
# false immediately after unlock even though the crypt IS open (measured ~140ms lag on a Pi 4). So probe
# with `dmsetup` (synchronous): if the crypt is open, WAIT for the node, then mount it. The data is
# encrypted — we just raced udev. tmpfs ONLY if the crypt genuinely isn't open (unlock truly failed).
if dmsetup ls --target crypt 2>/dev/null | grep -q hookprobe-data-crypt; then
  udevadm settle 2>/dev/null || true
  i=0; while [ ! -b "$MAP" ] && [ "$i" -lt 20 ]; do sleep 0.25; i=$((i + 1)); done
  mkdir -p "$TARGET"
  if [ -b "$MAP" ] && mount -o noatime,nodev,nosuid "$MAP" "$TARGET" 2>/dev/null; then
    echo "data-guard: self-healed the udev race — mounted encrypted $MAP at $TARGET"
    exit 0
  fi
  echo "data-guard: crypt is open but node/mount failed ($MAP) — falling through to tmpfs"
fi

# Mapper absent (unlock truly failed) → refuse to persist plaintext: overlay a tmpfs so any
# writes are VOLATILE (lost on reboot) rather than landing unencrypted on the SD. Alert loudly so the
# operator/QSECBIT sees a degraded posture. Availability preserved (device runs); confidentiality held.
echo "data-guard: WARNING — $TARGET is NOT the encrypted volume (src='${src:-none}'; unlock failed?)."
echo "data-guard: mounting a VOLATILE tmpfs so NO plaintext secrets/data are written to disk (DEGRADED)."
mkdir -p "$TARGET"
mount -t tmpfs -o mode=0700,nosuid,nodev,noexec tmpfs "$TARGET" \
  || { echo "data-guard: tmpfs mount FAILED — refusing to continue (would write plaintext)"; exit 1; }
mkdir -p "$TARGET"
echo "encrypted data volume unavailable; running on volatile tmpfs (no persistence)" > "$TARGET/.DEGRADED"
exit 0
