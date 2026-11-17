#!/usr/bin/env bash
# =============================================================================
# tools/ci/apt-install.sh — `apt-get update && apt-get install` for CI runners, retried.
#
# Why: a hosted runner sometimes gets a partial index — #1240 (2026-11-16): `apt-get update` fetched only the
# Microsoft repo, so `qemu-system-arm` / `mtools` were "not available" and the QEMU gate went red with no code
# change. A fresh update a little later succeeds. Three attempts with a pause; a package that is really gone still
# fails (after the third try), so this never hides a genuine rename.
#
#   tools/ci/apt-install.sh qemu-system-arm mtools dosfstools fdisk
# =============================================================================
set -u
[ $# -gt 0 ] || { echo "usage: $0 <package>..." >&2; exit 2; }
for attempt in 1 2 3; do
  if sudo apt-get update && sudo apt-get install -y --no-install-recommends "$@"; then
    exit 0
  fi
  [ "$attempt" = 3 ] && break
  echo "apt-install: attempt $attempt failed (partial package index?) — retrying in $((attempt * 20)) s" >&2
  sleep $((attempt * 20))
done
echo "apt-install: FAILED after 3 attempts: $*" >&2
exit 100
