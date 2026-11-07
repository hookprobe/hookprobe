#!/usr/bin/env bash
# Sequential, ISOLATED rebuild of both edge-kernel flavours: 2712 (CM5 acid test) then v8.
# Each flavour builds out-of-tree into its own $WORK/build-<flavour> via O=, so they
# cannot share .config/vmlinux and cannot clobber each other. Progress -> progress.log.
set -uo pipefail
HERE="/home/andrei/hookprobe-os/builder"
PROG="$HERE/kernel-build/out/progress.log"
mark(){ printf '[%(%H:%M:%S)T] %s\n' -1 "$*" | tee -a "$PROG"; }

: > "$PROG"
mark "=== edge-kernel clean rebuild START (2712 then v8, isolated O= builds) ==="

for FL in 2712 v8; do
  mark ">>> flavour=$FL : starting"
  if FLAVOUR="$FL" bash "$HERE/build-edge-kernel.sh"; then
    mark "<<< flavour=$FL : SUCCESS"
  else
    rc=$?
    mark "!!! flavour=$FL : FAILED rc=$rc (see out/build-$FL.log). Continuing to next flavour."
  fi
done

mark "=== edge-kernel clean rebuild DONE ==="
mark "artifacts:"
ls -la "$HERE/kernel-build/out" | tee -a "$PROG"
