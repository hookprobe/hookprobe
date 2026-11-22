#!/usr/bin/env bash
# HookProbe Neuro N0 hosted by heqk — the [P-neuro-*] QEMU self-tests (the repo-root design doc heqk-neuro-integration.md §8).
#
#   tools/neuro-qemu.sh [max seconds]        (default 900)
#
# Builds the Mission Control kernel with the `neuro` feature (never shipped) and boots it once. The el0-neuro tests run
# in the boot self-tests after the other EL0 servers: ABI v1.1 handshake, the 1,200 golden hour closes bit-exact
# through the real ABI, fault containment + journal, reply validation (complaint + reset), the host path (MAC
# attribution, batching, UTC hour roll, behaviour-deviation evidence) and backpressure. QEMU only: CM5 metal evidence
# is a separate step. Needs HEQK_UI_DIST (a built os/mission-control/dist), like tools/mc-e2e.sh. Heavy: run it under
# the machine-wide lock when other validate / QEMU runs share the host.
set -u
MAX="${1:-900}"
cd "$(dirname "$0")/.."
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-target/neuro}"
cargo build -q -p kernel --features mcserve,wpa3,hsh,neuro || exit 2
LOG="${NEURO_LOG:-$(mktemp /tmp/heqk-neuro.XXXXXX.log)}"; : > "$LOG"
K="$CARGO_TARGET_DIR/aarch64-unknown-none-softfloat/debug/kernel"
qemu-system-aarch64 -M virt -cpu cortex-a72 -m 512M -nographic -serial mon:stdio -semihosting \
  -global virtio-mmio.force-legacy=false -netdev user,id=n0 -device virtio-net-device,netdev=n0 \
  -kernel "$K" > "$LOG" 2>&1 < /dev/null &
QP=$!; t0=$(date +%s); rc=1
while kill -0 "$QP" 2>/dev/null; do
  grep -aq "\[P-neuro\] " "$LOG" && break
  [ $(( $(date +%s) - t0 )) -ge "$MAX" ] && { echo "TIMEOUT after $MAX s"; break; }
  sleep 3
done
sleep 1; kill "$QP" 2>/dev/null; wait "$QP" 2>/dev/null
grep -a "\[NEURO\]\|\[P-neuro" "$LOG"
grep -aE "^\[PANIC\]|panicked" "$LOG" | head -3
grep -aq "\[P-neuro\] PASS" "$LOG" && rc=0
echo "log: $LOG   wall: $(( $(date +%s) - t0 )) s"
exit $rc
