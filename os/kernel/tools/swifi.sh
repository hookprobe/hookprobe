#!/usr/bin/env bash
# Autoheal harness H6 — the software fault-injection campaign ([P-swifi]) in QEMU.
#
#   tools/swifi.sh [N] [max seconds]        (default: 10000 injections, 5400 s)
#
# Builds the Mission Control kernel with the `swifi` feature (never shipped) and boots it once. The campaign runs
# inside the boot self-tests: N injections with a fixed seed into el0-lansvc and el0-tlshost — one flipped bit in a
# random page of the server's image (text, read-only data, writable data), or a call with a random command id and
# random input. After each injection the server's functional probe runs, the whole image is put back from the signed
# ELF, and the server must answer its probe again. PASS = no injection left a server unable to answer, the kernel
# survived, and every journal entry the campaign opened is closed.
#
# Needs HEQK_UI_DIST (a built os/mission-control/dist), like tools/mc-e2e.sh. Heavy: run it under the machine-wide
# lock when other validate / QEMU runs share the host.
set -u
N="${1:-10000}"; MAX="${2:-5400}"
cd "$(dirname "$0")/.."
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-target/swifi}"
HEQK_SWIFI_N="$N" cargo build -q -p kernel --features mcserve,wpa3,hsh,swifi || exit 2
LOG="${SWIFI_LOG:-$(mktemp /tmp/heqk-swifi.XXXXXX.log)}"; : > "$LOG"
qemu-system-aarch64 -M virt -cpu cortex-a72 -m 512M -nographic -serial mon:stdio -semihosting \
  -global virtio-mmio.force-legacy=false -netdev user,id=n0 -device virtio-net-device,netdev=n0 \
  -kernel "$CARGO_TARGET_DIR/aarch64-unknown-none-softfloat/debug/kernel" > "$LOG" 2>&1 < /dev/null &
QP=$!; t0=$(date +%s); rc=1
while kill -0 "$QP" 2>/dev/null; do
  grep -aq "\[P-swifi\] " "$LOG" && break
  [ $(( $(date +%s) - t0 )) -ge "$MAX" ] && { echo "TIMEOUT after $MAX s"; break; }
  sleep 5
done
sleep 2; kill "$QP" 2>/dev/null; wait "$QP" 2>/dev/null
grep -a "\[swifi\]" "$LOG" | tail -3
grep -a "\[P-swifi\]" "$LOG"
grep -aq "\[P-swifi\] PASS" "$LOG" && rc=0
echo "log: $LOG   wall: $(( $(date +%s) - t0 )) s"
exit $rc
