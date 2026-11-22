#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# QEMU integration-test profile (`qemu-itest`, operator decision 2026-11-22): the virtio-rng entropy checks.
#   tools/itest-qemu.sh [max seconds]
# Boot 1: with `-device virtio-rng-device` (host /dev/urandom)  -> expects `[P-itest-rng] PASS`.
# Boot 2: WITHOUT it                                           -> expects `[P-itest-rng] FAIL-CLOSED` (no key generation).
# No -semihosting (the S1 harness forbids host file I/O for the guest). Needs HEQK_UI_DIST like tools/mc-e2e.sh.
set -u
MAX="${1:-600}"
cd "$(dirname "$0")/.."
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-target/itest}"
cargo build -q -p kernel --features mcserve,wpa3,hsh,qemu-itest || exit 2
K="$CARGO_TARGET_DIR/aarch64-unknown-none-softfloat/debug/kernel"
W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT
head -c 32 /dev/urandom > "$W/kek.bin"; chmod 600 "$W/kek.bin"
boot() { # $1 = log, $2 = with rng (1/0), $3 = tag to wait for
  local rng=(); [ "$2" = 1 ] && rng=(-object rng-random,id=rng0,filename=/dev/urandom -device virtio-rng-device,rng=rng0)
  qemu-system-aarch64 -M virt -cpu cortex-a72 -m 512M -nodefaults -display none -monitor none -serial "file:$1" \
    -global virtio-mmio.force-legacy=false "${rng[@]}" -fw_cfg name=opt/hookprobe/kek,file="$W/kek.bin" \
    -netdev user,id=n0 -device virtio-net-device,netdev=n0 -kernel "$K" &
  local qp=$! t0=$(date +%s)
  while kill -0 $qp 2>/dev/null; do grep -aq "\[P-itest-rng\] " "$1" 2>/dev/null && break; [ $(( $(date +%s) - t0 )) -ge "$MAX" ] && break; sleep 3; done
  sleep 1; kill $qp 2>/dev/null; wait $qp 2>/dev/null
}
boot "$W/with.log" 1; boot "$W/without.log" 0
grep -a "\[P-itest-rng\]" "$W/with.log" "$W/without.log" | sed "s#$W/##"
grep -aE "^\[PANIC\]|panicked" "$W/with.log" "$W/without.log" | head -3
rc=1
grep -aq "\[P-itest-rng\] PASS" "$W/with.log" && grep -aq "\[P-itest-rng\] FAIL-CLOSED" "$W/without.log" && rc=0
echo "ITEST-RNG: $([ $rc = 0 ] && echo PASS || echo FAIL) (with device: PASS expected; without: FAIL-CLOSED expected)"
exit $rc
