#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# QEMU integration-test profile (`qemu-itest`, operator decision 2026-11-22): entropy + per-VM sealed-volume checks.
#   tools/itest-qemu.sh [max seconds per boot]
# Same device set as the S1 harness (PR #1489), no -semihosting. Needs HEQK_UI_DIST like tools/mc-e2e.sh.
#  R1 with virtio-rng                         -> [P-itest-rng] PASS
#  R2 without virtio-rng                      -> [P-itest-rng] FAIL-CLOSED (no keys)
#  V1 VM-A blank disk, KEK-A                  -> formatted, VEK created, identity A, PASS
#  V2 VM-A again, KEK-A                       -> VEK loaded, same identity, 1 earlier marker verified, PASS
#  V3 VM-A with VM-B's KEK                    -> FAIL-CLOSED (wrong key: refused, nothing written)
#  V4 VM-A, KEK-A + kek-next N                -> rotation done, PASS
#  V5 VM-A, KEK N                             -> loaded under the rotated key, same identity, 3 earlier markers, PASS
#  V6 VM-A, KEK-A (after rotation)            -> FAIL-CLOSED (the old KEK no longer opens it)
#  V7 VM-B blank disk, KEK-B                  -> a DIFFERENT identity (no key shared across VMs)
#  V8 no KEK                                  -> [P-itest-vol] FAIL-CLOSED
#  host: VM-A's raw disk holds no plaintext marker and no KEK bytes
set -u
MAX="${1:-600}"
cd "$(dirname "$0")/.."
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-target/itest}"
cargo build -q -p kernel --features mcserve,wpa3,hsh,qemu-itest || exit 2
K="$CARGO_TARGET_DIR/aarch64-unknown-none-softfloat/debug/kernel"
W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT
for k in A B N; do head -c 32 /dev/urandom > "$W/kek$k.bin"; chmod 600 "$W/kek$k.bin"; done
truncate -s 64M "$W/diskA.img" "$W/diskB.img"
# the host provisions the partition table (the guest never writes LBA 0): one 0xDA DataVolume partition from LBA 2048
for d in "$W/diskA.img" "$W/diskB.img"; do printf 'start=2048, type=da\n' | sfdisk --quiet --label dos "$d" || exit 2; done
truncate -s 64M "$W/diskU.img" # unprovisioned: must be refused
ok=0; n=0; chk() { n=$((n+1)); if [ "$1" = 0 ]; then echo "ok  $2"; ok=$((ok+1)); else echo "BAD $2"; fi; }
# boot <log> <rng 1|0> <kek file|-> <disk|-> [kek-next file] ; waits for the last [P-itest-*] line
boot() {
  local log=$1 rng=() fw=() dsk=() tag="P-itest-vol"
  [ "$2" = 1 ] && rng=(-object rng-random,id=rng0,filename=/dev/urandom -device virtio-rng-device,rng=rng0)
  [ "$3" != - ] && fw=(-fw_cfg name=opt/hookprobe/kek,file="$3")
  [ -n "${5:-}" ] && fw+=(-fw_cfg name=opt/hookprobe/kek-next,file="$5")
  [ "$4" != - ] && dsk=(-drive file="$4",format=raw,if=none,id=hd0 -device virtio-blk-device,drive=hd0)
  qemu-system-aarch64 -M virt -cpu cortex-a72 -m 512M -nodefaults -display none -monitor none -serial "file:$log" \
    -global virtio-mmio.force-legacy=false "${rng[@]}" "${fw[@]}" -netdev user,id=n0 -device virtio-net-device,netdev=n0 \
    "${dsk[@]}" -kernel "$K" &
  local qp=$! t0=$(date +%s)
  while kill -0 $qp 2>/dev/null; do grep -aq "\[$tag\] " "$log" 2>/dev/null && break; [ $(( $(date +%s) - t0 )) -ge "$MAX" ] && break; sleep 3; done
  sleep 1; kill $qp 2>/dev/null; wait $qp 2>/dev/null
}
line() { grep -a "\[$2\]" "$1" | head -1 | cut -c1-300; }
pk() { grep -ao "\[ITEST\] device identity pk=[0-9a-f]*" "$1" | head -1 | cut -d= -f2; }
boot "$W/r1.log" 1 "$W/kekA.bin" "$W/diskA.img"; echo "   $(line "$W/r1.log" P-itest-rng)"; grep -aq "\[P-itest-rng\] PASS" "$W/r1.log"; chk $? "R1 virtio-rng entropy health-checked and sane"
line "$W/r1.log" P-itest-vol | sed 's/^/   V1: /'
grep -aq "\[P-itest-vol\] PASS.*disk new.*created from virtio-rng" "$W/r1.log"; chk $? "V1 provisioned disk: per-VM VEK created from virtio-rng, sealed under the KEK"
PKA=$(pk "$W/r1.log"); [ ${#PKA} = 64 ]; chk $? "V1 per-VM identity printed (${PKA:0:16}…)"
boot "$W/r2.log" 0 "$W/kekA.bin" -; grep -aq "\[P-itest-rng\] FAIL-CLOSED" "$W/r2.log" && grep -aq "\[P-itest-vol\] FAIL-CLOSED" "$W/r2.log"; chk $? "R2 without virtio-rng: entropy and volume both fail closed"
boot "$W/v2.log" 1 "$W/kekA.bin" "$W/diskA.img"; line "$W/v2.log" P-itest-vol | sed 's/^/   V2: /'
grep -aq "\[P-itest-vol\] PASS.*VEK loaded.*earlier boots' markers verified=1" "$W/v2.log" && [ "$(pk "$W/v2.log")" = "$PKA" ]; chk $? "V2 reboot: VEK loaded, same identity, boot-1 record verified (persistence)"
cp "$W/diskA.img" "$W/diskA.before-v3"
boot "$W/v3.log" 1 "$W/kekB.bin" "$W/diskA.img"; line "$W/v3.log" P-itest-vol | sed 's/^/   V3: /'
grep -aq "\[P-itest-vol\] FAIL-CLOSED.*does not unseal" "$W/v3.log" && cmp -s "$W/diskA.img" "$W/diskA.before-v3"; chk $? "V3 another VM's KEK: refused, disk byte-identical (nothing written, no key generated)"
boot "$W/v4.log" 1 "$W/kekA.bin" "$W/diskA.img" "$W/kekN.bin"; line "$W/v4.log" P-itest-vol | sed 's/^/   V4: /'
grep -aq "\[P-itest-vol\] PASS.*rotation done" "$W/v4.log"; chk $? "V4 key rotation to kek-next through the staging slot"
boot "$W/v5.log" 1 "$W/kekN.bin" "$W/diskA.img"; line "$W/v5.log" P-itest-vol | sed 's/^/   V5: /'
grep -aq "\[P-itest-vol\] PASS.*VEK loaded.*verified=3" "$W/v5.log" && [ "$(pk "$W/v5.log")" = "$PKA" ]; chk $? "V5 the rotated KEK opens the volume: same identity, all earlier records verified"
boot "$W/v6.log" 1 "$W/kekA.bin" "$W/diskA.img"; grep -aq "\[P-itest-vol\] FAIL-CLOSED" "$W/v6.log"; chk $? "V6 the old KEK no longer opens the volume after rotation"
boot "$W/v7.log" 1 "$W/kekB.bin" "$W/diskB.img"; PKB=$(pk "$W/v7.log"); [ ${#PKB} = 64 ] && [ "$PKB" != "$PKA" ]; chk $? "V7 a second VM gets a different identity and VEK (nothing shared)"
boot "$W/v8.log" 1 - "$W/diskB.img"; grep -aq "\[P-itest-vol\] FAIL-CLOSED.*no per-VM KEK" "$W/v8.log"; chk $? "V8 no KEK: volume and keys refused"
boot "$W/v9.log" 1 "$W/kekA.bin" "$W/diskU.img"; grep -aq "\[P-itest-vol\] FAIL-CLOSED.*no partition table" "$W/v9.log" && [ -z "$(head -c 512 "$W/diskU.img" | tr -d '\0')" ]; chk $? "V9 unprovisioned disk refused; LBA 0 untouched (the guest never writes the MBR)"
! grep -aq "HQ-ITEST-PERSIST-MARKER" "$W/diskA.img" && ! grep -Faq "$(cat "$W/kekA.bin")" "$W/diskA.img" && ! grep -Faq "$(cat "$W/kekN.bin")" "$W/diskA.img"; chk $? "host scan of VM-A's raw disk: no plaintext marker, no KEK bytes"
grep -aE "^\[PANIC\]|panicked" "$W"/*.log | head -3
echo "ITEST: $([ $ok = $n ] && echo PASS || echo FAIL) ($ok/$n)"
[ $ok = $n ]
