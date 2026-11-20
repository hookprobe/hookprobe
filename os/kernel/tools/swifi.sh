#!/usr/bin/env bash
# Autoheal harness H6 — the software fault-injection campaign ([P-swifi]) in QEMU.
#
#   tools/swifi.sh [N] [max seconds]        (default: 10000 injections, 5400 s)
#
# Builds the Mission Control kernel with the `swifi` feature (never shipped) and boots it once. The campaign runs
# inside the boot self-tests: N injections with a fixed seed into el0-lansvc, el0-tlshost and el0-hsh — one flipped bit in a
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
K="$CARGO_TARGET_DIR/aarch64-unknown-none-softfloat/debug/kernel"
QEMU=(qemu-system-aarch64 -M virt -cpu cortex-a72 -m 512M -nographic -serial mon:stdio -semihosting
  -global virtio-mmio.force-legacy=false -netdev user,id=n0 -device virtio-net-device,netdev=n0)
# H6e: the TLS handshake workload needs HTTPS on, i.e. a certificate for the key this kernel derives. Same recipe as
# tools/mc-e2e.sh: a first short boot prints the public key, a throwaway name-constrained CA certifies it, and the
# campaign boot gets a disk whose boot partition carries MCTLS.CRT. Without the tools for that (python cryptography,
# mtools, sfdisk) the campaign still runs, without the handshake calls (the report says how many calls were usable).
W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT
DRIVE=()
"${QEMU[@]}" -kernel "$K" > "$W/boot1.log" 2>&1 < /dev/null &
P1=$!; t=0
while kill -0 "$P1" 2>/dev/null && [ $t -lt 240 ]; do grep -aq 'pub=04[0-9a-f]\{128\}' "$W/boot1.log" && break; sleep 2; t=$((t + 2)); done
kill "$P1" 2>/dev/null; wait "$P1" 2>/dev/null
PUB=$(tr -d '\r' < "$W/boot1.log" | grep -ao 'pub=04[0-9a-f]\{128\}' | head -1 | cut -d= -f2)
if [ ${#PUB} = 130 ] && python3 tools/mctls-provision.py --ca-dir "$W/ca" --pub "$PUB" --name heqk.local --ip 127.0.0.1 \
     --permit-dns heqk.local --permit-ip 127.0.0.0/255.0.0.0 --out "$W/MCTLS.CRT" >/dev/null 2>&1 \
   && truncate -s 64M "$W/disk.img" && printf 'start=2048, size=129024, type=c\n' | sfdisk --quiet --label dos "$W/disk.img" \
   && truncate -s $((129024 * 512)) "$W/p1" && mkfs.vfat -F 32 -s 1 "$W/p1" >/dev/null && mcopy -i "$W/p1" "$W/MCTLS.CRT" ::MCTLS.CRT \
   && dd if="$W/p1" of="$W/disk.img" bs=512 seek=2048 conv=notrunc status=none; then
  DRIVE=(-drive "file=$W/disk.img,format=raw,if=none,id=hd0" -device virtio-blk-device,drive=hd0)
  echo "certificate provisioned for the campaign boot (TLS handshake workload on)"
else
  echo "no certificate provisioned (TLS handshake workload off): the campaign runs without it"
fi
"${QEMU[@]}" "${DRIVE[@]}" -kernel "$K" > "$LOG" 2>&1 < /dev/null &
QP=$!; t0=$(date +%s); rc=1
while kill -0 "$QP" 2>/dev/null; do
  grep -aq "\[P-swifi\] " "$LOG" && break
  [ $(( $(date +%s) - t0 )) -ge "$MAX" ] && { echo "TIMEOUT after $MAX s"; break; }
  sleep 5
done
sleep 2; kill "$QP" 2>/dev/null; wait "$QP" 2>/dev/null
grep -a "\[swifi\]" "$LOG" | tail -3
grep -a "\[P-swifi\]" "$LOG"
grep -a "MC-TLS\] HTTPS" "$LOG" | head -1
grep -aq "\[P-swifi\] PASS" "$LOG" && rc=0
echo "log: $LOG   wall: $(( $(date +%s) - t0 )) s"
exit $rc
