#!/usr/bin/env bash
# mc-e2e-tls-soak.sh — repro loop for the HTTPS keep-alive stall (CI g3 2026-11-12: after mc-e2e [7]'s TLS stress
# the Detect page's API calls got no answer for 60 s). Boots the mcserve kernel with a provisioned certificate
# (same image + disk recipe as tools/mc-e2e.sh), then ROUNDS times: the [7] stress (80-connection flood, garbage on
# :443, an AES-GCM-only client) followed by tools/mc-e2e/tls-stall.mjs (fresh browser contexts: sign in, Home with
# its SSE stream open -> Detect, every Detect API call timed). Prints the per-slot dump the device logs every 10 s.
#
#   tools/mc-e2e-tls-soak.sh                  ROUNDS=3 REPS=3 INNER=3
#   ROUNDS=10 tools/mc-e2e-tls-soak.sh        more repetitions
#   MC_E2E_PCAP=1 ...                         also write a QEMU user-net pcap (filter-dump) into the run dir
# Exit 0 = no stall in any round. One QEMU at a time (it takes the host's QEMU slot).
set -u
cd "$(dirname "$0")/.."
[ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"
export PATH="$HOME/.local/node/bin:$PATH"
ROUNDS=${ROUNDS:-3}
PB=${MC_E2E_PORT_BASE:-19500}
HOST=127.0.0.1; HTTP=$((PB+80)); HTTPS=$((PB+443)); P4444=$((PB+444))
RUN=$(mktemp -d /tmp/mc-tls-soak.XXXX); LOG="$RUN/qemu.log"
echo "  (ports ${HTTP}/${HTTPS}, run dir $RUN)"
[ -d tools/mc-e2e/node_modules/playwright ] || { echo "Playwright not installed in tools/mc-e2e"; exit 2; }
[ -f ../mission-control/dist/index.html ] || { echo "os/mission-control/dist missing (see tools/mc-e2e.sh [1])"; exit 2; }
export CARGO_TARGET_DIR=target/mc
cargo build -p kernel --features mcserve,wpa3,hsh >"$RUN/build.log" 2>&1 || { tail -20 "$RUN/build.log"; exit 2; }
KERNEL=target/mc/aarch64-unknown-none-softfloat/debug/kernel

TOKEN="E2E$(python3 -I -c 'import secrets;print(secrets.token_hex(12))')"
DISK="$RUN/disk.img"; PART="$RUN/part.img"
truncate -s 64M "$DISK"; printf 'start=2048, size=129024, type=c\n' | sfdisk --quiet --label dos "$DISK"
truncate -s $((129024*512)) "$PART"; mkfs.vfat -F 32 -s 1 "$PART" >/dev/null
python3 -I - "$RUN/owner" "$TOKEN" <<'PY'
import sys, os, hashlib
salt = os.urandom(16)
open(sys.argv[1], "w").write(f"HQOWN1 {salt.hex()} {hashlib.sha256(salt + sys.argv[2].encode()).hexdigest()}".ljust(127) + "\n")
PY
mcopy -i "$PART" "$RUN/owner" ::OWNER.TXT

QPID=
boot() { # $1 = log; $2.. = extra QEMU args
  local log=$1; shift
  qemu-system-aarch64 -M virt -cpu cortex-a72 -m 512M -nographic -serial mon:stdio -semihosting \
    -global virtio-mmio.force-legacy=false \
    -netdev user,id=n0,hostfwd=tcp:$HOST:$HTTP-:80,hostfwd=tcp:$HOST:$HTTPS-:443,hostfwd=tcp:$HOST:$P4444-:4444 \
    -device virtio-net-device,netdev=n0 "$@" \
    -drive file="$DISK",format=raw,if=none,id=hd0 -device virtio-blk-device,drive=hd0 -kernel "$KERNEL" >"$log" 2>&1 &
  QPID=$!
  for _ in $(seq 1 120); do grep -qa "\[MC\] heqk Mission Control serving on http://10.0.2.15" "$log" && return 0; sleep 1; done
  return 1
}
trap '[ -n "$QPID" ] && kill "$QPID" 2>/dev/null' EXIT

# boot 1: read the device's TLS public key; certify it with a throwaway owner CA
dd if="$PART" of="$DISK" bs=512 seek=2048 conv=notrunc status=none
boot "$RUN/boot1.log" || { echo "boot 1 did not serve"; exit 2; }
PUB=$(tr -d '\r' < "$RUN/boot1.log" | grep -ao 'pub=04[0-9a-f]\{128\}' | head -1 | cut -d= -f2)
kill "$QPID"; wait "$QPID" 2>/dev/null; QPID=
python3 tools/mctls-provision.py --ca-dir "$RUN/ca" --pub "$PUB" --name heqk.local --ip 127.0.0.1 \
  --permit-dns heqk.local --permit-ip 127.0.0.0/255.0.0.0 --permit-ip 10.0.0.0/255.0.0.0 --out "$RUN/MCTLS.CRT" >/dev/null || { echo "provisioning failed"; exit 2; }
mcopy -i "$PART" "$RUN/MCTLS.CRT" ::MCTLS.CRT && dd if="$PART" of="$DISK" bs=512 seek=2048 conv=notrunc status=none

# boot 2: HTTPS
PCAP=(); [ "${MC_E2E_PCAP:-0}" = 1 ] && PCAP=(-object "filter-dump,id=f0,netdev=n0,file=$RUN/net.pcap")
boot "$LOG" "${PCAP[@]}" || { echo "boot 2 did not serve"; exit 2; }
grep -qa "HTTPS ready on :443" "$LOG" || { echo "HTTPS not ready"; exit 2; }
BS="https://heqk.local:$HTTPS"
C=(--cacert "$RUN/ca/ca.pem" --resolve "heqk.local:$HTTPS:$HOST" -sS -m 30)
SPKI=$(openssl x509 -in <(dd if="$RUN/MCTLS.CRT" bs=1 skip=12 count=$(python3 -I -c "import struct,sys;print(struct.unpack('<H',open(sys.argv[1],'rb').read()[10:12])[0])" "$RUN/MCTLS.CRT") status=none) -inform DER -pubkey -noout | openssl pkey -pubin -outform DER | openssl dgst -sha256 -binary | base64)

stress() { # mc-e2e [7]: AES-GCM-only client, 80-connection flood, keep-alive pair, garbage
  echo | timeout 20 openssl s_client -connect "$HOST:$HTTPS" -servername heqk.local -tls1_3 -ciphersuites TLS_AES_256_GCM_SHA384 >/dev/null 2>&1
  local FP=(); for _ in $(seq 1 80); do curl "${C[@]}" -o /dev/null -m 5 "$BS/api/health" 2>/dev/null & FP+=($!); done; wait "${FP[@]}" 2>/dev/null
  for _ in 1 2 3 4 5; do sleep 2; [ -n "$(curl "${C[@]}" "$BS/api/health" 2>/dev/null)" ] && break; done
  curl "${C[@]}" -o /dev/null -o /dev/null "$BS/api/health" "$BS/api/health" 2>/dev/null
  head -c 3000 /dev/urandom | timeout 10 nc -q 2 "$HOST" "$HTTPS" >/dev/null 2>&1
  curl "${C[@]}" -o /dev/null "$BS/api/health" 2>/dev/null
}

TOTAL=0; STALLS=0; MAX=0
for r in $(seq 1 "$ROUNDS"); do
  echo "== round $r/$ROUNDS: [7] stress, then the browser"
  stress
  OUT=$(cd tools/mc-e2e && MC_E2E_SPKI="$SPKI" node tls-stall.mjs "$BS" "$TOKEN" 2>&1); echo "$OUT"
  L=$(grep -a '^TLS-STALL' <<<"$OUT" | tail -1)
  n=$(sed -n 's/.* calls=\([0-9]*\).*/\1/p' <<<"$L"); s=$(sed -n 's/.* stalls=\([0-9]*\).*/\1/p' <<<"$L"); m=$(sed -n 's/.* max_ms=\([0-9]*\).*/\1/p' <<<"$L")
  TOTAL=$((TOTAL+${n:-0})); STALLS=$((STALLS+${s:-1})); [ "${m:-0}" -gt "$MAX" ] && MAX=$m
  tr -d '\r' < "$LOG" | grep -a "MC-TLS slots\|MC-TLS hb" | tail -2 | sed 's/^/        /'
done
sleep 11; tr -d '\r' < "$LOG" | grep -a "MC-TLS slots\|MC-TLS hb\|MC hb" | tail -3 | sed 's/^/        /'
echo "TLS-SOAK rounds=$ROUNDS calls=$TOTAL stalls=$STALLS max_ms=$MAX (log $LOG)"
[ "$STALLS" = 0 ]
