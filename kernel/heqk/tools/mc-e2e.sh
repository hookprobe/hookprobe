#!/usr/bin/env bash
# mc-e2e.sh — END-TO-END proof that heqk alone runs the SOC and serves Mission Control
# (ADR 0047): real attack traffic → heqk IPS (packet::verdict) → SOAR event → device evidence
# state → heqk's own HTTP API → the unchanged Mission Control UI in a real browser.
# No Linux anywhere in the device path (QEMU emulates the hardware only).
#
#   tools/mc-e2e.sh            build + boot + API assertions (+ browser assertions if available)
#   MC_E2E_KEEP=1 tools/...    leave the VM running afterwards (open http://127.0.0.1:18080)
#
# Browser leg: needs node (~/.local/node/bin) + Playwright Chromium (tools/mc-e2e/). Without them
# the script says so and reports the API leg only — never a silent pass.
set -u
cd "$(dirname "$0")/.."
[ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"
export PATH="$HOME/.local/node/bin:$PATH"

HOST=127.0.0.1; HTTP=18080; P4444=14444; P23=12323
B="http://$HOST:$HTTP"
LOG=$(mktemp /tmp/mc-e2e-qemu.XXXX.log)
FAILS=0
ok()   { echo "  PASS  $*"; }
bad()  { echo "  FAIL  $*"; FAILS=$((FAILS+1)); }
jget() { python3 -I -c "import json,sys; d=json.load(sys.stdin); print(eval(sys.argv[1], {'d': d}))" "$1"; }

echo "[1] build the Mission Control UI (same-origin API) + the heqk mcserve kernel"
UI=../../ui
if [ ! -f "$UI/dist/index.html" ]; then
  command -v npm >/dev/null || { echo "  npm not found and ui/dist missing — cannot embed the UI"; exit 2; }
  (cd "$UI" && npm ci --no-audit --no-fund >/dev/null && PUBLIC_API_BASE='' npm run build >/dev/null) || { echo "  UI build failed"; exit 2; }
fi
# Private target dir: never overwrite the shared target/ other builders/sessions flash from.
export CARGO_TARGET_DIR=target/mc
cargo build -p kernel --features mcserve >/tmp/mc-e2e-build.log 2>&1 || { tail -20 /tmp/mc-e2e-build.log; exit 2; }
KERNEL=target/mc/aarch64-unknown-none-softfloat/debug/kernel

echo "[1b] boot disk with an owner key (ADR 0037 D3: the device stores only a salted verifier)"
TOKEN="E2E$(python3 -I -c 'import secrets;print(secrets.token_hex(12))')"
DISK=$(mktemp /tmp/mc-e2e-disk.XXXX.img); PART=$(mktemp)
truncate -s 64M "$DISK"; printf 'start=2048, size=129024, type=c\n' | sfdisk --quiet --label dos "$DISK"
truncate -s $((129024*512)) "$PART"; mkfs.vfat -F 32 -s 1 "$PART" >/dev/null
python3 -I - "$PART.owner" "$TOKEN" <<'PY'
import sys, os, hashlib
salt = os.urandom(16)
line = f"HQOWN1 {salt.hex()} {hashlib.sha256(salt + sys.argv[2].encode()).hexdigest()}"
open(sys.argv[1], "w").write(line.ljust(127) + "\n")
PY
mcopy -i "$PART" "$PART.owner" ::OWNER.TXT && dd if="$PART" of="$DISK" bs=512 seek=2048 conv=notrunc status=none
rm -f "$PART" "$PART.owner"
JAR=$(mktemp)

echo "[2] boot heqk in QEMU (host :$HTTP→80, :$P4444→4444, :$P23→23)"
qemu-system-aarch64 -M virt -cpu cortex-a72 -m 512M -nographic -serial mon:stdio -semihosting \
  -global virtio-mmio.force-legacy=false \
  -netdev user,id=n0,hostfwd=tcp:$HOST:$HTTP-:80,hostfwd=tcp:$HOST:$P4444-:4444,hostfwd=tcp:$HOST:$P23-:23 \
  -device virtio-net-device,netdev=n0 \
  -drive file="$DISK",format=raw,if=none,id=hd0 -device virtio-blk-device,drive=hd0 -kernel "$KERNEL" >"$LOG" 2>&1 &
QPID=$!
cleanup() { [ "${MC_E2E_KEEP:-0}" = 1 ] || { kill "$QPID" 2>/dev/null; rm -f "$DISK" "$JAR"; }; }
trap cleanup EXIT
# "serving" is printed only once DHCP has leased an address (QEMU user-net serves 10.0.2.15).
for _ in $(seq 1 90); do grep -qa "\[MC\] heqk Mission Control serving" "$LOG" && break; sleep 1; done
grep -a "\[MC\]" "$LOG" | sed 's/^/        /'
grep -qa "serving on http://10.0.2.15:80 (DHCP lease)" "$LOG" && ok "address obtained by DHCP (10.0.2.15)" || bad "no DHCP lease (expected 10.0.2.15)"

echo "[3a] owner authentication: nothing protected without the owner key"
grep -qa "owner: CLAIMED" "$LOG" && ok "device loaded the owner verifier from its boot disk" || bad "owner verifier not loaded"
[ "$(curl -s -o /dev/null -w '%{http_code}' -m 10 "$B/api/detections")" = 401 ] && ok "API refuses without a session (401)" || bad "API reachable without a session"
[ "$(curl -s -o /dev/null -w '%{http_code} %{redirect_url}' -m 10 "$B/detect/feed")" = "302 $B/login" ] && ok "UI pages redirect to /login without a session" || bad "UI page reachable without a session"
[ "$(curl -s -o /dev/null -w '%{http_code}' -m 10 -d 'token=WRONG-KEY-0000000' "$B/api/login" -c "$JAR")" = 303 ] && ! grep -q hq_session "$JAR" && ok "a wrong owner key gets no session" || bad "wrong key handling"
curl -s -o /dev/null -m 10 -d "token=$TOKEN" "$B/api/login" -c "$JAR"
grep -q hq_session "$JAR" && ok "the owner key yields an HttpOnly session cookie" || bad "login with the owner key failed"
C="-b $JAR"

echo "[3] device health: served by heqk, rule plane armed"
H=$(curl -s -m 10 $C "$B/api/health")
[ "$(echo "$H" | jget "d['substrate']")" = heqk ] && ok "API answered by heqk ($H)" || bad "health: $H"
[ "$(echo "$H" | jget "d['rules_active']")" -gt 0 ] 2>/dev/null && ok "rule plane armed" || bad "rule plane NOT armed (IPS would pass everything)"
D0=$(curl -s -m 10 $C "$B/api/detections" | jget "d['count']")
# A baseline that could not be read must FAIL the run, never default to 0 (a vacuous pass).
[[ "$D0" =~ ^[0-9]+$ ]] || { bad "could not read the baseline detection count ($D0)"; D0=999999; }

echo "[4] real attack traffic at the device: C2 port 4444 ×3, telnet 23 ×2"
for p in $P4444 $P4444 $P23 $P4444 $P23; do curl -s -m 2 "http://$HOST:$p/" >/dev/null 2>&1; done
sleep 3

echo "[5] the attack was enforced and is visible through heqk's own API"
H=$(curl -s -m 10 $C "$B/api/health")
DR=$(echo "$H" | jget "d['dropped']")
[ "$DR" -ge 5 ] 2>/dev/null && ok "heqk dropped the attack frames on the wire (dropped=$DR)" || bad "attack frames not dropped (dropped=$DR)"
DETS=$(curl -s -m 10 $C "$B/api/detections?limit=50")
N=$(echo "$DETS" | jget "d['count']")
[ "$N" -ge $((D0 + 5)) ] 2>/dev/null && ok "detections recorded ($D0 → $N)" || bad "expected ≥5 new detections, got $D0 → $N"
echo "$DETS" | jget "any(x['rule_id']==1200001 and 'C2 port 4444' in x['rule_msg'] and x['severity']==2 for x in d['detections'])" | grep -q True \
  && ok "C2-4444 detection: rule 1200001, HIGH, with verdict class" || bad "no C2-4444 detection in $DETS"
echo "$DETS" | jget "any(x['rule_id']==1200002 for x in d['detections'])" | grep -q True && ok "telnet-23 detection present" || bad "no telnet-23 detection"
echo "$DETS" | jget "all(x['src_ip']=='10.0.2.2' for x in d['detections'])" | grep -q True && ok "attributed to the attacking source 10.0.2.2" || bad "attribution wrong"
INC=$(curl -s -m 10 $C "$B/api/incidents")
echo "$INC" | jget "d['count']>=1 and d['incidents'][0]['device_ip']=='10.0.2.2' and d['incidents'][0]['priority']=='High'" | grep -q True \
  && ok "correlated into a High incident for 10.0.2.2" || bad "incident correlation: $INC"
sleep 2
Q=$(curl -s -m 10 $C "$B/api/qsecbit")
echo "$Q" | jget "d['latest'] is not None and d['latest']['score']>0" | grep -q True && ok "QSecBit-lite risk rose under attack ($(echo "$Q" | jget "d['latest']"))" || bad "qsecbit: $Q"

echo "[6] the unchanged Mission Control UI, loaded FROM the device, shows the live attack"
BROWSER=skipped
if [ -d tools/mc-e2e/node_modules/playwright ] && command -v node >/dev/null; then
  BROWSER=ran
  (cd tools/mc-e2e && node ui-check.mjs "$B" "$TOKEN") && ok "browser: UI rendered live heqk data (screenshots in /tmp/mc-e2e-*.png)" || bad "browser assertions failed"
else
  echo "  SKIP  browser leg — Playwright not installed (cd tools/mc-e2e && npm i && npx playwright install chromium)"
fi

echo
if [ "$FAILS" != 0 ]; then echo "MC-E2E: FAIL ($FAILS)"
elif [ "$BROWSER" = ran ]; then echo "MC-E2E: PASS — attack → heqk IPS → evidence → heqk API → Mission Control UI in a real browser, no Linux in the device path"
else echo "MC-E2E: API LEG PASS, BROWSER LEG SKIPPED — the UI rendering was NOT verified"; fi
[ "${MC_E2E_KEEP:-0}" = 1 ] && echo "VM left running (pid $QPID): open $B"
exit "$FAILS"
