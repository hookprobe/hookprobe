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
UI=../mission-control
if [ ! -f "$UI/dist/index.html" ]; then
  command -v npm >/dev/null || { echo "  npm not found and os/mission-control/dist missing — cannot embed the UI"; exit 2; }
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
IID=$(echo "$INC" | jget "d['incidents'][0]['id']")
ID=$(curl -s -m 10 $C "$B/api/incidents/$(python3 -c 'import sys,urllib.parse;print(urllib.parse.quote(sys.argv[1],safe=""))' "$IID")")
echo "$ID" | jget "d['explanation']['model'] is None and d['explanation']['evidence']>=5 and d['attack_path']['node_count']>=2" | grep -q True \
  && ok "incident drill-down: deterministic explanation (no AI model claimed) + attack path" || bad "incident detail: $ID"
TL=$(curl -s -m 10 $C "$B/api/incidents/$IID/timeline")
echo "$TL" | jget "d['found'] and d['count']>=5 and all(e['kind'] in ('detection','flow') for e in d['events'])" | grep -q True \
  && ok "incident timeline served by heqk" || bad "timeline: $TL"
DNS=$(curl -s -m 10 $C "$B/api/dns")
echo "$DNS" | jget "'lists' in d and 'counters' in d and isinstance(d['recent'],list) and d['policy']['encrypted_dns'] in ('block','allow')" | grep -q True \
  && ok "Shield v2 /api/dns answers (lists, counters, policy, query log)" || bad "/api/dns: $DNS"
[ "$(curl -s -o /dev/null -w '%{http_code}' -m 10 "$B/api/dns")" = 401 ] && ok "/api/dns requires the owner session" || bad "/api/dns reachable without a session"
EN=$(curl -s -m 10 $C "$B/api/engines")
echo "$EN" | jget "len(d['engines'])>=6 and all(e['source']=='real' for e in d['engines']) and any(e['kind']=='signature' and e['hits']>=5 for e in d['engines'])" | grep -q True \
  && ok "/api/engines: the device's real detection tiers, signature hits counted" || bad "/api/engines: $EN"
ES=$(curl -s -m 10 $C "$B/api/evidence/stats")
echo "$ES" | jget "d['nodes']['detections']>=5 and d['nodes']['incidents']>=1 and d['last_prune'] is None" | grep -q True \
  && ok "/api/evidence/stats from live evidence (no prune fabricated)" || bad "/api/evidence/stats: $ES"
EG=$(curl -s -m 10 $C "$B/api/evidence/graph?node=$(python3 -c 'import sys,urllib.parse;print(urllib.parse.quote(sys.argv[1],safe=""))' "$IID")")
echo "$EG" | jget "d['node_count']>=2 and any(n['type']=='Threat' for n in d['nodes'])" | grep -q True \
  && ok "/api/evidence/graph drills from the incident to its rules and targets" || bad "/api/evidence/graph: $EG"
EF=$(curl -s -m 10 $C "$B/api/enforcement")
echo "$EF" | jget "'policy' in d and isinstance(d['sources'],list) and d['count']==len(d['sources'])" | grep -q True \
  && ok "/api/enforcement lists live enforcement (self-reverting, read-only)" || bad "/api/enforcement: $EF"
RL=$(curl -s -m 10 $C "$B/api/reports")
RID=$(echo "$RL" | jget "d['reports'][0]['id']")
RD=$(curl -s -m 10 $C "$B/api/reports/$RID")
echo "$RD" | jget "d['report']['device_ip']=='10.0.2.2' and len(d['report']['evidence_node_ids'])>=5 and len(d['report']['response_taken'])>=1" | grep -q True \
  && ok "/api/reports/:id: a deterministic incident report with evidence ids and the actions taken" || bad "report: $RD"
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

echo "[7] HTTPS (ADR 0051): the EL0 TLS server, a key the device derives, a certificate from a name-constrained owner CA"
PUB=$(tr -d '\r' < "$LOG" | grep -ao 'pub=04[0-9a-f]\{128\}' | head -1 | cut -d= -f2)
grep -qa "HTTPS OFF — no certificate provisioned" "$LOG" && [ ${#PUB} = 130 ] && ok "unprovisioned: HTTPS stays off and the device publishes its TLS public key" || bad "no TLS public key / unexpected HTTPS state"
TLSD=$(mktemp -d)
if python3 tools/mctls-provision.py --ca-dir "$TLSD/ca" --pub "$PUB" --name heqk.local --ip 127.0.0.1 \
     --permit-dns heqk.local --permit-ip 127.0.0.0/255.0.0.0 --permit-ip 10.0.0.0/255.0.0.0 --out "$TLSD/MCTLS.CRT" >/dev/null; then
  ok "owner CA certified the device key (CA is name-constrained; its private key never touches the device)"
else bad "provisioning failed"; fi
# The CA cannot certify other names: a leaf for evil.example signed by it must fail verification.
openssl ecparam -name prime256v1 -genkey -noout -out "$TLSD/evil.key" 2>/dev/null
openssl req -new -key "$TLSD/evil.key" -subj /CN=evil.example -out "$TLSD/evil.csr" 2>/dev/null
printf 'subjectAltName=DNS:evil.example\n' > "$TLSD/evil.ext"
openssl x509 -req -in "$TLSD/evil.csr" -CA "$TLSD/ca/ca.pem" -CAkey "$TLSD/ca/ca.key" -CAcreateserial -days 2 -extfile "$TLSD/evil.ext" -out "$TLSD/evil.pem" 2>/dev/null
openssl verify -CAfile "$TLSD/ca/ca.pem" "$TLSD/evil.pem" 2>&1 | grep -q "permitted subtree violation" && ok "name constraints: the owner CA cannot mint a certificate for another site" || bad "name constraints not enforced"
kill "$QPID" 2>/dev/null; wait "$QPID" 2>/dev/null
# second boot: same image, the boot disk now carries MCTLS.CRT
PART=$(mktemp); dd if="$DISK" of="$PART" bs=512 skip=2048 count=129024 status=none
mcopy -i "$PART" "$TLSD/MCTLS.CRT" ::MCTLS.CRT && dd if="$PART" of="$DISK" bs=512 seek=2048 conv=notrunc status=none; rm -f "$PART"
LOG2=$(mktemp /tmp/mc-e2e-qemu-tls.XXXX.log); HTTPS=18443; BS="https://heqk.local:$HTTPS"
qemu-system-aarch64 -M virt -cpu cortex-a72 -m 512M -nographic -serial mon:stdio -semihosting \
  -global virtio-mmio.force-legacy=false \
  -netdev user,id=n0,hostfwd=tcp:$HOST:$HTTP-:80,hostfwd=tcp:$HOST:$HTTPS-:443,hostfwd=tcp:$HOST:$P4444-:4444 \
  -device virtio-net-device,netdev=n0 \
  -drive file="$DISK",format=raw,if=none,id=hd0 -device virtio-blk-device,drive=hd0 -kernel "$KERNEL" >"$LOG2" 2>&1 &
QPID=$!
for _ in $(seq 1 90); do grep -qa "\[MC\] heqk Mission Control serving on http://10.0.2.15" "$LOG2" && break; sleep 1; done
C=(--cacert "$TLSD/ca/ca.pem" --resolve "heqk.local:$HTTPS:$HOST" -sS -m 30)
grep -qa "HTTPS ready on :443" "$LOG2" && ok "device loaded MCTLS.CRT: HTTPS ready on :443 (EL0 TLS server)" || bad "HTTPS not ready after provisioning"
HS=$(curl "${C[@]}" "$BS/api/health")
[ "$(echo "$HS" | jget "d['substrate']")" = heqk ] && ok "https://heqk.local/api/health answered with the certificate verified against the owner CA" || bad "https health: $HS"
SC=$(echo | timeout 30 openssl s_client -connect "$HOST:$HTTPS" -servername heqk.local -CAfile "$TLSD/ca/ca.pem" 2>/dev/null)
echo "$SC" | grep -q "TLSv1.3, Cipher is TLS_CHACHA20_POLY1305_SHA256" && echo "$SC" | grep -q "Server Temp Key: X25519" \
  && echo "$SC" | grep -q "Verify return code: 0" && ok "negotiated TLS 1.3 / CHACHA20_POLY1305 / X25519 / ECDSA, chain verified" || bad "unexpected TLS parameters"
RD=$(curl -s -o /dev/null -w '%{http_code} %{redirect_url}' -m 10 -H "Host: heqk.local:$HTTP" "$B/detect/feed?x=1")
[ "$RD" = "308 https://heqk.local/detect/feed?x=1" ] && ok "plain :80 now only redirects to https (308, path + query kept)" || bad "redirect: $RD"
JAR2=$(mktemp)
curl "${C[@]}" -o /dev/null -D "$TLSD/h" --data-urlencode "token=$TOKEN" "$BS/api/login" -c "$JAR2"
grep -qi '^set-cookie: hq_session=.*HttpOnly.*Secure' "$TLSD/h" && ok "owner sign-in over https; the session cookie is HttpOnly + Secure" || bad "https login / Secure cookie"
for _ in 1 2 3; do curl -s -m 3 -o /dev/null "http://$HOST:$P4444/" 2>/dev/null; done
sleep 3
DT=$(curl "${C[@]}" -b "$JAR2" "$BS/api/detections?limit=20")
echo "$DT" | jget "any(x['rule_id']==1200001 for x in d['detections'])" | grep -q True && ok "attack during TLS service still dropped + detected, visible over https" || bad "detections over https: $DT"
echo | timeout 20 openssl s_client -connect "$HOST:$HTTPS" -servername heqk.local -tls1_3 -ciphersuites TLS_AES_256_GCM_SHA384 2>&1 | grep -q "Cipher is (NONE)" \
  && ok "a client offering only AES-GCM is refused (one-suite policy)" || bad "AES-GCM-only client was not refused"
# A handshake flood is rate-limited (ADR 0051): 80 new sessions as fast as possible — some refused, none crash it.
FP=(); for _ in $(seq 1 80); do curl "${C[@]}" -o /dev/null -m 5 "$BS/api/health" 2>/dev/null & FP+=($!); done; wait "${FP[@]}" 2>/dev/null
sleep 2
HSF=$(curl "${C[@]}" "$BS/api/health")
[ "$(echo "$HSF" | jget "d['substrate']")" = heqk ] && ok "after 80 simultaneous connections (most abandoned) HTTPS still serves — no slot left pinned" || bad "https after connection flood: $HSF"
KA=$(curl "${C[@]}" -v -o /dev/null -o /dev/null "$BS/api/health" "$BS/api/health" 2>&1)
echo "$KA" | grep -qi "Re-using existing connection" && ok "keep-alive: two https requests share one connection (one TLS handshake)" || bad "https keep-alive not reused"
head -c 3000 /dev/urandom | timeout 10 nc -q 2 "$HOST" "$HTTPS" >/dev/null 2>&1
HS2=$(curl "${C[@]}" "$BS/api/health")
[ "$(echo "$HS2" | jget "d['substrate']")" = heqk ] && ok "garbage on :443 fails that connection only — HTTPS keeps serving" || bad "https after garbage: $HS2"
if [ "$BROWSER" = ran ]; then
  SPKI=$(openssl x509 -in <(dd if="$TLSD/MCTLS.CRT" bs=1 skip=12 count=$(python3 -I -c "import struct,sys;print(struct.unpack('<H',open(sys.argv[1],'rb').read()[10:12])[0])" "$TLSD/MCTLS.CRT") status=none) -inform DER -pubkey -noout | openssl pkey -pubin -outform DER | openssl dgst -sha256 -binary | base64)
  (cd tools/mc-e2e && MC_E2E_SPKI="$SPKI" node ui-check.mjs "https://heqk.local:$HTTPS" "$TOKEN") && ok "browser: the UI over https (pinned to the device key) rendered live heqk data" || bad "browser over https failed"
fi
sleep 11
TH=$(tr -d '\r' < "$LOG2" | grep -a "MC-TLS hb" | tail -1)
echo "        $TH"
echo "$TH" | grep -q "timeouts=0 faults=0" && echo "$TH" | grep -Eq "handshakes=[1-9]" && ok "TLS server: handshakes counted, no watchdog timeout, no EL0 fault" || bad "TLS server counters: $TH"
TS=$(tr -d '\r' < "$LOG2" | grep -a "MC-TLS slots" | tail -1)
echo "        $TS"
echo "$TS" | grep -Eq "slots\] (L ){8}" && ok "every HTTPS slot back in Listen after the flood" || bad "HTTPS slots not recycled: $TS"
if [ "$BROWSER" = ran ]; then
  echo "$TH" | grep -Eq "pq_hybrid=[1-9]" && ok "the browser negotiated hybrid post-quantum X25519MLKEM768 with the device" || bad "no X25519MLKEM768 handshake from the browser: $TH"
fi
LOG="$LOG2"; rm -rf "$TLSD" "$JAR2"

echo
if [ "$FAILS" != 0 ]; then echo "MC-E2E: FAIL ($FAILS)"
elif [ "$BROWSER" = ran ]; then echo "MC-E2E: PASS — attack → heqk IPS → evidence → heqk API → Mission Control UI in a real browser, no Linux in the device path"
else echo "MC-E2E: API LEG PASS, BROWSER LEG SKIPPED — the UI rendering was NOT verified"; fi
if [ "${MC_E2E_KEEP:-0}" = 1 ]; then
  ( umask 077; echo "$TOKEN" > /tmp/mc-e2e-owner-key )
  echo "VM left running (pid $QPID): open $B — owner key in /tmp/mc-e2e-owner-key (mode 600)"
fi
exit "$FAILS"
