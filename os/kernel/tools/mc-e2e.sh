#!/usr/bin/env bash
# mc-e2e.sh — END-TO-END proof that heqk alone runs the SOC and serves Mission Control
# (ADR 0047): real attack traffic → heqk IPS (packet::verdict) → SOAR event → device evidence
# state → heqk's own HTTP API → the unchanged Mission Control UI in a real browser.
# No Linux anywhere in the device path (QEMU emulates the hardware only).
#
#   tools/mc-e2e.sh            build + boot + API assertions (+ browser assertions if available)
#   MC_E2E_KEEP=1 tools/...    leave the VM running afterwards (the URL is printed)
#
# Browser leg: needs node (~/.local/node/bin) + Playwright Chromium (tools/mc-e2e/). Without them
# the script says so and reports the API leg only — never a silent pass.
set -u
cd "$(dirname "$0")/.."
[ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"
export PATH="$HOME/.local/node/bin:$PATH"

# Per-run host ports + temp files: several sessions/CI jobs run this concurrently on one machine.
# MC_E2E_PORT_BASE pins them (default: the first base in 18000..19900 with all four ports free).
port_free() { ! ss -ltnH 2>/dev/null | awk '{print $4}' | grep -qE "[:.]$1\$"; }
if [ -z "${MC_E2E_PORT_BASE:-}" ]; then
  for b in $(seq 18000 100 19900); do
    if port_free $((b+80)) && port_free $((b+444)) && port_free $((b+323)) && port_free $((b+443)); then MC_E2E_PORT_BASE=$b; break; fi
  done
fi
PB=${MC_E2E_PORT_BASE:-18000}
HOST=127.0.0.1; HTTP=$((PB+80)); P4444=$((PB+444)); P23=$((PB+323)); HTTPS_PORT=$((PB+443))
RUN=$(mktemp -d /tmp/mc-e2e-run.XXXX)
echo "  (host ports ${HTTP}/${HTTPS_PORT}/${P4444}/${P23}, run dir ${RUN})"
B="http://$HOST:$HTTP"
LOG=$(mktemp /tmp/mc-e2e-qemu.XXXX.log)
echo "  (QEMU console: $LOG)"
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
# wpa3: the SAE station-frame walk in el0-lansvc ([P-lansvc-sae], ADR 0050 D4 step 5c) needs the sae crate
# hsh: the shell's web carrier POST /api/hsh + [P-hsh-web] (R6 = D, owner-signed HQMGMT1 envelopes)
cargo build -p kernel --features mcserve,wpa3,hsh >"$RUN/build.log" 2>&1 || { tail -20 "$RUN/build.log"; exit 2; }
KERNEL=target/mc/aarch64-unknown-none-softfloat/debug/kernel

echo "[1b] boot disk with an owner key (ADR 0037 D3 (retired 2026-11-12; see in part 0051 / 0054 / 0058 / 0059): the device stores only a salted verifier)"
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
# R6 = D: a TEST owner key K_own (seed 0x6b x 32, the same test key [P-hsh-web] uses). QEMU has no DataVolume to
# enroll into, so the public half goes on the test disk (MGMTPK.TXT, read only by the QEMU build); the private half
# stays here and signs HQMGMT1 envelopes with tools/policy-sign.py (mgmt-sign), as an owner's machine would.
KOWN="$RUN/kown.pem"
python3 -I - "$KOWN" "$PART.mgmtpk" <<'PY'
import sys, os
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization as ser
k = Ed25519PrivateKey.from_private_bytes(bytes([0x6b]) * 32)
old = os.umask(0o077)
open(sys.argv[1], "wb").write(k.private_bytes(ser.Encoding.PEM, ser.PrivateFormat.PKCS8, ser.NoEncryption()))
os.umask(old)
open(sys.argv[2], "w").write(k.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw).hex() + "\n")
PY
TEST_KOWN_PK=$(cat "$PART.mgmtpk" | tr -d '\n')
mcopy -i "$PART" "$PART.owner" ::OWNER.TXT && mcopy -i "$PART" "$PART.mgmtpk" ::MGMTPK.TXT && dd if="$PART" of="$DISK" bs=512 seek=2048 conv=notrunc status=none
rm -f "$PART" "$PART.owner" "$PART.mgmtpk"
# SIGN <confirm|rollback> [KEYFILE]: an HQMGMT1 envelope (312 hex) bound to what GET /api/config "envelope" reports now
SIGN() { curl -s -m 10 $C "$B/api/config" | python3 -I -c "
import sys, json, importlib.util
spec = importlib.util.spec_from_file_location('ps', sys.argv[3]); ps = importlib.util.module_from_spec(spec); spec.loader.exec_module(ps)
e = json.load(sys.stdin)['envelope']
print(ps.mgmt_envelope(ps.load(sys.argv[2]), bytes.fromhex(e['device_id']), bytes.fromhex(e['epoch']), int(e['next_seq']), sys.argv[1], 0, int(e['generation']), bytes.fromhex(e['digest'])).hex())" "$1" "${2:-$KOWN}" "$PWD/tools/policy-sign.py"; }
# SIGNX <msg> <arg> <generation> <digest hex | -> [KEYFILE]: an envelope for Mission Control's owner endpoints (R6 = D)
SIGNX() { curl -s -m 10 $C "$B/api/config" | python3 -I -c "
import sys, json, importlib.util
spec = importlib.util.spec_from_file_location('ps', sys.argv[6]); ps = importlib.util.module_from_spec(spec); spec.loader.exec_module(ps)
e = json.load(sys.stdin)['envelope']
dg = bytes(32) if sys.argv[4] == '-' else bytes.fromhex(sys.argv[4])
print(ps.mgmt_envelope(ps.load(sys.argv[5]), bytes.fromhex(e['device_id']), bytes.fromhex(e['epoch']), int(e['next_seq']), sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), dg).hex())" "$1" "$2" "$3" "$4" "${5:-$KOWN}" "$PWD/tools/policy-sign.py"; }
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
echo "$H" | jget "all(k in d['lan_relay'] for k in ('arp_proxied','relayed','refused_policy','refused_not_leased','discovery_copies','discovery_rate_limited'))" | grep -q True && ok "/api/health reports the Wi-Fi station relay counters" || bad "health: no lan_relay counters"
# UI contract (2026-11-10): the capability manifest + the planner's honest not-configured answers
CAP=$(curl -s -m 10 $C "$B/api/capabilities")
echo "$CAP" | jget "d['source']=='manifest' and d['schema']==2 and 'ids' in d['granted'] and all(isinstance(v,str) and v for v in d['denied'].values()) and not set(d['granted']) & set(d['denied'])" | grep -q True && ok "/api/capabilities: manifest schema 2, granted ids, every denial carries a reason, no id in both" || bad "capabilities: $CAP"
echo "$H" | jget "d['capabilities']==$(echo "$CAP" | jget "d['granted']" | tr "'" '"')" | grep -q True && ok "/api/health echoes the granted capabilities" || bad "health capabilities echo"
echo "$(curl -s -m 10 $C "$B/api/planner/status")" | jget "d['configured'] is False and d['endpoint'] is None" | grep -q True && ok "/api/planner/status: honestly not configured" || bad "planner status"
[ "$(curl -s -o /dev/null -w '%{http_code}' -m 10 $C -X POST -H "Origin: $B" --data 'intent=x' "$B/api/planner/propose")" = 503 ] && ok "POST /api/planner/propose: 503 not_configured (no mock proposal)" || bad "planner propose"
# ADR 0050 D4 step 1: every request is parsed in the EL0 server; a malformed one is refused there (400), no fault
BADR=$(python3 -I -c "import socket,sys,urllib.parse as u; p=u.urlparse(sys.argv[1]); s=socket.create_connection((p.hostname,p.port),5); s.sendall(b'GARBAGE \\x01 / HTTP/9\\r\\n\\r\\n'); print(s.recv(64)[:12].decode(errors='replace'))" "$B" 2>&1)
grep -q " 400" <<<"$BADR" && ok "a malformed request line is refused by the EL0 parser (400)" || bad "malformed request: $BADR"
# ADR 0050 D4 step 2: Shield's DNS parsing runs in the EL0 LAN-services server (boot self-test + health)
grep -qa "\[P-lansvc\] PASS" "$LOG" && ok "Shield DNS parsing in the EL0 LAN-services server: same facts as in-kernel, fault contained ([P-lansvc])" || bad "lansvc: $(grep -a 'P-lansvc\|LANSVC' "$LOG" | head -3)"
grep -qa "\[P-lansvc-sae\] PASS" "$LOG" && ok "ADR 0050 D4 step 5c: the WPA3-SAE station-frame walk in el0-lansvc — same PMK as in-kernel, malformed / oversized refused, fault rejects + forgets, no SAE material on the IO page ([P-lansvc-sae])" || bad "lansvc-sae: $(grep -a 'P-lansvc-sae' "$LOG" | head -2 | cut -c1-400)"
grep -qa "\[P-hsh\] PASS" "$LOG" && ok "ADR 0059 step 4a: the EL0 shell — parser limits, read commands via the management ABI, role enforced by the kernel, fault contained ([P-hsh])" || bad "hsh: $(grep -a 'P-hsh\|\[HSH\]' "$LOG" | head -3 | cut -c1-400)"
grep -qa "\[P-mgmtabi\] PASS" "$LOG" && ok "ADR 0059 D9: management ABI read messages answer from the /api producers ([P-mgmtabi])" || bad "mgmtabi: $(grep -a 'P-mgmtabi' "$LOG" | head -2 | cut -c1-300)"
grep -qa "\[P-hsh-web\] PASS" "$LOG" && ok "R6 = D: owner-signed HQMGMT1 envelopes on the web carrier — view on the session alone; session-only / wrong key / other device / other boot / replay / gen N while N+1 on trial / other operation / tampered refused; valid accepted; each journaled ([P-hsh-web])" || bad "hsh-web: $(grep -a 'P-hsh-web' "$LOG" | head -2 | cut -c1-600)"
HCS=$(curl -s -m 10 $C "$B/api/session" | jget "d['csrf']")
HSH() { curl -s -m 10 $C -H "Origin: $B" -H "X-HQ-CSRF: $HCS" -H 'Content-Type: text/plain' --data-binary "$1" "$B/api/hsh"; }
[ "$(curl -s -o /dev/null -w '%{http_code}' -m 10 --data-binary 'info' "$B/api/hsh")" = 401 ] && ok "POST /api/hsh requires the owner session" || bad "/api/hsh reachable without a session"
[ "$(curl -s -o /dev/null -w '%{http_code}' -m 10 $C -H 'Origin: https://evil.example' -H "X-HQ-CSRF: $HCS" --data-binary 'info' "$B/api/hsh")" = 403 ] && ok "POST /api/hsh refuses a foreign Origin" || bad "/api/hsh foreign origin"
HSH info | grep -q "HEQK Management Environment" && ok "web console: a view command answers on the session" || bad "web console info: $(HSH info | head -3)"
HSH "config confirm" | grep -q "needs an owner-signed envelope" && ok "web console: config confirm on the session alone is refused (R6 = D)" || bad "web console confirm: $(HSH 'config confirm' | head -3)"
HP=$(curl -s -m 10 $C "$B/api/health")
echo "$HP" | jget "d['http_parser']['where']=='el0' and d['http_parser']['requests']>5 and d['http_parser']['parser_faults']==0 and d['http_parser']['server_faults']==0" | grep -q True && ok "Mission Control requests are parsed in the EL0 server (ADR 0050 D4 step 1), no faults: $(echo "$HP" | jget "d['http_parser']")" || bad "http parser placement: $(echo "$HP" | jget "d.get('http_parser')")"
echo "$HP" | jget "d['dns_parser']['where']=='el0' and d['dns_parser']['el0_messages']>0" | grep -q True && ok "/api/health dns_parser: el0 $(echo "$HP" | jget "d['dns_parser']")" || bad "dns_parser: $(echo "$HP" | jget "d.get('dns_parser')")"
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
# five attack connections from one source on two rules: every frame dropped, ONE event per (rule, source) per
# minute (alert de-duplication, detection benchmark 2026-11-09) -> exactly two new detections
[ "$N" -ge $((D0 + 2)) ] 2>/dev/null && ok "detections recorded ($D0 → $N)" || bad "expected ≥2 new detections, got $D0 → $N"
[ "$N" -le $((D0 + 2)) ] 2>/dev/null && [ "$DR" -ge 5 ] 2>/dev/null && ok "repeats collapse to one event per rule and source while every frame is dropped (dropped=$DR, events +$((N - D0)))" || bad "alert de-duplication: dropped=$DR, events $D0 → $N"
echo "$DETS" | jget "any(x['rule_id']==1200001 and 'C2 port 4444' in x['rule_msg'] and x['severity']==2 for x in d['detections'])" | grep -q True \
  && ok "C2-4444 detection: rule 1200001, HIGH, with verdict class" || bad "no C2-4444 detection in $DETS"
echo "$DETS" | jget "any(x['rule_id']==1200002 for x in d['detections'])" | grep -q True && ok "telnet-23 detection present" || bad "no telnet-23 detection"
echo "$DETS" | jget "all(x['src_ip']=='10.0.2.2' for x in d['detections'])" | grep -q True && ok "attributed to the attacking source 10.0.2.2" || bad "attribution wrong"
INC=$(curl -s -m 10 $C "$B/api/incidents")
echo "$INC" | jget "d['count']>=1 and d['incidents'][0]['device_ip']=='10.0.2.2' and d['incidents'][0]['priority']=='High'" | grep -q True \
  && ok "correlated into a High incident for 10.0.2.2" || bad "incident correlation: $INC"
IID=$(echo "$INC" | jget "d['incidents'][0]['id']")
ID=$(curl -s -m 10 $C "$B/api/incidents/$(python3 -c 'import sys,urllib.parse;print(urllib.parse.quote(sys.argv[1],safe=""))' "$IID")")
echo "$ID" | jget "d['explanation']['model'] is None and d['explanation']['evidence']>=2 and d['attack_path']['node_count']>=2" | grep -q True \
  && ok "incident drill-down: deterministic explanation (no AI model claimed) + attack path" || bad "incident detail: $ID"
TL=$(curl -s -m 10 $C "$B/api/incidents/$IID/timeline")
echo "$TL" | jget "d['found'] and d['count']>=2 and all(e['kind'] in ('detection','flow') for e in d['events'])" | grep -q True \
  && ok "incident timeline served by heqk" || bad "timeline: $TL"
DNS=$(curl -s -m 10 $C "$B/api/dns")
echo "$DNS" | jget "'lists' in d and 'counters' in d and isinstance(d['recent'],list) and d['policy']['encrypted_dns'] in ('block','allow') and d['policy']['level'] in ('relaxed','balanced','strict') and 'level-allowed' in d['counters']" | grep -q True \
  && ok "Shield v2 /api/dns answers (lists, counters, policy incl. the ADR 0057 level, query log)" || bad "/api/dns: $DNS"
[ "$(curl -s -o /dev/null -w '%{http_code}' -m 10 "$B/api/dns")" = 401 ] && ok "/api/dns requires the owner session" || bad "/api/dns reachable without a session"
OR=$(curl -s -m 10 $C "$B/api/owner-rules")
echo "$OR" | jget "d['persistent'] is False and isinstance(d['rules'],list) and 'journal' in d" | grep -q True && ok "ADR 0055 /api/owner-rules answers (RAM journal in QEMU: persistent=false)" || bad "/api/owner-rules: $OR"
[ "$(curl -s -o /dev/null -w '%{http_code}' -m 10 "$B/api/owner-rules")" = 401 ] && ok "/api/owner-rules requires the owner session" || bad "/api/owner-rules reachable without a session"
# G47 device label (ADR 0058): an owner rename is a journal kind; the GET lists it (value = the label)
CSRF=$(curl -s -m 10 $C "$B/api/session" | jget "d['csrf']"); SQN=$(curl -s -m 10 $C "$B/api/session" | jget "d['next_seq']")
LR=$(curl -s -m 10 $C -H "Origin: $B" -H "X-HQ-CSRF: $CSRF" --data "op=set&kind=device_label&target=02:00:00:00:00:47&value=Mia%27s+iPad&reason=rename+test&permanent=true&seq=$SQN" --data-urlencode "owner_key=$TOKEN" "$B/api/owner-rules")
curl -s -m 10 $C "$B/api/owner-rules" | jget "any(r['kind']=='device_label' and r['target']=='02:00:00:00:00:47' and r['value']==\"Mia's iPad\" for r in d['rules'])" | grep -q True && ok "G47: an owner rename is stored and listed (device_label)" || bad "device_label: $LR"
BLR=$(curl -s -m 10 $C -H "Origin: $B" -H "X-HQ-CSRF: $CSRF" --data "op=set&kind=device_label&target=02:00:00:00:00:48&value=bad%22quote&reason=rename+test&permanent=true&seq=$((SQN+1))" --data-urlencode "owner_key=$TOKEN" "$B/api/owner-rules")
grep -q '"refused":"value' <<<"$BLR" && ok "G47: a label outside the grammar is refused" || bad "bad label accepted: $BLR"
# G49 reboot: refused without re-authentication (the QEMU run must not actually restart here)
RB=$(curl -s -m 10 $C -H "Origin: $B" -H "X-HQ-CSRF: $CSRF" --data "reason=apply+now&permanent=true&seq=$((SQN+2))&owner_key=wrong-key-000000000" "$B/api/reboot")
grep -q 're-authentication failed' <<<"$RB" && ok "G49: /api/reboot refuses without owner re-authentication" || bad "reboot guard: $RB"
# ADR 0058: the full trust-anchor key is exposed (null on an image without an operator key)
curl -s -m 10 $C "$B/api/network" | jget "(lambda k: k is None or (len(k)==64 and all(c in '0123456789abcdef' for c in k)))(d['trust_anchor']['public_key'])" | grep -q True && ok "ADR 0058: /api/network trust_anchor carries public_key" || bad "trust_anchor public_key missing"
# ADR 0058 D3: owner configuration key — the state is reported; enrollment needs re-auth and (QEMU) has no DataVolume
AN=$(curl -s -m 10 $C "$B/api/anchor")
echo "$AN" | jget "d['owner_enrolled'] is True and d['owner_key']=='$TEST_KOWN_PK' and d['can']=='rotate' and d['config_files_verified_by']=='owner' and d['config_protected'] is True and 'wan' in d['floors']" | grep -q True && ok "ADR 0058 D3: /api/anchor reports the (QEMU test) owner key as enrolled — it verifies configuration and envelopes" || bad "/api/anchor: $AN"
[ "$(curl -s -o /dev/null -w '%{http_code}' -m 10 "$B/api/anchor")" = 401 ] && ok "/api/anchor requires the owner session" || bad "/api/anchor reachable without a session"
PK=$(printf '%064d' 7); PF=$(printf '%0128d' 7)
AE=$(curl -s -m 10 $C -H "Origin: $B" -H "X-HQ-CSRF: $CSRF" --data "public_key=$PK&proof=$PF&seq=$((SQN+3))&owner_key=wrong-key-000000000" "$B/api/anchor/enroll")
grep -q 're-authentication failed' <<<"$AE" && ok "ADR 0058 D3: owner-key enrollment refuses without re-authentication" || bad "enroll guard: $AE"
AE2=$(curl -s -m 10 $C -H "Origin: $B" -H "X-HQ-CSRF: $CSRF" --data "public_key=$PK&proof=$PF&seq=$((SQN+4))" --data-urlencode "owner_key=$TOKEN" "$B/api/anchor/enroll")
grep -q '"refused":"no DataVolume' <<<"$AE2" && ok "ADR 0058 D3: enrollment with no DataVolume is refused honestly (QEMU)" || bad "enroll without DataVolume: $AE2"
# ADR 0059 step 3 + R6 = D (hard switch): the configuration lifecycle is reported; confirm / rollback are authorised
# ONLY by an owner-signed HQMGMT1 envelope (the owner token no longer authorises a change); QEMU refuses honestly after
CF=$(curl -s -m 10 $C "$B/api/config")
echo "$CF" | jget "d['state']=='none' and d['on_trial'] is False and d['window_s']==300 and d['auto_rollback'] is True" | grep -q True && ok "ADR 0059: /api/config reports the cfgd lifecycle (no bundle in QEMU)" || bad "/api/config: $CF"
echo "$CF" | jget "d['live']['phase']=='idle' and d['live']['changes']==[] and d['live']['remaining_s']==0 and d['live']['last']['result']=='none' and isinstance(d['live']['policy_generation'], int) and d['needs_confirm'] is False" | grep -q True && ok "sealed-config live apply: /api/config carries the live engine's phase / changes / remaining_s / last outcome (idle in QEMU)" || bad "/api/config live: $CF"
echo "$CF" | jget "d['live']['mgmt_ok'] is None and d['live']['mgmt_probe'] is None and d['at_rest']['volatile_ram_only'] is False and d['at_rest']['persisted'] is True" | grep -q True && ok "live-apply follow-up: /api/config carries the management re-probe (live.mgmt_ok, null outside a trial) and whether the configuration in force is RAM-only (at_rest.volatile_ram_only, false in QEMU)" || bad "/api/config follow-up fields: $CF"
# [P-cfgd-pppoe] / [P-cfgd-mgmt] / [P-cfgd-volatile] / [P-cfgd-wifi-after] run in validate.sh's boot (rows Pcfgdpppoe ...), not in this mcserve boot
CFR=$(curl -s -m 10 $C -H "Origin: $B" -H "X-HQ-CSRF: $CSRF" --data "reason=confirm+test&permanent=true&seq=$((SQN+5))" --data-urlencode "owner_key=$TOKEN" "$B/api/config/confirm")
grep -q '"refused":"refused: needs an owner-signed envelope"' <<<"$CFR" && ok "R6 = D: a token-only /api/config/confirm (session + owner_key, no envelope) is refused" || bad "token-only confirm: $CFR"
echo "$CF" | jget "d['envelope']['format']=='HQMGMT1' and len(d['envelope']['epoch'])==16 and d['envelope']['next_seq']>=1 and d['envelope']['generation']==0 and d['envelope']['digest']=='00'*32 and d['envelope']['owner_enrolled'] is True" | grep -q True && ok "R6 = D: /api/config reports what an envelope binds (device, boot epoch, next sequence, the bundle in force)" || bad "/api/config envelope: $CF"
ENV1=$(SIGN confirm)
CFE=$(curl -s -m 10 $C -H "Origin: $B" -H "X-HQ-CSRF: $CSRF" --data "reason=confirm+test&permanent=true&seq=$((SQN+6))&envelope=$ENV1" "$B/api/config/confirm")
grep -q '"refused":"no configuration on trial"' <<<"$CFE" && ok "R6 = D: an owner-signed envelope (policy-sign.py mgmt-sign, no owner token) is accepted and reaches cfgd — honestly nothing on trial in QEMU" || bad "signed confirm: $CFE"
CFP=$(curl -s -m 10 $C -H "Origin: $B" -H "X-HQ-CSRF: $CSRF" --data "reason=confirm+test&permanent=true&seq=$((SQN+7))&envelope=$ENV1" "$B/api/config/confirm")
grep -q '"refused":"refused: replayed or stale sequence"' <<<"$CFP" && ok "R6 = D: the same envelope replayed is refused (403)" || bad "replayed envelope: $CFP"
CRB=$(curl -s -m 10 $C -H "Origin: $B" -H "X-HQ-CSRF: $CSRF" --data "reason=rollback+test&permanent=true&seq=$((SQN+8))&envelope=$(SIGN rollback)" "$B/api/config/rollback")
grep -q '"refused":"no configuration store on this device"' <<<"$CRB" && ok "R6 = D: an owner-signed rollback envelope reaches cfgd — honestly no configuration store in QEMU" || bad "signed rollback: $CRB"
HSH "config confirm
$(SIGN confirm)" | grep -q "no configuration on trial" && ok "R6 = D: web console config confirm + envelope line verifies in EL1 and reaches cfgd (same decision as Mission Control)" || bad "web console signed confirm"
UPS=$(curl -s -m 10 $C "$B/api/upload")
echo "$UPS" | jget "d['store'] is False and [t['type'] for t in d['types']]==['shield_block','shield_allow','ioc','rules','oui','devices','wan','wifi','policy','config'] and all(t['source']=='boot' for t in d['types']) and [t['applies'] for t in d['types']]==['now']*6+['next_boot']*4 and d['in_flight'] is None" | grep -q True && ok "ADR 0056 /api/upload answers (no artifact store in QEMU: every pack from the boot copy)" || bad "/api/upload: $UPS"
[ "$(curl -s -o /dev/null -w '%{http_code}' -m 10 -X POST --data 'type=devices&size=600' "$B/api/upload/begin")" = 401 ] && ok "/api/upload/begin requires the owner session" || bad "/api/upload/begin reachable without a session"
# ADR 0058 rollback: owner re-authentication first; with no artifact store in QEMU nothing can be rolled back
# R6 = D (operator 2026-11-12): pack rollback, factory reset and owner-key rotation are authorised only by an
# owner-signed envelope too; the owner token alone is refused. A second session keeps these writes out of the first
# session's 20-writes-a-minute budget.
RBK=$(curl -s -m 10 $C -H "Origin: $B" -H "X-HQ-CSRF: $CSRF" --data "type=wan&seq=$((SQN+9))" --data-urlencode "owner_key=$TOKEN" "$B/api/upload/rollback")
grep -q '"refused":"refused: needs an owner-signed envelope"' <<<"$RBK" && ok "R6 = D: a token-only /api/upload/rollback is refused (needs an owner-signed envelope)" || bad "token-only pack rollback: $RBK"
RBN=$(curl -s -m 10 $C -H "Origin: $B" -H "X-HQ-CSRF: $CSRF" --data "type=wan&seq=$((SQN+9+1))&envelope=$(SIGNX pack-rollback 6 1 -)" "$B/api/upload/rollback")
grep -q '"refused":"no artifact store"' <<<"$RBN" && ok "R6 = D: an owner-signed pack-rollback envelope verifies; QEMU then refuses honestly (no artifact store)" || bad "signed pack rollback: $RBN"
JAR2=$(mktemp); curl -s -o /dev/null -m 10 -d "token=$TOKEN" "$B/api/login" -c "$JAR2"
C2="-b $JAR2"; S2=$(curl -s -m 10 $C2 "$B/api/session"); CS2=$(echo "$S2" | jget "d['csrf']"); Q2=$(echo "$S2" | jget "d['next_seq']")
FR=$(curl -s -m 10 $C2 -H "Origin: $B" -H "X-HQ-CSRF: $CS2" --data "confirm=ERASE&reason=e2e+reset&permanent=true&seq=$Q2" --data-urlencode "owner_key=$TOKEN" "$B/api/factory-reset")
grep -q '"refused":"refused: needs an owner-signed envelope"' <<<"$FR" && ok "R6 = D: a token-only /api/factory-reset is refused" || bad "token-only factory reset: $FR"
FR2=$(curl -s -m 10 $C2 -H "Origin: $B" -H "X-HQ-CSRF: $CS2" --data "confirm=ERASE&reason=e2e+reset&permanent=true&seq=$((Q2+1))&envelope=$(SIGNX factory-reset 0 0 -)" "$B/api/factory-reset")
grep -q '"refused":"no persistent journal' <<<"$FR2" && ok "R6 = D: an owner-signed factory-reset envelope verifies; QEMU then refuses honestly (RAM journal: nothing durable to erase)" || bad "signed factory reset: $FR2"
RPK=$(printf '%064d' 9); RSG=$(printf '%0128d' 9)
CURFP=$(python3 -I -c "import hashlib,struct,sys; print(struct.unpack('<Q', hashlib.sha256(bytes.fromhex(sys.argv[1])).digest()[:8])[0])" "$TEST_KOWN_PK")
NEWDG=$(python3 -I -c "import hashlib,sys; print(hashlib.sha256(bytes.fromhex(sys.argv[1])).hexdigest())" "$RPK")
RT=$(curl -s -m 10 $C2 -H "Origin: $B" -H "X-HQ-CSRF: $CS2" --data "public_key=$RPK&proof=$PF&generation=2&signature=$RSG&seq=$((Q2+2))&envelope=$(SIGNX rotate $CURFP 2 $(printf '%064d' 1))" "$B/api/anchor/rotate")
grep -q '"refused":"refused: envelope binds another target"' <<<"$RT" && ok "R6 = D: a rotate envelope signed for another new key is refused" || bad "rotate wrong target: $RT"
RT2=$(curl -s -m 10 $C2 -H "Origin: $B" -H "X-HQ-CSRF: $CS2" --data "public_key=$RPK&proof=$PF&generation=2&signature=$RSG&seq=$((Q2+3))&envelope=$(SIGNX rotate $CURFP 2 $NEWDG)" "$B/api/anchor/rotate")
grep -q '"refused":"no DataVolume' <<<"$RT2" && ok "R6 = D: a rotate envelope bound to the current + new key verifies; QEMU then refuses honestly (no DataVolume)" || bad "signed rotate: $RT2"
rm -f "$JAR2"
EN=$(curl -s -m 10 $C "$B/api/engines")
echo "$EN" | jget "len(d['engines'])>=6 and all(e['source']=='real' for e in d['engines']) and any(e['kind']=='signature' and e['hits']>=2 for e in d['engines'])" | grep -q True \
  && ok "/api/engines: the device's real detection tiers, signature hits counted" || bad "/api/engines: $EN"
ES=$(curl -s -m 10 $C "$B/api/evidence/stats")
echo "$ES" | jget "d['nodes']['detections']>=2 and d['nodes']['incidents']>=1 and d['last_prune'] is None" | grep -q True \
  && ok "/api/evidence/stats from live evidence (no prune fabricated)" || bad "/api/evidence/stats: $ES"
EG=$(curl -s -m 10 $C "$B/api/evidence/graph?node=$(python3 -c 'import sys,urllib.parse;print(urllib.parse.quote(sys.argv[1],safe=""))' "$IID")")
echo "$EG" | jget "d['node_count']>=2 and any(n['type']=='Threat' for n in d['nodes'])" | grep -q True \
  && ok "/api/evidence/graph drills from the incident to its rules and targets" || bad "/api/evidence/graph: $EG"
# Audit A8: the Get Online read side requires the session; under QEMU there is no AP, so it must say so
[ "$(curl -s -o /dev/null -w '%{http_code}' -m 10 "$B/api/network")" = 401 ] && ok "/api/network requires the owner session" || bad "/api/network reachable without a session"
NW=$(curl -s -m 10 $C "$B/api/network")
grep -q '"available":false' <<<"$NW" && ok "/api/network answers honestly without an AP (available:false, no invented values)" || bad "/api/network: $NW"
IN=$(curl -s -m 10 $C "$B/api/intel")
echo "$IN" | jget "d['ioc']['mode']=='detect-only' and 'devices' in d and d['ioc']['file'] in ('none','loaded','refused')" | grep -q True \
  && ok "/api/intel reports the IOC pack (detect-only) and the device-policy file" || bad "/api/intel: $IN"
EF=$(curl -s -m 10 $C "$B/api/enforcement")
echo "$EF" | jget "'policy' in d and isinstance(d['sources'],list) and d['count']==len(d['sources'])" | grep -q True \
  && ok "/api/enforcement lists live enforcement (self-reverting, read-only)" || bad "/api/enforcement: $EF"
RL=$(curl -s -m 10 $C "$B/api/reports")
RID=$(echo "$RL" | jget "d['reports'][0]['id']")
RD=$(curl -s -m 10 $C "$B/api/reports/$RID")
echo "$RD" | jget "d['report']['device_ip']=='10.0.2.2' and len(d['report']['evidence_node_ids'])>=2 and len(d['report']['response_taken'])>=1" | grep -q True \
  && ok "/api/reports/:id: a deterministic incident report with evidence ids and the actions taken" || bad "report: $RD"
# ADR 0053 operator actions over real HTTP: session bootstrap, guards, audit, revoke.
SS=$(curl -s -m 10 $C "$B/api/session"); CS=$(echo "$SS" | jget "d['csrf']"); SQ=$(echo "$SS" | jget "d['next_seq']")
ACT() { curl -s -m 10 $C -H "Origin: $B" -H "X-HQ-CSRF: $1" -o /dev/null -w '%{http_code}' --data "$2" "$B/api/actions"; }
[ "$(ACT "$CS" "kind=hold_ip&target=203.0.113.9&ttl=600&reason=e2e+scanner&seq=$SQ")" = 200 ] && ok "action accepted: hold_ip with TTL + reason (origin, CSRF, sequence verified)" || bad "hold_ip refused"
[ "$(ACT "$CS" "kind=hold_ip&target=203.0.113.10&ttl=600&reason=e2e+again&seq=$SQ")" = 409 ] && ok "a replayed sequence number is refused (409)" || bad "replay not refused"
[ "$(curl -s -m 10 $C -H 'Origin: https://evil.example' -H "X-HQ-CSRF: $CS" -o /dev/null -w '%{http_code}' --data "kind=ack&target=10.0.2.2&reason=x+y+z&seq=$((SQ+1))" "$B/api/actions")" = 403 ] && ok "a foreign Origin is refused (403)" || bad "foreign origin accepted"
[ "$(ACT "" "kind=ack&target=10.0.2.2&reason=x+y+z&seq=$((SQ+2))")" = 403 ] && ok "a missing CSRF token is refused (403)" || bad "missing csrf accepted"
[ "$(ACT "$CS" "kind=hold_ip&target=203.0.113.11&ttl=999999&reason=too+long&seq=$((SQ+3))")" = 400 ] && ok "a TTL above 24 h is refused by the kernel (400)" || bad "over-long TTL accepted"
AL=$(curl -s -m 10 $C "$B/api/actions")
echo "$AL" | jget "any(a['kind']=='hold_ip' and a['target']=='203.0.113.9' and 0 < a['expires_in_s'] <= 600 for a in d['active']) and sum(1 for x in d['audit'] if not x['ok']) >= 4 and any(x['reason']=='e2e scanner' for x in d['audit'])" | grep -q True \
  && ok "active actions show time left; the audit log records accepted AND refused attempts with reasons" || bad "actions/audit: $AL"
AID=$(echo "$AL" | jget "[a['id'] for a in d['active'] if a['target']=='203.0.113.9'][0]")
[ "$(curl -s -m 10 $C -H "Origin: $B" -H "X-HQ-CSRF: $CS" -o /dev/null -w '%{http_code}' --data "id=$AID&seq=$((SQ+4))" "$B/api/actions/revoke")" = 200 ] \
  && [ "$(curl -s -m 10 $C "$B/api/actions" | jget "len(d['active'])")" = 0 ] && ok "revoke ends the action at once" || bad "revoke"
# G28 logout: a second session ends only itself; the cookie is expired and refused afterwards.
JAR3=$(mktemp); curl -s -o /dev/null -m 10 -d "token=$TOKEN" "$B/api/login" -c "$JAR3"
LO=$(curl -s -m 10 -b "$JAR3" -c "$JAR3" -X POST -D - "$B/api/logout")
echo "$LO" | grep -qi "Max-Age=0" && echo "$LO" | grep -q '"logged_out":true' && ok "logout ends the session and expires the cookie" || bad "logout: $LO"
[ "$(curl -s -o /dev/null -w '%{http_code}' -m 10 -b "$JAR3" "$B/api/detections")" = 401 ] && [ "$(curl -s -o /dev/null -w '%{http_code}' -m 10 $C "$B/api/detections")" = 200 ] \
  && ok "after logout that session is refused; the other session still works" || bad "post-logout session state"
rm -f "$JAR3"
sleep 2
Q=$(curl -s -m 10 $C "$B/api/qsecbit")
echo "$Q" | jget "d['latest'] is not None and d['latest']['score']>0" | grep -q True && ok "QSecBit-lite risk rose under attack ($(echo "$Q" | jget "d['latest']"))" || bad "qsecbit: $Q"

echo "[6] the unchanged Mission Control UI, loaded FROM the device, shows the live attack"
BROWSER=skipped
if [ -d tools/mc-e2e/node_modules/playwright ] && command -v node >/dev/null; then
  BROWSER=ran
  (cd tools/mc-e2e && MC_E2E_SHOTS="$RUN" node ui-check.mjs "$B" "$TOKEN") && ok "browser: UI rendered live heqk data (screenshots in $RUN)" || bad "browser assertions failed"
  # Mission Control's own live specs (os/mission-control/tests/ui/specs/live, read-only): every route
  # without the sample banner, device-reported values on setup / feedback / administration.
  (cd tools/mc-e2e && UI_LIVE_TOKEN="$TOKEN" node ../../../mission-control/tests/ui/run.mjs "$PWD/node_modules" "$B") \
    && ok "browser: Mission Control live specs pass against heqk" || bad "Mission Control live specs failed"
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
LOG2=$(mktemp /tmp/mc-e2e-qemu-tls.XXXX.log); HTTPS=$HTTPS_PORT; BS="https://heqk.local:$HTTPS"
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
# the device sheds the abandoned handshakes on its own timer: allow up to ~10 s, a hang is still a FAIL
for _ in 1 2 3 4 5; do sleep 2; HSF=$(curl "${C[@]}" "$BS/api/health"); [ -n "$HSF" ] && break; done
[ "$(echo "$HSF" | jget "d['substrate']")" = heqk ] && ok "after 80 simultaneous connections (most abandoned) HTTPS still serves — no slot left pinned" || bad "https after connection flood: $HSF"
KA=$(curl "${C[@]}" -v -o /dev/null -o /dev/null "$BS/api/health" "$BS/api/health" 2>&1)
echo "$KA" | grep -qi "Re-using existing connection" && ok "keep-alive: two https requests share one connection (one TLS handshake)" || bad "https keep-alive not reused"
head -c 3000 /dev/urandom | timeout 10 nc -q 2 "$HOST" "$HTTPS" >/dev/null 2>&1
HS2=$(curl "${C[@]}" "$BS/api/health")
[ "$(echo "$HS2" | jget "d['substrate']")" = heqk ] && ok "garbage on :443 fails that connection only — HTTPS keeps serving" || bad "https after garbage: $HS2"
if [ "$BROWSER" = ran ]; then
  SPKI=$(openssl x509 -in <(dd if="$TLSD/MCTLS.CRT" bs=1 skip=12 count=$(python3 -I -c "import struct,sys;print(struct.unpack('<H',open(sys.argv[1],'rb').read()[10:12])[0])" "$TLSD/MCTLS.CRT") status=none) -inform DER -pubkey -noout | openssl pkey -pubin -outform DER | openssl dgst -sha256 -binary | base64)
  (cd tools/mc-e2e && MC_E2E_SHOTS="$RUN" MC_E2E_SPKI="$SPKI" node ui-check.mjs "https://heqk.local:$HTTPS" "$TOKEN") && ok "browser: the UI over https (pinned to the device key) rendered live heqk data" || bad "browser over https failed"
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
