#!/usr/bin/env bash
# cm5-hsh-check — the heqk management shell (el0-hsh, ADR 0059 step 4a) on metal, over its DEVELOPMENT transport
# (POST /api/hsh, bench images built with the hsh-dev feature only — release builds refuse it). Proves:
#   - every read-only command answers from the EL0 shell with real device state (role view);
#   - the shell's `config status` agrees with /api/config before and after a LIVE change and after a reboot;
#   - commands that change state (config confirm / rollback) are refused without elevation (role operate);
#   - unknown commands and spec commands not in this build are refused cleanly; malformed arguments are refused;
#   - oversized / binary input does not break the shell (it keeps answering);
#   - the transport keeps the /api guards (no session -> 401, wrong Origin / CSRF -> 403).
#   tools/diagnostics/cm5-hsh-check.sh <owner-key-file> <serial-log> <config-key> [mc]
set -u -o pipefail
KEY="${1:?owner key file}"; LOG="${2:?serial log}"; CK="${3:?configuration signing key}"; MC="${4:-https://192.168.200.146}"
HERE=$(cd "$(dirname "$0")" && pwd); ROOT=$(cd "$HERE/../.." && pwd)
HQ="python3 -I $ROOT/os/kernel/tools/hqcfg.py"
UP="python3 -I $ROOT/os/kernel/tools/hq-upload.py --mc $MC --owner-key-file $KEY --insecure"
ok=0; n=0
chk() { n=$((n + 1)); if [ "$1" = 0 ]; then echo "ok  $2"; ok=$((ok + 1)); else echo "BAD $2"; fi; }
T=$(mktemp -d); chmod 700 "$T"; trap 'shred -u "$T"/* 2>/dev/null; rm -rf "$T"' EXIT
# sh "<line>" [origin-override] -> prints the shell's reply (HTTP status on the last line as "HTTP <code>")
sh() { python3 -I - "$MC" "$KEY" "$1" "${2:-}" <<'PY'
import json, ssl, sys, urllib.parse, urllib.request, http.cookiejar
mc, key, line, origin = sys.argv[1], open(sys.argv[2]).read().strip(), sys.argv[3], sys.argv[4] or sys.argv[1]
c = ssl.create_default_context(); c.check_hostname = False; c.verify_mode = ssl.CERT_NONE
o = urllib.request.build_opener(urllib.request.HTTPSHandler(context=c), urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
o.open(mc + "/api/login", urllib.parse.urlencode({"token": key}).encode(), timeout=10).read()
s = json.loads(o.open(mc + "/api/session", timeout=10).read())
rq = urllib.request.Request(mc + "/api/hsh", line.encode("latin-1"), {"Origin": origin, "X-HQ-CSRF": s["csrf"], "Content-Type": "text/plain"})
try:
    r = o.open(rq, timeout=15); print(r.read().decode("utf-8", "replace")); print("HTTP", r.status)
except urllib.error.HTTPError as e:
    print(e.read().decode("utf-8", "replace")); print("HTTP", e.code)
PY
}
api() { python3 -I - "$MC" "$KEY" "$1" "${2:-}" <<'PY'
import json, ssl, sys, urllib.parse, urllib.request, http.cookiejar
mc, key, path, reason = sys.argv[1], open(sys.argv[2]).read().strip(), sys.argv[3], sys.argv[4]
c = ssl.create_default_context(); c.check_hostname = False; c.verify_mode = ssl.CERT_NONE
o = urllib.request.build_opener(urllib.request.HTTPSHandler(context=c), urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
o.open(mc + "/api/login", urllib.parse.urlencode({"token": key}).encode(), timeout=10).read()
if not reason:
    print(o.open(mc + path, timeout=10).read().decode()); sys.exit(0)
s = json.loads(o.open(mc + "/api/session", timeout=10).read())
rq = urllib.request.Request(mc + path, urllib.parse.urlencode({"reason": reason, "permanent": "true", "seq": s["next_seq"], "owner_key": key}).encode(), {"Origin": mc, "X-HQ-CSRF": s["csrf"]})
try:
    print(o.open(rq, timeout=10).read().decode())
except urllib.error.HTTPError as e:
    print(e.read().decode())
PY
}
gen_api() { api /api/config | python3 -c 'import json,sys; print(json.load(sys.stdin)["generation"])'; }
gen_sh() { sh "config status" | grep -oE "generation [0-9]+" | head -1 | awk '{print $2}'; }
answers() { local r; r=$(sh "$1"); grep -q "HTTP 200" <<<"$r" && ! grep -qiE "^ERROR|fault|unsupported" <<<"$r" && [ "$(grep -vc '^HTTP' <<<"$r")" -ge 1 ]; }
# --- transport guards ---
c=$(curl -sk -o /dev/null -w '%{http_code}' -m 10 -X POST --data 'version' "$MC/api/hsh"); [ "$c" = 401 ] || [ "$c" = 403 ]; chk $? "T1 no owner session -> refused ($c)"
sh "version" "https://evil.example" | grep -q "HTTP 403"; chk $? "T2 foreign Origin -> 403"
# --- read-only commands (role view) answer with real state ---
for cmd in "help" "version" "info" "uptime" "wan status" "interface show wan" "qsecbit status" "config status" "owner status" "security posture"; do
  answers "$cmd"; chk $? "R '$cmd' answers from the EL0 shell"
done
sh "help" | grep -q "config status"; chk $? "R help lists only what this build supports (config status present)"
sh "security posture" | grep -qi "el0\|EL0"; chk $? "R security posture reports the EL0 parser placement"
sh "uptime" > "$T/u1"; sleep 3; sh "uptime" > "$T/u2"; ! cmp -s "$T/u1" "$T/u2"; chk $? "R uptime advances (live state, not a canned reply)"
# --- refusals ---
sh "config confirm" | grep -qiE "operate|not permitted|elevat|denied|refused"; chk $? "P config confirm refused without elevation (role operate)"
sh "config rollback" | grep -qiE "operate|not permitted|elevat|denied|refused"; chk $? "P config rollback refused without elevation"
sh "frobnicate now" | grep -qiE "unknown|not a command|ERROR"; chk $? "P unknown command refused"
sh "firewall show" | grep -qiE "not in this build|later|not yet|unsupported"; chk $? "P a spec command not in this build is refused as such"
sh "config stage zz" | grep -qi "Invalid argument"; chk $? "P malformed argument refused (config stage zz)"
sh "owner elevate 00 11" | grep -qi "Invalid argument"; chk $? "P malformed signature refused (owner elevate)"
long=$(python3 -c 'print("info " + "A" * 3000)'); sh "$long" > /dev/null; answers "version"; chk $? "F oversized line: the shell still answers afterwards"
sh $'info \x01\x02\xff' > /dev/null; answers "uptime"; chk $? "F binary bytes: the shell still answers afterwards"
# --- the shell agrees with the API through a live change and a reboot ---
g0=$(gen_api); [ "$(gen_sh)" = "$g0" ]; chk $? "C config status (shell) = /api/config generation ($g0)"
G=$((g0 + 1)); [ "$(api /api/config | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["floor"])')" -ge "$G" ] && G=$(( $(api /api/config | python3 -c 'import json,sys; print(json.load(sys.stdin)["floor"])') + 1 ))
printf 'HQPOL1\nacl LAN-IN seq 10 block tcp any 1.1.1.1/32 80\nacl LAN-IN default allow\ninterface lan acl in LAN-IN\nroute 0.0.0.0/0 via wan\n' > "$T/p"
$HQ bundle "$CK" $G "$T/b.bin" "$T/b.sig" --policy "$T/p" >/dev/null
$UP --type config --sig "$T/b.sig" --file "$T/b.bin" > "$T/r" 2>&1; grep -q '"applies": "live"' "$T/r"; chk $? "C a policy bundle gen $G applies live"
for _ in $(seq 1 20); do sh "config status" | grep -q "generation $G" && break; sleep 2; done
sh "config status" | grep -q "generation $G"; chk $? "C the shell sees gen $G live (no reboot)"
for _ in $(seq 1 20); do sh "config status" | grep -qi "committed\|in force" && break; sleep 2; done
mark=$(stat -c %s "$LOG"); $UP --reboot "hsh check" >/dev/null 2>&1; sleep 25
for _ in $(seq 1 60); do curl -sk -o /dev/null -m 5 "$MC/" && break; sleep 3; done
[ "$(gen_sh)" = "$G" ] && [ "$(gen_api)" = "$G" ]; chk $? "C after the reboot: shell and API both report gen $G (kept)"
sh "owner status" | grep -qiE "[0-9a-f]{8}"; chk $? "C owner status shows key fingerprints only after the reboot"
! sh "owner status" | grep -qE "[0-9a-f]{64}"; chk $? "C no full key material in owner status"
[ "$ok" -eq "$n" ] && { echo "HSH: PASS ($ok/$n)"; exit 0; } || { echo "HSH: FAIL ($ok/$n)"; exit 1; }
