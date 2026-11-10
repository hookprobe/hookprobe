#!/usr/bin/env bash
# cm5-alert-hook-check — owner alert webhook on metal (operator 2026-11-10; release gate DET-03).
#   1. the bench Pi runs a tiny ntfy-style receiver on :8099 that verifies X-HQ-Signature (HMAC-SHA256 with the
#      secret below) and logs every request;
#   2. the owner sets the hook through Mission Control (POST /api/alert-hook, re-auth) -> the Pi, format ntfy;
#   3. the Pi triggers a high-severity detection (rule 124: 30 SSH attempts to the bench WAN host, answered);
#   4. acceptance: exactly ONE signed alert reaches the receiver for that burst (storm gate), its signature
#      verifies, /api/alert-hook counts sent >= 1; then the hook is removed (op=remove) and the receiver stopped.
#   tools/diagnostics/cm5-alert-hook-check.sh <owner-key-file> [mc] [pi] [pi-ip]
set -u -o pipefail
KEY="${1:?owner key file}"; MC="${2:-https://192.168.200.146}"; PI="${3:-claude@10.200.0.4}"; PIIP="${4:-10.99.0.10}"
HERE=$(cd "$(dirname "$0")" && pwd)
SECRET="bench-alert-secret-$(date +%s)"
ok=0; n=0
chk() { n=$((n + 1)); if [ "$1" = 0 ]; then echo "ok  $2"; ok=$((ok + 1)); else echo "BAD $2"; fi; }
pi() { ssh -o BatchMode=yes -o ConnectTimeout=8 "$PI" "$@"; }
J=$(mktemp); trap 'rm -f "$J"; pi "pkill -f hq-alert-rx.py" >/dev/null 2>&1' EXIT
login() { curl -sk -o /dev/null -m 10 --data-urlencode "token=$(cat "$KEY")" "$MC/api/login" -c "$J"; }
sess() { S=$(curl -sk -m 10 -b "$J" "$MC/api/session"); CS=$(python3 -c 'import json,sys;print(json.loads(sys.argv[1])["csrf"])' "$S"); SQ=$(python3 -c 'import json,sys;print(json.loads(sys.argv[1])["next_seq"])' "$S"); }
post() { R=$(curl -sk -m 10 -b "$J" -H "Origin: $MC" -H "X-HQ-CSRF: $CS" --data "$1&seq=$SQ" --data-urlencode "owner_key=$(cat "$KEY")" "$MC/api/alert-hook"); SQ=$((SQ + 1)); }
"$HERE/pi-ensure-ap.sh" "$PI" >/dev/null 2>&1
# receiver (verifies the signature with sha256(secret) as the HMAC key, exactly as the device keys it)
pi "cat > /tmp/hq-alert-rx.py" <<'PY'
import hashlib, hmac, http.server, sys
key = hashlib.sha256(sys.argv[1].encode()).digest()
class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        sig = self.headers.get("X-HQ-Signature", "")
        good = sig == "sha256=" + hmac.new(key, body, hashlib.sha256).hexdigest()
        with open("/tmp/hq-alert-rx.log", "a") as f:
            f.write(f"{'SIGOK' if good else 'SIGBAD'} {self.path} {self.headers.get('Title','')} | {body.decode(errors='replace')}\n")
        self.send_response(200); self.send_header("Content-Length", "2"); self.end_headers(); self.wfile.write(b"ok")
    def log_message(self, *a): pass
http.server.HTTPServer(("0.0.0.0", 8099), H).serve_forever()
PY
pi "rm -f /tmp/hq-alert-rx.log; nohup python3 /tmp/hq-alert-rx.py '$SECRET' >/dev/null 2>&1 &"
sleep 2
login; sess
post "op=set&ip=$PIIP&port=8099&format=ntfy&path=/heqk-alerts&min_severity=high&reason=bench+alert+check&permanent=true" ; R1=$R
post "op=set&ip=$PIIP&port=8099&format=ntfy&path=/heqk-alerts&min_severity=high&reason=bench+alert+check&permanent=true&secret=$SECRET"
grep -q '"ok":true' <<<"$R" && grep -q 'secret' <<<"$R1"; chk $? "hook refused without a secret, accepted with one ($R)"
curl -sk -m 10 -b "$J" "$MC/api/alert-hook" | grep -q '"configured":true'; chk $? "GET /api/alert-hook: configured"
sleep 3
# high-severity detection: rule 124 (answered SSH brute-force burst to the bench WAN host)
pi "for i in \$(seq 1 30); do timeout 1 bash -c '</dev/tcp/10.100.0.1/22' 2>/dev/null; done" >/dev/null 2>&1
sleep 20
L=$(pi "cat /tmp/hq-alert-rx.log 2>/dev/null")
echo "$L" | sed 's/^/  rx: /' | cut -c1-200
c=$(grep -c . <<<"$L"); [ "$c" -ge 1 ]; chk $? "an alert reached the receiver ($c request(s))"
grep -q "^SIGOK" <<<"$L" && ! grep -q "^SIGBAD" <<<"$L"; chk $? "every alert's X-HQ-Signature verifies with the owner's secret"
[ "$(grep -c 'rule 1200124' <<<"$L")" -le 1 ]; chk $? "one alert for the burst (storm gate), not one per attempt"
S=$(curl -sk -m 10 -b "$J" "$MC/api/alert-hook"); echo "  status: $S" | cut -c1-200
grep -qE '"sent":[1-9]' <<<"$S"; chk $? "/api/alert-hook counts the delivery"
sess; post "op=remove&reason=bench+done&permanent=true"
curl -sk -m 10 -b "$J" "$MC/api/alert-hook" | grep -q '"configured":false'; chk $? "hook removed"
echo "ALERT-HOOK: $([ $ok = $n ] && echo PASS || echo FAIL) ($ok/$n)"
[ $ok = $n ]
