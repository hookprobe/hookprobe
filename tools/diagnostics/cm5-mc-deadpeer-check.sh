#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Pre-soak finding 1 on metal: 8 HTTPS clients to Mission Control (AP side, 10.99.0.1, from the bench Pi over Wi-Fi)
# whose peer then goes silent (a Pi-only nft rule drops exactly those 8 connections, by source port — no FIN, no RST).
# Before #1468 the slots stay pinned and a 9th client is refused; with #1468 they are reaped ~60 s after the peer went
# silent. Needs PI_SUDO_FILE. Everything is on the Pi and removed at the end.
set -u
: "${PI_SUDO_FILE:?}"; PI=claude@10.200.0.4; MAXS="${1:-240}"
pi() { ssh -o BatchMode=yes -o ConnectTimeout=8 "$PI" "$@"; }
cleanup() {
  pi 'sudo -S -p "" nft delete table inet heqk_deadpeer 2>/dev/null; pkill -f heqk_deadpeer_hold 2>/dev/null; rm -f /dev/shm/heqk_tok; true' < "$PI_SUDO_FILE"
  # sign the test session out (POST /api/logout with the session's CSRF), then forget it
  pi 'test -f /dev/shm/heqk_sid && python3 - <<"PY"
import json, ssl, urllib.request
c = ssl.create_default_context(); c.check_hostname = False; c.verify_mode = ssl.CERT_NONE
sid = open("/dev/shm/heqk_sid").read().strip(); h = {"Cookie": "hq_session=" + sid}
try:
    s = json.loads(urllib.request.urlopen(urllib.request.Request("https://10.99.0.1/api/session", headers=h), context=c, timeout=8).read())
    h.update({"Origin": "https://10.99.0.1", "X-HQ-CSRF": s.get("csrf", "")})
    urllib.request.urlopen(urllib.request.Request("https://10.99.0.1/api/logout", b"", h), context=c, timeout=8).read()
    print("test session signed out")
except Exception as e:
    print("logout:", e)
PY
rm -f /dev/shm/heqk_sid; true'
}
trap cleanup EXIT
cleanup
# sign in once on the Pi (the bench owner token via stdin into a 0600 tmpfs file, deleted right after), then hold 8 live
# SSE streams (/api/stream) from source ports 45100..45107 — the server keeps pinging them (the case that pinned slots)
KEY="${OWNER_KEY_FILE:?OWNER_KEY_FILE (the bench owner key)}"
pi 'umask 077; cat > /dev/shm/heqk_tok' < "$KEY"
pi 'nohup python3 - heqk_deadpeer_hold >/tmp/heqk_deadpeer.log 2>&1 <<"PY" &
import socket, ssl, time, os, urllib.request, urllib.parse, http.cookiejar
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
tok = open("/dev/shm/heqk_tok").read().strip(); os.remove("/dev/shm/heqk_tok")
cj = http.cookiejar.CookieJar()
o = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx), urllib.request.HTTPCookieProcessor(cj))
o.open("https://10.99.0.1/api/login", urllib.parse.urlencode({"token": tok}).encode(), timeout=10).read()
sid = [c.value for c in cj if c.name == "hq_session"][0]
open("/dev/shm/heqk_sid", "w").write(sid)
s = []
for i in range(8):
    r = socket.socket(); r.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); r.bind(("10.99.0.10", 45100 + i))
    r.settimeout(8); r.connect(("10.99.0.1", 443)); t = ctx.wrap_socket(r)
    t.sendall(("GET /api/stream HTTP/1.1\r\nHost: 10.99.0.1\r\nCookie: hq_session=%s\r\n\r\n" % sid).encode())
    head = t.recv(512).split(b"\r\n")[0]
    s.append(t)
    print("stream", i, head.decode(errors="replace"), flush=True)
print("held", len(s), flush=True)
time.sleep(900)
PY
sleep 8; cat /tmp/heqk_deadpeer.log'
# the peer goes silent: drop those 8 connections both ways (nothing else)
pi 'sudo -S -p "" nft -f - <<"NFT"
table inet heqk_deadpeer {
  chain o { type filter hook output priority -10; tcp sport 45100-45107 drop; }
  chain i { type filter hook input priority -10; tcp dport 45100-45107 drop; }
}
NFT
echo silenced' < "$PI_SUDO_FILE"
T0=$(date +%s); first_ok=""; fails=0; oks=0
while [ $(( $(date +%s) - T0 )) -lt "$MAXS" ]; do
  t=$(( $(date +%s) - T0 ))
  c=$(pi "curl -sk -o /dev/null -m 4 -w '%{http_code}' https://10.99.0.1/api/health" 2>/dev/null)
  if [ "$t" -ge 20 ]; then
    if [ "$c" = 200 ]; then oks=$((oks + 1)); [ -z "$first_ok" ] && first_ok=$t; else fails=$((fails + 1)); fi
  fi
  echo "  t=${t}s 9th client: ${c:-none}"
  [ -n "$first_ok" ] && [ $(( t - first_ok )) -ge 30 ] && break
  sleep 5
done
echo "DEADPEER: 9th client after the 8 went silent (from t=20s): first served at t=${first_ok:-never}s, fails=$fails oks=$oks"
