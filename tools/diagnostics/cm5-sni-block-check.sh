#!/usr/bin/env bash
# cm5-sni-block-check — rule 126 enforcement on metal (operator 2026-11-10; G31).
# The bench Pi BYPASSES Shield's DNS: it resolves names through 1.1.1.1 and connects by IP with the name as SNI
# (exactly what DoH / a hard-coded IP does). Expected:
#   - doubleclick.net (bench BLOCK.TXT, category ads): the TLS connection is refused (no handshake), and the
#     Shield log (/api/dns recent) lists it with qtype 443, verdict blocked, category ads;
#   - example.com (allowed): the same bypass connects normally (ADR 0023: a bypass to an allowed name passes).
#   tools/diagnostics/cm5-sni-block-check.sh <owner-key-file> [mc] [pi]
set -u -o pipefail
KEY="${1:?owner key file}"; MC="${2:-https://192.168.200.146}"; PI="${3:-claude@10.200.0.4}"
HERE=$(cd "$(dirname "$0")" && pwd)
ok=0; n=0
chk() { n=$((n + 1)); if [ "$1" = 0 ]; then echo "ok  $2"; ok=$((ok + 1)); else echo "BAD $2"; fi; }
pi() { ssh -o BatchMode=yes -o ConnectTimeout=8 "$PI" "$@"; }
"$HERE/pi-ensure-ap.sh" "$PI" >/dev/null 2>&1
# bypass: the address is resolved OFF the AP path (here, on the bench host — as a DoH resolver or a hard-coded
# IP would) and handed to the Pi, which connects by IP with the name as SNI. (Plain DNS to any resolver through
# the AP is still Shield-inspected — that is not a bypass on heqk.)
bypass() {   # <name> -> http code of an HTTPS GET to the name's real IP with SNI = name
  local ip; ip=$(dig +short +time=3 +tries=2 @1.1.1.1 "$1" A | grep -E '^[0-9.]+$' | head -1)
  [ -n "$ip" ] || { echo NOIP; return; }
  pi "curl -s -o /dev/null -m 8 -w '%{http_code}' --resolve $1:443:$ip https://$1/ 2>/dev/null || true"
}
b=$(bypass doubleclick.net); echo "  doubleclick.net over a DNS bypass -> HTTP ${b}"
[ "$b" = 000 ]; chk $? "a DNS bypass to a Shield-blocked name (ads) is refused at the TLS ClientHello"
a=$(bypass example.com); echo "  example.com over a DNS bypass -> HTTP ${a}"
[ -n "$a" ] && [ "$a" != 000 ] && [ "$a" != NOIP ]; chk $? "a DNS bypass to an allowed name passes"
J=$(mktemp); trap 'rm -f "$J"' EXIT
curl -sk -o /dev/null -m 10 --data-urlencode "token=$(cat "$KEY")" "$MC/api/login" -c "$J"
D=$(curl -sk -m 10 -b "$J" "$MC/api/dns?limit=256")
E=$(python3 -c 'import json,sys
r=[e for e in json.loads(sys.argv[1]).get("recent",[]) if e.get("qtype")==443 and e.get("name")=="doubleclick.net"]
print(json.dumps(r[0]) if r else "")' "$D" 2>/dev/null)
echo "  shield log: ${E:-<none>}"
grep -q '"verdict": "blocked"' <<<"$E" && grep -q '"category": "ads"' <<<"$E"; chk $? "the block is in the Shield log with qtype 443 (TLS SNI), verdict blocked, category ads"
echo "SNI-BLOCK: $([ $ok = $n ] && echo PASS || echo FAIL) ($ok/$n)"
[ $ok = $n ]
