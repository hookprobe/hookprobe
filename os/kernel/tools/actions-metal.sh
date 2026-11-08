#!/usr/bin/env bash
# ADR 0053 request-level metal checks (metal plan H7-H10, I9) against the device MC.
# usage: os/kernel/tools/actions-metal.sh <owner-key-file> [https://<device>]
set -u
B="${2:-https://192.168.200.146}"
TOKEN=$(cat "$1")
JAR=$(mktemp); C="-k -b $JAR"
r() { echo "$1: $2"; }
curl -sk -o /dev/null -m 10 --data-urlencode "token=$TOKEN" "$B/api/login" -c "$JAR"
grep -q hq_session "$JAR" && r login ok || { r login FAILED; exit 1; }
SS=$(curl -s -m 10 $C "$B/api/session"); echo "session: $SS"
CS=$(python3 -c 'import json,sys;print(json.loads(sys.argv[1])["csrf"])' "$SS")
SQ=$(python3 -c 'import json,sys;print(json.loads(sys.argv[1])["next_seq"])' "$SS")
P() { curl -s -m 10 $C -H "Origin: ${3:-$B}" ${1:+-H "X-HQ-CSRF: $1"} -w ' [%{http_code}]' --data "$2" "$B/api/actions"; echo; }
echo "H-ok   hold TEST-NET 203.0.113.9 120 s: $(P "$CS" "kind=hold_ip&target=203.0.113.9&ttl=120&reason=metal+H7+test&seq=$SQ")"
echo "H7     replay same seq:                 $(P "$CS" "kind=hold_ip&target=203.0.113.9&ttl=120&reason=metal+H7+test&seq=$SQ")"
echo "H8a    foreign Origin:                  $(P "$CS" "kind=ack&target=203.0.113.9&reason=metal+H8&seq=$((SQ+1))" https://evil.example)"
echo "H8b    missing CSRF:                    $(P "" "kind=ack&target=203.0.113.9&reason=metal+H8&seq=$((SQ+2))")"
echo "H9     ttl=999999:                      $(P "$CS" "kind=hold_ip&target=203.0.113.9&ttl=999999&reason=metal+H9&seq=$((SQ+3))")"
echo "H10    hold mgmt 192.168.200.1:         $(P "$CS" "kind=hold_ip&target=192.168.200.1&ttl=120&reason=metal+H10&seq=$((SQ+4))")"
echo "H5neg  shield_allow wrong owner key:    $(P "$CS" "kind=shield_allow&target=example.org&ttl=600&reason=metal+H5&owner_key=WRONG-KEY&seq=$((SQ+5))")"
echo "H11a   shield_pause 2 h (max 1 h):    $(P "$CS" "kind=shield_pause&target=10.99.0.250&ttl=7200&reason=metal+H11&owner_key=$TOKEN&seq=$((SQ+7))")"
echo "H11b   shield_pause no owner key:       $(P "$CS" "kind=shield_pause&target=10.99.0.250&ttl=600&reason=metal+H11&seq=$((SQ+8))")"
echo "H11c   shield_pause 10 min (owner key): $(P "$CS" "kind=shield_pause&target=10.99.0.250&ttl=600&reason=metal+H11&owner_key=$TOKEN&seq=$((SQ+9))")"
A=$(curl -s -m 10 $C "$B/api/actions"); echo "actions: $(echo "$A" | head -c 1500)"
AID=$(python3 -c 'import json,sys;a=json.loads(sys.argv[1])["active"];print(next((x["id"] for x in a if x["target"]=="203.0.113.9"),0))' "$A")
echo "revoke $AID: $(curl -s -m 10 $C -H "Origin: $B" -H "X-HQ-CSRF: $CS" -w ' [%{http_code}]' --data "id=$AID&seq=$((SQ+10))" "$B/api/actions/revoke")"
echo "active after revoke: $(curl -s -m 10 $C "$B/api/actions" | python3 -c 'import json,sys;print(len(json.load(sys.stdin)["active"]))')"
curl -s -o /dev/null -m 10 $C -H "Origin: $B" -H "X-HQ-CSRF: $CS" --data "" "$B/api/logout"
rm -f "$JAR"
