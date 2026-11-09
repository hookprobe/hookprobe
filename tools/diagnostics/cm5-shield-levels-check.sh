#!/usr/bin/env bash
# cm5-shield-levels-check — ADR 0057 on metal: transparent Shield levels from the categorised bench list
# (docs/design/bench-task26/block-bench.txt: example.org = general, doubleclick.net = ads, www.example.net = malware).
#   1. the bench Pi at its signed level (strict): ads + general blocked;
#   2. the owner moves the Pi to `relaxed` (owner journal, permanent): ads + general resolve (level-allowed) while
#      the malware listing still blocks, and /api/dns explains it ("category":"ads","level":"relaxed");
#   3. an owner allow of the malware name is shadowed (confirmed malicious) and the name stays blocked;
#   4. the owner removes the profile: back to the signed level.
#   tools/diagnostics/cm5-shield-levels-check.sh <owner-key-file> [pi-wifi-mac|auto] [mc] [pi]
#   (auto = the MAC of the Pi interface that routes to the AP, 10.99.0.1)
set -u -o pipefail
KEY="${1:?owner key file}"; MAC="${2:-auto}"; MC="${3:-https://192.168.200.146}"; PI="${4:-claude@10.200.0.4}"
ADS=doubleclick.net; GEN=example.org; MAL=www.example.net
ok=0; n=0
chk() { n=$((n + 1)); if [ "$1" = 0 ]; then echo "ok  $2"; ok=$((ok + 1)); else echo "BAD $2"; fi; }
pi() { ssh -o BatchMode=yes -o ConnectTimeout=8 "$PI" "$@"; }
J=$(mktemp); trap 'rm -f "$J"' EXIT
login() { curl -sk -o /dev/null -m 10 --data-urlencode "token=$(cat "$KEY")" "$MC/api/login" -c "$J"; }
sess() { S=$(curl -sk -m 10 -b "$J" "$MC/api/session"); CS=$(python3 -c 'import json,sys;print(json.loads(sys.argv[1])["csrf"])' "$S"); SQ=$(python3 -c 'import json,sys;print(json.loads(sys.argv[1])["next_seq"])' "$S"); }
# sets R (not via $(...): the seq increment must survive in this shell)
post() { R=$(curl -sk -m 10 -b "$J" -H "Origin: $MC" -H "X-HQ-CSRF: $CS" --data "$1&seq=$SQ" --data-urlencode "owner_key=$(cat "$KEY")" "$MC/api/owner-rules"); SQ=$((SQ + 1)); }
resolves() { pi "dig +short +time=3 +tries=1 @10.99.0.1 $1 A" | grep -qE '^[0-9.]+$'; }
[ "$MAC" = auto ] && MAC=$(pi 'cat /sys/class/net/$(ip -4 route get 10.99.0.1 | sed -n "s/.* dev \([^ ]*\).*/\1/p")/address')
echo "bench Pi client MAC: $MAC"
login; sess
D=$(curl -sk -m 10 -b "$J" "$MC/api/dns")
python3 -c 'import json,sys; d=json.loads(sys.argv[1]); sys.exit(0 if d["policy"]["level"]=="balanced" and "level-allowed" in d["counters"] else 1)' "$D"; chk $? "/api/dns: network level balanced, level-allowed counter present"
resolves $ADS; [ $? -ne 0 ]; chk $? "strict (signed): $ADS (ads) blocked"
resolves $GEN; [ $? -ne 0 ]; chk $? "strict (signed): $GEN (general) blocked"
post "op=set&kind=shield_profile&target=$MAC&value=relaxed&reason=levels+metal+test&permanent=true"
grep -q '"ok":true' <<<"$R"; chk $? "owner sets the Pi to relaxed ($R)"
sleep 1
resolves $ADS; chk $? "relaxed: $ADS resolves (level-allowed)"
resolves $GEN; chk $? "relaxed: $GEN resolves (level-allowed)"
resolves $MAL; [ $? -ne 0 ]; chk $? "relaxed: $MAL (malware) still blocked"
D=$(curl -sk -m 10 -b "$J" "$MC/api/dns?limit=64")
grep -q "\"name\":\"$ADS\",\"verdict\":\"level-allowed\",\"category\":\"ads\",\"level\":\"relaxed\"" <<<"$D"; chk $? "/api/dns explains: $ADS level-allowed, ads, relaxed"
grep -q "\"name\":\"$MAL\",\"verdict\":\"blocked\",\"category\":\"malware\",\"level\":\"relaxed\"" <<<"$D"; chk $? "/api/dns explains: $MAL blocked, malware, relaxed"
post "op=set&kind=shield_allow&target=$MAL&reason=levels+metal+test&permanent=true&dry_run=1"
grep -q 'confirmed malicious' <<<"$R"; chk $? "owner allow of the malware name previews as shadowed ($R)"
post "op=remove&kind=shield_profile&target=$MAC&reason=cleanup"
grep -q '"ok":true' <<<"$R"; chk $? "owner removes the profile"
sleep 1
resolves $ADS; [ $? -ne 0 ]; chk $? "back to the signed strict level: $ADS blocked again"
[ "$ok" -eq "$n" ] && { echo "SHIELD-LEVELS: PASS ($ok/$n)"; exit 0; } || { echo "SHIELD-LEVELS: FAIL ($ok/$n)"; exit 1; }
