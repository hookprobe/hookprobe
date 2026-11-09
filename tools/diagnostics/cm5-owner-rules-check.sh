#!/usr/bin/env bash
# cm5-owner-rules-check — ADR 0055 on metal: a durable owner rule set through Mission Control survives a POWER
# CYCLE (owner policy journal in the DataVolume), and removing it is a journal record too.
#   1. dry run (nothing written), then a permanent shield_block (owner re-auth + permanent=true) of $DOMAIN —
#      the bench Pi's lookup must now be NXDOMAIN;
#   2. cut power (relay K1); after the boot the block must still hold and /api/owner-rules must say
#      persistent=true with the rule replayed from the journal;
#   3. remove the rule — the name resolves again.
#   tools/diagnostics/cm5-owner-rules-check.sh <owner-key-file> <serial-log> [mc] [pi] [domain]
set -u -o pipefail
KEY="${1:?owner key file}"; LOG="${2:?serial log}"; MC="${3:-https://192.168.200.146}"; PI="${4:-claude@10.200.0.4}"; DOMAIN="${5:-iana.org}"
HERE=$(cd "$(dirname "$0")" && pwd)
ok=0; n=0
chk() { n=$((n + 1)); if [ "$1" = 0 ]; then echo "ok  $2"; ok=$((ok + 1)); else echo "BAD $2"; fi; }
pi() { ssh -o BatchMode=yes -o ConnectTimeout=8 "$PI" "$@"; }
J=$(mktemp); trap 'rm -f "$J"' EXIT
login() { curl -sk -o /dev/null -m 10 --data-urlencode "token=$(cat "$KEY")" "$MC/api/login" -c "$J"; }
sess() { S=$(curl -sk -m 10 -b "$J" "$MC/api/session"); CS=$(python3 -c 'import json,sys;print(json.loads(sys.argv[1])["csrf"])' "$S"); SQ=$(python3 -c 'import json,sys;print(json.loads(sys.argv[1])["next_seq"])' "$S"); }
# sets R (not via $(...): the seq increment must survive in this shell)
post() { R=$(curl -sk -m 10 -b "$J" -H "Origin: $MC" -H "X-HQ-CSRF: $CS" --data "$1&seq=$SQ" --data-urlencode "owner_key=$(cat "$KEY")" "$MC/api/owner-rules"); SQ=$((SQ + 1)); }
resolves() { pi "dig +short +time=3 +tries=1 @10.99.0.1 $DOMAIN A" | grep -qE '^[0-9.]+$'; }
login; sess
resolves; chk $? "$DOMAIN resolves before any owner rule"
post "op=set&kind=shield_block&target=$DOMAIN&reason=owner+journal+metal+test&dry_run=1"
grep -q '"dry_run":true' <<<"$R" && resolves; chk $? "dry run previews ($R) and writes nothing"
post "op=set&kind=shield_block&target=$DOMAIN&reason=owner+journal+metal+test"
grep -q 'permanent=true required' <<<"$R"; chk $? "a set without permanent=true is refused"
post "op=set&kind=shield_block&target=$DOMAIN&reason=owner+journal+metal+test&permanent=true"
grep -q '"ok":true' <<<"$R"; chk $? "permanent shield_block accepted ($R)"
sleep 1
resolves; [ $? -ne 0 ]; chk $? "the Pi's lookup of $DOMAIN is now blocked"
echo "== power cycle (relay K1)"
mark=$(stat -c %s "$LOG")
python3 "$HERE/cm5-relay.py" --backend nano --dev auto cycle >/dev/null 2>&1
for _ in $(seq 1 60); do tail -c +$((mark + 1)) "$LOG" | tr -d '\r\000' | grep -aq "\[AP-OWNER\]" && break; sleep 3; done
L=$(tail -c +$((mark + 1)) "$LOG" | tr -d '\r\000' | grep -a "\[AP-OWNER\]" | tail -1); echo "  $L"
grep -q "records replayed, [1-9]" <<<"$L"; chk $? "after the power cycle the journal replays the rule"
for _ in $(seq 1 40); do pi "ip route | grep -q '^default via 10.99.0.1'" && curl -sk -o /dev/null -m 5 "$MC/" && break; sleep 3; done
sleep 5
login; sess
G=$(curl -sk -m 10 -b "$J" "$MC/api/owner-rules")
python3 -c 'import json,sys; d=json.loads(sys.argv[1]); sys.exit(0 if d["persistent"] and any(r["kind"]=="shield_block" and r["target"]==sys.argv[2] for r in d["rules"]) else 1)' "$G" "$DOMAIN"; chk $? "/api/owner-rules: persistent=true and the rule is back"
resolves; [ $? -ne 0 ]; chk $? "the block still applies after the power cycle"
post "op=remove&kind=shield_block&target=$DOMAIN&reason=cleanup"
grep -q '"ok":true' <<<"$R"; chk $? "remove accepted (a journal record too)"
sleep 1
resolves; chk $? "$DOMAIN resolves again"
[ "$ok" -eq "$n" ] && { echo "OWNER-RULES: PASS ($ok/$n)"; exit 0; } || { echo "OWNER-RULES: FAIL ($ok/$n)"; exit 1; }
