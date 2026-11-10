#!/usr/bin/env bash
# cm5-owner-rotate-check — G28 owner-key rotation on metal, LEAVING THE BENCH KEY IN PLACE:
#   1. rotate the owner key to a temporary one (POST /api/owner-key, re-auth with the bench key);
#   2. the bench key no longer signs in, the temporary key does;
#   3. power cycle (relay K1): the rotation came back from the sealed journal ([OWNER] … rotated by the owner);
#   4. rotate BACK to the bench key (re-auth with the temporary key) and confirm the bench key signs in again.
#   tools/diagnostics/cm5-owner-rotate-check.sh <owner-key-file> <serial-log> [mc]
set -u -o pipefail
KEY="${1:?owner key file}"; LOG="${2:?serial log}"; MC="${3:-https://192.168.200.146}"
HERE=$(cd "$(dirname "$0")" && pwd)
TMPK="rotate-check-$(date +%s)-$RANDOM-key"
ok=0; n=0
chk() { n=$((n + 1)); if [ "$1" = 0 ]; then echo "ok  $2"; ok=$((ok + 1)); else echo "BAD $2"; fi; }
J=$(mktemp); trap 'rm -f "$J"' EXIT
login() { curl -sk -o /dev/null -m 10 -w '%{http_code}' --data-urlencode "token=$1" "$MC/api/login" -c "$J"; }
sess() { S=$(curl -sk -m 10 -b "$J" "$MC/api/session"); CS=$(python3 -c 'import json,sys;print(json.loads(sys.argv[1])["csrf"])' "$S"); SQ=$(python3 -c 'import json,sys;print(json.loads(sys.argv[1])["next_seq"])' "$S"); }
rotate() {   # <current> <new>
  R=$(curl -sk -m 10 -b "$J" -H "Origin: $MC" -H "X-HQ-CSRF: $CS" --data "reason=rotate+check&permanent=true&seq=$SQ" \
      --data-urlencode "owner_key=$1" --data-urlencode "new_owner_key=$2" "$MC/api/owner-key"); SQ=$((SQ + 1)); }
up() { for _ in $(seq 1 60); do curl -sk -o /dev/null -m 5 "$MC/" && return 0; sleep 3; done; return 1; }
BENCH=$(cat "$KEY")
login "$BENCH" >/dev/null; sess
rotate "$BENCH" "$TMPK"; echo "  rotate: $R"
grep -q '"ok":true' <<<"$R"; chk $? "owner key rotated (re-auth with the current key)"
[ "$(login "$BENCH")" != 200 ]; chk $? "the old (bench) key no longer signs in"
[ "$(login "$TMPK")" = 200 ]; chk $? "the new key signs in"
mark=$(stat -c %s "$LOG")
python3 "$HERE/cm5-relay.py" --backend nano --dev auto cycle >/dev/null 2>&1
up; sleep 5
tail -c +$((mark + 1)) "$LOG" | tr -d '\r\000' | grep -a "\[OWNER\]" | tail -1 | sed 's/^/  /'
tail -c +$((mark + 1)) "$LOG" | tr -d '\r\000' | grep -a "\[OWNER\] Mission Control owner key: rotated by the owner" >/dev/null; chk $? "after a power cycle the rotation came back from the sealed journal"
[ "$(login "$TMPK")" = 200 ]; chk $? "the rotated key still signs in after the power cycle"
sess; rotate "$TMPK" "$BENCH"; echo "  rotate back: $R"
grep -q '"ok":true' <<<"$R" && [ "$(login "$BENCH")" = 200 ]; chk $? "rotated back: the bench key signs in again"
echo "OWNER-ROTATE: $([ $ok = $n ] && echo PASS || echo FAIL) ($ok/$n)"
[ $ok = $n ]
