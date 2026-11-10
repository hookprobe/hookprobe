#!/usr/bin/env bash
# cm5-powerloss-torture — readiness 3.4: randomized power cuts WHILE the owner journal is being written.
# Each cycle: owner rules are written through Mission Control (one every ~3.5 s, under the 20-per-minute session
# limit); after a random 4–30 s the relay cuts power. After the boot:
#   - `[AP-OWNER] … records replayed` (a torn tail may be dropped — that is the designed recovery, counted);
#   - EVERY rule the device ACKNOWLEDGED before the cut is still listed (durability of acknowledged writes);
#   - the sealed evidence log mounts and Mission Control answers.
# Starts and ends with an owner revoke-all (a sealed OP_CLEAR record) so the bench is left clean.
#   tools/diagnostics/cm5-powerloss-torture.sh <owner-key-file> <serial-log> [cycles] [mc]
set -u -o pipefail
KEY="${1:?owner key file}"; LOG="${2:?serial log}"; N="${3:-8}"; MC="${4:-https://192.168.200.146}"
HERE=$(cd "$(dirname "$0")" && pwd)
J=$(mktemp); A=$(mktemp); trap 'rm -f "$J" "$A"' EXIT
ok=0; n=0; torn=0
chk() { n=$((n + 1)); if [ "$1" = 0 ]; then ok=$((ok + 1)); else echo "BAD $2"; fi; }
since() { tail -c +$(($1 + 1)) "$LOG" | tr -d '\r\000'; }
wait_for() { local t=0; while [ $t -lt "$3" ]; do since "$1" | grep -aE "$2" >/dev/null && return 0; sleep 3; t=$((t + 3)); done; return 1; }
login() { curl -sk -o /dev/null -m 10 --data-urlencode "token=$(cat "$KEY")" "$MC/api/login" -c "$J"; }
sess() { S=$(curl -sk -m 10 -b "$J" "$MC/api/session"); CS=$(python3 -c 'import json,sys;print(json.loads(sys.argv[1])["csrf"])' "$S" 2>/dev/null); SQ=$(python3 -c 'import json,sys;print(json.loads(sys.argv[1])["next_seq"])' "$S" 2>/dev/null); }
post() { R=$(curl -sk -m 10 -b "$J" -H "Origin: $MC" -H "X-HQ-CSRF: $CS" --data "$1&seq=$SQ" --data-urlencode "owner_key=$(cat "$KEY")" "$MC/api/owner-rules"); SQ=$((SQ + 1)); }
listed() { curl -sk -m 10 -b "$J" "$MC/api/owner-rules"; }
up() { for _ in $(seq 1 40); do curl -sk -o /dev/null -m 5 "$MC/" && return 0; sleep 3; done; return 1; }
up; login; sess; post "op=revoke_all&reason=torture+start&permanent=true"; echo "start: revoke_all $R"
for c in $(seq 1 "$N"); do
  : > "$A"
  login; sess
  delay=$((4 + RANDOM % 27))
  ( k=0; while :; do k=$((k + 1)); post "op=set&kind=shield_block&target=pl$c-$k.torture.invalid&reason=power+loss+torture&permanent=true"
      grep -q '"ok":true' <<<"$R" && echo "pl$c-$k.torture.invalid" >> "$A"; sleep 3.5; done ) &
  wp=$!
  sleep "$delay"
  mark=$(stat -c %s "$LOG")
  python3 "$HERE/cm5-relay.py" --backend nano --dev auto cycle >/dev/null 2>&1
  kill "$wp" 2>/dev/null; wait "$wp" 2>/dev/null
  acked=$(grep -c . "$A")
  wait_for "$mark" "\[AP-OWNER\] owner policy journal: LBA" 240; r1=$?
  line=$(since "$mark" | grep -a "\[AP-OWNER\] owner policy journal" | tail -1)
  grep -q "torn tail was dropped" <<<"$line" && torn=$((torn + 1))
  chk $r1 "cycle $c: journal replayed after the cut"
  wait_for "$mark" "\[AP-EVLOG\] sealed evidence log" 120; chk $? "cycle $c: evidence log mounted"
  up; chk $? "cycle $c: Mission Control answers"
  login; L=$(listed); miss=0
  while read -r t; do [ -n "$t" ] && ! grep -q "\"$t\"" <<<"$L" && miss=$((miss + 1)); done < "$A"
  [ "$miss" = 0 ]; chk $? "cycle $c: all $acked acknowledged rules survived ($miss missing)"
  echo "  cycle $c: cut after ${delay}s, $acked acked, $miss missing | $(cut -c1-160 <<<"$line" | sed 's/^ *//')"
done
login; sess; post "op=revoke_all&reason=torture+end&permanent=true"; echo "end: revoke_all $R"
echo "  torn tails recovered: $torn of $N cuts"
echo "POWERLOSS-TORTURE: $([ $ok = $n ] && echo PASS || echo FAIL) ($ok/$n checks, $N cuts)"
[ $ok = $n ]
