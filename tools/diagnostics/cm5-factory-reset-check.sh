#!/usr/bin/env bash
# cm5-factory-reset-check — Phase 7 factory reset on metal (release gate REL-09).
#   1. the owner leaves durable state: a Shield block rule and an alert hook (sealed journal); the evidence log
#      already holds detections from earlier bench runs;
#   2. POST /api/factory-reset is refused without confirm=ERASE and with a wrong owner key;
#   3. with confirm=ERASE + re-auth it is accepted; the device reboots, the serial console shows the four wipe
#      steps and DONE, and the boot after that replays 0 journal records and an empty evidence log;
#   4. the label key (OWNER.TXT = the bench key) signs in; no owner rule, no alert hook.
# Destroys the bench unit's owner data by design (owner rules, hook, evidence) — bench only.
#   tools/diagnostics/cm5-factory-reset-check.sh <owner-key-file> <serial-log> [mc]
set -u -o pipefail
KEY="${1:?owner key file}"; LOG="${2:?serial log}"; MC="${3:-https://192.168.200.146}"
ok=0; n=0
chk() { n=$((n + 1)); if [ "$1" = 0 ]; then echo "ok  $2"; ok=$((ok + 1)); else echo "BAD $2"; fi; }
J=$(mktemp); trap 'rm -f "$J"' EXIT
login() { local loc; loc=$(curl -sk -o /dev/null -m 10 -w '%{redirect_url}' --data-urlencode "token=$(cat "$KEY")" "$MC/api/login" -c "$J"); case "$loc" in */login) echo no ;; */) echo ok ;; *) echo no ;; esac; }
sess() { S=$(curl -sk -m 10 -b "$J" "$MC/api/session"); CS=$(python3 -c 'import json,sys;print(json.loads(sys.argv[1])["csrf"])' "$S"); SQ=$(python3 -c 'import json,sys;print(json.loads(sys.argv[1])["next_seq"])' "$S"); }
post() { R=$(curl -sk -m 10 -b "$J" -H "Origin: $MC" -H "X-HQ-CSRF: $CS" --data "$2&seq=$SQ" --data-urlencode "owner_key=${3:-$(cat "$KEY")}" "$MC$1"); SQ=$((SQ + 1)); }
up() { for _ in $(seq 1 80); do curl -sk -o /dev/null -m 5 "$MC/" && return 0; sleep 3; done; return 1; }
[ "$(login)" = ok ] || { echo "FACTORY-RESET: FAIL — the bench key does not sign in to start with"; exit 1; }; sess
post /api/owner-rules "op=set&kind=shield_block&target=factory-reset-check.example&reason=before+reset&permanent=true"
post /api/alert-hook "op=set&ip=10.99.0.11&port=8099&format=ntfy&path=/before-reset&min_severity=high&reason=before+reset&permanent=true&secret=factory-reset-check-secret"
G=$(curl -sk -m 10 -b "$J" "$MC/api/owner-rules"); H=$(curl -sk -m 10 -b "$J" "$MC/api/alert-hook")
grep -q factory-reset-check.example <<<"$G" && grep -q '"configured":true' <<<"$H"; chk $? "owner state present before the reset (a rule + an alert hook)"
post /api/factory-reset "reason=factory+reset+check&permanent=true"; R1=$R
post /api/factory-reset "confirm=ERASE&reason=factory+reset+check&permanent=true" "not-the-owner-key-0000"; R2=$R
grep -q 'confirm=ERASE' <<<"$R1" && grep -q 're-authentication' <<<"$R2"; chk $? "refused without confirm=ERASE and with a wrong key ($R1 | $R2)"
mark=$(stat -c %s "$LOG")
post /api/factory-reset "confirm=ERASE&reason=factory+reset+check&permanent=true"; echo "  reset: $R"
grep -q '"ok":true' <<<"$R"; chk $? "factory reset accepted (re-auth + confirm=ERASE)"
sleep 20; up; sleep 8
T=$(tail -c +$((mark + 1)) "$LOG" | tr -d '\r\000')
grep -a "\[FACTORY-RESET\]" <<<"$T" | sed 's/^/  /' | cut -c1-200
grep -aq "\[FACTORY-RESET\] 4/4 owner journal: .* DONE" <<<"$T"; chk $? "the boot wipe ran all four steps (serial)"
grep -aq "\[FACTORY-RESET\] 1/4 sealed evidence log: Ok" <<<"$T" && grep -aq "2/4 artifact manifest: Ok" <<<"$T" && grep -aq "3/4 sealed snapshot .*: true" <<<"$T"; chk $? "evidence log, artifact manifest and snapshot erased"
AFTER=$(awk '/4\/4 owner journal/{f=1} f' <<<"$T")
grep -aq "\[AP-OWNER\] owner policy journal: .* 0 records replayed, 0 rules active" <<<"$AFTER"; chk $? "the next boot replays an empty journal"
grep -aq "\[AP-EVLOG\] sealed evidence log (DataVolume): 0 records" <<<"$AFTER"; chk $? "the next boot mounts an empty (freshly formatted) evidence log"
[ "$(login)" = ok ]; chk $? "the label key (OWNER.TXT) signs in after the reset"
G=$(curl -sk -m 10 -b "$J" "$MC/api/owner-rules"); H=$(curl -sk -m 10 -b "$J" "$MC/api/alert-hook")
! grep -q factory-reset-check.example <<<"$G" && grep -q '"configured":false' <<<"$H"; chk $? "no owner rule and no alert hook after the reset"
echo "FACTORY-RESET: $([ $ok = $n ] && echo PASS || echo FAIL) ($ok/$n)"
[ $ok = $n ]
