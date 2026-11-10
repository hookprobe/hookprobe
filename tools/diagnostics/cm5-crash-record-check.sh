#!/usr/bin/env bash
# cm5-crash-record-check — metal test plan J10: the crash record survives the EL2-gate reset.
# Run right after booting a BENCH image built with `--features crashtest` (it panics once, 120 s into the AP loop):
#   1. wait for `[PANIC] … crashtest` on the serial console (the unit resets through hvc #0);
#   2. the next boot must print `[CRASH] the previous boot ended in a panic: … crashtest …`;
#   3. Mission Control `/api/health` reports `last_crash.kind = "panic"`;
#   4. that boot does not panic again (the crashtest panics only when no record was found).
# If DRAM does not keep the page across the reset, step 2 fails — record the result either way.
#   tools/diagnostics/cm5-crash-record-check.sh <owner-key-file> <serial-log> [mc]
set -u -o pipefail
KEY="${1:?owner key}"; LOG="${2:?serial log}"; MC="${3:-https://192.168.200.146}"
ok=0; n=0
chk() { n=$((n + 1)); if [ "$1" = 0 ]; then echo "ok  $2"; ok=$((ok + 1)); else echo "BAD $2"; fi; }
since() { tail -c +$(($1 + 1)) "$LOG" | tr -d '\r\000'; }
wait_for() { local t=0; while [ $t -lt "$3" ]; do since "$1" | grep -aE "$2" >/dev/null && return 0; sleep 3; t=$((t + 3)); done; return 1; }
mark=${J10_MARK:-$(stat -c %s "$LOG")}   # J10_MARK: a serial-log offset taken BEFORE the boot (the panic can come early)
wait_for "$mark" "\[PANIC\].*crashtest" 420; chk $? "the crashtest image panicked in the AP loop"
m2=$(since "$mark" | grep -abo "\[PANIC\].*crashtest" | head -1 | cut -d: -f1); m2=$((mark + ${m2:-0}))
wait_for "$m2" "\[CRASH\] the previous boot ended in a panic: .*crashtest" 300; chk $? "the next boot reports the crash record (DRAM kept the page across the reset)"
since "$m2" | grep -a "\[CRASH\]" | tail -1 | cut -c1-240
wait_for "$m2" "\[P11-AP3\] persistent WPA2 AP serve loop up" 240; chk $? "the AP is back after the crash"
for _ in $(seq 1 20); do curl -sk -o /dev/null -m 5 "$MC/" && break; sleep 3; done
J=$(mktemp); trap 'rm -f "$J"' EXIT
curl -sk -o /dev/null -m 10 --data-urlencode "token=$(cat "$KEY")" "$MC/api/login" -c "$J"
H=$(curl -sk -m 10 -b "$J" "$MC/api/health")
grep -o '"last_crash":{[^}]*}' <<<"$H" | cut -c1-240
grep -q '"last_crash":{"kind":"panic"' <<<"$H"; chk $? "/api/health last_crash.kind = panic"
m3=$(stat -c %s "$LOG"); sleep 200
since "$m3" | grep -a "\[PANIC\]" >/dev/null; [ $? -ne 0 ]; chk $? "the reporting boot did not panic again"
echo "CRASH-RECORD: $([ $ok = $n ] && echo PASS || echo FAIL) ($ok/$n)"
[ $ok = $n ]
