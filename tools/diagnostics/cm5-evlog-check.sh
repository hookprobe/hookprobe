#!/usr/bin/env bash
# cm5-evlog-check — #54 on metal: detections are sealed into the DataVolume evidence log and come back after a
# real POWER CYCLE from it (not only from the 64-event snapshot).
#   1. wait for "[AP-EVLOG] N detections sealed" (the log writes a full 22-event record at once, or once a minute
#      after the clock is known) — run after something produced detections (the LAN-client suite does);
#   2. cut power with the relay rig (K1);
#   3. on the next boot require "[AP-EVLOG] sealed evidence log ... M detections" with M >= what was sealed, and
#      "[AP-PERSIST] N detections restored ... (sealed evidence log)", and Mission Control listing the bench Pi.
#   tools/diagnostics/cm5-evlog-check.sh <owner-key-file> <serial-log> [mc-url] [pi-ip]
set -u -o pipefail
KEY="${1:?owner key file}"; LOG="${2:?serial capture log}"; MC="${3:-https://192.168.200.146}"; PIIP="${4:-10.99.0.10}"
HERE=$(cd "$(dirname "$0")" && pwd)
mark=$(stat -c %s "$LOG")
echo "== waiting for the evidence log to seal detections (<= 3 min)"
for _ in $(seq 1 36); do
  tail -c +$((mark + 1)) "$LOG" | tr -d '\r\000' | grep -aq "\[AP-EVLOG\] [0-9]* detections sealed" && break
  sleep 5
done
W=$(tr -d '\r\000' < "$LOG" | grep -a "\[AP-EVLOG\] [0-9]* detections sealed" | tail -1)
[ -n "$W" ] || { echo "EVLOG: FAIL — the image never sealed a detection to the evidence log"; exit 1; }
echo "  $W"
echo "== power cycle (relay K1)"
mark=$(stat -c %s "$LOG")
python3 "$HERE/cm5-relay.py" --backend nano --dev auto cycle >/dev/null 2>&1 || { echo "EVLOG: FAIL — relay cycle failed"; exit 1; }
for _ in $(seq 1 60); do
  tail -c +$((mark + 1)) "$LOG" | tr -d '\r\000' | grep -aq "\[AP-PERSIST\] [0-9]* detections restored" && break
  sleep 3
done
NEW=$(tail -c +$((mark + 1)) "$LOG" | tr -d '\r\000')
E=$(grep -a "\[AP-EVLOG\] sealed evidence log" <<<"$NEW" | tail -1)
R=$(grep -a "\[AP-PERSIST\] [0-9]* detections restored" <<<"$NEW" | tail -1)
echo "  ${E:-<no AP-EVLOG mount line>}"
echo "  ${R:-<no AP-PERSIST restore line>}"
m=$(sed -n 's/.*records, \([0-9]*\) detections kept.*/\1/p' <<<"$E")
[ "${m:-0}" -gt 0 ] && grep -q "sealed evidence log)" <<<"$R" || { echo "EVLOG: FAIL — no detections came back from the evidence log"; exit 1; }
for _ in $(seq 1 30); do curl -sk -o /dev/null -m 5 "$MC/" && break; sleep 3; done
J=$(mktemp); trap 'rm -f "$J"' EXIT
curl -sk -o /dev/null -m 10 --data-urlencode "token=$(cat "$KEY")" "$MC/api/login" -c "$J"
D=$(curl -sk -m 10 -b "$J" "$MC/api/detections?limit=300")
if grep -q "\"src_ip\":\"$PIIP\"" <<<"$D"; then
  echo "EVLOG: PASS — $m detections kept in the sealed evidence log across a power cycle; Mission Control lists the bench Pi's"
  exit 0
fi
echo "EVLOG: FAIL — restored on serial but Mission Control shows none from $PIIP"; exit 1
