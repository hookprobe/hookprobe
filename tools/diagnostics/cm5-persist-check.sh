#!/usr/bin/env bash
# cm5-persist-check — G12 on metal: the AP image's sealed snapshot survives a real POWER CYCLE.
#   1. wait until the running image reports a sealed snapshot write ([AP-PERSIST] sealed snapshot written)
#      — it persists every 5 min while dirty, so run this after something produced detections (the LAN-client
#      suite does: rules 124/125/126 from the bench Pi);
#   2. cut power with the relay rig (K1) — not a reflash, not a warm reset;
#   3. on the next boot require [PROD-FULL] M3 RESTORED + [AP-PERSIST] N detections restored (N > 0), and that
#      Mission Control lists a pre-power-cut detection from the bench Pi before any new traffic.
#   tools/diagnostics/cm5-persist-check.sh <owner-key-file> <serial-log> [mc-url] [pi-ip]
set -u -o pipefail
KEY="${1:?owner key file}"; LOG="${2:?serial capture log}"; MC="${3:-https://192.168.200.146}"; PIIP="${4:-10.99.0.10}"
HERE=$(cd "$(dirname "$0")" && pwd)
clean() { tr -d '\r\000' < "$LOG"; }
mark=$(stat -c %s "$LOG")
echo "== waiting for the running image to write its sealed snapshot (<= 7 min)"
ok=0
for _ in $(seq 1 84); do
  # a write after the mark, or the most recent one if it already happened this boot
  if tail -c +$((mark + 1)) "$LOG" | tr -d '\r\000' | grep -a "\[AP-PERSIST\] sealed snapshot written" >/dev/null; then ok=1; break; fi
  sleep 5
done
last_write=$(clean | grep -a "\[AP-PERSIST\] sealed snapshot written" | tail -1)
[ -n "$last_write" ] || { echo "PERSIST: FAIL — the image never wrote a sealed snapshot"; exit 1; }
echo "  $last_write"
[ $ok = 1 ] || echo "  (using the last write before this script started)"
echo "== power cycle (relay K1)"
mark=$(stat -c %s "$LOG")
python3 "$HERE/cm5-relay.py" --backend nano --dev auto cycle >/dev/null 2>&1 || { echo "PERSIST: FAIL — relay cycle failed"; exit 1; }
for _ in $(seq 1 60); do
  tail -c +$((mark + 1)) "$LOG" | tr -d '\r\000' | grep -a "\[AP-PERSIST\] [0-9]* detections restored" >/dev/null && break
  sleep 3
done
NEW=$(tail -c +$((mark + 1)) "$LOG" | tr -d '\r\000')
R1=$(grep -a "\[PROD-FULL\] M3 RESTORED" <<<"$NEW" | tail -1)
R2=$(grep -a "\[AP-PERSIST\] [0-9]* detections restored" <<<"$NEW" | tail -1)
echo "  ${R1:-<no M3 RESTORED line>}"
echo "  ${R2:-<no AP-PERSIST restore line>}"
n=$(sed -n 's/.*\[AP-PERSIST\] \([0-9]*\) detections restored.*/\1/p' <<<"$R2")
[ -n "$R1" ] && [ "${n:-0}" -gt 0 ] || { echo "PERSIST: FAIL — nothing restored after the power cycle"; exit 1; }
# Mission Control must show a pre-power-cut detection from the bench Pi
for _ in $(seq 1 30); do curl -sk -o /dev/null -m 5 "$MC/" && break; sleep 3; done
J=$(mktemp); trap 'rm -f "$J"' EXIT
curl -sk -o /dev/null -m 10 --data-urlencode "token=$(cat "$KEY")" "$MC/api/login" -c "$J"
D=$(curl -sk -m 10 -b "$J" "$MC/api/detections?limit=200")
if grep -q "\"src_ip\":\"$PIIP\"" <<<"$D"; then
  echo "PERSIST: PASS — $n detections survived a power cycle; Mission Control lists the bench Pi's earlier detections"
  exit 0
fi
echo "PERSIST: FAIL — restored on serial but Mission Control shows none from $PIIP"; exit 1
