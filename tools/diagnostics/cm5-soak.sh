#!/usr/bin/env bash
# cm5-soak — production-readiness 3.1: run the heqk AP for HOURS under continuous real client traffic and
# prove it stays up and healthy. Every interval: Mission Control /api/health (counters must only grow — a
# drop means a silent reboot), a short throughput sample from the bench Pi through the AP, a DNS lookup,
# and the FTDI serial log scanned for a reboot banner / panic / fault. Between samples the Pi browses.
# Writes a CSV + a PASS/FAIL summary.
#   tools/diagnostics/cm5-soak.sh <owner-key-file> <serial-log> <hours> [interval-s] [mc] [pi] [out-dir]
set -u -o pipefail
KEY="${1:?owner key}"; LOG="${2:?serial log}"; HOURS="${3:?hours}"; IV="${4:-300}"
MC="${5:-https://192.168.200.146}"; PI="${6:-claude@10.200.0.4}"; OUT="${7:-$HOME/heqk-metal-logs/soak-$(date +%Y%m%d-%H%M)}"
mkdir -p "$OUT"; CSV="$OUT/soak.csv"; J=$(mktemp); trap 'rm -f "$J"' EXIT
echo "t,elapsed_s,health,seen,forwarded,dropped,detections,clients,dns_inspected,mbps,dns_ok,serial_events" > "$CSV"
pi() { ssh -o BatchMode=yes -o ConnectTimeout=8 "$PI" "$@"; }
login() { curl -sk -o /dev/null -m 10 --data-urlencode "token=$(cat "$KEY")" "$MC/api/login" -c "$J"; }
"$(dirname "$0")/pi-ensure-ap.sh" "$PI" || echo "soak: WARNING — the Pi is not on the CM5 AP"
IF=$(pi "ip -4 route get 10.99.0.1 | sed -n 's/.* dev \([^ ]*\).*/\1/p'" 2>/dev/null)
echo "soak: ${HOURS} h, sample every ${IV} s, client interface ${IF:-?}, out $OUT"
# background browsing load on the Pi for the whole soak
SITES="wikipedia.org github.com stackoverflow.com bbc.co.uk cloudflare.com mozilla.org debian.org python.org rust-lang.org apple.com google.com youtube.com"
pi "nohup bash -c 'end=\$((SECONDS+${HOURS}*3600)); while [ \$SECONDS -lt \$end ]; do for s in $SITES; do curl --interface $IF -s -o /dev/null -m 10 -L https://\$s/; sleep \$((RANDOM%10+3)); done; done' >/dev/null 2>&1 &"
t0=$(date +%s); mark=$(stat -c %s "$LOG"); prev_seen=0; reboots=0; fails=0; n=0; worst=999999
end=$((t0 + HOURS * 3600))
login
while [ "$(date +%s)" -lt "$end" ]; do
  n=$((n + 1)); now=$(date +%s)
  H=$(curl -sk -m 10 -b "$J" "$MC/api/health")
  grep -q '"seen"' <<<"$H" || { login; H=$(curl -sk -m 10 -b "$J" "$MC/api/health"); }
  read -r ok seen fwd drop det cli dns < <(python3 -c '
import json,sys
try:
    d=json.loads(sys.argv[1]); w=d.get("wan",{})
    print("ok", d["seen"], d["forwarded"], d["dropped"], d["detections"], w.get("clients",0), w.get("dns_inspected",0))
except Exception: print("down 0 0 0 0 0 0")' "$H")
  b=$(pi "curl --interface $IF -s -o /dev/null -m 20 -w '%{speed_download}' '${HQ_SINK_URL:-http://10.100.0.1:8088/blob}'" 2>/dev/null || echo 0)
  mbps=$(awk -v b="$b" 'BEGIN{printf "%.1f", b*8/1e6}')
  dns=$(pi "dig +short +time=3 +tries=1 @10.99.0.1 example.com A" 2>/dev/null | grep -cE '^[0-9.]+$')
  ev=$(tail -c +$((mark + 1)) "$LOG" | tr -d '\r\000' | grep -acE "secure boot: PASS|PANIC|panic|EXCEPTION|SError|Synchronous|data abort|watchdog reset")
  if [ "$ok" = ok ] && [ "$seen" -lt "$prev_seen" ]; then reboots=$((reboots + 1)); fi
  [ "$ev" -gt 0 ] && reboots=$((reboots + ev))
  [ "$ok" != ok ] || [ "$dns" = 0 ] || awk -v m="$mbps" 'BEGIN{exit !(m<20)}' && fails=$((fails + 1))
  awk -v m="$mbps" -v w="$worst" 'BEGIN{exit !(m<w)}' && worst=$mbps
  echo "$(date -Is),$((now - t0)),$ok,$seen,$fwd,$drop,$det,$cli,$dns,$mbps,$dns,$ev" >> "$CSV"
  [ "$ok" = ok ] && prev_seen=$seen
  mark=$(stat -c %s "$LOG")
  printf '  %5ds %s seen=%s det=%s %s Mbps dns=%s serial_events=%s\n' $((now - t0)) "$ok" "$seen" "$det" "$mbps" "$dns" "$ev"
  sleep "$IV"
done
med=$(awk -F, 'NR>1{print $10}' "$CSV" | sort -n | awk '{a[NR]=$1} END{print a[int((NR+1)/2)]}')
S="SOAK: ${HOURS} h, ${n} samples — reboots/faults=${reboots}, failed samples=${fails}, throughput median ${med} Mbps (worst ${worst}) — CSV $CSV"
if [ "$reboots" -eq 0 ] && [ "$fails" -le $((n / 20)) ]; then echo "PASS — $S" | tee "$OUT/summary"; exit 0; fi
echo "FAIL — $S" | tee "$OUT/summary"; exit 1
