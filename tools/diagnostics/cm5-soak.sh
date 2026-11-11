#!/usr/bin/env bash
# cm5-soak — production-readiness 3.1: run the heqk AP for HOURS under continuous real client traffic and
# prove it stays up and healthy. Every interval: Mission Control /api/health (counters must only grow — a
# drop means a silent reboot), a short throughput sample from the bench Pi through the AP, a DNS lookup,
# and the FTDI serial log scanned for a reboot banner / panic / fault. Between samples the Pi browses.
# Writes a CSV + a PASS/FAIL summary.
# Operator decision 2026-11-11 (REL-08, soak failure at h 10.2 on W22): a self-heal reset whose cause is a Wi-Fi
# FIRMWARE TRAP (kernel line "[SELF-HEAL] Wi-Fi firmware HALTED") is a RECORDED EVENT, not a failure, when client
# traffic is back within FW_RECOVERY_S (180 s) and there are at most FW_EVENTS_MAX (3) in the run. Anything else —
# a panic, a watchdog reset, any other reboot, a slower recovery, a 4th trap — still fails the soak.
#   tools/diagnostics/cm5-soak.sh <owner-key-file> <serial-log> <hours> [interval-s] [mc] [pi] [out-dir]
set -u -o pipefail
KEY="${1:?owner key}"; LOG="${2:?serial log}"; HOURS="${3:?hours}"; IV="${4:-300}"
MC="${5:-https://192.168.200.146}"; PI="${6:-claude@10.200.0.4}"; OUT="${7:-$HOME/heqk-metal-logs/soak-$(date +%Y%m%d-%H%M)}"
mkdir -p "$OUT"; CSV="$OUT/soak.csv"; J=$(mktemp); trap 'rm -f "$J"' EXIT
echo "t,elapsed_s,health,seen,forwarded,dropped,detections,clients,dns_inspected,mbps,dns_ok,dns_ms,serial_events" > "$CSV"
pi() { ssh -o BatchMode=yes -o ConnectTimeout=8 "$PI" "$@"; }
login() { curl -sk -o /dev/null -m 10 --data-urlencode "token=$(cat "$KEY")" "$MC/api/login" -c "$J"; }
"$(dirname "$0")/pi-ensure-ap.sh" "$PI" || echo "soak: WARNING — the Pi is not on the CM5 AP"
IF=${SOAK_IF:-$(pi "ip -4 route get 10.99.0.1 | sed -n 's/.* dev \([^ ]*\).*/\1/p'" 2>/dev/null)}
echo "soak: ${HOURS} h, sample every ${IV} s, client interface ${IF:-?}, out $OUT"
# background browsing load on the Pi for the whole soak
SITES="wikipedia.org github.com stackoverflow.com bbc.co.uk cloudflare.com mozilla.org debian.org python.org rust-lang.org apple.com google.com youtube.com"
pi "nohup bash -c 'end=\$((SECONDS+${HOURS}*3600)); while [ \$SECONDS -lt \$end ]; do for s in $SITES; do curl --interface $IF -s -o /dev/null -m 10 -L https://\$s/; sleep \$((RANDOM%10+3)); done; done' >/dev/null 2>&1 &"
FW_RECOVERY_S=${FW_RECOVERY_S:-180}; FW_EVENTS_MAX=${FW_EVENTS_MAX:-3}; fw_events=0; fw_worst=0
t0=$(date +%s); mark=$(stat -c %s "$LOG"); prev_seen=0; reboots=0; fails=0; n=0; worst=999999
# after a firmware-trap reset: poll every 15 s until a client download through the AP works again; echo the seconds
fw_recover() {
  local s0; s0=$(date +%s)
  while [ $(( $(date +%s) - s0 )) -le "$FW_RECOVERY_S" ]; do
    local m; m=$(pi "curl --interface $IF -s -o /dev/null -m 8 -r 0-999999 -w '%{http_code}' '${HQ_SINK_URL:-http://10.100.0.1:8088/blob}'" 2>/dev/null)
    case "$m" in 200|206) echo $(( $(date +%s) - s0 )); return 0 ;; esac
    sleep 15
  done
  echo -1; return 1
}
end=$((t0 + HOURS * 3600))
# fail fast: the run is lost once more samples have failed than the PASS rule (<= n/20) allows over the whole run
expected=$(( HOURS * 3600 / (IV + 15) )); [ "$expected" -lt 1 ] && expected=1
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
  # DNS first (not right after the full-rate download, which floods the AP queue) — 3 tries of 2 s, the time
  # the answer took is logged. $dns stays the device's dns_inspected counter (it was overwritten before).
  D=$(pi "dig +time=2 +tries=3 @10.99.0.1 example.com A" 2>/dev/null)
  dnsok=$(grep -A3 "ANSWER SECTION" <<<"$D" | grep -cE "IN[[:space:]]+A[[:space:]]+[0-9.]+")
  dnsms=$(sed -n 's/^;; Query time: \([0-9]*\) msec.*/\1/p' <<<"$D" | tail -1)
  b=$(pi "curl --interface $IF -s -o /dev/null -m 20 -w '%{speed_download}' '${HQ_SINK_URL:-http://10.100.0.1:8088/blob}'" 2>/dev/null || echo 0)
  mbps=$(awk -v b="$b" 'BEGIN{printf "%.1f", b*8/1e6}')
  chunk=$(tail -c +$((mark + 1)) "$LOG" | tr -d '\r\000')
  ev=$(grep -acE "secure boot: PASS|PANIC|panic|EXCEPTION|SError|Synchronous|data abort|watchdog reset" <<<"$chunk")
  # the firmware's own console prints "data abort" inside its trap dump: count only kernel-side events
  fwtrap=$(grep -ac "\[SELF-HEAL\] Wi-Fi firmware HALTED" <<<"$chunk")
  boots=$(grep -ac "secure boot: PASS" <<<"$chunk")
  other=$(grep -avE "\[FWCON\]|\[FWTRAP\]" <<<"$chunk" | grep -acE "PANIC|panic|EXCEPTION|SError|Synchronous|watchdog reset")
  if [ "$fwtrap" -ge 1 ] && [ "$boots" -le "$fwtrap" ] && [ "$other" = 0 ]; then
    fw_events=$((fw_events + fwtrap))
    rs=$(fw_recover)
    echo "  firmware-trap self-heal #$fw_events (recorded event): client traffic back after ${rs} s (limit ${FW_RECOVERY_S} s)"
    echo "$(date -Is),fw_trap_event,$fw_events,recovery_s=$rs" >> "$OUT/events.csv"
    if [ "$rs" -lt 0 ] || [ "$fw_events" -gt "$FW_EVENTS_MAX" ]; then reboots=$((reboots + 1)); fi
    [ "$rs" -gt "$fw_worst" ] && fw_worst=$rs
    login; H=$(curl -sk -m 10 -b "$J" "$MC/api/health"); prev_seen=0; ev=0
  else
    if [ "$ok" = ok ] && [ "$seen" -lt "$prev_seen" ]; then reboots=$((reboots + 1)); fi
    [ "$ev" -gt 0 ] && reboots=$((reboots + ev))
  fi
  [ "$ok" != ok ] || [ "$dnsok" = 0 ] || awk -v m="$mbps" 'BEGIN{exit !(m<20)}' && fails=$((fails + 1))
  awk -v m="$mbps" -v w="$worst" 'BEGIN{exit !(m<w)}' && worst=$mbps
  echo "$(date -Is),$((now - t0)),$ok,$seen,$fwd,$drop,$det,$cli,$dns,$mbps,$dnsok,${dnsms:-},$ev" >> "$CSV"
  [ "$ok" = ok ] && prev_seen=$seen
  mark=$(stat -c %s "$LOG")
  printf '  %5ds %s seen=%s det=%s %s Mbps dns_ok=%s dns_ms=%s serial_events=%s\n' $((now - t0)) "$ok" "$seen" "$det" "$mbps" "$dnsok" "${dnsms:-?}" "$ev"
  if [ "$reboots" -gt 0 ] || [ "$fails" -gt $((expected / 20)) ]; then
    echo "  fail-fast: reboots/faults=$reboots, failed samples=$fails > the $((expected / 20)) allowed over ~$expected samples — stopping"
    break
  fi
  sleep "$IV"
done
med=$(awk -F, 'NR>1{print $10}' "$CSV" | sort -n | awk '{a[NR]=$1} END{print a[int((NR+1)/2)]}')
S="SOAK: ${HOURS} h, ${n} samples — reboots/faults=${reboots}, failed samples=${fails}, firmware-trap events=${fw_events} (worst recovery ${fw_worst} s, limit ${FW_RECOVERY_S} s, max ${FW_EVENTS_MAX}), throughput median ${med} Mbps (worst ${worst}) — CSV $CSV"
if [ "$reboots" -eq 0 ] && [ "$fails" -le $((n / 20)) ] && [ "$fails" -le $((expected / 20)) ]; then echo "PASS — $S" | tee "$OUT/summary"; exit 0; fi
echo "FAIL — $S" | tee "$OUT/summary"; exit 1
