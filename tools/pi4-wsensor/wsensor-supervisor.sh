#!/usr/bin/env bash
# Pi 4 wireless sensor supervisor (M1). RECEIVE-ONLY: monitor mode + dumpcap, never transmits.
#
# Every TICK seconds:
#   lock = heqk  -> make sure we hold nothing, health coverage=off (reason heqk_bench)
#   otherwise    -> hold the dongle in monitor mode on the configured channel, keep two dumpcap
#                   rings alive (mgmt full-length, data header-only), extract closed ring files to
#                   JSONL, bounce the interface if frames stop (stall), write health.json
# Never claims coverage it does not have: coverage=on only while monitor+dumpcap+frames flowing.
set -uo pipefail
export PATH=$PATH:/usr/sbin:/sbin
HERE=$(cd "$(dirname "$0")" && pwd)
CONF=${WSENSOR_CONF:-/etc/pi4-wsensor/wsensor.conf}
# shellcheck source=/dev/null
[ -f "$CONF" ] && . "$CONF"
FREQ=${FREQ:-5180}; WIDTH=${WIDTH:-80}; CENTER=${CENTER:-5210}
DATA_DIR=${DATA_DIR:-/var/lib/pi4-wsensor}
RING_MB=${RING_MB:-10}            # per ring file
MGMT_FILES=${MGMT_FILES:-50}      # mgmt ring: 50 x 10 MB = 500 MB cap
DATA_FILES=${DATA_FILES:-20}      # data ring: 20 x 10 MB = 200 MB cap
ROTATE_S=${ROTATE_S:-60}          # close a ring file at least every minute (extract latency)
DATA_SNAP=${DATA_SNAP:-128}       # radiotap + 802.11 header; no payload
EVENTS_KEEP_DAYS=${EVENTS_KEEP_DAYS:-7}
EVENTS_MAX_MB=${EVENTS_MAX_MB:-500}
STALL_S=${STALL_S:-60}
TICK=${TICK:-10}
LOCK=/run/lock/hp-dongle.owner
STATE=/run/lock/hp-dongle.monitor-state
SENSOR=$(hostname)

mkdir -p "$DATA_DIR"/{pcap/mgmt,pcap/data,events,run}
HEALTH=$DATA_DIR/health.json
log() { echo "$(date -Is) $*"; }

MGMT_PID=""; DATA_PID=""; HOLD=0; DONGLE=""
last_rx=0; last_rx_change=$(date +%s); stalls=0; bounces=0; yields=0
started=$(date +%s); covered_s=0; last_tick=$(date +%s)

owner() { awk '{print $1}' "$LOCK" 2>/dev/null; }
rx() { cat "/sys/class/net/$DONGLE/statistics/rx_packets" 2>/dev/null || echo 0; }
rxd() { cat "/sys/class/net/$DONGLE/statistics/rx_dropped" 2>/dev/null || echo 0; }
alive() { [ -n "$1" ] && kill -0 "$1" 2>/dev/null; }

stop_capture() {
  for p in $MGMT_PID $DATA_PID; do kill "$p" 2>/dev/null; done
  for p in $MGMT_PID $DATA_PID; do wait "$p" 2>/dev/null; done
  MGMT_PID=""; DATA_PID=""
}

release() {
  stop_capture
  if [ "$HOLD" = 1 ]; then
    if "$HERE/dongle-lock.sh" release; then HOLD=0; log "released dongle"
    else log "RELEASE INCOMPLETE — lock kept; operator/heqk must check"; fi
  fi
}

acquire() {
  "$HERE/dongle-lock.sh" acquire >/dev/null || return 1
  HOLD=1
  DONGLE=$(awk -F= '$1=="if"{print $2}' "$STATE")
  if [ "$WIDTH" = 20 ]; then iw dev "$DONGLE" set freq "$FREQ"
  else iw dev "$DONGLE" set freq "$FREQ" "$WIDTH" "$CENTER"; fi || { log "tune failed"; return 1; }
  last_rx=$(rx); last_rx_change=$(date +%s)
  log "acquired $DONGLE @ $FREQ/$WIDTH"
}

start_capture() {
  if ! alive "$MGMT_PID"; then
    dumpcap -q -i "$DONGLE" -y IEEE802_11_RADIO -f "type mgt" -s 0 \
      -b filesize:$((RING_MB*1024)) -b files:"$MGMT_FILES" -b duration:"$ROTATE_S" \
      -w "$DATA_DIR/pcap/mgmt/mgmt.pcapng" 2>>"$DATA_DIR/run/dumpcap.err" &
    MGMT_PID=$!
  fi
  if ! alive "$DATA_PID"; then
    dumpcap -q -i "$DONGLE" -y IEEE802_11_RADIO -f "type data" -s "$DATA_SNAP" \
      -b filesize:$((RING_MB*1024)) -b files:"$DATA_FILES" -b duration:"$ROTATE_S" \
      -w "$DATA_DIR/pcap/data/data.pcapng" 2>>"$DATA_DIR/run/dumpcap.err" &
    DATA_PID=$!
  fi
}

extract_closed() {
  # every ring file except the newest (still being written) gets extracted once
  for ring in mgmt data; do
    mapfile -t files < <(ls -1t "$DATA_DIR/pcap/$ring"/*.pcapng 2>/dev/null)
    for f in "${files[@]:1}"; do
      out="$DATA_DIR/events/$(basename "${f%.pcapng}").jsonl"
      [ -e "$out" ] && continue
      nice -n 10 python3 "$HERE/wsensor_extract.py" --pcap "$f" --out "$out" --sensor "$SENSOR" \
        --salt-file "$DATA_DIR/ssid.salt" >/dev/null 2>>"$DATA_DIR/run/extract.err" || true
    done
  done
  # retention: age, then size cap
  find "$DATA_DIR/events" -name '*.jsonl' -mtime +"$EVENTS_KEEP_DAYS" -delete
  while [ "$(du -sm "$DATA_DIR/events" | cut -f1)" -gt "$EVENTS_MAX_MB" ]; do
    oldest=$(ls -1tr "$DATA_DIR/events"/*.jsonl 2>/dev/null | head -1); [ -n "$oldest" ] || break; rm -f "$oldest"
  done
  # drop events for ring files dumpcap already recycled? no — events outlive pcaps by design
}

write_health() {
  local coverage=$1 reason=$2 now rxn rate
  now=$(date +%s)
  rxn=$(rx); rate=0
  [ "$coverage" = on ] && covered_s=$((covered_s + now - last_tick))
  if [ "$HOLD" = 1 ]; then rate=$(( (rxn - ${prev_rx:-$rxn}) / (now - last_tick > 0 ? now - last_tick : 1) )); fi
  prev_rx=$rxn; last_tick=$now
  cat >"$HEALTH.tmp" <<EOF
{"ts":"$(date -Is)","sensor":"$SENSOR","coverage":"$coverage","reason":"$reason",
 "lock_owner":"$(owner || true)","dongle":"${DONGLE:-}","freq_mhz":$FREQ,"width_mhz":$WIDTH,
 "mode":"fixed","rx_packets":$rxn,"rx_dropped":$(rxd),"rx_pps":$rate,
 "last_frame_age_s":$((now - last_rx_change)),"dumpcap_mgmt":$(alive "$MGMT_PID" && echo true || echo false),
 "dumpcap_data":$(alive "$DATA_PID" && echo true || echo false),"stalls":$stalls,"bounces":$bounces,
 "yields":$yields,"uptime_s":$((now - started)),"covered_s":$covered_s,
 "coverage_ratio":$(awk -v c=$covered_s -v u=$((now - started)) 'BEGIN{printf "%.3f", (u>0?c/u:0)}'),
 "temp_c":$(awk '{printf "%.1f",$1/1000}' /sys/class/thermal/thermal_zone0/temp),
 "disk_used_pct":$(df --output=pcent "$DATA_DIR" | tail -1 | tr -dc 0-9),
 "limits":"single time-shared 1x1 radio; fixed channel only; no control frames or noise floor (rtw88); encrypted payloads not visible"}
EOF
  mv "$HEALTH.tmp" "$HEALTH"
}

trap 'log "stopping"; release; write_health off stopped; exit 0' TERM INT
log "start: freq=$FREQ width=$WIDTH data=$DATA_DIR"
while :; do
  o=$(owner || true)
  if [ -n "$o" ] && [ "$o" != monitor ]; then
    if [ "$HOLD" = 1 ]; then log "lock taken by '$o' — yielding"; yields=$((yields+1)); release; fi
    write_health off "lock_held_by_$o"
  elif [ ! -e /sys/class/net/"${DONGLE:-__none__}" ] && [ "$HOLD" = 1 ]; then
    log "dongle vanished (USB removal?)"; stop_capture; HOLD=0
    rm -f "$STATE"; [ "$(owner)" = monitor ] && rm -f "$LOCK"
    write_health off dongle_missing
  else
    if [ "$HOLD" = 0 ]; then
      if ! acquire; then write_health off acquire_failed; sleep "$TICK"; continue; fi
    fi
    start_capture
    now=$(date +%s); cur=$(rx)
    if [ "$cur" != "$last_rx" ]; then last_rx=$cur; last_rx_change=$now; fi
    if [ $((now - last_rx_change)) -ge "$STALL_S" ]; then
      log "stall: no frames for $((now - last_rx_change))s — bouncing $DONGLE"
      stalls=$((stalls+1)); bounces=$((bounces+1)); release; sleep 2; continue
    fi
    extract_closed
    if alive "$MGMT_PID" && [ $((now - last_rx_change)) -lt "$STALL_S" ]; then write_health on capturing
    else write_health off capture_down; fi
  fi
  sleep "$TICK"
done
