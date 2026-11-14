#!/usr/bin/env bash
# DFS evidence capture (RECEIVE-ONLY). On heqk's signal, retune the monitor dongle to a pinned
# DFS channel and measure whether/when an AP's beacons appear there — a passive view of the AP's
# DFS channel-availability-check (CAC): a compliant AP must stay silent on a DFS channel until its
# CAC completes (60 s on ch52; up to 600 s on weather-radar channels 120-128), so time-to-first-
# beacon is a lower bound on when the AP started beaconing.
#
# Usage (on the Pi):  dfs-watch.sh <freq> <center> <label> [max_s] [bssid]
#   dfs-watch.sh 5260 5290 ch52 120        # ch52 VHT80, watch up to 120 s
#   dfs-watch.sh 5500 5530 ch100 660       # ch100 VHT80, watch up to 660 s
# Does NOT transmit. Acquires via the time-share lock; releases on exit.
set -uo pipefail
export PATH=$PATH:/usr/sbin:/sbin
SUDO=sudo; [ "$(id -u)" = 0 ] && SUDO=""
HERE=$(cd "$(dirname "$0")" && pwd)
FREQ=${1:?freq}; CENTER=${2:?center}; LABEL=${3:?label}; MAX=${4:-120}
BSSID=${5:-76:0d:02:f8:d2:da}   # CM5 AP HookProbe-Setup-R3Q1
OUT=/var/lib/pi4-wsensor/dfs; sudo mkdir -p "$OUT" 2>/dev/null || mkdir -p "$OUT"
TS=$(date +%Y%m%dT%H%M%S); PCAP="$OUT/dfs-$LABEL-$TS.pcap"

cleanup() { "$HERE/dongle-lock.sh" release >/dev/null 2>&1 || true; }
trap cleanup EXIT

"$HERE/dongle-lock.sh" acquire >/dev/null || { echo "cannot acquire dongle (lock held?)"; exit 3; }
D=$(awk -F= '$1=="if"{print $2}' /run/lock/hp-dongle.monitor-state)
# radar channels often refuse an 80 MHz set in monitor; beacons ride the primary 20 MHz, so fall back.
# the set can also EPERM transiently right after the link comes up, so retry the 20 MHz set.
sleep 1
$SUDO iw dev "$D" set freq 5180 2>/dev/null || true   # non-DFS anchor: rtw88 refuses a cold jump to a DFS channel
sleep 1; width=80
if ! $SUDO iw dev "$D" set freq "$FREQ" 80 "$CENTER" 2>/dev/null; then
  width=20
  for try in 1 2 3 4 5 6; do
    if $SUDO iw dev "$D" set freq "$FREQ" 2>/dev/null; then break; fi
    [ "$try" = 6 ] && { echo "retune failed (80 and 20 MHz) on $FREQ after 6 tries"; exit 4; }
    sleep 1
  done
  echo "note: 80 MHz refused on $LABEL (DFS); capturing primary 20 MHz on $FREQ"
fi
got=$(iw dev "$D" info | awk '/channel/{print $2}')
echo "watching $LABEL ($FREQ/${width}, AP pinned 80 MHz centre $CENTER) BSSID $BSSID up to ${MAX}s on $D (tuned ch$got)"

# live capture; count all on-channel beacons and the first from BSSID. frame.time_relative is
# seconds since capture start, i.e. a lower bound on when the AP began beaconing here.
first=""; total_any=0; total_bssid=0
while read -r trel _freq bssid_f; do
  [ -z "$trel" ] && continue
  total_any=$((total_any+1))
  if [ "$bssid_f" = "$BSSID" ]; then
    total_bssid=$((total_bssid+1))
    [ -z "$first" ] && { first=$trel; echo "FIRST $BSSID beacon at t=${first}s (rel to capture start)"; }
  fi
done < <(sudo timeout "$MAX" tshark -i "$D" -l -n -Y "wlan.fc.type_subtype==8" \
           -T fields -E separator=' ' -e frame.time_relative -e radiotap.channel.freq -e wlan.bssid \
           -w "$PCAP" -P 2>/dev/null; true)

echo "RESULT $LABEL: bssid_beacons=$total_bssid any_beacons=$total_any first=${first:-NONE} window=${MAX}s pcap=$PCAP"
if [ -z "$first" ]; then
  echo "  -> no $BSSID beacons on $LABEL within ${MAX}s: AP silent (CAC not complete / radar / not pinned here)"
else
  echo "  -> AP beaconing on $LABEL; first beacon ${first}s into the window (lower bound on CAC completion)"
fi
