#!/usr/bin/env bash
# M0 monitor-mode evidence test (RECEIVE-ONLY). Runs ON the Pi with sudo.
#  - takes the dongle via dongle-lock.sh (refuses if heqk holds it)
#  - tunes it to a fixed channel, captures radiotap frames for N seconds (no TX, no injection)
#  - samples the management radio (built-in) link every 5 s to prove it stays connected
#  - releases the dongle and verifies managed + NetworkManager-managed + same driver
# Usage: m0-monitor-test.sh <freq_mhz> [width center_mhz] [seconds]
#   e.g. m0-monitor-test.sh 5180 80 5210 60
set -euo pipefail
export PATH=$PATH:/usr/sbin:/sbin
HERE=$(cd "$(dirname "$0")" && pwd)
FREQ=${1:?freq}; WIDTH=${2:-20}; CENTER=${3:-}; SECS=${4:-60}
OUT=/var/tmp/pi4-wsensor; sudo mkdir -p "$OUT"; sudo chmod 1777 "$OUT"
TS=$(date +%Y%m%dT%H%M%S); PCAP=$OUT/m0-$FREQ-$TS.pcap

mgmt_if() {  # built-in radio = non-USB wifi netdev with an SSID
  for i in /sys/class/net/*; do [ -e "$i/phy80211" ] || continue
    case "$(readlink -f "$i/device")" in *usb*) ;; *) echo "${i##*/}"; return;; esac; done; }
M=$(mgmt_if)
cleanup() { "$HERE/dongle-lock.sh" release || true; }
trap cleanup EXIT

echo "## before"; iw dev "$M" link | grep -E 'Connected|SSID|freq|signal'
"$HERE/dongle-lock.sh" acquire
D=$(awk -F= '$1=="if"{print $2}' /run/lock/hp-dongle.monitor-state)
if [ "$WIDTH" = 20 ]; then sudo iw dev "$D" set freq "$FREQ"; else sudo iw dev "$D" set freq "$FREQ" "$WIDTH" "$CENTER"; fi
iw dev "$D" info | grep -E 'type|channel'
rx0=$(cat /sys/class/net/"$D"/statistics/rx_packets); rxd0=$(cat /sys/class/net/"$D"/statistics/rx_dropped)
sudo timeout "$SECS" tcpdump -i "$D" -y IEEE802_11_RADIO -s 256 -w "$PCAP" -q 2>"$OUT/tcpdump-$TS.err" &
TP=$!
for ((t=0; t<SECS; t+=5)); do sleep 5
  s=$(iw dev "$M" link | awk '/SSID/{print $2} /signal/{print $2}' | paste -sd' ')
  echo "t=$((t+5))s mgmt[$M]=${s:-DISCONNECTED} ping_gw=$(ping -c1 -W1 -I "$M" "$(ip route show dev "$M" default | awk '{print $3; exit}')" >/dev/null 2>&1 && echo ok || echo FAIL)"
done
wait $TP || true
rx1=$(cat /sys/class/net/"$D"/statistics/rx_packets); rxd1=$(cat /sys/class/net/"$D"/statistics/rx_dropped)
echo "## tcpdump"; cat "$OUT/tcpdump-$TS.err"
echo "netdev rx_packets=$((rx1-rx0)) rx_dropped=$((rxd1-rxd0))"
echo "pcap=$PCAP size=$(stat -c %s "$PCAP")"
trap - EXIT; "$HERE/dongle-lock.sh" release
echo "## after"; iw dev "$M" link | grep -E 'Connected|SSID|freq|signal'
"$HERE/dongle-lock.sh" status
