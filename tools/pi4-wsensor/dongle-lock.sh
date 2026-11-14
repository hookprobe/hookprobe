#!/usr/bin/env bash
# Time-share lock for the Pi 4 USB Wi-Fi dongle, shared between the heqk metal bench
# (second WPA3-SAE station for REL-08) and the wireless monitor sensor.
# Protocol agreed with the heqk session 2026-11-14:
#   /run/lock/hp-dongle.owner = "heqk <ts>" | "monitor <ts>" | absent
#   - monitor takes the dongle only when the lock is absent or already "monitor"
#   - on release: managed mode, NetworkManager-managed, same driver, NM profiles untouched
#   - release within 1 minute when heqk asks
# Usage (on the Pi):  dongle-lock.sh status | acquire | release
set -euo pipefail
LOCK=/run/lock/hp-dongle.owner
STATE=/run/lock/hp-dongle.monitor-state   # what we found, so release restores it exactly
cmd=${1:-status}

dongle_if() {  # the USB Wi-Fi netdev, by bus identity, never by wlanN name
  for i in /sys/class/net/*; do
    [ -e "$i/phy80211" ] || continue
    case "$(readlink -f "$i/device")" in *usb*) echo "${i##*/}"; return 0;; esac
  done
  return 1
}
iftype() { iw dev "$1" info | awk '/type/{print $2}'; }
nmstate() { nmcli -t -f DEVICE,STATE dev 2>/dev/null | awk -F: -v d="$1" '$1==d{print $2}'; }
drvof() { basename "$(readlink -f "/sys/class/net/$1/device/driver")"; }

case "$cmd" in
status)
  echo "lock: $(cat "$LOCK" 2>/dev/null || echo absent)"
  d=$(dongle_if || echo none); echo "dongle: $d"
  if [ "$d" != none ]; then echo "type=$(iftype "$d") drv=$(drvof "$d") nm=$(nmstate "$d")"; fi ;;
acquire)
  owner=$(awk '{print $1}' "$LOCK" 2>/dev/null || true)
  if [ -n "$owner" ] && [ "$owner" != monitor ]; then echo "REFUSED: lock held by '$owner'"; exit 3; fi
  d=$(dongle_if) || { echo "no USB dongle present"; exit 4; }
  echo "monitor $(date -Is)" | sudo tee "$LOCK" >/dev/null
  if [ ! -f "$STATE" ]; then
    printf 'if=%s\ndrv=%s\nnm=%s\nmac=%s\n' "$d" "$(drvof "$d")" "$(nmstate "$d")" \
      "$(cat "/sys/class/net/$d/address")" | sudo tee "$STATE" >/dev/null
  fi
  sudo nmcli dev set "$d" managed no 2>/dev/null || true
  sudo ip link set "$d" down
  sudo iw dev "$d" set type monitor
  sudo ip link set "$d" up
  echo "acquired $d -> type=$(iftype "$d")" ;;
release)
  [ -f "$STATE" ] || { echo "nothing to release"; exit 0; }
  R_if=$(awk -F= '$1=="if"{print $2}' "$STATE"); R_drv=$(awk -F= '$1=="drv"{print $2}' "$STATE")
  d=$(dongle_if || echo "$R_if")
  sudo pkill -f "(tcpdump|dumpcap|airodump-ng|kismet).*$d" 2>/dev/null || true
  sudo ip link set "$d" down
  sudo iw dev "$d" set type managed
  sudo ip link set "$d" up
  sudo nmcli dev set "$d" managed yes 2>/dev/null || true
  sleep 3
  now=$(nmstate "$d"); drv=$(drvof "$d"); t=$(iftype "$d"); ok=1
  [ "$drv" = "$R_drv" ] || ok=0
  case "$now" in unmanaged|unavailable|"") ok=0;; esac
  [ "$t" = managed ] || ok=0
  if [ "$ok" = 1 ]; then
    sudo rm -f "$STATE"
    if [ "$(awk '{print $1}' "$LOCK" 2>/dev/null)" = monitor ]; then sudo rm -f "$LOCK"; fi
    echo "released $d: type=$t nm=$now drv=$drv"
  else
    echo "RELEASE INCOMPLETE: if=$d type=$t drv=$drv (was $R_drv) nm=$now -- lock kept, notify heqk"; exit 5
  fi ;;
*) echo "usage: $0 status|acquire|release"; exit 2 ;;
esac
