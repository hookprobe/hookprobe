#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Pre-soak finding 3 on metal: does a station that vanishes WITHOUT a deauth (the Pi's Wi-Fi driver unloaded) ever leave
# the AP's station set? Watch the serial for its Leave and the heartbeat's stations= for 10 min. Needs PI_SUDO_FILE.
set -u
: "${PI_SUDO_FILE:?}"; PI=claude@10.200.0.4; S=~/heqk-metal-logs/20261108-relay-serial.log; W="${1:-600}"
pi() { ssh -o BatchMode=yes -o ConnectTimeout=8 "$PI" "$@"; }
since() { tail -c +$(($1 + 1)) "$S" | tr -d '\r\000'; }
restore() { pi 'sudo -S -p "" modprobe brcmfmac; sudo -S -p "" modprobe brcmfmac_cyw 2>/dev/null; true' < "$PI_SUDO_FILE"; sleep 20; $HOME/wt-np2/tools/diagnostics/pi-ensure-ap.sh >/dev/null 2>&1; }
trap restore EXIT
M=$(stat -c %s "$S")
echo "before: $(since $(( M > 400000 ? M - 400000 : 0 )) | grep -a '\[WIFI-HEAL\] state' | tail -1 | grep -o 'stations=[0-9]*')"
pi 'sudo -S -p "" modprobe -r brcmfmac_cyw brcmfmac; sleep 2; if ip link show wlan0 >/dev/null 2>&1; then echo "RADIO STILL UP"; else echo "Pi radio gone (driver unloaded, no deauth sent)"; fi' < "$PI_SUDO_FILE" | tee /dev/stderr | grep -q "radio gone" || { echo "GHOST: INVALID — the Pi radio did not go away"; exit 2; }
M0=$(stat -c %s "$S"); T0=$(date +%s)
while [ $(( $(date +%s) - T0 )) -lt "$W" ]; do sleep 30
  echo "  t=$(( $(date +%s) - T0 ))s $(since "$M0" | grep -a '\[WIFI-HEAL\] state' | tail -1 | grep -o 'stations=[0-9]*')  leaves=$(since "$M0" | grep -ac 'left (deauth/disassoc)')"
done
echo "--- AP-side lines about the station since the radio vanished:"
since "$M0" | grep -a "b6:88\|left (deauth\|firmware event\|\[P11-AP3\] station" | head -10 | cut -c1-200
st=$(since "$M0" | grep -a '\[WIFI-HEAL\] state' | tail -1 | grep -o 'stations=[0-9]*')
lv=$(since "$M0" | grep -ac 'left (deauth/disassoc)')
echo "GHOST: after ${W}s with the station gone: ${st} leaves=${lv} -> $([ "$lv" = 0 ] && [ "$st" != "stations=0" ] && echo 'GHOST (station kept)' || echo 'cleaned up')"
