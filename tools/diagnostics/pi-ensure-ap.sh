#!/usr/bin/env bash
# pi-ensure-ap — make sure the bench Pi is a Wi-Fi client of the CM5 AP (10.99.0.1). NetworkManager stops
# retrying after a few failed attempts while the CM5 reboots/reflashes, leaving both adapters
# "disconnected" (seen 2026-11-10: every Wi-Fi check failed with a healthy AP). Re-activates every saved
# HookProbe profile until a default route via 10.99.0.1 exists.
#   tools/diagnostics/pi-ensure-ap.sh [pi] [sudo-pass-file]     (default claude@10.200.0.4, $PI_SUDO_FILE)
set -u
PI="${1:-claude@10.200.0.4}"; SP="${2:-${PI_SUDO_FILE:-${SUDO_PASS_FILE:-}}}"
pi() { ssh -o BatchMode=yes -o ConnectTimeout=8 "$PI" "$@"; }
for i in $(seq 1 6); do
  if pi "ip route | grep -q '^default via 10.99.0.1'"; then echo "pi-ensure-ap: joined (try $i)"; exit 0; fi
  [ -n "$SP" ] && [ -f "$SP" ] || { echo "pi-ensure-ap: not joined and no sudo password file"; exit 1; }
  for c in $(pi "nmcli -t -f NAME con show | grep -i hookprobe"); do
    # pin the built-in radio (brcmfmac, wlan0): the USB rtw88 dongle on wlan1 caps throughput at ~40 Mbps,
    # so a run that lands there is not comparable (2026-11-10)
    pi "sudo -S -p '' nmcli con up '$c' ifname wlan0 >/dev/null 2>&1 || sudo -S -p '' nmcli con up '$c' >/dev/null 2>&1" < "$SP"
  done
  sleep 10
done
echo "pi-ensure-ap: the Pi did not join the CM5 AP"; exit 1
