#!/usr/bin/env bash
# cm5-wpa3-probe-check — WPA3-SAE on the AP: what does THIS firmware do? (bench image built with `--features wpa3probe`)
#   1. the boot's `[WPA3-PROBE] wpa_auth=SAE … sae_password … event_msgs_ext …` line (what the firmware accepted);
#   2. the bench Pi scans with its USB adapter (wlan1, rtw88 on mac80211: SAE in software) — does the beacon say WPA3?
#   3. it tries a WPA3-SAE join (PMF required) with the AP's passphrase (taken from the Pi's saved profile, never
#      printed), through a temporary NetworkManager profile that is deleted afterwards;
#   4. every firmware event the AP logged during the attempt is printed (type / status / auth_type / payload head):
#      the evidence for "firmware does SAE", "firmware hands SAE to the host", or "not supported".
# Exit 0 = the probe RAN (verdict is in the output); it does not judge.
#   tools/diagnostics/cm5-wpa3-probe-check.sh <serial-log> [pi]          (needs PI_SUDO_FILE)
set -u -o pipefail
LOG="${1:?serial log}"; PI="${2:-claude@10.200.0.4}"; PS="${PI_SUDO_FILE:?PI_SUDO_FILE}"
pi() { ssh -o BatchMode=yes -o ConnectTimeout=8 "$PI" "$@"; }
psudo() { pi "sudo -S -p '' $*" < "$PS"; }
echo "== firmware configuration at AP bring-up"
tr -d '\r\000' < "$LOG" | grep -a "\[WPA3-PROBE\] wpa_auth" | tail -1
PROF=$(pi "nmcli -t -f NAME con show | grep -i hookprobe | head -1")
SSID=$(psudo "nmcli -s -g 802-11-wireless.ssid con show '$PROF'")
PSK=$(psudo "nmcli -s -g 802-11-wireless-security.psk con show '$PROF'")
[ -n "$SSID" ] && [ -n "$PSK" ] || { echo "WPA3-PROBE: could not read the AP SSID / passphrase from the Pi profile '$PROF'"; exit 1; }
echo "== scan from wlan1 (SSID $SSID)"
psudo "nmcli dev wifi rescan ifname wlan1" >/dev/null 2>&1; sleep 6
pi "nmcli -f SSID,SECURITY,CHAN dev wifi list ifname wlan1" | grep -F "$SSID" | head -2
psudo "/sbin/iw dev wlan1 scan ssid '$SSID'" 2>/dev/null | grep -aE "RSN|Authentication suites|Capabilities: .*MFP|Group mgmt" | head -6
mark=$(stat -c %s "$LOG")
echo "== WPA3-SAE join attempt on wlan1 (PMF required)"
psudo "nmcli con delete hq-wpa3-probe" >/dev/null 2>&1
psudo "nmcli con add type wifi ifname wlan1 con-name hq-wpa3-probe ssid '$SSID' wifi-sec.key-mgmt sae wifi-sec.psk '$PSK' wifi-sec.pmf required ipv4.method auto ipv6.method ignore connection.autoconnect no" >/dev/null 2>&1
R=$(psudo "timeout 60 nmcli -w 50 con up hq-wpa3-probe" 2>&1 | tail -2)
echo "  nmcli: $R"
ST=$(pi "nmcli -t -f GENERAL.STATE dev show wlan1" 2>/dev/null)
echo "  wlan1 state: $ST"
pi "journalctl -u wpa_supplicant -u NetworkManager --since '-2 min' --no-pager 2>/dev/null | grep -iE 'sae|auth|assoc|reason|status' | tail -12" | cut -c1-200 | sed 's/^/  pi: /'
psudo "nmcli con down hq-wpa3-probe" >/dev/null 2>&1; psudo "nmcli con delete hq-wpa3-probe" >/dev/null 2>&1
sleep 2
echo "== firmware events on the AP during the attempt"
tail -c +$((mark + 1)) "$LOG" | tr -d '\r\000' | grep -a "\[WPA3-PROBE\] ev#" | head -60
echo "== event types seen (type:count)"
tail -c +$((mark + 1)) "$LOG" | tr -d '\r\000' | grep -ao "\[WPA3-PROBE\] ev#[0-9]* type=[0-9]*" | sed 's/.*type=//' | sort -n | uniq -c | tr '\n' ' '; echo
echo "WPA3-PROBE: RAN"
