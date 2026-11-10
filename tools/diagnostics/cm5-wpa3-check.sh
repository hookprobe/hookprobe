#!/usr/bin/env bash
# cm5-wpa3-check — WPA3-SAE on the AP on metal (release gate NET-03; image built with `--features wpa3`).
#   1. the boot says which security the AP runs ([WPA3] AP security …, IGTK installed);
#   2. the bench Pi's USB adapter (wlan1: rtw88/mac80211, SAE in software) scans: the beacon RSN (AKMs, MFP bits);
#   3. it joins with key-mgmt SAE and PMF REQUIRED through a temporary NetworkManager profile (passphrase taken
#      from the Pi's saved AP profile, never printed), gets a DHCP lease from the AP and pings the gateway;
#   4. the AP side: the SAE exchange ([WPA3] SAE … -> Accepted), the mgmt_frame TX status, the 4-way with akm=SAE.
#   wpa_supplicant runs at debug level for the attempt (D-Bus DebugLevel) so a refused M3 shows why.
#   tools/diagnostics/cm5-wpa3-check.sh <serial-log> [pi]          (needs PI_SUDO_FILE)
set -u -o pipefail
LOG="${1:?serial log}"; PI="${2:-claude@10.200.0.4}"; PS="${PI_SUDO_FILE:?PI_SUDO_FILE}"
ok=0; n=0
chk() { n=$((n + 1)); if [ "$1" = 0 ]; then echo "ok  $2"; ok=$((ok + 1)); else echo "BAD $2"; fi; }
pi() { ssh -o BatchMode=yes -o ConnectTimeout=8 "$PI" "$@"; }
psudo() { pi "sudo -S -p '' $*" < "$PS"; }
dbg() { psudo "busctl set-property fi.w1.wpa_supplicant1 /fi/w1/wpa_supplicant1 fi.w1.wpa_supplicant1 DebugLevel s $1" >/dev/null 2>&1; }
cleanup() { psudo "nmcli con down hq-wpa3" >/dev/null 2>&1; psudo "nmcli con delete hq-wpa3" >/dev/null 2>&1; dbg info; }
trap cleanup EXIT
B=$(tr -d '\r\000' < "$LOG" | grep -a "\[WPA3\] AP security" | tail -1); echo "  $B" | cut -c1-220
grep -q "set=true mfp .* set=true .*armed=true" <<<"$B"; chk $? "the AP runs a WPA3 mode (wpa_auth + mfp set, SAE events armed)"
PROF=$(pi "nmcli -t -f NAME con show | grep -i hookprobe | head -1")
SSID=$(psudo "nmcli -s -g 802-11-wireless.ssid con show '$PROF'")
PSK=$(psudo "nmcli -s -g 802-11-wireless-security.psk con show '$PROF'")
[ -n "$SSID" ] && [ -n "$PSK" ] || { echo "WPA3: could not read the AP SSID / passphrase from the Pi profile '$PROF'"; exit 1; }
psudo "nmcli dev wifi rescan ifname wlan1" >/dev/null 2>&1; sleep 6
pi "nmcli -f SSID,SECURITY,CHAN dev wifi list ifname wlan1" | grep -F "$SSID" | head -2 | sed 's/^/  scan: /'
psudo "iw dev wlan1 scan dump" 2>/dev/null | awk -v s="$SSID" '/^BSS /{b=$0} /SSID: /{x=($2==s)} x&&/RSN:|Authentication suites|Capabilities: .*(PTKSA|MFP)|Group mgmt/' | head -6 | sed 's/^/  rsn: /'
dbg debug
mark=$(stat -c %s "$LOG"); t0=$(date '+%Y-%m-%d %H:%M:%S')
psudo "nmcli con delete hq-wpa3" >/dev/null 2>&1
psudo "nmcli con add type wifi ifname wlan1 con-name hq-wpa3 ssid '$SSID' wifi-sec.key-mgmt sae wifi-sec.psk '$PSK' wifi-sec.pmf required ipv4.method auto ipv4.never-default yes ipv6.method ignore connection.autoconnect no" >/dev/null 2>&1
R=$(psudo "timeout 70 nmcli -w 60 con up hq-wpa3" 2>&1 | tail -1); echo "  nmcli: $R"
ST=$(pi "nmcli -t -f GENERAL.STATE dev show wlan1" 2>/dev/null); echo "  wlan1: $ST"
grep -q "100 (connected)" <<<"$ST"; chk $? "the Pi joined over WPA3-SAE with PMF required"
IP=$(pi "ip -4 -o addr show wlan1 | awk '{print \$4}'"); echo "  wlan1 address: $IP"
grep -q "^10\.99\.0\." <<<"$IP"; chk $? "DHCP lease from the AP over the SAE-keyed link"
pi "ping -c 3 -W 2 -I wlan1 10.99.0.1" >/dev/null 2>&1; chk $? "the gateway answers over the SAE link (unicast data keyed)"
psudo "journalctl -u wpa_supplicant --since '$t0' --no-pager" 2>/dev/null | grep -aiE "SAE:|WPA:.*(3/4|IE|IGTK|MFP|key)|PMF|reason|CTRL-EVENT" | grep -v "hexdump" | tail -25 | cut -c1-200 | sed 's/^/  pi: /'
sleep 2
T=$(tail -c +$((mark + 1)) "$LOG" | tr -d '\r\000')
grep -a "\[WPA3\]\|akm=SAE\|akm=PSK" <<<"$T" | head -30 | cut -c1-220 | sed 's/^/  ap: /'
grep -aq "\[WPA3\] SAE .* -> Accepted" <<<"$T"; chk $? "the AP accepted the SAE exchange (commit + confirm answered on the host)"
grep -aq "akm=SAE .*m4_mic=true .*authorized=true" <<<"$T"; chk $? "the 4-way ran with the SAE PMK (AKM 8) and the station is authorized"
echo "WPA3: $([ $ok = $n ] && echo PASS || echo FAIL) ($ok/$n)"
[ $ok = $n ]
