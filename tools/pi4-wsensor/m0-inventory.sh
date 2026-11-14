#!/usr/bin/env bash
# M0 read-only hardware/visibility inventory for the Pi 4 wireless sensor bench.
# Runs ON the Pi (pipe it over ONE ssh session). Changes nothing: no mode switch,
# no driver load, no NetworkManager change, no frames transmitted.
# Usage (from the dev host):  ssh andrei@PI 'bash -s' < m0-inventory.sh > m0-$(date +%F).txt
set -u
S() { printf '\n===== %s =====\n' "$*"; }
SUDO=""; sudo -n true 2>/dev/null && SUDO="sudo -n"

S "time"; date -Is
S "model"; tr -d '\0' </proc/device-tree/model 2>/dev/null; echo
grep -E '^(Revision|Model)' /proc/cpuinfo
S "os"; head -5 /etc/os-release; uname -a
S "cpu/mem"; nproc; free -m
S "storage"; lsblk -o NAME,SIZE,TYPE,TRAN,MOUNTPOINT; df -h / /var 2>/dev/null
S "thermal"; vcgencmd measure_temp 2>/dev/null || awk '{print $1/1000 " C"}' /sys/class/thermal/thermal_zone0/temp
vcgencmd get_throttled 2>/dev/null || true
S "lsusb"; lsusb; S "lsusb -t"; lsusb -t
S "netdev -> driver/bus (identity, not name)"
for i in /sys/class/net/*; do n=${i##*/}; [ "$n" = lo ] && continue
  dev=$(readlink -f "$i/device" 2>/dev/null); drv=$(basename "$(readlink -f "$i/device/driver" 2>/dev/null)")
  phy=$(basename "$(readlink -f "$i/phy80211" 2>/dev/null)" 2>/dev/null)
  bus=other; case "$dev" in *usb*) bus=usb;; *mmc*) bus=sdio;; *platform*) bus=platform;; esac
  usbid=""
  if [ "$bus" = usb ]; then p=$dev; while [ "$p" != / ] && [ ! -f "$p/idVendor" ]; do p=$(dirname "$p"); done
    [ -f "$p/idVendor" ] && usbid="$(cat "$p/idVendor"):$(cat "$p/idProduct") $(cat "$p/manufacturer" 2>/dev/null) $(cat "$p/product" 2>/dev/null) speed=$(cat "$p/speed" 2>/dev/null)M"
  fi
  echo "$n mac=$(cat "$i/address") drv=$drv bus=$bus phy=${phy:-none} oper=$(cat "$i/operstate") $usbid"
done
S "iw dev"; iw dev
S "ip"; ip -br link; ip -br addr; ip route; ip -6 route 2>/dev/null | head
S "rfkill"; rfkill 2>/dev/null || $SUDO rfkill
S "ethtool -i"; for i in /sys/class/net/*; do n=${i##*/}; [ "$n" = lo ] && continue; echo "-- $n"; ethtool -i "$n" 2>&1 | head -4; done
S "modules"; lsmod | grep -iE 'brcm|88xx|rtl|rtw|mt7|ath|cfg80211|mac80211'
modinfo 88XXau 2>/dev/null | grep -E '^(filename|version|srcversion|vermagic)'
S "network managers"; for u in NetworkManager wpa_supplicant systemd-networkd iwd hostapd; do echo "$u: $(systemctl is-active $u 2>&1)"; done
if command -v nmcli >/dev/null; then nmcli -t -f DEVICE,TYPE,STATE,CONNECTION dev; nmcli -t -f NAME,TYPE,DEVICE con show; fi
S "dongle lock"; cat /run/lock/hp-dongle.owner 2>/dev/null || echo "(absent)"
S "dmesg wifi/usb"; ($SUDO dmesg 2>/dev/null || dmesg 2>/dev/null) | grep -iE 'brcmf|88xx|rtl8|rtw|usb [0-9-]+:.*(new|Product|Manufacturer)|cfg80211|firmware|regdom' | tail -60
S "regdom"; iw reg get
S "link (managed)"; for w in $(iw dev | awk '/Interface/{print $2}'); do echo "-- $w"; iw dev "$w" link; iw dev "$w" info; done
S "tools present"; for t in tcpdump tshark airodump-ng kismet arp-scan nmap avahi-browse nft iperf3 dkms gcc make apt-get; do printf '%s=%s\n' "$t" "$(command -v "$t" || echo -)"; done
if ls "/lib/modules/$(uname -r)/build" >/dev/null 2>&1; then echo "kernel headers: present"; else echo "kernel headers: absent"; fi
S "iw list (all phys)"; iw list
S "end"; date -Is
