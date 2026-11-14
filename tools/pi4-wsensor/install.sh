#!/usr/bin/env bash
# Install / update the Pi 4 wireless sensor on the bench Pi (idempotent). Run ON the Pi:
#   sudo ./install.sh [--enable]
# Installs receive-only capture/analysis tools only (tshark/dumpcap, iw). No injection tools.
set -euo pipefail
export PATH=$PATH:/usr/sbin:/sbin
SRC=$(cd "$(dirname "$0")" && pwd)
[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }
need=()
for p in tshark iw; do command -v "$p" >/dev/null || need+=("$p"); done
[ ${#need[@]} -eq 0 ] || DEBIAN_FRONTEND=noninteractive apt-get install -y -q "${need[@]}"
install -d -m 0755 /opt/pi4-wsensor /etc/pi4-wsensor
install -d -m 0755 /var/lib/pi4-wsensor   # health.json + events readable by the dashboard/operator
# keep raw captures private
install -d -m 0700 /var/lib/pi4-wsensor/pcap
for f in wsensor-supervisor.sh dongle-lock.sh wsensor_extract.py m0-inventory.sh m0-monitor-test.sh; do
  install -m 0755 "$SRC/$f" /opt/pi4-wsensor/
done
[ -f "$SRC/README.md" ] && install -m 0644 "$SRC/README.md" /opt/pi4-wsensor/
[ -f /etc/pi4-wsensor/wsensor.conf ] || install -m 0644 "$SRC/wsensor.conf" /etc/pi4-wsensor/
install -m 0644 "$SRC/pi4-wsensor.service" /etc/systemd/system/
systemctl daemon-reload
if [ "${1:-}" = --enable ]; then systemctl enable --now pi4-wsensor.service; fi
echo "installed. status: systemctl status pi4-wsensor; health: cat /var/lib/pi4-wsensor/health.json"
