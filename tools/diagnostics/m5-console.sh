#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# m5-console — capture the NanoPi M5 debug console (UART0_M0, 3-pin header J1: GND/TX/RX, 3.3 V,
# 1 500 000 8N1) into a log, forever, so every metal round and every boot is on disk.
#
#   tools/diagnostics/m5-console.sh [--dev /dev/hq-m5-console] [--log FILE]
#
# The adapter must be 3.3 V and do 1.5 Mbaud: CP2102N, FT232R(L) or CH343 — NOT the original CP2102 or
# a PL2303. Wire adapter RX <- board TX (J1 pin 2), adapter TX -> board RX (J1 pin 3), GND <- pin 1.
# Never connect the adapter's 3.3 V/5 V pin. To type into U-Boot while this runs: write to the same
# device from another shell (printf 'version\r' > /dev/hq-m5-console) — the capture keeps reading.
set -u -o pipefail
DEV="${M5_CONSOLE:-/dev/hq-m5-console}"
LOG="$HOME/heqk-metal-logs/m5-$(date +%Y%m%d-%H%M%S)-serial.log"
while [ $# -gt 0 ]; do
  case "$1" in
    --dev) DEV="$2"; shift ;;
    --log) LOG="$2"; shift ;;
    *) echo "unknown argument $1" >&2; exit 2 ;;
  esac
  shift
done
[ -e "$DEV" ] || { echo "no console device $DEV (udev rule: tools/diagnostics/m5-netboot/99-hq-m5-bench.rules.example)" >&2; exit 1; }
real=$(readlink -f "$DEV")
# Never capture from (and so never hold open) the CM5 console or the LTE modem.
for l in /dev/serial/by-id/*FTDI_FT232R_USB_UART_AB0OHO28* /dev/serial/by-id/*Sierra_Wireless*; do
  [ -e "$l" ] && [ "$(readlink -f "$l")" = "$real" ] && { echo "refusing $DEV: that is $l" >&2; exit 2; }
done
mkdir -p "$(dirname "$LOG")"
stty -F "$DEV" 1500000 cs8 -cstopb -parenb raw -echo -crtscts clocal || { echo "cannot set 1500000 baud on $DEV" >&2; exit 1; }
echo "== m5-console $(date -Is) $DEV -> $LOG" | tee -a "$LOG"
exec cat "$DEV" >> "$LOG"
