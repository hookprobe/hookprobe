#!/usr/bin/env bash
# cm5-metal-loop — one unattended metal round on the CM5 bench:
#   relay rpiboot -> flash + read-back verify -> relay boot -> wait for serial markers -> PASS/FAIL
#
#   tools/diagnostics/cm5-metal-loop.sh --image IMG [--log SERIAL.log] [--timeout 240]
#        [--relay "--backend nano --dev auto"] [--expect REGEX]... [--fail REGEX]...
#
# The serial console must be captured into --log (default: start our own capture from the
# FTDI console). sudo is needed for the flash: run with a cached sudo ticket, or set
# SUDO_PASS_FILE to a 0600 file holding the password. Exit 0 = every --expect marker seen and
# no --fail marker; the per-run report is written next to the log.
set -u -o pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
IMG=""
LOG=""
TIMEOUT=240
RELAY="--backend nano --dev auto"
CONSOLE="/dev/serial/by-id/usb-FTDI_FT232R_USB_UART_AB0OHO28-if00-port0"
EXPECT=()
FAIL=()
while [ $# -gt 0 ]; do
  case "$1" in
    --image) IMG="$2"; shift ;;
    --log) LOG="$2"; shift ;;
    --timeout) TIMEOUT="$2"; shift ;;
    --relay) RELAY="$2"; shift ;;
    --console) CONSOLE="$2"; shift ;;
    --expect) EXPECT+=("$2"); shift ;;
    --fail) FAIL+=("$2"); shift ;;
    *) echo "unknown argument $1" >&2; exit 2 ;;
  esac
  shift
done
[ -f "$IMG" ] || { echo "--image IMG is required" >&2; exit 2; }
# Defaults: the AP image's boot contract.
[ ${#EXPECT[@]} -gt 0 ] || EXPECT=('secure boot: PASS' '\[HBoot-AB\] PASS' '\[P10-B\] PASS' '\[P11-AP2\] PASS' '\[AP-MC\] owner:')
[ ${#FAIL[@]} -gt 0 ] || FAIL=('secure boot: FAIL' '\[P10-B\] SILENT' 'PANIC' 'panicked' 'halting;' 'AP will NOT start')

RELAYPY=(python3 "$HERE/cm5-relay.py" $RELAY)
SUDO=(sudo)
if [ -n "${SUDO_PASS_FILE:-}" ]; then SUDO=(sudo -S -p ''); fi
run_sudo() { if [ -n "${SUDO_PASS_FILE:-}" ]; then "${SUDO[@]}" "$@" < "$SUDO_PASS_FILE"; else "${SUDO[@]}" "$@"; fi; }

CAPPID=""
if [ -z "$LOG" ]; then
  LOG="$HOME/heqk-metal-logs/loop-$(date +%Y%m%d-%H%M%S)-serial.log"
  mkdir -p "$(dirname "$LOG")"
  stty -F "$CONSOLE" 115200 raw -echo || { echo "cannot open console $CONSOLE" >&2; exit 1; }
  cat "$CONSOLE" >> "$LOG" &
  CAPPID=$!
fi
REPORT="${LOG%.log}-round-$(date +%H%M%S).txt"
cleanup() { [ -n "$CAPPID" ] && kill "$CAPPID" 2>/dev/null; }
trap cleanup EXIT

say() { echo "$*" | tee -a "$REPORT"; }
say "== cm5-metal-loop $(date -Is) image=$(basename "$IMG") sha256=$(sha256sum "$IMG" | cut -c1-16)"

say "-- 1/4 relay: rpiboot"
"${RELAYPY[@]}" rpiboot 2>&1 | tee -a "$REPORT" || { say "FAIL: board did not enter rpiboot"; exit 1; }

say "-- 2/4 flash + verify"
FLOG="${REPORT%.txt}-flash.txt"
run_sudo "$ROOT/os/kernel/cm5-boot/flash-image.sh" "$IMG" --confirm-erase > "$FLOG" 2>&1
tr '\r' '\n' < "$FLOG" | grep -v "bytes.*copied" | tail -6 | tee -a "$REPORT"
grep -aq '^VERIFIED' "$FLOG" || { say "FAIL: flash or read-back verify failed (see $FLOG)"; exit 1; }

MARK=$(stat -c %s "$LOG")
say "-- 3/4 relay: boot (serial mark $MARK)"
"${RELAYPY[@]}" boot 2>&1 | tee -a "$REPORT" || { say "FAIL: relay boot"; exit 1; }

say "-- 4/4 waiting up to ${TIMEOUT}s for ${#EXPECT[@]} markers"
t0=$(date +%s)
while :; do
  NEW=$(tail -c +$((MARK + 1)) "$LOG" | tr -d '\r\000')
  for f in "${FAIL[@]}"; do
    if grep -aqE "$f" <<<"$NEW"; then
      say "FAIL marker: $f"
      grep -aE "$f" <<<"$NEW" | head -3 | sed 's/^/   | /' | tee -a "$REPORT"
      say "RESULT: FAIL"
      exit 1
    fi
  done
  missing=0
  for e in "${EXPECT[@]}"; do grep -aqE "$e" <<<"$NEW" || missing=$((missing + 1)); done
  [ "$missing" -eq 0 ] && break
  if [ $(( $(date +%s) - t0 )) -ge "$TIMEOUT" ]; then
    for e in "${EXPECT[@]}"; do grep -aqE "$e" <<<"$NEW" || say "MISSING: $e"; done
    say "RESULT: FAIL (timeout)"
    exit 1
  fi
  sleep 2
done
for e in "${EXPECT[@]}"; do say "ok  $(grep -aE "$e" <<<"$NEW" | head -1 | cut -c1-160)"; done
say "RESULT: PASS ($(( $(date +%s) - t0 ))s after power-on)"
