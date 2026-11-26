#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# m5-metal-loop — one unattended metal round on the NanoPi M5 bench, netboot flavour:
#   stage image in the TFTP root -> relay power-cycle -> U-Boot (SPI-NOR) DHCP/TFTP/booti
#   -> wait for serial markers -> PASS/FAIL report. Nothing is flashed: the SPI-NOR loader only
#   changes through m5-spi-flash.sh.
#
#   tools/diagnostics/m5-metal-loop.sh --image heqk-m5.img --log SERIAL.log [--dtb X.dtb]
#        [--timeout 120] [--expect REGEX]... [--fail REGEX]...
#
# Needs: m5-console.sh capturing into --log, dnsmasq running with m5-netboot/dnsmasq-m5.conf,
# boot.scr.uimg in the TFTP root, $M5_RELAY set (or --relay-dev). Exit 0 = all --expect seen, no --fail.
set -u -o pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
TFTP="${M5_TFTP:-$HOME/heqk-m5-bench/tftp}"
IMG="" DTB="" LOG="" TIMEOUT=120 RDEV="${M5_RELAY:-}"
EXPECT=() FAIL=()
while [ $# -gt 0 ]; do
  case "$1" in
    --image) IMG="$2"; shift ;;
    --dtb) DTB="$2"; shift ;;
    --log) LOG="$2"; shift ;;
    --timeout) TIMEOUT="$2"; shift ;;
    --relay-dev) RDEV="$2"; shift ;;
    --expect) EXPECT+=("$2"); shift ;;
    --fail) FAIL+=("$2"); shift ;;
    *) echo "unknown argument $1" >&2; exit 2 ;;
  esac
  shift
done
[ -f "$IMG" ] || { echo "--image is required" >&2; exit 2; }
[ -f "$LOG" ] || { echo "--log must be the running m5-console.sh capture" >&2; exit 2; }
[ -f "$TFTP/heqk-m5/boot.scr.uimg" ] || { echo "no $TFTP/heqk-m5/boot.scr.uimg (see m5-netboot/boot.cmd)" >&2; exit 2; }
# Default contract = the bring-up probe (os/kernel/m5probe, runbook §7a): booti reached, probe at EL2, PASS.
# For heqk images pass --expect/--fail for the M5-0 contract (runbook §7b).
[ ${#EXPECT[@]} -gt 0 ] || EXPECT=('== booti ' '\[m5probe\] EL2 ' '\[m5probe\] RESULT: PASS')
[ ${#FAIL[@]} -gt 0 ] || FAIL=('\[m5probe\] RESULT: FAIL' '\[m5probe\] EXCEPTION' 'PANIC' 'panicked' 'Retry count exceeded' 'Bad Linux ARM64 Image magic' 'no FDT address' 'resetting \.\.\.')

REPORT="${LOG%.log}-round-$(date +%H%M%S).txt"
say() { echo "$*" | tee -a "$REPORT"; }
say "== m5-metal-loop $(date -Is) image=$(basename "$IMG") sha256=$(sha256sum "$IMG" | cut -c1-16)"

install -D -m 0644 "$IMG" "$TFTP/heqk-m5/heqk-m5.img"
if [ -n "$DTB" ]; then install -D -m 0644 "$DTB" "$TFTP/heqk-m5/heqk-m5.dtb"; else rm -f "$TFTP/heqk-m5/heqk-m5.dtb"; fi
say "-- 1/3 staged in $TFTP/heqk-m5"

start=$(stat -c %s "$LOG")
say "-- 2/3 relay power cycle"
python3 "$HERE/m5-relay.py" --dev "$RDEV" cycle 2>&1 | tee -a "$REPORT" || { say "FAIL: relay"; exit 1; }

say "-- 3/3 wait ${TIMEOUT}s for markers"
deadline=$(( $(date +%s) + TIMEOUT ))
while [ "$(date +%s)" -lt "$deadline" ]; do
  new=$(tail -c +"$((start + 1))" "$LOG" | tr -d '\r')
  for f in "${FAIL[@]}"; do
    if grep -qE -- "$f" <<<"$new"; then say "FAIL marker: $f"; grep -nE -- "$f" <<<"$new" | head -5 | tee -a "$REPORT"; exit 1; fi
  done
  all=1
  for e in "${EXPECT[@]}"; do grep -qE -- "$e" <<<"$new" || all=0; done
  if [ "$all" = 1 ]; then say "PASS: all ${#EXPECT[@]} markers seen"; exit 0; fi
  sleep 1
done
new=$(tail -c +"$((start + 1))" "$LOG" | tr -d '\r')
for e in "${EXPECT[@]}"; do grep -qE -- "$e" <<<"$new" && say "  seen    $e" || say "  MISSING $e"; done
say "FAIL: timeout"
exit 1
