#!/usr/bin/env bash
# cm5-rpiboot-check — prove the bench can put the CM5 into rpiboot and expose its eMMC as USB mass storage, WITHOUT
# writing anything, then return the board to a normal eMMC boot. Step 1 of docs/design/heqk-flash-runbook.md.
#   tools/diagnostics/cm5-rpiboot-check.sh [--msd]      (--msd also loads the mass-storage gadget: needs sudo /
#                                                        SUDO_PASS_FILE; read-only — the disk is only listed)
# Exit 0 = rpiboot (and, with --msd, mass storage) worked and the board booted back; any failure stops at once.
set -u -o pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
RELAY=(python3 "$HERE/cm5-relay.py" --backend nano --dev auto)
MSD=0; [ "${1:-}" = "--msd" ] && MSD=1
say() { echo "$(date +%T) $*"; }
back() { say "returning the board to a normal eMMC boot"; "${RELAY[@]}" boot; }
# 0. resting state, nothing else driving the bench
st=$("${RELAY[@]}" status 2>&1 | tail -1); say "relays: $st"
grep -q "power=1 rpiboot=0" <<<"$st" || { say "FAIL: relay rig not in its resting state"; exit 1; }
lsusb | grep -q "0a5c:271[12]" && { say "FAIL: a boot ROM is already on USB"; exit 1; }
[ "$(pgrep -fc 'cm5-metal-loop|flash-image.sh|cm5-soak.sh')" -le 0 ] || { say "FAIL: another bench job is running"; exit 1; }
# 1. nRPIBOOT held + power cycle (read-back checked inside cm5-relay.py) + boot ROM on USB
if ! "${RELAY[@]}" rpiboot; then say "FAIL: the boot ROM did not enumerate"; back; exit 1; fi
say "ok boot ROM: $(lsusb | grep '0a5c:271' | head -1)"
# 2. optional: the mass-storage gadget — the eMMC must appear as a USB disk (listed, never written)
if [ $MSD = 1 ]; then
  SUDO=(sudo); [ -n "${SUDO_PASS_FILE:-}" ] && SUDO=(sudo -S -p '')
  run() { if [ -n "${SUDO_PASS_FILE:-}" ]; then "${SUDO[@]}" "$@" < "$SUDO_PASS_FILE"; else "${SUDO[@]}" "$@"; fi; }
  GD=$(ls -d /usr/share/rpiboot/mass-storage-gadget64 2>/dev/null || ls -d "$HOME"/usbboot/mass-storage-gadget64 2>/dev/null | head -1)
  [ -n "$GD" ] || { say "FAIL: mass-storage-gadget64 not found"; back; exit 1; }
  run timeout 60 rpiboot -d "$GD" >/dev/null 2>&1 || { say "FAIL: rpiboot -d mass-storage-gadget64"; back; exit 1; }
  for _ in $(seq 1 30); do lsusb | grep -q "0a5c:0104" && break; sleep 1; done
  lsusb | grep -q "0a5c:0104" || { say "FAIL: mass-storage gadget (0a5c:0104) did not appear"; back; exit 1; }
  sleep 3; say "ok mass storage: $(lsblk -dno NAME,SIZE,MODEL,TRAN | grep -i usb | head -2 | tr '\n' ';')"
fi
# 3. back to normal; the board must answer again
back
say "rpiboot check: PASS$([ $MSD = 1 ] && echo ' (incl. mass storage)')"
