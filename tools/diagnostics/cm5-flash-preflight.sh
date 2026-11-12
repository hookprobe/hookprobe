#!/usr/bin/env bash
# cm5-flash-preflight — READ-ONLY checks before any CM5 flash (docs/design/heqk-flash-runbook.md). It never switches a
# relay, never powers the board, never writes a disk. Every line is ok / BAD / WARN; any BAD = do not flash.
#   tools/diagnostics/cm5-flash-preflight.sh <image-dir with disk.img + heqk8.img> [serial-log] [pi] [mc]
set -u -o pipefail
D="${1:?image dir}"; LOG="${2:-$HOME/heqk-metal-logs/20261108-relay-serial.log}"
PI="${3:-claude@10.200.0.4}"; MC="${4:-https://192.168.200.146}"
HERE=$(cd "$(dirname "$0")" && pwd)
bad=0; warn=0
ok() { echo "ok   $*"; }
no() { echo "BAD  $*"; bad=$((bad + 1)); }
wn() { echo "WARN $*"; warn=$((warn + 1)); }
echo "== cm5-flash-preflight $(date -Is) image dir $D"
# 1. the image
if [ -f "$D/disk.img" ] && [ -f "$D/heqk8.img" ]; then
  s=$(stat -c %s "$D/heqk8.img"); [ "$s" -le 5242880 ] && ok "heqk8.img $s B <= 5,242,880 (headroom $((5242880 - s)) B)" || no "heqk8.img $s B over the 5 MiB hboot limit"
  ok "disk.img sha256 $(sha256sum "$D/disk.img" | cut -c1-16)… heqk8 $(sha256sum "$D/heqk8.img" | cut -c1-16)…"
  [ -f "$D.log" ] && grep -aq "FACTORY: PASS" "$D.log" && ok "factory log says PASS ($D.log)" || wn "no factory PASS line next to the image ($D.log)"
else no "missing $D/disk.img or $D/heqk8.img"; fi
# 2. host tools + credentials (no secret is read or printed)
command -v rpiboot >/dev/null || [ -x /usr/bin/rpiboot ] || [ -x /usr/local/bin/rpiboot ] && ok "rpiboot present" || no "rpiboot not installed"
[ -n "${SUDO_PASS_FILE:-}" ] && [ -f "$SUDO_PASS_FILE" ] && [ "$(stat -c %a "$SUDO_PASS_FILE")" = 600 ] && ok "sudo password file present, mode 600" || wn "SUDO_PASS_FILE not set / not 0600 (the flash step needs sudo)"
df_k=$(df -k --output=avail "$HOME" | tail -1); [ "$df_k" -gt 2000000 ] && ok "free space $((df_k / 1024)) MiB" || no "less than 2 GiB free in \$HOME"
# 3. relay rig: reachable, and in the resting state (power on, rpiboot released) — status only
R=$(timeout 20 python3 "$HERE/cm5-relay.py" --backend nano --dev auto status 2>&1 | tail -2)
grep -q "power=1 rpiboot=0" <<<"$R" && ok "relay rig answers, resting state ($(tail -1 <<<"$R"))" || no "relay rig: $(tr '\n' ' ' <<<"$R")"
# 4. USB: the boot ROM must NOT be present now (a board stuck in rpiboot is a fault), the serial + relay adapters must
lsusb | grep -q "0a5c:271[12]" && no "a CM5 boot ROM is already on USB (board stuck in rpiboot?)" || ok "no boot ROM on USB (board is not stuck in rpiboot)"
lsusb | grep -q "0403:6001" && ok "FTDI serial console adapter present" || no "FTDI serial console (0403:6001) missing"
lsusb | grep -q "1a86:7523" && ok "CH340 relay controller present" || no "CH340 relay controller (1a86:7523) missing"
echo "     USB tree (for the record):"; lsusb -t 2>/dev/null | sed 's/^/       /' | head -20
# 5. serial capture alive and recent
if [ -f "$LOG" ]; then
  age=$(( $(date +%s) - $(stat -c %Y "$LOG") ))
  # a dead capture means no batch can prove which image booted (2026-11-12: it died when the FTDI re-enumerated)
  [ "$age" -lt 120 ] && ok "serial log written ${age}s ago ($LOG)" || no "serial log idle for ${age}s — restart the capture (cat the FTDI by-id path >> the log)"
  pgrep -f "cat /dev/serial/by-id/usb-FTDI" >/dev/null && ok "serial capture running on the FTDI by-id path" || no "no serial capture on /dev/serial/by-id/usb-FTDI… (ttyUSB numbers change on re-enumeration — always capture by-id)"
  tail -c 200000 "$LOG" | tr -d '\r\000' | grep -a "HEQK\|HBoot" | tail -1 | cut -c1-120 | sed 's/^/     last boot line: /'
else no "serial log $LOG missing"; fi
# 6. the bench around the board
ip link show enp4s0.100 >/dev/null 2>&1 && ip link show enp4s0.200 >/dev/null 2>&1 && ok "bench VLANs up (enp4s0.100 / .200)" || no "bench VLANs down — run docs/design/bench-task26/fortress-vlan-bench.sh setup"
ssh -o BatchMode=yes -o ConnectTimeout=6 "$PI" true 2>/dev/null && ok "bench Pi reachable ($PI)" || no "bench Pi unreachable ($PI)"
ssh -o BatchMode=yes -o ConnectTimeout=6 "$PI" "nmcli -t -f NAME con show | grep -qi hookprobe" 2>/dev/null && ok "Pi has a saved HookProbe AP profile" || wn "Pi has no saved HookProbe AP profile"
c=$(curl -sk -o /dev/null -w '%{http_code}' -m 6 "$MC/api/health"); [ "$c" = 200 ] && ok "current image answers on the management VLAN ($MC)" || wn "Mission Control on $MC: HTTP $c (board down or on another image)"
# 7. nothing else is driving the bench
others=$(pgrep -af "cm5-metal-loop|cm5-soak.sh|flash-image.sh|cm5-relay.py" | grep -v "pgrep\|preflight" | wc -l)
[ "$others" -eq 0 ] && ok "no other flash / soak / relay job running" || no "$others other bench job(s) running"
echo "== preflight: $bad BAD, $warn WARN — $([ $bad -eq 0 ] && echo 'GO only with the operator' || echo 'DO NOT FLASH')"
[ $bad -eq 0 ]
