#!/usr/bin/env bash
# cm5-latelink-test — "cable plugged after boot" on the relay rig, without touching a cable:
#   host port DOWN -> relay boot -> CM5 boots with no carrier -> host port UP -> the CM5 must recover by itself
#   (WAN lease, management lease, Mission Control on the management VLAN, HTTPS answering).
#
#   tools/diagnostics/cm5-latelink-test.sh --iface enp4s0 --log SERIAL.log --mgmt 192.168.200.146
# Needs sudo for `ip link` (cached ticket, or SUDO_PASS_FILE). Exit 0 = recovered.
set -u -o pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
IFACE=enp4s0
LOG=""
MGMT=""
RELAY="--backend nano --dev auto"
while [ $# -gt 0 ]; do
  case "$1" in
    --iface) IFACE="$2"; shift ;;
    --log) LOG="$2"; shift ;;
    --mgmt) MGMT="$2"; shift ;;
    --relay) RELAY="$2"; shift ;;
    *) echo "unknown argument $1" >&2; exit 2 ;;
  esac
  shift
done
[ -f "$LOG" ] || { echo "--log SERIAL.log (a running console capture) is required" >&2; exit 2; }
run_sudo() { if [ -n "${SUDO_PASS_FILE:-}" ]; then sudo -S -p '' "$@" < "$SUDO_PASS_FILE"; else sudo "$@"; fi; }
wait_for() { # <regex> <seconds> <mark>
  local t0; t0=$(date +%s)
  until tail -c +$(($3 + 1)) "$LOG" | tr -d '\r\000' | grep -aqE "$1"; do
    [ $(( $(date +%s) - t0 )) -ge "$2" ] && return 1
    sleep 2
  done
}
trap 'run_sudo ip link set "$IFACE" up' EXIT

echo "== late-link test $(date -Is): $IFACE down, boot, $IFACE up"
run_sudo ip link set "$IFACE" down || exit 1
MARK=$(stat -c %s "$LOG")
python3 "$HERE/cm5-relay.py" $RELAY boot || exit 1
wait_for '\[P11-AP2\] PASS|\[AP-MC\] owner' 240 "$MARK" || { echo "FAIL: the CM5 did not come up with the port down"; exit 1; }
echo "   booted with no carrier (AP up)"
MARK2=$(stat -c %s "$LOG")
run_sudo ip link set "$IFACE" up || exit 1
T_UP=$(date +%s)
echo "   $IFACE up at $(date +%T)"
ok=0
wait_for 'WAN came up after boot' 120 "$MARK2" && { echo "ok  WAN recovered after $(( $(date +%s) - T_UP ))s"; ok=$((ok + 1)); } || echo "BAD WAN did not recover in 120 s"
wait_for 'Mission Control also on' 90 "$MARK2" && { echo "ok  management VLAN leased + MC served"; ok=$((ok + 1)); } || echo "BAD management VLAN / MC did not come up"
if [ -n "$MGMT" ]; then
  code=$(curl -sk -m 10 -o /dev/null -w '%{http_code}' "https://$MGMT/api/health")
  [ "$code" = 200 ] && { echo "ok  https://$MGMT/api/health 200"; ok=$((ok + 1)); } || echo "BAD https://$MGMT/api/health -> $code"
fi
tail -c +$((MARK2 + 1)) "$LOG" | tr -d '\r\000' | grep -aE '\[WAN\] (link up|retry)|WAN came up after boot' | head -5 | sed 's/^/   | /'
need=2; [ -n "$MGMT" ] && need=3
[ "$ok" -eq "$need" ] && { echo "LATE-LINK: PASS"; exit 0; } || { echo "LATE-LINK: FAIL"; exit 1; }
