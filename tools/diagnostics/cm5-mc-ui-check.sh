#!/usr/bin/env bash
# cm5-mc-ui-check — Mission Control in a real browser (Playwright Chromium) against the CM5 on metal, over BOTH paths:
#   mgmt  the management VLAN (https://192.168.200.146), and
#   ap    the Wi-Fi AP as a LAN client sees it: an SSH tunnel through the bench Pi, which is a client of the CM5 AP
#         (fortress 127.0.0.1:18443 -> Pi -> 10.99.0.1:443 over the Pi's Wi-Fi).
# Runs the read-only live specs (os/mission-control/tests/ui/specs/live). The device certificate is trusted by SPKI pin.
#   tools/diagnostics/cm5-mc-ui-check.sh <owner-key-file> [mc] [pi] [shots-dir]
set -u -o pipefail
KEY="${1:?owner key file (device password)}"; MC="${2:-https://192.168.200.146}"; PI="${3:-claude@10.200.0.4}"; SHOTS="${4:-}"
HERE=$(cd "$(dirname "$0")" && pwd); ROOT=$(cd "$HERE/../.." && pwd)
[ -d "$HOME/.local/node/bin" ] && export PATH="$HOME/.local/node/bin:$PATH"
PW="${PW_DIR:-$ROOT/os/kernel/tools/mc-e2e/node_modules}"
[ -d "$PW/playwright" ] || (cd "$ROOT/os/kernel/tools/mc-e2e" && npm ci --no-audit --no-fund >/dev/null 2>&1) || { echo "MC-UI: playwright missing ($PW)"; exit 2; }
spki() { echo | openssl s_client -connect "$1" -servername heqk.local 2>/dev/null | openssl x509 -pubkey -noout \
  | openssl pkey -pubin -outform der 2>/dev/null | openssl dgst -sha256 -binary | base64; }
rc=0; [ -n "$SHOTS" ] && mkdir -p "$SHOTS/mgmt" "$SHOTS/ap"
H=${MC#https://}; S=$(spki "$H:443"); [ -n "$S" ] || { echo "MC-UI: no TLS answer on $H"; exit 2; }
echo "== mgmt path ($MC)"; UI_LIVE_TOKEN="$(cat "$KEY")" node "$HERE/cm5-mc-ui.mjs" "$PW" "$MC" "$S" ${SHOTS:+"$SHOTS/mgmt"}; rc=$((rc + $?))
echo "== AP path (through the Pi's Wi-Fi, 10.99.0.1)"
ssh -o BatchMode=yes -o ExitOnForwardFailure=yes -N -L 127.0.0.1:18443:10.99.0.1:443 "$PI" & TP=$!; sleep 3
if kill -0 $TP 2>/dev/null; then
  S2=$(spki 127.0.0.1:18443)
  UI_LIVE_TOKEN="$(cat "$KEY")" node "$HERE/cm5-mc-ui.mjs" "$PW" https://127.0.0.1:18443 "$S2" ${SHOTS:+"$SHOTS/ap"}; rc=$((rc + $?))
  kill $TP 2>/dev/null
else echo "MC-UI: AP tunnel through $PI failed (is the Pi on the AP?)"; rc=$((rc + 1)); fi
[ $rc = 0 ] && echo "MC-UI-CHECK: PASS (both paths)" || echo "MC-UI-CHECK: FAIL ($rc)"
exit $(( rc > 100 ? 100 : rc ))
