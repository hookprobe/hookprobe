#!/usr/bin/env bash
# mc-e2e-metal.sh — the METAL acceptance run for the production CM5 image (prod-mc, ADR 0047):
# the same assertions as tools/mc-e2e.sh (QEMU), against a REAL CM5 across the bench network.
#
#   tools/mc-e2e-metal.sh --ip <device-ip> --key-file <image>.owner-key [--serial-log <file>] [--no-browser]
#
# --ip           the device's address: the "[MC] heqk Mission Control serving on http://<ip>:80"
#                serial line, or the bench DHCP leases.
# --key-file     the owner key the image factory wrote next to the image (mode 600).
# --serial-log   (optional) a capture of the device's serial console from power-on: the script
#                extracts the boot markers and the [BOOT-TIMING] budget for the late-confirm decision.
#
# Writes a results file under ~/heqk-metal-logs/ (archive it with the image sha256).
set -u
cd "$(dirname "$0")/.."
export PATH="$HOME/.local/node/bin:$PATH"
IP=""; KEYF=""; SERIAL=""; BROWSER=1
# Dry-run overrides (to rehearse this script against the QEMU device before a bench session):
# QEMU reaches the device via forwarded host ports and sees the attacker as 10.0.2.2.
HTTP_PORT=80; C2_PORT=4444; TELNET_PORT=23; EXPECT_SRC=""
while [ $# -gt 0 ]; do
  case "$1" in
    --ip) IP="$2"; shift ;;
    --key-file) KEYF="$2"; shift ;;
    --serial-log) SERIAL="$2"; shift ;;
    --no-browser) BROWSER=0 ;;
    --http-port) HTTP_PORT="$2"; shift ;;
    --c2-port) C2_PORT="$2"; shift ;;
    --telnet-port) TELNET_PORT="$2"; shift ;;
    --expect-src) EXPECT_SRC="$2"; shift ;;
    *) echo "usage: $0 --ip <device-ip> --key-file <file> [--serial-log <file>] [--no-browser]"; exit 2 ;;
  esac
  shift
done
[ -n "$IP" ] && [ -r "$KEYF" ] || { echo "usage: $0 --ip <device-ip> --key-file <file> [--serial-log <file>]"; exit 2; }
TOKEN="$(tr -d ' \n\r' < "$KEYF")"
B="http://$IP"; [ "$HTTP_PORT" = 80 ] || B="http://$IP:$HTTP_PORT"
JAR=$(mktemp); trap 'rm -f "$JAR"' EXIT
mkdir -p "$HOME/heqk-metal-logs"
TAG=prod-mc-metal-acceptance; [ -n "$EXPECT_SRC" ] && TAG=prod-mc-DRYRUN-qemu
OUT="$HOME/heqk-metal-logs/$(date +%Y%m%d-%H%M%S)-$TAG.txt"
exec > >(tee "$OUT") 2>&1
FAILS=0
ok()  { echo "  PASS  $*"; }
bad() { echo "  FAIL  $*"; FAILS=$((FAILS+1)); }
jget() { python3 -I -c "import json,sys; d=json.load(sys.stdin); print(eval(sys.argv[1], {'d': d}))" "$1" 2>/dev/null; }
SRC="${EXPECT_SRC:-$(ip -o route get "$IP" 2>/dev/null | sed -n 's/.* src \([0-9.]*\).*/\1/p')}"
echo "== prod-mc METAL acceptance — device $IP, attacking from $SRC, $(date -Is)"

echo "[1] the device answers — Mission Control served by heqk"
H=$(curl -s -m 8 "$B/api/health")
[ "$(echo "$H" | jget "d['substrate']")" = heqk ] && ok "heqk answered on $B ($H)" || { bad "no heqk Mission Control at $B ($H)"; echo "MC-METAL: FAIL — device unreachable"; exit 1; }
[ "$(echo "$H" | jget "d['claimed']")" = True ] && ok "device is CLAIMED (owner verifier loaded from eMMC OWNER.TXT)" || bad "device reports UNCLAIMED — wrong image or OWNER.TXT not read"

echo "[2] owner authentication on metal"
[ "$(curl -s -o /dev/null -w '%{http_code}' -m 8 "$B/api/detections")" = 401 ] && ok "API refuses without a session (401)" || bad "API reachable without a session"
[ "$(curl -s -o /dev/null -w '%{http_code}' -m 8 "$B/detect/feed")" = 302 ] && ok "UI pages redirect to /login" || bad "UI page reachable without a session"
curl -s -o /dev/null -m 8 -d 'token=WRONG-KEY-00000000' "$B/api/login" -c "$JAR"
! grep -q hq_session "$JAR" && ok "a wrong owner key gets no session" || bad "wrong key yielded a session"
curl -s -o /dev/null -m 8 -d "token=$TOKEN" "$B/api/login" -c "$JAR"
grep -q hq_session "$JAR" && ok "the owner key yields a session" || { bad "login with the owner key failed"; }
C="-b $JAR"

echo "[3] rule plane armed, baseline"
H=$(curl -s -m 8 $C "$B/api/health")
[ "$(echo "$H" | jget "d['rules_active']")" -gt 0 ] 2>/dev/null && ok "rule plane armed ($H)" || bad "rule plane NOT armed — the IPS would pass everything ($H)"
D0=$(curl -s -m 8 $C "$B/api/detections" | jget "d['count']")
[[ "$D0" =~ ^[0-9]+$ ]] || { bad "could not read the baseline detection count"; D0=999999; }
DR0=$(echo "$H" | jget "d['dropped']")

echo "[4] real attack traffic at the device (C2 port 4444 x3, telnet 23 x2) while the UI stays in use"
for p in $C2_PORT $C2_PORT $TELNET_PORT $C2_PORT $TELNET_PORT; do curl -s -m 2 "http://$IP:$p/" >/dev/null 2>&1; done
LEG=$(curl -s -o /dev/null -w '%{http_code}' -m 8 $C "$B/api/health")
[ "$LEG" = 200 ] && ok "legit operator traffic still served during the attack (ADR 0023)" || bad "operator UI disrupted during the attack ($LEG)"
sleep 3

echo "[5] enforced on the wire and visible through heqk's own API"
H=$(curl -s -m 8 $C "$B/api/health"); DR=$(echo "$H" | jget "d['dropped']")
[ "$DR" -gt "${DR0:-0}" ] 2>/dev/null && ok "heqk dropped the attack frames on the real GEM wire (dropped $DR0 -> $DR)" || bad "no drops recorded ($DR0 -> $DR)"
DETS=$(curl -s -m 8 $C "$B/api/detections?limit=50"); N=$(echo "$DETS" | jget "d['count']")
[ "$N" -ge $((D0 + 3)) ] 2>/dev/null && ok "detections recorded ($D0 -> $N)" || bad "expected new detections, got $D0 -> $N"
echo "$DETS" | jget "any(x['rule_id']==1200001 and x['src_ip']=='$SRC' for x in d['detections'])" | grep -q True \
  && ok "C2-4444 detection attributed to the attacker $SRC" || bad "no C2-4444 detection from $SRC"
INC=$(curl -s -m 8 $C "$B/api/incidents")
echo "$INC" | jget "any(i['device_ip']=='$SRC' and i['priority']=='High' for i in d['incidents'])" | grep -q True \
  && ok "correlated into a High incident for $SRC" || bad "no High incident for $SRC ($INC)"
sleep 2
Q=$(curl -s -m 8 $C "$B/api/qsecbit")
echo "$Q" | jget "d['latest'] is not None and d['latest']['score']>0" | grep -q True && ok "QSecBit-lite risk rose under attack" || bad "QSecBit did not move ($Q)"

echo "[6] the unchanged Mission Control UI, loaded FROM the device, signed in, shows the attack"
if [ "$BROWSER" = 1 ] && [ -d tools/mc-e2e/node_modules/playwright ]; then
  (cd tools/mc-e2e && node ui-check.mjs "$B" "$TOKEN") && ok "browser: live heqk data rendered (screenshots /tmp/mc-e2e-*.png)" || bad "browser assertions failed"
else
  echo "  SKIP  browser leg (--no-browser or Playwright missing)"
fi

if [ -n "$SERIAL" ] && [ -r "$SERIAL" ]; then
  echo "[7] boot markers from the serial log"
  for m in "\[HBoot-AB\]" "\[P8\] rule plane" "\[MC\] Mission Control node UP" "\[MC\] owner:" "\[MC\] heqk Mission Control serving" "\[BOOT-TIMING\]"; do
    L=$(grep -a "$m" "$SERIAL" | tail -1 | tr -d '\r'); [ -n "$L" ] && echo "        $L" || echo "        (missing: ${m//\\/})"
  done
  PL=$(grep -a "prod loop entered at t=+" "$SERIAL" | tail -1 | sed -n 's/.*t=+\([0-9]*\) ms.*/\1/p')
  CF=$(grep -a "\[HBoot-AB\] PASS.*BOOT-TIMING\] t=+" "$SERIAL" | tail -1 | sed -n 's/.*t=+\([0-9]*\) ms.*/\1/p')
  if [ -n "$PL" ]; then
    LATE=$((PL + 2000))
    echo "        early confirm at +${CF:-?} ms; prod loop at +$PL ms; a late confirm would land at ~+$LATE ms of the 15000 ms watchdog budget"
    [ "$LATE" -le 10000 ] && echo "        => late-confirm FITS with >= 5 s margin: safe to make it the default" \
                          || echo "        => late-confirm does NOT leave a 5 s margin: keep it opt-in (or shorten boot first)"
  else
    echo "        (no [BOOT-TIMING] prod-loop marker — was the image built from >= 3698aca?)"
  fi
fi

echo
[ "$FAILS" = 0 ] && echo "MC-METAL: PASS — prod-mc on CM5 metal: claimed, signed in, attack dropped + detected + shown in the UI" || echo "MC-METAL: FAIL ($FAILS)"
echo "results: $OUT"
exit "$FAILS"
