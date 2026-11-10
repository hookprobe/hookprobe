#!/usr/bin/env bash
# cm5-identity-v6only-check — G36 IPv6-only devices + G32 JA4 identity hint, on metal, with the bench Pi's USB adapter
# (wlan1) through temporary NetworkManager profiles (passphrase from the Pi's saved AP profile, never printed):
#   G36: wlan1 joins IPv6-ONLY (no IPv4), makes 30 answered SSH attempts to the bench host's IPv6 sshd -> rule 124 is
#        raised for that device: "src_ipv6_only":true and "src_device" = wlan1's MAC (it used to be skipped: no lease).
#   G32: wlan1 joins with private MAC A, sends ClientHellos from three TLS stacks, leaves; rejoins with private MAC B
#        and does the same -> /api/devices shows B "likely_same_as" A (basis ja4), and A has >= 2 fingerprints.
#   tools/diagnostics/cm5-identity-v6only-check.sh <owner-key-file> [mc] [pi]          (needs PI_SUDO_FILE)
set -u -o pipefail
KEY="${1:?owner key file}"; MC="${2:-https://192.168.200.146}"; PI="${3:-claude@10.200.0.4}"; PS="${PI_SUDO_FILE:?PI_SUDO_FILE}"
V6HOST=2001:db8:100::1; TLSHOST=10.100.0.1
ok=0; n=0
chk() { n=$((n + 1)); if [ "$1" = 0 ]; then echo "ok  $2"; ok=$((ok + 1)); else echo "BAD $2"; fi; }
pi() { ssh -o BatchMode=yes -o ConnectTimeout=8 "$PI" "$@"; }
psudo() { pi "sudo -S -p '' $*" < "$PS"; }
JAR=$(mktemp); trap 'rm -f "$JAR"; psudo "nmcli con delete hq-idtest" >/dev/null 2>&1' EXIT
curl -sk -o /dev/null -m 10 --data-urlencode "token=$(cat "$KEY")" "$MC/api/login" -c "$JAR"
api() { curl -sk -m 10 -b "$JAR" "$MC$1"; }
PROF=$(pi "nmcli -t -f NAME con show | grep -i hookprobe | head -1")
SSID=$(psudo "nmcli -s -g 802-11-wireless.ssid con show '$PROF'")
PSK=$(psudo "nmcli -s -g 802-11-wireless-security.psk con show '$PROF'")
up() {   # <cloned-mac> <ipv4: auto|disabled>; with IPv4, a route to the bench host scoped to this profile only
  local r4=""; [ "$2" = auto ] && r4="ipv4.routes '10.100.0.1/32 10.99.0.1'"
  psudo "nmcli con delete hq-idtest" >/dev/null 2>&1
  psudo "nmcli con add type wifi ifname wlan1 con-name hq-idtest ssid '$SSID' wifi-sec.key-mgmt wpa-psk wifi-sec.psk '$PSK' wifi.cloned-mac-address $1 ipv4.method $2 ipv4.never-default yes $r4 ipv6.method auto connection.autoconnect no" >/dev/null 2>&1
  psudo "timeout 70 nmcli -w 60 con up hq-idtest" >/dev/null 2>&1
}
down() { psudo "nmcli con down hq-idtest" >/dev/null 2>&1; psudo "nmcli con delete hq-idtest" >/dev/null 2>&1; }
# ---- G36: IPv6-only device
MV6=02:6c:00:00:36:01
up $MV6 disabled
A4=$(pi "ip -4 -o addr show wlan1 | wc -l"); A6=""
for _ in $(seq 1 15); do A6=$(pi "ip -6 -o addr show wlan1 scope global | awk '{print \$4}' | head -1"); [ -n "$A6" ] && break; sleep 3; done
echo "  wlan1 ($MV6): IPv4 addresses $A4, IPv6 $A6"
[ "$A4" = 0 ] && [ -n "$A6" ]; chk $? "wlan1 is IPv6-only on the AP (no IPv4 lease, a global IPv6 address)"
# bound to wlan1 (wlan0 is on the same AP with its own routes and lease: unbound attempts would be ITS traffic)
pi "for i in \$(seq 1 30); do curl -s -m 1 --interface wlan1 telnet://[$V6HOST]:22 </dev/null >/dev/null 2>&1; done; true"
sleep 3
D=$(api "/api/detections?limit=200")
grep -q "\"rule_id\":1200124[^}]*\"src_device\":\"$MV6\",\"src_ipv6_only\":true" <<<"$D"; chk $? "G36: rule 124 over IPv6 from the IPv6-only device, attributed to its MAC (src_device, src_ipv6_only)"
down
# ---- G32: private-MAC rotation A -> B with the same TLS stacks
hellos() {   # three distinct TLS client stacks from wlan1 (JA4 differs by ALPN / max version); the ClientHello is
             # fingerprinted even though the bench host's sshd answers it
  pi "for o in '' '--http1.1' '--tls-max 1.2'; do timeout 4 curl -sk --interface wlan1 \$o --resolve example.net:22:$TLSHOST https://example.net:22/ >/dev/null 2>&1; done; true"
}
MA=02:6c:00:00:32:0a; MB=02:6c:00:00:32:0b
up $MA auto; sleep 3; hellos; hellos; down
sleep 5
up $MB auto; sleep 3; hellos; hellos
sleep 2
DV=$(api "/api/devices")
python3 - "$DV" "$MA" "$MB" <<'PY'
import json, sys
d = json.loads(sys.argv[1]); a, b = sys.argv[2], sys.argv[3]
rows = {r.get("mac"): r for r in d.get("devices", d if isinstance(d, list) else [])}
ra, rb = rows.get(a, {}), rows.get(b, {})
print(f"  A {a}: ja4_fingerprints={ra.get('ja4_fingerprints')} | B {b}: ja4_fingerprints={rb.get('ja4_fingerprints')} likely_same_as={rb.get('likely_same_as')}")
PY
python3 -c 'import json,sys; d=json.loads(sys.argv[1]); r={x.get("mac"):x for x in d.get("devices",[])}; b=r.get(sys.argv[3],{}); a=r.get(sys.argv[2],{}); sys.exit(0 if (a.get("ja4_fingerprints") or 0)>=2 and (b.get("likely_same_as") or {}).get("mac")==sys.argv[2] else 1)' "$DV" "$MA" "$MB"
chk $? "G32: after a private-MAC rotation the new MAC is shown likely_same_as the old one (basis ja4, >= 2 fingerprints)"
down
echo "IDENTITY-V6ONLY: $([ $ok = $n ] && echo PASS || echo FAIL) ($ok/$n)"
[ $ok = $n ]
