#!/usr/bin/env bash
# cm5-lan-client — detection + protection tests from a REAL client behind heqk (the bench Pi 4: Wi-Fi on the
# CM5 AP = the test path, eth0 on the fortress LAN = SSH control only). Reads the device's own view through
# Mission Control on the management VLAN.
#   tools/diagnostics/cm5-lan-client.sh --pi claude@10.200.0.4 --mc https://192.168.200.146 --key OWNER_KEY_FILE
#     [--ssh-target 10.100.0.1] [--blocked example.org]
set -u -o pipefail
PI=claude@10.200.0.4; MC=https://192.168.200.146; KEY=""; SSHT=10.100.0.1; BLOCKED=example.org
while [ $# -gt 0 ]; do
  case "$1" in --pi) PI="$2"; shift ;; --mc) MC="$2"; shift ;; --key) KEY="$2"; shift ;; --ssh-target) SSHT="$2"; shift ;; --blocked) BLOCKED="$2"; shift ;; *) exit 2 ;; esac
  shift
done
[ -f "$KEY" ] || { echo "--key OWNER_KEY_FILE required" >&2; exit 2; }
pi() { ssh -o BatchMode=yes -o ConnectTimeout=8 "$PI" "$@"; }
JAR=$(mktemp); trap 'rm -f "$JAR"' EXIT
curl -sk -o /dev/null -m 10 --data-urlencode "token=$(cat "$KEY")" "$MC/api/login" -c "$JAR"
api() { curl -sk -m 10 -b "$JAR" "$MC$1"; }
ok=0; n=0
chk() { n=$((n + 1)); if [ "$1" = 0 ]; then echo "ok  $2"; ok=$((ok + 1)); else echo "BAD $2"; fi; }
# the Pi's Wi-Fi interface on the CM5 AP is whichever holds the default route via 10.99.0.1 (it has two
# adapters and NetworkManager may pick either) — wait for it after a CM5 reboot instead of sleeping blindly
"$(dirname "$0")/pi-ensure-ap.sh" "$PI" >/dev/null 2>&1 || true
IF=""; PIIP=""
for _ in $(seq 1 45); do
  IF=$(pi "ip route | awk '/^default via 10.99.0.1/ {print \$5; exit}'" 2>/dev/null)
  [ -n "$IF" ] && PIIP=$(pi "ip -4 -br addr show $IF | awk '{print \$3}' | cut -d/ -f1") && [ -n "$PIIP" ] && break
  sleep 2
done
[ -n "$PIIP" ] || { echo "BAD the Pi never rejoined the CM5 AP"; echo "LAN-CLIENT: FAIL (0/1)"; exit 1; }
echo "== LAN client $PIIP on $IF (Wi-Fi via the CM5)"

# 1. connectivity through heqk (v4 + v6)
pi "curl -4 -s -m 10 -o /dev/null -w '%{http_code}' http://example.com/" | grep -q 200; chk $? "IPv4 web through the CM5"
r=1; for _ in $(seq 1 15); do pi "ip -6 route | grep -q 'default.*$IF' && ping -6 -c2 -W3 2001:db8:100::1 >/dev/null" && { r=0; break; }; sleep 3; done   # PD -> RA -> SLAAC after a boot
chk $r "IPv6 (delegated prefix, SLAAC) reaches the WAN-side router"

# 2. Shield: blocked name -> NXDOMAIN, allowed name resolves
R=$(pi "dig +time=3 +tries=1 @10.99.0.1 $BLOCKED A" )
grep -q "status: NXDOMAIN" <<<"$R"; chk $? "Shield: $BLOCKED -> NXDOMAIN"
pi "dig +short +time=3 +tries=1 @10.99.0.1 debian.org A | grep -qE '^[0-9.]+$'"; chk $? "Shield: an allowed name resolves"

# 2b. G22 per-client Shield profile: the bench DEVICES.TXT gives the Pi shield=strict, so Private Relay (only
#     reported under the global policy) is blocked FOR IT; /api/devices shows the profile
R=$(pi "dig +time=3 +tries=1 @10.99.0.1 mask.icloud.com A")
grep -q "status: NOERROR" <<<"$R" && grep -q "IN.*A.*[0-9]" <<<"$R"; [ $? -ne 0 ]; chk $? "G22 shield=strict: Private Relay (mask.icloud.com) not resolved for the Pi"
MACNOW=$(pi "cat /sys/class/net/$IF/address")
api "/api/devices?limit=50" | grep -q "\"mac\":\"$MACNOW\"[^}]*\"shield_profile\":\"strict\""; chk $? "G22: /api/devices reports shield_profile strict for the Pi"

# 3. JA4: the Pi's TLS ClientHellos are fingerprinted
pi "curl -s -m 10 -o /dev/null https://www.debian.org/ ; curl -s -m 10 -o /dev/null https://example.com/" || true
sleep 2
T=$(api /api/tls)
grep -q "\"client\":\"$PIIP\",\"ja4\":\"t1" <<<"$T"; chk $? "JA4: the Pi's TLS clients appear in /api/tls ($(grep -o '"hellos":[0-9]*' <<<"$T"))"

# 3b. rule 125: a TLS client whose JA4 is on the IOC pack (bench: openssl s_client, no ALPN) — curl stays clean
pi "echo | timeout 8 openssl s_client -4 -connect example.net:443 -servername example.net >/dev/null 2>&1" || true
sleep 2
T=$(api /api/tls)
grep -q "\"client\":\"$PIIP\",\"ja4\":\"t13d301000_[^\"]*\",\"sni\":\"example.net\"[^}]*\"ioc\":true" <<<"$T"; chk $? "rule 125: the IOC-listed TLS client (openssl) is flagged ioc"
! grep -q "\"client\":\"$PIIP\",\"ja4\":\"t13d3011h2_[^}]*\"ioc\":true" <<<"$T"; chk $? "rule 125 negative: curl's JA4 is not flagged"
r=1; for _ in 1 2 3 4 5; do api "/api/detections?limit=200" | grep -q '"rule_id":1200125' && { r=0; break; }; sleep 2; done; chk $r "rule 125 detection raised"

# 3c. JA4 over IPv6: a v6 TLS client is fingerprinted under its v6 address and tied to the device's IPv4 lease
# (the bench IPv6 is a lab prefix with no internet route: aim at the WAN-side router's sshd — the ClientHello is
# sent as soon as TCP connects, which is all the fingerprint needs)
pi "echo | timeout 6 openssl s_client -connect '[2001:db8:100::1]:22' -servername example.net >/dev/null 2>&1" || true
sleep 2
api /api/tls | grep -q "\"client\":\"[0-9a-f:]*:[0-9a-f:]*\",\"lease\":\"$PIIP\",\"ja4\":\"t13d301000_[^\"]*\",\"sni\":\"example.net\""; chk $? "JA4 over IPv6: the Pi's v6 TLS client fingerprinted + attributed to its lease"

# 4. rule 126: TLS to a Shield-blocked name without Shield (resolved elsewhere -> pinned IP)
IP=$(dig +short "$BLOCKED" A @1.1.1.1 | grep -E '^[0-9.]+$' | head -1)
[ -n "$IP" ] && pi "curl -s -m 10 -o /dev/null --resolve $BLOCKED:443:$IP https://$BLOCKED/" || true
sleep 2
api /api/tls | grep -q "\"sni\":\"$BLOCKED\".*\"shield_bypass\":true"; chk $? "rule 126: TLS to $BLOCKED (DNS bypassed via a pinned IP) flagged shield_bypass"
r=1; for _ in 1 2 3 4 5; do api "/api/detections?limit=200" | grep -q '"rule_id":1200126' && { r=0; break; }; sleep 2; done; chk $r "rule 126 detection raised"

# 5a. G36: rule 124 over IPv6 — 30 answered attempts to the bench host's sshd on its v6 address, attributed to the
# Pi's IPv4 lease (runs FIRST: the rule then cools down per source, so the IPv4 run below re-proves only the path)
pi "for i in \$(seq 1 30); do timeout 2 bash -c '</dev/tcp/2001:db8:100::1/22' 2>/dev/null; done; true"
sleep 3
r=1; for _ in 1 2 3 4 5; do api "/api/detections?limit=200" | grep -q "\"rule_id\":1200124[^}]*\"src_ip\":\"$PIIP\"" && { r=0; break; }; sleep 2; done; chk $r "G36 rule 124 over IPv6: 30 answered attempts to [2001:db8:100::1]:22 detected, attributed to $PIIP"

# 5b. G24a: an IPv6 peer on the signed IOC pack (bench: the WAN-side router, contacted over IPv6 above)
r=1; for _ in 1 2 3 4 5; do api "/api/detections?limit=200" | grep -q "\"rule_id\":1200302[^}]*\"src_ip\":\"$PIIP\"" && { r=0; break; }; sleep 2; done
chk $r "G24a IOC over IPv6: the Pi's IPv6 connection to a listed address raised the IOC detection (302), attributed to $PIIP"

# 5. rule 124: brute force on one answering SSH service (the bench host's sshd on the WAN side)
pi "for i in \$(seq 1 30); do timeout 2 bash -c '</dev/tcp/$SSHT/22' 2>/dev/null; done; true"
sleep 3
r=1; for _ in 1 2 3 4 5; do api "/api/detections?limit=200" | grep -q '"rule_id":1200124' && { r=0; break; }; sleep 2; done; chk $r "rule 124 brute force: 30 attempts to $SSHT:22 (answered) detected"

# 6. G14 hold on the client: traffic stops, revoke restores
S=$(api /api/session); CS=$(python3 -c 'import json,sys;print(json.loads(sys.argv[1])["csrf"])' "$S"); SQ=$(python3 -c 'import json,sys;print(json.loads(sys.argv[1])["next_seq"])' "$S")
R=$(curl -sk -m 10 -b "$JAR" -H "Origin: $MC" -H "X-HQ-CSRF: $CS" --data "kind=hold_ip&target=$PIIP&ttl=120&reason=lan+client+test&seq=$SQ" "$MC/api/actions")
AID=$(python3 -c 'import json,sys;print(json.loads(sys.argv[1]).get("id",0))' "$R" 2>/dev/null || echo 0)
pi "curl -4 -s -m 6 -o /dev/null -w '%{http_code}' http://example.com/" | grep -q 200; [ $? -ne 0 ]; chk $? "G14 hold: the held client cannot reach the internet"
curl -sk -m 10 -b "$JAR" -H "Origin: $MC" -H "X-HQ-CSRF: $CS" -o /dev/null --data "id=$AID&seq=$((SQ + 1))" "$MC/api/actions/revoke"
sleep 1
pi "curl -4 -s -m 10 -o /dev/null -w '%{http_code}' http://example.com/" | grep -q 200; chk $? "G14 revoke: traffic resumes at once"

curl -sk -o /dev/null -m 10 -b "$JAR" -H "Origin: $MC" -H "X-HQ-CSRF: $CS" --data "" "$MC/api/logout"
[ "$ok" -eq "$n" ] && { echo "LAN-CLIENT: PASS ($ok/$n)"; exit 0; } || { echo "LAN-CLIENT: FAIL ($ok/$n)"; exit 1; }
