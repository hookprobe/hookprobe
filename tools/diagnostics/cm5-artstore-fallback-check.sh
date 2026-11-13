#!/usr/bin/env bash
# cm5-artstore-fallback-check — ADR 0059 Phase 0.4 on metal ("the active store half is bad -> the OTHER half loads, not
# the boot-partition copy"; until now QEMU evidence only, [P-artstore]) on a BENCH image built with the `artstore-bench`
# feature (never shipped; tools/ci/shipping_guard.py forbids it). The trigger `artstore tamper-test <type>` (web console
# POST /api/hsh, carried by an owner-signed HQMGMT1 envelope, msg 41 ARTSTORE_TAMPER_TEST bound to the type) flips
# byte 0 of the first data sector of that type's ACTIVE store half on the eMMC — nothing else; the next boot's
# unchanged loader and the real boot fallback do the rest.
#
#   0  preflight: Mission Control up, the bench owner key enrolled (R6 = D), a bench image (/api/health
#      artstore_bench), and this boot did not already fall back for DEVICES
#   1  two operator-signed DEVICES packs, generations N and N+1 (above whatever is active), uploaded + activated with
#      owner-signed envelopes -> both halves valid: /api/upload devices = store gen N+1, rollback_to N
#   2  `artstore tamper-test devices` accepted; serial `[ARTSTORE-BENCH] tampered devices active half H (gen N+1) lba L`;
#      no reboot by itself (still serving, gen N+1 still in force in RAM)
#   3  reboot (hq-upload --reboot, as the other checks)
#   4  serial: the loader REFUSED the stored DEVICES pack, and `devices from the artifact store (generation N)` —
#      the OTHER half, not the boot copy and not N+1; /api/upload devices = store gen N; the device serves normally
#   5  restore: the same trigger again flips the same byte back (the active half is still H in the manifest), reboot
#      -> no refusal, devices = store gen N+1 (the bench is left as it was found, with both halves valid)
#
#   tools/diagnostics/cm5-artstore-fallback-check.sh <owner-key-file> <serial-log> [operator-key] [mc]
#   operator-key (default ~/heqk-owner-ca/policy.key) signs the DEVICES packs (the vendor/operator key the image
#   verifies packs with); SIGN_KEY (default ~/heqk-owner-ca/bench-owner.key) = the enrolled bench OWNER key that signs
#   every envelope (activate, tamper-test).
# Exit 0 = every check ok, 1 = a check failed, 2 = not runnable (not a bench image, or already in fallback).
set -u -o pipefail
KEY="${1:?owner key file}"; LOG="${2:?serial log}"
OPK="${3:-$HOME/heqk-owner-ca/policy.key}"; MC="${4:-https://192.168.200.146}"
HERE=$(cd "$(dirname "$0")" && pwd); ROOT=$(cd "$HERE/../.." && pwd)
SIGN="${SIGN_KEY:-$HOME/heqk-owner-ca/bench-owner.key}"   # the bench OWNER key (must differ from the vendor key)
PSG="python3 -I $ROOT/os/kernel/tools/policy-sign.py"
UP="python3 -I $ROOT/os/kernel/tools/hq-upload.py --mc $MC --owner-key-file $KEY --insecure --sign-key $SIGN"
ok=0; n=0
chk() { n=$((n + 1)); if [ "$1" = 0 ]; then echo "ok  $2"; ok=$((ok + 1)); else echo "BAD $2"; fi; return "$1"; }
T=$(mktemp -d); chmod 700 "$T"; trap 'rm -rf "$T"' EXIT
mark=$(stat -c %s "$LOG")
since() { tail -c +$((mark + 1)) "$LOG" | tr -d '\r\000'; }
waitlog() { for _ in $(seq 1 "$2"); do since | grep -aq "$1" && return 0; sleep 2; done; return 1; }
api() { python3 -I - "$MC" "$KEY" "$1" <<'PY'
import ssl, sys, urllib.parse, urllib.request, http.cookiejar
mc, key, path = sys.argv[1], open(sys.argv[2]).read().strip(), sys.argv[3]
c = ssl.create_default_context(); c.check_hostname = False; c.verify_mode = ssl.CERT_NONE
o = urllib.request.build_opener(urllib.request.HTTPSHandler(context=c), urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
o.open(mc + "/api/login", urllib.parse.urlencode({"token": key}).encode(), timeout=10).read()
print(o.open(mc + path, timeout=10).read().decode())
PY
}
mc_up() { for _ in $(seq 1 80); do curl -sk -o /dev/null -m 5 "$MC/" && return 0; sleep 3; done; return 1; }
mgmt200() { [ "$(curl -sk -o /dev/null -w '%{http_code}' -m 8 "$MC/api/health")" = 200 ]; }
ensure_owner() { local e; e=$(api /api/config | python3 -c 'import json,sys; print(bool(json.load(sys.stdin).get("envelope", {}).get("owner_enrolled")))')
  [ "$e" = True ] && return 0
  $PSG enroll-proof "$SIGN" > "$T/enroll.txt" && $UP --enroll "$T/enroll.txt" > "$T/enroll.out" 2>&1
  local rc=$?; echo "     owner key enrolled for the envelopes (rc=$rc: $(cut -c1-100 "$T/enroll.out"))"; return $rc; }
# dev '<python expr over t>' — the devices row of GET /api/upload
dev() { $UP --status | python3 -c "import json,sys; t=[x for x in json.load(sys.stdin)['types'] if x['type']=='devices'][0]; print($1)"; }
pack() {  # pack GEN -> $T/D<GEN>.TXT + .SIG (the bench list + a harmless marker line naming the generation)
  { grep -v '^#' "$ROOT/docs/design/bench-task26/devices-bench.txt"; printf '02:00:00:00:a5:5a lan_only artstore-fallback-gen%s\n' "$1"; } > "$T/D$1.TXT"
  $PSG sign-devices "$OPK" "$T/D$1.TXT" "$1" "$T/D$1.SIG" >/dev/null; }
upload() { $UP --type devices --sig "$T/D$1.SIG" --file "$T/D$1.TXT" > "$T/up$1" 2>&1; }
tamper() { $UP --hsh "artstore tamper-test devices" 2>&1 | tee "$T/hsh.out"; }
reboot() { mark=$(stat -c %s "$LOG"); $UP --reboot "artstore fallback check: $1" >/dev/null 2>&1; sleep 25; mc_up; }

# ---- 0. preflight ----
mc_up || { echo "ARTSTORE-FALLBACK: Mission Control not reachable at $MC"; exit 2; }
ensure_owner || { echo "ARTSTORE-FALLBACK: the bench owner key is not enrolled"; exit 2; }
[ "$(api /api/health | python3 -c 'import json,sys; print(json.load(sys.stdin).get("artstore_bench"))')" = True ] \
  || { echo "ARTSTORE-FALLBACK: not an artstore-bench image (/api/health has no artstore_bench)"; exit 2; }
[ -r "$OPK" ] || { echo "ARTSTORE-FALLBACK: operator key $OPK not readable (arg 3)"; exit 2; }
mark=$(grep -abo "HEQK Core" "$LOG" | tail -1 | cut -d: -f1); mark=${mark:-0}   # from the last boot banner
if since | grep -aq "stored devices pack REFUSED"; then
  echo "ARTSTORE-FALLBACK: this boot already fell back for DEVICES (a tampered half from an earlier run?) — restore it first:"
  echo "    $UP --hsh 'artstore tamper-test devices'   (flips the same byte back), then reboot"; exit 2
fi
chk 0 "0.1 bench image (artstore_bench), owner key enrolled, no DEVICES fallback in this boot"

# ---- 1. two signed generations: both halves valid ----
G0=$(dev 't["generation"]'); N=$((G0 + 1)); M=$((G0 + 2)); echo "     devices generation in force $G0 -> test N=$N (other half), N+1=$M (active, tampered)"
pack $N; pack $M
upload $N; chk $? "1.1 signed DEVICES gen $N uploaded + activated (owner-signed envelope) ($(grep -o '"ok": [a-z]*' "$T/up$N" | tr '\n' ' '))"
upload $M; chk $? "1.2 signed DEVICES gen $M uploaded + activated ($(grep -o '"ok": [a-z]*' "$T/up$M" | tr '\n' ' '))"
[ "$(dev 't["source"], t["generation"], t.get("rollback_to")')" = "('store', $M, $N)" ]
chk $? "1.3 /api/upload devices: store gen $M, the other half verifies at gen $N ($(dev 't'))"

# ---- 2. the trigger: tamper the ACTIVE half ----
mark=$(stat -c %s "$LOG")
tamper >/dev/null; grep -q "accepted (BENCH build) — tampered active half [AB] (gen $M)" "$T/hsh.out"
chk $? "2.1 'artstore tamper-test devices' accepted with an owner-signed envelope ($(head -1 "$T/hsh.out" | cut -c1-140))"
waitlog "\[ARTSTORE-BENCH\] tampered devices active half [AB] (gen $M) lba [0-9]* — reboot to see the fallback" 15
chk $? "2.2 serial: $(since | grep -a '\[ARTSTORE-BENCH\]' | tail -1 | cut -c1-120)"
LBA=$(since | grep -ao '\[ARTSTORE-BENCH\] tampered devices active half [AB] (gen [0-9]*) lba [0-9]*' | tail -1 | awk '{print $NF}')
HALF=$(since | grep -ao 'tampered devices active half [AB]' | tail -1 | awk '{print $NF}')
sleep 3
mgmt200 && [ "$(dev 't["generation"]')" = "$M" ] && ! since | grep -aq "HEQK Core"
chk $? "2.3 no reboot by itself: still serving, gen $M still in force until the next boot"

# ---- 3. reboot ----
reboot "tampered devices half $HALF"; chk $? "3.1 device back after the reboot"
waitlog "\[AP-STORE\] devices from the artifact store" 60

# ---- 4. the OTHER half is in force ----
since | grep -aq "DEVICES.TXT REFUSED"; chk $? "4.1 serial: the loader refused the tampered active half ($(since | grep -a '\[DEVICES\] per-device policy' | tail -1 | cut -c1-100))"
since | grep -aq "\[AP-STORE\] stored devices pack REFUSED by its loader"; chk $? "4.2 serial: the boot fallback ran for devices"
since | grep -aq "\[AP-STORE\] devices from the artifact store (generation $N)"
chk $? "4.3 serial: devices from the artifact store, generation $N = the OTHER half ($(since | grep -a '\[AP-STORE\] devices from' | tail -1 | cut -c1-100))"
! since | grep -aq "\[AP-STORE\] devices from the artifact store (generation $M)"; chk $? "4.4 serial: NOT the tampered generation $M"
[ "$(dev 't["source"], t["generation"]')" = "('store', $N)" ]; chk $? "4.5 /api/upload devices: store gen $N, not the boot copy ($(dev 't'))"
mgmt200 && sleep 10 && mgmt200 && curl -sk -o /dev/null -m 8 "$MC/"; chk $? "4.6 the device boots and serves normally (/api/health 200 twice, / answers)"
! since | grep -aqE "\[CRASH\]|PANIC|panicked"; chk $? "4.7 no crash / panic in this boot"

# ---- 5. restore: flip the same byte back, reboot -> gen N+1 again, no fallback ----
tamper >/dev/null; grep -q "accepted (BENCH build) — tampered active half $HALF (gen $M) lba $LBA" "$T/hsh.out"
chk $? "5.1 the trigger again on the same half + sector (half $HALF lba $LBA) restores byte 0 ($(head -1 "$T/hsh.out" | cut -c1-120))"
reboot "restore devices half $HALF"; chk $? "5.2 device back after the restore reboot"
waitlog "\[AP-STORE\] devices from the artifact store" 60
! since | grep -aq "stored devices pack REFUSED" && since | grep -aq "\[AP-STORE\] devices from the artifact store (generation $M)"
chk $? "5.3 serial: no refusal, devices from the artifact store at generation $M again"
[ "$(dev 't["source"], t["generation"], t.get("rollback_to")')" = "('store', $M, $N)" ]; chk $? "5.4 /api/upload devices: store gen $M, rollback_to $N (both halves valid)"
[ "$ok" -eq "$n" ] && { echo "ARTSTORE-FALLBACK: PASS ($ok/$n)"; exit 0; } || { echo "ARTSTORE-FALLBACK: FAIL ($ok/$n)"; exit 1; }
