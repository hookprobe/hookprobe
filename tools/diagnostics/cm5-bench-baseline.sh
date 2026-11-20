#!/usr/bin/env bash
# cm5-bench-baseline — put the bench CM5 back on the image's own setup before / between checks that change the
# configuration: a policy-only HQCFG1 bundle with the bench policy (docs/design/bench-task26/policy-bench.txt), so the
# per-file WAN (VLAN + management VLAN) and the image's Wi-Fi apply again. Removing a WAN / Wi-Fi section is a
# management-plane change: the owner's confirm is given here, as the owner would. Idempotent: a no-op when the bench
# policy alone is already in force.
#   tools/diagnostics/cm5-bench-baseline.sh <owner-key-file> <serial-log> [mc]
set -u -o pipefail
KEY="${1:?owner key file}"; LOG="${2:?serial log}"; MC="${3:-https://192.168.200.146}"
HERE=$(cd "$(dirname "$0")" && pwd); ROOT=$(cd "$HERE/../.." && pwd)
SIGN="${SIGN_KEY:-$HOME/heqk-owner-ca/bench-owner.key}"   # the enrolled owner key (R6 = D)
UP="python3 -I $ROOT/os/kernel/tools/hq-upload.py --mc $MC --owner-key-file $KEY --insecure --sign-key $SIGN"
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
# A full flash wipes the enrolled owner signing key (R6 = D): without it every activation below is refused and the
# baseline reports "generation N not in force" (2026-11-20, first check after a flash). Enrol it first, as the OTA
# check does; a no-op when it is already enrolled.
if ! python3 -I "$ROOT/os/kernel/tools/hq-upload.py" --mc "$MC" --owner-key-file "$KEY" --insecure --hsh "info" 2>/dev/null | grep -ai "signing key" | grep -q ENROLLED; then
  python3 -I "$ROOT/os/kernel/tools/policy-sign.py" enroll-proof "$SIGN" > "$T/enroll" \
    && python3 -I "$ROOT/os/kernel/tools/hq-upload.py" --mc "$MC" --owner-key-file "$KEY" --insecure --enroll "$T/enroll" >/dev/null 2>&1 \
    || echo "   (owner signing key could not be enrolled — the activation will be refused)"
fi
cfg() { python3 -I - "$MC" "$KEY" <<'PY'
import json, ssl, sys, time, urllib.parse, urllib.request, http.cookiejar
mc, key = sys.argv[1], open(sys.argv[2]).read().strip()
c = ssl.create_default_context(); c.check_hostname = False; c.verify_mode = ssl.CERT_NONE
for i in range(5):   # the HTTPS rate limiter may reset a burst of new sessions (#129)
    try:
        o = urllib.request.build_opener(urllib.request.HTTPSHandler(context=c), urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        o.open(mc + "/api/login", urllib.parse.urlencode({"token": key}).encode(), timeout=10).read()
        print(o.open(mc + "/api/config", timeout=10).read().decode()); break
    except Exception:
        time.sleep(2 * (i + 1))
PY
}
# hqcfg takes canonical ASCII: drop comments / blanks (the bench file's comments are not ASCII)
sed -e 's/[[:space:]]*$//' -e '/^#/d' -e '/^$/d' "$ROOT/docs/design/bench-task26/policy-bench.txt" > "$T/p.txt"
# the device digests the section as encoded in the bundle (hqcfg from_legacy), not the text file
want=$(python3 -I -c 'import hashlib, sys; sys.path.insert(0, sys.argv[1]); import hqcfg; print(hashlib.sha256(hqcfg.from_legacy("policy", open(sys.argv[2], "rb").read())).hexdigest())' "$ROOT/os/kernel/tools" "$T/p.txt")
C=$(cfg)
read -r secs pol gen <<<"$(python3 -c 'import json,sys; d=json.loads(sys.argv[1]); s=d.get("sections") or {}
print(",".join(k for k in ("wan","wifi") if (s.get(k) or {}).get("present")) or "-", (s.get("policy") or {}).get("digest") or "-", max(d["generation"], d["floor"]))' "$C")"
if [ "$secs" = "-" ] && [ "$pol" = "$want" ]; then echo "BASELINE: already in force (generation $gen)"; exit 0; fi
G=$((gen + 1)); mark=$(stat -c %s "$LOG")
python3 -I "$ROOT/os/kernel/tools/hqcfg.py" bundle "$SIGN" $G "$T/b.bin" "$T/b.sig" --policy "$T/p.txt" >/dev/null || { echo "BASELINE: FAIL — bundle"; exit 1; }
$UP --type config --sig "$T/b.sig" --file "$T/b.bin" > "$T/r" 2>&1
grep -q '"needs_confirm": true' "$T/r" && { sleep 10; $UP --config-confirm "bench baseline" >/dev/null 2>&1; }
for _ in $(seq 1 30); do tail -c +$((mark + 1)) "$LOG" | tr -d '\r\000' | grep -aq "bundle generation $G COMMITTED" && break; sleep 2; done
sleep 20   # the per-file WAN comes back (DHCP in the loop)
C=$(cfg); ok=$(python3 -c 'import json,sys; d=json.loads(sys.argv[1]); s=d.get("sections") or {}
print("yes" if d.get("generation")==int(sys.argv[2]) and not (s.get("wan") or {}).get("present") and not (s.get("wifi") or {}).get("present") else "no")' "$C" "$G")
echo "BASELINE: $([ "$ok" = yes ] && echo "PASS — generation $G (bench policy only; before: sections $secs)" || echo "FAIL — generation $G not in force")"
[ "$ok" = yes ]
