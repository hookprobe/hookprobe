#!/usr/bin/env bash
# cm5-upload-check — ADR 0056 on metal: a newer operator-signed Shield blocklist uploaded over Mission Control
# HTTPS takes effect live, survives a POWER CYCLE from the artifact store, an older generation is refused,
# and a tampered pack is refused. Restores the bench list at the end (a reflash also resets the store).
#   tools/diagnostics/cm5-upload-check.sh <owner-key-file> <serial-log> <operator-key> [mc] [pi]
set -u -o pipefail
KEY="${1:?owner key file}"; LOG="${2:?serial log}"; OPK="${3:?operator (policy) signing key}"
MC="${4:-https://192.168.200.146}"; PI="${5:-claude@10.200.0.4}"; DOMAIN=iana.org
HERE=$(cd "$(dirname "$0")" && pwd); ROOT=$(cd "$HERE/../.." && pwd)
SIGN="python3 -I $ROOT/os/kernel/tools/policy-sign.py"; UP="python3 -I $ROOT/os/kernel/tools/hq-upload.py --mc $MC --owner-key-file $KEY --insecure"
ok=0; n=0
chk() { n=$((n + 1)); if [ "$1" = 0 ]; then echo "ok  $2"; ok=$((ok + 1)); else echo "BAD $2"; fi; }
pi() { ssh -o BatchMode=yes -o ConnectTimeout=8 "$PI" "$@"; }
resolves() { pi "dig +short +time=3 +tries=1 @10.99.0.1 $DOMAIN A" | grep -qE '^[0-9.]+$'; }
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
BENCH="$ROOT/docs/design/bench-task26/block-bench.txt"
{ cat "$BENCH"; printf '#! category=general\n%s\n' "$DOMAIN"; } > "$T/BLOCK.TXT"
# generations above whatever is active now (a store from an earlier run survives until a reflash)
G0=$($UP --status | python3 -c 'import json,sys; print(max([t["generation"] for t in json.load(sys.stdin)["types"] if t["type"]=="shield_block"]+[0]))')
G1=$((G0 + 10)); G2=$((G0 + 11)); echo "active shield_block generation $G0 -> test $G1, restore $G2"
$SIGN sign-blocklist "$OPK" "$T/BLOCK.TXT" $G1 "$T/BLOCK.SIG" >/dev/null
$SIGN sign-blocklist "$OPK" "$T/BLOCK.TXT" 1 "$T/OLD.SIG" >/dev/null
sed "s/doubleclick/doublecl1ck/" "$T/BLOCK.TXT" > "$T/TAMPERED.TXT"
resolves; chk $? "$DOMAIN resolves with the flashed list"
$UP --type shield_block --sig "$T/BLOCK.SIG" --file "$T/TAMPERED.TXT" > "$T/r" 2>&1; R=$(cat "$T/r")
grep -q '"ok": false' <<<"$R" && grep -qi 'digest\|signature' <<<"$R"; chk $? "a tampered list is refused at finish ($(grep finish "$T/r" | cut -c1-120))"
$UP --type shield_block --sig "$T/BLOCK.SIG" --file "$T/BLOCK.TXT" > "$T/r" 2>&1; chk $? "signed gen-$G1 list uploaded + verified + activated ($(grep activate "$T/r" | cut -c1-120))"
sleep 1
resolves; [ $? -ne 0 ]; chk $? "live: $DOMAIN now blocked (no reflash)"
S=$($UP --status)
python3 -c 'import json,sys; d=json.loads(sys.argv[1]); t=[x for x in d["types"] if x["type"]=="shield_block"][0]; sys.exit(0 if t["source"]=="store" and t["generation"]==int(sys.argv[2]) and any(a["result"]=="activated" for a in d["activations"]) else 1)' "$S" $G1
chk $? "/api/upload: shield_block from the store, generation $G1, journal activation record"
$UP --type shield_block --sig "$T/OLD.SIG" --file "$T/BLOCK.TXT" > "$T/r" 2>&1; R=$(cat "$T/r")
grep -q 'rollback refused' <<<"$R"; chk $? "an older generation (1) is refused (anti-rollback)"
echo "== power cycle (relay K1)"
mark=$(stat -c %s "$LOG")
python3 "$HERE/cm5-relay.py" --backend nano --dev auto cycle >/dev/null 2>&1
for _ in $(seq 1 60); do tail -c +$((mark + 1)) "$LOG" | tr -d '\r\000' | grep -a "\[AP-STORE\] artifact store" >/dev/null && break; sleep 3; done
L=$(tail -c +$((mark + 1)) "$LOG" | tr -d '\r\000' | grep -a "\[AP-STORE\]" | tail -3); echo "$L" | sed 's/^/  /'
grep -q "shield_block from the artifact store (generation $G1)" <<<"$L"; chk $? "after the power cycle the list loads from the artifact store"
for _ in $(seq 1 40); do pi "ip route | grep -q '^default via 10.99.0.1'" && curl -sk -o /dev/null -m 5 "$MC/" && break; sleep 3; done
sleep 5
resolves; [ $? -ne 0 ]; chk $? "$DOMAIN still blocked after the power cycle"
$SIGN sign-blocklist "$OPK" "$BENCH" $G2 "$T/BENCH.SIG" >/dev/null
$UP --type shield_block --sig "$T/BENCH.SIG" --file "$BENCH" > "$T/r" 2>&1; chk $? "restore: the bench list re-uploaded (gen $G2)"
sleep 1
resolves; chk $? "$DOMAIN resolves again"
[ "$ok" -eq "$n" ] && { echo "UPLOAD: PASS ($ok/$n)"; exit 0; } || { echo "UPLOAD: FAIL ($ok/$n)"; exit 1; }
