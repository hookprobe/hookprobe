#!/usr/bin/env bash
# cm5-ota-rollback-check — metal test plan J2: an OS update whose trial never gets a usable WAN must roll back.
#   1. upload + activate a signed image (another build id) → the device trial-boots it;
#   2. during the trial, DHCP on the bench WAN VLAN is blocked (a temporary nft table on the fortress,
#      udp/67 in on enp4s0.100 — removed on exit, whatever happens);
#   3. the trial reports `[OTA] this boot: Trial`, never commits, and after its 5-min deadline reboots;
#   4. the next (cold) boot runs the PREVIOUS build — the one-shot tryboot was spent, config.txt unchanged.
# Needs SUDO_PASS_FILE (fortress sudo) and the same-commit image pair as cm5-ota-check.sh.
#   tools/diagnostics/cm5-ota-rollback-check.sh <owner-key-file> <serial-log> <new-heqk8.img> <new-build-id> <running-build-id> [mc]
set -u -o pipefail
# (no grep -q at the end of a pipe: SIGPIPE + pipefail would turn a match into a failure)
KEY="${1:?owner key}"; LOG="${2:?serial log}"; NEW="${3:?signed image}"; BID="${4:?new build id}"; PREV="${5:?running build id}"
MC="${6:-https://192.168.200.146}"; HERE=$(cd "$(dirname "$0")" && pwd); UP="$HERE/../../os/kernel/tools/hq-upload.py"
SP="${SUDO_PASS_FILE:?SUDO_PASS_FILE}"
# R6 = D: activating an os_image needs an HQMGMT1 envelope signed by the ENROLLED owner key (msg 23); the token only
# opens the session. SIGN_KEY (default ~/heqk-owner-ca/bench-owner.key, bench-only) is enrolled first if none is.
SIGN="${SIGN_KEY:-$HOME/heqk-owner-ca/bench-owner.key}"
ensure_owner() { local e; e=$(python3 "$UP" --mc "$MC" --owner-key-file "$KEY" --insecure --hsh "info" 2>/dev/null | grep -ai "signing key" | grep -c ENROLLED)
  [ "$e" -ge 1 ] && return 0
  local t; t=$(mktemp); python3 -I "$HERE/../../os/kernel/tools/policy-sign.py" enroll-proof "$SIGN" > "$t" && python3 "$UP" --mc "$MC" --owner-key-file "$KEY" --insecure --enroll "$t" >/dev/null 2>&1; local rc=$?; rm -f "$t"; return $rc; }
ensure_owner || echo "     (owner key enrollment failed — the activation will be refused)"
ok=0; n=0
chk() { n=$((n + 1)); if [ "$1" = 0 ]; then echo "ok  $2"; ok=$((ok + 1)); else echo "BAD $2"; fi; }
since() { tail -c +$(($1 + 1)) "$LOG" | tr -d '\r\000'; }
wait_for() { local t=0; while [ $t -lt "$3" ]; do since "$1" | grep -aE "$2" >/dev/null && return 0; sleep 3; t=$((t + 3)); done; return 1; }
unblock() { sudo -S -p '' nft delete table inet hqota < "$SP" 2>/dev/null || true; }
trap unblock EXIT

mark=$(stat -c %s "$LOG")
R=$(python3 "$UP" --mc "$MC" --owner-key-file "$KEY" --insecure --sign-key "$SIGN" --type os_image --file "$NEW" 2>&1); echo "$R" | tail -2
grep -q '^activate: {"ok": true' <<<"$R"; chk $? "upload + activate of the new image"
# block the trial's WAN DHCP before it boots
NFT=$(mktemp); printf 'table inet hqota {\n chain input { type filter hook input priority -10; iifname "enp4s0.100" udp dport 67 drop; }\n}\n' > "$NFT"
sudo -S -p '' nft -f "$NFT" < "$SP"; rm -f "$NFT"
sudo -S -p '' nft list table inet hqota < "$SP" >/dev/null 2>&1; chk $? "bench WAN DHCP blocked for the trial"
wait_for "$mark" "\[OTA\] this boot: Trial" 300; chk $? "the device trial-boots the new image"
since "$mark" | grep -a "build=$BID" >/dev/null; chk $? "the trial runs the uploaded build ($BID)"
# kernel prints: "[OTA] trial not healthy within 300 s (WAN usable=… AP serving=…)"
wait_for "$mark" "\[OTA\] trial not healthy within" 480; chk $? "the trial never gets a usable WAN and gives up after its deadline"
since "$mark" | grep -a "\[OTA\] COMMITTED" >/dev/null; [ $? -ne 0 ]; chk $? "the unhealthy trial never committed"
unblock
# from the original mark: the rollback boot follows the deadline within seconds (a later mark can miss it)
wait_for "$mark" "\[OTA\] this boot: Cold build=$PREV" 300; chk $? "the next boot runs the previous build ($PREV) — rolled back"
echo "OTA-ROLLBACK: $([ $ok = $n ] && echo PASS || echo FAIL) ($ok/$n)"
[ $ok = $n ]
