#!/usr/bin/env bash
# cm5-ota-check — production phase 1 / audit A1 on the CM5 bench: an OS-image update over Mission Control.
#   1. a corrupted copy of the new image is refused at `finish` (bad signature) and nothing is written;
#   2. the signed new image (SVN >= running, a different build id, the same HBoot) is uploaded, written to
#      the inactive slot, and the device trial-boots it (tryboot one-shot);
#   3. the trial classifies itself as a TRIAL and commits once the AP serves and the WAN is usable;
#   4. after a power cycle (relay K1) the COLD boot runs the new build.
# Needs: the bench image flashed from the same commit (identical HBoot), the new image built with
#   SVN>=current and HEQK_BUILD_ID=<id> (see docs/design/heqk-metal-test-plan.md, OTA rows).
#   tools/diagnostics/cm5-ota-check.sh <owner-key-file> <serial-log> <new-heqk8.img> <build-id> [mc]
set -u -o pipefail
# (no grep -q on a pipe: it exits at the first match, tail dies of SIGPIPE and pipefail turns a match into a
# failure — that reported a false BAD on metal 2026-11-10 although HBoot printed 'secure boot: PASS')
KEY="${1:?owner key}"; LOG="${2:?serial log}"; NEW="${3:?signed new heqk8.img}"; BID="${4:?build id of the new image}"
MC="${5:-https://192.168.200.146}"; HERE=$(cd "$(dirname "$0")" && pwd); UP="$HERE/../../os/kernel/tools/hq-upload.py"
ok=0; n=0
chk() { n=$((n + 1)); if [ "$1" = 0 ]; then echo "ok  $2"; ok=$((ok + 1)); else echo "BAD $2"; fi; }
since() { tail -c +$(($1 + 1)) "$LOG" | tr -d '\r\000'; }
wait_for() { # mark pattern seconds
  local t=0; while [ $t -lt "$3" ]; do since "$1" | grep -aE "$2" >/dev/null && return 0; sleep 3; t=$((t + 3)); done; return 1; }

# 1. corrupted image: one payload byte flipped -> refused at finish, nothing activated
BAD=$(mktemp); trap 'rm -f "$BAD"' EXIT
cp "$NEW" "$BAD"; python3 - "$BAD" <<'PY'
import sys; p = sys.argv[1]; b = bytearray(open(p, 'rb').read()); b[0x200000 + 7992 + 4096] ^= 0x40; open(p, 'wb').write(b)
PY
R=$(python3 "$UP" --mc "$MC" --owner-key-file "$KEY" --insecure --type os_image --file "$BAD" 2>&1)
grep -q "bad signature" <<<"$R"; chk $? "a corrupted image is refused at finish (bad signature)"
! grep -q '^activate: {"ok": true' <<<"$R"; chk $? "the corrupted image is never activated"

# 2. the real image
mark=$(stat -c %s "$LOG")
R=$(python3 "$UP" --mc "$MC" --owner-key-file "$KEY" --insecure --type os_image --file "$NEW" 2>&1); echo "$R" | tail -3
grep -q '^activate: {"ok": true' <<<"$R"; chk $? "upload: begin / chunks / finish (verified) / activate (written + re-hashed from the slot)"
wait_for "$mark" "\[OTA\] tryboot flag set" 60; chk $? "the device trial-boots the new slot (tryboot one-shot)"
wait_for "$mark" "\[OTA\] this boot: Trial" 240; chk $? "the trial boot classifies itself as a TRIAL"
since "$mark" | grep -a "build=$BID" >/dev/null; chk $? "the trial runs the uploaded build ($BID)"
wait_for "$mark" "\[OTA\] COMMITTED" 360; chk $? "commit-on-health: committed once the AP serves and the WAN is usable"

# 3. cold boot runs the new build
mark=$(stat -c %s "$LOG")
python3 "$HERE/cm5-relay.py" --backend nano --dev auto cycle >/dev/null 2>&1
wait_for "$mark" "\[OTA\] this boot: Cold build=$BID" 300; chk $? "after a power cycle the COLD boot runs the new build"
since "$mark" | grep -a "secure boot: PASS" >/dev/null; chk $? "HBoot verified the committed image at the cold boot"

echo "OTA: $([ $ok = $n ] && echo PASS || echo FAIL) ($ok/$n)"
[ $ok = $n ]
