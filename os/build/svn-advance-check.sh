#!/usr/bin/env bash
# svn-advance-check — validate the anti-rollback SVN ADVANCEMENT procedure on the host, with the real
# signer (heqk-sign mirrors HBoot's verify: BOTH signatures over the SVN-bound message AND svn >= floor).
# No hardware, no fuses: this checks the compile-time-floor procedure HBoot enforces today
# (hboot/src/rollback.rs COMPILE_FLOOR; OTP block-3 thermometer stays blank by operator decision 2026-11-08).
#
#   os/build/svn-advance-check.sh [PAYLOAD] [N]
#     PAYLOAD  kernel payload to sign (default: objcopy of the factory-built kernel ELF)
#     N        the current release SVN (default 1); the check advances to N+1
# Keys: HEQK_KEYDIR (default ~/heqk-sign/keys). Exit 0 = every expectation held.
set -u -o pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
KEYDIR="${HEQK_KEYDIR:-$HOME/heqk-sign/keys}"
SIGNER="$HERE/heqk-sign/target/release/heqk-sign"
N="${2:-1}"
M=$((N + 1))
TMP="$(mktemp -d)"
trap 'rm -r "$TMP"' EXIT

[ -x "$SIGNER" ] || (cd "$HERE/heqk-sign" && CARGO_TARGET_DIR="$HERE/heqk-sign/target" cargo build --release -q) || { echo "cannot build heqk-sign"; exit 1; }
PAYLOAD="${1:-}"
if [ -z "$PAYLOAD" ]; then
  ELF="$ROOT/os/kernel/target/factory/aarch64-unknown-none-softfloat/release/kernel"
  [ -f "$ELF" ] || { echo "no payload given and no factory kernel at $ELF (run the factory first)"; exit 1; }
  llvm-objcopy -O binary "$ELF" "$TMP/kernel.bin"
  PAYLOAD="$TMP/kernel.bin"
fi

"$SIGNER" sign "$KEYDIR" "$PAYLOAD" "$N" "$TMP/old.ed" "$TMP/old.pq" > /dev/null
"$SIGNER" sign "$KEYDIR" "$PAYLOAD" "$M" "$TMP/new.ed" "$TMP/new.pq" > /dev/null

fails=0
check() { # <label> <expect PASS|FAIL> <svn claimed> <floor> <sig prefix>
  if "$SIGNER" verify "$KEYDIR" "$PAYLOAD" "$3" "$4" "$TMP/$5.ed" "$TMP/$5.pq" > "$TMP/out" 2>&1; then got=PASS; else got=FAIL; fi
  if [ "$got" = "$2" ]; then mark=ok; else mark=WRONG; fails=$((fails + 1)); fi
  printf '  %-5s %-62s expect %-4s got %s\n' "$mark" "$1" "$2" "$got"
}
echo "== SVN advancement $N -> $M (payload $(sha256sum "$PAYLOAD" | cut -c1-16), keys $KEYDIR)"
check "release N   (svn $N) under the current floor $N"          PASS "$N" "$N" old
check "release N+1 (svn $M) under the current floor $N"          PASS "$M" "$N" new
check "release N+1 (svn $M) under the advanced floor $M"         PASS "$M" "$M" new
check "release N   (svn $N) under the advanced floor $M (rollback)" FAIL "$N" "$M" old
check "release N relabelled svn $M (signature binds the SVN)"    FAIL "$M" "$M" old
check "release N+1 relabelled svn $N (signature binds the SVN)"  FAIL "$N" "$N" new
if [ "$fails" -eq 0 ]; then
  echo "SVN-ADVANCE: PASS — a release built with SVN=$M boots on today's floor, and once COMPILE_FLOOR=$M ships, SVN=$N images are refused"
else
  echo "SVN-ADVANCE: FAIL ($fails unexpected results)"
  exit 1
fi
