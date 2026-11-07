#!/usr/bin/env bash
# =============================================================================
# builder/test-artifact-digest-gate.sh — fixture test for the ADR 0016/0017 three-case
# artifact-digest gate (`hookprobe-supervisor --check-artifact-digests`), the ONE Rust
# check `builder/release-pass.sh` and `builder/verify-staging.sh` (check #5) now both
# call instead of each re-implementing a presence-only (or hard-fail-on-placeholder)
# check in shell/python. Exercises the exact host-telemetry-shaped gap this closed:
# a sysext/native-loader module whose `artifacts[].path` is an on-device DEST, resolved
# via its OWN `staging.artifacts[].src -> dest` mapping (NOT a hand-authored second
# convention).
#
# Cases (must match ADR 0016/0017's three-case model exactly):
#   1. PASS       digest present + recomputed match                 -> exit 0
#   2. FAIL       digest present + recomputed MISMATCH (tamper)      -> exit 1 (hard)
#   3. PENDING    a recognized placeholder value                    -> exit 0 (tracked, non-fatal)
#   4. UNVERIFIED staging src cannot be resolved/read in this env    -> exit 0 (tracked, non-fatal)
#   5. D5 hard-fail: signature:required, NO executing-payload artifact declared at all -> exit 1
#   6. status: stub is exempted entirely (never reached)
#
# Usage: builder/test-artifact-digest-gate.sh
# Exit 0 iff every case above produced the verdict this fixture expects.
# =============================================================================
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/.." && pwd)

SUP="$REPO/target/release/hookprobe-supervisor"
[ -x "$SUP" ] || SUP="$REPO/target/debug/hookprobe-supervisor"
if [ ! -x "$SUP" ]; then
  echo "SKIP: $SUP not built -- run 'cargo build -p hookprobe-supervisor' first" >&2
  exit 0
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
MODULES="$TMP/modules"
mkdir -p "$MODULES"

FAIL=0
ok()   { echo "  PASS: $*"; }
bad()  { echo "  FAIL: $*"; FAIL=1; }

# Real bytes to hash against (arbitrary, deterministic per fixture module).
mkdir -p "$TMP/srcs"
printf 'real bytes for the PASS case\n' > "$TMP/srcs/pass-payload.bin"
printf 'real bytes for the FAIL case\n' > "$TMP/srcs/fail-payload.bin"
PASS_HASH="$(sha256sum "$TMP/srcs/pass-payload.bin" | awk '{print $1}')"
FAIL_HASH_REAL="$(sha256sum "$TMP/srcs/fail-payload.bin" | awk '{print $1}')"
# A well-formed (64-char) sha256 that is GUARANTEED to differ from the real bytes'
# hash: take the real digest and flip its first nibble. Using the real hash (rather
# than a hand-typed literal) keeps the fixture a valid-length digest and a genuine
# tamper mismatch — a hardcoded literal was 62 chars (invalid length) and left
# FAIL_HASH_REAL computed-but-unused.
_fail_rest="${FAIL_HASH_REAL#?}"
_fail_first="${FAIL_HASH_REAL%"$_fail_rest"}"
[ "$_fail_first" = "0" ] && _fail_first="1" || _fail_first="0"
FAIL_HASH_WRONG="${_fail_first}${_fail_rest}"

make_module() {
  local id="$1" yaml="$2"
  mkdir -p "$MODULES/$id"
  printf '%s' "$yaml" > "$MODULES/$id/module.yaml"
}

# --- Case 1: PASS (sysext-src resolution + real byte match) --------------------------------
make_module "case-pass" "id: case-pass
version: \"1\"
runtime: sysext
signature: required
staging:
  artifacts:
    - { src: \"{repo}/srcs/pass-payload.bin\", dest: \"/usr/lib/hookprobe/case-pass-loader\", mode: \"0755\" }
artifacts:
  - path: /usr/lib/hookprobe/case-pass-loader
    role: loader
    digest: { alg: sha256, value: \"$PASS_HASH\" }
"

# --- Case 2: FAIL (real MISMATCH -- tamper) -------------------------------------------------
make_module "case-fail" "id: case-fail
version: \"1\"
runtime: sysext
signature: required
staging:
  artifacts:
    - { src: \"{repo}/srcs/fail-payload.bin\", dest: \"/usr/lib/hookprobe/case-fail-loader\", mode: \"0755\" }
artifacts:
  - path: /usr/lib/hookprobe/case-fail-loader
    role: loader
    digest: { alg: sha256, value: \"$FAIL_HASH_WRONG\" }
"

# --- Case 3: PENDING (placeholder value, honest tracked-populated-at-release state) ---------
make_module "case-pending" "id: case-pending
version: \"1\"
runtime: sysext
signature: required
staging:
  artifacts:
    - { src: \"{repo}/srcs/pass-payload.bin\", dest: \"/usr/lib/hookprobe/case-pending-loader\", mode: \"0755\" }
artifacts:
  - path: /usr/lib/hookprobe/case-pending-loader
    role: loader
    digest: { alg: sha256, value: \"PENDING\" }
"

# --- Case 4: UNVERIFIED (staged src genuinely absent in this environment) ------------------
make_module "case-unverified" "id: case-unverified
version: \"1\"
runtime: sysext
signature: required
staging:
  artifacts:
    - { src: \"{bin}/this-binary-was-never-cross-built\", dest: \"/usr/lib/hookprobe/case-unverified-loader\", mode: \"0755\" }
artifacts:
  - path: /usr/lib/hookprobe/case-unverified-loader
    role: loader
    digest: { alg: sha256, value: \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\" }
"

# --- Case 5: D5 hard-fail (signature: required, no executing-payload artifact at all) -------
make_module "case-unprotected" "id: case-unprotected
version: \"1\"
runtime: sysext
signature: required
"

# --- Case 6: status: stub is exempted entirely ----------------------------------------------
make_module "case-stub" "id: case-stub
version: \"1\"
runtime: sysext
status: stub
signature: required
"

# NOTE: `resolve_staging_src`'s `{repo}` placeholder resolves against the PARENT of `--modules`
# (exactly how `gen-staging.sh`/`stage-apply.sh`'s REPO is always `<modules-dir>/..` in this
# repo's own layout) -- so `--modules "$MODULES"` (== `$TMP/modules`) makes `{repo}/srcs/...`
# resolve to `$TMP/srcs/...` automatically; no extra env override needed.
run_case() {
  local id="$1"
  "$SUP" --check-artifact-digests "$id" --modules "$MODULES" 2>&1
}

# Case 1
OUT="$(run_case case-pass)"; RC=$?
if [ "$RC" -eq 0 ] && echo "$OUT" | grep -q "PASS case-pass"; then
  ok "case-pass: exit 0, PASS verdict"
else
  bad "case-pass: expected exit 0 + PASS, got rc=$RC:\n$OUT"
fi

# Case 2
OUT="$(run_case case-fail)"; RC=$?
if [ "$RC" -ne 0 ] && echo "$OUT" | grep -q "FAIL case-fail.*MISMATCH"; then
  ok "case-fail: exit non-zero, FAIL MISMATCH verdict (tamper)"
else
  bad "case-fail: expected non-zero exit + FAIL MISMATCH, got rc=$RC:\n$OUT"
fi

# Case 3
OUT="$(run_case case-pending)"; RC=$?
if [ "$RC" -eq 0 ] && echo "$OUT" | grep -q "PENDING case-pending"; then
  ok "case-pending: exit 0, PENDING verdict (tracked, non-fatal)"
else
  bad "case-pending: expected exit 0 + PENDING, got rc=$RC:\n$OUT"
fi

# Case 4
OUT="$(run_case case-unverified)"; RC=$?
if [ "$RC" -eq 0 ] && echo "$OUT" | grep -q "UNVERIFIED case-unverified"; then
  ok "case-unverified: exit 0, UNVERIFIED verdict (tracked, non-fatal)"
else
  bad "case-unverified: expected exit 0 + UNVERIFIED, got rc=$RC:\n$OUT"
fi

# Case 5
OUT="$(run_case case-unprotected)"; RC=$?
if [ "$RC" -ne 0 ] && echo "$OUT" | grep -q "FAIL case-unprotected"; then
  ok "case-unprotected: exit non-zero, D5 hard-fail (no executing-payload artifact at all)"
else
  bad "case-unprotected: expected non-zero exit + FAIL, got rc=$RC:\n$OUT"
fi

# Case 6
OUT="$(run_case case-stub)"; RC=$?
if [ "$RC" -eq 0 ] && echo "$OUT" | grep -q "status=stub, exempted"; then
  ok "case-stub: exit 0, exempted"
else
  bad "case-stub: expected exit 0 + exempted, got rc=$RC:\n$OUT"
fi

# Case 7: the `all` sweep must be exit non-zero overall (case-fail + case-unprotected present),
# proving a single genuinely-tampered/unprotected module fails the WHOLE sweep -- this is exactly
# what release-pass.sh/verify-staging.sh rely on to hard-fail a real release without needing their
# own per-module loop.
OUT="$("$SUP" --check-artifact-digests all --modules "$MODULES" 2>&1)"; RC=$?
if [ "$RC" -ne 0 ]; then
  ok "all-sweep: exit non-zero when ANY module hard-fails (case-fail + case-unprotected present)"
else
  bad "all-sweep: expected non-zero exit, got rc=$RC:\n$OUT"
fi

echo
if [ "$FAIL" -eq 0 ]; then
  echo "=== test-artifact-digest-gate: ALL CASES PASSED ==="
  exit 0
else
  echo "=== test-artifact-digest-gate: FAILED -- see FAIL lines above ==="
  exit 1
fi
