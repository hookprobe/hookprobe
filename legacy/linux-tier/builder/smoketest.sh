#!/usr/bin/env bash
# =============================================================================
# smoketest.sh — validate a built HookProbe OS image by running the first-boot
# self-provisioning chain INSIDE it and asserting each stage. This is the Gate-2
# check (software flow) that runs after `podman build`, before the VM/hardware boot.
#
#   Usage: builder/smoketest.sh [IMAGE] [--plan builder/generated/staging-plan.json]
#          (default IMAGE: hookprobe-os:debian-min)
#
# It proves, on the real image userspace: binaries present → bootstrap writes a
# SIGNED + classified manifest → supervisor VERIFIES the signature → AEGIS reconciles
# one intent into network artifacts → network-apply --check is clean. Read-only;
# `--net=host` so the probe sees real interfaces. Exit 0 = all green.
#
# Section 6 (ADR 0015 D3): runs builder/verify-staging.sh against the BUILT IMAGE's
# actual filesystem (exported via `podman export`, not just the plan-only checks) —
# fails the smoke run on any orphaned registry entry / hollow preset / out-of-registry
# artifact, catching the exact "hollow bootc SOC" class of bug in a built image.
# =============================================================================
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
IMG=${1:-hookprobe-os:debian-min}
PLAN="$HERE/generated/staging-plan.json"
while [ $# -gt 0 ]; do
  case "$1" in
    --plan) PLAN="$2"; shift 2 ;;
    *) shift ;;
  esac
done

podman run --rm -i --net=host "$IMG" bash -s <<'SMOKE'
set -uo pipefail
PASS=0; FAIL=0
ok()  { echo "  PASS: $*"; PASS=$((PASS+1)); }
bad() { echo "  FAIL: $*"; FAIL=$((FAIL+1)); }
M=/var/lib/hookprobe/manifest.json
mkdir -p /var/lib/hookprobe /run/hookprobe/network /tmp/empty-modules

echo "## 1. binaries + symlinks"
for b in /usr/lib/hookprobe/hookprobe-bootstrap /usr/bin/hookprobe-supervisor \
         /usr/lib/hookprobe/network-apply.sh /usr/lib/hookprobe/trust-reconcile.sh; do
  [ -e "$b" ] && ok "exists $b" || bad "missing $b"
done

echo "## 2. bootstrap → signed + classified manifest"
if /usr/lib/hookprobe/hookprobe-bootstrap --out "$M" --platforms /usr/share/hookprobe/platforms >/tmp/bs.log 2>&1; then
  ok "bootstrap ran"
  cls=$(jq -r '.platform.class // ""' "$M" 2>/dev/null)
  sig=$(grep -ao 'ed25519-puf' "$M" | head -1)
  echo "   class=$cls sig=$sig"
  { [ -n "$cls" ] && [ "$cls" != "null" ] && [ "$sig" = "ed25519-puf" ]; } \
    && ok "manifest classified ($cls) + ed25519-puf signed" || bad "manifest unsigned/unclassified"
else bad "bootstrap failed"; tail -5 /tmp/bs.log; fi

echo "## 3. supervisor VERIFIES the manifest signature (refuses a tampered one)"
[ -f "$M" ] && /usr/bin/hookprobe-supervisor "$M" --modules /tmp/empty-modules >/tmp/sup.log 2>&1
grep -qiE "signature: VERIFIED" /tmp/sup.log 2>/dev/null && ok "supervisor VERIFIED" || { bad "supervisor verify"; tail -5 /tmp/sup.log 2>/dev/null; }

echo "## 4. AEGIS network reconcile (one intent → artifacts)"
INTENT=/etc/hookprobe/network.yaml
if [ -f "$M" ] && [ -f "$INTENT" ]; then
  if /usr/bin/hookprobe-supervisor "$M" --reconcile-network "$INTENT" --network-write /run/hookprobe/network >/tmp/net.log 2>&1; then
    n=$(find /run/hookprobe/network -type f 2>/dev/null | wc -l)
    [ "$n" -ge 3 ] && ok "reconcile produced $n artifacts" || { bad "too few artifacts ($n)"; tail -5 /tmp/net.log; }
  else bad "reconcile-network failed"; tail -5 /tmp/net.log; fi
else bad "intent not installed at $INTENT"; fi

echo "## 5. network-apply --check (dry run)"
STAGE=/run/hookprobe/network /usr/lib/hookprobe/network-apply.sh --check >/tmp/apply.log 2>&1 \
  && ok "network-apply --check clean" || { bad "network-apply --check"; tail -4 /tmp/apply.log; }

echo; echo "=== SMOKE RESULT: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
SMOKE
SMOKE_RC=$?

echo
echo "## 6. staging completeness (ADR 0015 D3 gate — builder/verify-staging.sh)"
if [ ! -f "$PLAN" ]; then
  echo "  SKIP: $PLAN not found — run builder/gen-staging.sh --arch <arch> first"
  STAGING_RC=0
else
  IMGROOT="$(mktemp -d)"
  trap 'rm -rf "$IMGROOT"' EXIT
  CID="$(podman create "$IMG" true 2>/dev/null)"
  if [ -n "$CID" ] && podman export "$CID" | tar -x -C "$IMGROOT" 2>/dev/null; then
    podman rm -f "$CID" >/dev/null 2>&1 || true
    "$HERE/verify-staging.sh" --plan "$PLAN" --root "$IMGROOT"
    STAGING_RC=$?
  else
    echo "  FAIL: could not export $IMG's filesystem for the staging gate"
    podman rm -f "$CID" >/dev/null 2>&1 || true
    STAGING_RC=1
  fi
fi

echo
if [ "$SMOKE_RC" -eq 0 ] && [ "$STAGING_RC" -eq 0 ]; then
  echo "=== smoketest.sh: ALL GATES PASSED (first-boot chain + staging completeness) ==="
  exit 0
else
  echo "=== smoketest.sh: FAILED (first-boot chain rc=$SMOKE_RC, staging gate rc=$STAGING_RC) ==="
  exit 1
fi
