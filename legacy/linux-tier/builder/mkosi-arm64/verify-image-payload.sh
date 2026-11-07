#!/usr/bin/env bash
# verify-image-payload.sh — ROOTFS-payload static gate for any assembled HookProbe image (the
# missing sibling of verify-pi-bootpart.sh, which only proves the FAT *boot* partition).
#
# WHY THIS EXISTS (field defect 2026-07-09, "006"): the unified Pi image booted to a supervisor
# restart-loop because /usr/share/hookprobe/platforms/ was EMPTY — bootstrap could not classify
# the device, found no `generic.yaml` fallback, exited 1, never wrote the manifest, and the
# supervisor crash-looped on "reading manifest ...: No such file or directory". Root cause: the
# base rootfs (hookprobe-os-arm64.raw) was baked from a HALF-POPULATED mkosi.extra — build-arm64.sh
# aborted mid-staging (after installing the two binaries, before stage-apply + platforms/schema/
# trust) and `mkosi` was run against it anyway. The ENTIRE module payload, trust store, manifest
# schema and platform profiles were silently absent from every image derived from that rootfs.
# The boot-partition gate was green (kernels/DTBs/initrd fine) but no gate inspected the rootfs
# payload — the textbook "passes-build, fails-on-metal" class. This gate closes that hole.
#
# Reads the ext4 rootfs partition(s) directly via `debugfs` (`img?offset=N` form) — NO loop
# device, NO mount, NO root — so it runs on a plain dev box exactly like verify-pi-bootpart.sh.
# Handles BOTH layouts: monolithic /usr (payload at /usr/share|/usr/lib) and split /usr on a
# separate `hp-usr` partition (payload at /share|/lib). A required item passes if it is found in
# ANY ext partition under EITHER path form.
#
#   builder/mkosi-arm64/verify-image-payload.sh [IMG]
#     IMG   default: builder/mkosi-arm64/hookprobe-os-pi.img
#
# Exit codes: 0 = PASS, 1 = FAIL (a real defect — do NOT flash), 2 = SKIP (no image to check).
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
IMG="${1:-${HERE}/hookprobe-os-pi.img}"

if [ ! -f "$IMG" ]; then
  echo "SKIP: no image at $IMG — the privileged build (make-pi-image.sh, needs sudo/loop/mkfs) has not run here. Not a check failure."
  exit 2
fi
command -v debugfs >/dev/null 2>&1 || { echo "ABORT: e2fsprogs (debugfs) not installed"; exit 1; }
command -v sfdisk  >/dev/null 2>&1 || { echo "ABORT: util-linux (sfdisk) not installed";  exit 1; }

FAIL=0
ok()  { echo "  OK   $*"; }
bad() { echo "  FAIL $*"; FAIL=$((FAIL+1)); }

# --- enumerate ext-formatted partitions (no root: sfdisk -J reads a plain file) ---------------
echo "=== enumerating ext partitions in $(basename "$IMG") ==="
mapfile -t OFFSETS < <(sfdisk -J "$IMG" 2>/dev/null | python3 -c '
import json,sys
try: d=json.load(sys.stdin)["partitiontable"]
except Exception: sys.exit(0)
ss=d.get("sectorsize",512)
for p in d.get("partitions",[]):
    print(p["start"]*ss)
')
EXT_OFFSETS=()
for off in "${OFFSETS[@]}"; do
  # A partition is "ext" if debugfs can read its root directory.
  if debugfs -R "ls /" "${IMG}?offset=${off}" >/dev/null 2>&1; then
    EXT_OFFSETS+=("$off")
    echo "  .. ext partition at byte offset $off"
  fi
done
if [ "${#EXT_OFFSETS[@]}" -eq 0 ]; then
  echo "FAIL: no readable ext partition found in $IMG (debugfs could not open any partition)"
  exit 1
fi

# --- helpers: search every ext partition under both monolithic and split-/usr path forms ------
# _exists <relpath-under-usr-or-root>  e.g. "share/hookprobe/platforms/generic.yaml"
# tries  /usr/<rel>  (monolithic)  and  /<rel>  (hp-usr split partition).
_exists() {
  local rel="$1" off
  for off in "${EXT_OFFSETS[@]}"; do
    if debugfs -R "stat \"/usr/${rel}\"" "${IMG}?offset=${off}" 2>/dev/null | grep -q '^Inode:'; then return 0; fi
    if debugfs -R "stat \"/${rel}\""     "${IMG}?offset=${off}" 2>/dev/null | grep -q '^Inode:'; then return 0; fi
  done
  return 1
}
# _dir_count <reldir> — max real-entry count (excl . ..) of that dir across all ext partitions.
_dir_count() {
  local rel="$1" off best=0 n path
  for off in "${EXT_OFFSETS[@]}"; do
    for path in "/usr/${rel}" "/${rel}"; do
      n=$(debugfs -R "ls -l \"$path\"" "${IMG}?offset=${off}" 2>/dev/null \
            | awk 'NF>=9{print $NF}' | grep -vxE '\.|\.\.' | grep -c . || true)
      [ "$n" -gt "$best" ] && best="$n"
    done
  done
  echo "$best"
}

# --- REQUIRED payload (each absence is a boot-breaking defect, mapped to its 006 symptom) ------
echo "=== asserting hookprobe rootfs payload ==="

# 1. Platform profiles — WITHOUT generic.yaml, bootstrap has no fallback → no manifest → the exact
#    006 supervisor restart-loop. All six shipping profiles must be present.
for prof in generic rpi4 rpi5 rk3588 n100 cloud; do
  if _exists "share/hookprobe/platforms/${prof}.yaml"; then ok "platforms/${prof}.yaml"; else bad "platforms/${prof}.yaml MISSING — bootstrap cannot classify/fall back (006 boot-loop)"; fi
done

# 2. Manifest schema — supervisor validates the manifest against it.
if _exists "share/hookprobe/schema/manifest.schema.json"; then ok "schema/manifest.schema.json"; else bad "schema/manifest.schema.json MISSING"; fi

# 3. Trust store — without it EVERY signature:required module is REFUSED (SOC has no detectors).
TRUST_N=$(_dir_count "share/hookprobe/trust")
if [ "$TRUST_N" -ge 1 ]; then ok "trust store present ($TRUST_N key(s))"; else bad "trust store EMPTY — every signed module will be REFUSED"; fi

# 4. Core binaries.
for b in hookprobe-bootstrap hookprobe-supervisor; do
  if _exists "lib/hookprobe/${b}"; then ok "lib/hookprobe/${b}"; else bad "lib/hookprobe/${b} MISSING"; fi
done

# 5. Module payload — the SOC engines. A correctly-staged image carries ~10 module dirs; a
#    dropped-overlay image (like 006) carries ZERO. Require a sane floor, not an exact count.
MOD_N=$(_dir_count "lib/hookprobe/modules")
if [ "$MOD_N" -ge 6 ]; then ok "lib/hookprobe/modules populated ($MOD_N modules)"; else bad "lib/hookprobe/modules has only $MOD_N entries (expected >=6) — module payload dropped from the image"; fi

echo "=== payload gate summary: FAIL count = $FAIL ==="
if [ "$FAIL" -gt 0 ]; then
  echo "RESULT: FAIL — image rootfs payload is INCOMPLETE. Do NOT flash. Rebuild the base rootfs:"
  echo "  build-arm64.sh must fully succeed (stage-apply + platforms/schema/trust) BEFORE 'mkosi build'."
  exit 1
fi
echo "RESULT: PASS — rootfs payload complete (platforms, schema, trust, binaries, modules)."
exit 0
