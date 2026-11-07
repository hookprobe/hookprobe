#!/usr/bin/env bash
# builder/verify-staging.sh — ADR 0015 D3: the verification gate. Silent orphaning becomes
# a build error. Invoked by builder/smoketest.sh (Gate 2, inside a built image) AND
# standalone in CI against just the generated plan (no privileged build needed).
#
# Checks (D3):
#   1. No orphaned registry entry — every modules/*/module.yaml with `signature: required`
#      is either staged+signed (or gate:{capability,reason}) in the plan.
#   2. No hollow preset — every `enable`/`disable` line in the base + generated presets
#      resolves to a unit file that is ACTUALLY staged somewhere (a module action, a
#      base/units/ file, or the small allowlist of base-OS/apt-provided units). THIS is
#      the direct catch for the "hollow bootc SOC" disease (ADR 0015 context).
#   3. No staged artifact outside the registry (best-effort; only meaningful with --root).
#   4. Parity — the staged module id set is identical across two plans (e.g. arm64 vs
#      amd64), modulo arch-specific artifact differences (checked by id only).
#
# Usage:
#   builder/verify-staging.sh --plan builder/generated/staging-plan.json
#                             [--root <staged-tree-or-image-root>]
#                             [--parity-with <other-plan.json>]
#                             [--base-preset base/config/presets/80-hookprobe.preset]
#                             [--gen-preset  builder/generated/85-hookprobe-modules.preset]
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/.." && pwd)

PLAN="$REPO/builder/generated/staging-plan.json"
ROOT=""
PARITY_WITH=""
BASE_PRESET="$REPO/base/config/presets/80-hookprobe.preset"
GEN_PRESET="$REPO/builder/generated/85-hookprobe-modules.preset"

while [ $# -gt 0 ]; do
  case "$1" in
    --plan)         PLAN="$2"; shift 2 ;;
    --root)         ROOT="$2"; shift 2 ;;
    --parity-with)  PARITY_WITH="$2"; shift 2 ;;
    --base-preset)  BASE_PRESET="$2"; shift 2 ;;
    --gen-preset)   GEN_PRESET="$2"; shift 2 ;;
    *) echo "verify-staging.sh: unknown arg $1" >&2; exit 1 ;;
  esac
done

[ -f "$PLAN" ] || { echo "verify-staging.sh: FAIL: plan not found: $PLAN (run builder/gen-staging.sh first)"; exit 1; }

FAIL=0
fail() { echo "FAIL: $*"; FAIL=1; }
ok()   { echo "PASS: $*"; }

# ---------------------------------------------------------------------------
# 1. No orphaned registry entry.
# ---------------------------------------------------------------------------
echo "## 1. no orphaned registry entry (every signature:required module: staged+signed OR gated-with-a-reason)"
mapfile -t REGISTRY_IDS < <(find "$REPO/modules" -mindepth 2 -maxdepth 2 -name module.yaml -printf '%h\n' | xargs -n1 basename | sort)
for id in "${REGISTRY_IDS[@]}"; do
  entry_json=$(jq -c --arg id "$id" '.modules[] | select(.id == $id)' "$PLAN")
  if [ -z "$entry_json" ]; then
    fail "orphan: $id has a module.yaml but is ABSENT from the plan ($PLAN is stale — regenerate it)"
    continue
  fi
  status=$(jq -r '.status // "null"' <<<"$entry_json")
  if [ "$status" = "stub" ]; then
    ok "$id: status=stub, exempted (shipped: no)"
    continue
  fi
  sig=$(jq -r '.signature' <<<"$entry_json")
  gate=$(jq -c '.gate' <<<"$entry_json")
  if [ "$sig" != "required" ]; then
    ok "$id: signature=$sig, not subject to the orphan check"
    continue
  fi
  if [ "$gate" != "null" ]; then
    reason=$(jq -r '.reason' <<<"$gate")
    if [ -n "$reason" ] && [ "$reason" != "null" ]; then
      ok "$id: gated (capability-managed, reason recorded): $reason"
      continue
    fi
    fail "orphan: $id has a gate with an EMPTY reason — not a valid staged-but-managed record"
    continue
  fi
  has_sig_action=$(jq -r '[.actions[] | select(.requires_sig == true)] | length' <<<"$entry_json")
  if [ "$has_sig_action" -lt 1 ]; then
    fail "orphan: $id is signature:required but neither staged+signed nor capability-gated-with-a-reason"
    continue
  fi
  if [ -n "$ROOT" ]; then
    missing=0
    while IFS= read -r dest; do
      [ -e "$ROOT$dest" ] || { fail "orphan: $id action dest not present under --root: $dest"; missing=1; }
    done < <(jq -r '.actions[].dest' <<<"$entry_json")
    [ "$missing" -eq 0 ] && ok "$id: staged+signed, verified present under --root $ROOT"
  else
    ok "$id: staged+signed in the plan (no --root given — physical presence not checked)"
  fi
done

# ---------------------------------------------------------------------------
# 2. No hollow preset — the direct catch for the "hollow bootc SOC" bug.
# ---------------------------------------------------------------------------
echo "## 2. no hollow preset (every enable/disable line resolves to a staged unit)"
# Units provided by base/units/ (always shipped identically by every build path).
mapfile -t BASE_UNITS < <(find "$REPO/base/units" -maxdepth 1 -type f -printf '%f\n' | sort)
# Units provided by the base OS / apt packages (systemd itself, openvswitch-switch's own
# package units) — never staged by a module.yaml, legitimately absent from the plan.
ALLOWLIST=(systemd-pcrphase.service systemd-pcrphase-sysinit.service
           openvswitch-switch.service ovsdb-server.service ovs-vswitchd.service
           # wpa_supplicant.service ships with the `wpasupplicant` apt package (added to mkosi.conf
           # for STATION-role Wi-Fi uplinks); the 80-hookprobe.preset DISABLES it by default (ADR
           # 0034 — never run a supplicant on an AP-role radio), so the disable line is legitimate.
           wpa_supplicant.service)

# NOTE: deliberately checks ONLY base/units/ + the allowlist + the plan's own ACTIONS
# (never the plan's `preset[]` list) — `preset[]` is DERIVED from a module's actions by
# gen-staging.sh, so cross-checking a preset line against `preset[]` would be circular
# (a plan that hand-corrupted/dropped an action while leaving `preset[]` stale would
# wrongly pass). Actions are the one place that records "this unit is ACTUALLY staged".
is_allowlisted_unit() {
  local u="$1"
  for a in "${ALLOWLIST[@]}"; do [ "$a" = "$u" ] && return 0; done
  return 1
}

is_known_unit() {
  local u="$1"
  for b in "${BASE_UNITS[@]}"; do [ "$b" = "$u" ] && return 0; done
  is_allowlisted_unit "$u" && return 0
  jq -e --arg u "$u" '.modules[].actions[]? | select(.dest | endswith("/"+$u))' "$PLAN" >/dev/null 2>&1 && return 0
  return 1
}

check_preset_file() {
  local f="$1"
  [ -f "$f" ] || { echo "  (no such preset file: $f — skipping)"; return; }
  while IFS= read -r line; do
    case "$line" in
      \#*|"") continue ;;
    esac
    # shellcheck disable=SC2206
    words=($line)
    verb="${words[0]:-}"
    unit="${words[1]:-}"
    [ "$verb" = "enable" ] || [ "$verb" = "disable" ] || continue
    [ -n "$unit" ] || continue
    if ! is_known_unit "$unit"; then
      fail "hollow preset: $(basename "$f") ${verb}s ${unit} which is not installed anywhere (not in base/units/, not in the plan's staged actions, not on the base-OS allowlist)"
      continue
    fi
    # Structural check passed. If --root was given, ALSO assert the unit file is
    # PHYSICALLY present there — the literal hollow-SOC bug (a build path whose plan
    # says a unit is staged, but that specific run never actually placed the file).
    # Allowlisted units (systemd/apt-package-provided) are exempt from the physical
    # check: they legitimately don't exist in a pre-install staging tree (e.g.
    # mkosi.extra/ before mkosi lays down packages) — only a fully assembled/booted
    # rootfs would have them, which is out of scope for this plan-and-stage-tree gate.
    if [ -n "$ROOT" ] && ! is_allowlisted_unit "$unit"; then
      if [ -e "$ROOT/usr/lib/systemd/system/$unit" ]; then
        ok "$(basename "$f"): '$verb $unit' resolves to a staged unit, present under --root"
      else
        fail "hollow preset: $(basename "$f") ${verb}s ${unit}, which the plan claims is staged but is NOT physically present under --root ($ROOT/usr/lib/systemd/system/$unit)"
      fi
    else
      ok "$(basename "$f"): '$verb $unit' resolves to a staged/known unit$([ -n "$ROOT" ] && echo " (base-OS/apt-provided — not checked physically here)" || echo " (no --root — physical presence not checked)")"
    fi
  done < "$f"
}

check_preset_file "$BASE_PRESET"
check_preset_file "$GEN_PRESET"

# ---------------------------------------------------------------------------
# 3. No staged artifact outside the registry (best-effort; needs --root).
# ---------------------------------------------------------------------------
echo "## 3. no staged artifact outside the registry (best-effort, needs --root)"
# NOTE (security F2/F3 fix — unify the trust path): the trust ANCHOR (release.pub) every
# module.sig verifies against now stages ONLY at /usr/share/hookprobe/trust — outside
# every directory this loop scans (usr/lib/hookprobe/{modules,bin,bpf}) — so it never
# needs (and can no longer hit) a special-case exemption here; it just isn't examined by
# this registry-membership check, which is scoped to the module registry tree, not the
# trust store.
if [ -n "$ROOT" ]; then
  for d in usr/lib/hookprobe/modules usr/lib/hookprobe/bin usr/lib/hookprobe/bpf; do
    [ -d "$ROOT/$d" ] || continue
    while IFS= read -r f; do
      rel="/${f#"$ROOT/"}"
      jq -e --arg d "$rel" '.modules[].actions[]? | select(.dest == $d)' "$PLAN" >/dev/null 2>&1 \
        && ok "traced to the registry: $rel" \
        || fail "staged outside the registry: $rel (no module.yaml action produces this path)"
    done < <(find "$ROOT/$d" -type f)
  done
else
  echo "  (no --root given — skipped; this check needs a built/staged tree)"
fi

# ---------------------------------------------------------------------------
# 4. Parity — identical staged module id set across two plans (e.g. arm64 vs amd64).
# ---------------------------------------------------------------------------
echo "## 4. arm64/bootc module-set parity (needs --parity-with)"
if [ -n "$PARITY_WITH" ]; then
  if [ ! -f "$PARITY_WITH" ]; then
    fail "parity: $PARITY_WITH not found"
  else
    diff <(jq -r '.modules[] | select(.status != "stub") | .id' "$PLAN" | sort) \
         <(jq -r '.modules[] | select(.status != "stub") | .id' "$PARITY_WITH" | sort) \
         > /tmp/verify-staging-parity.diff
    if [ -s /tmp/verify-staging-parity.diff ]; then
      fail "parity: staged module id sets differ between $PLAN and $PARITY_WITH:"
      sed 's/^/  /' /tmp/verify-staging-parity.diff
    else
      ok "parity: identical staged module id set ($(jq -r '[.modules[]|select(.status!="stub")]|length' "$PLAN") modules) between $(basename "$PLAN") and $(basename "$PARITY_WITH")"
    fi
  fi
else
  echo "  (no --parity-with given — skipped)"
fi

# ---------------------------------------------------------------------------
# 5. Artifact-hash signing (ADR 0016 D5/verify-staging gate): every `signature: required`,
#    non-stub module.yaml pins a digest for whatever payload actually EXECUTES. Missing this
#    is the "signed manifest, unprotected payload" hole ADR 0016 closes — catching it here, at
#    bake time, is strictly better than the supervisor's own runtime D5 gate (which only ever
#    sees `runtime: wasm` modules — the only runtime the supervisor actually loads today), so
#    this is the ONE check that covers sysext/host/image-layer modules too.
#
#    "The executing payload" is `role: executable` for a `runtime: wasm` module (ADR 0016 D2's
#    literal wording), but a sysext module's D1 worked example (napse-quarantine) pins its
#    loader ELF as `role: loader`, not `executable` — there IS no wasm loader to bind an
#    `executable` role to for a non-wasm runtime. So this check accepts EITHER role as
#    satisfying "the module's main executing payload is pinned"; it does NOT accept
#    `bpf-object`/`data` alone (a kernel object or a config file is not, by itself, "what
#    executes").
# ---------------------------------------------------------------------------
echo "## 5. artifact-hash signing (ADR 0016/0017: three-case gate -- PASS / FAIL-tamper / PENDING|UNVERIFIED-tracked)"
# Prefer the REAL byte-level recompute (`hookprobe-supervisor --check-artifact-digests`, ADR
# 0016/0017): PASS (digest present + recomputed match) / FAIL (digest present + recomputed
# mismatch -- tamper, HARD) / PENDING|UNVERIFIED (a recognized placeholder, or a build-tree
# source that can't be resolved/read in THIS environment -- e.g. a cross-arch native binary with
# no cross-toolchain here -- tracked, LOUD, non-fatal; must become PASS by the real per-arch
# release build). This is the SAME check + resolver `builder/release-pass.sh` calls (single
# source of truth, never re-implemented per script) -- it also resolves a sysext/native-loader
# module's on-device artifact path back to its `staging.artifacts[].src` build-tree source (ADR
# 0016/0017 sysext-artifact-digest gap fix), which a structural YAML-only read cannot do.
SUP="$REPO/target/release/hookprobe-supervisor"
[ -x "$SUP" ] || SUP="$REPO/target/debug/hookprobe-supervisor"
if [ -x "$SUP" ]; then
  echo "  (byte-level recompute via $(basename "$SUP") --check-artifact-digests)"
  if CHECK_OUT="$("$SUP" --check-artifact-digests all --modules "$REPO/modules" 2>&1)"; then
    echo "$CHECK_OUT" | sed 's/^check-artifact-digests: /  /'
  else
    echo "$CHECK_OUT" | sed 's/^check-artifact-digests: /  /' >&2
    fail "artifact-hash signing: at least one hard failure (digest MISMATCH-tamper, or a signature:required module with no executing-payload digest pinned at all) -- see lines above"
  fi
else
  echo "  ($(basename "$SUP") not built -- falling back to structural-only check: presence + placeholder-TOLERANT, no byte recompute)"
  python3 - "$REPO" <<'PY'
import glob, os, sys, yaml

repo = sys.argv[1]
EXECUTING_ROLES = {"executable", "loader"}
PLACEHOLDER = {"", "PENDING", "TODO", "DEADBEEF"}
fail = False
for mf in sorted(glob.glob(os.path.join(repo, "modules", "*", "module.yaml"))):
    with open(mf) as f:
        doc = yaml.safe_load(f) or {}
    mid = doc.get("id", os.path.basename(os.path.dirname(mf)))
    if doc.get("status") == "stub":
        print(f"PASS: {mid}: status=stub, exempted (shipped: no)")
        continue
    if doc.get("signature") != "required":
        print(f"PASS: {mid}: signature={doc.get('signature')!r}, not subject to the ADR 0016 check")
        continue
    artifacts = doc.get("artifacts") or []
    execs = [a for a in artifacts if (a.get("role") or "executable") in EXECUTING_ROLES]
    if not execs:
        print(f"FAIL: {mid}: signature: required but no executing-payload (role: executable|loader) "
              f"artifact declared AT ALL (ADR 0016 D5 -- run "
              f"`hookprobe-supervisor --write-artifact-digests {mid}` then re-sign)")
        fail = True
        continue
    pending = [a for a in execs if (a.get("digest") or {}).get("value", "").strip().upper() in PLACEHOLDER]
    ready = [a for a in execs if a not in pending]
    for a in pending:
        print(f"WARN: {mid}: artifact '{a.get('path')}' has a placeholder digest -- tracked-pending "
              f"(populated at the real per-arch release build; run --write-artifact-digests then "
              f"re-sign before shipping), NOT a failure")
    if ready:
        print(f"PASS: {mid}: {len(ready)} executing-payload digest(s) structurally pinned "
              f"({', '.join(a.get('path', '?') for a in ready)}) -- no supervisor binary available "
              f"here for byte recompute")
if fail:
    sys.exit(1)
PY
  [ $? -eq 0 ] || FAIL=1
fi

# ---------------------------------------------------------------------------
# 5b. arm64 CI blind-spot close (2026-07-16, ADR 0021): check #5 above binds
#     `hookprobe-supervisor --check-artifact-digests` to running_arch() of WHATEVER `$SUP` binary
#     this build HOST happens to run -- on an amd64 dev box / amd64 CI runner, that is ALWAYS
#     "amd64", so an arm64-only-missing `role: executable`/`loader` digest (module.yaml has an
#     `arch: amd64` entry, no `arch: arm64` sibling) prints a harmless-looking "not this gate's
#     arch (amd64), skipping" line and the gate PASSES -- exactly the gap a pre-flash audit found
#     in `modules/dns-sinkhole/module.yaml` (staged arm64 ELF, zero digest binding it) that this
#     amd64-only gate had silently let through. Two layers, in order of preference:
#
#     (a) REAL arm64 byte-level recompute, no rebuild needed: `builder/refresh-aot.sh`'s own
#         no-sysroot recipe -- run the repo's already-cross-built STATIC-musl
#         aarch64-unknown-linux-musl `hookprobe-supervisor` under `qemu-aarch64-static`
#         (`running_arch()` is a compile-time `cfg!(target_arch)` check, so the musl-vs-gnu libc of
#         the *supervisor doing the hashing* is irrelevant -- it still correctly resolves+hashes
#         whatever GNU/musl staged binary the arm64 artifact entry names). Falls back to the
#         aarch64-gnu leg + $ARM64_SYSROOT if no musl leg was built (same fallback order
#         refresh-aot.sh uses).
#     (b) If no arm64 supervisor binary or no `qemu-aarch64-static`/`qemu-user-static` is available
#         in this environment (e.g. a minimal CI runner) -- a structural PARITY check instead of
#         skipping silently: any `role: executable`/`loader` artifact group (same `path`+`role`)
#         that declares an `arch:` on ANY of its entries (i.e. this module opted into the
#         per-arch-digest convention at all, ADR 0021) MUST have both an `amd64` and an `arm64`
#         entry -- a group with only one arch present is a hard FAIL, loud, not a silent skip.
#         (riscv64 is a recognized `running_arch()` token but not yet a shipped target -- not
#         required here; single-arch-canonical entries with no `arch:` field at all are untouched,
#         same as check #5.)
# ---------------------------------------------------------------------------
echo "## 5b. arm64 artifact-digest gate (ADR 0021 CI blind-spot close -- closes the amd64-only-checked gap check #5 cannot see)"
ARM64_QEMU="${ARM64_QEMU:-qemu-aarch64-static}"
ARM64_SYSROOT="${ARM64_SYSROOT:-/tmp/bookworm-arm64-sysroot}"
ARM64_MUSL_SUP="$REPO/target/aarch64-unknown-linux-musl/release/hookprobe-supervisor"
ARM64_GNU_SUP="$REPO/target/aarch64-unknown-linux-gnu/release/hookprobe-supervisor"
ARM64_RUNNER=()
ARM64_SUP=""
if [ -x "$ARM64_MUSL_SUP" ] && command -v "$ARM64_QEMU" >/dev/null 2>&1; then
  ARM64_SUP="$ARM64_MUSL_SUP"
  ARM64_RUNNER=("$ARM64_QEMU")
elif [ -x "$ARM64_GNU_SUP" ] && command -v "$ARM64_QEMU" >/dev/null 2>&1 && [ -d "$ARM64_SYSROOT" ]; then
  ARM64_SUP="$ARM64_GNU_SUP"
  ARM64_RUNNER=("$ARM64_QEMU" -L "$ARM64_SYSROOT")
fi
if [ -n "$ARM64_SUP" ]; then
  echo "  (byte-level recompute via $ARM64_QEMU + $(basename "$ARM64_SUP") --check-artifact-digests, real arm64 running_arch())"
  if CHECK_OUT="$("${ARM64_RUNNER[@]}" "$ARM64_SUP" --check-artifact-digests all --modules "$REPO/modules" 2>&1)"; then
    echo "$CHECK_OUT" | sed 's/^check-artifact-digests: /  [arm64] /'
  else
    echo "$CHECK_OUT" | sed 's/^check-artifact-digests: /  [arm64] /' >&2
    fail "arm64 artifact-hash signing: at least one hard failure under qemu-aarch64 (digest MISMATCH-tamper, or a signature:required module with no arm64 executing-payload digest pinned at all) -- see [arm64] lines above"
  fi
else
  echo "  (no arm64 hookprobe-supervisor + $ARM64_QEMU available -- falling back to structural amd64<->arm64 PARITY check, no byte recompute)"
  python3 - "$REPO" <<'PY'
import glob, os, sys, yaml

repo = sys.argv[1]
EXECUTING_ROLES = {"executable", "loader"}
REQUIRED_ARCHES = {"amd64", "arm64"}  # riscv64 recognized by running_arch() but not yet shipped
fail = False
for mf in sorted(glob.glob(os.path.join(repo, "modules", "*", "module.yaml"))):
    with open(mf) as f:
        doc = yaml.safe_load(f) or {}
    mid = doc.get("id", os.path.basename(os.path.dirname(mf)))
    if doc.get("status") == "stub" or doc.get("signature") != "required":
        continue
    artifacts = doc.get("artifacts") or []
    groups = {}
    for a in artifacts:
        role = a.get("role") or "executable"
        if role not in EXECUTING_ROLES:
            continue
        groups.setdefault((a.get("path"), role), []).append(a)
    for (path, role), entries in groups.items():
        arches = {a.get("arch") for a in entries if a.get("arch")}
        if not arches:
            print(f"PASS: {mid}: '{path}' (role: {role}) is single-arch-canonical (no `arch:` field) -- not subject to parity")
            continue
        missing = REQUIRED_ARCHES - arches
        if missing:
            print(f"FAIL: {mid}: '{path}' (role: {role}) declares arch-qualified digest(s) for {sorted(arches)} "
                  f"but is MISSING {sorted(missing)} -- an arm64-cross-built payload with no arm64 digest is "
                  f"cryptographically unbound on that arch (ADR 0016/0021). Run "
                  f"`hookprobe-supervisor --write-artifact-digests {mid}` under the missing arch (or "
                  f"qemu-aarch64-static, see builder/refresh-aot.sh), then re-sign.")
            fail = True
        else:
            print(f"PASS: {mid}: '{path}' (role: {role}) has a digest entry for every required arch {sorted(REQUIRED_ARCHES)}")
if fail:
    sys.exit(1)
PY
  [ $? -eq 0 ] || FAIL=1
fi

# ---------------------------------------------------------------------------
# 6. Path-binding mirror assertion (ADR 0016 Finding 3 / Fix B): the file a declared
#    `role: executable`/`role: loader` artifact digest is pinned to must be the SAME path the
#    build actually STAGES (an `install`/`copy` action's `dest`) — never a coincidentally-similar
#    but unrelated path. This is the build-time mirror of `module_sig::verify_executable_binding`'s
#    runtime path-binding check: catching a declared artifact `path:` that the staging plan never
#    actually produces at bake time is strictly better than discovering it as a boot-time refusal.
# ---------------------------------------------------------------------------
echo "## 6. path-binding mirror assertion (ADR 0016 Finding 3/Fix B: declared executable/loader artifact path must match a staged action dest)"
python3 - "$REPO" "$PLAN" <<'PY'
import glob, os, sys, yaml, json

repo, plan_path = sys.argv[1], sys.argv[2]
with open(plan_path) as f:
    plan = json.load(f)
EXECUTING_ROLES = {"executable", "loader"}
fail = False
for mf in sorted(glob.glob(os.path.join(repo, "modules", "*", "module.yaml"))):
    with open(mf) as f:
        doc = yaml.safe_load(f) or {}
    mid = doc.get("id", os.path.basename(os.path.dirname(mf)))
    if doc.get("status") == "stub" or doc.get("signature") != "required":
        continue
    entry = next((m for m in plan.get("modules", []) if m.get("id") == mid), None)
    if entry is None:
        # Already reported as an orphan by check #1 -- avoid a duplicate FAIL here.
        continue
    dests = {a.get("dest") for a in entry.get("actions", []) if a.get("op") in ("install", "copy")}
    for a in doc.get("artifacts") or []:
        role = a.get("role") or "executable"
        if role not in EXECUTING_ROLES:
            continue
        path = a.get("path", "")
        if not path:
            continue
        # The wasm co-located convention resolves a RELATIVE path under the on-device install
        # dir; an ABSOLUTE path (sysext/host-integral convention) is used as-is -- mirrors
        # `module_sig::resolve_artifact_path` exactly.
        expected = path if os.path.isabs(path) else f"/usr/lib/hookprobe/modules/{mid}/{path}"
        if expected in dests:
            print(f"PASS: {mid}: executing artifact '{path}' (role={role}) is staged at {expected}")
        else:
            print(f"FAIL: {mid}: executing artifact '{path}' (role={role}) expects to be staged at "
                  f"{expected}, but no staged action produces that dest -- the digest-pinned file "
                  f"would never be the one that actually executes (ADR 0016 Finding 3)")
            fail = True
if fail:
    sys.exit(1)
PY
[ $? -eq 0 ] || FAIL=1

# ---------------------------------------------------------------------------
# 7. ADR 0017 arch-aware AOT check: EVERY `role: aot` artifact declared for the CURRENT PLAN
#    ARCH (there may be more than one now — 2026-07-07 per-microarch AOT enhancement: a plain
#    A72-safe baseline `arch: arm64` entry AND a `cpu: cortex-a76`-tagged `arch: arm64` entry,
#    same arch, different `path`) must be staged and byte-match its signed digest
#    (reproducibility + tamper gate, needs --root); every OTHER arch's `role: aot` entry is
#    inert metadata and must NEVER trigger a "not staged" failure; a `signature: required` wasm
#    module that declares NO `role: aot` entry at all for this arch is a WARNING (falls back to
#    verified JIT at runtime), not a failure — mirroring stage-apply.sh's `optional: true`
#    handling of the same artifact. (Before this fix: only `this_arch_entries[0]` was ever
#    checked, so a second same-arch entry — e.g. the A76 variant — silently got NO check at all,
#    neither PASS nor WARN nor FAIL; closed here by checking every one of them.)
# ---------------------------------------------------------------------------
echo "## 7. ADR 0017 arch-aware AOT check (this plan's arch: role:aot staged + byte-matches its signed digest; other arches: inert metadata, never required)"
python3 - "$REPO" "$PLAN" "$ROOT" <<'PY'
import glob, hashlib, os, sys, yaml, json

repo, plan_path, root = sys.argv[1], sys.argv[2], sys.argv[3]
with open(plan_path) as f:
    plan = json.load(f)
plan_arch = plan.get("arch")
fail = False
for mf in sorted(glob.glob(os.path.join(repo, "modules", "*", "module.yaml"))):
    with open(mf) as f:
        doc = yaml.safe_load(f) or {}
    mid = doc.get("id", os.path.basename(os.path.dirname(mf)))
    if doc.get("status") == "stub" or doc.get("signature") != "required" or doc.get("runtime") != "wasm":
        continue
    entry = next((m for m in plan.get("modules", []) if m.get("id") == mid), None)
    if entry is None:
        continue  # already reported as an orphan by check #1
    aot_entries = [a for a in (doc.get("artifacts") or []) if (a.get("role") or "executable") == "aot"]
    this_arch_entries = [a for a in aot_entries if a.get("arch") == plan_arch]
    other_arch_entries = [a for a in aot_entries if a.get("arch") != plan_arch]
    for a in other_arch_entries:
        print(f"PASS: {mid}: aot entry for arch={a.get('arch')!r} is inert metadata on a {plan_arch} plan (never checked here)")
    if not this_arch_entries:
        print(f"WARN: {mid}: no role:aot artifact declared for this plan's arch ({plan_arch}) -- "
              f"falls back to the verified-JIT floor at runtime (ADR 0017 D3, not a failure)")
        continue
    # Check EVERY entry for this arch (not just the first) -- see the header note above.
    for a in this_arch_entries:
        cpu = a.get("cpu")
        tag = f"{plan_arch}/cpu={cpu}" if cpu else plan_arch
        path = a.get("path", "")
        expected_dest = path if os.path.isabs(path) else f"/usr/lib/hookprobe/modules/{mid}/{path}"
        dests = {act.get("dest") for act in entry.get("actions", []) if act.get("op") in ("install", "copy")}
        if expected_dest not in dests:
            if cpu:
                # A `cpu:`-tagged microarch tier (e.g. the A76 variant) is OPT-IN per platform
                # (builder/gen-staging.sh's ARM64_A76_PLATFORMS — only rpi5/rk3588 targets stage
                # it); a plan that doesn't stage it just means THIS platform build didn't opt
                # into that tier yet, not a broken/incomplete baseline. Never a hard failure.
                print(f"WARN: {mid}: role:aot artifact '{path}' (arch={tag}) is declared but NOT "
                      f"staged in this plan -- this platform build doesn't opt into this "
                      f"microarch tier (falls back to the baseline arch entry, not a failure)")
                continue
            print(f"FAIL: {mid}: role:aot artifact '{path}' (arch={tag}) expects to be staged at "
                  f"{expected_dest}, but no staged action produces that dest")
            fail = True
            continue
        print(f"PASS: {mid}: role:aot artifact '{path}' (arch={tag}) is staged at {expected_dest}")
        if root:
            physical = os.path.join(root, expected_dest.lstrip("/"))
            if not os.path.isfile(physical):
                print(f"WARN: {mid}: role:aot artifact not physically present under --root ({physical}) -- "
                      f"ADR 0017 D3: a missing AOT blob for the built arch is a warning, not a failure")
                continue
            digest_alg = (a.get("digest") or {}).get("alg", "sha256")
            digest_expected = (a.get("digest") or {}).get("value", "").strip().lower()
            if digest_expected in ("", "pending", "todo", "deadbeef"):
                print(f"WARN: {mid}: role:aot artifact '{path}' has a placeholder digest ({digest_expected!r}) "
                      f"-- run `hookprobe-supervisor --write-artifact-digests {mid}` then re-sign")
                continue
            with open(physical, "rb") as bf:
                data = bf.read()
            HASHLIB_NAME = {"sha256": "sha256", "sha384": "sha384", "sha3-256": "sha3_256"}
            actual = hashlib.new(HASHLIB_NAME.get(digest_alg, digest_alg), data).hexdigest()
            if actual.lower() == digest_expected:
                print(f"PASS: {mid}: staged role:aot blob byte-matches its signed digest ({digest_alg})")
            else:
                print(f"FAIL: {mid}: staged role:aot blob at {physical} does NOT match its signed digest "
                      f"(expected {digest_expected}, got {actual}) -- reproducibility/tamper gate")
                fail = True
if fail:
    sys.exit(1)
PY
[ $? -eq 0 ] || FAIL=1

echo
if [ "$FAIL" -eq 0 ]; then
  echo "=== verify-staging: ALL CHECKS PASSED ==="
  exit 0
else
  echo "=== verify-staging: FAILED — see FAIL lines above ==="
  exit 1
fi
