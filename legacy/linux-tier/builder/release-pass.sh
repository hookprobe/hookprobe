#!/usr/bin/env bash
# =============================================================================
# builder/release-pass.sh — assemble the `release.json` evidence bundle (ADR 0012
# D3, "enable Cortex at every release", schema 1) from LOCAL evidence.
# =============================================================================
# This is the REHEARSAL/dry-run path: release-engineer runs it by hand against a
# dev-built digest to preview or rehearse a release pass. The CANONICAL path that
# actually ships is the CI `promote` + `release-pass` jobs
# (`.github/workflows/build-os.yml`) — both write the EXACT SAME bundle shape (ADR
# 0012 D3 "two paths, same bundle shape"), so `hookprobe-evidence` has one ingest
# path regardless of origin.
#
# GOVERNANCE (ADR 0011 D3): the release pass is 🟠 Amber — agents/release-engineer
# PRODUCE it, the operator APPROVES it. This script enforces that mechanically:
# it always prints the four Ring-1 attestation checklist items and REFUSES to write
# --out unless all four are attested (`--attest all`, or the four individual
# `--attest <role>` flags). The actual publish/tag/push/promote action stays 🔴 Red
# (never here — that's CI's `promote` job, reviewer-gated separately).
#
# Usage:
#   builder/release-pass.sh --version 2026.7 --channel stable \
#     --digest edge-pro:arm64:sha256:<hex> --digest cloud:amd64:sha256:<hex> \
#     --gate workspace-tests:pass:174 tests --gate clippy:pass \
#     --attest all \
#     --out release.json
#
# See `docs/adr/0012-release-definition-cortex-pass.md` D3 for the full contract.
# =============================================================================
set -euo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"

VERSION=""; CHANNEL=""; OUT=""; TS=""
SBOM=""; CBOM=""; PROVENANCE=""; NOTES=""
DIGESTS=(); GATES=(); PLATFORMS=(); COMMITS=(); ATTEST_ROLES=()
ATTEST_ALL=0

ALL_ROLES=(verification-engineer security-auditor release-engineer product-steward)

usage() {
  cat >&2 <<'EOF'
usage: release-pass.sh --version <v> --channel <stable|beta>
         --digest <profile:arch:sha256:hex> [--digest ...]
         --gate <stage:verdict[:detail]> [--gate ...]
         --out <path>
         (--attest all | --attest <role> [--attest <role> ...])
         [--platform <name>]... [--commit <id[:subject]>]...
         [--sbom <ref>] [--cbom <ref>] [--provenance <ref>] [--notes <path>] [--ts <iso8601>]

Assembles a release.json evidence bundle (ADR 0012 D3, schema 1) from local
evidence -- the REHEARSAL path. `.github/workflows/build-os.yml`'s `promote` /
`release-pass` jobs are the canonical path that ships; both write the exact same
bundle shape.

Roles (ADR 0012 D3): verification-engineer security-auditor release-engineer product-steward
Refuses to write --out unless all four are attested (the Amber gate).
EOF
  exit 2
}

is_known_role() {
  local r="$1"
  for k in "${ALL_ROLES[@]}"; do [ "$k" = "$r" ] && return 0; done
  return 1
}

while [ $# -gt 0 ]; do case "$1" in
  --version)    VERSION="${2:-}"; shift 2;;
  --channel)    CHANNEL="${2:-}"; shift 2;;
  --digest)     DIGESTS+=("${2:-}"); shift 2;;
  --gate)       GATES+=("${2:-}"); shift 2;;
  --platform)   PLATFORMS+=("${2:-}"); shift 2;;
  --commit)     COMMITS+=("${2:-}"); shift 2;;
  --sbom)       SBOM="${2:-}"; shift 2;;
  --cbom)       CBOM="${2:-}"; shift 2;;
  --provenance) PROVENANCE="${2:-}"; shift 2;;
  --notes)      NOTES="${2:-}"; shift 2;;
  --ts)         TS="${2:-}"; shift 2;;
  --out)        OUT="${2:-}"; shift 2;;
  --attest)
    val="${2:-}"
    if [ "$val" = "all" ]; then ATTEST_ALL=1
    elif is_known_role "$val"; then ATTEST_ROLES+=("$val")
    else echo "ERROR: unknown --attest role '$val' (expected: all | ${ALL_ROLES[*]})" >&2; exit 2
    fi
    shift 2;;
  -h|--help) usage;;
  *) echo "unknown arg: $1" >&2; usage;;
esac; done

# ---- validate required fields ----
[ -n "$VERSION" ] || { echo "ERROR: --version is required" >&2; exit 2; }
[ -n "$CHANNEL" ] || { echo "ERROR: --channel is required" >&2; exit 2; }
[ -n "$OUT" ]     || { echo "ERROR: --out is required" >&2; exit 2; }
case "$CHANNEL" in
  stable|beta) ;;
  *) echo "WARNING: --channel '$CHANNEL' is not 'stable' or 'beta' (ADR 0012 D2) — proceeding, but check this is intentional" >&2;;
esac
[ "${#DIGESTS[@]}" -gt 0 ] || { echo "ERROR: at least one --digest is required" >&2; exit 2; }
[ "${#GATES[@]}" -gt 0 ]   || { echo "ERROR: at least one --gate is required (the gate ladder, ADR 0012 D3)" >&2; exit 2; }
for d in "${DIGESTS[@]}"; do
  case "$d" in
    *:*:*) ;;
    *) echo "ERROR: malformed --digest '$d' (expected profile:arch:sha256:hex)" >&2; exit 2;;
  esac
done
for g in "${GATES[@]}"; do
  case "$g" in
    *:*) ;;
    *) echo "ERROR: malformed --gate '$g' (expected stage:verdict[:detail])" >&2; exit 2;;
  esac
done

# ---- ADR 0020 Gate R: a RED resilience breach is a hard, non---attest-overridable release block --
# same mechanism as the ADR 0016 post-sign gate below: no flag anywhere in this script can override
# a `--gate resilience:fail:...` / `--gate resilience:red:...` entry. Absence of a resilience gate
# entry is SKIPPED (not failed) here -- `builder/gate-ladder.sh --gate-r` honestly SKIPs when no
# privileged/netns-capable runner is available (ADR 0020 residual risk), so a rehearsal or a
# CI tier without that runner must not be blocked by an entry that was never produced. This is
# NOT a substitute for actually running Gate R before a real release -- see release runbook.
echo "ADR 0020 Gate R (adversarial resilience) check:"
RESILIENCE_GATE=""
for g in "${GATES[@]}"; do
  case "$g" in
    resilience:*) RESILIENCE_GATE="$g" ;;
  esac
done
if [ -z "$RESILIENCE_GATE" ]; then
  echo "  (skipped -- no --gate resilience:... entry passed; run 'builder/gate-ladder.sh --gate-r' before a real release and pass its verdict here)"
else
  RESILIENCE_VERDICT="$(echo "$RESILIENCE_GATE" | cut -d: -f2)"
  case "$RESILIENCE_VERDICT" in
    pass) echo "  resilience: pass ($RESILIENCE_GATE)" ;;
    fail|red)
      echo "ERROR: ADR 0020 Gate R reported '$RESILIENCE_VERDICT' ($RESILIENCE_GATE) -- a RED resilience" \
           "breach blocks the release, non---attest-overridable (same discipline as the ADR 0016 gate)." >&2
      exit 1
      ;;
    *) echo "  resilience: unrecognized verdict '$RESILIENCE_VERDICT' ($RESILIENCE_GATE) -- treating as non-blocking, but check this is intentional" ;;
  esac
fi
echo ""

[ -n "$TS" ] || TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
[ -n "$NOTES" ] || NOTES="docs/releases/${VERSION}.md"   # convention (ADR 0012 D4); need not exist yet

# ---- ADR 0016 post-sign gate: artifact-hash signing must have run, in order --------------
# `builder/sign-release.sh` enforces build -> digest -> sign per module; this gate re-checks
# BOTH halves independently of that script actually having run correctly:
#   1. re-verify every module signature (a digest written AFTER signing invalidates the .sig
#      the exact "digest post-dates its signature" inversion ADR 0016 D3 calls out — a stale
#      module.yaml edit after `--sign-modules` would show up here as an INVALID verdict).
#   2. every `signature: required`, non-stub module pins >=1 `role: executable` artifact
#      digest (D5 — "no unprotected payload ships"; mirrors builder/verify-staging.sh's own
#      ADR 0016 check, run here too since a rehearsal release-pass may run standalone).
# `SKIP_ADR0016_GATE=1` exists ONLY for a rehearsal pass with no built supervisor binary
# available (e.g. docs-only dry run); the canonical CI path never sets it.
if [ "${SKIP_ADR0016_GATE:-0}" != "1" ]; then
  echo "ADR 0016 post-sign gate (artifact-hash signing):"
  SUP="$REPO/target/release/hookprobe-supervisor"
  [ -x "$SUP" ] || SUP="$REPO/target/debug/hookprobe-supervisor"
  BOOT="$REPO/target/release/hookprobe-bootstrap"
  [ -x "$BOOT" ] || BOOT="$REPO/target/debug/hookprobe-bootstrap"
  if [ -x "$SUP" ] && [ -d "$REPO/modules" ]; then
    TMPMAN="$(mktemp)"
    if [ -x "$BOOT" ]; then "$BOOT" -o "$TMPMAN" >/dev/null 2>&1 || true; else echo '{}' > "$TMPMAN"; fi
    TRUST="${TRUST_OUT:-$REPO/builder/trust}"
    RECONCILE_OUT="$("$SUP" "$TMPMAN" --modules "$REPO/modules" --trust "$TRUST" 2>&1 || true)"
    rm -f "$TMPMAN"
    if echo "$RECONCILE_OUT" | grep -q "INVALID"; then
      echo "$RECONCILE_OUT" | grep -B1 "INVALID" >&2
      echo "ERROR: ADR 0016 post-sign gate: at least one module signature is INVALID against $TRUST" \
           "-- a digest written AFTER signing invalidates the .sig (build -> digest -> sign order violated?)." >&2
      exit 1
    fi
    echo "  signatures: re-verified against $TRUST, no INVALID verdicts"

    # Byte-level three-case artifact-digest gate (ADR 0016/0017), NOT a presence-only check: PASS
    # (digest present + recomputed match) / FAIL (digest present + recomputed mismatch — tamper,
    # HARD) / PENDING|UNVERIFIED (digest is a recognized placeholder, OR its build-tree source
    # can't be resolved/read in THIS environment — e.g. a cross-arch native binary with no
    # cross-toolchain here — tracked, LOUD, NON-FATAL; must become PASS by the real per-arch
    # release build). A `signature: required` module with NO executing-payload digest declared AT
    # ALL is still a hard FAIL (D5, unprotected payload — unchanged). This ONE Rust check
    # (`hookprobe-supervisor --check-artifact-digests`) also resolves a sysext/native-loader
    # module's on-device artifact path back to its `staging.artifacts[].src` build-tree source
    # (ADR 0016/0017 sysext-artifact-digest gap fix) — the SAME resolution `--write-artifact-digests`
    # uses, so this check and the tool that populates the digests never diverge.
    #
    # Deliberately guarded by `if ... ; then ... else ... exit 1; fi`, NOT a bare command whose
    # non-zero exit would trip `set -e` and silently abort the rest of this script before the
    # ADR 0017 AOT checks below ever run (the exact host-telemetry bug this replaces). Lives
    # INSIDE this `[ -x "$SUP" ]` branch (needs the same built binary the signature re-verify
    # above already required) — `SKIP_ADR0016_GATE=1` / no built `$SUP` skips it exactly like
    # the signature re-verify, never a silent abort either way.
    if ARTIFACT_CHECK_OUT="$("$SUP" --check-artifact-digests all --modules "$REPO/modules" 2>&1)"; then
      echo "$ARTIFACT_CHECK_OUT" | sed 's/^check-artifact-digests: /  /'
      echo "  artifact-digest gate: no hard failures (PENDING/UNVERIFIED entries above are tracked, non-fatal)"
    else
      echo "$ARTIFACT_CHECK_OUT" | sed 's/^check-artifact-digests: /  /' >&2
      echo "ERROR: ADR 0016/0017 artifact-digest gate FAILED -- at least one digest MISMATCH (tamper) or a" \
           "signature:required module with no executing-payload digest pinned at all (see FAIL lines above)." >&2
      exit 1
    fi
  else
    echo "  (skipped -- $SUP or $REPO/modules not found; run builder/sign-release.sh first, or set SKIP_ADR0016_GATE=1 for a docs-only rehearsal)"
  fi

  # ADR 0016 Finding 3 / Fix B: the SAME path-binding mirror assertion verify-staging.sh's check
  # #6 runs — a declared executable/loader artifact must resolve to a path the staging plan
  # ACTUALLY stages, not merely be present in module.yaml. Best-effort: skipped (not failed) if
  # no staging plan has been generated yet (a rehearsal pass with no `gen-staging.sh` run).
  STAGING_PLAN="${STAGING_PLAN:-$REPO/builder/generated/staging-plan.json}"
  if [ -f "$STAGING_PLAN" ]; then
    echo "ADR 0016 Finding 3/Fix B path-binding mirror assertion (against $STAGING_PLAN):"
    python3 - "$REPO" "$STAGING_PLAN" <<'PY'
import glob, json, os, sys, yaml

repo, plan_path = sys.argv[1], sys.argv[2]
with open(plan_path) as f:
    plan = json.load(f)
EXECUTING_ROLES = {"executable", "loader"}
fail = False
for mf in sorted(glob.glob(os.path.join(repo, "modules", "*", "module.yaml"))):
    doc = yaml.safe_load(open(mf)) or {}
    if doc.get("status") == "stub" or doc.get("signature") != "required":
        continue
    mid = doc.get("id", os.path.basename(os.path.dirname(mf)))
    entry = next((m for m in plan.get("modules", []) if m.get("id") == mid), None)
    if entry is None:
        continue
    dests = {a.get("dest") for a in entry.get("actions", []) if a.get("op") in ("install", "copy")}
    for a in doc.get("artifacts") or []:
        role = a.get("role") or "executable"
        if role not in EXECUTING_ROLES:
            continue
        path = a.get("path", "")
        if not path:
            continue
        expected = path if os.path.isabs(path) else f"/usr/lib/hookprobe/modules/{mid}/{path}"
        if expected not in dests:
            print(f"ERROR: {mid}: executing artifact '{path}' (role={role}) expects {expected}, "
                  f"which no staged action produces (ADR 0016 Finding 3)", file=sys.stderr)
            fail = True
        else:
            print(f"  {mid}: '{path}' binds to staged {expected}")
if fail:
    sys.exit(1)
PY
    echo ""

    # ADR 0017 — arch-aware AOT reproducibility/tamper gate: the CURRENT PLAN ARCH's role:aot
    # artifact (if declared) must be staged and its digest present/well-formed; other-arch
    # entries are inert metadata (never checked here); a module with NO role:aot entry for this
    # arch is a WARNING (falls back to verified JIT at runtime, ADR 0017 D3), never a failure.
    echo "ADR 0017 arch-aware AOT gate (against $STAGING_PLAN):"
    python3 - "$REPO" "$STAGING_PLAN" <<'PY'
import glob, json, os, sys, yaml

repo, plan_path = sys.argv[1], sys.argv[2]
with open(plan_path) as f:
    plan = json.load(f)
plan_arch = plan.get("arch")
fail = False
for mf in sorted(glob.glob(os.path.join(repo, "modules", "*", "module.yaml"))):
    doc = yaml.safe_load(open(mf)) or {}
    if doc.get("status") == "stub" or doc.get("signature") != "required" or doc.get("runtime") != "wasm":
        continue
    mid = doc.get("id", os.path.basename(os.path.dirname(mf)))
    entry = next((m for m in plan.get("modules", []) if m.get("id") == mid), None)
    if entry is None:
        continue
    dests = {a.get("dest") for a in entry.get("actions", []) if a.get("op") in ("install", "copy")}
    aot = [a for a in (doc.get("artifacts") or []) if (a.get("role") or "executable") == "aot"]
    this_arch = [a for a in aot if a.get("arch") == plan_arch]
    if not this_arch:
        print(f"  WARN: {mid}: no role:aot artifact for this plan's arch ({plan_arch}) -- falls back to verified JIT (ADR 0017 D3)")
        continue
    a = this_arch[0]
    path = a.get("path", "")
    expected = path if os.path.isabs(path) else f"/usr/lib/hookprobe/modules/{mid}/{path}"
    value = (a.get("digest") or {}).get("value", "").strip().upper()
    if expected not in dests:
        print(f"ERROR: {mid}: role:aot artifact '{path}' (arch={plan_arch}) expects {expected}, "
              f"which no staged action produces (ADR 0017)", file=sys.stderr)
        fail = True
    elif value in ("", "PENDING", "TODO", "DEADBEEF"):
        print(f"  WARN: {mid}: role:aot artifact '{path}' (arch={plan_arch}) has a placeholder digest "
              f"({value!r}) -- run --write-artifact-digests on {plan_arch} then re-sign before shipping")
    else:
        print(f"  {mid}: role:aot artifact '{path}' (arch={plan_arch}) binds to staged {expected}, digest populated")
if fail:
    sys.exit(1)
PY
    echo ""
  else
    echo "  (skipped -- $STAGING_PLAN not found; run builder/gen-staging.sh first for the full ADR 0016 Finding 3 / ADR 0017 AOT check)"
    echo ""
  fi
fi

# ---- the Amber gate: print the Ring-1 checklist; refuse to write unless complete ----
attested() {
  local role="$1"
  [ "$ATTEST_ALL" = 1 ] && return 0
  for r in "${ATTEST_ROLES[@]}"; do [ "$r" = "$role" ] && return 0; done
  return 1
}

echo "Ring-1 release-pass attestation checklist (ADR 0012 D3):"
missing=0
for role in "${ALL_ROLES[@]}"; do
  if attested "$role"; then
    echo "  [x] $role"
  else
    echo "  [ ] $role"
    missing=$((missing + 1))
  fi
done

if [ "$missing" -gt 0 ]; then
  echo "" >&2
  echo "Amber gate: $missing of 4 Ring-1 attestation(s) missing — refusing to write $OUT." >&2
  echo "Pass --attest all (once every role has actually signed off) or the missing --attest <role> flag(s)." >&2
  exit 1
fi

# ---- assemble the bundle (schema 1) ----
mkdir -p "$(dirname "$OUT")"
TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT

# Everything travels via argv, NOT stdin: this command already has a heredoc
# (`<<'PY'`) supplying the python PROGRAM on fd 0 — piping data in on the same fd
# would silently lose it (the heredoc wins; `sys.stdin` inside the script would
# see EOF, not our data). Each item is tagged (`DIGEST=`, `GATE=`, `PLATFORM=`,
# `COMMIT=`) so one flat argv can carry all four repeatable kinds; split once on
# the FIRST `=` (values may themselves contain `=`, e.g. a commit subject).
PY_ARGS=("$VERSION" "$CHANNEL" "$TS" "$SBOM" "$CBOM" "$PROVENANCE" "$NOTES")
for r in "${ATTEST_ROLES[@]}"; do PY_ARGS+=("ATTEST=$r"); done
# `--all-hint` is only appended when `--attest all` was actually passed — a plain
# `${ATTEST_ALL:+...}` would misfire here since ATTEST_ALL="0" is non-empty (truthy
# to `:+`) even when unset by the operator; branch explicitly instead.
[ "$ATTEST_ALL" = 1 ] && PY_ARGS+=("ATTEST_ALL=1")
for d in "${DIGESTS[@]}"; do PY_ARGS+=("DIGEST=$d"); done
for g in "${GATES[@]}"; do PY_ARGS+=("GATE=$g"); done
for p in "${PLATFORMS[@]}"; do [ -n "$p" ] && PY_ARGS+=("PLATFORM=$p"); done
for c in "${COMMITS[@]}"; do [ -n "$c" ] && PY_ARGS+=("COMMIT=$c"); done

python3 - "${PY_ARGS[@]}" > "$TMP" <<'PY'
import sys, json

argv = sys.argv[1:]
version, channel, ts, sbom, cbom, provenance, notes = argv[:7]

attest, images, gates, platforms, commits = [], [], [], [], []
attest_all = False
for item in argv[7:]:
    tag, _, val = item.partition("=")
    if tag == "ATTEST":
        attest.append(val)
    elif tag == "ATTEST_ALL":
        attest_all = True
    elif tag == "DIGEST":
        profile, rest = val.split(":", 1)
        arch, digest = rest.split(":", 1)
        images.append({"profile": profile, "arch": arch, "digest": digest})
    elif tag == "GATE":
        parts = val.split(":", 2)
        stage = parts[0]
        verdict = parts[1] if len(parts) > 1 else ""
        detail = parts[2] if len(parts) > 2 else ""
        gates.append({"stage": stage, "verdict": verdict, "detail": detail, "ts": ts})
    elif tag == "PLATFORM":
        platforms.append(val)
    elif tag == "COMMIT":
        if ":" in val:
            cid, subject = val.split(":", 1)
        else:
            cid, subject = val, ""
        commits.append({"id": cid, "subject": subject})

if attest_all:
    attest = ["verification-engineer", "security-auditor", "release-engineer", "product-steward"]

bundle = {
    "schema": 1,
    "kind": "release",
    "version": version,
    "channel": channel,
    "ts": ts,
    "images": images,
    "platforms": platforms,
    "commits": commits,
    "gates": gates,
    "attestations": attest,
    "sbom": sbom,
    "cbom": cbom,
    "provenance": provenance,
    "notes": notes,
}
print(json.dumps(bundle, indent=2))
PY

mv "$TMP" "$OUT"
trap - EXIT
echo "release-pass: wrote $OUT (version=$VERSION channel=$CHANNEL images=${#DIGESTS[@]} gates=${#GATES[@]})"
