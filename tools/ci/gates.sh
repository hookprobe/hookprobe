#!/usr/bin/env bash
# =============================================================================
# tools/ci/gates.sh — THE single entrypoint of the HookProbe gate spine (ADR 0052).
#
# CI workflows call this script verbatim and a developer runs the identical
# command locally, so "green on my box" and "green in CI" can never diverge
# (same DRY rule as build-heqk.yml → validate.sh). Gates are deterministic and
# fail-closed; AI never decides a gate (C9: AI proposes, gates enforce).
#
#   tools/ci/gates.sh g0 g1          run specific gates
#   tools/ci/gates.sh pr             g0 g1 g4        (fast PR set)
#   tools/ci/gates.sh full           g0 g1 g2 g3 g4  (everything QEMU can prove)
#   tools/ci/gates.sh nightly        full + g4r      (+ reproducibility)
#   tools/ci/gates.sh --list         describe gates
#
# Gate ladder:
#   g0  hygiene + CI wiring meta-gate + CI-tooling self-tests
#   g1  static + unit: clippy ratchet, host unit tests, validate.sh phase ratchet
#   g2  QEMU boot gate (os/kernel/validate.sh, all implemented phases)
#   g3  Mission Control end-to-end in QEMU (os/kernel/tools/mc-e2e.sh)
#   g4  supply chain: cargo-deny (RustSec) on every lockfile, npm audit, SBOM
#   g4r reproducibility: build the shipped `prod` kernel twice, hashes must match
#   g6  metal (self-hosted CM5 runner only): mc-e2e-metal.sh
#
# Output: $CI_OUT (default out/ci)/gate-results.json + logs/<gate>.log — the
# input of the heal loop (tools/ci/heal/) and the Cortex feed (tools/ci/cortex/).
# Env:   CI_STRICT=1 (default under CI) turns "tool missing" into FAIL, not SKIP.
# =============================================================================
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT" || exit 2
[ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"
[ -d "$HOME/.local/node/bin" ] && export PATH="$HOME/.local/node/bin:$PATH"

CI_OUT="${CI_OUT:-$ROOT/out/ci}"
LOGS="$CI_OUT/logs"
mkdir -p "$LOGS"
RESULTS="$CI_OUT/gate-results.jsonl"
STRICT="${CI_STRICT:-${CI:-0}}"
[ "$STRICT" = "true" ] && STRICT=1

ALL_GATES="g0 g1 g2 g3 g4 g4r g6"
declare -A DESC=(
  [g0]="hygiene + CI wiring meta-gate + CI-tooling self-tests"
  [g1]="static + unit (clippy ratchet, host unit tests, phase ratchet)"
  [g2]="QEMU boot gate (validate.sh)"
  [g3]="Mission Control end-to-end in QEMU (mc-e2e.sh)"
  [g4]="supply chain (cargo-deny/RustSec, npm audit, SBOM)"
  [g4r]="reproducible build of the shipped prod kernel"
  [g6]="metal gate on the self-hosted CM5 bench"
)

# ---------------------------------------------------------------- helpers
FAILFILE="$CI_OUT/.step-fails"
fail_inc() { echo x >> "$FAILFILE"; }   # survives the `| tee` subshell the gate runs in
step() {            # step <label> <cmd...>  — run one sub-check, never abort the gate early
  local label="$1"; shift
  echo "::group::$label"
  echo "+ $*"
  # stdin from /dev/null: a sub-check that reads stdin (e.g. `podman run -i`) must never swallow
  # the `while read` loop feeding it — that once silently cut the SBOM loop to 1 of 9 lockfiles.
  if "$@" </dev/null; then echo "  [ok]   $label"; else echo "  [FAIL] $label"; fail_inc; fi
  echo "::endgroup::"
}
need() {            # need <tool> — missing tool = SKIP locally, FAIL under CI_STRICT
  command -v "$1" >/dev/null 2>&1 && return 0
  if [ "$STRICT" = 1 ]; then echo "  [FAIL] required tool '$1' not installed (CI_STRICT)"; fail_inc;
  else echo "  [skip] '$1' not installed — install it to run this check locally"; fi
  return 1
}
lockdirs() { grep -vE '^\s*(#|$)' tools/ci/lockfiles.txt | awk -v e="$1" '$1==e{print $2}'; }

# ---------------------------------------------------------------- gates
gate_g0() {
  step "CI wiring meta-gate"            python3 -I tools/ci/g0_wiring.py --root "$ROOT"
  step "CI tooling self-tests"          python3 -I -m unittest discover -s tools/ci/tests -t tools/ci -q
  if need shellcheck; then
    step "shellcheck tools/ci"          shellcheck -S warning tools/ci/*.sh tools/ci/heal/*.sh
  fi
}

gate_g1() {
  # CI_TARGET_ROOT (optional): one shared build dir for drills / heal re-runs in fresh worktrees.
  local T="${CI_TARGET_ROOT:-}"
  tdir() { if [ -n "$T" ]; then echo "$T/$1"; else echo target/ci; fi; }
  step "clippy ratchet (heqk kernel workspace)" python3 -I tools/ci/clippy_ratchet.py --root "$ROOT"
  step "validate.sh phase ratchet"     python3 -I tools/ci/phase_ratchet.py --root "$ROOT"
  # Host unit tests on STABLE: nightly build-std of std for the host broke on a newer nightly in CI
  # (E0152 duplicate lang item `sized`, 2026-11-08) and host tests need no build-std at all.
  step "host tests: heqk-tlsprov"      bash -c "cd os/kernel/tlsprov && CARGO_TARGET_DIR=$(tdir tlsprov) cargo +stable test --release --target x86_64-unknown-linux-gnu"
  step "host tests: responder-sim"     bash -c "cd onboarding/enrollment/responder-sim && CARGO_TARGET_DIR=$(tdir responder-sim) cargo +stable test --release"
  step "host tests: heqk-sign"         bash -c "cd os/build/heqk-sign && CARGO_TARGET_DIR=$(tdir heqk-sign) cargo +stable test --release"
}

gate_g2() {
  need qemu-system-aarch64 || return 0
  # The P15 OTA / A-B phases build a real FAT32 disk; without these tools validate.sh SKIPS them and
  # then reports them as "missing marker" — a phantom kernel regression (CI, 2026-11-08). Under
  # CI_STRICT a missing tool fails here, by name.
  local t; for t in mkfs.vfat mcopy sfdisk; do need "$t" || return 0; done
  step "heqk validate.sh (QEMU)"       bash -c 'cd os/kernel && ./validate.sh'
}

ensure_ui() {
  [ -f os/mission-control/dist/index.html ] && return 0
  need npm || return 1
  (cd os/mission-control && npm ci --no-audit --no-fund && PUBLIC_API_BASE='' npm run build)
}

run_mce2e() {
  local rc
  (cd os/kernel && ./tools/mc-e2e.sh) > "$CI_OUT/mc-e2e.out" 2>&1; rc=$?
  cat "$CI_OUT/mc-e2e.out"
  return $rc
}

ensure_browser() {   # the real-browser leg (HTTP + HTTPS pinned to the device key + PQ hybrid KEX)
  [ -d os/kernel/tools/mc-e2e/node_modules/playwright ] && return 0
  need npm || return 1
  (cd os/kernel/tools/mc-e2e && npm ci --no-audit --no-fund && npx playwright install chromium)
}

gate_g3() {
  need qemu-system-aarch64 || return 0
  need mcopy || return 0
  step "build Mission Control UI"      ensure_ui
  ensure_browser || echo "  [skip] Playwright Chromium unavailable — browser/HTTPS leg will be skipped"
  step "mc-e2e (heqk serves Mission Control, QEMU)" run_mce2e
  # A skipped browser leg must never pass as green in CI: it is the only proof of the device TLS
  # stack (ECDSA P-256 cert key + X25519MLKEM768) against a real browser.
  if [ "$STRICT" = 1 ] && grep -q "SKIP  browser leg" "$CI_OUT/mc-e2e.out" 2>/dev/null; then
    echo "  [FAIL] browser leg skipped under CI_STRICT"; fail_inc
  fi
}

gate_g4() {
  if need cargo-deny; then
    local d
    while read -r d; do
      step "cargo-deny $d" bash -c "cd '$d' && cargo deny --log-level error --config '$ROOT/tools/ci/deny.toml' check"
    done < <(lockdirs cargo)
  fi
  if need npm; then
    while read -r d; do
      step "npm audit (prod deps, high+) $d" bash -c "cd '$d' && npm audit --omit=dev --audit-level=high"
    done < <(lockdirs npm)
  fi
  if need syft; then
    rm -rf "$CI_OUT/sbom"; mkdir -p "$CI_OUT/sbom"
    while read -r d; do
      step "SBOM $d" syft scan "dir:$d" -q -o "cyclonedx-json=$CI_OUT/sbom/$(echo "$d" | tr / _).cdx.json"
    done < <(lockdirs cargo; lockdirs npm)
    # Completeness self-check: one SBOM per registered lockfile, or the gate did less than it claims.
    local want got
    want=$( (lockdirs cargo; lockdirs npm) | wc -l)
    got=$(find "$CI_OUT/sbom" -name '*.cdx.json' -size +0 | wc -l)
    step "SBOM completeness ($got/$want lockfiles)" test "$got" -eq "$want"
  fi
}

gate_g4r() {
  need sha256sum || return 0
  step "reproducible prod kernel (2 clean builds, identical hash)" tools/ci/repro.sh
}

gate_g6() {
  if [ -z "${HEQK_METAL:-}" ]; then
    echo "  [skip] g6 needs the self-hosted CM5 bench (HEQK_METAL=1 + serial/usbboot wired)"
    if [ "$STRICT" = 1 ] && [ "${GITHUB_WORKFLOW:-}" = "metal" ]; then fail_inc; fi
    return 0
  fi
  step "mc-e2e on CM5 metal"           bash -c 'cd os/kernel && ./tools/mc-e2e-metal.sh'
}

# ---------------------------------------------------------------- driver
run_gate() {
  local g="$1" t0 t1 status
  echo "================ $g — ${DESC[$g]}"
  : > "$FAILFILE"
  t0=$(date +%s)
  "gate_$g" 2>&1 | tee "$LOGS/$g.log"
  t1=$(date +%s)
  STEP_FAILS=$(wc -l < "$FAILFILE")
  if [ "$STEP_FAILS" -eq 0 ]; then status=pass; else status=fail; fi
  if grep -q '\[skip\]' "$LOGS/$g.log" && ! grep -q '\[ok\]' "$LOGS/$g.log" && [ "$status" = pass ]; then status=skip; fi
  printf '{"gate":"%s","desc":"%s","status":"%s","seconds":%d,"failed_steps":%d,"log":"%s"}\n' \
    "$g" "${DESC[$g]}" "$status" "$((t1-t0))" "$STEP_FAILS" "$LOGS/$g.log" >> "$RESULTS"
  echo "================ $g: ${status^^} ($((t1-t0))s)"
  [ "$status" != fail ]
}

expand() {
  for a in "$@"; do
    case "$a" in
      pr)      echo g0 g1 g4 ;;
      full)    echo g0 g1 g2 g3 g4 ;;
      nightly) echo g0 g1 g2 g3 g4 g4r ;;
      all)     echo "$ALL_GATES" ;;
      *)       echo "$a" ;;
    esac
  done
}

if [ "${1:-}" = "--list" ] || [ $# -eq 0 ]; then
  for g in $ALL_GATES; do printf '  %-4s %s\n' "$g" "${DESC[$g]}"; done
  echo "  aliases: pr | full | nightly | all"
  [ $# -eq 0 ] && exit 2 || exit 0
fi

: > "$RESULTS"
FAILED=()
for g in $(expand "$@"); do
  [ -n "${DESC[$g]:-}" ] || { echo "unknown gate: $g (try --list)"; exit 2; }
  run_gate "$g" || FAILED+=("$g")
done
python3 -I tools/ci/results.py --in "$RESULTS" --out "$CI_OUT/gate-results.json" || true
if [ ${#FAILED[@]} -gt 0 ]; then
  echo "GATES FAILED: ${FAILED[*]}   (logs: $LOGS) — classify: python3 tools/ci/heal/classify.py $CI_OUT/gate-results.json"
  exit 1
fi
echo "ALL GATES PASSED: $(expand "$@" | tr '\n' ' ')"
