#!/usr/bin/env bash
# =============================================================================
# builder/gate-ladder.sh — ONE entrypoint for the gate ladder (verification-engineer
# canon, docs/roadmap/BuildPlan.md's gate-ladder definition; ADR 0011 D4 "the gate ladder IS
# the sandbox"). Wires together gates that already exist and, until now, had to be
# run by hand: cargo test/clippy, builder/verify-staging.sh (ADR 0015), the ADR
# 0016/0017 artifact-digest fixture harness, and builder/release-pass.sh's post-sign
# gate. Nothing here reimplements a check another script already owns — this is
# purely dependency-ordered wiring + PASS/FAIL/SKIP reporting.
#
# Tiers (cheapest first — D4):
#   Gate 0 (fast, always runs on a dev box):
#     0.1  cargo fmt --check                 (skip-with-reason if rustfmt isn't installed)
#     0.2  cargo clippy --workspace --all-targets --features hookprobe-supervisor/wasm
#          -- 0 errors is the bar; warning COUNT must not increase over the recorded
#          baseline (see CLIPPY_WARN_BASELINE below) -- NOT `-D warnings`, because this
#          tree carries known-tolerated pre-existing clippy warnings (verified before
#          writing this gate: 36 warnings / 0 errors, `--message-format=json`) and
#          `-D warnings` would turn every one of those into a merge-blocking failure
#          for code nobody asked this change to touch.
#     0.3  cargo test --workspace --features hookprobe-supervisor/wasm       (debug, 393 tests)
#     0.4  manifest/validate.py                                             (ADR 0003 fixtures)
#     0.5  ui/ build (0 TS errors)              (skip-with-reason if no npm/node -- this box
#          has neither; the check is real whenever npm IS present)
#     0.6  builder/lint-units.sh                (systemd [Unit]/[Service]/[Install] misplacement)
#     0.7  THE ENFORCEMENT-SEPARATION VALIDATION MATRIX (2026-07-07, operator step-3
#          requirement -- "the SOC breaks a legit device" bug class must never ship again):
#          `cargo test -p hookprobe-manifest --test separation_matrix` (the responder-level
#          half -- scan_responder::decide, l2_responder::decide_l2, nac::{default_policy,
#          resolve}, multi_wan::render_ra_guard_*, scan_responder::evaluate_resource_reality,
#          all exercised through the REAL napse-loader packet trackers, never a reimplemented
#          verdict) + `cargo test -p napse-loader --test separation_matrix_frames` (the
#          raw-frame companion -- napse_loader::dpi::frame_anomaly_reason_local/parse_arp_obs/
#          classify_scan_probe). Already covered by 0.3/1.1's whole-workspace `cargo test`, but
#          named as its OWN first-class gate so a matrix regression is never buried in a
#          373-test workspace summary -- this failing IS the release-blocking signal.
#
#   Gate 1 (release-shaped; PR gate):
#     1.1  cargo test --workspace --features hookprobe-supervisor/wasm --release
#     1.2  builder/gen-staging.sh (regenerate the plan for the current tree) then
#          builder/verify-staging.sh --plan ...           (ADR 0015 D3 registry gate)
#     1.3  builder/test-artifact-digest-gate.sh            (ADR 0016/0017 7-case fixture)
#     1.4  builder/release-pass.sh REHEARSAL (dummy version/channel/digest, --attest all,
#          writes to a throwaway --out) -- exercises the SAME post-sign ADR 0016 gate a
#          real release pass runs, without needing a real image digest.
#     1.5  F2-primary provenance/freshness gate (2026-07-06): fresh-build hookprobe-evidence/
#          napse-dpi/hookprobe-execsnoop and assert each contains its expected runtime
#          marker string (host-EDR ruleset / udp_scan+icmp_sweep / real bpf feature, NOT
#          the no-bpf stub) -- catches "digest matches but binary is stale/wrong-featured"
#          (bit twice: napse-dpi earlier, hookprobe-evidence in this same pentest pass).
#     1.6  ADR 0029 unified Pi fat-boot image -- boot-partition STATIC gate
#          (builder/mkosi-arm64/verify-pi-bootpart.sh via mtools, no root/loop needed): asserts
#          both Raspberry Pi kernels, all four board DTBs, both regenerated initrds
#          (well-formed + storage-driver-union), and the config.txt [pi4]/[cm4]/[pi5]/[cm5]/[all]
#          filter matrix are present on an assembled builder/mkosi-arm64/hookprobe-os-pi.img.
#          SKIPs (not FAILs) when no such image exists on this box -- the privileged build
#          (sudo/loop/mkfs/mount/chroot) only runs on a build host.
#
#   Gate 2 (image; opt-in / CI-only -- needs podman + time, never implied by --fast):
#     2.1  podman build -f base/Containerfile .            (Gate 0/2 image build)
#     2.2  builder/smoketest.sh <tag> --plan ...            (boot self-provision chain
#          + the staging-completeness check against the BUILT image's filesystem)
#
#   Gate R (adversarial resilience; opt-in / privileged-runner-only, ADR 0020 D5 -- NEVER
#   implied by --fast/--full, only explicit --gate-r):
#     R.1  build redteam-engine + hookprobe-evidence (a real build failure FAILS this gate;
#          "no privileged runner" is the ONLY honest SKIP reason, never a build error)
#     R.2  security/redteam/dut/netns-dut.sh up      (netns/veth DUT + real napse-dpi)
#     R.3  fire the phase-active smoke probes (mac-flood, syn-scan) through redteam-engine
#          (the SAME ROE-gated `target_guard` a real campaign uses -- no shortcuts here)
#     R.4  ingest the resulting attack_run/findings into a THROWAWAY evidence.db
#     R.5  netns-dut.sh down (always, even on failure -- never leaves the DUT running)
#     R.6  a RED verdict (an un-caught critical the phase-active probes could observe) is a
#          hard FAIL, non-`--attest`-overridable, mirroring the ADR 0016 gate discipline.
#   SKIP-with-reason (never synthetic-green) when CAP_NET_ADMIN/CAP_NET_RAW/root is
#   unavailable in this environment -- this is the honest, expected case in most CI tiers
#   today (ADR 0020 residual risk #1: needs a privileged, netns-capable runner).
#
# Honesty rule (verification-engineer canon): a gate that can't run in this environment
# is SKIPPED with a printed reason, never silently treated as green. Fail-fast: the
# first FAILing gate stops the ladder (its exit code becomes gate-ladder.sh's exit
# code) -- but the summary table printed so far is never suppressed.
#
# Usage:
#   builder/gate-ladder.sh                 # Gate 0 + Gate 1 (the default dev-box run)
#   builder/gate-ladder.sh --fast          # Gate 0 only
#   builder/gate-ladder.sh --full          # Gate 0 + Gate 1 + Gate 2 (podman permitting)
#   builder/gate-ladder.sh --gate0         # just Gate 0
#   builder/gate-ladder.sh --gate1         # just Gate 1
#   builder/gate-ladder.sh --gate2         # just Gate 2 (forces the attempt even if
#                                            # podman looks slow; still a clean SKIP if
#                                            # podman itself is absent)
#   builder/gate-ladder.sh --gate-r        # just Gate R (adversarial resilience; needs a
#                                            # privileged/netns-capable runner, SKIPs honestly)
#   builder/gate-ladder.sh --gate0 --gate1 --gate2   # equivalent to --full
#
# Env knobs (all optional; pass-through to the underlying gates):
#   ARCH                    arch for gen-staging.sh/verify-staging.sh (default: amd64)
#   SKIP_ADR0016_GATE=1     forwarded to release-pass.sh's rehearsal call (dev docs-only
#                            runs with no built supervisor binary -- the CANONICAL CI
#                            path never sets this; gate-ladder.sh itself does NOT set it)
#   CLIPPY_WARN_BASELINE    override the recorded non-increasing warning-count baseline
#   IMAGE_TAG               tag to build/reuse for Gate 2 (default: hookprobe-gate-ladder:probe)
#   GATE2_PODMAN_BUILD_ARGS extra `podman build` args (e.g. "--build-arg SKIP_GITHUB_DL=1")
#   GATE2_BUILD_TIMEOUT     seconds to allow the Gate 2 podman build (default: 1800)
#   REDTEAM_SUDO=1          allow Gate R to use `sudo -n` for netns/raw-socket ops when not
#                            already root (never interactive; a password prompt = SKIP)
#
# Exit codes: 0 = every gate that ran, passed (SKIPs don't count against this). Non-zero
# = the exit code of the first FAILing gate (or 1 if none is meaningfully propagatable).
# =============================================================================
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
cd "$REPO" || exit 1

# ---------------------------------------------------------------------------
# Flags
# ---------------------------------------------------------------------------
RUN_G0=0; RUN_G1=0; RUN_G2=0; RUN_GR=0
ANY_TIER_FLAG=0
for a in "$@"; do
  case "$a" in
    --fast)   RUN_G0=1; ANY_TIER_FLAG=1 ;;
    --full)   RUN_G0=1; RUN_G1=1; RUN_G2=1; ANY_TIER_FLAG=1 ;;
    --gate0)  RUN_G0=1; ANY_TIER_FLAG=1 ;;
    --gate1)  RUN_G1=1; ANY_TIER_FLAG=1 ;;
    --gate2)  RUN_G2=1; ANY_TIER_FLAG=1 ;;
    --gate-r) RUN_GR=1; ANY_TIER_FLAG=1 ;;
    -h|--help)
      sed -n '2,70p' "$0" | sed 's/^# \{0,1\}//'
      exit 0 ;;
    *) echo "gate-ladder.sh: unknown arg '$a' (see --help)" >&2; exit 2 ;;
  esac
done
# Default (no tier flags at all): Gate 0 + Gate 1 -- "a dev-box run of Gate 0/1
# stays fast"; Gate 2 is never implied, only explicit --gate2/--full asks for it.
if [ "$ANY_TIER_FLAG" -eq 0 ]; then RUN_G0=1; RUN_G1=1; fi

ARCH="${ARCH:-amd64}"
IMAGE_TAG="${IMAGE_TAG:-hookprobe-gate-ladder:probe}"
GATE2_BUILD_TIMEOUT="${GATE2_BUILD_TIMEOUT:-1800}"
GATE2_PODMAN_BUILD_ARGS="${GATE2_PODMAN_BUILD_ARGS:-}"
CARGO_FEATURES="--features hookprobe-supervisor/wasm"
PLAN="$REPO/builder/generated/staging-plan.json"

# ---------------------------------------------------------------------------
# Reporting plumbing
# ---------------------------------------------------------------------------
declare -a RESULTS=()   # "GATE_ID|STATUS|elapsed_s|note"
START_TS=$(date +%s)

banner() { printf '\n=== %s ===\n' "$*"; }

record() {
  local id="$1" status="$2" elapsed="$3" note="${4:-}"
  RESULTS+=("$id|$status|$elapsed|$note")
  case "$status" in
    PASS) printf '\n>>> [%s] PASS  (%ss)\n' "$id" "$elapsed" ;;
    FAIL) printf '\n>>> [%s] FAIL  (%ss) -- %s\n' "$id" "$elapsed" "$note" ;;
    SKIP) printf '\n>>> [%s] SKIP  -- %s\n' "$id" "$note" ;;
  esac
}

summary() {
  local total=$(( $(date +%s) - START_TS ))
  banner "GATE LADDER SUMMARY (total ${total}s)"
  printf '%-8s %-6s %-8s %s\n' "GATE" "RESULT" "TIME(s)" "NOTE"
  local r id status elapsed note
  for r in "${RESULTS[@]}"; do
    IFS='|' read -r id status elapsed note <<<"$r"
    printf '%-8s %-6s %-8s %s\n' "$id" "$status" "$elapsed" "$note"
  done
}

FAIL_EXIT=0
run_gate() {
  # run_gate <id> <cmd...>  -- runs, times, records PASS/FAIL. Returns the command's
  # exit code (caller decides whether that's fatal -- everything here is fail-fast
  # by construction: main() below stops the ladder on the first non-zero return).
  local id="$1"; shift
  local t0 t1 rc
  banner "GATE $id: $*"
  t0=$(date +%s)
  "$@"
  rc=$?
  t1=$(date +%s)
  if [ "$rc" -eq 0 ]; then
    record "$id" PASS "$((t1 - t0))"
  else
    record "$id" FAIL "$((t1 - t0))" "exit $rc"
    FAIL_EXIT=$rc
  fi
  return "$rc"
}

skip_gate() {
  local id="$1" reason="$2"
  banner "GATE $id: SKIPPED"
  record "$id" SKIP 0 "$reason"
}

have() { command -v "$1" >/dev/null 2>&1; }

# ---------------------------------------------------------------------------
# Gate 0.1 -- cargo fmt --check
# ---------------------------------------------------------------------------
gate_0_1_fmt() {
  if ! cargo fmt --version >/dev/null 2>&1; then
    skip_gate "0.1-fmt" "rustfmt component not installed on this toolchain (rustup component add rustfmt)"
    return 0
  fi
  run_gate "0.1-fmt" cargo fmt --all --check
}

# ---------------------------------------------------------------------------
# Gate 0.2 -- clippy: 0 errors is the hard bar; warning COUNT must not increase
# over a recorded baseline (repo carries known-tolerated warnings -- see header).
# ---------------------------------------------------------------------------
gate_0_2_clippy() {
  local id="0.2-clippy"
  local baseline="${CLIPPY_WARN_BASELINE:-36}"
  banner "GATE $id: cargo clippy --workspace --all-targets $CARGO_FEATURES (0 errors; warnings <= $baseline)"
  local t0 t1
  t0=$(date +%s)
  local json_out
  json_out="$(mktemp)"
  # shellcheck disable=SC2086
  cargo clippy --workspace --all-targets $CARGO_FEATURES --message-format=json >"$json_out" 2>/tmp/gate-ladder-clippy.stderr
  local build_rc=$?
  t1=$(date +%s)
  local errors warnings
  errors=$(jq -s '[.[] | select(.reason=="compiler-message") | select(.message.level=="error")] | length' "$json_out" 2>/dev/null || echo -1)
  warnings=$(jq -s '[.[] | select(.reason=="compiler-message") | select(.message.level=="warning")] | length' "$json_out" 2>/dev/null || echo -1)
  rm -f "$json_out"
  echo "  clippy: build_rc=$build_rc errors=$errors warnings=$warnings (baseline=$baseline)"
  if [ "$build_rc" -ne 0 ] && [ "$errors" -le 0 ]; then
    # non-zero exit with no compiler errors parsed == clippy itself couldn't run
    # (bad JSON, cargo internal failure) -- surface stderr and fail loud, not silently.
    tail -40 /tmp/gate-ladder-clippy.stderr >&2
    record "$id" FAIL "$((t1 - t0))" "cargo clippy invocation itself failed (rc=$build_rc), see stderr"
    FAIL_EXIT=1
    return 1
  fi
  if [ "$errors" -gt 0 ]; then
    record "$id" FAIL "$((t1 - t0))" "$errors clippy error(s) -- 0 is the bar"
    FAIL_EXIT=1
    return 1
  fi
  if [ "$warnings" -gt "$baseline" ]; then
    record "$id" FAIL "$((t1 - t0))" "$warnings warnings > baseline $baseline (new warnings introduced -- fix them or, if intentional, bump CLIPPY_WARN_BASELINE with a reviewed reason)"
    FAIL_EXIT=1
    return 1
  fi
  record "$id" PASS "$((t1 - t0))" "$warnings warnings (<= baseline $baseline), 0 errors"
  return 0
}

# ---------------------------------------------------------------------------
# Gate 0.3 -- workspace unit/integration tests (debug)
# ---------------------------------------------------------------------------
gate_0_3_test_debug() {
  # shellcheck disable=SC2086
  run_gate "0.3-test-debug" cargo test --workspace $CARGO_FEATURES
}

# ---------------------------------------------------------------------------
# Gate 0.4 -- manifest schema/fixture validation (ADR 0003)
# ---------------------------------------------------------------------------
gate_0_4_manifest() {
  if ! have python3; then
    skip_gate "0.4-manifest" "python3 not present"
    return 0
  fi
  if ! python3 -c "import jsonschema" >/dev/null 2>&1; then
    skip_gate "0.4-manifest" "python module 'jsonschema' not installed (pip install -r manifest/requirements.txt)"
    return 0
  fi
  run_gate "0.4-manifest" python3 "$REPO/manifest/validate.py"
}

# ---------------------------------------------------------------------------
# Gate 0.7 -- THE ENFORCEMENT-SEPARATION VALIDATION MATRIX (2026-07-07, operator step-3
# requirement). Two crates, each calling REAL public enforcement-decision functions (never a
# reimplementation) with representative LEGIT + ATTACKER inputs -- see
# crates/hookprobe-manifest/tests/separation_matrix.rs's module doc for the full matrix and
# modules/napse-capture/loader/tests/separation_matrix_frames.rs for the raw-frame companion.
# Named as its own gate (rather than relying solely on 0.3/1.1's whole-workspace `cargo test`)
# so a regression in "does the SOC still forward legit traffic" is never lost in a several-
# -hundred-test summary line -- a FAIL here is the release-blocking signal by itself.
# ---------------------------------------------------------------------------
gate_0_7_separation_matrix() {
  local id="0.7-separation-matrix"
  banner "GATE $id: cargo test -p hookprobe-manifest --test separation_matrix && cargo test -p napse-loader --test separation_matrix_frames"
  local t0 t1
  t0=$(date +%s)
  cargo test -p hookprobe-manifest --test separation_matrix \
    && cargo test -p napse-loader --test separation_matrix_frames
  local rc=$?
  t1=$(date +%s)
  if [ "$rc" -eq 0 ]; then
    record "$id" PASS "$((t1 - t0))"
  else
    record "$id" FAIL "$((t1 - t0))" "exit $rc -- a legit-traffic false-drop or a missed-attack regression; see the test output above for the named scenario"
    FAIL_EXIT=$rc
  fi
  return "$rc"
}

# ---------------------------------------------------------------------------
# Gate 0.5 -- ui/ build (0 TS errors)
# ---------------------------------------------------------------------------
gate_0_5_ui() {
  if ! have npm; then
    skip_gate "0.5-ui-build" "npm not present in this environment (this box has no Node toolchain) -- runs for real in CI"
    return 0
  fi
  local id="0.5-ui-build"
  banner "GATE $id: npm ci && npm run build (ui/)"
  local t0 t1
  t0=$(date +%s)
  ( cd "$REPO/../../os/mission-control" && npm ci && npm run build )
  local rc=$?
  t1=$(date +%s)
  if [ "$rc" -eq 0 ]; then
    record "$id" PASS "$((t1 - t0))"
  else
    record "$id" FAIL "$((t1 - t0))" "exit $rc"
    FAIL_EXIT=$rc
  fi
  return "$rc"
}

# ---------------------------------------------------------------------------
# Gate 1.1 -- release-mode workspace tests
# ---------------------------------------------------------------------------
gate_1_1_test_release() {
  # shellcheck disable=SC2086
  run_gate "1.1-test-release" cargo test --workspace $CARGO_FEATURES --release
}

# ---------------------------------------------------------------------------
# Gate 1.2 -- regenerate the staging plan for $ARCH, then verify-staging.sh
# ---------------------------------------------------------------------------
gate_1_2_verify_staging() {
  local id="1.2-verify-staging"
  if ! have jq; then
    skip_gate "$id" "jq not present (verify-staging.sh requires it)"
    return 0
  fi
  banner "GATE $id: gen-staging.sh --arch $ARCH && verify-staging.sh --plan $PLAN"
  local t0 t1
  t0=$(date +%s)
  "$REPO/builder/gen-staging.sh" --arch "$ARCH" --out "$PLAN" \
      --preset-out "$REPO/builder/generated/85-hookprobe-modules.preset" \
    && "$REPO/builder/verify-staging.sh" --plan "$PLAN"
  local rc=$?
  t1=$(date +%s)
  if [ "$rc" -eq 0 ]; then
    record "$id" PASS "$((t1 - t0))"
  else
    record "$id" FAIL "$((t1 - t0))" "exit $rc"
    FAIL_EXIT=$rc
  fi
  return "$rc"
}

# ---------------------------------------------------------------------------
# Gate 1.3 -- the ADR 0016/0017 artifact-digest fixture harness
# ---------------------------------------------------------------------------
gate_1_3_digest_fixture() {
  run_gate "1.3-digest-fixture" "$REPO/builder/test-artifact-digest-gate.sh"
}

# ---------------------------------------------------------------------------
# Gate 1.5 -- F2-primary provenance/freshness gate (2026-07-06 Pi4 pentest finding):
# the ADR 0016/0017 digest gate (1.3/1.4) proves a staged binary's BYTES match whatever
# digest is pinned in module.yaml -- it says nothing about whether those bytes are the
# CURRENT, feature-complete build. A stale `hookprobe-evidence` binary predating the
# host_edr ruleset was shipped and PASSED every digest check (the digest matched the
# stale binary -- of course it did, nothing ever re-derived the digest from a fresh
# build). This is the class of bug that already bit twice (napse-dpi's portscan
# detectors earlier, hookprobe-evidence's host-EDR ruleset here): "digest matches" is
# necessary but NOT sufficient -- it must also be the RIGHT, CURRENT feature set.
#
# Fix: build each key binary FRESH, right here, with the same feature flags the real
# staging pipeline uses (`module.yaml`'s `staging.build[].features`), then assert it
# actually CONTAINS an expected runtime string marker unique to the feature/ruleset it's
# supposed to ship -- a stale/wrong-featured binary (predating the marker's code, or
# built with the wrong Cargo features) provably will not contain it. Never a digest
# comparison (that's 1.3/1.4's job) -- a byte-content assertion on FRESHLY built bytes.
#
#   hookprobe-evidence  MUST contain "HookProbe Host-EDR" (crates/hookprobe-evidence/
#                       src/host_edr.rs's rule_msg literals -- absent iff host_edr.rs's
#                       ruleset predates this build, exactly the live-found gap).
#   napse-dpi           MUST contain "udp_scan" AND "icmp_sweep" (portscan.rs's
#                       UDP_SCAN_CATEGORY/ICMP_SWEEP_CATEGORY consts -- absent iff this
#                       binary predates those detectors, the earlier napse-dpi gap).
#   hookprobe-execsnoop MUST NOT contain "built without the `bpf` feature" (main.rs's
#                       `#[cfg(not(feature = "bpf"))]` stub `run()`'s bail! message --
#                       PRESENT iff this binary was built WITHOUT --features bpf, i.e.
#                       it can never actually attach/load anything — the F7 sibling gap
#                       this same pentest pass found for the eBPF loader).
#
# A build failure for any of the three is a REAL regression (hard FAIL, not a SKIP --
# these binaries are mandatory staged artifacts on every real image); grep failures are
# reported by binary+marker so a future addition/removal of a marker string is an
# obvious, auditable diff here, not a silent gap.
# ---------------------------------------------------------------------------
gate_1_5_provenance() {
  local id="1.5-provenance"
  banner "GATE $id: fresh-build + runtime-marker provenance check (F2-primary)"
  local t0 t1
  t0=$(date +%s)
  local log; log="$(mktemp -t gate-ladder-provenance-XXXX.log)"
  local fail_reason=""

  {
    echo "-- building hookprobe-evidence, napse-loader (napse-dpi), hookprobe-execsnoop (--features bpf) --"
    cargo build --release -p hookprobe-evidence -p napse-loader
    echo "build-evidence-napse-dpi rc=$?"
    cargo build --release -p hookprobe-execsnoop --features bpf
    echo "build-execsnoop-bpf rc=$?"
  } >"$log" 2>&1
  if ! grep -q "^build-evidence-napse-dpi rc=0$" "$log" || ! grep -q "^build-execsnoop-bpf rc=0$" "$log"; then
    tail -60 "$log" >&2
    fail_reason="one or more provenance-gate binaries failed to build fresh (see log) -- a real regression, not an environment limitation"
  fi

  # {bin} vs {gnu_bin}: hookprobe-evidence/napse-dpi are plain `cargo build --release` (host
  # triple, target/release/); hookprobe-execsnoop's real staging convention is `{gnu_bin}`
  # (aarch64/x86_64-unknown-linux-gnu) but a plain `--release` build on this box's OWN host
  # triple still produces the SAME source bytes/feature set this check cares about (the
  # marker's presence/absence is a Cargo-feature question, not an arch/triple one) --
  # target/release/ is the right, simplest path for this gate on any single build host.
  local evidence_bin="$REPO/target/release/hookprobe-evidence"
  local dpi_bin="$REPO/target/release/napse-dpi"
  local execsnoop_bin="$REPO/target/release/hookprobe-execsnoop"

  check_contains() {
    local bin="$1" marker="$2"
    if [ ! -f "$bin" ]; then
      fail_reason="${fail_reason:+$fail_reason; }$bin: binary not found after build"
      return
    fi
    if ! grep -a -q -- "$marker" "$bin"; then
      fail_reason="${fail_reason:+$fail_reason; }$bin: missing expected marker '$marker' (stale/wrong-featured binary?)"
    fi
  }
  check_not_contains() {
    local bin="$1" marker="$2"
    if [ ! -f "$bin" ]; then
      fail_reason="${fail_reason:+$fail_reason; }$bin: binary not found after build"
      return
    fi
    if grep -a -q -- "$marker" "$bin"; then
      fail_reason="${fail_reason:+$fail_reason; }$bin: contains forbidden marker '$marker' (built without the required feature?)"
    fi
  }

  check_contains "$evidence_bin" "HookProbe Host-EDR"
  check_contains "$dpi_bin" "udp_scan"
  check_contains "$dpi_bin" "icmp_sweep"
  check_not_contains "$execsnoop_bin" "built without the \`bpf\` feature"

  rm -f "$log"
  t1=$(date +%s)
  if [ -n "$fail_reason" ]; then
    record "$id" FAIL "$((t1 - t0))" "$fail_reason"
    FAIL_EXIT=1
    return 1
  fi
  record "$id" PASS "$((t1 - t0))" "hookprobe-evidence/napse-dpi/hookprobe-execsnoop all carry their expected fresh-build markers"
  return 0
}

# ---------------------------------------------------------------------------
# Gate 1.4 -- release-pass.sh REHEARSAL (dummy version/channel/digest, all four
# Ring-1 roles attested so the write actually happens; --out to a throwaway
# path). This exercises the exact SAME post-sign ADR 0016 gate a real release
# pass runs -- signature re-verify + the byte-level artifact-digest check +
# the Finding-3 path-binding mirror + the ADR 0017 arch-aware AOT check.
# ---------------------------------------------------------------------------
gate_1_4_release_pass_rehearsal() {
  local id="1.4-release-pass-rehearsal"
  banner "GATE $id: release-pass.sh (rehearsal, dummy digest, --attest all)"
  local t0 t1 out
  out="$(mktemp -t gate-ladder-release-XXXX.json)"
  t0=$(date +%s)
  "$REPO/builder/release-pass.sh" \
    --version "0.0.0-gate-ladder-rehearsal" \
    --channel beta \
    --digest "gate-ladder-rehearsal:$ARCH:sha256:0000000000000000000000000000000000000000000000000000000000000" \
    --gate "gate-ladder:pass:rehearsal" \
    --attest all \
    --out "$out"
  local rc=$?
  t1=$(date +%s)
  rm -f "$out"
  if [ "$rc" -eq 0 ]; then
    record "$id" PASS "$((t1 - t0))"
  else
    record "$id" FAIL "$((t1 - t0))" "exit $rc"
    FAIL_EXIT=$rc
  fi
  return "$rc"
}

# ---------------------------------------------------------------------------
# Gate 1.6 -- ADR 0029 unified Pi fat-boot image: boot-partition STATIC gate.
# builder/mkosi-arm64/verify-pi-bootpart.sh asserts (via mtools -- no root/loop/mount needed)
# that an assembled builder/mkosi-arm64/hookprobe-os-pi.img carries BOTH Raspberry Pi kernels,
# all FOUR board DTBs (Pi4/CM4/Pi5/CM5), BOTH regenerated initrds (well-formed +
# storage-driver-union, module-or-confirmed-built-in), and the config.txt
# [pi4]/[cm4]/[pi5]/[cm5]/[all] filter matrix. This dev box cannot run the PRIVILEGED build
# (make-pi-image.sh needs sudo/loop/mkfs/mount/chroot) -- exit code 2 from the verify script
# means "no image assembled yet", which is an honest SKIP, never a fabricated PASS or a FAIL.
# A real image (built on the operator's build host) makes this gate genuinely load-bearing.
# ---------------------------------------------------------------------------
gate_1_6_pi_bootpart() {
  local id="1.6-pi-bootpart"
  banner "GATE $id: ADR 0029 unified Pi image boot-partition static gate"
  local t0 t1 log rc
  t0=$(date +%s)
  log="$(mktemp -t gate-ladder-pi-bootpart-XXXX.log)"
  "$REPO/builder/mkosi-arm64/verify-pi-bootpart.sh" >"$log" 2>&1
  rc=$?
  cat "$log"
  t1=$(date +%s)
  case "$rc" in
    0)
      record "$id" PASS "$((t1 - t0))" "unified Pi image boot partition verified (both kernels, 4 DTBs, both initrds, config.txt matrix)"
      rm -f "$log"; return 0 ;;
    2)
      skip_gate "$id" "no builder/mkosi-arm64/hookprobe-os-pi.img on this dev box -- needs the privileged build (sudo/loop/mkfs/mount) on a build host, not this sandbox"
      rm -f "$log"; return 0 ;;
    *)
      record "$id" FAIL "$((t1 - t0))" "boot partition assembly defect -- see log tail above"
      rm -f "$log"; FAIL_EXIT=1; return 1 ;;
  esac
}

# ---------------------------------------------------------------------------
# Gate 1.7 -- unified Pi image: ROOTFS-PAYLOAD static gate (field defect 006, 2026-07-09).
# The 1.6 bootpart gate proves the FAT boot partition; NOTHING proved the ext4 rootfs actually
# carries the hookprobe payload. The 006 image booted to a supervisor restart-loop because its
# /usr/share/hookprobe/platforms was EMPTY (base rootfs baked from a half-staged mkosi.extra) --
# bootstrap had no fallback profile, never wrote the manifest, and the supervisor crash-looped.
# builder/mkosi-arm64/verify-image-payload.sh asserts (via debugfs -- no root/loop/mount) that the
# assembled image's rootfs carries platforms(+generic.yaml), manifest schema, a non-empty trust
# store, the core binaries, and the module payload. Same exit-2=SKIP honesty as 1.6.
# ---------------------------------------------------------------------------
gate_1_7_pi_payload() {
  local id="1.7-pi-payload"
  banner "GATE $id: unified Pi image rootfs-payload static gate (006 regression guard)"
  local t0 t1 log rc
  t0=$(date +%s)
  log="$(mktemp -t gate-ladder-pi-payload-XXXX.log)"
  "$REPO/builder/mkosi-arm64/verify-image-payload.sh" >"$log" 2>&1
  rc=$?
  cat "$log"
  t1=$(date +%s)
  case "$rc" in
    0)
      record "$id" PASS "$((t1 - t0))" "unified Pi image rootfs payload verified (platforms+generic.yaml, schema, trust, binaries, modules)"
      rm -f "$log"; return 0 ;;
    2)
      skip_gate "$id" "no builder/mkosi-arm64/hookprobe-os-pi.img on this dev box -- needs the privileged build on a build host, not this sandbox"
      rm -f "$log"; return 0 ;;
    *)
      record "$id" FAIL "$((t1 - t0))" "rootfs payload INCOMPLETE (006 class -- empty platforms/trust/modules) -- see log tail above; DO NOT flash"
      rm -f "$log"; FAIL_EXIT=1; return 1 ;;
  esac
}

# ---------------------------------------------------------------------------
# Gate 1.8 -- ADR 0030 D1 page-size-alignment gate (16K Pi5/CM5 safety).
# The unified image runs ONE rootfs under a 4K kernel on Pi4/CM4 and a 16K kernel on Pi5/CM5.
# An aarch64 ELF whose max LOAD p_align < 16K execs fine on Pi4 but EINVALs on Pi5/CM5 -- a
# green Pi4 boot cannot catch it. builder/verify-binary-alignment.sh (readelf, no root) makes
# that silent cross-board trap a hard failure. Was an ORPHANED gate (never wired) until 2026-07-09.
# Runs against the populated mkosi.extra tree; SKIP(2) honest when it hasn't been staged yet.
# ---------------------------------------------------------------------------
gate_1_8_alignment() {
  local id="1.8-page-align" tree="$REPO/builder/mkosi-arm64/mkosi.extra/usr/lib/hookprobe"
  banner "GATE $id: ADR 0030 D1 16K page-alignment gate (Pi5/CM5)"
  local t0 t1 log rc
  t0=$(date +%s)
  log="$(mktemp -t gate-ladder-align-XXXX.log)"
  "$REPO/builder/verify-binary-alignment.sh" "$tree" >"$log" 2>&1
  rc=$?
  cat "$log"
  t1=$(date +%s)
  case "$rc" in
    0) record "$id" PASS "$((t1 - t0))" "all staged aarch64 ELF >= 16K aligned (Pi5/CM5 exec-safe)"; rm -f "$log"; return 0 ;;
    2) skip_gate "$id" "no staged mkosi.extra tree to check -- run build-arm64.sh first"; rm -f "$log"; return 0 ;;
    *) record "$id" FAIL "$((t1 - t0))" "an aarch64 ELF is under-aligned for the 16K Pi5/CM5 kernel -- would EINVAL on metal; see log"; rm -f "$log"; FAIL_EXIT=1; return 1 ;;
  esac
}

# ---------------------------------------------------------------------------
# Gate 2.1/2.2 -- image build + boot self-provisioning smoketest
# ---------------------------------------------------------------------------
gate_2_image() {
  local id="2-image"
  if ! have podman; then
    skip_gate "$id" "podman not installed in this environment"
    return 0
  fi
  banner "GATE $id: podman build (timeout ${GATE2_BUILD_TIMEOUT}s) + builder/smoketest.sh"
  local t0 t1 rc
  t0=$(date +%s)
  # shellcheck disable=SC2086
  timeout "$GATE2_BUILD_TIMEOUT" podman build -f "$REPO/base/Containerfile" "$REPO" \
      -t "$IMAGE_TAG" $GATE2_PODMAN_BUILD_ARGS \
    && "$REPO/builder/smoketest.sh" "$IMAGE_TAG" --plan "$PLAN"
  rc=$?
  t1=$(date +%s)
  if [ "$rc" -eq 124 ]; then
    record "$id" FAIL "$((t1 - t0))" "podman build timed out after ${GATE2_BUILD_TIMEOUT}s (bump GATE2_BUILD_TIMEOUT)"
    FAIL_EXIT=1
    return 1
  fi
  if [ "$rc" -eq 0 ]; then
    record "$id" PASS "$((t1 - t0))"
  else
    record "$id" FAIL "$((t1 - t0))" "exit $rc"
    FAIL_EXIT=$rc
  fi
  return "$rc"
}

# ---------------------------------------------------------------------------
# Gate R -- adversarial resilience (ADR 0020 D5). SKIP-with-reason (never synthetic-green)
# when this environment cannot provide CAP_NET_ADMIN/CAP_NET_RAW; a REAL build failure of
# redteam-engine/hookprobe-evidence is still a hard FAIL (that is a real regression, not an
# environment limitation).
# ---------------------------------------------------------------------------
gate_r_resilience() {
  local id="R-resilience"
  local run_as_root=0
  if [ "$(id -u)" -eq 0 ]; then
    run_as_root=1
  elif [ "${REDTEAM_SUDO:-0}" = "1" ] && sudo -n true 2>/dev/null; then
    run_as_root=1
  fi
  if [ "$run_as_root" -ne 1 ]; then
    skip_gate "$id" "no CAP_NET_ADMIN/root available (not uid 0, and no non-interactive sudo -- set REDTEAM_SUDO=1 with a passwordless sudoer to enable this gate). This is the ADR 0020 residual risk: Gate R needs a privileged, netns-capable runner, not available on the free CI tier."
    return 0
  fi
  if ! have ip; then
    skip_gate "$id" "'ip' (iproute2) not present -- required for the netns/veth DUT"
    return 0
  fi

  banner "GATE $id: build redteam-engine + hookprobe-evidence, stand up the netns DUT, fire smoke probes"
  local t0 t1
  t0=$(date +%s)

  if ! cargo build -p redteam-engine -p hookprobe-evidence >/tmp/gate-ladder-redteam-build.log 2>&1; then
    tail -60 /tmp/gate-ladder-redteam-build.log >&2
    record "$id" FAIL "$(( $(date +%s) - t0 ))" "redteam-engine/hookprobe-evidence failed to build (see log) -- a real regression, not an environment limitation"
    FAIL_EXIT=1
    return 1
  fi

  local sudo_prefix=""
  [ "$(id -u)" -ne 0 ] && sudo_prefix="sudo -n"

  local out_dir; out_dir="$(mktemp -d -t gate-ladder-redteam-XXXX)"
  local db; db="$(mktemp -t gate-ladder-redteam-evidence-XXXX.db)"; rm -f "$db"
  local events="/tmp/redteam-dut-events.jsonl"
  local teardown_done=0
  teardown() {
    [ "$teardown_done" -eq 1 ] && return 0
    $sudo_prefix "$REPO/security/redteam/dut/netns-dut.sh" down >/tmp/gate-ladder-redteam-teardown.log 2>&1 || true
    teardown_done=1
  }
  trap teardown EXIT

  if ! $sudo_prefix "$REPO/security/redteam/dut/netns-dut.sh" up >/tmp/gate-ladder-redteam-dut-up.log 2>&1; then
    cat /tmp/gate-ladder-redteam-dut-up.log >&2
    teardown
    record "$id" FAIL "$(( $(date +%s) - t0 ))" "netns-dut.sh up failed (see log) -- CAP_NET_ADMIN reported available but the netns/veth setup itself failed"
    FAIL_EXIT=1
    return 1
  fi

  local engine_bin="$REPO/target/debug/redteam-engine"
  local any_fail=0
  # mac-flood: L2, validates napse_loader::l2guard::MacFloodTracker (ADR 0020 Phase-1a).
  $sudo_prefix "$engine_bin" --roe "$REPO/security/redteam/rules-of-engagement.yaml" \
    --out "$out_dir" --probe mac-flood --iface veth-dut --netns hookprobe-dut --count 200 \
    --events "$events" --verify-substr l2_mac_flood --cadence smoke \
    >/tmp/gate-ladder-redteam-macflood.log 2>&1 || true
  cat /tmp/gate-ladder-redteam-macflood.log
  # syn-scan: L4 fan-out, validates napse_loader::portscan::PortScanTracker. napse-dpi's default
  # PortScanTracker threshold is 50 distinct ports (DEFAULT_THRESHOLD, portscan.rs) -- the port list
  # below must exceed it or this is an honest under-threshold non-trigger, not a defense breach.
  local scan_ports; scan_ports="$(seq 4000 4054 | paste -sd,)"
  $sudo_prefix "$engine_bin" --roe "$REPO/security/redteam/rules-of-engagement.yaml" \
    --out "$out_dir" --probe syn-scan --iface veth-dut --target 10.99.0.2 --ports "$scan_ports" \
    --events "$events" --verify-substr "port_scan" --cadence smoke \
    >/tmp/gate-ladder-redteam-synscan.log 2>&1 || true
  cat /tmp/gate-ladder-redteam-synscan.log

  teardown

  if [ ! -f "$out_dir/attack_run.json" ]; then
    record "$id" FAIL "$(( $(date +%s) - t0 ))" "no attack_run.json produced -- the engine did not run at all"
    FAIL_EXIT=1
    return 1
  fi

  "$REPO/target/debug/hookprobe-evidence" --db "$db" \
    --ingest-attack-run "$out_dir/attack_run.json" \
    --ingest-findings "$out_dir/findings.jsonl" >/tmp/gate-ladder-redteam-ingest.log 2>&1 || true
  cat /tmp/gate-ladder-redteam-ingest.log

  # Fail-closed RED check: read the LAST attack_run verdict written (both probe invocations above
  # overwrite the SAME out_dir/attack_run.json in place -- the file's final content is this run's
  # combined verdict). A RED verdict from EITHER probe is a hard, non-overridable gate failure.
  if have jq; then
    local verdict; verdict="$(jq -r '.verdict' "$out_dir/attack_run.json" 2>/dev/null || echo unknown)"
  else
    local verdict; verdict="$(grep -o '"verdict"[^,}]*' "$out_dir/attack_run.json" | tail -1 | grep -o '"[a-z]*"$' | tr -d '"')"
  fi
  rm -rf "$out_dir" "$db"

  if [ "$verdict" = "red" ]; then
    record "$id" FAIL "$(( $(date +%s) - t0 ))" "RED resilience breach -- a phase-active probe found an uncaught critical (ADR 0020 D5; non---attest-overridable)"
    FAIL_EXIT=1
    any_fail=1
  fi
  t1=$(date +%s)
  if [ "$any_fail" -eq 0 ]; then
    record "$id" PASS "$((t1 - t0))" "verdict=$verdict"
  fi
  return "$any_fail"
}

# ---------------------------------------------------------------------------
# Main -- dependency order, fail-fast.
# ---------------------------------------------------------------------------
main() {
  echo "HookProbe OS gate ladder -- $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "repo: $REPO"
  echo "tiers requested: gate0=$RUN_G0 gate1=$RUN_G1 gate2=$RUN_G2 gate-r=$RUN_GR"

  if [ "$RUN_G0" -eq 1 ]; then
    gate_0_1_fmt          || { summary; exit "$FAIL_EXIT"; }
    gate_0_2_clippy       || { summary; exit "$FAIL_EXIT"; }
    gate_0_3_test_debug   || { summary; exit "$FAIL_EXIT"; }
    gate_0_4_manifest     || { summary; exit "$FAIL_EXIT"; }
    gate_0_5_ui           || { summary; exit "$FAIL_EXIT"; }
    # 0.6 unit-lint (2026-07-06): catch [Service] directives misplaced in [Unit]/[Install], which
    # systemd SILENTLY IGNORES — the class that disabled the bootstrap first-boot re-probe gate
    # (ExecCondition= in [Unit]). Static, no systemd needed.
    run_gate "0.6-unit-lint" bash "$REPO/builder/lint-units.sh" || { summary; exit "$FAIL_EXIT"; }
    gate_0_7_separation_matrix || { summary; exit "$FAIL_EXIT"; }
  fi

  if [ "$RUN_G1" -eq 1 ]; then
    gate_1_1_test_release          || { summary; exit "$FAIL_EXIT"; }
    gate_1_2_verify_staging        || { summary; exit "$FAIL_EXIT"; }
    gate_1_3_digest_fixture        || { summary; exit "$FAIL_EXIT"; }
    gate_1_4_release_pass_rehearsal || { summary; exit "$FAIL_EXIT"; }
    gate_1_5_provenance            || { summary; exit "$FAIL_EXIT"; }
    gate_1_6_pi_bootpart            || { summary; exit "$FAIL_EXIT"; }
    gate_1_7_pi_payload             || { summary; exit "$FAIL_EXIT"; }
    gate_1_8_alignment              || { summary; exit "$FAIL_EXIT"; }
  fi

  if [ "$RUN_G2" -eq 1 ]; then
    gate_2_image || { summary; exit "$FAIL_EXIT"; }
  fi

  if [ "$RUN_GR" -eq 1 ]; then
    gate_r_resilience || { summary; exit "$FAIL_EXIT"; }
  fi

  summary
  echo
  echo "=== gate-ladder.sh: ALL REQUESTED GATES PASSED (SKIPs, if any, are logged above) ==="
  exit 0
}

main
