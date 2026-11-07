#!/usr/bin/env bash
# =============================================================================
# fleet/agent.sh — pull-based GitOps agent (Readme "Fleet & scale").
# =============================================================================
# Pulls the node's desired state, diffs it against the live device, and converges
# — drift self-heal, resilient to intermittent links (PULL, never push), works
# disconnected (re-converges when the link returns). Run on a timer (systemd) on
# each node. Health-gated: a failed module apply is shed/reverted by the
# supervisor's health phase; a bad image upgrade is caught by the boot-health gate
# (greenboot → `bootc rollback`). Promotion follows rollout rings (canary→ring→fleet).
# =============================================================================
set -euo pipefail
REPO_URL="${FLEET_REPO:-https://example.com/fleet.git}"   # desired-state repo (or OCI ref at scale)
NODE="${FLEET_NODE:-$(hostname)}"
WORK="${FLEET_WORK:-/var/lib/hookprobe/fleet}"
MANIFEST="${MANIFEST:-/var/lib/hookprobe/manifest.json}"
SUP="${SUP:-/usr/bin/hookprobe-supervisor}"

# 1. Pull desired state (disconnected-safe: reuse the last good copy on failure).
mkdir -p "$WORK"
if [ -d "$WORK/.git" ]; then
  git -C "$WORK" pull --ff-only 2>/dev/null || echo "fleet: offline — using last-known desired state"
else
  git clone --depth 1 "$REPO_URL" "$WORK" 2>/dev/null || echo "fleet: clone failed — provide $WORK/hookprobe.yaml manually"
fi
DESIRED="$WORK/nodes/$NODE/hookprobe.yaml"
[ -f "$DESIRED" ] || DESIRED="$WORK/hookprobe.yaml"
# Rollout state (ADR 0012 D2/build-step-3): repo-root, not per-node — it describes
# which rings a promoted digest has reached, same shape for every node on a channel.
# Absent = legacy behavior (every channel mismatch is actionable, no ring window).
ROLLOUT="$WORK/rollout.yaml"
ROLLOUT_ARGS=()
[ -f "$ROLLOUT" ] && ROLLOUT_ARGS=(--rollout "$ROLLOUT")

# 2. Verify sig → reconcile → self-test/heal → print fleet drift (desired vs live).
#    Capture stdout so step 3 can act on it AND still show the operator everything
#    the supervisor printed (health, budget, drift) — nothing is thrown away.
OUT="$("$SUP" "$MANIFEST" --fleet "$DESIRED" "${ROLLOUT_ARGS[@]}" --write "$MANIFEST")"
echo "$OUT"

# 3. Channel drift → health-gated bootc upgrade, ONLY in this node's ring window.
#    The supervisor already did the ring-window math (`fleet::diff_ring_gated`) and
#    printed two DISTINCT drift lines — this step only has to tell them apart:
#      "drift (actionable): channel '..' != desired '..' -> bootc upgrade"   (act now)
#      "drift (pending, ring not promoted -- no upgrade): channel ..."       (wait)
#    `bootc` may not exist on this host (VM/dev/container) — gate on `command -v
#    bootc` rather than fail. `HOOKPROBE_FLEET_DRY_RUN=1` prints the call instead of
#    running it, for testing this script without a real bootc-managed system.
#    HONESTY: the guarded call is `bootc upgrade --check` (verify-only, non-mutating)
#    — deliberately conservative until this path is validated against a real bootc
#    host. TODO: wire the actual mutating `bootc upgrade` apply once that's possible
#    (greenboot already catches a bad boot via auto-rollback on the apply side).
if echo "$OUT" | grep -q "drift (actionable):.*channel .* -> bootc upgrade\|drift (actionable):.*channel .*→ bootc upgrade"; then
  if [ "${HOOKPROBE_FLEET_DRY_RUN:-0}" = "1" ]; then
    echo "fleet: [dry-run] in ring window — would run: bootc upgrade --check"
  elif command -v bootc >/dev/null 2>&1; then
    echo "fleet: actionable channel drift, ring in window — bootc upgrade --check"
    bootc upgrade --check || echo "fleet: bootc upgrade --check reported no update / failed (non-fatal here)"
  else
    echo "fleet: actionable channel drift, ring in window, but no 'bootc' on this host — skipping"
  fi
elif echo "$OUT" | grep -q "drift (pending, ring not promoted"; then
  echo "fleet: channel drift exists but this node's ring is not yet promoted — waiting, no upgrade"
fi

echo "fleet: converged for node=$NODE (desired=$DESIRED)"
