# fleet/ — pull-based GitOps fleet management

How a fleet of HookProbe OS devices stays in desired state — **without** a central
push system poking each box. Each node **pulls** its desired state, diffs it against
its own live manifest, and converges. Resilient by design: pull (not push) survives
intermittent links; nodes operate disconnected and re-converge when the link returns.

## Model

```
desired state (Git / signed OCI)            device (live)
  fleet/hookprobe.yaml          ── pull ──►  manifest.json + running modules
  fleet/rollout.yaml (rings)  ─┐ ── pull ──►
                                │                  │
        └──────── fleet::diff_ring_gated ──────────┘
                          │ drift (actionable | pending)
                          ▼
        supervisor: reconcile + self-test/heal   (modules)
        bootc upgrade --check (ring-gated; real apply is a TODO) (OS image)
```

- **Desired state** (`hookprobe.yaml`): channel, mode, modules to enable/disable,
  rollout ring. Per-node at scale: `fleet/nodes/<node>/hookprobe.yaml`.
- **Rollout state** (`rollout.yaml`, ADR 0012 D2/D3): `version`, `digest`,
  `promoted_rings` (e.g. `[canary]`), `channel` — which rings a promoted digest has
  reached, written by the `promote`/`release-pass` CI jobs
  (`.github/workflows/build-os.yml`). Repo-root, not per-node; same shape for every
  node on a channel. **Absence is not an error** — it's the legacy path (see below).
- **Drift** (`crate::fleet::diff`, unit-tested): module-should-start / -stop /
  channel-mismatch. Pure function — no ring awareness, desired vs actual only.
- **Ring-gated drift** (`crate::fleet::diff_ring_gated`, unit-tested — in-window,
  out-of-window, no-rollout-file legacy path all covered): wraps `diff` and
  downgrades a `ChannelMismatch` to the non-actionable `ChannelMismatchPending` when
  the node's `rollout.ring` (from `hookprobe.yaml`) is not yet in `rollout.yaml`'s
  `promoted_rings` — printed as a DISTINCT line by the supervisor `--fleet` output
  (`drift (actionable): ...` vs `drift (pending, ring not promoted — no upgrade): ...`)
  so the operator sees "behind, but waiting on your ring" instead of nothing.
- **Self-heal:** the supervisor's health phase sheds/reverts a failed apply; a bad
  image upgrade is caught by the boot-health gate (`bootc rollback`).
- **Rollout rings:** changes promote `canary → ring → fleet`, health-gated at each
  step — a rising failure rate halts promotion (promotion criteria: ADR 0012 D2).

## Try it

```bash
# Build the tools, generate a live manifest, then diff a desired state against it:
cargo build -p hookprobe-supervisor
./target/debug/hookprobe-bootstrap -o /tmp/m.json
./target/debug/hookprobe-supervisor /tmp/m.json --modules modules \
   --sign-modules /tmp/rk.key \          # so signature:required modules verify
   --fleet fleet/hookprobe.yaml \        # prints "Fleet GitOps (desired vs live)" drift
   --rollout fleet/rollout.yaml          # optional: ring-gates the channel-mismatch drift

# Exercise the pull loop against a local (non-Git) desired-state dir:
mkdir -p /tmp/fleetwork && cp fleet/hookprobe.yaml fleet/rollout.yaml /tmp/fleetwork/
FLEET_WORK=/tmp/fleetwork MANIFEST=/tmp/m.json \
  SUP=./target/debug/hookprobe-supervisor HOOKPROBE_FLEET_DRY_RUN=1 ./fleet/agent.sh
```

`fleet/agent.sh` is the on-device pull loop (run via a systemd timer): pull → diff
(ring-gated) → converge → guarded `bootc upgrade --check` when the drift is
actionable AND `bootc` is present on the host; `HOOKPROBE_FLEET_DRY_RUN=1` prints the
call instead of running it.

## Status

- ✅ desired-state schema + drift engine (`crate::fleet::diff`, unit-tested) +
  supervisor `--fleet` wiring (prints drift).
- ✅ ring-window enforcement (ADR 0012 D2/build-step-3): `rollout.yaml` schema +
  `crate::fleet::diff_ring_gated` (unit-tested: in-window, out-of-window, legacy) +
  supervisor `--fleet --rollout` wiring (prints actionable vs pending distinctly) +
  `agent.sh` step 3 (parses the supervisor output; gates the `bootc upgrade --check`
  call on `command -v bootc`; `HOOKPROBE_FLEET_DRY_RUN=1` for testing).
- 🟡 **HONESTY**: `agent.sh`'s guarded call is `bootc upgrade --check` (verify-only,
  non-mutating) — the actual mutating `bootc upgrade` apply is a documented TODO,
  deliberately not wired until this path is validated against a real bootc-managed
  host. Promotion itself (who writes `rollout.yaml`, and when) is the CI `promote` /
  `release-pass` jobs in `.github/workflows/build-os.yml` — also cannot run on a
  box without a registry/cosign identity; see that workflow's own HONESTY banner.
- ⬜ central control-plane views (Customers/Fleet workspaces), signed-OCI desired
  state at very large scale, automated ring promotion (the 7-day evidence-based
  criteria in ADR 0012 D2 — canary/ring health signal aggregation — isn't built).

See `docs/architecture/Readme.md` "Fleet & scale", `docs/adr/0012-release-definition-cortex-pass.md`
(D2/D3), `docs/roadmap/BuildPlan.md`, `docs/architecture/OS-platform-report.md`.
