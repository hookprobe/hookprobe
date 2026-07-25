# ADR 0012 — What a release is: versioning, channels, rings, and the Cortex release pass

**Status:** ✅ Accepted (2026-07-03) — D1–D4 accepted; D5 decided by the operator the same day:
**customer feedback is the priority** → the opt-in product-health beacon (the recommended shape
below) is adopted; alternative (b) (detection-efficacy stats) stays out pending its own threat model.
**Deciders:** operator, release-engineer, product-steward.
**Relates to:** [ADR 0011](0011-product-cortex.md) (Product Cortex), [ADR 0009](0009-soc-brain-edge-cloud.md)
(evidence graph / offload), [ADR 0002](0002-crypto-agility-pqc.md) (signing/HSM),
[ADR 0007](0007-data-at-rest-encryption.md) (signed releases), `.github/workflows/build-os.yml`,
`fleet/`, `builder/`.

## Context — two conventions, one missing blessing point

The repo already knows how to *build* a release but not how to *define* one. Contradictions found:

- `.github/workflows/build-os.yml:56-58` hardcodes `IMAGE_VERSION: "2026.6"` with a `# TODO: derive
  from the git tag on release (vX.Y.Z) and the calendar channel (2026.6)` — a note that itself
  proposes two incompatible schemes. `base/README.md:141-159` tags images
  `2026.6-<profile>-<arch>` (calendar). CI triggers on `tags: ["v*"]`
  (`build-os.yml:23`). Nothing reconciles "vX.Y.Z" vs "2026.6" today.
- The `promote` job (`build-os.yml:462-478`, `if: startsWith(github.ref, 'refs/tags/v')`) is a
  literal `echo "TODO: skopeo copy staging->stable for each (profile,arch); cosign sign promoted
  tags"` — the comment even calls this out as *"the only place a digest is blessed for fleet
  rollout"*. That place does not exist yet.
- `fleet/hookprobe.yaml` declares `channel: stable` and `rollout.ring: canary`.
  `crates/hookprobe-manifest/src/fleet.rs:37-39,51-75` parses `ring` into `DesiredState` but never
  reads it in `diff()` — only `ChannelMismatch` is emitted. `fleet/agent.sh:32-35` is a `# TODO:
  parse the drift output; if a ChannelMismatch applies to this ring: bootc upgrade` echo — ring
  windows are declared, not enforced.
- ADR 0011 D1 promises `release_image` / `shipped_in` / `gate_result` node types in
  `crates/hookprobe-evidence`, but that crate today only knows security-event node `Kind`s
  (`crates/hookprobe-evidence/src/main.rs:10-14`) — no lifecycle types exist, and nothing says who
  would emit a `release_image` node at release time.
- Run-side health evidence already exists and is currently thrown away at the boot boundary:
  `supervisor/src/main.rs:844-865` — `cli.health_gate` prints `BOOT HEALTHY`/`BOOT UNHEALTHY` and
  `exit(1)` on missing required modules (greenboot then runs `bootc rollback`); per-module outcomes
  are `HealthState::{Healthy,Healed,Failed,Reverted}`
  (`crates/hookprobe-manifest/src/health.rs:42-46`). `crates/hookprobe-evidence` can `--export`
  JSONEachRow (`src/main.rs:112-114`) but only writes to a local path — no transport moves it
  anywhere, cloud or otherwise.
- No product-feedback / opt-in-telemetry / crash-report channel exists anywhere in the specs. The
  standalone invariant (`docs/Readme.md`: no account, no cloud, air-gapped by default) means nothing
  leaves a standalone device today. ADR 0009 designs the JSONEachRow → ClickHouse offload for
  cloud-linked tenants, but per the point above, the transport is unbuilt.

This ADR fixes the *definition* (version/channel/ring/pass/notes). It does not implement CI,
fleet, or BuildPlan changes — those are separate, sequenced build steps owned by release-engineer
and reconciled into `docs/BuildPlan.md` by product-steward.

## Decision

### D1 · One versioning scheme

| | Decision |
|---|---|
| Release version | **Calendar**: `YYYY.M[.patch]` (e.g. `2026.7`, `2026.7.1`) — matches the existing `2026.6` convention already used in `base/README.md` image-tag examples. |
| Release trigger | A git tag `v<version>` (e.g. `v2026.7`) — matches the existing `tags: ["v*"]` CI trigger (`build-os.yml:23`), no workflow change needed. |
| `IMAGE_VERSION` in CI | **Derived from the tag** (`${GITHUB_REF_NAME#v}`), closing the `build-os.yml:57-58` TODO. Hardcoding is retired. |
| Image tags | Unchanged shape: `<version>-<profile>-<arch>` (`base/README.md:141-159`). |
| What gets blessed | **The OCI digest**, not the tag. Tags are human-readable pointers; `promote` (D3) re-points channel tags (`:stable`, `:beta`) at a specific already-built, already-signed digest. A tag can be re-cut; a promoted digest cannot silently change under a channel name. |

**Explicitly superseded:** the `vX.Y.Z` semver phrasing in the `build-os.yml:57` TODO comment. This
project has no independently-versioned components to semver against (bootc-image-builder tags are
opaque hardware artifacts, not a public API) — calendar versioning is the correct, and now the only,
scheme. Update the TODO comment to point at this ADR when D1 is implemented (build step 1, below).

### D2 · Channels and rings

| Concept | Values | Source |
|---|---|---|
| Channel | `stable` (default), `beta` (opt-in, receives releases first) | new — not yet in code; `fleet/hookprobe.yaml:9` currently hardcodes `channel: stable` |
| Ring (within a channel) | `canary → ring → fleet` | already declared: `fleet/hookprobe.yaml:22`, `crates/hookprobe-manifest/src/fleet.rs:37` |

**Promotion criteria (evidence-based, named against real signals that exist today):**

- **canary → ring**: promote only after **7 days** on `stable` (beta may promote faster —
  release-engineer sets a shorter window per release, never zero) with, across the canary
  population: zero `BOOT UNHEALTHY` / greenboot `bootc rollback` events
  (`supervisor/src/main.rs:844-865`), zero commit-confirmed `HealthState::Reverted` outcomes, and no
  *new* `Failed`/shed baseline module compared to the previous release's canary run
  (`crates/hookprobe-manifest/src/health.rs:42-46`).
- **ring → fleet**: same criteria, evaluated over the (larger) ring population, same window.
- **Consumption mechanism**: devices already detect they're behind via `Drift::ChannelMismatch`
  (`fleet.rs:53,60-61`, `"channel '{have}' != desired '{want}' → bootc upgrade"`); this ADR specifies
  that `fleet/agent.sh` step 3 (currently the `# TODO: parse the drift output` echo,
  `agent.sh:32-35`) must gate the `bootc upgrade` call on the node's `rollout.ring` being inside the
  promoted window for the target digest — closing that TODO is build step 3 below.
- **Honest limitation**: standalone/air-gapped devices (`docs/Readme.md` standalone invariant: no
  account, no cloud) do not phone home and cannot contribute health signal to a promotion decision,
  and do not auto-pull `bootc upgrade` at all — they update manually, operator-triggered. Promotion
  criteria above can therefore only be computed from **cloud-linked fleet devices + lab/QEMU/hardware
  gate devices** (ADR 0011 D4's gate ladder). A release with a large standalone install base is
  promoted on a smaller evidence sample than its true user population — say so in the release notes
  (D4), don't hide it.

### D3 · The Cortex release pass ("enable Cortex at every release")

Every promotion to a channel (D2) requires a **release pass**, assembled by the Ring-1 agents
(ADR 0011 D5) and approved by the operator. Per ADR 0011 D3, this pass is **Amber** — agents produce
the pass, the operator approves; the actual publish/tag/push/promote action is **Red** (never
autonomous), matching this file's own Boundaries.

| Role | Attests |
|---|---|
| `verification-engineer` | The gate ladder is green for this digest: workspace tests → clippy → `podman build` + `builder/smoketest.sh` → mkosi/QEMU boot (amd64 KVM, arm64 emulated) → greenboot health-gate semantics → hardware gates (Pi4/N100) when boot/partition/units changed (ADR 0011 D4). |
| `security-auditor` | Supply-chain: cosign signature, SBOM, CBOM, SLSA provenance present and *honestly* described (no claimed-but-absent PQC, no stale CBOM suite); reviews the diff since the last released digest for anything that should have triggered a hardware gate and didn't. |
| `release-engineer` | Produces the release notes (D4) and the version/channel/ring assignment (D1/D2). |
| `product-steward` | Verifies `docs/BuildPlan.md` truth (features claimed as shipped in the notes actually moved to ✅ in BuildPlan) and records the release in the Change Log. |

**Mechanical output — this closes the ADR 0011 "who emits `release_image`" hole:** the pass writes a
`release.json` evidence bundle (version, digest per profile/arch, channel, platforms, gate results,
signer identity, SBOM/CBOM refs) that `hookprobe-evidence` ingests as:

- one `release_image` node (version, digest, channel, platforms),
- `shipped_in` edges from the `commit`/`requirement` nodes in the diff since the last release,
- `validated_by` edges to one `gate_result` node per gate-ladder stage that ran.

**Emitter (two paths, same bundle shape):** (a) the CI `promote` job, once it exists (build step 2,
below) — the canonical path for anything that ships; (b) a local `builder/release-pass.sh` that
release-engineer can run against a dev-built digest for dry-run/rehearsal — extends `builder/`
per this file's own house rule of not forking parallel scripts. Both write the same `release.json`
shape so `hookprobe-evidence` has one ingest path regardless of origin.

### D4 · Release notes contract

Every promoted release gets an operator-readable note covering: what changed, platforms affected,
upgrade instructions (`bootc upgrade` / manual image re-flash for standalone), rollback instructions
(`bootc rollback`; greenboot auto-rollback conditions), a gate-evidence summary (pulled from the
`release.json` bundle — pass/fail per stage, not just "tests passed"), and known limitations stated
honestly (e.g., the Pi 4 software-key anchor documented in ADR 0007, or a promotion evaluated on a
canary population that under-represents standalone installs per D2).

Two artifacts, both required:
1. A `docs/BuildPlan.md` Change Log row (reconciled by product-steward, not this ADR).
2. A `docs/releases/<version>.md` note (new directory; does not exist yet — created as part of build
   step 4 tooling, populated per release thereafter).

### D5 · DECIDED (operator, 2026-07-03) — the customer-feedback return path is the opt-in beacon

No mechanism today lets a device tell anyone (HookProbe or the operator's own fleet ops) how a
release is actually behaving, except the cloud-linked ClickHouse offload designed in ADR 0009
(unbuilt transport) and lab/canary evidence. The invariant at stake, verbatim from `docs/Readme.md`
and this file's own canon: **"never gate the device on an account"** and standalone devices are
**"no account, no cloud, air-gapped"** by default — nothing leaves without explicit opt-in.

**Adopted shape:** an opt-in, **off-by-default** "product health beacon" —
capability-gated, with its own consent screen in Administration (not bundled into any other
setting), shipping *only* product-lifecycle signals: release version, platform class, boot/health/
rollback verdicts (`HealthState`), module-shed events, aggregate QSecBit — **never** security
telemetry, flow data, or customer data. Cloud-linked/MSSP tenants additionally get the full ADR 0009
evidence offload (that's already their model). Air-gapped operators could export the same beacon
file manually and attach it to a GitHub issue — no new transport required for that path.

**Alternatives to weigh:**
- (a) **No beacon.** Feedback stays cloud-linked-tenant evidence + GitHub issues only. Simplest,
  fully consistent with the standalone invariant as written today, but the promotion-evidence gap in
  D2 (standalone installs invisible to the loop) never closes.
- (b) **Beacon also carries anonymized detection-efficacy stats** (e.g., aggregate detection counts
  by category). More learning value for tuning HYDRA/QSecBit across the fleet, but materially more
  trust risk for a security product whose pitch is sovereignty — needs its own threat model before
  it could be proposed, not bundled into this ADR.

**Consequence of staying undecided:** the Cortex feedback loop (ADR 0011's `informed_by` edge,
field evidence → roadmap) works today for lab and cloud-linked evidence only. That is a real,
acknowledged limitation of D1–D4 as accepted, not a blocker to accepting them.

## Consequences

- **+** One version string, one trigger, one blessing point (the digest) — the `2026.6` vs `vX.Y.Z`
  contradiction is resolved in the record even before CI is touched.
- **+** Promotion is criteria-based and cites signals that already exist on-device
  (`HealthState`, greenboot rollback) instead of "someone decides it feels stable."
- **+** ADR 0011's dangling `release_image` emitter question has a concrete answer and an owner
  (`promote` job / `release-pass.sh` → `hookprobe-evidence`).
- **−** Promotion criteria are only as good as the canary/ring population that reports them; a
  release can be "promoted" while behaving differently on the (invisible, by design) standalone
  fleet. D5 is the only thing that closes this, and it is explicitly not decided here.
- ~~**−** Ring enforcement in `fleet/agent.sh` and `fleet.rs::diff()` does not exist yet (build step 3)~~
  — ✅ **LANDED 2026-07-05:** build steps 1–3 are built + tested. `fleet.rs::diff_ring_gated` (+ `RolloutState`)
  downgrades a `ChannelMismatch` to the non-actionable `ChannelMismatchPending` when the node's ring is
  outside the promoted window; `build-os.yml` derives `IMAGE_VERSION` from the `v*` tag (D1) and its
  `promote` job is a real `skopeo copy` + `cosign sign` (D2). Ring-gated rollout IS now live in the code.
- **−** The lifecycle graph ingest (`release_image`/`gate_result`/`shipped_in`) depends on ADR 0011
  build step 2 (lifecycle node/edge types in `crates/hookprobe-evidence`) — ✅ landed: the `releases`/
  `gate_results` node tables + `shipped_in`/`validated_by` edges exist and D3's emitter writes to them.

## Build steps (small, sequenced)

1. Derive `IMAGE_VERSION` from the `v*` git tag in `build-os.yml`; delete the hardcoded `"2026.6"`
   and the superseded semver TODO comment (D1).
2. Implement the `promote` job: `skopeo copy` the built-and-signed digest to the channel tag,
   `cosign sign` the promoted ref, gated on the release pass (D3) being attached — replaces the
   `build-os.yml:462-478` TODO echo.
3. Ring-window enforcement: `fleet.rs::diff()` reads the promoted-rings-per-digest data (from the
   `release.json` bundle or a small rollout-state file) and only emits an actionable
   `ChannelMismatch` when the node's `rollout.ring` is inside the promoted window;
   `fleet/agent.sh` step 3 calls `bootc upgrade` on that signal — replaces the `agent.sh:32-35` TODO.
4. `builder/release-pass.sh` + lifecycle-graph ingest in `hookprobe-evidence` (depends on ADR 0011
   build step 2); stand up `docs/releases/` with the first `<version>.md` note.
5. D5, once the operator decides: implement the beacon (or explicitly choose alternative (a) and
   record that as the closing decision on this ADR).

---

## heqk migration — see [ADR 0043](0043-heqk-microkernel-substrate.md)

**Coupling: SOFT.** The calendar-versioning + channels/rings + cortex-release-pass model survives unchanged. Only the *consumption* mechanism (`bootc upgrade` / greenboot rollback / OCI digest) is replaced by heqk's A/B update transport — which already ships on metal (`heqk8.img`/`-b` + watchdog tryboot). The release pass gains a heqk digest type. → **Phase M3**.
