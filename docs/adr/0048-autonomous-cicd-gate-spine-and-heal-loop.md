# ADR 0048 — Autonomous CI/CD: one deterministic gate spine, five lifecycle loops

**Status:** 🟡 **Proposed (2026-11-08)** — operator review. Implementation landed on branch
`worktree-autonomous-cicd` (tools/ci/**, 5 new workflows, root dependabot) and was validated
locally (see *Evidence*); GitHub-side behaviour (autoheal issues/PRs, metal runner) activates
after merge + the one-time setup in `tools/ci/README.md`.
**Deciders:** verification-engineer (gate ladder), release-engineer (release/rings/signing
boundary), security-auditor (guard + workflow threat model), product-steward (this record),
operator (ratification; branch protection + secrets + bench runner — **Red, operator-run**).
**Relates to:** ADR 0011 (Product Cortex, C9 "AI proposes, gates enforce"), ADR 0012 (release
rings), ADR 0013 (lifecycle events), ADR 0020 (adversarial harness), ADR 0023 (enforcement
separation), ADR 0036 (reproducible/verifiable supply chain), ADR 0046 (key custody, secrets
gate), ADR 0047 (heqk everywhere — new capability in `os/`).

> **Thesis.** The gates decide; agents only propose. Every check is ONE script
> (`tools/ci/gates.sh`) that runs identically on a laptop and in Actions. Around it, five loops:
> **Gate** (every PR), **Heal** (every red run → rerun / draft fix-PR / human),
> **Watch** (nightly fresh-advisory + full ladder, dependabot), **Release** (tag → unsigned,
> attested candidate; signing stays offline), **Learn** (every result → the Cortex graph).

## Context — what was actually true on 2026-11-07

Audited before designing (not assumed):

| Finding | Consequence |
|---|---|
| Only **2** live workflows (`build-heqk`, `secrets-scan`); `gate-ladder.yml` parked in `legacy/linux-tier/ci-workflows/` by the merge | no unit tests, clippy, or supply-chain check on any live path |
| `os/kernel/.github/{dependabot.yml, workflows/validation-matrix.yml}` | **inert** — GitHub reads only the root `.github/`; the matrix workflow, if revived, pushed straight to `main` |
| No `cargo audit`/`cargo-deny`/`npm audit` anywhere | first scan found **RUSTSEC-2026-0387** (crypto-bigint 0.5.5 constant-time leaks) reaching the **device TLS signing key** via `p256 0.13` in `tlsprov` + `el0-tlshost` — and osv.dev did **not** report it (verified by a parallel session's scan) |
| heqk clippy never run | 231 findings + **12 deny-by-default errors**, so `-D warnings` is unusable |
| `tlsprov` host tests | **2/4 failed** under the README's own invocation — a process-global RNG raced across parallel tests (flaky, schedule-dependent) |
| 7 Rust lockfiles + 2 npm lockfiles across detached workspaces | nothing guaranteed a new workspace would ever be scanned |

The pattern: **protection that silently stops**. Nothing failed — it just wasn't wired.

## Decision

### D1 · One gate spine, one entrypoint
`tools/ci/gates.sh` owns the ladder `g0 → g1 → g2 → g3 → g4 → g4r → g6`; workflows are thin
wrappers. Results land in `out/ci/gate-results.json` (machine-readable, the input of D4/D7).
Locally a missing tool is a *skip*; under `CI_STRICT=1` (all CI) it is a *fail* — CI can never
go green by not running something.

### D2 · G0 — "a gate that is not wired is not a gate"
`tools/ci/g0_wiring.py` fails on: a nested live `.github/` (W1); a workflow without top-level
`permissions`, with an unpinned action, with `pull_request_target`, or letting a PR reach a
self-hosted runner (W2); a workflow calling a missing script (W3); a live lockfile not in
`tools/ci/lockfiles.txt` (W4) or not covered by root dependabot (W5); a ladder gate not wired
into any workflow (W6); protected-path list not covering the gate machinery (W7). Plus
self-tests of all CI tooling and shellcheck — the gates are tested before they are trusted.

### D3 · Ratchets instead of big-bang strictness
Where the codebase is not yet clean, the gate is a **ratchet**, green on day one and only ever
stricter: `baselines/clippy.json` (per crate × lint, counts may only fall) and
`baselines/validate-phases.txt` (an implemented validate.sh phase may never be downgraded to
`plan` or deleted — the cheapest way to "fix" a red QEMU gate). Lowering a floor is a human PR.

### D4 · G4 — RustSec is the source of truth for Rust advisories
`cargo-deny` with one policy (`tools/ci/deny.toml`) over every lockfile: vulnerabilities and
yanked crates fatal; permissive AGPL-compatible licences only; crates.io only; every exception
carries a reason + re-review trigger. npm audit (prod, high+) and CycloneDX SBOMs (syft) per
lockfile. G4r: the shipped `prod` kernel must build bit-identically twice (ADR 0036 Rung 1).

### D5 · L2 Heal — deterministic triage, isolated autofix, guard, human merge
1. `heal/classify.py` (regex, no model) → `rerun` | `autofix` | `human`, with a stable failure
   **signature** (one issue, one attempt budget per signature).
2. `autofix` runs an agent (Claude Code headless by default; any command pluggable) in its own
   `git worktree` on `autofix/<sig>-aN`. It never commits/pushes; the harness does.
3. `heal/autofix_guard.py` rejects the diff if it touches a protected path (gates, workflows,
   deny/baselines, signing + keys, ADRs, governance), removes tests/asserts/PASS markers, adds a
   suppression, or is too large. The originally-red gate must re-run **green in that worktree**.
4. Only then: a **draft PR**. Merge is Red tier — always a human. Max 2 attempts/signature;
   per-attempt spend cap (`HEAL_MAX_BUDGET_USD`).
5. On GitHub (`autoheal.yml`, `workflow_run`): only trusted default-branch code executes; the
   failing run's logs are data; fork runs ignored; autofix only for default-branch failures
   (PR authors own their PRs and get the classification as an issue).

### D6 · L3 Watch / L4 Release / G6 Metal
`nightly.yml` re-runs the whole ladder on `main` against today's advisory DB (new CVE, unchanged
code), adds g2 unconditionally + g4r, and turns the validation-matrix refresh into a **PR** (never
a push to main). `release.yml`: tag → gates → `prod-mc` candidate + SBOM + SLSA provenance
attestation → **draft** release + signing checklist; heqk boot signing stays offline (ADR 0046
D4). `metal.yml`: self-hosted `cm5-bench` runner, nightly + dispatch, never from a PR; Gate-R
stays attended (dispatch input).

### D7 · L5 Learn
`cortex/ci_to_cortex.py` turns gate results and heal outcomes into schema-1 lifecycle events
(the same JSONL `hookprobe-evidence --ingest-lifecycle` already ingests); the dev-time hook now
also records `gates.sh`/`validate.sh`/`mc-e2e`/`heal.py` runs. Recurring signatures become
new-gate candidates: every new failure class gets a classifier rule + fixture test.

## Consequences
- **+** Silent un-wiring (the merge failure mode) is now a red G0. New detached workspaces must
  be registered or CI fails. A real device-crypto advisory was found and fixed on day one.
- **+** The heal loop removes triage toil without giving an agent the power to weaken a gate.
- **−** CI minutes rise (g3 boots QEMU + Chromium per PR; g4r doubles a release build nightly).
- **−** `autoheal` PRs opened with `GITHUB_TOKEN` don't trigger `ci.yml`; set `AUTOFIX_TOKEN`.
- **−** Regex classification will meet unknown failures — those go to a human (fail-safe), and
  each one is a prompt to add a rule.

## Evidence
(filled from the 2026-11-08 validation run — see below)
