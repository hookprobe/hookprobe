# Ownership, protected paths and task registry

Established 2026-11-17 from repository evidence before any change was made.

## 1. Kernel boundary — read-only, owned by homepods

| Evidence | Finding |
|---|---|
| `git log -200 -- os/kernel` | 200/200 commits by the `homepods` GitHub account (also signs as "Andrei Toma", same noreply id `3350272+homepods`) |
| CLAUDE.md, layout | `os/kernel/` is "ONE self-contained nightly no_std Cargo workspace (never split it)" |
| `.gitmodules`, `CODEOWNERS` | None exist. Ownership is by convention, not enforced by GitHub |

**The agent never modifies, refactors, reverts or commits anything under `os/kernel/**`**,
including kernel tests, build config, `boot-abi`, `hboot`, `hal/src/release.rs` and
`os/kernel/tools/`. It reads the kernel to learn its interfaces (HTTP API served to Mission
Control, upload bundle formats, IPC) and files any kernel need in
[HOMEPODS_HANDOFF.md](HOMEPODS_HANDOFF.md).

## 2. Protected paths — never changed by the agent

Canonical list: `tools/ci/heal/protected-paths.txt` (ADR 0063 L2, enforced by
`tools/ci/heal/autofix_guard.py`). The agent applies it to all of its own work, not only to
autofix, plus the kernel tree:

| Group | Paths |
|---|---|
| Kernel (owner: homepods) | `os/kernel/**` |
| Gate machinery | `.github/`, `tools/ci/`, `tools/build/git-hooks/`, `os/kernel/validate.sh`, `os/kernel/tools/` |
| Build-time code and lint config | `*build.rs`, `*/.cargo/*`, `.cargo/*`, `*clippy.toml`, `*rust-toolchain*`, `.gitattributes`, `*/.gitattributes` |
| Secret and supply-chain policy | `.gitleaks.toml` |
| Signing, keys, trust anchors (Red tier) | `os/build/heqk-sign/`, `os/build/make-cm5-heqk-image.sh`, `os/build/make-cm5-heqk-disk.sh`, `os/kernel/hboot/src/attest_keys.rs` |
| Governance | `docs/adr/`, `LICENSE`, `LICENSING.md`, `SECURITY.md`, `CLAUDE.md`, `.claude/` |
| Frozen | `legacy/**` (bug and security fixes only, ADR 0047; agent treats as read-only unless asked) |

When ownership of a path is unclear, the agent treats it as protected and asks.

The agent's own guard: before every commit, run
`python3 tools/ci/heal/autofix_guard.py --base origin/main` from the worktree. A1 (protected
path), A2 (tests removed), A3 (suppression added) or A6 (PASS marker edited) blocks the commit.

## 3. Governance tiers (CLAUDE.md, Cortex contract C9)

| Tier | Covers | Agent may |
|---|---|---|
| Green | docs, analysis | do autonomously |
| Amber | code, ADR, roadmap changes | prepare on an isolated branch; operator reviews |
| Red | commits, releases, flashing, merging | **only with operator approval** |

> **Operator decision (2026-11-17):** the agent may commit and push to its own non-`main`
> branches and open draft PRs. It never pushes to `main`, never merges, never force-pushes; the
> operator reviews and merges. Releases, signing and flashing stay Red (operator only).

## 4. Writable scope for the agent

Everything not listed above. In practice: `os/mission-control/**` (except files another
session is changing, see §5), `onboarding/**` (same caveat), `tools/{flash,diagnostics}/`,
`appliance/**`, `docs/**` except `docs/adr/`, `os/{drivers,networking,security,provisioning}/`
index READMEs, `assets/**`.

## 5. Task ownership registry

Check here before starting anything. One owner per file set.

| Work | Owner | Branch | Paths | State |
|---|---|---|---|---|
| heqk kernel | homepods | various | `os/kernel/**` | active |
| Sealed evidence export (HQX3) + ADR 0066 | session "Hookprobe isolated branch setup" | `feat/sealed-evidence-export` | `onboarding/enrollment/evidence-export/`, `docs/adr/0066-sealed-evidence-export.md` | committed locally, not merged |
| Mission Control explainability (Dig deeper drawer, Case card, QSecBit band, Shield audit) | session "Hookprobe isolated branch setup" | `feat/mc-explainability` (main checkout, 6 commits, local) | `os/mission-control/src/store/{explain,qsecbitLive}.ts`, `src/components/{DigDeeper,IncidentExplain,QsecbitBand,Drawer,IncidentApp,MissionControlApp,ShieldApp}.tsx`, `src/styles/pro.css` (end block), `src/store/{mock,live}.ts`, `src/components/{AppRail,App,TopBar}.tsx`, `src/styles/{global,layer0}.css` (appended lines), `package.json`, `tests/unit/`, `docs/adr/notes/2026-11-17-mc-explainability-payload.md` | committed locally, not merged |
| Engineering audit + backlog | this agent | `agent/engineering-audit` | `docs/autonomous-agent/**` | merged (#1269) |
| AB-09/10 Investigate honest states | this agent | `agent/mc-investigate-honest` | `src/components/InvestigateApp.tsx`, `tests/ui/specs/investigate-honest.mjs` | pushed, draft PR |
| AB-12 notBuilt gate | this agent | `agent/mc-intel-honest` | `src/components/{Gate,GetOnlineApp,ProtectApp}.tsx`, `tests/ui/specs/gate-not-built.mjs` | merged (#1298) |
| AB-11 Remove all owner rules | this agent | `agent/mc-revoke-all` | `src/components/{ProtectApp,RevokeAllPlan}.tsx`, `src/store/ownerRules.ts`, `tests/ui/specs/revoke-all.mjs` | merged (#1281) |
| AB-06 package.json description | this agent | `agent/mc-pkg-description` | `os/mission-control/package.json` | merged (#1280) |
| AB-17 docs corrections | this agent | `agent/docs-ab17` | `docs/design/{heqk-parity-gaps,mission-control-ui-requirements}.md`, `os/provisioning/README.md`, `tools/{flash,provisioning}/README.md`, `appliance/waveshare-dual-eth/README.md` | merged (#1279) |
| AB-05 Copilot AI-models link | this agent | `agent/mc-honest-states` | `src/components/{CommandPalette,AdministrationApp}.tsx`, `tests/ui/specs/pro-workspace-admin.mjs` | merged (#1268) |

## 6. Working-copy rules

- The main checkout `~/Documents/hookprobe` belongs to the other session. This agent never
  checks out, stashes or commits there.
- Agent worktrees live in `~/Documents/hookprobe-worktrees/<task>`, one per branch.
- Prove location (`git rev-parse --show-toplevel`, branch) before every git write.
