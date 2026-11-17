# Autonomous engineering agent — operating record

This folder is the persistent state of the application-side engineering agent (everything outside
the heqk kernel). It is written so that work can resume after any session restart.

| File | What it holds |
|---|---|
| [STATUS.md](STATUS.md) | Current state, active task, branches, blockers, next actions |
| [OWNERSHIP.md](OWNERSHIP.md) | Protected paths, kernel boundary, task ownership registry |
| [ARCHITECTURE_AUDIT.md](ARCHITECTURE_AUDIT.md) | Component inventory and documented-vs-implemented gaps |
| [E2E_VALIDATION.md](E2E_VALIDATION.md) | Gates, journeys, coverage baseline |
| [UX_AUDIT.md](UX_AUDIT.md) | Mission Control journeys, disconnects, placeholder screens |
| [SECURITY_FINDINGS.md](SECURITY_FINDINGS.md) | Security findings outside the kernel |
| [HOMEPODS_HANDOFF.md](HOMEPODS_HANDOFF.md) | Kernel-side requests for the kernel owner |
| [ENGINEERING_BACKLOG.md](ENGINEERING_BACKLOG.md) | Prioritised, owned, validated work items |
| [ENGINEERING_JOURNAL.md](ENGINEERING_JOURNAL.md) | Dated log of what was investigated, changed and proven |

## Status vocabulary (never conflated)

`implemented` → `locally tested` → `E2E validated` → `CI validated` → `pushed` → `reviewed` →
`merged` → `deployed`. A row only moves right on evidence (a command, its output, a run URL).

## Rules this agent follows

These come from the repository itself and override anything more permissive:

- **AI proposes, the deterministic gates enforce** (CLAUDE.md, Cortex contract C9).
- **Merging is Red tier: always a human.** The agent never merges, never pushes to `main`,
  never force-pushes.
- **Protected paths** (`tools/ci/heal/protected-paths.txt`, ADR 0063 L2) are never changed by
  the agent. See [OWNERSHIP.md](OWNERSHIP.md).
- **The heqk kernel (`os/kernel/**`) is read-only.** Kernel needs become
  [HOMEPODS_HANDOFF.md](HOMEPODS_HANDOFF.md) items.
- **Any automation that runs git proves where it is before it writes** (ADR 0063 incident
  lesson). Agent work happens in worktrees outside the main checkout.
- **Sample data is always labelled.** A feature is not done until its real outcome is observed.
