# Engineering journal

Newest first. Each entry: what was investigated or changed, the evidence, and its status.

## 2026-11-17 — Session 1: discovery

**Setup**
- Main checkout `~/Documents/hookprobe` is on `feat/mc-explainability`, owned by the parallel
  session "Hookprobe isolated branch setup". Agent works in
  `~/Documents/hookprobe-worktrees/agent-audit` on `agent/engineering-audit` from `origin/main`
  @ `65196b0b`.
- Operator approved pushing to non-`main` branches; operator reviews and merges.

**Findings with evidence**
- Kernel ownership: 200/200 recent `os/kernel` commits by the `homepods` account. No CODEOWNERS
  and no submodules, so the boundary is convention only. Protected list adopted from
  `tools/ci/heal/protected-paths.txt`.
- The gate-spine ADR is 0063, not 0052.
- `docs/architecture/{README.md,Readme.md,readme.md}` differ only by case. On macOS's
  case-insensitive filesystem every fresh checkout shows one as modified (reproduced in a brand-new
  worktree). Risk: an `add -A` commits a clobbered architecture doc.
- `os/build/heqk-sign/src/main.rs` has no `#[test]`/`#[cfg(test)]`, while `tools/ci/gates.sh:101`
  runs `cargo test` there as a G1 step: a green step that tests nothing, on the image-signing tool.
- This Mac has no QEMU, cargo or npm, so G1–G4 cannot be proven locally.
- Wireframe canvas cross-checked against `os/kernel/kernel/src/mcstate.rs` (read-only):
  QSecBit `band()` = risk <300‰ GREEN, <700‰ AMBER, else RED; `render_incident` keys are
  `id, title, priority, status, device_ip, threat_score, ts, explanation{why, confidence, evidence,
  model, related_events}, attack_path`. Canvas v60 corrected to match.

**Status:** analysis only. Nothing implemented.
