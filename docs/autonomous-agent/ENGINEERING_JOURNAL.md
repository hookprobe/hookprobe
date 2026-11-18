# Engineering journal

Newest first. Each entry: what was investigated or changed, the evidence, and its status.

## 2026-11-18 — Session 2 (cont.): AB-06 and AB-11

- **AB-06** (#1280): `package.json` description says heqk serves the UI. One line; `release_check.py` passes.
- **AB-11**: Protect → Rules gains "Remove all owner rules…". Contract read from `ownerapi.rs`
  (read-only): `POST /api/owner-rules/revoke-all`, `op=revoke_all`, reason ≥ 3, `dry_run=1` preview,
  then `permanent=true` + `owner_key`. One `OP_CLEAR` journal record zeroes every owner rule and clears
  the LAN-access exception table (`ownerjournal.rs:376`); signed baseline and management floor stay.
  The UI previews with the device's dry run, lists what it reports (rules + LAN-access count), asks for
  reason + device password in the destructive Approve sheet, and says "verified" only when
  `/api/owner-rules` and `/api/lan-access` read back empty.
- Evidence: `astro check` 0 errors; `astro build` 27 pages; full flow driven in the in-app browser
  against a local mock device (Python, test data only): dry run → approve → "Applied and verified",
  table empty, button disabled; the mock recorded exactly the two expected POSTs. New Playwright spec
  `revoke-all.mjs` is not run locally (no Playwright here); CI g3 runs it.
- **`main` was rewritten** on 2026-11-18 at the operator's request, to correct commit authorship
  (old `main` `88d88169`, new `6e875c87`; trees identical). Work is now based only on the new
  `origin/main`, never merged from old-history branches, and committed only as the `hookprobes`
  noreply identity. #1281 was re-parented with `git commit-tree` (same tree, no force-push). The
  other session replayed #1280 onto the new `main`; my first read missed that (I checked a stale
  local worktree), so I opened a duplicate, #1282, to be closed.
- Lesson from #1278/#1279: status updates now ride in the PR for the work they describe.

## 2026-11-18 — Session 2: AB-17 docs corrections

- #1268 and #1269 were merged by the operator on 2026-11-17. `main` @ `1a4f2b11` also carries the
  other session's `feat/mc-explainability` and `feat/sealed-evidence-export`.
- **G13:** the row was already marked done for the four Investigate routes. Re-checked:
  `/api/manifest` and `/api/verdicts/dns` are served nowhere in `os/kernel` and nothing in
  `os/mission-control/src` calls them. The row now says they were dropped, not done.
- **G12:** "MC QR panel" was half true. Mission Control has a QR for the home Wi-Fi
  (`QrSheet.tsx`, `51336c8f`), but no QR for the setup network, which is only on the printed
  label. The row now says that, and stays open.
- **G48:** the row said "until G43/G44 land". G44 is closed and G43 is built (QEMU only), so the
  row now says both files upload on a running device.
- **ADR 0037:** five citations read "ADR 0037 (retired …; see in part 0051 / 0054 / 0058 / 0059)",
  an inserted phrase that broke the sentences. Each now names the decision that applies. Per
  ADR 0037's own status note, D3 is still cited by ADR 0053/0054 and the browser flasher has no
  other design, so those two stay attributed to ADR 0037 and are marked retired.
- Not touched: `os/kernel/GAP_REGISTER.md` (kernel, homepods) and `docs/adr/` (protected).

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

**Delivered (local)**
- `agent/engineering-audit`: audit docs, 2 commits.
- `agent/mc-honest-states` @ `02cb4780`: Copilot "no AI model" link fixed (AB-05). Evidence:
  `astro check` 0 errors / 111 files; `astro build` 27 pages; in-app browser against the preview
  build: no hash → "Edge node", `#ai` → AI models + "no on-device planner", `#nonsense` → "Edge
  node". Local tooling trick: symlinked the main checkout's `node_modules` (read-only), removed
  after. Playwright not installed, so the added spec line was not executed.
- `git push` → 403 for account `hookprobes` on both branches. Nothing pushed.

**Handed to other session:** AB-04 (TopBar "Protected" from sample 92; fake sparklines), as it
owns the QSecBit files.
