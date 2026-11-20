# Engineering journal

Newest first. Each entry: what was investigated or changed, the evidence, and its status.


## 2026-11-20 — AB-15: the Linux-tier architecture doc is removed

- Asked whether to rename the legacy `docs/architecture/Readme.md` or the small `README.md` index (they collide on macOS), the operator answered "no linux remove anything about linux". Done for this item: `Readme.md` deleted (last version `e4c48181` in history), `README.md` kept as the folder index with ADR 0047 first.
- Live links repointed in 9 unprotected files (README, CONTRIBUTING, docs index, HLD, BuildPlan, Architecture.md, runtime-engine-map, V1-alignment). Dated research notes and journal rows that name the file in plain text are history and left as written.
- Not touched (protected or frozen): `CLAUDE.md` (3 mentions), 17 ADRs, `.claude/agents/` (4), `legacy/linux-tier/` (12). Wider "remove anything about Linux" (the `legacy/linux-tier/` workspace, CLAUDE.md's legacy sections, Track B in BuildPlan) is a larger change: asked the operator for its scope instead of guessing.
## 2026-11-18 — Session 2 (cont.): real rule ids in the sample incident

- The device reports rule ids as `HEQK_RULE_BAND` (1,200,000) + the kernel id (`rulecat.rs:12`). The
  preview incident used 100004 / 100017, which no device emits, and a "domain on 3 threat feeds"
  detection that has no rule: known-bad names are Shield blocks, not detections.
- `IncidentExplain` and `IncidentApp` samples now tell the same story as the design canvas: rule
  1200125 "Known-malicious TLS client (JA4)" (ioc_match, T1071.001, high), then 1200113 "Port scan"
  (port_scan, T1046, medium), rule_msg in the device's "<msg> (<verdict>, <class>)" form; zone
  Full access (IoT is not a zone). Unit-test fixtures keep their own arbitrary ids.

## 2026-11-18 — Session 2 (cont.): the real logo

- Operator: "the logo here is the logo". Both rails showed a placeholder glyph ("◣◢") and the favicon was
  a generic green circle. The mark is the hexagon symbol between "HOOK" and "PROBE" in
  `assets/hookprobe-logo.svg`. New `LogoMark.tsx` draws it inline in `currentColor` (viewBox
  `1128 25 580 620` in the path's own coordinates); `public/favicon.svg` is the white mark on the
  existing dark tile. The design canvas uses near-black copies (TopBar wordmark, ProRail mark).

## 2026-11-18 — Session 2 (cont.): AB-09 and AB-10

- #1298 merged with 13 checks still running; its CI result is recorded when it finishes.
- homepods' `heqk-gap-fix-plan-2026-11-18.md` (#1297) is kernel-only (R1–R10, E1–E5); no overlap.
- **AB-09**: heqk serves an always-empty process tree on purpose (`http.rs:713`, no EDR agent), but
  the panel said "this device's EDR layer may not have observed process activity for it yet". The
  empty state now keys on capability `host_telemetry`: granted → "not linked yet"; otherwise "This
  device does not see processes" with why. Capability-gated, not substrate-branched. HP-09 asks
  homepods to deny `host_telemetry` with a reason so the device states it.
- **AB-10**: `/api/reports` clamps `limit` to 32 (`http.rs:741`, `MAX_INCIDENTS` = 32, most recent
  activity first) and does not say when it cut the list. A full page of 32 now shows "Showing the 32
  most recently active incidents, the most this device lists."
- Evidence: `astro check` 0 errors; `astro build` 27 pages. **Not browser-checked**: the mock server
  binds and answers inside its own process, but this shell's sandbox now refuses localhost between
  processes and the in-app browser cannot reach it either. New spec `investigate-honest.mjs` covers
  both states and both capability cases; its first run is CI g3.

## 2026-11-18 — Session 2 (cont.): AB-07 and AB-12

- #1280 and #1281 merged with CI green. g3 ran the new `revoke-all` spec: 12/12, UI suite 437/437.
- **AB-07**: no change. The Intelligence CVE tab has shown an honest empty state since
  `47a2ad85` (2026-11-10); the audit's U-03 read the kernel gap (no `/api/exploitability`) as a UI
  problem.
- **AB-12**: heqk denies `multi_wan`, `guest_ssid` and `openvswitch` with reasons
  (`capabilities.rs:28-30`), so the three handler-less buttons are greyed today. If one were granted,
  `Gate` would render a live-looking button that does nothing. `Gate` gains `notBuilt`: granted +
  `notBuilt` renders like denied with that reason. Applied to "Add backup", "Turn on guest Wi-Fi" and
  "Configure segmentation". `hide` still keys on the real answer. Evidence: in-app browser against a
  mock device granting all three: each greyed, inert, "Mission Control has no screen for this yet."
  New spec `gate-not-built.mjs` (CI g3 runs it).

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
