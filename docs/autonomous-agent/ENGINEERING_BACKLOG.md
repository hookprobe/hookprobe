# Engineering backlog

Priority order (operator brief): security/isolation → broken critical journeys → wrong enforcement →
data integrity → broken integrations → reliability → missing essentials → UX → performance → docs.
Status: `open` · `in progress` · `blocked` · `implemented` · `locally tested` · `CI validated` ·
`pushed` · `in review` · `merged`. Owner: `agent` (this agent), `other-session`, `homepods`,
`operator`.

| ID | Item | Components | Root cause | Impact (customer / security) | Sev | Depends | Proposed change | Validation | Owner | Status |
|---|---|---|---|---|---|---|---|---|---|---|
| AB-01 | Release trust chain incomplete (TC-01..04, SEC-05) | release-gate, signing | signoffs never done | cannot ship safely / high | P1 | operator | operator signoffs; agent can draft the SEC-05 review checklist | `tools/release-gate` items green | operator | blocked |
| AB-02 | Getting-started describes one image + one owner key for all buyers | docs/getting-started | doc ahead of product | customer can't onboard; shared key / high | P1 | AB-01 | rewrite as the real path (factory-provisioned unit, owner card) and mark self-flash "not available yet" | doc review vs `tools/provisioning` | agent | open |
| AB-03 | Two shipping-flavour definitions (`release.yml` prod-mc vs `shipping-features.txt`) | release.yml, tools/ci | drift | wrong image could ship / medium | P1 | — | operator picks one; agent fixes docs to match | G0 drift check | operator (protected) | open |
| AB-04 | TopBar "Protected" + fake sparklines from sample data on a live device (U-01, U-02) | mission-control TopBar, AppRail, mock.ts | sample seeds not gated | false reassurance / medium | P2 | — | gate on `qsecbitKnown`; empty state instead of heartbeat | UI spec with live-mode empty history | other-session | merged to `main` with `feat/mc-explainability` |
| AB-05 | Broken Copilot link `/administration/ai-models` (U-07) | CommandPalette.tsx | page never built | dead end / none | P2 | — | link `/admin/identity#ai` (AI models section) + hash deep link | astro check + browser + UI spec | agent | merged (#1268, 2026-11-17) |
| AB-06 | `package.json` says "served by Rust/Axum" (U-12) | mission-control package.json | stale since ADR 0047 | confusing / none | P4 | other session's branch | say "served on-device by heqk" | G0 release_check (version unchanged) | agent | merged (#1280) |
| AB-07 | Intelligence CVE board never live (U-03, HP-01) | itlLive.ts, kernel | route missing | feature unavailable | P2 | HP-01 | until served: label tab "Not on this device yet" instead of silent fallback | UI spec | agent | no change needed: honest empty state since `47a2ad85` (audit finding was wrong) |
| AB-08 | Device map shows bare IPs (U-05, HP-02) | obsLive.ts, kernel | thin payload | unusable inventory | P2 | HP-02 | UI empty-field states now; full fix kernel-side | UI spec | homepods + agent | blocked |
| AB-09 | Process tree always empty (U-06) | Investigate | no EDR on heqk | dead panel | P3 | — | hide behind a capability or explain "no endpoint agent" | UI spec | agent | open (wait for other-session's Investigate work) |
| AB-10 | Reports silently capped at 32 (U-09, HP-05) | investigateLive.ts | undocumented cap | missing history | P3 | — | show "latest 32" | UI spec | agent | open (after other-session) |
| AB-11 | Served routes without UI: revoke-all, lan-access (U-10) | Administration | not built | owner can't revoke all sessions/rules in one step / low | P3 | — | add "Revoke all owner rules" with confirm | UI spec + mc-e2e covers route | agent | merged (#1281) |
| AB-12 | Latent dead buttons inside `Gate` (U-11) | GetOnline, Protect | no handler | broken when capability lands | P3 | — | add handlers or explicit "coming" state | UI spec with capability granted | agent | implemented, locally tested (mock device), pushed, draft PR |
| AB-13 | `heqk-sign` has no tests; G1 runs empty `cargo test` (SF-04) | os/build/heqk-sign, tools/ci | never written | signer untested | P2 | — | human-authored tests (protected path) | G1 shows >0 tests | operator | open |
| AB-14 | `tools/provisioning` (42) + `pi4-wsensor` (13) tests not in CI | tools, .github | not wired | factory regressions undetected | P2 | — | add to gates.sh G1 (protected) — agent drafts the patch text for a human PR | G1 runs them | operator | open |
| AB-15 | Case-colliding `docs/architecture/{README,Readme,readme}.md` (G-14) | docs | three names | every macOS checkout dirty; clobber risk | P2 | operator naming choice | rename legacy one to `LEGACY-linux-tier.md`, merge the other two; fix links | fresh macOS worktree clean | agent (after operator OK) | open |
| AB-16 | Docs contradict ADR 0047 (MissionControl.md §12 bootc/Marketplace; Wasm/Sigma/RBAC "implemented") (G-07, G-08, G-11) | docs | drift | wrong expectations | P3 | — | docs outside `docs/adr/` fixed by agent; ADR status lines → operator | review | agent + operator | open |
| AB-17 | Stale gap-register rows (G13, G48, G12 QR) and READMEs citing retired ADR 0037 (G-09, G-12) | docs/design, READMEs | drift | misleading status | P4 | — | correct rows with evidence | review | agent | merged (#1279, 2026-11-18) |
| AB-18 | No browser-driven E2E for WAN/Wi-Fi/firewall change, login UI, onboarding against a device | mc-e2e | coverage gap | journeys unproven | P2 | protected (`os/kernel/tools/`) | agent drafts new specs; wiring is a human PR | G3 | operator | open |
| AB-19 | G6 metal gate dark (last 5 runs skipped) | metal.yml, bench | runner offline? | no hardware truth | P2 | bench | operator checks the self-hosted runner | metal.yml green | operator | open |
| AB-20 | No local toolchain here (QEMU, cargo, npm) | dev env | — | agent can't run gates locally | P3 | operator OK to install | `brew install qemu rustup node` or a Linux runner | gates.sh pr runs | operator | open |
