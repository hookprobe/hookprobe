# Status

_Updated 2026-11-18 (later)._

## Platform status

**Kernel and API are in good shape; the customer journey is not.** The device API serves almost
everything the UI calls, auth is consistent (no unauthenticated writes found), and sample data is
labelled. What a customer cannot do yet: obtain and claim a device without the factory station,
reach a captive setup portal, or rely on the Intelligence, device-name, process-tree and Copilot
views. Release trust-chain signoffs are open. See [ARCHITECTURE_AUDIT.md](ARCHITECTURE_AUDIT.md).

## Active task

AB-15: operator said "no linux, remove anything about linux". `docs/architecture/Readme.md` (the Linux-tier architecture) deleted, which ends the macOS case collision with `README.md`; live links outside protected paths repointed to ADR 0047 / `os/kernel/ARCHITECTURE.md`. Branch `agent/docs-ab15`, draft PR.

## Delivery ledger

| Work | Branch | Implemented | Local tests | CI | Pushed | PR | Merged |
|---|---|---|---|---|---|---|---|
| Engineering audit docs | `agent/engineering-audit` | yes | n/a (docs) | green | yes | [#1269](https://github.com/hookprobe/hookprobe/pull/1269) | yes (2026-11-17) |
| AB-05 Copilot AI-models link | `agent/mc-honest-states` @ `02cb4780` | yes | astro check 0 errors; build 27 pages; browser check of 3 hash cases; Playwright spec added but not run locally | green (g3: "PASS pro-workspace-admin: admin: #ai deep link opens AI models") | yes | [#1268](https://github.com/hookprobe/hookprobe/pull/1268) | yes (2026-11-17) |
| AB-17 stale register rows + ADR 0037 citations | `agent/docs-ab17` | yes | n/a (docs) | secrets-scan pass; ci + CodeQL still running at merge | yes | [#1279](https://github.com/hookprobe/hookprobe/pull/1279) | yes (2026-11-18) |
| AB-06 package.json description | `agent/mc-pkg-description` | yes | release_check passes | green (18 pass) | yes | [#1280](https://github.com/hookprobe/hookprobe/pull/1280) | yes (2026-11-18) |
| AB-11 Remove all owner rules (Protect) | `agent/mc-revoke-all` | yes | astro check 0 errors; build 27 pages; full flow in the in-app browser against a local mock device (dry run → approve → verified; requests match the heqk contract); new UI spec `revoke-all` not run locally (no Playwright) | green (17 pass; g3: 12/12 revoke-all checks, UI suite 437/437) | yes | [#1281](https://github.com/hookprobe/hookprobe/pull/1281) | yes (2026-11-18) |

| AB-12 controls with no screen stay greyed | `agent/mc-intel-honest` | yes | astro check 0 errors; build 27 pages; browser against a mock device granting `multi_wan`, `guest_ssid`, `openvswitch`: all three greyed, inert, with the reason; new spec `gate-not-built` not run locally | running at merge | yes | [#1298](https://github.com/hookprobe/hookprobe/pull/1298) | yes (2026-11-18) |
| AB-09/10 Investigate: process tree and reports cap | `agent/mc-investigate-honest` | yes | astro check 0 errors; build 27 pages; **no browser check** (this shell can no longer reach a local mock server); new spec `investigate-honest` not run locally | pending | yes | [#1299](https://github.com/hookprobe/hookprobe/pull/1299) draft | no |
| HookProbe logo in Mission Control (rails + favicon) | `agent/mc-brand-logo` | yes | astro check 0 errors; build 27 pages; browser: mark renders in the rail (22 px, theme colour), favicon is the mark | pending | yes | draft | no |
| Sample incident uses real rule ids (1200125, 1200113) | `agent/mc-sample-rule-ids` | yes | unit 12/12; astro check 0 errors; build 27 pages; browser: sample incident shows the new story and rule 1200125, no old DNS-feed text | pending | yes | draft | no |
| AB-15 drop the Linux-tier `Readme.md` (ends the case collision) | `agent/docs-ab15` | yes | n/a (docs); no markdown link to it left outside protected paths (`git grep`); fresh worktree has a clean `git status` | pending | yes | draft | no |

AB-07 needed no change: the CVE tab has said "This device does not report software exposure yet" since `47a2ad85` (2026-11-10). The audit finding was wrong.

## Tests and coverage

Baseline in [E2E_VALIDATION.md](E2E_VALIDATION.md). CI on `main`: nightly 5/5 green; ci 7/15
green; build-heqk fuzz red ×4 today, fixed by #1266; metal gate dark.
Local gates: **cannot run on this Mac** (no QEMU / cargo / npm). Agent branches are validated by
GitHub CI only, and reported as such.

## Blocked / waiting

| Item | Waiting on |
|---|---|
| AB-01 trust chain, AB-03 shipping flavour, AB-13/14 CI wiring, AB-19 metal | operator |
| AB-07, AB-08 | homepods (HP-01, HP-02) |
| AB-15 links in protected paths | operator: `CLAUDE.md` (3), 17 ADRs, `.claude/agents/` (4 files), `legacy/linux-tier/` (12 files) still name `docs/architecture/Readme.md` |

## HomePods dependencies

8 open requests: [HOMEPODS_HANDOFF.md](HOMEPODS_HANDOFF.md).

## Continuous operation

This runs inside a desktop session; it is not 24/7 by itself. Options for genuine continuous
operation are listed in the journal (scheduled task in the desktop app, or a cloud routine).

## Next autonomous actions

1. Read g3 on the spec-fix PR; until it merges, g3 on `main` fails on `investigate-honest`.
2. AB-02: rewrite getting-started as the real path (factory-provisioned unit, owner card).
3. AB-16: docs outside `docs/adr/` that contradict ADR 0047.
