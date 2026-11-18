# Status

_Updated 2026-11-17._

## Platform status

**Kernel and API are in good shape; the customer journey is not.** The device API serves almost
everything the UI calls, auth is consistent (no unauthenticated writes found), and sample data is
labelled. What a customer cannot do yet: obtain and claim a device without the factory station,
reach a captive setup portal, or rely on the Intelligence, device-name, process-tree and Copilot
views. Release trust-chain signoffs are open. See [ARCHITECTURE_AUDIT.md](ARCHITECTURE_AUDIT.md).

## Active task

Both draft PRs are CI-green and waiting for operator review. Write access for `hookprobes` granted 2026-11-17.

## Delivery ledger

| Work | Branch | Implemented | Local tests | CI | Pushed | PR | Merged |
|---|---|---|---|---|---|---|---|
| Engineering audit docs | `agent/engineering-audit` | yes | n/a (docs) | **green** (14 pass, 2 skipped by design) | yes | [#1269](https://github.com/hookprobe/hookprobe/pull/1269) draft | no |
| AB-05 Copilot AI-models link | `agent/mc-honest-states` @ `02cb4780` | yes | astro check 0 errors; build 27 pages; browser check of 3 hash cases; Playwright spec added but not run locally | **green** (17 pass incl. g3: "PASS pro-workspace-admin: admin: #ai deep link opens AI models") | yes | [#1268](https://github.com/hookprobe/hookprobe/pull/1268) draft | no |

AB-06 (package.json description) deferred: `package.json` is claimed by the other session.

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
| AB-04 and Investigate-area items | other session (`feat/mc-explainability`) |
| AB-15 rename | operator naming choice |

## HomePods dependencies

8 open requests: [HOMEPODS_HANDOFF.md](HOMEPODS_HANDOFF.md).

## Continuous operation

This runs inside a desktop session; it is not 24/7 by itself. Options for genuine continuous
operation are listed in the journal (scheduled task in the desktop app, or a cloud routine).

## Next autonomous actions

1. Finish AB-05/06, push, draft PR, read CI.
2. AB-17 docs corrections (no code risk).
3. AB-11 revoke-all control (UI + confirm) once the other session's `feat/mc-explainability` lands,
   to avoid shell conflicts.
