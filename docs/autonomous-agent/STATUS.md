# Status

_Updated 2026-11-18._

## Platform status

**Kernel and API are in good shape; the customer journey is not.** The device API serves almost
everything the UI calls, auth is consistent (no unauthenticated writes found), and sample data is
labelled. What a customer cannot do yet: obtain and claim a device without the factory station,
reach a captive setup portal, or rely on the Intelligence, device-name, process-tree and Copilot
views. Release trust-chain signoffs are open. See [ARCHITECTURE_AUDIT.md](ARCHITECTURE_AUDIT.md).

## Active task

AB-11 "Remove all owner rules" on `agent/mc-revoke-all` (draft PR). AB-06 in draft PR #1280. #1282 is a duplicate of it, to close. #1279 (AB-17) merged.

## Delivery ledger

| Work | Branch | Implemented | Local tests | CI | Pushed | PR | Merged |
|---|---|---|---|---|---|---|---|
| Engineering audit docs | `agent/engineering-audit` | yes | n/a (docs) | green | yes | [#1269](https://github.com/hookprobe/hookprobe/pull/1269) | yes (2026-11-17) |
| AB-05 Copilot AI-models link | `agent/mc-honest-states` @ `02cb4780` | yes | astro check 0 errors; build 27 pages; browser check of 3 hash cases; Playwright spec added but not run locally | green (g3: "PASS pro-workspace-admin: admin: #ai deep link opens AI models") | yes | [#1268](https://github.com/hookprobe/hookprobe/pull/1268) | yes (2026-11-17) |
| AB-17 stale register rows + ADR 0037 citations | `agent/docs-ab17` | yes | n/a (docs) | secrets-scan pass; ci + CodeQL still running at merge | yes | [#1279](https://github.com/hookprobe/hookprobe/pull/1279) | yes (2026-11-18) |
| AB-06 package.json description | `agent/mc-pkg-description` | yes | release_check passes | pending | yes | [#1280](https://github.com/hookprobe/hookprobe/pull/1280) draft | no |
| AB-11 Remove all owner rules (Protect) | `agent/mc-revoke-all` | yes | astro check 0 errors; build 27 pages; full flow in the in-app browser against a local mock device (dry run → approve → verified; requests match the heqk contract); new UI spec `revoke-all` not run locally (no Playwright) | pending | yes | [#1281](https://github.com/hookprobe/hookprobe/pull/1281) draft | no |


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
| AB-15 rename | operator naming choice |

## HomePods dependencies

8 open requests: [HOMEPODS_HANDOFF.md](HOMEPODS_HANDOFF.md).

## Continuous operation

This runs inside a desktop session; it is not 24/7 by itself. Options for genuine continuous
operation are listed in the journal (scheduled task in the desktop app, or a cloud routine).

## Next autonomous actions

1. Read CI on #1280 and #1281. Close the duplicate #1282.
2. AB-07: label the Intelligence CVE tab "Not on this device yet" instead of a silent sample fallback.
3. AB-12: give the dead buttons inside `Gate` handlers or an explicit "coming" state.
