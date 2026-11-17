# E2E validation baseline

Baseline taken 2026-11-17 from `main` @ `65196b0b`. Read-only investigation; nothing re-run
locally yet (see "Local capability" below).

> The brief calls the gate spine "ADR 0052". In this repo it is **ADR 0063**
> (`docs/adr/0063-autonomous-cicd-gate-spine-and-heal-loop.md`, renumbered 2026-11-12). ADR 0052 is
> Shield v2 DNS.

## Gates (one script: `tools/ci/gates.sh`)

| Gate | Checks | Where it runs | State |
|---|---|---|---|
| G0 hygiene | workflow wiring W1–W7, release drift, CI-tool self-tests, shellcheck | ci.yml, nightly | wired, green |
| G1 static/unit | clippy ratchet, validate-phase ratchet, host `cargo test` (hal, tlsprov, responder-sim, superpop, heqk-sign) | ci.yml, nightly | wired |
| G2 QEMU | `os/kernel/validate.sh`, ~104 `[P-*]` phases, 147-line floor | build-heqk.yml (path-filtered), nightly | wired, **not in ci.yml**: a PR outside the filtered paths never boots QEMU |
| G3 MC E2E | `astro check`, UI preview suite, `mc-e2e.sh` (QEMU API + Playwright) | ci.yml, nightly, build-heqk | wired |
| G4 supply chain | cargo-deny all lockfiles, npm audit high+, syft SBOM completeness | ci.yml, nightly | wired |
| G4r reproducible | prod kernel built twice, hashes equal | nightly, release | wired |
| G6 metal | `mc-e2e-metal.sh` on CM5 bench | metal.yml | **no signal**: last 5 runs skipped/cancelled |
| Heal loop | triage → rerun / guarded autofix → draft PR | autoheal.yml | wired |

## CI health on `main` (gh run list, 2026-11-17)

| Workflow | Recent result |
|---|---|
| ci | 7 ok · 3 fail · 5 cancelled of last 15 |
| build-heqk | 10 of last 30 failed; 4 in a row today in the libFuzzer job, fixed by PR #1266 (19:36 green) |
| nightly | 5/5 green |
| metal | skipped/cancelled ×5 |
| release | never run |
| codeql, secrets-scan | green |

## Test inventory

| Area | Suite | Count | In CI |
|---|---|---|---|
| Mission Control UI | Playwright specs, custom runner `tests/ui/run.mjs`, **static preview build with sample data** | 49 | yes (G3) |
| Mission Control unit | none on `main` (no framework; `tests/unit/explain.test.ts` exists only on `feat/mc-explainability`) | 0 | — |
| Device API + browser | `os/kernel/tools/mc-e2e.sh` (472 lines) + `ui-check.mjs` | ~30 endpoints, 4 pages | yes (G3) |
| onboarding/enrollment | Rust `#[test]` (responder-sim, superpop) | 11 | yes (G1) |
| os/build/heqk-sign | G1 runs `cargo test`, **no `#[test]` found** | 0? | yes, possibly empty |
| tools/ci | Python self-tests | part of 131 | yes (G0) |
| tools/provisioning, tools/pi4-wsensor | Python tests | 55 | **no** |
| os/device-identity, appliance | — | 0 | — |
| fuzz, detbench | 4 fuzz targets, bench | — | build-heqk |

## Customer journeys

| Journey | Coverage | Evidence | Gap |
|---|---|---|---|
| Onboarding / first boot | partial, UI only | specs `setup-bundle`, `setup-feedback`, `layer0`, `l0-wifi-sheet` (preview); QEMU `[P-devid]`, `[P-apcred]` | browser leg never opens `/setup` against a device |
| WAN / LAN / DHCP / DNS / firewall | partial | `/api/network`, `/api/dns` reads; `[P-cfgd-wan]`, `[P-dhcpd]`, `[P-pppoe]`, `[P-shield*]` | no browser-driven config change applied and verified; no firewall-rule journey |
| Detect → enforce → event → dashboard | covered, narrow | mc-e2e attack yields exactly 2 de-duplicated detections (:194); browser renders `/detect/feed` | one attack class only |
| Auth / owner key | covered in QEMU API | HQMGMT1 signing, replay, rate limit, anchor enroll/rotate (:148–331) | browser login flow not driven |
| Multi-tenant | none | only P20 reach-policy tenant check, P-m6-export vs fake MC | no isolation or cross-tenant tests |
| Backup / upgrade / rollback | partial | `[P-otagate]`, `[P-abslot]`, `[P-otaverify]`, config rollback | no backup/restore; no metal A/B (G6 dark) |

## Local capability (this Mac)

`qemu-system-aarch64`, `qemu-system-x86_64`, `cargo`, `pnpm`, `npm`: **not installed**. Only
`node`. G1 host tests target `x86_64-unknown-linux-gnu`. Consequence: G1–G4 cannot be proven
locally here; validation of agent branches relies on GitHub CI (or a Linux host). The agent never
reports a gate as passed from a local skip.

## How to run

```
tools/ci/gates.sh --list | pr (g0 g1 g4) | full (g0–g4) | nightly (+g4r)
cd os/kernel && ./validate.sh            # G2
cd os/kernel && ./tools/mc-e2e.sh        # G3, MC_E2E_KEEP=1 keeps the VM
os/mission-control/tests/ui/run.sh       # UI preview suite, UI_SPECS=... to filter
```
Results: `out/ci/gate-results.json`. `CI_STRICT=1` turns a missing tool into a failure.
