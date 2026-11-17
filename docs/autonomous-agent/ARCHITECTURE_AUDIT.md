# Architecture and implementation audit

Baseline: `main` @ `65196b0b`, 2026-11-17. Read-only. Claims marked ✔ were re-verified by hand;
the rest come from a file-level sweep and carry their evidence pointer.

## 1. What the product is today

HookProbe OS = the **heqk** microkernel (`os/kernel/`, owner homepods) serving **Mission Control**
(`os/mission-control/`, Astro + SolidJS, embedded by `kernel/build.rs`) directly to the browser.
No Linux on the device (ADR 0047). Everything else in the repo is build/sign tooling, factory and
bench tools, hardware designs, docs, and frozen legacy.

### Kernel interfaces the application side depends on (read-only inventory)

| Interface | Detail |
|---|---|
| HTTP API (`kernel/src/http.rs`, ~50 routes) | reads: `/api/{health,stream,detections,incidents,devices,flows,dns,tls,intel,qsecbit,enforcement,reports,evidence/*,engines,capabilities}`; writes: `/api/{config,anchor,owner-key,owner-rules,upload/*,reboot,factory-reset,hsh,actions,alert-hook}` |
| Planner | ✔ `POST /api/planner/{propose,approve}` → 503 `not_configured` (`http.rs:427`), `/api/planner/status` → `configured:false`. Honest stub by design |
| Boot-partition files | `OWNER.TXT WIFI.TXT WAN.TXT POLICY.TXT DEVICES.TXT IOC.TXT OUI.TXT RULES.BIN MCTLS.CRT` (signed: `HQWSIG1`, `HQPSIG1`…) |
| Bundles / envelopes | `HQCFG1` config, `HQENR1`/`HQROT1` owner key, `HQMGMT1` signed management, `HQPOL1`, `HQWAN1`, `HQDEV1` |
| Wire | `HQT1` tunnel (UDP 7655, Noise 7654), `HQX1` v2 evidence export (`exportwire.rs`) |
| QSecBit | ✔ `mcstate.rs:675 band()`: risk <300‰ GREEN, <700‰ AMBER, else RED; samples are `{ts, score, band}` only |
| Incident | ✔ `render_incident`: `id, title, priority, status, device_ip, threat_score, ts, explanation{why, confidence, evidence, model, related_events}, attack_path` |

## 2. Component inventory (outside the kernel)

| Component | Does | Complete | Tests | Ships | Notes |
|---|---|---|---|---|---|
| `os/mission-control` | the UI, 27 pages | partial | 49 UI preview specs, 0 unit on main | yes | 17 components render `SampleDataNotice` |
| `os/build/make-cm5-heqk-{image,disk}.sh` | build + sign boot set, factory disk | complete | 0 | is the build | protected |
| `os/build/heqk-sign` | Ed25519 + SLH-DSA signer | complete | ✔ **0** (G1 runs an empty `cargo test`) | signing | protected |
| `os/build/kem-diff` | ML-KEM differential / ctgrind | partial | 0, not in CI | no | |
| `os/build/fpgen` | OUI / fingerprint DB generator | complete | 0 | data | |
| `os/{device-identity,drivers,networking,provisioning,security}` | index READMEs into the kernel (+ CYW43455 firmware) | index | — | firmware | |
| `onboarding/enrollment/{responder-sim,superpop}` | host control-plane responder, SASE PoP | complete / built | 3 + 8, in CI | no | sealed export (HQX3) only on `feat/sealed-evidence-export` |
| `onboarding/{wifi,setup-ui}`, `appliance/*` | READMEs only | index | — | — | no machine-readable board profile exists |
| `tools/provisioning` (hqprov) | factory station: flash → identity → owner key → TLS → label → self-test | complete for 1 unit | 42, **not in CI** | no | blocked on OTP (TC-02) and owner-CA choice |
| `tools/ci` | gate spine, heal loop | complete | 82 | no | protected |
| `tools/release-gate` | 46 release items → evidence | complete | 0 | no | many items blocked / need signoff |
| `tools/diagnostics` | 55 metal checks + relay rig | complete | n/a | no | |
| `tools/fuzz`, `tools/detbench` | 27 fuzz targets; detection corpus | complete / partial | — | no | build-heqk.yml |
| `tools/pi4-wsensor` | bench Wi-Fi sensor | bench | 13, not in CI | no | |
| `tools/flash` | flasher | **missing** (README only) | — | — | WebUSB flasher cited under retired ADR 0037 |
| `hardware/hookprobe-sbc` | RK3588 board rev A (generated) | partial, unrouted | 90 validate checks | no | gated behind CM5 |
| `legacy/v1`, `legacy/linux-tier` | frozen V1; bootc tier | obsolete | own | no | linux-tier duplicates planner/hydra/rbac logic |

## 3. Gaps — documented vs implemented

Ranked: security and broken customer journeys first. Each item is a backlog candidate.

| # | Gap | Evidence | Owner |
|---|---|---|---|
| G-01 | **No path for a customer to get a device.** Getting-started says download "image + `.owner-key`"; `release.yml` produces only unsigned `.elf` drafts; no public release; a shared owner key would be common to every buyer | `docs/getting-started/README.md`, `.github/workflows/release.yml` | operator + homepods |
| G-02 | Two "shipping" definitions disagree: `release.yml:84` builds `prod-mc`; `tools/ci/shipping-features.txt` says `hboot,apmc,wifi-bigtx,appersist,wpa3`; docs say `prod-mc` | as cited | operator (protected) |
| G-03 | Production trust chain unmet: TC-01..04 (key custody, OTP, fuses, RPMB) need signoffs, `docs/release/signoffs/` empty; SEC-05 owner-key review open | `tools/release-gate/items.txt` | operator (Red) |
| G-04 | ADR 0010 zero-touch captive portal not built (no captive DNS, no `setup.hookprobe.local`), yet MissionControl.md describes it as day 0 | grep `kernel/src`; ADR 0010 status line | homepods (kernel) + docs |
| G-05 | Flasher missing; docs still point at retired ADR 0037 WebUSB flasher | `tools/flash/README.md`, `os/provisioning/README.md` | agent (docs) |
| G-06 | ✔ UI calls routes heqk does not serve: `/api/exploitability` (`store/itlLive.ts:62`), `/api/planner/incidents/:id/explain` (`store/plannerApi.ts:112`) — both exist only in `legacy/linux-tier` | grep `http.rs` | agent (UI honest state) + homepods (route) |
| G-07 | Wasm detection host never ships: `wasmhost` feature in no product flavour; CLAUDE.md implies signed Wasm runs today | `kernel/Cargo.toml:69` | homepods + docs |
| G-08 | Sigma/YARA (ADR 0026), RBAC (0028), VEX (0024) exist only on the Linux tier; ADRs still read "Implemented, gate-green". heqk has a single owner, no roles | grep `kernel/src` | operator (ADR status) |
| G-09 | Gap register G13 marked done but `/api/manifest`, `/api/verdicts/dns` exist nowhere | `docs/design/heqk-parity-gaps.md` | agent (docs) |
| G-10 | Kernel routes with no UI: `/api/lan-access`, `/api/owner-rules/revoke-all` | `http.rs` | agent (UI) |
| G-11 | MissionControl.md §12 still describes bootc/Containerfile/Marketplace/sysext; UI `package.json` says "served by Rust/Axum"; ~27 of ~150 spec routes exist | as cited | agent (docs, package.json) |
| G-12 | Stale register/index rows: G48, G12 "MC QR panel" (exists: `QrSheet.tsx`), READMEs citing retired ADR 0037, `os/kernel/GAP_REGISTER.md` historical | as cited | agent (docs outside kernel) |
| G-13 | Test gaps: `heqk-sign` 0 tests; `tools/provisioning` (42) and `pi4-wsensor` (13) not in CI; no QEMU coverage of the ~1,400-line AP loop; virtual device identity unbuilt | as cited | mixed |
| G-14 | ✔ Case-colliding `docs/architecture/{README,Readme,readme}.md` dirty every macOS checkout | `git ls-files` | agent (needs operator choice of name) |
| G-15 | `appliance/` has no machine-readable profiles, so "adding hardware = one profile" is not true yet | `appliance/*` | operator decision |

## 4. Onboarding today, end to end

`make-cm5-heqk-disk.sh` → flash (rpiboot / `flash-image.sh`) → bench station (serial, owner key +
TLS onto eMMC, label with setup SSID/passphrase + QR) → device raises `HookProbe-Setup-XXXX` AP
(`apcred.rs`) → browser to `https://device`, sign in with the owner card → `/setup` signs WAN/Wi-Fi
in the browser → upload → cfgd trial/revert.

**Breaks for a real customer at:** no published image, no claim path without the factory
station, no captive portal, no flasher, trust-chain signoffs missing.

## 5. Secrets

No real keys or tokens committed outside the kernel. PEM hits are deliberate test fixtures in
`os/mission-control/tests/ui/specs/*.mjs` (gitleaks allowlisted). `legacy/v1` carries placeholder
default credentials in several deploy scripts (paths in SECURITY_FINDINGS.md); none looked real.
