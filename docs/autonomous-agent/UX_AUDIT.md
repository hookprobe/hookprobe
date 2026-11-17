# UX audit — Mission Control vs the device

Baseline `main` @ `65196b0b`, 2026-11-17. Router: `os/kernel/kernel/src/http.rs handle()`
(:361–1104); unmatched GET → 404 "not implemented on heqk" (:1097), unmatched POST → 405 (:658).
Target experience: `docs/architecture/MissionControl.md` + wireframe canvas
(https://claude.ai/artifact/WfTVHvAtfeh2QgufwoGfcJ, v60, aligned to heqk contracts).

## What is already right

- Every UI call except two is served, and spot-checked shapes (incidents, incident detail with
  `explanation` + `attack_path`, detections, qsecbit, config incl. `envelope`/`sections`, anchor)
  match `src/store/api.ts`.
- Sample data is gated per screen (`sample() = healthChecked() && !substrate()`), and the global
  `SampleDataNotice` shows only when no device answers.
- Greyed controls carry a reason (13 checked). No `href="#"`, no empty handlers.
- The planner stub is honest: 503 `not_configured`, and the UI shows a failed + retry state.

## Disconnects (ranked)

| # | Problem | Evidence | Owner |
|---|---|---|---|
| U-01 | TopBar pill can read "Protected" beside a "—" score on a live device: `protectionStatus()` reads `qsecbit()`, seeded with the sample 92 | `store/mock.ts:65,74`, `TopBar.tsx:45-50` | other session (QSecBit band) |
| U-02 | AppRail and Home sparklines draw hard-coded `INITIAL_HEARTBEAT` when `/api/qsecbit` history is empty | `mock.ts:127-132`, `AppRail.tsx:65`, `App.tsx:129`, `live.ts:46` | other session |
| U-03 | Intelligence CVE board can never go live: `/api/exploitability` not served (falls back to IOC tab) | `store/itlLive.ts:62` | homepods (route) / agent (label) |
| U-04 | Copilot and explainability have no backend: planner 503, explain route 405, incident `model` always null | `http.rs:427,698`; `plannerApi.ts:110` dead | other session + homepods |
| U-05 | Device Map / Zones / inventory show bare IPs: `/api/devices` emits only `id, ip, mac:null, first_seen, last_seen`; `DeviceRow` expects ~17 fields | `mcstate.rs:571+` | homepods |
| U-06 | Process-tree panel never has data: `/api/incidents/:id/processes` always empty (no EDR) | `http.rs:703-720` | agent: hide behind capability / explain |
| U-07 | Broken link: Copilot "AI models" goes to `/administration/ai-models`, no such page (spec route `/admin/ai-models` also missing) | `CommandPalette.tsx:166` | agent |
| U-08 | ~120 spec sub-routes have no page (e.g. `/admin/{audit,backup,lifecycle/*}`, `/detect/rules`, `/observe/dns`) | route map vs `src/pages` | agent, prioritised by journey |
| U-09 | Reports list asks for 200, kernel caps at 32; UI does not say it is truncated | `investigateLive.ts:203`, `http.rs:741` | agent |
| U-10 | Served but no UI: `/api/lan-access`, `/api/owner-rules/revoke-all` (no "revoke all" control) | `http.rs:696,559` | agent |
| U-11 | Latent dead buttons once a capability is granted: "Add backup", "Turn on guest Wi-Fi", "Configure segmentation" have no `onClick` inside `Gate` | `GetOnlineApp.tsx:87,118`, `ProtectApp.tsx:178`; denied today `capabilities.rs:28-30` | agent |
| U-12 | `package.json` description says the UI is "served by Rust/Axum" (ADR 0047: heqk) | `os/mission-control/package.json` | agent |

## Journeys (persona view)

| Persona | Journey | Today |
|---|---|---|
| Home user | get a device, plug in, protected | **blocked**: no published image, no consumer claim path, no captive portal (ARCHITECTURE_AUDIT G-01, G-04) |
| Home user | "what happened today" | works on live data (`story.ts`), sample fallback labelled |
| SME / IT admin | change WAN, Wi-Fi, firewall | `/setup` + signed bundle + trial/revert works in QEMU; no browser-driven E2E proving it |
| Security engineer | detection → incident story → evidence | works for the one attack class mc-e2e drives; explainability drawer in progress (other session) |
| MSSP | tenants, fleet | placeholder only in standalone; no multi-tenant backend on heqk |

## Wireframe direction (agreed with the other session)

The redesign (calm Mission Control, nine-step response flow, floating "Dig deeper") is drawn
against the real contracts. The nine-step stepper and the Respond / Know / Manage rail are **not**
being built yet: Action, Fix, Heal and Move on have no device data. They are tagged "Sample only"
on the canvas and stay design-only until the backend exists.
