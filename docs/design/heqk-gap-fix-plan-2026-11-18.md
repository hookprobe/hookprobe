# heqk — remaining gaps and bugs, and the fix plan (2026-11-18)

**Scope.** Everything still open in the kernel / device after the 2026-11-18 overnight end-to-end run and the
same-day regression of `main`, plus a code review (`/code-review high`) of every kernel and diagnostics change
since 2026-11-16 (58 commits, ~3.2k lines). **Excluded by the operator:** REL-08 (Infineon production firmware)
and REL-05 (the 72 h soak).

**Where things stand.** The regression of current `main` (image `am9`, 26 CM5 checks) is green once bench state
is reset between config-changing checks (`cm5-bench-baseline.sh`, #1293). The Wi-Fi driver split (ADR 0065) runs
every reload bus operation in el0-wifi (#1267, #1277, #1296). What is left is below, in fix order.

## Wave 1 — defects found by the code review (kernel; no operator input; fix now)

Severity: **H** = can crash / corrupt / wrongly refuse a security-relevant action; **M** = wrong behaviour in a
reachable case; **L** = cosmetic / diagnostic.

| # | Sev | Where | Defect | Fix | Proof |
|---|---|---|---|---|---|
| R1 | **H** | `el0srv.rs` `Server::call` → `on_fault` → `cyw43::bus_recover_after_el0_fault` | **Re-entrancy (regression from 4e-3b, #1296).** During a firmware reload every SDHCI access routes to el0-wifi (`KMmio` delegates to the driver's `r8..w32`, which `el0_reg` reroutes). A bus-server fault mid-reload runs the recovery, which calls back into the *same faulted server* before it is reset; a second fault recurses without bound. **Verified in code.** | The recovery always runs in EL1: a `RECOVERING` guard that `el0_reg` / `bus_hooks` honour, set around `on_fault`. | QEMU selftest (fault inside a routed op → recovery in-kernel, no nested call); CM5: `wifi-inject` CMD53 stall during a forced reload. |
| R2 | **H** | `lanaccess.rs` `selftest` | The boot self-test leaves `MGMT_SEEN` = the fake 192.168.200.146/gw .1. On a device with **no** management VLAN, a real upstream 192.168.200.0/24 is then refused as an exception target ("the management network is never opened"). | Restore `MGMT_SEEN` with the other saved state. | `[P-lanaccess]` asserts `MGMT_SEEN` unchanged; owner-rules exception to 192.168.200.20 accepted on a no-mgmt build. |
| R3 | M | `lanaccess.rs` `grant_temporary` / `hal::lanaccess::Table::add` | A temporary grant with the same scope **replaces an always exception** and gives it an expiry; after expiry the permanent exception is gone until reboot. | A temporary grant never downgrades an always entry (keep the always one; report "already allowed (always)"). | hal host test + `[P-ownerapi]` case. |
| R4 | M | `ownerjournal.rs` apply / `ownerapi.rs` `lan_access` | Table full: the always grant's `add()` failure is ignored → API says "allowed (always)", resolves the block, traffic still refused. The temporary path journals before `grant_temporary` can refuse. Expired temporaries occupy slots (prune only on GET). | Prune before add; refuse ("too many exceptions") **before** journaling; apply checks the result. | `[P-ownerapi]`: fill 32, add one → refused, nothing journaled. |
| R5 | M | `lanaccess.rs` `exception_refusal` | "Device's own addresses" checks only the prefix's network address; 192.168.1.0/24 containing the WAN address 192.168.1.10 passes. | Refuse a prefix that **contains** any local address (as the management guard does). | `[P-ownerapi]` case. |
| R6 | M | `apcore.rs` (client6 A-01) | IPv6 path lacks the "specific signed route = operator intent" exemption IPv4 has (v4/v6 policy asymmetry). | Same exemption for v6 routes. | `[P-lanaccess]` v6 route case; CM5 ULA route check. |
| R7 | M | `cyw43.rs` authorize | The `authorize` iovar fallback now runs only when the firmware answered `st != 0`; a control **write** that failed (no credit / el0 TX loss) gets no retry and the station stays unauthorized. | Retry the iovar when the request never reached the firmware (`tx` failed), not only on a firmware error. | QEMU fake-device case; CM5 claims C2/C3 under `wifi-inject` TX loss. |
| R8 | M | `wifiheal.rs` bus episodes | A bus that faults every < 2 s is one endless "episode" and **never escalates** to a firmware reload. | Cap an episode (by count and by total duration) so persistent faults escalate. | wifiheal host test (fault every 1 s for 60 s → reload); CM5 `wifi-inject` periodic fault. |
| R9 | M | `el0srv.rs` DRBG reseed | A failed hourly reseed is retried on **every** later el0-wpa call (TRNG reads + an extra excursion on the keying path). | Back off: record the attempt time on failure too (retry at the next interval / a short backoff). | `[P-el0wpa]` with a failing TRNG mock: one retry per interval. |
| R10 | L | `http.rs`, `hal/sdio.rs`, `cyw43.rs` | Doc comments detached from their items by inserted code (`render_tls`, `rxfail` vs `recover_abandoned`, `fw_reload` vs `RELOAD_PHASE_MS`). | Move the docs back. | Review. |

## Wave 2 — engineering gaps (no operator input; after Wave 1)

| # | Gap | Plan |
|---|---|---|
| E1 | **ADR 0065 D4.4 — first-boot bring-up still in EL1** | Step 4e-4 (branch `feat/4e4-first-boot-el0`): load the bus server before the first bring-up with **bus entry points only** (the keying hooks still arrive with el0-wpa), route the probe + download through it, retry once fully in EL1 on failure. CM5: OTA boot + cold power cycle + WPA3 + throughput + reload. Then radio power (GPIO) is the only EL1 Wi-Fi step; the D4.4 status change is an ADR edit (operator). |
| E2 | **No single source of truth for gate status** | `docs/design/heqk-remaining-gaps.md` (last 2026-11-12) and the 2026-11-10 audit table are stale. Replace with one status table (gate, owner, state, evidence link), updated by every PR that moves a gate. |
| E3 | **Bench hygiene in CI-like runs** | Call `cm5-bench-baseline.sh` before and after each config-changing check in the regression runner; make `a01md`-style checks read where Mission Control is served (setup AP vs custom credential) instead of assuming. |
| E4 | **Local mc-e2e is noisy** | The local browser leg runs the current UI suite against a stale `HEQK_UI_DIST`; build the UI dist from the same commit in the local runner (CI already does). |
| E5 | **Post-upload firmware round trips** | Occasional ~980 ms reloads (vs ~830) sit after the upload (version / pre-init control requests), on both the EL0 and EL1 paths (#1294). Low priority: measure which control request, then bound it as #1250 did. |

## Wave 3 — needs bench hardware / a person at the bench

| # | Gap | Blocker |
|---|---|---|
| H1 | L-02 certificate on the bench unit still the 2026-11-07 one (no 192.168.200.146 / unit name in the served SAN) | CM5 USB/rpiboot link did not enumerate (no USB event on the host); re-patch tool ready (exact-match replace, backup kept) |
| H2 | G-C browser flasher (ADR 0037) | same USB link + the operator-reviewed flash runbook |
| H3 | G19 PoP tunnel metal | the PoP must be started by the operator |
| H4 | /setup as HQCFG1 bundle metal batch (#80) | the operator scheduled it after the soak |

## Wave 4 — operator-owned release gates (not engineering-blocked)

TC-01..04 (key custody, OTP, SEC-3 fuses, RPMB — irreversible, manufacturing only), REL-06/07, CMP-01..05 (incl.
CMP-02 legal clearance of the RAM correction), DET-01 sign-off, the G46 security review (never waived), and ADR
status edits (ADR 0065 D4.4, ADR 0044 D1/D3 [vision] rows). Excluded here: REL-08, REL-05.

## Order and gates

Wave 1 first (R1 and R2 are the priority), each fix as its own PR: QEMU selftest + host tests + validate + mc-e2e
(CI) + clippy ratchet, and a CM5 proof where the defect is on a metal path (R1, R6, R7, R8). Then E1 (metal-proven),
E2–E4. Every PR states its evidence; nothing is marked done on QEMU alone where metal applies.
