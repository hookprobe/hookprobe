# heqk — remaining gaps and bugs, and the fix plan (2026-11-18)

**Scope.** Everything still open in the kernel / device after the 2026-11-18 overnight end-to-end run and the
same-day regression of `main`, plus a code review (`/code-review high`) of every kernel and diagnostics change
since 2026-11-16 (58 commits, ~3.2k lines). **Excluded by the operator:** REL-08 (Infineon production firmware)
and REL-05 (the 72 h soak).

**Where things stand.** The regression of current `main` (image `am9`, 26 CM5 checks) is green once bench state
is reset between config-changing checks (`cm5-bench-baseline.sh`, #1293). The Wi-Fi driver split (ADR 0065) runs
every reload bus operation in el0-wifi (#1267, #1277, #1296). What is left is below, in fix order.

**Status (2026-11-28).** Waves 1, 2 and 2b are merged; most of Wave 3 is done. The tables below are kept as written
(the plan). Each wave has a status line under its table. The live status is in `heqk-gate-status.md`
(rows `GF-*` and `AH-*`).

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

**Wave 1 status (2026-11-28; see `heqk-gate-status.md`):** all done. R1 done+metal (#1308, #1454). R2–R5 done-QEMU
(#1310). R6 done-QEMU (#1310); metal needs an IPv6 upstream on the bench WAN. R7 fix corrected on metal: re-sending
the ioctl authorizes, 6/6 (#1309, #1454). R8 done+metal (#1309). R9, R10 done (#1309).

## Wave 2 — engineering gaps (no operator input; after Wave 1)

| # | Gap | Plan |
|---|---|---|
| E1 | **ADR 0065 D4.4 — first-boot bring-up still in EL1** | Step 4e-4 (branch `feat/4e4-first-boot-el0`): load the bus server before the first bring-up with **bus entry points only** (the keying hooks still arrive with el0-wpa), route the probe + download through it, retry once fully in EL1 on failure. CM5: OTA boot + cold power cycle + WPA3 + throughput + reload. Then radio power (GPIO) is the only EL1 Wi-Fi step; the D4.4 status change is an ADR edit (operator). |
| E2 | **No single source of truth for gate status** | `docs/design/heqk-remaining-gaps.md` (last 2026-11-12) and the 2026-11-10 audit table are stale. Replace with one status table (gate, owner, state, evidence link), updated by every PR that moves a gate. |
| E3 | **Bench hygiene in CI-like runs** | Call `cm5-bench-baseline.sh` before and after each config-changing check in the regression runner; make `a01md`-style checks read where Mission Control is served (setup AP vs custom credential) instead of assuming. |
| E4 | **Local mc-e2e is noisy** | The local browser leg runs the current UI suite against a stale `HEQK_UI_DIST`; build the UI dist from the same commit in the local runner (CI already does). |
| E5 | **Post-upload firmware round trips** | Occasional ~980 ms reloads (vs ~830) sit after the upload (version / pre-init control requests), on both the EL0 and EL1 paths (#1294). Low priority: measure which control request, then bound it as #1250 did. |

**Wave 2 status (2026-11-28; see `heqk-gate-status.md`):** E1 done+metal (#1319); the ADR 0065 D4.4 status edit is
still the operator's. E2 done (`heqk-gate-status.md`). E3 done+metal (#1428). E4 done (#1427). E5 not reproduced on
current main: 6/6 reloads 834–838 ms (#1440).

## Wave 3 — needs bench hardware / a person at the bench

| # | Gap | Blocker |
|---|---|---|
| H1 | L-02 certificate on the bench unit still the 2026-11-07 one (no 192.168.200.146 / unit name in the served SAN) | CM5 USB/rpiboot link did not enumerate (no USB event on the host); re-patch tool ready (exact-match replace, backup kept) |
| H2 | G-C browser flasher (ADR 0037) | same USB link + the operator-reviewed flash runbook |
| H3 | G19 PoP tunnel metal | the PoP must be started by the operator |
| H4 | /setup as HQCFG1 bundle metal batch (#80) | the operator scheduled it after the soak |

**Wave 3 status (2026-11-28; see `heqk-gate-status.md`):** H1 done+metal (served SAN checked 2026-11-21). H2 open.
H3 done+metal (`metal-evidence/20261124-g19-cm5-live-pop.md`, 10/10). H4 done+metal for the safety path
(`metal-evidence/20261128-postsoak-r0-setup-w04-j5.md` §4, 20/20); the full success path needs an untagged-DHCP
bench port.

## Wave 4 — operator-owned release gates (not engineering-blocked)

TC-01..04 (key custody, OTP, SEC-3 fuses, RPMB — irreversible, manufacturing only), REL-06/07, CMP-01..05 (incl.
CMP-02 legal clearance of the RAM correction), DET-01 sign-off, the G46 security review (never waived), and ADR
status edits (ADR 0065 D4.4, ADR 0044 D1/D3 [vision] rows). Excluded here: REL-08, REL-05.

## Order and gates

Wave 1 first (R1 and R2 are the priority), each fix as its own PR: QEMU selftest + host tests + validate + mc-e2e
(CI) + clippy ratchet, and a CM5 proof where the defect is on a metal path (R1, R6, R7, R8). Then E1 (metal-proven),
E2–E4. Every PR states its evidence; nothing is marked done on QEMU alone where metal applies.

## Wave 2b — the autoheal harness (deep research, 2026-11-18)

A deep-research run (102 agents; every claim needed 2 of 3 adversarial votes to survive) compared heqk's
self-monitoring and recovery with **QNX Neutrino HAM / APS**, the **MINIX 3 Reincarnation Server** and its fault-injection
results, and **NIO's dependable seL4 design** (seL4 Summit 2025). Sources: QNX SDP 7.1 / 8.0 docs (HAM conditions /
actions, APS bankruptcy); Herder et al., DSN 2007 / 2009, ;login: 2010; seL4 Summit 2025 "Towards dependable".
**Not covered by any surviving claim:** Fuchsia restart policies, Zephyr, ARINC 653 health monitoring, AUTOSAR
WdgM / PHM, IEC 61508 / ISO 26262 diagnostic coverage, seL4 MCS. Those stay open questions, not inputs to this plan.

### What heqk already has (and where it is ahead)

- **Hangs are caught by construction.** EL0 servers run as bounded synchronous excursions with a per-call time budget
  (`budget_us`): a server that hangs or loops is cut off and reset on that call. QNX / MINIX need a heartbeat for this;
  in MINIX 3 fault injection heartbeats found only ~4–5 % of failures, but exactly the hangs nothing else catches.
- **Pristine images in RAM.** Each server restarts from its signed ELF embedded in the kernel image, never from storage
  (MINIX 3 needed a RAM copy for the disk driver; heqk has it for every server).
- **One restart owner per server** (`el0srv::Server`: fault → reset → backoff → reload on the next call).
- **A recovery ladder with an end state** (Wi-Fi: kick → BSS bounce → firmware reload → ONE reboot → degrade) and a
  hardware watchdog + crash record; config and OTA have trial / commit / revert.

### Gaps against the research, and the plan

| # | Research finding (confidence) | heqk today | Gap → plan |
|---|---|---|---|
| A1 | One supervisor holding a **declared table per server**: conditions, actions, start order, readiness handshake, identity stable across restarts (QNX HAM; high) | Each `Server` supervises itself; start order is code order in `main.rs`; readiness = `CMD_INIT` reply | A supervisor table (`superv.rs`): per server, its failure kinds → action, dependencies (el0-wpa after the bus server, el0-tlshost after DataVolume), readiness = `CMD_INIT` OK, generation counter as the stable identity. One place to read the whole tree. |
| A2 | **Failure kinds** drive the response; abnormal death vs exit; two heartbeat severities (QNX; high) | `[EL0-FAULT]` lines + counters; the crash record only for the self-heal reset | A typed failure kind (exception, budget overrun, refused-init, complaint, planned update) in every server fault record and in `/api/health`; the ladder branches on it. |
| A3 | **Restart only on death; every other signal becomes a kill first** — no competing restart paths (QNX HAM; high) | Faults and budget overruns already reset; Wi-Fi heal has its own reload path beside the server reset | Route every recovery trigger (budget, complaint, heal) through "kill → the server's single restart owner"; the firmware reload stays a separate, device-level rung. |
| A4 | **Six trigger channels**, incl. a **complaint** from a peer (MINIX 3 RS; high) | Exceptions, budgets, Wi-Fi stall signals; no generic complaint | A complaint call: a client reports its server (el0-wpa → bus timeouts, the data path → a stalled TX ring, Mission Control → TLS host unresponsive); complaints count toward the ladder like faults. |
| A5 | **Declarative, context-aware policy with capped exponential backoff + decay** (MINIX 3 RS: `1<<n`, cap 30; high) | Backoff per server is fixed-step; the Wi-Fi ladder is code (R8 just added an episode cap) | A policy table (server × kind × count-in-window → action, backoff 2^n capped, decay window); replaces hard-coded branches; host-tested like `wifiheal`. |
| A6 | **Functional probes**: liveness = "the service works", not "the process runs" (NIO seL4; medium) | Bench checks only (cm5-* scripts); OTA gate checks AP serving + WAN usable | In-device probes on a slow cadence: AP beacon + a self-association check, a DHCP lease round-trip on loopback, a DNS answer from Shield, a TLS handshake to el0-tlshost; a failing probe is a complaint (A4). |
| A7 | **Temporal isolation with a watchable fault**: per-partition CPU budget, bankruptcy event, throttle / cancel / (test-only) reboot policies (QNX APS; high) | Per-CALL budget only; no aggregate CPU budget per server per window | Per-server CPU budget per window (sum of excursion time), a bankruptcy event to the supervisor, throttle by refusing calls for the window; Basic policy (notify + throttle) in production. |
| A8 | **State is the limit of restart**: transparent only for stateless servers; checkpointing poor for fast-changing state (MINIX 3; high) | el0-wpa keeps persistent state pages (PMKSA survives a bus fault, metal claims C1/C5); TLS sessions are lost on a TLS-host restart; Wi-Fi state is rebuilt by the reload | Classify each server's state (stateless / re-derivable / persistent) in the supervisor table; persistent state pages only where it matters (el0-wpa today); a state-integrity check (checksum) before reuse after a fault. |
| A9 | **Fault injection at scale** proves isolation (MINIX 3: 3.4 M faults into 4 drivers, no OS crash; ~99 % recovered on real hardware vs 100 % emulated; medium–high) | `wifi-inject` (CMD53 stall, server faults, bus-fault bursts) + claims C1–C6; tens of faults per run | A SWIFI harness: random faults (server code / register mutation, forced aborts, injected hangs, SDIO stalls) at thousands per hour in QEMU and on the CM5 rig; acceptance = no kernel crash, no isolation breach (K1 memory scan), recovery rate and time per kind recorded. |
| A10 | **Evidence per recovery** | Beat lines, crash record, `/api/health` fields scattered per subsystem | One recovery journal (kind, server, rung, time-to-recover, outcome) in the sealed evidence log; Mission Control reads it. |

### Order (after Wave 1)

1. **A2 + A10** (typed failure kinds + one recovery journal): small, and every later item reports through them.
2. **A1 + A3 + A5** (supervisor table, single restart path, policy table with capped backoff): the core.
3. **A4 + A6** (complaints, functional probes): detection beyond crashes.
4. **A7** (CPU budget per window): temporal isolation.
5. **A9** (SWIFI at scale, QEMU then metal): the acceptance gate for 1–4.
6. **A8** (state classes + integrity check): with each server as it is touched.

Anti-patterns to keep out (from the research): reset loops (bounded by A5 decay + the one-reboot rule), competing
restart owners (A3), recovery that masks a real fault (every recovery is journaled, A10, and counted toward escalation).

### Execution plan for the autoheal harness (PR by PR)

Grounded in the code as it is today:
- `el0srv::Server` (el0-wifi, el0-wpa, el0-lansvc) already resets on a fault or budget overrun, with capped
  exponential backoff (50 ms doubling to 5 s, `BACKOFF_MS` / `BACKOFF_MAX_MS`), and logs `[EL0-FAULT] … kind=…`;
- **el0-tlshost has its own supervisor** (`tlshost::TlsHost`, its own restart / timeout / fault counters);
- the Wi-Fi ladder lives in `wifiheal.rs`;
- recovery evidence is spread over beat lines, `crashrec` and the sealed evidence log (`evlog`).

Each step is one PR: host / QEMU tests + validate + mc-e2e + clippy ratchet, and a CM5 proof where it touches a metal
path. Nothing is marked done on QEMU alone where metal applies.

| Step | Scope | Files | Tests | CM5 proof |
|---|---|---|---|---|
| **H1** failure kinds + recovery journal (A2, A10) | `hal::superv::Kind` {Exception, Budget, InitRefused, Complaint, Probe, Planned} and `Recovery` {server, kind, rung, t_detect, t_recovered, outcome}; every server fault and every heal rung emits one; a 64-entry RAM ring, flushed to `evlog`; `GET /api/recoveries` | `hal/src/superv.rs` (new), `el0srv.rs`, `tlshost.rs`, `wifiheal.rs`, `http.rs` | host tests for the encoding; `[P-superv]` QEMU: an injected server fault yields exactly one journal entry with the right kind | `wifi-inject` fault + a C5 burst: entries with kind, rung and time-to-recover; survives a power cycle via `evlog` |
| **H2** one supervisor table (A1, A3) | `superv.rs`: a static table per server (name, dependencies, state class, policy row, generation); `el0srv::Server` and `TlsHost` report into it and take restart decisions from it; start order from the dependencies with `CMD_INIT` = ready; a restart bumps the generation | `kernel/src/superv.rs` (new), `el0srv.rs`, `tlshost.rs`, `main.rs` (start order) | `[P-superv]`: dependency order; one restart per death; generation increments; no second restart path | boot order unchanged on the CM5 (`[EL0-*]` lines); claims C1–C5 unchanged |
| **H3** policy table with decay and escalation (A5) | per (server, kind): backoff (existing 2^n cap) + a count-in-window decay + an escalation action past N restarts (Wi-Fi bus → firmware reload, already the ladder; TLS host → in-kernel HTTPS refusal + journaled degrade; LAN services → keep the in-kernel fallback where one exists) — never a reboot loop (the one-reboot rule stays global) | `hal/src/superv.rs` (pure policy, host-tested), `superv.rs` | host tests: a fault storm escalates once; decay restores; no action repeats inside its window | a TLS-host fault burst (bench injector) escalates and is journaled |
| **H4** complaints + functional probes (A4, A6) | `superv::complain(server, why)`; probes on a slow cadence (≥ 60 s, jittered, inside the loop-gap budget): DNS answer from Shield, a TLS handshake to el0-tlshost from the kernel, AP serving (already in the OTA gate), a DHCP OFFER on loopback; a failing probe = a complaint | `superv.rs`, `apcore.rs` / `lansvc.rs` / `tlshost.rs` probe hooks | `[P-superv]` probes against QEMU servers; a broken server is detected by its probe | a hung-but-alive TLS host (injector: never answers) is detected by the probe and restarted; loop gap stays < 1 s |
| **H5** CPU budget per window (A7) | per server: excursion time summed over a 1 s window against a budget; over budget = "bankrupt" → calls refused for the rest of the window + a Budget complaint; System (EL1) unbounded | `el0srv.rs` (accounting exists per call), `superv.rs` | host test of the window accounting; `[P-el0srv]` a spinning server is throttled, others keep their share | throughput + WPA3 unchanged under a CPU-hog injector in one server |
| **H6** SWIFI at scale (A9) | a fault-injection campaign driver: random server faults (forced abort, budget hang, corrupted reply, register mutation in el0-wifi) at a configurable rate; QEMU nightly; CM5 on the relay rig | `tools/diagnostics/cm5-swifi.sh`, QEMU injector feature, `superv.rs` counters | QEMU: ≥ 10,000 injected faults, 0 kernel crashes, 0 isolation breaches (K1 scan), recovery rate per kind | CM5: ≥ 1,000 faults over a few hours: same acceptance + recovery-time percentiles; real-hardware recovery may need the reload rung (MINIX 3: ~99 % vs 100 % emulated) |
| **H7** state classes + integrity (A8) | the table records each server's state class; persistent state pages (el0-wpa) get a checksum verified before reuse after a fault (else wipe + the existing re-provision path) | `superv.rs`, `el0srv.rs` (state pages) | `[P-el0wpa]`: a corrupted state page is detected and wiped, never reused | a corrupted-state injection on el0-wpa: wiped, stations re-key, journaled |

**Order:** H1 → H2 → H3 → H4 → H5 → H6 (the acceptance gate for H1–H5) → H7 alongside. H1 and H2 are the foundation;
H6 is what lets us claim the harness works.

**Harness status (2026-11-28; see `heqk-gate-status.md`, rows `AH-*`):** H1–H7 all merged. H1 done+metal (#1320; across
a warm reset #1419). H2 done+metal (#1327). H3 done+metal for H3a (#1328); H3b done-QEMU (#1336). H4 done+metal for
H4a/H4b (#1339, #1351); H4c done-QEMU (#1409). H5 done+metal (#1356). H6 done+metal: 1000 CM5 injections, 0 unrecovered
(#1365–#1378, #1446). H7 done+metal (#1418, #1420). Follow-up D1 (probes for el0-hsh and el0-wpa) done-QEMU (#1430).

## Wave 2c — second research pass (2026-11-18)

The second pass targeted Fuchsia, Zephyr, ARINC 653, AUTOSAR WdgM / PHM, IEC 61508 / ISO 26262 and seL4 MCS. Its claims
were checked against primary sources (22 sources, 101 claims extracted, 25 verified by 3-vote adversarial review, 22
confirmed). **Only Fuchsia and Zephyr survived verification.** No claim was confirmed for ARINC 653 health monitoring,
AUTOSAR WdgM / PHM, the IEC 61508 / ISO 26262 diagnostic-coverage tables or seL4 MCS. Those stay **open research**, and
nothing in H2–H5 may cite them as support until a later pass confirms it.

What was confirmed, and what it changes:

| # | Finding (source) | Folded into |
|---|---|---|
| C1 | "Fatal to system" is a per-component, policy-gated property: Fuchsia `on_terminate: reboot` defaults to none, works only for monikers on a security-policy allowlist, and is checked a second time at build time (RFC-0110, termination_policies.md) | **H2**: the supervisor table carries a `critical` flag fixed in the signed image; only critical entries may escalate straight to the reboot rung. Everything else stops at degrade |
| C2 | Reboot happens in two stages: an orderly Admin/Reboot (topology torn down in reverse dependency order) with a bounded wait, then panic / watchdog (RFC-0110, RFC-0152) | **H3**: the reboot rung is "flush crash record + journal, then reset" under a deadline; the hardware watchdog forces the reset if the deadline passes |
| C3 | Driver restart is opt-in (`host_restart_on_crash`, default false); without it the failed node is removed and the system runs degraded. A driver dropping its Node channel counts as a failure (DFv2 driver_runner.md) | **H2**: each entry states its default (`restart` or `remove-and-degrade`) and its restart unit. **H4**: an *abandoned endpoint* (a server that stops answering its protocol without faulting) is its own failure kind |
| C4 | The restart owner tears the crashed instance down completely before the new one starts (driver_manager waits on DestroyChild, March 2026; medium confidence) | **H2** invariant, already true for `el0srv` (restore + ring wipe before the next call). Made explicit: the journal entry records `t_teardown` separately from `t_recovered` |
| C5 | Reboot reasons are recorded as reason + culprit and exposed over an API and telemetry; some reasons are generic with no culprit (why_fuchsia_devices_reboot.md) | **H1** follow-up: the persisted record and the boot replay carry the culprit component and kind (the Wi-Fi record already does); `/api/recoveries` shows the last boot's reason |
| C6 | Zephyr `task_wdt`: one channel per supervised thread, each with its own period and expiry action; a hardware watchdog backs it in case the task watchdog or the scheduler fails | **H4/H5**: per-server alive supervision (a liveness period for each resident server, not only per-call budgets), with the existing hardware watchdog as the fallback tier |
| C7 | Zephyr fatal-error policy is a single hook owned by the integrator: abort the faulting thread (contained) or halt (kernel panic means reset) | Already matches heqk: an EL0 fault is contained, an EL1 fault goes through the crash record + reset. No change |

Still unsupported, and the questions for a third, targeted pass: the AUTOSAR WdgM logical-supervision graph (checkpoints,
transitions, failed-reference-cycle tolerance, local and global status), ARINC 653 warm vs cold partition restart and the
process / partition / module error levels, the diagnostic coverage IEC 61508-2 Table A.10 and ISO 26262-5 Annex D give
a simple vs windowed vs independent-time-base watchdog, and seL4 MCS scheduling contexts with timeout fault handlers
(for H5). Until then, H5 (per-window CPU budget) is designed from the heqk excursion model and the first pass's QNX APS
finding only.
