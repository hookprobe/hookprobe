# ADR 0060: heqk SMP execution model, core roles and the transitional big kernel lock

**Status:** 🟡 Proposed (2026-11-11). Operator direction recorded 2026-11-11; the text below needs
operator review.

**Scope:** os/kernel (hboot, scheduler, GIC, IPC, data plane), os/build (gates).

**Evidence:**
- `docs/design/heqk-wan-routing-architecture-2026-11-11.md`;
- the gap table below, with citations against `origin/main` @ `fd6fb038`.

**Related ADRs:**
- **Replaces** the single-core contract in `os/kernel/ARCHITECTURE.md:142-175` once D3 lands.
- **Builds on** ADR 0050 (EL0 placement) and ADR 0023 (the separation matrix must be re-proven).
- **Companions:** ADR 0061 (memory) and ADR 0062 (microarchitectural isolation).

## Context

heqk runs on one core.

| # | Gap | Status | Evidence |
|---|---|---|---|
| S1 | hboot parks non-zero cores forever (`cbnz x2, park` / `park: wfe; b park`) | NOT IMPLEMENTED | `hboot/src/boot.s:28-30, 166-168` |
| S2 | PSCI: VERSION, FEATURES, SYSTEM_OFF, SYSTEM_RESET over HVC only; no `CPU_ON`, no SMC | PARTIAL | `arch-aarch64/src/smccc.rs:18-26, 101-110` |
| S3 | How the CM5 firmware starts secondary cores, and whether it has EL3 | UNKNOWN | Needs metal |
| S4 | Stage-2 (SEC-2) is installed on CPU0 only | IMPLEMENTED (CPU0) | `hboot/src/stage2.rs:105-115` |
| S5 | Single-core, non-reentrant contract | IMPLEMENTED (constraint) | `ARCHITECTURE.md:142-175` |
| S6 | Scheduler: global `static mut`, no affinity, budgets or per-CPU queues; 36 threads | PARTIAL | `kernel/src/scheduler.rs:1-25` |
| S7 | IPC critical sections assume one core | PARTIAL | `kernel/src/ipc.rs:5-7` |
| S8 | SPIs routed to CPU0 (`ITARGETSR = 1`) or to the boot CPU's affinity; no SGIs | PARTIAL | `arch-aarch64/src/gic.rs:38-45`; `gic_v3.rs:75-80, 152` |
| S9 | Frame free-list ABA race | NOT IMPLEMENTED | `PRODUCTION_READINESS.md:198-199` |
| S10 | Per-core RSS rings | DESIGN ONLY | `ZEROCOPY_IPC_RING.md:95, 170-200` |
| S11 | CPU pressure signal is global | IMPLEMENTED (single core) | `kernel/src/ratelimit.rs:711-829` |
| S12 | No CPU topology or RAM in the capability manifest | NOT IMPLEMENTED | `kernel/src/capabilities.rs:1-25` |
| S13 | NIC multi-queue / RSS support on CM5 | UNKNOWN | — |
| S14 | N100: no x86 port; Limine planned for SMP start-up | DESIGN ONLY | `ARCHITECTURE.md:76` |

A SASE PoP must run routing, encryption, inspection and forwarding **at the same time** (operator
requirement, 2026-11-11). That calls for a deliberately multi-core and multi-RAM design.

## Decision

**D1. Multi-core is the architecture.** A one-core boot is the same model in degraded mode: roles
become time-sliced reservations, and the data-plane reservation is guaranteed.

**D2. Secondary cores start only through hboot.**
- Start method: PSCI `CPU_ON` (SMC or HVC, taken from the DTB or ACPI) or the spin table.
- Each core gets EL2 vectors and **the same stage-2 tables** before it enters the kernel at EL1.
- A core whose stage-2 cannot be confirmed stays parked and is reported.
- Rationale (S4): starting cores from the kernel would drop the SEC-2 carve-out on those cores.

**D3. Before a second core runs kernel code, convert in one pass:**
- SPSC producers (`events.rs`, `packet.rs`) become per-core rings, or get a reservation index plus
  a commit index;
- `ratelimit.rs` window resets become a single CAS;
- scheduler tables become per-CPU;
- the frame free list gets a tagged pointer and per-core caches (S9);
- IPC sections move under the BKL (D8);
- driver diagnostic latches stay with the core that owns the device.

**D4. Core roles:**
- **DP (data-plane worker):** run-to-completion per flow shard. Handles RX dispatch, verdict,
  forwarding, NAT, crypto and TX.
- **CP (control plane):** routing, IKE and BFD control services.
- **MG (management):** cfgd, mgmtabi, Mission Control, TLS, telemetry export, the FIB installer,
  timers, best-effort work.
- **IRQs:** each NIC queue's IRQ goes to the DP core that owns the ring; timers and the management
  path go to MG.

**D5. Profile defaults plus admission-time allocation within measured bounds.** Defaults and
floors, not fixed tables:

| Profile | DP floor | CP floor | MG floor |
|---|---|---|---|
| Gateway | ≥1 core, ≥60% of cores | 0 (CP work shares MG) | MG reserve (D9) |
| Advanced Gateway | ≥1 core | 0.5 core-equivalent | MG reserve |
| SASE PoP | ≥2 cores where available | ≥1 core | MG reserve |
| Provider Edge | ≥2 cores | ≥1 core + ≥1 for label/VPN control | MG reserve |

**Admission (cfgd, when configuration is staged):**
1. Reserve MG, including the management-safety reserve; MG traffic is protected by the ADR 0023
   management floor before any shedding.
2. Reserve the DP floor.
3. Size DP to the requested throughput using the attested per-core rate.
4. Size CP to the requested convergence targets.
5. Put the remainder in reserve.
6. If the request is infeasible, refuse it with a reason (shown in `/api/capabilities`).

**Rebalancing:**
- **Allowed automatically:** CP service budgets move within attested min/max; CP may borrow
  **idle MG** time.
- **Never:** CP or MG work on DP cores, or anything below a floor.
- **A role change** (for example DP to CP) is a **cfgd trial event**. Its flows drain naturally
  (new flows stop hashing to the core); flow state is never migrated.
- **Larger hardware** gets more cores under the same rules.

**D6. Scheduling:**
- per-CPU runqueues and affinity masks;
- budget-per-period reservations for CP and MG;
- cross-core Notification wake-ups through SGIs;
- no migration by default;
- service thread counts are a function of the cores granted.

**D7. Shared state:**
- Flow state is shard-local (single writer). Without RSS, the RX owner core steers packets with a
  symmetric hash; NAT external ports are partitioned per shard; tunnels and SAs are pinned to a
  shard.
- FIB, ACLs and rule/IOC tables are read-mostly, generation-published, and reclaimed with
  quiescent-state reclamation at the end of each DP burst.
- Counters and event rings are per core.
- Per-source rate limits use per-core token buckets with periodic merging. **The 33-row
  separation matrix must be re-proven** before this replaces the current limiter.

**D8. The big kernel lock (BKL) is transitional.**

- **Covers:** capability space, Untyped retype/revoke, the endpoint/notification tables, IPC
  rendezvous, cross-core TCB lifecycle, and the configuration-state **pointer swap** (cfgd
  generation, holds, device policy, journal, rule/IOC packs).
- **Never covers:**
  - forwarding, verdict, NAT, crypto or RX/TX on DP cores. **DP-core attempts = 0** is a hard
    invariant: fatal in debug builds, alarmed in production;
  - blocking I/O (eMMC writes run on an MG thread that owns the block device);
  - parsing, signature verification, unbounded allocation, sending or waiting.
- **Packet slow paths without the BKL:**
  - ARP/ND miss: the per-NIC neighbour owner, reached through SPSC request rings;
  - route miss: local ICMP with a per-core rate limit;
  - punt: one SPSC ring per DP core per service;
  - IDS events: per-core rings;
  - Shield: per core.
  - Any slow path that does need the BKL must be benchmarked at worst-case and sustained rates.
- **Lock ordering:** BKL, then the per-CPU runqueue lock, then future object locks. Never take the
  BKL while holding a runqueue lock. No BKL in IRQ context. The lock is a ticket lock (FIFO), held
  with IRQs masked and for a bounded time.

**D9. Provisional gates** (operator decision 2026-11-11; validated per platform tuple on CM5 and
N100):

| Metric | Gate | Definition |
|---|---:|---|
| BKL p99 acquisition wait | ≤ 50 µs | From the first attempt (ticket taken) to acquisition |
| BKL maximum hold | ≤ 100 µs | From acquisition to release; **every violation recorded** |
| Contended acquisitions | ≤ 1% | Acquisitions whose ticket was not served at the first check ÷ all acquisitions (a count ratio, not a time ratio) |
| Decomposition trigger | > 5% | Under an admitted representative workload: mandatory decomposition review, and the **SMP performance gate cannot be claimed** |
| DP-core BKL attempts | = 0 | Hard invariant |
| MG CPU safety reserve | ≥ 5% of total CPU | Protected; never available to tenant admission |
| MG memory safety reserve | ≥ 64 MiB | Protected Untyped grant; never available to tenant admission |

- The reserves are **minimums**. Admission may reserve more based on measurement.
- **Outcomes:** PASS (all gates hold on every workload); FAIL; REVIEW (above 5% contention).
- **Changing a gate** requires CM5 and N100 evidence plus an ADR amendment, never a constant edit.

**D10. Instrumentation** (per core, allocation-free, present in production builds):
- **Clock:** `CNTPCT_EL0` (TSC on x86), with resolution from `CNTFRQ_EL0` recorded with every
  result. A counter coarser than 1 µs fails calibration.
- **Counters:** acquisitions, contended acquisitions, log₂ wait and hold histograms (1 µs
  sub-buckets up to 128 µs), maximum wait and hold with the call-site id, and the longest
  IRQ-masked window.
- **Violation ring:** fixed size, records `{t, core, site, wait_us, hold_us}`, plus an overflow
  counter.
- **Export:** `/api/*` and mgmtabi `GET_*`, plus the `[P-bkl]` marker.
- **Probe overhead** is itself measured and reported.

**D11. Measurement method:**
- **Sustained:** at least 60 minutes of the admitted representative mix: full-table BGP from N peers
  with MRT replay at 1×, IDS/IPS at profile depth, G19 and IPsec traffic with rekeys, IMIX
  forwarding at the attested rate, telemetry, and management operations (Mission Control, hsh, a
  cfgd stage/confirm).
- **Bursts:** at least 10 × 60 s episodes inside the sustained run: churn at 10× plus a peer flap,
  a tunnel-establishment storm, a punt flood at the cap, and a management burst.
- **MG reserve proof:** login, diagnostics, config stage and rollback, and emergency revert must
  each complete within target latency during the worst burst.
- **Recorded per run:**
  - workload id and duration;
  - core count and role allocation;
  - RAM and the budget map;
  - acquisition and contention counts;
  - p50, p95, p99 and maximum wait; maximum hold; the violation list;
  - per-core and per-service CPU; per-budget memory high-water marks;
  - image hash and platform tuple.

**D12. BKL exit.** Decompose when any gate is missed, contention exceeds 5%, or a hold lies on the
convergence or rekey SLO critical path. Order:
1. per-object capability and IPC locks;
2. single-owner MG threads for configuration and storage, with lock-free publication;
3. per-CPU TCB management.

The BKL is gone when the PoP mix shows zero acquisitions on the measured critical paths.

## Consequences

- R0 of the routing roadmap is gated on this ADR. Bring-up order: QEMU `-smp`, then the OCI A1
  cloud tier (PSCI over HVC already present), then CM5 (after the REL-05 soak).
- New validation markers: `[P-smp-stage2]`, `[P-smp-roles]`, `[P-smp-matrix]`, `[P-bkl]`.
- The first security review gate is stage-2 coverage on every core.
- `ARCHITECTURE.md:142-175` is rewritten as the SMP concurrency contract once D3 lands.

---

## Amendment (2026-11-26, proposed): worker cores first, general SMP later

**Status:** proposed; awaits operator review. It changes the order of this ADR, not its end state.

**Why:** the operator set SMP as the next priority (2026-11-26), ahead of the Conductor agent and the storage
track. Two facts changed since this ADR was written against `fd6fb038`:
1. **S3 is resolved on metal.** The CM5 has 4 cores at MPIDR `0x000 / 0x100 / 0x200 / 0x300`,
   `enable-method = "psci"`, and PSCI 1.1 `CPU_ON` over SMC to TF-A (`docs/design/heqk-t0-cm5-inventory-mb23.md:47, 67, 87`).
2. **The D3 conversion grew.** On main at `917f74359` there are 616 `static mut` in `kernel` (396) and
   `arch-aarch64` (220): `cyw43.rs` 124, `kernel/src/main.rs` 63, `uplink.rs` 35, `el0srv.rs` 32, `cfgd.rs` 30.
   Converting all of it before any second core runs (D3) is a large audit that blocks every benefit of SMP.

Already correct and not to be redone: normal memory is mapped inner-shareable on QEMU and CM5
(`arch-aarch64/src/mmu.rs:41`, `mmu_cm5.rs:20`), TLB maintenance uses `dsb ish`, and the event ring publishes
with acquire/release (`kernel/src/events.rs:78-108`).

### W1. Two kinds of core

- **Core 0 runs the existing kernel** under the existing single-core contract (`ARCHITECTURE.md`, concurrency
  invariant), unchanged. It carries the MG and CP roles and, until S3, the data plane.
- **Cores 1..n are worker cores.** They run a separate `no_std` worker executive, in its own crate, that never
  executes kernel code:
  - own exception vectors and stack, GIC redistributor and per-core timer set up by itself;
  - talks to core 0 only through single-producer, single-consumer rings using the frozen discipline of
    `ZEROCOPY_IPC_RING.md`, plus an SGI doorbell;
  - allocates nothing: core 0 assigns its memory before start;
  - a fault on a worker core parks that core and is reported to core 0; it never takes the system down.
- **The crate boundary is the proof.** The worker crate cannot name kernel statics, so "no shared mutable
  state with core 0 except the rings" is enforced by the compiler, not by review. This realises D4 and the D8
  invariant "DP-core BKL attempts = 0" structurally, before the BKL exists.

D3 (the one-pass conversion) and the BKL (D8) now apply when **kernel code** first runs on more than one core
(W3 stage S4), not before.

### W2. Start path per tier (scopes D2)

| Tier | Who starts secondaries | Stage-2 | Marker |
|---|---|---|---|
| CM5 | HBoot at EL2, PSCI `CPU_ON` over SMC; each core installs HBoot's EL2 vectors and **the same stage-2 tables**, verified by read-back, before it may run anything at EL1 | required (SEC-2) | `[P-smp-stage2]` |
| QEMU `virt` (no EL2) and OCI A1 (EL1 guest) | the kernel on core 0, PSCI `CPU_ON` over HVC (conduit from DTB or ACPI) | none exists on these tiers | `[P-smp-boot]` |

HBoot never runs under the QEMU gate (`validate.sh` boots the kernel at EL1), so the CM5 row can only be
proven in a metal batch.

### W3. Stages (replace the bring-up order under Consequences)

| Stage | Content | Gate |
|---|---|---|
| S0a | QEMU `-smp 4`: core 0 starts cores 1–3 over HVC into a minimal worker entry (stack, vectors, MMU on the shared kernel tables, then park) | `[P-smp-boot]` in `validate.sh`; every existing row still passes with `-smp 4`. **Built 2026-11-26:** `arch-aarch64/src/smp.rs`, kernel feature `smpboot`; all implemented phases GREEN at `-smp 4`; a single-core boot fails the gate |
| S0b | CM5: HBoot `CPU_ON` over SMC; per-core EL2 setup and stage-2, read back; cores parked at EL2 | `[P-smp-stage2]` on metal; first security review (stage-2 on every core) |
| S1 | The worker executive: GICR and timer, SGI doorbell, rings to core 0, fault-park-report. **S1a built 2026-11-28** (QEMU): crate `os/kernel/worker` (`heqk-worker`, no dependencies), split-once SPSC rings, GICv2 SGI doorbell polled with IRQs masked, window-checked job vocabulary, `[P-smp-worker]`. **S1b built 2026-11-28** (QEMU): private stage-1 tables per worker (kernel .data/.bss unmapped, window read-only), proven by MMU faults on unchecked probes. **S1c built 2026-11-28** (QEMU): per-core timer heartbeat (banked CNTP, PPI 30, IRQs masked), deadline jobs, `busy_since`, frozen-heartbeat watchdog (`[P-smp-timer]`). **Open:** CM5 GIC bases and tables (`linker-cm5.ld`), each secondary copying HBoot's `CNTHCTL_EL2` timer-access setup (S0b), metal memory-ordering tests | ring stress plus memory-ordering litmus tests **on CM5 metal** (QEMU's TCG does not model the A76's weak ordering, so it cannot catch a missing barrier) |
| S2 | First workload: a compute-role core running the Conductor P0 engine and crypto/hash offload, with FP/SIMD enabled on that core. **S2a built 2026-11-28** (QEMU): the engine is a separate hard-float image (`os/kernel/worker-engine`) mapped only in worker tables, workers set `CPACR_EL1.FPEN` for themselves, core 0 stays softfloat, int8 GEMV bit-identical across scalar/NEON/SDOT and cores (`[P-smp-simd]`). **S2b:** the Conductor's `conductor_p0::core_job` as the engine (#1646), model region and windows from core 0 | first CM5 tok/s and AES-GCM throughput; separation matrix unchanged with the compute core busy; DRAM-bandwidth interference on the packet path measured (ADR 0071 risk) |
| S3 | Data-plane worker cores, flow-sharded (D4, D7). Depends on S13 (RP1 NIC queues); without RSS, core 0 steers into per-worker rings | 33-row separation matrix re-proven (`[P-smp-matrix]`); throughput |
| S4 | This ADR's general SMP: D3 conversion, per-CPU scheduler (D6), BKL (D8) with the D9 gates, when MG/CP need more than one core | D9, `[P-bkl]` |

### W4. Relation to ADR 0072 (FP/SIMD grant)

ADR 0072 grants FP/SIMD to one EL0 server, enabled only inside its excursion, with owner-switch scrubbing
required before a second grant. On a compute-role worker core that runs only the granted server, there is no
owner switch: FP/SIMD can stay enabled on that core, and core 0 stays softfloat with no V-register save. This
is a simpler realisation of ADR 0072's single grant, not a second grant. ADR 0072's G46 review still applies.

### W5. Flagged, not resolved

- **ADR 0067** says "single-core fixes before SMP". The worker-core order does not change core 0, so it does
  not skip those fixes; whether they gate S0 or only S4 is an operator call.
- **CM5 bench access** is via metal batches (REL-05 soak deferred). S0b, S1 and S2 each need a slot.
