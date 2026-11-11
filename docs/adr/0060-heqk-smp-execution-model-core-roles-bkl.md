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
