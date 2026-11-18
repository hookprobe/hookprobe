# 12 — Requests to HomePods (kernel requirements, handoff)

> Native Inference Research Programme, 2026-11-18. **Requests, not changes.** `os/kernel/**` is owned
> by HomePods and was not modified. Each request:
> - names the evidence in `00` (file:line);
> - says whether it is needed at all;
> - gives the smallest interface that would satisfy it.
>
> Requests are ordered by when the inference work would need them. Earlier tiers never wait for later
> requests.

## R0 — Readouts (no design work; needed before any decision)

| Item | Why | How (suggestion) |
|---|---|---|
| CPACR_EL1, CPTR_EL2 values as firmware leaves them | decides whether an accidental NEON instruction is contained, resets the SoC, or leaks V-registers (`00` §3.2) | extend the `t0inv` inventory (`hboot/src/t0inv.rs`) and publish in the MB23 doc |
| ID_AA64ISAR0_EL1 (DotProd), ID_AA64DFR0_EL1 (PMUVer), ID_AA64PFR0_EL1 (MPAM) | `t0inv.rs:37` reads ISAR0/DFR0 already; values not published | publish |
| CNTKCTL_EL1[1:0], MDCR_EL2, PMUSERENR_EL0 | EL0 timing and PMU feasibility | publish |
| eMMC sequential read MB/s with the current driver, and the bus width actually in use | model load time is 25–133 s if 1-bit/4-bit at 25 MHz (`07`) | one timed CMD18 run on metal |
| Frame-pool and heap high-water marks in a shipping build | nobody has measured RAM use per subsystem (`00` §3.8, ADR 0061 M9/M10) | print at the end of boot and after a soak |

## R1 — Nothing (tiers B–C)

The temporal and specialist tier (Neural DNA, int8 heads, a tiny recurrent cell) needs **no kernel
change**. It runs as one more EL0 server under the existing model:
- ≤ 4 MiB window, softfloat, scalar integer;
- bounded excursions (`excursion_bounded`, `main.rs:13706`);
- inputs from the detection ring.

The only HomePods involvement is the usual one: adding an `el0-*` crate to `kernel/build.rs` behind a
feature, and an excursion budget.

## R2 — Per-server FP/SIMD (needed for any NEON kernel)

- **Evidence:** no CPACR/CPTR write anywhere. The thread frame has no V-registers (`thread.rs:1-10`).
  All crates are softfloat. GAP_REGISTER CORE-7 / XC-8 and remediation A5 are undecided.
- **Smallest interface:** a capability (or a static per-server flag) that grants FP/SIMD to **one**
  EL0 server.
  - The kernel sets CPACR_EL1.FPEN for that server only, and keeps the trap for everything else,
    including EL1.
  - It saves V0–V31, FPCR and FPSR on switch away and restores them on switch back. Lazy save is fine.
  - It **scrubs** them before running any other server, so no state can leak.
  - The server's crate builds for `aarch64-unknown-none` (hard-float) instead of `-softfloat`.
- **Not asked:** FP in EL1.

## R3 — A model region (needed for any model > ~3 MiB)

- **Evidence:** `USER_WINDOW = 4 MiB` (`mmu_cm5.rs:73`); ELF segments ≤ 2 MiB (`elf.rs:60-61`);
  L3 pages only.
- **Smallest interface:** a second, larger EL0 virtual window for **one** server, mapped:
  - read-only for the weights, read-write for the arena and state;
  - with 2 MiB block descriptors where aligned;
  - backed by a physically contiguous reservation made at admission, outside the 128 MiB pool.

  Sizes come from the HNX manifest (`06`): 0.3–1 GiB on 4/8 GB parts.
- **Depends on:** ADR 0061 D1 (knowing the RAM size; today `BootInfo` has none) and D4 admission.

## R4 — Load a large extent from storage (needed with R3)

- **Evidence:** PIO, ≤ 25 MHz, no CMD6 (`emmc.rs:46`, `:9-12`); staging 20 MiB; artifact caps
  ≤ 16 MiB (`artstore.rs:66-75`); no EL0 blob path.
- **Smallest interface:**
  - a DataVolume region (or partition) for model packages;
  - a kernel operation that streams an extent into an R3 reservation, hashing segment by segment;
  - an upload path for packages larger than 20 MiB (chunked straight into that region, not through
    staging).
- **Performance part (separable):** CMD6 to 4/8-bit and high-speed timing, or DMA. Without it, a
  300 MiB load takes 25–100 s. That is tolerable for load-once-at-boot, not for load-on-demand.

## R5 — Verify a model package (needed with R4)

- **Evidence:** `verify_payload` / `verify_digest` (`boot-abi/src/verify.rs:120,158`) have two callers
  (hboot, OTA) and one trust root. Operator packs are Ed25519-only (`policysig.rs`).
- **Smallest interface:** `verify_package(root_hash, signature) → ok | err`, with the same hybrid
  scheme (Ed25519 + SLH-DSA-SHA2-128s). Either:
  - under the vendor root, with a distinct domain-separation tag for models; or
  - under a model-signing key certified by it.

  It is called by the kernel during R4, never by the engine.
- **Open policy question for `security-auditor`:** may operators sign models (like data packs), or
  only the vendor?

## R6 — Admission and leases (needed with R3–R5)

- **Evidence:** ADR 0061 (Proposed) D4 already describes reserve-or-refuse at configuration time.
- **Smallest interface:** a `Model` budget kind in the ADR 0061 admission scheme. Inputs come from
  the manifest:
  - weight bytes;
  - arena bytes;
  - state bytes per session;
  - max sessions;
  - bytes per token;
  - CPU class.

  Output: a lease, or a refusal reason shown in `/api/capabilities`. The lease is revocable under
  pressure. Revocation unmaps the region, and the engine falls back to "explanation unavailable".

## R7 — CPU for the language tier (needed for an on-device language tier)

- **Evidence:** one core. Production runs a polled loop with servers as bounded excursions (20–250 ms).
  The scheduler runs only as a boot demo (`main.rs:2626-2683`). The main loop's worst gap is already
  330–347 ms.
- **Two acceptable shapes; HomePods to choose:**
  - (a) **ADR 0060 SMP with a best-effort/AI role on non-DP cores.** The engine runs there and can
    never be scheduled on a DP core.
  - (b) **Single core, token-sized excursions.** Each excursion computes ≤ N layers within a small
    budget (e.g. ≤ 10 ms), and the engine keeps its state between excursions. This needs no new
    mechanism, only a budget. It makes language output slow, but never delays the packet path beyond
    the budget.
- **We recommend (b) as the first on-device step** and (a) when ADR 0060 lands.

## R8 — Data-plane pressure page (needed with R7)

- **Evidence:** `ratelimit.rs:822-837` is synthetic on CM5. There is no real signal.
- **Smallest interface:** one read-only page mapped into the engine with data-plane counters: ring
  occupancy, drops, packets per second, and a monotonically increasing "pressure epoch". The engine
  stops at the next layer boundary when pressure rises.

## R9 — Later, only if E-INT shows the need

| Request | Condition |
|---|---|
| EL0 counter (CNTVCT) access on CM5 | needed for engine-side pacing and measurement; small, possibly earlier |
| PMU access for closed-loop bandwidth regulation | only if open-loop pacing from bytes per token fails E-INT2 |
| Cache partitioning | only if E-INT shows L2/L3 eviction hurting DP p99 |
| Attestation field for the admitted model's root hash | when a language tier ships |

## Summary for HomePods

| Request | Needed for | Size |
|---|---|---|
| **R0 readouts** | every decision | small |
| R1 | nothing; tier B–C ships without kernel work | — |
| **R2 FP/SIMD per server** | any NEON kernel | medium; a security-sensitive context-switch change |
| R3–R6 | any on-device model > 3 MiB | large; depends on ADR 0061 |
| R7 | the language tier on-device | (b) small, (a) is ADR 0060 |
| R8 | pacing | small |
| R9 | evidence-driven only | — |
