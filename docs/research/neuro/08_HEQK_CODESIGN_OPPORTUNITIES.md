# 08 — heqk and inference co-design opportunities (Gate 8)

> Native Inference Research Programme, 2026-11-18. **Nothing here is implemented, and nothing here
> changes heqk.** For each capability:
> 1. what exists, per `00`;
> 2. what is missing;
> 3. why inference needs it;
> 4. whether the runtime could do without it;
> 5. what it would gain;
> 6. the minimum interface.
>
> The interfaces are written up as requests to HomePods in `12`.

## 1. What a capability microkernel can give inference that Linux cannot (easily)

Linux can run inference well. What it cannot cheaply give is **guarantees**. heqk's model is
explicit grants, no overcommit (ADR 0061), per-server address spaces and bounded excursions. That
makes four properties natural on heqk that are retrofits on Linux:

1. **Admission before execution.** A model either gets all its memory reserved up front or does not
   start. It never overcommits, never meets the OOM killer, and never sees a page-cache eviction storm.
2. **Immutability of weights by construction.** The weights are a read-only region mapped from a
   verified package. No process can write them, including the engine.
3. **The packet path has a hard priority.** The data plane owns its cores (ADR 0060: "never CP or
   MG work on DP cores"), so inference is structurally unable to run on them.
4. **One trust root for code and models.** The hybrid PQ signature that admits the kernel can admit
   the model.

Linux gets close only with cgroups, mlock, hugetlbfs, IMA/fs-verity and isolcpus, each bolted on
separately. The co-design opportunity is to make these **one mechanism, driven by the HNX manifest**
(`06`).

## 2. Capability by capability

| # | Capability | Exists today (`00`) | Missing | Why inference needs it | Without it? | Gain | Minimum interface |
|---|---|---|---|---|---|---|---|
| C1 | **FP/SIMD for one EL0 server** | nothing: softfloat everywhere; no CPACR policy; no V-reg save | per-thread FPEN, V-reg save/restore or scrub on switch | every useful kernel is NEON (SDOT/TBL) | integer-scalar only: fine for tiers B–C, useless for D (≈ 10–30× slower GEMV, estimate) | enables all of `01`/`02` | capability `FpSimd` on a TCB; kernel saves/scrubs V0–V31, FPCR, FPSR when switching from/to it; others stay trapped |
| C2 | **Large read-only region** | EL0 window 4 MiB; RO page mapping exists (`map_user_data_ro_in`) | window size; 2 MiB block mappings for EL0 | weights are 0.3–1 GiB | no: impossible above ~3 MiB | TLB reach (2 MiB blocks cut TLB misses on streaming GEMV) | a second EL0 window (e.g. a whole GB) for a `ModelRegion` mapped RO with 2 MiB blocks |
| C3 | **Bounded scratch arena** | frames from the bump pool | reservation sized from a manifest; freeing | static arena per model instance | yes, if small (≤ 1 MiB fits the current window) | determinism | part of the admission grant |
| C4 | **Model load from storage** | eMMC CMD18, PIO, ≤ 25 MHz, no CMD6; no EL0 path; staging 20 MiB | a streaming read of a large DataVolume extent into a reserved region; faster eMMC mode (CMD6 to 4/8-bit, HS) or NVMe | 300 MiB–1 GiB loads | no | load time 25–133 s → a few s (`07`) | kernel-side `load_extent(extent, region)` with hashing as it streams; a new DataVolume region for packages |
| C5 | **Verification of a model package** | hybrid verify, hboot + OTA only; operator Ed25519 packs | a verify call over a package root hash, same trust root (or a model key under it) | integrity, attestation | partly: an operator-signed pack type, but capped at 16–20 MiB | one trust model for code + models | `verify_package(root_hash, sig) → ok/err` in the kernel; Merkle segments checked during `load_extent` |
| C6 | **Admission and budgets** | ADR 0061 proposed: no admission code | cfgd reserve/refuse from a manifest | refuse before load, show why | no (would violate "no overcommit") | predictability; operator sees capacity | `admit(manifest) → lease | refusal(reason)` |
| C7 | **CPU time for inference** | single core; bounded excursions ≤ 250 ms; scheduler only in boot demo | SMP (ADR 0060), an AI or best-effort role on non-DP cores, or long preemptible excursions | decode takes 50–500 ms per token | yes for tiers B–C (µs per event); **no** for D on one core without stalling the main loop (worst gap already 330 ms) | concurrency without touching DP | a lease of N cores at MG/best-effort priority, revocable |
| C8 | **Preemption and deadlines** | excursion watchdog (virtual timer) | resumable work, deadlines | an explanation may be abandoned when the DP is busy | yes: chunk decode into token-sized excursions (each < 20 ms at 0.6B? to be measured) | DP latency unaffected | reuse excursions; engine keeps state between them (already how servers work) |
| C9 | **Data-plane pressure signal** | `runnable_depth()*10`, synthetic, not used on CM5 | a real signal (ring occupancy, drops, Mpps) readable by the engine | pace or pause decode under load | partly: the engine could pace from its own clock only | protects p99 (E-INT) | a read-only shared page with DP counters, updated by the data plane |
| C10 | **Bandwidth regulation** | no PMU access; no MPAM on A76 (UNVERIFIED for BCM2712) | PMU counters (MemGuard-style) | the only shared resource the DP cannot reserve is DRAM bandwidth | yes: **pace from the manifest's bytes-per-token** (open-loop) | measured in E-INT2 | optional: PMU access for closed-loop pacing |
| C11 | **Cache-aware execution** | caches on (write-back); no partitioning | cache colouring / partitioning (PALLOC-style) | GEMV streams weights through L2/L3, evicting DP tables | yes | unknown: needs E-INT measurement first | **not requested now** |
| C12 | **DMA-safe loading** | no SD/eMMC DMA; IOMMU enforcement unknown | DMA into the reserved region | faster loads, less CPU | yes (PIO works, slowly) | load CPU time | later, with C4 |
| C13 | **Attestation of the running model** | attestation service with per-boot key (`attest_svc.rs`) | include the admitted package root hash in the measured state | owner/MSSP can verify which model explained an incident | yes (log it in the evidence log) | trust in explanations | add a field to the attestation report |
| C14 | **Isolation from networking** | per-server ASID, no network caps for EL0 servers by default | — | a model must never reach the network | **already true** by construction | — | keep: the engine gets no network capability |
| C15 | **Telemetry of inference cost** | — | per-lease counters (CPU time, bytes loaded, tokens, refusals) | operator honesty: show what AI costs | yes (engine-reported) | trust; capacity planning | counters page; `/api/capabilities` shows lease state |

## 3. What not to ask for (yet)

- **Cache partitioning (C11) and closed-loop PMU regulation (part of C10)** need evidence first. E-INT1
  on a Linux CM5 bench, or later heqk SMP, must show that open-loop pacing is not enough.
- **An inference syscall or in-kernel engine.** The kernel image has 33 KB of headroom, and putting the
  engine in EL1 breaks the boundary.
- **Demand paging or a page cache for weights.** That contradicts ADR 0061 and makes latency
  non-deterministic.
- **Generic Untyped retype for EL0.** C2/C3/C6 can be served by a narrower "model region" grant.

## 4. The smallest useful co-design step

**Tiers B–C need none of C1–C15.** They run today inside a ≤ 4 MiB EL0 server as scalar integer
code in bounded excursions, exactly like `el0-lansvc`.

So the first co-design step is on the HookProbe side, not the kernel side:
- port the DNA and specialists to fixed-point Rust;
- run them in an EL0 server;
- measure excursion cost on metal.

The first kernel request (C1, FP/SIMD per server) only becomes necessary when a NEON kernel is
wanted. The second batch (C2, C4–C7) only becomes necessary when the language tier comes on-device.
