# 00 — System capability audit: what heqk really provides (Gate 0)

> Native Inference Research Programme, 2026-11-18. **Read-only audit of this worktree** (branch
> `agent/neuro-engine-research`, based on `main` after #1274). `os/kernel/**` is owned by HomePods;
> nothing was modified, built or run. Paths are relative to `os/kernel/` unless they start with
> `docs/`. The decisive lines were re-read by hand after two independent audit passes.
>
> **Status classes.**
> - **Metal** — a CM5 run cited in `docs/design/metal-evidence/*`, an ADR status table or `PRODUCTION_READINESS.md`.
> - **QEMU** — a marker in `validate.sh` or `tools/mc-e2e.sh`.
> - **Impl** — code exists, no test cited.
> - **Planned** — ADR or design doc only.
> - **Missing** — searched for, not found.
> - **Unknown** — needs a readout on hardware.
>
> **Ignored as evidence:** `docs/architecture/Readme.md` and `legacy/`, which describe the old Linux tier.

## 1. The one-paragraph answer

**heqk today can host a very small, integer-only, statically sized intelligence engine inside one
EL0 server, and nothing larger.** The real ceiling per server is set by:

| Limit | Value | Source |
|---|---|---|
| EL0 virtual window | **4 MiB** | `arch-aarch64/src/mmu_cm5.rs:73` |
| ELF segment cap | 2 MiB | `kernel/src/elf.rs:60-61` |
| Floating point / NEON | **none can be generated** — every crate builds for `aarch64-unknown-none-softfloat` | `.cargo/config.toml` in each crate |
| Scheduler | no preemption in production: each server runs as a bounded synchronous excursion of 20–250 ms inside a polled single-core loop | `kernel/src/main.rs:2682`, `:13706` |
| Syscalls | no map, allocate, file, block or crypto syscall; EL0 has no path to a blob larger than a few MiB | `abi/src/lib.rs:22-40`; `main.rs:11978-11999` |
| eMMC | PIO at ≤ 25 MHz with no CMD6 bus-width switch: a few MB/s, not the 100–250 MB/s the Linux-tier docs assume | `arch-aarch64/src/emmc.rs:46` |

Every one of these is a HomePods decision. Each becomes a precise request in `12`.

## 2. Corrections to the earlier Gate 0 (`docs/research/neuro-engine/NEURO_CM5_RESOURCE_BUDGET.md`)

| Earlier claim | Corrected |
|---|---|
| "128 MiB frame pool for every EL0 server" | The pool (`mmu_cm5.rs:410-411`, bump, never frees) is shared backing for frames **and page tables**. **One server can map at most 4 MiB** (`USER_WINDOW = 2 * M2`, `:73`; checked in `user_va_ok` `:169-178` and `elf.rs:86-88`). `validate.sh:76` already notes "the GB5 2-MiB window is too small for a MiB heap". |
| "Only the first 4 GiB is mapped" | GB0–3 are Normal memory, EL1-only. GB4–511 are mapped as **Device** memory (stage-1 `mmu_cm5.rs:319`; stage-2 `hboot/src/stage2.rs`). |
| "hboot parks cores 1–3" | Firmware (TF-A) holds the secondaries until PSCI `CPU_ON`, and no code calls it. hboot's park is a latent guard (`hboot/src/boot.s:27-35`, `park:` `:170-173`). MB23 (metal) shows PSCI 1.1 over SMC with `CPU_ON` supported and 4 cores. |
| "FP/SIMD trapped" | **Not verified on hardware.** No code writes CPACR_EL1 or CPTR_EL2, and no V-registers are saved (`thread.rs:1-10`, `vectors.s`). The firmware-left values are **unknown**. The toolchain is softfloat everywhere, so the question has not arisen yet. |
| "eMMC as a cold tier, 3.6–10.9 s/token" | Worse on heqk. **There is no path for EL0 to read a large blob at all** (§3.6). |
| Frame pool lines 405–425; hboot park 166–168 | Line drift: now `:410-431` and `:170-173`. |

## 3. Capability matrix (the 18 Gate 0 questions)

### 3.1 Build structure and boot (questions 1–2)

| Capability | Status | Evidence | Note |
|---|---|---|---|
| One `no_std` Cargo workspace: kernel, hal, arch-aarch64, abi, hboot, boot-abi, sae | Metal | `Cargo.toml` | `kernel/src/main.rs` is 16,790 lines |
| EL0 servers as detached crates, built by `kernel/build.rs:287 build_el0_crate`, linked at fixed addresses (`link-cm5.ld`), embedded with `include_bytes!` | Metal | `el0srv.rs:23-25`; per-crate `build.rs` | adding an inference server is the same pattern |
| Boot: TF-A (EL3) → hboot (EL2, resident; verifies the kernel, installs stage-2) → kernel (EL1) → EL0 servers | Metal | `hboot/src/boot.s:119-145`; `arch-aarch64/src/boot_hboot.s:15-37`; `main.rs:543` | any lower-EL sync exception at EL2 resets the SoC (`boot.s:~196-213`) |
| Shipping features `hboot,apmc,wifi-bigtx,appersist,wpa3` | — | `tools/ci/shipping-features.txt` | **`wasmhost` is not shipped** |

### 3.2 CPU and exception model (question 3)

| Capability | Status | Evidence | Note |
|---|---|---|---|
| Single core, non-reentrant contract | Metal | `ARCHITECTURE.md:142+` | — |
| SMP, core roles, BKL | Planned | ADR 0060 (🟡 Proposed 2026-11-11) | no `CPU_ON` call in code |
| PSCI on CM5 | Missing (probe only) | `boot-abi/src/t0.rs:124,158`; `smccc.rs` is cloud/HVC-only | — |
| FP/SIMD enable (CPACR.FPEN) | Missing | no CPACR/CPTR writes | GAP_REGISTER CORE-7 / XC-8, remediation A5 undecided (`HEQK_REMEDIATION_PLAN.md:101`) |
| FP/SIMD context save | Missing | thread frame = x0–x30, ELR, SPSR, SP_EL0 (`thread.rs:1-10`) | — |
| FP/NEON code generation | Disabled | `aarch64-unknown-none-softfloat` in all `.cargo/config.toml` | — |
| CPU feature registers (ISAR0 DotProd, DFR0 PMUVer, PFR0 MPAM) | Unknown | `hboot/src/t0inv.rs:37` reads ISAR0/DFR0, but MB23 does not publish them | MB23 does show SHA2/AES/PMULL present |

**What happens if an EL0 server executes a NEON instruction today?** It depends on unknown firmware
state:
- **FPEN ≠ 0b11** → the CPU traps to EL1 (EC 0x07). The kernel treats it as a contained EL0 fault and resets the server (`main.rs:13832`, `:13940-13985`).
- **FPEN = 0b11 and CPTR_EL2.TFP = 1** → the trap goes to EL2, and hboot **resets the SoC**.
- **Neither** → the instruction runs, and V-register state **leaks** between servers and EL1, because nothing saves it.

**All three outcomes are unacceptable for a product.** This makes the FP/SIMD policy the first
prerequisite.

### 3.3 Memory, MMU, cache (questions 4–6)

| Capability | Status | Evidence | Note |
|---|---|---|---|
| RAM discovery at runtime | Missing | `BootInfo` has no memory fields (`boot-abi/src/lib.rs:157-175`); DTB parsed only by the opt-in `t0inv` | the shipping boot has no DTB (MB23) |
| Kernel heap | Metal | 1 MiB bump allocator, never frees (`heap.rs:10,58-60`) | — |
| EL0 frame pool | Metal | `0x3000_0000..0x3800_0000`, bump allocator (`mmu_cm5.rs:410-431`) | shared with page tables |
| **EL0 VA window** | Metal | **4 MiB**, 4 KiB pages only (`mmu_cm5.rs:73,169-178,510-533`) | the binding limit |
| 2 MiB / huge EL0 mappings | Missing | — | — |
| Large contiguous EL0 region (100s of MiB) | Missing | — | — |
| Read-only EL0 data pages | Impl, metal claimed without a log | `map_user_data_ro_in` (`mmu_cm5.rs:546`) | — |
| W^X user code | Metal | `link-cm5.ld`; SCTLR.WXN set (`mmu_cm5.rs:372-376`) | — |
| EL0↔EL0 shared memory | Impl, one page only | key page el0-wpa→el0-wifi (`el0srv.rs:35-45`) | — |
| Zero-copy rings | Planned | `ZEROCOPY_IPC_RING.md` ("design document") | — |
| Untyped-backed EL0 memory | Missing | `caps.rs:9-12` | servers get frames straight from `alloc_frame` (`el0srv.rs:182-186`) |
| Memory budgets, admission, pressure signal | Planned | ADR 0061 (🟡 Proposed; M9 not implemented) | — |

MMU and cache facts (`mmu_cm5.rs:304-385`):

| Register / feature | Configuration |
|---|---|
| MAIR | attr0 Device-nGnRnE, attr1 Normal write-back RW-allocate, attr2 Normal non-cacheable |
| TCR | 39-bit VA, 4 KiB granule, 16-bit ASIDs, IPS 40-bit, no TTBR1 |
| SCTLR | M, C, I and WXN set |
| Address spaces | per-AS L1 copied from the kernel's, plus a private GB5 L2/L3 (`:463-497`) |
| Stage-2 | VTCR `0x8002_3559` (39-bit IPA, 4 KiB granule) |

### 3.4 Scheduling and IPC (questions 7–8)

| Capability | Status | Evidence | Note |
|---|---|---|---|
| Preemptive scheduler: fixed `u8` priorities, round-robin, 36 slots, 100 Hz tick | Metal **boot demo only** | `scheduler.rs`; `cm5_scheduler_demo` `main.rs:2626-2683` | the demo stops the timer (`:2671`) and leaves `EL0_SCHED_MODE = false` (`:2682`) |
| **Production execution model** | Metal | polled run-to-completion loop at EL1 with IRQs masked (`cm5_prod_service` `main.rs:1370-1372`); servers run as **bounded excursions** (`excursion_bounded` `:13706`) with budgets el0-wifi 20 ms, lansvc 20 ms, hsh 50 ms, wpa 250 ms, tlshost 250 ms | round trip 388 ns / 1.2 µs (ADR 0065 `:147`) |
| Main-loop worst gap | Metal | **330–347 ms** (`PRODUCTION_READINESS.md:18`; `metal-evidence/20261110-batch29.md:68`) | already long for a network appliance; inference must not add to it |
| CPU budgets, deadlines, reservations | Missing | — | ADR 0060 planned |
| CPU pressure signal | QEMU (synthetic only) | `ratelimit.rs:822-837` (`runnable_depth()*10`) | does not reflect load on CM5 |
| Syscalls | QEMU (most), metal (EXIT_USER) | `abi/src/lib.rs:22-40`; `main.rs:11979-11984` | 2–7 basic, 16–22 notify/pub-sub, 24–26 CALL/EP_RECV/REPLY; **no map, alloc, retype, thread, file, block or crypto** |
| Sync IPC, notifications, pub-sub | QEMU | `[P4]`, `[P-r1-ipc]`, `[P12]` | need the scheduler, so not on the CM5 production path |
| Kernel↔EL0 rings | Metal | `hal/src/el0ring.rs`: 32 slots × 2 KiB, copied by the kernel | — |

### 3.5 Timers, interrupts, counters (question 9)

| Capability | Status | Evidence |
|---|---|---|
| GIC-400, SPIs to CPU0 | Metal | `gic.rs:11-14,45` |
| Physical timer PPI 30 (tick), virtual timer PPI 27 (excursion watchdog), CNTFRQ 54 MHz | Metal | `timer.rs:7,13`; MB23 |
| IRQ delivery to EL0 | Missing | — |
| EL0 counter read (CNTVCT) | QEMU only (`p17_overlay_qemu`, `main.rs:7894,7921`); **CM5 unknown** | `timer.rs:59,73-81` |
| PMU (PMCR, PMCCNTR, PMUSERENR) | Missing | — |

### 3.6 Storage (questions 10–12)

| Capability | Status | Evidence | Note |
|---|---|---|---|
| eMMC read, CMD17 / CMD18 multi-block | Metal | `emmc.rs:111,312,327` | **PIO only, ≤ 25 MHz (`:46`), no CMD6** (`:9-12`), so the bus width stays at the power-on default; no DMA, no HS200 |
| eMMC throughput | Unknown (no MB/s report) | `validate.sh:149` suggests ~1.4 MB/s for single-sector scans; boot takes 60 s (`PRODUCTION_READINESS.md:18`) | **ceiling ≈ 3.1 MB/s (1-bit) or ≈ 12.5 MB/s (4-bit) at 25 MHz** — arithmetic, not measured |
| eMMC gated write | Metal | allowlisted regions only (`emmc.rs:490`) | — |
| Filesystem | Metal (read-only) | FAT32 root directory, 8.3 names (`fat.rs:145`); fslog record ring | no writer |
| DataVolume layout | Metal | 2 × 56 MiB artifact-store halves, 20 MiB staging, evidence ≥ 64 MiB (`datavol.rs:22-31`) | — |
| Artifact store + upload API | Metal | closed list of types, **largest cap 16 MiB** (`artstore.rs:66-75`; `upload.rs`) | — |
| EL0 file / blob / block API | Missing | — | — |
| **Path to load a > 20 MiB blob** | **Missing** | staging 20 MiB; p1 64 MiB; EL0 window 4 MiB | — |
| PCIe RC1 + RTL8111H | Metal | `rtl8111.rs`; `GAP_REGISTER.md:554` | — |
| NVMe | Missing (planned for RK3588, ADR 0064) | — | — |
| IOMMU enforcement | Unknown | `iommu.rs` (address ceiling only) | — |

### 3.7 Debug, crypto, identity (questions 13–14)

| Capability | Status | Evidence | Note |
|---|---|---|---|
| UART console, TX only | Metal | `uart.rs:3-25` | — |
| Crash record | QEMU; metal partial | `crashrec.rs` | — |
| GDB | QEMU only | `HACKING.md:35-39` | no metal debugger documented |
| Hybrid image verify (Ed25519 + SLH-DSA-SHA2-128s, SVN floor) | Metal | `boot-abi/src/verify.rs:60,72,120,158` | **two callers only: hboot and the kernel OTA path; one trust root, the vendor key** |
| Operator-signed data packs (Ed25519, first-use pinning) | Metal | `policysig.rs`; `anchor.rs` | — |
| Wasm modules, Ed25519 | QEMU / metal fixture | `wasmhost.rs:31-38` | — |
| Signed-blob verification from EL0 | Missing | no crypto syscall | — |
| SHA-256, HMAC, HKDF, AES, ChaCha20-Poly1305, X25519, ML-KEM-768, P-256 | QEMU, used on metal | `boot-abi/src/{sha256,kdf}.rs` etc. | kernel-only; **no BLAKE2/3** |
| Sealed storage (HQKSEAL1), SRK derived from OTP | Metal | `seal.rs`; `main.rs:6213` | `SEALED_STORAGE.md:3` is stale |
| TPM | Missing | DICE-style AK + SRK instead | SEC-3 fuses open (first stage is trust-on-first-use) |

### 3.8 Applications, services, data plane, footprint (questions 15–18)

| Capability | Status | Evidence | Note |
|---|---|---|---|
| EL0 servers | Metal | `el0-tlshost` (rustls; image 512 KiB, heap 896 KiB), `el0-lansvc` (256 KiB), `el0-wifi` (128 KiB; 98–106 Mb/s), `el0-wpa` (128 KiB + 8 state pages); `el0-hsh` QEMU | ADR 0065 `:143-157`; `hal/src/tlsabi.rs:10-16` |
| `el0-wasmhost` (wasmi 0.32.3) | Metal for one fixture; **not shipped** | no fuel or StoreLimits; 256 KiB heap on CM5 (`el0-wasmhost/src/main.rs:41`) | an interpreter: unsuitable for inference |
| Mission Control API | Metal | in **EL1** (`http.rs:361`); TLS terminated in el0-tlshost | — |
| AI planner / copilot | **Missing, reported honestly** | `/api/planner/*` → 503 `not_configured` or `configured:false` (`http.rs:425-429,698-699`); capability "planner" denied (`capabilities.rs:32`); QEMU e2e (`tools/mc-e2e.sh:126-131`) | — |
| Explanations today | Metal | template-built: `det_row` (`mcstate.rs:744-785`), report summary (`:1310-1324`), static rule catalogue (`rulecat.rs`) | the natural integration point for L0 + model explanation |
| Data plane and IDS | Metal | EL1 fast path (ADR 0050); BPF interpreter, verifier and arm64 JIT (`bpf.rs`, `absdom.rs`, `bpf_jit.rs`) | — |
| IDS cost | Metal | **398–441 ns/pkt, 2.27–2.51 Mpps on one A76 core**; ≈ 1% of a core at 150 Mb/s Wi-Fi | `metal-evidence/20261109-detection-network-series.md:7-19` |
| Per-subsystem RAM use, pool high-water mark | **Unknown (never measured)** | ADR 0061 M9/M10 | — |
| Images | Metal | shipping kernel 3,104,072 B against a 3,137,736 B hboot window (`rust-toolchain.toml:2-5`) | **33 KB of headroom**: an inference engine cannot live in the kernel image even if it should |
| Targets | — | QEMU virt (cortex-a72) is the gate target; OCI A1 cloud tier partial; **x86_64 missing**; RK3588 planned | — |

## 4. What this means for the research programme

1. **The kernel is not the bottleneck for intelligence that does not need a model.** Rules, evidence
   cards, the behavioural memory (672 B per device) and integer specialists can run inside one EL0
   server today: 4 MiB window, softfloat, scalar integer, bounded excursion. The behavioural memory's
   scoring uses `log2`/`sqrt`, which must become fixed point; softfloat would work but is slow.
2. **Any SIMD kernel needs a kernel decision first** (CPACR/CPTR policy plus V-register save).
   Without it, the A76 analysis in `02` describes hardware heqk cannot use.
3. **Any model larger than ~3 MiB needs four kernel changes:**
   - a large read-only mapping;
   - a load path from storage;
   - a faster eMMC mode or NVMe;
   - admission.
   It cannot be done in EL0 alone.
4. **Any concurrent inference needs SMP or preemption.** Today a 250 ms excursion budget is the
   *largest* slice a server gets, and the main loop already shows 330 ms gaps.
5. **Hardware readouts are the cheapest next step:**
   - CPACR_EL1, CPTR_EL2, CNTKCTL_EL1[1:0], MDCR_EL2, PMUSERENR_EL0;
   - ID_AA64ISAR0 (DotProd), ID_AA64DFR0 (PMUVer), ID_AA64PFR0 (MPAM);
   - one eMMC MB/s figure.

   HomePods' `t0inv` already reads two of these registers. Publishing them settles several
   "unknowns" without design work.

## 5. Stale documents found (for HomePods / `product-steward`, not changed here)

- `GAP_REGISTER.md` is historical (`heqk-decisions-2026-11-08.md` §A).
- `SEALED_STORAGE.md:3` and `PERIPHERAL_BUSES.md:3` say "designed, not implemented", but the code runs on metal.
- `seal.rs:18-22` describes a synthetic SRK.
- `rtl8111.rs:3` says "not yet wired".
- `PER_TCB_CSPACE.md` says "designed", but `CSPACE[MAX_THREADS]` exists (`main.rs:12013`).
- `BPF_THREAT_PLANE.md` places the BPF VM in a sidecar; the code runs it in EL1 (ADR 0050).
- `docs/design/heqk-everywhere-report-2026-10-09.md:17` calls wasip1 proven on metal, but code says QEMU-path only.
- `PRODUCTION_READINESS.md:40` cites a "metal batch 22" that has no document.
