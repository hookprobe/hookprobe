# HookProbe Microkernel — Build Plan (deep-fixed, concrete)

**How to actually build the custom Rust aarch64 microkernel: toolchain, workspace, the design commitments to bake in from day one, and a QEMU-first P0→P7 roadmap where every phase is gated on a runnable test — grounded in how seL4, L4, Redox, and the rust-raspberrypi tutorials were actually built.**

Status: **authoritative build plan**, supersedes the earlier seL4-vs-from-scratch (Track A/B) framing — that decision is **made: custom Rust kernel** (see `ARCHITECTURE.md` §0, and the "OS is the sensor" justification in §6). This document is the *engineering* companion to `ARCHITECTURE.md` (the *what*); here is the *how*. Sources are cited inline; `VERIFY` = confirm against your exact QEMU/toolchain build before trusting.

---

## 1. The approach in one page (the load-bearing calls, from proven kernels)

Six principles, each learned the hard way by a real kernel, that determine success before you write a line:

1. **QEMU `virt` first, always.** Build the entire core against clean, documented hardware (PL011 UART, GIC, generic timer, virtio) with a sub-second edit-compile-boot loop. The `rust-raspberrypi-OS-tutorials` prove this progression (tutorials 01–16 are QEMU-runnable). CM5/RP1 is a *later HAL+driver effort against a finished kernel* — never a simultaneous core+hardware bringup (`ARCHITECTURE.md` §2).
2. **HAL trait boundary from commit one.** The `kernel` crate contains **zero `cfg(target_arch)`**; all arch code lives behind traits in `hal`, implemented by `arch-aarch64` (Redox's `src/arch/` split is the model). A second arch (x86_64/N100) becomes additive, not a rewrite.
3. **IPC register-only fast-path is designed first, not last.** Liedtke's SOSP'93 lesson ("Improving IPC by Kernel Design," 20× over Mach) still governs: *IPC is the make-or-break*. seL4's fastpath is ~468 cycles one-way (Skylake; `VERIFY` arm64 numbers on [seL4 performance](https://sel4.systems/performance.html)). Design the `Call`/`ReplyRecv` register-only path before the slow path; everything else can be slow.
4. **No dynamic allocation in the kernel — ever.** Adopt seL4's **untyped→retype** model: memory starts as Untyped capabilities, userspace carves typed objects, the kernel never `malloc`s. This gives bounded kernel memory, no in-kernel OOM, and is the property that makes isolation tractable. Retrofitting this is agony — bake it in at P2.
5. **Drivers, stacks, filesystems are userspace.** Only the GIC, the timer, and a minimal early UART live in the kernel. Everything else is a capability-bounded, restartable userspace server (this is the whole microkernel thesis and the fault-isolation story).
6. **Right-size for edge, not the datacenter.** Adaptive NAPI data plane, 2 MiB hugepages, 1–2.5 GbE target (`ARCHITECTURE.md` §5) — not spin-poll-forever / 1 GiB / 100 GbE.

---

## 2. Project setup (the concrete "how you start typing")

### Toolchain
- **Target:** `aarch64-unknown-none-softfloat` (built-in Tier-2). **Softfloat, not hardfloat** — a kernel must not clobber FP/SIMD registers before saving them on trap/switch; rustc's own docs say prefer `-softfloat` for kernels ([rustc platform-support](https://doc.rust-lang.org/beta/rustc/platform-support/aarch64-unknown-none.html)). The rpi tutorials use it.
- **Nightly, pinned.** `rust-toolchain.toml`:
  ```toml
  [toolchain]
  channel   = "nightly-2026-07-01"   # pin; bump deliberately
  components = ["rust-src", "llvm-tools"]
  targets   = ["aarch64-unknown-none-softfloat"]
  ```
- **`build-std`** (`.cargo/config.toml`) to get `core`+`alloc` for a target without prebuilt std:
  ```toml
  [unstable]
  build-std = ["core", "alloc", "compiler_builtins"]
  build-std-features = ["compiler-builtins-mem"]   # provides memcpy/memset
  [build]
  target = "aarch64-unknown-none-softfloat"
  ```
- Built-in target beats a custom JSON spec (since rustc ships `rust-std` for these); only write a `.json` if you must change code-model/features.

### Workspace layout (HAL-abstracted — Redox / rpi-tutorials pattern)
```
/Cargo.toml          # [workspace]
/kernel      # arch-neutral: scheduler, IPC, capabilities, VM policy, sensor taps. NO cfg(target_arch)
/hal         # traits + types: Mmu, Timer, IrqController, Console, context_switch, early_init
/arch-aarch64# impls hal: boot.S stub, EL1 vectors, GIC, generic timer, MMU, aarch64-cpu regs
/arch-x86_64 # (P-later) impls hal for N100
/abi         # #![no_std] shared syscall numbers + trap-frame/cap structs — used by kernel AND userspace
/user/*      # userspace servers: root task, PCI server, virtio-net driver, IDS sidecar
```
Keep `abi` tiny and stable — it is the contract between ring 0 and ring 3 and between arches.

### Crates (every dep is TCB — keep it minimal, MIT/Apache only, no GPL)
| Crate | Role | License |
|---|---|---|
| `aarch64-cpu` (was `cortex-a`) | typed system-register access (`SCTLR_EL1`, `VBAR_EL1`, barriers, `wfe`) | Apache/MIT |
| `tock-registers` | MMIO register-field DSL (`register_bitfields!`) | Apache/MIT |
| `spin` / `spinning_top` | `no_std` spinlock / `Once` | MIT |
| `buddy_system_allocator` | frame + heap allocator (used by rCore/reL4) — *for userspace & the pre-retype boot heap only* | MIT |
| `fdt` | parse the DTB QEMU passes in `x0` (discover RAM/UART/GIC) | MIT/Apache |
| `bitflags` | page-table / permission flag types | MIT/Apache |
| (optional) `aarch64-rt` (Google) | startup + exception vectors if you don't hand-roll boot asm | Apache/MIT |
**Avoid in-kernel:** anything pulling `std`, heavy `syn`/proc-macro chains, allocating `log` backends, async runtimes, serde/hashbrown unless unavoidable.

### QEMU dev loop
```
qemu-system-aarch64 -M virt -cpu cortex-a72 -m 512M -nographic \
  -serial mon:stdio -semihosting \
  -kernel target/aarch64-unknown-none-softfloat/debug/kernel
```
- `-M virt`: PL011 UART @ `0x0900_0000`, GICv2 by default (`-machine gic-version=3` for v3), DTB at RAM base. `-kernel` loads the ELF at **`0x4008_0000`** (`VERIFY` on your QEMU via the generated DTB / `-d int`) and enters at EL1 (or EL2 with `-machine virtualization=on`).
- **Exit-from-code for tests:** aarch64 `virt` has **no** `isa-debug-exit` (that's x86-only — phil-opp's `0xf4` trick does not port). Use **ARM semihosting `SYS_EXIT`** (`hlt #0xf000`, `x0=0x18`) with `-semihosting`, or **PSCI `SYSTEM_OFF`** (`hvc`/`smc`, supported by `virt`). `VERIFY` the exact semihosting parameter block against the spec — it's easy to get subtly wrong.
- **Test harness:** `#![feature(custom_test_frameworks)]`, `#![test_runner(crate::test_runner)]`, `#![reexport_test_harness_main="test_main"]`; the runner iterates `&[&dyn Fn()]`, prints over PL011, then semihosting-exits with pass/fail. Wire `[target.aarch64-unknown-none-softfloat] runner = "qemu-system-aarch64 -M virt -cpu cortex-a72 -semihosting -nographic -kernel"` so `cargo test` boots each test binary. (phil-opp's [Testing chapter](https://os.phil-opp.com/testing/) — take the *methodology*, swap the x86 exit for semihosting.)
- **Debug:** add `-s -S`, then `gdb-multiarch kernel -ex 'target remote :1234'`.

---

## 3. Reference kernels — study, don't fork (what to take from each)
| Project | License | Take exactly this |
|---|---|---|
| **rust-raspberrypi-OS-tutorials** | Apache/MIT | **Most relevant.** aarch64 boot, EL-drop, exception vectors, MMU, `tock-registers` MMIO style; QEMU-runnable progression 01→16 |
| **Redox kernel** | MIT | arch-neutral core + `src/arch/{aarch64,x86_64}` module split; real Rust microkernel <40k LoC |
| **seL4 (+ reL4 / rust-sel4)** | GPLv2 / MIT | the object model (TCB/Endpoint/Notification/CNode/Untyped/VSpace), IPC fastpath design, untyped/retype, CDT revoke. reL4 shows these *in Rust* (`VERIFY` maintenance) |
| **phil-opp blog_os** | Apache/MIT | the `no_std` + `custom_test_frameworks` **testing methodology** (its arch code is x86-only) |
| **Hermit** | Apache/MIT | clean nightly/build-std tooling & boot path (it's a unikernel, not a microkernel model) |
| **Theseus** | MIT | idea only: enforce isolation via Rust types (research-grade) |

---

## 4. Design commitments to bake in from day one (cheap now, agony to retrofit)
- **Untyped→retype allocation** — kernel never allocates; userspace policy (§1.4). Decide the Untyped/Retype API at P2.
- **Register-only IPC fastpath** — `Call`/`ReplyRecv`, reply cap in the receiver TCB; design before the slow path (§1.3).
- **Non-preemptible, bounded syscalls** — classic L4/seL4: short syscalls, long ops made restartable/incremental → no in-kernel locks, simple reasoning. Decide at P1.
- **ASID-tagged address spaces** — set `TCR_EL1.AS`/`A1`, write ASID+base into `TTBR0_EL1` per switch to avoid full TLB flushes; barrier discipline (`dsb ish; isb; tlbi`) after every mapping change. Bake into the MMU/HAL at P0.
- **Capabilities in CNodes** — caps stored in kernel CNode slots, named by CSpace index, never in user memory (`CAPABILITY_MODEL.md`).
- **"OS is the sensor" taps** — reserve, from P2, an event hook on capability invoke / retype / revoke / IPC / scheduling-anomaly that P6 pipes to QSecBit. It's a design seam, not a feature to bolt on later (`ARCHITECTURE.md` §6).

---

## 5. The roadmap — P0→P7, each phase gated on a runnable test

### P0 — Skeleton (QEMU virt)
- **Boot stub** (`arch-aarch64/boot.S`, minimal asm): land from firmware (QEMU `virt` drops you in **EL2** on the boot CPU), **EL2→EL1 drop** — `HCR_EL2.RW=1` (EL1 is AArch64), `SPSR_EL2.M=0b0101` (EL1h) + DAIF masked, `ELR_EL2`=EL1 entry, set `SP_EL1`, `eret`. Zero `.bss`, set SP, call Rust `kmain`.
- **PL011 UART** console (via HAL `Console`); `#[panic_handler]` prints + halts.
- **Exception vectors:** 2 KB-aligned, 16 entries × 0x80 bytes (Sync/IRQ/FIQ/SError × 4 EL/SP combos), base → `VBAR_EL1`. Catch faults and print (never silent-reset).
- **Physical page allocator** (bitmap/buddy over the DTB-reported RAM map).
- **MMU enable:** `MAIR_EL1` (idx0 Device-nGnRnE, idx1 Normal-WB), `TCR_EL1` (T0SZ/T1SZ, 4 KB granule, cacheable inner-shareable walks, IPS from `ID_AA64MMFR0_EL1`), build tables, `TTBR0/TTBR1_EL1`, `dsb ish; isb`, `SCTLR_EL1.M=1`, `isb`. Kernel heap (`buddy_system_allocator`) as the pre-retype boot heap only.
- **Gate P0:** boots on QEMU, prints from Rust `kmain`, a deliberate bad access is *caught and reported* by the vectors. `cargo test` runs one semihosting-exit test green.
- **✅ GREEN (2026-07-20).** Workspace scaffolded (`kernel`/`hal`/`arch-aarch64`/`abi`, HAL boundary enforced); Rust nightly 1.99 + `aarch64-unknown-none-softfloat`. Boots on `qemu-system-aarch64 -M virt` (QEMU 8.2.2): banner + `hello from EL1` over PL011; `brk #0` self-test traps to `VBAR_EL1` (`ESR_EL1` EC=0x3c Breakpoint) → reported → clean exit. **EL2→EL1 drop verified** via `virtualization=on` (CPU starts EL2, still lands EL1). `cargo run` is the one-command loop. Repro: `HACKING.md`. *(bss zeroing + stack + vectors done; full MMU/phys-allocator/heap is the remainder of P0 → rolls into P1.)*

### P1 — Execution
- **TCB** struct; **context switch** saving callee-saved `x19–x28`, `x29`(FP), `x30`(LR), `SP` (lazy FP/SIMD via `CPACR_EL1` trap).
- **Preemptive priority scheduler** on the **generic timer**: read `CNTFRQ_EL0`, arm `CNTP_TVAL_EL0`, enable `CNTP_CTL_EL0`; timer fires as **PPI INTID 30** (`VERIFY`) through the GIC. **GIC init** (v2 default on `virt`: `GICD_CTLR` + `GICC_CTLR`/`GICC_PMR`/`GICC_IAR`/`GICC_EOIR`; v3: redistributor + `ICC_*_EL1` sysregs). Thread pinning API.
- **Gate P1:** two threads round-robin under timer preemption; pin works; scheduler tick verified in a test.
- **✅ GREEN (2026-07-20).** Kernel heap (zero-dep bump allocator; `Vec`/`alloc` working). **GICv2** brought up (distributor + CPU interface); **ARM generic timer** armed at 100 Hz (EL1 physical, PPI 14 → INTID 30). Full **trap-frame context switch** in `vectors.s` `irq_entry` (saves x0–x30 + ELR + SPSR, switches SP, restores, `eret`). **Round-robin preemptive scheduler** (`kernel/scheduler.rs`, arch-neutral, opaque `sp`; arch builds frames in `thread.rs`). 3 worker threads + idle interleave under timer preemption with **per-thread counters advancing across switches** (`A0 B0 C0 C1 A1 B1 …`) — proves context save/restore. Boots + runs on QEMU 8.2.2; repro in `HACKING.md`. **Honest scope:** scheduler is round-robin (priority is a small extension, not yet done); **MMU/paging still OFF** (running identity-mapped physical) → that's **P1b** next; thread "pinning" is trivial until SMP.

### P2 — Capabilities
- **CNode** (cap table), **Untyped**, `Untyped_Retype` → TCB/Endpoint/Notification/CNode/Frame/PageTable; **CSpace** resolution (guarded radix walk); **CDT** (mapping database) so `Revoke` recursively deletes derived caps with no GC pause. Add the **sensor tap** on retype/revoke here.
- **Gate P2:** retype an Untyped into objects; revoke a subtree and prove all derived caps vanish synchronously (test).
- **✅ GREEN (2026-07-20).** `kernel/caps.rs` (arch-neutral — capabilities need no HAL): `CapSpace` with untyped→retype into CNode/Endpoint/Frame/Tcb/sub-Untyped, a capability derivation tree, and synchronous recursive `revoke`. Self-test proves: derivation tree renders (8 caps), type-safety rejects retyping a non-Untyped and using an Endpoint as a Frame, `revoke(sub)` deletes a subtree (8→6), `revoke(root)` deletes all derived + reclaims memory (6→1). `[P2] PASS`.
- **P1b ✅ GREEN (2026-07-20).** `arch-aarch64/mmu.rs`: 4 KiB-granule stage-1 MMU (MAIR/TCR/TTBR0/SCTLR, identity 1 GiB blocks — GB0 device, GB1 normal), physical frame allocator, fine-grained `map_page`. Proof: MMU on, fresh frame mapped at a high VA, r/w verified, VA≠PA; preemption still works with MMU+caches on. `[P1b] PASS`.

### P3 — Userspace
- **SVC syscall boundary:** `svc #imm` → EL1 Sync vector; decode `ESR_EL1` (`EC=0x15`), save trap frame (x0–x30, `SP_EL0`, `ELR_EL1`, `SPSR_EL1`); args x0–x7, number in x8; `eret` back to EL0. Narrow, validated API (`ipc_send/recv`, `cap_*`, `yield`).
- **Root task** at EL0 holding all initial caps (the primordial manager).
- **Gate P3:** root task runs at EL0, invokes a cap via SVC, a fault in it is contained (kernel survives).
- **✅ GREEN (2026-07-20).** EL0 entry + kernel-resume glue (`arch-aarch64/syscall.s`, setjmp/longjmp-style), `lower_sync_entry` vector servicing SVC + containing faults, and a per-page **user address space** (dedicated EL0 code+stack pages via `map_user_page`; **kernel RAM stays EL1-only** — real isolation, learned after a first attempt that made kernel RAM EL0-accessible and broke privileged access). A position-independent user program runs at EL0, makes 3 syscalls (incl. a return-value round-trip), then a data abort (`EC=0x24`) is caught by the kernel, which contains it and resumes. `[P3] PASS`.
- **P0–P3 gap-closure (2026-07-20).** Hardened after audit: **priority scheduler** (was round-robin) + **thread lifecycle/exit** (`kernel/scheduler.rs`); capabilities now **backed by real reserved physical frames** (a Frame cap's memory is write/read-verified) instead of nominal addresses; and P3 now does a **genuine capability invocation from EL0** (`SYS_CAP_IDENTIFY` resolves a CPtr in the root task's CSpace — meeting the gate's "invoke a cap via SVC" wording) with a real **root-task CSpace**. Deliberately deferred (named, not faked): SMP, DTB-sized RAM, frame/heap free-lists, real per-AS ASIDs + W^X + kernel-page block-splitting, nested CSpaces + Grant/mint delegation, FP/SIMD lazy save, EL0 tasks as scheduled TCBs.

- **Gate P4 (revised): synchronous IPC rendezvous over an Endpoint.** *(The zero-copy ring moves to P5, where it is the north-star datapath.)*
- **✅ GREEN (2026-07-20).** `kernel/ipc.rs` + scheduler **block/unblock** states: a consumer thread `recv()`s and blocks; a lower-priority producer `send(0xBEEF)`s, deposits the message and unblocks the consumer, which resumes and receives `0xbeef`. Critical sections mask IRQs (single-core atomic check-and-block). `[P4] PASS`. IPC + the priority-scheduler demo run in one scheduler episode.

- **Gate P5: Packet Engine — zero-copy ring + in-place verdict** *(the north-star datapath; real NIC wire is P5b, the RFC 9669 BPF VM is P6/AI Runtime).*
- **✅ GREEN (2026-07-20).** `kernel/packet.rs`: an SPSC descriptor ring (Region B) over a frame pool (Region C, real reserved physical), release/acquire indices (Region A). Producer writes a packet into a pool frame (the DMA-equivalent) and publishes a descriptor; the consumer acquires it and runs a verdict **against the payload in place — no copy** — dropping a blocked dst-port. 10 synthetic packets (ring wraps) → 5 DROP / 5 PASS. `[P5] PASS`. This is the datapath the whole product exists to run.
- **Rename → HEQK Core (Hardened Edge Quantum-safe Kernel), folder `~/heqk`.** Subsystem architecture in `HEQK_SUBSYSTEMS.md`: Scheduler + Capability Model (built), Security Framework (partial), Packet Engine (P5, built), Telemetry Bus + AI Runtime (P6), and a new **PQC** subsystem (ML-KEM/ML-DSA) for quantum-safe signing/attestation.

- **Gate P5b: real wire — virtio-net RX into the ring.**
- **✅ GREEN (2026-07-20).** `arch-aarch64/virtio.rs`: a minimal **virtio-net (virtio-mmio v2)** driver — device discovery, feature negotiation (MAC + VERSION_1), split-virtqueue RX/TX setup, RX-buffer posting. It **ARPs the gateway (10.0.2.2) and receives the real ARP reply** (64 B, ethertype 0x0806), which is pushed through the Packet Engine ring (`produce_raw`) and gets a verdict. `[P5b] PASS`. Requires QEMU `-global virtio-mmio.force-legacy=false -netdev user,id=n0 -device virtio-net-device,netdev=n0` (wired into `.cargo/config.toml` + `validate.sh`). *Debugging note: it silently failed until we forced virtio-mmio v2 — QEMU defaults to legacy (v1), whose register layout differs.*
- **P0–P5 gap-closure (round 2, 2026-07-20).** **Frame allocator now has a free list** (`free_frame` + LIFO reuse — proven: free then re-alloc returns the same frame) — the bump-only allocator is closed. Still deliberately deferred (named, not faked): SMP/secondary cores, DTB-sized RAM (hardcoded 512 MiB matches the `-m` flag), full W^X + per-AS ASIDs + kernel-page block-splitting, nested CSpaces + Grant/mint, FP/SIMD lazy save, EL0 tasks as scheduled TCBs. These are later-phase, not shortcuts in what's claimed green.

- **Gate P6: AI Runtime — RFC 9669 BPF VM as the verdict.**
- **✅ GREEN (2026-07-20).** `kernel/bpf.rs`: a small **RFC 9669 BPF interpreter** (64-bit regs; LDX/LSH/OR/JNE/MOV/EXIT subset) runs a **signed first-party threat rule** as real bytecode — DROP if the dst-port field == 4444. It replaces P5's native stand-in: **the Packet Engine's verdict IS this VM** (P5/P5b run it on every packet). A **runtime bounds check** (Layer-2 software sandbox) rejects an out-of-bounds load on a truncated packet, and a step limit guarantees termination. `[P6] PASS`. The moat: the same bytecode runs on the Linux/FreeBSD/QNX HookProbe substrates. **P6b (next):** a JIT (native codegen), a PREVAIL-style verifier for third-party rules, QSecBit scoring, and the "OS is the sensor" telemetry taps.
- **Gate P6b: BPF verifier + JIT + self-heal + telemetry.**
- **✅ GREEN (2026-07-20).** (1) **Static verifier** (`bpf.rs::verify`): known-opcodes, valid-registers, **no backward jumps** (termination), reachable EXIT — accepts the signed rule, rejects a looping one. (2) **JIT** (`arch-aarch64/bpf_jit.rs`): compiles the rule to native ARM64, **W^X-locked** (RO+exec via `map_code_page`), and its verdicts **match the interpreter**. (3) **Self-heal supervisor** (`main.rs`): HAM-style restart-on-fault — a flaky component faults twice, the supervisor restarts it, it recovers. (4) **Telemetry Bus + QSecBit-lite** (`kernel/telemetry.rs`): cap-revoke/fault/packet-drop/self-heal events emitted from the TCB, summed into a threat score (33) — "the OS is the sensor." `[P6b] PASS`.
- **Enhanced healing (two layers):** *runtime* — the kernel self-heals via the P6b supervisor + telemetry; *build-time* — `validate.sh` now auto-prints a **HEAL block** (first failing gate + captured exception/`FAR_EL1` or hang tail) so the `kernel-validator` agent diagnoses immediately.
- **Gate DRV: driver isolation — an EL0 driver server drives device MMIO via a capability.**
- **✅ GREEN (2026-07-20).** A position-independent driver runs at **EL0** with *only* a capability-granted device-MMIO window (`map_user_device_page`: the NIC's virtio-mmio page, Device memory, UXN+PXN) — it reads the NIC's DeviceID register (=1), reports it via syscall, and exits. **No kernel access**: a compromise is contained to EL0 + that one device. `[DRV] PASS`. *This proves the isolation mechanism; migrating the full virtio-net driver (DMA + virtqueues + IRQ) into a user-space server is the larger staged effort.*

- **Security audit + hardening (2026-07-20, `SECURITY_AUDIT.md`).** Adversarial review of all kernel source, 5 findings, 4 fixed + 1 partially-mitigated/deferred: **(HIGH)** untrusted virtio `id`/`len` now bounded (no OOB read); **(HIGH)** user pages now **UXN+PXN** (no exec-stack, no EL1 execution of user memory) — code RO+exec (W^X), data/device RW+non-exec; **(MED)** kernel faults now `exit(1)` (a crash can't fake success); **(LOW)** BPF verifier off-by-one fixed + **verify-before-run** enforced. **Deferred (named):** full W^X for kernel text + JIT needs kernel-page **block-splitting** (same item that gates per-AS ASIDs).
- **Continuous V&V:** every gate above is re-proven on each run by `./validate.sh` (the kernel-validator) against the `LIFECYCLE.md` V-model; the `kernel-validator` agent heals regressions and implements the next PLANNED phase.

### P4 — Communication
- **Register-only fastpath IPC** (`Call`/`ReplyRecv`, reply cap in receiver TCB) + the **zero-copy shared-memory ring** primitive (`ZEROCOPY_IPC_RING.md`: hugepage Frame caps mapped into two VSpaces, SPSC, release/acquire, cache-line-isolated + cached indices, batch publish, adaptive-NAPI wakeup via Notification).
- **Gate P4:** measure control IPC round-trip cycles (compare to the seL4 fastpath bar); a ring passes data zero-copy between two userspace components; DMA (virtio) confined by mapping.

### P5 — First driver (**the north star**)
- **Userspace virtio-net driver** on QEMU (virtqueue split-ring; the design mirror for the packet ring).
- **Gate P5 (north star):** **one packet: wire → ring → a BPF DROP/PASS verdict, entirely in userspace.** Everything before this is scaffolding; this proves the whole thesis on clean hardware.

### P6 — Detection
- **RFC 9669 BPF VM + verifier + JIT (ARM64 backend)** in the IDS sidecar (`BPF_THREAT_PLANE.md`: v1 signed-first-party rules, verifier deferred; W^X via RW→RX cap remap; constant-blinding + retpolines). Wire the **"OS is the sensor"** taps (P2 hooks) → event schema → **QSecBit**.
- **Gate P6:** the *same* HookProbe BPF rules that run on the Linux/FreeBSD/QNX tracks run here unchanged (parity); QSecBit scores live QEMU traffic + capability-telemetry.

### P7 — CM5 bringup (the driver boss fight)
- Implement `Hal` for the board + the **RP1 stack**: PCIe RC (or lean on `pciex4_reset=0` firmware config first), RP1's custom 64-source interrupt controller, **MACB/GEM Ethernet**, **DWC2/xHCI USB**; early console on the **BCM2712-side debug UART** (not behind RP1). Cross-reference the shared hardware recon in `~/hookprobe-bsd/drivers/DOSSIERS.md`.
- **Gate P7:** the P5 north-star packet path runs on **CM5 metal** via RP1, on the shared HIL rig.
- **✅ GREEN (2026-07-21) — north-star on metal.** A real Ethernet frame on the CM5's RP1 Gigabit MAC (`end0`) flows **wire → GEM RX DMA → Packet Engine ring → BPF verdict** on the microkernel, plus a live **DROP** of an injected UDP→:4444 threat frame alongside `PASS` on real traffic. Getting there required, on metal: PHY reset (RP1 GPIO32), RGMII-id gigabit bring-up, the **BCM2712 PCIe RC inbound DMA window** (firmware sets outbound only → the missing piece behind BNA), and correct DMA/descriptor programming. Console is the RP1 UART via the firmware outbound window. See `RP1_GEM_BRINGUP.md`.
- **✅ RX datapath COMPLETE (2026-07-21) — real hardware frame lengths.** The GEM now writes the RX descriptor status/length word correctly and HEQK reads it (`w1=0xc072` = EOF\|SOF\|114 on a 114 B frame, exact; also 218/64/94). The full recipe, **derived by booting the mainline `macb` driver on the same silicon as an oracle** (see the methodology note below), is: extended-BD `DMACFG=0x70200710` + **6-word (24-byte) descriptors** + a **non-cacheable descriptor ring** (an MMU `Normal-NC` alias, matching `dma_alloc_coherent`) + **`NCFGR` DBW128** (128-bit AXI bus width — the final key). This retired the earlier "PCIe write-ordering / cosmetic quirk" dead-ends. `RP1_GEM_BRINGUP.md` has the four-part recipe + the exact `w1` decodes.
- **✅ P7a GREEN (2026-07-21) — inline IPS ENFORCEMENT on metal.** GEM **TX** brought up; the BPF verdict now *acts on the wire*: a benign UDP→:53 frame is **FORWARDED** (`tx_ctrl` HW-USED set = transmitted), a threat UDP→:4444 is **DROPPED, not forwarded**. Detect-only → real inline IPS. Single port proves the mechanism; true 2-port bump-in-the-wire is P9.

### P7-TOOL — the "Linux-as-oracle" bring-up methodology (reusable asset)
Five rounds of documentation-based guessing on the GEM descriptor bug all failed; **booting Linux on the target and *observing* the working driver** cracked it in one pass. This is now a standing tool for RP1/BCM2712 hardware bring-up:
- The **hookprobe-edge kernel** (RPi downstream + BTF, full RP1 support; `~/hookprobe-os/builder/kernel-build/out/*.deb`) + the on-eMMC `hookprobe-root` rootfs boot on the CM5 with a swapped `config.txt` (kernel restored via `config.txt.heqk`). The exact `macb` driver **source** is at `~/hookprobe-os/builder/kernel-build/linux-*`.
- Method: boot Linux, confirm the peripheral works (e.g. `end0` got a DHCP lease, `rx_length_errors=0` ⇒ the HW *can* do it), then read the driver source for the exact register/descriptor recipe and mirror it in HEQK. Use `iomem=relaxed` + `busybox devmem` for live register dumps (STRICT_DEVMEM blocks it otherwise).
- **Directly de-risks P9** (the RTL8111H 2nd port): Linux already brings it up as `enP1p1s0` on the external PCIe RC1 — boot the oracle, read `r8169` + the brcmstb PCIe-RC init, mirror it.

### P7-SEC — Quantum-safe secure boot + attestation (emergent workstream, not in the original P0–P7 ladder)
Bringing the kernel up on real hardware forced a trust-chain that QEMU never needed. Built and on metal:
- **HBoot** — an EL2-resident boot manager (`heqk-boot`) that firmware loads; it verifies, measures, and launches the EL1 kernel. Four crates: `boot-abi`, `hboot`, `kernel`, `heqk-services`.
- **Hybrid quantum-safe secure boot** — ed25519 **AND** SLH-DSA (FIPS-205) over the payload; geometry-pinned so a malicious image can't redirect the load; **anti-rollback SVN floor**.
- **Measured boot** (TPM-style PCR chain) + **remote attestation** (device AK signs `nonce‖svn‖PCRs`), replayed/verified by the kernel.
- **Round-2 security audit (2026-07-21, `SECURITY_AUDIT.md`):** 4-agent adversarial review of the full tree incl. the new driver/DMA/boot surface. Enforcement spine verified sound; 4 fixes landed (IPv6/QinQ IDS-evasion, IPC TOCTOU, 2 OOB-read gaps); 9 items triaged to the backlog below with explicit fix paths.
- **Honest residual:** attestation is **demo-grade** until the AK is hardware-bound — the AK is currently a software constant compiled into the image (forgeable). The nonce is **no longer fixed** — P7d-a mints it from the BCM2712 hardware TRNG per boot (see §5a P7d) — but a verifier-supplied per-request challenge (full B-2) and the hardware-bound AK (B-1) remain. Do not represent quotes as authenticity proofs until B-1/B-2 are fully closed.

---

## 5a. Next-phase integration roadmap (post-metal north-star)

The north-star proves the datapath on metal; the product (a **fast IDS/IPS** users trust) needs the phases below. They are ordered by dependency, and three of them are gated on two **keystone efforts** that unlock multiple findings at once:

- **Keystone K1 — kernel-page block-splitting.** **✅ ESSENTIALLY COMPLETE (2026-07-21).** All three payoffs delivered: **non-cacheable descriptor ring** (B-4, the #1 fix), **W^X at EL1** (B-5, QEMU + metal), and **per-AS ASIDs** (address-space isolation + ASID-tagged TLB, QEMU). The MMU now does fine per-page attributes, a `Normal-NC` alias, static L2/L3 W^X split, and per-address-space page tables with ASID-tagged `TTBR0` switching. Residual: the JIT identity-alias W^X gap (defense-in-depth, B-9) + the debug GB256 alias — both minor.
- **Keystone K2 — BCM2712 OTP + eMMC RPMB drivers.** Unlocks: **hardware-bound AK** (B-1) → real attestation, **hardware anti-rollback counter** (B-8), and the measured-boot CRTM anchor (B-7). Turns attestation from demo-grade into a genuine authenticity proof.

**Phase ordering (each gated on a runnable/metal test):**
1. ~~**P7a — IPS inline enforcement.**~~ **✅ DONE (2026-07-21)** — GEM TX + verdict-gated forward/drop on the wire, on metal.
2. **P7b — K1 (block-splitting) → W^X.** **✅ W^X DONE (2026-07-21, QEMU + CM5 metal).** The coarse 1 GiB blocks are split: kernel `.text` RO+X, all other RAM RW+PXN, `SCTLR.WXN` on (mmu.rs `build_wx_ram` / mmu_cm5.rs `build_wx_gb0`, static L2/L3). Verified on metal (`.text` AP=0b10 PXN=0, data AP=0b0 PXN=1; datapath + inline IPS unaffected) — closes audit B-5. **Remaining K1: per-AS ASIDs** — folded into P7c (they only matter once there are multiple EL0 address spaces). Residual: the GB256 debug alias is still a writable view of `.text` (WXN blocks exec-via-alias; full close-out with P7e).
3. **P7c — EL0 driver isolation for GEM.** **✅ Step 1 DONE (2026-07-21, QEMU): EL0-as-scheduled-TCB** — EL0 tasks are now preemptible scheduler TCBs (`make_el0_thread`, IRQ-on entry, lower-EL IRQ → reschedule, SP_EL0 in the trap frame). Proof: an uncooperative infinite-loop EL0 task is preempted (300 ticks, box not wedged) — **closes B-6**. **✅ Step 2 DONE (2026-07-21, QEMU): per-AS ASIDs** — `new_addr_space`/`map_user_data_in`/`switch_ttbr0`; same VA → different frames in two ASIDs, no-flush switch isolates them (`[P7c-ASID] PASS`). Completes keystone K1.
**✅ Step 3a DONE (2026-07-21, QEMU): scheduler address-space switching** — per-TCB `TTBR0` (`spawn_as` + `handle_irq` switches address space on context switch); `map_user_device_in`/`map_user_code_in`. Proof: the preemptible EL0 task now runs in its OWN ASID (asid=3), fully isolated + preempted (counter 1.25e9 / 300 ticks). This is the complete **isolated-EL0-driver runtime** (preemptible + own ASID + capability-granted MMIO).
**Step 3b (metal): port the GEM driver onto that runtime** — staged, GEM is CM5-only.
  - **✅ Stage 1 DONE (2026-07-21, CM5 metal): isolated EL0 GEM register probe.** Added EL0 user-page mapping to `mmu_cm5` (GB5 user window: `L1[5]→L2_USER→L3_USER`, installed pre-MMU-enable; `map_user_code/data/device`; static EL0 code/stack frames) + the first EL0 execution + SVC syscalls on CM5. An EL0 driver granted ONLY the GEM MMIO page read `NCFGR=0x00580412` through that capability — **MATCHing the kernel's read** (`[P7c] PASS`), no fault, no hang, datapath intact. Proves the real GEM is reachable from an isolated EL0 driver on metal.
  - **✅ Stage 2 DONE (2026-07-21, CM5 metal): RX hot path at EL0.** The clean split — the kernel keeps the privileged one-time `rx_init` (clocks/PHY/PCIe, no packet data); the RX poll loop (which touches attacker-controlled packets) runs isolated at EL0, granted ONLY a Normal-NC window onto the descriptor ring (EL0 can't do cache ops → NC keeps it coherent). `gem_rx_stub` scans the ring, reads a received frame's status word. Result: **8/9 boots read a real frame** (`w1=0xc0xx`, EOF|SOF, lens 64–639 B of live end0 traffic); the 1 miss is a poll-timing artifact (no frame in that ~1s window), not a bug. No fault; datapath intact. `mmu_cm5::map_user_nc`, `gem::rxring_pa`.
  - **✅ Stage 3 DONE (2026-07-21, CM5 metal): TX at EL0.** Kernel does the privileged prep (`tx_prep_el0`: fill the TX buffer + set the descriptor address, clean to DRAM); the EL0 driver, granted the TX-ring NC window + the GEM register window, arms the descriptor (word1=len|LAST|WRAP), kicks `NCR.TSTART`, and polls word1 for USED. Result: **7/7 boots** `word1=0xc0008040` (USED|WRAP|LAST|len 64) = **hardware completed the transmit**. No fault. `gem::txring_pa/tx_prep_el0`, `gem_tx_stub`.
  - **✅ Stage 4a DONE (2026-07-21, CM5 metal): the IDS loop closed with the driver at EL0.** The EL0 RX driver locates a received frame and reports (descriptor index<<16 | length) via syscall; the kernel packet-engine reads that buffer (`gem::peek_rx_frame`) and runs the signed BPF verdict. Metal: driver delivered a real IPv4 frame (desc 3, 218 B, et=0800, dst_port 5353) → kernel verdict PASS. The packet-touching driver is isolated at EL0; the detection engine stays in the trusted kernel. `gem_ids_stub`, `cm5_gem_el0_ids`.
  - **✅ Stage 4b DONE (2026-07-21, QEMU): fault-contain-and-restart of a scheduled EL0 driver.** `handle_lower_sync` returns the sp to eret from; `lower_sync_entry` switches to it + saves/restores SP_EL0. A scheduled EL0 TCB that faults is rebuilt from stored restart params and rescheduled (with the AS switch); after a budget it is killed. Proof: a crash-on-entry stub is contained + restarted #1/#2/#3 then killed, kernel workers running throughout (`[P7c] EL0 fault-restart PASS`).
  - **✅ Stage 4d DONE (2026-07-21, CM5 metal): continuous, restartable isolated EL0 GEM driver server.** `cm5_gem_el0_server` runs a continuous RX→IDS loop (EL0 driver locates a frame → kernel classifies via signed BPF → `gem::recycle_rx` re-arms for a fresh frame); one iteration loads a crashing driver, which the kernel contains + RESTARTS. Metal: processed 3 real ARP frames (IDS PASS) + survived 1 crash-restart, no fault. A self-contained, self-healing, packet-isolated driver server on real hardware.
  - **Remaining — true Stage 4c on CM5:** run the driver as a *preemptible scheduled EL0 TCB in its own ASID* on CM5 (not the cooperative loop) — proven on QEMU (steps 1–4b), needs porting the scheduler `TTBR0` switch + `make_el0_thread` + `new_addr_space` + a frame allocator to the CM5 `mmu_cm5` path (a large runtime port). The 4d CM5 capstone above uses the cooperative `enter_user` loop instead (lower metal risk).

**Net P7c status: the isolated-EL0-driver goal is demonstrated end-to-end.** All GEM data-plane ops run isolated at EL0 on metal (register/RX/TX/RX→IDS), each granted only its windows; the full preemptible + own-ASID + fault-restart runtime is proven on QEMU; and a continuous, restartable, packet-isolated driver server runs on CM5 metal. The one remaining piece (preemptible-scheduled-in-own-ASID *on CM5*) is a runtime port, not new mechanism.
4. **P7d — K2 (OTP/RPMB) → real attestation & anti-rollback.** Close B-1/B-2/B-7/B-8. Gate: a quote signed by a per-device OTP-derived AK with a verifier-supplied fresh nonce; a rollback to an older signed bundle is refused by hardware state.
   - **Hardware-reachability research (2026-07-21, cited):** BCM2712 **rng200 TRNG** @ CPU `0x10_7D20_8000` is pure MMIO (no VideoCore) → per-boot nonce is the cheap first win. The device-unique **OTP secret** (block-3 private-key, 512b) and the **customer-OTP anti-rollback counter** are reachable **only via the VideoCore mailbox** @ `0x10_7C01_3880` ch8 (`GET_USER_OTP 0x00030024` / `SET_USER_OTP 0x00038024`); there is **no documented bare-metal MMIO OTP path**, and the RP1 OTP register interface is undocumented. A truly non-extractable per-device AK needs a **one-time deliberate OTP provision** (irreversible fuse blow — never auto-performed).
   - **✅ P7d-a DONE + VALIDATED ON METAL (2026-07-21): hardware-TRNG per-boot nonce (`hboot/src/rng.rs`).** HBoot drives the BCM2712 rng200 (bounded spins + CNTPCT fold → never deadlocks/zeroes the boot) to mint a **fresh 32-byte nonce each boot**. Three power-cycles produced three distinct 8/8-word-hardware-random nonces (`e0b7aec3`/`fb87c1e9`/`1513977a`). Kills the static/identical nonce (B-2 half a).
   - **✅ P7d-b2 DONE (2026-07-21): B-2 FULLY CLOSED — runtime attestation service (`kernel/src/attest_svc.rs`).** Two-tier design: HBoot mints a per-boot **ephemeral ed25519 key** (TRNG-seeded), hybrid-AK-certifies it (`eph_pk‖svn‖device_id‖PCRs` — quantum-safe), publishes it at `ATTEST_EPH_ADDR`, then **scrubs the device AK** (`attest_keys::scrub` — the AK never persists in RAM). The kernel holds only the ephemeral key and signs **verifier-supplied challenge nonces** on demand (no SLH-DSA in the kernel). QEMU `[P7d-B2] PASS`: distinct nonces → distinct valid sigs, cross-replay rejected. On CM5 the kernel also verifies the AK cert chain on-device (ed25519 half). BootInfo v5 + `AttestEphemeral`.
   - **✅ P7d-b DONE + VALIDATED ON METAL (2026-07-21): VideoCore mailbox client (`hboot/src/mailbox.rs`).** Bare-metal BCM2712 property mailbox (`0x10_7C01_3880` ch8, VC-alias pointer + identity fallback, cvac/ivac coherency, all polls bounded → fail-safe). Read a **real board serial 0x010256173c495a31** from EL2 → `device_id` bound into the ephemeral cert (a cert can't be replayed device-to-device).
   - **✅ P7d-b1 DONE + VALIDATED ON METAL (2026-07-21): B-1 FULLY CLOSED — hardware-bound per-device AK (`hboot/src/ak_derive.rs`).** HBoot generates a 256-bit secret from the on-device TRNG, burns it into **customer OTP block 1** once (`SET_USER_OTP`), and derives the per-device AK (ed25519 + deterministic SLH-DSA-128f keygen) from the read-back contents; publishes the per-device AK pubkeys, which the kernel verifies the cert against. Metal: boot 1 `OTP burn OK`, boot 2 idempotent `already provisioned` → **same** `ak_ed_pk=0x03699d2a`; kernel `AK=HARDWARE-BOUND … VERIFIED`. The AK now lives only in fuses — not in the image, per-device. **Honest limit:** OTP is readable by on-device supervisor code (not HSM-grade); AK is now permanent (no rotation).
   - **P7d-c (deferred, careful): OTP-fuse anti-rollback counter** via `SET_USER_OTP` block-1 (256b) — mechanism documented, gated behind explicit non-automatic policy (blows are permanent). RPMB only if 256b is outgrown.
5. **P7e — EL1↔EL2 isolation** (B-3): **✅ DONE + VALIDATED ON CM5 METAL (2026-07-21).** HBoot enables **stage-2** before `eret` (`hboot/src/stage2.rs`) with its own footprint `0x200000..0x800000` carved out (invalid IPA); an EL1 access there faults to EL2 (`el1_blocked` → recover). Metal: kernel boots normally under stage-2, and an EL1 probe of `0x200000` is trapped to EL2 (`X`) — **closes B-3**. `VTCR_EL2=0x8002_3559`, single 4KB L1 table, `HCR_EL2.VM` in `hboot_launch_el1`.
6. **P8 — detection plane at scale.** **✅ STARTED (2026-07-22): PREVAIL-style verifier for third-party rules** (`kernel/src/bpf.rs::verify_prevail`) — abstract-interprets a rule (regs tracked as Uninit/Scalar/Pkt{offset-interval}) and STATICALLY proves memory safety (every load packet-relative, no uninit reads, forward-DAG termination, real verdict) before running; returns the min packet length for which it's in-bounds. QEMU `[P8] PASS`: signed rule accepted (min_len=4), adversarial third-party rules (wild load / backward loop / uninit verdict) statically rejected. **Next (QEMU-testable):** ISA expansion (ADD/pointer-arith in verifier), QSecBit scoring, JIT (`bpf_jit`). Gate: HookProbe rules run unchanged on live gigabit traffic.
7. **P9 — 2nd interface (RTL8111H / `eth1`).** **✅ INVESTIGATED + CODE PREPARED (2026-07-22, `P9_P10_BRINGUP.md`).** RC1 (`pcie1 @ 0x10_0011_0000`) is register-identical to RC2 (the GEM's controller); DMA offset (`+0x10_0000_0000`), GB257 NC alias, polled-OWN all reuse. **Track A** (`dtparam=pciex1` → firmware trains the link) makes it *easier than the GEM* (no PHY-GPIO/MDIO/extended-BD). Prepared: `arch-aarch64/src/rtl8111.rs` (RC1 status/link, inbound window, config-space, enumerate/MAC, RX/TX — compiles, `cfg(cm5)`, ready to wire). Staged plan (proof-point/flash): status → vendor-ID `0x816810EC` → BAR/MAC → RX → TX (~2–3 flashes via Track A).
8. **P10 — WiFi CYW43455 regdomain.** **✅ INVESTIGATED (2026-07-22, `P9_P10_BRINGUP.md`).** SDIO controller = **BCM2712 SDHCI @ `0x10_0110_0000`** (GIC SPI 274), NOT the RP1. Staged: A (SDIO+chip-ID `0x4345`) → B (firmware/NVRAM/CLM upload + ARMCR4 start — hardest) → **C (regdomain: `clmload` + `country` iovar `{ccode="GB",rev}` → real ISO not 00/99 — the backlog target, control-channel only)**. Control layer (BCDC/iovar/clmload/country/NVRAM parser) codeable off-metal now; ~3–5× the RTL effort. Oracle: Pico-W `cyw43-driver`.

**Immediate next step (recommended): P7b — the K1 block-split for W^X + ASIDs.** It's the last big internal-hardening keystone, its NC-mapping half is already proven, and W^X closes the highest-severity remaining *internal* finding. (P7d/K2 is the highest-value *security* step but is gated on new OTP/RPMB drivers; P8 is the highest-value *product* step but benefits from P7b's ASIDs first.)

**North-star framing (user direction):** HEQK is meant to **replace the Linux in `~/hookprobe-os`** as the product's OS substrate — today hookprobe ships the IDS/IPS as Linux/eBPF userspace; the endgame is HEQK running this datapath natively. That reframes P7b→P9 as productization, and makes P8 (rule parity with the Linux/FreeBSD tracks) the convergence gate.

Full finding-by-finding backlog with fix paths: `SECURITY_AUDIT.md` (Round 2). Keystones K1 and K2 are the critical path — everything user-visible about speed and trust flows through them.

---

## 6. Honest risk ledger & timeline
| Risk | Severity | Mitigation |
|---|---|---|
| **RP1 is the boss fight** (PCIe-endpoint peripherals, custom IRQ ctrl, bleeding-edge even in Linux) | **Highest, P7** | Kernel 100% gated on QEMU first; `pciex4_reset=0` + BCM2712 debug UART; RP1 = HAL+driver project vs a finished kernel |
| **IPC fastpath under-designed** | High | Design it first (P4 not last); measure cycles vs seL4 bar |
| Custom (unverified) TCB vs seL4's proof | High (accepted) | Rust removes the memory-safety bug class; mandatory TCB security audit (budget line); the "OS is the sensor" feature is why custom is chosen (`ARCHITECTURE.md` §6) |
| BPF verifier soundness (a bug = escape) | High | v1 signed-first-party, no verifier; PREVAIL-style v2 only for third-party, audited |
| Scope explosion (it's an OS) | High | Ruthless P0→P7 gating; the P5 north-star is the only thing that matters until green |
| `VERIFY` items (semihosting exit block, timer PPI, QEMU load addr, GIC version) | Low-Med | Confirm each against the generated DTB / QEMU `-d int` on first boot |

**Timeline (plan the budget on this):** **P0–P5 on QEMU is a focused solo effort measured in months.** **P7 (RP1) + a hardened detection plane is where the multi-year, driver-side weight sits.** Keep the Linux/NanoBSD + FreeBSD tracks shipping in parallel so this endgame is funded while it matures.

---

## 7. Immediate next actions (the first week)
1. **Scaffold the workspace** (§2): `kernel` / `hal` / `arch-aarch64` / `abi`; `rust-toolchain.toml` + `.cargo/config.toml` with `build-std`; a linker script placing the image at `0x4008_0000`.
2. **P0 boot stub → PL011 "hello from EL1"** on QEMU; confirm the EL2→EL1 drop and that `-serial mon:stdio` shows output. First green.
3. **Wire the semihosting-exit test runner** so `cargo test` is a one-command QEMU gate from day one (this discipline is what keeps P0→P7 honest).
4. **Clone the `rust-raspberrypi-OS-tutorials`** locally as the aarch64 boot/MMU/exception reference (study, don't fork); keep the seL4 manual open for the P2 object model.
5. **Stub the `Hal` trait** with every method P0–P4 will need, so the arch boundary is enforced before it's tempting to shortcut it.

---

*This is the deep-fixed plan: the committed custom-Rust-kernel path, made concrete with the real toolchain, the reference kernels' actual structure, the seL4/L4 design lessons baked in, and a QEMU-first ladder where each rung is a runnable test. `ARCHITECTURE.md` is the what; this is the how; the P5 north-star packet is the proof.*
