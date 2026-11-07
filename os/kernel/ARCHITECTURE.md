# HookProbe Microkernel — The Architecture (custom, Rust, edge-first)

**The clear, committed architecture for a custom-built HookProbe microkernel — sized for HookProbe's actual hardware (CM5 / N100), not a datacenter template. Decision made; this is the spine every other doc now serves.**

Status: **authoritative** · Supersedes the datacenter assumptions in the early draft of `ZEROCOPY_IPC_RING.md` (spin-poll-forever, 1 GiB hugepages, 100 GbE budget) — those are corrected here for edge. Companions: `CAPABILITY_MODEL.md`, `ZEROCOPY_IPC_RING.md`, `BPF_THREAT_PLANE.md`; grounding in `RESEARCH_LANDSCAPE.md`.

---

## 0. The committed decisions (no relitigating)

| Decision | Call | Why |
|---|---|---|
| **Kernel language** | **Rust** (`no_std`), minimal inline asm for arch stubs only | Memory safety in the TCB eliminates the exact bug class (overflow, UAF) verification exists to rule out — without a proof team. Study **Redox**'s microkernel; don't fork it. |
| **First target** | **QEMU aarch64 `virt`**, then CM5, then N100 | Clean PL011/GIC/generic-timer/virtio → build the whole core against documented hardware with a sub-second dev loop; CM5 becomes a *driver/HAL* effort, not a core rewrite. |
| **Portability** | **HAL trait boundary from line one** | x86_64/N100 is a *port*, not a rewrite. The N100 (standard PCIe, Intel i226, UEFI+Limine) is *easier* silicon than CM5 for real-hardware validation. |
| **Boot** | aarch64: custom **early-init stub** (firmware hands you AArch64 state); x86_64: **Limine** (BSD-2-Clause) | You don't write a traditional aarch64 bootloader; the legitimately-custom part is EL2→EL1 + MMU + vectors + jump to Rust. Hand-rolling UEFI on x86 buys nothing defensible. |
| **Data plane** | **Adaptive NAPI-style** (interrupt → bounded poll budget → sleep), pin+spin only under sustained load | Permanent per-core spin-polling starves AI detection on a 4-core CM5 with a 1–2.5 GbE link. Right-sized for edge. |
| **Hugepages** | **2 MiB** (not 1 GiB) | TLB win is already captured at 2 MiB; you don't have RAM to burn on 1 GiB. |
| **The differentiator** | **"The OS is the sensor"** — capability/IPC/scheduling telemetry piped to QSecBit | A generic capability microkernel is an L4 clone. The kernel already mediates *every* resource access with perfect fidelity; exposing that as a tamper-evident stream from a tiny owned TCB is a hardware-level detection story no Linux competitor can replicate. **This feature is the reason to build custom.** |

---

## 1. Target hardware ladder (and the HAL that spans it)

```
   QEMU aarch64 virt   ──▶   Raspberry Pi CM5      ──▶   Intel N100 (x86_64)
   (build the core)         (strategic endgame,          (easier silicon,
                             brutal first bringup)         earliest real-HW proof)
   PL011 UART, GIC,         BCM2712 + RP1 southbridge,    UEFI+Limine, standard
   generic timer,           debug UART on-SoC,            PCIe, Intel i226 NIC,
   virtio-net/blk           MACB/GEM eth, DWC2/xHCI usb   HPET/APIC, x86 hugepages
        │                          │                            │
        └──────────────── one `Hal` trait boundary ─────────────┘
```

The `Hal` trait (Rust) abstracts exactly the arch/board-specific surface — nothing more:
```rust
trait Hal {
    // CPU / privilege
    fn early_init();                       // EL2→EL1 (aarch64) / long-mode entry (x86)
    fn install_exception_vectors();
    fn context_switch(prev: *mut Tcb, next: *mut Tcb);
    fn syscall_entry();                    // SVC (aarch64) / SYSCALL (x86)
    // MMU
    fn map_page(vspace: &mut VSpace, va: VAddr, pa: PAddr, attrs: PageAttrs);
    fn hugepage_2mib(vspace: &mut VSpace, va: VAddr, pa: PAddr, attrs: PageAttrs);
    // Interrupt controller (GIC / APIC) + timer (generic timer / HPET)
    fn irq_ack() -> IrqId;  fn irq_mask(id: IrqId);  fn irq_eoi(id: IrqId);
    fn timer_arm(deadline: Ticks);
    // Early console
    fn debug_putc(c: u8);                  // PL011 on virt/CM5-debug-UART; 16550/Limine on x86
}
```
Everything above the HAL — capabilities, scheduler, IPC, the ring primitive, the syscall ABI — is arch-neutral Rust. Porting = implementing `Hal` + writing the board's device drivers (which live in *user space* anyway).

---

## 2. The CM5 / RP1 reality (plan around it, don't fight it)

This is the single hardest thing about the endgame target and it must shape the plan (it is the same keystone the FreeBSD track flagged — cross-reference `~/hookprobe-bsd/drivers/DOSSIERS.md`, which already recon'd this exact board).

- **BCM2712 reaches Ethernet, USB, GPIO, and most UARTs only through the RP1 southbridge**, wired as a **PCIe endpoint** (≈5.0 Gbps ×4 link). RP1 exposes ~61 peripherals behind a **custom interrupt controller with 64 sources.**
- **Consequence:** there is no "write to a fixed MMIO address for hello-world" on CM5 — even the RP1 UART sits behind the PCIe mapping, and hitting it wrong is a **data abort** on the ARM core.
- **Two things make first bringup survivable:**
  1. **Early serial on the BCM2712-side debug UART** (the dedicated debug UART is *not* behind RP1) — that's your P0 console on CM5.
  2. **`pciex4_reset=0` in `config.txt`** so the firmware leaves PCIe configured — you can reach RP1 without first writing a bare-metal PCIe root-complex driver. That defers the RC driver to P7.
- **Device identities (match the FreeBSD dossiers):** RP1 Ethernet = **Cadence MACB/GEM**; USB = **DWC2 / xHCI**. `VERIFY` per board stepping — this is bleeding-edge even for Linux (mainline RP1 Ethernet/USB landed only very recently; BCM2712D0 / rev-1.1 boards still have device-tree gaps). **This is the eventual driver boss fight (P7) — and precisely why the kernel is built on QEMU first.**

**Design rule that falls out:** the kernel core must be **100% done and gated green on QEMU** before RP1 is touched. RP1 is a HAL+driver effort against a finished, tested kernel — never a core-and-hardware bringup at the same time.

---

## 3. Boot model (per arch, owned where it's defensible)

- **aarch64 (QEMU virt / CM5):** firmware (QEMU or the Pi GPU firmware) loads the kernel image and hands the CPU in AArch64 state. The **HookProbe early-init stub** (the legitimately-custom boot code) then: **EL2→EL1 drop → set up stack → install exception vectors → build initial page tables + enable MMU → jump to Rust `kmain`.** That is custom and necessary.
- **x86_64 (N100):** use **Limine** (BSD-2-Clause — matches the licensing stance) for long mode + higher-half + SMP startup. Hand-rolling UEFI here is wasted effort with nothing defensible to show for it.
- **Image integrity** (both): signed + measured image, A/B slices with rollback — the same RO-image discipline as the FreeBSD/QNX tracks; W^X enforced by the capability model (`BPF_THREAT_PLANE.md` §3).

---

## 4. The core (Zone 1) — arch-neutral Rust, tiny TCB

- **Capabilities** — `CAPABILITY_MODEL.md` verbatim: untyped→retype, CNode/CSpace O(1) invocation, badges, Grant, **capability derivation tree** for recursive, GC-free teardown. This is the whole authority model; no ACLs.
- **Scheduler** — preemptive, priority-based, real-time, on the **ARM generic timer + GIC** (HAL-abstracted to HPET/APIC on x86). **Thread pinning** available but used sparingly (pin the detection thread only under sustained load — §5). CPU-budget accounting so the detection plane is guaranteed time under flood.
- **IPC** — synchronous **register-only fast-path** for control messages (direct sender→receiver switch, no run-queue). **Data never uses IPC** — it uses the ring (§5). This is the classic microkernel make-or-break; keep the fast-path hand-tuned and measured.
- **VMM primitive** — minimal map physical→virtual + expose the virtualization extension (Arm EL2 / x86 VT-x) as capabilities so a *user-space* VMM can host a monitored Linux guest later (Zone 4). Not a P0–P6 concern.
- **2 MiB hugepage support** is first-class from the MMU layer up (the ring pools need it).

---

## 5. The data plane — right-sized for edge (this corrects the earlier doc)

The mechanism from `ZEROCOPY_IPC_RING.md` is correct; the **policy** is now edge-tuned:

- **Adaptive NAPI, not permanent spin.** Default: the NIC interrupt (delivered as a Notification to the user-space driver) wakes the driver; it **polls a bounded budget** of packets from the ring, processes the batch, and **sleeps when the ring drains.** Only under *sustained* load does the detection thread get **pinned and allowed to spin** — that's the mode transition, not the default. On a 4-core CM5 with a 1–2.5 GbE link, permanent spinning would starve the AI detection; NAPI keeps cores available for QSecBit.
- **Keep everything else from the ring design:** capability-shared zero-copy SPSC ring, descriptor/payload split, cache-line-isolated + thread-locally-cached indices, release/acquire ordering (real `STLR`/`LDAR` on aarch64), batch publishing, **IOMMU/SMMU-gated DMA** confining the NIC to the payload pool.
- **2 MiB hugepages** for the rings + payload pool (not 1 GiB — the TLB win is captured at 2 MiB and RAM is scarce).
- **Throughput target is edge-honest:** the design point is **1–2.5 GbE line rate with headroom for detection**, not 100 GbE. The 100 GbE / ~20-cycle-per-packet math in the research is the *ceiling the pattern can reach on big silicon*, not this product's target — don't over-engineer the CM5 datapath toward it.

## 6. The threat plane (Zone 3) & "the OS is the sensor" (the differentiator)

- **Detection:** the RFC 9669 BPF VM + JIT (ARM64 backend) + verifier live in the **user-space IDS sidecar**, fed from the ring (`BPF_THREAT_PLANE.md`). v1 = signed first-party rules, verifier deferred to v2. Verdicts (DROP/PASS/ALERT) flow back through the ring descriptor.
- **The feature that justifies a custom kernel — "the OS is the sensor":** the capability kernel already mediates **every** resource access in the system with perfect fidelity. Expose that as a **first-class, tamper-evident telemetry stream** — capability invocations, IPC patterns, scheduling anomalies, retype/revoke events — normalized into the **event schema** and piped to **QSecBit**. This is host/behavioral detection rooted in a **tiny TCB you fully own**, at a fidelity a Linux-based competitor (watching from eBPF/auditd *inside* the thing being attacked) structurally cannot match.
  - **This is also the honest answer to "why not just run on seL4":** the sensor feature wants **native instrumentation of the capability/IPC layer itself**, which you cannot add to verified seL4 without either working purely at the observation edges or forking (and voiding the proof). Owning the kernel is what makes the kernel a sensor. That is the defensible reason the custom-kernel decision is right — and it's why this differentiator, not raw throughput, is the north star.

## 7. Userspace tiers (Zones 2 & 4)

- **Zone 2 (drivers):** PCI enumeration server mints IRQ + BAR caps and Grants them to driver sidecars; NIC/USB/storage drivers are user-space, capability-bounded, individually restartable. USB in the most-sandboxed sidecar (huge attack surface).
- **Zone 4 (apps):** a **user-space VMM hosts a monitored Linux guest** (Home Assistant etc.) whose virtual NIC routes through Zone 3 — the app tier is inside the inspection plane and cannot starve it (CPU budget). Containers run *inside* that guest. This is post-P6 work; it is the "grow with every user" surface, not the bringup.

---

## 8. The roadmap (QEMU-first, each phase gated on the last)

| Phase | Deliverable | Gate (green = evidence recorded) |
|---|---|---|
| **P0 — Skeleton (QEMU virt)** | boot stub → PL011 UART → EL1 exception vectors → physical page allocator → virtual memory/page tables → kernel heap | prints from Rust `kmain`; faults are caught & reported, not silent-reset |
| **P1 — Execution** | TCBs, context switch, preemptive priority scheduler on generic timer + GIC, thread pinning | two threads round-robin + pin; timer preemption works |
| **P2 — Capabilities** | CNodes, untyped→retype, CSpaces, capability derivation tree (recursive revoke, no GC pause) | teardown of a subtree revokes all derived caps synchronously |
| **P3 — Userspace** | SVC syscall boundary, drop to EL0, spawn root task with all initial caps | root task runs at EL0, invokes a cap, faults are contained |
| **P4 — Communication** | synchronous fast-path IPC + the zero-copy shared-memory ring primitive | control IPC round-trip measured; ring passes data zero-copy between two components |
| **P5 — First driver** | user-space **virtio-net** driver on QEMU | **North star: one packet wire → ring → BPF DROP/PASS verdict, entirely in userspace.** Everything before this is scaffolding. |
| **P6 — Detection** | BPF-ISA VM + verifier + JIT (ARM64 backend) in the IDS sidecar, fed from the ring + the "OS is the sensor" telemetry tap → QSecBit | shared HookProbe BPF rules run unchanged; QSecBit scores live QEMU traffic |
| **P7 — CM5 bringup** | the RP1 stack: PCIe RC, RP1 interrupt controller, MACB/GEM Ethernet, DWC2/xHCI USB | the P5 north-star packet path runs on CM5 metal via RP1 |

**Realistic framing (plan the budget on this):** **P0–P5 on QEMU is a focused solo effort measured in months.** **P7 (RP1) plus a hardened detection plane is where the multi-year weight sits — driver-side.** Keep the Linux/NanoBSD product shipping in parallel (as the FreeBSD/QNX tracks already plan) so this endgame is funded while it matures.

---

## 9. Honest risk ledger (delta from the generic plan)

| Risk | Severity | Mitigation |
|---|---|---|
| **RP1 is the bringup boss fight** (PCIe-endpoint peripherals, custom 64-source IRQ ctrl, bleeding-edge even in Linux) | **Highest, P7** | Kernel 100% gated on QEMU first; `pciex4_reset=0` + BCM2712 debug UART for early CM5; treat RP1 as a HAL+driver project against a finished kernel |
| Custom (unverified) kernel vs seL4's proof | High (accepted) | Accepted deliberately: the "OS is the sensor" feature requires owning/instrumenting the kernel; Rust removes the memory-safety bug class; mandatory security audit of the TCB (budget line item) |
| IDS/IPS on a custom microkernel has no prior art | High | QEMU→metal gates; the shared moat (RFC 9669 rules, QSecBit) is already proven on 3 substrates |
| Scope explosion (it's an OS) | High | Ruthless P0–P7 gating; the P5 north-star packet path is the only thing that matters until it's green |
| Edge data-plane mis-sizing | Med (fixed here) | Adaptive NAPI + 2 MiB hugepages + 1–2.5 GbE target replace the datacenter spin/1 GiB/100 GbE assumptions |
| Solo-effort timeline for P7 + hardening | Med-High | Multi-year, driver-side; ship Linux/BSD in parallel; add a kernel engineer for RP1 |

---

## Concurrency invariant (SINGLE-CORE, NON-REENTRANT) — a global safety contract

HEQK currently runs on **one core**, and several safety arguments depend on it. This
is a **load-bearing invariant**, stated here so it is explicit and cannot be lifted
by accident (remediation X2 / gap XC-1):

> **The kernel executes on a single core, and its state-mutating paths are
> non-reentrant.** Every `static mut` global, and every SPSC ring, assumes exactly
> one writer at a time.

What relies on it (audit ALL of these before enabling SMP or reentrancy):

- **The telemetry ring** (`events.rs`): `push_hit` is a *single-producer* SPSC ring —
  a plain `HEAD.load` then `store`, not a `fetch_add` reservation. Correct with one
  producer (the verdict engine in the TCB); a second producer would race the index.
  `drain` is the single consumer (the EL0 exporter).
- **The packet ring** (`packet.rs`): same SPSC discipline (producer HEAD, consumer TAIL).
- **The rate limiter** (`ratelimit.rs`): the window reset is a `load` of `WIN_START`
  then separate `store`s of `WIN_START`/`COUNT`/`KEY` — a benign read-modify-write on
  one core, an MPSC race on many.
- **The scheduler** (`scheduler.rs`): `static mut` SP/PRIO/ALIVE/BLOCKED/TTBR0 tables,
  accessed only from IRQ context — "single core, non-reentrant, so no locking".
- **Driver diagnostic globals** (`cyw43.rs`, `gem.rs`, `bt.rs`, …): the many
  `static mut` diag latches are sound only because bring-up is single-threaded.

**To lift this invariant** (SMP or reentrant IRQ paths) you must, in one pass:
convert every SPSC producer index to a proper reservation (`fetch_add` + a separate
commit index) or add per-ring locks; make the rate-limiter reset a single CAS; and
put the scheduler tables behind a lock or per-CPU state. Until then, **do not add a
second writer to any of the above** — including a reentrant call to `push_hit` from
an IRQ handler. New SPSC rings must reuse the frozen discipline in
`ZEROCOPY_IPC_RING.md` and cite this invariant.

---

*This is the clear architecture. `ZEROCOPY_IPC_RING.md` (mechanism), `CAPABILITY_MODEL.md` (authority), and `BPF_THREAT_PLANE.md` (detection) are its subsystems; `buildPlan.md` now defers its phase plan to §8 here. The differentiator is "the OS is the sensor," not throughput — that is what makes a custom HookProbe microkernel worth building.*
