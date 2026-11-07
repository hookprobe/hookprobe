# HookProbe-OS Microkernel — Architecture Blueprint

**A capability-secured microkernel whose only job is to verify permissions and route messages, wrapped around a zero-copy datapath purpose-built for line-rate IDS/IPS, able to host SOC services plus custom VMs and containers.**

Status: design spine · Ties together `CAPABILITY_MODEL.md`, `ZEROCOPY_IPC_RING.md`, `BPF_THREAT_PLANE.md`; grounded in `RESEARCH_LANDSCAPE.md`; sequenced in `buildPlan.md`. The kernel does almost nothing; the OS is the user-space components around it.

---

## 0. The thesis

Never route data-plane traffic through a general-purpose kernel — interrupt and context-switch overhead suffocate the CPU at the ~20-cycle/packet budget of 100 GbE. Instead: **a microkernel that is only an arbiter of memory geography and authority, a fully user-space zero-copy datapath, and detection logic as isolated capability-bounded components.** This is the Arrakis "OS is the control plane" model (OSDI'14) fused with the seL4 capability model and a DPDK/AF_XDP-class datapath — a combination no shipping system currently offers for IDS/IPS (`RESEARCH_LANDSCAPE.md` §4, the open gap).

The design is organized as **strict functional zones** communicating only through capabilities and shared-memory rings. A fault or compromise in any zone is spatially contained.

---

## 1. Zone map

```
 ┌───────────────────────────────────────────────────────────────────────────────┐
 │  ZONE 4 — APP / TENANT TIER   (SOC services · custom VMs · containers)          │
 │   Linux guest VM (Home Assistant) via libvmm │ native capability components      │
 │   each = a protection domain holding only the caps it was granted                │
 ├───────────────────────────────────────────────────────────────────────────────┤
 │  ZONE 3 — DATA & THREAT PLANE   (the moat, all user-space)                        │
 │   NIC PMD sidecar ──zero-copy ring──▶ IDS/IPS engine (RFC 9669 BPF VM+JIT+verify) │
 │   ──▶ event schema ──▶ QSecBit scoring / AEGIS   │  VFS server │ storage sidecar   │
 ├───────────────────────────────────────────────────────────────────────────────┤
 │  ZONE 2 — HARDWARE FRONTIER   (user-space drivers, capability-gated)              │
 │   PCI enumeration server │ interrupt→notification shims │ PMD NIC │ NVMe │ USB(sandboxed) │
 ├───────────────────────────────────────────────────────────────────────────────┤
 │  ZONE 1 — CORE (the ONLY privileged code — target ~10k LOC)                       │
 │   capabilities · scheduler (priority + budgets) · IPC (fastpath) · minimal VMM    │
 │   >>> recommended realization: seL4 (verified). Track-B alt: HookProbe Kernel     │
 ├───────────────────────────────────────────────────────────────────────────────┤
 │  BOOT — HookProbe-owned boot chain (UEFI/Multiboot2 loader → long mode → root task)│
 └───────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Zone 1 — the core (do almost nothing, and do it provably)

- **Capabilities** — the sole authority mechanism (`CAPABILITY_MODEL.md`). Untyped→retype, CNode/CSpace O(1) invocation, badges, Grant, CDT revocation. No ACLs.
- **Scheduler** — preemptive, priority-based, real-time, with **thread pinning** (lock the IDS engine and each PMD to a dedicated core for L1/L2 cache locality) and **CPU budgets** (seL4 MCS scheduling-contexts = (budget, period), donatable over IPC) so the detection plane is guaranteed CPU under flood — the starvation-resistance property the QNX track prized, here formally schedulable.
- **IPC** — synchronous register-only **fastpath** for control messages (seL4 ≈600 cycles); direct sender→receiver context switch bypassing the run-queue. **Data never uses IPC** — it uses the shared ring; IPC only sets up the ring and delivers idle-wakeups.
- **VMM primitive** — minimal: map physical→virtual, and (for Zone 4) expose the CPU's virtualization extension (Arm EL2 / x86 VT-x) as capabilities so a user-space VMM can run guests. **Hugepage support (2 MiB/1 GiB) is first-class** — the datapath's ring + payload pools are hugepage-backed to kill TLB misses (`ZEROCOPY_IPC_RING.md` §8).
- **Realization:** **seL4** provides all of the above, verified, today (recommended). The from-scratch **HookProbe Kernel** (Track B, `buildPlan.md`) would reimplement exactly this surface.

## 3. Zone 2 — the hardware frontier (drivers in user space, authority by token)

- **PCI enumeration server** — scans the bus at boot; for each device, retypes untyped into the device's **IRQHandler** cap + **BAR Frame** caps and **Grants** them to that device's driver sidecar (`CAPABILITY_MODEL.md` §4). Nothing else can touch that hardware.
- **Interrupt handling** — the kernel's only IRQ job: acknowledge, mask, and **send an async Notification** to the owning driver. All device logic is in user space.
- **NIC drivers = Poll Mode Drivers** — interrupts off, busy-poll the NIC rings from user space, DMA straight into hugepage payload frames. This is the DPDK/AF_XDP model (`RESEARCH_LANDSCAPE.md` §2). A driver crash takes down only its (restartable) sidecar.
- **DMA is IOMMU/SMMU-gated** — the NIC can DMA *only* into the granted payload pool; a malicious NIC/firmware cannot DMA over kernel or other-tenant memory. The classic DMA attack is structurally impossible (this is why the datapath belongs on a capability kernel, not a monolith).
- **USB in the lowest-privilege, most-sandboxed sidecar** — USB is a huge attack surface; isolate it so a malicious device cannot reach the threat engine.

## 4. Zone 3 — the data & threat plane (the moat)

The heart. Flow (all user-space, zero kernel data crossings):
1. **NIC PMD sidecar** (Zone 2) DMAs packets into hugepage frames, publishes descriptors on the **zero-copy capability ring** (`ZEROCOPY_IPC_RING.md`).
2. **IDS/IPS engine** pulls descriptors, runs **RFC 9669 BPF rules** (verified/signed → JIT → W^X-locked native code) against the packet in place (`BPF_THREAT_PLANE.md`). Verdict written to the descriptor; DROP/PASS/REDIRECT/ALERT.
3. Alerts + flow features normalize into the **event schema** (ADR-008 contract) consumed by **QSecBit** scoring and **AEGIS** intent — the same userspace moat as the FreeBSD/QNX tracks, ported by the same contracts.
4. **VFS server** and **storage (NVMe) sidecar** run as user-space servers reached by async IPC, so writing threat logs never blocks the inspection loop. (VFS can be content-blind — it manages files without read authority over their bytes — a least-authority refinement.)
- **Multi-core scale-out:** one SPSC ring set per NIC hardware queue ↔ pinned IDS core, flows steered by RSS. No shared ring, no lock, linear scaling (`ZEROCOPY_IPC_RING.md` §8).
- **Optional FlexNIC-style pre-filter:** push coarse match+action steering into a SmartNIC/XDP-offload to drop obvious noise before the CPU (`RESEARCH_LANDSCAPE.md` §3) — a later throughput multiplier, not a v1 requirement.

## 5. Zone 4 — SOC services, VMs, containers (grow with every user)

- **Native components** — SOC services (the GUI backend, control plane, MSSP link) run as capability-bounded protection domains, each holding only what it was granted. Adding a service = adding a component + its caps; the blast radius is that component.
- **Custom VMs** — a **user-space VMM** (seL4 `libvmm`/Microkit on Arm, or CAmkES) runs an **unmodified Linux guest** (e.g. Home Assistant) using the CPU virtualization extension exposed by Zone 1. Per `RESEARCH_LANDSCAPE.md` §5 this is the **only production-adjacent path to a Linux VM on a verified microkernel**, and it is **Arm-first** (matches the CM5/edge target); x86 VM support is less mature (`VERIFY`). The guest's virtual NICs route through Zone 3 — so **the app tier is itself inside the inspection plane**, the same "the SOC watches the apps" property as the FreeBSD/QNX tracks.
- **Containers** — OCI containers run *inside* a Linux guest VM (Firecracker/Kata/crosvm all need Linux+KVM — they live above the guest, not on the microkernel), or as native capability components for HookProbe-authored services. Honest constraint: **there is no direct "Docker on the bare microkernel"** — containers imply a Linux guest. Plan the marketplace around a managed Linux app-VM, exactly as the FreeBSD track defers full app hosting to capable hardware.
- **The MCS budget guarantee** means a hostile or runaway app-VM **cannot starve the detection plane** — Zone 3 is scheduled with a reserved budget. Starvation resistance, formally.

## 6. Boot — owned end to end ("everything is HookProbe")

Per the operator directive, the boot chain is HookProbe's own (`buildPlan.md` Phase 0):
- **HookProbe loader** targeting **UEFI** (production) and/or **Multiboot2** (bring-up simplicity) — this is genuinely ownable in weeks, not years, so build it.
- Assembly entry stub → 64-bit long mode → flat GDT → IDT catching faults → serial + framebuffer for debug → hand control to the microkernel, which spawns the **root task** holding all initial capabilities. The root task is the primordial manager that starts the PCI server, drivers, and the threat plane.
- Image is **signed and measured** (the capability/W^X/secpol integrity story); A/B images with rollback, mirroring the FreeBSD/QNX RO-image discipline.

---

## 7. What is genuinely novel vs. what is adopted

| Novel to HookProbe (the moat) | Adopted / standing on giants |
|---|---|
| IDS/IPS **on a capability microkernel** (no prior art — `RESEARCH_LANDSCAPE.md` §4) | The capability model (seL4) and datapath pattern (DPDK/AF_XDP/virtio) |
| RFC 9669 BPF threat plane bounded by *both* capability and verifier walls | The BPF ISA (IETF), uBPF/rbpf runtimes, PREVAIL verifier technique |
| QSecBit scoring / AEGIS intent / event schema on this substrate | seL4 MCS budgets, libvmm for the Linux app-VM |
| The owned boot chain + signed A/B image + the whole integrated product | UEFI/Multiboot2 protocols; the SysV ABI; clang/LLVM for rule authoring |

The pattern is the same discipline as the FreeBSD and QNX tracks: **build the detection intelligence and integration; stand on solved, permissively-usable primitives for everything else** — and spend the "own it from scratch" budget only where it buys real defensibility.

---

*Sequencing, the seL4-vs-from-scratch decision, effort estimates, and the honest risk ledger are in `buildPlan.md`.*
