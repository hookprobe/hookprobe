# HookProbe-OS Microkernel — Research Landscape

**A grounded survey of the microkernels, dataplane systems, and capability research that a security-first, IDS/IPS-native OS should stand on. Every non-obvious claim carries a source.**

Status: living reference · Feeds `ARCHITECTURE_BLUEPRINT.md`, `CAPABILITY_MODEL.md`, `ZEROCOPY_IPC_RING.md`, `buildPlan.md`. Produced from five parallel web-research passes (2026-07). Claims that could not be verified are marked **[FLAG]**.

---

## 0. The three findings that shape every decision

1. **seL4 is the only microkernel with a machine-checked correctness proof, and it already implements the exact capability model HookProbe wants** (untyped→retype, CNode/CSpace, badges, Grant, capability-derivation-tree revocation). It is also the only *production-adjacent* path to running a Linux VM on a genuine security microkernel (Arm, via Microkit+libvmm). Its kernel is GPLv2 but **the GPL boundary stops at the kernel/user line** — all HookProbe user-space stays proprietary. → *For a security product, the microkernel core is the one component where adopting seL4 beats writing your own, because the value is the proof.* (Details: §1, §5.)
2. **The high-speed datapath is a solved pattern, independent of the OS:** poll-mode drivers + a descriptor/payload-split, cache-line-isolated, batched, hugepage-backed SPSC ring, with a poll-hot/notify-idle wakeup. DPDK, AF_XDP, netmap, virtio, and VPP-memif are five independent implementations of the same structure. HookProbe's ring (`ZEROCOPY_IPC_RING.md`) mirrors them. (§2.)
3. **"IDS/IPS *on* a verified microkernel" is an open gap, not prior art.** Suricata/Snort run on DPDK/AF_XDP on Linux; seL4 has building blocks (a verified network stack in progress) but *no published IDS/IPS system*. → This is genuinely novel territory and a real differentiator — and a real risk (no one has de-risked it for you). (§3, §4.)

---

## 1. Microkernels & capability OSes

### seL4 — the base to beat
- **Verification:** first/only OS kernel with machine-checked **functional correctness** (C refines abstract spec), plus **integrity**, **availability**, and **confidentiality/non-interference** proofs. ([seL4 FAQ](https://sel4.systems/About/FAQ.html); [verification project](https://trustworthy.systems/projects/OLD/seL4-verification/))
- **Per-arch assurance:** functional-correctness proofs for **Arm32, AArch64, x86-64, RISC-V64**; **RISC-V64 additionally has binary-level + security proofs** (strongest). AArch64 confidentiality and MCS-config proofs **in progress** — verify before relying on "verified + MCS + aarch64" simultaneously. ([verified-configurations](https://docs.sel4.systems/projects/sel4/verified-configurations.html); [RISC-V binary proof](https://microkerneldude.org/2021/05/05/sel4-on-risc-v-verified-to-binary-code/))
- **IPC:** register-only **Call/ReplyRecv fastpath ≈600 cycles** (x64 Kaby Lake), slowpath >1100. ([arXiv 2210.04328](https://arxiv.org/pdf/2210.04328)) A single authoritative per-arch cycle table wasn't found — measure on the target SoC via [sel4bench](https://docs.sel4.systems/projects/sel4bench/). **[FLAG]**
- **MCS scheduler:** scheduling-context capabilities = **(budget, period)**, passable over IPC (donation), giving temporal isolation + mixed-criticality real-time. ([MCS tutorial](https://docs.sel4.systems/Tutorials/mcs.html)) → the mechanism to guarantee the detection plane its CPU under load.
- **Capabilities:** RAM starts as **Untyped**; `seL4_Untyped_Retype` is the sole allocation primitive (no in-kernel malloc). IRQs, x86 I/O ports, device MMIO are all capabilities. Zero-copy channel = one **Frame** mapped into two VSpaces + a **Notification** for wakeup. ([Untyped](https://docs.sel4.systems/Tutorials/untyped.html); [Notifications](https://docs.sel4.systems/Tutorials/notifications.html); [Reference Manual 12.1.0](https://sel4.systems/Info/Docs/seL4-manual-12.1.0.pdf))
- **Licensing:** kernel **GPLv2, propagation stops at the kernel/user boundary**; libs BSD-2. User-space servers/drivers/apps may be proprietary. ([Licensing](https://sel4.systems/Legal/); [Heiser on the license](https://microkerneldude.org/2019/12/09/what-does-sel4s-license-imply/))
- **Frameworks:** **seL4 Microkit** (modern: Protection Domains, channels, memory regions) is the recommended path; CAmkES is the older static-component system; libsel4 is raw. ([sel4 docs](https://docs.sel4.systems/projects/sel4/))
- **Governance/use:** seL4 Foundation (Swiss non-profit under Linux Foundation, 2020); Data61/UNSW/Proofcraft. Real use: **DARPA HACMS Boeing ULB helicopter**; **HENSOLDT TRENTOS** on MiG-V RISC-V. ([Foundation](https://sel4.systems/Foundation/); [TS seL4](https://trustworthy.systems/projects/seL4/); [HENSOLDT](https://www.hensoldt.net/news/extended-trustworthiness-through-binary-verification-of-sel4r-microkernel-on-risc-vr-processor-architecture))

### The rest of the field (what to learn from, why not to base on)
| System | Status | Model / language | License | Takeaway for HookProbe |
|---|---|---|---|---|
| **NOVA microhypervisor** (BlueRock/ex-Bedrock) | **Active**, self-labeled experimental | capability micro*hypervisor*, C++, VT-x/AMD-V, June-2026 AMD IOMMU DMA isolation | GPLv2 | Closest *commercial capability-microhypervisor*; x86 VM path via Genode. ([repo](https://github.com/bedrocksystems/NOVA)) |
| **Fiasco.OC / L4Re** (Kernkonzept) | **Active** | 3rd-gen L4, C++, multi-arch | MIT | Live commercial L4; MIT core if you want a permissive capability kernel to study |
| **Zircon/Fuchsia** (Google) | **Active** (narrowed) | handle+rights object model, C++, *not* purist microkernel | MIT/BSD/Apache **[FLAG]** | Best least-privilege *handle-rights* reference; too big to be minimal TCB. ([kernel objects](https://fuchsia.dev/fuchsia-src/reference/kernel_objects/objects)) |
| **Redox OS** | **Active** | Unix-like Rust microkernel; "Redox Server" edge variant | MIT | The most-alive **Rust** microkernel; a Rust-native reference/base candidate. ([news](https://www.redox-os.org/news/this-month-260630/)) |
| **Theseus OS** | Dormant (research) | "**intralingual**": single address space + Rust type safety instead of MMU rings | MIT | Idea source (compiler-enforced isolation, live evolution); trusts toolchain, no HW isolation. ([OSDI'20](https://www.usenix.org/conference/osdi20/presentation/boos)) |
| **HelenOS** | Active (research/hobby) | multiserver microkernel, C | BSD-3 | Clean driver/FS/net fault-isolation reference |
| **Barrelfish** (ETH/MSR) | **Dead** (no commits since 2020) | "**multikernel**": one kernel/core, no shared memory, message-passing | MIT | Idea source for many-core scale-out; not a base. ([wiki](https://en.wikipedia.org/wiki/Barrelfish_(operating_system))) |
| **OKL4/Pistachio** | Dead (historical) | L4, shipped on billions of basebands | BSD | Heiser's group moved to seL4 — follow that arrow |

### Capability theory (canonical references)
- **Object-capability model** — unforgeable reference fusing *designation + authority*; authority conveyed only by passing references. Miller, *Robust Composition*, **2006**. ([erights.org](http://www.erights.org/talks/thesis/))
- **Confused deputy** — Hardy, **1988**; ocap structurally removes it by fusing designation with authority. ([cap-lore](http://cap-lore.com/CapTheory/ConfusedDeputy.html))
- **Ambient authority / POLA** — Unix `open()` has ambient authority; ocap requires holding a reference to act → least *authority* (Miller), refining least *privilege* (Saltzer & Schroeder **1975**).

---

## 2. High-speed userspace datapaths (the ring is a solved pattern)

- **DPDK PMD:** poll-mode (interrupts off, cores pinned/`isolcpus`), hugepage mempools, NUMA-local. **`rte_ring`**: power-of-two, free-running masked indices, **producer/consumer index couples on separate cache lines**; SPSC = plain load/store, no atomics. **mbuf/mempool** separates metadata descriptor from payload. ([poll_mode_drv](https://doc.dpdk.org/guides/prog_guide/poll_mode_drv.html); [ring_lib](https://doc.dpdk.org/guides/prog_guide/ring_lib.html); [mbuf_lib](https://doc.dpdk.org/guides/prog_guide/mbuf_lib.html))
- **AF_XDP:** **UMEM** frame pool + **four SPSC rings** (FILL/RX/TX/COMPLETION) passing frame ownership; `XDP_ZEROCOPY` DMAs into UMEM; `XDP_USE_NEED_WAKEUP` flag cuts syscalls. → the model HookProbe's 2-ring/4-ring topology follows. ([af_xdp docs](https://docs.kernel.org/networking/af_xdp.html))
- **netmap:** `netmap_ring` head/cur/tail + `slot{buf_idx,len,flags}` indexing a shared buffer pool; kernel touches rings only during a syscall (safer, general). ([netmap(4)](https://man.freebsd.org/cgi/man.cgi?netmap%284%29=))
- **virtio (the canonical layout):** *split* virtqueue = descriptor table + avail ring (driver) + used ring (device); *packed* virtqueue collapses to one ring with wrap-bit flags + in-place completion (better cache locality). `VIRTIO_F_EVENT_IDX` suppresses notifications. ([split](https://github.com/oasis-tcs/virtio-spec/blob/master/split-ring.tex); [packed](https://github.com/oasis-tcs/virtio-spec/blob/master/packed-ring.tex); [Red Hat explainer](https://www.redhat.com/en/blog/virtqueues-and-virtio-ring-how-data-travels))
- **VPP memif + vector processing:** shared ring over a Unix-socket control channel; interrupt (eventfd) vs polling modes; VPP pushes packets through the graph as **vectors** (batches) to amortize I-cache. ([libmemif](https://s3-docs.fd.io/vpp/22.06/interfacing/libmemif/index.html))
- **Ring engineering:** Lamport SPSC; **head/tail on separate 64-B cache lines** (false sharing is the dominant cost); **thread-local cached indices** (Rigtorp: ~300M→15M cache misses, 5.5M→112M items/s over 100M ops); **release/acquire** pairing — free on x86 TSO, needs real **STLR/LDAR/DMB** on aarch64; **batch index publishes (~32)** (MCRingBuffer 2.5–4.9×). ([Rigtorp](https://rigtorp.se/ringbuffer/); [AArch64 barriers](https://devblogs.microsoft.com/oldnewthing/20220812-00/?p=106968); [MCRingBuffer](https://www.cse.cuhk.edu.hk/~pclee/www/pubs/ancs09poster.pdf))
- **Budget reality:** 100 GbE 64-B = **148.8 Mpps ≈ 6.7 ns/packet ≈ ~20 cycles @3 GHz** (derived; **[FLAG]** arithmetic) — less than one LLC miss (~70–100 ns) → batching/prefetch/zero-copy are mandatory, not optional. DPDK forwarding ~100–150 cyc/pkt vs kernel-stack 2,000–10,000 (secondary-source, order-of-magnitude **[FLAG]**). ([Arm Neoverse DPDK](https://developer.arm.com/community/arm-community-blogs/b/servers-and-cloud-computing-blog/posts/dpdk-scalability-analysis-neoverse-v2))
- **Backpressure = a security decision:** inline IDS/IPS must pick an explicit **fail-open** (pass uninspected, availability) vs **fail-close** (drop, security) posture with a drop counter — never undefined overwrite. ([fail-open vs fail-close](https://cloudswit.ch/blogs/fail-open-vs-fail-close-choose-inline-bypass-ha/))

---

## 3. Research systems worth mining (the vanguard the user named)

- **Arrakis** (UW, **OSDI'14 Best Paper**): "the OS is the control plane" — kernel does naming/access-control/limits; apps get **direct SR-IOV NIC access**, kernel off the data path. → architectural template for HookProbe's control/data split. ([usenix](https://www.usenix.org/conference/osdi14/technical-sessions/presentation/peter))
- **FlexNIC** (Kaufmann, Peter, Anderson, Krishnamurthy — HotOS'15 / ASPLOS'16): install **match+action rules into the NIC** for DMA-time steering/demux/transform. → the academic basis for "push IDS pre-filter/steering into the NIC." ([hotos15](https://www.usenix.org/conference/hotos15/workshop-program/presentation/kaufmann); [ASPLOS'16](https://www.semanticscholar.org/paper/High-Performance-Packet-Processing-with-FlexNIC-Kaufmann-Peter/b59b7ea2dd3a5cfff08e2ab1f2d486bd1e744712))
- **Demikernel** (MSR, **SOSP'21**): kernel-bypass datapath libOS, **PDPIX** zero-copy queue API, ns-scale, largely Rust. → interface pattern for a µs-scale IPS datapath. ([ACM](https://dl.acm.org/doi/10.1145/3477132.3483569))
- **Snap** (Google, **SOSP'19**): userspace networking as **composable engines**, hot-upgradable, 3+ yrs in production. → closest production analog to "IDS/IPS as a microkernel engine." ([research.google](https://research.google/pubs/snap-a-microkernel-approach-to-host-networking/))
- **IX** (Stanford/EPFL, **OSDI'14**) & **ZygOS** (**SOSP'17**): protected **run-to-completion, zero-copy, batched** dataplane on dedicated cores; ZygOS work-stealing for tail latency. → the throughput/tail-latency model for inline IPS. ([IX](https://www.usenix.org/conference/osdi14/technical-sessions/presentation/belay))
- **eBPF/XDP + SmartNIC/P4 offload:** hXDP (OSDI'20, eBPF on FPGA NICs), P4 match-action surveys, SmartNIC-security survey. → practical mechanisms for FlexNIC-style in-NIC pre-filtering today. ([hXDP](https://arxiv.org/pdf/2010.14145))
- **On "Joyride":** **[FLAG — verify]** the only real system by that name is a **Sept-2025 Penn State workshop paper** (Du & Nikolaev, KISV'25, [arXiv 2509.25015](https://arxiv.org/abs/2509.25015)) — a microkernel-style centralized userspace TCP/IP service on DPDK + FreeBSD stack, transparent via a libc shim. It is an **early vision, not a mature/foundational architecture**, and **not** from UW/Simon Peter. If you meant a proven dataplane-OS, you're likely thinking of **TAS/FlexTCP, Snap, or Demikernel** — cite those, not "Joyride."

---

## 4. IDS/IPS on this stack — state of the art and the gap

- **Suricata + DPDK** is official and real: ~10–40 Gbps line-rate detection multi-core, up to 100 Gb/s with XDP (limited ruleset). ([dpdk.org](https://www.dpdk.org/elevating-network-security-performance-suricatas-integration-with-dpdk/)) **Snort + DPDK + Hyperscan** likewise (2021).
- **The gap:** no published IDS/IPS running *on seL4 or any verified microkernel*. seL4 has a **verified pure-C network stack in progress** but nothing detection-grade on top. → HookProbe's core thesis (line-rate detection on a capability microkernel) is **novel and unde-risked** — the upside and the risk are the same fact.

---

## 5. Running VMs & containers on top (the "SOC + custom VM/container" requirement)

| Path | Runs Linux on a *microkernel* host? | Status | Note |
|---|---|---|---|
| **seL4 + libvmm (Microkit) / CAmkES VMM** | **Yes** (Arm EL2 mature; x86 less so **[FLAG]**) | Active; **VMM layer NOT verified**, libvmm 0.1.0 "not production" | The only production-adjacent verified-host path. ([libvmm](https://github.com/au-ts/libvmm); [Microkit VMM tutorial](https://docs.sel4.systems/projects/microkit/tutorial/part4.html)) |
| **NOVA + Genode** | Yes (x86, research-grade) | Active | VirtualBox/Seoul VMM on NOVA |
| **Firecracker / crosvm / Kata** | **No** — require **Linux+KVM** | Active | Belong *inside* a Linux guest, not on the microkernel |
| **Jailhouse** | No (static partitioning, Linux-launched) | Upstream dormant | No device emulation/overcommit; wrong fit for a general Linux VM |
| **bhyve** | No (host is monolithic FreeBSD) | Active | The hookprobe-bsd track's VM path |

**Consequence for the blueprint:** the "run Home Assistant / custom Linux VM" requirement is satisfiable on a microkernel **only via seL4-on-Arm (libvmm/CAmkES) today**; containers (OCI) run *inside* such a Linux guest or as native capability-bounded components. Plan the app tier accordingly (`ARCHITECTURE_BLUEPRINT.md` Zone 4).

---

## 6. Language for the build (Zig vs Rust vs C)

- **Rust:** ownership/borrow-checker eliminates use-after-free, overflows, data races at compile time; `no_std` for bare metal; now mainline in Linux with real drivers (Nova GPU ~6.15). **~70% of CVEs are memory-safety bugs** (MS 2019 / Chromium 2020 / CISA 2023) — a direct argument for a memory-safe security kernel. `unsafe` still needed for MMIO/DMA (contained, not eliminated). ([Chromium memory safety](https://www.chromium.org/Home/chromium-security/memory-safety/); [rust-for-linux](https://rust-for-linux.com/))
- **Zig:** excellent control, `comptime`, simpler than Rust, great for MMIO/DMA and precise memory layout (`packed struct`, `align`) — but **no borrow-checker**, so memory safety is on the developer. Strong for the *bootloader and driver* layers; weaker as the safety story for the *kernel TCB*.
- **The decisive precedent:** **seL4 is C, and its assurance comes from a machine-checked proof, not the language.** Language safety removes bug *classes*; it does not *prove* correctness. → If you build a from-scratch kernel, Rust buys the most safety per unit effort; but neither Zig nor Rust gives you seL4's proof. This is the crux of the Track-A-vs-B decision in `buildPlan.md`.

---

*Every design doc in this folder cites back here. Re-run the research passes when a base decision is being committed — especially the seL4 aarch64 MCS/confidentiality proof status and the libvmm maturity, both of which are moving.*
