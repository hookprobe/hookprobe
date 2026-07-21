# HEQK Core — Hardened Edge Quantum-safe Kernel

**HookProbe's IDS/IPS-native microkernel: capability-secured, zero-copy datapath, quantum-safe (PQC) integrity, purpose-built to run a SOC plus custom VMs/containers — the long-horizon endgame of the HookProbe OS program.** Subsystem map in `HEQK_SUBSYSTEMS.md`.

Sibling to `~/hookprobe-bsd` (base of record) and `~/hookprobe-qnx` (real-time/uptime benchmark). This track asks: if we design the OS *around* threat detection from scratch, what does it look like — and what should we actually build vs. stand on?

---

## Read in this order

1. **`ARCHITECTURE.md`** — **the spine. The clear, committed, custom HookProbe microkernel architecture** (Rust, QEMU-first, CM5/RP1 + N100, HAL trait, adaptive-NAPI data plane, "the OS is the sensor"). Read this first.
2. **`buildPlan.md`** — the concrete, best-practice build plan for actually writing the kernel — toolchain, workspace, reference kernels, P0→P7 with test gates.
3. **`CAPABILITY_MODEL.md`** — the object-capability model (untyped→retype, CSpace, badges, Grant, CDT revocation).
4. **`ZEROCOPY_IPC_RING.md`** — the packet ring fully mapped: 3 memory regions, descriptor/payload split, SPSC + release/acquire, adaptive NAPI, IOMMU-gated DMA, multi-core scale-out.
5. **`BPF_THREAT_PLANE.md`** — the RFC 9669 BPF VM + JIT + verifier, inside the unprivileged IDS sidecar.
6. **`RESEARCH_LANDSCAPE.md`** — the deep investigation (seL4, L4/NOVA/Zircon/Redox/Theseus, DPDK/AF_XDP/virtio, Arrakis/FlexNIC/Demikernel, capability theory, VM/container options) — all cited.
7. **`ARCHITECTURE_BLUEPRINT.md`** — the earlier generic zone blueprint (kept for context; superseded on edge-sizing by `ARCHITECTURE.md`).

---

## The thesis in five sentences

- **The kernel should do almost nothing** — verify capabilities and route messages — because at 100 GbE the per-packet budget is ~20 cycles and a general-purpose kernel's interrupt/context-switch overhead suffocates the CPU (`RESEARCH_LANDSCAPE.md` §2).
- **The datapath is fully user-space and zero-copy**: NIC DMA → hugepage frame → capability-shared SPSC ring → IDS reads in place → verdict, with the microkernel off the data path entirely (`ZEROCOPY_IPC_RING.md`).
- **Detection is a standards-pure RFC 9669 BPF plane** (JIT-compiled, sandbox-verified) inside a capability-bounded sidecar, so a breach of the inspection engine cannot even *address* the host runtime (`BPF_THREAT_PLANE.md`, `CAPABILITY_MODEL.md`).
- **VMs and containers run in Zone 4** (a monitored Linux guest via seL4 libvmm on Arm), inside the inspection plane and unable to starve it — "the SOC watches the apps," formally scheduled.
- **The moat ports here unchanged** — event schema, BPF ISA, WASI, QSecBit, AEGIS — the same three portability contracts that carry it across the Linux, FreeBSD, and QNX tracks now carry it to a fourth substrate.

## The decision (made — no longer relitigated)

The build a **custom Rust microkernel from scratch** — not seL4 — is the committed direction. The earlier docs weighed adopting the verified seL4 core (its capability model *is*, point-for-point, the one drafted here, and it took formal-methods researchers ~15 years to prove). That trade-off is real and consciously accepted, for one decisive reason: **the differentiator is "the OS is the sensor"** — instrumenting the capability/IPC layer itself as a tamper-evident telemetry stream into QSecBit — and *that feature requires owning and modifying the kernel*, which verified seL4 cannot provide without voiding its proof. Owning the kernel is what makes the kernel a sensor. Rust removes the memory-safety bug class in lieu of a proof team; a mandatory TCB security audit covers the rest. See `ARCHITECTURE.md` §0 and §6.

## What's novel (and therefore risky)

**IDS/IPS on a verified capability microkernel has no prior art** (`RESEARCH_LANDSCAPE.md` §4) — Suricata/Snort exist on DPDK/Linux, seL4 has building blocks, but no one has built detection-grade security on a microkernel. The upside and the risk are the same fact. The build plan de-risks it with QEMU→metal gates, the shared HIL rig, and the already-proven shared moat.

---

*Status: **P0–P6b GREEN on QEMU (2026-07-20) — a real preemptive, paged, capability kernel with userspace, IPC, a zero-copy Packet Engine fed by a real NIC, a BPF threat-detection VM+JIT, and runtime self-healing.** Validated in one boot by `./validate.sh`: P0 boot; P1 **priority** scheduler + lifecycle; P1b MMU + frame allocator + free list; P2 capabilities (real frames); P3 EL0 + SVC + **capability invocation** + fault containment; P4 **synchronous IPC**; P5 **Packet Engine** (zero-copy ring); **P5b real wire** (virtio-net ARP round-trip); **P6 AI Runtime** — an **RFC 9669 BPF VM** as the verdict; **P6b** — a **BPF verifier** + a native **JIT** (W^X) matching the interpreter, a **self-heal supervisor** (HAM-style restart-on-fault), and a **telemetry/QSecBit** bus ("the OS is the sensor" — a threat score aggregated from TCB events). **DRV** — driver isolation: an **EL0 driver server** drives the NIC's MMIO through a capability-granted device window and nothing else (a compromised driver is contained to EL0 + that one device). A **security audit** (`SECURITY_AUDIT.md`) fixed 5 findings incl. two HIGH (untrusted-device OOB read; missing UXN/PXN → exec-stack + EL1-exec-of-user-memory). Subsystem map in `HEQK_SUBSYSTEMS.md`; safety-style V-model (`LIFECYCLE.md`) with an always-on validator + `kernel-validator` agent (dev-time healer) alongside the kernel's runtime self-heal. **Remaining:** P7 (CM5/RP1 metal — needs hardware), the PQC subsystem (ML-KEM/ML-DSA), and the deferred kernel-page block-splitting for full W^X. Build/run/debug in `HACKING.md`.*
