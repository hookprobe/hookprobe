# HEQK — Hardened Edge Quantum-safe Kernel

**An IDS/IPS-native microkernel.** HEQK is the HookProbe project's capability-secured operating system kernel for edge security appliances: a fully user-space, zero-copy packet datapath, post-quantum boot integrity rooted in hardware fuses, and a threat-detection plane built into the operating system itself — purpose-built to run a SOC alongside customer VMs and containers.

![License: AGPL-3.0](https://img.shields.io/badge/license-AGPL--3.0%20%2F%20commercial-blue)
![Language: Rust no_std](https://img.shields.io/badge/rust-no__std-orange)
![Architecture: aarch64](https://img.shields.io/badge/arch-aarch64-informational)
![Targets: QEMU · Raspberry Pi CM5](https://img.shields.io/badge/targets-QEMU%20%C2%B7%20RPi%20CM5%20(BCM2712)-lightgrey)

> 📊 **What we build — [validation matrix](#validation-matrix--p0--p17)** (P0→P17, below): every feature in the kernel and where it is proven — on Raspberry Pi CM5 (BCM2712) silicon, under QEMU, or both — plus in-flight residuals and the automation-underlay and assurance roadmaps. The table is regenerated automatically from a live validation run.

HEQK is the fourth substrate of the HookProbe program, alongside its Linux, FreeBSD, and QNX tracks. This track asks: if we design the OS *around* threat detection from scratch, what does it look like — and what should we actually build versus stand on?

---

## Design principles

- **The kernel does almost nothing** — verify capabilities and route messages. At 100 GbE the per-packet budget is roughly 20 cycles, and a general-purpose kernel's interrupt and context-switch overhead suffocates the CPU (`RESEARCH_LANDSCAPE.md` §2).
- **The datapath is fully user-space and zero-copy**: NIC DMA → hugepage frame → capability-shared SPSC ring → IDS reads in place → verdict. The microkernel is off the data path entirely (`ZEROCOPY_IPC_RING.md`).
- **Detection is a standards-pure RFC 9669 BPF plane** — JIT-compiled, sandbox-verified — inside a capability-bounded sidecar, so a breach of the inspection engine cannot even *address* the host runtime (`BPF_THREAT_PLANE.md`, `CAPABILITY_MODEL.md`).
- **VMs and containers run inside the inspection plane** (a monitored Linux guest, Zone 4) and cannot starve it — "the SOC watches the apps," formally scheduled.
- **The moat ports here unchanged** — event schema, BPF ISA, WASI, QSecBit, AEGIS: the same portability contracts that carry HookProbe across its Linux, FreeBSD, and QNX tracks carry it to this fourth substrate.

## Why a custom kernel — and not seL4

Building a **custom Rust microkernel from scratch** is the committed direction; the alternative was adopting the formally verified seL4 core, whose capability model is, point for point, the one drafted here — and which took formal-methods researchers roughly fifteen years to prove. That trade-off is real and consciously accepted, for one decisive reason: the differentiator is **"the OS is the sensor"** — instrumenting the capability/IPC layer itself as a tamper-evident telemetry stream into QSecBit — and that feature requires owning and modifying the kernel, which verified seL4 cannot permit without voiding its proof. Owning the kernel is what makes the kernel a sensor. Rust removes the memory-safety bug class in lieu of a proof team; a mandatory TCB security audit covers the rest (`ARCHITECTURE.md` §0, §6).

**What is novel is also what is risky:** IDS/IPS on a capability microkernel has no prior art (`RESEARCH_LANDSCAPE.md` §4). Suricata and Snort exist on DPDK/Linux; seL4 has the building blocks; no one has built detection-grade security on a microkernel. The build plan de-risks it with QEMU→metal phase gates, a hardware-in-the-loop rig, and the already-proven shared moat.

## Status

**P0–P8 are live: a preemptive, paged, capability kernel with EL0 userspace, synchronous IPC, a zero-copy Packet Engine fed by real hardware, a verified BPF threat-detection plane (interpreter + W^X JIT), quantum-safe measured boot, and runtime self-healing — proven on Raspberry Pi CM5 silicon and under QEMU.** Every phase gate is validated in a single boot by `./validate.sh`; the [validation matrix](#validation-matrix--p0--p17) below is the authoritative, per-feature record of what is proven where, and is refreshed automatically. A TCB security audit (`SECURITY_AUDIT.md`) has been completed, with all findings fixed. Development follows a safety-style V-model (`LIFECYCLE.md`) with an always-on validator.

## Getting started

```sh
./validate.sh        # one-boot QEMU validation of every phase gate
```

Toolchain setup, QEMU flags, CM5 flashing, and debugging workflows are in [`HACKING.md`](HACKING.md).

## Documentation

| Document | What it covers |
|---|---|
| [`ARCHITECTURE.md`](ARCHITECTURE.md) | **The spine.** The committed HookProbe microkernel architecture — Rust, QEMU-first, CM5/RP1 + N100, HAL trait, adaptive-NAPI data plane, "the OS is the sensor." Read this first. |
| [`buildPlan.md`](buildPlan.md) | The concrete build plan — toolchain, workspace, reference kernels, phases P0→P17 with test gates. |
| [`CAPABILITY_MODEL.md`](CAPABILITY_MODEL.md) | The object-capability model: untyped→retype, CSpace, badges, Grant, CDT revocation. |
| [`ZEROCOPY_IPC_RING.md`](ZEROCOPY_IPC_RING.md) | The packet ring, fully mapped: three memory regions, descriptor/payload split, SPSC + release/acquire, adaptive NAPI, IOMMU-gated DMA, multi-core scale-out. |
| [`BPF_THREAT_PLANE.md`](BPF_THREAT_PLANE.md) | The RFC 9669 BPF VM, JIT, and verifier inside the unprivileged IDS sidecar. |
| [`RESEARCH_LANDSCAPE.md`](RESEARCH_LANDSCAPE.md) | The deep investigation — seL4, L4/NOVA/Zircon/Redox/Theseus, DPDK/AF_XDP/virtio, Arrakis/FlexNIC/Demikernel, capability theory, VM/container options — all cited. |
| [`HEQK_SUBSYSTEMS.md`](HEQK_SUBSYSTEMS.md) | Subsystem map of the kernel tree. |
| [`LIFECYCLE.md`](LIFECYCLE.md) | The safety-style V-model: phase gates, the always-on validator, and the self-healing development loop. |
| [`SECURITY_AUDIT.md`](SECURITY_AUDIT.md) | The TCB security audit — findings and fixes. |
| [`HACKING.md`](HACKING.md) | Build, run, flash, and debug. |
| [`ARCHITECTURE_BLUEPRINT.md`](ARCHITECTURE_BLUEPRINT.md) | The earlier generic zone blueprint — kept for context; superseded on edge-sizing by `ARCHITECTURE.md`. |

## Contributing, security, and licensing

- **Contributing** — see [`CONTRIBUTING.md`](CONTRIBUTING.md); HEQK-specific development workflows are in [`HACKING.md`](HACKING.md). All participants are bound by the [`Code of Conduct`](CODE_OF_CONDUCT.md).
- **Security reports** — please follow the [security policy](SECURITY.md); do not open public issues for vulnerabilities.
- **License** — dual-licensed: [AGPL-3.0](LICENSE) for open-source use, commercial licensing available for SaaS and embedded redistribution. Details in [`LICENSING.md`](LICENSING.md).

---

## Validation matrix — P0 → P17

<!-- VALIDATION-MATRIX:BEGIN (generated by tools/gen-readme-matrix.py — edit heqk-validation.html, not this section) -->

*As of 2026-07-22. QEMU gates are re-derived live from a `./validate.sh` run; metal rows carry their last-recorded boot state on CM5. Generated from `heqk-validation.html` (built by `tools/gen-validation.py`); this section is refreshed automatically by CI.*

| **36** | **27** | **23** | **0** |
|---|---|---|---|
| features built | proven on CM5 metal | proven under QEMU | hardware blockers |

Legend: **Metal** = validated on CM5 (BCM2712) hardware · **QEMU** = validated under emulation · **HW-gated** = code complete, blocked on hardware · **Planned** = designed & gated, not yet built.

### L0 · Microkernel core

*seL4-style capability kernel — the trusted computing base*

| Feature | Phase | Proves | Validated | Marker |
|---|---|---|---|---|
| Boot chain EL2→EL1 + PL011 UART + exception vectors — fault trapped, not fatal | P0 | Boots and prints; a fault is caught, not fatal. | **Metal** · QEMU | [CM5-BOOT] · [P0] |
| Preemptive priority scheduler + context switch | P1 | H>M>L preemption; an uncooperative task is timer-preempted. | **Metal** · QEMU | [P7b] · [P1] |
| MMU stage-1 + physical frame allocator | P1b | Live translation; VA≠PA read-back proves the walk. | **Metal** · QEMU | [P1b] |
| Capabilities — untyped / retype / CDT / revoke + rights — iterative revoke; rights-diminished mint; enforcement on invoke | P2 | Capability derivation tree; iterative (non-recursive) revoke; monotonic rights diminution — a read-only frame's write is denied, amplification refused. | QEMU | [P2] |
| EL0 userspace + SVC syscall boundary + fault containment | P3 | User/kernel split; an EL0 fault is contained. | **Metal** · QEMU | [P3] |
| Synchronous IPC — Endpoint rendezvous + register fastpath | P4 | Block/unblock over an Endpoint; reply-cap fastpath. | QEMU | [P4] |
| Packet Engine — zero-copy SPSC ring + in-place verdict | P5 | Payload inspected in place, never copied through the ring. | QEMU | [P5] |
| Real wire — virtio-net ARP round-trip → ring → verdict | P5b | A real received frame reaches the verdict engine. | QEMU | [P5b] |
| RFC 9669 BPF VM (interpreter) + bounds sandbox | P6 | Signed bytecode is the verdict; OOB load rejected. | **Metal** · QEMU | [P6] |
| BPF static verifier + JIT (W^X) + self-heal + telemetry | P6b | Verify-before-run; native codegen; HAM restart; QSecBit-lite. | QEMU | [P6b] |

### L1 · Metal bring-up & driver isolation

*the microkernel on real silicon, drivers pushed out of the TCB*

| Feature | Phase | Proves | Validated | Marker |
|---|---|---|---|---|
| CM5 / BCM2712 bring-up — RP1 UART console, high-PA MMU | P7 | Boots and prints on real silicon over the FTDI console. | **Metal** | [CM5-BOOT] |
| Inline IPS — wire → ring → BPF → enforce | P7a | Benign :53 forwarded, threat :4444 dropped on the wire. | **Metal** | [P8] IPS |
| W^X — kernel .text RO+X, data RW+PXN, SCTLR.WXN | P7b | No writable-executable memory anywhere (K1 block-split). | **Metal** · QEMU | [P7b] W^X |
| Isolated EL0 GEM driver — register probe | P7c·1 | EL0 driver reads real GEM MMIO; matches kernel, nothing else granted. | **Metal** | [P7c] |
| Isolated EL0 GEM driver — TX from EL0 | P7c·3 | Transmit armed + kicked + completed from user space. | **Metal** | [P7c] |
| Continuous restartable EL0 driver server | P7c·4d | 5 real frames judged; a driver crash contained + restarted. | **Metal** | [P7c] |
| EL0 driver as preemptible scheduled TCB in its own ASID — counter 1.29 B, preempted, zero EL0 faults | P7c·4c | Full driver-isolation runtime — own address space, ASID-tagged TTBR0 switch — on metal. | **Metal** · QEMU | [P7c-4c] |
| EL1↔EL2 stage-2 isolation — HBoot region hidden | P7e | An EL1 access into HBoot's footprint traps to EL2 (B-3 closed). | **Metal** | stage2 armed |

### L2 · Secure boot & hardware attestation

*quantum-safe, OTP-rooted — HBoot at EL2*

| Feature | Phase | Proves | Validated | Marker |
|---|---|---|---|---|
| Hybrid quantum-safe secure boot — ed25519 AND SLH-DSA (FIPS-205) | — | Breaking boot needs breaking classical ECC AND post-quantum. | **Metal** | verify PASS |
| Measured boot + CRTM anchor — PCR0 rooted in OTP device id 0x0102…5a31 | B-7 | PCR chain rooted in the immutable OTP-fused identity, not a free-floating self-measurement. | **Metal** | CRTM-anchored |
| Hardware-bound per-device AK — OTP-derived, non-extractable | B-1 | Attestation key lives only in fuses, per device — not in the image. | **Metal** | [P7d-B1] |
| Runtime attestation — ephemeral key answers verifier nonces | B-2 | Fresh challenge → fresh signature; replay rejected; AK scrubbed post-boot. | **Metal** | [P7d-B2] |
| Anti-rollback SVN floor — OTP thermometer, fail-closed — watermark held on read failure — no rollback | B-8 · P7d-c | Monotonic hardware floor; a forced OTP read-failure can't roll it back. | **Metal** | floor read OK |
| Hardware TRNG per-boot nonce — BCM2712 rng200 | P7d-a | A fresh 32-byte nonce each boot; kills the static-nonce weakness. | **Metal** | hw-trng |

### L3 · Detection plane at scale

*the IDS/IPS product surface — “the OS is the sensor”*

| Feature | Phase | Proves | Validated | Marker |
|---|---|---|---|---|
| PREVAIL-style static verifier — abstract interpretation | P8 | Proves rule memory-safety before it runs; rejects wild-load / loop / uninit-verdict. | **Metal** · QEMU | [P8] |
| General BPF JIT — two-pass, W^X, forward branches — EL1 RO+X code window on metal (GB6) | P8 | Native aarch64 codegen; verdicts match the interpreter — on QEMU and CM5 silicon. | **Metal** · QEMU | [P8-JIT] |
| HookProbe rule registry — parity corpus — 3/3 rules JIT-compiled to native ARM64 on metal | P8 | The same signed bytecode runs on the Linux/FreeBSD/QNX tracks and here, unchanged. | **Metal** · QEMU | rule plane |
| Live QSecBit scoring — severity-weighted, in the TCB | P8 | Rule hits on real traffic scored inside the kernel — the OS is the sensor. | QEMU | [P8-plane] |
| Adaptive NAPI data plane — grows under load, idles when quiet | P8 | Poll-budget peaks under a burst, re-arms the IRQ when quiet; spin-poll retired. | QEMU | [P8-napi] |
| L2 guard — malformed-ARP + ARP-spoof drop — napse-l2guard parity; JIT'd + running on metal (drop-logic proven on QEMU) | P8 | Deterministic frame-level enforcement: bad ARP shape (is_malformed) + spoofed sender-MAC (eth_mismatch) dropped before L4. | **Metal** · QEMU | [P8-l2] |
| TCP scan detection — NULL / FIN / Xmas / SYN-FIN — stateless anomalous-flag signatures (Nmap/Suricata-style) | P8 | Anomalous TCP flag combinations dropped as scans; normal SYN/ACK pass (no false positives). | QEMU | [P8-tcp] |
| Stateful substrate — BPF CALL helper + rate limiter — running on metal (10-rule plane, CALL interp path, 0 faults); logic proven on QEMU | P8 | A signed rule decides on a RATE, not one packet — verifier admits CALL, JIT declines it, interpreter runs it. Substrate for the stateful WAN tier. | **Metal** · QEMU | [P8-syn] |
| Per-source SYN-flood — live datapath rule — keyed by IP source; running in live classify on metal (isolation proven on QEMU) | P8 | Wired into live classify: a per-source SYN flood is rate-limited inline while other sources' connection setups pass. | **Metal** · QEMU | [P8-synsrc] |
| Threat-feed blocklist — keyed CIDR lookup (helper #2) — signed block set; running in live classify on metal (drop-logic proven on QEMU) | P8 | The stateful substrate generalizes beyond a counter to a keyed lookup: frames from a blocked source prefix are dropped inline; clean sources pass. | **Metal** · QEMU | [P8-block] |
| Verifier self-hardening — abstract-operator soundness harness — Agni-style; modular operators (absdom.rs); injected unsoundness caught | P16 | The verifier that gates every rule is itself checked: each abstract operator over-approximates the concrete semantics; a deliberately-unsound operator is caught by the CI harness, not by prod. | QEMU | [P16-verifier] |

### L4 · Second interface

*external PCIe (RTL8111H) — trained + enumerated on metal*

| Feature | Phase | Proves | Validated | Marker |
|---|---|---|---|---|
| RTL8111H external PCIe RC1 bring-up — pcie-brcmstb train: RESCAL, SERDES, refclk-MDIO, DIS_PLL_PD, Gen1, tperst; then enumerate | P9 | HEQK trains the external PCIe (RC1 LINK UP, status 0x0003e0bf) and enumerates the RTL8111H at 01:00.0 (vendor/device 0x816810ec) on metal. The long 'won't train' was PHYSICAL — the CM5 was not fully seated in the carrier (Linux failed identically); once reseated it trains. RX datapath (BAR2 MMIO window + ring → IDS, mirrors the GEM) is the remaining step. | **Metal** | [P9] PASS · RTL8111H found |

<!-- VALIDATION-MATRIX:END -->
