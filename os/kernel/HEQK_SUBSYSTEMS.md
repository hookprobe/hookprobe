# HEQK Core — Subsystem Architecture

**HEQK = Hardened · Edge · Quantum-safe · Kernel.** The name states the purpose, and the subsystem set follows from it: a tiny hardened microkernel TCB, sized for edge silicon, quantum-safe at the integrity/attestation layer, purpose-built to sense and stop threats. Each subsystem below maps to a lifecycle phase (`LIFECYCLE.md`) and to real code.

```
                              HEQK Core
                                  │
      ┌──────────┬───────────┬────┴─────┬───────────┬────────────┬──────────┐
      │          │           │          │           │            │          │
    PQC       AI Runtime  Packet    Security    Capability   Telemetry   Scheduler
 (ML-KEM/    (QSecBit/   Engine    Framework      Model         Bus
  ML-DSA)     WASI)     (0-copy)  (enforce)    (authority)  (OS=sensor)
```

Why each fits the purpose (and where it is today):

| Subsystem | What it is / why it fits HEQK | Status | Code / phase |
|---|---|---|---|
| **Scheduler** | Priority preemptive scheduler with thread lifecycle + blocking. The **Hardened/real-time** floor: bounded, deterministic, un-starvable (priority + budgets). | ✅ **built** | `kernel/scheduler.rs` — P1 |
| **Capability Model** | Object-capability authority (untyped→retype, CNode/CSpace, CDT, revoke). The **Hardened** core — no ambient authority; a breached component can't even *address* what it doesn't hold. | ✅ **built** | `kernel/caps.rs` — P2 (real-frame-backed) |
| **Security Framework** | Enforcement built *on* the Capability Model: EL0/EL1 isolation, **W^X** (JIT code is RO+exec), signed rules, IOMMU-gated DMA, MAC/secpol. Turns capabilities into policy. | ◑ **partial (W^X built)** | EL0 isolation + fault containment (P3); MMU AP + `map_code_page` W^X (P1b/P6b); PQC signing planned |
| **Packet Engine** | The **Edge** datapath: zero-copy SPSC ring (descriptor + payload pool in shared frames), feeding detection with no copies/kernel-crossings. Real virtio-net wire (P5b). | ✅ **built** | `kernel/packet.rs` + `arch-aarch64/virtio.rs` — P5/P5b |
| **AI Runtime** | RFC 9669 BPF: **VM** (interpreter) + static **verifier** + native **JIT** (W^X) run the signed threat rule as the Packet Engine's verdict, with a runtime bounds sandbox — portable across all HookProbe substrates. | ✅ **built (VM+verifier+JIT)** | `kernel/bpf.rs` + `arch-aarch64/bpf_jit.rs` — P6/P6b |
| **Telemetry Bus** | "The OS is the sensor" — capability/IPC/fault/self-heal events emitted from the TCB, summed into a **QSecBit-lite threat score**. Feeds a **self-heal supervisor** (HAM-style restart-on-fault). The differentiator that justifies a custom kernel. | ✅ **built** | `kernel/telemetry.rs` — P6b |
| **PQC (ML-KEM / ML-DSA)** | The **Quantum-safe** layer: NIST PQC — **ML-KEM** (FIPS 203, key encapsulation) + **ML-DSA** (FIPS 204, signatures) — for signed A/B images, secure/measured boot, attestation, and the control-plane channel. Makes "trustworthy at the root" survive a quantum adversary. | ○ **planned (new)** | new subsystem; slots into Security Framework's signing + boot chain |

Legend: ✅ built & validated · ◑ partial · ▶ next phase · ○ planned.

---

## The build order (why this sequence)

1. **Scheduler + Capability Model first** (P1/P2) — the two subsystems every other one stands on: you can't isolate or schedule detection without them. **Done.**
2. **Security Framework grows with each phase** (P3 added EL0 isolation + fault containment; P1b added MMU protection) — enforcement accretes as the kernel gains privilege levels and memory control.
3. **Packet Engine next** (P5) — the edge datapath is the prerequisite for *any* detection: no ring, no packets to inspect. This is the north-star (`packet → ring → BPF verdict`).
4. **AI Runtime + Telemetry Bus** (P6) — detection intelligence + the "OS is the sensor" stream, both fed by the Packet Engine and the Capability Model.
5. **PQC** threads through the Security Framework's signing/boot/attestation — quantum-safe integrity is added once there's an image and a boot chain to sign (P5-hardening onward). It is deliberately a *cross-cutting integrity* concern, not a datapath one.

Each subsystem is a HAL-respecting component: arch-neutral logic in `kernel/`, arch mechanics behind `hal` in `arch-*/`. The `kernel-validator` agent advances them phase by phase and keeps the whole TCB green (`LIFECYCLE.md`).

---

*PQC is the newest addition and the sharpest expression of the name: an edge security kernel whose root of trust is quantum-safe. It does not change the datapath (Packet Engine) or detection (AI Runtime); it hardens what those depend on — the signed image and attested boot — against a future adversary. Tracked as a planned Security-Framework subsystem.*
