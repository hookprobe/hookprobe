# HookProbe Microkernel — Product Lifecycle & Continuous V&V

**The kernel is built and maintained on a safety-style V-model lifecycle (aligned with how Arm Cortex safety products are developed under ISO 26262 / IEC 61508), with an always-on kernel-validator agent providing continuous verification, validation, and self-healing.**

This answers two needs: a disciplined **phase-gated lifecycle** (so a mission-critical kernel is built *right* and is the *right* thing), and a **persistent validator** (`validate.sh` + the `kernel-validator` agent) that keeps it green forever.

---

## 1. Why a lifecycle at all

HookProbe targets mission-critical SOC/IDS deployment. That class of system is not "code until it boots" — it is developed against a lifecycle with explicit **verification** ("did we build the kernel right?" — unit/integration gates) and **validation** ("did we build the right kernel?" — does it actually detect threats at line rate, safely). The **V-model** is the standard for this (safety-critical Arm Cortex-R/-M products use it under ISO 26262 / IEC 61508). We adopt it, mapped onto the P0→P7 build phases.

```
   CONCEPT ─────────────────────────────────────────────► VALIDATION
     │  Requirements                              System validation │
     │     │  Architecture                     Integration test  │  │
     │     │     │  Design                    Unit verification │  │  │
     │     │     │     └────── Implementation ─────┘           │  │  │
     └─────┴─────┴───────────────────────────────────────────┴──┴──┘
                         (left = specify, right = prove)
                  RELEASE ──► MAINTENANCE (continuous V&V + self-heal)
```

The **left arm** is the design docs already written; the **right arm** is the per-phase self-tests and the north-star validation; **maintenance** is the always-on validator.

---

## 2. Lifecycle stages → HookProbe artifacts

| V-model stage | HookProbe artifact | "Cortex-safety" analog |
|---|---|---|
| **Concept** | `ARCHITECTURE.md` §0 (thesis, "OS is the sensor") | Item definition |
| **Requirements** | `buildPlan.md` §1 principles; `README.md` thesis | Safety/functional requirements |
| **Architecture** | `ARCHITECTURE.md` zones; `RESEARCH_LANDSCAPE.md` | System architecture |
| **Design** | `CAPABILITY_MODEL.md`, `ZEROCOPY_IPC_RING.md`, `BPF_THREAT_PLANE.md` | Software unit design |
| **Implementation** | `kernel/`, `arch-aarch64/`, `hal/`, `abi/` (P0→) | Coding (MISRA-style discipline: Rust safety + tiny TCB) |
| **Unit Verification** | per-phase self-tests (P0–P2 markers) | Unit test |
| **Integration Verification** | full-boot validator (`validate.sh`) — all gates in one boot | Integration test |
| **System Validation** | P5 north-star packet + the separation matrix (legit passes, attacks caught) | System/safety validation |
| **Release** | signed A/B image (P5-hardening) | Production release |
| **Maintenance** | `kernel-validator` agent: continuous re-validation + heal + gap-fill | Field monitoring / safety case upkeep |

---

## 3. Phase gates (the right arm — each proves the matching left-arm design)

| Phase | Lifecycle | Gate (machine-checked marker) | Status |
|---|---|---|---|
| **P0** | Impl+Verify | boot EL2→EL1, PL011, exception vectors → `[P0] PASS` | ✅ |
| **P1** | Impl+Verify | preemptive scheduler + context switch → `[P1] PASS` | ✅ |
| **P1b** | Impl+Verify | MMU stage-1 + frame allocator, VA≠PA translation → `[P1b] PASS` | ✅ |
| **P2** | Impl+Verify | capabilities: untyped/retype/CDT/recursive revoke → `[P2] PASS` | ✅ |
| **P3** | Impl+Verify | EL0 userspace + SVC syscalls + fault containment (isolated user page) → `[P3] PASS` | ✅ |
| **P4** | Impl+Verify | synchronous IPC rendezvous over an Endpoint (block/unblock) → `[P4] PASS` | ✅ |
| **P5** | Validation | **Packet Engine** — zero-copy ring + in-place verdict (synthetic packets) → `[P5] PASS` | ✅ |
| **P5b** | Validation | **real wire** — virtio-net ARP round-trip → ring → verdict (real packet) → `[P5b] PASS` | ✅ |
| **P6** | Validation | **AI Runtime** — RFC 9669 BPF VM (interpreter) runs the threat rule + bounds sandbox → `[P6] PASS` | ✅ |
| **P6b** | Validation | BPF **verifier** + **JIT** (native codegen, W^X) + **self-heal supervisor** + telemetry/QSecBit → `[P6b] PASS` | ✅ |
| **P7** | Validation | CM5/RP1 metal bring-up (→ M1 acceptance) | ✅ metal 4/4 (2026-08-20): boot + `:53` forward / `:4444` drop / forced-bad-boot rollback |

**Beyond P7 — the migration Track C (M1–M7)** continues in `docs/roadmap/BuildPlan.md` (this table stops at the microkernel's own P0–P7 bring-up). Metal status as of 2026-09-08: **M1** accepted 4/4; **M2** detection parity SIGNED OFF (CONDITIONAL-GO — 31/31 heqk-plane rows + 2 off-device, Gate-R single-pass on metal); **M3** persistence metal-proven (eMMC write + sealed store w/ real OTP SRK + DataVolume log-store + A/B OTA forward-flip + rollback); **segmentation** reach-enforcement plane built + metal-proven (disarmed, C7); **M4** GEM bridge FIRST-LIGHT + presence beacon **metal-proven** (2026-09-08): heqk answers `arping 10.200.0.2` (5/5, sub-ms) and emits a UDP beacon on the real wire, via the Linux-`macb` SINGLE-ring-owner datapath (a 2nd RX-ring walker was the BNA-stall bug, fixed). The full PQ-hybrid Noise **control plane** is then built + QEMU-proven end-to-end: `ControlPlane` initiator handshake ([P19-controlplane]), `reconcile_reach_policy` arms segmentation off a channel-fetched signed policy ([P20-reconcile] — the QEMU half of U2b), DNS-sinkhole ([P20-dns-sink]). **Metal-tomorrow:** the live handshake (host MSSP-sim on the wire) + metal segmentation arming (Gate-R U2b sign-off); M5 wasm-on-cm5 un-gate (build-plumbing per product-steward FLAG-1, the W^X fix already has a cm5 mirror); M3 eMMC-scale; the hardware-blocked P9/WAN/WiFi. See `docs/design/heqk-gap-plan.md` §"2026-09-08 QEMU build-out". See `docs/design/heqk-gap-plan.md`.

A gate is green **only** with a recorded marker from the tier it names (same honesty rule as the FreeBSD/QNX tracks). `validate.sh` enforces this every run.

---

## 4. The always-on validator (maintenance = continuous V&V + self-heal)

Two forms of the same thing:

1. **`validate.sh`** — the executable validator. Builds, boots on QEMU, checks every phase marker, prints this lifecycle report, lists **gaps** (regressions in built phases, or not-yet-built phases), exits non-zero on regression. Run it after every change; wire it into CI. This is the mechanical "always there" gate.

2. **The `kernel-validator` agent** — the intelligent layer. Invocable any time to: run `validate.sh`, **diagnose** a failure (build error, boot hang, missing marker) down to the offending file/line, **heal** it (propose + apply a fix, re-validate), and **fill the next gap** (implement the next PLANNED phase against its design doc, then prove its gate). It is the software-lifecycle analog of the FreeBSD/QNX **HAM** (High Availability Manager) and of HookProbe's own "self-healing SOC" thesis — applied to the kernel's own development: the kernel is never left red, and gaps are continuously closed against the lifecycle.

**Self-heal loop:**
```
validate.sh ──fail──► diagnose (build/boot/marker) ──► propose fix ──► apply ──► validate.sh
     ▲                                                                              │
     └──────────────────────────── green ◄─────────────────────────────────────────┘
                 (on green with gaps: implement next PLANNED phase, repeat)
```

---

## 5. Traceability (every gate traces to a requirement)

- Requirement "tiny, memory-safe TCB" → Design "Rust `no_std`, HAL boundary" → Impl `kernel` has no `cfg(target_arch)` → Verify `validate.sh` build + P0–P2 markers.
- Requirement "capability isolation" → Design `CAPABILITY_MODEL.md` → Impl `caps.rs` → Verify `[P2] PASS` (retype/revoke/type-safety).
- Requirement "line-rate safe detection" → Design `ZEROCOPY_IPC_RING.md` + `BPF_THREAT_PLANE.md` → Impl P4/P5/P6 → **Validate** `[P5] PASS` north-star packet + separation matrix.

The validator keeps this chain unbroken: no phase is "done" without its gate, and no gate stays green by accident — it is re-proven on every run.
