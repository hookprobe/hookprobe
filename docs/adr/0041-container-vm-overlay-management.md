# ADR 0041 — The container & VM overlay: runtime, isolation & lifecycle management

**Status:** 🟡 Proposed (2026-07-17) — a design-session **posture**, not an implemented change. Records the architecture for the *workload overlay* — how user containers/VMs run on the HookProbe underlay, what runs them, how they are isolated and resourced, and how their lifecycle and catalog work. Each principle is tagged **[realized]** (already true in-repo), **[partial]**, or **[vision]** (roadmap, not built), the same honesty discipline as [ADR 0035](0035-substrate-ownership-underlay-overlay.md). This ADR owns the *overlay architecture*; it does **not** re-spec the GUI/UX that drives it — that is [ADR 0040](0040-experience-ux-ui-scope-gui-features.md).
**Deciders:** os-architect (author), security-auditor, release-engineer, code-developer.
**Relates to:** [ADR 0035](0035-substrate-ownership-underlay-overlay.md) (the underlay/overlay split + the D7/D8 GUI-managed-overlay and hard-reservation principles this makes concrete), [ADR 0040](0040-experience-ux-ui-scope-gui-features.md) (the GUI/UX surface for this overlay), [ADR 0038](0038-ai-tiers-bpf-lsm-process-trust.md) (the security-plane isolation this must not breach), [ADR 0019](0019-bootc-debian-substrate.md) (rootless Podman/Quadlet is already the runtime for HookProbe's own services), [ADR 0036](0036-verifiable-supply-chain-reproducible-bootstrappable.md) (the cosign/SBOM chain the signed catalog reuses), [ADR 0031](0031-dataplane-performance-strategy.md) (the cgroup two-wall backing the reservation).

This ADR takes [ADR 0035] D7 (*"the overlay is GUI-managed, its catalog curated + signed"*) and D8 (*"two hard invariants keep the overlay from dissolving the underlay"*) from principle to architecture: **what actually runs the workloads, and how they are kept from touching the security plane.**

---

## Context

[ADR 0035] D1 establishes HookProbe OS as a **secure underlay** and user containers/VMs as an **overlay** it secures *by construction* — the underlay sits beneath, inspecting every packet and syscall by default. The positioning follows: *run your workloads on HookProbe and they are secured the moment they boot, because HookProbe is the ground they stand on* — a claim no bolt-on security product can make.

Today, **rootless Podman + Quadlet already run HookProbe's own heavy stateful services** ([ADR 0019]/[ADR 0003]) — the container substrate exists and is proven. What does **not** yet exist is a *user-workload* manager, any **VM** layer, or a **catalog** — those are net-new (⬜). This ADR is the posture for building them without letting an arbitrary workload beside a hardened sensor become a liability.

---

## Decision

### D1 · Reuse the runtime, never reinvent it **[partial]**

Per [ADR 0035] D2/D3 (own the differentiation, rent the commodity — a bespoke container/VM runtime is pure CVE-manufacturing with zero differentiation):

- **Containers = rootless Podman + Quadlet** **[realized for own-services / vision for user workloads]**. Already in the stack, portable, declarative. User workloads reuse the *same* runtime HookProbe's own services run on — no second container system.
- **VMs = a lightweight KVM layer** **[vision]**. Recommend a **Rust VMM (cloud-hypervisor / Firecracker-class)** over full libvirt/QEMU for the edge, because it fits the minimal + memory-safe + small-attack-surface ethos ([ADR 0035] D4/D6). Honest tradeoff: **libvirt** brings feature breadth and device/compat coverage; a **Rust VMM** brings a smaller footprint and a memory-safe control plane. VM support is **capability-gated** — offered only where the Platform Manifest grants hardware virtualization *and* the resource envelope has RAM headroom to spare after the security/ML plane's reservation (D4).

### D2 · Isolation is the load-bearing invariant **[vision]**

Workloads run in a **strongly isolated overlay tier that cannot touch the security plane** — this is the rule that keeps [ADR 0035] D1 a moat instead of a liability:

- Separate **cgroup slice**, **rootless**, tight **seccomp**, and a separate **netns/VRF** for containers; **hardware isolation** for VMs.
- The **security/ML plane is a distinct, protected domain** ([ADR 0038]) — no overlay workload can read its memory, share its namespaces, or attach to its eBPF maps.
- The operator's way *into the box* is an **authenticated API or restricted shell, never root bash** ([ADR 0035] D8 / D6's no-pivot-surface) — an overlay is not a shell escape hatch.

### D3 · The security/ML plane holds a hard, guaranteed reservation **[vision]**

[ADR 0035] D8 made concrete: the security/ML plane owns a **guaranteed cgroup slice the overlay cannot cross**, backed by the two-wall budget model ([ADR 0031]). A greedy workload starving the detector is a **security failure** — an attacker installing a workload to *blind the sensor* — not a UX annoyance. The resource-as-UX warnings in [ADR 0040] are **backed by this real floor**, not merely displayed: the reconciler refuses (or throttles) an overlay allocation that would breach the reserved slice.

### D4 · Lifecycle is declarative/intent, like everything else **[vision]**

Install / start / stop / remove / update a workload is **desired-state**, not an imperative click: a workload entry in `hookprobe.yaml`, reconciled by the **same reconciler** that drives the rest of the OS. This means the overlay is **GitOps-able for fleets** and **GUI-driven for a single box** ([ADR 0040] surfaces the same desired-state as a plan-as-a-diff). One reconciliation model for the OS, its services, *and* user workloads.

### D5 · The catalog is curated + signed; BYO images are quarantined **[vision]**

The workload catalog reuses the existing supply-chain posture ([ADR 0036]): catalog images are **cosign-verified + SBOM-checked before install**, and the device verifies signatures against its own trust store on pull — the App-Store-as-supply-chain-security model ([ADR 0035] D7). **Bring-your-own image is allowed but flagged UNVERIFIED** and confined to the isolated overlay tier (D2) with no path to the security plane — freedom for power users without weakening the default trust story.

---

## Consequences / risks

- **The overlay enlarges attack surface on the same box** — acceptable *only* under D2 (isolation) + D3 (reservation). Security-auditor gates any overlay implementation on both; skip either and the underlay/overlay story flips from moat to liability.
- **A VM layer is a real net-new subsystem** (D1) — the Rust-VMM-vs-libvirt call, device passthrough, and image formats are genuine scope; VM support stays capability-gated and later than container support, which reuses the existing Podman/Quadlet base.
- **Reservation enforcement must be live, not advisory** (D3) — until the reconciler actually refuses/throttles overreaching overlay allocations against the reserved slice, the "guaranteed floor" is a promise, not a control; the GUI must not claim protection the runtime doesn't yet enforce.
- **Curation is an ongoing cost** (D5) — a signed catalog needs someone vetting and signing entries; reuses the cosign/SBOM pipeline but adds an editorial/security-review burden (release-engineer + security-auditor).
- **Nothing here changes how HookProbe's own services run** — they remain rootless Podman/Quadlet ([ADR 0019]); this ADR adds a *user-workload* tier alongside them, it does not restructure the existing one.

---

## Alternatives considered

- **No overlay — pure sensor, no user workloads.** Safer, and remains the shipped *default* ([ADR 0037] passive-first; [ADR 0035] D8 alt). Rejected only as the ceiling: the underlay/overlay differentiator (D1) is worth offering, gated and opt-in, once D2/D3 make it safe.
- **A bespoke container/VM runtime.** Rejected per [ADR 0035] D2 — reinventing security-critical, CVE-prone plumbing for zero differentiation. Own the *orchestration/intent* (D4), rent the runtime.
- **libvirt/QEMU as the VM layer.** Not rejected outright — the feature/compat default. Deferred to the Rust-VMM recommendation (D1) for the edge on footprint + memory-safety grounds, with libvirt as the fallback where device breadth is required; the manifest gates which is offered per platform.
- **Uncurated "run any image" catalog.** Rejected as the *default* (it forfeits the App-Store-as-security win, D5) but preserved as the explicit, quarantined BYO path — curation is the default, freedom is opt-in and isolated.

---

## heqk migration — see [ADR 0043](0043-heqk-microkernel-substrate.md)

**Coupling: HARD — CM5-OUT-OF-SCOPE per [ADR 0044](0044-zero-linux-rpi-native-cm5.md) D1 (2026-07-25).** Podman/Quadlet/KVM/cloud-hypervisor/Firecracker/cgroups/seccomp/netns are all Linux and have no heqk-native equivalent. ⚠️ **The earlier resolution here — "the overlay runtime moves into a monitored Linux guest VM (heqk `ARCHITECTURE_BLUEPRINT` Zone 4); heqk replaces Linux-as-substrate, not Linux-as-app-host" — is SUPERSEDED.** The operator chose **path B (zero Linux on CM5, ADR 0044)**: **no Linux runs on the CM5 device, not even a guest,** so the Zone-4 VMM (ADR 0043 D5.6) and this overlay runtime are **out of scope for the CM5/rpi-native tier.** The heavy app tier there is instead **native-on-heqk (B1) or hosted off-device (B2, recommended)** — an open M6 sub-decision (ADR 0044 D3), with the on-device Wasm detection host required either way. **This ADR remains valid, unchanged, on the UEFI/amd64 tiers**, which keep Linux/Podman/Quadlet permanently. → **Track C M6** in `docs/BuildPlan.md`.
