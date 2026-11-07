# ADR 0035 — HookProbe Linux: substrate ownership & the underlay/overlay architecture

**Status:** 🟡 Proposed (2026-07-17) — a design-session **posture**, not an implemented change. Records the strategic architecture the operator and Director settled during the "HookProbe Linux" design conversation: what HookProbe *owns* vs *rents*, how far the base should be minimized, and how user workloads relate to the security plane. Each principle below is tagged **[realized]** (already true in-repo), **[partial]**, or **[vision]** (roadmap, not built) so this ADR never overstates the tree — the same honesty discipline as [ADR 0019](0019-bootc-debian-substrate.md).
**Deciders:** os-architect (author), security-auditor, release-engineer, product-steward.
**Relates to:** [ADR 0019](0019-bootc-debian-substrate.md) (the bootc/Debian substrate this refines "upward" into an ownership posture), [ADR 0005](0005-unified-ebpf-detection.md) (the eBPF/XDP moat that dictates the base must be Linux), [ADR 0031](0031-dataplane-performance-strategy.md) (the cgroup two-wall budget model D7 relies on), [ADR 0036](0036-verifiable-supply-chain-reproducible-bootstrappable.md) (the verifiable-build chain that makes an *owned* base trustworthy), [ADR 0037](0037-zero-touch-onboarding-flasher-provisioning.md) (how the overlay/workload UX is delivered), [ADR 0038](0038-ai-tiers-bpf-lsm-process-trust.md) (what runs on the underlay). `docs/architecture/Readme.md` Pillar 1, CLAUDE.md decision #1.

This ADR does not relitigate [ADR 0019]'s boot-model split. It sits one level above it: *given* the OS is a signed OCI image on a Debian base today, **how much of that base should HookProbe own, how minimal should it get, and how do customer workloads fit without dissolving the security guarantee?**

---

## Context — measured reality (2026-07-16, this box)

The image was measured byte-for-byte (`debugfs rdump` on the built Pi image): **~89% Debian, ~4% HookProbe's own code**, and **~40% is provable dead weight** — a 328 MB stock Debian kernel that never boots, plus ~110 MB of firmware for radios the hardware doesn't have. The dependency surface reduces to **four commodity Debian dependencies**: glibc (forced only by the libbpf/CO-RE loaders + rusqlite-bundled), systemd (deep but *protocol*-coupled, not `libsystemd`-linked), bootc/OSTree/composefs (UEFI tier only), and apt's firmware/kernel breadth. Everything that differentiates — the self-compiled edge kernel ([ADR 0032]), the Wasm detection modules, the static-Rust binaries, the reconciler/intent model, the Platform Manifest — is **already owned and already distro-portable**.

The insight this ADR crystallizes: **a general-purpose distro is, by definition, noise for a single-purpose appliance.** The question is not "Debian or not" but "what do we actually *need*, and what do we own vs rent."

---

## Decision

### D1 · The underlay/overlay architecture **[vision]**

HookProbe OS is the **secure underlay**. User VMs and containers are an **overlay** that runs *on* it, and the underlay secures the overlay **by construction** — it sits underneath, inspecting every packet and syscall by default. This reframes "users want to run other workloads on the box" from a threat into the core positioning: *run your workloads on HookProbe and they are secured the moment they boot, because HookProbe is the ground they stand on.* No bolt-on security product can make that claim.

### D2 · Own the differentiation, rent the commodity **[realized in principle]**

The durable ownership line, matching how FreeBSD owns its base yet imports third-party into `contrib/`, and how Apple built XNU on Mach+BSD and owned everything *above* a kernel it did not write:

- **OWN:** the kernel *config + patches + release cadence* ([ADR 0032]), the eBPF/XDP/Wasm detection+enforcement logic ([ADR 0005]), the reconciler/intent model, the Platform Manifest, the operator experience.
- **RENT (never rewrite):** libc, init, coreutils, the DHCP/PPPoE client, routing, the container runtime. These are security-critical, CVE-prone, and carry **zero** differentiation — reimplementing a DHCP client only manufactures new CVEs. Own the *orchestration/intent* over these (the reconciler already generates nftables/OVS/WireGuard from intent); borrow the battle-tested implementations underneath.

### D3 · Rejected alternatives, recorded with reasons

- **A BSD base — rejected.** BSD is a genuine coherent monolith, but it has **no eBPF/XDP/PSI/cgroups** — the exact Linux-kernel primitives that *are* HookProbe's moat. macOS (BSD-lineage) and classic Juniper Junos (FreeBSD) do security the pf/DTrace way *because* they have no eBPF — and **Junos Evolved migrated to Linux** for programmability. Following BSD means rewriting the dataplane in netmap/pf and throwing away the moat. The coherent-monolith appeal is reachable on Linux via Buildroot/Yocto (D5), eBPF intact.
- **A from-scratch kernel with Linux features — rejected.** Reimplementing the eBPF verifier/JIT, XDP, PSI, cgroups, BTF, drivers, and the syscall ABI is hundreds of engineer-years rebuilding what Linux gives free; the closest "Rust BSD-like," Redox, has no eBPF and no SoC support. It fails the "with all Linux features" bar by definition. — ⛔ **SUPERSEDED on the rpi-native tier by [ADR 0043](0043-heqk-microkernel-substrate.md) (2026-07-24) + [ADR 0044](0044-zero-linux-rpi-native-cm5.md) (2026-07-25).** This bullet's premise (eBPF is the irreplaceable moat) is reconciled by ADR 0043 D2: the moat is the *detection rules + evidence graph + signing*, portable via the **RFC 9669 BPF ISA**, not Linux's in-kernel eBPF — so heqk (a from-scratch Rust aarch64 microkernel) does **not** reimplement the verifier/JIT/CO-RE/BTF machinery. Rejection stands on **UEFI/amd64**; overturned on **rpi-native/CM5**. Retained as history; see the Coupling note at the end of this ADR and Track C in `docs/roadmap/BuildPlan.md`.
- **Replacing systemd / podman — rejected.** Maximum cost, ≈zero differentiation. systemd is **protocol-coupled, not `libsystemd`-linked** (the tree carries a hand-rolled zero-dependency `sd_notify` client), and the reconciler is *already* the launchd-equivalent orchestration layer above it. Podman/Quadlet is portable and fine. The Apple move is to own the layer *above* the init, which is done — not to rewrite the init.

### D4 · Minimal — "only what we need" — via a durable filter **[vision]**

The base is minimized by a standing rule, not a one-time diet:

> **A component earns its place only if it is on the boot → detect → enforce → report critical path, OR it is a capability the Platform Manifest actually grants on *this* hardware. Everything else is noise.**

Run through this filter, the NEED set is short (stripped kernel, one libc, one init, the product's own binaries + Wasm + eBPF, a tiny bring-up userland) and the NOISE set is most of the 89% (apt/dpkg at runtime, perl/python, full coreutils, docs/locales, general firmware, the second kernel — and, radically, the shell and SSH themselves). **The size win *is* a security win:** every package not shipped is a CVE that cannot apply and an exploit primitive that is not present. Minimal is a *security posture*, not just a footprint optimization — and it directly serves the edge-ML mission by freeing CPU/RAM for on-device inference ([ADR 0038]).

### D5 · The owned-minimal path is Buildroot/Yocto — decoupled from the UX **[vision]**

Owning "only what we need" sustainably means a **deterministic, purpose-built builder (Buildroot/Yocto), not curated-Debian-forever and not LFS-from-scratch.** Buildroot/Yocto give a minimal, reproducible, self-owned image *while an upstream still tracks package versions and CVEs* — "only what we need" without becoming a from-scratch distro-security team (which LFS would make us). This is the same bet as verifiable builds ([ADR 0036]): a deterministic builder delivers minimal + owned + reproducible in one move.

**Critically, this is decoupled from the experience.** Proxmox, TrueNAS SCALE, and Ubiquiti UniFi all deliver a beloved GUI appliance *on a Debian base* — the GUI, not the substrate, is the UX moat. So: ship the Apple-grade experience on **curated-Debian now**, and slide the Buildroot-minimal base in underneath **later, invisibly** (the user only ever sees the GUI). Two independent tracks; neither gates the other. This keeps velocity while preserving the endgame.

### D6 · The Talos-radical north star **[vision]**

The limit of "only what we need" is nearly all HookProbe already: **kernel (ours) + this-hardware firmware + a handful of static-Rust binaries + Wasm modules + eBPF programs — no shell, no SSH, no general libc userland.** The one remaining cord to a glibc userland is the eBPF loaders (libbpf-rs → C libbpf → glibc); migrating them to **aya** (pure-Rust eBPF, CO-RE and all, no libbpf/glibc) lets the loaders go static-musl and removes it. The payoff is the strongest anti-attacker posture there is — *no pivot surface* — which matters most against automated/AI-scaled attackers who need a landing zone and persistence ([ADR 0038]).

### D7 · The overlay is GUI-managed, and its catalog is curated + signed **[vision]**

One GUI (Mission Control) manages both the **SOC** and the **workloads** — install/remove/inspect VMs and containers — with **live resource/capability awareness**: the Platform Manifest surfaced as UX (e.g. *"this VM would leave your detection AI below its guaranteed floor — throttle, pick lighter, or proceed?"*). The workload catalog is **curated + signed** (an App-Store model) — which is simultaneously the *simplicity* win (one-click vetted workloads) and the *supply-chain-security* win, reusing the existing cosign/SBOM posture. Curation-as-security is exactly Apple's App Store lesson.

### D8 · Two hard invariants that keep the overlay from dissolving the underlay **[vision]**

Running arbitrary workloads beside a hardened sensor is only safe under two non-negotiable rules:

1. **The security/ML plane gets a hard-reserved cgroup slice the overlay cannot cross.** A greedy container starving the detector is a *security failure* (an attacker installs a workload to blind the sensor), not a UX annoyance. Backed by the cgroup two-wall budget model ([ADR 0031]) — the GUI's resource warning must be enforced by a guaranteed floor, not merely displayed.
2. **Strong isolation between the security plane and the workload plane** — workloads run in isolated VMs / tightly-sandboxed rootless podman that cannot touch the security engine, and the pro "escape hatch" is an **authenticated API or restricted shell, never root bash** (preserving D6's no-pivot-surface).

---

## Consequences / risks

- **Two build tracks in flight** (curated-Debian experience now, Buildroot-minimal later). Mitigated by D5's decoupling — the GUI/experience is substrate-agnostic, so the base swap is invisible to users and independently gated.
- **The Talos-radical end-state (D6) depends on the aya migration** landing without regressing CO-RE/BTF loading; until then a glibc userland remains, and the "no libc userland" claim is aspirational.
- **The overlay (D1/D7) enlarges attack surface on the same box** — acceptable *only* with D8's hard reservation + isolation; if either is skipped, the underlay/overlay story becomes a liability instead of a moat. Security-auditor gates any overlay work on D8.
- **Owning a minimal base (D5) is a real maintenance burden** — bounded by leaning on the Buildroot/Yocto upstream for CVE currency rather than hand-rolling, but release-engineer owns the bump cadence, exactly as [ADR 0019] D2 already notes for the self-built bootc base.
- **Nothing here regresses today's boot.** This is posture; the curated-Debian image keeps shipping while the minimal base and the overlay UX are built independently and gate-laddered.

---

## Alternatives considered

- **Stay on general-purpose Debian indefinitely, hide it behind the GUI (the Proxmox model).** Not rejected — it is explicitly D5's *first* phase. Rejected only as the *permanent* end-state: it leaves ~40% dead weight and a larger CVE/attack surface than a single-purpose appliance needs. The GUI ships on it; the minimal base replaces it underneath later.
- **Go straight to a from-scratch / LFS distro for maximum ownership.** Rejected: it inherits perpetual CVE-backport labor for the least-differentiating layers (libc/init/coreutils), the exact trap D2 names. Buildroot/Yocto captures the ownership/minimalism win while keeping upstream CVE leverage.
- **Keep workloads off the box entirely (pure sensor, no overlay).** Viable and *safer*, and remains the shipped default posture ([ADR 0037] passive-first). Rejected as the *ceiling*: the underlay/overlay story (D1) is a differentiator no bolt-on competitor can match, and D8 makes it safe — so the overlay is offered, gated, opt-in, never forced.

---

## heqk migration — see [ADR 0043](0043-heqk-microkernel-substrate.md)

**Coupling: HARD — the central conflict; D3 superseded by ADR 0043.** This ADR's D3 ("a from-scratch kernel — rejected"; "the base must be Linux because eBPF/XDP/PSI/cgroups are the moat") is the exact thesis the migration overturns *on the rpi-native tier* — superseded by ADR 0043, which reconciles the moat via the RFC 9669 portability contract. **D6 (the Talos-radical north star: no shell/SSH/libc, aya pure-Rust, "no pivot surface") is salvaged as the migration's philosophical anchor** — heqk executes D6 to its logical conclusion. D5's "slide the minimal base in underneath invisibly" is *how* heqk lands; D8's overlay isolation is enforced by heqk capability spaces instead of cgroups/seccomp. → **Phases M0/M6/M7**.
