# ADR 0043 — The heqk microkernel substrate: replacing Linux on the rpi-native tier

> 🛑 **Superseded in part by [ADR 0047](0047-heqk-everywhere-on-device-mission-control.md) (2026-10-09):** heqk replaces Linux on **every** platform and Mission Control is served by heqk on the device. The two-substrate tier split no longer holds: the Linux/UEFI tier is transitional on every platform.

**Status:** 🟢 **Ratified by operator (2026-07-25)** — M0 governance gate CLEARED; heqk code may now land in the OS tree. First landing (Phase M1): heqk relocated to `os/kernel/` (own git repo, 316 commits + licensed firmware preserved), the root Cargo workspace `exclude`s it, and `os/build/make-cm5-heqk-image.sh` builds the signed CM5 substrate image by-reference. The rpi-native Linux image is untouched and keeps shipping (parallel tier, ADR 0035 D5). _Was: 🟡 Proposed (2026-07-24)._ — the **keystone** substrate-replacement ADR. Supersedes [ADR 0035](0035-substrate-ownership-underlay-overlay.md) **D3** (the "a from-scratch kernel — rejected" clause) *for the rpi-native tier only*, and reconciles [ADR 0005](0005-unified-ebpf-detection.md)'s "eBPF is the moat" thesis with a substrate-portable detection contract. Every principle below is tagged **[realized]** (already true on `~/heqk` metal), **[partial]**, or **[vision]** (design-only) — the same honesty discipline as ADR 0019/0035, because overstating heqk's readiness is the one way this ADR could do harm.
**Deciders:** os-architect (author), security-auditor (TCB threat model), product-steward (ADR 0035/0005 reconciliation), release-engineer (build + rollback), verification-engineer (gate ladder), operator (ratification — **required; not yet given**).
**Relates to:** the `~/heqk` microkernel (`ARCHITECTURE.md`, `BPF_THREAT_PLANE.md`, `ZEROCOPY_IPC_RING.md`, `CAPABILITY_MODEL.md`, `buildPlan.md §5a` — *"HEQK is meant to replace the Linux in ~/hookprobe-os"*); [ADR 0035](0035-substrate-ownership-underlay-overlay.md) (the ownership posture this executes to its D6 conclusion), [ADR 0005](0005-unified-ebpf-detection.md)/[ADR 0031](0031-dataplane-performance-strategy.md)/[ADR 0009](0009-soc-brain-edge-cloud.md) (the eBPF dataplane re-decided here), [ADR 0019](0019-bootc-debian-substrate.md) (the boot/update model heqk becomes a third variant of), [ADR 0036](0036-verifiable-supply-chain-reproducible-bootstrappable.md) (whose bootstrappable north star heqk fulfils), [ADR 0002](0002-crypto-agility-pqc.md) (the `no_std` PQC signing that ports verbatim), [ADR 0029](0029-unified-pi-fatboot-dual-kernel.md)/[ADR 0030](0030-single-kernel-convergence-bridge.md)/[ADR 0032](0032-custom-edge-kernel-btf-mainline-rp1.md) (Linux-kernel ADRs this makes **obsolete** on the rpi-native tier). Companion: `docs/architecture/MIGRATION-heqk.md` (the phased plan + end-to-end flow validation).

> **One-line thesis:** *The OS is the sensor.* HookProbe's moat is not Linux eBPF — it is the **detection rules, the signed-artifact discipline, and the evidence graph**, all of which are already substrate-portable by contract (event schema + RFC 9669 BPF ISA + WASI). heqk lets that moat run on a ~33k-LOC owned Rust TCB that mediates *every* packet, capability, and IPC event tamper-evidently — a hardware-level detection story no Linux-based competitor can replicate. This ADR makes that move governable.

---

## Context — why this ADR must exist before any heqk code lands in the OS tree

Three findings from the 2026-07-24 deep investigation force this ADR:

1. **The governance record contains a standing decision *against* this migration.** [ADR 0035](0035-substrate-ownership-underlay-overlay.md) D3 explicitly rejects "a from-scratch kernel with Linux features" (naming Redox as unsuitable) and commits to Linux *because "eBPF/XDP/PSI/cgroups … **are** HookProbe's moat."* Per `product-steward` canon, a contradiction with an accepted decision must be **flagged and re-decided via a superseding ADR, never silently resolved.** This ADR is that supersession. It does **not** delete ADR 0035 — it marks D3 superseded-for-the-rpi-native-tier and salvages D6.

2. **The eBPF-is-the-dataplane axiom is corpus-wide and, until now, unquestioned.** ADRs 0005/0009/0018/0022/0023/0031/0038 all treat XDP/TC/BPF-LSM/conntrack as the irreplaceable substrate. No ADR contemplated a non-eBPF dataplane. heqk has none of those primitives — but it has something the corpus's own portability contract already anticipated (see D2).

3. **heqk is real, metal-proven, and already targets this exact replacement.** heqk's `buildPlan.md §5a` states the goal in as many words. On CM5 silicon today heqk boots (attested, hybrid-PQC-signed, A/B-tryboot), drives the RP1 GEM NIC end-to-end, and runs its RFC 9669 BPF threat plane inline on the wire (forward `:53` / drop `:4444` proven). It is **not yet an OS** — no persistent storage, no TCP/IP stack, no process/loader model, no Wasm host — and this ADR must say so plainly so the plan sequences those gaps rather than assuming them away.

---

## The reconciliation with ADR 0005 (the crux — read this before the decision)

ADR 0005's fear is correct *about Linux eBPF*: reimplementing Linux's verifier/JIT/CO-RE/BTF/kfunc/map machinery is "hundreds of engineer-years." **heqk does not do that.** It targets the **IETF-standardized RFC 9669 BPF ISA** — a clean, OS-independent 64-bit RISC-like VM: input a packet, run pure logic, return a verdict, no kernel state. This is *already the committed HookProbe portability contract* — the sibling FreeBSD track's ADR-008 freezes exactly three cross-substrate contracts: **event schema, BPF ISA (RFC 9669), WASI** — precisely so detection logic never touches OS-specific machinery.

The consequence is decisive: **the same clang-compiled BPF bytecode threat rules run on the Linux teaser, the FreeBSD track, the QNX track, and heqk** — one rule artifact, four substrates. The detection moat was portable all along; ADR 0005 conflated *the moat* (rules + integration + evidence graph) with *one implementation of it* (Linux's in-kernel eBPF). heqk already ships this plane on metal: an RFC-9669 interpreter + a PREVAIL-style abstract-interpretation verifier (with a machine-checked reduced-width soundness harness) + a two-pass W^X arm64 JIT with constant-blinding, validated against the interpreter by an exhaustive 65536-input differential. That is *stronger* than eBPF-in-a-monolithic-kernel, because a verifier bug there is a **kernel** compromise, whereas on heqk it is contained by an independent hardware-capability wall (the sidecar can address only the packet ring).

---

## Decision

### D1 · heqk is the rpi-native substrate tier — a **third boot model**, Pi-first, not a fleet-wide big-bang **[partial]**

[ADR 0019](0019-bootc-debian-substrate.md) split the world into two boot/update models (bootc-UEFI; rpi-native OCI A/B image-sync). heqk is a **third**: bare-metal aarch64, no UEFI/bootc/composefs/systemd/OCI. It is adopted **only on the rpi-native tier (CM5 first, then Pi5/Pi4)** where the OS *already* boots by SoC-firmware direct-kernel load — the exact seam heqk drops into. **The amd64/N100/UEFI/cloud tiers stay on Linux/bootc** (heqk is aarch64-only); they are out of scope for this ADR. This is a *parallel substrate epic*, exactly the safe pattern [ADR 0035](0035-substrate-ownership-underlay-overlay.md) D5 already prescribes ("slide the minimal base in underneath invisibly, GUI-agnostic, independently gate-laddered, neither track gating the other") — heqk is simply the most radical realization of that move.

- **[realized]** The boot handoff exists: `~/heqk/cm5-boot/` produces `heqk8.img` (a drop-in for the Pi's `kernel8.img` in `config.txt`), with A/B slots (`heqk8.img`/`heqk8-b.img` via `tryboot.txt`, `ab-update.sh`), an attested `hboot` secure-boot stage, WiFi-firmware staging, and `linux-boot-backup/` retaining the Linux kernel — so **Linux⇄heqk is a reversible `config.txt` swap.**
- **[realized]** This fulfils [ADR 0030](0030-single-kernel-convergence-bridge.md) D4's own prediction verbatim: *"`config.txt`'s `kernel=` can point at a Debian `vmlinuz` exactly as at `kernel8.img`."* It now points at `heqk8.img`.

### D2 · The portability contract is load-bearing and adopted into this corpus **[partial]**

The **event schema + RFC 9669 BPF ISA + WASI** triad (the FreeBSD track's ADR-008) becomes an explicit HookProbe-OS contract, not just a sibling-track one. All detection/policy logic compiles to RFC 9669 bytecode and/or WASI components and is signed per [ADR 0016](0016-artifact-hash-signing.md). Detection authored once runs on Linux eBPF *and* heqk's BPF plane. **This is what preserves the moat across the swap** and de-risks the migration: the detection IP (ADRs 0014/0026/0016/0021/0024/0027 and the science in 0009) is *re-hosted, not re-decided*.

### D3 · The dataplane is re-implemented on heqk's native primitives, gated by rule-parity **[partial → vision]**

The Linux dataplane (ADRs 0005/0009/0018/0022/0023/0031 + the 0038 BPF-LSM leg) is re-decided against heqk's zero-copy Packet Engine (`ZEROCOPY_IPC_RING.md`) + BPF threat plane:

- **[realized]** L2 inline IDS/IPS on the GEM NIC with signed first-party rules (port blocks, ARP guard, TCP-scan flags, per-source SYN-flood rate-limit, CIDR blocklist) — heqk P8.
- **[vision]** Stateful flow accounting (replacing `nf_conntrack`), OVS-class switching/microsegmentation (replacing OpenVSwitch), and the tri-state `decide()`/`decide_l2` enforcement-separation posture ([ADR 0023](0023-enforcement-separation.md)) ported into the Packet Engine. **The Gate 0.7 enforcement-separation matrix and Gate R must pass on heqk before any promotion** — the "a legit customer connection must ALWAYS pass" invariant does not bend for the substrate.
- **Convergence gate (P8 rule-parity):** heqk must reproduce the hookprobe-os detection catalogue's verdicts, rule-for-rule, on the same test corpus, before heqk can carry a release.

### D4 · Invariants that survive the swap unchanged (the reason this is bounded) **[realized]**

- **Signing / crypto-agility ([ADR 0002](0002-crypto-agility-pqc.md), [0016](0016-artifact-hash-signing.md)):** the implemented hybrid **ML-DSA-65 + Ed25519** *module* signing is pure-Rust `no_std` RustCrypto, so the *module* verifier re-hosts onto a bare-metal kernel cleanly. But heqk's `hboot` **boot** signing is a **different PQC family** — hybrid **Ed25519 + SLH-DSA-SHA2-128s** (FIPS 205, stateless hash-based; `fips205` + `ed25519-compact`), **not** ML-DSA-65 (FIPS 204, lattice) — so the two keypairs are **non-interoperable**: the module verifier does *not* port into the boot verifier. They are **distinct-but-co-rooted** — unified by one governed custody/rotation process + a release-identity record binding boot-SVN ↔ module-signing epoch, **not** one shared key (see the [ADR 0002](0002-crypto-agility-pqc.md) heqk-coupling note + `docs/design/heqk-signing-identity.md`).
- **Platform Manifest ([ADR 0003](0003-platform-manifest-schema.md)):** the schema and "detect-once, capability-not-branch" model are substrate-independent; only the *probe* re-targets from `/proc`/`/sys`/`iw` to heqk's hardware enumeration.
- **Rollback ([ADR 0019](0019-bootc-debian-substrate.md)/[0035](0035-substrate-ownership-underlay-overlay.md) invariant):** heqk already ships A/B + watchdog tryboot on metal — rollback parity is **[realized]**, not aspirational, so heqk can satisfy the "every substrate change preserves rollback" release rule.
- **Evidence graph, QSecBit, AEGIS, RBAC, UX (ADRs 0011/0013/0008/0028/0040, and the ~47k LOC Rust brain):** substrate-portable by design; re-hosted, not re-decided. QSecBit gains a stronger source — heqk streams capability/IPC/scheduling events from inside the TCB ("the OS is the sensor").

### D5 · Honest gap list — what heqk must **build**, not port (sequenced in the plan) **[vision]**

The migration's real bill, ranked (see `docs/architecture/MIGRATION-heqk.md` for phasing):
1. **Capability enforcement wired to mapping/IPC/IRQ** + real sync IPC (heqk remediation R1) — today the cap model is a data structure, not yet the mechanism.
2. **Block driver (eMMC/SDHCI) + minimal filesystem + on-device A/B update transport** — heqk has *no* post-boot persistent storage today; without it the evidence graph, QSecBit history, and OTA cannot exist.
3. **Userspace TCP/IP stack (smoltcp-class) + TLS** — for the MSSP link, update fetch, DNS, NTP. heqk today cannot open a connection to anything.
4. **Process/loader ABI (ELF loader, root task, real syscall surface)** — replacing the 7 demo syscalls; the largest single gap.
5. **A Wasm/WASI host on heqk** (a `no_std`-capable runtime, or the `.cwasm` AOT path from [ADR 0017](0017-authenticated-aot-cache.md)) — the module model needs it.
6. **The overlay runtime ([ADR 0041](0041-container-vm-overlay-management.md)) via a monitored Linux guest VM** — per heqk `ARCHITECTURE_BLUEPRINT.md` Zone 4, containers/heavy stateful services keep running in a Linux *guest* that heqk supervises. **heqk replaces Linux-as-substrate, not Linux-as-app-host** — an explicit, deliberate scoping that keeps the app tier shippable while the underlay hardens.
7. **WiFi association + data path** (heqk P10 D/E) and the **RTL8111 WAN datapath** (link trained, datapath pending); AP-control + monitor-capture surfaces for ADRs 0034/0042.

### D6 · This *executes ADR 0035 D6*, it does not contradict ADR 0035's spirit **[realized framing]**

ADR 0035 D3 (Linux is mandatory) and D6 (the "Talos-radical north star": no shell, no SSH, no libc userland, migrate eBPF loaders to pure-Rust `aya`, "no pivot surface") point in opposite directions. **heqk resolves that internal tension in D6's favour.** The corpus already contains the seed of its own substrate replacement; this ADR frames the migration as *"executing ADR 0035 D6 to its logical conclusion,"* not a reversal — and inherits D6/D4's "attack-surface starvation / no landing zone" thesis as a security *argument for* heqk against automated/AI-scaled attackers. It likewise fulfils [ADR 0036](0036-verifiable-supply-chain-reproducible-bootstrappable.md): a ~33k-LOC Rust kernel is far more reproducible/bootstrappable than a 1.3 GB Debian image, and it deletes the kernel-BTF/`pahole` reproducibility landmine that ADR flags.

### D7 · The unbuild is governed like a build, run in reverse **[vision]**

Removing Linux from the rpi-native tier is a `retirement-agent`-driven **unbuild**, not a silent delete: each Debian/Linux component (base image, stock+edge kernels, libbpf/glibc, out-of-tree drivers, systemd/podman) is enumerated as a batched `retirement` event ranked by confidence + blast-radius; `product-steward` **marks supersession (never deletes — superseded things get marked)**; `code-developer` performs approved removals; `verification-engineer` proves the gates (0.7 separation matrix, Gate R) still pass on heqk; `release-engineer` preserves rollback. Every teardown is **Amber-proposed, gate-verified, operator-approved** (contract C9). ADRs 0029/0030/0032 are marked **obsolete/superseded** by this ADR on the rpi-native tier (no Linux kernel to fat-boot, converge, or BTF-recompile) — they remain valid history and remain in force on the UEFI tier's kernel story where applicable.

---

## Consequences / risks

- **Two substrates in flight on arm64** (Linux/bootc on UEFI-arm64 + heqk on rpi-native) plus the amd64 Linux tier. Mitigated by D2's portability contract — the divergence is confined to the boot substrate and the dataplane *implementation*, not the detection logic, the manifest, the signing, or the UX.
- **heqk is 🟡/⬜ on most of D5.** `market-intelligence` gates any external claim: heqk is a *sensor kernel* today, not a shippable OS — the "own the kernel" positioning must not over-claim (it is a roadmap, honestly SBOM'd, exactly as ADR 0035 D5 requires of the minimal-base track).
- **The verifier is a proof engine; a bug is a sandbox escape.** Held to v1 = **signed first-party rules only, no open verifier** (the entire third-party-rule attack surface deferred to v2), and contained by the independent capability wall. This is heqk's own drafted sequencing and it is sound.
- **The overlay (D5.6) enlarges attack surface on the same box** — permitted only under ADR 0035 D8's hard cgroup-equivalent reservation + strong plane isolation, now enforced by heqk capability spaces rather than cgroups/seccomp. `security-auditor` gates any overlay work.
- **BCM2712 has no per-device IOMMU** — heqk's "bounded DMA" is ceiling-containment + cap-checked descriptor addresses, not true per-device isolation; Spectre on the A76 is unmitigated → the **single-tenant edge doctrine** is a hard scoping (no untrusted multi-tenant VMs on the heqk tier). Documented, not hidden.
- **Nothing regresses today's shipping OS.** The Linux rpi-native image (M1: full SOC on Pi4+CM5) keeps shipping; heqk slides in underneath on its own gate ladder and is promoted only when it passes P8 rule-parity + Gate 0.7 + Gate R on metal.

---

## Alternatives considered

- **Stay on Linux, execute ADR 0035 D5 (Buildroot/Yocto minimal base) only.** Not rejected — it remains the *near-term* minimization path and the amd64/UEFI answer. Rejected only as the rpi-native *ceiling*: it still ships a general-purpose Linux kernel and its CVE/attack surface, and forgoes the "OS is the sensor" TCB story heqk uniquely enables.
- **Big-bang: replace Linux on every tier at once.** Rejected: heqk is aarch64-only, most of D5 is unbuilt, and the app tier (0041) has no heqk runtime yet. Pi-first + Linux-guest-app-host is the bounded, reversible path.
- **Port Linux eBPF/XDP to heqk.** Rejected for exactly ADR 0005/0035's stated reason (hundreds of engineer-years) — which is why D2 targets the clean RFC 9669 ISA instead, per the existing portability contract.
- **Keep heqk as a separate product, never merge into HookProbe OS.** Rejected: heqk's own `buildPlan.md §5a` sets the replacement as its purpose, the detection IP is shared, and running them as one governed lifecycle (Product Cortex) is the whole point of the migration mandate.

---

## Sources / evidence (in-tree)

- `~/heqk/BPF_THREAT_PLANE.md` (RFC 9669 VM/JIT/verifier; the eBPF-moat reconciliation), `ZEROCOPY_IPC_RING.md`, `CAPABILITY_MODEL.md`, `ARCHITECTURE.md`/`ARCHITECTURE_BLUEPRINT.md` (Zone 4 Linux-guest app tier), `HEQK_KERNEL_DOSSIER.md`, `HEQK_REMEDIATION_PLAN.md` (R1 gaps), `buildPlan.md §5a` (the replacement mandate), `cm5-boot/` (the `heqk8.img`/A-B/`hboot` boot seam, metal-proven), `SECURITY_AUDIT.md`.
- This tree: [ADR 0035](0035-substrate-ownership-underlay-overlay.md) D3/D5/D6/D8, [ADR 0005](0005-unified-ebpf-detection.md), [ADR 0019](0019-bootc-debian-substrate.md), [ADR 0030](0030-single-kernel-convergence-bridge.md) D4, [ADR 0002](0002-crypto-agility-pqc.md), [ADR 0036](0036-verifiable-supply-chain-reproducible-bootstrappable.md); `docs/roadmap/BuildPlan.md` M1 (2026-07-20); `docs/architecture/MIGRATION-heqk.md` (phased plan + flow validation).
