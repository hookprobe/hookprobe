# ADR 0040 — The experience layer: UX principles, UI scope & GUI features (the "Apple of security")

**Status:** 🟡 Proposed (2026-07-17) — captures the experience-layer principles from a design session; pending operator ratification. **`docs/MissionControl.md` remains the canonical UX/dashboard spec**; this ADR records the governing *decisions* that steer it (and the one net-new surface it predates), never a re-spec. Each decision is tagged **[realized] / [partial] / [vision]** for honesty.
**Deciders:** ux-architect (author), product-steward, os-architect, security-auditor.
**Relates to:** [`docs/MissionControl.md`](../MissionControl.md) (the canonical UX spec — this ADR governs it, never duplicates it), [ADR 0037](0037-zero-touch-onboarding-flasher-provisioning.md) (onboarding / passive-first / flasher), [ADR 0035](0035-substrate-ownership-underlay-overlay.md) D7/D8 (the GUI-managed overlay + the hard-reserved security plane), [ADR 0010](0010-zero-touch-provisioning.md) (the captive portal that becomes Mission Control), [ADR 0038](0038-ai-tiers-bpf-lsm-process-trust.md) (the three AI tiers → the explanation panel / copilot), [ADR 0036](0036-verifiable-supply-chain-reproducible-bootstrappable.md) (the signed catalog's supply chain), [ADR 0025](0025-aegis-byo-llm-planner.md) (the BYO-LLM copilot).

---

## Context

The moat is not features. Windows, Linux, and Android are all *more capable* than what HookProbe ships. HookProbe wins the way Apple won consumer computing: **the simplest form-to-function experience fused with rock-solid security** — done open-source and fast. Simplicity is the moat, and the **first ten seconds are the product**.

`docs/MissionControl.md` already specifies the control plane end to end — 13 workspaces over one evidence graph + one telemetry fabric + one ⌘-K copilot, the design language, the global chrome, the cross-cutting patterns. **This ADR does not re-spec any of that.** It records the load-bearing *experience decisions* the spec must obey, and the single net-new surface (overlay/workload management) the spec predates because it emerged from the ADR 0035 underlay/overlay architecture. Where this ADR and MissionControl.md ever disagree, **the spec wins and this ADR is updated to match** (the repo's docs-win rule).

Grounding: MissionControl.md §Operating principles / §Global chrome / §Cross-cutting patterns / §Administration (Marketplace + Modules); [ADR 0037](0037-zero-touch-onboarding-flasher-provisioning.md); [ADR 0035](0035-substrate-ownership-underlay-overlay.md) D7/D8.

## Decision

### D1 · Boot & first impression — hide the machine, stay honest **[partial]**

HookProbe logo + splash from power-on; **no kernel/Linux boot spew** (the existing splash kargs) — the operator never learns they're on Linux unless they go looking. But the splash is **health-gated** (greenboot, per the existing health phase): a boot that fails the gate *says so* — **never a green logo on a broken box.** Beautiful by default, honest on failure. *(Boot splash exists today; the health-gated-splash semantics are vision.)*

### D2 · Value before configuration **[vision]**

Because detection is **passive-first** ([ADR 0037](0037-zero-touch-onboarding-flasher-provisioning.md) D4), the first authenticated screen shows **the network already mapped + the first finding** — *not* a configuration form. The industry default (configure first, get value later) is inverted: the box is useful at second zero, and configuration becomes optional refinement of something already valuable. This is a UX decision with an architectural precondition (passive-first onboarding); the two ship together or neither lands.

### D3 · Intent-driven front door, CLI as the pro basement **[partial]**

The front door reads **intent** — *"what are you protecting?"* — and generates config; the **⌘-K AI Copilot** (MissionControl.md §13; [ADR 0038](0038-ai-tiers-bpf-lsm-process-trust.md) tier-3 / [ADR 0025](0025-aegis-byo-llm-planner.md)) is the intent surface in every workspace. The classical `config interface / set / edit` vendor grammar (VyOS/Junos/Fortinet-familiar, importable so operators feel at home) is the **pro escape hatch, never the default path**. Onboarding is **three knobs max** ([ADR 0037](0037-zero-touch-onboarding-flasher-provisioning.md)): WAN (DHCP / fixed / PPPoE / wireless-SSID), LAN (SSID). VPN, segmentation, and VLANs are day-2 — they live in the Network/Gateway workspace's Pro layer (MissionControl.md §6b), never in first-run.

### D4 · UI scope — one app, many lenses, plus one net-new surface **[partial]**

Keep MissionControl.md's **"one app, many lenses"**: the SOC workspaces (Observe / Detect / Investigate / Protect / Intelligence / Automate / Administration / …) are *views* over one evidence graph + one telemetry fabric + one copilot. **This ADR neither adds nor reshuffles the SOC workspaces.** It adds exactly **one** net-new surface the spec predates — **overlay / workload management** (D5) — because [ADR 0035](0035-substrate-ownership-underlay-overlay.md) makes HookProbe the *underlay* that runs the operator's VMs/containers. Today MissionControl.md manages the security **modules** (Administration → Modules; `runtime` wasm/container/sysext) and a signed **Marketplace** catalog; it does not yet manage *user-run* workloads.

### D5 · GUI features — manage the SOC **and** the workloads (the appliance-OS-with-a-polished-GUI model, security-native) **[vision]**

The proven pattern — Synology DSM / Proxmox / TrueNAS / UniFi: an owned-ish base + **one polished GUI** that also installs/removes VMs & containers. HookProbe does it *security-native*, on the underlay/overlay split ([ADR 0035](0035-substrate-ownership-underlay-overlay.md) D1/D7):

- **Install / remove / uninstall** VMs & containers from the GUI (rootless Podman / a VM manager under the hood).
- **Resource-as-UX** — the capability/resource manifest surfaced *live*: the install dialog negotiates in plain language — *"this VM needs 2 GB, leaving your detection AI below its guaranteed floor — install anyway / throttle detection / pick a lighter workload?"* Headroom is shown, not hidden. This is the Platform Manifest (ADR 0003) + the cgroup two-wall budget rendered as UX. **Nobody in security or NAS does this.**
- **Curated + signed workload catalog** — extend the existing signed **Marketplace** (MissionControl.md §Administration) from security modules to *user workloads*: one-click **vetted** workloads, cosign/SBOM-verified ([ADR 0036](0036-verifiable-supply-chain-reproducible-bootstrappable.md)), never "install any random image." The App-Store move is **simplicity and supply-chain security in one mechanism**.
- The security/ML plane's **hard-reserved slice** ([ADR 0035](0035-substrate-ownership-underlay-overlay.md) D8) is shown and *enforced* in the UI — a workload cannot be installed past the point that starves the detector (a **security failure**, not a UX annoyance). The pro escape-hatch is an **authenticated API / restricted shell, never root bash** (preserve the no-pivot-surface, [ADR 0035](0035-substrate-ownership-underlay-overlay.md) D6).

### D6 · The MissionControl.md UX rules are restated here as GOVERNING principles (referenced, not re-spec'd) **[realized/partial]**

- **Capability-gated rendering** — render / grey-with-reason / hide, straight from the manifest (ADR 0003). The UI **never** branches on hardware.
- **Everything clickable** → drills to the evidence graph (the single source of truth).
- **AI explanation panel everywhere** — *why · confidence · evidence · model · related events*; [ADR 0038](0038-ai-tiers-bpf-lsm-process-trust.md) makes "model" concrete (which of the three AI tiers produced the number).
- **Intent bar → a plan as a diff** the reconciler applies and verifies — never a hidden mutation.
- **Mode-aware** — standalone hides fleet/tenant/business (MissionControl.md §Visibility by mode); onboarding *and* the overlay surface must honor this.
- **Less-is-more / fewer-steps** — the tie-breaker for every screen: if a step can be a sane default, it is ([ADR 0035](0035-substrate-ownership-underlay-overlay.md) D4's "only what we need," applied to the UI).

## Consequences

- **+** One coherent experience thesis that the SOC spec, the onboarding ADR (0037), and the substrate ADR (0035) all serve — the UI stops being "a dashboard" and becomes the product's moat.
- **+** The overlay surface turns "users want to run other stuff" ([ADR 0035](0035-substrate-ownership-underlay-overlay.md) D1) from a threat into a first-class, revenue-relevant GUI feature, **reusing the signed-Marketplace machinery** rather than inventing a second catalog.
- **−** D2 (value-before-config) and D5 (workload management) are the most vision-heavy, and each has a **hard architectural precondition** (passive-first onboarding; the hard-reserved slice + plane isolation of [ADR 0035](0035-substrate-ownership-underlay-overlay.md) D8) — they cannot ship as UI alone.
- **−** Resource-as-UX is only honest if the reservation is **real** ([ADR 0035](0035-substrate-ownership-underlay-overlay.md) D8): a warning without a guaranteed floor is theater *and* a security risk.
- **−** This ADR **governs but does not re-spec**. MissionControl.md stays canonical; conflicts resolve there, and this ADR is updated to match.
- **Follow-ups:** MissionControl.md gains an **overlay/workload-management** view (a workspace, or an Administration subpage) reflecting D5; the boot-splash health-gate semantics (D1) and the passive-first first-screen (D2) are net-new build items tracked against ADR 0037.

---

## heqk migration — see [ADR 0043](0043-heqk-microkernel-substrate.md)

**Coupling: NEUTRAL.** The browser dashboard "one app, many lenses," value-before-config, intent-driven experience is substrate-independent; capability-gated rendering keys off the (re-sourced) manifest. ADR 0035 D5's whole point is that the substrate swap is **invisible** to the GUI — ux-architect's job is to keep it invisible. → **Phase M6**.
