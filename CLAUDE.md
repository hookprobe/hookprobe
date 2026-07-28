# HookProbe OS — Project Guide (V2: "One System")

> **One operating system. Every platform. Hardware only unlocks capabilities.**
> HookProbe OS is an AI-native security operating system. V2's defining idea is **one system**: a single OS, one data model, one evidence graph, one AI — with every named component being a *module/lens* on the same substrate, never a separate product.

**Positioning sentence (use everywhere):** *HookProbe OS is the operating system. SOC is its default workspace. Hardware only unlocks capabilities.*

The canonical architecture lives in:
- `docs/Readme.md` — the OS architecture (bootc, Wasm, intent, supply chain, PQC).
- `docs/MissionControl.md` — **the target dashboard/UI spec.** This is what Mission Control should look like; all UI work adapts to it (workspaces, evidence graph, telemetry fabric, route map).

When these docs and this file disagree, **the docs win** — update this file to match.

---

## The three load-bearing decisions

> ⚠️ **Substrate pivot (ADR 0043 + ADR 0044, ratified 2026-07-25).** HookProbe OS now runs on **two substrates**, and decisions #1/#2 below are **tier-scoped, not universal — "don't relitigate" applies only to the Linux/UEFI tier.** On the **UEFI + amd64/N100/cloud** tier: bootc/Debian, Wasm+Podman, exactly as written (canonical + permanent). On the **rpi-native tier (CM5 only, ADR 0044 D2)**: Linux is being **replaced entirely by the heqk microkernel** — a from-scratch Rust aarch64 capability microkernel as substrate **and** app-host (**zero Linux on CM5, not even a guest**, ADR 0044 D1). See `docs/BuildPlan.md` **Track C** and `docs/MIGRATION-heqk.md`. **Do not read #1/#2 as universal.**

1. **The OS is a Containerfile — on the Linux/UEFI tier.** One signed OCI image is the source of truth; build with `podman build`, ship to a registry. The *update mechanism* splits by boot model (**ADR 0019**): on **UEFI** platforms (amd64/N100/VM/cloud, arm64-virt) bootc performs `upgrade`/`rollback` against a self-built Debian-bootc base; on **Raspberry-Pi-native Linux** an OCI-derived **A/B image-sync** delivers equivalent transactional update + rollback — bootc architecturally cannot manage the Pi's MBR/`config.txt`/SoC-firmware boot. Base distro **Debian/Ubuntu**; composefs-native backend pinned + tracked (experimental). mkosi/make-pi4 remains the factory first-flash. **⚠️ Superseded on the CM5/rpi-native tier (ADR 0043/0044):** heqk is a **third boot model** — bare-metal aarch64, `config.txt kernel=heqk8.img`, A/B tryboot + `hboot` — **no bootc/OCI/composefs/systemd/Debian.** *(Linux/UEFI: refined + accepted, not reopened. CM5: replaced by heqk.)*
2. **Logic & detection are Wasm components (WASI 0.2/0.3, WIT).** One `.wasm` runs on arm64/amd64/riscv64; capability-sandboxed by default; ~1–5 ms cold start; inference via WASI-NN (no GPU drivers). Heavy stateful services run as **rootless Podman containers (Quadlet)**; host-integral pieces (OVS, kernel bits) layer into the bootc image (`sysext`). **⚠️ On the CM5/heqk tier (ADR 0044):** the on-device Wasm host is a build target (Track C M5); detection rules are portable via the **RFC 9669 BPF ISA** (ADR 0043 D2, not Linux eBPF); and heavy services run **native-on-heqk or hosted off-device (ADR 0044 D3) — NOT in Podman/Quadlet and NOT in a Linux guest.**
3. **Operated by intent, not configured.** The operator declares *what they want*; **AEGIS** reconciles it. Config is a generated artifact, never the interface.

## Architecture — three layers

```
HookProbe OS (experience)  — operated by INTENT · Mission Control · AEGIS
LOGIC: Wasm (WASI)  +  SERVICES: Podman (rootless, Quadlet)   [Linux/UEFI tier]
        Wasm host on heqk  +  services native-on-heqk / off-device [CM5/heqk tier, ADR 0044]
SUBSTRATE:  UEFI/amd64 → HookProbe Base (Containerfile · bootc · Debian)
            CM5/rpi-native → heqk microkernel (bare-metal aarch64, zero Linux — ADR 0043/0044)
Hardware: Pi 5 · RK3588 · N100 · VM · Cloud · HP appliances   |   CM5 (heqk)
```
Everything above "Substrate" is identical **from the operator's view** on every platform (capability-gated off the Platform Manifest). Hardware differences are absorbed by the Base image + the **Platform Manifest**; on CM5 the substrate itself differs (heqk), but the swap is designed to be **invisible** to Mission Control (ADR 0044 M6).

## Core invariants

- **Detect once, query forever.** Bootstrap probes hardware *once* at first boot and writes the signed **Platform Manifest** (`/var/lib/hookprobe/manifest.json`, schema 2). Nothing else re-probes hardware. The manifest carries capabilities **and** crypto posture.
- **Capabilities, not branches.** Code never asks "is this a Pi?" — it asks "is `wifi7`/`openvswitch`/`edge_ai` granted?" The UI renders, greys-with-reason, or hides purely from the manifest.
- **Standalone by default.** A device runs a full local SOC with **no account, no cloud, air-gapped**. Cloud/account is an *additive* enrollment layer (MSSP or self-hosted control plane), never a precondition. Device identity (TPM-bound keypair) exists before any account.
- **AEGIS = deterministic reconciler (always local, no model needed) + AI planner (BYO LLM, assistive, never in the enforcement path).** Model is the operator's choice: any OpenAI-compatible endpoint, or local Ollama/llama.cpp/vLLM.
- **Bounded & honest retention.** Local retention is capped by storage and the real window is shown to the operator; tiered (pcap → events → alerts/evidence); offload to SIEM/object store to exceed local capacity. Data lives on a persistent partition separate from the immutable rootfs.
- **Data plane out-of-band by default**, inline opt-in; per-interface fail-open (default) / fail-closed (policy choice).
- **Enforcement separation — observe by default; drop only a genuine attack or resource-exhaustion event (ADR 0023).** A legitimate customer connection must ALWAYS pass. Detectors emit alerts; a single `decide()` enforces, graduated by confidence into a tri-state verdict (`Observed` → `RateLimit` (bounded, self-reverting) → `Quarantine`/`FrameDrop` (confirmed, ADR 0018)), plus a management-safety `Allowlisted` floor. The **only** inline drops keyed on suspicion-free facts are: a confirmed port scan, a truly-malformed frame, a real L1/L2 flood, and the new **resource-shed** (per-source new-conn cap + conntrack-saturation guard + PSI CPU/mem pressure — self-reverting, keyed on RESOURCE REALITY, never identity). Beaconing/lateral/UDP-slow-ICMP-scan/host-EDR are observe-only by construction. Enforced by the release-blocking `0.7-separation-matrix` gate (33 rows: 22 verdict-level + 11 frame-level, legit-passes + attacks-caught, both directions).
- **Trust nothing unsigned.** OS images, Wasm modules, and manifests are cosign-signed; SBOM + CBOM per image; SLSA provenance. **Crypto-agile / PQC-ready** posture (per ADR 0002): **implemented today** — hybrid **ML-DSA-65 + Ed25519** module signing (fail-closed, no downgrade) and a real hash-agility seam; the CBOM reports implemented-vs-roadmap honestly. **Roadmap** — ML-KEM KEX and LMS/XMSS boot signing (no code yet; marked roadmap, never fabricated). Image signing is cosign-keyless ECDSA-P256 today.

## Components (all modules on one base — none is a separate product)

| Component | Role | Mission Control workspace |
|---|---|---|
| **Senzorium** | Observation: capture, flows, host/eBPF telemetry, log ingest → common event schema | **Observe** |
| **NAPSE** | Network IDS/IPS sensor | **Detect** |
| **AEGIS** | Deterministic reconciler + pluggable AI planner | **Investigate** (and the intent layer everywhere) |
| **HYDRA** | Threat-intelligence & enrichment pipeline (IOC/STIX/TAXII/MISP, CVE, anomaly, predictor — the production 11-service `ids-hydra-*` stack) | **Intelligence** |
| **QSECBIT** | Composite cyber-resilience score (Mahalanobis + ML attack prob. + entropy) | Security Score / the **Organism Status** orb |
| **Platform Manifest** | Signed source of truth (capabilities, crypto posture, modules) | — |
| **Supervisor** | Resolves module `requires`/`grants`/`provides` vs manifest; reconciles modules; *is* the Marketplace backend | — |
| **Mission Control** | Manifest-driven operator UX | — |

> ⚠️ **Mapping corrected against production (2026-06-29; see `docs/v2-reconciliation.md`).** **HYDRA = threat-intelligence / enrichment** → the **Intelligence** workspace (confirmed 4× on real devices: `fortress-ids`, `guardian-hydra-lite "Threat Feed Sync"`, and the cloud's 11-service `ids-hydra-*` pipeline). The **Automate** workspace is a *net-new* automation/SOAR concern — no V1 "HYDRA automation" engine exists; seed it from the proven reconcilers (`sdn_autopilot`/`organism_selfheal`/`nac-policy-sync`) under AEGIS. The earlier "HYDRA = automation" resolution was wrong against reality and is reverted.

## Mission Control — one app, many lenses

One platform, one data model, one **evidence graph** (`Device → Interface → Packet → Connection → Session → Application → User → … → Threat → Incident → Response → Report`), one **Telemetry Fabric** (the elevated "logs"), one omnipresent **AI Copilot** (`⌘/Ctrl-K`). Workspaces are *views* over the shared kernel + core services, not separate apps.

Workspaces: Mission Control · Workspace · Observe · Detect · Investigate · Protect · Automate · Intelligence · Customers · Business · Knowledge · Administration · AI Copilot.

Lifecycle maps onto workspaces: **Build/Deploy** → Administration (Builder, Images, Modules, Provisioning, Enrollment, Edge Nodes); **Run** → Mission Control/Observe/Detect/Investigate/Protect/Automate/Intelligence; **Manage** → Administration/Customers/Business/Knowledge.

UX rules: capability-gated rendering · everything clickable (drills to evidence graph) · AI explanation panel everywhere (*why · confidence · evidence · model · related events*) · intent bar produces a **plan as a diff** the reconciler applies & verifies · mode-aware (standalone hides fleet/tenant/business). Route map is in `docs/MissionControl.md` appendix.

## Deployment modes

| Mode | Account? | For |
|---|---|---|
| **Standalone** (default) | none | Community, single-site, air-gap, sovereignty |
| **Cloud-linked (MSSP)** | `mssp.hookprobe.com` tenant | Fleets, multi-tenant, billing |
| **Self-hosted control plane** | your own endpoint | Enterprise/gov fleet ops without our cloud |

**Recursive multi-tenancy** (AWS-Organizations-style): `HookProbe → MSSP → Customer → Customer → …` by tenant inheritance, unlimited depth, no code changes. Hard per-tenant isolation (segregated data, scoped RBAC, separate keys). **Fleet** = pull-based GitOps; desired state (`hookprobe.yaml`) in Git; drift self-heal; staged rollout rings (canary → ring → fleet, health-gated). **Business model: open-core** — base OS + standalone SOC free under **GNU AGPL-3.0**; offering-as-a-service / the cloud/account layer requires a **commercial license** (dual-license, AGPL-3.0 + Commercial). See `LICENSING.md`.

## Naming

Software name is **always HookProbe OS**. *Guardian / Fortress / Virtual / Cloud* are marketing SKU names (hardware/target), never separate software.

## Repository layout (target; repo is currently docs-only)

```
base/ bootstrap/ supervisor/ manifest/ modules/{napse,hydra,ovs,…}
builder/ ui/ fleet/ security/ platforms/{rpi5.yaml,rk3588.yaml,edge-pro.yaml}
```
**The design test:** adding new hardware = *one file* in `platforms/`. No UI, installer, or API change.

---

## Project agents (`.claude/agents/`) — the Product Cortex, Ring 1

Eleven personas drive the V2 lifecycle (**ADR 0011 — Product Cortex**: agentic PLM as a lens on the evidence graph; roster **capped at 11 (ADR 0013)** — the requirement→retirement extension; new roles need an ADR). Delegate by role:
- **`product-steward`** — PLM brain: `docs/BuildPlan.md` status truth, ADR hygiene, cross-doc reconciliation, traceability, roadmap reviews. Canon: `docs/BuildPlan.md` + `docs/adr/0011-product-cortex.md`.
- **`ux-architect`** — interaction design, flows, wireframes, navigation, "fewer-steps" simplification, competitive UX positioning. Canon: `docs/MissionControl.md` (the target dashboard).
- **`os-architect`** — OS/RTOS architecture: bootc image, Wasm module model, Platform Manifest, supervisor/reconciler, data plane, retention, supply chain/PQC, fleet. Canon: `docs/Readme.md`.
- **`code-developer`** — implements Mission Control + modules; benchmarks the stack before committing (see below).
- **`security-auditor`** — adversarial reviews: threat models, supply chain (cosign/SBOM/CBOM/SLSA), PQC posture, eBPF/Wasm privilege boundaries, RBAC/encryption.
- **`verification-engineer`** — the gate ladder (tests → smoketest → QEMU boots → greenboot → hardware gates), CI, benchmark honesty.
- **`release-engineer`** — `builder/` pipeline, signing/trust store, image variants, rollout rings, changelog discipline.
- **`telemetry-analyst`** — field/test evidence → lifecycle feedback: perf regressions, capability-tier truth per platform, evidence-graph queries (read-only on live devices).
- **`ideation-scout`** — upstream signal → candidate requirements: market/CVE/MITRE-ATT&CK/competitor/GitHub-issue scanning, proposes `idea`/`requirement` nodes (ADR 0013 D3).
- **`market-intelligence`** — positioning & competitive tracking, the hookprobe.com narrative; owns `docs/product-cortex-competitive.md` (ADR 0013 D3/D5).
- **`retirement-agent`** — downstream EOL: finds dead APIs/features/stale rules/unsupported hardware → proposes `retirement` events (ADR 0013 D3).

Cortex governance (all agents): **AI proposes, the deterministic gates enforce** (contract C9). Green = docs/analysis; Amber = code/ADR/roadmap changes (operator reviews); Red = commits, releases, flashing — never autonomous.

## Open decision — the application stack

Mission Control's stack is **not yet locked.** Starting hypothesis: **Astro + React**. Constraints: dense real-time SOC dashboard (live telemetry, websockets/SSE) that must run on **edge hardware (Pi 5 / RK3588 / N100)** *and* a content-heavy CMS/SEO surface. `code-developer` is to benchmark frontend (React vs Solid/Svelte/Qwik vs Astro islands) and edge backend (Rust/Axum vs Go vs Node) and record an ADR. Bias: small edge footprint, fast live updates, alignment with the OS's existing Rust/Wasm posture.

## Design north star (V2)

**Customer-first, less-is-more, fewer steps.** Position as a **"SOC on a budget" that is ahead of FortiSOC / Microsoft Sentinel / Defender XDR** — zero-setup SOC from first boot, intent/natural-language instead of query languages, one unified console instead of many, capability-gated simplicity. `docs/MissionControl.md` is the guiding spec.

## Working conventions for this repo

- Treat `docs/Readme.md` + `docs/MissionControl.md` as canonical; keep them and this file in sync, and flag (don't silently resolve) any new contradictions.
- Capability-gate, don't hardware-branch. Manifest is the single source of truth.
- Default to `runtime: wasm` for detection/policy/enrichment; `container` only for heavy stateful services; `sysext`/image layer for host-integral pieces.
- Everything signed (cosign); every image carries SBOM + CBOM; crypto choices are policy, not hardcoded.
- Never gate the device on an account; cloud features are additive.
