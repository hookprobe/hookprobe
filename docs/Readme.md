# HookProbe OS

> 🛑 **Superseded in part by [ADR 0047](adr/0047-heqk-everywhere-on-device-mission-control.md) (2026-10-09):** heqk replaces Linux on **every** platform and Mission Control is served by heqk on the device. Pillar 1 ('the OS is a Containerfile/bootc') describes the transitional Linux tier; the product substrate is heqk.

> **One operating system. Every platform. Hardware only unlocks capabilities.**
>
> HookProbe OS is an AI-native security operating system delivered as a signed container image. The **OS is a Containerfile** (bootc), **detections and policy are sandboxed WebAssembly components** (WASI), and the system is **operated by intent** — you declare what you want and an agent reconciles it. The same image, the same Mission Control, and the same AI run on a Raspberry Pi, an RK3588 board, an Intel N100 appliance, a VM, the cloud, or future HookProbe hardware.

This document is the canonical architecture. Every load-bearing decision has been back-tested against the 2026 ecosystem; sources are listed in [Back-test: evidence](#back-test-evidence).

---

## TL;DR — the decisions (back-tested)

These are made, not offered as options.

| Concern | Decision | Why it survives scrutiny |
|---|---|---|
| Branding | **One software: HookProbe OS.** Guardian / Fortress = hardware SKU names only. | One codebase, one set of docs, one thing to learn and sell. |
| Base distro | **Debian/Ubuntu** | OVS is a free first-class package; ARM SoCs (Pi, RK3588) are natively supported; you can ship your own kernel; no per-device subscription. |
| OS delivery | **bootc** — the OS is a signed OCI image | Build with `podman build`, ship to a registry, `bootc upgrade`/`rollback`. One toolchain you already use; CNCF project; distro-agnostic. Replaces mkosi+RAUC+custom-builder+package-manager. |
| Logic / detection unit | **WebAssembly components** (WASI 0.2/0.3, WIT) | One binary runs on arm64/amd64/RISC-V; capability-sandboxed by default; ~1–5 ms cold start; inference via WASI-NN without GPU drivers. Neither OpenWRT nor any SIEM can match this. |
| Heavy services | **Rootless Podman containers** (Quadlet) | For stateful/long-running services that aren't a fit for Wasm yet. |
| Host-level capability (OVS, DPDK, kernel bits) | **Layered into the bootc image** | You own every layer; `RUN apt-get install -y openvswitch-switch` — the "the distro doesn't ship X" class of problem disappears. |
| Enrollment | **Standalone by default**; account/cloud is an optional layer | Edge devices must run disconnected; community/DIY can't be login-gated; security buyers reject mandatory vendor cloud. |
| Operating model | **Declarative intent, reconciled by AEGIS** | Not config files (UCI/RouterOS). The interface is "what you want"; config becomes a generated artifact. This is the differentiator incumbents structurally cannot copy. |
| AEGIS model | **Bring your own LLM** (OpenAI-compatible; local via Ollama) | Air-gap needs local inference to be efficient; model choice is the operator's, not a lock-in. Enforcement is a deterministic local reconciler that works with no model at all. |
| Source of truth | **Platform Manifest** — signed, generated at first boot | Capability grants + crypto posture. Every component queries it; nothing re-probes hardware. |
| Data plane | **Out-of-band by default**, inline opt-in; fail-open/closed configurable. **Enforcement separation (ADR 0023):** observe by default; drop only a confirmed attack or a resource-exhaustion event; a legit connection always passes. | An edge box must never be able to take the network down with it — and must never false-drop a paying customer. |
| Data & retention | **Bounded by storage, surfaced to the operator**; tiered + offload | On a Pi you can't retain everything; the device shows its real window instead of pretending. |
| Fleet | **Pull-based GitOps**, desired state in Git, drift self-heal | Resilient to intermittent links; scales to thousands of nodes without proportional ops cost. |
| Supply chain | **Everything signed** (sigstore/cosign), SBOM + CBOM per image, SLSA provenance | It's a security product; integrity of the whole OS stack is the credibility moat. |
| Crypto | **Crypto-agility from day one**; module signing is hybrid ML-DSA-65 + Ed25519 **today** (fail-closed, both legs enforced); ML-KEM transport + LMS/XMSS boot signing are named **roadmap** (no code yet) | RSA/ECC deprecate by 2030; firmware-signing PQC mandates land 2027. Ship the cheap, real leg now; keep the rest honestly labeled, not fabricated. |
| License | **Open-core, dual-license** — base OS + standalone SOC under **GNU AGPL-3.0**; offering-as-a-service / cloud layer requires a **commercial license** (see `LICENSING.md`) | AGPL network-copyleft keeps the community on-ramp open and audit-able while stopping SaaS free-riding; the business is the managed/service layer. |

**Positioning sentence (use everywhere):**
> *HookProbe OS is the operating system. SOC is its default workspace. Hardware only unlocks capabilities.*

---

## Why this is not OpenWRT / RouterOS

An image + a web builder *is* the OpenWRT ImageBuilder / RouterOS playbook. Competing there means out-engineering a 20-year incumbent on device-support breadth — a losing fight. HookProbe differentiates where their architecture cannot follow, and gets "simpler/cheaper/faster" by adopting the newest substrate.

| Axis | OpenWRT / RouterOS | HookProbe OS |
|---|---|---|
| OS delivery | Firmware blob / buildroot | OCI image, `bootc upgrade` / `rollback` |
| Extension unit | opkg package (arch-specific, unsandboxed) | Signed Wasm component (any arch, capability-sandboxed) |
| Update model | Flash / sysupgrade | Atomic image switch, instant rollback, registry deltas |
| Interface | Config files (UCI / CLI) | Declarative intent, agent-reconciled |
| Plugin trust | Trust the package | Granted capabilities only — cannot escape |
| AI | None / bolted on | Native operator (AEGIS) |
| Toolchain | buildroot + opkg + sysupgrade | Podman/OCI + Wasm — one stack |

---

## Principles

1. **Hardware is replaceable. HookProbe OS is forever.** New hardware is a deployment target, never a new product.
2. **The container is the operating system.** Build, test, sign, ship, and roll back the OS with the same tools as an app.
3. **Detect once, query forever.** Bootstrap probes hardware one time and writes a signed manifest. Nothing else touches hardware detection.
4. **Logic is portable and sandboxed.** Detection, policy, enrichment, and transforms are Wasm components granted only the capabilities they need.
5. **Declare, don't script.** A node — or a fleet — is a YAML desired state. Apply it; the system converges and self-heals.
6. **Capabilities, not branches.** Code never asks "is this a Pi?" It asks "is `wifi7` granted?" The manifest answers.
7. **Trust nothing unsigned.** Every image, module, and manifest is signed and inventoried (SBOM/CBOM).
8. **Crypto is swappable.** Algorithms are a policy choice, not an architectural assumption.
9. **Local-first; the cloud is optional.** A device runs a full SOC with no account and no connectivity. Cloud linkage is an additive enrollment layer, never a precondition.
10. **Bounded and honest.** Local retention is capped to the hardware, and the operator is always shown the real window — the box never pretends to remember more than it can.

---

## Architecture — three layers

```
┌──────────────────────────────────────────────────────────────┐
│  HookProbe OS (experience) — operated by INTENT               │
│  Mission Control · SOC · Network · AI (AEGIS reconciler)      │
│  — consumes the Platform Manifest; renders only what exists — │
├──────────────────────────────────────────────────────────────┤
│  LOGIC: Wasm components (WASI)   +   SERVICES: Podman          │
│  NAPSE · HYDRA · policy · enrichment   |  stateful daemons     │
│  — capability-granted, hot-loadable    |  rootless, Quadlet —  │
├──────────────────────────────────────────────────────────────┤
│  HookProbe Base — the OS is a Containerfile (bootc, Debian)   │
│  kernel · drivers · Podman · Wasm runtime · supervisor        │
├──────────────────────────────────────────────────────────────┤
│  Hardware:  Pi 5 · RK3588 · N100 · VM · Cloud · HP appliances │
└──────────────────────────────────────────────────────────────┘
```

Everything above "Base" is identical on every platform. Hardware differences are absorbed entirely by the Base image + Manifest.

---

## Components

The named pieces are modules and services on the same base — none is a separate product.

| Component | Role |
|---|---|
| **Senzorium** | Observation layer — packet capture, flows, host telemetry (eBPF/XDP), syslog/log ingest, taps. Normalizes everything to a common event schema. |
| **NAPSE** | Network IDS/IPS sensor — inspects packets and flows for anomalies and known-bad. |
| **HYDRA** | Threat-intelligence & enrichment pipeline — resolves IOCs against feeds (STIX/TAXII, MISP) and enriches/correlates events (CVE, anomaly, predictor, temporal — the production `ids-hydra-*` services). Surfaced in the **Intelligence** workspace. |
| **AEGIS** | Autonomous orchestrator — the deterministic reconciler plus the pluggable AI planner that turns intent into desired state. |
| **QSECBIT** | Composite cyber-resilience score — combines Mahalanobis distance, ML attack probability, and entropy into one posture number. |
| **Mission Control** | Operator experience — manifest-driven UI that renders only what the device can do. |
| **Supervisor** | Resolves module `requires`/`grants` against the manifest and reconciles running modules to desired state. |
| **Platform Manifest** | Signed source of truth — capabilities, crypto posture, installed modules. |

---

## Pillar 1 — The OS is a Containerfile (bootc)

The OS ships as a bootable OCI image — **one signed image is the universal source of truth for every platform.** How that image *updates* splits by boot model (ADR 0019): on **UEFI platforms** (amd64/N100/VM/cloud, arm64-virt) devices update with `bootc upgrade` (and `bootc rollback` in seconds if a boot fails), against a self-built Debian-bootc base; on **Raspberry-Pi-native platforms** (Pi4/Pi5/CM5) an OCI-derived **A/B image-sync** delivers the same transactional update + rollback from the same signed image, because bootc cannot manage the Pi's MBR/`config.txt`/SoC-firmware boot. bootc is a CNCF project, not tied to any distribution — there is an active Debian/Ubuntu effort (Bootcrew, composefs-rs, which we pin + track while its composefs-native backend stabilizes), and SteamOS already ships on bootc.

Why this beats a hand-rolled firmware pipeline:
- **One toolchain.** OS, services, and registry are all Podman/OCI. No mkosi, no RAUC, no bespoke image-builder webapp.
- **You own every layer.** Missing OVS? `RUN apt-get install -y openvswitch-switch`. The "the distro doesn't include X" problem evaporates because the image is yours.
- **Atomic + reversible.** Updates either complete or roll back cleanly; the previous image stays until pruned.
- **Cheap updates.** Devices pull registry deltas; composefs (overlayfs + EROFS + fsverity) deduplicates and integrity-checks blocks.

```dockerfile
# Containerfile — the entire OS, one file
FROM ghcr.io/hookprobe/base-debian:trixie-bootc   # illustrative; the real base is in base/Containerfile
RUN apt-get update && apt-get install -y \
      openvswitch-switch podman wasmtime \
 && rm -rf /var/lib/apt/lists/*
COPY supervisor/   /usr/lib/hookprobe/
COPY manifest/     /usr/lib/hookprobe/manifest/
# kargs, sysctls, signed-by config, etc.
```

`bootc-image-builder` turns that one image into the UEFI artifacts — `.iso` (x86), `.qcow2` (VM), cloud `.raw`/AMI; the Pi/RK3588 `.img.xz` is produced from the *same* image by the rpi-native factory path (`make-pi4-image.sh`, ADR 0019 D6).

---

## Pillar 2 — Logic & detection are Wasm components (WASI)

OpenWRT extends via opkg (arch-specific, mutable, unsandboxed); RouterOS barely extends at all. HookProbe extends via **signed WebAssembly components**:

- **One binary, every CPU.** A single `.wasm` runs unchanged on arm64, amd64, and RISC-V — no per-arch package matrix.
- **Capability security by default — which *is* the manifest philosophy.** A module gets no filesystem, network, or env access unless explicitly granted. A buggy or hostile detection rule physically cannot escape its grant. For a security product, "our detection plugins cannot compromise the box" is a real, sellable property.
- **Hundreds of modules on a Pi.** ~1–5 ms cold start and MB-scale footprints; hot-load/unload detections; ship a new one nightly as a ~200 KB registry pull. **WASI-NN** runs model inference inside the sandbox — no GPU drivers, no Python runtime — which directly solves the old Pi-inference-latency problem. *(Supply-chain note, ADR 0016/0017: this ~1–5 ms figure is the AUTHENTICATED path — a build-time-precompiled `.cwasm`, arch-native, digest-pinned inside the SAME signed `module.yaml` the source `.wasm` already covers, shipped read-only in the image. A writable, on-device-precompiled AOT cache was found to be an unauthenticated bypass and is never trusted for a `signature: required` module; any doubt (absent/mismatched/version-drifted blob) falls back to a slower but always-safe verified-JIT compile of the same signed `.wasm` — see `docs/adr/0016-artifact-hash-signing.md`, `docs/adr/0017-authenticated-aot-cache.md`.)*
- **Composable, polyglot.** WIT interfaces let modules authored in Rust (smoothest), TinyGo, or others compose without glue. The Marketplace becomes a signed registry of `.wasm` + WIT.

Boundary (honest): Wasm is production-ready for the right workloads — edge functions, plugins, sandboxing, inference — not for everything (threading/library gaps outside that niche). So: **base + heavy stateful services = bootc/containers; detection, policy, enrichment, transforms = Wasm.** Right tool per layer.

---

## Pillar 3 — Operated by intent, not configured

Incumbents are config-centric (UCI files + LuCI; CLI/Winbox). HookProbe inverts it: the user or the AI states **what they want**, and **AEGIS** compiles that into Wasm modules + manifest grants + network state and continuously reconciles it. The config file becomes a generated artifact, never the interface.

```
"guest wifi that can't see the LAN"
        │
        ▼  AEGIS plans against the Platform Manifest
   ┌─────────────────────────────────────────────┐
   │ load wifi-ap.wasm (cap: wifi_ap)            │
   │ load vlan-isolation.wasm (cap: openvswitch) │
   │ write desired state → reconcile → verify    │
   └─────────────────────────────────────────────┘
```

This is what Kubernetes did for workloads, applied to security posture on a node — and, at scale, across a fleet (see [Fleet & scale](#fleet--scale)). It is also the architectural form of "what is the organism doing right now?": the OS is *operated*, not *configured*. User onboarding friction drops toward zero — there is no syntax to learn.

Crucially, two parts do this work: a **deterministic reconciler** that always runs locally (it converges declared desired state — no AI required), and an **AI planner** that translates free-form intent into that desired state. The planner is assistive and model-pluggable (see [AEGIS & the AI layer](#aegis--the-ai-layer-bring-your-own-model)); the reconciler is what enforces — so the system stays fully operable air-gapped, and even with no model at all.

---

## AEGIS & the AI layer (bring your own model)

AEGIS has two parts, and only one of them is "AI":

- **The reconciler is deterministic and always local.** It takes a desired-state spec (modules + grants + network/policy) and converges the device to it, then holds it there. No model, no network, no account required — applying a saved intent or a `hookprobe.yaml` works on a fully air-gapped box.
- **The planner is the AI front-end.** It turns free-form intent ("isolate any host beaconing to a new C2") into that desired-state spec, and explains incidents in plain language. It is assistive — never in the enforcement path.

**The model is the operator's choice — HookProbe ships the integration, not the model.** AEGIS talks to any OpenAI-compatible endpoint:

- **Air-gapped / local:** point AEGIS at a local **Ollama** (or llama.cpp / vLLM) running whatever model the operator trusts; on devices with an NPU it can use it. Air-gapped deployments need a local LLM to be efficient — so *how* you run it and *which* model you use is deliberately a community/operator decision, not a HookProbe lock-in.
- **Cloud-linked:** optionally use a hosted model through the same adapter.

**Guardrails.** AEGIS proposes a plan as a diff; actions are policy-gated — low-impact changes auto-apply, high-impact ones (isolation, blocking, firewall changes) require approval unless the operator opts into autonomy per playbook. Every action is recorded with its rationale, confidence, and evidence, so "why did the AI do this?" always has an answer. The deterministic reconciler is the backstop: if the model is unavailable, the system keeps enforcing the last approved state.

---

## The Platform Manifest — single source of truth

Generated once by Bootstrap, signed, stored at `/var/lib/hookprobe/manifest.json`, exposed read-only over a local socket. UI, AEGIS, Marketplace, updater, and supervisor all read it; none re-probe hardware. It now also carries crypto posture so the system is self-describing for compliance and PQC migration.

```yaml
schema: 2
platform:
  id: edge-pro            # edge-lite | edge-pro | cloud | virtual | dev
  sku: HP-EP-001          # marketing SKU (Guardian / Fortress)
  serial: HP0001421
hardware:
  arch: arm64             # arm64 | amd64 | riscv64
  cpu: "RK3588"
  memory_mb: 16384
  tpm: true
  secure_boot: true
  npu: true               # → WASI-NN acceleration available
network:
  ethernet: 4
  wifi: { present: true, max_standard: wifi7 }
  lte:  { present: true, model: "RM520N-GL" }
capabilities:             # the contract every module relies on
  soc: true
  ids: true
  openvswitch: true       # gated on arch + nics
  wifi_ap: true
  edge_ai: true           # gated on memory/npu
crypto:                   # crypto-agility + PQC readiness — IMPLEMENTED vs ROADMAP (docs/adr/0002)
  agility: true
  module_signing: ["ml-dsa-65", "ed25519"]  # IMPLEMENTED — hybrid, both legs fail-closed-enforced
  image_signing: ["ecdsa-p256"]              # IMPLEMENTED — real mechanism: cosign KEYLESS (Fulcio/Rekor)
  tls_kex: ["ml-kem-768+x25519"]             # ROADMAP — no TLS/rustls stack in this tree yet
  boot_signing: "lms"                        # ROADMAP — stateful hash-based, no code yet
  cbom: "/usr/share/hookprobe/cbom.json"     # per-algorithm implemented|roadmap status lives here
modules:
  - { id: napse, version: 2.4.1, runtime: wasm, state: running }
signature: "cosign:sigstore:..."             # TPM-bound where available
```

A capability is `true` only if Bootstrap proved the prerequisites. The UI hides, greys out, or offers "install" based purely on this object.

---

## Modules

A module is the only way to add functionality. SOC, IDS, VPN, a detection rule, a marketplace app — all modules.

```yaml
id: napse
version: 2.4.1
title: "NAPSE — IDS/IPS"
runtime: wasm                 # wasm | container | sysext
artifact: registry.hookprobe.com/modules/napse:2.4.1   # OCI (wasm or container)
requires:
  capabilities: [soc, ids]
  min_memory_mb: 512          # wasm modules are cheap
grants:                       # the ONLY host access this module receives
  - read: /var/lib/hookprobe/flows
  - wasi-nn: cpu
provides:
  capabilities: [napse]
signature: required
```

- **`runtime: wasm`** → the default for detection/policy/enrichment logic. Sandboxed, arch-independent, hot-loadable.
- **`runtime: container`** → rootless Podman + Quadlet for heavy stateful services.
- **`runtime: sysext`** / image layer → for host-integral pieces (OVS datapath, kernel modules).

The **supervisor** resolves `requires`/`provides`/`grants` against the manifest, refuses incompatible installs cleanly, and reconciles running modules to the desired state. This *is* the Marketplace backend — a signed index of module manifests.

---

## Data, detection & retention

A SOC is only as good as what it ingests, how it decides, and what it can prove later.

### Ingestion (Senzorium)
Telemetry enters through Senzorium and is normalized to a common event schema before any detection runs:
- **Network:** packet capture and flows via eBPF/XDP (NAPSE), plus SPAN/tap/mirror inputs.
- **Host:** process, file, and syscall telemetry via eBPF.
- **Logs:** syslog / CEF / JSON ingest from other devices.
- **External:** threat-intel feeds (STIX/TAXII, MISP) via **HYDRA** annotate events with IOC context, surfaced in the Intelligence workspace.

### Detection content (don't reinvent rules)
HookProbe wraps the established detection ecosystems rather than inventing a rule language:
- **Suricata** rule-packs for network IDS/IPS, **YARA** for file/content, **Sigma** for log detections — all mapped to **MITRE ATT&CK** so coverage is legible.
- A rule-pack ships as a signed module (an engine module consumes the pack); custom logic ships as a Wasm module. QSECBIT rolls live signals into one resilience score.

### Storage & retention (bounded by hardware, and you're told)
Event, flow, and evidence data live on a **persistent data partition, separate from the immutable rootfs** — wiping or upgrading the OS never touches it. The store is a lightweight embedded engine (SQLite/DuckDB-class for events + a compact flow store), not a heavyweight Elastic cluster.

Retention is **capped by available storage and surfaced to the operator** — the device computes and displays its current retention window, keeps defaults conservative, and warns before data rotates out. It is tiered, so the highest-fidelity data expires first:

| Tier | What | Relative lifetime |
|---|---|---|
| Full-fidelity pcap | raw packets | shortest (hours–days) |
| Flow / event metadata | normalized events | medium (weeks) |
| Alerts / evidence / QSECBIT history | the incident record | longest (months) |

Indicative local-only windows on a Raspberry Pi by storage size — **defaults, not guarantees**; real windows depend on traffic volume and which tiers are enabled:

| Storage | Full pcap | Event metadata | Alerts / evidence |
|---|---|---|---|
| 16 GB | hours | ~1–2 weeks | months |
| 32 GB | ~1 day | ~3–4 weeks | many months |
| 64 GB | days | ~1–2 months | year+ |

To exceed local capacity, **offload**: forward events to the fleet store, a SIEM, or object storage (see [Integrations](#integrations--interoperability)). The principle is honesty — the box never silently pretends to retain more than it can.

---

## Data plane & availability

Where HookProbe sits in the network is configurable per interface, because the safe default and the powerful default differ:

- **Out-of-band (default):** IDS via SPAN/tap/mirror. HookProbe sees a copy of traffic and can alert, but is never in the path — zero risk to connectivity.
- **Inline (opt-in):** IPS / firewall / segmentation (bump-in-the-wire). Required for active blocking, VLAN isolation, and "isolate this host" intents.

For inline interfaces, failure behavior is an explicit policy choice:
- **Fail-open** (default for availability-sensitive links): if HookProbe stops, traffic keeps flowing — hardware-bypass NICs where available, software bridge bypass otherwise.
- **Fail-closed** (for high-security segments): if protection is down, the segment blocks.

The manifest records each interface's role; intent can set per-segment failure mode ("the OT VLAN fails closed"). Stating this up front matters — an edge security box that can take the network down with it is a non-starter for most buyers.

**Enforcement separation — the drop discipline (ADR 0023).** Where a box *is* inline, being in the path is not license to drop on suspicion. The rule is **observe by default; drop only a genuine, high-confidence attack or a resource-exhaustion/DDoS event; a legitimate customer connection must ALWAYS pass.** Detectors only emit alerts; a single `decide()` chooses a **tri-state verdict graduated by confidence** — `Observed` (log only) → `RateLimit` (a bounded, self-reverting per-source cap) → `Quarantine`/`FrameDrop` (durable, only after an ADR-0018 confirmation) — with a management-safety `Allowlisted` floor the operator can never self-lock-out through. The only suspicion-free inline drops are a confirmed port scan, a truly-malformed frame (dropped for *what it structurally is*), a real L1/L2 flood, and the **resource-shed**: a per-source new-connection cap plus a conntrack-saturation guard plus PSI CPU/mem-pressure shedding — self-reverting and keyed on *measured resource reality*, never on identity, so a volumetric DDoS is shed while a heavy but legitimate flow is not durably blocked. Behavioural findings whose confidence can't clear the wire bar (beaconing, lateral movement, ARP binding flip-flop) are observe-only by construction. This is regression-locked by the release-blocking `0.7-separation-matrix` gate (33 rows: legit-passes + attacks-caught, both directions).

---

## Integrations & interoperability

A SOC must fit an existing stack, so interop ships as modules and the core stays lean:
- **Egress / forwarding:** events and alerts to SIEM (Splunk HEC, Microsoft Sentinel, Elastic), syslog/CEF, webhooks, email/Slack; SOAR triggers.
- **Threat intel in:** STIX/TAXII and MISP feeds via HYDRA.
- **Rule feeds in:** Suricata / Sigma / YARA sources, signed and versioned.
- **Local API:** a read/write API behind the same auth as Mission Control, so HookProbe can be driven by existing automation.

---

## Resource limits & performance

The "hundreds of modules on a Pi" claim only holds with hard governance:
- **Per-module budgets.** Each `module.yaml` declares CPU/memory; the supervisor enforces them. Wasm modules are capped by memory limits and CPU via fuel/epoch interruption; containers via cgroups. Over-budget → the module is throttled or stopped, never the host.
- **Graceful degradation under pressure.** When the box saturates, low-priority detections shed first; ingestion applies back-pressure rather than crashing; the operator is alerted.
- **Performance is platform-bound.** Throughput (inline pps, monitored endpoints, events/sec) scales with hardware — benchmark per platform before committing SLAs. Indicative fit: Pi-class = home/branch/single-site, mostly out-of-band; N100-class = SMB/branch with inline IPS; server/cloud = aggregation and multi-tenant. Treat these as tiers, not numbers.

Each platform manifest declares a **minimum and recommended spec** so the builder can warn on under-provisioned targets.

---

## The Builder — one Containerfile, many outputs

```
Git monorepo
   │
   ▼ CI: podman build (arm64 + amd64 matrix)
   ├── OS image ──► sign (cosign) ──► registry
   └── modules  ──► .wasm / OCI ──► sign ──► registry
   │
   ▼ bootc-image-builder (per platform profile)
   ├── hookprobe-rpi5.img.xz   ├── hookprobe-n100.iso
   ├── hookprobe-rk3588.img.xz ├── hookprobe-vm.qcow2
   └── hookprobe-cloud.raw / .ami
```

One pipeline serves three audiences identically: **Community** (`builder.hookprobe.com` web form, or just fork the Containerfile), **Enterprise** (YAML/Containerfile with branding + policies → `vodafone-hookprobe.iso`), **Factory** (`POST /build` with serial + edition → signed image flashed on the line). There is no second build path.

---

## User journey — from image to SOC

The defining property: **there is no "set up the SOC" step.** The SOC is the default workspace and it is monitoring from the moment the box boots. Time-to-SOC ≈ first boot — compared to days or weeks to stand up a traditional SIEM.

```
Get the image  →  Flash / deploy  →  First boot      →  Claim device   →  SOC is live  →  Operate by intent
(build/fork/    (Imager, USB,      (bootstrap writes   (open Mission     (monitoring     (state goals,
 pre-built)      VM import)         the manifest)        Control, set admin) from boot)      AEGIS reconciles)
   minutes          minutes            ~1–2 min, once       ~1 min           immediate        ongoing
```

**1. Get the image.** *You do:* pick a path — Community (`builder.hookprobe.com`, or fork the Containerfile and `podman build`), Enterprise (submit YAML/Containerfile → branded `.iso`), or buy a pre-flashed appliance. *You see:* a download or a box. All three converge on the same image lineage — no "Guardian vs Fortress" choice, because the image detects the hardware itself.

**2. Flash or deploy.** *You do:* standard tooling — Raspberry Pi Imager / `dd` for SBCs, USB for x86, `.qcow2`/AMI import for VM/cloud. *You see:* a normal flash; nothing HookProbe-specific yet.

**3. First boot → Bootstrap.** *You do:* power it on. *What happens:* the immutable image boots and Bootstrap runs exactly once — probes hardware, derives capabilities, writes the signed Platform Manifest. *You see:* a short first-boot screen with a local address (`https://hookprobe.local`) or a QR/claim code. No feature menus — the manifest already knows what the box can do.

**4. Claim the device.** *You do:* open Mission Control at `hookprobe.local` and set a local admin credential — **no account required** (standalone). Optionally, link it to a tenant by entering an enrollment token from `mssp.hookprobe.com` (or your own control plane). *You see:* the dashboard populates *to match the hardware* — a card appears only if the manifest grants its capability. Cloud-linked devices are zero-touch from here: they pull their `hookprobe.yaml` and reconcile. See [Deployment modes & device identity](#deployment-modes--device-identity).

**5. SOC is live.** *You do:* nothing — it's already running. *What happens:* the SOC has been monitoring since boot. You land on Organism Status — QSecBit score, threat level, AI activity, open incidents.

**6. Operate by intent.** *You do:* state goals instead of editing config — "guest Wi-Fi that can't see the LAN," "alert me if anything beacons to a new C2," "isolate compromised hosts automatically." AEGIS plans against the manifest, loads the right Wasm modules with only the capabilities they need, reconciles, and verifies. Adding a Marketplace detection is a signed `.wasm` pull — hot-loaded, no reboot. *You see:* the system doing the work and showing its reasoning, not a wall of config fields.

**Lifecycle stays just as light:** updates are `bootc upgrade` (auto-rollback if a boot fails); new detections arrive as module updates without touching the OS; fleet-wide changes are a Git commit every node converges to.

---

## Deployment modes & device identity

An account is **never** required to run HookProbe OS. Registration with `mssp.hookprobe.com` is an optional enrollment layer for managed, multi-tenant, or fleet use. The same image runs in all three modes — they differ only in what the device is *linked* to.

| Mode | Account? | What you get | For |
|---|---|---|---|
| **Standalone** (default) | none | Full local SOC; Mission Control at `hookprobe.local`; local admin | Community, single-site, air-gap, sovereignty |
| **Cloud-linked (MSSP)** | `mssp.hookprobe.com` tenant | Fleet view, GitOps desired-state, multi-tenant portal, central updates, billing | MSSPs and orgs managing fleets |
| **Self-hosted control plane** | your own endpoint | The same fleet management pointed at *your* control plane / Git, not ours | Enterprise/gov wanting fleet ops without our cloud |

**Device identity exists before any account.** At first boot the device generates its own keypair (TPM-bound where present) alongside the signed Platform Manifest — an attestable identity in its own right. From there:

- **Claiming (local)** sets the local admin credential, binding the box to a local operator. This is all standalone needs.
- **Linking (optional)** binds the device identity to an account/tenant via an enrollment token, gated by attestation (same mechanism as the supply-chain section). Devices can be linked later, unlinked, or transferred — which matters for resale, RMA, and decommission.
- **Graceful degradation.** A linked device that loses connectivity keeps enforcing its last-known desired state and keeps the SOC running. The cloud is never in the data path of detection.

**Business model implication — open-core.** Base OS + standalone is free (keeps the community/DIY on-ramp open); the paid tier is the account/cloud layer: multi-tenant MSSP, fleet management, billing, and premium Marketplace detections. The lever is the managed layer, not a gate on the device.

**Multi-tenancy isolation (MSSP).** In cloud-linked mode each customer is a hard-isolated tenant: per-tenant data segregation, scoped RBAC, and separate keys — one tenant's operators never see another's telemetry. A managed device belongs to exactly one tenant; the MSSP's cross-tenant view is an aggregation layer *above* isolated stores, not shared access to them.

---

## Fleet & scale

A one-OS strategy only pays off if 10,000 nodes cost roughly the same to run as 10. The pattern (validated across bootc edge fleets, SUSE Fleet, Red Hat Edge Manager, GitOps-at-scale practice):

- **Desired state lives in Git.** Each node/group has a `hookprobe.yaml`. A lightweight, pull-based agent on the device reconciles toward it.
- **Pull, not push.** Devices fetch their desired state and updates; they keep working through intermittent links and converge when connectivity returns. No central hub holding credentials for every node (avoids the hub-and-spoke blast radius).
- **Drift self-heal.** The agent continuously compares actual vs desired and corrects unauthorized change — the same mechanism that blocks manual tampering on a security appliance.
- **OCI as the state store at scale.** Past ~thousands of nodes, package configs as signed OCI artifacts (not raw Git clones) so reconciliation stays fast.
- **Health is measured, not assumed.** Track reconciliation convergence per node/site to spot drift and failed rollouts early.
- **Staged rollout (rings).** Updates promote through canary → ring → fleet, health-gated at each step, with auto-halt on rising failure or rollback rates — so one bad signed image can't brick every node at once.
- **Observe the monitor.** Every node heartbeats its health, version, and module state upstream; a silent or degraded node raises an alert instead of failing quietly.

Same `bootc upgrade`/`rollback` and same intent model on one Pi or a national fleet — that's the operational payoff of one OS.

---

## Security & supply chain

For a security product this is the credibility moat, and it's where the bootc + Wasm choices compound.

- **Sign everything — and prove it covers the payload, not just the metadata.** OS images, Wasm modules, and manifests are signed with sigstore/cosign; bootc lets container-grade signing, scanning, and validation cover the entire OS stack — kernel, drivers, bootloader included. A module's `module.sig` signs its `module.yaml`, which pins the payload's own digest(s) in an `artifacts:` block (ADR 0016); the supervisor verifies each declared artifact's hash against the EXACT bytes it is about to compile/execute — read once, checked, then compiled from those same verified bytes, never a re-opened path — and requires the resolved executable to match a declared artifact, fail-closed on any mismatch, missing file, unbound path, or (for a `signature: required` module) a missing digest block; a payload swap that leaves `module.yaml` byte-identical is caught, not merely a stripped/absent signature. **Enforced coverage today is wasm modules (the supervisor's load path) plus the native eBPF loaders this repo owns end-to-end (`napse-quarantine`)** — container/sysext paths systemd launches directly are a tracked follow-up, not yet gated (ADR 0016 Errata).
- **SBOM per image, CBOM per image.** Ship a Software Bill of Materials and a **Cryptographic** Bill of Materials so operators (and regulators) can inventory dependencies and crypto in one query. CBOM is becoming a required artifact alongside SBOM.
- **Provenance.** Build with SLSA-style provenance so every artifact traces back to a commit and a pipeline.
- **Capability sandboxing as defense-in-depth.** Even a compromised detection module is boxed by its WASI grants — it cannot reach the host, the network, or other modules.
- **Hardware root of trust.** Use TPM-backed signing/attestation where present; the manifest records `secure_boot` and `tpm` so policy can require attestation before a node joins a fleet.
- **Secrets stay off the image.** Certs, API keys, and enrollment tokens never live in the Containerfile — they sit on the persistent data partition, sealed to the TPM where present, and are rotatable. The image stays reproducible and secret-free.

### Post-quantum readiness (build it in now)

NIST finalized the PQC standards (FIPS 203 ML-KEM, 204 ML-DSA, 205 SLH-DSA); RSA/ECC are slated for deprecation by 2030 and disallowed by 2035, the EU expects high-risk migration by 2030, and NSA CNSA 2.0 requires PQC for new acquisitions in 2027 with **software/firmware signing PQC-exclusive from Jan 1, 2027**. "Harvest now, decrypt later" makes this a present risk for any data with multi-year value — squarely HookProbe's domain.

The architectural lesson is **crypto-agility**, not picking one algorithm: separate crypto from logic so an algorithm swap is a policy/config change, not a re-architecture (the EU Cyber Resilience Act mandates exactly this). The mechanism is real and load-bearing today — the CBOM (`security/cbom/gen-cbom.py`) tags every algorithm `hookprobe:status: implemented | roadmap` and never claims quantum resistance for a leg nobody has wired up — but not every domain below has code behind it yet. Split honestly:

**Shipped today:**
- **Module signing:** hybrid **ML-DSA-65 + Ed25519**, both legs fail-closed-enforced (`crates/hookprobe-manifest/src/module_sig.rs::verify_module_for_suite`) — a module missing its ML-DSA sidecar under the hybrid suite is refused, never silently downgraded to Ed25519-only. Driven entirely by the manifest's `crypto.module_signing` policy: an Ed25519-only suite genuinely runs Ed25519-only (the agility mechanism is exercised, not just declared).
- **Image signing:** real cosign **KEYLESS** signing (Fulcio-issued short-lived **ECDSA-P256** certificate, Rekor transparency log — `.github/workflows/build-os.yml`). Not PQC yet: sigstore/cosign's own PQC signing mode is still maturing upstream (see Consequences in ADR 0002).
- **Don't touch what's safe:** AES-256 and SHA-2/3 remain quantum-resistant as-is; migration focus is public-key crypto only.

**Roadmap (named in policy, no implementation yet — tracked, not fabricated):**
- **Firmware/boot:** stateful hash-based (LMS/XMSS) for secure-boot chains, ahead of the 2027 firmware-signing mandate. The stateful-HBS key-custody design (release-HSM-only, leaf index never forked) is already decided (ADR 0002 §5); the signing/verification code itself is future work.
- **Transport:** hybrid ML-KEM + classical KEX for fleet/control-plane TLS — there is no TLS/rustls stack in this tree yet to carry it.

Shipping crypto-agility + an honest CBOM is itself a differentiator versus appliance vendors that hard-code RSA/ECC — and versus a CBOM that certifies algorithms no code implements.

### Threat model

HookProbe is itself a high-value target; each surface has a named control:
- **Device / local access** → signed immutable image, secure boot, sealed secrets, local admin auth.
- **Wasm sandbox escape** → capability grants are the blast-radius limit; the runtime is kept current via OS image updates.
- **Update / registry channel** → cosign signatures + attestation; a tampered image fails verification and won't boot-switch.
- **Cloud control plane** → optional and out of the detection path; a compromise can't silently alter a device's enforced state without a signed, attested change.
- **Supply chain** → SBOM/CBOM + SLSA provenance; reproducible builds.

Residual risks are stated, not pretended away: a correctly-signed but malicious first-party module, or a local admin with physical access, are managed by policy and review — not eliminated.

#### The AI-accelerated attacker (Akrites-era)

A distinct, named adversary now shapes the landscape: an attacker who uses AI to **discover and weaponize vulnerabilities in minutes, not weeks** — compressing the disclosure-to-deploy window while fewer than 5% of vulnerabilities are ever patched (the premise behind the Linux Foundation's Akrites initiative, 2026-06-25). The danger is not a single exploit but the *speed*: a fix may exist upstream (or not exist yet at all) long before it reaches a fielded device, and that gap — the window before the fix reaches the device — is exactly where AI-accelerated attackers operate.

- **Where HookProbe has a structural advantage.** Our defense does not depend on knowing the CVE or having the patch. Behavioral edge enforcement catches exploitation by its **on-wire and on-host behavior**, regardless of patch status: napse-dpi L2/L7 detection, host EDR (`crates/hookprobe-evidence/src/host_edr.rs`, rules `1_000_100..=1_000_115` — reverse shell, credential-store access, persistence), and behavioral quarantine keyed on resource-reality rather than signatures (ADR 0022) — all under the observe-by-default, drop-only-a-genuine-attack posture (ADR 0023). A novel exploit that opens a reverse shell, moves laterally, or exhausts a resource is caught by the *effect*, not by a prior signature. This is proven on real Pi 4 hardware, not aspirational.
- **Where we do NOT (yet) have an advantage — stated honestly.** HookProbe does **not** perform ML-based attack-pattern *anticipation* and does **not** run "AI-vs-AI" autonomous defense. The AI in the system is an *assistive, bring-your-own-LLM planner barred from the enforcement path* (contract C9, `docs/Architecture.md`): it proposes a plan-as-a-diff; the deterministic reconciler and the gate ladder enforce. Today's defense is deterministic rules + behavioral heuristics — strong against exploitation-by-behavior, but not predictive; it does not close the window by anticipating the attacker's next move. The **exploitability pipeline** that would prioritize the pre-patch window (VEX reachability from the signed SBOM, EPSS exploit-probability, SSVC operator decisions, HYDRA live CVE↔SBOM enrichment) is **being built in parallel and is not shippable as a claim yet** (Tier 2 — tracked in `docs/BuildPlan.md` and `docs/product-cortex-competitive.md`).

**Positioning (Amber — needs product-steward + operator sign-off before hookprobe.com):** *"Akrites fixes open source upstream; HookProbe OS defends the window before the fix reaches your device — behaviorally, on owned hardware, regardless of patch status."* Akrites (founders include **Vodafone and Ericsson** — the telco-edge / SASE space) is the **upstream, coordinated-remediation half**; HookProbe is the **downstream, on-device half** — a complement, not a competitor. HookProbe both consumes critical OSS (and so benefits from Akrites directly) and is itself an OSS security project that should live by Akrites' coordinated-vulnerability-disclosure discipline.

**Honesty guardrails — do not claim on the public site until built:** VEX / EPSS / SSVC and live-CVE prioritization as a *capability* (they are roadmap / Tier 2, not shipped); any framing of the AI as *autonomous* or *predictive* defense (it is assistive and C9-barred). **Lead instead with what is proven on metal:** behavioral enforcement that catches exploitation regardless of patch status.

### Compliance

The architecture is built to *support* certification, not to claim it: immutable + signed + SBOM/CBOM eases SOC 2 / ISO 27001 evidence; crypto-agility + PQC tracks the EU CRA and NIS2 trajectory; local-first supports data-residency and air-gap requirements. FIPS-validated crypto is available on the Debian/Ubuntu base (e.g., Ubuntu Pro FIPS) for regulated deployments.

---

## Repository layout

```
hookprobe-os/
├── base/                  # Containerfile(s): Debian bootc base, kernel, runtimes
│   └── profiles/          # edge-lite | edge-pro | cloud | virtual | dev
├── bootstrap/             # hardware discovery + signed manifest generation
├── supervisor/            # reconciler: hookprobe.yaml ↔ manifest ↔ modules
├── manifest/              # JSON Schema + signing for the Platform Manifest
├── modules/               # one dir per module (module.yaml + Rust/TinyGo or Containerfile)
│   ├── napse/             # runtime: wasm
│   ├── hydra/             # runtime: wasm
│   └── ovs/               # image layer / sysext
├── builder/               # CI + bootc-image-builder + thin builder.hookprobe.com
├── ui/                    # Mission Control (manifest-driven)
├── fleet/                 # GitOps agent + desired-state schema
├── security/              # SBOM/CBOM generation, signing, SLSA provenance, crypto policy
└── platforms/             # one manifest YAML per board/SKU
    ├── rpi5.yaml
    ├── rk3588.yaml
    └── edge-pro.yaml      # future HookProbe hardware = just another file
```

**Adding future hardware = one file in `platforms/`.** No UI, installer, or API change. That is the test that the design worked.

---

## License & governance

Open-core — final license is a decision to lock, with a recommendation:

- **Open core:** the base OS, standalone SOC, Senzorium / NAPSE / HYDRA, the AEGIS reconciler, the manifest, and the supervisor under a permissive OSS license — **Apache-2.0 recommended** for the widest community/DIY adoption. (Alternative: AGPL-3.0 if you want to force reciprocity from anyone offering it as a service — stronger moat, smaller adoption funnel. Pick deliberately.)
- **Commercial:** the cloud/account layer — multi-tenant MSSP portal, fleet management, billing, premium Marketplace detections — under a commercial license.
- **Trademark:** "HookProbe" and SKU names (Guardian / Fortress) are protected; community builds ship as HookProbe OS but can't use the marks to imply official endorsement.
- **Contributions:** DCO sign-off (or a lightweight CLA) so the project can dual-license the core.

The lever is always the managed layer, never a gate on the device — consistent with local-first.

---

## Naming & positioning

| Hardware | Marketing SKU | Software |
|---|---|---|
| Raspberry Pi / RK3588 | HookProbe Guardian | HookProbe OS |
| Intel N100 / x86 | HookProbe Fortress | HookProbe OS |
| VM | HookProbe Virtual | HookProbe OS |
| Cloud | HookProbe Cloud | HookProbe OS |

The software name is always HookProbe OS. **Elevator pitch:** the AI-native, container-native security OS — the OS ships as a signed container, detections run as sandboxed Wasm, and an agent operates it from intent. It runs the same on a Pi or a multi-tenant cloud; hardware just unlocks capabilities. Every piece is a named industry wave (bootc/CNCF, WASI, GitOps reconciliation, PQC), so the story is legible to engineers, customers, and investors alike.

---

## Roadmap — pragmatic phases

1. **Foundation (highest leverage).** Debian bootc base + the Platform Manifest schema; UI reads only from the manifest. Prove **one Wasm detection module loading against a manifest grant**. That single demo is the whole thesis working.
2. **Modules, data & supervisor.** OCI/Wasm registry + cosign; convert NAPSE/HYDRA to Wasm; ship the reconciler, the data/retention tier, and the AEGIS LLM adapter (Ollama/OpenAI-compatible); apply `hookprobe.yaml`. Marketplace becomes nearly free.
3. **Fleet.** Pull-based GitOps agent, drift self-heal, disconnected operation.
4. **Builder.** CI matrix → all image formats; `builder.hookprobe.com`; enterprise + factory paths.
5. **Supply chain & PQC.** SBOM/CBOM, SLSA provenance, hybrid PQC signing/TLS, TPM attestation for fleet join.
6. **Own hardware.** Add `platforms/edge-pro.yaml`. Nothing else changes — proof the abstraction held.

The one genuine engineering pole is a **custom kernel for edge SoCs** (RK3588/Pi) — plan for it early; on Debian/Armbian, shipping your own kernel in the image is routine.

---

## Why this is cheaper, faster, easier

- **Build:** one toolchain (Podman/OCI) for OS + services, Wasm for logic. No firmware pipeline, no per-arch package builds, no second build path.
- **Use:** `bootc upgrade`/`rollback`; intent instead of config; nothing to learn.
- **Operate at scale:** desired-state GitOps means a few engineers manage thousands of nodes; drift self-heals.
- **Trust:** signed, inventoried, sandboxed, crypto-agile — the security posture is the product.
- **Talk about:** riding bootc, Wasm, GitOps, and PQC instead of out-engineering a 20-year incumbent on its own turf.

---

## Back-test: evidence

Load-bearing external facts behind the decisions above (2026):

- **bootc** is a CNCF project, distro-agnostic, with a stable CLI; image mode replaces imperative provisioning with a declarative Containerfile ("the container is the operating system"); Debian/Ubuntu support exists via the Bootcrew effort and composefs-rs, and SteamOS ships on bootc. (Red Hat Developer; bootc-dev/bootc; The Register, Jun 2026; CIQ.)
- **WebAssembly/WASI:** Preview 2 is stable and Preview 3 (async, Feb 2026) shipped; components are capability-sandboxed by default; one binary runs across x86/ARM/RISC-V; ~1–5 ms cold starts; WASI-NN enables in-sandbox inference without GPU drivers. Production-ready for edge/plugin/inference workloads, not general backends. (WebAssembly/WASI repos; dev.to/InfraGap/Codefinity, 2026.)
- **Open vSwitch** ships as a free first-class package in Debian `main` (`apt install openvswitch-switch`) — no subscription channel required. (OVS distribution docs.)
- **Edge-SoC kernels:** RK3588 mainline enablement tracks recent kernels (6.14+) plus vendor BSPs; Debian/Ubuntu/Armbian natively support Pi/RK3588 and shipping a custom kernel in the image. (Arch Linux ARM / Collabora RK3588 status; FriendlyELEC BSP.)
- **Detection & local AI reuse:** network/file/log detection builds on established engines (Suricata, YARA, Sigma) mapped to MITRE ATT&CK; local LLM inference via Ollama/llama.cpp and eBPF/XDP telemetry are mature, standard building blocks. (project docs for each.)
- **Fleet/GitOps:** pull-based, desired-state reconciliation with drift self-heal is the established pattern for immutable/bootc edge fleets; OCI as state store scales past Git limits. (Red Hat Edge Manager; SUSE Fleet; platformengineering.org; IoT For All, 2026.)
- **Post-quantum:** NIST FIPS 203/204/205 finalized; RSA/ECC deprecated by 2030, disallowed 2035; EU high-risk migration by 2030; NSA CNSA 2.0 PQC for new acquisitions 2027 and firmware-signing PQC-exclusive from Jan 1, 2027; crypto-agility (and CBOM) is the architectural requirement. (NIST IR 8547; NCSC; Cloudflare; EU PQC roadmap, 2026.)
```
