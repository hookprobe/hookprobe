# HookProbe OS — Mission Control (the control plane)

> Not a dashboard, and not a set of pages. HookProbe OS is an **operating system for cybersecurity, business operations, content, and AI-driven decisions** — think macOS or Windows, where everything belongs to one ecosystem. The operator never leaves HookProbe; every module is a different **lens on the same underlying data**.
>
> **One platform. One data model. One evidence graph. One AI. Multiple workspaces.**

This document specifies the control plane: the foundations it stands on, the design language, the global chrome, and every workspace and subpage from **Build to Run**.

---

## Operating principles

1. **One ecosystem, many lenses.** SOC, endpoint, threat intel, business, CMS/SEO, logging, and multi-tenant ops are not separate apps — they are workspaces over one kernel, one evidence graph, and one telemetry fabric.
2. **Capability-driven.** Every page renders only what the device's signed **Platform Manifest** grants. No Wi-Fi hardware → no Wi-Fi page; no `openvswitch` → no inline-segmentation controls.
3. **Mode-aware.** The same app runs **standalone** (one device, local, no account), **cloud-linked (MSSP)** (multi-tenant fleet), and **self-hosted control plane**. Fleet/tenant/business workspaces appear only when linked.
4. **AI is the interaction layer, not a feature.** The same copilot context — ask, explain, predict, recommend, investigate, generate, automate, document, search, learn — is available from every workspace.
5. **Intent, not config.** You state what you want; AEGIS proposes a plan as a diff; a **deterministic reconciler** applies and verifies it. Works air-gapped, with or without a model.
6. **Recursive multi-tenancy.** Tenants nest like AWS Organizations — any customer can become an MSSP for its own customers, by inheritance, with no code changes.

---

## Layered architecture

HookProbe OS is built as four layers, so it grows without fragmenting:

| Layer | What it holds |
|---|---|
| **Kernel** | Identity, tenants, permissions, the **evidence graph**, storage, messaging, APIs. |
| **Core Services** | **Telemetry Fabric**, AI Engine, Search, Automation, Logging, Knowledge Graph. |
| **Workspaces** | Mission Control, Workspace, Observe, Detect, Investigate, Protect, Automate, Intelligence, Customers, Business, Knowledge, Administration. |
| **AI Interaction Layer** | A persistent copilot that can search, explain, automate, and generate from anywhere. |

Workspaces are views; the kernel and core services are the substance. The same incident, asset, or IOC referenced in the SOC, a business report, or a blog post is the *same node* in the graph — never a copy.

---

## Foundations

### The Evidence Graph — the single source of truth

Don't think "database." Think **graph**, where every artifact points somewhere and nothing is duplicated:

```
Device → Interface → Packet → Connection → Session → Application
       → User → Credential → Process → File → Registry
       → Threat → Incident → Response → Report
```

Every workspace reads and writes this one graph. A detection links to the packets that triggered it; an incident links to the credentials, processes, and files involved; an executive report links back to the raw evidence. This is what makes drill-down universal and what lets the AI reason across the whole system.

### The Telemetry Fabric — instead of "logs"

Logging is elevated from a feature to a fabric. Every event is fully traceable from raw source to executive report:

```
Sources → Ingestion → Parsing → Enrichment → Normalization → Correlation
        → Storage → Compression → Deduplication → Timeline → AI Summary → Search
```

Example trace (a FortiGate event, end to end):

```
FortiGate syslog → raw log → parser → normalized event → entity extraction
→ MITRE mapping → risk score → correlation → threat → incident → executive report
```

The Telemetry Fabric is surfaced operationally in **Observe** and administered in **Administration → Telemetry Fabric**. Retention is bounded by storage and shown to the operator (see Administration → Storage).

### The AI Interaction Layer — universal copilot

AI is not a page; it overlays everything. The same verbs are available in SEO, CMS, telemetry, incident response, or tenant management:

```
Ask · Explain · Predict · Recommend · Investigate · Generate · Automate · Document · Search · Learn
```

**AEGIS** has two parts: a **deterministic reconciler** (always local; converges declared desired state with no model) and an **AI planner** (turns intent into that desired state and explains it). The model is **bring-your-own** — any OpenAI-compatible endpoint, or a local **Ollama / llama.cpp / vLLM** for air-gapped sites. Choice of model is the operator's; HookProbe ships the integration, not the model.

---

## Design language

The look is a dark command center — calm, dense without clutter, decision-first (reference: the V2 dashboard mockup `~/hookprobe-v2-dashboard.png`, which realizes this spec — plus Linear / Vercel / Warp and operational cues from Defender XDR / Darktrace). The V2 dashboard is built **fresh from this spec** (no reuse of V1 dashboard pages); only the V1 **Astro theme** (dark styling) is carried over, and the layout must track customer feedback.

- **Near-black navy canvas**, panels a shade lighter with hairline borders; neon accents used as signal, never decoration.
- **One color language:** green = healthy/protected, purple = AI, blue = information, amber = needs attention, red = critical, grey = inactive.
- **Signature element:** the **Organism Status** — a glowing orb with the live **QSecBit** score and a heartbeat sparkline. It is the one bold thing; everything around it stays quiet.
- **Bento grid** of operational panels; large KPIs, small uppercase labels.
- **Radial gauges/rings** for single scores (QSecBit, confidence, health %); **stacked bars, sparklines, timelines, node graphs, heatmaps** for everything else. Avoid multi-slice pie charts for compositions.
- **Everything is clickable** — every number drills to its evidence in the graph.
- **AI explanations everywhere** — every recommendation/action carries *why · confidence · evidence · model · related events*.
- **Living, not refreshing** — subtle motion on counters, threat pulse, mesh links, heartbeats. Respect reduced-motion.

---

## Global chrome (persistent everywhere)

| Element | Behavior |
|---|---|
| **Command bar (AI Copilot)** | `⌘/Ctrl-K`. State intent or ask anything; returns an answer with evidence, or a plan as a diff to approve. |
| **Organism status pill** | QSecBit + protected/at-risk, always top-left → Mission Control. |
| **Scope switcher** | Standalone: hidden. Linked: *this device / site / fleet / tenant*. |
| **Mode badge** | `standalone` / `cloud-linked` / `self-hosted`; online or "degraded — enforcing last approved state." |
| **Notifications** | Incidents, approvals awaiting you, failed reconciliations, retention warnings, updates. |
| **Identity** | Local admin (standalone) or tenant identity (linked); RBAC role. |

---

## Navigation map

```
HOOKPROBE OS
│
├─ Mission Control          global situational awareness
├─ Workspace                your recent work (like VS Code)
├─ Observe                  all telemetry entering the platform · Senzorium
├─ Detect                   detections & rules · NAPSE
├─ Investigate              incidents become stories · AEGIS
├─ Protect                  response & posture
├─ Network/Gateway          router/LAN — Get Online · Wi-Fi · device map · bubbles · device trust · DNS
├─ Automate                 playbooks, agents, workflows (net-new SOAR)
├─ Intelligence             threat intelligence
├─ Customers                recursive multi-tenant portal
├─ Business                 licenses, billing, marketplace, revenue
├─ Knowledge                growth engine: CMS, SEO, docs, runbooks
├─ Administration           identity, edge nodes, telemetry fabric, AI models, build/deploy
└─ AI Copilot               omnipresent overlay (⌘-K)
```

### Lifecycle mapping — Build → Deploy → Run → Manage

The OS lifecycle maps onto the workspaces (the Build/Deploy pieces the original dashboard set was missing now live in Administration):

| Phase | Where it lives |
|---|---|
| **Build** | Administration → Builder, Images, Modules |
| **Deploy** | Administration → Provisioning, Enrollment, Edge Nodes |
| **Run** | Mission Control, Observe, Detect, Investigate, Protect, Automate, Intelligence |
| **Manage** | Administration, Customers, Business, Knowledge |

### Visibility by mode

| Workspace | Standalone | Cloud-linked (MSSP) | Self-hosted CP |
|---|---|---|---|
| Mission Control, Observe, Detect, Investigate, Protect, **Network/Gateway**, Automate, Intelligence | ✓ (this device) | ✓ (any scope) | ✓ |
| Workspace, Knowledge, Administration | ✓ | ✓ | ✓ |
| Customers | — | ✓ | optional |
| Business | local/licensing only | ✓ (full) | optional |

---

# Workspaces

## 1. Mission Control
**Purpose:** global operational awareness — "what is the organism doing right now?" (NASA Mission Control.)

```
Mission Control
├─ Global Health          Organism Status: PROTECTED + QSecBit (the orb)
├─ Threat Pulse           velocity, current level, attacks blocked, top families, trend
├─ AI Activity            decisions by component (NAPSE/HYDRA/AEGIS), escalations, autonomous remediations, confidence
├─ Customer Health        per-tenant cards (linked only)
├─ Fleet Health           healthy / needs-attention / critical
├─ Security Score         QSecBit breakdown
├─ Active Incidents       open queue + priority
├─ Autonomous Actions     what the system did on its own, with rationale
├─ Infrastructure         edges, connections, blocked attacks / global map
├─ Performance            ingest rate, latency, resource headroom
├─ AI Timeline            chronological AI decisions
└─ Notifications          approvals, warnings, updates
```
**Notes:** every card opens its full view; every number drills into the evidence graph. Fleet/Customer cards hidden in standalone. The command bar is most prominent here.

## 2. Workspace
**Purpose:** your recent and saved work, in one place (like VS Code's recents).

```
Workspace
├─ Recent Customers      ├─ Recent Reports      ├─ Bookmarks
├─ Recent Incidents      ├─ AI Conversations    ├─ Favorites
├─ Saved Searches        └─ Draft Playbooks
└─ Saved Investigations
```
**Notes:** scoped to the signed-in operator/tenant; everything links back to live graph objects.

## 3. Observe · Senzorium
**Purpose:** everything entering the platform — all telemetry. Surfaces the Telemetry Fabric operationally.

```
Observe
├─ Endpoints                 ├─ Network      ├─ Syslog
│   ├─ Windows  ├─ Linux     ├─ DNS          ├─ Events
│   ├─ macOS    ├─ Android   ├─ HTTP         ├─ Sensors
│   ├─ IoT      ├─ Containers├─ Packets      ├─ Asset Inventory
│   └─ Kubernetes            ├─ NetFlow      └─ Live Stream
```
**Notes:** sources normalized to a common event schema (eBPF/XDP capture, flows, log ingest). Per-interface roles (out-of-band vs inline) and the **current retention window** are shown here. Capture/inline controls appear only if the manifest grants them. Drill-down: flow → session → packets → raw pcap (within retention tier).

## 4. Detect · NAPSE
**Purpose:** detections, anomalies, and the rules behind them.

```
Detect
├─ Threat Feed            ├─ Sigma          ├─ MITRE
├─ AI Detection          ├─ YARA           ├─ Detection Rules
├─ Behavioral Detection  ├─ IOC Matching   ├─ Rule Builder
├─ Signature Detection   ├─ Threat Hunting └─ Rule Testing
```
**Notes:** wraps the established engines (Suricata / YARA / Sigma) mapped to **MITRE ATT&CK**; custom logic ships as signed Wasm modules. Detection → Investigate (story) or Threat Graph. Gated on `ids`. Intent: "Show today's ransomware attempts and what blocked them."

## 5. Investigate · AEGIS
**Purpose:** turn an alert into an explained narrative — everything becomes a story.

```
Investigate
├─ Incident Queue       ├─ Graph View       ├─ Root Cause
├─ AI Investigation     ├─ Evidence         ├─ Similar Incidents
├─ Attack Timeline      ├─ Packet Replay    ├─ Recommendations
├─ Process Tree         └─ Executive Summary
```
**Notes:** the differentiator. **Incident Story** timeline + **Why AEGIS decided this** (confidence, evidence, alternative hypotheses, model) + context (ATT&CK, CVE, Sigma/YARA, related campaigns) + a **proposed plan (diff)** to approve. Backed by the evidence graph and the BYO LLM; deterministic correlation works with no model.

## 6. Protect
**Purpose:** response and posture — active defense and the controls that hold it.

```
Protect
├─ Firewall      ├─ Isolation     ├─ Patch Management
├─ Endpoint      ├─ VPN           ├─ Compliance
├─ Network       ├─ Zero Trust    └─ Risk
├─ Quarantine    └─ Policies
```
**Notes:** the **data-plane** surface. Per-interface posture (out-of-band default, inline opt-in) and **fail-open / fail-closed** policy per segment. Active controls (blocking, isolation, segmentation) gated on the relevant grants; otherwise alert-only. Intent: "Make the OT VLAN fail-closed." / "Isolate 10.4.2.17 now."

## 6b. Network / Gateway  ·  the router/LAN half (NEW — D1)
**Purpose:** operate the device *as the network* — the gateway/router role V2 originally omitted (`docs/v2-reconciliation.md` D1), and the home of the customer's LAN-management + DNS + Wi-Fi pillars (`docs/v2-customer-experience.md`). Sits between Protect and Automate.

```
Network / Gateway
├─ Get Online        WAN: PPPoE · DHCP · LTE · multi-WAN failover (PBR), link health, speed
│                    (also the permanent home of the newbie Quick-Setup lens — setup.hookprobe.local, ADR 0010)
├─ Wi-Fi             APs (hostapd), SSIDs, bands, DFS/channel intelligence, guest Wi-Fi
├─ Device Map        all clients, online/idle/offline (ARP), drill to device
├─ Zones (Bubbles)   segmentation groups, types, drag-move, pin, AI suggestions, Quarantine
├─ Device Trust      NAC: identify (Fingerbank: DHCP+OUI+hostname+mDNS), tag, trust, block
├─ Apple/IoT Ecosystem  mDNS reflection scope per zone (AirPlay/HomeKit/cast), device-to-device matrix
├─ DNS / Shield      dnsXai resolver, ad/tracker/malware blocking, per-zone DNS profiles
└─ Segmentation Flows (Pro)  the generated OVS/OpenFlow + VLAN + nftables artifacts (read/edit)
```
**Notes:** a **Run** workspace. Capability-gated on `wan`/`dhcp`/`dns`/`wifi_ap`/`openvswitch`; new tokens: `wan`, `dhcp`, `dns`, `dns_filtering`, `segmentation`, `device_trust`, `mdns_reflection` (+ existing `multi_wan`/`wifi_ap`; `wifi_dfs` is **planned, ADR 0042** — not an existing token, and hard-denied on the onboard brcmfmac per ADR 0034 RC-DFS). Customer pillars (Get Online, Device Map, Zones, Shield) are Layer 0; **Segmentation Flows** is Layer 2 (Pro) — the explicit home for OVS/OpenFlow/VLAN/PBR artifacts so they never leak onto the default path. Intent: "put the kids' tablets in their own bubble" / "let the living-room devices see the Apple TV." Full UX in `docs/v2-customer-experience.md`.

## 7. Automate  (net-new SOAR — HYDRA moved to Intelligence, see §reconciliation)
**Purpose:** orchestration — playbooks, agents, and workflows as pipelines.

```
Automate
├─ Playbooks         ├─ Integrations   ├─ Notifications
├─ AI Agents         ├─ Webhooks       ├─ Approval Queue
├─ Workflows         ├─ API            └─ Automation Analytics
├─ Scheduled Tasks
```
**Notes:** playbooks shown as CI/CD-style pipelines (detect → validate → contain → notify → recover → verify → close), each with state and the AEGIS rationale per stage. Autonomy is policy-gated per stage (auto-apply vs approval). Intent: "Auto-contain credential-stuffing but require approval before isolating a server."

## 8. Intelligence · HYDRA
**Purpose:** threat intelligence as a workspace — backed by **HYDRA**, the threat-intel/enrichment pipeline (the production 11-service `ids-hydra-*` stack: feeds/CVE/IOC/anomaly/predictor/temporal).

```
Intelligence
├─ CVEs          ├─ Campaigns   ├─ Reputation
├─ IOC           ├─ MITRE       ├─ Dark Web
├─ Threat Actors ├─ Exploits    ├─ AI Research
├─ Malware       └─ Knowledge Graph
```
**Notes:** ingests STIX/TAXII and MISP feeds; enrichment annotates the graph. IOC → every event/endpoint it touched; CVE → affected assets across scope. Intent: "Show every endpoint exposed to CVE-2024-3094."

## 9. Customers
**Purpose:** the recursive multi-tenant portal — where HookProbe becomes very powerful.

```
Customers
├─ My Organization
├─ Managed Customers
│   ├─ Customer A  ├─ Customer B  ├─ Customer C  └─ …
├─ Customer Dashboard   ├─ SLA          ├─ Reports
├─ Assets               ├─ Compliance   └─ API
├─ Users   ├─ Sites     ├─ Security Score
└─ Billing
```
**Recursive tenancy (AWS Organizations–style):** `HookProbe → MSSP → Customer → Customer → …`. Each customer can itself become an MSSP for its own customers by **tenant inheritance** — unlimited depth, no code changes. **Isolation:** strict per-tenant data segregation, scoped RBAC, separate keys; cross-tenant views are aggregation *above* isolated stores, never shared access. Cloud-linked / self-hosted only.

## 10. Business
**Purpose:** the commercial layer most SOCs ignore — run the business inside the platform.

```
Business
├─ Dashboard   ├─ Quotes      ├─ Revenue   ├─ AI Cost
├─ Licenses    ├─ Usage       ├─ Costs     └─ Reports
├─ Billing     ├─ Contracts   ├─ SLA
├─ Marketplace ├─ Customers
```
**Notes:** **Marketplace** is the signed module catalog (detections, integrations, services; premium modules in cloud-linked mode). **AI Cost** tracks model spend per tenant/workspace. This is the commercial half of the open-core model; standalone shows licensing only.

## 11. Knowledge
**Purpose:** much more than docs — the **growth engine**.

```
Knowledge
├─ Blog CMS         ├─ LinkedIn     ├─ Runbooks
├─ SEO AI           ├─ Newsletter   ├─ SOP
├─ Keyword Research ├─ Documentation├─ Markdown
├─ Page Generator   ├─ Wiki         └─ AI Writer
├─ Video Generator
```
**Notes:** content creation and security knowledge share the same AI layer and evidence graph — a post-incident write-up, a runbook, and a blog article are different lenses on the same material. Drives marketing/SEO from inside the platform.

## 12. Administration
**Purpose:** everything technical — identity, infrastructure, and the OS lifecycle.

```
Administration
├─ Identity & Access        ├─ Infrastructure         ├─ OS Lifecycle (Build → Deploy)
│   ├─ Users                │   ├─ Clusters           │   ├─ Builder
│   ├─ Roles                │   ├─ Edge Nodes         │   ├─ Images & artifacts
│   ├─ Permissions          │   ├─ Storage            │   ├─ Modules
│   ├─ Authentication       │   ├─ Queue              │   ├─ Provisioning
│   ├─ SSO  ├─ OAuth        │   ├─ Databases          │   └─ Enrollment & mode
│   ├─ API Keys             │   └─ AI Models          │
│   └─ Secrets              │                         ├─ Telemetry Fabric
│                           ├─ Operations             ├─ Logging  ├─ Audit
│                           │   ├─ Backup             ├─ Settings
│                           │   └─ Monitoring         └─ Feedback & Diagnostics
```

**OS Lifecycle (the Build → Deploy pieces):**
- **Builder** — compose a signed image for a platform (modules, branding, AEGIS model reference, output formats: `.img.xz` / `.iso` / `.qcow2` / cloud). Community = web form or fork the Containerfile; Factory = `POST /build`.
- **Images & artifacts** — built images by channel (stable/edge/dev), signature/attestation, SBOM + CBOM, provenance; promote/rollback.
- **Modules** — installed modules with `runtime` (wasm/container/sysext), granted capabilities, resource budgets, signatures; install from Marketplace (hot-loaded, no reboot).
- **Provisioning / Enrollment & mode** — flash/import, first-boot claim (local admin, no account), and optional linking to a tenant (standalone / cloud-linked / self-hosted). The day-0 experience is **zero-touch onboarding** (below); enrollment is the optional last step, never a precondition.

**First run — zero-touch onboarding (the captive portal that *becomes* Mission Control)** — headless, no keyboard/monitor/serial (ADR 0010). Power on → factory-key auto-unlock → the SASE-edge AP `HookProbe` comes up → connect a phone/laptop → the OS captive-portal-detects and slides the **setup portal** onto the screen (no IP to type, no SSL warning to dismiss). Setup is **not a form** — it's the **Copilot** with **progressive disclosure**: newbies get ~3 conversational taps (*"I see link on eth0 already pulling a lease — use it as your internet? [Yes] · [PPPoE] · [Advanced]"* → Wi-Fi name/password → **Launch**); *Advanced* reveals only what the manifest grants (PPPoE, VLANs, multi-WAN, DoH, mesh — the full `WanIntent`/`LanIntent`). "Launch" is one **plan-as-diff** you approve → the deterministic reconciler applies + verifies it (never hand-poked config). The handoff is **seamless — L2 stays stable** (same SSID, same `10.66.0.1`), only routing/DNS flip, so the browser never drops; the portal polls **WAN-readiness** and only then redirects to `os.hookprobe.local` (mDNS; stable-IP fallback). One optional screen enrolls a **passphrase** (flips the encryption anchor `software → passphrase`). Afterwards the same UI persists — no longer captive — at **`setup.hookprobe.local`** as the **newbie lens of Network / Gateway → Get Online** (§6b): day-0 setup and day-300 ISP swaps are the same tool at two disclosure levels. Fleet/air-gap uses the **same reconciler** via a signed USB `ignition.hp` (transports are pluggable; the engine is one).

**Edge Nodes** is the per-device control: the **Platform Manifest** viewer (hardware, capabilities, crypto posture), **OS version & channel** with tier-aware updates (`bootc upgrade`/`rollback` on UEFI platforms; OCI-derived A/B image-sync on Pi-native — same signed image, ADR 0019), **storage & retention** (immutable rootfs vs persistent data, per-tier retention window, fill, offload targets), and fleet **rollout rings** (canary → ring → fleet, health-gated).

**Telemetry Fabric** administers the pipeline (sources, parsing, enrichment, normalization, correlation, storage, compression, dedup, AI summary, search).

**AI Models** configures the AEGIS endpoint (Ollama / OpenAI-compatible / cloud), autonomy per playbook, confidence thresholds.

**Settings** — platform, networking (data-plane mode, fail-open/closed defaults), security (secrets sealed to TPM, attestation for fleet join), crypto/PQC (active signing/KEX algorithms, boot scheme, CBOM), updates, integrations (SIEM/SOAR egress, syslog/CEF, webhooks, feeds, API tokens), deployment mode, advanced.

**Feedback & Diagnostics** — the opt-in, **off-by-default** product-health beacon (ADR 0012 D5): its own consent screen showing *exactly* the `beacon.json` that leaves the device (release health only — never security telemetry), a one-click revocable toggle, and an **Export diagnostics file** path that works air-gapped. Cloud-linked mode additionally shows the separate, enrollment-consented ADR 0009 tenant evidence offload. Full UX in `docs/feedback-ux.md`.

## 13. AI Copilot
**Purpose:** the omnipresent conversational front-end to everything — the single biggest UX lever.
**Behavior:** `⌘-K` from any workspace. Returns answers with evidence, or proposed plans as diffs you approve. Scope-aware (device / site / fleet / tenant). Backed by the BYO LLM; deterministic actions run through the reconciler. Examples: "Why is Vodafone risk increasing?", "Find Linux servers missing patches", "Summarise last night's incidents", "Generate a customer report".

---

## Cross-cutting patterns

- **Drill-down contract.** Any aggregate is a link into the evidence graph: `142 threats → families → endpoint → packet → raw evidence`. No dead-end numbers.
- **AI explanation panel.** Reusable side panel on any decision: *why · confidence · evidence · model · related events.*
- **Intent bar.** The command bar produces a **plan as a diff**; the deterministic reconciler applies and verifies it. Same pattern device-wide and fleet-wide.
- **Evidence & retention indicators.** Wherever raw data is referenced, show whether it's still within this device's retention window; offer offload if not.
- **Capability gating.** A control is rendered, greyed-with-reason, or hidden purely from the manifest — never a broken or no-op button.
- **Mode adaptation.** Standalone hides fleet/tenant/business scope; cloud-linked adds the scope switcher and customer/mesh/business views; offline shows "degraded — enforcing last approved state."

---

## Appendix — route map

```
/mission            (landing)
/workspace
/observe/{endpoints, network, dns, http, packets, netflow, syslog, events, sensors, assets, live}
/detect/{feed, ai, behavioral, signature, sigma, yara, ioc, hunting, mitre, rules, builder, testing}
/investigate/{queue, ai, timeline, process-tree, graph, evidence, replay, root-cause, similar, recommendations, summary}
/protect/{firewall, endpoint, network, quarantine, isolation, vpn, zero-trust, policies, patch, compliance, risk}
/network/{wan, wifi, failover, map, zones, devices, trust, ecosystem, dns, flows}
/automate/{playbooks, agents, workflows, scheduled, integrations, webhooks, api, notifications, approvals, analytics}
/intelligence/{cves, ioc, actors, malware, campaigns, mitre, exploits, reputation, darkweb, research, graph}
/customers/{org, managed, dashboard, assets, users, sites, billing, sla, compliance, score, reports, api}
/business/{dashboard, licenses, billing, marketplace, quotes, usage, contracts, customers, revenue, costs, sla, ai-cost, reports}
/knowledge/{blog, seo, keywords, page-gen, video-gen, linkedin, newsletter, docs, wiki, runbooks, sop, markdown, ai-writer}
/admin/{identity, infra, lifecycle, telemetry-fabric, ai-models, logging, audit, backup, settings, feedback}
/admin/lifecycle/{builder, images, modules, provisioning, enrollment, edge-nodes}
```

**Zero-touch onboarding** (ADR 0010) is a device-local flow, not a `/admin` route: the first-boot captive **setup portal** → after Launch it persists (no longer captive) at `setup.hookprobe.local` (the Network/Gateway → Get Online newbie lens) and the full console at `os.hookprobe.local` — both mDNS, stable-IP fallback.

Copilot (`⌘-K`) overlays every route. All routes are scope-aware — in cloud-linked mode they accept a `device / site / fleet / tenant` scope without changing the page's structure. One interface, every platform, every scale.

---

## Reconciliation note

This layout maps components as: **Observe → Senzorium**, **Detect → NAPSE**, **Investigate → AEGIS**, **Intelligence → HYDRA** (threat-intel/enrichment pipeline), **Automate → net-new SOAR** (playbooks/agents; seeded from AEGIS + the V1 autopilots `sdn_autopilot`/`organism_selfheal`/`nac-policy-sync`), **Security Score → QSecBit**. **Corrected 2026-06-29 against production** (see `docs/v2-reconciliation.md`): HYDRA is the threat-intel pipeline (confirmed 4× on real devices), **not** automation — the earlier resolution is reverted. The §7 (Automate) / §8 (Intelligence) workspace bodies still need updating to match.
