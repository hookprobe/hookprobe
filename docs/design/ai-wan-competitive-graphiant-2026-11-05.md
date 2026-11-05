# AI WAN — Graphiant and the field vs HookProbe OS (2026-11-05)

Research pass by the `market-intelligence` agent; saved and fact-corrected by the main session.
Tags: **[V]** verified against a primary vendor source / press release · **[VS]** vendor-stated,
not independently benchmarked · **[U]** unverified.

> **Correction applied (main session):** the agent listed "IDS on the heqk AP path" as an open item.
> It was **metal-proven on 2026-11-04**: an iPhone on heqk's AP, Private Relay off, SYNs to
> 1.1.1.1:4444 dropped by signed rule 1 `block-port-4444` (43 drops, zero packets on the wire) —
> `docs/design/heqk-ap-nat-investigation-2026-11-04.md`.

## Name check
"Graphian" = **Graphiant** (San Jose, network-as-a-service). Founder Khalid Raza co-founded
**Viptela** (SD-WAN, acquired by Cisco 2017) — not Juniper. Series B $62M (Mar 2023, Sequoia) +
$19M extension (May 2025, Wa'ed/Aramco, Tali/stc).

## 1. What Graphiant ships
- **Architecture [V/VS]:** edges encrypt the payload once and add IPv6/metadata labels; a
  **stateless core** forwards on labels and never decrypts ("no customer routes or VRFs in the
  core", "no mesh of IPsec tunnels"); TPM/HSM-backed keys; cloud gateways in carrier-neutral
  facilities with private on-ramps to AWS/Azure/GCP; one cloud portal. A private middle-mile
  backbone sold as a service.
- **AI = "Gina AI" (5 Nov 2025) [V/VS]:** an operational assistant inside the portal — fabric
  telemetry analysis, real-time path validation and deviation flags, audit-ready compliance
  evidence ("Graphiant Data Assurance"); models undisclosed. CEO (Apr 2026): "fully agentic
  platform", MCP server for agents, "1/4th" the ops staff **[VS]**.
- **Recent:** PQC suites + crypto-agility with Intel (Mar 2026; algorithms not named) [V/VS];
  SASE in the fabric — ZTNA, threat detection, malware, DLP "at no additional cost" (Apr 2026;
  inspection point undisclosed) [V/VS]; Peraton federal partnership (Aug 2026) [V].
- **Customers / price:** enterprises, carriers/SPs, AI data-centre operators, US federal;
  subscription, no per-site licences; price not public; "two-thirds cheaper" is an analyst quote
  in Graphiant's own release **[VS]**.

**In one line:** cloud-hosted assurance and compliance over a backbone they own — not on-device
decisions, not an IDS.

## 2. The field (directional)
- **HPE Juniper Mist WAN Assurance + Marvis:** cloud AIOps, anomaly detection, NL troubleshooting.
- **Cisco Catalyst SD-WAN:** AI Assistant (beta) for NL config/troubleshooting, AgenticOps.
- **Fortinet:** FortiAI-Assist / FortiOS 8.0 agents; FortiAIOps a separate subscription.
- **Palo Alto Prisma SD-WAN:** AIOps + ADEM + Strata Copilot.
- **Cato Networks:** agentic CVE mitigation / threat prevention in Cato's PoP cloud.

**Common thread:** the AI lives in the vendor's cloud, needs an account and connectivity; none ships
a full local IDS/IPS that keeps enforcing with the AI switched off.

## 3. HookProbe OS: where we are ahead, where we are behind
**Ahead**
1. **The WAN edge is the SOC.** Inline detection + enforcement on the device, legit always passes
   (ADR 0023); 31/31 heqk-plane separation rows metal-proven (Gate R CONDITIONAL-GO); IPS proven on
   the heqk AP path (2026-11-04). Graphiant's core never opens the payload by design.
2. **Standalone / air-gapped.** No account, no portal.
3. **AI never in the enforcement path (C9).** Deterministic reconciler enforces; the operator's own
   LLM (local or remote) only proposes — immune to the "agentic enforcement" failure modes.
4. **One signed evidence graph** — on-device, verifiable audit evidence (Gina's pitch, without the
   cloud); M6 evidence export built.
5. **Open core (AGPL), cheap hardware, signed supply chain**; PQ-hybrid control channel
   (X25519 + ML-KEM-768 Noise) Established on CM5 metal against a simulator.

**Behind (say so plainly)**
- No backbone, no SLA, no cloud on-ramps or carrier partners.
- SASE tunnel to a super-PoP not built (`edge.rs`: kill-switch decision + anti-replay only).
- Multi-WAN failover and the Get-Online / WAN wizard not built (BuildPlan §6b). **WAN modes
  static/DHCP/PPPoE on heqk are being built now (task #24).**
- heqk AP is young (steady 22 Mbps on 2026-11-04).
- No multi-site fleet yet (Phase 7); no path-quality (loss/jitter/latency) steering.

## 4. Differentiation bets (prioritized)
1. **"The WAN that inspects itself"** — inline IPS on every uplink + the AP, with
   legit-always-passes as a published, reproducible proof (Gate R across WAN + AP ports).
2. **AI WAN that keeps working with the AI and the cloud off** — intent-driven multi-WAN (wired /
   Wi-Fi STA / LTE): "keep payroll on fiber, fail over to LTE" → plan-as-diff → apply → verify →
   roll back; the LLM only proposes. Proof: timed failover on metal with the planner disabled.
3. **Offline, signed WAN assurance in the evidence graph** — uplink health, path changes, policy
   checks as signed nodes exportable as compliance evidence a third party can verify.
4. **Sovereign, portable SASE edge with a self-hostable PoP** — HTP-v2 PQ-hybrid tunnel + an AGPL
   super-PoP an MSSP/government can run; reuse the kill-switch logic.
5. **Positioning:** the secure on-ramp *into* Graphiant or any NaaS — the site edge, not a rival
   backbone.

## Do NOT claim
SLA / backbone / global path optimisation; SASE tunnelling as shipping; "zero-Linux SOC" as a
reproducible gate (one acceptance run ≠ the ADR 0044 D4 gate); "first/only PQC" (accurate: hybrid
ML-DSA-65 + Ed25519 module signing; hybrid ML-KEM control channel on metal vs a simulator; no
ML-KEM data plane); Wi-Fi throughput leadership; multi-site fleet maturity.

## Follow-ups
- Add a "WAN/SASE field" section to `docs/product-cortex-competitive.md` (market-intelligence).
- Candidate requirements (ideation-scout): multi-WAN intent failover; Gate R on the AP path;
  self-hostable super-PoP.

## Sources
Graphiant: [next-gen WAN without tunnels](https://www.graphiant.com/resources/next-gen-wan-without-tunnels) ·
[docs](https://docs.graphiant.com/docs/what-is-graphiant.md) ·
[Gina AI](https://www.newswire.com/news/graphiant-introduces-gina-ai-an-intelligent-network-assistant-woven-22667055) ·
[native SASE](https://www.graphiant.com/resources/graphiant-commoditizes-sase-by-embedding-it-directly-into-its-naas-fabric) ·
[PQC (CIO Dive)](https://www.ciodive.com/press-release/20260317-graphiant-introduces-quantum-ready-crypto-agile-encryption-capabilities-fo/) ·
[CEO interview (Pulse 2.0)](https://pulse2.com/graphiant-profile-ali-shaikh-interview/) ·
[Peraton](https://www.graphiant.com/resources/graphiant-and-peraton-announce-partnership-on-fully-ai-capable-network-services) ·
[Peraton analysis](https://www.remio.ai/post/peraton-and-graphiants-ai-network-partnership-faces-a-federal-test) ·
[Series B](https://convergedigest.com/graphiant-lands-62-million-for-its-network-edge-service/) ·
[$19M extension](https://www.wamda.com/index.php/2025/05/waed-ventures-leads-19-million-investment-graphiant).
Field: [Juniper Mist WAN Assurance](https://juniper.net/gb/en/products/cloud-services/wan-assurance.html) ·
[Cisco SD-WAN AI Assistant](https://selfservelabs.cisco.com/guides/catalyst-sd-wan-instant-demo-2/section4/page1/) ·
[Cisco Live 2026](https://www.presidio.com/blogs/cisco-live-2026-the-agentic-era-has-arrived/) ·
[FortiOS 8.0](https://www.marketscreener.com/quote/stock/FORTINET-INC-60103137/news/Fortinet-Introduces-FortiOS-8-0-to-Expand-Secure-Networking-with-Secure-AI-Controls-Fabric-based-AI-52650499/) ·
[Prisma ADEM](https://docs.paloaltonetworks.com/prisma-sd-wan/cloudblades/prisma-access-integrations/autonomous-dem-adem-for-prisma-sd-wan-remote-networks) ·
[Cato agentic threat prevention](https://networkworld.com/article/4204054/cato-networks-launches-agentic-threat-prevention.html) ·
[Cato agentic CVE mitigation](https://www.prnewswire.com/il/news-releases/cato-networks-sets-new-benchmark-cutting-time-to-protect-to-45-minutes-with-full-agentic-cve-mitigation-302786546.html).
