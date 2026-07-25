# HookProbe V2 ↔ V1 reality reconciliation

> Grounded in **three real tiers probed 2026-06-29** — Guardian (RPi4/arm64), Fortress (N100/amd64), Cloud-MSSP (`mesh.hookprobe.com`, Ubuntu 24.04/arm64/Oracle) — plus the full system maps `docs/v1-map-{runtime,source,hookprobe-com}.md`. This doc reconciles what V2 *specifies* with what V1 *actually runs*, records the decisions, and lists the fixes.
>
> **Meta-point:** V2-as-originally-specced modeled an idealized "SOC on bootc." The real product is a **router + SOC + MSSP** with a proven Python/Zig/eBPF stack. The V2 *spine* (signed Platform Manifest · capabilities · supervisor · Wasm · bootc · PQC) is the right modernization — but it must **wrap the real product**, not a simplified picture of it.
>
> **Governing framing (operator, 2026-06-29):** V2 takes **V1 as its example and base, and expands it to production-ready** (per `Readme.md`) — it is **not** a from-scratch rewrite. *Keep & harden* V1's engines / mesh / router / detection-science; the **production layer** is what V2 *adds*: the immutable signed **bootc** image, supply chain (SBOM/CBOM/cosign/SLSA), the **manifest/capability** model, **Wasm** sandboxing, **PQC/crypto-agility**, and pull-based **GitOps fleet**. The single fresh rebuild is the **UI** (SolidJS per `MissionControl.md`, keeping the V1 Astro theme); everything else is **expand-not-replace**.

## 1. Decisions made (2026-06-29)

| # | Decision | Rationale (ground truth) |
|---|---|---|
| **D1** | **The gateway/router role is first-class in V2.** | Both edge tiers ARE full gateways: PPPoE WAN + LTE backup + WAN-failover (PBR tables 100/200/300), DHCP/DHCPv6-PD, DNS, hostapd Wi-Fi APs, OVS bridges/VXLAN. V2 had *no* router concept — its biggest gap. |
| **D2** | **HYDRA = threat-intelligence / enrichment** (revert the earlier "HYDRA=automation" resolution). | Confirmed **4×**: N100 `fortress-ids`, Pi `guardian-hydra-lite "Threat Feed Sync"`, and the cloud's **11-service `ids-hydra-*` pipeline** (consumer/enricher/features/cve/anomaly/temporal/predictor/feed/sentinel/sentinel-engine/lifecycle). There is no "HYDRA automation engine" anywhere. |
| **D3** | **Standalone *and* cloud-linked MSSP are both first-class.** | Reality is account/MSSP-first (Keycloak, the whole Oracle VM, `node.conf` API key on by default). Keep standalone as the *differentiator* (air-gap/sovereignty — it must always work), but MSSP is the primary deployment path, not merely "additive." |

## 2. Settled by ground truth (no decision needed)

- **eBPF = CO-RE, conditioned on V2 owning the kernel.** `CONFIG_DEBUG_INFO_BTF` is `n` across the *entire* Raspberry Pi OS kernel family (v8 **and** 2712 — so Pi5/CM5 don't fix it). But V2 ships its own bootc kernel (the Readme's "custom edge-SoC kernel" pole) → set `BTF=y` → CO-RE works uniformly, no on-device compiler in the image. Interim/stock-Pi-OS bring-up: ship a `pahole`-generated BTF blob (`btf_custom_path`) or runtime-BCC. The `modules/napse-capture` precompiled-CO-RE sysext scaffold stands.
- **Platform matching needs a CPU-model fallback.** Real N100 has blank DMI (`"Default string"`) → currently misclassifies as `generic`; `platforms/n100.yaml` must also match on `cpu.model ~= "Intel(R) N100"`. DT matching works correctly on ARM (`raspberrypi,4-model-b`/`brcm,bcm2711`).
- **HTP forward-secrecy is a *production* issue, not just future work.** The live gateways (cloud + guardian) are **PSK-only, no DH/FS** (`htp_gateway.py --psk-file`). The HTP-v2 hardened handshake (`docs/htp-v2-handshake.md`) must reconcile against **`hsg`** — the real Zig "HTP Synaptic Gateway" (`/opt/hookprobe/bin/hsg`, PKI cert/key) — not just the Python `htp_gateway.py`.
- **arm64 is the PRIMARY arch; the lever is resource-tiering.** The cloud MSSP is **Ampere arm64** (Oracle) — the *heavy* tier: the 11-service HYDRA pipeline, ClickHouse, AI-WAF/ML, federated learning, the planner LLM. The **Pi is constrained arm64** (4c / ≤8 GB) — the *lean* tier. N100 is the amd64 mid-tier outlier. So the **same arm64 Wasm + containers run on cloud and Pi**, differing only by what the manifest grants and budgets. **"Get the most out of the Pi"** = a curated lean module set + tight Wasm budgets (fuel/epoch + memory caps) + **offload heavy work to the Ampere cloud** (the Readme's bounded-retention/offload) + use the NPU/`edge_ai` where the board has one. Heavy engines (HYDRA pipeline, ClickHouse, federated learning, large ML) are **cloud/Nexus-tier, never Pi-tier** — the products tiers (sentinel→guardian→fortress→nexus) already encode this gradient.

## 3. Corrected component → V2 mapping (all tiers)

Replaces the earlier component table. Runtime per `docs/runtime-engine-map.md` (corrected for HYDRA).

| V1 component (real) | V2 workspace | Runtime | Capability | Notes |
|---|---|---|---|---|
| Senzorium (capture/ingest) | Observe | sysext (XDP) + wasm | `capture`→`flows`/`packets` | XDP capture = `napse-capture` sysext (CO-RE) |
| **NAPSE** synthesis | Detect | wasm | `napse` | ported ✅ (Viterbi-HMM + Bayesian + signatures) |
| **HYDRA** (threat-intel pipeline) | **Intelligence** (NOT Automate) | container (11 services) | `threat_intel` | **reverted**: feeds/enrich/CVE/anomaly/predictor — STIX/TAXII/MISP |
| **AEGIS** (planner + reconciler) | Investigate + intent everywhere | wasm (guard) + container (planner) | `policy_guard`, `ai_planner` | guard ported ✅; **reconciler runs nowhere in prod** — real automation = `sdn_autopilot`/`organism_selfheal`/`nac-policy-sync` (reuse as AEGIS's first actions) |
| **QSECBIT** score | Security Score / orb | wasm | `qsecbit` | ported ✅ (xdp_manager rate-limit = `ddos_mitigation`, separate) |
| **Automate** (playbooks/SOAR) | Automate | wasm/container | (new `automation`) | **net-new** — no dedicated V1 engine; seed from the autopilots |
| dnsXai | Detect/Protect (DNS) | wasm | `dns_filtering` | ported ✅; runs live as a DoH resolver on Guardian |
| **Gateway/router** (PPPoE/LTE/WAN-failover/DHCP/DNS) | **NEW: Network/Gateway** | sysext/container | new: `wan`, `multi_wan`✓, `dhcp`, `dns` | **D1** — the missing half |
| hostapd Wi-Fi AP | Network/Gateway | sysext/container | `wifi_ap`✓, `wifi_dfs`✓ | dual-radio (AP + WAN scan) on Pi |
| OVS / SDN (`sdn_autopilot`) | Network/Protect | image-layer | `sdn`✓, `openvswitch`✓ | 108KB OpenFlow autopilot |
| **HTP/Neuro/DSM mesh** (+ `hsg` Zig) | Automate/Fleet (additive) | container + image-layer | `secure_tunnel`✓, `fleet_mesh`✓ | `mesh_server.py`+`htp_gateway.py`+`hsg`; PSK→harden per HTP-v2 |
| **CNO / organism** | Mission Control (orb) | container | (new `organism`) | Ollama tinyllama; the "organism" viz |
| **AIOCHI** (Suricata + Zeek + identity/bubble/logshipper) | Observe/Detect | container | (new `nsm`) | real NSM engines — wraps Suricata/Zeek as Readme promised |
| aegis-ledger | Investigate/Protect | container | (new `evidence_ledger`) | signed action/IOC ledger → evidence graph |
| ai-waf (TinyBERT ONNX) | Protect | wasm (WASI-NN) / container | (new `waf`) | ModSecurity on Guardian; TinyBERT in cloud |
| fingerprint / presence / device-trust (NAC) | Observe/Protect | container/wasm | (new `nac`, `fingerprint`) | unified_fingerprint, JA3, lstm, fingerbank |
| Nexus (federated learning, red/purple) | Administration/Intelligence | container | (new `fleet_learning`) | aggregation/privacy/digital-twin |
| Alexandria / Django MSSP backend | Customers/Business/Knowledge | container | — | the MSSP portal + CMS (cloud lens) |

New capability tokens implied: `wan`, `dhcp`, `dns`, `organism`, `nsm`, `evidence_ledger`, `waf`, `nac`, `fingerprint`, `automation`, `fleet_learning` (to fold into `platforms/*.yaml` + ADR 0003, same pattern as the prior batch).

## 4. The HYDRA remap (D2) — workspace impact

- **Intelligence** workspace ← **HYDRA** (the threat-intel/enrichment pipeline: feeds, CVE, IOC, anomaly, predictor, temporal). This is what HYDRA *is*.
- **Automate** workspace ← a **net-new automation/SOAR** capability (playbooks/agents/workflows) — there is no V1 "HYDRA automation"; seed it from the proven reconcilers (`sdn_autopilot`, `organism_selfheal`, `nac-policy-sync`) under AEGIS.
- **Detect** (NAPSE) consumes HYDRA enrichment. The Readme/MissionControl/CLAUDE.md are corrected accordingly.

## 5. Actions

**Applied now (canonical doc fixes):** HYDRA reverted to threat-intel across `CLAUDE.md`, `docs/Readme.md`, `docs/MissionControl.md`; this doc added; memory updated.
**Queued (scaffold/code fixes):**
1. Add the **Network/Gateway** workspace + `wan`/`dhcp`/`dns` capabilities to MissionControl.md + `platforms/*.yaml` (D1).
2. `platforms/n100.yaml`: add CPU-model match fallback; fix the probe's virtual-NIC filtering.
3. Fold the new capability tokens (§3) into `platforms/*.yaml` + ADR 0003.
4. Reconcile `docs/htp-v2-handshake.md` against **`hsg`** (Zig); prioritize the FS fix for the *live* gateway.
5. Map the unmapped subsystems (CNO/AIOCHI/aegis-ledger/ai-waf/nac/Nexus) into the runtime-engine-map with runtimes.
6. V2 kernel: set `CONFIG_DEBUG_INFO_BTF=y` in `base/` (the custom-kernel work).

## 6. Open follow-ups for the operator

- Confirm the **Network/Gateway** workspace shape (it's a big addition to MissionControl.md — `ux-architect` task).
- Decide whether **Automate** is AEGIS-playbooks or a distinct engine.
- The dashboard's **read-only-except-`master_admin`** model conflicts with V2's plan-as-diff *write* model — resolve.
