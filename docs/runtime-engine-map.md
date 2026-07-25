# Runtime-per-engine map (V1 parts → V2 modules)

> Bridges the V1 inventory ([V1-alignment.md](V1-alignment.md)) to the V2 module model. For **every significant engine** in `~/hookprobe` it decides: which V2 component/workspace it becomes, its **chosen runtime** (`wasm` | `container` | `sysext` | `image-layer`), a `module.yaml` sketch, and a migration call (repackage / rewrite-in-Rust-Wasm / rebuild).
>
> Canon it obeys: [Readme.md](Readme.md) "right tool per layer" (wasm = detection/policy/enrichment logic; container = heavy stateful services; sysext/image-layer = host-integral kernel/dataplane), [Architecture.md](Architecture.md) C10–C12 + two-wall budgets, [ADR 0003](adr/0003-platform-manifest-schema.md) (module model, capability tokens, `grant = presence ∧ known-good ∧ policy`), [ADR 0002](adr/0002-crypto-agility-pqc.md) (standards crypto replaces V1 bespoke). Sketches follow `modules/*/module.yaml`.
>
> **Findings are first-hand** from inspecting `~/hookprobe` on 2026-06-28: Python-first monorepo, native hot paths in **Zig (XDP/eBPF), C (eBPF), Mojo (SIMD ML classify)**, shipped as **containers + a host installer** (not image-based). Confirmed: `core/napse` Containerfile declares *"Requires host network + SYS_BPF + NET_ADMIN + NET_RAW"* and a *"Zig (capture) + Mojo (classify) + Python (synthesis)"* split-brain; `core/brain/hw_detect.py` re-probes 13 accelerator types at startup (a detect-once violation, see notes); `core/neuro/synaptic_encryption.py` is bespoke "nobody-knows-the-key" crypto marked *Proprietary*; `core/htp/crypto/hybrid_kem.py` is X25519+**Kyber512** (pre-final param set).

---

## 0. The honest constraint (why not everything is Wasm)

Wasm/WASI **cannot** host these cleanly today, so the V2 default (`runtime: wasm`) does **not** apply to them:

- **eBPF/XDP** (Zig `xdp_program.zig`, C `xdp_gate.c`/`af_xdp_rx.c`/`syscall_monitor.c`) — runs in the kernel, needs `CAP_BPF`/`CAP_NET_ADMIN`/`CAP_NET_RAW`, AF_XDP socket rings. → **sysext / image-layer**, governed by a cgroup *slice*, not a Wasm module budget.
- **Mojo** (`brain/src/*.mojo`) — no production Wasm target; depends on the Mojo/MAX runtime. → **container** now; flagged WASI-NN rewrite candidate.
- **Heavy stateful Python ML / long-running daemons** (qsecbit ML training, aegis orchestrator, mirage honeypot) → **container** (rootless Podman/Quadlet).
- **Greenfield, portable detection/policy/enrichment logic** → **wasm** (rewrite-in-Rust), the V2 default.
- **OVS / hostapd-OVS** → **image-layer/sysext** (host-integral dataplane).

So several V1 dirs **split** across runtimes (napse and qsecbit most of all) — a V1 dir is *not* a V2 module 1:1.

---

## 1. The map (every significant engine)

Budget tiers (from ADR 0003 `resources.defaults`): **wasm-S** = 25%/128MB · **wasm-M** = 50%/256MB · **container-S** = 100%/512MB · **container-H** = 200%+/1–4GB · **sysext** = host slice (cgroup, not a module budget) · **N/A** = retired/superseded.

| V1 engine | V1 lang / host needs | V2 component · workspace | Runtime | Budget | Migration call |
|---|---|---|---|---|---|
| **core/napse** (capture: Zig XDP + C eBPF) | Zig/C; SYS_BPF, NET_ADMIN, NET_RAW, AF_XDP | Senzorium · Observe (+ NAPSE feed) | **sysext / image-layer** | sysext | **Repackage as-is** (crown jewel); pre-compile CO-RE objects into image |
| **core/napse** (classify: Mojo SIMD/HMM) | Mojo; MAX runtime | NAPSE · Detect | **container** | container-S | Repackage now; **WASI-NN rewrite candidate** |
| **core/napse** (synthesis/intelligence: Python bayesian/entity_graph/intent_decoder) | Python | NAPSE · Detect | **wasm** | wasm-M | **Rewrite-in-Rust/Wasm** (portable detection logic) |
| **core/aegis** (orchestrator/oracle/narrator/neurokernel) | Python; calls LLMs | AEGIS · Investigate (AI planner) | **container** | container-S | Repackage as the **BYO-LLM planner adapter** (assistive, never enforcing) |
| **core/aegis** (principle_guard / reflex / verdict) | Python | AEGIS · Investigate (policy) | **wasm** | wasm-S | Rewrite-in-Rust/Wasm (deterministic policy guards) |
| **core/aegis** (neurokernel `ebpf_compiler`/templates) | Python → eBPF | Senzorium dataplane control | **image-layer** + host bridge | sysext | Rebuild: prefer **pre-compiled CO-RE**, not runtime compilation on an immutable image |
| **core/qsecbit** (score: Mahalanobis + entropy + L2–L7 detectors) | Python | QSECBIT · Organism Status orb | **wasm** | wasm-M | **Rewrite-in-Rust/Wasm** (the resilience score is portable logic) |
| **core/qsecbit** (ml: vae/classifier/hybrid/neural_drift) | Python; numpy/torch | QSECBIT · score | **container** | container-H | Repackage; inference → **WASI-NN candidate**, training stays container |
| **core/qsecbit** (xdp_manager / nic_detector DDoS) | Python over eBPF maps | NAPSE/Protect (DDoS) | **sysext** + host bridge | sysext | Repackage dataplane; `nic_detector` is **superseded by bootstrap** (detect-once) |
| **core/hydra** (playbooks/lifecycle/anomaly/predictor) | Python | HYDRA · Intelligence (anomaly/predictor/enrichment); playbooks → **Automate** (net-new SOAR, not HYDRA-branded) | **wasm** | wasm-M | **Rewrite-in-Rust/Wasm** (enrichment/baselining → Intelligence; SOAR playbooks seed the net-new Automate reconcilers) |
| **core/hydra** (feed_sync/cve_enricher/rdap_enricher) | Python; net egress | Intelligence (feeds) | **container** | container-S | Repackage; **note: feeds = Intelligence workspace**, not HYDRA (canon) |
| **core/hydra** (bpf_map_ops) | Python over eBPF maps | dataplane control | host bridge | sysext | Fold into the OS-Agent host bridge |
| **core/cno** ("cognitive organism": prefrontal/metacognition/global_workspace) | Python; heavy | AEGIS/QSECBIT (organism) | **container** | container-H | **Selectively reuse** (research-grade); not Phase-1/2 critical |
| **core/cno** (federated_sync/peer_transport/native xsk_consumer) | Python + Zig/C AF_XDP | Fleet (additive) / dataplane | **container** + sysext | container-S | **Fleet-layer, additive** — never a precondition (see §3) |
| **core/brain** (inference backends: llama/openvino/tensorrt/hailo/rknn/coreml/litert) | Python | edge_ai provider | **container** (fallback) | container-H | **Largely superseded by WASI-NN**; keep container only for backends WASI-NN can't reach yet |
| **core/brain** (`hw_detect.py`) | Python; probes HW at startup | — | **N/A (retire)** | — | **Rebuild into bootstrap** — re-probing HW violates detect-once; `edge_ai` comes from the manifest |
| **core/neuro** (NSE `synaptic_encryption`) | Python; bespoke crypto | — | **N/A (replace)** | — | **Rebuild per ADR 0002** — bespoke "nobody-knows-the-key" crypto is a credibility risk; drop |
| **core/neuro** (PUF/`hardware_fingerprint`/attestation/device_identity) | Python | Identity / bootstrap | **container** → bootstrap | container-S | Reuse *concepts* for IDevID, but conform to ADR 0002 + ADR 0003 `identity` block |
| **core/neuro** (adversarial engine/mitigator/analyzer) | Python | NAPSE · Detect | **wasm** | wasm-M | Rewrite-in-Rust/Wasm (adversarial-input detection is portable) |
| **core/htp** (transport/vpn/steganography/domain_fronting) | Python | Fleet mesh transport (additive) | **container** | container-S | **Fleet-layer, additive**; reconcile vs pull-GitOps (§3) |
| **core/htp** (`hybrid_kem` X25519+Kyber512) | Python | crypto | **N/A (align)** | — | Replace Kyber512 → **ML-KEM-768+x25519** per ADR 0002 `tls_kex` |
| **core/common** (health, clickhouse) | Python | backend infra | **N/A** | — | Drop clickhouse (Architecture mandates **SQLite+DuckDB**); `health` → backend `sd_notify` |
| **shared/dnsXai** (AI adblock: lexical features + neural classifier + CNAME uncloak) | Python; lightweight ML | NAPSE/Senzorium · Detect/Intelligence | **wasm** | wasm-M | **Rewrite-in-Rust/Wasm + WASI-NN** — ideal Wasm fit (edge classifier) |
| **shared/hostapd-ovs** (hostapd 2.10/2.11 + OVS bridge patch) | bash/C build | OVS + Wi-Fi dataplane | **image-layer** | sysext | **Repackage as-is** into the image; provides `wifi_ap` over OVS |
| **shared/network** (segmentation + SDN OpenFlow controller) | Python over OVS | AEGIS reconciler / segmentation | **wasm** (policy) + host bridge | wasm-S | Rewrite policy in Wasm; flow programming via OVS host bridge (`sdn` cap) |
| **shared/response** (mitigation/kali bash + systemd) | bash; iptables/host | **Automate** (net-new SOAR) / Protect | **wasm** playbooks + host bridge | wasm-S | **Rebuild** — don't carry bash; actions go through the narrow OS-Agent bridge |
| **shared/wireless** (DFS intelligence, channel scanner) | Python + bash; NET_ADMIN, regdb | Wi-Fi (under `wifi_ap`) | **container** + host bridge | container-S | Repackage; needs regulatory-domain host access (`wifi_dfs`) |
| **shared/mirage** (adaptive honeypot, deception) | Python; opens listeners | Protect / Detect (deception) | **container** | container-S | Repackage as deception service (`deception` cap) |
| **shared/slaai** (SLA failover/failback, PBR, cost-aware routing) | Python; PBR/routing | Automate / Protect (continuity) | **wasm** (decide) + host bridge | wasm-M | Rewrite decision logic in Wasm; routing via host bridge (`multi_wan`) |
| **shared/mobile_security** (mobile network protection) | Python; small | NAPSE · Detect | **wasm** | wasm-S | Rewrite-in-Rust/Wasm (niche detection) |
| **shared/aiochi** ("AI Eyes" narrative layer + openrouter client) | Python; large; LLM | AEGIS · AI Copilot (narration) | **container** | container-S | Repackage narration into the AEGIS planner/Copilot (BYO-LLM); much is UX → Mission Control |
| **shared/iam** (RBAC + Keycloak middleware) | Python | Administration (auth) | **container** | container-S | **Cloud-lens only** — standalone uses local-admin claim; must NOT gate the device |
| **shared/mssp** (multi-tenant telemetry/bootstrap/client) | Python | Customers / cloud control plane | **container** | container-S | **Additive cloud layer** (mode-aware); never a precondition |
| **shared/cortex** (fleet command center, globe, node registry, geo) | Python + JS | Fleet view (cloud-linked) | **container** | container-S | **Additive fleet layer**; UI folds into Mission Control fleet view |
| **shared/dsm** (Byzantine consensus, merkle, gossip, BLS, ledger, bloom_ioc) | Python; BLS crypto | Fleet (additive) / Intelligence (IOC) | **container** | container-H | **Fleet-layer, additive**; BLS/attestation → ADR 0002; **flag P2P vs GitOps** (§3) |
| **shared/mesh** (federated transport, NAT traversal, gossip, htp_gateway) | Python | Fleet (additive) | **container** | container-S | **Fleet-layer, additive** (§3) |
| **shared/common** (gossip_envelope) | Python | Fleet (additive) | **container** | wasm-S | Fleet-layer shared lib |

---

## 2. Capability tokens introduced

Beyond the ADR 0003 baseline (`soc`, `ids`, `openvswitch`, `wifi_ap`, `edge_ai`, `inline_ips`), these engines imply new **flat, stable tokens** (each needs `known-good`/policy entries in `platforms/*.yaml`):

| Token | Granted when (presence ∧ known-good ∧ policy) | Gated engines |
|---|---|---|
| `capture` | NIC supports XDP (native/SKB) + `CAP_BPF` | napse capture (sysext) |
| `host_telemetry` | kernel BTF/CO-RE + `CAP_BPF` for process/file/syscall eBPF | napse syscall/process tracers |
| `ddos_mitigation` | `capture` + inline/XDP-drop-capable NIC on known-good list | qsecbit xdp_manager |
| `sdn` | `openvswitch` granted (OVS/OpenFlow programmable) | network OpenFlow controller |
| `wifi_dfs` | `wifi_ap` + DFS-capable PHY + reg-domain access | wireless DFS |
| `dns_filtering` | `soc` (DNS interception path available) | dnsXai |
| `threat_intel` | `soc` + egress policy allows feed fetch | hydra feeds, dsm bloom_ioc |
| `deception` | `soc` + spare listener ports / honeypot subnet | mirage |
| `multi_wan` | ≥2 WAN-capable interfaces | slaai failover/PBR |
| `fleet_mesh` | **enrolled** + policy opt-in (additive; never a precondition) | htp, dsm, mesh, cno-federated, cortex |
| `ai_planner` | reachable OpenAI-compatible/Ollama endpoint configured | aegis planner, aiochi |

Notes:
- `multi_tenant`/MSSP is a **deployment-mode** flag (`identity.tenant` set), not a hardware capability — keep it out of `capabilities`.
- `npu` inference stays under existing **`edge_ai`** (don't add a token; brain/qsecbit-ml route through WASI-NN where possible).
- `fleet_mesh` is the single gate that keeps the entire V1 P2P herd-immunity stack (htp/dsm/mesh/cno-federated/cortex) **additive** — a standalone air-gapped box never grants it, satisfying standalone-first.

---

## 3. The federated mesh — runtime + flag

htp / dsm / mesh / cno-federated / cortex / neuro-validation are the V1 **P2P "herd-immunity" mesh** (HTP transport, DSM Byzantine consensus, NEURO fingerprinting/NSE, Nexus aggregators). For V2:

- **Runtime:** **container** (heavy stateful Python), gated by `fleet_mesh` (granted only when enrolled + policy opt-in).
- **Flag (open decision, carried from V1-alignment §6):** V2's fleet is **pull-based GitOps** ([Readme.md](Readme.md) Fleet & scale), *not* P2P Byzantine consensus. These engines are **additive enrichment**, never the control plane. Decide whether the P2P mesh ships as an optional intel-sharing overlay *on top of* GitOps, or is dropped. Either way it is **never a precondition** — standalone-first holds.
- **Crypto:** all mesh crypto (NSE `synaptic_encryption`, htp Kyber512, dsm BLS/attestation) is **bespoke or pre-final** → must move to ADR 0002 standards (ML-KEM-768+x25519, ML-DSA-65, LMS/XMSS for boot) before any of it ships. NSE "nobody-knows-the-key" is dropped, not migrated.

---

## 4. Sample `module.yaml` sketches (the load-bearing ones)

NAPSE splits into three artifacts; here are the new/changed sketches consistent with `modules/*/module.yaml`. (Existing `modules/napse`, `modules/hydra`, `modules/edge-ai-detector`, `modules/inline-guard` already cover the wasm faces.)

**napse-capture (sysext — the Zig/C XDP dataplane):**
```yaml
id: napse-capture
runtime: sysext              # kernel/eBPF; governed by a cgroup slice, not a Wasm budget
requires:
  capabilities: [capture]    # NIC XDP-capable + CAP_BPF, known-good gated
grants:
  - cap: [bpf, net_admin, net_raw]
  - af_xdp: rx
provides:
  capabilities: [flows, packets]   # feeds /var/lib/hookprobe/flows for wasm modules
signature: required
```

**napse-classify (container — Mojo, WASI-NN rewrite candidate):**
```yaml
id: napse-classify
runtime: container
requires:
  capabilities: [soc, ids, flows]
grants:
  - read: /var/lib/hookprobe/flows
resources: { cpu_pct: 100, memory_mb: 512 }
provides:
  capabilities: [classification]
signature: required
```

**qsecbit (wasm — the resilience score):**
```yaml
id: qsecbit
runtime: wasm
requires:
  capabilities: [soc, flows]
  min_memory_mb: 256
grants:
  - read: /var/lib/hookprobe/events
  - wasi-nn: cpu            # Mahalanobis/entropy on CPU; npu via edge_ai when granted
resources: { cpu_pct: 50, memory_mb: 256, epoch_ms: 50 }
provides:
  capabilities: [qsecbit]
signature: required
```

**dnsXai (wasm — ideal fit):**
```yaml
id: dns-filter
runtime: wasm
requires:
  capabilities: [soc, dns_filtering]
  min_memory_mb: 128
grants:
  - read: /var/lib/hookprobe/dns
  - wasi-nn: cpu
resources: { cpu_pct: 25, memory_mb: 128, epoch_ms: 50 }
provides:
  capabilities: [dns_filtering]
signature: required
```

**aegis-planner (container — additive, assistive only):**
```yaml
id: aegis-planner
runtime: container
requires:
  capabilities: [soc, ai_planner]    # soft: reconciler runs with NO planner
grants:
  - net: { egress: [llm_endpoint] }  # BYO OpenAI-compatible / local Ollama
  - read: /var/lib/hookprobe/events
resources: { cpu_pct: 100, memory_mb: 512 }
provides:
  capabilities: [ai_planning]
signature: required
```

> Every `grants:` entry above is the WASI/host access the supervisor enforces (Architecture C10–C11): wasm via Wasmtime epoch + `StoreLimits`; container via cgroups; sysext via a host slice. `requires` for the AI planner is **soft** (`required=false` semantics, ADR-0003 §capability model) — the deterministic reconciler must keep enforcing with no model.

---

## 5. Runtime split (counts)

Counting by **resolved artifact** (napse → 3, qsecbit → 3, hydra → 3, aegis → 3, brain/neuro/htp/common split):

- **wasm** (~12): napse-synthesis, aegis policy guards, qsecbit score, hydra playbooks, neuro-adversarial, dnsXai, network policy, response playbooks, slaai decision, mobile_security, (+ existing napse/hydra/inline-guard/edge-ai wasm faces).
- **container** (~14): napse-classify (Mojo), aegis-planner, qsecbit-ml, hydra-feeds, cno, brain-fallback, neuro-identity, htp, wireless, mirage, aiochi, iam, mssp, cortex, dsm, mesh.
- **sysext / image-layer** (~5): napse-capture (Zig/C XDP), qsecbit xdp_manager, aegis ebpf templates (pre-compiled CO-RE), hydra bpf_map_ops, hostapd-ovs.
- **N/A — retire/replace** (4): brain `hw_detect` (→ bootstrap), neuro NSE crypto (→ ADR 0002), htp Kyber512 (→ ML-KEM-768), common clickhouse (→ SQLite/DuckDB).

**Headline calls:** detection *science* is repackaged not rebuilt; the **delivery + spine + crypto** are rebuilt. The crown-jewel **Zig/C XDP** stays as-is (sysext). The biggest single rewrite win is the **portable Python detection/score logic → Wasm**; the biggest *deletion* is **bespoke NSE crypto**; the biggest *containment* is the **P2P mesh → optional `fleet_mesh` overlay**.

---

## 6. Open questions to lock

1. **Mojo's future** — keep classifiers in a container (Mojo/MAX runtime in the image), or port the hot SIMD/HMM classifiers to **Rust + WASI-NN**? Mojo has no clean Wasm target; the container is the bridge, not the destination.
2. **eBPF lifecycle on an immutable image** — aegis `ebpf_compiler` compiles eBPF at runtime, which is awkward under bootc. Decide: ship **pre-compiled CO-RE objects** in the image (preferred) vs allow on-device compilation (needs clang/headers in the image).
3. **WASI-NN coverage** — which `core/brain` backends (TensorRT/Hailo/CoreML/RKNN) does WASI-NN cover on our targets? Backends it can't reach are the only justification to keep `brain` as a container; everything else routes through `edge_ai`.
4. **Host-action bridge scope** — `shared/response` (iptables), `shared/network` (OpenFlow), `slaai` (PBR), `hydra` (bpf_map_ops), `wireless` (regdb) all need privileged host actions. Confirm they all funnel through **one HAOS-style OS-Agent bridge** (Architecture §4.4), not scattered helpers.
5. **Fleet model** — P2P herd-immunity mesh (htp/dsm/cno-federated/cortex) as an **optional overlay on GitOps**, or dropped? (Carried from V1-alignment decision #1.) Until locked, all of it stays behind `fleet_mesh` and additive.
6. **Crypto migration order** — confirm NSE drop + Kyber512→ML-KEM-768 + DSM-BLS→ML-DSA-65 is a hard precondition before any mesh engine ships (ADR 0002).
7. **`nic_detector` / `hw_detect` retirement** — confirm bootstrap fully subsumes V1's two HW-probing paths so nothing re-probes after first boot (detect-once invariant).
8. **New tokens into `platforms/*.yaml`** — who authors the known-good lists for `capture`/`host_telemetry`/`ddos_mitigation` (XDP-native NIC dependent — the pfSense TSO/LRO lesson applies)?
</content>
</invoke>
