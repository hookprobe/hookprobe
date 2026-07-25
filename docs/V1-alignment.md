# HookProbe V1 ↔ V2 alignment

> Read-only investigation (2026-06-28): does HookProbe **V1** align with the **V2** vision in this repo's `docs/`, and how should we reconcile? Companion to [Readme.md](Readme.md), [Architecture.md](Architecture.md), [ADR 0001](adr/0001-mission-control-stack.md), [ADR 0002](adr/0002-crypto-agility-pqc.md), [ADR 0003](adr/0003-platform-manifest-schema.md).

## 0. Scope note

`~/hookprobe-com` is **now present** and was inspected directly (an earlier pass ran before it was on this machine). It is a large repo: `astro-dashboard`, `astro-landing`, `astro-docs`, plus `hookprobe`, `alexandria`, `hsg`, a blog system, etc. **The pasted "Dashboard Architecture Report" is accurate** — `astro-dashboard/package.json` confirms **Astro 5.16 (SSR, `@astrojs/node`) + React 19 (`@astrojs/react`) + three/@react-three/fiber/drei + @tiptap/react + zustand + nanostores + oidc-client-ts + d3-force-3d**, with 55 `.astro` pages and ~28 files touching three/R3F. Engine findings are first-hand from `~/hookprobe`.

## 1. V1 inventory (`~/hookprobe`)

A **Python-first monorepo** (571 `.py`) with native hot-paths in **Zig (XDP/eBPF), Mojo (ML classify), C**, shipped as **containers + a 131 KB host installer** (`install.sh` uses `apt-get`/`systemctl` — *not* image-based).

- **`core/`** — `aegis` (AI orchestrator: orchestrator/oracle/narrator/reflex/principle_guard/tool_executor/autonomous), `napse` (IDS/IPS: Zig XDP `aegis/src/xdp_program.zig`, Mojo classifiers `brain/src/*.mojo`, `Containerfile.napse`, needs `SYS_BPF/NET_ADMIN`), `qsecbit` (score: detectors/ml/xdp_manager/gdpr_privacy), `hydra`, `cno`, `brain`, `neuro`, `htp`.
- **`shared/`** — `mssp` (multi-tenant), `iam` (RBAC + Keycloak), `dnsXai`, `mesh`, `mirage`, `wireless`, `hostapd-ovs`, `dsm`, `mobile_security`, `response`, `network`.
- **`products/`** — `sentinel` (IoT 256 MB) → `guardian` (RPi 1.5 GB) → `fortress` (Mini-PC 4 GB) → `nexus` (server 16 GB+): hardware tiers, "same core, different scales."
- **Organizing principle** — a **federated, privacy-preserving mesh** ("herd immunity"): HTP transport, DSM Byzantine consensus, NEURO fingerprinting, NSE "neural synaptic encryption (nobody knows the key)," Nexus regional aggregators.
- **Concept grep:** `intent` 53, `capability` 32, `post-quantum` 23, `multi-tenant` 20, `keycloak` 4 — **but** `bootc` 0, `wasi` 0, `quadlet` 0, `platform manifest` 0, `wasm` 2, `cosign` 2, `ml-kem`/`ml-dsa` 0.

## 2. V1 → V2 "one system" mapping

| V2 | V1 equivalent | Strength |
|---|---|---|
| NAPSE / Detect | `core/napse` (Zig XDP + Mojo + Python) | **Direct** (same name) |
| AEGIS / Investigate + intent | `core/aegis` | **Direct & rich** |
| QSECBIT / Score | `core/qsecbit` | **Direct** |
| HYDRA / Intelligence | `core/hydra` | threat-intel/enrichment (canon); SOAR playbooks → net-new **Automate** |
| Senzorium / Observe | *no single dir* — capture spread across napse/dnsXai/mesh/network | V2 consolidation/rename |
| Cloud-linked MSSP | `shared/mssp`, `shared/iam` (Keycloak) | Direct |
| Platform profiles / SKUs | `products/{sentinel,guardian,fortress,nexus}` | Philosophically aligned |
| Fleet (GitOps) | the HTP/DSM/NEURO/NSE federated mesh | **Concept mismatch** (P2P vs GitOps) |

**V2 concepts with NO V1 home:** bootc delivery, Wasm/WASI module model, the **signed Platform Manifest + capability-gating + supervisor/reconciler**, Quadlet, cosign/SBOM/**CBOM**, standards PQC hybrid suite, **standalone-no-account default**.
**V1 concepts with weak/no V2 home:** the **P2P herd-immunity mesh** (HTP/DSM Byzantine/NSE) — V2's fleet is pull-based **GitOps**, not P2P consensus.

## 3. Alignment assessment

**Strong (keep):** shared vocabulary/components (NAPSE/AEGIS/HYDRA/QSECBIT already exist with real substance); **eBPF/XDP fast path already shipped in Zig** — exactly Architecture.md C12, a crown jewel; "same core, different scales" ≈ "one OS, hardware unlocks capabilities"; PQC *ambition* present (HTP).

**Divergent (rebuild):**
- **Delivery** — V1 host installer (`apt`/`systemd`) + containers vs V2 **immutable bootc OCI image**.
- **The manifest/capability/supervisor spine does not exist in V1** — V2's core invariant, net-new.
- **Module model** — V1 Containerfiles + bash vs V2 **Wasm/WASI** (heavy/native → sysext/image layer).
- **Posture** — V1 mesh-first/cloud-first vs V2 **standalone local-first** (mesh/cloud additive).
- **Crypto** — V1 *bespoke* (NSE "nobody knows the key", keyless) is a **risk** vs V2 standards-based cosign/CBOM + NIST hybrid (ADR 0002); `ml-kem`/`ml-dsa` absent in V1.

## 4. React vs SolidJS — **ADR 0001 upheld**

The dashboard report's "keep React" is explicitly conditioned on *"you are not greenfield."* **V2 is greenfield (user-confirmed)**, so that condition fails for V2 — the advice applies to evolving V1's dashboard *in place*, not to building V2.

- **Uphold ADR 0001 (Solid shell + Rust/Axum) — now with NO exceptions.** The generic React islands are ordinary widgets — cheap to rebuild in Solid, which is the point of "right from the start."
- **The Glass Brain is DROPPED (product decision, 2026-06-28).** It was the *only* asset that justified a React island (R3F is React-only; `solid-three` immature). The user determined it has **no real customer value**, and the Mission Control pages/subpages in `docs/MissionControl.md` already provide the needed layout. Removing it eliminates the last reason to run any React in V2 → **V2 is 100% SolidJS, zero React.** The ~28 V1 three/R3F files are not carried over.
- **Tiptap:** use the framework-agnostic **ProseMirror/TipTap core** from Solid (already mandated by ADR 0001) — don't port React-Tiptap.

**Verdict: ADR 0001 upheld unconditionally. V2 is pure Solid + Rust/Axum — no React, no R3F, no Glass Brain.**

## 5. Deployment-mode alignment — one conflict to flag

The V1 mssp dashboard maps cleanly to V2's **cloud-linked lens**. **But** the report's BFF + Keycloak + httpOnly-cookie auth is **cloud-only**, and adopting it as *the* auth model **violates V2's "never gate the device on an account" invariant.** Resolution per the docs:
- **Mode-aware auth** (the V2 mode badge): **standalone → local-admin claim, no account, no Keycloak**; **cloud-linked → Keycloak/OIDC via BFF**; **self-hosted → your IdP**. The BFF/httpOnly work is correct **for the cloud lens only**.
- The dashboard must become **manifest-driven** (render / grey-with-reason / hide). V1's 53 pages are not capability-gated — required for "one app, many lenses."

## 6. Recommendation — coexist now, rebuild the spine, selectively reuse

Treat V1 as **reference + parts donor, not a constraint** (greenfield confirmed):
- **`~/hookprobe` engines = crown jewels. Don't rebuild the detection science — repackage** each as a V2 module behind `module.yaml` (`requires`/`grants`/`provides`): Zig XDP → **sysext/image layer**; Mojo/Python classifiers → **container** (Wasm where feasible); QSecBit/AEGIS logic → modules reading the manifest. Fastest path to a *working* V2 with real detection.
- **Dashboard = rebuild fresh from `docs/MissionControl.md` — ZERO reuse of V1 pages.** MissionControl.md is the V2 core/base; the visual target is `~/hookprobe-v2-dashboard.png` (which realizes it). Keep **only the V1 Astro *theme*** (the dark command-center styling), not its pages/components. Built mode-aware, manifest-driven, capability-gated, and **matched to customer feedback**. Reuse the framework-agnostic ProseMirror/TipTap core where an editor is needed. The strangler-fig plan was for evolving V1 in place — it does NOT apply to V2.
- **Don't carry** `install.sh` — V2 is bootc.

**Top decisions to lock:**
1. **Federated mesh's place in V2** — reframe HTP/DSM/NEURO/NSE as the additive fleet/cloud layer (never a precondition), or decide if HTP-mesh replaces GitOps fleet. (Readme: local-first; Fleet = pull GitOps.)
2. **Mode-aware auth** — local-admin (standalone) vs Keycloak-BFF (cloud-linked); cloud auth must not gate the device. (Readme invariant.)
3. **Crypto reconciliation** — replace V1 bespoke NSE/keyless crypto with ADR-0002 standards-based crypto-agility (cosign/CBOM, ML-KEM/ML-DSA). V1's homegrown crypto is a security/credibility risk. (ADR 0002.)
4. **Runtime-per-engine map** — confirm Zig/Mojo natives → **sysext/container**, not Wasm. (Readme "right tool per layer"; Architecture C10–C12.)
5. **Manifest/capability layer is net-new** — V2's spine, no V1 source; build first (Phase 1, underway). (ADR 0003.)

**Bottom line:** V1 and V2 are **strongly aligned in *substance*** (components, XDP detection, AI orchestration, PQC ambition, tiered hardware) but **divergent in *delivery and posture*** (host-installer + mesh-first + cloud-auth vs bootc-image + manifest-capability + standalone-first). Keep V1's detection/AI engines as repackaged modules; rebuild the OS spine, supply-chain, and UI per the V2 docs; uphold ADR 0001 with the single R3F-island exception.
