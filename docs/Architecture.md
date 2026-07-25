# HookProbe OS — Architecture (connections & build plan)

> This document operationalizes the HLD in [`Readme.md`](Readme.md). The Readme says *what* HookProbe OS is; this says *how the pieces connect* and *in what order we build them*. It specifies the bootstrap-to-runtime spine — **unified installer → device scanner → classification → capability mapper → resource allocator → signed Platform Manifest → local backend → supervisor/reconciler → Mission Control** — as a set of explicit connections (contract · mechanism · failure mode), then a phased plan whose **Phase 1 is the Readme core**.
>
> Canonical companions: [`Readme.md`](Readme.md) (HLD), [`MissionControl.md`](MissionControl.md) (UX), [ADR 0001](adr/0001-mission-control-stack.md) (stack), [ADR 0002](adr/0002-crypto-agility-pqc.md) (crypto/PQC). When this doc and those disagree, **they win** — flag the contradiction, don't silently resolve it.

---

## 1. Scope and the "real-time" framing (be honest)

HookProbe OS is **soft real-time / low-latency, event-driven** — responsive live operations (sub-second telemetry → dashboard), not a hard-deadline RTOS. We engineer responsiveness with an eBPF/XDP fast path, async runtimes, and bounded queues — **not** PREEMPT_RT determinism.

**Hard real-time (PREEMPT_RT, `SCHED_DEADLINE`/`SCHED_FIFO`) is warranted in exactly one place:** an *inline, fail-closed IPS* segment with a guaranteed per-packet deadline — and even then it is scoped to specific threads, never the whole OS. The default data-plane posture is out-of-band (a copy of traffic), so the common case needs low latency, not determinism. We will not market "RTOS"; we say **"low-latency, event-driven."**

This doc covers the on-device control plane and its connections. The fleet/cloud layer is additive (see Readme § Deployment modes) and out of the detection path.

---

## 2. The spine — data/control flow

```
                          ┌──────────────────────────────────────────────┐
  Build (CI)              │  Unified OCI/bootc image (byte-identical)      │
  podman build + cosign ──►  + signed static ID→capability tables (RO)     │
                          └───────────────────┬──────────────────────────┘
                                              │ flash / import (FIT+DTB | UEFI | qcow2/AMI)
                                              ▼
                          ┌──────────────────────────────────────────────┐
   UNIFIED INSTALLER ─────►  First boot (once): seed only (identity,       │
   (one menu, adapts)      │  network, claim token) via Ignition/claim     │
                          └───────────────────┬──────────────────────────┘
                                              ▼
   DEVICE SCANNER  ──►  AUTO-CLASSIFICATION  ──►  CAPABILITY MAPPER  ──►  RESOURCE ALLOCATOR
   (probe once,         (DT compatible → DMI     (facts → capability      (per-module CPU/mem/IO
    as root, post-       tuple → virt overlay;    TOKENS; grant =          budgets: cgroups v2
    udev-settle)         + "unknown" fallback)    presence∧known-good∧     outer wall + Wasmtime
        │                                         policy)                  epoch/limiter inner wall)
        └───────────────────────────┬───────────────────────────────────────────┘
                                     ▼
                    ┌─────────────────────────────────────────────┐
                    │  SIGNED PLATFORM MANIFEST                    │
                    │  /var/lib/hookprobe/manifest.json (schema 2) │
                    │  capabilities + crypto posture + budgets     │
                    │  cosign-signed, TPM-sealed where present     │
                    └───────┬───────────────────────────┬─────────┘
                  RO manifest UDS (0444)        RW control UDS (admin-only)
                            │                            │
                            ▼                            ▼
   ┌────────────────────────────────┐   ┌──────────────────────────────────────┐
   │  SUPERVISOR + AEGIS RECONCILER  │   │  LOCAL BACKEND (control plane)        │
   │  level-triggered, idempotent    │◄──┤  Rust/Axum: REST + WS control +       │
   │  resolves requires/grants/      │   │  SSE telemetry; SQLite(state) +       │
   │  provides → loads modules:      │   │  DuckDB(flows); tiered retention      │
   │  • Wasm (WASI) detection/policy │   └───────────────────┬──────────────────┘
   │  • rootless Podman (Quadlet)    │                       │ SSE (sub-second) + WS
   │  fast path: eBPF/XDP at the NIC │                       ▼
   └────────────────────────────────┘        MISSION CONTROL (SolidJS) + Astro content
```

This refines the Readme's three-layer diagram (Experience / Logic+Services / Base); it does not contradict it. The manifest is the hinge: everything above the scanner **reads** it and nothing else re-probes hardware ("detect once, query forever").

---

## 3. Connections (the contracts between components)

Each edge is a contract (what crosses), a mechanism (how), and a failure mode (what happens when it breaks).

| # | Edge | Contract (data) | Mechanism | Failure mode |
|---|---|---|---|---|
| C1 | CI → Image | Signed OCI image + RO `id→capability` tables + SBOM/CBOM | `podman build`, cosign sign, registry push | Unsigned/tampered image fails cosign verify → won't boot-switch (bootc keeps prior) |
| C2 | Installer → First boot | Minimal **seed**: device identity material, network, optional claim token | Ignition/Butane *or* Talos-style API-claim; cloud-init only as fallback (`cloud-init clean` mandatory) | Missing seed → safe defaults + headless claim UI; never drop to an un-answerable wizard |
| C3 | First boot → Scanner | "probe needed?" signal | `systemd` `ExecCondition=hookprobe-bootstrap --check-rules-version` — re-probes when the manifest is absent **or** the image's `PLATFORM_RULES_VERSION` is newer than the frozen manifest's; ordered `After=systemd-udev-trigger` | Re-run on missing manifest or a platform-rules bump (a classification fix in a new image lands on next boot); otherwise a cheap one-JSON-read no-op |
| C4 | Scanner → Classifier | Raw hardware facts (JSON): DMI tuple, DT `compatible` tokens, CPU, PCI/USB numeric IDs, NIC supported modes, Wi-Fi PHY caps, TPM, Secure Boot, NPU present/driver-ready, virt | Merge of `lshw -json`, `/sys/class/dmi/id/*`, `/proc/device-tree/compatible`, `lscpu -J`, `ethtool`, `iw phy`, `/sys/class/tpm`, `mokutil`, `systemd-detect-virt` | A probe failing → fact recorded as **"unknown/absent" (absence is data)**, never silently a class |
| C5 | Classifier → Capability Mapper | Platform **class** + match against `platforms/*.yaml` | Priority tree: DT present → ARM SoC+board; else x86 DMI tuple; overlay virt; **"generic" fallback** | No match → `generic` class with conservative baseline capabilities (full local SOC still runs) |
| C6 | Capability Mapper → Manifest | Capability **tokens** (`wifi7`, `openvswitch`, `edge_ai`, …) + per-module **budgets** | `grant = presence ∧ known-good ∧ policy`; static RO `id→capability` tables (hwdb pattern) + known-good/quirk list | Hardware present but not known-good/policy-denied → capability **withheld** (rendered as disable-with-reason in UI) |
| C7 | Mapper/Allocator → Manifest write | `manifest.json` schema 2: capabilities + crypto posture + budgets + module states | Write to **persistent partition** (separate from immutable rootfs); cosign-sign; TPM-seal where present | Unsealed/altered manifest → verification fails at next boot → re-probe + alert |
| C8 | Manifest → readers (UI, modules, AEGIS, updater) | Read-only capabilities/crypto/budgets | **RO manifest UDS** (`SO_PEERCRED`, mode 0444-style); never re-probe | Socket down → readers use last cached signed manifest; degraded badge shown |
| C9 | Operator/AI → Reconciler | **Intent** → desired-state spec (modules + grants + network/policy); AI emits a **plan as a diff** | **RW control UDS** (admin-only); AI planner proposes, never enforces | Model absent → deterministic reconciler keeps enforcing last approved state (air-gap-safe) |
| C10 | Reconciler → Modules | Resolved `requires`/`grants`/`provides` vs manifest → load/stop | Supervisor; Wasm via Wasmtime, services via Podman/Quadlet; **level-triggered, idempotent** | Unmet requires → clean refusal; over-budget module → throttle → pause → evict (host stays up) |
| C11 | Budget enforcement | Per-module CPU/mem/IO ceilings | **Outer:** systemd + cgroups v2 (`CPUQuota`/`CPUWeight`, `MemoryHigh`→`MemoryMax`, `IOWeight`). **Inner:** Wasmtime epoch interruption + `StoreLimits` + pooling allocator | `MemoryHigh` back-pressure before OOM; epoch trap aborts a single invocation without killing the process/siblings |
| C12 | NIC → Fast path | Packets | eBPF/XDP at RX (drop/flag before `sk_buff`/full stack); TC `clsact` for egress; heavy analysis in user space | Per-interface fail-open (default) / fail-closed (policy); out-of-band sees a copy only |
| C13 | Modules/ingest → Backend store | Normalized events, flows, evidence-graph nodes/edges | Bounded queues + back-pressure + priority load-shedding; SQLite (WAL, single writer, batched) + DuckDB (analytics) | Saturation → shed sampling/enrichment first, keep alerts + evidence writes; **surface "sampling on / window shrank"** |
| C14 | Backend → Mission Control | Live telemetry/score push + bidirectional control | **SSE over HTTP/2** (telemetry, auto-reconnect) + **one WebSocket** (control); over hybrid-PQC TLS (ADR 0002) | SSE auto-reconnects; WS loss → UI shows "degraded — enforcing last approved state" |
| C15 | Backend supervision | Liveness | systemd `Type=notify`, `sd_notify(READY=1)` + `WATCHDOG=1` from the **real work loop**; `Restart=on-failure` + `StartLimitBurst` | Missed heartbeat → restart; restart storm capped by StartLimit (no SD-card burn / fault masking) |
| C16 | Device → Account (optional) | Additive **LDevID** bound to IDevID | Enrollment token, attestation-gated; never a re-key | Never required; standalone fully functional forever if never enrolled |

---

## 4. Component specifications

### 4.1 Unified installation menu

**Goal:** one image, one installer that *adapts to the hardware*; zero-config "live from first boot"; fewest steps.

- **One image, many boards.** UEFI for x86/VM/cloud; **U-Boot FIT + multiple DTBs** (SPL selects the DTB by board ID) or Tow-Boot for Pi 5 / RK3588. Never per-device images — hardware variance is absorbed in `platforms/*.yaml`. Budget explicitly for the ARM bootloader/DTB long tail (the easy x86/VM 90% hides it).
- **Seed, don't configure.** Inject only machine-specific seed at install (identity, network, claim token); generate all config at first boot. Preferred engines: **Ignition/Butane** (declarative, runs once in initramfs) or **Talos-style API-claim** (no shell, config precedence chain) — both keep config a generated artifact with no post-install drift. **cloud-init** is the broad-compat fallback *only* with mandatory `cloud-init clean` before imaging (else cloned images share SSH host keys) and a `#cloud-config` header (missing → silently ignored).
- **Fewest-steps UX.** Follow Raspberry Pi Imager / Subiquity-autoinstall: **sane defaults for every step** so partial input still completes — every interactive question lacking a default is a stall point.
- **Pitfalls:** never gate first boot on Wi-Fi (SteamOS bug — enumerate *all* interfaces); don't ship plaintext credentials (hash them); version-skew in the customizer can silently fail.

### 4.2 Unified device scanner + automatic classification

**Goal:** probe hardware **exactly once**, deterministically, and hand classification to the capability mapper.

- **Run once, as root, after `systemd-udev-settle`.** No component re-probes after this; later consumers are unprivileged manifest readers.
- **Merge multiple sources** (no single tool suffices): `lshw -json` baseline; **x86** → `/sys/class/dmi/id/*` keyed on the **vendor+product+board tuple** (DMI is firmware-asserted, often blank/"Default string" — treat empties as unknown); **ARM** → `/proc/device-tree/compatible` (NUL-separated tokens; match SoC + board; *more* deterministic than DMI; absent on ACPI systems); `lscpu -J`; PCI/USB **numeric** `vendor:device` (names cosmetic — frozen `pci.ids`/`usb.ids` age out on an immutable image); NIC via `ethtool` **supported link modes** (not current speed); Wi-Fi gen via `iw phy` capability bitmaps (HE ⇒ Wi-Fi 6, EHT ⇒ Wi-Fi 7); TPM via `/sys/class/tpm/*` + `/dev/tpmrm0`; Secure Boot via `mokutil`/EFI var (absent on legacy/DT-ARM = information); NPU per-vendor recording **`npu_present` AND `npu_driver_ready` separately**; `systemd-detect-virt` for VM/cloud.
- **Classification = priority decision tree:** DT present → ARM SoC+board match; else x86 DMI tuple; overlay `systemd-detect-virt`; always a **`generic` fallback class**. Match keys live in `platforms/*.yaml` (the "add hardware = one file" test).
- **Prior art to emulate:** Subiquity/`probert` (one replayable JSON profile — enables offline testing of the immutable image), OpenWrt `board.json`, systemd `hwdb` (ship static ID→capability tables read-only). **Gap we close:** none sign their facts — we cosign-sign + TPM-seal the manifest ("trust nothing unsigned"). Re-probe only when the hardware fingerprint changes.
- **Pitfalls:** capture *supported* (stable) not *current* (transient — link-down NIC, un-enumerated PCIe); **absence is data**, never a silent class; frozen DBs refresh on OS upgrade only.

### 4.3 Device capability mapper + resource allocation

**Goal:** turn signed hardware facts into capability **tokens** and per-module **budgets** — the contract the whole system gates on.

- **Two layers, Android-HAL-style:** a layer that *drives* hardware below; a flat namespace of stable **capability tokens** (`soc`, `ids`, `openvswitch`, `wifi_ap`, `edge_ai`, …) queried above. Code asks "is `edge_ai` granted?", never "is this a Pi?" ("capabilities, not branches" = feature-detect, don't UA-sniff).
- **`grant = presence ∧ known-good ∧ policy`.** Detection is necessary but not sufficient: the **pfSense TSO/LRO lesson** — hardware *supporting* a feature ≠ *safe to enable* (driver bugs). Gate behind a known-good/quirk list with policy override. Centralize capability evaluation (don't scatter inline `hasCapability()` — that re-creates model-branching).
- **Module contract:** `requires`/`grants`/`provides` maps to Android `uses-feature required=true|false` — `required=true` is a hard dependency (don't load if unmet); `required=false` is soft (load with graceful degradation). The supervisor resolves this against the manifest locally and continuously.
- **UI is three-state:** **render** (granted+validated) · **disable-with-reason** (relevant but unmet/unsafe — preferred over silent hiding; the visible form of the pfSense lesson) · **hide** (fundamentally absent).
- **Resource allocation = two enforcement walls (both mandatory):**
  - **Outer host wall** — systemd + cgroups v2: `CPUQuota` (hard ceiling) + `CPUWeight` (contention only); `MemoryHigh` (throttle/back-pressure) *before* `MemoryMax` (OOM); `IOWeight`/bandwidth caps on pcap/log writers; high-priority *live* slice vs low-priority `background.slice` (retention compaction, model pulls); `TasksMax`; Podman `Delegate=yes`.
  - **Inner per-module wall** — Wasmtime **epoch interruption** (cheaper than fuel; needs a ticker thread; fuel only for deterministic metering) + `Store` `ResourceLimiter`/`StoreLimits` (memory/table/instance caps) + **pooling allocator** (pre-reserved slots → ~1–5 ms cold start).
  - Supervisor watches cgroup `*.stat`/PSI → **throttle → pause → evict** the offending module; the host and live path stay up. cgroups protect the *host*; Wasmtime protects *between modules* — neither alone is enough.
- **Pitfalls:** don't enforce only in-Wasm (a native container/host-call can still exhaust the box); don't kill the host process to stop a module; cap restart loops on evicted modules.

### 4.4 Local backend app (on-device control plane)

**Goal:** the on-device service that exposes the manifest, accepts intent, runs the reconciler, stores evidence, and feeds Mission Control. Rust/Axum per [ADR 0001](adr/0001-mission-control-stack.md).

- **Transport = Unix domain sockets, not localhost TCP:** filesystem perms + `SO_PEERCRED` peer credentials (no bespoke authn), ~0.01–0.05 ms vs 0.1–1 ms. **Two sockets:** a **read-only manifest socket** (world-readable; manifest + grants for UI/modules) and an **admin-only read/write control socket** (intent submission + reconcile). Never bind the control API to `0.0.0.0`. A tiny reverse proxy bridges UDS↔HTTP/2 for the browser.
- **Data stores, tiered:** **SQLite** as the operational store (config, manifest cache, alerts, evidence-graph nodes/edges; WAL mode, single writer, batched writes — the k3s rationale); **DuckDB** for analytical/time-series queries over events/flows (not a high-frequency ingest TSDB). **Tiered retention** hot pcap → warm events → cold alerts/evidence, auto-evict, **show the real window**; run compaction in the low-priority `background.slice`.
- **AEGIS reconciler = Kubernetes-controller-style, level-triggered, idempotent:** react to *current* state (survives missed events/restarts, self-heals drift), derive desired from world-state, enqueue **keys** not events, workqueue with exponential backoff. The deterministic reconciler is **local and model-free**; the AI planner only proposes a diff — **never in the enforcement path**.
- **Supervision:** systemd `Type=notify`; `sd_notify(READY=1)` then periodic `WATCHDOG=1` driven from the **actual work loop** (not a detached timer, or a deadlocked loop still looks alive); `Restart=on-failure` + `StartLimitBurst`/`StartLimitIntervalSec`; unit hardening.
- **Privileged host bridge:** mirror Home Assistant's OS-Agent — **one** narrow privileged agent (e.g., over D-Bus/UDS) for supervisor↔host actions (mount, network, OVS), so the boundary is auditable rather than scattered.
- **Reference architectures:** copy **Talos** (immutable, API-driven, no-shell), **HAOS** (minimal Linux + Supervisor + one host-agent + A/B OTA, which parallels `bootc upgrade`/`rollback`), **k3s** (single binary, SQLite default). **Avoid full Kubernetes** on a single node — replicate the reconciler *pattern* without etcd/scheduler/cluster machinery; keep cloud/fleet additive.

---

## 5. Mapping to the repo layout

The spine maps onto the Readme's target layout:

| Spine component | Repo dir |
|---|---|
| Unified image / base | `base/` (+ `base/profiles/`) |
| Installer seed / first-boot | `bootstrap/` (+ installer assets) |
| Device scanner + classification | `bootstrap/` |
| Capability mapper + budgets | `manifest/` (schema + signing) + `platforms/*.yaml` (match keys + budgets) |
| Platform Manifest | `manifest/` → runtime `/var/lib/hookprobe/manifest.json` |
| Supervisor + reconciler | `supervisor/` |
| Modules (Wasm/container/sysext) | `modules/{napse,hydra,ovs,…}` |
| Local backend + Mission Control | `ui/` (+ backend crate) |
| Fleet (additive) | `fleet/` |
| Supply chain / PQC | `security/` |

**The design test still holds:** adding hardware = one file in `platforms/`. No installer, UI, or API change.

---

## 6. Phased build plan

**Phase 1 — the Readme core (highest leverage; build this first).**
Prove the spine's hinge end to end on one board:
1. Debian **bootc base** image (`base/`) that builds with `podman build`, signs with cosign, and `bootc upgrade`/`rollback` works (UEFI tier; Pi-native updates via OCI-derived A/B image-sync from the same image — ADR 0019).
2. **Bootstrap probe** (`bootstrap/`): one-shot scanner + classifier (DT/DMI/virt tree) → writes the **signed Platform Manifest** (`manifest/` schema 2) to the persistent partition, exposed over the **RO manifest UDS**.
3. Minimal **supervisor** (`supervisor/`) that resolves a module's `requires`/`grants` against the manifest.
4. **The thesis demo:** load **one Wasm detection module against a manifest grant**, enforced by a cgroup + Wasmtime budget. (Readme: "that single demo is the whole thesis working.")
*Exit criterion:* on a Pi 5 *and* an N100, first boot writes a signed manifest and the supervisor hot-loads one capability-gated Wasm module within budget.

**Phase 2 — modules, data & reconciler.** OCI/Wasm registry + cosign; convert NAPSE/HYDRA to Wasm; the **level-triggered reconciler** + AEGIS BYO-LLM adapter (Ollama/OpenAI-compatible); the SQLite/DuckDB store + tiered retention; apply a `hookprobe.yaml`. Marketplace becomes nearly free (signed module index).

**Phase 3 — local backend + Mission Control.** Rust/Axum control plane (RO manifest socket + RW control socket), SSE/WS over hybrid-PQC TLS; SolidJS dashboard + Astro content (ADR 0001); capability-gated rendering (render / disable-with-reason / hide). Vertical-slice benchmarks on Pi 5 + N100 (validates ADR 0001 & 0002).

**Phase 4 — installer & claim UX.** Unified installer (FIT+DTB / UEFI / cloud images); Ignition/Talos-style seed; headless claim via `.local` web wizard (with `IP:port` fallback, all-NIC enumeration) + device-displayed single-use claim code bound to the attested key; TPM-anchored IDevID with the **software/OTP fallback as the common Pi path**.

**Phase 5 — fleet (additive).** Pull-based GitOps agent, drift self-heal, staged rollout rings, disconnected operation. Replicate the reconciler pattern at fleet scale; OCI as the state store.

**Phase 6 — supply chain & PQC hardening.** Full SBOM/CBOM, SLSA provenance, hybrid PQC signing/TLS end-to-end, TPM attestation for fleet join (ADR 0002).

**Phase 7 — own hardware.** Add `platforms/edge-pro.yaml`. Nothing else changes — the proof the abstraction held.

> This extends, and is consistent with, the Readme's roadmap (it adds the explicit connection contracts and the installer/claim phase). The one genuine engineering pole remains a **custom kernel for edge SoCs** (RK3588/Pi) — plan for it during Phase 1/2.

---

## 7. Cross-cutting pitfalls

- **A detected fact is not a capability** until it is *validated, signed, and safely gated* (`grant = presence ∧ known-good ∧ policy`). This single rule recurs across scanner, mapper, and UI.
- **Two enforcement layers, always** (cgroups for the host, Wasmtime for between modules).
- **Every queue bounded; every drop visible; every retention window honestly reported.** Silent loss destroys trust in a security tool.
- **Level-triggered + idempotent reconcile**, or you lose drift-correction and self-healing — the whole point of intent ops.
- **Absence is data** — missing DT/efivars/TPM are expected on some of the five targets; encode them explicitly.
- **"Real-time" honestly** — low-latency/event-driven, not hard RTOS (except a scoped inline fail-closed IPS path).
- **Standalone-first must hold** — identity and full SOC function exist with no account, forever.

## 8. Open questions / decisions to lock

1. **First-boot engine:** Ignition vs Talos-style API-claim as the *primary* (cloud-init as fallback) — pick one primary to build in Phase 4.
2. **Pi identity floor:** since Pi 5/CM5 have no discrete TPM, confirm the **software/OTP-sealed** keypair as the accepted baseline assurance for standalone Pi (TPM as upgrade).
3. **Manifest sealing:** cosign-sign only, TPM-seal where present, or both — and the re-seal flow on OS update (PCR-sealing is brittle across updates).
4. **Backend ↔ host privilege bridge:** adopt a single HAOS-style OS-Agent boundary (recommended) vs per-action helpers.
5. **DuckDB vs a dedicated TSDB** for the highest event-rate tier on N100-class aggregation nodes — measure in Phase 3.
6. **Embedded store write path** under packet/event floods — confirm SQLite-WAL single-writer + batching holds, or introduce a write-ahead ring.
