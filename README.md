# HookProbe OS

> **One operating system. Every platform. Hardware only unlocks capabilities.**
>
> HookProbe OS is an AI-native security operating system — a zero-setup SOC from
> first boot. It positions as a **"SOC on a budget"**: the unified detection,
> investigation, and response console that FortiSOC / Microsoft Sentinel /
> Defender XDR give you, but self-contained, edge-native, and operated by intent
> instead of query languages.

**Positioning:** *HookProbe OS is the operating system. SOC is its default
workspace. Hardware only unlocks capabilities.*

---

## What it is

HookProbe OS is **one system**: a single OS, one data model, one evidence graph,
one AI. Every named component — Senzorium (observation), NAPSE (IDS/IPS), AEGIS
(reconciler + AI planner), HYDRA (threat intelligence), QSECBIT (resilience
score) — is a *lens* on the same substrate, never a separate product. You operate
it by **declaring what you want**; a deterministic reconciler makes it so, and
configuration becomes a generated artifact rather than the interface.

### Core ideas

- **One image, every platform.** The same OS and the same Mission Control run on
  a Raspberry Pi, an RK3588 board, an Intel N100 appliance, a VM, or the cloud.
- **Detect once, query forever.** The device probes hardware once at first boot
  and writes a signed **Platform Manifest**; everything else asks
  "is this capability granted?" — never "is this a Pi?".
- **Standalone by default.** A full local SOC runs with no account, no cloud,
  air-gapped. Cloud/account is an *additive* layer, never a precondition.
- **Observe by default; enforce with a customer-safe floor.** Detectors emit
  alerts; a single decision path enforces, graduated by confidence. A legitimate
  connection always passes; only a genuine attack or resource-exhaustion event is
  dropped.
- **Trust nothing unsigned.** OS images, modules, and manifests are cosign-signed;
  SBOM + CBOM per image; a crypto-agile / PQC-ready posture (hybrid
  ML-DSA-65 + Ed25519 module signing is implemented today).

### Capabilities (representative)

- Network IDS/IPS with L2–L7 detection wired to the wire
- Host EDR (exec/persistence telemetry → detections → incidents)
- Threat-intelligence enrichment (IOC/STIX/TAXII/MISP, CVE, anomaly)
- DNS protection / sinkhole (RPZ)
- Composite cyber-resilience scoring (QSECBIT)
- Autonomous Wi-Fi AP with regulatory-domain and channel auto-calibration
- Intent-driven operation with a bring-your-own-LLM AI copilot (assistive,
  never in the enforcement path)
- Evidence graph: Device → Interface → Packet → Connection → Session →
  Application → User → Threat → Incident → Response → Report

---

## Two substrates

HookProbe OS runs on **two substrates**, chosen by platform tier:

| Tier | Substrate | Status |
|---|---|---|
| **UEFI + amd64 / N100 / VM / cloud** | **Linux** — a signed OCI/`bootc` image (Debian base), Wasm detection modules + rootless Podman services | Canonical + **permanent** |
| **rpi-native / CM5** | **HEQK** — a from-scratch Rust aarch64 capability microkernel that replaces Linux as substrate *and* app-host (**zero Linux on the device, not even a guest**) | Multi-year epic, **early** — see status below |

The Linux tier is the well-trodden path (ADR 0019). The CM5/HEQK tier is a
deliberate long-term bet ratified in **ADR 0043 + ADR 0044**: "the OS is the
sensor," with no Linux running on the device at all. Until each HEQK component
passes its own metal gate, the **Linux rpi-native image keeps shipping** as the
production image — no capability is removed before its HEQK replacement is proven.

---

## Project status (honest)

We hold ourselves to an explicit **honesty floor** (ADR 0044 D5): we do not
overclaim. Here is the candid split of proven-on-metal vs roadmap.

### Proven on metal — the Linux rpi-native SOC (Milestone M1, 2026-07-20)

A single signed image boots the **full SOC** on two Raspberry Pi boards — Pi 4
(Cortex-A72) and CM5 (Cortex-A76) — and every load-bearing invariant is proven
from the signed image itself:

- Boots clean and healthy (`is-system-running` = running, `SELFTEST: PASS`).
- One image, both platforms; hybrid ML-DSA-65 + Ed25519 signed modules
  verified → running.
- Reflex enforcement is live; host-EDR + NAPSE L2/L7 detection wired to wire.
- **Enforcement separation proven both directions, both boards**: a non-mgmt
  attacker is detected → quarantined (self-reverting TTL), while a legitimate /
  management connection always passes.
- Autonomous Wi-Fi lands and holds 5 GHz VHT80.

### Roadmap / early — the HEQK zero-Linux microkernel (CM5)

**HEQK today is a QEMU-green capability-microkernel core** with thin,
single-run, polling-only CM5 bring-up. **It is not a running SOC.** Its
validation gate covers QEMU only; "23/23 green, metal-proven" in its own docs
describes single bench runs, and its design docs run ahead of the running
kernel. Delivering "zero-Linux HookProbe SOC on CM5" is an honestly **multi-year,
component-by-component epic** — a userspace-server substrate, an on-device Wasm
host, storage, detection-catalogue parity, a native dataplane, a TCP/IP stack,
and Wi-Fi AP all have to be rebuilt with no Linux fallback. **Do not read the
HEQK tier as a shipping SOC.** Track its real state in `docs/BuildPlan.md`
Track C.

### Other honest gaps

Much of Mission Control's backend is built but not fully surfaced; several
supply-chain items (PQC TLS, SLSA, TPM attestation) are scaffolded but not run
end-to-end. `docs/BuildPlan.md` is the single source of truth for what is planned
vs built, with per-row status marks.

---

## Documentation

- **[`docs/Readme.md`](docs/Readme.md)** — the canonical OS architecture
  (bootc, Wasm, intent, supply chain, PQC).
- **[`docs/MissionControl.md`](docs/MissionControl.md)** — the target
  dashboard / UI specification.
- **[`docs/BuildPlan.md`](docs/BuildPlan.md)** — the single source of truth for
  plan vs built (status marks, change log, Track A/B/C).
- **[`docs/adr/`](docs/adr/)** — architecture decision records. Start with
  [ADR 0043](docs/adr/0043-heqk-microkernel-substrate.md) and
  [ADR 0044](docs/adr/0044-zero-linux-rpi-native-cm5.md) for the HEQK substrate
  decision.
- **[`docs/MIGRATION-heqk.md`](docs/MIGRATION-heqk.md)** — the HEQK epic spine.

---

## License

HookProbe OS is **open-core, dual-licensed**:

- **GNU AGPL-3.0** for the base OS + standalone SOC — free to run for your own
  personal or business self-protection. See [`LICENSE`](LICENSE).
- **Commercial license** for offering HookProbe OS as a service to third parties
  (the AGPL network-copyleft clause) and for the proprietary core-innovation and
  cloud/account components.

See **[`LICENSING.md`](LICENSING.md)** for the full policy, the component
breakdown, usage scenarios, and commercial contact.

Contact: **qsecbit@hookprobe.com**
