# ADR 0003 — The Platform Manifest schema

**Status:** ✅ Accepted (2026-06-27) — **schema_version 2**. The Phase-1 contract; build against this.
**Date:** 2026-06-27
**Deciders:** os-architect (author), code-developer, security
**Relates to:** [`Readme.md`](../architecture/Readme.md) (manifest concept), [`Architecture.md`](../architecture/Architecture.md) (connections C4–C8), [ADR 0002](0002-crypto-agility-pqc.md) (the `crypto` block). The Readme's inline manifest snippet is *illustrative*; **this ADR is the canonical schema** — the Readme should point here.

## Context

The Platform Manifest is the single source of truth for "detect once, query forever." Bootstrap writes it once at first boot; the UI, AEGIS, supervisor, updater, and every module read it and **nothing else re-probes hardware**. It must be: signed, self-describing (capabilities **and** crypto posture **and** resource budgets), versioned, machine-validatable, and cheap to query ("is `edge_ai` granted?"). This ADR defines the exact on-disk schema so the build team can implement the writer (bootstrap), the readers (everything), and the JSON Schema validator in parallel.

## Decision — principles

1. **One file, one schema, signed.** `/var/lib/hookprobe/manifest.json` on the **persistent partition** (never the immutable rootfs). JSON, UTF-8, canonical (sorted keys) for reproducible signing. Validated against `manifest/schema/manifest.schema.json` (JSON Schema Draft 2020-12) at write time *and* in CI.
2. **Facts vs grants are separate.** `hardware`/`network` hold *detected facts* (including "absent"); `capabilities` hold *grants* derived by the rule `grant = presence ∧ known-good ∧ policy`. Readers gate on grants, not facts.
3. **Absence is data.** A missing TPM/NPU/efivar is an explicit fact (`present: false`), never an omitted key.
4. **Classify on durable identifiers** (DT `compatible` tokens, DMI vendor+product+board tuple, numeric PCI/USB IDs) — names are cosmetic. Carry a `generic` fallback class.
5. **Capability tokens are a flat, stable namespace** (`soc`, `ids`, `openvswitch`, `wifi_ap`, `edge_ai`, …). Code asks for a token; it never branches on hardware model.
6. **The manifest is generated, never hand-edited.** Desired state (intent / `hookprobe.yaml`) is a *separate* artifact reconciled by AEGIS; the manifest reflects reality.

---

## The schema — annotated example

```jsonc
{
  "schema_version": 2,

  "identity": {
    "device_id": "hp-7f3a2c10-…",        // stable UUID derived at first boot
    "serial": "HP0001421",                // from DMI/board or assigned; null if unknown
    "idevid": {
      "type": "tpm",                      // tpm | dice | software   (Pi 5/CM5 → usually "software")
      "pubkey_fpr": "SHA256:bd9f…",       // device identity public-key fingerprint
      "sealed": true                       // sealed to TPM/OTP where present
    },
    "claim_state": "claimed",             // unclaimed | claimed | enrolled
    "tenant": null                         // null in standalone; set when enrolled (LDevID)
  },

  "platform": {
    "class": "edge-pro",                  // edge-lite | edge-pro | cloud | virtual | dev | generic
    "profile": "rk3588",                  // matches platforms/<profile>.yaml
    "sku": "HP-EP-001",                   // marketing SKU (Guardian/Fortress); cosmetic
    "match": {                             // WHY this class was chosen (audit/debug)
      "method": "device-tree",            // device-tree | dmi-tuple | virt | fallback
      "key": "rockchip,rk3588"            // the durable identifier that matched
    }
  },

  "hardware": {
    "arch": "arm64",                      // arm64 | amd64 | riscv64
    "cpu": { "model": "RK3588", "cores": 8 },
    "memory_mb": 16384,
    "storage": [ { "dev": "mmcblk0", "size_gb": 64, "type": "emmc" } ],
    "tpm": { "present": true, "version": "2.0", "kind": "discrete" },  // kind: discrete|firmware|none
    "secure_boot": { "supported": true, "enabled": true },
    "npu": { "present": true, "driver_ready": true, "vendor": "rockchip", "model": "rknpu" },
    "virt": "none",                       // none | kvm | qemu | vmware | aws | … (systemd-detect-virt)
    "fingerprint": "SHA256:11aa…"         // hash of STABLE hw facts → re-probe trigger if it changes
  },

  "network": {
    "interfaces": [
      { "name": "eth0", "mac": "…", "type": "ethernet",
        "supported_modes": ["1000baseT/Full","2500baseT/Full"],
        "role": "out-of-band", "fail_mode": null,    "state": "up" },
      { "name": "eth1", "mac": "…", "type": "ethernet",
        "supported_modes": ["1000baseT/Full"],
        "role": "inline",      "fail_mode": "fail-open", "state": "up" }
    ],
    "wifi": { "present": true, "max_standard": "wifi7" },   // from iw phy bitmaps (HE→6, EHT→7)
    "lte":  { "present": false }
  },

  "capabilities": {                        // token → grant object (see Capability state model)
    "soc":         { "state": "granted",  "reason": null,
                     "evidence": ["cpu","memory_mb"] },
    "ids":         { "state": "granted",  "reason": null, "evidence": ["soc"] },
    "openvswitch": { "state": "granted",  "reason": null, "evidence": ["arch","network.interfaces>=2"] },
    "wifi_ap":     { "state": "granted",  "reason": null, "evidence": ["wifi.present"] },
    "edge_ai":     { "state": "granted",  "reason": null, "evidence": ["npu.driver_ready","memory_mb>=8192"] },
    "inline_ips":  { "state": "present_unsafe",
                     "reason": "NIC offload (TSO/LRO) not on known-good list for this driver",
                     "evidence": ["network.interfaces[1].role=inline"] }
  },

  "resources": {                           // the allocatable envelope + defaults (see Budgets model)
    "total":    { "cpu_pct": 800, "memory_mb": 16384 },   // cpu_pct: 100 = 1 core
    "reserved": { "cpu_pct": 150, "memory_mb": 2048 },    // host + backend
    "allocatable": { "cpu_pct": 650, "memory_mb": 14336 },
    "defaults": {
      "wasm":      { "cpu_pct": 25,  "memory_mb": 128, "epoch_ms": 50 },
      "container": { "cpu_pct": 100, "memory_mb": 512 }
    }
  },

  "crypto": {                              // canonical block — see ADR 0002
    "agility": true,
    "suite_id": "hookprobe-pqc-hybrid-2026",
    // NOTE (2026-07-05, ADR 0002 honesty-pass sync): `image_signing` is `ecdsa-p256` — the REAL
    // cosign-KEYLESS mechanism the code emits (crypto.rs, manifest/examples/*.json). `module_signing`
    // is the one IMPLEMENTED hybrid leg. `boot_signing`/`tls_*`/`device_identity` are policy-NAMED
    // but ROADMAP (no code yet) per ADR 0002 §3 — the CBOM tags each `implemented|roadmap`.
    "image_signing":  ["ecdsa-p256"],
    "module_signing": ["ml-dsa-65", "ed25519"],
    "boot_signing":   "lms",
    "tls_kex":        ["ml-kem-768+x25519"],
    "tls_auth":       ["ml-dsa-65", "ecdsa-p256"],
    "data_at_rest":   "aes-256-gcm",
    "hash":           ["sha-256", "sha-384", "sha3-256"],
    "device_identity":["ml-dsa-65", "ed25519"],
    "cbom":           "/usr/share/hookprobe/cbom.json"
  },

  "retention": {                           // bounded by storage, surfaced honestly
    "tiers": [
      { "name": "pcap",     "cap_gb": 8,  "window": "hours" },
      { "name": "events",   "cap_gb": 20, "window": "~3-4 weeks" },
      { "name": "evidence", "cap_gb": 16, "window": "many months" }
    ],
    "computed_at": "2026-06-27T10:00:00Z"
  },

  "modules": [
    { "id": "napse", "version": "2.4.1", "runtime": "wasm", "state": "running",
      "budget": { "cpu_pct": 50, "memory_mb": 256, "epoch_ms": 50 },
      "signature": "verified" }
  ],

  "provenance": {
    "image_ref": "ghcr.io/hookprobe/os:2026.6",
    "image_digest": "sha256:…",
    "generated_at": "2026-06-27T09:58:11Z",
    "generator": "bootstrap/1.0.0",
    "schema_version": 2
  },

  "signature": {
    "method": "cosign",
    "sig": "MEUCIQ…",
    "cert": "-----BEGIN CERTIFICATE-----…",
    "tpm_sealed": true,
    "pcr_policy": "sha256:0,2,7"          // PCRs bound, if sealed; null otherwise
  }
}
```

---

## Field reference (build-team contract)

**Top level** — all required: `schema_version`(int=2), `identity`, `platform`, `hardware`, `network`, `capabilities`, `resources`, `crypto`, `retention`, `modules`(array, may be empty), `provenance`, `signature`. Readers **must tolerate unknown extra keys** (forward-compat).

| Section | Key fields | Source | Notes |
|---|---|---|---|
| `identity` | `device_id`, `serial?`, `idevid{type,pubkey_fpr,sealed}`, `claim_state`, `tenant?` | first-boot identity mint | `serial`/`tenant` nullable; `type=software` is the common Pi path |
| `platform` | `class`, `profile`, `sku?`, `match{method,key}` | classifier | `match` records *why*; `class=generic` is the fallback |
| `hardware` | `arch`, `cpu`, `memory_mb`, `storage[]`, `tpm`, `secure_boot`, `npu`, `virt`, `fingerprint` | scanner (merged probes) | facts only; `present:false` is explicit; `npu_present`≠`driver_ready` |
| `network` | `interfaces[]{name,mac,type,supported_modes,role,fail_mode,state}`, `wifi`, `lte` | scanner + policy | capture *supported* modes not current speed; `fail_mode` only for `role=inline` |
| `capabilities` | token → `{state,reason,evidence[]}` | capability mapper | the gate everything reads; see state model below |
| `resources` | `total`, `reserved`, `allocatable`, `defaults{wasm,container}` | profile + memory_mb | `cpu_pct`: 100 = one core |
| `crypto` | per ADR 0002 | profile + detection | the canonical crypto block |
| `retention` | `tiers[]{name,cap_gb,window}`, `computed_at` | storage calc | window is a default, not a guarantee |
| `modules` | `{id,version,runtime,state,budget,signature}` | supervisor (mutated as modules load) | the only section the supervisor updates post-write. `runtime` ∈ wasm/container/sysext; `state` ∈ pending/running/throttled/paused/stopped/failed/evicted (the throttle→pause→evict lifecycle, Architecture.md C11); `signature` ∈ verified/required/unsigned (the verification *result*, not the policy) |
| `provenance` | `image_ref/digest`, `generated_at`, `generator`, `schema_version` | bootstrap + bootc aleph | ties manifest to the exact image |
| `signature` | `method`, `sig`, `cert`, `tpm_sealed`, `pcr_policy?` | cosign + TPM | covers all fields except `signature` itself |

---

## Capability state model (the grant logic)

`grant = presence ∧ known-good ∧ policy`. Each token resolves to one of four states, which **drive the 3-state UI** directly:

| `state` | Meaning | UI |
|---|---|---|
| `granted` | present ∧ known-good ∧ policy-allowed | **render** |
| `present_unsafe` | present but not on the known-good/quirk list (e.g. buggy NIC offload — the pfSense TSO/LRO lesson) | **disable-with-reason** |
| `policy_denied` | present ∧ known-good but disabled by policy | **disable-with-reason** |
| `absent` | hardware/prereq not present | **hide** |

- `reason` is **required** when state ≠ `granted` (the operator always sees *why*).
- `evidence[]` lists the facts/tokens that produced the decision (drill-down + audit).
- Convenience for readers: `granted(token) := capabilities[token]?.state === "granted"`. Centralize this in one library; never scatter inline checks.

### Token kinds — platform-capability vs module-provided service

Two kinds of token share the flat namespace; the distinction resolves a circularity the sysext work surfaced (a module must never *require ∧ provide* the same token):

- **Platform-capability token** — *"this device CAN do X"*, derived by `grant = presence ∧ known-good ∧ policy` and recorded in `manifest.capabilities` (e.g. `capture`, `openvswitch`, `edge_ai`, `inline_ips`). A module `requires` these.
- **Module-provided service token** — *"this module materializes service Y"*, declared in a module's `provides` and added to the granted set when it loads (e.g. `napse`, `flows`, `packets`, `dns_filtering`). Downstream modules `require` these to express a producer→consumer chain.

Example (the fix): the XDP **`napse-capture`** sysext **requires `capture`** (the platform must support XDP capture) and **provides `flows`/`packets`** (the materialized feed); the wasm **`napse`** synthesis then consumes `flows`. It would be wrong for `napse-capture` to *provide* `capture`. A token may legitimately be both (a platform token for one module's `requires` and never a `provides` of a module that also requires it).

### sysext modules — budgeting & gating

A `runtime: sysext` module is **not** sandbox-loaded (no Wasmtime fuel/epoch/StoreLimits) and its in-kernel part (XDP program, OVS datapath) is **not cgroup-accountable**; only its userspace loader is bounded, via a host cgroup **slice** (e.g. `hookprobe-dataplane.slice`), so its `modules[].budget` carries `cpu_pct`/`memory_mb` and **no `epoch_ms`**. It is still **capability-gated** (the supervisor enables/attaches it iff its `requires` are granted) and **cosign-signed**. *Tracked refinement:* sysext modules may need an optional `min_kernel` / `requires_btf` gate (CO-RE/BTF availability per board) — not yet in the schema; see Open Questions.

### Base-tier capability tokens (2026-07-15 additive note)

The $50-base-platform work (ADR 0031 base-tier amendment, [ADR 0014](0014-continuous-improvement-detection-lifecycle.md) D6, [ADR 0021](0021-multiarch-native-artifact-digests.md) D7) introduces new capability tokens. **They are FLAT, per Principle 5** — the base-tier draft spec used a dotted/namespaced spelling (`dataplane.tc_bpf`, `inference.cpu_simd`, …) which is **non-conforming**; the canonical token is the flat name and **dotted names must never appear in a manifest**. Adding these tokens is **additive** (new optional grants; no `schema_version` bump, per Versioning), and each resolves through the standard four-state grant model above.

| Canonical (flat) token | Non-conforming draft alias | Grant basis (`presence ∧ known-good ∧ policy`) | Owning ADR |
|---|---|---|---|
| `tc_bpf` | `dataplane.tc_bpf` | BPF+BTF present — the detection floor (and, on macb, the ceiling: no native XDP) | 0005 / 0031 |
| `xdp_native` | `dataplane.xdp_native` | NIC driver on the native-XDP known-good list (igc) — **module tier**, not base | 0031 |
| `xdp_zerocopy` | *(none)* | native-XDP NIC + AF_XDP zero-copy validated — **module tier** | 0031 |
| `resource_shed_v2` | `ddos.resource_shed_v2` | eBPF PSI pressure-valve path present (PSI + pinned shed maps) | 0031 / 0018 / 0023 |
| `ml_cpu` | `inference.cpu_simd` | CPU can run the ML model tier **within the epoch budget** (A76: yes; A72: budget-gated) | 0014 / 0021 |
| `ptp_hw` | `time.ptp_hw` | MAC + kernel IEEE-1588 HW timestamping (macb TSU) | 0031 |
| `gpu_compute` | *(already flat)* | VideoCore VII / v3dv Vulkan — **experimental, policy-flag-gated**, default `policy_denied` | 0031 |

**NPU naming:** the draft's `inference.npu` is the **same NPU capability already modelled here** — the platform token is `edge_ai` (line 82), and a module additionally `provides` a `wasi-nn: npu` service token (the producer→consumer distinction in "Token kinds" above). No new base-tier NPU token is minted; NPU is a module-tier concern tracked in the modular-router hardware doc. `ml_cpu` (CPU inference) and `edge_ai`/`wasi-nn: npu` (accelerator inference) are deliberately distinct: the CPU path is never a precondition for the accelerator path or vice-versa.

---

## Resource-budget model

- `resources.total` = detected envelope; `reserved` = host + local backend; `allocatable` = what modules may consume; `defaults` = per-runtime starting budgets.
- The **supervisor** assigns each module a budget from `allocatable` and records it in `modules[].budget`. Enforced at two layers (Architecture.md C11): cgroups v2 outer wall (`CPUQuota`/`MemoryHigh`) + Wasmtime epoch/limiter inner wall (`epoch_ms`, memory cap).
- `cpu_pct` is the cross-runtime unit (100 = one core) so the same number maps to `CPUQuota=` and to fuel/epoch tuning.

---

## Generation & lifecycle

1. **First boot** (once, as root, `After=systemd-udev-settle`): scanner merges probes → classifier picks class via priority tree → mapper computes capabilities + budgets → write `manifest.json` (canonical JSON).
2. **Sign & seal:** cosign-sign the canonical bytes; **TPM-seal where present** (bind to `pcr_policy`); on Pi (no TPM) seal to OTP/keyring or cosign-only — record which in `signature`.
3. **Persist** to `/var/lib/hookprobe/manifest.json` (persistent partition; survives `bootc upgrade`).
4. **Re-probe rule:** only when `hardware.fingerprint` changes (hardware swap) — otherwise every boot reuses the signed manifest. Bump `provenance.generated_at` on re-probe.
5. **Mutation:** only the supervisor updates `modules[]` (and re-signs); all other sections are immutable between probes. PCR-sealing is brittle across OS updates — **the OS-update flow must re-seal** the manifest, or readers fall back to cosign verification.

## Exposure (read contract)

- **RO manifest UDS** (Architecture.md C8): world-readable socket, `SO_PEERCRED`, serves the verified manifest read-only. Readers never touch the file directly and never re-probe.
- A small versioned read API (`GET /manifest`, `GET /capabilities/{token}`) over the UDS; if the socket is down, readers use the last cached signed copy and the UI shows a degraded badge.
- Desired-state mutation goes through the **separate admin-only RW control socket** — it changes intent, which the reconciler turns into module loads; it does **not** edit the manifest.

## Versioning & compatibility

- `schema_version` is an integer. **Additive changes** (new optional keys) do **not** bump it; readers ignore unknown keys. **Breaking changes** (removed/renamed/retyped fields) bump to 3 with a documented migration.
- Every reader checks `schema_version` and refuses (clean error, not crash) a major it doesn't support.
- `manifest/schema/manifest.schema.json` is the normative validator; the example above is informative.

## Validation invariants (CI + write-time)

1. Validates against the JSON Schema (types, enums, required).
2. `platform.class` ∈ enum; if `generic`, capabilities limited to the conservative baseline.
3. Every `capabilities[*].state ≠ granted` has a non-null `reason`.
4. `resources.allocatable = total − reserved` (per dimension), all ≥ 0.
5. Every `network.interfaces[*]` with `role=inline` has a `fail_mode`; non-inline has `fail_mode=null`.
6. `crypto` validates against ADR 0002's allowed algorithm sets for `suite_id`.
7. `signature` verifies over the canonical bytes (all fields except `signature`).
8. Round-trip: `probert`-style replay of a saved hardware profile reproduces an identical manifest (offline testability).

## Relationship to `platforms/*.yaml`

`platforms/<profile>.yaml` is the **build-team input**; the manifest is the **per-device output**. Each profile file carries: the **match keys** (DT tokens / DMI tuples) → `platform.class`/`profile`; the **known-good/quirk lists** feeding `known-good` in the grant rule; **capability policy defaults**; `resources.reserved`/`defaults`; and min/recommended spec. **Adding hardware = one new `platforms/*.yaml`** — no scanner, mapper, schema, or UI change. That is the design test.

## Files & layout (for the build team)

```
manifest/
├── schema/
│   └── manifest.schema.json      # JSON Schema 2020-12 — the normative contract
├── examples/
│   ├── rk3588.manifest.json      # full annotated examples per class
│   ├── n100.manifest.json
│   └── generic.manifest.json
├── fixtures/                     # probert-style saved hw profiles for offline tests
│   ├── rpi5.profile.json
│   └── n100.profile.json
├── sign/                         # cosign + TPM-seal helpers (shared with security/)
└── README.md                     # this ADR distilled + how to regenerate examples
```

Build-team split: (a) **writer** = `bootstrap/` consumes a hardware profile + `platforms/*.yaml` → emits + signs the manifest; (b) **schema/validator** = `manifest/schema` + CI gate; (c) **reader library** = the `granted()`/budget helpers shared by `supervisor/`, `ui/` backend, and AEGIS; (d) **fixtures** = `manifest/fixtures` enable testing all three without real boards.

## Consequences / risks

- **Capabilities as objects** (not bare booleans) are richer than the Readme's snippet — slightly more verbose, but they carry `reason`/`evidence` that the 3-state UI and audit need. Worth it; the `granted()` helper hides the verbosity.
- **PCR-sealing brittleness** across OS updates is the main operational risk — mitigated by re-seal-on-update; cosign verification is the fallback.
- **`modules[]` is mutable** while the rest is immutable — keep the supervisor the *only* writer and re-sign on change, or the signature breaks.
- **Schema drift vs Readme** — the Readme's inline example must be updated to point at this ADR (flagged, not silently changed).

## Open questions

1. Sealing default per ADR 0002 §open-Q: cosign-only vs TPM-seal-where-present vs both — and the exact re-seal hook in the `bootc upgrade` flow.
2. Should `modules[]` live in the signed manifest at all, or in a **separate signed module-state file** so the immutable manifest never needs re-signing? (Leaning: split it out in Phase 2.)
3. `resources.total` on shared/virt/cloud where cores are elastic — express as a range or reconcile at runtime?
4. `device_id` derivation — from the identity pubkey vs a random UUID sealed at first boot.

## Sources / prior art

JSON Schema 2020-12; OpenWrt `board.json` (detect-once fact file); Canonical `probert` (replayable profile); systemd `hwdb` (static RO tables); Android system-feature tokens (`hasSystemFeature`); sigstore/cosign; TCG TPM 2.0 PCR sealing; ADR 0002 (crypto block). Consistent with [`Architecture.md`](../architecture/Architecture.md) connections C4–C11.

---

## heqk migration — see [ADR 0043](0043-heqk-microkernel-substrate.md)

**Coupling: SOFT.** The manifest schema and the "detect-once, capability-not-branch" model are substrate-independent and carry over unchanged. Only the *probe/scanner* re-targets from `/proc`·`/sys`·DT·DMI·`iw` to heqk's own hardware enumeration, and the RO-manifest UDS + `SO_PEERCRED` exposure re-expresses against heqk IPC. → **Phase M1**.
