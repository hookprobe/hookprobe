//! Module definition types (`modules/*/module.yaml`).
//!
//! These are read by the supervisor/reconciler. The real loader (Wasmtime /
//! Podman) is a future impl; see the `Loader` trait in `supervisor/src/main.rs`.
//! TODO: Wasmtime (epoch+StoreLimits) for wasm, Podman/Quadlet for container;
//!       enforce budgets at cgroup + Wasmtime layers.

use serde::{Deserialize, Serialize};

use crate::types::{Budget, Runtime};

/// A module definition from `modules/<id>/module.yaml`.
#[derive(Debug, Clone, Deserialize)]
pub struct ModuleDef {
    pub id: String,
    pub version: String,
    pub runtime: Runtime,
    #[serde(default)]
    pub requires: ModuleRequires,
    #[serde(default)]
    pub provides: ModuleProvides,
    /// Requested budget. If absent, supervisor falls back to
    /// `manifest.resources.defaults[runtime]`.
    pub resources: Option<Budget>,
    /// `"required"` or `"unsigned"`.
    #[serde(default = "unsigned")]
    pub signature: String,
    /// The ONLY host access the module receives (WASI caps). Each entry is a single-key map whose
    /// value is a string (`{read: /var/lib/hookprobe/flows}`, `{wasi-nn: cpu}`) or a list
    /// (`{cap: [bpf, net_admin, net_raw]}` for sysext/container). The Wasmtime loader turns `read`
    /// grants into WASI preopened dirs; a module gets NOTHING it does not list here.
    #[serde(default)]
    pub grants: Vec<std::collections::BTreeMap<String, GrantValue>>,
    /// OCI artifact ref (e.g. `registry.hookprobe.com/modules/napse:2.4.1`). The local loader maps
    /// this (or the module id) to the on-disk `.wasm`/`.cwasm`; None for host/sysext modules.
    #[serde(default)]
    pub artifact: Option<String>,
    /// Payload digest(s) the `module.sig` signature transitively covers (ADR 0016 D1). The
    /// supervisor recomputes and compares each of these against the file actually on disk
    /// BEFORE executing (`module_sig::verify_artifact_digests`) — closing the gap where
    /// `module_digest()` signs `module.yaml` but never the `.wasm`/loader-ELF/`.bpf.o` payload
    /// `locate_wasm`/`locate_executable` resolves. Empty for a module that ships no discrete
    /// payload file; for a `signature: required` module an empty block is a fail-closed
    /// condition the supervisor enforces per ADR 0016 D5 (hard fail in release, loud warn in
    /// dev/debug) — NOT validated here, since that policy depends on the build profile, which
    /// this schema-only type has no business knowing about.
    #[serde(default)]
    pub artifacts: Vec<ArtifactDigest>,
    /// `status: stub` (ADR 0015 D3 escape hatch) — nothing buildable exists yet for this module;
    /// `builder/gen-staging.sh` stages nothing and every registry gate exempts it. `None` for
    /// every normal (non-stub) module.yaml. Mirrors the SAME field `gen-staging.sh`'s Python
    /// already reads directly from YAML (`m.get("status")`) — added here so Rust callers (the
    /// `--write-artifact-digests`/`--check-artifact-digests` registry sweeps) can apply the
    /// identical exemption without re-parsing the YAML a second way.
    #[serde(default)]
    pub status: Option<String>,
    /// The `staging:` override block (ADR 0015 D1) for irregular runtimes (sysext/host/
    /// container/image-layer). Parsed here (not just by `gen-staging.sh`'s Python) so the digest
    /// tooling can resolve a sysext/native-loader module's on-device `artifacts[].path` (the
    /// staged **dest**) back to the **build-tree source** `gen-staging.sh`/`stage-apply.sh`
    /// already stage it from — the SAME `staging.artifacts[].src` convention those scripts
    /// interpret, not a second one (ADR 0016/0017 sysext-artifact-digest gap fix). `None` for
    /// every wasm-convention module (co-located `.wasm`, no override needed).
    #[serde(default)]
    pub staging: Option<ModuleStaging>,
    /// Runtime-set by the supervisor after cosign-style verification (NOT from YAML):
    /// `None` = not externally verified (reference/tests trust); `Some(false)` = failed.
    #[serde(skip)]
    pub sig_verified: Option<bool>,
}

/// `module.yaml`'s `staging:` override block (ADR 0015 D1) — modeled minimally, ONLY the
/// sub-fields the digest tooling needs (`artifacts[].src`/`dest`). `build:`/`units:`/`preset:`/
/// `self_gated:` remain consumed exclusively by `builder/gen-staging.sh`'s Python today; adding
/// them here later is additive/back-compat whenever a Rust consumer needs them too.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct ModuleStaging {
    #[serde(default)]
    pub artifacts: Vec<StagingArtifact>,
}

/// One `staging.artifacts[]` entry: `src` (the build-tree path `gen-staging.sh`/`stage-apply.sh`
/// resolve via the `{repo}`/`{wasm}`/`{bin}`/`{gnu_bin}` placeholder convention, or a bare
/// repo-relative path) that gets staged to the on-device `dest` — the SAME `dest` a sysext
/// module's `artifacts[].path` entry pins (see `modules/napse-quarantine/module.yaml`'s worked
/// example).
#[derive(Debug, Clone, Deserialize)]
pub struct StagingArtifact {
    pub src: String,
    pub dest: String,
    #[serde(default)]
    pub mode: Option<String>,
}

/// A grant value: a scalar (`read: /path`, `wasi-nn: cpu`) or a list (`cap: [bpf, net_admin]`).
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum GrantValue {
    Str(String),
    List(Vec<String>),
}

impl ModuleDef {
    /// Host paths this module is granted READ access to (→ WASI preopened dirs).
    pub fn read_grants(&self) -> Vec<&str> {
        self.grants
            .iter()
            .filter_map(|g| match g.get("read") {
                Some(GrantValue::Str(p)) => Some(p.as_str()),
                _ => None,
            })
            .collect()
    }
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct ModuleRequires {
    #[serde(default)]
    pub capabilities: Vec<String>,
    #[serde(default)]
    pub min_memory_mb: u64,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct ModuleProvides {
    #[serde(default)]
    pub capabilities: Vec<String>,
}

fn unsigned() -> String {
    "unsigned".to_string()
}

// --- ADR 0016: artifact-hash signing — the `artifacts:` block --------------------------------

/// One payload file a module ships, named + digest-pinned (ADR 0016 D1). The signature over
/// `module.yaml` transitively covers these bytes because they live INSIDE the signed manifest —
/// the supervisor's job is only to prove the file on disk still matches (recompute + compare).
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct ArtifactDigest {
    /// Resolved relative to the module's install dir (the co-located `.wasm` convention — e.g.
    /// `napse.wasm` next to this `module.yaml`, on-device `/usr/lib/hookprobe/modules/<id>/<id>.wasm`),
    /// or used AS-IS if absolute (the sysext/host-integral convention, e.g.
    /// `/usr/lib/hookprobe/bin/napse-quarantine`). ADR 0017: a `role: aot` entry's `path` may
    /// legitimately REPEAT across entries (one per built arch, e.g. `napse.cwasm` for both
    /// `arch: arm64` and `arch: amd64`) — `arch` (below), not `path`, disambiguates those.
    pub path: String,
    /// `executable | bpf-object | loader | data | aot` — informational (the supervisor's own
    /// loader, not this field, decides which physical file actually gets executed for
    /// `runtime: wasm`); `Executable` is the one role a `signature: required` module is expected
    /// to declare so the mandatory payload-execution check (ADR 0016 D2) has something to bind
    /// to. `Aot` (ADR 0017) pins a build-time-precompiled `.cwasm` — arch-qualified (see `arch`),
    /// NEVER treated as a substitute for the `executable` binding check: a `.cwasm` is an
    /// alternate, faster way to obtain the SAME verified code, not a different payload.
    #[serde(default)]
    pub role: ArtifactRole,
    /// ADR 0017 D1: which target arch this artifact was built for (`arm64` | `amd64` |
    /// `riscv64`). `None` for every arch-independent artifact (the `.wasm` source, a `bpf-object`,
    /// a native `loader` ELF built for the image's own single arch) — those keep meaning "this
    /// one entry covers whichever arch actually ships it". `Some(_)` is required for `role: aot`
    /// (a `.cwasm` is Wasmtime-version- and target-specific) so a single signed `module.yaml` can
    /// enumerate one digest per built arch; the supervisor consults ONLY the entry whose `arch`
    /// equals its own running arch (`module_sig::running_arch()`) — every other arch's entry is
    /// inert signed metadata, never looked at, never a reason to refuse a load.
    #[serde(default)]
    pub arch: Option<String>,
    /// ADR 0017/0021 CPU-microarch tier this AOT blob was precompiled for (e.g. `cortex-a76` —
    /// LSE atomics ON, ARMv8.2, rpi5/rk3588). `None` = the arch's SAFE BASELINE, loadable on the
    /// oldest CPU that arch ships (Cortex-A72/ARMv8.0 on arm64 — NO LSE, the Pi 4). Meaningful
    /// only for `role: aot`: a module MAY declare, in ADDITION to the baseline `role: aot`
    /// entry, a second `role: aot` entry for the same `arch` carrying `cpu:` — a faster tier. The
    /// supervisor selects the `cpu:`-qualified blob ONLY when the SIGNED Platform Manifest's
    /// `hardware.cpu.tier` equals it (`module_sig::verify_aot_binding` / `wasm_loader::
    /// load_module_gated`); on ANY doubt it falls back to the baseline (never an A76 blob on an
    /// A72 — that would trap on an illegal LSE instruction), then to verified JIT. Fail-closed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu: Option<String>,
    /// Possibly a list in a future hash-migration window (ADR 0016 D1); today exactly one named
    /// algorithm per artifact.
    pub digest: Digest,
}

/// What kind of payload file an `ArtifactDigest` entry names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum ArtifactRole {
    #[default]
    Executable,
    BpfObject,
    Loader,
    Data,
    /// ADR 0017 — a build-time-precompiled, Wasmtime-native `.cwasm`, arch-qualified (see
    /// `ArtifactDigest::arch`), shipped in the RO rootfs. An authenticated fast path IN FRONT of
    /// (never a replacement for) the `role: executable` verified-JIT floor: any doubt at all
    /// (absent, wrong arch, digest mismatch, or a Wasmtime version/config-drift `deserialize`
    /// error) falls back to compiling the verified `.wasm`, never executes an unverified blob.
    Aot,
}

/// A NAMED-algorithm digest — crypto-agile per ADR 0002 (`crypto.module_signing` is policy, never
/// hardcoded). `sha256` is today's default; `sha384`/`sha3-256` are drop-in by naming them
/// differently. The verifier (`module_sig::digest_hex`) rejects any alg it does not implement,
/// fail-closed, rather than silently treating an unknown name as a pass.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct Digest {
    pub alg: String,
    pub value: String,
}
