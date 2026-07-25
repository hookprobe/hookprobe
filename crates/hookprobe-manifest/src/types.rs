//! Schema-2 Platform Manifest serde types.
//!
//! Every struct here serializes to JSON that passes
//! `manifest/schema/manifest.schema.json` (Draft 2020-12).

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Top-level document
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub schema_version: u32,
    pub identity: Identity,
    pub platform: ManifestPlatform,
    pub hardware: Hardware,
    pub network: Network,
    pub capabilities: HashMap<String, Capability>,
    pub resources: Resources,
    pub crypto: Crypto,
    pub retention: Retention,
    pub modules: Vec<ModuleEntry>,
    pub provenance: Provenance,
    pub signature: SignatureBlock,
}

// ---------------------------------------------------------------------------
// identity
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Identity {
    pub device_id: String,
    pub serial: Option<String>,
    pub idevid: IDevId,
    pub claim_state: ClaimState,
    pub tenant: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IDevId {
    #[serde(rename = "type")]
    pub kind: IDevIdType,
    pub pubkey_fpr: String,
    pub sealed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum IDevIdType {
    Tpm,
    Dice,
    Software,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ClaimState {
    Unclaimed,
    Claimed,
    Enrolled,
}

// ---------------------------------------------------------------------------
// platform
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestPlatform {
    pub class: PlatformClass,
    pub profile: String,
    pub sku: Option<String>,
    #[serde(rename = "match")]
    pub match_info: MatchInfo,
    /// 2026-07-05 FIX (backend-audit P1 #5 — "first-boot manifest freezes capability
    /// grants"): the version of the CLASSIFICATION/CAPABILITY-MAPPING logic
    /// (`crate::builder::PLATFORM_RULES_VERSION`) baked into the image that GENERATED
    /// this manifest — NOT a hardware fact. Compared against the running image's own
    /// `PLATFORM_RULES_VERSION` by `hookprobe-bootstrap --check-rules-version` so a
    /// classification/capability-mapping fix that ships in a later image can reach an
    /// already-provisioned device (re-probe) without re-probing on every boot and
    /// without needing a hardware change. `#[serde(default)]` so an OLDER manifest
    /// (written before this field existed) deserializes as `0` — always "older" than
    /// any real `PLATFORM_RULES_VERSION >= 1`, so the very first check after upgrading
    /// past this fix correctly re-probes once, then settles.
    #[serde(default)]
    pub platform_rules_version: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "kebab-case")]
pub enum PlatformClass {
    EdgeLite,
    EdgePro,
    Cloud,
    Virtual,
    Dev,
    Generic,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchInfo {
    pub method: MatchMethod,
    pub key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum MatchMethod {
    DeviceTree,
    DmiTuple,
    CpuModel,
    Virt,
    Fallback,
}

// ---------------------------------------------------------------------------
// hardware
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hardware {
    pub arch: Arch,
    pub cpu: Cpu,
    pub memory_mb: u64,
    pub storage: Vec<StorageDevice>,
    pub tpm: Tpm,
    pub secure_boot: SecureBoot,
    pub npu: Npu,
    pub virt: String,
    pub fingerprint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Arch {
    Arm64,
    Amd64,
    Riscv64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Cpu {
    pub model: String,
    pub cores: u32,
    /// CPU microarch tier for per-tier AOT blob selection (ADR 0017/0021). `cortex-a76` for
    /// rpi5/rk3588 (ARMv8.2, LSE atomics); `None` = the arch's SAFE BASELINE (Cortex-A72/ARMv8.0
    /// on arm64 — no LSE). Derived ONCE at classification time from the platform profile
    /// (`PlatformSpec::cpu_tier`) and frozen into the signed manifest — "detect once, query
    /// forever": the loader READS this, never re-probes the CPU. See `wasm_loader::
    /// load_module_gated`. `#[serde(default)]` so an older manifest (written before this field)
    /// deserializes as `None` = baseline, always the safe choice.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tier: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageDevice {
    pub dev: String,
    pub size_gb: f64,
    #[serde(rename = "type")]
    pub kind: String,
    /// Stable hardware ID (disk serial / wwid). The device fingerprint keys off this
    /// so `device_id` doesn't change when /dev names reorder (sda↔nvme↔mmcblk).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub serial: Option<String>,
    /// Removable media (SD card / USB stick) vs fixed (NVMe / eMMC).
    #[serde(default)]
    pub removable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tpm {
    pub present: bool,
    pub version: Option<String>,
    pub kind: TpmKind,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum TpmKind {
    Discrete,
    Firmware,
    None,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecureBoot {
    pub supported: bool,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Npu {
    pub present: bool,
    pub driver_ready: bool,
    pub vendor: Option<String>,
    pub model: Option<String>,
}

// ---------------------------------------------------------------------------
// network
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Network {
    pub interfaces: Vec<ManifestInterface>,
    pub wifi: Wifi,
    pub lte: Lte,
    /// The "Get Online" view: every WAN candidate (wired / Wi-Fi-station /
    /// cellular) in failover order. Read by the console + the multi-WAN reconciler.
    #[serde(default)]
    pub uplinks: Vec<ManifestUplink>,
    /// Each Wi-Fi radio with its STABLE-identity role (station vs AP), computed at
    /// build time by `net_roles::assign_wifi_roles`. Read by the Wi-Fi config
    /// reconciler so it never has to re-probe `onboard` at apply time.
    #[serde(default)]
    pub wifi_radios: Vec<WifiRadio>,
    /// Host kernel supports the stateful BPF fast-path (SCHED_CLS + `bpf_ct_lookup`, kernel ≥ 5.19).
    /// Derived once from the kernel release (`xdp::kernel_bpf_stateful`). `false` ⇒ the inspect
    /// ladder falls to the userspace software floor. See ADR 0005.
    #[serde(default)]
    pub bpf_stateful: bool,
}

/// One Wi-Fi radio + its assigned role in the signed manifest.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WifiRadio {
    pub name: String,
    /// "station" (sole-uplink radio) | "ap" (serving radio; the default on a router).
    pub role: String,
    /// Band(s) by stable phy capability: "2.4" | "5" | "6" | combo "2.4+5". Drives
    /// per-radio `hw_mode`/channel in the generated hostapd config. May be absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub band: Option<String>,
}

/// One WAN uplink candidate in the signed manifest (see `net_roles::enumerate_uplinks`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ManifestUplink {
    pub name: String,
    /// "wired" | "wifi-station" | "cellular".
    pub kind: String,
    /// Failover priority — lower = preferred.
    pub priority: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestInterface {
    pub name: String,
    pub mac: Option<String>,
    #[serde(rename = "type")]
    pub iface_type: InterfaceType,
    pub supported_modes: Vec<String>,
    pub role: InterfaceRole,
    pub fail_mode: Option<String>,
    pub state: String,
    /// Does this NIC's driver support NATIVE (driver-hook) XDP? Derived once by bootstrap from the
    /// driver name (`xdp::driver_supports_native_xdp`). `false` ⇒ the inspect ladder uses TC-bpf
    /// (universal, incl. Wi-Fi). A fact, not a grant. See ADR 0005.
    #[serde(default)]
    pub xdp_native: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum InterfaceType {
    Ethernet,
    Wifi,
    Lte,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum InterfaceRole {
    OutOfBand,
    Inline,
    Mgmt,
    Unassigned,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Wifi {
    pub present: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_standard: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Lte {
    pub present: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
}

// ---------------------------------------------------------------------------
// capabilities
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Capability {
    pub state: CapabilityState,
    pub reason: Option<String>,
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityState {
    Granted,
    PresentUnsafe,
    PolicyDenied,
    Absent,
}

// ---------------------------------------------------------------------------
// resources
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Resources {
    pub total: CpuMem,
    pub reserved: CpuMem,
    pub allocatable: CpuMem,
    pub defaults: Defaults,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpuMem {
    pub cpu_pct: u64,
    pub memory_mb: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Defaults {
    pub wasm: Budget,
    pub container: Budget,
}

/// Resource budget — the "two resource walls" (Readme.md "Resource limits & performance",
/// `docs/BuildPlan.md`'s "Resource budgets" row). `cpu_pct`/`memory_mb` are the ACCOUNTING
/// figures the reconciler subtracts from `manifest.resources.allocatable` (unchanged, existing
/// behavior) and ALSO the HARD-wall ceiling handed to the enforcement layer: cgroup `MemoryMax`/
/// `CPUQuota` for a container, and Wasmtime `StoreLimits` memory + (new) `fuel` for a wasm
/// module. `epoch_ms` is the pre-existing wall-clock wall (Wasmtime epoch interruption — a
/// runaway module is interrupted on a timer, regardless of how much CPU it actually burned).
///
/// NEW fields (resource-budgets feature) add the SOFT wall + weighting + the wasm CPU-metering
/// wall, all optional so every existing manifest/module.yaml/platforms/*.yaml keeps parsing
/// unchanged; `resource_budget::effective_*` fills in a sensible per-runtime default when unset
/// (see that module for the numbers and the ADR-worthy fork this note flags).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Budget {
    #[serde(default)]
    pub cpu_pct: u64,
    #[serde(default)]
    pub memory_mb: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub epoch_ms: Option<u64>,
    /// SOFT wall: cgroup `MemoryHigh` (throttle-back-pressure, never kills) — always <=
    /// `memory_mb`. `None` = derive from `memory_mb` at enforcement time
    /// (`resource_budget::Budget::effective_mem_high_mb`), never hardcoded at the call site.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mem_high_mb: Option<u64>,
    /// Relative cgroup `CPUWeight` (100-10000; systemd default 100) — only matters under
    /// contention between sibling units in the same slice. `None` = per-runtime default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu_weight: Option<u64>,
    /// Wasm-only CPU-metering wall: a Wasmtime fuel budget (`Config::consume_fuel` + one fuel
    /// unit per wasm instruction, roughly). Ignored for `runtime: container`/`sysext`/etc — those
    /// have no wasm engine to meter. `None` = per-runtime default
    /// (`resource_budget::Budget::effective_fuel`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fuel: Option<u64>,
}

// ---------------------------------------------------------------------------
// crypto
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Crypto {
    pub agility: bool,
    pub suite_id: String,
    pub image_signing: Vec<String>,
    pub module_signing: Vec<String>,
    pub boot_signing: String,
    pub tls_kex: Vec<String>,
    pub tls_auth: Vec<String>,
    pub data_at_rest: String,
    pub hash: Vec<String>,
    pub device_identity: Vec<String>,
    pub cbom: String,
}

// ---------------------------------------------------------------------------
// retention
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Retention {
    pub tiers: Vec<RetentionTier>,
    pub computed_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetentionTier {
    pub name: String,
    pub cap_gb: f64,
    pub window: String,
}

// ---------------------------------------------------------------------------
// modules (in manifest)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleEntry {
    pub id: String,
    pub version: String,
    pub runtime: Runtime,
    pub state: ModuleState,
    pub budget: Budget,
    pub signature: SignatureStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum Runtime {
    Wasm,
    Container,
    Sysext,
    ImageLayer,
    /// A host-native helper (systemd unit / script) — e.g. `senzorium-flow` reading conntrack, which
    /// WASI cannot. Not sandboxed by Wasmtime; runs with its declared host caps.
    Host,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ModuleState {
    Pending,
    Running,
    Throttled,
    Paused,
    Stopped,
    Failed,
    Evicted,
}

impl ModuleState {
    pub fn is_live(&self) -> bool {
        matches!(
            self,
            ModuleState::Pending | ModuleState::Running | ModuleState::Throttled | ModuleState::Paused
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum SignatureStatus {
    Verified,
    Required,
    Unsigned,
}

// ---------------------------------------------------------------------------
// provenance + signature
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Provenance {
    pub image_ref: String,
    pub image_digest: String,
    pub generated_at: String,
    pub generator: String,
    pub schema_version: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureBlock {
    pub method: String,
    pub sig: String,
    pub cert: String,
    pub tpm_sealed: bool,
    pub pcr_policy: Option<String>,
}
