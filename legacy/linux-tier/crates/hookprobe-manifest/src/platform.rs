//! Platform YAML types (`platforms/*.yaml`).
//!
//! These are the BUILD-TIME INPUT combined with scanner facts to produce the
//! signed Platform Manifest. "Adding hardware = one file in platforms/."

use serde::Deserialize;
use std::collections::HashMap;

use crate::types::Budget;

/// Top-level platform spec (one per `platforms/*.yaml`).
#[derive(Debug, Clone, Deserialize)]
pub struct PlatformSpec {
    pub profile: String,
    pub class: String,
    pub sku: Option<String>,
    /// CPU microarch tier for per-tier AOT blob selection (ADR 0017/0021 — `builder/refresh-aot.sh
    /// --with-a76`). `cortex-a76` for rpi5/rk3588 (ARMv8.2, LSE atomics); absent = the arch's SAFE
    /// baseline (Cortex-A72/ARMv8.0 on arm64 — no LSE, the Pi 4). Fully data-driven: giving a new
    /// board a faster AOT tier is ONE line in its `platforms/*.yaml`, no code change. Frozen into
    /// `manifest.hardware.cpu.tier` by `build_manifest`; the loader reads it, never re-probes.
    #[serde(default)]
    pub cpu_tier: Option<String>,
    #[serde(rename = "match")]
    pub match_rule: PlatformMatch,
    #[serde(default)]
    pub resources: PlatformResources,
    /// Ordered map of capability token -> policy.
    /// Ordering matters: `ids` requires `soc` to be resolved first.
    /// The fixpoint loop in `map_capabilities` handles any ordering correctly.
    #[serde(default)]
    pub capabilities: HashMap<String, CapabilityPolicy>,
    pub crypto_suite: String,
    #[serde(default)]
    pub retention: RetentionPolicy,
    /// Retirement audit #8 (2026-07-08) honesty marker: `true` ONLY for a profile that has
    /// a REAL on-silicon boot+selftest gate record (today: `rpi4` alone — see
    /// `docs/roadmap/BuildPlan.md`'s 2026-07-05/07-06 Pi4 boot entries). Every other profile is
    /// classification-tested only and must default to `false` rather than imply parity it
    /// hasn't earned. Optional/defaulted so existing profiles that predate this field still
    /// parse (schema-compatible, additive).
    #[serde(default)]
    pub hardware_validated: bool,
    /// Human-readable note explaining the `hardware_validated` verdict (e.g. "classification-
    /// tested; no on-silicon boot-gate record yet"). Optional — absent is honest (means
    /// "no note recorded yet"), never fabricated.
    #[serde(default)]
    pub validation_note: Option<String>,
}

/// How the classifier matches this platform profile.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "method", rename_all = "kebab-case")]
pub enum PlatformMatch {
    DeviceTree {
        #[serde(default)]
        device_tree_compatible: Vec<String>,
    },
    DmiTuple {
        #[serde(default)]
        dmi_tuples: Vec<DmiTuple>,
    },
    /// Match on the CPU model string (fnmatch globs). For x86 whitebox boards
    /// whose DMI is blank ("Default string"), e.g. the Intel N100.
    CpuModel {
        #[serde(default)]
        cpu_models: Vec<String>,
    },
    /// Match on the detected virtualization platform (e.g. `kvm`, `qemu`).
    Virt {
        #[serde(default)]
        virt: Vec<String>,
    },
    Fallback,
}

/// A DMI tuple entry. `*` is a wildcard for any field.
#[derive(Debug, Clone, Deserialize)]
pub struct DmiTuple {
    #[serde(default = "star")]
    pub sys_vendor: String,
    #[serde(default = "star")]
    pub product_name: String,
    #[serde(default = "star")]
    pub board_name: String,
}

fn star() -> String {
    "*".to_string()
}

/// Resource policy section of the platform YAML.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct PlatformResources {
    #[serde(default)]
    pub reserved: CpuMemRaw,
    #[serde(default)]
    pub defaults: PlatformDefaults,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct CpuMemRaw {
    #[serde(default)]
    pub cpu_pct: u64,
    #[serde(default)]
    pub memory_mb: u64,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct PlatformDefaults {
    #[serde(default)]
    pub wasm: Budget,
    #[serde(default)]
    pub container: Budget,
}

/// Single capability policy entry.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct CapabilityPolicy {
    /// Requirement expressions. Grammar:
    ///   - `"soc"` / `"ids"` — capability dependency (must be state=granted)
    ///   - `"cpu"` / `"memory_mb"` / `"arch"` — hardware fact presence
    ///   - `"memory_mb>=N"` / `"network.interfaces>=N"` — threshold
    ///   - `"wifi.present"` / `"npu.driver_ready"` / `"network.role:inline"` — feature flags
    #[serde(default)]
    pub requires: Vec<String>,
    /// `"enabled"` (default) or `"disabled"`.
    #[serde(default = "enabled")]
    pub policy: String,
    /// Drivers whose offload (TSO/LRO) has been validated for inline use.
    #[serde(default)]
    pub known_good_nic_drivers: Vec<String>,
}

fn enabled() -> String {
    "enabled".to_string()
}

/// Retention policy from the platform YAML.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct RetentionPolicy {
    /// Map of tier name -> fraction of usable storage (0.0–1.0).
    #[serde(default)]
    pub tier_fractions: HashMap<String, f64>,
}
