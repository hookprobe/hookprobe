//! Resource allocation and retention computation.
//!
//! Mirrors `allocate_resources()` and `compute_retention()` in
//! `bootstrap/reference/generate_manifest.py`.

use crate::platform::PlatformSpec;
use crate::scan::HardwareScan;
use crate::types::{CpuMem, Defaults, Resources, Retention, RetentionTier};

/// Fraction of raw storage considered usable for the data partition.
const STORAGE_OVERHEAD: f64 = 0.8;

/// Allocate resources from scan facts + platform policy.
///
/// total   = { cpu_pct: cores * 100, memory_mb: scan.memory_mb }
/// allocatable = total - reserved
pub fn allocate_resources(scan: &HardwareScan, platform: &PlatformSpec) -> Resources {
    let total_cpu = scan.cpu.cores as u64 * 100;
    let total_mem = scan.memory_mb;
    let res = &platform.resources;

    Resources {
        total: CpuMem {
            cpu_pct: total_cpu,
            memory_mb: total_mem,
        },
        reserved: CpuMem {
            cpu_pct: res.reserved.cpu_pct,
            memory_mb: res.reserved.memory_mb,
        },
        allocatable: CpuMem {
            cpu_pct: total_cpu.saturating_sub(res.reserved.cpu_pct),
            memory_mb: total_mem.saturating_sub(res.reserved.memory_mb),
        },
        defaults: Defaults {
            wasm: res.defaults.wasm.clone(),
            container: res.defaults.container.clone(),
        },
    }
}

/// Compute retention tiers from actual storage + platform tier fractions.
///
/// usable = sum(storage.size_gb) * 0.8
/// cap_gb = round(usable * fraction)   (rounds to nearest integer)
pub fn compute_retention(
    scan: &HardwareScan,
    platform: &PlatformSpec,
    now_iso: &str,
) -> Retention {
    let usable: f64 = scan.storage.iter().map(|s| s.size_gb).sum::<f64>() * STORAGE_OVERHEAD;

    let mut tiers: Vec<RetentionTier> = platform
        .retention
        .tier_fractions
        .iter()
        .map(|(name, frac)| {
            let cap_gb = (usable * frac).round();
            let window = window_bucket(name, cap_gb);
            RetentionTier {
                name: name.clone(),
                cap_gb,
                window,
            }
        })
        .collect();

    // Sort tiers by name for deterministic output.
    tiers.sort_by(|a, b| a.name.cmp(&b.name));

    Retention {
        tiers,
        computed_at: now_iso.to_string(),
    }
}

/// Coarse, honest default window estimate — real window depends on traffic volume.
///
/// Mirrors `_window_bucket()` in the Python reference.
fn window_bucket(name: &str, cap_gb: f64) -> String {
    match name {
        "pcap" => {
            if cap_gb < 16.0 {
                "hours".to_string()
            } else {
                "~1 day".to_string()
            }
        }
        "events" => {
            if cap_gb < 24.0 {
                "~1-2 weeks".to_string()
            } else {
                "~1-2 months".to_string()
            }
        }
        _ => {
            if cap_gb < 24.0 {
                "months".to_string()
            } else {
                "year+".to_string()
            }
        }
    }
}
