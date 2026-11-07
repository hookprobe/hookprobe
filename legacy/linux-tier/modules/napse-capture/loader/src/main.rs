//! napse-loader — the userspace half of napse-capture (ADR 0005). Reads the signed manifest, builds
//! the self-selecting attach plan (native XDP where the driver supports it, TC-bpf otherwise), and —
//! with the `bpf` feature — attaches the CO-RE detection object, programs the role/config maps, and
//! drains the events ringbuf into `/var/lib/hookprobe/flows` (the NAPSE stream).
//!
//! Without `bpf` (the default / this dev box) it runs as a PLAN-ONLY dry run — still useful to see
//! exactly what would attach where. The BPF glue builds in CI, where libbpf + the compiled
//! `napse_detect.bpf.o` are present.

#[cfg(feature = "bpf")]
mod bpf;

use anyhow::{Context, Result};
use hookprobe_manifest::inspect::InspectIntent;
use hookprobe_manifest::Manifest;
use napse_loader::plan;

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

fn main() -> Result<()> {
    let manifest_path = env_or("MANIFEST", "/var/lib/hookprobe/manifest.json");
    let obj_path = env_or("NAPSE_OBJ", "/usr/lib/hookprobe/xdp/napse_detect.bpf.o");
    let flows = env_or("FLOWS", "/var/lib/hookprobe/flows");

    let raw = std::fs::read_to_string(&manifest_path).with_context(|| format!("read {manifest_path}"))?;
    let m: Manifest = serde_json::from_str(&raw).context("parse manifest")?;

    // Zero-trust default posture; EVERY uplink (primary + failover + cellular) is WAN-side.
    let intent = InspectIntent::default();
    let uplinks: Vec<&str> = m.network.uplinks.iter().map(|u| u.name.as_str()).collect();
    let targets = plan::build(&m, &intent, &uplinks, plan::sysfs_ifindex);

    eprintln!(
        "napse-loader: {} target(s), bpf_stateful={}, wan=[{}]",
        targets.len(),
        m.network.bpf_stateful,
        uplinks.join(",")
    );
    for t in &targets {
        eprintln!(
            "  {:<8} ifindex={:<3} attach={:?} role={}",
            t.iface, t.ifindex, t.attach, if t.role == 1 { "wan" } else { "lan" }
        );
    }

    #[cfg(feature = "bpf")]
    {
        bpf::run(&obj_path, &targets, &flows)?;
    }
    #[cfg(not(feature = "bpf"))]
    {
        let _ = (&obj_path, &flows);
        eprintln!(
            "napse-loader: built WITHOUT the `bpf` feature — plan-only dry run. \
             Rebuild `--features bpf` in CI (needs libbpf + napse_detect.bpf.o) to attach + drain."
        );
    }
    Ok(())
}
