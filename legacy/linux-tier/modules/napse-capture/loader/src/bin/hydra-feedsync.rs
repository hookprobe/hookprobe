//! hydra-feedsync — HYDRA threat-intel → BPF blocklist map (ADR 0005). Reads CIDR feed files a
//! fetcher dropped in FEEDS_DIR (Spamhaus DROP/EDROP, FireHOL, Emerging Threats, Feodo, …), parses +
//! dedups them (the tested `napse_loader::feed` core), and inserts them into the pinned `blocklist`
//! LPM map that napse_detect.bpf.c drops on. Runs on a timer (hourly). The fetch (curl the feeds) is
//! a separate step so this needs no HTTP stack. Without the `bpf` feature it's a dry-run counter.

use anyhow::{Context, Result};
use napse_loader::feed::{self, V4Prefix};
use std::collections::HashSet;

fn env_or(k: &str, d: &str) -> String {
    std::env::var(k).unwrap_or_else(|_| d.to_string())
}

fn collect(dir: &str) -> Result<Vec<V4Prefix>> {
    let mut seen = HashSet::new();
    let mut all = Vec::new();
    let rd = std::fs::read_dir(dir).with_context(|| format!("read feeds dir {dir}"))?;
    for entry in rd.flatten() {
        let p = entry.path();
        if !p.is_file() {
            continue;
        }
        if let Ok(body) = std::fs::read_to_string(&p) {
            for pfx in feed::parse_feed(&body) {
                if seen.insert((pfx.octets, pfx.prefixlen)) {
                    all.push(pfx);
                }
            }
        }
    }
    Ok(all)
}

fn main() -> Result<()> {
    let dir = env_or("FEEDS_DIR", "/var/lib/hookprobe/feeds");
    let prefixes = collect(&dir)?;
    eprintln!("hydra-feedsync: {} unique CIDR prefixes from {dir}", prefixes.len());

    #[cfg(feature = "bpf")]
    {
        let n = update_blocklist(&prefixes)?;
        eprintln!("hydra-feedsync: synced {n}/{} prefixes → BPF blocklist map", prefixes.len());
    }
    #[cfg(not(feature = "bpf"))]
    {
        for p in prefixes.iter().take(3) {
            eprintln!("  {}.{}.{}.{}/{}", p.octets[0], p.octets[1], p.octets[2], p.octets[3], p.prefixlen);
        }
        eprintln!("hydra-feedsync: dry-run (build --features bpf to update the pinned blocklist map)");
    }
    Ok(())
}

/// Open the pinned `blocklist` LPM map (napse-loader pins it under /sys/fs/bpf/napse) and insert
/// every prefix. Value is a presence byte; the BPF program only checks membership.
#[cfg(feature = "bpf")]
fn update_blocklist(prefixes: &[V4Prefix]) -> Result<usize> {
    use libbpf_rs::{MapCore, MapFlags, MapHandle};
    let path = env_or("BLOCKLIST_PIN", "/sys/fs/bpf/napse/blocklist");
    let map = MapHandle::from_pinned_path(&path)
        .with_context(|| format!("open pinned blocklist {path} — is napse-capture.service running?"))?;
    let val = [1u8];
    let mut n = 0;
    for p in prefixes {
        if map.update(&p.to_lpm_key(), &val, MapFlags::ANY).is_ok() {
            n += 1;
        }
    }
    Ok(n)
}
