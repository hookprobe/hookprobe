//! shed_ctrl_map — the `bpf`-feature-only half of `hookprobe-psid`: opens the PINNED `shed_ctrl`
//! map (created + zero-initialised by `napse-loader`, see `bpf.rs`'s doc on why it lives under
//! `/sys/fs/bpf/hookprobe/` and not `/sys/fs/bpf/napse/`) and writes the three scalars. Mirrors
//! `hydra-feedsync.rs`'s `update_blocklist` — a completely separate process opening a map another
//! process created/pinned by path, the same libbpf-rs `MapHandle::from_pinned_path` pattern.

use libbpf_rs::{MapCore, MapFlags, MapHandle};

// Must match napse_detect.h's SHED_KEY_* exactly (see that header's doc for why this is three
// plain u64 array slots rather than a packed struct value — no cross-language layout to agree on).
const SHED_KEY_TIER: u32 = 0;
const SHED_KEY_RATE_PPS: u32 = 1;
const SHED_KEY_HEARTBEAT_NS: u32 = 2;

/// Open the pinned map. `None` (never panics) if it isn't there yet — e.g. `napse-loader` hasn't
/// started/attached on this boot yet; `hookprobe-psid`'s own service ordering
/// (`base/units/hookprobe-psid.service`) retries the whole process via systemd `Restart=`, so a
/// transient miss here just means "try again shortly", not a hard failure.
pub fn open(pin_path: &str) -> Option<MapHandle> {
    match MapHandle::from_pinned_path(pin_path) {
        Ok(m) => Some(m),
        Err(e) => {
            eprintln!("hookprobe-psid: open pinned {pin_path} failed ({e}) — is napse-loader running yet?");
            None
        }
    }
}

/// Write all three scalars. Best-effort per-key (a single failed key — e.g. a torn-down map
/// mid-write during a napse-loader restart — must never crash this daemon; the BPF side already
/// fails open on a subsequently-stale heartbeat regardless).
pub fn write(map: &MapHandle, tier: u8, rate_pps: u32, heartbeat_ns: u64) {
    let put = |k: u32, v: u64| {
        if let Err(e) = map.update(&k.to_ne_bytes(), &v.to_ne_bytes(), MapFlags::ANY) {
            eprintln!("hookprobe-psid: shed_ctrl write key={k} failed: {e}");
        }
    };
    put(SHED_KEY_TIER, tier as u64);
    put(SHED_KEY_RATE_PPS, rate_pps as u64);
    put(SHED_KEY_HEARTBEAT_NS, heartbeat_ns);
}
