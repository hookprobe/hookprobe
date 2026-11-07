//! libbpf glue — compiled ONLY with `--features bpf` (needs libbpf + the compiled CO-RE
//! `l2guard.bpf.o`). Loads the object once, attaches `l2guard_ingress` at TC-bpf clsact INGRESS on
//! the LAN and WAN interfaces (same ADR 0005 rationale `modules/napse-quarantine/loader/src/bpf.rs`
//! documents: `wlan0`/brcmfmac has no native XDP, so TC-bpf is the one hook that covers both
//! without a driver-specific branch), pins the stats map, and — unlike `napse-quarantine` — has
//! NOTHING to reconcile: this program's enforcement logic is entirely self-contained inside the
//! compiled BPF bytecode (no external state file it mirrors into a map). The loader's only ongoing
//! job once attached is to (a) stay alive so the kernel attach isn't torn down (dropping a
//! `libbpf_rs::TcHook` detaches it — see `run`'s comment) and (b) periodically log the
//! pass/drop counters for cheap observability, the same `--status` convenience
//! `modules/napse-quarantine` offers.
//!
//! FAIL-OPEN CONTRACT (mirrors `napse-quarantine`'s bpf.rs exactly): any error loading the object,
//! finding the program, or attaching a hook is surfaced to the caller (`main.rs` logs it and exits
//! non-zero) WITHOUT touching anything that already exists — no qdisc is deleted, no packet is
//! treated any differently than before this process ran. `Restart=on-failure` retries this loader
//! on its own schedule.

use anyhow::{bail, Context, Result};
use libbpf_rs::{MapCore, MapFlags, Object, ObjectBuilder, TcHookBuilder, TC_INGRESS};
use std::ffi::OsStr;
use std::os::fd::AsFd;
use std::time::Duration;

/// The TC priority this program claims at clsact ingress. Chosen to sit strictly BETWEEN
/// `modules/napse-quarantine`'s priority 1 (identity quarantine — must win outright, evaluated
/// first) and `modules/napse-capture`'s priority 10 (the DPI mirror) — see that module's README
/// coexistence note. Malformed-frame drop and identity quarantine check independent conditions
/// (a matched malformed frame is dropped regardless of whether its source also happens to be
/// quarantined, and vice versa), so their relative order does not affect correctness, only which
/// one "wins" the stats-counter credit for a frame that both would have dropped — priority 5 is
/// picked purely to leave room on either side for a future Ring-0 program without renumbering
/// either existing one.
const TC_PRIORITY: u32 = 5;
const TC_HANDLE: u32 = 1;

fn find_prog<'o>(obj: &'o Object, name: &str) -> Option<libbpf_rs::ProgramMut<'o>> {
    obj.progs_mut().find(|p| p.name() == OsStr::new(name))
}

/// Resolve a NIC's ifindex from sysfs — mirrors `napse-quarantine`/`napse-loader`'s identical
/// resolver.
fn sysfs_ifindex(name: &str) -> Result<u32> {
    std::fs::read_to_string(format!("/sys/class/net/{name}/ifindex"))
        .with_context(|| format!("read ifindex for {name} (is the interface present?)"))?
        .trim()
        .parse()
        .with_context(|| format!("parse ifindex for {name}"))
}

fn pin_path(pin_dir: &str, name: &str) -> String {
    format!("{pin_dir}/{name}")
}

/// Load the object and pin its one stats map (fresh — any stale pin from a prior instance is
/// removed first, same reasoning as `napse-quarantine::load_and_pin`: `load()` always makes a NEW
/// map, so an orphaned pin would otherwise make `pin()` fail `EEXIST`).
fn load_and_pin(obj_path: &str, pin_dir: &str) -> Result<Object> {
    let mut builder = ObjectBuilder::default();
    // CO-RE BTF source (ADR 0029/0030): Debian/UEFI kernels expose native BTF and this is a no-op;
    // the RPi BSP kernels (6.12.93+rpt-rpi-v8 / -2712) do NOT enable CONFIG_DEBUG_INFO_BTF, so this
    // points libbpf at the shipped `/usr/lib/hookprobe/btf/vmlinux-$(uname -r).btf` blob. If neither
    // native BTF nor a shipped blob is present it errors here (fail-closed on load) rather than
    // crash-looping deep in libbpf. `_btf_guard` OWNS the path CString libbpf reads during
    // open_file — it MUST stay alive across the open/load below (do not drop early).
    let _btf_guard = hookprobe_manifest::xdp::apply_btf_custom_path(&mut builder)
        .map_err(anyhow::Error::msg)
        .context("resolve CO-RE BTF for l2guard")?;
    let mut obj = builder
        .open_file(obj_path)
        .with_context(|| format!("open {obj_path}"))?
        .load()
        .context("load l2guard object (verifier)")?;

    std::fs::create_dir_all(pin_dir).with_context(|| format!("mkdir {pin_dir}"))?;
    let path = pin_path(pin_dir, "stats");
    let _ = std::fs::remove_file(&path);
    match obj.maps_mut().find(|m| m.name() == OsStr::new("l2guard_stats")) {
        Some(mut map) => map.pin(&path).with_context(|| format!("pin l2guard_stats at {path}"))?,
        None => bail!("map l2guard_stats not found in {obj_path} — object/loader mismatch"),
    }
    Ok(obj)
}

/// Attach `l2guard_ingress` at clsact INGRESS on one iface. Idempotent: `create()` tolerates an
/// already-existing clsact qdisc, and `.replace(true)` makes re-running this loader a clean
/// re-attach, not a stacking duplicate — same convention as `napse-quarantine::attach_one`.
fn attach_one(prog: &libbpf_rs::ProgramMut<'_>, iface: &str) -> Result<libbpf_rs::TcHook> {
    let ifindex = sysfs_ifindex(iface)? as i32;
    let mut hook = TcHookBuilder::new(prog.as_fd())
        .ifindex(ifindex)
        .replace(true)
        .handle(TC_HANDLE)
        .priority(TC_PRIORITY)
        .hook(TC_INGRESS);
    hook.create().ok(); // clsact qdisc may already exist (napse-quarantine's, napse-capture's mirror tap, etc.)
    hook.attach().with_context(|| format!("attach l2guard_ingress on {iface} (tc ingress)"))?;
    Ok(hook)
}

fn read_stats(stats: &libbpf_rs::MapHandle) -> Result<(u64, u64)> {
    let pass = stats.lookup(&0u32.to_ne_bytes(), MapFlags::ANY)?.map(|v| u64::from_ne_bytes(v.try_into().unwrap())).unwrap_or(0);
    let drop = stats.lookup(&1u32.to_ne_bytes(), MapFlags::ANY)?.map(|v| u64::from_ne_bytes(v.try_into().unwrap())).unwrap_or(0);
    Ok((pass, drop))
}

/// Load, attach to the LAN and WAN ifaces, and stay resident (heartbeat + periodic stats log)
/// forever. There is no external state to reconcile (unlike `napse-quarantine`) — this program's
/// entire enforcement logic lives in the compiled BPF bytecode; the ONLY reason this process must
/// keep running is that dropping the `libbpf_rs::TcHook` values detaches them (the kernel's clsact
/// filter goes away when the owning fd/handle is released) — the `hooks` vec below is kept alive
/// for exactly that reason, mirroring `napse-quarantine::run`'s identical pattern.
pub fn run(obj_path: &str, lan_iface: &str, wan_iface: &str, pin_dir: &str, stats_interval: Duration) -> Result<()> {
    let obj = load_and_pin(obj_path, pin_dir)?;
    let prog = find_prog(&obj, "l2guard_ingress").context("l2guard_ingress prog not found in object")?;

    let mut hooks = Vec::new();
    for iface in [lan_iface, wan_iface] {
        match attach_one(&prog, iface) {
            Ok(h) => {
                hooks.push(h);
                eprintln!("napse-l2guard: attached l2guard_ingress on {iface} (tc clsact ingress, prio {TC_PRIORITY})");
            }
            // One bad iface (down, renamed, removed) must not stop enforcement on the others.
            Err(e) => eprintln!("napse-l2guard: WARN attach on {iface} failed: {e:#} — continuing with the rest"),
        }
    }
    if hooks.is_empty() {
        bail!("no interface attached — nothing enforced (fail-open: process exits, no drop enforcement on this device)");
    }

    let stats = libbpf_rs::MapHandle::from_pinned_path(pin_path(pin_dir, "stats")).context("open pinned stats map")?;
    eprintln!("napse-l2guard: enforcing malformed-frame/malformed-ARP drop; logging pass/drop counters every {stats_interval:?}");
    loop {
        std::thread::sleep(stats_interval);
        match read_stats(&stats) {
            Ok((pass, drop)) => eprintln!("napse-l2guard: stats pass={pass} drop={drop}"),
            Err(e) => eprintln!("napse-l2guard: WARN could not read stats this cycle: {e:#}"),
        }
    }
}

/// `--status`: read the pinned stats map directly (no attach) and print a JSON snapshot — the
/// on-device substitute for `bpftool map dump`, same convention as `napse-quarantine::status`.
pub fn status(pin_dir: &str) -> Result<()> {
    let stats = libbpf_rs::MapHandle::from_pinned_path(pin_path(pin_dir, "stats")).context("open pinned stats map (is the loader running?)")?;
    let (pass, drop) = read_stats(&stats)?;
    println!("{}", serde_json::json!({ "stats": { "pass": pass, "drop": drop } }));
    Ok(())
}
