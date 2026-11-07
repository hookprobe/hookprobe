//! libbpf glue — compiled ONLY with `--features bpf` (needs libbpf + the compiled CO-RE
//! `quarantine.bpf.o`). Loads the object once, attaches `quarantine_ingress` at TC-bpf clsact
//! INGRESS on the LAN and WAN interfaces (ADR 0005: Wi-Fi has no native XDP, so TC-bpf is the one
//! hook that covers both without a driver-specific branch), pins the three maps, and reconciles
//! `quarantine_ips`/`quarantine_macs` from the scan-responder's persisted state file on a short
//! poll loop. Mirrors `modules/napse-capture/loader/src/bpf.rs`'s libbpf-rs usage pattern (0.24,
//! iterator-based map/prog access).
//!
//! FAIL-OPEN CONTRACT: any error loading the object, finding the program, or attaching a hook is
//! surfaced to the caller (`main.rs` logs it and exits non-zero) WITHOUT touching anything that
//! already exists — no qdisc is deleted, no nft rule is touched, no packet is treated any
//! differently than before this process ran. The datapath a device already has (out-of-band
//! capture, the reactive nft quarantine) keeps working exactly as before; systemd's
//! `Restart=on-failure` retries this loader on its own schedule. This is what makes the whole
//! layer additive rather than a new way to brick the network.
//!
//! 2026-07-05 threat-model fix (HIGH #3): map VALUES are no longer a bare hit counter — they are
//! `struct quarantine_val { ifindex; hits; }` (`quarantine.h`), and `quarantine.bpf.c` only drops
//! a match when `skb->ingress_ifindex` equals the entry's OWN bound ifindex. This module resolves
//! the LAN/WAN interfaces' ifindexes once at startup and threads them through every reconcile
//! cycle (`state::PlaneIfindexes`) so a LAN-plane entry can never fire on the WAN ifindex or vice
//! versa — matching the nft layer's existing `iifname`-scoped rules.

use crate::state::{self, DesiredKeys, PlaneIfindexes};
use anyhow::{bail, Context, Result};
use hookprobe_manifest::scan_responder::QuarantineEntry;
use libbpf_rs::{MapCore, MapFlags, MapHandle, Object, ObjectBuilder, TcHookBuilder, TC_INGRESS};
use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::os::fd::AsFd;
use std::time::Duration;

/// Encode `struct quarantine_val { __u32 ifindex; __u32 hits; }` (quarantine.h) as the raw 8
/// bytes libbpf needs: each `__u32` field's own native-endian representation, concatenated in
/// declaration order (no padding — both fields are the same size and alignment) — exactly what a
/// C compiler for this (little-endian arm64/x86_64) target lays the struct out as.
fn encode_value(ifindex: u32, hits: u32) -> [u8; 8] {
    let mut v = [0u8; 8];
    v[0..4].copy_from_slice(&ifindex.to_ne_bytes());
    v[4..8].copy_from_slice(&hits.to_ne_bytes());
    v
}

/// Decode a `struct quarantine_val` value back into `(ifindex, hits)`.
fn decode_value(v: &[u8]) -> Option<(u32, u32)> {
    if v.len() < 8 {
        return None;
    }
    let ifindex = u32::from_ne_bytes(v[0..4].try_into().ok()?);
    let hits = u32::from_ne_bytes(v[4..8].try_into().ok()?);
    Some((ifindex, hits))
}

/// The TC priority this program claims at clsact ingress. Chosen to be the LOWEST (= first-
/// evaluated) priority in the stack on purpose: a quarantine hit must win outright, before any
/// other classifier (the future napse-capture detection/DPI-mirror TC program included) even
/// sees the packet — that IS the "earliest kernel point" this whole module exists for. See the
/// coexistence note in module.yaml: `modules/napse-capture/loader/src/bpf.rs`'s `napse_tc` attach
/// has been bumped to priority 10 specifically so the two can never collide/clobber each other
/// (same ifindex + same priority + same handle = `.replace(true)` overwrites the other program).
const TC_PRIORITY: u32 = 1;
const TC_HANDLE: u32 = 1;

fn find_prog<'o>(obj: &'o Object, name: &str) -> Option<libbpf_rs::ProgramMut<'o>> {
    obj.progs_mut().find(|p| p.name() == OsStr::new(name))
}

/// Resolve a NIC's ifindex from sysfs — the real (non-test) resolver, mirrors
/// `napse-loader`'s `plan::sysfs_ifindex`.
fn sysfs_ifindex(name: &str) -> Result<u32> {
    std::fs::read_to_string(format!("/sys/class/net/{name}/ifindex"))
        .with_context(|| format!("read ifindex for {name} (is the interface present?)"))?
        .trim()
        .parse()
        .with_context(|| format!("parse ifindex for {name}"))
}

/// Pin path convention: `<pin_dir>/{ips,macs,stats}` — mirrors napse-capture's
/// `/sys/fs/bpf/napse/{blocklist,allowlist}` pinning so `hydra-feedsync`-style external tools
/// (or a future Mission Control read-API) have one obvious place to look.
fn pin_path(pin_dir: &str, name: &str) -> String {
    format!("{pin_dir}/{name}")
}

/// Load the object, pin its 3 maps (fresh — any stale pin from a prior instance is removed
/// first, exactly like `napse-capture`'s `bpf.rs`: a `load()` always makes NEW maps, so an
/// orphaned pin would otherwise make `pin()` fail `EEXIST` and leave a stale map behind).
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
        .context("resolve CO-RE BTF for quarantine")?;
    let mut obj = builder
        .open_file(obj_path)
        .with_context(|| format!("open {obj_path}"))?
        .load()
        .context("load quarantine object (verifier)")?;

    std::fs::create_dir_all(pin_dir).with_context(|| format!("mkdir {pin_dir}"))?;
    for m in ["quarantine_ips", "quarantine_macs", "quarantine_stats"] {
        let path = pin_path(pin_dir, &m.replace("quarantine_", ""));
        let _ = std::fs::remove_file(&path);
        match obj.maps_mut().find(|x| x.name() == OsStr::new(m)) {
            Some(mut map) => map.pin(&path).with_context(|| format!("pin {m} at {path}"))?,
            None => bail!("map {m} not found in {obj_path} — object/loader mismatch"),
        }
    }
    Ok(obj)
}

/// Attach `quarantine_ingress` at clsact INGRESS on one iface. Idempotent: `create()` tolerates
/// an already-existing clsact qdisc (`.ok()`, mirrors napse-capture), and `.replace(true)` makes
/// re-running this loader (e.g. after a Restart=on-failure) a clean re-attach, not a stacking
/// duplicate.
fn attach_one(prog: &libbpf_rs::ProgramMut<'_>, iface: &str) -> Result<libbpf_rs::TcHook> {
    let ifindex = sysfs_ifindex(iface)? as i32;
    let mut hook = TcHookBuilder::new(prog.as_fd())
        .ifindex(ifindex)
        .replace(true)
        .handle(TC_HANDLE)
        .priority(TC_PRIORITY)
        .hook(TC_INGRESS);
    hook.create().ok(); // clsact qdisc may already exist (napse-dpi's mirror tap, etc.)
    hook.attach().with_context(|| format!("attach quarantine_ingress on {iface} (tc ingress)"))?;
    Ok(hook)
}

/// One reconcile cycle: read the state file, compute desired keys (each bound to its plane's
/// ifindex — HIGH #3), diff against the LIVE map contents (not a shadow copy in this process —
/// reading straight from the kernel map means a crash-and-restart of this loader can never desync
/// from what's actually enforced), and apply only the delta. Each `update`/`delete` is a single
/// atomic bpf() syscall per key; at the quarantine set's scale (a handful of exact addresses, not
/// a bulk CIDR feed — see `quarantine.h`'s doc comment) that is the right-sized atomicity, not a
/// double-buffered swap.
fn reconcile_once(
    ips_map: &MapHandle,
    macs_map: &MapHandle,
    state_file: &str,
    ifindexes: PlaneIfindexes,
) -> Result<(usize, usize)> {
    let state: Vec<QuarantineEntry> = state::load_state(state_file)?;
    let desired: DesiredKeys = state::desired_keys(&state, ifindexes);

    // IP key endianness: `quarantine.bpf.c` uses `saddr = ip->saddr` — a byte-for-byte copy
    // straight out of the packet, i.e. the RAW WIRE (big-endian/network) octets with no
    // htonl/ntohl anywhere. `parse_ipv4_be` builds the matching value via `from_be_bytes`, so the
    // round-trip back to wire bytes is `to_be_bytes()` — NOT `to_ne_bytes()` (that would reverse
    // the octets on every little-endian host, e.g. aarch64/x86_64, and silently never match).
    let current_ips: BTreeMap<u32, u32> = ips_map
        .keys()
        .filter_map(|k| {
            let ip = u32::from_be_bytes(k.clone().try_into().ok()?);
            let (ifindex, _hits) = ips_map.lookup(&k, MapFlags::ANY).ok().flatten().and_then(|v| decode_value(&v))?;
            Some((ip, ifindex))
        })
        .collect();
    // MAC key: `pack_mac()` COMPUTES a u64 via shift-OR (not a byte copy), so its in-memory
    // representation follows the compiled BPF target's (little-endian) integer layout — the same
    // convention `napse-capture`'s `role_by_ifindex.to_ne_bytes()` already uses for a
    // computed/passed integer key. Native-endian is therefore correct here, unlike the IP key.
    let current_macs: BTreeMap<u64, u32> = macs_map
        .keys()
        .filter_map(|k| {
            let mac = u64::from_ne_bytes(k.clone().try_into().ok()?);
            let (ifindex, _hits) = macs_map.lookup(&k, MapFlags::ANY).ok().flatten().and_then(|v| decode_value(&v))?;
            Some((mac, ifindex))
        })
        .collect();

    let (add_ips, rm_ips) = state::diff(&desired.ips, &current_ips);
    let (add_macs, rm_macs) = state::diff(&desired.macs, &current_macs);

    for (ip, ifindex) in &add_ips {
        ips_map.update(&ip.to_be_bytes(), &encode_value(*ifindex, 0), MapFlags::ANY)?;
    }
    for ip in &rm_ips {
        let _ = ips_map.delete(&ip.to_be_bytes()); // already gone is not an error (race with a parallel sweep)
    }
    for (mac, ifindex) in &add_macs {
        macs_map.update(&mac.to_ne_bytes(), &encode_value(*ifindex, 0), MapFlags::ANY)?;
    }
    for mac in &rm_macs {
        let _ = macs_map.delete(&mac.to_ne_bytes());
    }

    Ok((add_ips.len() + add_macs.len(), rm_ips.len() + rm_macs.len()))
}

/// Load, attach to the LAN and WAN ifaces, and reconcile forever. Fail-open: any error here is
/// returned to the caller BEFORE anything is attached/pinned that would need cleanup, or (if it
/// happens mid-loop) simply ends the process — no destructive teardown of an already-attached
/// hook, since a partially-enforcing quarantine is still strictly safer than none.
pub fn run(obj_path: &str, lan_iface: &str, wan_iface: &str, state_file: &str, pin_dir: &str, poll: Duration) -> Result<()> {
    let obj = load_and_pin(obj_path, pin_dir)?;
    let prog = find_prog(&obj, "quarantine_ingress").context("quarantine_ingress prog not found in object")?;

    let mut hooks = Vec::new();
    for iface in [lan_iface, wan_iface] {
        match attach_one(&prog, iface) {
            Ok(h) => {
                hooks.push(h);
                eprintln!("napse-quarantine: attached quarantine_ingress on {iface} (tc clsact ingress, prio {TC_PRIORITY})");
            }
            // One bad iface (down, renamed, removed) must not stop enforcement on the others —
            // log and continue; the next full loader restart (Restart=on-failure / a future
            // reconcile trigger) will retry it.
            Err(e) => eprintln!("napse-quarantine: WARN attach on {iface} failed: {e:#} — continuing with the rest"),
        }
    }
    if hooks.is_empty() {
        bail!("no interface attached — nothing enforced (fail-open: process exits, nft quarantine still applies)");
    }

    let ips_map = MapHandle::from_pinned_path(pin_path(pin_dir, "ips")).context("open pinned ips map")?;
    let macs_map = MapHandle::from_pinned_path(pin_path(pin_dir, "macs")).context("open pinned macs map")?;

    // 2026-07-05 threat-model fix (HIGH #3): resolve each plane's ifindex ONCE — every reconcile
    // cycle binds entries to these, so a LAN-plane entry can never fire on the WAN ifindex or vice
    // versa. `unwrap_or(0)` is a safe fallback (ifindex 0 never matches a real interface — the
    // kernel starts numbering at 1, `lo`), not a silent wildcard: if an iface can't be resolved,
    // entries for its plane simply never match anything, which is fail-CLOSED-toward-no-drop, the
    // correct direction for a fail-open datapath.
    let ifindexes = PlaneIfindexes {
        lan: sysfs_ifindex(lan_iface).unwrap_or(0),
        wan: sysfs_ifindex(wan_iface).unwrap_or(0),
    };
    eprintln!(
        "napse-quarantine: plane ifindexes — LAN {lan_iface}={} WAN {wan_iface}={} (entries scoped per-plane)",
        ifindexes.lan, ifindexes.wan
    );

    eprintln!("napse-quarantine: reconciling {state_file} -> BPF maps every {poll:?}");
    loop {
        match reconcile_once(&ips_map, &macs_map, state_file, ifindexes) {
            Ok((added, removed)) if added > 0 || removed > 0 => {
                eprintln!("napse-quarantine: reconcile +{added} -{removed}");
            }
            Ok(_) => {}
            Err(e) => eprintln!("napse-quarantine: WARN reconcile failed this cycle: {e:#} (will retry)"),
        }
        std::thread::sleep(poll);
    }
}

/// `--status`: read the pinned maps directly (no attach, no state-file reconcile) and print a
/// JSON snapshot — the on-device substitute for `bpftool map dump` (this device ships no
/// bpftool; see the ADR 0005/Makefile honesty note about the immutable image having no
/// compiler/tooling baked in).
pub fn status(pin_dir: &str) -> Result<()> {
    let ips = MapHandle::from_pinned_path(pin_path(pin_dir, "ips")).context("open pinned ips map (is the loader running?)")?;
    let macs = MapHandle::from_pinned_path(pin_path(pin_dir, "macs")).context("open pinned macs map")?;
    let stats = MapHandle::from_pinned_path(pin_path(pin_dir, "stats")).context("open pinned stats map")?;

    let ip_entries: Vec<serde_json::Value> = ips
        .keys()
        .filter_map(|k| {
            // raw wire-order bytes (see reconcile_once's comment) — read them straight as octets,
            // no endian conversion needed to print A.B.C.D.
            let octets: [u8; 4] = k.clone().try_into().ok()?;
            let (ifindex, hits) =
                ips.lookup(&k, MapFlags::ANY).ok().flatten().and_then(|v| decode_value(&v)).unwrap_or((0, 0));
            Some(serde_json::json!({
                "ip": format!("{}.{}.{}.{}", octets[0], octets[1], octets[2], octets[3]),
                "ifindex": ifindex,
                "hits": hits,
            }))
        })
        .collect();

    let mac_entries: Vec<serde_json::Value> = macs
        .keys()
        .filter_map(|k| {
            let packed = u64::from_ne_bytes(k.clone().try_into().ok()?);
            let (ifindex, hits) =
                macs.lookup(&k, MapFlags::ANY).ok().flatten().and_then(|v| decode_value(&v)).unwrap_or((0, 0));
            let b = packed.to_be_bytes(); // low 48 bits of the be repr are the 6 mac bytes
            Some(serde_json::json!({
                "mac": format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", b[2], b[3], b[4], b[5], b[6], b[7]),
                "ifindex": ifindex,
                "hits": hits,
            }))
        })
        .collect();

    let pass = stats.lookup(&0u32.to_ne_bytes(), MapFlags::ANY)?.map(|v| u64::from_ne_bytes(v.try_into().unwrap())).unwrap_or(0);
    let drop = stats.lookup(&1u32.to_ne_bytes(), MapFlags::ANY)?.map(|v| u64::from_ne_bytes(v.try_into().unwrap())).unwrap_or(0);

    println!(
        "{}",
        serde_json::json!({
            "quarantined_ips": ip_entries,
            "quarantined_macs": mac_entries,
            "stats": { "pass": pass, "drop": drop },
        })
    );
    Ok(())
}
