//! libbpf glue — compiled ONLY with `--features bpf` (needs libbpf + the CO-RE `napse_detect.bpf.o`).
//! Loads the object once, attaches `napse_xdp` or `napse_tc` per target, programs the
//! `role_by_ifindex` + `napse_cfg` maps, pins the block/allow lists, and drains the `events` ringbuf
//! into the NAPSE flow stream via [`napse_loader::event::NapseEvent`]. libbpf-rs 0.24 API (pinned by
//! compiling against a real kernel): object access is iterator-based (`maps()`/`progs()` + `name()`).

use anyhow::{bail, Context, Result};
use libbpf_rs::{MapCore, MapFlags, Object, ObjectBuilder, RingBufferBuilder, TcHookBuilder, TC_EGRESS, TC_INGRESS};
use napse_loader::event::NapseEvent;
use napse_loader::plan::{AttachKind, AttachTarget};
use std::ffi::OsStr;
use std::fs::OpenOptions;
use std::io::Write;
use std::os::fd::AsFd;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const CFG_MODE_KEY: u32 = 0;
const MODE_MONITOR: u64 = 0; // fail-open default; MODE_ENFORCE=1 flips inline drop on

fn wall_secs() -> f64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0)
}

fn find_map<'o>(obj: &'o Object, name: &str) -> Option<libbpf_rs::Map<'o>> {
    obj.maps().find(|m| m.name() == OsStr::new(name))
}
// progs_mut() takes &self (immutable) but yields ProgramMut, which has attach_xdp + as_fd.
fn find_prog<'o>(obj: &'o Object, name: &str) -> Option<libbpf_rs::ProgramMut<'o>> {
    obj.progs_mut().find(|p| p.name() == OsStr::new(name))
}

/// Attach the detection engine per plan + drain events into `flows` forever.
pub fn run(obj_path: &str, targets: &[AttachTarget], flows: &str) -> Result<()> {
    let mut builder = ObjectBuilder::default();
    // CO-RE BTF source (ADR 0029/0030): napse_detect.bpf.c is CO-RE (vmlinux.h + ct_lookup kfuncs
    // that REQUIRE BTF). Native BTF on Debian/UEFI kernels ⇒ no-op; the RPi BSP kernels lack
    // CONFIG_DEBUG_INFO_BTF ⇒ point libbpf at the shipped /usr/lib/hookprobe/btf/vmlinux-$(uname
    // -r).btf blob, else fail here honestly. `_btf_guard` OWNS the path CString libbpf reads during
    // open_file — keep it alive across open/load (do not drop early).
    let _btf_guard = hookprobe_manifest::xdp::apply_btf_custom_path(&mut builder)
        .map_err(anyhow::Error::msg)
        .context("resolve CO-RE BTF for napse_detect")?;
    let mut obj = builder
        .open_file(obj_path)
        .with_context(|| format!("open {obj_path}"))?
        .load()
        .context("load napse_detect object (verifier)")?;

    // config: start in MONITOR (fail-open). Map is `napse_cfg` (`config` collides with a vmlinux typedef).
    find_map(&obj, "napse_cfg")
        .context("napse_cfg map")?
        .update(&CFG_MODE_KEY.to_ne_bytes(), &MODE_MONITOR.to_ne_bytes(), MapFlags::ANY)?;

    // Pin the block/allow lists so hydra-feedsync (a separate process) can update them. Each load()
    // makes FRESH maps; an orphaned pin from a prior instance would make pin() fail EEXIST and leave
    // hydra-feedsync writing to a dead map — so unpin first.
    std::fs::create_dir_all("/sys/fs/bpf/napse").ok();
    for m in ["blocklist", "allowlist"] {
        let path = format!("/sys/fs/bpf/napse/{m}");
        let _ = std::fs::remove_file(&path);
        // pin() needs a mutable Map view; maps_mut() borrows obj mutably — do it here, scoped, before
        // we take the (immutable) prog/map views below.
        match obj.maps_mut().find(|x| x.name() == OsStr::new(m)) {
            Some(mut map) => map.pin(&path).with_context(|| format!("pin {m}"))?,
            None => eprintln!("napse-loader: WARN map {m} absent — hydra-feedsync will have no target"),
        }
    }
    // Pin shed_ctrl (base-tier-build-ticket.md Phase 2) under its OWN `/sys/fs/bpf/hookprobe/`
    // directory — deliberately NOT `/sys/fs/bpf/napse/` above: shed_ctrl is a host-wide
    // PSI-pressure control scalar `hookprobe-psid` (a separate reflex daemon, not a NAPSE-feed
    // consumer like hydra-feedsync) drives, so it lives in the OS-level bpffs namespace, matching
    // the exact path the psid daemon opens (see `shed_ctrl::write` in the `hookprobe-psid` bin).
    // Zero-initialise all three slots to tier 0 / rate 0 / heartbeat 0 (== immediately stale, so
    // the fast loop fails open — tier 0/bypassed — from the instant this program loads until
    // psid's first real write, never a garbage-tier window).
    std::fs::create_dir_all("/sys/fs/bpf/hookprobe").ok();
    {
        let shed_ctrl_pin = "/sys/fs/bpf/hookprobe/shed_ctrl";
        let _ = std::fs::remove_file(shed_ctrl_pin);
        match obj.maps_mut().find(|x| x.name() == OsStr::new("shed_ctrl")) {
            Some(mut map) => {
                map.pin(shed_ctrl_pin).context("pin shed_ctrl")?;
                for k in 0u32..3 {
                    let _ = map.update(&k.to_ne_bytes(), &0u64.to_ne_bytes(), MapFlags::ANY);
                }
            }
            None => eprintln!("napse-loader: WARN map shed_ctrl absent — hookprobe-psid will have no target"),
        }
    }

    // Find the programs ONCE — their fd backs the TC hooks, so they must outlive the run.
    let prog_xdp = find_prog(&obj, "napse_xdp").context("napse_xdp prog")?;
    let prog_tc = find_prog(&obj, "napse_tc").context("napse_tc prog")?;

    // Attach napse_tc at clsact ingress+egress (universal / Wi-Fi path). `.replace(true)` = idempotent.
    //
    // COEXISTENCE NOTE (added with modules/napse-quarantine, ADR 0009 Ring-0 enforcement): that
    // module's `quarantine_ingress` claims TC priority 1 / handle 1 at clsact INGRESS on purpose —
    // a quarantine hit must win outright and stop the packet before it even reaches this
    // detection/DPI-mirror program. TC priority is evaluated lowest-first at the same hook, and
    // `.replace(true)` on an IDENTICAL (ifindex, priority, handle, direction) tuple silently
    // clobbers whichever program attached first — so this program deliberately does NOT also use
    // priority 1, to guarantee the two can never collide/overwrite each other if both are ever
    // enabled on the same device. Egress is unaffected (napse-quarantine is ingress-only).
    const NAPSE_TC_PRIORITY: u32 = 10;
    let attach_tc = |t: &AttachTarget, hooks: &mut Vec<libbpf_rs::TcHook>| -> Result<()> {
        for dir in [TC_INGRESS, TC_EGRESS] {
            let mut hook = TcHookBuilder::new(prog_tc.as_fd())
                .ifindex(t.ifindex as i32)
                .replace(true)
                .handle(1)
                .priority(NAPSE_TC_PRIORITY)
                .hook(dir);
            hook.create().ok(); // clsact may already exist
            hook.attach().with_context(|| format!("attach tc {} dir={dir}", t.iface))?;
            hooks.push(hook);
        }
        Ok(())
    };

    let mut _links = Vec::new();
    let mut _hooks: Vec<libbpf_rs::TcHook> = Vec::new();
    for t in targets {
        find_map(&obj, "role_by_ifindex")
            .context("role_by_ifindex map")?
            .update(&t.ifindex.to_ne_bytes(), &[t.role], MapFlags::ANY)?;
        match t.attach {
            AttachKind::Xdp => match prog_xdp.attach_xdp(t.ifindex as i32) {
                Ok(link) => {
                    _links.push(link);
                    eprintln!("napse-loader: attached napse_xdp on {} (native)", t.iface);
                }
                Err(e) => {
                    // Native XDP failed (stale link / driver doesn't really support it) — fall back to
                    // TC-bpf so the NIC is still covered rather than wedging the loader.
                    eprintln!("napse-loader: xdp attach on {} failed ({e}); falling back to tc-bpf", t.iface);
                    attach_tc(t, &mut _hooks)?;
                }
            },
            AttachKind::Tc => {
                attach_tc(t, &mut _hooks)?;
                eprintln!("napse-loader: attached napse_tc on {} (clsact in+eg)", t.iface);
            }
            AttachKind::SoftwareOnly => {
                eprintln!("napse-loader: {} → software floor (no BPF on this kernel)", t.iface);
            }
        }
    }

    // Drain the events ringbuf → flow records. Re-stamp wall-clock (kernel ts is monotonic); one
    // atomic write_all per record (< PIPE_BUF under O_APPEND) so it never interleaves with napse-dpi.
    // Two record kinds share this ONE ringbuf, dispatched by length alone (the schema-stability
    // guard in napse_detect.h keeps them permanently distinguishable in size): 32 bytes ==
    // `napse_event` (the existing flow stream), 24 bytes == `shed_event` (SHED_V2 telemetry,
    // base-tier-build-ticket.md Phase 2) — appended to the SAME flows stream with `"type":
    // "shed_v2"` so no new consumer wiring is needed downstream.
    let events = find_map(&obj, "events").context("events map")?;
    let flows_path = flows.to_string();
    let mut rb = RingBufferBuilder::new();
    rb.add(&events, move |data: &[u8]| {
        use napse_loader::shed::ShedEvent;
        let rendered = if let Some(ev) = NapseEvent::from_bytes(data) {
            Some(ev.to_flow_json(wall_secs()))
        } else {
            ShedEvent::from_bytes(data).map(|ev| ev.to_flow_json(wall_secs()))
        };
        if let Some(line) = rendered {
            if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(&flows_path) {
                let _ = f.write_all(format!("{line}\n").as_bytes());
            }
        }
        0
    })?;
    let rb = rb.build().context("build ringbuf")?;

    if targets.is_empty() {
        bail!("no attach targets — nothing to inspect");
    }
    eprintln!("napse-loader: draining events → {flows}");
    loop {
        rb.poll(Duration::from_millis(200))?;
    }
}
