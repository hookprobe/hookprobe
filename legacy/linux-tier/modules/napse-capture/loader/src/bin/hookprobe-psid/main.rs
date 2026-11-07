//! hookprobe-psid — the shed-v2 PSI pressure watcher (base-tier-build-ticket.md Phase 2, ADR
//! 0031 amendment §E / ADR 0023 D3). Runs in `hookprobe-background.slice` under a hard
//! `CPUQuota` (see `base/units/hookprobe-psid.service`) — this daemon is deliberately tiny: it
//! never touches a packet, only a scalar control map.
//!
//! WHAT this does: registers Linux psi-monitor trigger FDs on `/proc/pressure/{cpu,memory}`
//! (best-effort — silently falls back to plain timeout-driven polling if the kernel/permissions
//! don't allow it, see `open_trigger` below), blocks in `poll(2)`, and on every wake (a real
//! threshold-cross OR the fallback timeout) re-reads both pressure files, computes the escalation
//! tier (`napse_loader::shed::raw_tier_for`), applies 5s step-down hysteresis
//! (`napse_loader::shed::TierHysteresis`), and writes `tier` / `r_base_pps` / `heartbeat_ns` into
//! the pinned `shed_ctrl` BPF_MAP_TYPE_ARRAY at `/sys/fs/bpf/hookprobe/shed_ctrl` — the scalar
//! bridge `napse_detect.bpf.c`'s fast-loop token bucket reads every packet (PSI cannot be read
//! from eBPF directly).
//!
//! WITHOUT the `bpf` feature (the default / this dev box) the tier/rate/heartbeat are only
//! logged, never written — same "PLAN-ONLY dry run" convention `napse-loader`'s `main.rs`
//! documents for its own `bpf` feature gate.
//!
//! GATE: reads the signed manifest once at startup; if `resource_shed_v2` is not `granted` on
//! this device, logs why and exits 0 immediately (mirrors `dataplane-tune-apply.sh`'s own
//! `tc_bpf`-gate-then-exit-0 convention) — there is nothing to drive shed-v2 on hardware that
//! doesn't have the PSI+pinned-map path.

#[cfg(feature = "bpf")]
mod shed_ctrl_map;

use hookprobe_manifest::types::{CapabilityState, Manifest};
use napse_loader::shed::{parse_pressure, psi_trigger_string, raw_tier_for, rate_pps_for_tier, ShedTierThresholds, TierHysteresis};
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn env_or(k: &str, d: &str) -> String {
    std::env::var(k).unwrap_or_else(|_| d.to_string())
}

fn env_or_u64(k: &str, d: u64) -> u64 {
    std::env::var(k).ok().and_then(|s| s.parse().ok()).unwrap_or(d)
}

/// `CLOCK_MONOTONIC` nanoseconds — the SAME clock source `bpf_ktime_get_ns()` reads (both `psid`
/// and the kernel program must agree on one monotonic clock, or the `heartbeat_ns`
/// staleness/fail-open check in `shed_ctrl_read()` would be comparing incompatible epochs).
fn monotonic_ns() -> u64 {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    // SAFETY: `ts` is a valid, fully-initialised out-param; CLOCK_MONOTONIC is always supported.
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    (ts.tv_sec as u64).saturating_mul(1_000_000_000).saturating_add(ts.tv_nsec as u64)
}

fn wall_secs() -> f64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0)
}

/// Best-effort: open one Linux psi-monitor trigger FD (`/proc/pressure/{cpu,memory}`'s
/// write-then-`poll(POLLPRI)` protocol). Returns `None` (never panics/propagates) on ANY
/// failure — insufficient privilege, an older kernel without `CONFIG_PSI`, or a malformed
/// trigger string are all equally "this wake source isn't available", and the caller's
/// fixed-interval `poll()` timeout is the fallback that keeps the whole mechanism correct (if
/// slower to react) regardless.
fn open_trigger(path: &str, kind: &str, pct: f64, window_us: u64) -> Option<File> {
    let trigger = psi_trigger_string(kind, pct, window_us);
    let mut f = std::fs::OpenOptions::new().read(true).write(true).open(path).ok()?;
    // The kernel requires the ENTIRE trigger string in a single write(2) — write_all here is
    // still exactly one underlying write() call for a buffer this small (no partial-write
    // splitting risk in practice, but even if the kernel ever rejected a partial write it would
    // just make this open() attempt fail, handled the same as every other failure above).
    f.write_all(trigger.as_bytes()).ok()?;
    Some(f)
}

fn read_to_string_or_empty(path: &str) -> String {
    let mut s = String::new();
    if let Ok(mut f) = File::open(path) {
        let _ = f.read_to_string(&mut s);
    }
    s
}

fn main() {
    let manifest_path = env_or("MANIFEST", "/var/lib/hookprobe/manifest.json");
    let shed_ctrl_pin = env_or("SHED_CTRL_PIN", "/sys/fs/bpf/hookprobe/shed_ctrl");
    let cpu_pressure_path = env_or("CPU_PRESSURE_PATH", "/proc/pressure/cpu");
    let mem_pressure_path = env_or("MEM_PRESSURE_PATH", "/proc/pressure/memory");
    let poll_timeout_ms = env_or_u64("SHED_POLL_TIMEOUT_MS", 1000);
    const WINDOW_US: u64 = 1_000_000; // 1s psi-monitor window (matches the avg60-keyed tier design)

    // ---- gate: resource_shed_v2 granted? (mirrors dataplane-tune-apply.sh's tc_bpf gate) ----
    match std::fs::read_to_string(&manifest_path).ok().and_then(|raw| serde_json::from_str::<Manifest>(&raw).ok()) {
        Some(m) => match m.capabilities.get("resource_shed_v2").map(|c| c.state.clone()) {
            Some(CapabilityState::Granted) => {}
            other => {
                eprintln!(
                    "hookprobe-psid: resource_shed_v2 not granted on this device ({other:?}) — \
                     nothing to drive, exiting 0"
                );
                return;
            }
        },
        None => {
            eprintln!("hookprobe-psid: no manifest at {manifest_path} yet — exiting 0 (fail-open, retried by systemd)");
            return;
        }
    }

    let cfg = ShedTierThresholds::default();

    // Best-effort event-driven wake: one trigger FD per (resource, tier) pair. A tier's
    // threshold below it is implied by the NEXT rung's trigger firing; the actual tier VALUE
    // written to shed_ctrl always comes from re-reading + re-computing against the full PSI
    // text on every wake (raw_tier_for), never from "which fd fired" — the trigger FDs exist
    // purely to wake this process promptly, not to carry the decision themselves.
    let mut trigger_fds: Vec<File> = Vec::new();
    for (cpu_pct, mem_pct, _rate) in cfg.tiers.iter() {
        if let Some(f) = open_trigger(&cpu_pressure_path, "some", *cpu_pct, WINDOW_US) {
            trigger_fds.push(f);
        }
        if let Some(f) = open_trigger(&mem_pressure_path, "full", *mem_pct, WINDOW_US) {
            trigger_fds.push(f);
        }
    }
    if trigger_fds.is_empty() {
        eprintln!(
            "hookprobe-psid: could not register any PSI trigger FD (permission/kernel) — \
             falling back to plain {poll_timeout_ms}ms timeout-driven polling (still meets the \
             ~1s reaction gate, just always via the timeout path rather than an instant wake)"
        );
    } else {
        eprintln!("hookprobe-psid: registered {} PSI trigger FD(s)", trigger_fds.len());
    }

    let mut pollfds: Vec<libc::pollfd> =
        trigger_fds.iter().map(|f| libc::pollfd { fd: f.as_raw_fd(), events: libc::POLLPRI, revents: 0 }).collect();

    #[cfg(feature = "bpf")]
    let shed_map = shed_ctrl_map::open(&shed_ctrl_pin);
    #[cfg(not(feature = "bpf"))]
    eprintln!(
        "hookprobe-psid: built WITHOUT the `bpf` feature — tier/rate/heartbeat are LOGGED only, \
         never written to {shed_ctrl_pin}. Rebuild `--features bpf` in CI to drive the real map."
    );

    hookprobe_manifest::sd_notify::notify_ready();
    let mut watchdog = hookprobe_manifest::sd_notify::WatchdogPinger::new(Duration::from_secs(20));
    let mut hysteresis = TierHysteresis::default();
    let mut last_logged_tier: Option<u8> = None;

    eprintln!(
        "hookprobe-psid: watching {cpu_pressure_path}/{mem_pressure_path} → {shed_ctrl_pin} \
         (poll timeout {poll_timeout_ms}ms, step-down hysteresis 5s)"
    );

    loop {
        // Reset revents before each poll — libc::poll only WRITES it, but a stale value from a
        // previous iteration must never be misread if poll() itself errors this time.
        for pfd in pollfds.iter_mut() {
            pfd.revents = 0;
        }
        // SAFETY: `pollfds` is a valid, correctly-sized slice for the duration of this call; an
        // empty slice (no trigger FDs registered) is explicitly valid per poll(2) — it simply
        // blocks for exactly `timeout` (the fixed-interval fallback path).
        let rc = unsafe { libc::poll(pollfds.as_mut_ptr(), pollfds.len() as libc::nfds_t, poll_timeout_ms as libc::c_int) };
        if rc < 0 {
            // EINTR (a signal) is routine and not an error worth logging every time; anything
            // else, log once per occurrence and keep going — this daemon must never exit on a
            // transient poll() error (fail-open: a dead psid means shed_ctrl goes stale and the
            // BPF side already fails open on that within 30s regardless).
            let errno = std::io::Error::last_os_error();
            if errno.raw_os_error() != Some(libc::EINTR) {
                eprintln!("hookprobe-psid: poll() error: {errno} — continuing");
            }
        }

        // Re-derive the tier from the FULL current PSI text on EVERY wake (event or timeout) —
        // never from which trigger fd fired. This is also what keeps `heartbeat_ns` fresh even
        // during a long stretch with no threshold crossings at all.
        let cpu_text = read_to_string_or_empty(&cpu_pressure_path);
        let mem_text = read_to_string_or_empty(&mem_pressure_path);
        let (cpu, mem) = parse_pressure(&cpu_text, &mem_text);
        let raw = raw_tier_for(&cpu, &mem, &cfg);
        let now_ns = monotonic_ns();
        let tier = hysteresis.step(raw, now_ns);
        let rate_pps = rate_pps_for_tier(tier, &cfg);

        if last_logged_tier != Some(tier) {
            eprintln!(
                "hookprobe-psid: tier {} -> {tier} (raw={raw}, r_base_pps={rate_pps}) at {}",
                last_logged_tier.map(|t| t.to_string()).unwrap_or_else(|| "init".to_string()),
                wall_secs()
            );
            last_logged_tier = Some(tier);
        }

        #[cfg(feature = "bpf")]
        if let Some(map) = shed_map.as_ref() {
            shed_ctrl_map::write(map, tier, rate_pps, now_ns);
        }

        watchdog.tick();
    }
}
