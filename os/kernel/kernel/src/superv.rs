// SPDX-License-Identifier: AGPL-3.0-only
//! Autoheal harness H1: the kernel's one recovery journal (`hal::superv`), fed by every EL0 server fault/restart and
//! every Wi-Fi self-heal rung, served as `GET /api/recoveries`.
//!
//! RAM only in this step (the ring survives nothing): persistence across a reboot is the follow-up — the reboot rung's
//! own evidence already survives in the Wi-Fi recovery record (`wifiheal::boot_record`), which the boot replays here.

use hal::superv::{component_id, Journal, Kind, Outcome, Rung};

static mut JOURNAL: Journal = Journal::new();

fn j() -> &'static mut Journal {
    // single-writer: the main loop and the boot path (no SMP access to the journal)
    unsafe { &mut *core::ptr::addr_of_mut!(JOURNAL) }
}

/// Read-only view for the API.
pub fn journal() -> &'static Journal {
    unsafe { &*core::ptr::addr_of!(JOURNAL) }
}

/// Swap the journal out (self-tests run against an empty one and put the real one back).
pub fn swap(with: Journal) -> Journal {
    unsafe { MAYBE_OPEN = 0xff }; // re-derived lazily: a stale bit only costs one ring scan
    core::mem::replace(j(), with)
}

pub fn now_ms() -> u64 {
    crate::clock::ticks() / (crate::clock::freq() / 1000).max(1)
}

/// Components with a possibly-open entry (a fast path: `server_ok` runs on every good call of the hot servers).
static mut MAYBE_OPEN: u8 = 0;

fn mark(c: u8) {
    unsafe { MAYBE_OPEN |= 1 << c };
}

/// Set while a self-test faults a server ON PURPOSE (some run at every boot, on metal too): those faults are
/// journaled as `planned`, so an `exception` in the journal is always a real one.
static mut DELIBERATE: u8 = 0; // 0 = no, 1 = deliberate (not counted by the restart policy), 2 = a policy drill (counted)

/// Run `f`, journaling any server fault inside it as `planned` (a self-test's deliberate fault) and keeping it out
/// of the restart policy: a boot self-test must not leave the server with a fault streak.
pub fn deliberate<T>(f: impl FnOnce() -> T) -> T {
    scoped(1, f)
}

/// Like [`deliberate`], but the fault COUNTS for the restart policy (a self-test of the hold-off itself).
pub fn drill<T>(f: impl FnOnce() -> T) -> T {
    scoped(2, f)
}

fn scoped<T>(mode: u8, f: impl FnOnce() -> T) -> T {
    let was = unsafe { core::mem::replace(&mut *core::ptr::addr_of_mut!(DELIBERATE), mode) };
    let r = f();
    unsafe { DELIBERATE = was };
    r
}

/// Does a fault right now count for the restart policy (the streak / hold-off)? Not inside [`deliberate`].
pub fn fault_counts() -> bool {
    unsafe { DELIBERATE != 1 }
}

/// An EL0 server faulted (`budget` = it overran its time budget) and is being reset + restarted.
pub fn server_fault(name: &str, budget: bool) -> u32 {
    let c = component_id(name);
    mark(c);
    let kind = if unsafe { DELIBERATE } != 0 {
        Kind::Planned
    } else if budget {
        Kind::Budget
    } else {
        Kind::Exception
    };
    j().open(c, kind, Rung::Restart, now_ms())
}

// --- H5: the per-component CPU budget per window ---
static mut CPU: [hal::superv::CpuWindow; 8] = [hal::superv::CpuWindow::new(); 8];
/// Components whose throttle entry is open in the journal.
static mut THROTTLED: u8 = 0;

fn cpu(c: u8) -> &'static mut hal::superv::CpuWindow {
    unsafe { &mut (*core::ptr::addr_of_mut!(CPU))[(c & 7) as usize] }
}

/// May component `c` (a `hal::superv::C_*` id) run a call now? False = its CPU budget for this window is used up:
/// the caller refuses the call like a fault (fail closed). The first refusal of an episode is journaled (kind
/// budget-overrun, rung throttle); the first call admitted afterwards closes it.
pub fn cpu_admit(c: u8) -> bool {
    cpu_admit_at(c, now_ms())
}

pub fn cpu_admit_at(c: u8, now: u64) -> bool {
    // enforced on metal only: QEMU's emulated CPU time is not the device's (a TLS handshake under TCG would trip a
    // budget sized for the A76) — there every component is measured, none refused
    #[cfg(feature = "cm5")]
    let budget = hal::superv::cpu_budget_ms(c);
    #[cfg(not(feature = "cm5"))]
    let budget = 0;
    cpu_admit_with(c, now, budget)
}

fn cpu_admit_with(c: u8, now: u64, budget: u32) -> bool {
    let (ok, first) = cpu(c).admit(now, budget);
    let bit = 1u8 << (c & 7);
    if ok {
        if unsafe { THROTTLED } & bit != 0 {
            unsafe { THROTTLED &= !bit };
            let _ = j().close(c, Outcome::Recovered, now);
        }
    } else if first && unsafe { THROTTLED } & bit == 0 {
        unsafe { THROTTLED |= bit };
        j().open(c, Kind::Budget, Rung::Throttle, now);
        arch_aarch64::_print(format_args!(" [SUPERV] {} used its CPU budget ({} ms per {} ms window): calls refused until the next window (journaled, rung throttle)\n",
            hal::superv::component_name(c), budget, hal::superv::CPU_WINDOW_MS));
    }
    ok
}

/// A call of component `c` that started at `t0_ticks` just returned: charge its duration.
pub fn cpu_charge(c: u8, t0_ticks: u64) {
    let us = crate::clock::ticks().saturating_sub(t0_ticks) / (crate::clock::freq() / 1_000_000).max(1);
    cpu(c).charge(us);
}

/// H4a: a server answered a functional probe WRONGLY (no fault): it is being reset like a fault.
pub fn server_probe_failed(name: &str) -> u32 {
    let c = component_id(name);
    mark(c);
    let kind = if unsafe { DELIBERATE } != 0 { Kind::Planned } else { Kind::Probe };
    j().open(c, kind, Rung::Restart, now_ms())
}

static mut PROBES: hal::superv::ProbeClock = hal::superv::ProbeClock::new();
/// (probes run, probes failed) since boot.
static mut PROBE_STATS: (u64, u64) = (0, 0);
pub fn probe_stats() -> (u64, u64) {
    unsafe { PROBE_STATS }
}

/// H4a: one functional probe when due (the main loop calls this every iteration; it costs one comparison until then,
/// and at most one bounded EL0 excursion per `PROBE_PERIOD_MS`).
pub fn probe_tick(now_ms: u64) {
    // two slots in turn (each server is asked once per two periods): el0-lansvc, el0-tlshost
    let Some(slot) = (unsafe { (*core::ptr::addr_of_mut!(PROBES)).due(now_ms, 2) }) else { return };
    let (name, r) = match slot {
        0 => ("el0-lansvc", crate::lansvc::probe(false)),
        #[cfg(feature = "mctls")]
        _ => ("el0-tlshost", crate::tlshost::probe(false)),
        #[cfg(not(feature = "mctls"))]
        _ => ("el0-tlshost", None),
    };
    if let Some(ok) = r {
        unsafe {
            PROBE_STATS.0 += 1;
            if !ok {
                PROBE_STATS.1 += 1;
            }
        }
        if !ok {
            arch_aarch64::_print(format_args!(" [SUPERV] functional probe FAILED: {} answered wrongly without faulting — reset (journaled, kind probe)\n", name));
        }
    }
}

/// An EL0 server's initialisation failed or was refused.
pub fn server_init_refused(name: &str) -> u32 {
    let c = component_id(name);
    mark(c);
    j().open(c, Kind::InitRefused, Rung::Restart, now_ms())
}

/// An EL0 server answered a call: closes its open entry, if any (one bit test when none is open).
pub fn server_ok(name: &str) {
    let c = component_id(name);
    if unsafe { MAYBE_OPEN } & (1 << c) == 0 {
        return;
    }
    unsafe { MAYBE_OPEN &= !(1 << c) };
    let _ = j().close(c, Outcome::Recovered, now_ms());
}

/// One Wi-Fi self-heal tick: `act` = the `wifiheal::Action` code taken (0 = none), `healthy` = the classifier sees
/// a healthy link. A rung opens (or escalates) the Wi-Fi entry; a healthy tick closes it; degrade closes it Failed.
pub fn wifi_heal(act: u8, healthy: bool, t_ms: u64) {
    let c = component_id("wifi");
    let rung = match act {
        1 => Some(Rung::Kick),
        2 => Some(Rung::Bounce),
        3 => Some(Rung::Reload),
        4 => Some(Rung::Reboot),
        5 => Some(Rung::Degrade),
        _ => None,
    };
    let jj = j();
    match rung {
        Some(Rung::Degrade) => {
            jj.open(c, Kind::Probe, Rung::Degrade, t_ms);
            let _ = jj.close(c, Outcome::Failed, t_ms);
        }
        Some(r) => {
            jj.open(c, Kind::Probe, r, t_ms);
            // the port runs a bounce / reload synchronously inside the ladder step: `now` is when it returned
            if matches!(r, Rung::Bounce | Rung::Reload) {
                jj.acted(c, now_ms().max(t_ms));
            }
        }
        None if healthy && jj.is_open(c) => {
            let _ = jj.close(c, Outcome::Recovered, t_ms);
        }
        None => {}
    }
}

/// Boot: the previous boot ended in the Wi-Fi reboot rung (its recovery record survived): journal it as the first
/// entry of this boot, still open — the first healthy Wi-Fi tick closes it.
pub fn boot_after_wifi_reboot() {
    j().open(component_id("wifi"), Kind::Probe, Rung::Reboot, now_ms());
}

/// `GET /api/recoveries` (H1): totals and the ring, newest first.
#[cfg(feature = "netsvc")]
pub fn render(w: &mut crate::mcstate::JsonBuf<'_>, limit: usize) {
    use core::fmt::Write;
    use hal::superv::{component_name, KIND_NAMES, OUTCOME_NAMES};
    let jj = journal();
    let _ = write!(w, "{{\"total\":{},\"pending\":{},\"dropped\":{},\"by_kind\":{{", jj.total(), jj.pending(), jj.dropped);
    for (i, k) in KIND_NAMES.iter().enumerate() {
        let _ = write!(w, "{}\"{}\":{}", if i > 0 { "," } else { "" }, k, jj.by_kind[i]);
    }
    w.raw("},\"by_outcome\":{");
    for (i, o) in OUTCOME_NAMES.iter().enumerate().skip(1) {
        let _ = write!(w, "{}\"{}\":{}", if i > 1 { "," } else { "" }, o, jj.by_outcome[i]);
    }
    // why the previous boot ended (reason + culprit; the crash record's text as the detail)
    let c = crate::rtwdog::last_crash();
    let (reason, culprit) = hal::superv::last_boot_reason(c.map(|c| c.kind), c.map_or("", |c| c.text()), crate::rtwdog::last_planned(), crate::rtwdog::prev_reset_was_watchdog());
    let _ = write!(w, "}},\"last_boot\":{{\"reason\":\"{}\",\"culprit\":", reason);
    match culprit {
        Some(n) => {
            let _ = write!(w, "\"{}\"", n);
        }
        None => w.raw("null"),
    }
    w.raw(",\"detail\":");
    match c {
        Some(c) => w.string(c.text()),
        None => w.raw("null"),
    }
    // H2: the supervisor table (fixed in the signed image) — who may escalate to a reboot, and each restart policy
    w.raw("},\"supervised\":[");
    for (i, e) in hal::superv::TABLE.iter().enumerate() {
        let _ = write!(w, "{}{{\"component\":\"{}\",\"critical\":{},\"exhausted\":\"{}\",\"grace\":{},\"backoff_ms\":{},\"backoff_max_ms\":{}}}",
            if i > 0 { "," } else { "" }, e.name, e.critical, e.exhausted.name(), e.grace, e.backoff_ms, e.backoff_max_ms);
    }
    // H5: CPU use per component per window (us); budget 0 = measured only
    w.raw("],\"cpu\":[");
    for (i, e) in hal::superv::TABLE.iter().filter(|e| e.name != "wifi").enumerate() {
        let c = cpu(component_id(e.name));
        let _ = write!(w, "{}{{\"component\":\"{}\",\"window_ms\":{},\"budget_ms\":{},\"last_us\":{},\"peak_us\":{},\"throttled_windows\":{},\"refused_calls\":{}}}",
            if i > 0 { "," } else { "" }, e.name, hal::superv::CPU_WINDOW_MS, e.cpu_ms_per_window, c.last_us, c.peak_us, c.throttled_windows, c.refused_calls);
    }
    let (pr, pf) = probe_stats();
    let _ = write!(w, "],\"probes\":{{\"period_ms\":{},\"run\":{},\"failed\":{}}},\"now_ms\":{},\"recoveries\":[", hal::superv::PROBE_PERIOD_MS, pr, pf, now_ms());
    for (i, r) in jj.newest_first().take(limit).enumerate() {
        let _ = write!(w, "{}{{\"seq\":{},\"component\":\"{}\",\"kind\":\"{}\",\"rung\":\"{}\",\"outcome\":\"{}\",\"repeats\":{},\"t_detect_ms\":{},",
            if i > 0 { "," } else { "" }, r.seq, component_name(r.component), r.kind.name(), r.rung.name(), r.outcome.name(), r.repeats, r.t_detect_ms);
        match r.action_ms() {
            Some(a) => {
                let _ = write!(w, "\"action_ms\":{},", a);
            }
            None => w.raw("\"action_ms\":null,"),
        }
        match r.duration_ms() {
            Some(d) => {
                let _ = write!(w, "\"t_done_ms\":{},\"duration_ms\":{}}}", r.t_done_ms, d);
            }
            None => w.raw("\"t_done_ms\":null,\"duration_ms\":null}"),
        }
    }
    w.raw("]}");
}

/// Brackets and braces balance outside string literals, and the document is one object.
#[cfg(feature = "netsvc")]
fn json_balanced(b: &[u8]) -> bool {
    let (mut depth, mut in_str, mut esc, mut closed) = (0i32, false, false, false);
    let mut stack = [0u8; 16];
    for &c in b {
        if closed {
            return false; // bytes after the document
        }
        if in_str {
            if esc {
                esc = false;
            } else if c == b'\\' {
                esc = true;
            } else if c == b'"' {
                in_str = false;
            }
            continue;
        }
        match c {
            b'"' => in_str = true,
            b'{' | b'[' => {
                if depth as usize >= stack.len() {
                    return false;
                }
                stack[depth as usize] = c;
                depth += 1;
            }
            b'}' | b']' => {
                depth -= 1;
                if depth < 0 || stack[depth as usize] != if c == b'}' { b'{' } else { b'[' } {
                    return false;
                }
                closed = depth == 0;
            }
            _ => {}
        }
    }
    closed && !in_str
}

/// [P-superv] (QEMU): the journal is fed by the real paths — a Wi-Fi ladder kick → bounce → healthy yields one
/// escalated + one recovered entry; a degrade closes Failed; a server fault then a good call yields exactly one
/// recovered entry with the right kind. Leaves the journal as it found it.
pub fn selftest() -> bool {
    let saved = core::mem::replace(j(), Journal::new());
    wifi_heal(1, false, 1_000);
    wifi_heal(1, false, 1_100); // same rung: folded
    wifi_heal(2, false, 1_500); // escalates the kick
    wifi_heal(0, false, 1_600); // still unhealthy: stays open
    wifi_heal(0, true, 2_300); // healthy: recovered
    let jj = journal();
    let k = jj.get(1).copied();
    let b = jj.get(2).copied();
    let ladder = jj.total() == 2
        && k.is_some_and(|r| r.rung == Rung::Kick && r.outcome == Outcome::Escalated && r.repeats == 1 && r.duration_ms() == Some(500))
        && b.is_some_and(|r| r.rung == Rung::Bounce && r.outcome == Outcome::Recovered && r.duration_ms() == Some(800));
    wifi_heal(5, false, 3_000);
    let degrade = journal().get(3).is_some_and(|r| r.rung == Rung::Degrade && r.outcome == Outcome::Failed) && journal().pending() == 0;
    // a self-test's deliberate fault is journaled as planned, never as an exception
    let d = deliberate(|| server_fault("el0-hsh", false));
    server_ok("el0-hsh");
    let planned = journal().get(d).is_some_and(|r| r.kind == Kind::Planned && r.outcome == Outcome::Recovered) && journal().by_kind[Kind::Exception as usize] == 0;
    let s = server_fault("el0-tlshost", true);
    let again = server_fault("el0-tlshost", false) == s;
    server_ok("el0-tlshost");
    server_ok("el0-tlshost");
    let jj = journal();
    let fault = planned && jj.total() == 5
        && jj.get(s).is_some_and(|r| r.kind == Kind::Budget && r.outcome == Outcome::Recovered && r.repeats == 1)
        && jj.by_kind[Kind::Budget as usize] == 1
        && jj.by_outcome[Outcome::Recovered as usize] == 3;
    let unknown = component_id("no-such-server") == component_id("other");
    // H2: the table policy — only the Wi-Fi link is critical; a server that faults on every call is held off (capped)
    let t = hal::superv::entry("el0-tlshost");
    let table = hal::superv::TABLE.iter().filter(|e| e.critical).count() == 1
        && hal::superv::entry("wifi").is_some_and(|e| e.critical && e.exhausted == hal::superv::Exhausted::RebootOnce)
        && hal::superv::TABLE.iter().all(|e| e.critical || e.exhausted != hal::superv::Exhausted::RebootOnce);
    let policy = t.is_some_and(|e| {
        let mut s = hal::superv::Sup::new(e);
        let one_off = s.fault(1_000) == 0 && s.ready(1_000);
        let held = s.fault(1_000) == 50 && !s.ready(1_049) && s.ready(1_050);
        let mut n = 0u32;
        let mut now = 2_000u64;
        while now < 62_000 {
            if s.ready(now) {
                s.fault(now);
                n += 1;
            }
            now += 10;
        }
        one_off && held && n < 25 && s.ok() && s.fault(80_000) == 0
    });
    // the API document, rendered from the journal the test just filled: well-formed (brackets balance outside strings)
    #[cfg(feature = "netsvc")]
    let doc = {
        static mut DOC: [u8; 8192] = [0; 8192];
        let mut w = crate::mcstate::JsonBuf::new(unsafe { &mut *core::ptr::addr_of_mut!(DOC) });
        render(&mut w, 64);
        json_balanced(w.bytes()) && !w.overflow && w.bytes().ends_with(b"]}")
    };
    #[cfg(not(feature = "netsvc"))]
    let doc = true;
    *j() = saved;
    // H5: the CPU budget on the kernel's own path (el0-neuro's slot: no server uses it in this boot; fake clock)
    let cpu_ok = {
        let saved_j = core::mem::replace(j(), Journal::new());
        let c = hal::superv::C_NEURO;
        let saved_w = core::mem::replace(cpu(c), hal::superv::CpuWindow::new());
        let t = 10_000_000u64;
        let a1 = cpu_admit_with(c, t, 200);
        cpu(c).charge(250_000); // 250 ms against a 200 ms budget
        let refused = !cpu_admit_with(c, t + 300, 200) && !cpu_admit_with(c, t + 900, 200);
        let jr = journal().total() == 1 && journal().get(1).is_some_and(|r| r.kind == Kind::Budget && r.rung == Rung::Throttle && r.outcome == Outcome::Pending);
        let again = cpu_admit_with(c, t + 1_000, 200);
        let closed = journal().get(1).is_some_and(|r| r.outcome == Outcome::Recovered && r.duration_ms() == Some(700));
        let counted = cpu(c).throttled_windows == 1 && cpu(c).refused_calls == 2 && cpu(c).last_us == 250_000;
        // an unlimited component (the data-path server) is measured and never refused
        let w0 = core::mem::replace(cpu(hal::superv::C_WIFI_SRV), hal::superv::CpuWindow::new());
        cpu(hal::superv::C_WIFI_SRV).charge(5_000_000);
        let unlimited = cpu_admit_with(hal::superv::C_WIFI_SRV, t, hal::superv::cpu_budget_ms(hal::superv::C_WIFI_SRV)) && journal().total() == 1;
        *cpu(hal::superv::C_WIFI_SRV) = w0;
        *cpu(c) = saved_w;
        *j() = saved_j;
        a1 && refused && jr && again && closed && counted && unlimited
    };
    let plan_rec = arch_aarch64::crashrec::planned_selftest();
    let ok = ladder && degrade && again && fault && unknown && table && policy && doc && plan_rec && cpu_ok;
    arch_aarch64::_print(format_args!(
        " [P-superv] {} — autoheal harness H1, the recovery journal: Wi-Fi kick (repeat folded) -> bounce escalates it, a healthy tick closes the bounce Recovered with its time={} a degrade closes Failed={} an EL0 server fault opens one entry (budget-overrun), a second fault folds into it={} the next good call closes it Recovered, exactly one entry={} unknown components map to other={} | H2 supervisor table: only the Wi-Fi link is critical, no other entry may reboot={} a one-off server fault restarts at once, consecutive faults are held off (50 ms doubling, capped 5 s: < 25 restarts in 60 s of constant faulting), a fault-free stable period resets it (H3b: a good call alone does not — flapping is held off too)={} /api/recoveries renders well-formed={} H3a: the planned-reset reason is taken once, a torn / stale record never reads back={} H5: a component over its CPU budget is refused for the rest of the window (journaled budget-overrun / throttle), admitted in the next (entry closed), the data-path server is never refused={}\n",
        if ok { "PASS" } else { "FAIL" }, ladder, degrade, again, fault, unknown, table, policy, doc, plan_rec, cpu_ok
    ));
    ok
}
