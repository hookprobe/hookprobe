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

// --- H4c: the complaint channel ---
/// Why the kernel complained about a server's reply (index into the per-component counters).
pub const WHY_NAMES: [&str; 2] = ["bad-length", "bad-status"];
/// The reply reported more output than the IO region holds (or a record of the wrong size).
pub const WHY_BAD_LENGTH: u8 = 0;
/// The reply carried a status the protocol does not define for that command.
pub const WHY_BAD_STATUS: u8 = 1;
static mut COMPLAINTS: [[u32; 2]; 8] = [[0; 2]; 8];

/// H4c: a server answered without faulting, but its reply broke the call protocol (a length past its output region,
/// a status the ABI does not define). Until now the kernel clamped such a reply and used it; now the reply is refused
/// (the caller sees ST_PANIC, fail closed), the complaint is journaled (kind complaint, rung restart) and the server is
/// reset by its caller, like a fault. Returns the journal sequence number.
pub fn server_complaint(name: &str, why: u8) -> u32 {
    let c = component_id(name);
    mark(c);
    unsafe { (*core::ptr::addr_of_mut!(COMPLAINTS))[(c & 7) as usize][(why as usize).min(1)] += 1 };
    let kind = if unsafe { DELIBERATE } != 0 { Kind::Planned } else { Kind::Complaint };
    arch_aarch64::_print(format_args!(" [SUPERV] {} broke the call protocol ({}): reply refused, server reset (journaled, kind {})\n",
        name, WHY_NAMES[(why as usize).min(1)], kind.name()));
    j().open(c, kind, Rung::Restart, now_ms())
}

/// Complaints since boot, per component and reason.
pub fn complaints(c: u8) -> [u32; 2] {
    unsafe { (*core::ptr::addr_of!(COMPLAINTS))[(c & 7) as usize] }
}

/// H4c test hook (QEMU images only): the next reply of component `c` is read as if the server had reported a broken
/// length, so the self-test drives the real refusal path. A metal image has no way to set it.
#[cfg(not(feature = "cm5"))]
static mut INJECT: u8 = 0;

#[cfg(not(feature = "cm5"))]
pub fn inject_bad_reply(c: u8) {
    unsafe { INJECT |= 1 << (c & 7) };
}

/// Consume a pending test injection for component `c` (always false on metal).
#[inline]
pub fn take_injected(c: u8) -> bool {
    #[cfg(not(feature = "cm5"))]
    unsafe {
        let bit = 1u8 << (c & 7);
        let hit = INJECT & bit != 0;
        INJECT &= !bit;
        hit
    }
    #[cfg(feature = "cm5")]
    {
        let _ = c;
        false
    }
}

/// [P-superv-complain] (QEMU) — H4c: for each loaded EL0 server (el0-lansvc, el0-tlshost, el0-hsh) a reply with a broken
/// length is refused (the call answers ST_PANIC), the journal holds one `complaint` entry for that server, the server is
/// reset (a restart, the restart policy untouched), and the next call answers normally; the entry closes Recovered.
#[cfg(all(feature = "mctls", not(feature = "cm5")))]
pub fn complain_selftest() -> bool {
    let saved = swap(Journal::new());
    let counters = unsafe { *core::ptr::addr_of!(COMPLAINTS) }; // the drill's complaints are not the boot's
    let mut ran = 0u32;
    let mut pass = true;
    let mut one = |name: &str, r: Option<bool>| {
        let Some(ok) = r else { return };
        ran += 1;
        let c = component_id(name);
        let jj = journal();
        let entry = jj.newest_first().find(|e| e.component == c);
        let journaled = entry.is_some_and(|e| e.kind == Kind::Complaint && e.rung == Rung::Restart && e.outcome == Outcome::Recovered);
        let counted = complaints(c)[WHY_BAD_LENGTH as usize] > 0;
        arch_aarch64::_print(format_args!("   [P-superv-complain] {}: refused + reset + answers again={} journaled complaint, closed Recovered={} counted={}\n",
            name, ok, journaled, counted));
        pass &= ok && journaled && counted;
    };
    one("el0-lansvc", crate::lansvc::complain_drill());
    one("el0-tlshost", crate::tlshost::complain_drill());
    #[cfg(feature = "hsh")]
    one("el0-hsh", crate::hsh::complain_drill());
    let open = journal().newest_first().any(|e| e.outcome == Outcome::Pending);
    let _ = swap(saved);
    unsafe { COMPLAINTS = counters };
    let pass = pass && ran >= 2 && !open;
    arch_aarch64::_print(format_args!(
        " [P-superv-complain] {} — autoheal harness H4c, the complaint channel: {} servers drilled; a reply that breaks the call protocol is refused, journaled kind complaint and the server reset; no entry left open={}\n",
        if pass { "PASS" } else { "FAIL" }, ran, !open
    ));
    pass
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
    // H4c: complaints per component per reason (nonzero only)
    w.raw("],\"complaints\":{");
    let mut first = true;
    for e in hal::superv::TABLE.iter() {
        let n = complaints(component_id(e.name));
        if n.iter().all(|&x| x == 0) {
            continue;
        }
        let _ = write!(w, "{}\"{}\":{{", if first { "" } else { "," }, e.name);
        first = false;
        let mut f2 = true;
        for (k, why) in WHY_NAMES.iter().enumerate() {
            if n[k] > 0 {
                let _ = write!(w, "{}\"{}\":{}", if f2 { "" } else { "," }, why, n[k]);
                f2 = false;
            }
        }
        w.raw("}");
    }
    w.raw("}");
    let (pr, pf) = probe_stats();
    let _ = write!(w, ",\"probes\":{{\"period_ms\":{},\"run\":{},\"failed\":{}}},\"now_ms\":{},\"recoveries\":[", hal::superv::PROBE_PERIOD_MS, pr, pf, now_ms());
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

/// [P-swifi] — autoheal harness H6, the software fault-injection campaign (QEMU, feature `swifi`, never shipped).
/// `HEQK_SWIFI_N` injections (default 10 000, a fixed-seed xorshift so a run is reproducible) into el0-lansvc,
/// el0-tlshost, (H6d) el0-hsh and (H6f) el0-wpa, two fault models: (1) one flipped bit in the server's writable memory, (2) a call with a random
/// command id and random input. After each injection the server's functional probe runs: the injection is MASKED
/// (probe answers, nothing happened), or it surfaced as a FAULT (exception / budget overrun -> reset) or a WRONG
/// ANSWER (the probe caught it -> reset). Acceptance: after every injection the server answers its probe again
/// (bounded tries), the kernel is alive, and the journal has no entry left open. An injection that leaves a server
/// unable to answer is UNRECOVERED and fails the campaign.
#[cfg(all(feature = "swifi", feature = "mctls"))]
pub fn swifi_campaign() -> bool {
    const N: u64 = match option_env!("HEQK_SWIFI_N") {
        Some(s) => parse_u64(s),
        None => 10_000,
    };
    const fn parse_u64(s: &str) -> u64 {
        let b = s.as_bytes();
        let (mut i, mut v) = (0, 0u64);
        while i < b.len() {
            v = v * 10 + (b[i] - b'0') as u64;
            i += 1;
        }
        v
    }
    let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut rnd = move || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    let saved = core::mem::replace(j(), Journal::new());
    let t_start = now_ms();
    // counters: [lansvc, tlshost, hsh] x {injected, masked, fault, wrong, unrecovered}
    const NAMES: [&str; 4] = ["el0-lansvc", "el0-tlshost", "el0-hsh", "el0-wpa"];
    const NS: usize = 4;
    let mut c = [[0u64; 5]; NS];
    // H6f: the WPA security server (the product one is wired only on the CM5): a campaign instance
    let wpa_up = crate::el0srv::keyer::swifi_setup();
    let (mut flips, mut raws) = (0u64, 0u64);
    // wrong answers that only the golden workload caught (the probe still answered correctly)
    let mut wl_only = 0u64;
    // bit flips by image class: [text, read-only data, writable data] x {injected, surfaced}
    let mut cls = [[0u64; 2]; 3];
    let mut first_bad: Option<(u64, usize, u64)> = None;
    // the probe of server `s`: Some(true) ok, Some(false) wrong answer (already reset), None faulted / held off
    // (el0-hsh has no functional probe in production — it only runs on an owner's command: here its probe is
    // liveness, one known line answered without a fault; its wrong answers are the workload's to find)
    let probe = |s: usize| match s {
        0 => crate::lansvc::probe(false),
        1 => crate::tlshost::probe(false),
        2 => crate::hsh::swifi().and_then(|v| v.known_call(0)).map(|_| true),
        // (el0-wpa: liveness too — its state counters answered; its wrong answers are the workload's to find)
        _ => crate::el0srv::keyer::swifi_known(2).map(|_| true),
    };
    // H6b — the workload replayed after every injection: a fixed set of calls whose answers were recorded on the clean
    // image ("golden"). It reaches far more of each server than the probe: every el0-lansvc command with a well-formed
    // DNS query, a DNS answer, a DHCP DISCOVER and a patterned buffer; the el0-tlshost HTTP parser with eight requests
    // (`lansvc::Server::known_call`, `tlshost::KNOWN` — since H6c the probes sweep the same set).
    // work(s) = a digest over all answers; None = a call faulted / was refused.
    // one workload call by index: el0-lansvc has 18 commands x 4 inputs = 72, el0-tlshost 8 requests
    // (H6e: el0-tlshost = the 8 HTTP requests + 4 TLS handshake openings, the latter only with a certificate)
    const NW: [usize; NS] = [72, 12, 16, 4];
    let call = |s: usize, k: usize| -> Option<u64> {
        if s == 0 {
            crate::lansvc::swifi()?.known_call(k)
        } else if s == 1 {
            let h = crate::tlshost::host()?;
            if k < 8 { h.swifi_work(crate::tlshost::KNOWN[k]) } else { h.swifi_handshake(k - 8, None) }
        } else if s == 2 {
            crate::hsh::swifi()?.known_call(k)
        } else {
            crate::el0srv::keyer::swifi_known(k)
        }
    };
    let stats = |s: usize| -> (u64, u64) {
        if s == 0 {
            let (_, _, f, r, _) = crate::lansvc::stats();
            (f, r)
        } else if s == 1 {
            crate::tlshost::host().map_or((0, 0), |h| (h.faults as u64 + h.timeouts as u64, h.restarts as u64))
        } else if s == 2 {
            let (_, _, f, r) = crate::hsh::stats();
            (f, r)
        } else {
            crate::el0srv::keyer::swifi_stats()
        }
    };
    let restore = |s: usize| {
        if s == 0 {
            if let Some(v) = crate::lansvc::swifi() {
                v.swifi_restore();
            }
        } else if s == 1 {
            if let Some(h) = crate::tlshost::host() {
                h.swifi_restore();
            }
        } else if s == 2 {
            if let Some(v) = crate::hsh::swifi() {
                v.swifi_restore();
            }
        } else {
            crate::el0srv::keyer::swifi_restore();
        }
    };
    let both = crate::lansvc::swifi().is_some() && crate::tlshost::host().is_some() && crate::hsh::swifi().is_some() && wpa_up;
    // golden answers on the clean image, taken twice: the workload must be deterministic or it cannot judge anything
    // Golden answers on the clean image. Each call is taken TWICE; a call is used only if it answered both times with
    // the same digest (a call that faults on its input, or whose answer carries state, cannot judge anything).
    let mut golden = [[None::<u64>; 72]; NS];
    let mut usable = [0usize; NS];
    deliberate(|| {
        for s in 0..NS {
            restore(s);
            for k in 0..NW[s] {
                let a = call(s, k);
                if a.is_none() {
                    restore(s); // it faulted on a clean image: not a reference
                    continue;
                }
                if call(s, k) == a {
                    golden[s][k] = a;
                    usable[s] += 1;
                }
            }
            restore(s);
            server_ok(NAMES[s]);
        }
    });
    // the replay: 0 = every usable call answered as recorded, 1 = a call faulted / was refused, 2 = a wrong answer
    let last_bad = core::cell::Cell::new((usize::MAX, 0u64, 0u64));
    let work = |s: usize| -> u8 {
        for k in 0..NW[s] {
            if let Some(g) = golden[s][k] {
                match call(s, k) {
                    None => return 1,
                    Some(h) if h != g => {
                        last_bad.set((s * 1000 + k, h, g));
                        return 2;
                    }
                    Some(_) => {}
                }
            }
        }
        0
    };
    // H6e: what the server answered to the four hellos on the clean image (TLS record types: 0x16 handshake, 0x14
    // change-cipher-spec, 0x17 encrypted, 0x15 alert). With a certificate the accepted hello must get a ServerHello
    // followed by encrypted records, the unsupported-suite hello must get no encrypted record (this server refuses it
    // with an error status and sends nothing), and half a hello nothing yet — else the workload is not a handshake.
    let mut shapes = [([0u8; 8], 0usize); 4];
    let mut tls_on = false;
    deliberate(|| {
        if let Some(h) = crate::tlshost::host() {
            tls_on = h.ready;
            for (v, sh) in shapes.iter_mut().enumerate() {
                let _ = h.swifi_handshake(v, Some(sh));
            }
        }
        restore(1);
        server_ok(NAMES[1]);
    });
    let hs_ok = !tls_on || (shapes[0].0[0] == 0x16 && shapes[0].0[..shapes[0].1].contains(&0x17) && !shapes[1].0[..shapes[1].1].contains(&0x17) && shapes[2].1 == 0);
    arch_aarch64::_print(format_args!("   [swifi] TLS handshake workload: certificate={} | records answered to: accepted hello {:02x?}, unsupported suite {:02x?}, half a hello {:02x?}, hello + undecryptable record {:02x?} | as expected={}\n",
        tls_on, &shapes[0].0[..shapes[0].1], &shapes[1].0[..shapes[1].1], &shapes[2].0[..shapes[2].1], &shapes[3].0[..shapes[3].1], hs_ok));
    let stable = usable[0] >= 8 && usable[1] >= 4 && usable[2] >= 8 && usable[3] >= 3 && (0..NS).all(|s| work(s) == 0);
    let both = both && stable && hs_ok;
    let mut i = 0u64;
    while both && i < N {
        let r = rnd();
        let s = ((r >> 8) % NS as u64) as usize;
        let model_flip = (r >> 1) & 3 != 0; // 3 in 4 are bit flips, 1 in 4 a random call
        let (f0, r0) = stats(s);
        // --- inject (every fault inside is a campaign fault: journaled `planned`, kept out of the restart policy)
        deliberate(|| {
            let mut hit: Option<u8> = None;
            if model_flip {
                flips += 1;
                let rr = rnd();
                hit = match s {
                    0 => crate::lansvc::swifi().and_then(|v| v.swifi_flip(rr)),
                    1 => crate::tlshost::host().and_then(|h| h.swifi_flip(rr)),
                    2 => crate::hsh::swifi().and_then(|v| v.swifi_flip(rr)),
                    _ => crate::el0srv::keyer::swifi_flip(rr),
                };
                if let Some(k) = hit {
                    cls[k as usize][0] += 1;
                }
            } else {
                raws += 1;
                let mut buf = [0u8; 96];
                for b in buf.iter_mut() {
                    *b = rnd() as u8;
                }
                let (cmd, len) = ((rnd() % 128) as u32, (rnd() % 97) as usize);
                if s == 0 {
                    crate::lansvc::swifi().map(|v| v.swifi_raw(cmd, &buf[..len]));
                } else if s == 3 {
                    crate::el0srv::keyer::swifi_raw(cmd, &buf[..len]);
                } else if s == 2 {
                    crate::hsh::swifi().map(|v| v.swifi_raw(cmd, &buf[..len]));
                } else if cmd != hal::tlsabi::CMD_INIT {
                    // (INIT is the kernel's own, with the device scalar: never driven with random bytes)
                    crate::tlshost::host().map(|h| h.swifi_raw(cmd, (rnd() % 8) as usize, &buf[..len]));
                }
            }
            // --- observe: the probe, then the workload against its golden answers
            let mut p = probe(s);
            if p == Some(true) {
                match work(s) {
                    1 => p = None, // a workload call faulted (already reset by the fault path)
                    2 => {
                        // a WRONG ANSWER with no fault and a passing probe: only the workload saw it
                        let _ = server_probe_failed(NAMES[s]);
                        if s < 2 {
                            wl_only += 1;
                        }
                        p = Some(false);
                    }
                    _ => {}
                }
            }
            let (f1, r1) = stats(s);
            c[s][0] += 1;
            if p == Some(false) {
                c[s][3] += 1; // answered wrongly without faulting: caught by the probe, reset
            } else if f1 != f0 || p.is_none() {
                c[s][2] += 1; // exception / budget overrun (at the raw call or at the probe): reset by the fault path
            } else if r1 != r0 {
                c[s][2] += 1;
            } else {
                c[s][1] += 1; // masked
            }
            if let Some(k) = hit {
                if !(p == Some(true) && f1 == f0 && r1 == r0) {
                    cls[k as usize][1] += 1;
                }
            }
            // --- recover: a clean image, then the server must answer its probe (a faulted INIT gets two more tries)
            restore(s);
            let ok = (probe(s) == Some(true) || probe(s) == Some(true) || probe(s) == Some(true)) && work(s) == 0;
            // (the restore replaced the server's restart state, so close its journal entry here)
            server_ok(NAMES[s]);
            if !ok {
                c[s][4] += 1;
                if first_bad.is_none() {
                    first_bad = Some((i, s, r));
                }
                restore(s);
            }
        });
        i += 1;
        if i % 1000 == 0 {
            arch_aarch64::_print(format_args!("   [swifi] {} / {} injections, unrecovered so far {}\n", i, N, c.iter().map(|x| x[4]).sum::<u64>()));
        }
    }
    // the campaign's journal: every entry it opened is closed (nothing left pending), and the kinds are the planned ones
    let jj = journal();
    let (jt, jp) = (jj.total(), jj.pending());
    let jk = jj.by_kind;
    *j() = saved;
    // leave both servers clean and answering for the rest of the boot
    restore(0);
    restore(1);
    restore(2);
    restore(3);
    let alive = (0..NS).all(|s| probe(s) == Some(true) && work(s) == 0);
    crate::el0srv::keyer::swifi_teardown();
    let unrec: u64 = c.iter().map(|x| x[4]).sum();
    let surfaced: u64 = c.iter().map(|x| x[2] + x[3]).sum();
    let pass = both && i == N && unrec == 0 && jp == 0 && alive && surfaced > 0 && jk[Kind::Exception as usize] == 0;
    arch_aarch64::_print(format_args!(
        " [P-swifi] {} — autoheal harness H6, fault-injection campaign: {} injections ({} bit flips in the server image, {} random-command calls), seed fixed | el0-lansvc: injected {} masked {} fault {} wrong-answer {} unrecovered {} | el0-tlshost: injected {} masked {} fault {} wrong-answer {} unrecovered {} | el0-hsh: injected {} masked {} fault {} wrong-answer {} unrecovered {} | el0-wpa: injected {} masked {} fault {} wrong-answer {} unrecovered {} | bit flips surfaced by class: text {}/{} read-only data {}/{} writable data {}/{} | wrong answers only the golden workload caught in el0-lansvc / el0-tlshost (probe still correct): {} | golden workload: {} of 72 el0-lansvc calls, {} of 12 el0-tlshost calls (8 HTTP requests + 4 TLS handshake openings, the latter need a certificate), {} of 16 el0-hsh lines and {} of 4 el0-wpa exchanges (a WPA2 4-way against a simulated station among them) usable (answered twice identically on the clean image), replay clean={} | surfaced {} of {} | journal entries {} (planned {}), left pending {} | all four servers answer after the campaign={} | {} ms{}\n",
        if pass { "PASS" } else { "FAIL" }, i, flips, raws,
        c[0][0], c[0][1], c[0][2], c[0][3], c[0][4], c[1][0], c[1][1], c[1][2], c[1][3], c[1][4], c[2][0], c[2][1], c[2][2], c[2][3], c[2][4], c[3][0], c[3][1], c[3][2], c[3][3], c[3][4],
        cls[0][1], cls[0][0], cls[1][1], cls[1][0], cls[2][1], cls[2][0], wl_only, usable[0], usable[1], usable[2], usable[3], stable, surfaced, i, jt, jk[Kind::Planned as usize], jp, alive, now_ms().saturating_sub(t_start),
        match first_bad { Some((n, s, r)) => { let _ = (n, s, r); " | FIRST UNRECOVERED recorded above" } None => "" }
    ));
    if last_bad.get().0 != usize::MAX {
        let (w, h, g) = last_bad.get();
        arch_aarch64::_print(format_args!("   [swifi] last workload mismatch: {} known call #{} digest {:#x} vs golden {:#x}\n", NAMES[w / 1000], w % 1000, h, g));
    }
    if let Some((n, s, r)) = first_bad {
        arch_aarch64::_print(format_args!("   [swifi] first unrecovered: injection #{} server {} r={:#x}\n", n, NAMES[s], r));
    }
    pass
}

#[cfg(all(feature = "swifi", not(feature = "mctls")))]
pub fn swifi_campaign() -> bool {
    arch_aarch64::_print(format_args!(" [P-swifi] FAIL — needs the EL0 servers (feature mctls)\n"));
    false
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
