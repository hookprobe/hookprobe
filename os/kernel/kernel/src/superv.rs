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

/// An EL0 server faulted (`budget` = it overran its time budget) and is being reset + restarted.
pub fn server_fault(name: &str, budget: bool) -> u32 {
    let c = component_id(name);
    mark(c);
    j().open(c, if budget { Kind::Budget } else { Kind::Exception }, Rung::Restart, now_ms())
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
    let (reason, culprit) = hal::superv::last_boot_reason(c.map(|c| c.kind), c.map_or("", |c| c.text()), crate::rtwdog::prev_reset_was_watchdog());
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
    let _ = write!(w, "}},\"now_ms\":{},\"recoveries\":[", now_ms());
    for (i, r) in jj.newest_first().take(limit).enumerate() {
        let _ = write!(w, "{}{{\"seq\":{},\"component\":\"{}\",\"kind\":\"{}\",\"rung\":\"{}\",\"outcome\":\"{}\",\"repeats\":{},\"t_detect_ms\":{},",
            if i > 0 { "," } else { "" }, r.seq, component_name(r.component), r.kind.name(), r.rung.name(), r.outcome.name(), r.repeats, r.t_detect_ms);
        match r.duration_ms() {
            Some(d) => {
                let _ = write!(w, "\"t_done_ms\":{},\"duration_ms\":{}}}", r.t_done_ms, d);
            }
            None => w.raw("\"t_done_ms\":null,\"duration_ms\":null}"),
        }
    }
    w.raw("]}");
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
    let s = server_fault("el0-tlshost", true);
    let again = server_fault("el0-tlshost", false) == s;
    server_ok("el0-tlshost");
    server_ok("el0-tlshost");
    let jj = journal();
    let fault = jj.total() == 4
        && jj.get(s).is_some_and(|r| r.kind == Kind::Budget && r.outcome == Outcome::Recovered && r.repeats == 1)
        && jj.by_kind[Kind::Budget as usize] == 1
        && jj.by_outcome[Outcome::Recovered as usize] == 2;
    let unknown = component_id("no-such-server") == component_id("other");
    *j() = saved;
    let ok = ladder && degrade && again && fault && unknown;
    arch_aarch64::_print(format_args!(
        " [P-superv] {} — autoheal harness H1, the recovery journal: Wi-Fi kick (repeat folded) -> bounce escalates it, a healthy tick closes the bounce Recovered with its time={} a degrade closes Failed={} an EL0 server fault opens one entry (budget-overrun), a second fault folds into it={} the next good call closes it Recovered, exactly one entry={} unknown components map to other={}\n",
        if ok { "PASS" } else { "FAIL" }, ladder, degrade, again, fault, unknown
    ));
    ok
}
