//! Audit A7 / release workstream 3 — Wi-Fi field self-heal (task #60).
//!
//! One pure state machine, fed once per AP-loop iteration with progress counters; the radio side is a [`Port`]
//! (cyw43 on metal, a mock in `[P-wifiheal]`). It CLASSIFIES before it acts — a timer alone never proves a crash:
//!
//! ```text
//! congestion   credit window exhausted, deliveries queued, but tx_max (credit returned = completions) advancing -> none
//! sleep        nothing to deliver to: no associated station, or the queued head's station is in power save / gone
//!              (firmware sta_info, read once the stall passes PROBE_MS)                                             -> none
//! crash        the firmware's mailbox FWHALT counter moved (an event, not a timer)  -> diagnostics, firmware reload
//! freeze       queued + window exhausted + tx_max frozen while an AWAKE station is associated:
//!              KICK_MS -> control-frame kick, every KICK_REPEAT_MS (the metal-proven 2026-11-05 mitigation)
//!              STAGE_MS -> diagnostics, BSS bounce (ap_stop / ap_start on the same chanspec; firmware kept)
//!              STAGE_MS again within RECUR_MS of a bounce / reload -> diagnostics, firmware reload
//! reload       at most MAX_RELOADS per budget, the 2nd no sooner than RELOAD_BACKOFF_MS after the 1st (doubling);
//!              the budget refills after BUDGET_REFILL_MS without any recovery action
//! exhausted    -> RebootOnce (record kept: the next boot knows it rebooted); in the boot after that reboot, within
//!              POST_REBOOT_WINDOW_MS -> Degrade: Wi-Fi off (WL_ON low, SDIO gated), fault surfaced, NO more resets;
//!              wired LAN + WAN + Mission Control on the management VLAN keep running
//! ```
//!
//! Diagnostics are captured and written to the crash-record page BEFORE every bounce / reload / reboot / degrade
//! (`crashrec::write_heal`): firmware hash, PMKID-fix status, trap registers, mailbox halts, SDPCM tx_seq / tx_max /
//! flow-control mask, queue depth, frames read, firmware packet counters, stall time, stations, the attempt number.
//! No key, passphrase or station address is ever recorded. The REL-08 PMKID-cache work stays separate: a reload goes
//! through the same `firmware_upload`, so the `wifi-pmkid-fix` RAM correction is re-applied exactly as at boot.

use core::sync::atomic::{AtomicU32, Ordering::Relaxed};

pub const KICK_MS: u64 = 100;
pub const KICK_REPEAT_MS: u64 = 500;
pub const PROBE_MS: u64 = 2_000;
pub const REPROBE_MS: u64 = 10_000;
/// A confirmed freeze this long (an awake station waiting) escalates one stage.
pub const STAGE_MS: u64 = 10_000;
/// After a bounce / reload: stations re-join, nothing escalates.
pub const SETTLE_MS: u64 = 5_000;
/// A freeze within this long of the last bounce / reload escalates past the bounce.
pub const RECUR_MS: u64 = 120_000;
pub const MAX_RELOADS: u8 = 2;
pub const RELOAD_BACKOFF_MS: u64 = 60_000;
pub const BUDGET_REFILL_MS: u64 = 60 * 60_000;
pub const POST_REBOOT_WINDOW_MS: u64 = 30 * 60_000;

/// Persisted flags (crash-record page).
pub const F_REBOOTED: u32 = 1;
pub const F_DEGRADED: u32 = 2;

pub const WORDS: usize = arch_aarch64::crashrec::HEAL_WORDS;
// diagnostic word layout
pub const W_CLASS: usize = 0;
pub const W_ACTION: usize = 1;
pub const W_ATTEMPT: usize = 2;
pub const W_UPTIME_S: usize = 3;
pub const W_FW_HASH: usize = 4;
pub const W_PMKID_FIX: usize = 5; // 0 not built / other firmware, 1 applied, 2 write failed
pub const W_TRAP: usize = 6; // 4 words: type, epc, lr, pc
pub const W_HALTS: usize = 10;
pub const W_TX_SEQ: usize = 11;
pub const W_TX_MAX: usize = 12;
pub const W_FC_MASK: usize = 13;
pub const W_QUEUED: usize = 14;
pub const W_RX: usize = 15;
pub const W_PKTCNT: usize = 16; // 5 words: rx_good, rx_bad, tx_good, tx_bad, rx_ocast (0 when the firmware is down)
pub const W_STALL_MS: usize = 21;
pub const W_STATIONS: usize = 22;
pub const W_COUNTS: usize = 23; // kicks (16) | bounces (8) << 16 | reloads this boot (8) << 24

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum Class {
    Healthy = 0,
    Congestion = 1,
    Sleep = 2,
    Crash = 3,
    Freeze = 4,
}

impl Class {
    pub fn name(self) -> &'static str {
        ["healthy", "congestion", "station-sleep", "firmware-crash", "tx-freeze"][self as usize]
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum Action {
    None = 0,
    Kick = 1,
    BssBounce = 2,
    FirmwareReload = 3,
    RebootOnce = 4,
    Degrade = 5,
}

/// The firmware's view of the queued head's station (`sta_info`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Probe {
    Awake,
    Asleep,
    Gone,
    /// The control request failed (the control path itself is suspect): treated as a freeze.
    Failed,
    /// No unicast station at the head (broadcast / multicast): decided by the station count alone.
    Unknown,
}

/// One loop tick's progress counters.
#[derive(Clone, Copy, Default)]
pub struct Sample {
    pub now_ms: u64,
    /// Deliveries waiting for TX credit (the loop's Wi-Fi queues).
    pub queued: u32,
    pub tx_seq: u8,
    /// Advances when the firmware returns credit (= TX completions).
    pub tx_max: u8,
    pub rx_frames: u64,
    /// Associated stations (the loop's station set).
    pub stations: u8,
    /// The mailbox FWHALT counter.
    pub fw_halts: u32,
}

#[derive(Clone, Copy)]
pub struct Diag {
    pub w: [u32; WORDS],
}

/// The radio side.
pub trait Port {
    /// One control frame (the firmware resumes a station's TX queue when its wl layer runs an ioctl).
    fn kick(&mut self);
    fn probe(&mut self) -> Probe;
    /// Fill the firmware-side words (hash, PMKID fix, trap registers, packet counters, flow-control mask). For a
    /// crashed firmware no control request is sent.
    fn capture(&mut self, class: Class, d: &mut Diag);
    /// Persist the record (crash-record page) — called BEFORE the action it precedes.
    fn record(&mut self, flags: u32, d: &Diag);
    fn bounce(&mut self) -> bool;
    fn reload(&mut self) -> bool;
    /// Metal: never returns (EL2-gate reset with a kind-3 crash record).
    fn reboot(&mut self, d: &Diag);
    fn degrade(&mut self);
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum St {
    Run,
    Rebooting,
    Degraded,
}

pub struct Heal {
    post_reboot: bool,
    st: St,
    halts_seen: u32,
    last_max: Option<u8>,
    stall_since: u64,
    last_kick: u64,
    ep_kicks: u32,
    probe: Option<(Probe, u64)>,
    settle_until: u64,
    pending: Option<Class>,
    last_bounce: Option<u64>,
    last_reload: Option<u64>,
    last_action: u64,
    reloads: u8,
    pub class: Class,
    pub kicks: u32,
    pub bounces: u32,
    pub reloads_boot: u32,
    pub reload_fails: u32,
    pub last: Option<Diag>,
    /// The record the previous boot left (flags, words), for the boot log / health.
    pub prev: Option<(u32, Diag)>,
}

impl Heal {
    /// `rec` = the previous boot's record (`crashrec::take_heal`); `early_self_heal` = the previous boot ended in an
    /// early self-heal reset (`!rtwdog::self_heal_allowed()`), which also counts as "already rebooted".
    pub fn from_boot(rec: Option<(u32, [u32; WORDS])>, early_self_heal: bool) -> Heal {
        let flags = rec.map_or(0, |r| r.0);
        Heal {
            post_reboot: flags & (F_REBOOTED | F_DEGRADED) != 0 || early_self_heal,
            st: St::Run,
            halts_seen: 0,
            last_max: None,
            stall_since: 0,
            last_kick: 0,
            ep_kicks: 0,
            probe: None,
            settle_until: 0,
            pending: None,
            last_bounce: None,
            last_reload: None,
            last_action: 0,
            reloads: 0,
            class: Class::Healthy,
            kicks: 0,
            bounces: 0,
            reloads_boot: 0,
            reload_fails: 0,
            last: None,
            prev: rec.map(|(f, w)| (f, Diag { w })),
        }
    }

    /// The FWHALT counter when the AP loop starts (halts before it are the boot's business).
    pub fn baseline(&mut self, fw_halts: u32) {
        self.halts_seen = fw_halts;
    }

    pub fn degraded(&self) -> bool {
        self.st == St::Degraded
    }

    fn new_episode(&mut self, s: &Sample) {
        self.last_max = Some(s.tx_max);
        self.stall_since = 0;
        self.ep_kicks = 0;
        self.probe = None;
    }

    fn recent(at: Option<u64>, now: u64) -> bool {
        at.is_some_and(|t| now.saturating_sub(t) < RECUR_MS)
    }

    /// One tick. Never blocks except inside a bounce / reload the port runs (bounded, rare).
    pub fn step<P: Port>(&mut self, s: &Sample, p: &mut P) -> Action {
        let a = self.step_inner(s, p);
        publish(self);
        a
    }

    fn step_inner<P: Port>(&mut self, s: &Sample, p: &mut P) -> Action {
        if self.st != St::Run {
            return Action::None;
        }
        let now = s.now_ms;
        // the reload budget refills after a long stretch without any recovery action
        if self.reloads > 0 && self.pending.is_none() && now.saturating_sub(self.last_action) >= BUDGET_REFILL_MS {
            self.reloads = 0;
        }
        // 1. firmware crash: the mailbox FWHALT counter moved
        if s.fw_halts != self.halts_seen {
            self.halts_seen = s.fw_halts;
            self.class = Class::Crash;
            self.pending = Some(Class::Crash);
        }
        if let Some(c) = self.pending {
            return self.reload(c, s, p);
        }
        if now < self.settle_until {
            self.new_episode(s);
            return Action::None;
        }
        // 2. TX progress
        let w = s.tx_max.wrapping_sub(s.tx_seq);
        let exhausted = w <= 2 || w & 0x80 != 0;
        let moved = self.last_max.is_some_and(|m| m != s.tx_max);
        if s.queued == 0 || !exhausted || moved {
            self.class = if s.queued > 0 && exhausted { Class::Congestion } else { Class::Healthy };
            self.new_episode(s);
            return Action::None;
        }
        self.last_max = Some(s.tx_max);
        if self.stall_since == 0 {
            self.stall_since = now.max(1);
        }
        let d = now.saturating_sub(self.stall_since);
        // 3. nobody to deliver to
        if s.stations == 0 {
            self.class = Class::Sleep;
            return Action::None;
        }
        if d >= PROBE_MS && self.probe.map_or(true, |(_, at)| now.saturating_sub(at) >= REPROBE_MS) {
            self.probe = Some((p.probe(), now));
        }
        if matches!(self.probe, Some((Probe::Asleep | Probe::Gone, _))) {
            self.class = Class::Sleep;
            return Action::None;
        }
        // 4. a persistent TX freeze with an awake station
        self.class = Class::Freeze;
        if d >= STAGE_MS {
            if Self::recent(self.last_bounce, now) || Self::recent(self.last_reload, now) {
                return self.reload(Class::Freeze, s, p);
            }
            self.capture(Class::Freeze, Action::BssBounce, s, p, self.window_flags(now));
            self.bounces += 1;
            self.last_bounce = Some(now);
            self.last_action = now;
            let _ = p.bounce();
            self.settle(now);
            return Action::BssBounce;
        }
        if d >= KICK_MS && (self.ep_kicks == 0 || now.saturating_sub(self.last_kick) >= KICK_REPEAT_MS) {
            p.kick();
            self.ep_kicks += 1;
            self.kicks += 1;
            self.last_kick = now;
            return Action::Kick;
        }
        Action::None
    }

    fn settle(&mut self, now: u64) {
        self.settle_until = now + SETTLE_MS;
        self.last_max = None;
        self.stall_since = 0;
        self.ep_kicks = 0;
        self.probe = None;
    }

    fn in_window(&self, now: u64) -> bool {
        self.post_reboot && now < POST_REBOOT_WINDOW_MS
    }

    fn window_flags(&self, now: u64) -> u32 {
        if self.in_window(now) { F_REBOOTED } else { 0 }
    }

    fn reload<P: Port>(&mut self, c: Class, s: &Sample, p: &mut P) -> Action {
        let now = s.now_ms;
        if self.reloads >= MAX_RELOADS {
            return self.terminal(c, s, p);
        }
        if let Some(t) = self.last_reload {
            if self.reloads > 0 && now.saturating_sub(t) < RELOAD_BACKOFF_MS << (self.reloads - 1) {
                self.pending = Some(c); // owed, after the backoff
                return Action::None;
            }
        }
        self.pending = None;
        self.capture(c, Action::FirmwareReload, s, p, self.window_flags(now));
        self.reloads += 1;
        self.reloads_boot += 1;
        self.last_reload = Some(now);
        self.last_action = now;
        if !p.reload() {
            self.reload_fails += 1;
            self.pending = Some(c); // retried after the backoff, or terminal once the budget is spent
        }
        self.settle(now);
        Action::FirmwareReload
    }

    fn terminal<P: Port>(&mut self, c: Class, s: &Sample, p: &mut P) -> Action {
        self.pending = None;
        if self.in_window(s.now_ms) {
            self.capture(c, Action::Degrade, s, p, F_REBOOTED | F_DEGRADED);
            self.st = St::Degraded;
            p.degrade();
            return Action::Degrade;
        }
        self.capture(c, Action::RebootOnce, s, p, F_REBOOTED);
        self.st = St::Rebooting;
        let d = self.last.unwrap_or(Diag { w: [0; WORDS] });
        p.reboot(&d);
        Action::RebootOnce
    }

    /// Diagnostics FIRST: the loop's counters, then the firmware side, then the persisted record.
    fn capture<P: Port>(&mut self, c: Class, a: Action, s: &Sample, p: &mut P, flags: u32) {
        let mut d = Diag { w: [0; WORDS] };
        d.w[W_CLASS] = c as u32;
        d.w[W_ACTION] = a as u32;
        d.w[W_ATTEMPT] = self.reloads as u32 + 1;
        d.w[W_UPTIME_S] = (s.now_ms / 1000) as u32;
        d.w[W_HALTS] = s.fw_halts;
        d.w[W_TX_SEQ] = s.tx_seq as u32;
        d.w[W_TX_MAX] = s.tx_max as u32;
        d.w[W_QUEUED] = s.queued;
        d.w[W_RX] = s.rx_frames as u32;
        d.w[W_STALL_MS] = if self.stall_since == 0 { 0 } else { s.now_ms.saturating_sub(self.stall_since) as u32 };
        d.w[W_STATIONS] = s.stations as u32;
        d.w[W_COUNTS] = self.kicks.min(0xffff) | (self.bounces.min(0xff) << 16) | (self.reloads_boot.min(0xff) << 24);
        p.capture(c, &mut d);
        p.record(flags, &d);
        self.last = Some(d);
    }
}

pub fn class_name(c: u32) -> &'static str {
    ["healthy", "congestion", "station-sleep", "firmware-crash", "tx-freeze"].get(c as usize).copied().unwrap_or("?")
}

/// One console line for a diagnostic record (`flags` = the persisted flags, 0 when printing a live capture).
pub fn print_diag(tag: &str, flags: u32, d: &Diag) {
    let w = &d.w;
    arch_aarch64::_print(format_args!(
        "{}: flags={} class={} action={} attempt={} uptime={}s fw_hash={:#010x} pmkid_fix={} trap type={:#x} epc={:#010x} lr={:#010x} pc={:#010x} halts={} tx_seq={} tx_max={} fc_mask={:#04x} queued={} rx_frames={} pktcnts={:?} stall={}ms stations={} kicks={} bounces={} reloads={}\n",
        tag, flags, class_name(w[W_CLASS]), w[W_ACTION], w[W_ATTEMPT], w[W_UPTIME_S], w[W_FW_HASH], w[W_PMKID_FIX], w[W_TRAP], w[W_TRAP + 1], w[W_TRAP + 2], w[W_TRAP + 3],
        w[W_HALTS], w[W_TX_SEQ], w[W_TX_MAX], w[W_FC_MASK], w[W_QUEUED], w[W_RX], &w[W_PKTCNT..W_PKTCNT + 5], w[W_STALL_MS], w[W_STATIONS],
        w[W_COUNTS] & 0xffff, (w[W_COUNTS] >> 16) & 0xff, w[W_COUNTS] >> 24));
}

static mut BOOT_REC: Option<(u32, [u32; WORDS])> = None;

/// Early at boot (next to the crash record): take the Wi-Fi recovery record the previous boot left, once.
#[cfg(feature = "cm5")]
pub fn take_at_boot() {
    let r = arch_aarch64::crashrec::take_heal();
    if let Some((f, w)) = r {
        print_diag(" [WIFI-HEAL] previous boot's recovery record", f, &Diag { w });
    }
    unsafe { *core::ptr::addr_of_mut!(BOOT_REC) = r };
}

pub fn boot_record() -> Option<(u32, [u32; WORDS])> {
    unsafe { *core::ptr::addr_of!(BOOT_REC) }
}

// --- the published status (/api/health "wifi_heal", the heartbeat) ---
static ST: AtomicU32 = AtomicU32::new(0); // 0 ok, 1 recovering, 2 degraded, 3 rebooting
static CLASS: AtomicU32 = AtomicU32::new(0);
static COUNTS: AtomicU32 = AtomicU32::new(0); // W_COUNTS layout
static FLAGS: AtomicU32 = AtomicU32::new(0); // bit0 post-reboot boot, bit1 previous boot left a record

fn publish(h: &Heal) {
    let st = match h.st {
        St::Degraded => 2,
        St::Rebooting => 3,
        St::Run if h.pending.is_some() || matches!(h.class, Class::Crash | Class::Freeze) => 1,
        St::Run => 0,
    };
    ST.store(st, Relaxed);
    CLASS.store(h.class as u32, Relaxed);
    COUNTS.store(h.kicks.min(0xffff) | (h.bounces.min(0xff) << 16) | (h.reloads_boot.min(0xff) << 24), Relaxed);
    FLAGS.store(h.post_reboot as u32 | (h.prev.is_some() as u32) << 1, Relaxed);
}

/// (state name, last class name, kicks, bounces, reloads this boot, post-reboot boot)
pub fn status() -> (&'static str, &'static str, u32, u32, u32, bool) {
    let c = COUNTS.load(Relaxed);
    let class = match CLASS.load(Relaxed) {
        1 => Class::Congestion,
        2 => Class::Sleep,
        3 => Class::Crash,
        4 => Class::Freeze,
        _ => Class::Healthy,
    };
    (
        ["ok", "recovering", "degraded: Wi-Fi off after a failed recovery (wired LAN, WAN and management keep running)", "rebooting"][ST.load(Relaxed).min(3) as usize],
        class.name(),
        c & 0xffff,
        (c >> 16) & 0xff,
        c >> 24,
        FLAGS.load(Relaxed) & 1 != 0,
    )
}

/// Associated stations (the loop's view: ASSOC_IND adds, DEAUTH / DISASSOC removes).
pub struct StaSet {
    m: [[u8; 6]; 16],
    n: usize,
}

impl StaSet {
    pub const fn new() -> StaSet {
        StaSet { m: [[0; 6]; 16], n: 0 }
    }
    pub fn add(&mut self, mac: &[u8; 6]) {
        if !self.m[..self.n].contains(mac) && self.n < self.m.len() {
            self.m[self.n] = *mac;
            self.n += 1;
        }
    }
    pub fn remove(&mut self, mac: &[u8; 6]) {
        if let Some(i) = self.m[..self.n].iter().position(|x| x == mac) {
            self.m[i] = self.m[self.n - 1];
            self.n -= 1;
        }
    }
    pub fn clear(&mut self) {
        self.n = 0;
    }
    pub fn len(&self) -> u8 {
        self.n as u8
    }
}

// ---------------------------------------------------------------- [P-wifiheal]

struct Mock {
    log: [u8; 160],
    at: [u64; 160],
    n: usize,
    probe: Probe,
    reload_ok: bool,
    flags: [u32; 16],
    nrec: usize,
    recorded_class: u32,
}

impl Mock {
    fn new(probe: Probe) -> Mock {
        Mock { log: [0; 160], at: [0; 160], n: 0, probe, reload_ok: true, flags: [0; 16], nrec: 0, recorded_class: 99 }
    }
    fn push(&mut self, c: u8) {
        if self.n < self.log.len() {
            self.log[self.n] = c;
            self.at[self.n] = NOW.load(Relaxed) as u64;
            self.n += 1;
        }
    }
    fn calls(&self) -> &[u8] {
        &self.log[..self.n]
    }
    fn count(&self, c: u8) -> usize {
        self.calls().iter().filter(|&&x| x == c).count()
    }
    fn first(&self, c: u8) -> Option<usize> {
        self.calls().iter().position(|&x| x == c)
    }
    /// Every heavy action is preceded by capture ('c') then record ('r').
    fn diag_first(&self) -> bool {
        self.calls().iter().enumerate().all(|(i, &x)| !b"bLRD".contains(&x) || (i >= 2 && self.log[i - 2] == b'c' && self.log[i - 1] == b'r'))
    }
    /// The times (ms) of the calls `c`.
    fn times(&self, c: u8, out: &mut [u64]) -> usize {
        let mut k = 0;
        for i in 0..self.n {
            if self.log[i] == c && k < out.len() {
                out[k] = self.at[i];
                k += 1;
            }
        }
        k
    }
}

static NOW: AtomicU32 = AtomicU32::new(0);

impl Port for Mock {
    fn kick(&mut self) {
        self.push(b'k');
    }
    fn probe(&mut self) -> Probe {
        self.push(b'p');
        self.probe
    }
    fn capture(&mut self, class: Class, d: &mut Diag) {
        self.push(b'c');
        d.w[W_FW_HASH] = 0xfeed_f00d;
        self.recorded_class = class as u32;
    }
    fn record(&mut self, flags: u32, d: &Diag) {
        self.push(b'r');
        if self.nrec < self.flags.len() {
            self.flags[self.nrec] = flags;
            self.nrec += 1;
        }
        let _ = d;
    }
    fn bounce(&mut self) -> bool {
        self.push(b'b');
        true
    }
    fn reload(&mut self) -> bool {
        self.push(b'L');
        self.reload_ok
    }
    fn reboot(&mut self, _d: &Diag) {
        self.push(b'R');
    }
    fn degrade(&mut self) {
        self.push(b'D');
    }
}

/// Run `h` from `t0` to `t1` ms in 50-ms ticks; `f` shapes each sample.
fn run(h: &mut Heal, m: &mut Mock, t0: u64, t1: u64, f: &mut dyn FnMut(u64, &mut Sample)) {
    let mut t = t0;
    while t <= t1 {
        let mut s = Sample { now_ms: t, queued: 8, tx_seq: 40, tx_max: 40, rx_frames: 100, stations: 1, fw_halts: 0 };
        f(t, &mut s);
        NOW.store(t as u32, Relaxed);
        let _ = h.step(&s, m);
        t += 50;
    }
}

fn near(t: u64, want: u64) -> bool {
    t >= want && t <= want + 100
}

pub fn selftest() -> bool {
    let heap0 = crate::heap::used();
    // 1. congestion: window exhausted, deliveries queued, but completions (tx_max) advance every tick -> nothing
    let mut h = Heal::from_boot(None, false);
    let mut m = Mock::new(Probe::Awake);
    run(&mut h, &mut m, 1_000, 200_000, &mut |t, s| {
        s.tx_max = (t / 50) as u8;
        s.tx_seq = s.tx_max.wrapping_sub(1);
    });
    let congestion = m.n == 0 && h.class == Class::Congestion;
    // 2. no station associated: a frozen window is not a fault -> nothing, not even a kick
    let mut h = Heal::from_boot(None, false);
    let mut m = Mock::new(Probe::Awake);
    run(&mut h, &mut m, 1_000, 200_000, &mut |_, s| s.stations = 0);
    let nosta = m.n == 0 && h.class == Class::Sleep;
    // 3. the queued head's station is in power save (or gone): kicks until the probe says so, then NO recovery
    let mut sleep = true;
    for pr in [Probe::Asleep, Probe::Gone] {
        let mut h = Heal::from_boot(None, false);
        let mut m = Mock::new(pr);
        run(&mut h, &mut m, 1_000, 200_000, &mut |_, _| {});
        sleep &= h.class == Class::Sleep && m.count(b'b') + m.count(b'L') + m.count(b'R') + m.count(b'D') + m.count(b'c') == 0
            && m.count(b'k') == 4 && m.count(b'p') >= 2;
    }
    // 4. a persistent freeze with an awake station: kick (100 ms, every 500 ms) -> bounce at 10 s -> reload at
    //    10 + 5 (settle) + 10 = 25 s -> reload #2 only after the 60-s backoff (85 s) -> budget spent -> RebootOnce
    //    (at 85 + 5 + 10 = 100 s); nothing after it
    let mut h = Heal::from_boot(None, false);
    let mut m = Mock::new(Probe::Awake);
    run(&mut h, &mut m, 1_000, 400_000, &mut |_, _| {});
    let mut kt = [0u64; 4];
    let nk = m.times(b'k', &mut kt);
    let mut bt = [0u64; 4];
    let mut lt = [0u64; 4];
    let mut rt = [0u64; 4];
    let (nb, nl, nr) = (m.times(b'b', &mut bt), m.times(b'L', &mut lt), m.times(b'R', &mut rt));
    let ladder = nk >= 4 && near(kt[0], 1_100) && near(kt[1], 1_600) && nb == 1 && near(bt[0], 11_000) && nl == 2
        && near(lt[0], 26_000) && near(lt[1], 86_000) && nr == 1 && near(rt[0], 101_000) && m.count(b'D') == 0
        && m.first(b'b') < m.first(b'L') && m.first(b'L') < m.first(b'R');
    let diag = m.diag_first() && m.nrec == 4 && m.flags[..3] == [0, 0, 0] && m.flags[3] == F_REBOOTED
        && h.last.is_some_and(|d| d.w[W_CLASS] == Class::Freeze as u32 && d.w[W_ACTION] == Action::RebootOnce as u32
            && d.w[W_ATTEMPT] == 3 && d.w[W_QUEUED] == 8 && d.w[W_TX_SEQ] == 40 && d.w[W_FW_HASH] == 0xfeed_f00d
            && d.w[W_STATIONS] == 1 && d.w[W_COUNTS] >> 24 == 2);
    let once = h.step(&Sample { now_ms: 500_000, queued: 8, tx_seq: 40, tx_max: 40, rx_frames: 0, stations: 1, fw_halts: 9 }, &mut m) == Action::None
        && m.count(b'R') == 1;
    // 5. the boot after that reboot: the same failure within the window -> Degrade, Wi-Fi off, NO reset, ever
    let rec = Some((F_REBOOTED, h.last.map_or([0; WORDS], |d| d.w)));
    let mut h2 = Heal::from_boot(rec, false);
    let mut m2 = Mock::new(Probe::Awake);
    run(&mut h2, &mut m2, 1_000, 30 * 60_000 + 60_000, &mut |_, _| {});
    let mut m2h = Mock::new(Probe::Awake); // a firmware halt while degraded: still nothing
    let _ = h2.step(&Sample { now_ms: 40 * 60_000, queued: 8, tx_seq: 40, tx_max: 40, rx_frames: 0, stations: 1, fw_halts: 7 }, &mut m2h);
    let degrade = h2.degraded() && m2.count(b'D') == 1 && m2.count(b'R') == 0 && m2h.n == 0 && m2.diag_first()
        && m2.flags[m2.nrec - 1] == F_REBOOTED | F_DEGRADED && h2.prev.is_some_and(|(f, d)| f == F_REBOOTED && d.w[W_ACTION] == 4);
    // ...an early self-heal reset by the previous boot counts as "already rebooted" too
    let mut h3 = Heal::from_boot(None, true);
    let mut m3 = Mock::new(Probe::Failed); // the control path itself failing is a freeze, not a sleep
    run(&mut h3, &mut m3, 1_000, 200_000, &mut |_, _| {});
    let early = h3.degraded() && m3.count(b'R') == 0 && m3.count(b'D') == 1;
    // ...and after the window a new incident is a new incident (one reboot again, never a loop: the next boot degrades)
    let mut h4 = Heal::from_boot(Some((F_REBOOTED, [0; WORDS])), false);
    let mut m4 = Mock::new(Probe::Awake);
    run(&mut h4, &mut m4, 31 * 60_000, 31 * 60_000 + 200_000, &mut |_, _| {});
    let later = m4.count(b'R') == 1 && m4.count(b'D') == 0;
    // 6. firmware crash (mailbox FWHALT, no queue needed): diagnostics then reload at once; a failed reload is retried
    //    after the 60-s backoff; a halt once the budget is spent -> RebootOnce
    let mut h5 = Heal::from_boot(None, false);
    let mut m5 = Mock::new(Probe::Awake);
    m5.reload_ok = false;
    run(&mut h5, &mut m5, 1_000, 1_000, &mut |_, s| {
        s.queued = 0;
        s.fw_halts = 1;
    });
    let crash1 = m5.calls() == b"crL" && m5.recorded_class == Class::Crash as u32 && h5.class == Class::Crash;
    m5.reload_ok = true;
    run(&mut h5, &mut m5, 1_050, 200_000, &mut |t, s| {
        s.queued = 0;
        s.fw_halts = if t >= 100_000 { 2 } else { 1 };
    });
    let (mut lt5, mut rt5) = ([0u64; 4], [0u64; 2]);
    let (nl5, nr5) = (m5.times(b'L', &mut lt5), m5.times(b'R', &mut rt5));
    let crash2 = nl5 == 2 && near(lt5[1], 61_000) && nr5 == 1 && near(rt5[0], 100_000) && h5.reload_fails == 1 && m5.diag_first();
    // 7. the reload budget refills after an hour without any recovery action
    let mut h6 = Heal::from_boot(None, false);
    let mut m6 = Mock::new(Probe::Awake);
    for (t, n) in [(1_000u64, 1u32), (70_000, 2), (70_000 + 3_700_000, 3)] {
        run(&mut h6, &mut m6, t, t, &mut |_, s| {
            s.queued = 0;
            s.fw_halts = n;
        });
    }
    let refill = m6.count(b'L') == 3 && m6.count(b'R') == 0;
    // 8. the record format: written, taken once, a flipped word never reads back
    let record = arch_aarch64::crashrec::heal_selftest();
    // 9. the station set; the published status; no heap use by any of it
    let mut ss = StaSet::new();
    ss.add(&[2, 0, 0, 0, 0, 1]);
    ss.add(&[2, 0, 0, 0, 0, 1]);
    ss.add(&[2, 0, 0, 0, 0, 2]);
    ss.remove(&[2, 0, 0, 0, 0, 1]);
    let sta = ss.len() == 1;
    publish(&h2);
    let st = status().0.starts_with("degraded") && status().5;
    publish(&Heal::from_boot(None, false));
    let heap = crate::heap::used() == heap0;
    let pass = congestion && nosta && sleep && ladder && diag && once && degrade && early && later && crash1 && crash2 && refill && record && sta && st && heap;
    arch_aarch64::_print(format_args!(
        " [P-wifiheal] {} — audit A7 Wi-Fi self-heal: congestion (completions advancing) no action={} no station no action={} power-save / gone station: kicks then no recovery={} freeze ladder kick 100ms/500ms -> bounce 10s -> reload 25s -> reload 85s (60s backoff) -> RebootOnce 100s={} diagnostics captured + recorded before every bounce / reload / reboot={} at most one reboot={} post-reboot recurrence -> Degrade, no reset, halts ignored={} early self-heal counts as rebooted={} new incident after the window={} firmware halt -> reload at once, backoff, failed reload retried, then reboot={}/{} budget refill after 1 h={} record taken once, torn = none={} stations={} status={} heap growth 0={}\n",
        if pass { "PASS" } else { "FAIL" }, congestion, nosta, sleep, ladder, diag, once, degrade, early, later, crash1, crash2, refill, record, sta, st, heap
    ));
    pass
}
