// SPDX-License-Identifier: AGPL-3.0-only
//! Autoheal harness H1 (the 2026-11-18 gap-fix plan at the repository root, `heqk-gap-fix-plan-2026-11-18`, Wave 2b A2 + A10): failure kinds and
//! the recovery journal.
//!
//! Every recovery the kernel performs (an EL0 server restarted after a fault, a Wi-Fi self-heal rung) is one
//! [`Recovery`]: which component, what kind of failure was detected, which rung acted, when it was detected and
//! when it was over, and how it ended. The journal is a fixed ring (no allocation); the oldest entry is overwritten
//! and counted. Pure logic: the kernel owns the clock and the one static instance.
//!
//! An entry opens when the failure is detected and closes when the component is observed working again
//! (`Recovered`), when a higher rung takes over (`Escalated`), or when recovery gave up (`Failed`). A repeat of the
//! same rung on an entry that is still open is folded into it (`repeats`) instead of flooding the ring.

/// How the failure was detected (QNX HAM / MINIX 3 RS trigger channels).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum Kind {
    /// The server took an exception (or reported a panic status).
    Exception = 0,
    /// The server overran its per-call time budget.
    Budget = 1,
    /// The server refused or failed its initialisation.
    InitRefused = 2,
    /// Another component complained about it (H4).
    Complaint = 3,
    /// A functional probe failed (e.g. the Wi-Fi health classifier: TX freeze, firmware halt, bus faults).
    Probe = 4,
    /// An intentional restart (operator / OTA / config).
    Planned = 5,
}

/// What acted.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum Rung {
    /// The server's own reset + restart with backoff.
    Restart = 0,
    /// Wi-Fi: a control-frame kick.
    Kick = 1,
    /// Wi-Fi: a BSS bounce.
    Bounce = 2,
    /// Wi-Fi: a firmware reload.
    Reload = 3,
    /// The one reboot.
    Reboot = 4,
    /// Degrade: the component is switched off for this boot.
    Degrade = 5,
    /// H5: the component used up its CPU budget for this window — its calls are refused until the next window.
    Throttle = 6,
    /// H7: the component's persistent state was wiped (it failed its integrity check, or a fault could not be
    /// contained): a fresh, empty incarnation; whatever depended on that state starts over (stations re-key).
    Wipe = 7,
}

/// How it ended.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum Outcome {
    /// Still open.
    Pending = 0,
    /// The component was observed working again.
    Recovered = 1,
    /// A higher rung took over.
    Escalated = 2,
    /// Recovery gave up (degrade, or the ring overwrote an entry that never closed).
    Failed = 3,
}

impl Kind {
    pub fn name(self) -> &'static str {
        ["exception", "budget-overrun", "init-refused", "complaint", "probe", "planned"][self as usize]
    }
}

impl Rung {
    pub fn name(self) -> &'static str {
        ["restart", "kick", "bounce", "reload", "reboot", "degrade", "throttle", "wipe"][self as usize]
    }
}

impl Outcome {
    pub fn name(self) -> &'static str {
        ["pending", "recovered", "escalated", "failed"][self as usize]
    }
}

pub const KIND_NAMES: [&str; 6] = ["exception", "budget-overrun", "init-refused", "complaint", "probe", "planned"];
pub const OUTCOME_NAMES: [&str; 4] = ["pending", "recovered", "escalated", "failed"];

/// The components that recover, by a stable id (the journal stores the id, the API prints the name).
/// `el0-neuro` (the on-device inference server, a separate track) is listed ahead of its integration so its faults are
/// attributed by name from the first day. At most 8 components (the kernel keeps a u8 bitmask).
pub const COMPONENTS: [&str; 8] = ["el0-wifi", "el0-wpa", "el0-tlshost", "el0-lansvc", "el0-hsh", "wifi", "el0-neuro", "other"];
/// The component ids as constants (hot paths pass an id, never a name; a test pins them to `COMPONENTS`).
pub const C_WIFI_SRV: u8 = 0;
pub const C_WPA: u8 = 1;
pub const C_TLSHOST: u8 = 2;
pub const C_LANSVC: u8 = 3;
pub const C_HSH: u8 = 4;
pub const C_NEURO: u8 = 6;

/// The id of a component name (unknown names map to "other").
pub fn component_id(name: &str) -> u8 {
    COMPONENTS.iter().position(|c| *c == name).unwrap_or(COMPONENTS.len() - 1) as u8
}

pub fn component_name(id: u8) -> &'static str {
    COMPONENTS.get(id as usize).copied().unwrap_or("other")
}

/// One recovery.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Recovery {
    /// Monotonic per boot, from 1.
    pub seq: u32,
    pub component: u8,
    pub kind: Kind,
    pub rung: Rung,
    pub outcome: Outcome,
    /// Further detections folded into this open entry (same component, same rung).
    pub repeats: u16,
    pub t_detect_ms: u64,
    /// When the recovery ACTION itself finished (the server reset, the BSS bounce / firmware reload returned); 0 = not
    /// recorded. `t_done_ms` is later: when the component was OBSERVED working again (a good call, a healthy tick).
    pub t_acted_ms: u64,
    /// 0 while pending.
    pub t_done_ms: u64,
}

impl Recovery {
    /// How long the recovery action took (detection -> the action returned); None when not recorded.
    pub fn action_ms(&self) -> Option<u64> {
        (self.t_acted_ms != 0).then(|| self.t_acted_ms.saturating_sub(self.t_detect_ms))
    }
    /// Time to recover (or to escalate / give up); None while pending.
    pub fn duration_ms(&self) -> Option<u64> {
        (self.outcome != Outcome::Pending).then(|| self.t_done_ms.saturating_sub(self.t_detect_ms))
    }
}

pub const JOURNAL_N: usize = 64;

const EMPTY: Recovery =
    Recovery { seq: 0, component: 0, kind: Kind::Exception, rung: Rung::Restart, outcome: Outcome::Pending, repeats: 0, t_detect_ms: 0, t_acted_ms: 0, t_done_ms: 0 };

/// The recovery journal: a ring of the last `JOURNAL_N` recoveries plus totals that never wrap.
pub struct Journal {
    ring: [Recovery; JOURNAL_N],
    /// Entries ever opened (= the last seq).
    total: u32,
    /// Entries overwritten by newer ones.
    pub dropped: u32,
    /// Entries opened, per `Kind`.
    pub by_kind: [u32; 6],
    /// Entries closed, per `Outcome` (index 0 unused).
    pub by_outcome: [u32; 4],
    /// Bumped by every change (open, repeat, close, acted): the persister writes a snapshot only when it moved.
    gen: u32,
}

impl Default for Journal {
    fn default() -> Self {
        Self::new()
    }
}

impl Journal {
    pub const fn new() -> Self {
        Journal { ring: [EMPTY; JOURNAL_N], total: 0, dropped: 0, by_kind: [0; 6], by_outcome: [0; 4], gen: 0 }
    }

    pub fn total(&self) -> u32 {
        self.total
    }

    pub fn len(&self) -> usize {
        (self.total as usize).min(JOURNAL_N)
    }

    pub fn is_empty(&self) -> bool {
        self.total == 0
    }

    /// Changes so far (wraps): equal values = nothing to persist.
    pub fn generation(&self) -> u32 {
        self.gen
    }

    fn slot(seq: u32) -> usize {
        (seq as usize - 1) % JOURNAL_N
    }

    /// The open entry of a component (at most one is open per component), as a ring index.
    fn open_of(&self, component: u8) -> Option<usize> {
        let n = self.len() as u32;
        (0..n).map(|i| Self::slot(self.total - i)).find(|&s| self.ring[s].component == component && self.ring[s].outcome == Outcome::Pending)
    }

    fn finish(&mut self, s: usize, outcome: Outcome, t_ms: u64) {
        self.gen = self.gen.wrapping_add(1);
        let r = &mut self.ring[s];
        r.outcome = outcome;
        r.t_done_ms = t_ms.max(r.t_detect_ms);
        self.by_outcome[outcome as usize] += 1;
    }

    /// A failure was detected and `rung` is acting on it. A still-open entry of the same component at the same rung
    /// absorbs it (repeats += 1); at a different rung the open entry is closed `Escalated` and a new one opens.
    /// Returns the seq of the entry that now carries it.
    pub fn open(&mut self, component: u8, kind: Kind, rung: Rung, t_ms: u64) -> u32 {
        self.gen = self.gen.wrapping_add(1);
        if let Some(s) = self.open_of(component) {
            if self.ring[s].rung == rung {
                self.ring[s].repeats = self.ring[s].repeats.saturating_add(1);
                return self.ring[s].seq;
            }
            self.finish(s, Outcome::Escalated, t_ms);
        }
        self.total += 1;
        let s = Self::slot(self.total);
        if self.total as usize > JOURNAL_N {
            if self.ring[s].outcome == Outcome::Pending {
                // the ring wrapped over an entry that never closed: count it as given up
                self.by_outcome[Outcome::Failed as usize] += 1;
            }
            self.dropped += 1;
        }
        self.ring[s] = Recovery { seq: self.total, component, kind, rung, outcome: Outcome::Pending, repeats: 0, t_detect_ms: t_ms, t_acted_ms: 0, t_done_ms: 0 };
        self.by_kind[kind as usize] += 1;
        self.total
    }

    /// The component was observed working (or recovery gave up): close its open entry. Returns that entry's seq,
    /// or None when nothing was open (the common case: callers may report every success). `Pending` means
    /// `Recovered`.
    pub fn close(&mut self, component: u8, outcome: Outcome, t_ms: u64) -> Option<u32> {
        let s = self.open_of(component)?;
        self.finish(s, if outcome == Outcome::Pending { Outcome::Recovered } else { outcome }, t_ms);
        Some(self.ring[s].seq)
    }

    /// The recovery action on the component's open entry finished at `t_ms` (first report wins; no open entry: ignored).
    pub fn acted(&mut self, component: u8, t_ms: u64) {
        if let Some(s) = self.open_of(component) {
            let r = &mut self.ring[s];
            if r.t_acted_ms == 0 {
                r.t_acted_ms = t_ms.max(r.t_detect_ms).max(1);
                self.gen = self.gen.wrapping_add(1);
            }
        }
    }

    /// Is an entry of this component open?
    pub fn is_open(&self, component: u8) -> bool {
        self.open_of(component).is_some()
    }

    /// Entries still open.
    pub fn pending(&self) -> u32 {
        self.newest_first().filter(|r| r.outcome == Outcome::Pending).count() as u32
    }

    /// The entries, newest first.
    pub fn newest_first(&self) -> impl Iterator<Item = &Recovery> + '_ {
        let n = self.len() as u32;
        (0..n).map(move |i| &self.ring[Self::slot(self.total - i)])
    }

    /// The entry with this seq, if still in the ring.
    pub fn get(&self, seq: u32) -> Option<&Recovery> {
        if seq == 0 || seq > self.total || self.total - seq >= JOURNAL_N as u32 {
            return None;
        }
        Some(&self.ring[Self::slot(seq)])
    }
}

// --- the journal across a warm reset (H1 follow-up, plan Wave 2c C5) ---
// The kernel keeps a snapshot of the journal in the reserved crash-record page (`crashrec::journal_area`), rewritten
// whenever the journal changes; the next boot takes it once. A watchdog / panic / planned reset keeps DRAM, so the
// boot after it can say what the previous boot recovered from; a power cut loses it (and an invalid or torn snapshot
// reads as none — never as someone else's history).

const SNAP_MAGIC: u64 = u64::from_le_bytes(*b"HQJRNL01");
const SNAP_HDR: usize = 72;
const SNAP_ENT: usize = 24;
/// Bytes of one encoded snapshot (header + every ring slot + check word).
pub const SNAP_LEN: usize = SNAP_HDR + JOURNAL_N * SNAP_ENT + 8;

impl Kind {
    pub fn from_u8(v: u8) -> Option<Kind> {
        [Kind::Exception, Kind::Budget, Kind::InitRefused, Kind::Complaint, Kind::Probe, Kind::Planned].get(v as usize).copied()
    }
}
impl Rung {
    pub fn from_u8(v: u8) -> Option<Rung> {
        [Rung::Restart, Rung::Kick, Rung::Bounce, Rung::Reload, Rung::Reboot, Rung::Degrade, Rung::Throttle, Rung::Wipe].get(v as usize).copied()
    }
}
impl Outcome {
    pub fn from_u8(v: u8) -> Option<Outcome> {
        [Outcome::Pending, Outcome::Recovered, Outcome::Escalated, Outcome::Failed].get(v as usize).copied()
    }
}

fn snap_sum(b: &[u8]) -> u64 {
    // FNV-1a: detects a torn or random page (the reader only reports it; not a security boundary)
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for x in b {
        h ^= *x as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

fn ms32(t: u64) -> u32 {
    t.min(u32::MAX as u64) as u32
}

/// The previous boot's journal, as the next boot read it back (times in ms of THAT boot's uptime, saturated at
/// u32::MAX ~ 49 days).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrevBoot {
    pub total: u32,
    pub dropped: u32,
    pub by_kind: [u32; 6],
    pub by_outcome: [u32; 4],
    /// Uptime of that boot when the snapshot was written (its last journal change).
    pub written_ms: u64,
    /// Entries kept, newest first in `entries[..n]`.
    pub n: usize,
    pub entries: [Recovery; JOURNAL_N],
}

impl PrevBoot {
    pub fn newest_first(&self) -> impl Iterator<Item = &Recovery> + '_ {
        self.entries[..self.n].iter()
    }
}

impl Journal {
    /// Encode the journal (newest first) with `now_ms` as the write time.
    pub fn encode(&self, now_ms: u64, out: &mut [u8; SNAP_LEN]) {
        out.fill(0);
        out[0..8].copy_from_slice(&SNAP_MAGIC.to_le_bytes());
        out[8..12].copy_from_slice(&self.total.to_le_bytes());
        out[12..16].copy_from_slice(&self.dropped.to_le_bytes());
        for (i, v) in self.by_kind.iter().enumerate() {
            out[16 + 4 * i..20 + 4 * i].copy_from_slice(&v.to_le_bytes());
        }
        for (i, v) in self.by_outcome.iter().enumerate() {
            out[40 + 4 * i..44 + 4 * i].copy_from_slice(&v.to_le_bytes());
        }
        out[56..64].copy_from_slice(&now_ms.to_le_bytes());
        let n = self.len();
        out[64..68].copy_from_slice(&(n as u32).to_le_bytes());
        for (k, r) in self.newest_first().enumerate() {
            let o = SNAP_HDR + k * SNAP_ENT;
            out[o..o + 4].copy_from_slice(&r.seq.to_le_bytes());
            out[o + 4] = r.component;
            out[o + 5] = r.kind as u8;
            out[o + 6] = r.rung as u8;
            out[o + 7] = r.outcome as u8;
            out[o + 8..o + 10].copy_from_slice(&r.repeats.to_le_bytes());
            out[o + 12..o + 16].copy_from_slice(&ms32(r.t_detect_ms).to_le_bytes());
            out[o + 16..o + 20].copy_from_slice(&ms32(r.t_acted_ms).to_le_bytes());
            out[o + 20..o + 24].copy_from_slice(&ms32(r.t_done_ms).to_le_bytes());
        }
        let sum = snap_sum(&out[..SNAP_LEN - 8]);
        out[SNAP_LEN - 8..].copy_from_slice(&sum.to_le_bytes());
    }
}

/// Read a snapshot back. None = no snapshot (never written, cleared, a power cut) or one that fails its check or
/// holds a value no journal could have written.
pub fn decode_snapshot(b: &[u8]) -> Option<PrevBoot> {
    if b.len() < SNAP_LEN {
        return None;
    }
    let u32_at = |o: usize| u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]]);
    let u64_at = |o: usize| u64::from_le_bytes(b[o..o + 8].try_into().unwrap_or([0; 8]));
    if u64_at(0) != SNAP_MAGIC || u64_at(SNAP_LEN - 8) != snap_sum(&b[..SNAP_LEN - 8]) {
        return None;
    }
    let n = u32_at(64) as usize;
    let total = u32_at(8);
    if n > JOURNAL_N || n as u64 > total as u64 {
        return None;
    }
    let mut p = PrevBoot { total, dropped: u32_at(12), by_kind: [0; 6], by_outcome: [0; 4], written_ms: u64_at(56), n, entries: [EMPTY; JOURNAL_N] };
    for i in 0..6 {
        p.by_kind[i] = u32_at(16 + 4 * i);
    }
    for i in 0..4 {
        p.by_outcome[i] = u32_at(40 + 4 * i);
    }
    for k in 0..n {
        let o = SNAP_HDR + k * SNAP_ENT;
        p.entries[k] = Recovery {
            seq: u32_at(o),
            component: b[o + 4],
            kind: Kind::from_u8(b[o + 5])?,
            rung: Rung::from_u8(b[o + 6])?,
            outcome: Outcome::from_u8(b[o + 7])?,
            repeats: u16::from_le_bytes([b[o + 8], b[o + 9]]),
            t_detect_ms: u32_at(o + 12) as u64,
            t_acted_ms: u32_at(o + 16) as u64,
            t_done_ms: u32_at(o + 20) as u64,
        };
    }
    Some(p)
}

/// What happens when a component's own recovery is exhausted (plan Wave 2c C1 / C3).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum Exhausted {
    /// Keep restarting at the capped backoff (the service is refused meanwhile: fail closed).
    KeepRestarting = 0,
    /// Switch the component off for this boot and run degraded.
    Degrade = 1,
    /// One reboot, then degrade (only `critical` entries may name this).
    RebootOnce = 2,
}

impl Exhausted {
    pub fn name(self) -> &'static str {
        ["keep-restarting", "degrade", "reboot-once"][self as usize]
    }
}

/// One supervised component: the policy the single restart owner (the kernel) applies to it. The table is part of
/// the signed image — nothing at run time can make a component critical or change its policy.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Entry {
    pub name: &'static str,
    /// May escalate to the reboot rung. Everything else stops at degrade / refusal.
    pub critical: bool,
    pub exhausted: Exhausted,
    /// Consecutive faults restarted with no hold-off (a one-off fault costs the service nothing).
    pub grace: u8,
    /// The first hold-off after the grace; doubles per further consecutive fault up to `backoff_max_ms`.
    pub backoff_ms: u64,
    pub backoff_max_ms: u64,
    /// H3b: how long the component must run WITHOUT a fault before its streak is forgotten. 0 = one good call
    /// forgets it. Non-zero closes the flapping hole: a server that alternates fault / good call would otherwise
    /// restart on every other call for ever, never held off. The station-facing Wi-Fi servers keep 0 — a hostile
    /// station that can fault them must not be able to stretch the refusal window for every other station (they
    /// have their own bounds: per-station poisoning in el0-wpa, the bus-fault ladder for el0-wifi).
    pub stable_ms: u64,
    /// H5: the CPU the component may use per `CPU_WINDOW_MS` window, in ms (0 = measured only, never throttled). Each
    /// call is already bounded; this bounds the SUM — a server that is called (or made to work) so often that it
    /// would starve the main loop is refused until the next window, fail closed, and the episode is journaled.
    /// The Wi-Fi servers are measured only: el0-wifi IS the data path, and el0-wpa's SAE work comes in bursts whose
    /// size is set by how many stations join — both need metal numbers before a limit is honest.
    pub cpu_ms_per_window: u32,
    /// H7: what survives the component's own restart.
    pub state: StateClass,
}

/// H7: what a component keeps across its own restart — so the recovery for it is known up front.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum StateClass {
    /// Nothing between calls: a restart restores the signed image and loses nothing.
    Stateless,
    /// State lives only in the incarnation (TLS sessions, bus / firmware state): a restart loses it and the users
    /// start over (reconnect, re-init).
    Volatile,
    /// State pages kept ACROSS a restart (el0-wpa: PMKSA cache, SAE / 4-way state, keys). Reused only after an
    /// integrity check; a slot that fails it is never reused — the pages are wiped (rung wipe) and stations re-key.
    Persistent,
}

impl StateClass {
    pub fn name(self) -> &'static str {
        match self {
            StateClass::Stateless => "stateless",
            StateClass::Volatile => "volatile",
            StateClass::Persistent => "persistent",
        }
    }
}

/// The supervisor table. `wifi` is the Wi-Fi link as a whole (its ladder lives in `wifiheal`): the only critical
/// entry — its ladder ends in one reboot, then degrade. The EL0 servers restart in place and never reboot the device.
pub const TABLE: [Entry; 7] = [
    Entry { name: "el0-wifi", critical: false, exhausted: Exhausted::KeepRestarting, grace: 0, backoff_ms: 50, backoff_max_ms: 5_000, stable_ms: 0, cpu_ms_per_window: 0, state: StateClass::Volatile },
    Entry { name: "el0-wpa", critical: false, exhausted: Exhausted::KeepRestarting, grace: 0, backoff_ms: 50, backoff_max_ms: 5_000, stable_ms: 0, cpu_ms_per_window: 0, state: StateClass::Persistent },
    Entry { name: "el0-tlshost", critical: false, exhausted: Exhausted::KeepRestarting, grace: 1, backoff_ms: 50, backoff_max_ms: 5_000, stable_ms: 10_000, cpu_ms_per_window: 500, state: StateClass::Volatile },
    Entry { name: "el0-lansvc", critical: false, exhausted: Exhausted::KeepRestarting, grace: 1, backoff_ms: 50, backoff_max_ms: 5_000, stable_ms: 10_000, cpu_ms_per_window: 500, state: StateClass::Stateless },
    Entry { name: "el0-hsh", critical: false, exhausted: Exhausted::KeepRestarting, grace: 1, backoff_ms: 50, backoff_max_ms: 5_000, stable_ms: 10_000, cpu_ms_per_window: 500, state: StateClass::Stateless },
    Entry { name: "wifi", critical: true, exhausted: Exhausted::RebootOnce, grace: 0, backoff_ms: 0, backoff_max_ms: 0, stable_ms: 0, cpu_ms_per_window: 0, state: StateClass::Volatile },
    Entry { name: "el0-neuro", critical: false, exhausted: Exhausted::Degrade, grace: 1, backoff_ms: 50, backoff_max_ms: 5_000, stable_ms: 10_000, cpu_ms_per_window: 200, state: StateClass::Volatile },
];

/// The table entry of a component (None = not supervised by name).
pub fn entry(name: &str) -> Option<&'static Entry> {
    TABLE.iter().find(|e| e.name == name)
}

impl Entry {
    /// The hold-off after the `streak`-th consecutive fault (streak >= 1): 0 inside the grace, then
    /// `backoff_ms << n`, capped.
    pub fn hold_ms(&self, streak: u32) -> u64 {
        if streak <= self.grace as u32 {
            return 0;
        }
        let n = (streak - self.grace as u32 - 1).min(20);
        (self.backoff_ms << n).min(self.backoff_max_ms)
    }
}

/// One component's restart state under the table policy: the fault streak and when the next call may run. The one
/// place the backoff is computed — every EL0 server embeds one (no server restarts in a tight loop).
#[derive(Clone, Copy, Debug)]
pub struct Sup {
    pub entry: &'static Entry,
    pub streak: u32,
    pub next_ok_ms: u64,
    /// When the last fault happened (the streak is forgotten `entry.stable_ms` after it).
    pub last_fault_ms: u64,
    /// A fault since the last good call (the journal's close signal).
    open: bool,
}

impl Sup {
    pub const fn new(entry: &'static Entry) -> Self {
        Sup { entry, streak: 0, next_ok_ms: 0, last_fault_ms: 0, open: false }
    }
    /// May a call run now?
    pub fn ready(&self, now_ms: u64) -> bool {
        now_ms >= self.next_ok_ms
    }
    /// Hold-off left (0 = ready).
    pub fn left_ms(&self, now_ms: u64) -> u64 {
        self.next_ok_ms.saturating_sub(now_ms)
    }
    /// The component faulted (it has been reset): returns the hold-off before its next call. A streak older than
    /// the entry's stable period is forgotten first.
    pub fn fault(&mut self, now_ms: u64) -> u64 {
        if self.entry.stable_ms > 0 && self.streak > 0 && now_ms.saturating_sub(self.last_fault_ms) >= self.entry.stable_ms {
            self.streak = 0;
        }
        self.streak = self.streak.saturating_add(1);
        self.last_fault_ms = now_ms;
        self.open = true;
        let h = self.entry.hold_ms(self.streak);
        self.next_ok_ms = now_ms + h;
        h
    }
    /// A fault that does NOT count for the policy (a self-test's deliberate one): only the journal's close signal.
    pub fn fault_uncounted(&mut self) {
        self.open = true;
    }
    /// A good call. Returns whether it ended a fault episode (the journal's close signal). With `stable_ms == 0` the
    /// streak is forgotten at once; otherwise it stays until the component has been fault-free for that long.
    pub fn ok(&mut self) -> bool {
        let was = self.open;
        self.open = false;
        if self.entry.stable_ms == 0 {
            self.streak = 0;
        }
        was
    }
}

/// The CPU budget of a component id, without a table search (the el0-wifi call path runs once per frame). A test
/// pins it to the table.
pub const fn cpu_budget_ms(c: u8) -> u32 {
    match c {
        C_TLSHOST | C_LANSVC | C_HSH => 500,
        C_NEURO => 200,
        _ => 0,
    }
}

/// H5: the accounting window of the per-component CPU budget.
pub const CPU_WINDOW_MS: u64 = 1_000;

/// One component's CPU use in the current window. Pure: the kernel owns the clock and measures each excursion.
#[derive(Clone, Copy, Debug)]
pub struct CpuWindow {
    start_ms: u64,
    used_us: u64,
    tripped: bool,
    /// What the previous full window used.
    pub last_us: u64,
    /// The most any window used since boot.
    pub peak_us: u64,
    /// Windows in which the budget ran out.
    pub throttled_windows: u32,
    /// Calls refused because of it.
    pub refused_calls: u64,
}

impl Default for CpuWindow {
    fn default() -> Self {
        Self::new()
    }
}

impl CpuWindow {
    pub const fn new() -> Self {
        CpuWindow { start_ms: 0, used_us: 0, tripped: false, last_us: 0, peak_us: 0, throttled_windows: 0, refused_calls: 0 }
    }
    fn roll(&mut self, now_ms: u64) {
        if now_ms.saturating_sub(self.start_ms) >= CPU_WINDOW_MS {
            self.last_us = self.used_us;
            self.peak_us = self.peak_us.max(self.used_us);
            self.used_us = 0;
            self.start_ms = now_ms;
            self.tripped = false;
        }
    }
    /// May a call run now under `budget_ms` per window (0 = unlimited)? Returns (admitted, this is the first refusal
    /// of the window — the moment to journal the episode).
    pub fn admit(&mut self, now_ms: u64, budget_ms: u32) -> (bool, bool) {
        self.roll(now_ms);
        if budget_ms == 0 || self.used_us < budget_ms as u64 * 1_000 {
            return (true, false);
        }
        let first = !self.tripped;
        self.tripped = true;
        if first {
            self.throttled_windows += 1;
        }
        self.refused_calls += 1;
        (false, first)
    }
    /// A call of this component took `us`.
    pub fn charge(&mut self, us: u64) {
        self.used_us = self.used_us.saturating_add(us);
        self.peak_us = self.peak_us.max(self.used_us);
    }
    /// Use in the current window so far.
    pub fn used_us(&self) -> u64 {
        self.used_us
    }
}

/// H4a functional probes: every `PROBE_PERIOD_MS` the kernel asks ONE supervised server (in turn) a question whose
/// answer it knows. A server that answers wrongly WITHOUT faulting (corrupted data, a wedged state machine) is
/// invisible to the fault path; a failed probe restarts it like a fault (kind `probe`). Pure schedule: which
/// probe slot is due.
pub const PROBE_PERIOD_MS: u64 = 15_000;

pub struct ProbeClock {
    next_ms: u64,
    turn: u8,
}

impl Default for ProbeClock {
    fn default() -> Self {
        Self::new()
    }
}

impl ProbeClock {
    pub const fn new() -> Self {
        ProbeClock { next_ms: PROBE_PERIOD_MS, turn: 0 }
    }
    /// The slot (0..slots) to probe now, if one is due. At most one per call; a long stall never causes a burst.
    pub fn due(&mut self, now_ms: u64, slots: u8) -> Option<u8> {
        if slots == 0 || now_ms < self.next_ms {
            return None;
        }
        self.next_ms = now_ms + PROBE_PERIOD_MS;
        let t = self.turn % slots;
        self.turn = (t + 1) % slots;
        Some(t)
    }
}

/// Planned-reset codes (written before the reset, `arch crashrec::write_planned`).
pub const PLANNED_OWNER_REBOOT: u32 = 1;
pub const PLANNED_OTA_TRIAL: u32 = 2;
pub const PLANNED_OTA_REVERT: u32 = 3;
pub const PLANNED_FACTORY_RESET: u32 = 4;
pub const PLANNED_CONFIG_REVERT: u32 = 5;

/// Why the previous boot ended (plan Wave 2c C5: reason + culprit, as Fuchsia's last-reboot record): from the crash
/// record the previous boot left (`crash_kind` 1 = panic, 2 = kernel fault, 3 = self-heal reset; its text), the
/// planned-reset reason it wrote, and whether the reset was watchdog-type. A crash record wins over a planned
/// reason (a panic on the way down is the news). The culprit is the component that caused it, when one is known —
/// a generic reason (a watchdog reset with no record) names none rather than guess.
pub fn last_boot_reason(crash_kind: Option<u32>, text: &str, planned: Option<u32>, watchdog: bool) -> (&'static str, Option<&'static str>) {
    match (crash_kind, planned) {
        (Some(1), _) => ("kernel-panic", Some("kernel")),
        (Some(2), _) => ("kernel-fault", Some("kernel")),
        (Some(_), _) => ("self-heal-reset", if text.starts_with("Wi-Fi") { Some("wifi") } else { None }),
        (None, Some(PLANNED_OWNER_REBOOT)) => ("owner-reboot", None),
        (None, Some(PLANNED_OTA_TRIAL)) => ("ota-trial", None),
        (None, Some(PLANNED_OTA_REVERT)) => ("ota-revert", Some("ota")),
        (None, Some(PLANNED_FACTORY_RESET)) => ("factory-reset", None),
        (None, Some(PLANNED_CONFIG_REVERT)) => ("config-revert", Some("config")),
        (None, Some(_)) => ("planned", None),
        (None, None) if watchdog => ("watchdog", None),
        (None, None) => ("power-on", None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;
    use std::vec::Vec;

    const W: u8 = 0;
    const H: u8 = 5;

    #[test]
    fn open_close_recovered() {
        let mut j = Journal::new();
        assert_eq!(j.open(W, Kind::Exception, Rung::Restart, 1_000), 1);
        assert!(j.is_open(W));
        assert_eq!(j.close(W, Outcome::Recovered, 1_060), Some(1));
        let r = j.get(1).unwrap();
        assert_eq!(r.outcome, Outcome::Recovered);
        assert_eq!(r.duration_ms(), Some(60));
        assert!(!j.is_open(W));
        assert_eq!(j.close(W, Outcome::Recovered, 2_000), None);
        assert_eq!(j.by_kind[Kind::Exception as usize], 1);
        assert_eq!(j.by_outcome[Outcome::Recovered as usize], 1);
    }

    #[test]
    fn same_rung_folds_into_open_entry() {
        let mut j = Journal::new();
        j.open(W, Kind::Exception, Rung::Restart, 10);
        assert_eq!(j.open(W, Kind::Budget, Rung::Restart, 20), 1);
        assert_eq!(j.open(W, Kind::Exception, Rung::Restart, 30), 1);
        assert_eq!(j.total(), 1);
        assert_eq!(j.get(1).unwrap().repeats, 2);
    }

    #[test]
    fn higher_rung_escalates() {
        let mut j = Journal::new();
        j.open(H, Kind::Probe, Rung::Kick, 100);
        assert_eq!(j.open(H, Kind::Probe, Rung::Bounce, 300), 2);
        assert_eq!(j.get(1).unwrap().outcome, Outcome::Escalated);
        assert_eq!(j.get(1).unwrap().duration_ms(), Some(200));
        assert_eq!(j.pending(), 1);
        j.close(H, Outcome::Recovered, 900);
        assert_eq!(j.pending(), 0);
    }

    #[test]
    fn action_time_is_separate_from_recovery_time() {
        let mut j = Journal::new();
        j.acted(H, 5); // nothing open: ignored
        j.open(H, Kind::Probe, Rung::Reload, 1_000);
        assert_eq!(j.get(1).unwrap().action_ms(), None);
        j.acted(H, 1_830);
        j.acted(H, 9_999); // the first report wins
        j.close(H, Outcome::Recovered, 6_000);
        let r = j.get(1).unwrap();
        assert_eq!((r.action_ms(), r.duration_ms()), (Some(830), Some(5_000)));
    }

    #[test]
    fn components_are_independent() {
        let mut j = Journal::new();
        j.open(W, Kind::Exception, Rung::Restart, 1);
        j.open(H, Kind::Probe, Rung::Reload, 2);
        assert_eq!(j.close(W, Outcome::Recovered, 3), Some(1));
        assert!(j.is_open(H));
    }

    #[test]
    fn ring_wraps_and_counts() {
        let mut j = Journal::new();
        for i in 0..(JOURNAL_N as u64 + 10) {
            j.open(W, Kind::Exception, Rung::Restart, i * 10);
            j.close(W, Outcome::Recovered, i * 10 + 5);
        }
        assert_eq!(j.total(), JOURNAL_N as u32 + 10);
        assert_eq!(j.len(), JOURNAL_N);
        assert_eq!(j.dropped, 10);
        assert!(j.get(10).is_none());
        assert_eq!(j.get(11).unwrap().seq, 11);
        let v: Vec<u32> = j.newest_first().map(|r| r.seq).collect();
        assert_eq!(v[0], JOURNAL_N as u32 + 10);
        assert_eq!(*v.last().unwrap(), 11);
        assert_eq!(j.by_outcome[Outcome::Recovered as usize], JOURNAL_N as u32 + 10);
    }

    #[test]
    fn wrapped_pending_counts_failed() {
        let mut j = Journal::new();
        j.open(H, Kind::Probe, Rung::Degrade, 0);
        for i in 0..JOURNAL_N as u64 {
            j.open(W, Kind::Exception, Rung::Restart, i);
            j.close(W, Outcome::Recovered, i);
        }
        assert_eq!(j.by_outcome[Outcome::Failed as usize], 1);
        assert!(!j.is_open(H));
    }

    #[test]
    fn last_boot() {
        assert_eq!(last_boot_reason(None, "", None, false), ("power-on", None));
        assert_eq!(last_boot_reason(None, "", None, true), ("watchdog", None));
        assert_eq!(last_boot_reason(Some(1), "panicked at x", None, true), ("kernel-panic", Some("kernel")));
        assert_eq!(last_boot_reason(Some(2), "Sync/SPx", None, true), ("kernel-fault", Some("kernel")));
        assert_eq!(last_boot_reason(Some(3), "Wi-Fi recovery exhausted: x", None, true), ("self-heal-reset", Some("wifi")));
        assert_eq!(last_boot_reason(Some(3), "something else", None, true), ("self-heal-reset", None));
        // planned resets are named; a watchdog-type reset flag never hides them; a crash record wins over them
        assert_eq!(last_boot_reason(None, "", Some(PLANNED_OWNER_REBOOT), true), ("owner-reboot", None));
        assert_eq!(last_boot_reason(None, "", Some(PLANNED_OTA_TRIAL), false), ("ota-trial", None));
        assert_eq!(last_boot_reason(None, "", Some(PLANNED_OTA_REVERT), true), ("ota-revert", Some("ota")));
        assert_eq!(last_boot_reason(None, "", Some(PLANNED_FACTORY_RESET), true), ("factory-reset", None));
        assert_eq!(last_boot_reason(None, "", Some(PLANNED_CONFIG_REVERT), true), ("config-revert", Some("config")));
        assert_eq!(last_boot_reason(None, "", Some(99), true), ("planned", None));
        assert_eq!(last_boot_reason(Some(1), "p", Some(PLANNED_OTA_TRIAL), true), ("kernel-panic", Some("kernel")));
    }

    #[test]
    fn table_is_sane() {
        for e in TABLE.iter() {
            assert!(COMPONENTS.contains(&e.name), "{} not a journal component", e.name);
            // only a critical entry may name the reboot rung
            assert!(e.critical || e.exhausted != Exhausted::RebootOnce, "{}", e.name);
            assert!(e.backoff_ms <= e.backoff_max_ms);
        }
        assert_eq!(TABLE.iter().filter(|e| e.critical).count(), 1);
        assert!(entry("wifi").unwrap().critical);
        assert!(entry("nope").is_none());
    }

    #[test]
    fn backoff_policy() {
        let w = entry("el0-wifi").unwrap();
        assert_eq!([w.hold_ms(1), w.hold_ms(2), w.hold_ms(3), w.hold_ms(8), w.hold_ms(40)], [50, 100, 200, 5_000, 5_000]);
        let t = entry("el0-tlshost").unwrap();
        assert_eq!([t.hold_ms(1), t.hold_ms(2), t.hold_ms(3)], [0, 50, 100]);
        let mut s = Sup::new(t);
        assert!(s.ready(0));
        assert_eq!(s.fault(1_000), 0); // the grace: a one-off fault restarts at once
        assert!(s.ready(1_000));
        assert_eq!(s.fault(1_000), 50); // a second in a row: held off
        assert!(!s.ready(1_049) && s.ready(1_050));
        assert_eq!(s.left_ms(1_010), 40);
        assert!(s.ok());
        assert!(!s.ok());
        assert_eq!(s.fault(2_000), 100); // H3b: a good call does not forget the streak (flapping)...
        assert!(s.ok());
        assert_eq!(s.fault(2_000 + t.stable_ms), 0); // ...a fault-free stable period does
        // a server that faults on every call never restarts faster than the cap allows
        let mut loopy = Sup::new(t);
        let (mut now, mut restarts) = (0u64, 0u32);
        while now < 60_000 {
            if loopy.ready(now) {
                loopy.fault(now);
                restarts += 1;
            }
            now += 1;
        }
        assert!(restarts < 25, "{restarts} restarts in 60 s");
    }

    #[test]
    fn flapping_is_held_off() {
        // a server that alternates fault / good call: with a stable period the hold-off still grows to the cap
        let t = entry("el0-tlshost").unwrap();
        assert!(t.stable_ms > 0);
        let mut s = Sup::new(t);
        let (mut now, mut restarts, mut last_hold) = (0u64, 0u32, 0u64);
        while now < 60_000 {
            if s.ready(now) {
                last_hold = s.fault(now);
                restarts += 1;
                now += last_hold + 1;
                assert!(s.ready(now));
                assert!(s.ok()); // the call after the restart works...
                assert!(!s.ok());
            } else {
                now += 1;
            }
        }
        assert_eq!(last_hold, t.backoff_max_ms); // ...and yet it reached the cap
        assert!(restarts < 30, "{restarts} restarts in 60 s of flapping");
        // fault-free for the stable period: forgotten, the next one-off fault restarts at once again
        assert_eq!(s.fault(now + t.stable_ms), 0);
        // the station-facing servers forget at the first good call (a hostile station must not stretch the window)
        let w = entry("el0-wpa").unwrap();
        assert_eq!(w.stable_ms, 0);
        let mut s = Sup::new(w);
        for i in 0..20u64 {
            assert_eq!(s.fault(i * 1_000), 50);
            assert!(s.ok());
        }
    }

    #[test]
    fn cpu_window() {
        // the ids used on hot paths are the journal's
        for (id, name) in [(C_WIFI_SRV, "el0-wifi"), (C_WPA, "el0-wpa"), (C_TLSHOST, "el0-tlshost"), (C_LANSVC, "el0-lansvc"), (C_HSH, "el0-hsh"), (C_NEURO, "el0-neuro")] {
            assert_eq!(component_id(name), id);
        }
        for e in TABLE.iter() {
            assert_eq!(cpu_budget_ms(component_id(e.name)), e.cpu_ms_per_window, "{}", e.name);
        }
        assert_eq!(cpu_budget_ms(component_id("other")), 0);
        // the data-path server is never throttled; a per-call budget can never exceed the window budget's meaning
        assert_eq!(entry("el0-wifi").unwrap().cpu_ms_per_window, 0);
        assert!(TABLE.iter().all(|e| (e.cpu_ms_per_window as u64) < CPU_WINDOW_MS));
        let mut w = CpuWindow::new();
        // unlimited: measured, never refused
        w.charge(900_000);
        assert_eq!(w.admit(10, 0), (true, false));
        // a 200 ms budget: admitted until the sum reaches it, then refused for the rest of the window
        let mut w = CpuWindow::new();
        assert_eq!(w.admit(0, 200), (true, false));
        w.charge(150_000);
        assert_eq!(w.admit(100, 200), (true, false));
        w.charge(60_000); // 210 ms: one call may overshoot by at most its own (already bounded) length
        assert_eq!(w.admit(200, 200), (false, true)); // the first refusal: journal it
        assert_eq!(w.admit(300, 200), (false, false));
        assert_eq!(w.admit(999, 200), (false, false));
        assert_eq!((w.throttled_windows, w.refused_calls), (1, 3));
        // the next window: admitted again, the last window's use and the peak are kept
        assert_eq!(w.admit(1_000, 200), (true, false));
        assert_eq!((w.last_us, w.peak_us, w.used_us()), (210_000, 210_000, 0));
        // a second episode counts a second throttled window
        w.charge(200_000);
        assert_eq!(w.admit(1_500, 200), (false, true));
        assert_eq!(w.throttled_windows, 2);
        // a long idle gap rolls once, cleanly
        assert_eq!(w.admit(60_000, 200), (true, false));
        assert_eq!(w.used_us(), 0);
    }

    #[test]
    fn probe_clock() {
        let mut c = ProbeClock::new();
        assert_eq!(c.due(0, 2), None);
        assert_eq!(c.due(PROBE_PERIOD_MS - 1, 2), None);
        assert_eq!(c.due(PROBE_PERIOD_MS, 2), Some(0));
        assert_eq!(c.due(PROBE_PERIOD_MS + 1, 2), None); // one per period
        assert_eq!(c.due(2 * PROBE_PERIOD_MS, 2), Some(1));
        // a long stall: one probe, not a burst
        assert_eq!(c.due(100 * PROBE_PERIOD_MS, 2), Some(0));
        assert_eq!(c.due(100 * PROBE_PERIOD_MS + 5, 2), None);
        assert_eq!(c.due(u64::MAX / 2, 0), None);
    }

    #[test]
    fn snapshot_round_trip() {
        let mut j = Journal::new();
        let g0 = j.generation();
        j.open(1, Kind::Probe, Rung::Wipe, 100);
        j.acted(1, 120);
        j.close(1, Outcome::Pending, 300);
        j.open(2, Kind::Exception, Rung::Restart, 400);
        j.open(2, Kind::Exception, Rung::Restart, 401); // a repeat
        assert!(j.generation() != g0);
        let g1 = j.generation();
        j.close(9, Outcome::Pending, 500); // nothing open: no change
        assert_eq!(j.generation(), g1);
        let mut b = [0u8; SNAP_LEN];
        j.encode(777, &mut b);
        let p = decode_snapshot(&b).expect("valid snapshot");
        assert_eq!((p.total, p.n, p.written_ms, p.by_kind, p.by_outcome), (2, 2, 777, j.by_kind, j.by_outcome));
        let got: Vec<Recovery> = p.newest_first().copied().collect();
        let want: Vec<Recovery> = j.newest_first().copied().collect();
        assert_eq!(got, want);
        assert_eq!(got[0].repeats, 1);
        assert_eq!(got[1].rung, Rung::Wipe);
        // any flipped byte, a cleared page, a short buffer: no snapshot
        for i in [0, 9, 70, SNAP_HDR + 5, SNAP_LEN - 1] {
            let mut c = b;
            c[i] ^= 0x20;
            assert_eq!(decode_snapshot(&c), None, "byte {}", i);
        }
        assert_eq!(decode_snapshot(&[0u8; SNAP_LEN]), None);
        assert_eq!(decode_snapshot(&b[..SNAP_LEN - 1]), None);
        // a wrapped ring keeps the newest JOURNAL_N, newest first
        let mut w = Journal::new();
        for t in 0..(JOURNAL_N as u64 + 10) {
            w.open((t % 5) as u8, Kind::Budget, Rung::Throttle, t);
            w.close((t % 5) as u8, Outcome::Pending, t + 1);
        }
        w.encode(1, &mut b);
        let p = decode_snapshot(&b).unwrap();
        assert_eq!((p.n, p.total, p.dropped), (JOURNAL_N, JOURNAL_N as u32 + 10, 10));
        assert_eq!(p.entries[0].seq, JOURNAL_N as u32 + 10);
        // an empty journal is a valid snapshot ("nothing happened"), unlike no snapshot at all
        Journal::new().encode(5, &mut b);
        assert_eq!(decode_snapshot(&b).map(|p| (p.total, p.n)), Some((0, 0)));
        assert!(SNAP_LEN <= 0x800);
    }

    #[test]
    fn state_classes() {
        // only el0-wpa keeps state across its own restart (and so is the only one that can need a wipe)
        let persistent: usize = TABLE.iter().filter(|e| e.state == StateClass::Persistent).count();
        assert_eq!(persistent, 1);
        assert_eq!(entry("el0-wpa").map(|e| e.state), Some(StateClass::Persistent));
        assert_eq!(entry("el0-lansvc").map(|e| e.state), Some(StateClass::Stateless));
        assert_eq!(entry("el0-tlshost").map(|e| e.state), Some(StateClass::Volatile));
    }

    #[test]
    fn names() {
        assert_eq!(component_id("el0-tlshost"), 2);
        assert_eq!(component_id("nope"), 7);
        assert_eq!(component_id("el0-neuro"), 6);
        assert_eq!(component_name(component_id("wifi")), "wifi");
        assert_eq!(Kind::Budget.name(), KIND_NAMES[1]);
        assert_eq!(Rung::Reload.name(), "reload");
        assert_eq!(Rung::Throttle.name(), "throttle");
        assert_eq!(Rung::Wipe.name(), "wipe");
        assert_eq!(StateClass::Persistent.name(), "persistent");
        assert_eq!(Outcome::Escalated.name(), OUTCOME_NAMES[2]);
    }
}
