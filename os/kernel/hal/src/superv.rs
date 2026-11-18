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
        ["restart", "kick", "bounce", "reload", "reboot", "degrade"][self as usize]
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
    /// 0 while pending.
    pub t_done_ms: u64,
}

impl Recovery {
    /// Time to recover (or to escalate / give up); None while pending.
    pub fn duration_ms(&self) -> Option<u64> {
        (self.outcome != Outcome::Pending).then(|| self.t_done_ms.saturating_sub(self.t_detect_ms))
    }
}

pub const JOURNAL_N: usize = 64;

const EMPTY: Recovery =
    Recovery { seq: 0, component: 0, kind: Kind::Exception, rung: Rung::Restart, outcome: Outcome::Pending, repeats: 0, t_detect_ms: 0, t_done_ms: 0 };

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
}

impl Default for Journal {
    fn default() -> Self {
        Self::new()
    }
}

impl Journal {
    pub const fn new() -> Self {
        Journal { ring: [EMPTY; JOURNAL_N], total: 0, dropped: 0, by_kind: [0; 6], by_outcome: [0; 4] }
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

    fn slot(seq: u32) -> usize {
        (seq as usize - 1) % JOURNAL_N
    }

    /// The open entry of a component (at most one is open per component), as a ring index.
    fn open_of(&self, component: u8) -> Option<usize> {
        let n = self.len() as u32;
        (0..n).map(|i| Self::slot(self.total - i)).find(|&s| self.ring[s].component == component && self.ring[s].outcome == Outcome::Pending)
    }

    fn finish(&mut self, s: usize, outcome: Outcome, t_ms: u64) {
        let r = &mut self.ring[s];
        r.outcome = outcome;
        r.t_done_ms = t_ms.max(r.t_detect_ms);
        self.by_outcome[outcome as usize] += 1;
    }

    /// A failure was detected and `rung` is acting on it. A still-open entry of the same component at the same rung
    /// absorbs it (repeats += 1); at a different rung the open entry is closed `Escalated` and a new one opens.
    /// Returns the seq of the entry that now carries it.
    pub fn open(&mut self, component: u8, kind: Kind, rung: Rung, t_ms: u64) -> u32 {
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
        self.ring[s] = Recovery { seq: self.total, component, kind, rung, outcome: Outcome::Pending, repeats: 0, t_detect_ms: t_ms, t_done_ms: 0 };
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
    fn names() {
        assert_eq!(component_id("el0-tlshost"), 2);
        assert_eq!(component_id("nope"), 7);
        assert_eq!(component_id("el0-neuro"), 6);
        assert_eq!(component_name(component_id("wifi")), "wifi");
        assert_eq!(Kind::Budget.name(), KIND_NAMES[1]);
        assert_eq!(Rung::Reload.name(), "reload");
        assert_eq!(Outcome::Escalated.name(), OUTCOME_NAMES[2]);
    }
}
