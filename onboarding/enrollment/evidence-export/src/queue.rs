//! The export queue: what has been synced, what is in flight, and when to try again.
//!
//! * **Synced, not deleted.** [`SyncState::synced`] is the log position everything before which
//!   the control plane has acknowledged. It only moves on a matching ack and only forward. There
//!   is no operation here that removes or rewrites local evidence: the log keeps its own ring
//!   retention, and export only marks.
//! * **Monotonic batches.** Every frame gets a fresh `batch_seq` that is never reused, not even
//!   after a reboot ([`SyncState`] persists the next one).
//! * **Cumulative acks.** An ack for batch `k` covers every earlier batch. An ack for a batch
//!   that was never sent, that is already covered, or whose end position does not match what was
//!   sent is ignored and counted.
//! * **Offline.** Not enrolled: nothing is attempted and nothing changes (standalone is the
//!   default, never an error). Enrolled but unreachable: the queue keeps its position and waits
//!   with a capped, deterministic exponential backoff. An unacked batch times out and the queue
//!   rewinds to `synced`, resending the same events in new batches; the receiver de-duplicates on
//!   the log cursor.

use crate::wire::{Ack, Cursor};

/// The part of the queue that must survive a reboot. The kernel seals and stores
/// [`SyncState::encode`] (ADR 0066: a new fslog record type).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SyncState {
    /// Everything before this position is acknowledged.
    pub synced: Cursor,
    /// The next batch number to use.
    pub next_batch: u64,
}

pub const SYNC_STATE_LEN: usize = 32;
const SYNC_MAGIC: &[u8; 4] = b"HQXC";

impl SyncState {
    /// `"HQXC" | version u16 = 1 | idx u8 | 0 | log_seq u64 | next_batch u64 | SHA-256[..8]`.
    pub fn encode(&self) -> [u8; SYNC_STATE_LEN] {
        let mut b = [0u8; SYNC_STATE_LEN];
        b[0..4].copy_from_slice(SYNC_MAGIC);
        b[4..6].copy_from_slice(&1u16.to_le_bytes());
        b[6] = self.synced.idx;
        b[8..16].copy_from_slice(&self.synced.log_seq.to_le_bytes());
        b[16..24].copy_from_slice(&self.next_batch.to_le_bytes());
        let d = boot_abi::sha256::digest(&b[..24]);
        b[24..32].copy_from_slice(&d[..8]);
        b
    }

    /// Decode a stored state. A damaged state returns `None`; the caller then starts from the
    /// oldest live record, which resends (never skips) evidence.
    pub fn decode(b: &[u8]) -> Option<SyncState> {
        if b.len() != SYNC_STATE_LEN || &b[0..4] != SYNC_MAGIC || b[4..6] != 1u16.to_le_bytes() || b[7] != 0 {
            return None;
        }
        if b[24..32] != boot_abi::sha256::digest(&b[..24])[..8] {
            return None;
        }
        let mut s = [0u8; 8];
        s.copy_from_slice(&b[8..16]);
        let mut n = [0u8; 8];
        n.copy_from_slice(&b[16..24]);
        Some(SyncState { synced: Cursor::new(u64::from_le_bytes(s), b[6]), next_batch: u64::from_le_bytes(n) })
    }
}

/// What the kernel knows about the control-plane link.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Link {
    /// No enrollment: the standalone / air-gapped steady state.
    NotEnrolled,
    /// Enrolled, but the session is down or the control plane does not answer.
    Down,
    /// Enrolled and the session is up.
    Up,
}

#[derive(Clone, Copy, Debug)]
pub struct Config {
    /// Batches allowed in flight before waiting for an ack (1..=`MAX_WINDOW`).
    pub window: usize,
    pub ack_timeout_ms: u64,
    pub backoff_min_ms: u64,
    pub backoff_max_ms: u64,
}

impl Config {
    pub const DEFAULT: Config = Config { window: 4, ack_timeout_ms: 10_000, backoff_min_ms: 1_000, backoff_max_ms: 300_000 };
}

pub const MAX_WINDOW: usize = 8;

#[derive(Clone, Copy, Debug)]
struct Sent {
    batch_seq: u64,
    to: Cursor,
    sent_ms: u64,
    /// Still counted against the window (false once a timeout rewound past it; a late ack for
    /// it is still honoured).
    live: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    /// Standalone: export is off. Not an error.
    NotEnrolled,
    /// Everything up to the log head is sent.
    UpToDate,
    /// The window is full; waiting for acks.
    WindowFull,
    /// Offline or backing off: try again at this time.
    WaitUntil(u64),
    /// Build and send the batch starting at `from`, numbered `batch_seq`.
    Send { batch_seq: u64, from: Cursor },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AckResult {
    /// The synced position moved: persist the returned state.
    Advanced(SyncState),
    /// Already covered by an earlier ack (a duplicate or a replay).
    Stale,
    /// Names a batch this device never sent (forged, or from another session).
    Unknown,
    /// Names a sent batch but a different end position. Ignored.
    Mismatch,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    pub sent: u64,
    pub acked: u64,
    pub timeouts: u64,
    pub send_failures: u64,
    pub bad_acks: u64,
}

pub struct SyncQueue {
    state: SyncState,
    cfg: Config,
    /// Where the next batch starts (`>= state.synced`).
    send_from: Cursor,
    sent: [Option<Sent>; MAX_WINDOW],
    backoff_ms: u64,
    retry_at: u64,
    pub stats: Stats,
}

impl SyncQueue {
    pub fn new(state: SyncState, cfg: Config) -> Self {
        let mut cfg = cfg;
        cfg.window = cfg.window.clamp(1, MAX_WINDOW);
        cfg.backoff_min_ms = cfg.backoff_min_ms.max(1);
        cfg.backoff_max_ms = cfg.backoff_max_ms.max(cfg.backoff_min_ms);
        SyncQueue { state, cfg, send_from: state.synced, sent: [None; MAX_WINDOW], backoff_ms: 0, retry_at: 0, stats: Stats::default() }
    }

    pub fn state(&self) -> SyncState {
        self.state
    }

    pub fn send_from(&self) -> Cursor {
        self.send_from
    }

    fn live(&self) -> usize {
        self.sent.iter().flatten().filter(|s| s.live).count()
    }

    fn back_off(&mut self, now_ms: u64) {
        self.backoff_ms = if self.backoff_ms == 0 {
            self.cfg.backoff_min_ms
        } else {
            (self.backoff_ms.saturating_mul(2)).min(self.cfg.backoff_max_ms)
        };
        self.retry_at = now_ms.saturating_add(self.backoff_ms);
    }

    /// Resend from the synced position. Batches already sent stay known so a late ack counts.
    fn rewind(&mut self) {
        self.send_from = self.state.synced;
        for s in self.sent.iter_mut().flatten() {
            s.live = false;
        }
    }

    /// The oldest position still in the log moved past `synced` (ring retention): skip forward.
    /// Returns how many log records were lost before they were synced.
    pub fn clamp_to(&mut self, oldest: Cursor) -> u64 {
        if self.state.synced >= oldest {
            return 0;
        }
        let lost = oldest.log_seq - self.state.synced.log_seq;
        self.state.synced = oldest;
        if self.send_from < oldest {
            self.send_from = oldest;
        }
        lost
    }

    /// Decide what to do now. `head` is the log position after the newest record.
    pub fn poll(&mut self, now_ms: u64, link: Link, head: Cursor) -> Decision {
        if link == Link::NotEnrolled {
            return Decision::NotEnrolled;
        }
        // Ack timeout: the oldest live batch waited too long.
        let timed_out = self
            .sent
            .iter()
            .flatten()
            .any(|s| s.live && now_ms.saturating_sub(s.sent_ms) >= self.cfg.ack_timeout_ms);
        if timed_out {
            self.stats.timeouts += 1;
            self.rewind();
            self.back_off(now_ms);
        }
        if link == Link::Down {
            if now_ms >= self.retry_at {
                self.back_off(now_ms);
            }
            return Decision::WaitUntil(self.retry_at);
        }
        if now_ms < self.retry_at {
            return Decision::WaitUntil(self.retry_at);
        }
        if self.send_from >= head {
            return Decision::UpToDate;
        }
        if self.live() >= self.cfg.window {
            return Decision::WindowFull;
        }
        Decision::Send { batch_seq: self.state.next_batch, from: self.send_from }
    }

    /// The batch from `poll` went out and covers `[from, to)`. Returns the state to persist
    /// (the batch counter moved).
    pub fn on_sent(&mut self, batch_seq: u64, to: Cursor, now_ms: u64) -> SyncState {
        debug_assert_eq!(batch_seq, self.state.next_batch);
        self.state.next_batch = batch_seq.wrapping_add(1);
        self.send_from = to;
        let entry = Sent { batch_seq, to, sent_ms: now_ms, live: true };
        // Reuse a free slot, else the oldest entry that no longer counts, else the oldest.
        let idx = self
            .sent
            .iter()
            .position(|s| s.is_none())
            .or_else(|| self.oldest(|s| !s.live))
            .or_else(|| self.oldest(|_| true))
            .unwrap_or(0);
        self.sent[idx] = Some(entry);
        self.stats.sent += 1;
        self.state
    }

    fn oldest(&self, f: impl Fn(&Sent) -> bool) -> Option<usize> {
        self.sent
            .iter()
            .enumerate()
            .filter_map(|(i, s)| s.filter(|s| f(s)).map(|s| (i, s.batch_seq)))
            .min_by_key(|&(_, b)| b)
            .map(|(i, _)| i)
    }

    /// The transport could not send (session down, socket error). Nothing is lost: back off and
    /// resend from the synced position.
    pub fn on_send_failed(&mut self, now_ms: u64) {
        self.stats.send_failures += 1;
        self.rewind();
        self.back_off(now_ms);
    }

    /// Apply an ack (already opened on the session and checked for tenant).
    pub fn on_ack(&mut self, a: &Ack) -> AckResult {
        if a.batch_seq >= self.state.next_batch {
            self.stats.bad_acks += 1;
            return AckResult::Unknown;
        }
        let Some(s) = self.sent.iter().flatten().find(|s| s.batch_seq == a.batch_seq).copied() else {
            // Older than anything remembered: already covered, or never sent by this queue.
            self.stats.bad_acks += 1;
            return AckResult::Stale;
        };
        if s.to != a.to {
            self.stats.bad_acks += 1;
            return AckResult::Mismatch;
        }
        if a.to <= self.state.synced {
            self.stats.bad_acks += 1;
            return AckResult::Stale;
        }
        self.state.synced = a.to;
        if self.send_from < a.to {
            self.send_from = a.to;
        }
        // Cumulative: drop every batch at or before this one.
        for e in self.sent.iter_mut() {
            if matches!(e, Some(x) if x.batch_seq <= a.batch_seq || x.to <= a.to) {
                *e = None;
            }
        }
        self.backoff_ms = 0;
        self.retry_at = 0;
        self.stats.acked += 1;
        AckResult::Advanced(self.state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c(s: u64) -> Cursor {
        Cursor::new(s, 0)
    }

    fn q() -> SyncQueue {
        SyncQueue::new(SyncState::default(), Config { window: 2, ack_timeout_ms: 100, backoff_min_ms: 10, backoff_max_ms: 40 })
    }

    #[test]
    fn state_encoding() {
        let s = SyncState { synced: Cursor::new(77, 3), next_batch: 9 };
        let b = s.encode();
        assert_eq!(SyncState::decode(&b), Some(s));
        let mut d = b;
        d[9] ^= 1;
        assert_eq!(SyncState::decode(&d), None);
    }

    /// Deliverable (c): with no control plane nothing is attempted and nothing changes.
    #[test]
    fn not_enrolled_is_idle() {
        let mut q = q();
        for t in 0..1000 {
            assert_eq!(q.poll(t, Link::NotEnrolled, c(50)), Decision::NotEnrolled);
        }
        assert_eq!(q.state(), SyncState::default());
        assert_eq!(q.stats, Stats::default());
    }

    /// Deliverable (c): an unreachable control plane backs off (capped) and keeps the position.
    #[test]
    fn down_backs_off_and_keeps_position() {
        let mut q = q();
        assert_eq!(q.poll(0, Link::Down, c(5)), Decision::WaitUntil(10));
        assert_eq!(q.poll(10, Link::Down, c(5)), Decision::WaitUntil(30));
        assert_eq!(q.poll(30, Link::Down, c(5)), Decision::WaitUntil(70));
        assert_eq!(q.poll(70, Link::Down, c(5)), Decision::WaitUntil(110)); // capped at 40
        assert_eq!(q.poll(75, Link::Up, c(5)), Decision::WaitUntil(110));
        assert_eq!(q.poll(110, Link::Up, c(5)), Decision::Send { batch_seq: 0, from: c(0) });
        assert_eq!(q.state().synced, c(0));
    }

    #[test]
    fn window_ack_and_cumulative() {
        let mut q = q();
        let Decision::Send { batch_seq: 0, from } = q.poll(0, Link::Up, c(9)) else { panic!() };
        assert_eq!(from, c(0));
        q.on_sent(0, c(3), 0);
        let Decision::Send { batch_seq: 1, from } = q.poll(1, Link::Up, c(9)) else { panic!() };
        assert_eq!(from, c(3));
        q.on_sent(1, c(6), 1);
        assert_eq!(q.poll(2, Link::Up, c(9)), Decision::WindowFull);
        // Ack batch 1 only: cumulative, covers batch 0 too.
        let r = q.on_ack(&Ack { tenant_id: 0, batch_seq: 1, to: c(6) });
        assert_eq!(r, AckResult::Advanced(SyncState { synced: c(6), next_batch: 2 }));
        assert_eq!(q.poll(3, Link::Up, c(9)), Decision::Send { batch_seq: 2, from: c(6) });
    }

    /// Acks are replay-safe: duplicates, never-sent batches and wrong positions change nothing.
    #[test]
    fn bad_acks_ignored() {
        let mut q = q();
        q.poll(0, Link::Up, c(9));
        q.on_sent(0, c(3), 0);
        assert_eq!(q.on_ack(&Ack { tenant_id: 0, batch_seq: 5, to: c(9) }), AckResult::Unknown);
        assert_eq!(q.on_ack(&Ack { tenant_id: 0, batch_seq: 0, to: c(9) }), AckResult::Mismatch);
        assert!(matches!(q.on_ack(&Ack { tenant_id: 0, batch_seq: 0, to: c(3) }), AckResult::Advanced(_)));
        assert_eq!(q.on_ack(&Ack { tenant_id: 0, batch_seq: 0, to: c(3) }), AckResult::Stale);
        assert_eq!(q.state().synced, c(3));
        assert_eq!(q.stats.bad_acks, 3);
    }

    /// Deliverable (c): a lost ack rewinds to the synced position and resends in a new batch;
    /// a late ack for the old batch still counts.
    #[test]
    fn timeout_rewinds_and_late_ack_counts() {
        let mut q = q();
        q.poll(0, Link::Up, c(9));
        q.on_sent(0, c(3), 0);
        assert_eq!(q.poll(100, Link::Up, c(9)), Decision::WaitUntil(110));
        assert_eq!(q.stats.timeouts, 1);
        assert_eq!(q.poll(110, Link::Up, c(9)), Decision::Send { batch_seq: 1, from: c(0) });
        q.on_sent(1, c(3), 110);
        assert!(matches!(q.on_ack(&Ack { tenant_id: 0, batch_seq: 0, to: c(3) }), AckResult::Advanced(_)));
        assert_eq!(q.on_ack(&Ack { tenant_id: 0, batch_seq: 1, to: c(3) }), AckResult::Stale);
        assert_eq!(q.poll(111, Link::Up, c(9)), Decision::Send { batch_seq: 2, from: c(3) });
    }

    #[test]
    fn send_failure_keeps_everything() {
        let mut q = q();
        q.poll(0, Link::Up, c(9));
        q.on_sent(0, c(3), 0);
        q.on_send_failed(1);
        assert_eq!(q.send_from(), c(0));
        assert_eq!(q.poll(11, Link::Up, c(9)), Decision::Send { batch_seq: 1, from: c(0) });
    }

    #[test]
    fn eviction_is_counted() {
        let mut q = q();
        assert_eq!(q.clamp_to(c(40)), 40);
        assert_eq!(q.state().synced, c(40));
        assert_eq!(q.clamp_to(c(10)), 0);
    }
}
