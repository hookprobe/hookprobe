//! The whole export loop over two kernel-provided edges:
//!
//! * [`SlotSource`]: the sealed evidence log (on the device, `evlog`'s `LogStore` + `SealedStore`
//!   read path: geometry plus "read the sector that holds record `seq`");
//! * [`Transport`]: the enrolled session (on the device, `securechannel::RecordTx::seal` with the
//!   given associated data, then the UDP send to the control plane).
//!
//! The kernel calls [`Exporter::poll`] on its heartbeat and [`Exporter::on_ack`] when an
//! `AD_ACK` record opens on the session, and stores the [`SyncState`] either returns.

use crate::anon::{anonymize, ExportRec, Policy};
use crate::qsecbit::Window;
use crate::queue::{AckResult, Config, Decision, Link, SyncQueue, SyncState};
use crate::record::{verify, Outcome, SealOpener};
use crate::slot::SEC;
use crate::wire::{self, Cursor, Header, AD_FRAME, MAX_FRAME, MAX_RECS};

/// The log's shape, as `fslog::LogStore` knows it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Geometry {
    pub nslots: u64,
    /// The seq the next record will get (newest record + 1).
    pub next_seq: u64,
}

pub trait SlotSource {
    fn geometry(&self) -> Geometry;
    /// Read the 512-byte slot that holds record `seq` (slot `seq % nslots`).
    fn read(&mut self, seq: u64, out: &mut [u8; SEC]) -> Result<(), ()>;
}

pub trait Transport {
    /// Seal `frame` on the enrolled session under `ad` and send it.
    fn send(&mut self, ad: &[u8], frame: &[u8]) -> Result<(), ()>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Identity {
    pub tenant_id: u64,
    pub device_fp: [u8; 32],
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ExportStats {
    /// Records put on the wire (resends count again).
    pub exported: u64,
    /// Log records that failed verification (each counted once).
    pub rejected: u64,
    /// Log records overwritten by the ring before they were synced.
    pub evicted: u64,
    /// Polls that could not read the log.
    pub io_errors: u64,
}

/// What one poll did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Polled {
    pub decision: Decision,
    /// `(batch_seq, records)` of the frame sent, if any.
    pub sent: Option<(u64, usize)>,
    /// A new state to persist (the batch counter or the synced position moved).
    pub persist: Option<SyncState>,
}

/// QSECBIT samples kept for the window summary.
pub const QS_SAMPLES: usize = 64;

pub struct Exporter {
    id: Identity,
    policy: Policy,
    queue: SyncQueue,
    qs: Window<QS_SAMPLES>,
    qs_window_ms: u64,
    /// Evictions not yet acknowledged by the control plane: repeated in every frame until then.
    unreported_evicted: u64,
    /// Highest log seq whose rejection is already counted (resends do not count twice).
    rejected_through: Option<u64>,
    pub stats: ExportStats,
}

impl Exporter {
    pub fn new(id: Identity, policy: Policy, state: SyncState, cfg: Config, qs_window_ms: u64) -> Self {
        Exporter {
            id,
            policy,
            queue: SyncQueue::new(state, cfg),
            qs: Window::new(),
            qs_window_ms,
            unreported_evicted: 0,
            rejected_through: None,
            stats: ExportStats::default(),
        }
    }

    pub fn state(&self) -> SyncState {
        self.queue.state()
    }

    pub fn queue_stats(&self) -> crate::queue::Stats {
        self.queue.stats
    }

    /// Feed a QSECBIT sample (wall-clock ms, the device's fixed-point score).
    pub fn push_qsecbit(&mut self, ts_ms: u64, score: u32) {
        self.qs.push(ts_ms, score);
    }

    /// One heartbeat: maybe send one frame.
    pub fn poll<S: SlotSource, O: SealOpener + ?Sized, T: Transport>(
        &mut self,
        now_ms: u64,
        link: Link,
        src: &mut S,
        opener: &O,
        tx: &mut T,
    ) -> Polled {
        let g = src.geometry();
        let head = Cursor::new(g.next_seq, 0);
        let oldest = Cursor::new(g.next_seq.saturating_sub(g.nslots), 0);
        let mut persist = None;
        let lost = self.queue.clamp_to(oldest);
        if lost > 0 {
            self.stats.evicted += lost;
            self.unreported_evicted += lost;
            persist = Some(self.queue.state());
        }
        let decision = self.queue.poll(now_ms, link, head);
        let Decision::Send { batch_seq, from } = decision else {
            return Polled { decision, sent: None, persist };
        };

        let mut recs = [ExportRec::default(); MAX_RECS];
        let Some((n, to, rejected)) = self.build(src, opener, g, from, head, &mut recs) else {
            self.stats.io_errors += 1;
            self.queue.on_send_failed(now_ms);
            return Polled { decision, sent: None, persist };
        };
        let hdr = Header {
            tenant_id: self.id.tenant_id,
            device_fp: self.id.device_fp,
            batch_seq,
            from,
            to,
            rejected,
            evicted: self.unreported_evicted,
            qsecbit: self.qs.summary(now_ms, self.qs_window_ms),
        };
        let mut frame = [0u8; MAX_FRAME];
        // Cannot fail: n <= MAX_RECS, the buffer is MAX_FRAME, and anonymize only emits clean records.
        let Ok(len) = wire::serialize(&hdr, &recs[..n], &mut frame) else {
            self.queue.on_send_failed(now_ms);
            return Polled { decision, sent: None, persist };
        };
        if tx.send(AD_FRAME, &frame[..len]).is_err() {
            self.queue.on_send_failed(now_ms);
            return Polled { decision, sent: None, persist };
        }
        self.stats.exported += n as u64;
        let st = self.queue.on_sent(batch_seq, to, now_ms);
        Polled { decision, sent: Some((batch_seq, n)), persist: Some(st) }
    }

    /// Read verified events from `from` until the frame is full or the log ends.
    /// Returns `(records, end position, rejected log records)`, or `None` if nothing could be read.
    fn build<S: SlotSource, O: SealOpener + ?Sized>(
        &mut self,
        src: &mut S,
        opener: &O,
        g: Geometry,
        from: Cursor,
        head: Cursor,
        recs: &mut [ExportRec; MAX_RECS],
    ) -> Option<(usize, Cursor, u32)> {
        let mut cur = from;
        let mut n = 0usize;
        let mut rejected = 0u32;
        let mut sec = [0u8; SEC];
        while cur < head && n < MAX_RECS {
            if src.read(cur.log_seq, &mut sec).is_err() {
                break; // send what was read; the rest goes next time
            }
            let next = Cursor::new(cur.log_seq + 1, 0);
            match verify(&sec, cur.log_seq, g.nslots, opener) {
                Ok(v) => {
                    let mut i = cur.idx as usize;
                    while i < v.n && n < MAX_RECS {
                        recs[n] = anonymize(&v.events[i], &self.policy);
                        n += 1;
                        i += 1;
                    }
                    cur = if i >= v.n { next } else { Cursor::new(cur.log_seq, i as u8) };
                }
                Err(Outcome::Skip) => cur = next,
                Err(Outcome::Reject(_)) => {
                    rejected += 1;
                    if self.rejected_through.map_or(true, |t| cur.log_seq > t) {
                        self.stats.rejected += 1;
                        self.rejected_through = Some(cur.log_seq);
                    }
                    cur = next;
                }
            }
        }
        if cur == from {
            return None;
        }
        Some((n, cur, rejected))
    }

    /// An `AD_ACK` record opened on the session. Returns what it did; persist the state on
    /// `Advanced`.
    pub fn on_ack(&mut self, plaintext: &[u8]) -> AckResult {
        let Ok(a) = wire::parse_ack(plaintext) else {
            self.queue.stats.bad_acks += 1;
            return AckResult::Unknown;
        };
        if a.tenant_id != self.id.tenant_id {
            self.queue.stats.bad_acks += 1;
            return AckResult::Unknown;
        }
        let r = self.queue.on_ack(&a);
        if matches!(r, AckResult::Advanced(_)) {
            self.unreported_evicted = 0;
        }
        r
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::anon::{is_internal_v4, SrcKind};
    use crate::record::Event;
    use crate::testutil::{sealed_slot, TestOpener};
    use crate::wire::{parse, serialize_ack, Ack, ACK_LEN};
    use std::vec;
    use std::vec::Vec;

    /// An in-memory fslog ring.
    struct MemLog {
        slots: Vec<[u8; SEC]>,
        next_seq: u64,
        fail_reads: bool,
    }

    impl MemLog {
        fn new(nslots: usize) -> Self {
            MemLog { slots: vec![[0u8; SEC]; nslots], next_seq: 0, fail_reads: false }
        }
        fn append(&mut self, o: &TestOpener, evs: &[Event]) {
            let n = self.slots.len() as u64;
            let s = sealed_slot(o, self.next_seq, n, true, evs);
            self.slots[(self.next_seq % n) as usize] = s;
            self.next_seq += 1;
        }
        fn append_prov(&mut self, o: &TestOpener, p: crate::record::Prov, evs: &[Event]) {
            let n = self.slots.len() as u64;
            let s = crate::testutil::sealed_slot_prov(o, self.next_seq, n, p, evs);
            self.slots[(self.next_seq % n) as usize] = s;
            self.next_seq += 1;
        }
    }

    impl SlotSource for MemLog {
        fn geometry(&self) -> Geometry {
            Geometry { nslots: self.slots.len() as u64, next_seq: self.next_seq }
        }
        fn read(&mut self, seq: u64, out: &mut [u8; SEC]) -> Result<(), ()> {
            if self.fail_reads {
                return Err(());
            }
            *out = self.slots[(seq % self.slots.len() as u64) as usize];
            Ok(())
        }
    }

    /// A transport that records what it would have sealed, or fails while `up` is false.
    struct Tx {
        up: bool,
        frames: Vec<Vec<u8>>,
    }

    impl Transport for Tx {
        fn send(&mut self, ad: &[u8], frame: &[u8]) -> Result<(), ()> {
            assert_eq!(ad, AD_FRAME);
            if !self.up {
                return Err(());
            }
            self.frames.push(frame.to_vec());
            Ok(())
        }
    }

    const ID: Identity = Identity { tenant_id: 42, device_fp: [9; 32] };
    const KEEP: Policy = Policy { pseudonym_key: None, keep_public_src: true };
    const CFG: Config = Config { window: 2, ack_timeout_ms: 1_000, backoff_min_ms: 100, backoff_max_ms: 800 };

    fn ip(a: u8, b: u8, c: u8, d: u8) -> u32 {
        u32::from_be_bytes([a, b, c, d])
    }

    fn ev(i: u64, src: u32) -> Event {
        Event { ts_ms: 1_000 + i, src, rule_id: 10 + (i % 3) as u16, severity: 4, verdict: 2 }
    }

    fn ack_for(frame: &[u8]) -> Vec<u8> {
        let f = parse(frame).unwrap();
        let mut b = vec![0u8; ACK_LEN];
        serialize_ack(&Ack { tenant_id: 42, batch_seq: f.hdr.batch_seq, to: f.hdr.to }, &mut b).unwrap();
        b
    }

    /// A control plane that acks every frame and de-duplicates on the log cursor.
    fn drain(x: &mut Exporter, log: &mut MemLog, o: &TestOpener, tx: &mut Tx, mut now: u64) -> (Vec<ExportRec>, u64) {
        let mut got = Vec::new();
        let mut seen = Cursor::START;
        for _ in 0..1000 {
            let p = x.poll(now, Link::Up, log, o, tx);
            for f in tx.frames.drain(..) {
                let fr = parse(&f).unwrap();
                assert_eq!((fr.hdr.tenant_id, fr.hdr.device_fp), (ID.tenant_id, ID.device_fp));
                if fr.hdr.to > seen {
                    assert!(fr.hdr.from <= seen, "a gap in the export");
                    // keep only records after `seen` (a resend may overlap)
                    let skip = if fr.hdr.from == seen { 0 } else { usize::MAX };
                    assert_eq!(skip, 0, "overlapping resend not expected in this helper");
                    got.extend_from_slice(fr.records());
                    seen = fr.hdr.to;
                }
                assert!(matches!(x.on_ack(&ack_for(&f)), AckResult::Advanced(_) | AckResult::Stale));
            }
            if p.decision == Decision::UpToDate {
                break;
            }
            now += 10;
        }
        (got, now)
    }

    fn log_with(o: &TestOpener, records: u64, per: u64) -> MemLog {
        let mut log = MemLog::new(16);
        for r in 0..records {
            let evs: Vec<Event> = (0..per).map(|i| ev(r * per + i, ip(203, 0, 114, (i + 1) as u8))).collect();
            log.append(o, &evs);
        }
        log
    }

    /// Deliverable (c): no control plane, or an unreachable one, keeps every record, and the
    /// export resumes from the synced position without loss or deletion.
    #[test]
    fn offline_queue_retains_everything() {
        let o = TestOpener::new([5; 32]);
        let mut log = log_with(&o, 6, 10); // 60 events, more than one frame
        let before = log.slots.clone();
        let mut x = Exporter::new(ID, KEEP, SyncState::default(), CFG, 60_000);
        let mut tx = Tx { up: false, frames: Vec::new() };

        // Standalone: nothing attempted.
        for t in 0..50 {
            let p = x.poll(t * 100, Link::NotEnrolled, &mut log, &o, &mut tx);
            assert_eq!(p.decision, Decision::NotEnrolled);
        }
        // Enrolled but the control plane is unreachable: sends fail, backoff grows, nothing lost.
        let mut now = 10_000;
        for _ in 0..20 {
            x.poll(now, Link::Up, &mut log, &o, &mut tx);
            now += 50;
        }
        assert!(tx.frames.is_empty());
        assert!(x.queue_stats().send_failures > 0);
        assert_eq!(x.state().synced, Cursor::START);

        // Back online: every event arrives once, in order.
        tx.up = true;
        let (got, _) = drain(&mut x, &mut log, &o, &mut tx, now + 1_000);
        assert_eq!(got.len(), 60);
        for (i, r) in got.iter().enumerate() {
            assert_eq!(r.ts_ms, 1_000 + i as u64);
        }
        assert_eq!(x.state().synced, Cursor::new(6, 0));
        // Synced, never deleted: the log is byte-for-byte what it was.
        assert_eq!(log.slots, before);
    }

    /// A lost ack makes the queue resend the same events; nothing is skipped.
    #[test]
    fn lost_ack_resends() {
        let o = TestOpener::new([5; 32]);
        let mut log = log_with(&o, 1, 5);
        let mut x = Exporter::new(ID, KEEP, SyncState::default(), CFG, 60_000);
        let mut tx = Tx { up: true, frames: Vec::new() };
        let p = x.poll(0, Link::Up, &mut log, &o, &mut tx);
        assert_eq!(p.sent, Some((0, 5)));
        tx.frames.clear(); // the ack never comes
        assert_eq!(x.poll(1_000, Link::Up, &mut log, &o, &mut tx).decision, Decision::WaitUntil(1_100));
        let p = x.poll(1_100, Link::Up, &mut log, &o, &mut tx);
        assert_eq!(p.sent, Some((1, 5)));
        let f = parse(&tx.frames[0]).unwrap();
        assert_eq!((f.hdr.from, f.hdr.to), (Cursor::START, Cursor::new(1, 0)));
    }

    /// Deliverable (a), end to end: internal addresses and MAC octets never reach the wire.
    #[test]
    fn exported_frames_carry_no_internal_addresses() {
        let o = TestOpener::new([5; 32]);
        let mut log = MemLog::new(16);
        let internal = [ip(10, 0, 0, 5), ip(192, 168, 1, 20), ip(172, 20, 3, 4), ip(100, 64, 9, 9), ip(169, 254, 1, 1)];
        let mut evs: Vec<Event> = internal.iter().enumerate().map(|(i, &a)| ev(i as u64, a)).collect();
        evs.push(Event { ts_ms: 9, src: 0xAABB_CCDD, rule_id: 121, severity: 1, verdict: 1 }); // MAC octets
        evs.push(ev(7, ip(203, 0, 114, 66))); // public attacker
        log.append(&o, &evs);
        let mut x = Exporter::new(ID, KEEP, SyncState::default(), CFG, 60_000);
        let mut tx = Tx { up: true, frames: Vec::new() };
        x.poll(0, Link::Up, &mut log, &o, &mut tx);
        let raw = &tx.frames[0];
        for a in internal.iter().copied().chain([0xAABB_CCDDu32]) {
            let le = a.to_le_bytes();
            assert!(!raw.windows(4).any(|w| w == le), "{a:#x} found in the frame bytes");
        }
        let f = parse(raw).unwrap();
        assert_eq!(f.n, 7);
        for r in f.records() {
            assert!(r.src == 0 || !is_internal_v4(r.src));
        }
        assert_eq!(f.records()[5].src_kind, SrcKind::Redacted as u8);
        assert_eq!((f.records()[6].src, f.records()[6].src_kind), (ip(203, 0, 114, 66), SrcKind::PublicV4 as u8));
    }

    /// Deliverable (b), end to end: a tampered record is skipped and reported, the rest flows.
    #[test]
    fn tampered_record_is_reported_not_exported() {
        let o = TestOpener::new([5; 32]);
        let mut log = log_with(&o, 3, 4);
        log.slots[1][200] ^= 0x01; // inside record 1's sealed ciphertext (bytes 160..240)
        let mut x = Exporter::new(ID, KEEP, SyncState::default(), CFG, 60_000);
        let mut tx = Tx { up: true, frames: Vec::new() };
        x.poll(0, Link::Up, &mut log, &o, &mut tx);
        let f = parse(&tx.frames[0]).unwrap();
        assert_eq!(f.hdr.rejected, 1);
        assert_eq!(f.n, 8);
        let ts: Vec<u64> = f.records().iter().map(|r| r.ts_ms).collect();
        assert_eq!(ts, [1000, 1001, 1002, 1003, 1008, 1009, 1010, 1011]);
        assert_eq!(x.stats.rejected, 1);
    }

    #[test]
    fn eviction_and_qsecbit_reported() {
        let o = TestOpener::new([5; 32]);
        let mut log = log_with(&o, 20, 1); // a 16-slot ring: records 0..4 were overwritten
        let mut x = Exporter::new(ID, KEEP, SyncState::default(), CFG, 60_000);
        x.push_qsecbit(100, 700);
        x.push_qsecbit(200, 400);
        let mut tx = Tx { up: true, frames: Vec::new() };
        x.poll(300, Link::Up, &mut log, &o, &mut tx);
        let f = parse(&tx.frames[0]).unwrap();
        assert_eq!(f.hdr.evicted, 4);
        assert_eq!(f.hdr.from, Cursor::new(4, 0));
        assert_eq!((f.hdr.qsecbit.n, f.hdr.qsecbit.min, f.hdr.qsecbit.max, f.hdr.qsecbit.last), (2, 400, 700, 400));
        assert_eq!(x.stats.evicted, 4);
    }

    #[test]
    fn acks_from_another_tenant_or_garbage_are_ignored() {
        let o = TestOpener::new([5; 32]);
        let mut log = log_with(&o, 1, 2);
        let mut x = Exporter::new(ID, KEEP, SyncState::default(), CFG, 60_000);
        let mut tx = Tx { up: true, frames: Vec::new() };
        x.poll(0, Link::Up, &mut log, &o, &mut tx);
        let mut a = ack_for(&tx.frames[0]);
        a[8] ^= 1; // tenant
        assert_eq!(x.on_ack(&a), AckResult::Unknown);
        assert_eq!(x.on_ack(&[0u8; 3]), AckResult::Unknown);
        assert_eq!(x.state().synced, Cursor::START);
    }

    #[test]
    fn unreadable_log_backs_off() {
        let o = TestOpener::new([5; 32]);
        let mut log = log_with(&o, 1, 2);
        log.fail_reads = true;
        let mut x = Exporter::new(ID, KEEP, SyncState::default(), CFG, 60_000);
        let mut tx = Tx { up: true, frames: Vec::new() };
        let p = x.poll(0, Link::Up, &mut log, &o, &mut tx);
        assert_eq!(p.sent, None);
        assert_eq!(x.stats.io_errors, 1);
        assert!(matches!(x.poll(1, Link::Up, &mut log, &o, &mut tx).decision, Decision::WaitUntil(_)));
    }

    /// Since ADR 0067 N1 the kernel writes `RT_EVIDENCE_C` records. A log that mixes them with the
    /// older layouts (an OTA across the change) exports every event, none rejected or skipped.
    #[test]
    fn provenance_records_are_exported_alongside_older_layouts() {
        let o = TestOpener::new([1; 32]);
        let mut log = MemLog::new(16);
        let evs = |r: u64| -> Vec<Event> { (0..3).map(|i| ev(r * 3 + i, ip(203, 0, 114, (i + 1) as u8))).collect() };
        log.append(&o, &evs(0));
        log.append_prov(&o, crate::record::Prov { cfg_gen: 7, cfg: [0xa1; 8] }, &evs(1));
        log.append_prov(&o, crate::record::Prov::UNKNOWN, &evs(2));
        log.append(&o, &evs(3));
        let mut x = Exporter::new(ID, KEEP, SyncState::default(), CFG, 60_000);
        let mut tx = Tx { up: true, frames: Vec::new() };
        let (got, _) = drain(&mut x, &mut log, &o, &mut tx, 0);
        assert_eq!(got.len(), 12);
        let want: Vec<u64> = (0..12).map(|i| 1_000 + i).collect();
        assert_eq!(got.iter().map(|r| r.ts_ms).collect::<Vec<_>>(), want);
        assert_eq!(x.stats.rejected, 0);
    }
}
