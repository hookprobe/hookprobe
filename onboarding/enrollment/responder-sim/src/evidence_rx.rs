//! Off-device RECEIVER for the sealed-evidence stream (HQX3, ADR 0066): de-duplicates on the log
//! cursor and answers each batch with a cumulative ack.
//!
//! The codec is `onboarding/enrollment/evidence-export`'s own `wire` module, the one the device
//! side serializes with, so the receiver cannot drift from the device's frame format. `wire::parse`
//! re-checks the privacy rules, so a frame that carries an internal address is refused here too.
//!
//! What the receiver keeps per device: `through`, the end of the contiguous range it holds, and the
//! last few stored frames (their range and records). A frame is handled by where it sits against
//! `through`:
//!
//! | frame range `[from, to)`              | handling                                                   |
//! |---------------------------------------|------------------------------------------------------------|
//! | first frame seen                      | stored; starts the range                                   |
//! | `to <= through`                       | duplicate (a resend after a lost ack): acked again, not stored |
//! | `from == through`                     | stored                                                     |
//! | `from < through < to` (resend that grew) | the part up to `through` must equal what is stored; the rest is stored |
//! | `from > through`, frame reports evictions | stored; the gap is reported as evicted on the device   |
//! | `from > through`, no evictions        | held, not acked: an earlier batch is missing (reordered or lost). The device's ack timeout resends from its synced position |
//!
//! The ack names the frame's own `(batch_seq, to)`. The device advances only on an ack for a
//! batch it sent with that exact end (`queue::SyncQueue::on_ack`), so acking a stored or duplicate
//! frame can never move the device past evidence the receiver does not hold.
//!
//! Records carry no per-record cursor, so a partial overlap can be split only against frames the
//! receiver still remembers ([`HISTORY`]). An overlap that starts before that is held, never
//! guessed: the device resends, and an exact resend is a plain duplicate.

use std::collections::VecDeque;

use evidence_export::anon::{ExportRec, SrcKind};
use evidence_export::wire::{self, Ack, Cursor, Frame, WireErr};

/// Stored frames remembered for splitting a partial overlap (the device keeps far fewer in flight).
pub const HISTORY: usize = 64;

#[derive(Debug, PartialEq, Eq)]
pub enum EvErr {
    /// Not an HQX3 frame (bad magic, version, length or range).
    Malformed,
    /// A record breaks the privacy rules. Refused, never stored.
    Privacy,
    /// The frame names another tenant or device than the authenticated session.
    IdentityMismatch,
}

/// Why a well-formed frame was neither stored nor acked.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Held {
    /// `from > through` with no evictions reported: an earlier batch has not arrived.
    OutOfOrder,
    /// A partial overlap that starts before the remembered frames.
    UnknownOverlap,
    /// The overlapping part does not match what was stored for that range.
    Inconsistent,
}

#[derive(Debug)]
pub enum Outcome {
    /// New evidence: `frame.records()[skip..]` are the events not held before. `gap` is the
    /// range skipped over because the device reported evictions.
    Stored { frame: Frame, skip: usize, gap: Option<(Cursor, Cursor)> },
    /// Everything in the frame is already held.
    Duplicate { frame: Frame },
    Held { frame: Frame, why: Held },
}

impl Outcome {
    /// The ack to send back, if any: a stored or duplicate frame is acked with its own end.
    pub fn ack(&self, tenant_id: u64) -> Option<Ack> {
        match self {
            Outcome::Stored { frame, .. } | Outcome::Duplicate { frame } => {
                Some(Ack { tenant_id, batch_seq: frame.hdr.batch_seq, to: frame.hdr.to })
            }
            Outcome::Held { .. } => None,
        }
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Stats {
    pub frames: u64,
    pub stored_events: u64,
    pub duplicate_frames: u64,
    pub duplicate_events: u64,
    pub held_frames: u64,
    /// Log records the device reported as overwritten before they were synced.
    pub evicted_records: u64,
    /// Log records the device reported as failing verification (never exported).
    pub rejected_records: u64,
}

struct Seg {
    from: Cursor,
    to: Cursor,
    recs: Vec<ExportRec>,
}

/// One device's evidence stream. Keep it across sessions: de-duplication is per device, and a
/// device that re-handshakes resends from its last acked position.
pub struct EvidenceRx {
    tenant_id: u64,
    device_fp: [u8; 32],
    through: Option<Cursor>,
    history: VecDeque<Seg>,
    pub stats: Stats,
}

impl EvidenceRx {
    pub fn new(tenant_id: u64, device_fp: [u8; 32]) -> Self {
        EvidenceRx { tenant_id, device_fp, through: None, history: VecDeque::new(), stats: Stats::default() }
    }

    pub fn device_fp(&self) -> [u8; 32] {
        self.device_fp
    }

    /// End of the contiguous range held (`None` before the first frame).
    pub fn through(&self) -> Option<Cursor> {
        self.through
    }

    /// Accept one opened HQX3 plaintext.
    pub fn accept(&mut self, pt: &[u8]) -> Result<Outcome, EvErr> {
        let frame = wire::parse(pt).map_err(|e| match e {
            WireErr::Privacy => EvErr::Privacy,
            _ => EvErr::Malformed,
        })?;
        if frame.hdr.tenant_id != self.tenant_id || frame.hdr.device_fp != self.device_fp {
            return Err(EvErr::IdentityMismatch);
        }
        self.stats.frames += 1;
        let (from, to) = (frame.hdr.from, frame.hdr.to);

        let outcome = match self.through {
            None => self.store(frame, 0, None),
            Some(t) if to <= t => Outcome::Duplicate { frame },
            Some(t) if from == t => self.store(frame, 0, None),
            Some(t) if from > t => {
                if frame.hdr.evicted > 0 {
                    // The device moved past records it lost; nothing can fill [t, from) any more.
                    self.history.clear();
                    self.store(frame, 0, Some((t, from)))
                } else {
                    Outcome::Held { frame, why: Held::OutOfOrder }
                }
            }
            Some(t) => match self.held_prefix(from, t) {
                None => Outcome::Held { frame, why: Held::UnknownOverlap },
                Some(prefix) if prefix.len() > frame.n || prefix[..] != frame.records()[..prefix.len()] => {
                    Outcome::Held { frame, why: Held::Inconsistent }
                }
                Some(prefix) => {
                    let skip = prefix.len();
                    self.store(frame, skip, None)
                }
            },
        };
        match &outcome {
            Outcome::Stored { frame, skip, .. } => {
                // Rejections and evictions are counted once, with the frame that stores them.
                self.stats.rejected_records += frame.hdr.rejected as u64;
                self.stats.evicted_records += frame.hdr.evicted;
                self.stats.duplicate_events += *skip as u64;
            }
            Outcome::Duplicate { frame } => {
                self.stats.duplicate_frames += 1;
                self.stats.duplicate_events += frame.n as u64;
            }
            Outcome::Held { .. } => self.stats.held_frames += 1,
        }
        Ok(outcome)
    }

    fn store(&mut self, frame: Frame, skip: usize, gap: Option<(Cursor, Cursor)>) -> Outcome {
        let from = self.through.filter(|_| skip > 0).unwrap_or(frame.hdr.from);
        self.history.push_back(Seg { from, to: frame.hdr.to, recs: frame.records()[skip..].to_vec() });
        while self.history.len() > HISTORY {
            self.history.pop_front();
        }
        self.through = Some(frame.hdr.to);
        self.stats.stored_events += (frame.n - skip) as u64;
        Outcome::Stored { frame, skip, gap }
    }

    /// The records held for `[from, through)`, if the remembered frames cover it contiguously.
    fn held_prefix(&self, from: Cursor, through: Cursor) -> Option<Vec<ExportRec>> {
        let start = self.history.iter().position(|s| s.from == from)?;
        let mut out = Vec::new();
        let mut at = from;
        for s in self.history.iter().skip(start) {
            if s.from != at {
                return None;
            }
            out.extend_from_slice(&s.recs);
            at = s.to;
        }
        (at == through).then_some(out)
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn cursor_json(c: Cursor) -> serde_json::Value {
    serde_json::json!({ "log_seq": c.log_seq, "idx": c.idx })
}

/// Render a stored frame as JSON Lines: one `heqk_evidence` line per new event, then one
/// `heqk_evidence_frame` line with the range, the de-duplication and the loss accounting (so the
/// operator sees evidence that did not arrive, not just what did). Duplicates and held frames
/// render only the frame line. `rx_epoch` = wall-clock seconds when the datagram arrived.
pub fn outcome_to_jsonl(o: &Outcome, rx: &EvidenceRx, rx_epoch: f64) -> Vec<String> {
    let (frame, skip, gap, status) = match o {
        Outcome::Stored { frame, skip, gap } => (frame, *skip, *gap, "stored"),
        Outcome::Duplicate { frame } => (frame, frame.n, None, "duplicate"),
        Outcome::Held { frame, why } => (
            frame,
            frame.n,
            None,
            match why {
                Held::OutOfOrder => "held_out_of_order",
                Held::UnknownOverlap => "held_unknown_overlap",
                Held::Inconsistent => "held_inconsistent",
            },
        ),
    };
    let h = &frame.hdr;
    let fp = hex(&h.device_fp);
    let mut out = Vec::new();
    if matches!(o, Outcome::Stored { .. }) {
        for r in &frame.records()[skip..] {
            let kind = SrcKind::from_u8(r.src_kind);
            out.push(
                serde_json::json!({
                    "type": "heqk_evidence",
                    // wall-clock ms as the device logged it; null when the device had no time yet
                    "ts": if r.ts_ms == 0 { serde_json::Value::Null } else { serde_json::json!(r.ts_ms as f64 / 1000.0) },
                    "device_fp": fp,
                    "tenant": h.tenant_id,
                    "batch_seq": h.batch_seq,
                    "rule_id": r.rule_id,
                    "sev_points": r.severity,
                    "verdict": if r.verdict == 2 { "DROP" } else { "PASS" },
                    "class": if r.class == 0 { "unknown" } else { "reported" },
                    "class_code": r.class,
                    // only a public address ever leaves the device; everything else is a pseudonym or nothing
                    "src_ip": if kind == Some(SrcKind::PublicV4) { std::net::Ipv4Addr::from(r.src).to_string() } else { String::new() },
                    "src_pseudonym": if kind == Some(SrcKind::Pseudonym) { format!("{:08x}", r.src) } else { String::new() },
                    "src_kind": match kind {
                        Some(SrcKind::None) => "none",
                        Some(SrcKind::PublicV4) => "public_v4",
                        Some(SrcKind::Pseudonym) => "pseudonym",
                        Some(SrcKind::Redacted) => "redacted",
                        None => "invalid",
                    },
                })
                .to_string(),
            );
        }
    }
    let q = &h.qsecbit;
    out.push(
        serde_json::json!({
            "type": "heqk_evidence_frame",
            "ts": rx_epoch,
            "status": status,
            "device_fp": fp,
            "tenant": h.tenant_id,
            "batch_seq": h.batch_seq,
            "from": cursor_json(h.from),
            "to": cursor_json(h.to),
            "events": frame.n,
            "new_events": if matches!(o, Outcome::Stored { .. }) { frame.n - skip } else { 0 },
            "duplicate_events": if matches!(o, Outcome::Held { .. }) { 0 } else { skip },
            "rejected_records": h.rejected,
            "evicted_records": h.evicted,
            "gap": gap.map(|(a, b)| serde_json::json!({ "from": cursor_json(a), "to": cursor_json(b) })),
            "held_through": rx.through().map(cursor_json),
            "qsecbit": if q.n == 0 { serde_json::Value::Null } else {
                serde_json::json!({ "n": q.n, "span_ms": q.span_ms, "min": q.min, "max": q.max, "mean": q.mean, "last": q.last, "last_ts_ms": q.last_ts_ms })
            },
        })
        .to_string(),
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use evidence_export::qsecbit::Summary;
    use evidence_export::wire::Header;

    const T: u64 = 7;
    const FP: [u8; 32] = [3; 32];

    fn rec(i: u64) -> ExportRec {
        ExportRec { ts_ms: 1_700_000_000_000 + i, src: 0, src_kind: SrcKind::Redacted as u8, rule_id: 100 + i as u16, severity: 2, verdict: 2, class: 0 }
    }

    fn frame(batch: u64, from: u64, to: u64, recs: &[ExportRec], evicted: u64) -> Vec<u8> {
        let hdr = Header {
            tenant_id: T,
            device_fp: FP,
            batch_seq: batch,
            from: Cursor::new(from, 0),
            to: Cursor::new(to, 0),
            rejected: 0,
            evicted,
            qsecbit: Summary::default(),
        };
        let mut b = [0u8; wire::MAX_FRAME];
        let n = wire::serialize(&hdr, recs, &mut b).unwrap();
        b[..n].to_vec()
    }

    fn recs(a: u64, b: u64) -> Vec<ExportRec> {
        (a..b).map(rec).collect()
    }

    #[test]
    fn in_order_frames_are_stored_and_acked_with_their_own_end() {
        let mut rx = EvidenceRx::new(T, FP);
        let o = rx.accept(&frame(0, 0, 3, &recs(0, 3), 0)).unwrap();
        assert!(matches!(o, Outcome::Stored { skip: 0, gap: None, .. }));
        assert_eq!(o.ack(T), Some(Ack { tenant_id: T, batch_seq: 0, to: Cursor::new(3, 0) }));
        let o = rx.accept(&frame(1, 3, 5, &recs(3, 5), 0)).unwrap();
        assert!(matches!(o, Outcome::Stored { skip: 0, .. }));
        assert_eq!(rx.through(), Some(Cursor::new(5, 0)));
        assert_eq!(rx.stats.stored_events, 5);
    }

    #[test]
    fn resend_after_lost_ack_is_a_duplicate_and_acked_again() {
        let mut rx = EvidenceRx::new(T, FP);
        rx.accept(&frame(0, 0, 3, &recs(0, 3), 0)).unwrap();
        // the ack was lost; the device times out and resends the same range as a new batch
        let o = rx.accept(&frame(1, 0, 3, &recs(0, 3), 0)).unwrap();
        assert!(matches!(o, Outcome::Duplicate { .. }));
        assert_eq!(o.ack(T), Some(Ack { tenant_id: T, batch_seq: 1, to: Cursor::new(3, 0) }));
        assert_eq!((rx.stats.stored_events, rx.stats.duplicate_events), (3, 3));
        let lines = outcome_to_jsonl(&o, &rx, 1.0);
        assert_eq!(lines.len(), 1, "a duplicate writes no evidence lines");
    }

    #[test]
    fn grown_resend_stores_only_the_new_tail() {
        let mut rx = EvidenceRx::new(T, FP);
        rx.accept(&frame(0, 0, 2, &recs(0, 2), 0)).unwrap();
        rx.accept(&frame(1, 2, 3, &recs(2, 3), 0)).unwrap();
        // both acks lost; the log grew meanwhile, so the resend from 0 covers more
        let o = rx.accept(&frame(2, 0, 5, &recs(0, 5), 0)).unwrap();
        assert!(matches!(o, Outcome::Stored { skip: 3, .. }), "{o:?}");
        assert_eq!(rx.stats.stored_events, 5, "every event stored exactly once");
        let lines = outcome_to_jsonl(&o, &rx, 1.0);
        assert_eq!(lines.len(), 3, "two new events + the frame line");
        let e: serde_json::Value = serde_json::from_str(&lines[0]).unwrap();
        assert_eq!(e["rule_id"], 103);
    }

    #[test]
    fn overlap_that_disagrees_with_stored_evidence_is_held() {
        let mut rx = EvidenceRx::new(T, FP);
        rx.accept(&frame(0, 0, 2, &recs(0, 2), 0)).unwrap();
        let mut bad = recs(0, 4);
        bad[1].rule_id = 999;
        let o = rx.accept(&frame(1, 0, 4, &bad, 0)).unwrap();
        assert!(matches!(o, Outcome::Held { why: Held::Inconsistent, .. }));
        assert_eq!(o.ack(T), None, "never ack evidence that was not stored");
        assert_eq!(rx.through(), Some(Cursor::new(2, 0)));
    }

    #[test]
    fn reordered_batch_is_held_not_acked() {
        let mut rx = EvidenceRx::new(T, FP);
        rx.accept(&frame(0, 0, 2, &recs(0, 2), 0)).unwrap();
        // batch 2 overtakes batch 1: acking it would let the device drop batch 1 unseen
        let o = rx.accept(&frame(2, 4, 6, &recs(4, 6), 0)).unwrap();
        assert!(matches!(o, Outcome::Held { why: Held::OutOfOrder, .. }));
        assert_eq!(o.ack(T), None);
        assert!(matches!(rx.accept(&frame(1, 2, 4, &recs(2, 4), 0)).unwrap(), Outcome::Stored { .. }));
        assert!(matches!(rx.accept(&frame(3, 4, 6, &recs(4, 6), 0)).unwrap(), Outcome::Stored { .. }));
        assert_eq!(rx.stats.stored_events, 6);
    }

    #[test]
    fn eviction_gap_is_stored_and_reported() {
        let mut rx = EvidenceRx::new(T, FP);
        rx.accept(&frame(0, 0, 2, &recs(0, 2), 0)).unwrap();
        // the device was offline long enough for the ring to overwrite records 2..10
        let o = rx.accept(&frame(1, 10, 12, &recs(10, 12), 8)).unwrap();
        assert!(matches!(o, Outcome::Stored { gap: Some((a, b)), .. } if a == Cursor::new(2, 0) && b == Cursor::new(10, 0)));
        assert_eq!(rx.stats.evicted_records, 8);
        let lines = outcome_to_jsonl(&o, &rx, 1.0);
        let f: serde_json::Value = serde_json::from_str(lines.last().unwrap()).unwrap();
        assert_eq!(f["gap"]["from"]["log_seq"], 2);
        assert_eq!(f["evicted_records"], 8);
    }

    #[test]
    fn foreign_identity_and_malformed_frames_are_refused() {
        let mut rx = EvidenceRx::new(T + 1, FP);
        assert_eq!(rx.accept(&frame(0, 0, 1, &recs(0, 1), 0)).unwrap_err(), EvErr::IdentityMismatch);
        let mut rx = EvidenceRx::new(T, FP);
        assert_eq!(rx.accept(b"HQX3 but too short").unwrap_err(), EvErr::Malformed);
        assert_eq!(rx.stats.frames, 0);
    }

    #[test]
    fn an_internal_address_on_the_wire_is_refused() {
        let mut b = frame(0, 0, 1, &recs(0, 1), 0);
        // forge the record into "public 192.168.1.50": serialize would refuse, so patch the bytes
        let o = wire::FRAME_HDR;
        b[o + 8..o + 12].copy_from_slice(&0xC0A8_0132u32.to_le_bytes());
        b[o + 17] = SrcKind::PublicV4 as u8;
        let mut rx = EvidenceRx::new(T, FP);
        assert_eq!(rx.accept(&b).unwrap_err(), EvErr::Privacy);
    }

    #[test]
    fn evidence_lines_carry_only_public_or_pseudonymous_sources() {
        let mut rx = EvidenceRx::new(T, FP);
        let rs = [
            ExportRec { src: 0x0808_0808, src_kind: SrcKind::PublicV4 as u8, ..rec(0) },
            ExportRec { src: 0x1122_3344, src_kind: SrcKind::Pseudonym as u8, rule_id: 122, ..rec(1) },
            rec(2),
        ];
        let o = rx.accept(&frame(0, 0, 3, &rs, 0)).unwrap();
        let v: Vec<serde_json::Value> = outcome_to_jsonl(&o, &rx, 1.0).iter().map(|l| serde_json::from_str(l).unwrap()).collect();
        assert_eq!((v[0]["src_ip"].as_str(), v[0]["src_kind"].as_str()), (Some("8.8.8.8"), Some("public_v4")));
        assert_eq!((v[1]["src_ip"].as_str(), v[1]["src_pseudonym"].as_str()), (Some(""), Some("11223344")));
        assert_eq!((v[2]["src_ip"].as_str(), v[2]["src_kind"].as_str()), (Some(""), Some("redacted")));
        assert_eq!(v[0]["ts"].as_f64(), Some(1_700_000_000.0));
    }
}
