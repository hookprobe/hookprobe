// SPDX-License-Identifier: AGPL-3.0-only
//! ADR 0067 D6 / build-plan item X2a, step 1 — the flow-event ABI between the kernel and a signed
//! detection module. A module is not called per packet: the kernel queues one fixed-size record per
//! flow event (a flow closed, or a periodic summary of a long flow) and hands a module a VECTOR of
//! records per EL0 round trip. The module answers one 2-bit verdict per record, packed in one word.
//!
//! This file is the wire format and the queue only (pure, host-tested). The resident host that
//! delivers a batch from the product loop is a later step; nothing here is on a packet path.
//!
//! Record, 16 bytes, little-endian:
//!   [0..4]  src IPv4 (host order)      [4..8]   dst IPv4 (host order)
//!   [8..10] dst port                   [10]     IP protocol          [11] kind (`KIND_*`)
//!   [12..14] packets, saturating       [14..16] bytes / 1024, saturating
//!
//! Verdict word: record `i` of a batch owns bits `2i..2i+2`: 0 = no answer (fail-closed: treated as a
//! module fault for that record), 1 = pass (nothing to report), 2 = alert, 3 = fault. A module can
//! only ever raise an ALERT: the kernel maps it to an observe-class event. Enforcement stays in
//! `decide()` (ADR 0023); a module verdict is never a wire action.

/// Bytes per record.
pub const REC_LEN: usize = 16;
/// Records per batch: one 32-bit verdict word carries 16 two-bit verdicts.
pub const BATCH_MAX: usize = 16;
/// Bytes of a full batch.
pub const BATCH_BYTES: usize = REC_LEN * BATCH_MAX;

pub const KIND_CLOSE: u8 = 1;
pub const KIND_SUMMARY: u8 = 2;

pub const V_NONE: u8 = 0;
pub const V_PASS: u8 = 1;
pub const V_ALERT: u8 = 2;
pub const V_FAULT: u8 = 3;

/// One flow event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FlowEvt {
    pub src: u32,
    pub dst: u32,
    pub dport: u16,
    pub proto: u8,
    pub kind: u8,
    pub pkts: u16,
    pub kbytes: u16,
}

impl FlowEvt {
    pub const EMPTY: FlowEvt = FlowEvt { src: 0, dst: 0, dport: 0, proto: 0, kind: 0, pkts: 0, kbytes: 0 };

    /// From flow counters: packets and bytes saturate, they never wrap.
    pub fn new(src: u32, dst: u32, dport: u16, proto: u8, kind: u8, pkts: u64, bytes: u64) -> FlowEvt {
        FlowEvt { src, dst, dport, proto, kind, pkts: pkts.min(u16::MAX as u64) as u16, kbytes: (bytes / 1024).min(u16::MAX as u64) as u16 }
    }

    pub fn encode(&self) -> [u8; REC_LEN] {
        let mut b = [0u8; REC_LEN];
        b[0..4].copy_from_slice(&self.src.to_le_bytes());
        b[4..8].copy_from_slice(&self.dst.to_le_bytes());
        b[8..10].copy_from_slice(&self.dport.to_le_bytes());
        b[10] = self.proto;
        b[11] = self.kind;
        b[12..14].copy_from_slice(&self.pkts.to_le_bytes());
        b[14..16].copy_from_slice(&self.kbytes.to_le_bytes());
        b
    }

    /// Decode one record. `None` when `b` is shorter than a record or the kind is unknown.
    pub fn decode(b: &[u8]) -> Option<FlowEvt> {
        if b.len() < REC_LEN || !(b[11] == KIND_CLOSE || b[11] == KIND_SUMMARY) {
            return None;
        }
        Some(FlowEvt {
            src: u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
            dst: u32::from_le_bytes([b[4], b[5], b[6], b[7]]),
            dport: u16::from_le_bytes([b[8], b[9]]),
            proto: b[10],
            kind: b[11],
            pkts: u16::from_le_bytes([b[12], b[13]]),
            kbytes: u16::from_le_bytes([b[14], b[15]]),
        })
    }
}

/// Pack up to `BATCH_MAX` verdicts into one word (extra verdicts are ignored; a value above 3 is a fault).
pub fn pack_verdicts(v: &[u8]) -> u32 {
    let mut w = 0u32;
    for (i, &x) in v.iter().take(BATCH_MAX).enumerate() {
        w |= (if x > V_FAULT { V_FAULT } else { x } as u32) << (2 * i);
    }
    w
}

/// The verdict of record `i` in a verdict word (`V_NONE` beyond the batch).
pub fn verdict_at(word: u32, i: usize) -> u8 {
    if i >= BATCH_MAX {
        return V_NONE;
    }
    ((word >> (2 * i)) & 3) as u8
}

/// What the kernel does with a module's answer for a batch of `n` records: how many alerts to
/// raise and how many records count as a module fault. A record with no answer, a fault marker, or
/// any answer for a record that was not in the batch is a fault: fail-closed, never a silent pass.
pub fn tally(word: u32, n: usize) -> (u32, u32) {
    let (mut alerts, mut faults) = (0u32, 0u32);
    for i in 0..BATCH_MAX {
        let v = verdict_at(word, i);
        if i < n {
            match v {
                V_ALERT => alerts += 1,
                V_PASS => {}
                _ => faults += 1,
            }
        } else if v != V_NONE {
            faults += 1;
        }
    }
    (alerts, faults)
}

/// A bounded queue of flow events (single producer and consumer on one core). When it is full the
/// OLDEST event is overwritten and counted: flow events are evidence for detection, not state the
/// data plane depends on, and the count is reported so the loss is never hidden.
pub struct Queue<const N: usize> {
    buf: [FlowEvt; N],
    head: usize,
    len: usize,
    pub dropped: u64,
    pub pushed: u64,
}

impl<const N: usize> Default for Queue<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> Queue<N> {
    pub const fn new() -> Self {
        Queue { buf: [FlowEvt::EMPTY; N], head: 0, len: 0, dropped: 0, pushed: 0 }
    }
    pub fn len(&self) -> usize {
        self.len
    }
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
    pub fn push(&mut self, e: FlowEvt) {
        self.pushed += 1;
        if self.len == N {
            self.head = (self.head + 1) % N; // overwrite the oldest
            self.len -= 1;
            self.dropped += 1;
        }
        self.buf[(self.head + self.len) % N] = e;
        self.len += 1;
    }
    /// Move up to `BATCH_MAX` of the oldest events into `out` as encoded records, oldest first.
    /// Returns the number of records written (`out` must hold `BATCH_BYTES`; a shorter `out` takes fewer).
    pub fn drain_batch(&mut self, out: &mut [u8]) -> usize {
        let n = self.len.min(BATCH_MAX).min(out.len() / REC_LEN);
        for i in 0..n {
            out[i * REC_LEN..(i + 1) * REC_LEN].copy_from_slice(&self.buf[(self.head + i) % N].encode());
        }
        self.head = (self.head + n) % N;
        self.len -= n;
        n
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(i: u32) -> FlowEvt {
        FlowEvt::new(0x0a00_0000 + i, 0x5db8_d822, 443 + i as u16, 6, if i % 2 == 0 { KIND_CLOSE } else { KIND_SUMMARY }, i as u64 * 3, i as u64 * 5000)
    }

    #[test]
    fn record_round_trips_and_saturates() {
        let e = ev(7);
        assert_eq!(FlowEvt::decode(&e.encode()), Some(e));
        let big = FlowEvt::new(1, 2, 3, 17, KIND_CLOSE, u64::MAX, u64::MAX);
        assert_eq!((big.pkts, big.kbytes), (u16::MAX, u16::MAX));
        assert_eq!(FlowEvt::decode(&big.encode()), Some(big));
    }

    #[test]
    fn decode_refuses_short_and_unknown_kind() {
        let mut b = ev(1).encode();
        assert!(FlowEvt::decode(&b[..REC_LEN - 1]).is_none());
        b[11] = 0;
        assert!(FlowEvt::decode(&b).is_none());
        b[11] = 9;
        assert!(FlowEvt::decode(&b).is_none());
    }

    #[test]
    fn verdict_word_packs_sixteen_and_clamps() {
        let v: [u8; 18] = [1, 2, 3, 0, 1, 1, 2, 2, 9, 1, 1, 1, 1, 1, 1, 2, 2, 2];
        let w = pack_verdicts(&v);
        for i in 0..BATCH_MAX {
            assert_eq!(verdict_at(w, i), if v[i] > 3 { V_FAULT } else { v[i] }, "record {i}");
        }
        assert_eq!(verdict_at(w, BATCH_MAX), V_NONE);
        assert_eq!(pack_verdicts(&[]), 0);
    }

    #[test]
    fn tally_is_fail_closed() {
        // 3 records: pass, alert, alert
        assert_eq!(tally(pack_verdicts(&[1, 2, 2]), 3), (2, 0));
        // an unanswered record and a fault marker are faults, never passes
        assert_eq!(tally(pack_verdicts(&[1, 0, 3]), 3), (0, 2));
        // the all-ones "fail" word of a crashed host: every record is a fault, no alert is invented
        assert_eq!(tally(0xffff_ffff, 5), (0, 16));
        // an answer for a record that was not in the batch is a fault
        assert_eq!(tally(pack_verdicts(&[1, 1, 2]), 2), (0, 1));
        // an empty batch with an empty word is clean
        assert_eq!(tally(0, 0), (0, 0));
    }

    #[test]
    fn queue_drains_oldest_first_in_batches() {
        let mut q: Queue<64> = Queue::new();
        for i in 0..40 {
            q.push(ev(i));
        }
        let mut out = [0u8; BATCH_BYTES];
        let mut seen = 0u32;
        loop {
            let n = q.drain_batch(&mut out);
            if n == 0 {
                break;
            }
            assert!(n <= BATCH_MAX);
            for k in 0..n {
                assert_eq!(FlowEvt::decode(&out[k * REC_LEN..]), Some(ev(seen)));
                seen += 1;
            }
        }
        assert_eq!((seen, q.len(), q.dropped, q.pushed), (40, 0, 0, 40));
    }

    #[test]
    fn full_queue_overwrites_the_oldest_and_counts_it() {
        let mut q: Queue<8> = Queue::new();
        for i in 0..20 {
            q.push(ev(i));
        }
        assert_eq!((q.len(), q.dropped, q.pushed), (8, 12, 20));
        let mut out = [0u8; BATCH_BYTES];
        let n = q.drain_batch(&mut out);
        assert_eq!(n, 8);
        for k in 0..n {
            assert_eq!(FlowEvt::decode(&out[k * REC_LEN..]), Some(ev(12 + k as u32)));
        }
        assert!(q.is_empty());
    }

    #[test]
    fn short_output_takes_fewer_records_and_keeps_the_rest() {
        let mut q: Queue<8> = Queue::new();
        for i in 0..5 {
            q.push(ev(i));
        }
        let mut out = [0u8; 2 * REC_LEN + 7];
        assert_eq!(q.drain_batch(&mut out), 2);
        assert_eq!(q.len(), 3);
        let mut rest = [0u8; BATCH_BYTES];
        assert_eq!(q.drain_batch(&mut rest), 3);
        assert_eq!(FlowEvt::decode(&rest), Some(ev(2)));
    }
}
