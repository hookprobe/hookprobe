//! HQX3: the sealed-evidence export frame and its ack, as pure codecs (no channel crypto).
//!
//! The live stream (`exportwire.rs`, HQX1 v2) numbers events per boot from a RAM queue. Records
//! read back from the log span reboots and are resent after a lost ack, so HQX3 numbers them by
//! their place in the log instead: a [`Cursor`] `(log_seq, idx)` is "event `idx` of log record
//! `log_seq`", and fslog's `log_seq` only grows, across reboots too. The receiver de-duplicates on
//! the cursor, so a resend after a timeout is harmless.
//!
//! Both messages are sealed on the enrolled Noise session (ML-KEM-768 + X25519) with their own
//! associated data, so neither can be opened as the other or as any other record type:
//! [`AD_FRAME`] device→control plane, [`AD_ACK`] control plane→device. Replay of the sealed
//! datagrams is the session's job (explicit seq + the RFC 6479 window); replay of an ack *inside*
//! the session is the queue's job (acks are cumulative and only move the cursor forward).
//!
//! Frame layout (little-endian), header `FRAME_HDR` = 128 bytes:
//! ```text
//!   0 magic u32 "HQX3" | 4 version u16 = 1 | 6 n u16 | 8 tenant_id u64 | 16 device_fp [32]
//!  48 batch_seq u64    | 56 from.log_seq u64 | 64 from.idx u8 | 65 to.idx u8 | 66 reserved u16
//!  68 rejected u32     | 72 to.log_seq u64   | 80 evicted u64
//!  88 qs.n u16 | 90 reserved u16 | 92 qs.span_ms u32 | 96 qs.min u32 | 100 qs.max u32
//! 104 qs.mean u32 | 108 qs.last u32 | 112 qs.last_ts_ms u64 | 120 reserved u64
//! ```
//! `[from, to)` is the log range the frame accounts for: every event in it is either one of the
//! `n` records or was in a rejected log record. Then `n` × `REC_LEN` = 20-byte records:
//! `ts_ms u64 | src u32 | rule_id u16 | severity u8 | verdict u8 | class u8 | src_kind u8 | reserved u16`.
//!
//! Ack layout, `ACK_LEN` = 48 bytes:
//! `0 magic "HQXA" | 4 version u16 = 1 | 6 reserved u16 | 8 tenant_id u64 | 16 batch_seq u64 |
//!  24 to.log_seq u64 | 32 to.idx u8 | 33 reserved [15]`.

use crate::anon::{is_internal_v4, ExportRec, SrcKind};
use crate::qsecbit::Summary;

pub const MAGIC: u32 = 0x3358_5148; // b"HQX3" LE
pub const ACK_MAGIC: u32 = 0x4158_5148; // b"HQXA" LE
pub const VERSION: u16 = 1;
pub const FRAME_HDR: usize = 128;
pub const REC_LEN: usize = 20;
/// Records per frame. 128 + 32·20 = 768 B, so a sealed frame stays one unfragmented datagram
/// on a 1280-byte IPv6 minimum MTU.
pub const MAX_RECS: usize = 32;
pub const MAX_FRAME: usize = FRAME_HDR + MAX_RECS * REC_LEN;
pub const ACK_LEN: usize = 48;
pub const AD_FRAME: &[u8] = b"HQX3-evidence";
pub const AD_ACK: &[u8] = b"HQX3-evidence-ack";

/// A position in the evidence log: event `idx` of record `log_seq`. Ordered by `(log_seq, idx)`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Cursor {
    pub log_seq: u64,
    pub idx: u8,
}

impl Cursor {
    pub const START: Cursor = Cursor { log_seq: 0, idx: 0 };
    pub const fn new(log_seq: u64, idx: u8) -> Self {
        Cursor { log_seq, idx }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Header {
    pub tenant_id: u64,
    pub device_fp: [u8; 32],
    pub batch_seq: u64,
    pub from: Cursor,
    pub to: Cursor,
    /// Log records in `[from, to)` that failed verification (tamper/corruption), not exported.
    pub rejected: u32,
    /// Log records the ring overwrote before they were synced (lost to retention, reported).
    pub evicted: u64,
    pub qsecbit: Summary,
}

#[derive(Clone, Copy, Debug)]
pub struct Frame {
    pub hdr: Header,
    pub n: usize,
    pub recs: [ExportRec; MAX_RECS],
}

impl Frame {
    pub fn records(&self) -> &[ExportRec] {
        &self.recs[..self.n]
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ack {
    pub tenant_id: u64,
    pub batch_seq: u64,
    pub to: Cursor,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WireErr {
    TooManyRecords,
    ShortBuffer,
    Malformed,
    /// A record breaks the privacy rules (an internal address marked public, a redacted source
    /// that is not zero, an unknown source kind). Refused on both ends.
    Privacy,
}

fn put(b: &mut [u8], o: usize, v: &[u8]) {
    b[o..o + v.len()].copy_from_slice(v);
}
fn u16_at(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}
fn u32_at(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}
fn u64_at(b: &[u8], o: usize) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[o..o + 8]);
    u64::from_le_bytes(a)
}

/// The privacy rules a record must satisfy to be on the wire.
pub fn record_is_clean(r: &ExportRec) -> bool {
    match SrcKind::from_u8(r.src_kind) {
        Some(SrcKind::None) | Some(SrcKind::Redacted) => r.src == 0,
        Some(SrcKind::PublicV4) => r.src != 0 && !is_internal_v4(r.src),
        Some(SrcKind::Pseudonym) => true,
        None => false,
    }
}

/// Serialize a frame. Fail-closed: a record that breaks the privacy rules aborts the frame.
pub fn serialize(hdr: &Header, recs: &[ExportRec], out: &mut [u8]) -> Result<usize, WireErr> {
    if recs.len() > MAX_RECS {
        return Err(WireErr::TooManyRecords);
    }
    if !recs.iter().all(record_is_clean) {
        return Err(WireErr::Privacy);
    }
    let total = FRAME_HDR + recs.len() * REC_LEN;
    if out.len() < total {
        return Err(WireErr::ShortBuffer);
    }
    for x in out[..total].iter_mut() {
        *x = 0;
    }
    put(out, 0, &MAGIC.to_le_bytes());
    put(out, 4, &VERSION.to_le_bytes());
    put(out, 6, &(recs.len() as u16).to_le_bytes());
    put(out, 8, &hdr.tenant_id.to_le_bytes());
    put(out, 16, &hdr.device_fp);
    put(out, 48, &hdr.batch_seq.to_le_bytes());
    put(out, 56, &hdr.from.log_seq.to_le_bytes());
    out[64] = hdr.from.idx;
    out[65] = hdr.to.idx;
    put(out, 68, &hdr.rejected.to_le_bytes());
    put(out, 72, &hdr.to.log_seq.to_le_bytes());
    put(out, 80, &hdr.evicted.to_le_bytes());
    let q = &hdr.qsecbit;
    put(out, 88, &q.n.to_le_bytes());
    put(out, 92, &q.span_ms.to_le_bytes());
    put(out, 96, &q.min.to_le_bytes());
    put(out, 100, &q.max.to_le_bytes());
    put(out, 104, &q.mean.to_le_bytes());
    put(out, 108, &q.last.to_le_bytes());
    put(out, 112, &q.last_ts_ms.to_le_bytes());
    for (i, r) in recs.iter().enumerate() {
        let o = FRAME_HDR + i * REC_LEN;
        put(out, o, &r.ts_ms.to_le_bytes());
        put(out, o + 8, &r.src.to_le_bytes());
        put(out, o + 12, &r.rule_id.to_le_bytes());
        out[o + 14] = r.severity;
        out[o + 15] = r.verdict;
        out[o + 16] = r.class;
        out[o + 17] = r.src_kind;
    }
    Ok(total)
}

/// Parse a decrypted frame. Validates magic, version, length, range order and the privacy rules
/// of every record. Identity (tenant, device) is the caller's check.
pub fn parse(b: &[u8]) -> Result<Frame, WireErr> {
    if b.len() < FRAME_HDR || u32_at(b, 0) != MAGIC || u16_at(b, 4) != VERSION {
        return Err(WireErr::Malformed);
    }
    let n = u16_at(b, 6) as usize;
    if n > MAX_RECS || b.len() != FRAME_HDR + n * REC_LEN {
        return Err(WireErr::Malformed);
    }
    let mut device_fp = [0u8; 32];
    device_fp.copy_from_slice(&b[16..48]);
    let hdr = Header {
        tenant_id: u64_at(b, 8),
        device_fp,
        batch_seq: u64_at(b, 48),
        from: Cursor::new(u64_at(b, 56), b[64]),
        to: Cursor::new(u64_at(b, 72), b[65]),
        rejected: u32_at(b, 68),
        evicted: u64_at(b, 80),
        qsecbit: Summary {
            n: u16_at(b, 88),
            span_ms: u32_at(b, 92),
            min: u32_at(b, 96),
            max: u32_at(b, 100),
            mean: u32_at(b, 104),
            last: u32_at(b, 108),
            last_ts_ms: u64_at(b, 112),
        },
    };
    if hdr.to < hdr.from || (n > 0 && hdr.to == hdr.from) {
        return Err(WireErr::Malformed);
    }
    let mut recs = [ExportRec::default(); MAX_RECS];
    for (i, r) in recs.iter_mut().enumerate().take(n) {
        let o = FRAME_HDR + i * REC_LEN;
        *r = ExportRec {
            ts_ms: u64_at(b, o),
            src: u32_at(b, o + 8),
            rule_id: u16_at(b, o + 12),
            severity: b[o + 14],
            verdict: b[o + 15],
            class: b[o + 16],
            src_kind: b[o + 17],
        };
        if !record_is_clean(r) {
            return Err(WireErr::Privacy);
        }
    }
    Ok(Frame { hdr, n, recs })
}

pub fn serialize_ack(a: &Ack, out: &mut [u8]) -> Result<usize, WireErr> {
    if out.len() < ACK_LEN {
        return Err(WireErr::ShortBuffer);
    }
    for x in out[..ACK_LEN].iter_mut() {
        *x = 0;
    }
    put(out, 0, &ACK_MAGIC.to_le_bytes());
    put(out, 4, &VERSION.to_le_bytes());
    put(out, 8, &a.tenant_id.to_le_bytes());
    put(out, 16, &a.batch_seq.to_le_bytes());
    put(out, 24, &a.to.log_seq.to_le_bytes());
    out[32] = a.to.idx;
    Ok(ACK_LEN)
}

pub fn parse_ack(b: &[u8]) -> Result<Ack, WireErr> {
    if b.len() != ACK_LEN || u32_at(b, 0) != ACK_MAGIC || u16_at(b, 4) != VERSION {
        return Err(WireErr::Malformed);
    }
    Ok(Ack { tenant_id: u64_at(b, 8), batch_seq: u64_at(b, 16), to: Cursor::new(u64_at(b, 24), b[32]) })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(src: u32, kind: SrcKind) -> ExportRec {
        ExportRec { ts_ms: 5, src, src_kind: kind as u8, rule_id: 9, severity: 1, verdict: 2, class: 0 }
    }

    fn hdr() -> Header {
        Header {
            tenant_id: 7,
            device_fp: [3; 32],
            batch_seq: 11,
            from: Cursor::new(4, 2),
            to: Cursor::new(6, 0),
            rejected: 1,
            evicted: 2,
            qsecbit: Summary { n: 3, span_ms: 9, min: 1, max: 5, mean: 3, last: 4, last_ts_ms: 99 },
        }
    }

    #[test]
    fn frame_round_trip() {
        let recs = [rec(0, SrcKind::None), rec(0xCB00_7207, SrcKind::PublicV4), rec(0x1234, SrcKind::Pseudonym)];
        let mut b = [0u8; MAX_FRAME];
        let n = serialize(&hdr(), &recs, &mut b).unwrap();
        assert_eq!(n, FRAME_HDR + 3 * REC_LEN);
        let f = parse(&b[..n]).unwrap();
        assert_eq!(f.hdr, hdr());
        assert_eq!(f.records(), &recs);
    }

    /// Deliverable (a), defence in depth: the codec itself refuses to carry an internal address,
    /// on the device (serialize) and on the receiver (parse).
    #[test]
    fn codec_refuses_internal_addresses() {
        let mut b = [0u8; MAX_FRAME];
        let leak = rec(0xC0A8_0101, SrcKind::PublicV4); // 192.168.1.1 claimed public
        assert_eq!(serialize(&hdr(), &[leak], &mut b), Err(WireErr::Privacy));
        let hidden = rec(0x0A00_0001, SrcKind::Redacted); // "redacted" but still carries 10.0.0.1
        assert_eq!(serialize(&hdr(), &[hidden], &mut b), Err(WireErr::Privacy));
        // A frame forged on the wire with an internal address is refused on parse.
        let n = serialize(&hdr(), &[rec(0xCB00_7207, SrcKind::PublicV4)], &mut b).unwrap();
        b[FRAME_HDR + 8..FRAME_HDR + 12].copy_from_slice(&0xAC10_0005u32.to_le_bytes());
        assert_eq!(parse(&b[..n]).unwrap_err(), WireErr::Privacy);
        b[FRAME_HDR + 17] = 9; // unknown kind
        assert_eq!(parse(&b[..n]).unwrap_err(), WireErr::Privacy);
    }

    #[test]
    fn malformed_frames_refused() {
        let mut b = [0u8; MAX_FRAME];
        let n = serialize(&hdr(), &[], &mut b).unwrap();
        assert!(parse(&b[..n - 1]).is_err());
        let mut v = b;
        v[4] = 2;
        assert_eq!(parse(&v[..n]).unwrap_err(), WireErr::Malformed);
        let mut back = hdr();
        back.to = Cursor::new(1, 0); // range runs backwards
        let n = serialize(&back, &[], &mut b).unwrap();
        assert_eq!(parse(&b[..n]).unwrap_err(), WireErr::Malformed);
    }

    #[test]
    fn ack_round_trip() {
        let a = Ack { tenant_id: 7, batch_seq: 3, to: Cursor::new(10, 4) };
        let mut b = [0u8; ACK_LEN];
        serialize_ack(&a, &mut b).unwrap();
        assert_eq!(parse_ack(&b), Ok(a));
        b[0] ^= 1;
        assert!(parse_ack(&b).is_err());
    }

    #[test]
    fn cursor_order() {
        assert!(Cursor::new(1, 9) < Cursor::new(2, 0));
        assert!(Cursor::new(2, 0) < Cursor::new(2, 1));
    }
}
