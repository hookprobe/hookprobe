//! The fslog slot framing (kernel `fslog.rs`, M3.2), read side only.
//!
//! A slot is one 512-byte sector:
//! ```text
//!   0 magic u32 (REC_MAGIC)   16 len u16     24 digest[8] = SHA-256(bytes 0..24 ‖ payload)[..8]
//!   8 seq u64                 18 rtype u16   32 payload (<= 480 B)
//!                             20 reserved u32
//! ```
//! This mirrors `fslog::parse_record` + the ring-placement check in `fslog::LogStore::scan`.
//! The kernel's functions are private and the module needs the block-store types, so it cannot
//! be linked by `#[path]`; ADR 0066 asks the kernel to expose `parse_record` so the two stop
//! being separate copies. The framing digest is keyless: it catches torn writes, not forgery.
//! Forgery is caught by the seal (see `record`).

use boot_abi::sha256::Hasher;

pub const SEC: usize = 512;
pub const REC_HDR: usize = 32;
pub const MAX_PAYLOAD: usize = SEC - REC_HDR; // 480
pub const REC_MAGIC: u32 = 0x4652_4543; // b"CERF" LE

/// Untagged evidence batch (records written before the build tag).
pub const RT_EVIDENCE: u16 = 1;
/// Evidence batch led by a 16-byte build tag.
pub const RT_EVIDENCE_B: u16 = 5;
/// Evidence batch led by a 16-byte build tag and 16 bytes of provenance (ADR 0067 D10).
pub const RT_EVIDENCE_C: u16 = 6;

const R_SEQ: usize = 8;
const R_LEN: usize = 16;
const R_TYPE: usize = 18;
const R_DIGEST: usize = 24;

/// A slot that passed the framing checks.
#[derive(Clone, Copy, Debug)]
pub struct Slot<'a> {
    pub seq: u64,
    pub rtype: u16,
    /// The still-sealed payload.
    pub payload: &'a [u8],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SlotErr {
    /// No record magic: a never-written slot (or foreign data).
    Empty,
    /// Declared length larger than the slot.
    Oversize,
    /// The framing digest does not match: torn write or edited bytes.
    Torn,
    /// The record's seq does not belong in the slot it was read from (`seq % nslots != index`),
    /// or it is not the seq the reader asked for.
    Misplaced,
}

fn digest(sec: &[u8; SEC], len: usize) -> [u8; 8] {
    let mut h = Hasher::new();
    h.update(&sec[0..R_DIGEST]);
    h.update(&sec[REC_HDR..REC_HDR + len]);
    let d = h.finish();
    let mut o = [0u8; 8];
    o.copy_from_slice(&d[..8]);
    o
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

/// Parse the slot that should hold record `want_seq` of a ring with `nslots` slots.
/// Fail-closed: any doubt is an error, and the caller never sees the payload.
pub fn parse_slot(sec: &[u8; SEC], want_seq: u64, nslots: u64) -> Result<Slot<'_>, SlotErr> {
    if u32_at(sec, 0) != REC_MAGIC {
        return Err(SlotErr::Empty);
    }
    let len = u16_at(sec, R_LEN) as usize;
    if len > MAX_PAYLOAD {
        return Err(SlotErr::Oversize);
    }
    if sec[R_DIGEST..REC_HDR] != digest(sec, len) {
        return Err(SlotErr::Torn);
    }
    let seq = u64_at(sec, R_SEQ);
    if nslots == 0 || seq != want_seq || seq % nslots != want_seq % nslots {
        return Err(SlotErr::Misplaced);
    }
    Ok(Slot { seq, rtype: u16_at(sec, R_TYPE), payload: &sec[REC_HDR..REC_HDR + len] })
}

/// Frame a record exactly as `fslog::LogStore::append` writes it. Used by tests and fixtures;
/// the device never writes through this crate.
pub fn frame_slot(seq: u64, rtype: u16, payload: &[u8], out: &mut [u8; SEC]) -> bool {
    if payload.len() > MAX_PAYLOAD {
        return false;
    }
    *out = [0u8; SEC];
    out[0..4].copy_from_slice(&REC_MAGIC.to_le_bytes());
    out[R_SEQ..R_SEQ + 8].copy_from_slice(&seq.to_le_bytes());
    out[R_LEN..R_LEN + 2].copy_from_slice(&(payload.len() as u16).to_le_bytes());
    out[R_TYPE..R_TYPE + 2].copy_from_slice(&rtype.to_le_bytes());
    out[REC_HDR..REC_HDR + payload.len()].copy_from_slice(payload);
    let d = digest(out, payload.len());
    out[R_DIGEST..REC_HDR].copy_from_slice(&d);
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let mut s = [0u8; SEC];
        assert!(frame_slot(9, RT_EVIDENCE_B, b"hello", &mut s));
        let p = parse_slot(&s, 9, 4).unwrap();
        assert_eq!((p.seq, p.rtype, p.payload), (9, RT_EVIDENCE_B, &b"hello"[..]));
    }

    #[test]
    fn empty_torn_misplaced() {
        assert_eq!(parse_slot(&[0u8; SEC], 0, 4).unwrap_err(), SlotErr::Empty);
        let mut s = [0u8; SEC];
        frame_slot(9, RT_EVIDENCE, b"hello", &mut s);
        let mut t = s;
        t[REC_HDR] ^= 1;
        assert_eq!(parse_slot(&t, 9, 4).unwrap_err(), SlotErr::Torn);
        assert_eq!(parse_slot(&s, 5, 4).unwrap_err(), SlotErr::Misplaced); // same slot, older lap
        assert_eq!(parse_slot(&s, 9, 0).unwrap_err(), SlotErr::Misplaced);
        let mut o = s;
        o[R_LEN..R_LEN + 2].copy_from_slice(&481u16.to_le_bytes());
        assert_eq!(parse_slot(&o, 9, 4).unwrap_err(), SlotErr::Oversize);
    }
}
