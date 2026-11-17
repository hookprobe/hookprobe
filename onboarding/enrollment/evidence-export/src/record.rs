//! Open and check one sealed evidence record.
//!
//! The payload of an evidence slot is an HQKSEAL1 blob (kernel `seal.rs`) under the evidence
//! volume key `HKDF(SRK, "HQ-evidence-log-v1")`, bound to the device-only seal policy. This crate
//! never holds that key: the kernel passes a [`SealOpener`] that calls `seal::unseal` (ADR 0066).
//! The opener must authenticate before it decrypts and must write no plaintext on failure, which
//! is what `seal::unseal` already guarantees.
//!
//! Inside the seal (kernel `evlog.rs`):
//! * `RT_EVIDENCE_B`: a 16-byte build tag, then up to 21 event images of 16 bytes;
//! * `RT_EVIDENCE`: up to 22 event images, no tag (records written before the tag existed).
//!
//! Event image (kernel `export::ev_to_image`), little-endian:
//! `ts u64 (wall-clock ms, 0 = time unknown) | src u32 | rule_id u16 | severity u8 | verdict u8`.

use crate::slot::{self, SlotErr, RT_EVIDENCE, RT_EVIDENCE_B, SEC};

pub const SEAL_HDR_LEN: usize = 128;
pub const SEAL_MAGIC: &[u8; 8] = b"HQKSEAL1";
/// Largest plaintext a sealed slot can hold (480 − 128).
pub const MAX_SEALED_PAYLOAD: usize = slot::MAX_PAYLOAD - SEAL_HDR_LEN; // 352
pub const EV_IMAGE_LEN: usize = 16;
pub const BUILD_TAG_LEN: usize = 16;
/// Most images one record can carry (the untagged layout).
pub const MAX_IMAGES: usize = MAX_SEALED_PAYLOAD / EV_IMAGE_LEN; // 22

/// The wire verdict values (`events::Event::verdict`).
pub const VERDICT_PASS: u8 = 1;
pub const VERDICT_DROP: u8 = 2;

/// Opens an HQKSEAL1 blob with the device's evidence key. On the device this wraps
/// `seal::unseal(&vek, &evidence_policy(device_id), blob, out)`.
pub trait SealOpener {
    /// Authenticate `blob`, then decrypt it into `out`; return the plaintext length.
    /// On any failure return `Err` and leave `out` untouched.
    fn open(&self, blob: &[u8], out: &mut [u8]) -> Result<usize, ()>;
}

/// One event read back from the log.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Event {
    pub ts_ms: u64,
    pub src: u32,
    pub rule_id: u16,
    pub severity: u8,
    pub verdict: u8,
}

/// A record whose framing, seal and layout all checked out.
#[derive(Clone, Copy, Debug)]
pub struct Verified {
    pub seq: u64,
    pub build_tag: Option<[u8; BUILD_TAG_LEN]>,
    pub n: usize,
    pub events: [Event; MAX_IMAGES],
}

impl Verified {
    pub fn events(&self) -> &[Event] {
        &self.events[..self.n]
    }
}

/// Why a slot produced nothing to export.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Not an error: never written, or a non-evidence record type. Skipped silently.
    Skip,
    /// Evidence that failed a check. Counted and reported in the next frame, never exported.
    Reject(Reject),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reject {
    /// Framing digest or ring placement failed (torn write, edit, transplanted slot).
    Framing(SlotErr),
    /// Too short to hold a seal header, or not an HQKSEAL1 blob.
    NotSealed,
    /// The seal did not authenticate under the device key (tampered, or another device's data).
    Seal,
    /// Authenticated, but the plaintext is not a whole number of event images.
    Layout,
    /// Authenticated, but an image carries a value the kernel never writes.
    BadImage,
}

fn img(b: &[u8]) -> Event {
    let mut ts = [0u8; 8];
    ts.copy_from_slice(&b[0..8]);
    Event {
        ts_ms: u64::from_le_bytes(ts),
        src: u32::from_le_bytes([b[8], b[9], b[10], b[11]]),
        rule_id: u16::from_le_bytes([b[12], b[13]]),
        severity: b[14],
        verdict: b[15],
    }
}

/// Check the slot that should hold log record `seq` and return its events.
pub fn verify<O: SealOpener + ?Sized>(sec: &[u8; SEC], seq: u64, nslots: u64, opener: &O) -> Result<Verified, Outcome> {
    let s = match slot::parse_slot(sec, seq, nslots) {
        Ok(s) => s,
        Err(SlotErr::Empty) => return Err(Outcome::Skip),
        Err(e) => return Err(Outcome::Reject(Reject::Framing(e))),
    };
    let tagged = match s.rtype {
        RT_EVIDENCE_B => true,
        RT_EVIDENCE => false,
        _ => return Err(Outcome::Skip), // another record type sharing the log: not evidence
    };
    if s.payload.len() < SEAL_HDR_LEN || &s.payload[..8] != SEAL_MAGIC {
        return Err(Outcome::Reject(Reject::NotSealed));
    }
    let mut pt = [0u8; MAX_SEALED_PAYLOAD];
    let n = opener.open(s.payload, &mut pt).map_err(|_| Outcome::Reject(Reject::Seal))?;
    if n > MAX_SEALED_PAYLOAD {
        return Err(Outcome::Reject(Reject::Layout));
    }
    let (build_tag, body) = if tagged {
        if n < BUILD_TAG_LEN {
            return Err(Outcome::Reject(Reject::Layout));
        }
        let mut t = [0u8; BUILD_TAG_LEN];
        t.copy_from_slice(&pt[..BUILD_TAG_LEN]);
        (Some(t), &pt[BUILD_TAG_LEN..n])
    } else {
        (None, &pt[..n])
    };
    if body.len() % EV_IMAGE_LEN != 0 {
        return Err(Outcome::Reject(Reject::Layout));
    }
    let mut v = Verified { seq, build_tag, n: 0, events: [Event::default(); MAX_IMAGES] };
    for chunk in body.chunks_exact(EV_IMAGE_LEN) {
        let e = img(chunk);
        if e.verdict != VERDICT_PASS && e.verdict != VERDICT_DROP {
            return Err(Outcome::Reject(Reject::BadImage));
        }
        v.events[v.n] = e;
        v.n += 1;
    }
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{sealed_slot, TestOpener};

    fn ev(i: u32) -> Event {
        Event { ts_ms: 1_700_000_000_000 + i as u64, src: 0x0A00_0001 + i, rule_id: 7, severity: 3, verdict: VERDICT_DROP }
    }

    #[test]
    fn opens_tagged_and_untagged() {
        let o = TestOpener::new([1; 32]);
        let evs = [ev(0), ev(1), ev(2)];
        let s = sealed_slot(&o, 12, 8, true, &evs);
        let v = verify(&s, 12, 8, &o).unwrap();
        assert_eq!(v.events(), &evs);
        assert!(v.build_tag.is_some());
        let s = sealed_slot(&o, 13, 8, false, &evs);
        assert_eq!(verify(&s, 13, 8, &o).unwrap().events(), &evs);
    }

    /// Deliverable (b): a corrupted or tampered sealed record is rejected, never exported.
    #[test]
    fn tampered_records_are_rejected() {
        let o = TestOpener::new([1; 32]);
        let good = sealed_slot(&o, 3, 8, true, &[ev(0), ev(1)]);

        // A ciphertext edit whose framing digest is recomputed (what a forger would do):
        // only the seal catches it.
        let mut forged = good;
        let p = crate::slot::REC_HDR + SEAL_HDR_LEN + 5;
        forged[p] ^= 0x40;
        let payload_len = u16::from_le_bytes([forged[16], forged[17]]) as usize;
        let mut re = [0u8; SEC];
        crate::slot::frame_slot(3, RT_EVIDENCE_B, &forged[32..32 + payload_len], &mut re);
        assert_eq!(verify(&re, 3, 8, &o).unwrap_err(), Outcome::Reject(Reject::Seal));

        // A raw bit flip without fixing the digest: torn.
        let mut torn = good;
        torn[200] ^= 1;
        assert_eq!(verify(&torn, 3, 8, &o).unwrap_err(), Outcome::Reject(Reject::Framing(SlotErr::Torn)));

        // The right record read for the wrong position (a slot transplanted from an older lap).
        assert_eq!(verify(&good, 11, 8, &o).unwrap_err(), Outcome::Reject(Reject::Framing(SlotErr::Misplaced)));

        // Another device's key.
        let other = TestOpener::new([2; 32]);
        assert_eq!(verify(&good, 3, 8, &other).unwrap_err(), Outcome::Reject(Reject::Seal));

        // Not a seal at all.
        let mut plain = [0u8; SEC];
        crate::slot::frame_slot(3, RT_EVIDENCE_B, &[0u8; 160], &mut plain);
        assert_eq!(verify(&plain, 3, 8, &o).unwrap_err(), Outcome::Reject(Reject::NotSealed));
    }

    #[test]
    fn authenticated_but_malformed_is_rejected() {
        let o = TestOpener::new([1; 32]);
        // 16-byte tag + 20 bytes: not a whole image.
        let s = crate::testutil::sealed_raw(&o, 4, 8, RT_EVIDENCE_B, &[0u8; 36]);
        assert_eq!(verify(&s, 4, 8, &o).unwrap_err(), Outcome::Reject(Reject::Layout));
        // An image with verdict 0, which the kernel never writes.
        let mut bad = ev(0);
        bad.verdict = 0;
        let s = sealed_slot(&o, 4, 8, true, &[bad]);
        assert_eq!(verify(&s, 4, 8, &o).unwrap_err(), Outcome::Reject(Reject::BadImage));
    }

    #[test]
    fn empty_and_other_types_are_skipped() {
        let o = TestOpener::new([1; 32]);
        assert_eq!(verify(&[0u8; SEC], 0, 8, &o).unwrap_err(), Outcome::Skip);
        let s = crate::testutil::sealed_raw(&o, 2, 8, 2 /* RT_QSECBIT */, &[0u8; 16]);
        assert_eq!(verify(&s, 2, 8, &o).unwrap_err(), Outcome::Skip);
    }
}
