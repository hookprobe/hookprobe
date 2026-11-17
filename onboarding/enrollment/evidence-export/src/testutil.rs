//! Test fixtures: a stand-in sealer and a fake log.
//!
//! `TestOpener` is NOT HQKSEAL1. It only reproduces the properties the export relies on: a
//! 128-byte header with the HQKSEAL1 magic, a keyed tag over header and ciphertext checked before
//! anything is decrypted, and a different key failing. The real opener is the kernel's
//! `seal::unseal` (ADR 0066); the library treats opening as opaque, so these tests exercise the
//! library's handling of open/refuse, not the cipher.

use crate::record::{Event, SealOpener, BUILD_TAG_LEN, EV_IMAGE_LEN, MAX_SEALED_PAYLOAD, SEAL_HDR_LEN, SEAL_MAGIC};
use crate::slot::{frame_slot, RT_EVIDENCE, RT_EVIDENCE_B, SEC};
use boot_abi::kdf;

pub struct TestOpener {
    key: [u8; 32],
}

impl TestOpener {
    pub fn new(key: [u8; 32]) -> Self {
        TestOpener { key }
    }

    pub fn seal(&self, pt: &[u8], out: &mut [u8]) -> usize {
        assert!(pt.len() <= MAX_SEALED_PAYLOAD);
        let n = SEAL_HDR_LEN + pt.len();
        out[..SEAL_HDR_LEN].fill(0);
        out[..8].copy_from_slice(SEAL_MAGIC);
        out[64..68].copy_from_slice(&(pt.len() as u32).to_le_bytes());
        out[SEAL_HDR_LEN..n].copy_from_slice(pt);
        kdf::ctr_xor_nonce(&self.key, &[0u8; 16], &mut out[SEAL_HDR_LEN..n]);
        let tag = kdf::hmac_sha256_2(&self.key, &out[..96], &out[SEAL_HDR_LEN..n]);
        out[96..128].copy_from_slice(&tag);
        n
    }
}

impl SealOpener for TestOpener {
    fn open(&self, blob: &[u8], out: &mut [u8]) -> Result<usize, ()> {
        if blob.len() < SEAL_HDR_LEN {
            return Err(());
        }
        let n = u32::from_le_bytes([blob[64], blob[65], blob[66], blob[67]]) as usize;
        if SEAL_HDR_LEN + n != blob.len() || n > out.len() {
            return Err(());
        }
        let tag = kdf::hmac_sha256_2(&self.key, &blob[..96], &blob[SEAL_HDR_LEN..]);
        if !kdf::ct_eq(&tag, &blob[96..128]) {
            return Err(());
        }
        out[..n].copy_from_slice(&blob[SEAL_HDR_LEN..]);
        kdf::ctr_xor_nonce(&self.key, &[0u8; 16], &mut out[..n]);
        Ok(n)
    }
}

pub fn sealed_raw(o: &TestOpener, seq: u64, _nslots: u64, rtype: u16, pt: &[u8]) -> [u8; SEC] {
    let mut blob = [0u8; 480];
    let n = o.seal(pt, &mut blob);
    let mut s = [0u8; SEC];
    assert!(frame_slot(seq, rtype, &blob[..n], &mut s));
    s
}

pub fn sealed_slot(o: &TestOpener, seq: u64, nslots: u64, tagged: bool, evs: &[Event]) -> [u8; SEC] {
    let mut pt = [0u8; MAX_SEALED_PAYLOAD];
    let mut n = 0;
    if tagged {
        pt[..BUILD_TAG_LEN].copy_from_slice(b"test-build-tag!!");
        n = BUILD_TAG_LEN;
    }
    for e in evs {
        pt[n..n + 8].copy_from_slice(&e.ts_ms.to_le_bytes());
        pt[n + 8..n + 12].copy_from_slice(&e.src.to_le_bytes());
        pt[n + 12..n + 14].copy_from_slice(&e.rule_id.to_le_bytes());
        pt[n + 14] = e.severity;
        pt[n + 15] = e.verdict;
        n += EV_IMAGE_LEN;
    }
    sealed_raw(o, seq, nslots, if tagged { RT_EVIDENCE_B } else { RT_EVIDENCE }, &pt[..n])
}
