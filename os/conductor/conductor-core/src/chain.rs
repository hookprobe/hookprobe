// SPDX-License-Identifier: AGPL-3.0-only
//! The delegation ledger as a hash chain (C1 logic, built and tested here so the kernel can lift it as is).
//!
//! Each entry: `seq u64 ‖ prev_mac[32] ‖ record[RECORD_LEN] ‖ mac[32]`, where
//! `mac = HMAC(ledger_key, TAG ‖ seq ‖ prev_mac ‖ record)`. The chain detects edited, reordered, inserted
//! and removed entries. Removing the TAIL is only detectable against an ANCHOR `(seq, mac)` kept in sealed
//! storage next to the ADR 0069 counter, so the commit protocol is:
//!
//! 1. append the entry to the store;
//! 2. then advance the sealed anchor to it.
//!
//! After a power cut, [`recover`] keeps every entry up to the anchor, rolls forward one complete, valid
//! entry beyond it (step 2 was lost), and discards anything else (a torn or unanchored tail). Entries
//! before the anchor that fail are tampering, never "recovered".
//!
//! The ledger key is its own purpose (key separation): never the delegation key, the salt key or a Noise key.
//! Records carry hashes and codes only, so the ledger holds no sensitive content.

use crate::crypto::{ct_eq, hmac_sha256};
use crate::ledger::{Record, RECORD_LEN};

pub const TAG: &[u8] = b"hookprobe/conductor/ledger/v1\0";
pub const ENTRY_LEN: usize = 8 + 32 + RECORD_LEN + 32;
/// The MAC that precedes entry 1.
pub const GENESIS: [u8; 32] = [0; 32];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Anchor {
    /// Sequence number of the last committed entry (0 = empty ledger).
    pub seq: u64,
    pub mac: [u8; 32],
}

impl Anchor {
    pub const EMPTY: Self = Self { seq: 0, mac: GENESIS };
}

fn mac(key: &[u8; 32], seq: u64, prev: &[u8; 32], rec: &[u8]) -> [u8; 32] {
    hmac_sha256(key, &[TAG, &seq.to_le_bytes(), prev, rec])
}

/// Build the next entry after `head`. Returns the entry and the anchor to commit once it is stored.
pub fn append(key: &[u8; 32], head: &Anchor, rec: &Record) -> Option<([u8; ENTRY_LEN], Anchor)> {
    let seq = head.seq.checked_add(1)?;
    let mut r = [0u8; RECORD_LEN];
    rec.encode(&mut r);
    let m = mac(key, seq, &head.mac, &r);
    let mut e = [0u8; ENTRY_LEN];
    let mut w = crate::wire::Writer::new(&mut e);
    w.u64(seq)?;
    w.put(&head.mac)?;
    w.put(&r)?;
    w.put(&m)?;
    Some((e, Anchor { seq, mac: m }))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChainError {
    /// Entry `n` (1-based position) fails its MAC or does not link to its predecessor: tampering.
    Broken(u64),
    /// Sequence numbers are not 1, 2, 3, …: an entry was removed, duplicated or reordered.
    Sequence(u64),
    /// The chain ends before the anchor: committed entries were removed.
    Truncated { have: u64, anchored: u64 },
    /// The chain does not pass through the anchor's MAC: history was rewritten.
    AnchorMismatch,
}

struct Parsed {
    seq: u64,
    prev: [u8; 32],
    mac: [u8; 32],
    ok: bool,
}

fn parse(key: &[u8; 32], e: &[u8]) -> Option<Parsed> {
    let mut r = crate::wire::Reader::new(e);
    let seq = r.u64()?;
    let prev: [u8; 32] = r.arr()?;
    let rec = r.take(RECORD_LEN)?;
    let m: [u8; 32] = r.arr()?;
    let ok = ct_eq(&mac(key, seq, &prev, rec), &m);
    Some(Parsed { seq, prev, mac: m, ok })
}

/// Verify a whole stored chain (concatenated entries) against the sealed anchor. Strict: every byte must
/// be a complete, valid entry, and the chain must reach exactly the anchor or one entry beyond it.
pub fn verify(key: &[u8; 32], store: &[u8], anchor: &Anchor) -> Result<Anchor, ChainError> {
    let mut head = Anchor::EMPTY;
    let mut passed_anchor = anchor.seq == 0;
    for (i, e) in store.chunks(ENTRY_LEN).enumerate() {
        let n = u64::try_from(i).unwrap_or(u64::MAX).saturating_add(1);
        let p = parse(key, e).ok_or(ChainError::Broken(n))?;
        if p.seq != n {
            return Err(ChainError::Sequence(n));
        }
        if !p.ok || !ct_eq(&p.prev, &head.mac) {
            return Err(ChainError::Broken(n));
        }
        head = Anchor { seq: p.seq, mac: p.mac };
        if head.seq == anchor.seq {
            if !ct_eq(&head.mac, &anchor.mac) {
                return Err(ChainError::AnchorMismatch);
            }
            passed_anchor = true;
        }
    }
    if head.seq < anchor.seq {
        return Err(ChainError::Truncated { have: head.seq, anchored: anchor.seq });
    }
    if !passed_anchor || head.seq > anchor.seq.saturating_add(1) {
        return Err(ChainError::AnchorMismatch);
    }
    Ok(head)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Recovered {
    /// Bytes of the store to keep (a whole number of entries).
    pub keep_bytes: usize,
    /// The anchor to (re)commit.
    pub anchor: Anchor,
    /// True when one complete entry beyond the old anchor was rolled forward.
    pub rolled_forward: bool,
    /// Bytes discarded from the tail (torn or unanchored).
    pub discarded_bytes: usize,
}

/// Boot-time recovery after a possible power cut. Everything up to the anchor must verify (else
/// `Err`: tampering is reported, never repaired). Beyond it, at most one complete valid entry is kept.
pub fn recover(key: &[u8; 32], store: &[u8], anchor: &Anchor) -> Result<Recovered, ChainError> {
    let anchored_bytes = usize::try_from(anchor.seq)
        .ok()
        .and_then(|n| n.checked_mul(ENTRY_LEN))
        .ok_or(ChainError::Truncated { have: 0, anchored: anchor.seq })?;
    let committed = store.get(..anchored_bytes).ok_or(ChainError::Truncated {
        have: u64::try_from(store.len() / ENTRY_LEN).unwrap_or(0),
        anchored: anchor.seq,
    })?;
    verify(key, committed, anchor)?;
    let tail = store.get(anchored_bytes..).unwrap_or(&[]);
    let mut out = Recovered { keep_bytes: anchored_bytes, anchor: *anchor, rolled_forward: false, discarded_bytes: tail.len() };
    if let Some(next) = tail.get(..ENTRY_LEN) {
        if let Some(p) = parse(key, next) {
            if p.ok && Some(p.seq) == anchor.seq.checked_add(1) && ct_eq(&p.prev, &anchor.mac) {
                out.keep_bytes = anchored_bytes.saturating_add(ENTRY_LEN);
                out.anchor = Anchor { seq: p.seq, mac: p.mac };
                out.rolled_forward = true;
                out.discarded_bytes = tail.len().saturating_sub(ENTRY_LEN);
            }
        }
    }
    Ok(out)
}
