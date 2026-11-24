// SPDX-License-Identifier: AGPL-3.0-only
//! Delegation ledger records. The harness emits one per significant step; the host seals them (C1: the
//! kernel's sealed, append-only store with power-loss recovery). Records carry hashes and codes, never
//! prompt or output content, so the ledger itself holds no sensitive data.

use crate::wire::Writer;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Kind {
    Placed = 1,
    Refused = 2,
    Signed = 3,
    ResultAccepted = 4,
    ToolRun = 5,
    ToolRefused = 6,
    Violation = 7,
    Done = 8,
    Aborted = 9,
    SloMiss = 10,
    LeaseEnded = 11,
    QuoteDeclined = 12,
    QuoteAccepted = 13,
    /// Guard G edited the answer's prose. `code` = distinct tokens removed; `digest` = SHA-256 of the prose before.
    GroundingEdit = 14,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Record {
    pub kind: Kind,
    pub job_id: [u8; 16],
    pub capability_id: [u8; 16],
    pub tier: u8,
    pub step: u8,
    /// Reason / status code (meaning depends on `kind`).
    pub code: u16,
    /// Request hash, output hash or zero.
    pub digest: [u8; 32],
}

pub const RECORD_LEN: usize = 1 + 16 + 16 + 1 + 1 + 2 + 32;

impl Record {
    pub fn encode(&self, out: &mut [u8; RECORD_LEN]) {
        let mut w = Writer::new(out);
        // Fixed sizes that sum to RECORD_LEN, so none of these can fail.
        let _ = w.u8(self.kind as u8);
        let _ = w.put(&self.job_id);
        let _ = w.put(&self.capability_id);
        let _ = w.u8(self.tier);
        let _ = w.u8(self.step);
        let _ = w.u16(self.code);
        let _ = w.put(&self.digest);
    }
}
