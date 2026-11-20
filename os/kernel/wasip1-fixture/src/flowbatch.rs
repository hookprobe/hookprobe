// SPDX-License-Identifier: AGPL-3.0-only
//! ADR 0067 D6 / build-plan item X2a, step 2 — a `wasm32-wasip1` detection module that takes a
//! VECTOR of flow-event records per run instead of one input. It reads up to 256 bytes from
//! STDIN (16 records of 16 bytes, the `hal::flowevt::FlowEvt` wire format), and writes exactly
//! one verdict byte per COMPLETE record to STDOUT: 2 (alert) when the record's dst port (bytes
//! [8..10], little-endian) is 4444, 23 or 31337 (the same corpus as the port-signature module),
//! else 1 (pass). A trailing partial record gets no byte, so the host sees it as unanswered.
use std::io::{Read, Write};

const REC_LEN: usize = 16; // == hal::flowevt::REC_LEN
const BATCH_BYTES: usize = 256; // == hal::flowevt::BATCH_BYTES

fn is_threat(port: u16) -> bool {
    port == 4444 || port == 23 || port == 31337
}

fn main() {
    let mut buf = [0u8; BATCH_BYTES];
    let mut n = 0usize;
    // Read until the batch is full or stdin is at its end (a read may return less than asked).
    while n < BATCH_BYTES {
        match std::io::stdin().read(&mut buf[n..]) {
            Ok(0) | Err(_) => break,
            Ok(k) => n += k,
        }
    }
    let recs = n / REC_LEN;
    let mut out = [0u8; BATCH_BYTES / REC_LEN];
    for i in 0..recs {
        let r = &buf[i * REC_LEN..(i + 1) * REC_LEN];
        let port = u16::from_le_bytes([r[8], r[9]]);
        out[i] = if is_threat(port) { 2 } else { 1 };
    }
    let _ = std::io::stdout().write_all(&out[..recs]);
    let _ = std::io::stdout().flush();
}
