// SPDX-License-Identifier: AGPL-3.0-only
//! HQFL v1 — the wire format between the browser flasher and the stub (ADR 0070 D4). The host side is
//! `tools/flash/web/src/stubproto.mjs`; every constant here mirrors it.
//!
//! Frame (little-endian): a 16-byte header, then the payload.
//!   0 magic "HQFL" · 4 version (1) · 5 type · 6 status (responses) · 7 reserved · 8 seq u32 · 12 payload length u32
//!
//! One message is one bulk transfer, and no frame length is ever a multiple of 512 (the high-speed max packet), so
//! every transfer ends in a short packet and neither side needs a zero-length packet. `encode` enforces that for
//! the responses this stub sends.

pub const MAGIC: [u8; 4] = *b"HQFL";
pub const VERSION: u8 = 1;
pub const HDR: usize = 16;
pub const SECTOR: usize = 512;
/// Data bytes per VDATA / WRITE.
pub const MAX_CHUNK: usize = 64 * 1024;
/// Largest request frame: header + 16 bytes of WRITE arguments + one chunk.
pub const MAX_FRAME: usize = HDR + 16 + MAX_CHUNK;
/// Largest response this stub sends (INFO: header + 64).
pub const MAX_RESP: usize = HDR + 64;

/// Request and response types.
pub mod t {
    pub const HELLO: u8 = 0x01;
    pub const VBEGIN: u8 = 0x02;
    pub const VDATA: u8 = 0x03;
    pub const VEND: u8 = 0x04;
    pub const WBEGIN: u8 = 0x05;
    pub const WRITE: u8 = 0x06;
    pub const FINISH: u8 = 0x07;
    pub const ABORT: u8 = 0x08;
    pub const INFO: u8 = 0x81;
    pub const ACK: u8 = 0x82;
    pub const VERDICT: u8 = 0x84;
    pub const RESULT: u8 = 0x87;
    pub const ERROR: u8 = 0xee;
}

/// Status codes (ADR 0070 D4).
pub mod s {
    pub const OK: u8 = 0;
    pub const BAD_FRAME: u8 = 1;
    pub const BAD_VERSION: u8 = 2;
    pub const BAD_STATE: u8 = 3;
    pub const TOO_BIG: u8 = 4;
    pub const BAD_HEADER: u8 = 5;
    pub const SIG_FAIL: u8 = 6;
    pub const ROLLBACK: u8 = 7;
    pub const BAD_OFFSET: u8 = 8;
    pub const BAD_CRC: u8 = 9;
    pub const IO: u8 = 10;
    pub const RANGE: u8 = 11;
    pub const READBACK_MISMATCH: u8 = 12;
    pub const SLOT_MISMATCH: u8 = 13;
    pub const NOT_VERIFIED: u8 = 14;
}

/// A status code's name (for the UART log).
pub fn status_name(st: u8) -> &'static str {
    const N: [&str; 15] = [
        "OK", "BAD_FRAME", "BAD_VERSION", "BAD_STATE", "TOO_BIG", "BAD_HEADER", "SIG_FAIL", "ROLLBACK", "BAD_OFFSET",
        "BAD_CRC", "IO", "RANGE", "READBACK_MISMATCH", "SLOT_MISMATCH", "NOT_VERIFIED",
    ];
    N.get(st as usize).copied().unwrap_or("?")
}

/// A decoded frame borrowing its payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Frame<'a> {
    pub version: u8,
    pub ty: u8,
    pub status: u8,
    pub seq: u32,
    pub payload: &'a [u8],
}

pub fn le32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}
pub fn le64(b: &[u8], o: usize) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[o..o + 8]);
    u64::from_le_bytes(a)
}

/// The request seq of a frame that may be malformed (0 if the frame is too short to carry one).
pub fn seq_of(b: &[u8]) -> u32 {
    if b.len() >= 12 {
        le32(b, 8)
    } else {
        0
    }
}

/// Decode one frame. A short, overlong or mis-tagged frame is `None` (the server answers BAD_FRAME).
pub fn decode(b: &[u8]) -> Option<Frame<'_>> {
    if b.len() < HDR || b[..4] != MAGIC {
        return None;
    }
    let len = le32(b, 12) as usize;
    if b.len() != HDR + len {
        return None;
    }
    Some(Frame { version: b[4], ty: b[5], status: b[6], seq: le32(b, 8), payload: &b[HDR..] })
}

/// Encode a response into `out`; returns its length. Refuses (None) a length that is a multiple of 512 or does not
/// fit — a response the host could only read with a zero-length packet is never sent.
pub fn encode(out: &mut [u8], ty: u8, seq: u32, status: u8, payload: &[u8]) -> Option<usize> {
    let n = HDR + payload.len();
    if n > out.len() || n % SECTOR == 0 {
        return None;
    }
    out[..4].copy_from_slice(&MAGIC);
    out[4] = VERSION;
    out[5] = ty;
    out[6] = status;
    out[7] = 0;
    out[8..12].copy_from_slice(&seq.to_le_bytes());
    out[12..16].copy_from_slice(&(payload.len() as u32).to_le_bytes());
    out[HDR..n].copy_from_slice(payload);
    Some(n)
}

/// CRC-32 (IEEE 802.3, reflected, poly 0xEDB88320) — the same function as `hash.mjs::crc32` on the host.
pub fn crc32(data: &[u8]) -> u32 {
    const TABLE: [u32; 256] = {
        let mut t = [0u32; 256];
        let mut i = 0;
        while i < 256 {
            let mut c = i as u32;
            let mut k = 0;
            while k < 8 {
                c = if c & 1 != 0 { 0xEDB8_8320 ^ (c >> 1) } else { c >> 1 };
                k += 1;
            }
            t[i] = c;
            i += 1;
        }
        t
    };
    let mut c = !0u32;
    for &b in data {
        c = TABLE[((c ^ b as u32) & 0xff) as usize] ^ (c >> 8);
    }
    !c
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc32_check_value() {
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(crc32(b""), 0);
    }

    #[test]
    fn frames_round_trip_and_never_a_512_multiple() {
        let mut out = [0u8; MAX_RESP];
        let n = encode(&mut out, t::INFO, 7, s::OK, &[1, 2, 3]).unwrap();
        let f = decode(&out[..n]).unwrap();
        assert_eq!((f.version, f.ty, f.status, f.seq, f.payload), (1, t::INFO, 0, 7, &[1u8, 2, 3][..]));
        let mut big = [0u8; 600];
        assert!(encode(&mut big, t::ACK, 1, 0, &[0u8; 512 - HDR]).is_none());
        assert!(decode(&out[..n - 1]).is_none());
        assert!(decode(&out[..HDR - 1]).is_none());
        // every response this stub sends: ACK/ERROR 8, VERDICT 40, RESULT 33, INFO 64
        for p in [8usize, 40, 33, 64] {
            assert_ne!((HDR + p) % SECTOR, 0);
        }
    }
}
