//! ADR 0065 step 4d: the CYW43455 control channel (BCDC dcmd over SDPCM channel 0), pure.
//!
//! The driver used to build each request and match each reply inline (`cyw43::bcdc_dcmd`). Both halves are here so
//! the kernel and el0-wifi run the same code, the reply matcher is fuzzed (its input is the firmware's output), and
//! the frame layout has host tests.

use crate::SDPCM_HDRLEN;

/// The BCDC dcmd header: cmd, len, flags (SET bit, interface [15:12], request id [31:16]), status.
pub const HDRLEN: usize = 16;
/// SDPCM channel 0 = control.
pub const CHANNEL: u8 = 0;
/// The SET flag (vs a GET).
pub const SET: u32 = 0x2;
/// The largest request payload the driver sends (one firmware-download chunk + an iovar name).
pub const PAYLOAD_MAX: usize = 1400 + 64 - SDPCM_HDRLEN - HDRLEN;
/// The request buffer: the frame padded to 4 B.
pub const FRAME_MAX: usize = SDPCM_HDRLEN + HDRLEN + PAYLOAD_MAX;

/// Build one control request. `reply_len` = how many bytes a GET may return (the BCDC `len` is the larger of it and
/// the payload). Returns the SDPCM length; the bytes to write are `out[..(len + 3) & !3]` (the tail is zero).
#[allow(clippy::too_many_arguments)]
pub fn request(seq: u8, cmd: u32, flags: u32, reqid: u16, ifidx: u8, payload: &[u8], reply_len: usize, out: &mut [u8; FRAME_MAX]) -> usize {
    out.fill(0);
    let w0: u32 = (seq as u32) | ((CHANNEL as u32) << 8) | ((SDPCM_HDRLEN as u32) << 24);
    let blen = if reply_len == 0 { payload.len() } else { reply_len.max(payload.len()) };
    let b = SDPCM_HDRLEN;
    out[b..b + 4].copy_from_slice(&cmd.to_le_bytes());
    out[b + 4..b + 8].copy_from_slice(&(blen as u32).to_le_bytes());
    let flg = flags | ((reqid as u32) << 16) | (((ifidx & 0xf) as u32) << 12);
    out[b + 8..b + 12].copy_from_slice(&flg.to_le_bytes());
    let body = b + HDRLEN;
    let n = payload.len().min(out.len() - body);
    out[body..body + n].copy_from_slice(&payload[..n]);
    let total = (body + n) as u16;
    out[0..2].copy_from_slice(&total.to_le_bytes());
    out[2..4].copy_from_slice(&(!total).to_le_bytes());
    out[4..8].copy_from_slice(&w0.to_le_bytes());
    total as usize
}

/// What one received frame means to a waiting control request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reply {
    /// The reply to `reqid`: the firmware's status and where the body is in the frame (`off..end`, possibly empty).
    Ours { status: u32, off: usize, end: usize },
    /// A control frame for another request id (or without a whole BCDC header): skip it.
    OtherCtl,
    /// An event / data frame: the caller parks it for the serve loop.
    NotCtl,
}

/// Classify one received frame (`frame[..len]` with SDPCM `chan` / data offset `doff`, as `crate::sdpcm_hdr`
/// checked them) against the request id we wait for. Every bound is checked against `len` and the buffer.
pub fn reply(frame: &[u8], len: usize, chan: u8, doff: usize, reqid: u16) -> Reply {
    if chan != CHANNEL {
        return Reply::NotCtl;
    }
    let valid = len.min(frame.len());
    if doff < SDPCM_HDRLEN || doff + HDRLEN > valid {
        return Reply::OtherCtl;
    }
    let w = |o: usize| u32::from_le_bytes([frame[doff + o], frame[doff + o + 1], frame[doff + o + 2], frame[doff + o + 3]]);
    if (w(8) >> 16) as u16 != reqid {
        return Reply::OtherCtl;
    }
    Reply::Ours { status: w(12), off: doff + HDRLEN, end: valid }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_layout() {
        let mut f = [0xffu8; FRAME_MAX];
        let n = request(9, 263, SET, 0x1234, 1, b"ver\0", 0, &mut f);
        assert_eq!(n, 12 + 16 + 4);
        assert_eq!(u16::from_le_bytes([f[0], f[1]]), n as u16);
        assert_eq!(u16::from_le_bytes([f[2], f[3]]), !(n as u16));
        assert_eq!(u32::from_le_bytes([f[4], f[5], f[6], f[7]]), 9 | 12 << 24);
        assert_eq!(u32::from_le_bytes([f[12], f[13], f[14], f[15]]), 263);
        assert_eq!(u32::from_le_bytes([f[16], f[17], f[18], f[19]]), 4, "a SET's len is its payload");
        assert_eq!(u32::from_le_bytes([f[20], f[21], f[22], f[23]]), SET | 1 << 12 | 0x1234 << 16);
        assert_eq!(&f[28..32], b"ver\0");
        assert!(f[32..].iter().all(|&b| b == 0));
        // a GET advertises the reply buffer
        request(1, 262, 0, 1, 0, b"ver\0", 256, &mut f);
        assert_eq!(u32::from_le_bytes([f[16], f[17], f[18], f[19]]), 256);
        // the receive side's header check accepts a request-shaped frame
        let h = crate::sdpcm_hdr(&f[..64]).unwrap().unwrap();
        assert_eq!((h.chan, h.doff), (0, 12));
    }

    #[test]
    fn reply_matching() {
        let mut f = [0u8; 128];
        let mk = |f: &mut [u8; 128], reqid: u32, status: u32| {
            f[12 + 8..12 + 12].copy_from_slice(&(reqid << 16).to_le_bytes());
            f[12 + 12..12 + 16].copy_from_slice(&status.to_le_bytes());
        };
        mk(&mut f, 7, 0);
        assert_eq!(reply(&f, 60, 0, 12, 7), Reply::Ours { status: 0, off: 28, end: 60 });
        assert_eq!(reply(&f, 60, 0, 12, 8), Reply::OtherCtl);
        assert_eq!(reply(&f, 60, 2, 12, 7), Reply::NotCtl);
        mk(&mut f, 7, 0xffff_ffe9);
        assert_eq!(reply(&f, 60, 0, 12, 7), Reply::Ours { status: 0xffff_ffe9, off: 28, end: 60 });
        // a header that does not fit, a data offset inside the SDPCM header, a length past the buffer
        assert_eq!(reply(&f, 20, 0, 12, 7), Reply::OtherCtl);
        assert_eq!(reply(&f, 60, 0, 4, 7), Reply::OtherCtl);
        assert_eq!(reply(&f, 4000, 0, 12, 7), Reply::Ours { status: 0xffff_ffe9, off: 28, end: 128 });
        assert_eq!(reply(&f, 60, 0, 120, 7), Reply::OtherCtl);
    }
}
