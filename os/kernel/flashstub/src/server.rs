// SPDX-License-Identifier: AGPL-3.0-only
//! The HQFL v1 server (ADR 0070 D3, D4): one request frame in, one response frame out.
//!
//! Security contract, enforced here and by the medium's own gate:
//! * Nothing reaches the medium before `image::verify_slot_image` (both signatures, `svn >= floor`, HBoot prefix)
//!   returned a verdict. WBEGIN / WRITE without one are answered NOT_VERIFIED. A refusal is final for the session
//!   (until a USB bus reset): no second VBEGIN.
//! * The whole-medium write gate (`Medium::admit_full_medium`, the eMMC driver's `flashstub` gate) is opened at
//!   WBEGIN — after the verdict — and closed when the session ends, whatever the outcome.
//! * LBA 0 (the MBR) is written LAST. The first WRITE zeroes LBA 0 before anything else is written and keeps the
//!   image's MBR in RAM; FINISH reads the whole range back (with the held MBR in place of LBA 0), compares three
//!   hashes (the host's, the running hash of what arrived, the read-back), finds both slot files through FAT and
//!   verifies each, and only then writes the MBR and reads it back. So a board whose write was interrupted, failed
//!   its read-back or its slot check — or lost power or USB at any point — has no MBR and does not boot a half-
//!   written or substituted image. A failure after the MBR went down (its read-back) zeroes it again; so do ABORT
//!   and a USB bus reset.
//! * No OTP, no RPMB, no boot partitions: the server only calls `Medium` (user-area sector read / write).

use crate::image::{self, HbootRef, Refusal, Verdict, IMG_MAX};
use crate::proto::{self, le32, le64, s, t, HDR, MAX_CHUNK, MAX_RESP, SECTOR};
use boot_abi::sha256::Hasher;

/// The block device the stub writes (the CM5 eMMC user area; a RAM disk in the host tests).
pub trait Medium {
    /// 512-byte sectors.
    fn sectors(&self) -> u64;
    /// Read `out.len() / 512` sectors from `lba`.
    fn read(&mut self, lba: u64, out: &mut [u8]) -> bool;
    /// Write one sector. Refused by the medium unless `admit_full_medium` is in force.
    fn write(&mut self, lba: u64, sec: &[u8; 512]) -> bool;
    /// Open the whole-medium write window (LBA 0..sectors) for this session. False = refused.
    fn admit_full_medium(&mut self) -> bool;
    /// Close it.
    fn revoke_full_medium(&mut self);
    /// EXT_CSD CACHE_CTRL bit 0 (reported in INFO).
    fn cache_on(&self) -> bool {
        false
    }
    /// EXT_CSD DEVICE_LIFE_TIME_EST_TYP_A / _B (reported in INFO).
    fn wear(&self) -> (u8, u8) {
        (0, 0)
    }
}

/// Fixed facts of this stub build.
#[derive(Clone, Copy)]
pub struct Config {
    /// Compiled-in anti-rollback floor (ADR 0070 D3.1).
    pub svn_floor: u64,
    /// Trust root is not a development key (`release::trust_root_is_release`).
    pub release: bool,
    /// Identity of this stub (HBoot's measurement of the stub payload).
    pub build: [u8; 32],
    /// UART log sink.
    pub log: fn(core::fmt::Arguments),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    /// No HELLO yet.
    Init,
    Ready,
    Verifying,
    Verified,
    /// Refused this session; only HELLO / ABORT are answered with anything but BAD_STATE.
    Refused,
    Writing,
    /// FINISH ran (successfully or not).
    Done,
}

/// Counters for the log and the tests.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    pub sector_writes: u64,
    pub admits: u32,
    pub lba0_clears: u32,
}

pub struct Server<'b> {
    cfg: Config,
    hboot: &'b dyn HbootRef,
    /// The slot image under verification (>= IMG_MAX bytes); scratch for read-back / slot checks after the verdict.
    img: &'b mut [u8],
    state: State,
    vlen: usize,
    vnext: usize,
    verdict: Option<Verdict>,
    wlen: u64,
    next: u64,
    hash: Hasher,
    /// The image's LBA 0, written last (see the module comment).
    mbr: [u8; 512],
    /// Something reached the medium this session (LBA 0 has been zeroed).
    written: bool,
    admitted: bool,
    pub stats: Stats,
}

macro_rules! log { ($s:expr, $($a:tt)*) => { ($s.cfg.log)(format_args!($($a)*)) }; }

impl<'b> Server<'b> {
    /// `img` must hold at least `IMG_MAX` bytes.
    pub fn new(cfg: Config, hboot: &'b dyn HbootRef, img: &'b mut [u8]) -> Self {
        assert!(img.len() >= IMG_MAX, "slot-image buffer below IMG_MAX");
        Server {
            cfg,
            hboot,
            img,
            state: State::Init,
            vlen: 0,
            vnext: 0,
            verdict: None,
            wlen: 0,
            next: 0,
            hash: Hasher::new(),
            mbr: [0; 512],
            written: false,
            admitted: false,
            stats: Stats::default(),
        }
    }

    pub fn state(&self) -> State {
        self.state
    }

    /// Handle one request frame; the response is written to `out`, its length returned.
    pub fn handle<M: Medium>(&mut self, m: &mut M, req: &[u8], out: &mut [u8; MAX_RESP]) -> usize {
        let seq = proto::seq_of(req);
        let Some(f) = proto::decode(req) else {
            let next = self.resume_point();
            log!(self, " hqfl: BAD_FRAME ({} bytes) -> next {}\n", req.len(), next);
            return ack(out, seq, next, s::BAD_FRAME);
        };
        if f.version != proto::VERSION {
            return ack(out, seq, 0, s::BAD_VERSION);
        }
        let p = f.payload;
        match f.ty {
            t::HELLO => self.hello(m, seq, p, out),
            t::VBEGIN => self.vbegin(seq, p, out),
            t::VDATA => self.vdata(seq, p, out),
            t::VEND => self.vend(seq, out),
            t::WBEGIN => self.wbegin(m, seq, p, out),
            t::WRITE => self.write(m, seq, p, out),
            t::FINISH => self.finish(m, seq, p, out),
            t::ABORT => {
                self.end_session(m, "ABORT");
                if self.state != State::Refused {
                    self.state = State::Ready;
                }
                ack(out, seq, 0, s::OK)
            }
            _ => ack(out, seq, 0, s::BAD_FRAME),
        }
    }

    /// USB bus reset or disconnect: the session is over. A half-written medium keeps LBA 0 zero.
    pub fn on_bus_reset<M: Medium>(&mut self, m: &mut M) {
        if self.state != State::Init {
            self.end_session(m, "USB reset");
            self.state = State::Init;
        }
    }

    /// Where a host resends from after BAD_FRAME / BAD_CRC / IO.
    fn resume_point(&self) -> u64 {
        match self.state {
            State::Writing => self.next,
            State::Verifying => self.vnext as u64,
            _ => 0,
        }
    }

    fn hello<M: Medium>(&mut self, m: &mut M, seq: u32, p: &[u8], out: &mut [u8; MAX_RESP]) -> usize {
        if p.len() < 4 || le32(p, 0) != 1 {
            return ack(out, seq, 0, s::BAD_VERSION);
        }
        if matches!(self.state, State::Writing | State::Verifying | State::Verified) {
            self.end_session(m, "HELLO mid-session");
        }
        if self.state != State::Refused {
            self.state = State::Ready;
        }
        let mut i = [0u8; 64];
        i[0..4].copy_from_slice(&1u32.to_le_bytes());
        i[4..8].copy_from_slice(&(MAX_CHUNK as u32).to_le_bytes());
        i[8..16].copy_from_slice(&m.sectors().to_le_bytes());
        i[16..24].copy_from_slice(&self.cfg.svn_floor.to_le_bytes());
        i[24] = self.cfg.release as u8;
        i[25] = m.cache_on() as u8;
        (i[26], i[27]) = m.wear();
        i[32..64].copy_from_slice(&self.cfg.build);
        respond(out, t::INFO, seq, s::OK, &i)
    }

    fn vbegin(&mut self, seq: u32, p: &[u8], out: &mut [u8; MAX_RESP]) -> usize {
        if self.state != State::Ready {
            return ack(out, seq, 0, s::BAD_STATE);
        }
        if p.len() < 4 {
            return ack(out, seq, 0, s::BAD_FRAME);
        }
        let len = le32(p, 0) as usize;
        if len == 0 || len > IMG_MAX {
            return ack(out, seq, 0, s::TOO_BIG);
        }
        self.vlen = len;
        self.vnext = 0;
        self.state = State::Verifying;
        ack(out, seq, 0, s::OK)
    }

    fn vdata(&mut self, seq: u32, p: &[u8], out: &mut [u8; MAX_RESP]) -> usize {
        if self.state != State::Verifying {
            return ack(out, seq, 0, s::BAD_STATE);
        }
        if p.len() < 8 {
            return ack(out, seq, self.vnext as u64, s::BAD_FRAME);
        }
        let (off, d) = (le32(p, 0) as usize, &p[8..]);
        if off != self.vnext {
            return ack(out, seq, self.vnext as u64, s::BAD_OFFSET);
        }
        if d.len() > MAX_CHUNK || off + d.len() > self.vlen {
            return ack(out, seq, self.vnext as u64, s::RANGE);
        }
        self.img[off..off + d.len()].copy_from_slice(d);
        self.vnext += d.len();
        ack(out, seq, self.vnext as u64, s::OK)
    }

    fn vend(&mut self, seq: u32, out: &mut [u8; MAX_RESP]) -> usize {
        if self.state != State::Verifying || self.vnext != self.vlen {
            return ack(out, seq, 0, s::BAD_STATE);
        }
        let r = image::verify_slot_image(&self.img[..self.vlen], self.cfg.svn_floor, self.hboot);
        let mut v = [0u8; 40];
        let st = match r {
            Ok(vd) => {
                v[..8].copy_from_slice(&vd.svn.to_le_bytes());
                v[8..].copy_from_slice(&vd.hash);
                self.verdict = Some(vd);
                self.state = State::Verified;
                log!(self, " hqfl: VERIFIED svn {} (floor {}), {} bytes — nothing written yet\n", vd.svn, self.cfg.svn_floor, self.vlen);
                s::OK
            }
            Err(e) => {
                self.verdict = None;
                self.state = State::Refused;
                let st = match e {
                    Refusal::SigFail => s::SIG_FAIL,
                    Refusal::Rollback => s::ROLLBACK,
                    Refusal::BadHeader | Refusal::HbootMismatch => s::BAD_HEADER,
                };
                log!(self, " hqfl: REFUSED {:?} -> {} — nothing written, refusal final for this session\n", e, proto::status_name(st));
                st
            }
        };
        respond(out, t::VERDICT, seq, st, &v)
    }

    fn wbegin<M: Medium>(&mut self, m: &mut M, seq: u32, p: &[u8], out: &mut [u8; MAX_RESP]) -> usize {
        if self.state != State::Verified || self.verdict.is_none() {
            return ack(out, seq, 0, s::NOT_VERIFIED);
        }
        if p.len() < 8 {
            return ack(out, seq, 0, s::BAD_FRAME);
        }
        let len = le64(p, 0);
        if len == 0 || len % SECTOR as u64 != 0 || len / SECTOR as u64 > m.sectors() {
            return ack(out, seq, 0, s::RANGE);
        }
        // The write window opens here, after the verdict, and only here.
        if !m.admit_full_medium() {
            log!(self, " hqfl: the eMMC driver refused the whole-medium window\n");
            return ack(out, seq, 0, s::IO);
        }
        self.admitted = true;
        self.stats.admits += 1;
        self.wlen = len;
        self.next = 0;
        self.hash = Hasher::new();
        self.mbr = [0; 512];
        self.state = State::Writing;
        log!(self, " hqfl: WBEGIN {} bytes ({} sectors of {})\n", len, len / 512, m.sectors());
        ack(out, seq, 0, s::OK)
    }

    fn write<M: Medium>(&mut self, m: &mut M, seq: u32, p: &[u8], out: &mut [u8; MAX_RESP]) -> usize {
        if self.state != State::Writing {
            return ack(out, seq, 0, s::NOT_VERIFIED);
        }
        if p.len() < 16 {
            return ack(out, seq, self.next, s::BAD_FRAME);
        }
        let (off, crc, d) = (le64(p, 0), le32(p, 8), &p[16..]);
        if off != self.next {
            return ack(out, seq, self.next, s::BAD_OFFSET);
        }
        if d.is_empty() || d.len() % SECTOR != 0 || d.len() > MAX_CHUNK || off + d.len() as u64 > self.wlen {
            return ack(out, seq, self.next, s::RANGE);
        }
        if proto::crc32(d) != crc {
            return ack(out, seq, self.next, s::BAD_CRC);
        }
        if !self.written {
            // Before the first byte of the image: no MBR, so nothing on this board boots until FINISH proves it all.
            if !self.zero_lba0(m) {
                return ack(out, seq, self.next, s::IO);
            }
            self.written = true;
        }
        let lba0 = off / SECTOR as u64;
        for (i, sec) in d.chunks_exact(SECTOR).enumerate() {
            let lba = lba0 + i as u64;
            let sec: &[u8; 512] = sec.try_into().unwrap();
            if lba == 0 {
                self.mbr = *sec; // held back: written last, by FINISH
                continue;
            }
            if !m.write(lba, sec) {
                log!(self, " hqfl: IO writing LBA {} -> next {}\n", lba, self.next);
                return ack(out, seq, self.next, s::IO);
            }
            self.stats.sector_writes += 1;
        }
        self.hash.update(d);
        self.next += d.len() as u64;
        ack(out, seq, self.next, s::OK)
    }

    fn finish<M: Medium>(&mut self, m: &mut M, seq: u32, p: &[u8], out: &mut [u8; MAX_RESP]) -> usize {
        let mut r = [0u8; 33];
        if self.state != State::Writing || self.next != self.wlen {
            return respond(out, t::RESULT, seq, s::BAD_STATE, &r);
        }
        if p.len() != 32 {
            return respond(out, t::RESULT, seq, s::BAD_FRAME, &r);
        }
        let recv = core::mem::replace(&mut self.hash, Hasher::new()).finish();
        // Full read-back of [0, wlen), with the held MBR standing in for LBA 0.
        let mut h = Hasher::new();
        let total = self.wlen / SECTOR as u64;
        let mut lba = 0u64;
        let mut io_ok = true;
        let step = (MAX_CHUNK / SECTOR) as u64;
        while lba < total {
            let n = (total - lba).min(step) as usize;
            let buf = &mut self.img[..n * SECTOR];
            if !m.read(lba, buf) {
                io_ok = false;
                break;
            }
            if lba == 0 {
                buf[..SECTOR].copy_from_slice(&self.mbr);
            }
            h.update(buf);
            lba += n as u64;
        }
        let readback = h.finish();
        r[..32].copy_from_slice(&readback);
        let mut st = s::OK;
        if !io_ok || readback != recv || p != recv {
            st = s::READBACK_MISMATCH;
        } else {
            let mbr = self.mbr;
            let mut rd = |l: u64, b: &mut [u8]| -> bool {
                if !m.read(l, b) {
                    return false;
                }
                if l == 0 {
                    b[..SECTOR].copy_from_slice(&mbr);
                }
                true
            };
            r[32] = image::slot_flags(&mut rd, &mut *self.img, self.cfg.svn_floor, self.hboot);
            if r[32] != 3 {
                st = s::SLOT_MISMATCH;
            }
        }
        // LBA 0 has been zero (and read back zero) since the first WRITE; it stays so unless the MBR goes down here.
        let mut lba0_zero = true;
        if st == s::OK {
            // Everything proved: now, and only now, the MBR — then read it back.
            let mut back = [0u8; 512];
            if m.write(0, &self.mbr) && m.read(0, &mut back) && back == self.mbr {
                self.stats.sector_writes += 1;
            } else {
                st = s::READBACK_MISMATCH;
                lba0_zero = self.zero_lba0(m);
            }
        }
        log!(self, " hqfl: FINISH {} — read-back {} host, slot flags {:#x}{}\n", proto::status_name(st),
            if readback == recv && p == recv { "==" } else { "!=" }, r[32],
            if st == s::OK { "; MBR written last" } else { "; LBA 0 left zero (the board will not boot this image)" });
        // A completed flash is not "half-written"; a failed one has a zero LBA 0 — unless clearing it failed, in
        // which case a later ABORT / bus reset tries again.
        self.written = !lba0_zero;
        self.close_window(m);
        self.verdict = None;
        self.state = State::Done;
        respond(out, t::RESULT, seq, st, &r)
    }

    /// Session end by ABORT, HELLO or bus reset: a half-written medium keeps (or gets) a zero LBA 0.
    fn end_session<M: Medium>(&mut self, m: &mut M, why: &str) {
        if self.written {
            if !self.admitted && m.admit_full_medium() {
                self.admitted = true;
            }
            let ok = self.zero_lba0(m);
            log!(self, " hqfl: {} after a write — LBA 0 {}\n", why, if ok { "zeroed" } else { "NOT zeroed (IO)" });
        }
        self.written = false;
        self.close_window(m);
        self.verdict = None;
        self.hash = Hasher::new();
    }

    fn close_window<M: Medium>(&mut self, m: &mut M) {
        if self.admitted {
            m.revoke_full_medium();
            self.admitted = false;
        }
    }

    fn zero_lba0<M: Medium>(&mut self, m: &mut M) -> bool {
        let z = [0u8; 512];
        let mut back = [0xffu8; 512];
        let ok = m.write(0, &z) && m.read(0, &mut back) && back == z;
        if ok {
            self.stats.lba0_clears += 1;
        }
        ok
    }
}

fn respond(out: &mut [u8; MAX_RESP], ty: u8, seq: u32, st: u8, payload: &[u8]) -> usize {
    // Every payload here is 8, 33, 40 or 64 bytes: never a 512 multiple, always within MAX_RESP.
    proto::encode(out, ty, seq, st, payload).expect("response frame")
}

/// ACK (status OK) or ERROR (any other status), payload u64 next.
fn ack(out: &mut [u8; MAX_RESP], seq: u32, next: u64, st: u8) -> usize {
    respond(out, if st == s::OK { t::ACK } else { t::ERROR }, seq, st, &next.to_le_bytes())
}

const _: () = assert!(HDR + 64 <= MAX_RESP);
