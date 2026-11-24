// SPDX-License-Identifier: AGPL-3.0-only
//! Shared test fixtures: the DWC2 model + host, a factory-layout disk with two real signed slot images, a RAM
//! medium that enforces the write gate like the eMMC driver, and a Rust port of the browser's HQFL client
//! (`tools/flash/web/src/stubproto.mjs`) so the server tests mirror `tools/flash/web/test/stub.test.mjs`.
#![allow(dead_code)]
pub mod mock_dwc2;

use boot_abi::sha256;
use flashstub::image::{self, OFF};
use flashstub::proto::{self, le32, le64, s, t, HDR, MAX_CHUNK, SECTOR};
use flashstub::server::{Config, Medium, Server};

/// A real hybrid-signed payload (header + 512-byte body, svn 5) signed with the trust root compiled into
/// boot-abi — the same fixture the kernel's OTA self-tests use (kernel/src/testdata).
pub const CANDIDATE: &[u8] = include_bytes!("../../../kernel/src/testdata/ota_candidate.bin");
/// A real signed header for a 3,000,000-byte all-zero body, svn 2.
pub const BIG_HDR: &[u8] = include_bytes!("../../../kernel/src/testdata/ota_big_hdr.bin");

pub fn log(a: std::fmt::Arguments) {
    print!("{a}");
}

/// A stand-in for `hboot.bin`: deterministic bytes, ending in two zero bytes (so the prefix match must search).
pub fn hboot_bin() -> Vec<u8> {
    let mut x = 0x2545_F491_4F6C_DD1Du64;
    let mut v: Vec<u8> = (0..150_000)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 32) as u8 | 1
        })
        .collect();
    v.extend_from_slice(&[0, 0]);
    v
}

pub fn hboot_digest() -> [u8; 32] {
    sha256::digest(&hboot_bin())
}

/// A slot file: HBoot zero-padded to OFF, then the signed header + payload.
pub fn slot_image(hboot: &[u8], signed: &[u8]) -> Vec<u8> {
    let mut v = hboot.to_vec();
    v.resize(OFF, 0);
    v.extend_from_slice(signed);
    v
}

pub fn good_slot() -> Vec<u8> {
    slot_image(&hboot_bin(), CANDIDATE)
}

pub fn big_slot() -> Vec<u8> {
    let mut s = BIG_HDR.to_vec();
    s.resize(BIG_HDR.len() + 3_000_000, 0);
    slot_image(&hboot_bin(), &s)
}

// ── a factory-layout disk (MBR + FAT32 p1 with config.txt, HEQK8-A.IMG, HEQK8-B.IMG) ─────────────────────────
pub const P1: u64 = 2048;
const SPC: u64 = 8;
const RSVD: u64 = 32;

pub struct Disk {
    pub bytes: Vec<u8>,
    /// first sector of each slot file
    pub a_lba: u64,
    pub b_lba: u64,
}

pub fn factory_disk(a: &[u8], b: &[u8], config: &str) -> Disk {
    let csz = (SPC * 512) as usize;
    let na = a.len().div_ceil(csz) as u32;
    let nb = b.len().div_ceil(csz) as u32;
    let (root, cfgc, ac) = (2u32, 3u32, 4u32);
    let bc = ac + na;
    let last = bc + nb;
    let fatsz = ((last as u64 + 1) * 4).div_ceil(512);
    let data = P1 + RSVD + fatsz;
    let p1_size = RSVD + fatsz + (last as u64 - 1) * SPC + 64;
    let total = P1 + p1_size;
    let mut d = vec![0u8; total as usize * 512];
    // MBR
    d[510] = 0x55;
    d[511] = 0xAA;
    d[446 + 4] = 0x0c;
    d[446 + 8..446 + 12].copy_from_slice(&(P1 as u32).to_le_bytes());
    d[446 + 12..446 + 16].copy_from_slice(&(p1_size as u32).to_le_bytes());
    // BPB
    let bpb = P1 as usize * 512;
    d[bpb + 11..bpb + 13].copy_from_slice(&512u16.to_le_bytes());
    d[bpb + 13] = SPC as u8;
    d[bpb + 14..bpb + 16].copy_from_slice(&(RSVD as u16).to_le_bytes());
    d[bpb + 16] = 1;
    d[bpb + 36..bpb + 40].copy_from_slice(&(fatsz as u32).to_le_bytes());
    d[bpb + 44..bpb + 48].copy_from_slice(&root.to_le_bytes());
    d[bpb + 510] = 0x55;
    d[bpb + 511] = 0xAA;
    let fat = (P1 + RSVD) as usize * 512;
    let set_fat = |d: &mut Vec<u8>, c: u32, v: u32| d[fat + c as usize * 4..fat + c as usize * 4 + 4].copy_from_slice(&v.to_le_bytes());
    let chain = |d: &mut Vec<u8>, first: u32, n: u32| {
        for k in 0..n {
            set_fat(d, first + k, if k + 1 == n { 0x0FFF_FFFF } else { first + k + 1 });
        }
    };
    chain(&mut d, root, 1);
    chain(&mut d, cfgc, 1);
    chain(&mut d, ac, na);
    chain(&mut d, bc, nb);
    let clba = |c: u32| (data + (c as u64 - 2) * SPC) as usize * 512;
    let dir = clba(root);
    let ent = |d: &mut Vec<u8>, slot: usize, name: &[u8; 11], first: u32, size: usize| {
        let e = &mut d[dir + slot * 32..dir + slot * 32 + 32];
        e[..11].copy_from_slice(name);
        e[11] = 0x20;
        e[20..22].copy_from_slice(&((first >> 16) as u16).to_le_bytes());
        e[26..28].copy_from_slice(&(first as u16).to_le_bytes());
        e[28..32].copy_from_slice(&(size as u32).to_le_bytes());
    };
    ent(&mut d, 0, b"CONFIG  TXT", cfgc, config.len());
    ent(&mut d, 1, b"HEQK8-A IMG", ac, a.len());
    ent(&mut d, 2, b"HEQK8-B IMG", bc, b.len());
    let c = clba(cfgc);
    d[c..c + config.len()].copy_from_slice(config.as_bytes());
    let (pa, pb) = (clba(ac), clba(bc));
    d[pa..pa + a.len()].copy_from_slice(a);
    d[pb..pb + b.len()].copy_from_slice(b);
    Disk { bytes: d, a_lba: (pa / 512) as u64, b_lba: (pb / 512) as u64 }
}

pub fn good_disk() -> (Vec<u8>, Disk) {
    let slot = good_slot();
    let disk = factory_disk(&slot, &slot, "arm_64bit=1\nkernel=heqk8-a.img\n");
    (slot, disk)
}

// ── a RAM medium with the eMMC driver's write gate ──────────────────────────────────────────────────────────
pub struct RamMedium {
    pub data: Vec<u8>,
    pub admitted: bool,
    pub admits: u32,
    pub writes: u64,
    /// writes the gate refused (not admitted)
    pub refused: u64,
    /// every LBA written, in order
    pub order: Vec<u64>,
    /// a sector that always fails to write
    pub io_fail_lba: Option<u64>,
}

impl RamMedium {
    pub fn new(sectors: u64) -> Self {
        RamMedium { data: vec![0; sectors as usize * 512], admitted: false, admits: 0, writes: 0, refused: 0, order: vec![], io_fail_lba: None }
    }
    /// Pre-filled with an "old install" so tests can see what changed.
    pub fn with_old(sectors: u64) -> Self {
        let mut m = Self::new(sectors);
        for (i, b) in m.data.iter_mut().enumerate() {
            *b = (i % 251) as u8 | 0x80;
        }
        m
    }
    pub fn lba0_is_zero(&self) -> bool {
        self.data[..512].iter().all(|&b| b == 0)
    }
}

impl Medium for RamMedium {
    fn sectors(&self) -> u64 {
        (self.data.len() / 512) as u64
    }
    fn read(&mut self, lba: u64, out: &mut [u8]) -> bool {
        let a = lba as usize * 512;
        if a + out.len() > self.data.len() || out.len() % 512 != 0 {
            return false;
        }
        out.copy_from_slice(&self.data[a..a + out.len()]);
        true
    }
    fn write(&mut self, lba: u64, sec: &[u8; 512]) -> bool {
        if !self.admitted {
            self.refused += 1;
            return false;
        }
        if Some(lba) == self.io_fail_lba || lba >= self.sectors() {
            return false;
        }
        let a = lba as usize * 512;
        self.data[a..a + 512].copy_from_slice(sec);
        self.writes += 1;
        self.order.push(lba);
        true
    }
    fn admit_full_medium(&mut self) -> bool {
        self.admitted = true;
        self.admits += 1;
        true
    }
    fn revoke_full_medium(&mut self) {
        self.admitted = false;
    }
    fn cache_on(&self) -> bool {
        false
    }
    fn wear(&self) -> (u8, u8) {
        (1, 2)
    }
}

pub fn config(floor: u64, release: bool) -> Config {
    Config { svn_floor: floor, release, build: [0xAB; 32], log }
}

// ── the HQFL client (port of stubproto.mjs StubClient) ──────────────────────────────────────────────────────

/// One request in, one response out.
pub trait Link {
    fn call(&mut self, frame: &[u8]) -> Vec<u8>;
}

/// The server called directly (no USB).
pub struct Direct<'a> {
    pub srv: Server<'a>,
    pub m: RamMedium,
}
impl Link for Direct<'_> {
    fn call(&mut self, frame: &[u8]) -> Vec<u8> {
        let mut out = [0u8; proto::MAX_RESP];
        let n = self.srv.handle(&mut self.m, frame, &mut out);
        out[..n].to_vec()
    }
}

/// Faults in flight on WRITE requests (1-based ordinals, like the JS mock): truncate the frame, or flip a data byte.
#[derive(Default)]
pub struct Faults {
    pub short_on: Vec<u32>,
    pub crc_flip_on: Vec<u32>,
    writes: u32,
}

#[derive(Debug)]
pub struct Resp {
    pub ty: u8,
    pub status: u8,
    pub seq: u32,
    pub payload: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ClientErr {
    Refused(u8),
    Failed { status: u8, next: i64 },
}

pub struct Client<L: Link> {
    pub link: L,
    seq: u32,
    pub faults: Faults,
    pub short_writes: u32,
}

fn frame(ty: u8, seq: u32, payload: &[u8]) -> Vec<u8> {
    let mut f = Vec::with_capacity(HDR + payload.len());
    f.extend_from_slice(b"HQFL");
    f.extend_from_slice(&[1, ty, 0, 0]);
    f.extend_from_slice(&seq.to_le_bytes());
    f.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    f.extend_from_slice(payload);
    assert_ne!(f.len() % 512, 0, "client frame of {} bytes", f.len());
    f
}

pub fn digest(b: &[u8]) -> [u8; 32] {
    sha256::digest(b)
}

impl<L: Link> Client<L> {
    pub fn new(link: L) -> Self {
        Client { link, seq: 1, faults: Faults::default(), short_writes: 0 }
    }

    pub fn call(&mut self, ty: u8, payload: &[u8]) -> Resp {
        let seq = self.seq;
        self.seq += 1;
        let mut f = frame(ty, seq, payload);
        if ty == t::WRITE {
            self.faults.writes += 1;
            let k = self.faults.writes;
            if self.faults.short_on.contains(&k) {
                f.truncate(f.len() - 100);
                self.short_writes += 1;
            }
            if self.faults.crc_flip_on.contains(&k) {
                f[HDR + 16 + 7] ^= 0xff;
            }
        }
        let r = self.link.call(&f);
        let d = proto::decode(&r).expect("response frame");
        assert_eq!(d.seq, seq, "response seq");
        assert_ne!(r.len() % 512, 0);
        Resp { ty: d.ty, status: d.status, seq: d.seq, payload: d.payload.to_vec() }
    }

    pub fn hello(&mut self) -> Resp {
        self.call(t::HELLO, &1u32.to_le_bytes())
    }

    pub fn verify(&mut self, img: &[u8], chunk: usize) -> Result<(u64, [u8; 32]), ClientErr> {
        let r = self.call(t::VBEGIN, &(img.len() as u32).to_le_bytes());
        if r.status != s::OK {
            return Err(ClientErr::Refused(r.status));
        }
        let mut off = 0;
        while off < img.len() {
            let mut n = chunk.min(img.len() - off);
            if (HDR + 8 + n) % SECTOR == 0 {
                n -= 1;
            }
            let mut p = (off as u32).to_le_bytes().to_vec();
            p.extend_from_slice(&[0; 4]);
            p.extend_from_slice(&img[off..off + n]);
            let r = self.call(t::VDATA, &p);
            if r.status != s::OK {
                return Err(ClientErr::Refused(r.status));
            }
            off = le64(&r.payload, 0) as usize;
        }
        let r = self.call(t::VEND, &[]);
        if r.ty != t::VERDICT || r.status != s::OK {
            return Err(ClientErr::Refused(r.status));
        }
        Ok((le64(&r.payload, 0), r.payload[8..40].try_into().unwrap()))
    }

    /// Stream the disk image with per-chunk ack and resume (at most `max_retries` in a row).
    pub fn write(&mut self, disk: &[u8], chunk: usize, max_retries: u32) -> Result<([u8; 32], u32), ClientErr> {
        let r = self.call(t::WBEGIN, &(disk.len() as u64).to_le_bytes());
        if r.status != s::OK {
            return Err(ClientErr::Refused(r.status));
        }
        let c = chunk.min(MAX_CHUNK) / SECTOR * SECTOR;
        let (mut off, mut retries, mut resumes) = (0usize, 0, 0);
        while off < disk.len() {
            let n = c.min(disk.len() - off);
            let d = &disk[off..off + n];
            let mut p = (off as u64).to_le_bytes().to_vec();
            p.extend_from_slice(&proto::crc32(d).to_le_bytes());
            p.extend_from_slice(&[0; 4]);
            p.extend_from_slice(d);
            let r = self.call(t::WRITE, &p);
            let next = if r.payload.len() >= 8 { le64(&r.payload, 0) as i64 } else { -1 };
            if r.status == s::OK && next == (off + n) as i64 {
                off += n;
                retries = 0;
                continue;
            }
            let transient = matches!(r.status, s::BAD_FRAME | s::BAD_CRC | s::IO | s::BAD_OFFSET);
            if transient && next >= 0 && next as usize <= off && next as usize % SECTOR == 0 {
                retries += 1;
                if retries <= max_retries {
                    resumes += 1;
                    off = next as usize;
                    continue;
                }
            }
            return Err(ClientErr::Failed { status: r.status, next });
        }
        Ok((digest(disk), resumes))
    }

    pub fn finish(&mut self, dg: &[u8; 32]) -> Resp {
        self.call(t::FINISH, dg)
    }
}

pub fn info_release(r: &Resp) -> bool {
    r.payload[24] == 1
}
pub fn info_sectors(r: &Resp) -> u64 {
    le64(&r.payload, 8)
}
pub fn info_floor(r: &Resp) -> u64 {
    le64(&r.payload, 16)
}
pub fn info_max_chunk(r: &Resp) -> u32 {
    le32(&r.payload, 4)
}

pub fn hboot_ref() -> image::MeasuredHboot {
    image::MeasuredHboot { digest: Some(hboot_digest()) }
}
