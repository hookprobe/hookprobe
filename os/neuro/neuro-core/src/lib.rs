// SPDX-License-Identifier: AGPL-3.0-only
//! HookProbe Neuro, stage 1 (N0): the integer-only, streaming Neural DNA.
//!
//! This is a bit-exact port of `tools/neuro-research/dna_fixed.py`. That file is the specification;
//! `tests/golden.rs` checks every hour's score against vectors it generated.
//!
//! - Q8 fixed point (x256) for log-domain values; Q16 for shares and EWMA rates.
//! - Every product is done in `i64`. Arithmetic shifts floor, like Python `>>`.
//! - Every division has a non-negative numerator, so Rust `/` equals Python `//`.
//!
//! No allocation, no floating point, no `unsafe`, no dependencies. It runs on the softfloat target as is.
//!
//! The engine **observes and scores**. It never decides enforcement (ADR 0023, contract C9).
#![no_std]
#![forbid(unsafe_code)]

mod log2_lut;
pub use log2_lut::LOG2_LUT;
pub mod peerkey;

// ---- parameters (mirror dna_fixed.py) ------------------------------------------------------------------
pub const BLOOM_BITS: usize = 1024;
pub const BLOOM_BYTES: usize = BLOOM_BITS / 8;
pub const BLOOM_K: u64 = 3;
pub const ALPHA_Q16: i64 = 9830; // 0.15
pub const CALM_Q8: i64 = 256; // 1.0
pub const SLOT_MIN: i64 = 3;
pub const COLD_WIDEN_Q8: i64 = 256;
pub const PERSIST_K: u8 = 6;
pub const PENDING_SLOTS: usize = 8;
pub const NOVEL_LIST: usize = 16;
pub const ROTATE_HOURS: u32 = 168;
const DEV_INIT_Q8: u16 = 256;
const NOVDEV_INIT_Q8: u16 = 128;
const HALF_Q8: i64 = 128;
const NOV_EPS_Q8: i64 = 77;
const ACT_MARGIN_Q8: i64 = 384;

// ---- hashing -------------------------------------------------------------------------------------------
pub fn splitmix64(x: u64) -> u64 {
    let mut z = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// Item identity on the device: the 32-bit fingerprint of a 64-bit key.
pub fn fingerprint(key: u64) -> u32 {
    (splitmix64(key) >> 32) as u32
}

/// Key of a remote peer: IPv4 address and port.
pub fn peer_key(ip: u32, port: u16) -> u64 {
    ((ip as u64) << 16) | port as u64
}

/// FNV-1a 64 (DNS suffix bytes -> key).
pub fn fnv1a64(b: &[u8]) -> u64 {
    let mut h: u64 = 0xCBF2_9CE4_8422_2325;
    for &c in b {
        h = (h ^ c as u64).wrapping_mul(0x0000_0100_0000_01B3);
    }
    h
}

/// log2(x) in Q8 for x >= 1; 0 for x == 0. Integer only: the MSB plus a 256-entry table on the next 8 bits.
pub fn log2_q8(x: u64) -> i64 {
    if x == 0 {
        return 0;
    }
    let n = 63 - x.leading_zeros();
    let frac8 = ((((x as u128) << 8) >> n) & 0xFF) as usize;
    n as i64 * 256 + LOG2_LUT[frac8] as i64
}

fn ewma(v: i64, x: i64, a_q16: i64) -> i64 {
    v + (((x - v) * a_q16) >> 16)
}

fn clamp16(v: i64) -> u16 {
    v.clamp(0, 65535) as u16
}

// ---- Bloom filters -------------------------------------------------------------------------------------
#[derive(Clone, Copy)]
pub struct Bloom {
    bits: [u8; BLOOM_BYTES],
}

impl Bloom {
    pub const fn new() -> Self {
        Bloom { bits: [0; BLOOM_BYTES] }
    }
    fn idx(fp: u32, i: u64) -> usize {
        let h = splitmix64(fp as u64);
        let h1 = h & 0xFFFF_FFFF;
        let h2 = (h >> 32) | 1;
        (((h1 + i * h2) & 0xFFFF_FFFF) % BLOOM_BITS as u64) as usize
    }
    pub fn test(&self, fp: u32) -> bool {
        (0..BLOOM_K).all(|i| {
            let j = Self::idx(fp, i);
            self.bits[j >> 3] >> (j & 7) & 1 == 1
        })
    }
    /// Set the item's bits. True if it was not already present.
    pub fn set(&mut self, fp: u32) -> bool {
        let mut new = false;
        for i in 0..BLOOM_K {
            let j = Self::idx(fp, i);
            if self.bits[j >> 3] >> (j & 7) & 1 == 0 {
                new = true;
                self.bits[j >> 3] |= 1 << (j & 7);
            }
        }
        new
    }
    pub fn merge(&mut self, o: &Bloom) {
        for (a, b) in self.bits.iter_mut().zip(o.bits.iter()) {
            *a |= *b;
        }
    }
}

impl Default for Bloom {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Default)]
pub struct AgingBloom {
    cur: Bloom,
    old: Bloom,
}

impl AgingBloom {
    pub fn test(&self, fp: u32) -> bool {
        self.cur.test(fp) || self.old.test(fp)
    }
    pub fn rotate(&mut self) {
        self.old = self.cur;
        self.cur = Bloom::new();
    }
}

// ---- the hour aggregator -------------------------------------------------------------------------------
pub const KIND_PEER: u8 = 0;
pub const KIND_DNS: u8 = 1;

#[derive(Clone, Copy)]
pub struct HourAgg {
    pub conns: u64,
    pub bytes_out: u64,
    peers: Bloom,
    dns: Bloom,
    pub n_peers: u32,
    pub novel_peers: u32,
    pub n_dns: u32,
    pub novel_dns: u32,
    pub q_total: u32,
    pub q_nx: u32,
    novel: [(u8, u32); NOVEL_LIST],
    n_novel: u8,
}

impl HourAgg {
    pub const fn new() -> Self {
        HourAgg {
            conns: 0,
            bytes_out: 0,
            peers: Bloom::new(),
            dns: Bloom::new(),
            n_peers: 0,
            novel_peers: 0,
            n_dns: 0,
            novel_dns: 0,
            q_total: 0,
            q_nx: 0,
            novel: [(0, 0); NOVEL_LIST],
            n_novel: 0,
        }
    }
    pub fn reset(&mut self) {
        *self = Self::new();
    }
    fn push_novel(&mut self, kind: u8, fp: u32) {
        if (self.n_novel as usize) < NOVEL_LIST {
            self.novel[self.n_novel as usize] = (kind, fp);
            self.n_novel += 1;
        }
    }
    /// One flow (or flow summary). `fp = None` counts volume only.
    pub fn add_flow(&mut self, mem: &Dna, fp: Option<u32>, bytes_out: u64, conns: u64) {
        self.conns = self.conns.saturating_add(conns);
        self.bytes_out = self.bytes_out.saturating_add(bytes_out);
        if let Some(fp) = fp {
            if self.peers.set(fp) {
                self.n_peers += 1;
                if !mem.peers.test(fp) {
                    self.novel_peers += 1;
                    self.push_novel(KIND_PEER, fp);
                }
            }
        }
    }
    pub fn add_dns(&mut self, mem: &Dna, fp: u32, nx: bool) {
        self.q_total += 1;
        self.q_nx += nx as u32;
        if self.dns.set(fp) {
            self.n_dns += 1;
            if !mem.dns.test(fp) {
                self.novel_dns += 1;
                self.push_novel(KIND_DNS, fp);
            }
        }
    }
    pub fn nx_q16(&self) -> i64 {
        if self.q_total == 0 {
            0
        } else {
            (self.q_nx as i64 * 65536) / self.q_total as i64
        }
    }
}

impl Default for HourAgg {
    fn default() -> Self {
        Self::new()
    }
}

// ---- score ---------------------------------------------------------------------------------------------
/// One hour's verdict. All values Q8 (256 = 1.0). `score >= CALM_Q8` is an alarm; `driver` names the
/// largest part, so every alarm explains itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Score {
    pub score: i64,
    pub vol: i64,
    pub fan: i64,
    pub novel: i64,
    pub dns: i64,
    pub act: i64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Driver {
    Volume,
    FanOut,
    NovelPeers,
    Dns,
    Activity,
}

impl Score {
    /// Ties resolve in the order vol, fan, novel, dns, act (the Python dict order).
    pub fn driver(&self) -> Driver {
        let parts = [
            (self.vol, Driver::Volume),
            (self.fan, Driver::FanOut),
            (self.novel, Driver::NovelPeers),
            (self.dns, Driver::Dns),
            (self.act, Driver::Activity),
        ];
        let mut best = parts[0];
        for p in parts.iter().skip(1) {
            if p.0 > best.0 {
                best = *p;
            }
        }
        best.1
    }
}

// ---- the per-device memory -----------------------------------------------------------------------------
#[derive(Clone, Copy)]
struct Pending {
    kind: u8,
    fp: u32,
    count: u8,
}

#[derive(Clone, Copy)]
pub struct Dna {
    pub act: [u16; 24],
    pub bmu: [u16; 24],
    pub bdev: [u16; 24],
    pub fmu: [u16; 24],
    pub fdev: [u16; 24],
    pub n: [u8; 24],
    pub n_all: u16,
    /// pooled profile: act, bmu, bdev, fmu, fdev
    pub p: [u16; 5],
    pub nx: u16,
    pub nov_mu: u16,
    pub nov_dev: u16,
    peers: AgingBloom,
    dns: AgingBloom,
    pending: [Pending; PENDING_SLOTS],
    n_pending: u8,
    pub hours: u32,
}

impl Dna {
    pub const fn new() -> Self {
        Dna {
            act: [0; 24],
            bmu: [0; 24],
            bdev: [DEV_INIT_Q8; 24],
            fmu: [0; 24],
            fdev: [DEV_INIT_Q8; 24],
            n: [0; 24],
            n_all: 0,
            p: [0, 0, DEV_INIT_Q8, 0, DEV_INIT_Q8],
            nx: 0,
            nov_mu: 0,
            nov_dev: NOVDEV_INIT_Q8,
            peers: AgingBloom { cur: Bloom::new(), old: Bloom::new() },
            dns: AgingBloom { cur: Bloom::new(), old: Bloom::new() },
            pending: [Pending { kind: 0, fp: 0, count: 0 }; PENDING_SLOTS],
            n_pending: 0,
            hours: 0,
        }
    }

    fn base(&self, hr: usize) -> [i64; 5] {
        let slot = [
            self.act[hr] as i64,
            self.bmu[hr] as i64,
            self.bdev[hr] as i64,
            self.fmu[hr] as i64,
            self.fdev[hr] as i64,
        ];
        if self.n[hr] as i64 >= SLOT_MIN || self.n_all == 0 {
            return slot;
        }
        let w = self.n[hr] as i64;
        let mut m = [0i64; 5];
        for i in 0..5 {
            m[i] = (w * slot[i] + (SLOT_MIN - w) * self.p[i] as i64) / SLOT_MIN;
        }
        let widen = (SLOT_MIN - w) * COLD_WIDEN_Q8 / SLOT_MIN;
        [m[0] + widen, m[1], m[2] + widen, m[3], m[4] + widen]
    }

    /// Score an hour without changing anything.
    pub fn score(&self, hr: usize, agg: &HourAgg) -> Score {
        let [b_act, b_mu, b_dev, f_mu, f_dev] = self.base(hr);
        let lb = log2_q8(agg.bytes_out.saturating_add(1));
        let num = lb - b_mu;
        let vol = if num > 0 { num * 256 / (b_dev + HALF_Q8) } else { 0 };
        let lf = log2_q8(agg.n_peers as u64 + 1);
        let num = lf - f_mu;
        let fan = if num > 0 { num * 256 / (f_dev + HALF_Q8) } else { 0 };
        let num = agg.novel_peers as i64 * 256 - self.nov_mu as i64;
        let novel = if num > 0 { num * 256 / (self.nov_dev as i64 + NOV_EPS_Q8) } else { 0 };
        let frac = agg.novel_dns as i64 * 256 / (agg.n_dns.max(1) as i64);
        let m = (agg.novel_dns as i64 * 256 / 5).min(256);
        let d_nx = agg.nx_q16() - self.nx as i64;
        let dns = ((frac * m) >> 8) * 4 + if d_nx > 0 { (d_nx * 8) >> 8 } else { 0 };
        let num = log2_q8(agg.conns.saturating_add(1)) - b_act - ACT_MARGIN_Q8;
        let act = if num > 0 { num } else { 0 };
        let score = vol.max(fan).max(novel).max(dns).max(act);
        Score { score, vol, fan, novel, dns, act }
    }

    fn update(&mut self, hr: usize, agg: &HourAgg, admit_items: bool) {
        self.n[hr] = self.n[hr].saturating_add(1);
        self.n_all = self.n_all.saturating_add(1);
        let a = ALPHA_Q16.max(65536 / self.n[hr] as i64);
        let ap = ALPHA_Q16.max(65536 / self.n_all as i64);
        let lb = log2_q8(agg.bytes_out.saturating_add(1));
        let lf = log2_q8(agg.n_peers as u64 + 1);
        let lc = log2_q8(agg.conns.saturating_add(1));
        let [pa, pbm, pbd, pfm, pfd] = self.p.map(|v| v as i64);
        let pbd = if self.n_all > 1 { clamp16(ewma(pbd, (lb - pbm).abs(), ap)) } else { DEV_INIT_Q8 };
        let pbm = clamp16(ewma(pbm, lb, ap));
        let pfd = if self.n_all > 1 { clamp16(ewma(pfd, (lf - pfm).abs(), ap)) } else { DEV_INIT_Q8 };
        let pfm = clamp16(ewma(pfm, lf, ap));
        let pa = clamp16(ewma(pa, lc, ap));
        self.p = [pa, pbm, pbd, pfm, pfd];
        let nn = agg.novel_peers as i64 * 256;
        let (mu, dv) = (self.nov_mu as i64, self.nov_dev as i64);
        self.nov_dev = clamp16(ewma(dv, (nn - mu).abs(), a));
        self.nov_mu = clamp16(ewma(mu, nn, a));
        let first = self.n[hr] == 1;
        self.act[hr] = clamp16(ewma(self.act[hr] as i64, lc, a));
        let d = (lb - self.bmu[hr] as i64).abs();
        self.bmu[hr] = clamp16(ewma(self.bmu[hr] as i64, lb, a));
        if !first {
            self.bdev[hr] = clamp16(ewma(self.bdev[hr] as i64, d, a));
        }
        let d = (lf - self.fmu[hr] as i64).abs();
        self.fmu[hr] = clamp16(ewma(self.fmu[hr] as i64, lf, a));
        if !first {
            self.fdev[hr] = clamp16(ewma(self.fdev[hr] as i64, d, a));
        }
        self.nx = clamp16(ewma(self.nx as i64, agg.nx_q16(), a));
        if admit_items {
            self.peers.cur.merge(&agg.peers);
            self.dns.cur.merge(&agg.dns);
        }
    }

    fn pending_remove(&mut self, j: usize) {
        let n = self.n_pending as usize;
        for q in j..n - 1 {
            self.pending[q] = self.pending[q + 1];
        }
        self.n_pending -= 1;
    }

    fn admit_persistent(&mut self, agg: &HourAgg) {
        for &(kind, fp) in &agg.novel[..agg.n_novel as usize] {
            let known = if kind == KIND_PEER { self.peers.test(fp) } else { self.dns.test(fp) };
            if known {
                continue;
            }
            let n = self.n_pending as usize;
            let j = match (0..n).find(|&q| self.pending[q].kind == kind && self.pending[q].fp == fp) {
                Some(q) => q,
                None if n < PENDING_SLOTS => {
                    self.pending[n] = Pending { kind, fp, count: 0 };
                    self.n_pending += 1;
                    n
                }
                None => {
                    // replace the lowest count; the first such entry on ties
                    let mut q = 0;
                    for c in 1..n {
                        if self.pending[c].count < self.pending[q].count {
                            q = c;
                        }
                    }
                    self.pending[q] = Pending { kind, fp, count: 0 };
                    q
                }
            };
            self.pending[j].count += 1;
            if self.pending[j].count >= PERSIST_K {
                if kind == KIND_PEER {
                    self.peers.cur.set(fp);
                } else {
                    self.dns.cur.set(fp);
                }
                self.pending_remove(j);
            }
        }
    }

    pub fn cold(&self, hr: usize) -> bool {
        (self.n[hr] as i64) < SLOT_MIN
    }

    /// Score the hour, then apply the guarded update:
    /// - calm hour: learn statistics and admit its items;
    /// - alarming hour: learn statistics only while the slot is cold; novel items count toward persistence.
    ///
    /// The caller resets `agg` afterwards.
    pub fn close_hour(&mut self, hr: usize, agg: &HourAgg) -> Score {
        let s = self.score(hr, agg);
        if s.score < CALM_Q8 {
            self.update(hr, agg, true);
        } else {
            if self.cold(hr) {
                self.update(hr, agg, false);
            }
            self.admit_persistent(agg);
        }
        self.hours = self.hours.wrapping_add(1);
        if self.hours.is_multiple_of(ROTATE_HOURS) {
            self.peers.rotate();
            self.dns.rotate();
        }
        s
    }
}

impl Default for Dna {
    fn default() -> Self {
        Self::new()
    }
}

/// Bytes per device, including the hour aggregator. These are the real struct sizes; `tests/golden.rs`
/// prints them next to the Python estimate.
pub const fn bytes_per_device() -> usize {
    core::mem::size_of::<Dna>() + core::mem::size_of::<HourAgg>()
}
