// SPDX-License-Identifier: AGPL-3.0-only
//! HookProbe Neuro L1 (candidate, not deployed): the DNA v1 host-hour vector in fixed point and the frozen S1
//! scorer as an integer twin.
//!
//! **Status: research artefact.** M3 (doc 31) failed S1's recall gate. This crate exists so that doc 35's M4
//! (L1-IoT) can measure the *integer* path on its sealed data, and so that a later EL0 L1 server has a reviewed core.
//! Nothing in the kernel uses it. No model may reach a device without passing a sealed gate and a signed package
//! (heqk D3).
//!
//! **Input.** One [`Conn`] per connection, as the reference `tools/neuro-research/bench/dna_features.py` sees a flow
//! event. EL1 would supply these (doc 34 §4: a per-connection summary that `neuro-dp` does not produce today); this
//! crate never sees an address: peers are fingerprints with a LAN flag, and "novel" is decided by the caller from its
//! 24 h peer memory.
//!
//! **Output.** [`HourAgg::quantise`] gives the 28 S1 features as u8, exactly as `s1_model.json` quantises the
//! reference's float vector, up to fixed-point rounding (tests/parity.rs measures it on real dev windows); then
//! [`score`] / [`alert`] apply the frozen weights.
//!
//! **Arithmetic.** Integers only: Q32 logarithms by repeated squaring, integer square root, i128 intermediates.
//! No float, no allocation, no `unsafe`.
//!
//! **Bounded state** (each bound counted in [`Overflow`]; within the bounds the result equals the reference):
//! - 3/4 of [`REMOTES`] (3,072) distinct peers with counts; further peers are counted by linear counting (and miss
//!   the periodicity log);
//! - 3/4 of [`PORTS`] (1,536) destination ports with counts; further ports use an exact 65,537-bit distinct set and count
//!   as singletons in the port entropy and top share;
//! - [`LOG`] (peer, time) entries for the periodicity of the top-3 peers (the reference keeps every peer's first
//!   400 times; this keeps the first `LOG` connections of the hour).
#![no_std]
#![forbid(unsafe_code)]

pub mod s1_model;

pub const REMOTES: usize = 4096;
pub const PORTS: usize = 2048;
pub const LOG: usize = 16384;
/// Times per peer used for periodicity (reference: 400).
pub const TIMES_PER_PEER: usize = 400;
const LC_BITS: usize = 1 << 15;
const NO_PORT: u32 = 65_536;
const ONE: i128 = 1 << 32;
/// ln 2 in Q32.
const LN2_Q32: i128 = 2_977_044_472;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Proto {
    Tcp,
    Udp,
    Icmp,
    Other,
}

/// One connection, from the host's point of view (field meanings as in `dna_features.py`).
#[derive(Clone, Copy, Debug)]
pub struct Conn {
    /// Microseconds since the start of the UTC hour (< 3,600,000,000).
    pub t_us: u32,
    /// The host initiated it (sent the first packet / SYN).
    pub out: bool,
    /// Peer fingerprint (never an address).
    pub peer: u32,
    /// The peer is a LAN address.
    pub peer_lan: bool,
    /// Destination port of an outbound connection; `None` for inbound or port-less.
    pub port: Option<u16>,
    pub proto: Proto,
    /// No reply / rejected / reset without data (`dna_features.FAIL`).
    pub failed: bool,
    /// Bytes the host sent / received on it.
    pub bytes_out: u64,
    pub bytes_in: u64,
    pub dur_us: u64,
    /// Packets sent by the initiator (the reference's `orig_pkts`).
    pub pkts: u32,
    /// Outbound and (host, peer) was not seen in the previous 24 h.
    pub novel: bool,
}

/// How often a bound was hit during the hour (0 = exact).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Overflow {
    pub remotes: u32,
    pub ports: u32,
    pub log: u32,
}

#[derive(Clone, Copy)]
struct Remote {
    used: bool,
    peer: u32,
    count: u32,
    order: u32,
    lan: bool,
    inbound: bool,
}

const R0: Remote = Remote { used: false, peer: 0, count: 0, order: 0, lan: false, inbound: false };

/// Per host-hour aggregate. Large (~200 KiB): keep it in a static, not on a stack.
pub struct HourAgg {
    n: u64,
    out: u64,
    fail: u64,
    bo: u128,
    bi: u128,
    dur: u128,
    pk: u128,
    tcp: u64,
    udp: u64,
    icmp: u64,
    pairs: u64,
    novel: u64,
    per_min: [u32; 60],
    remotes: [Remote; REMOTES],
    n_remotes: u32,
    lc_all: [u64; LC_BITS / 64],
    lc_lan: [u64; LC_BITS / 64],
    lc_inb: [u64; LC_BITS / 64],
    ports: [(u32, u32); PORTS],
    n_ports: u32,
    port_seen: [u64; 1025],
    port_out_total: u64,
    log: [(u16, u32); LOG],
    n_log: usize,
    pub overflow: Overflow,
}

impl Default for HourAgg {
    fn default() -> Self {
        Self::new()
    }
}

fn mix(x: u32) -> u32 {
    let mut z = x.wrapping_mul(0x9E37_79B9);
    z ^= z >> 16;
    z = z.wrapping_mul(0x85EB_CA6B);
    z ^ (z >> 13)
}

impl HourAgg {
    pub const fn new() -> Self {
        Self {
            n: 0,
            out: 0,
            fail: 0,
            bo: 0,
            bi: 0,
            dur: 0,
            pk: 0,
            tcp: 0,
            udp: 0,
            icmp: 0,
            pairs: 0,
            novel: 0,
            per_min: [0; 60],
            remotes: [R0; REMOTES],
            n_remotes: 0,
            lc_all: [0; LC_BITS / 64],
            lc_lan: [0; LC_BITS / 64],
            lc_inb: [0; LC_BITS / 64],
            ports: [(u32::MAX, 0); PORTS],
            n_ports: 0,
            port_seen: [0; 1025],
            port_out_total: 0,
            log: [(0, 0); LOG],
            n_log: 0,
            overflow: Overflow { remotes: 0, ports: 0, log: 0 },
        }
    }

    /// Start a new hour (keeps the allocation).
    pub fn clear(&mut self) {
        *self = Self::new();
    }

    fn remote_slot(&mut self, peer: u32) -> Option<usize> {
        let mut i = mix(peer) as usize % REMOTES;
        for _ in 0..REMOTES {
            let r = &self.remotes[i];
            if !r.used {
                if self.n_remotes as usize >= REMOTES * 3 / 4 {
                    return None;
                }
                self.remotes[i] = Remote { used: true, peer, count: 0, order: self.n_remotes, lan: false, inbound: false };
                self.n_remotes += 1;
                return Some(i);
            }
            if r.peer == peer {
                return Some(i);
            }
            i = (i + 1) % REMOTES;
        }
        None
    }

    fn port_add(&mut self, port: u32) {
        let (w, b) = (port as usize / 64, port % 64);
        self.port_seen[w] |= 1 << b;
        let mut i = mix(port) as usize % PORTS;
        for _ in 0..PORTS {
            if self.ports[i].0 == port {
                self.ports[i].1 += 1;
                return;
            }
            if self.ports[i].0 == u32::MAX {
                if self.n_ports as usize >= PORTS * 3 / 4 {
                    break;
                }
                self.ports[i] = (port, 1);
                self.n_ports += 1;
                return;
            }
            i = (i + 1) % PORTS;
        }
        self.overflow.ports += 1;
    }

    pub fn add(&mut self, c: &Conn) {
        self.n += 1;
        self.out += c.out as u64;
        self.fail += c.failed as u64;
        self.bo += c.bytes_out as u128;
        self.bi += c.bytes_in as u128;
        self.dur += c.dur_us as u128;
        self.pk += c.pkts as u128;
        match c.proto {
            Proto::Tcp => self.tcp += 1,
            Proto::Udp => self.udp += 1,
            Proto::Icmp => self.icmp += 1,
            Proto::Other => {}
        }
        let bin = (c.t_us / 60_000_000).min(59) as usize;
        self.per_min[bin] += 1;
        if c.out {
            self.pairs += 1;
            self.novel += c.novel as u64;
            self.port_out_total += 1;
            self.port_add(c.port.map_or(NO_PORT, u32::from));
        }
        match self.remote_slot(c.peer) {
            Some(i) => {
                let r = &mut self.remotes[i];
                r.count += 1;
                r.lan |= c.peer_lan;
                r.inbound |= !c.out;
                if self.n_log < LOG {
                    self.log[self.n_log] = (i as u16, c.t_us);
                    self.n_log += 1;
                } else {
                    self.overflow.log += 1;
                }
            }
            None => {
                self.overflow.remotes += 1;
                let h = mix(c.peer ^ 0x5bd1_e995) as usize % LC_BITS;
                self.lc_all[h / 64] |= 1 << (h % 64);
                if c.peer_lan {
                    self.lc_lan[h / 64] |= 1 << (h % 64);
                }
                if !c.out {
                    self.lc_inb[h / 64] |= 1 << (h % 64);
                }
            }
        }
    }

    pub fn events(&self) -> u64 {
        self.n
    }

    fn lc(bits: &[u64; LC_BITS / 64]) -> u64 {
        // linear counting: m * ln(m / zeros), integer via Q32 logs
        let ones: u32 = bits.iter().map(|w| w.count_ones()).sum();
        if ones == 0 {
            return 0;
        }
        let m = LC_BITS as u128;
        let zeros = (m - ones as u128).max(1);
        let est = (m as i128 * (ln_q32(m) - ln_q32(zeros))) >> 32;
        est.max(ones as i128) as u64
    }

    /// The 28 S1 features (order of `s1_model.json`), quantised to u8 as the frozen model does.
    pub fn quantise(&self) -> [u8; 28] {
        let mut x = [0i128; 28];
        let n = self.n.max(1) as u128;
        let frac = |a: u64, b: u128| ((a as i128) << 32) / (b.max(1) as i128);
        let lg_int = |v: u128| ln_q32(v + 1);
        let lg_rat = |a: u128, b: u128| ln_q32(a + b) - ln_q32(b); // ln(1 + a/b), b > 0
        // distinct remotes / LAN / inbound (tracked exactly + linear-counted overflow)
        let (mut d_lan, mut d_inb) = (0u64, 0u64);
        for r in self.remotes.iter().filter(|r| r.used) {
            d_lan += r.lan as u64;
            d_inb += r.inbound as u64;
        }
        let d_rem = self.n_remotes as u64 + Self::lc(&self.lc_all);
        d_lan += Self::lc(&self.lc_lan);
        d_inb += Self::lc(&self.lc_inb);
        // ports (outbound only)
        let po = self.port_out_total.max(1);
        let d_ports: u64 = self.port_seen.iter().map(|w| w.count_ones() as u64).sum();
        let mut top = 0u32;
        let mut clogc: i128 = 0; // sum c * log2(c), Q32
        let (mut wk, mut tel, mut ssh, mut smb, mut web, mut dns, mut ntp) = (0u64, 0u64, 0u64, 0u64, 0u64, 0u64, 0u64);
        for &(p, c) in self.ports.iter().filter(|e| e.0 != u32::MAX) {
            top = top.max(c);
            clogc += c as i128 * log2_q32(c as u128);
            let c = c as u64;
            if p < 1024 {
                wk += c;
            }
            match p {
                23 | 2323 => tel += c,
                22 => ssh += c,
                445 | 139 => smb += c,
                80 | 443 | 8080 => web += c,
                53 => dns += c,
                123 => ntp += c,
                _ => {}
            }
        }
        if self.overflow.ports > 0 {
            top = top.max(1); // overflow ports count as singletons (c log c = 0)
        }
        let ent = if self.port_out_total == 0 { 0 } else { log2_q32(po as u128) - clogc / po as i128 };
        let (cv, period) = self.periodicity();
        x[0] = lg_int(self.n as u128);
        x[1] = frac(self.out, n);
        x[2] = lg_int(d_rem as u128);
        x[3] = lg_int(d_ports as u128);
        x[4] = ent;
        x[5] = if self.port_out_total == 0 { 0 } else { frac(top as u64, po as u128) };
        x[6] = frac(self.fail, n);
        x[7] = lg_int(self.bo);
        x[8] = lg_int(self.bi);
        x[9] = ln_q32(self.bo + 1) - ln_q32(self.bi + 1);
        x[10] = lg_rat(self.dur, n * 1_000_000);
        x[11] = lg_rat(self.pk, n);
        x[12] = frac(self.tcp, n);
        x[13] = frac(self.udp, n);
        x[14] = frac(self.icmp, n);
        x[15] = frac(wk, po as u128);
        x[16] = frac(tel, po as u128);
        x[17] = frac(ssh, po as u128);
        x[18] = frac(smb, po as u128);
        x[19] = frac(web, po as u128);
        x[20] = frac(dns, po as u128);
        x[21] = frac(ntp, po as u128);
        x[22] = cv;
        x[23] = period;
        x[24] = lg_int(*self.per_min.iter().max().unwrap_or(&0) as u128);
        x[25] = if self.pairs == 0 { 0 } else { frac(self.novel, self.pairs as u128) };
        x[26] = frac(d_lan, d_rem.max(1) as u128);
        x[27] = lg_int(d_inb as u128);
        let mut q = [0u8; 28];
        for i in 0..28 {
            q[i] = quantise_one(x[i], s1_model::LO_Q32[i] as i128, s1_model::RANGE_Q32[i] as i128);
        }
        q
    }

    /// Reference: among the 3 most frequent peers (ties: first seen), the lowest coefficient of variation of the
    /// positive gaps between the sorted first-400 times, if >= 6 times and >= 5 gaps; start cv = 1, period = 0.
    /// Returns (cv, ln(1 + mean gap in seconds)) in Q32.
    fn periodicity(&self) -> (i128, i128) {
        let mut top: [Option<(u32, u32, usize)>; 3] = [None; 3]; // (count, order, slot)
        for (i, r) in self.remotes.iter().enumerate().filter(|(_, r)| r.used) {
            let cand = (r.count, r.order, i);
            for k in 0..3 {
                let better = match top[k] {
                    None => true,
                    Some((c, o, _)) => cand.0 > c || (cand.0 == c && cand.1 < o),
                };
                if better {
                    for j in (k + 1..3).rev() {
                        top[j] = top[j - 1];
                    }
                    top[k] = Some(cand);
                    break;
                }
            }
        }
        let (mut best_cv, mut best_mean): (i128, Option<(u128, u128)>) = (ONE, None);
        for (_, _, slot) in top.iter().flatten() {
            let mut ts = [0u32; TIMES_PER_PEER];
            let mut k = 0;
            for &(s, t) in self.log[..self.n_log].iter() {
                if s as usize == *slot && k < TIMES_PER_PEER {
                    ts[k] = t;
                    k += 1;
                }
            }
            if k < 6 {
                continue;
            }
            let ts = &mut ts[..k];
            ts.sort_unstable();
            let (mut l, mut s1, mut s2) = (0u128, 0u128, 0u128);
            for w in ts.windows(2) {
                if w[1] > w[0] {
                    let d = (w[1] - w[0]) as u128;
                    l += 1;
                    s1 += d;
                    s2 += d * d;
                }
            }
            if l < 5 || s1 == 0 {
                continue;
            }
            // cv^2 = (L*S2 - S1^2) / S1^2 ; scale both down to keep (num << 64) in u128
            let num = l * s2 - s1 * s1;
            let den = s1 * s1;
            if num >= den {
                continue; // cv >= 1 can never beat the starting cv of 1 (and would overflow the scaling below)
            }
            let sh = (128 - den.leading_zeros()).saturating_sub(62);
            let (num, den) = (num >> sh, (den >> sh).max(1));
            let cv = isqrt((num << 64) / den) as i128; // Q32
            if cv < best_cv {
                best_cv = cv;
                best_mean = Some((s1, l));
            }
        }
        let period = match best_mean {
            None => 0,
            Some((s1, l)) => ln_q32(l * 1_000_000 + s1) - ln_q32(l * 1_000_000),
        };
        (best_cv, period)
    }
}

fn quantise_one(x: i128, lo: i128, range: i128) -> u8 {
    // q = round(255 * (x - lo) / range), half away from zero on the integer grid; clipped to [0, 255]
    let num = 255 * (x - lo);
    let q = if num >= 0 { (2 * num + range) / (2 * range) } else { -((-2 * num + range) / (2 * range)) };
    q.clamp(0, 255) as u8
}

/// log2(n) in Q32 for n >= 1 (n = 0 gives 0): integer part from the bit length, 32 fraction bits by squaring.
pub fn log2_q32(n: u128) -> i128 {
    if n == 0 {
        return 0;
    }
    let e = 127 - n.leading_zeros() as i32;
    let mut m: u128 = if e >= 62 { n >> (e - 62) } else { n << (62 - e) }; // Q62 in [1, 2)
    let mut frac: i128 = 0;
    for i in (0..32).rev() {
        m = (m * m) >> 62;
        if m >= 2u128 << 62 {
            m >>= 1;
            frac |= 1 << i;
        }
    }
    ((e as i128) << 32) | frac
}

/// ln(n) in Q32.
pub fn ln_q32(n: u128) -> i128 {
    (log2_q32(n) * LN2_Q32) >> 32
}

pub fn isqrt(v: u128) -> u128 {
    if v < 2 {
        return v;
    }
    let mut x = 1u128 << ((128 - v.leading_zeros()).div_ceil(2));
    loop {
        let y = (x + v / x) / 2;
        if y >= x {
            return x;
        }
        x = y;
    }
}

/// S1 accumulator: sum(wq * q) + bq (|acc| < 2^31 for every u8 input, checked at generation).
pub fn score(q: &[u8; 28]) -> i32 {
    let acc = s1_model::WQ.iter().zip(q).fold(s1_model::BQ as i64, |a, (&w, &v)| a + w as i64 * v as i64);
    acc as i32
}

/// The frozen S1 decision: acc > THR_Q. Evidence for the owner-notification tier only, never an enforcement input.
pub fn alert(q: &[u8; 28]) -> bool {
    score(q) > s1_model::THR_Q
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log2_exact_powers_and_monotone() {
        for e in 0..100u32 {
            assert_eq!(log2_q32(1u128 << e), (e as i128) << 32);
        }
        let mut last = -1;
        for n in 1..5000u128 {
            let v = log2_q32(n);
            assert!(v > last);
            last = v;
        }
        // log2(3) = 1.584962500721156
        let err = (log2_q32(3) - 6_807_362_106).abs();
        assert!(err <= 2, "{err}");
    }

    #[test]
    fn isqrt_floor() {
        for v in 0..10_000u128 {
            let r = isqrt(v);
            assert!(r * r <= v && (r + 1) * (r + 1) > v);
        }
    }

    #[test]
    fn state_size() {
        let s = core::mem::size_of::<HourAgg>();
        assert!(s < 256 * 1024, "{s}");
    }

    #[test]
    fn accumulator_fits() {
        let mut worst = s1_model::BQ.unsigned_abs() as i64;
        for w in s1_model::WQ {
            worst += 255 * (w as i64).abs();
        }
        assert!(worst < i32::MAX as i64);
    }
}
