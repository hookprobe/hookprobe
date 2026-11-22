// SPDX-License-Identifier: AGPL-3.0-only
//! HookProbe Neuro: the kernel's data-plane adapter (docs/research/neuro/20 §2).
//!
//! Turns the frames a device sends and receives into the engine's inputs, **exactly as the reference converter**
//! `tools/neuro-research/unsw_to_d1.py --peer-key v2-24 --name-table 4096` does (pinned by `tests/parity.rs` on a
//! capture), with bounded state:
//! - **DNS query** (device -> UDP/53): one DNS event, fingerprint of the registered domain; held until its response
//!   (NX flag = rcode 3) or a timeout.
//! - **DNS response** (UDP/53 -> device): every A/AAAA answer goes into the name table (`peerkey::NameTable<4096>`,
//!   128 KiB, stores an FNV state, never a name or an address string).
//! - **New connection**: a TCP SYN without ACK from the device, or a UDP 5-tuple from the device idle >= 120 s; the
//!   peer fingerprint is `peerkey::peer_fp(Mode::V2 { plen: 24 }, ..)`.
//! - **Bytes**: the IP length of every packet the device sends.
//!
//! This is EL1 code: it sees addresses and names so that the EL0 engine never does; what leaves it is fingerprints
//! and counts. No allocation, no float, no `unsafe`; every read is bounds-checked (a malformed frame yields nothing).
//!
//! Differences from the reference, all bounded-state consequences, documented and counted:
//! - the UDP idle table holds `UDP_N` 5-tuples (hashed, 4-way, oldest evicted): an evicted live flow counts again as
//!   a new connection (`Counters::udp_evicted`);
//! - a DNS query waits at most `PEND_TIMEOUT_US` for its response and `PEND_N` queries are pending at once; past
//!   either it is reported without the NX flag (`Counters::dns_timeouts`, `dns_evicted`). The reference waits forever.
//! - the event for a DNS query is produced when its response (or timeout) arrives; it carries the QUERY time.
#![no_std]
#![forbid(unsafe_code)]

use neuro_core::peerkey::{self, Ip, Mode, NameTable, Proto, Rule};
use neuro_core::{fingerprint, fnv1a64, splitmix64};

/// The deployed peer key (doc 20).
pub const MODE: Mode = Mode::V2 { plen: 24 };
/// Name-table entries (doc 20: 4,096 = 128 KiB).
pub const NAMES: usize = 4096;
/// A UDP 5-tuple idle this long starts a new connection (doc 17).
pub const UDP_IDLE_US: u64 = 120_000_000;
pub const UDP_N: usize = 1024;
const UDP_WAYS: usize = 4;
const _: () = assert!(UDP_N.is_multiple_of(UDP_WAYS) && (UDP_N / UDP_WAYS).is_power_of_two());
pub const PEND_N: usize = 256;
pub const PEND_TIMEOUT_US: u64 = 10_000_000;
/// Longest question name kept (RFC 1035: 255 octets on the wire; a replacement char can take 3 bytes per byte).
const QNAME_MAX: usize = 3 * 255;

/// One adapter output. `ts_us` is the time the event belongs to (a DNS event: its query).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Out {
    /// A new connection from `dev` to peer fingerprint `fp`.
    Flow { dev: u16, fp: u32, ts_us: u64 },
    /// A DNS query from `dev` for registered-domain fingerprint `fp`; `nx` = its response had rcode 3.
    Dns { dev: u16, fp: u32, nx: bool, ts_us: u64 },
    /// IP bytes sent by `dev` in one packet.
    Bytes { dev: u16, bytes: u32, ts_us: u64 },
}

/// Honesty counters (doc 20 "rule counters"): never sent to the engine.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counters {
    pub frames: u64,
    pub unparsed: u64,
    pub rule_class: u64,
    pub rule_local: u64,
    pub rule_named: u64,
    pub rule_prefix: u64,
    pub udp_evicted: u64,
    pub dns_timeouts: u64,
    pub dns_evicted: u64,
    pub names_learned: u64,
}

#[derive(Clone, Copy)]
struct UdpEnt {
    used: bool,
    key: u64,
    last_us: u64,
}

#[derive(Clone, Copy)]
struct Pend {
    used: bool,
    dev: u16,
    txid: u16,
    qkey: u64,
    fp: u32,
    ts_us: u64,
}

/// The adapter. ~128 KiB (name table) + 24 KiB (UDP table) + 8 KiB (pending DNS); the kernel keeps one in .bss.
pub struct Dp {
    names: NameTable<NAMES>,
    udp: [UdpEnt; UDP_N],
    pend: [Pend; PEND_N],
    pub c: Counters,
}

/// A parsed frame (the reference `parse()`; IPv6 without extension-header walking, as there).
#[derive(Clone, Copy, Debug)]
pub struct Pkt<'a> {
    pub src_mac: [u8; 6],
    pub dst_mac: [u8; 6],
    pub src: Ip,
    pub dst: Ip,
    pub proto: u8,
    pub sport: u16,
    pub dport: u16,
    pub flags: u8,
    pub payload: &'a [u8],
    pub ip_len: u32,
}

fn be16(b: &[u8], i: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*b.get(i)?, *b.get(i + 1)?]))
}

/// Parse an Ethernet II frame (802.1Q / QinQ tags skipped). None = not IPv4/IPv6 or too short.
pub fn parse(frame: &[u8]) -> Option<Pkt<'_>> {
    if frame.len() < 14 {
        return None;
    }
    let dst_mac: [u8; 6] = frame[0..6].try_into().ok()?;
    let src_mac: [u8; 6] = frame[6..12].try_into().ok()?;
    let mut et = be16(frame, 12)?;
    let mut off = 14;
    while (et == 0x8100 || et == 0x88A8) && frame.len() >= off + 4 {
        et = be16(frame, off + 2)?;
        off += 4;
    }
    let (src, dst, proto, l4, ip_len) = if et == 0x0800 && frame.len() >= off + 20 {
        let ihl = (frame[off] & 0x0F) as usize * 4;
        let ip_len = be16(frame, off + 2)? as u32;
        let s: [u8; 4] = frame[off + 12..off + 16].try_into().ok()?;
        let d: [u8; 4] = frame[off + 16..off + 20].try_into().ok()?;
        (Ip::V4(s), Ip::V4(d), frame[off + 9], off + ihl, ip_len)
    } else if et == 0x86DD && frame.len() >= off + 40 {
        let ip_len = be16(frame, off + 4)? as u32 + 40;
        let s: [u8; 16] = frame[off + 8..off + 24].try_into().ok()?;
        let d: [u8; 16] = frame[off + 24..off + 40].try_into().ok()?;
        (Ip::V6(s), Ip::V6(d), frame[off + 6], off + 40, ip_len)
    } else {
        return None;
    };
    let base = Pkt { src_mac, dst_mac, src, dst, proto, sport: 0, dport: 0, flags: 0, payload: &[], ip_len };
    if proto == 6 && frame.len() >= l4 + 14 {
        let doff = (frame[l4 + 12] >> 4) as usize * 4;
        return Some(Pkt { sport: be16(frame, l4)?, dport: be16(frame, l4 + 2)?, flags: frame[l4 + 13], payload: frame.get(l4 + doff..).unwrap_or(&[]), ..base });
    }
    if proto == 17 && frame.len() >= l4 + 8 {
        return Some(Pkt { sport: be16(frame, l4)?, dport: be16(frame, l4 + 2)?, payload: &frame[l4 + 8..], ..base });
    }
    Some(base)
}

/// A DNS message's question: (txid, rcode, is_response, name length). The name (labels joined with '.', a non-ASCII
/// byte as U+FFFD, as the reference decodes it) is written into `name`. Uncompressed question names only.
pub fn dns_question(p: &[u8], name: &mut [u8; QNAME_MAX]) -> Option<(u16, u8, bool, usize)> {
    if p.len() < 12 {
        return None;
    }
    let txid = be16(p, 0)?;
    let flags = be16(p, 2)?;
    if be16(p, 4)? < 1 {
        return None;
    }
    let (mut i, mut n, mut labels) = (12usize, 0usize, 0usize);
    while i < p.len() {
        let ln = p[i] as usize;
        if ln == 0 {
            break;
        }
        if ln & 0xC0 != 0 || i + 1 + ln > p.len() {
            return None;
        }
        if labels > 0 {
            *name.get_mut(n)? = b'.';
            n += 1;
        }
        for &c in &p[i + 1..i + 1 + ln] {
            if c < 0x80 {
                *name.get_mut(n)? = c;
                n += 1;
            } else {
                for r in [0xEF, 0xBF, 0xBD] {
                    *name.get_mut(n)? = r;
                    n += 1;
                }
            }
        }
        labels += 1;
        i += 1 + ln;
    }
    if labels == 0 {
        return None;
    }
    Some((txid, (flags & 0x0F) as u8, flags & 0x8000 != 0, n))
}

fn chars(s: &[u8]) -> usize {
    s.iter().filter(|b| **b & 0xC0 != 0x80).count()
}

/// The registered domain (doc 17): lowercased, the last two labels, or three when the second-to-last label has <= 3
/// characters. Written into `out`; returns its length.
pub fn registered_domain(name: &[u8], out: &mut [u8; QNAME_MAX]) -> usize {
    // the last three non-empty labels, as the reference splits the joined name on '.' (spans[0] = the last label)
    let mut spans = [(0usize, 0usize); 3];
    let mut count = 0usize;
    let mut end = name.len();
    loop {
        let s = name[..end].iter().rposition(|&c| c == b'.').map_or(0, |p| p + 1);
        if s < end {
            if count < 3 {
                spans[count] = (s, end);
            }
            count += 1;
        }
        if s == 0 {
            break;
        }
        end = s - 1;
    }
    let k = if count <= 2 { count } else if chars(&name[spans[1].0..spans[1].1]) <= 3 { 3 } else { 2 };
    let mut n = 0;
    for j in (0..k).rev() {
        if n > 0 {
            out[n] = b'.';
            n += 1;
        }
        for &c in &name[spans[j].0..spans[j].1] {
            out[n] = c.to_ascii_lowercase();
            n += 1;
        }
    }
    n
}

/// The DNS event fingerprint of a question name: `fingerprint(fnv1a64(registered domain))`.
pub fn dns_fp(name: &[u8]) -> u32 {
    let mut rd = [0u8; QNAME_MAX];
    let n = registered_domain(name, &mut rd);
    fingerprint(fnv1a64(&rd[..n]))
}

fn skip_name(p: &[u8], mut i: usize) -> Option<usize> {
    while i < p.len() {
        let ln = p[i] as usize;
        if ln == 0 {
            return Some(i + 1);
        }
        if ln & 0xC0 == 0xC0 {
            return Some(i + 2);
        }
        i += 1 + ln;
    }
    None
}

/// Every A/AAAA address in a DNS response's answer section (name compression handled), in order.
pub fn dns_answers(p: &[u8], mut f: impl FnMut(Ip)) {
    if p.len() < 12 {
        return;
    }
    let (Some(qd), Some(an)) = (be16(p, 4), be16(p, 6)) else { return };
    let mut i = 12;
    for _ in 0..qd {
        match skip_name(p, i) {
            Some(j) => i = j + 4,
            None => return,
        }
    }
    for _ in 0..an {
        let Some(j) = skip_name(p, i) else { break };
        i = j;
        if i + 10 > p.len() {
            break;
        }
        let typ = be16(p, i).unwrap_or(0);
        let rdlen = be16(p, i + 8).unwrap_or(0) as usize;
        i += 10;
        if i + rdlen > p.len() {
            break;
        }
        if typ == 1 && rdlen == 4 {
            if let Ok(a) = p[i..i + 4].try_into() {
                f(Ip::V4(a));
            }
        } else if typ == 28 && rdlen == 16 {
            if let Ok(a) = p[i..i + 16].try_into() {
                f(Ip::V6(a));
            }
        }
        i += rdlen;
    }
}

fn lower_key(name: &[u8]) -> u64 {
    let mut h: u64 = 0xCBF2_9CE4_8422_2325;
    for &c in name {
        h = (h ^ c.to_ascii_lowercase() as u64).wrapping_mul(0x0000_0100_0000_01B3);
    }
    h
}

fn ip_bytes(ip: &Ip, out: &mut [u8; 17]) -> usize {
    match ip {
        Ip::V4(a) => {
            out[0] = 4;
            out[1..5].copy_from_slice(a);
            5
        }
        Ip::V6(a) => {
            out[0] = 6;
            out[1..17].copy_from_slice(a);
            17
        }
    }
}

impl Dp {
    pub const fn new() -> Self {
        Dp {
            names: NameTable::new(),
            udp: [UdpEnt { used: false, key: 0, last_us: 0 }; UDP_N],
            pend: [Pend { used: false, dev: 0, txid: 0, qkey: 0, fp: 0, ts_us: 0 }; PEND_N],
            c: Counters { frames: 0, unparsed: 0, rule_class: 0, rule_local: 0, rule_named: 0, rule_prefix: 0, udp_evicted: 0, dns_timeouts: 0, dns_evicted: 0, names_learned: 0 },
        }
    }

    fn peer(&mut self, dev: u16, ts_us: u64, dst: &Ip, port: u16, proto: Proto) -> u32 {
        let named = self.names.lookup(dev, dst, (ts_us / 1_000_000) as u32);
        let (fp, rule) = peerkey::peer_fp(MODE, dst, port, proto, named);
        match rule {
            Rule::Class => self.c.rule_class += 1,
            Rule::Local | Rule::Exact => self.c.rule_local += 1,
            Rule::Named => self.c.rule_named += 1,
            Rule::Prefix => self.c.rule_prefix += 1,
        }
        fp
    }

    /// Is this UDP 5-tuple of `dev` a new connection at `ts_us` (first seen, or idle >= 120 s)? Records it.
    fn udp_new(&mut self, dev: u16, p: &Pkt, ts_us: u64) -> bool {
        let mut k = [0u8; 2 + 17 + 17 + 4];
        k[..2].copy_from_slice(&dev.to_le_bytes());
        let mut b = [0u8; 17];
        let n1 = ip_bytes(&p.src, &mut b);
        k[2..2 + n1].copy_from_slice(&b[..n1]);
        let n2 = ip_bytes(&p.dst, &mut b);
        k[2 + n1..2 + n1 + n2].copy_from_slice(&b[..n2]);
        let o = 2 + n1 + n2;
        k[o..o + 2].copy_from_slice(&p.sport.to_be_bytes());
        k[o + 2..o + 4].copy_from_slice(&p.dport.to_be_bytes());
        let key = fnv1a64(&k[..o + 4]);
        let base = (splitmix64(key) % (UDP_N / UDP_WAYS) as u64) as usize * UDP_WAYS;
        let set = &mut self.udp[base..base + UDP_WAYS];
        if let Some(e) = set.iter_mut().find(|e| e.used && e.key == key) {
            // the reference: new when `ts - last >= 120`; a clock that went back is not a new connection
            let new = ts_us >= e.last_us && ts_us - e.last_us >= UDP_IDLE_US;
            e.last_us = ts_us;
            return new;
        }
        let j = match set.iter().position(|e| !e.used) {
            Some(j) => j,
            None => {
                self.c.udp_evicted += 1;
                let mut v = 0;
                for (i, e) in set.iter().enumerate() {
                    if e.last_us < set[v].last_us {
                        v = i;
                    }
                }
                v
            }
        };
        set[j] = UdpEnt { used: true, key, last_us: ts_us };
        true
    }

    fn pend_query(&mut self, dev: u16, txid: u16, qkey: u64, fp: u32, ts_us: u64, out: &mut impl FnMut(Out)) {
        // the same (device, txid, name) again: the reference keeps the earlier event (no NX) and re-keys
        if let Some(e) = self.pend.iter_mut().find(|e| e.used && e.dev == dev && e.txid == txid && e.qkey == qkey) {
            out(Out::Dns { dev, fp: e.fp, nx: false, ts_us: e.ts_us });
            *e = Pend { used: true, dev, txid, qkey, fp, ts_us };
            return;
        }
        let j = match self.pend.iter().position(|e| !e.used) {
            Some(j) => j,
            None => {
                let mut v = 0;
                for (i, e) in self.pend.iter().enumerate() {
                    if e.ts_us < self.pend[v].ts_us {
                        v = i;
                    }
                }
                self.c.dns_evicted += 1;
                let e = self.pend[v];
                out(Out::Dns { dev: e.dev, fp: e.fp, nx: false, ts_us: e.ts_us });
                v
            }
        };
        self.pend[j] = Pend { used: true, dev, txid, qkey, fp, ts_us };
    }

    /// One frame at `ts_us`. `dev_src` / `dev_dst` = the device slots of the source / destination MAC (None = not a
    /// tracked device). Outputs go to `out` as they are decided.
    pub fn frame(&mut self, frame: &[u8], ts_us: u64, dev_src: Option<u16>, dev_dst: Option<u16>, out: &mut impl FnMut(Out)) {
        self.c.frames += 1;
        let Some(p) = parse(frame) else {
            self.c.unparsed += 1;
            return;
        };
        let mut name = [0u8; QNAME_MAX];
        if let Some(dev) = dev_src {
            out(Out::Bytes { dev, bytes: p.ip_len, ts_us });
            if p.proto == 17 && p.dport == 53 {
                if let Some((txid, _rc, false, n)) = dns_question(p.payload, &mut name) {
                    let fp = dns_fp(&name[..n]);
                    self.pend_query(dev, txid, lower_key(&name[..n]), fp, ts_us, out);
                }
                return;
            }
            if p.proto == 6 && p.flags & 0x02 != 0 && p.flags & 0x10 == 0 {
                let fp = self.peer(dev, ts_us, &p.dst, p.dport, Proto::Tcp);
                out(Out::Flow { dev, fp, ts_us });
            } else if p.proto == 17 && self.udp_new(dev, &p, ts_us) {
                let fp = self.peer(dev, ts_us, &p.dst, p.dport, Proto::Udp);
                out(Out::Flow { dev, fp, ts_us });
            }
        }
        if let Some(dev) = dev_dst {
            if p.proto == 17 && p.sport == 53 {
                if let Some((txid, rcode, true, n)) = dns_question(p.payload, &mut name) {
                    let mut rd = [0u8; QNAME_MAX];
                    let rn = registered_domain(&name[..n], &mut rd);
                    let st = peerkey::svc_state(&rd[..rn]);
                    let now_s = (ts_us / 1_000_000) as u32;
                    let mut learned = 0;
                    dns_answers(p.payload, |a| {
                        self.names.insert(dev, &a, st, now_s);
                        learned += 1;
                    });
                    self.c.names_learned += learned;
                    let qkey = lower_key(&name[..n]);
                    if let Some(e) = self.pend.iter_mut().find(|e| e.used && e.dev == dev && e.txid == txid && e.qkey == qkey) {
                        e.used = false;
                        out(Out::Dns { dev, fp: e.fp, nx: rcode == 3, ts_us: e.ts_us });
                    }
                }
            }
        }
    }

    /// Report every DNS query pending longer than `PEND_TIMEOUT_US` (no response seen) without the NX flag.
    pub fn expire(&mut self, now_us: u64, out: &mut impl FnMut(Out)) {
        for e in self.pend.iter_mut() {
            if e.used && now_us.saturating_sub(e.ts_us) >= PEND_TIMEOUT_US {
                e.used = false;
                self.c.dns_timeouts += 1;
                out(Out::Dns { dev: e.dev, fp: e.fp, nx: false, ts_us: e.ts_us });
            }
        }
    }

    /// Report every pending DNS query now (end of a capture), oldest first, without the NX flag.
    pub fn drain(&mut self, out: &mut impl FnMut(Out)) {
        loop {
            let mut v: Option<usize> = None;
            for (i, e) in self.pend.iter().enumerate() {
                if e.used && v.is_none_or(|j| e.ts_us < self.pend[j].ts_us) {
                    v = Some(i);
                }
            }
            let Some(i) = v else { return };
            let e = self.pend[i];
            self.pend[i].used = false;
            out(Out::Dns { dev: e.dev, fp: e.fp, nx: false, ts_us: e.ts_us });
        }
    }

    /// A device slot was reassigned: forget its pending queries and its UDP flows' idle clocks are left to age out.
    pub fn forget_dev(&mut self, dev: u16) {
        for e in self.pend.iter_mut() {
            if e.dev == dev {
                e.used = false;
            }
        }
    }
}

impl Default for Dp {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rd(s: &str) -> &'static str {
        let mut o = [0u8; QNAME_MAX];
        let n = registered_domain(s.as_bytes(), &mut o);
        let v: &'static mut [u8] = std::boxed::Box::leak(o[..n].to_vec().into_boxed_slice());
        core::str::from_utf8(v).unwrap()
    }
    extern crate std;

    #[test]
    fn registered_domain_rule() {
        assert_eq!(rd("www.Example.COM"), "example.com");
        assert_eq!(rd("a.b.co.uk"), "b.co.uk");
        assert_eq!(rd("example.com"), "example.com");
        assert_eq!(rd("localhost"), "localhost");
        assert_eq!(rd("x.y.z.example.org."), "example.org");
        assert_eq!(rd("..a..b.com"), "a.b.com"); // "b" has <= 3 chars -> three labels
        assert_eq!(rd("api.svc.io"), "api.svc.io"); // "svc" has 3 chars -> three labels
    }
}
