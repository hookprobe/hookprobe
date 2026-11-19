// SPDX-License-Identifier: AGPL-3.0-only
//! L-02 (operator 2026-11-17): a minimal mDNS responder for the device's OWN names (`heqk.local`, the unit-unique
//! `<label>.heqk.local`), aligned with the legacy fortress's Avahi setup: address records only (IPv4 — legacy ran
//! `use-ipv6=no`), no service publishing, no reflector. Pure logic, host-tested; the kernel decides where it runs
//! (the AP and the management VLAN, never the WAN) and who it answers.
//!
//! [`answer`] reads one mDNS query (RFC 6762) and, when a question asks A or ANY for one of `names`, builds the
//! response. [`frame4`] wraps it in Ethernet / IPv4 / UDP.

pub const PORT: u16 = 5353;
pub const GROUP4: [u8; 4] = [224, 0, 0, 251];
pub const GROUP4_MAC: [u8; 6] = [0x01, 0x00, 0x5e, 0x00, 0x00, 0xfb];
/// TTL of our address record (RFC 6762 recommends 120 s for records with host names).
pub const TTL: u32 = 120;
const T_A: u16 = 1;
const T_ANY: u16 = 255;

/// How the reply goes back.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dest {
    /// To the group (224.0.0.251:5353).
    Multicast,
    /// To the querier (a QU question, RFC 6762 §5.4).
    Unicast,
    /// A legacy one-shot resolver (source port != 5353, §6.7): unicast to its port, same id, question echoed.
    Legacy,
}

/// Read a (possibly compressed) name at `off` into `out` as lowercase dotted text; the offset after the name in
/// the original position. At most 8 pointer hops and 255 bytes (no loops, no overruns).
fn read_name(p: &[u8], mut off: usize, out: &mut [u8; 256]) -> Option<(usize, usize)> {
    let mut n = 0usize;
    let mut after: Option<usize> = None;
    let mut hops = 0;
    loop {
        let l = *p.get(off)? as usize;
        if l == 0 {
            off += 1;
            break;
        }
        if l & 0xc0 == 0xc0 {
            let ptr = ((l & 0x3f) << 8) | *p.get(off + 1)? as usize;
            if after.is_none() {
                after = Some(off + 2);
            }
            hops += 1;
            if hops > 8 || ptr >= off {
                return None; // forward / self pointers: refuse
            }
            off = ptr;
            continue;
        }
        if l > 63 {
            return None;
        }
        let lab = p.get(off + 1..off + 1 + l)?;
        if n + l + 1 > out.len() {
            return None;
        }
        if n > 0 {
            out[n] = b'.';
            n += 1;
        }
        for &c in lab {
            out[n] = c.to_ascii_lowercase();
            n += 1;
        }
        off += 1 + l;
    }
    Some((n, after.unwrap_or(off)))
}

fn write_name(name: &[u8], out: &mut [u8], mut o: usize) -> Option<usize> {
    for lab in name.split(|&c| c == b'.') {
        if lab.is_empty() || lab.len() > 63 {
            return None;
        }
        *out.get_mut(o)? = lab.len() as u8;
        out.get_mut(o + 1..o + 1 + lab.len())?.copy_from_slice(lab);
        o += 1 + lab.len();
    }
    *out.get_mut(o)? = 0;
    Some(o + 1)
}

/// One mDNS query in `q` (the UDP payload, from source port `sport`): the response for every A / ANY question
/// about one of `names` (lowercase, dotted) with address `ip`, written to `out`. None = nothing to answer
/// (not a query, nothing of ours asked, malformed).
pub fn answer(q: &[u8], sport: u16, names: &[&[u8]], ip: [u8; 4], out: &mut [u8]) -> Option<(usize, Dest)> {
    if q.len() < 12 || q[2] & 0x80 != 0 || q[2] & 0x78 != 0 {
        return None; // a response, or not a standard query
    }
    let qd = u16::from_be_bytes([q[4], q[5]]) as usize;
    if qd == 0 || qd > 16 {
        return None;
    }
    let legacy = sport != PORT;
    let mut off = 12;
    let mut hits: [usize; 4] = [usize::MAX; 4];
    let mut nh = 0;
    let mut all_qu = true;
    let mut buf = [0u8; 256];
    for _ in 0..qd {
        let (n, next) = read_name(q, off, &mut buf)?;
        let qt = u16::from_be_bytes([*q.get(next)?, *q.get(next + 1)?]);
        let qc = u16::from_be_bytes([*q.get(next + 2)?, *q.get(next + 3)?]);
        off = next + 4;
        if qc & 0x7fff != 1 || !(qt == T_A || qt == T_ANY) {
            continue;
        }
        if let Some(i) = names.iter().position(|&m| m == &buf[..n]) {
            if !hits[..nh].contains(&i) && nh < hits.len() {
                hits[nh] = i;
                nh += 1;
                all_qu &= qc & 0x8000 != 0;
            }
        }
    }
    if nh == 0 {
        return None;
    }
    // header: id (legacy: echo; else 0), flags = response + authoritative, qd = legacy ? 1 : 0, an = nh
    let id = if legacy { [q[0], q[1]] } else { [0, 0] };
    out.get_mut(..12)?.copy_from_slice(&[id[0], id[1], 0x84, 0x00, 0, if legacy { 1 } else { 0 }, 0, nh as u8, 0, 0, 0, 0]);
    let mut o = 12;
    if legacy {
        let n0 = names[hits[0]];
        o = write_name(n0, out, o)?;
        out.get_mut(o..o + 4)?.copy_from_slice(&[0, 1, 0, 1]);
        o += 4;
    }
    for &i in &hits[..nh] {
        o = write_name(names[i], out, o)?;
        // type A, class IN with the cache-flush bit (unique record; not for legacy resolvers, §10.2), TTL, rdata
        let class: u16 = if legacy { 1 } else { 0x8001 };
        let ttl = if legacy { TTL.min(10) } else { TTL };
        let rec = [0, 1, (class >> 8) as u8, class as u8];
        out.get_mut(o..o + 4)?.copy_from_slice(&rec);
        out.get_mut(o + 4..o + 8)?.copy_from_slice(&ttl.to_be_bytes());
        out.get_mut(o + 8..o + 10)?.copy_from_slice(&4u16.to_be_bytes());
        out.get_mut(o + 10..o + 14)?.copy_from_slice(&ip);
        o += 14;
    }
    let dest = if legacy { Dest::Legacy } else if all_qu { Dest::Unicast } else { Dest::Multicast };
    Some((o, dest))
}

/// Ethernet + IPv4 (TTL 255, as RFC 6762 §11 requires) + UDP around `payload`; the frame length.
#[allow(clippy::too_many_arguments)]
pub fn frame4(smac: &[u8; 6], dmac: &[u8; 6], sip: [u8; 4], dip: [u8; 4], sport: u16, dport: u16, payload: &[u8], out: &mut [u8]) -> Option<usize> {
    let ul = 8 + payload.len();
    let il = 20 + ul;
    let fl = 14 + il;
    let f = out.get_mut(..fl)?;
    f[0..6].copy_from_slice(dmac);
    f[6..12].copy_from_slice(smac);
    f[12..14].copy_from_slice(&[0x08, 0x00]);
    let ip = &mut f[14..34];
    ip.copy_from_slice(&[0x45, 0, (il >> 8) as u8, il as u8, 0, 0, 0x40, 0, 255, 17, 0, 0, sip[0], sip[1], sip[2], sip[3], dip[0], dip[1], dip[2], dip[3]]);
    let c = crate::inet_csum(ip, 0);
    ip[10..12].copy_from_slice(&c.to_be_bytes());
    let u = &mut f[34..];
    u[0..2].copy_from_slice(&sport.to_be_bytes());
    u[2..4].copy_from_slice(&dport.to_be_bytes());
    u[4..6].copy_from_slice(&(ul as u16).to_be_bytes());
    u[6..8].copy_from_slice(&[0, 0]);
    u[8..].copy_from_slice(payload);
    let ph = crate::pseudo_sum(&sip, &dip, 17, ul as u16);
    let mut c = crate::inet_csum(&f[34..], ph);
    if c == 0 {
        c = 0xffff;
    }
    f[40..42].copy_from_slice(&c.to_be_bytes());
    Some(fl)
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;
    use std::vec::Vec;

    fn query(id: u16, qs: &[(&str, u16, bool)]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&id.to_be_bytes());
        v.extend_from_slice(&[0, 0, 0, qs.len() as u8, 0, 0, 0, 0, 0, 0]);
        for (n, t, qu) in qs {
            for l in n.split('.') {
                v.push(l.len() as u8);
                v.extend_from_slice(l.as_bytes());
            }
            v.push(0);
            v.extend_from_slice(&t.to_be_bytes());
            v.extend_from_slice(&(if *qu { 0x8001u16 } else { 1 }).to_be_bytes());
        }
        v
    }
    const NAMES: [&[u8]; 2] = [b"heqk.local", b"r3q1.heqk.local"];
    const IP: [u8; 4] = [10, 99, 0, 1];

    #[test]
    fn answers_our_names_only_a_and_any() {
        let mut o = [0u8; 512];
        let (n, d) = answer(&query(7, &[("HEQK.local", 1, false)]), 5353, &NAMES, IP, &mut o).unwrap();
        assert_eq!(d, Dest::Multicast);
        assert_eq!(&o[..4], &[0, 0, 0x84, 0], "id 0, response + authoritative");
        assert_eq!(o[7], 1, "one answer");
        assert_eq!(&o[n - 4..n], &IP);
        assert_eq!(&o[n - 14..n - 10], &[0, 1, 0x80, 1], "type A, class IN + cache-flush");
        // the unit-unique name, asked QU -> unicast
        let (_, d) = answer(&query(0, &[("r3q1.heqk.local", 255, true)]), 5353, &NAMES, IP, &mut o).unwrap();
        assert_eq!(d, Dest::Unicast);
        // not ours / not A: silent
        assert!(answer(&query(0, &[("printer.local", 1, false)]), 5353, &NAMES, IP, &mut o).is_none());
        assert!(answer(&query(0, &[("heqk.local", 28, false)]), 5353, &NAMES, IP, &mut o).is_none(), "AAAA: IPv4 only, as legacy");
        assert!(answer(&query(0, &[("_http._tcp.local", 12, false)]), 5353, &NAMES, IP, &mut o).is_none(), "no service publishing");
    }

    #[test]
    fn legacy_resolver_gets_its_id_and_the_question() {
        let mut o = [0u8; 512];
        let (n, d) = answer(&query(0x1234, &[("heqk.local", 1, false)]), 40000, &NAMES, IP, &mut o).unwrap();
        assert_eq!(d, Dest::Legacy);
        assert_eq!(&o[..2], &[0x12, 0x34]);
        assert_eq!((o[5], o[7]), (1, 1), "question echoed, one answer");
        assert_eq!(&o[n - 14..n - 10], &[0, 1, 0, 1], "no cache-flush bit for legacy");
    }

    #[test]
    fn hostile_input_is_refused() {
        let mut o = [0u8; 512];
        let mut r = query(0, &[("heqk.local", 1, false)]);
        r[2] = 0x84; // a response, not a query
        assert!(answer(&r, 5353, &NAMES, IP, &mut o).is_none());
        // a compression loop
        let mut l = query(0, &[("x", 1, false)]);
        l[12] = 0xc0;
        l[13] = 12;
        assert!(answer(&l, 5353, &NAMES, IP, &mut o).is_none());
        // truncated
        let t = query(0, &[("heqk.local", 1, false)]);
        assert!(answer(&t[..t.len() - 3], 5353, &NAMES, IP, &mut o).is_none());
        assert!(answer(&[0u8; 5], 5353, &NAMES, IP, &mut o).is_none());
    }

    #[test]
    fn frame_has_ttl_255_and_valid_checksums() {
        let mut o = [0u8; 512];
        let (n, _) = answer(&query(0, &[("heqk.local", 1, false)]), 5353, &NAMES, IP, &mut o).unwrap();
        let mut f = [0u8; 600];
        let k = frame4(&[2, 0, 0, 0, 0, 1], &GROUP4_MAC, IP, GROUP4, PORT, PORT, &o[..n], &mut f).unwrap();
        assert_eq!(f[22], 255);
        assert_eq!(crate::inet_csum(&f[14..34], 0), 0, "IPv4 header checksum");
        let ph = crate::pseudo_sum(&IP, &GROUP4, 17, (k - 34) as u16);
        assert_eq!(crate::inet_csum(&f[34..k], ph), 0, "UDP checksum");
    }
}
