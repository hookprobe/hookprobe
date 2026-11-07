//! `block` = REJECT (task #26): the answer a blocked sender gets back, so it fails fast instead of
//! timing out. Pure (no MMIO), built on every target so QEMU tests it.
//! - TCP -> RST (RFC 9293 §3.10.7.1): for a segment carrying ACK, RST with seq = its ack; otherwise
//!   RST+ACK with seq 0 and ack = its seq + its length (+1 for SYN, +1 for FIN) — the form the
//!   sender's stack accepts. The RST comes FROM the destination address the sender tried.
//! - anything else -> ICMP Destination Unreachable code 13 "communication administratively prohibited"
//!   (RFC 1812 §5.2.7.1) / ICMPv6 type 1 code 1 (RFC 4443 §3.1), FROM the router's address, quoting
//!   the offending packet (IPv4: header + 8 bytes; IPv6: as much as fits in 1280 bytes).
//! Never answer an ICMP error or a RST (no error storms), nor a non-unicast destination.

use crate::ip6::l4_csum;
use hal::inet_csum;

fn csum_ip4(h: &mut [u8]) {
    h[10] = 0;
    h[11] = 0;
    let c = inet_csum(h, 0);
    h[10..12].copy_from_slice(&c.to_be_bytes());
}

fn pseudo4(s: &[u8], d: &[u8], proto: u8, len: usize) -> u32 {
    let mut x = 0u32;
    for k in (0..4).step_by(2) {
        x += u16::from_be_bytes([s[k], s[k + 1]]) as u32 + u16::from_be_bytes([d[k], d[k + 1]]) as u32;
    }
    x + proto as u32 + len as u32
}

/// Build the TCP RST answering `tcp` (the offending segment's TCP header + payload) into `o`.
fn rst(tcp: &[u8], payload_len: usize, o: &mut [u8]) {
    let flags = tcp[13];
    let seq = u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]);
    let ack = u32::from_be_bytes([tcp[8], tcp[9], tcp[10], tcp[11]]);
    o[..20].fill(0);
    o[0..2].copy_from_slice(&tcp[2..4]);
    o[2..4].copy_from_slice(&tcp[0..2]);
    if flags & 0x10 != 0 {
        o[4..8].copy_from_slice(&ack.to_be_bytes());
        o[13] = 0x04; // RST
    } else {
        let mut a = seq.wrapping_add(payload_len as u32);
        if flags & 0x02 != 0 {
            a = a.wrapping_add(1);
        }
        if flags & 0x01 != 0 {
            a = a.wrapping_add(1);
        }
        o[8..12].copy_from_slice(&a.to_be_bytes());
        o[13] = 0x14; // RST+ACK
    }
    o[12] = 5 << 4;
}

/// Reject for an untagged Ethernet/IPv4 frame `f`. `router` = our address on that interface (the ICMP
/// source), `mac` = our MAC. Returns the Ethernet frame length in `out`, or None (not answered).
pub fn reject4(f: &[u8], router: &[u8; 4], mac: &[u8; 6], out: &mut [u8]) -> Option<usize> {
    if f.len() < 34 || f[12] != 0x08 || f[13] != 0x00 || f[14] >> 4 != 4 || f[0] & 1 != 0 {
        return None;
    }
    let ihl = ((f[14] & 0x0f) as usize) * 4;
    let tot = (u16::from_be_bytes([f[16], f[17]]) as usize).min(f.len() - 14);
    if ihl < 20 || tot < ihl || f[30] >= 224 || f[30..34] == [255; 4] {
        return None;
    }
    let ip = &f[14..14 + tot];
    let proto = ip[9];
    out[0..6].copy_from_slice(&f[6..12]);
    out[6..12].copy_from_slice(mac);
    out[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
    let h = 14;
    if proto == 6 && tot >= ihl + 20 {
        let tcp = &ip[ihl..];
        if tcp[13] & 0x04 != 0 {
            return None; // never answer a RST
        }
        let doff = ((tcp[12] >> 4) as usize) * 4;
        let plen = tot.saturating_sub(ihl + doff);
        let n = 20 + 20;
        out[h..h + 20].copy_from_slice(&[0x45, 0, 0, n as u8, 0, 0, 0x40, 0, 64, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        out[h + 12..h + 16].copy_from_slice(&ip[16..20]); // from the address the sender tried
        out[h + 16..h + 20].copy_from_slice(&ip[12..16]);
        csum_ip4(&mut out[h..h + 20]);
        rst(tcp, plen, &mut out[h + 20..h + 40]);
        let c = inet_csum(&out[h + 20..h + 40], pseudo4(&ip[16..20], &ip[12..16], 6, 20));
        out[h + 36..h + 38].copy_from_slice(&c.to_be_bytes());
        return Some(h + n);
    }
    if proto == 1 && tot >= ihl + 1 && !matches!(ip[ihl], 0 | 8 | 13 | 15 | 17) {
        return None; // never answer an ICMP error with an ICMP error
    }
    let q = (ihl + 8).min(tot);
    let n = 20 + 8 + q;
    out[h..h + 20].copy_from_slice(&[0x45, 0, 0, 0, 0, 0, 0x40, 0, 64, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    out[h + 2..h + 4].copy_from_slice(&(n as u16).to_be_bytes());
    out[h + 12..h + 16].copy_from_slice(router);
    out[h + 16..h + 20].copy_from_slice(&ip[12..16]);
    csum_ip4(&mut out[h..h + 20]);
    let ic = h + 20;
    out[ic..ic + 8].copy_from_slice(&[3, 13, 0, 0, 0, 0, 0, 0]);
    out[ic + 8..ic + 8 + q].copy_from_slice(&ip[..q]);
    let c = inet_csum(&out[ic..ic + 8 + q], 0);
    out[ic + 2..ic + 4].copy_from_slice(&c.to_be_bytes());
    Some(h + n)
}

/// Reject for an untagged Ethernet/IPv6 frame `f` (no extension headers). `router` = our address on
/// that interface (the ICMPv6 source).
pub fn reject6(f: &[u8], router: &[u8; 16], mac: &[u8; 6], out: &mut [u8]) -> Option<usize> {
    if f.len() < 54 || f[12] != 0x86 || f[13] != 0xdd || f[14] >> 4 != 6 || f[0] & 1 != 0 || f[38] == 0xff {
        return None;
    }
    let plen = (u16::from_be_bytes([f[18], f[19]]) as usize).min(f.len() - 54);
    let ip = &f[14..54 + plen];
    let nh = ip[6];
    let (mut s, mut d) = ([0u8; 16], [0u8; 16]);
    s.copy_from_slice(&ip[8..24]);
    d.copy_from_slice(&ip[24..40]);
    out[0..6].copy_from_slice(&f[6..12]);
    out[6..12].copy_from_slice(mac);
    out[12..14].copy_from_slice(&0x86ddu16.to_be_bytes());
    let h = 14;
    let hdr = |o: &mut [u8], src: &[u8; 16], dst: &[u8; 16], nh: u8, len: usize| {
        o[0..4].copy_from_slice(&[0x60, 0, 0, 0]);
        o[4..6].copy_from_slice(&(len as u16).to_be_bytes());
        o[6] = nh;
        o[7] = 64;
        o[8..24].copy_from_slice(src);
        o[24..40].copy_from_slice(dst);
    };
    if nh == 6 && plen >= 20 {
        let tcp = &ip[40..];
        if tcp[13] & 0x04 != 0 {
            return None;
        }
        let doff = ((tcp[12] >> 4) as usize) * 4;
        hdr(&mut out[h..h + 40], &d, &s, 6, 20);
        rst(tcp, plen.saturating_sub(doff), &mut out[h + 40..h + 60]);
        let c = l4_csum(&d, &s, 6, &out[h + 40..h + 60]);
        out[h + 56..h + 58].copy_from_slice(&c.to_be_bytes());
        return Some(h + 60);
    }
    if nh == 58 && plen >= 1 && ip[40] < 128 {
        return None; // never answer an ICMPv6 error
    }
    let q = ip.len().min(1280 - 48);
    hdr(&mut out[h..h + 40], router, &s, 58, 8 + q);
    let ic = h + 40;
    out[ic..ic + 8].copy_from_slice(&[1, 1, 0, 0, 0, 0, 0, 0]);
    out[ic + 8..ic + 8 + q].copy_from_slice(&ip[..q]);
    let c = l4_csum(router, &s, 58, &out[ic..ic + 8 + q]);
    out[ic + 2..ic + 4].copy_from_slice(&c.to_be_bytes());
    Some(ic + 8 + q)
}
