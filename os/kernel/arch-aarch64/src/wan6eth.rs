//! IPv6 on an Ethernet WAN (DHCP / static uplink) — parity G17, operator decision 2026-11-08.
//!
//! PPPoE carries IPv6 inside the session (ip6.rs builders + pppoe encap). On an Ethernet WAN the same
//! RS / RA / DHCPv6-PD exchange needs Ethernet framing to the right multicast MACs, and the router must be
//! able to reach us: we answer Neighbor Solicitations and echo requests for our link-local address (RFC
//! 4861 §7.2.4 / RFC 4443). Pure helpers here (QEMU-tested, `selftest`); the uplink drives them.

use crate::ip6::{l4_csum, link_local};

/// 33:33:00:00:00:02 — all-routers (RS).
pub const MAC_ALL_ROUTERS: [u8; 6] = [0x33, 0x33, 0, 0, 0, 2];
/// 33:33:00:01:00:02 — All_DHCP_Relay_Agents_and_Servers (DHCPv6 Solicit / Request / Renew).
pub const MAC_ALL_DHCP: [u8; 6] = [0x33, 0x33, 0, 1, 0, 2];
/// ff02::1 — all-nodes.
const ALL_NODES: [u8; 16] = [0xff, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];

/// Ethernet-frame a bare IPv6 packet. Returns the frame length (0 if `out` is too small).
pub fn eth6(dst: &[u8; 6], src: &[u8; 6], ip6: &[u8], out: &mut [u8]) -> usize {
    let n = 14 + ip6.len();
    if out.len() < n {
        return 0;
    }
    out[0..6].copy_from_slice(dst);
    out[6..12].copy_from_slice(src);
    out[12..14].copy_from_slice(&0x86ddu16.to_be_bytes());
    out[14..n].copy_from_slice(ip6);
    n
}

/// The multicast MAC for an IPv6 multicast destination (33:33 + low 32 bits), or None for unicast.
pub fn mcast_mac(dst: &[u8; 16]) -> Option<[u8; 6]> {
    (dst[0] == 0xff).then(|| [0x33, 0x33, dst[12], dst[13], dst[14], dst[15]])
}

fn addr(b: &[u8], o: usize) -> [u8; 16] {
    let mut a = [0u8; 16];
    a.copy_from_slice(&b[o..o + 16]);
    a
}

fn ip6_hdr(out: &mut [u8], src: &[u8; 16], dst: &[u8; 16], plen: usize, hop: u8) {
    out[0..4].copy_from_slice(&[0x60, 0, 0, 0]);
    out[4..6].copy_from_slice(&(plen as u16).to_be_bytes());
    out[6] = 58;
    out[7] = hop;
    out[8..24].copy_from_slice(src);
    out[24..40].copy_from_slice(dst);
}

/// What a WAN-side IPv6 packet addressed to us needs.
#[derive(Debug, PartialEq, Eq)]
pub enum Answer {
    /// Reply with this bare IPv6 packet (length) to this destination MAC.
    Reply(usize, [u8; 6]),
    /// Not ours to answer.
    None,
}

/// Answer a Neighbor Solicitation for `ours` (our link-local) with a solicited Neighbor Advertisement
/// carrying our MAC, or an echo request to `ours` with an echo reply. `src_mac` is the frame's source
/// (the asker). `ip` is the bare IPv6 packet. Checks hop limit 255 for ND and the ICMPv6 checksum.
pub fn answer(ip: &[u8], src_mac: &[u8; 6], ours: &[u8; 16], our_mac: &[u8; 6], out: &mut [u8]) -> Answer {
    if ip.len() < 48 || ip[0] >> 4 != 6 || ip[6] != 58 || out.len() < 40 + 32 {
        return Answer::None;
    }
    let plen = u16::from_be_bytes([ip[4], ip[5]]) as usize;
    if 40 + plen > ip.len() || plen < 8 {
        return Answer::None;
    }
    let (src, dst) = (addr(ip, 8), addr(ip, 24));
    let icmp = &ip[40..40 + plen];
    if l4_csum(&src, &dst, 58, icmp) != 0 {
        return Answer::None;
    }
    match icmp[0] {
        // Neighbor Solicitation (RFC 4861 §4.3): hop 255, code 0, target = ours.
        135 if ip[7] == 255 && icmp[1] == 0 && plen >= 24 && addr(icmp, 8) == *ours => {
            let dad = src == [0u8; 16];
            let to = if dad { ALL_NODES } else { src };
            let body = 32; // NA (24) + target link-layer address option (8)
            ip6_hdr(out, ours, &to, body, 255);
            let na = &mut out[40..40 + body];
            na.fill(0);
            na[0] = 136;
            na[4] = if dad { 0x20 } else { 0x60 }; // O (override), + S (solicited) unless answering DAD
            na[8..24].copy_from_slice(ours);
            na[24] = 2; // TLLAO
            na[25] = 1;
            na[26..32].copy_from_slice(our_mac);
            let c = l4_csum(ours, &to, 58, &out[40..40 + body]);
            out[42..44].copy_from_slice(&c.to_be_bytes());
            let dmac = if dad { [0x33, 0x33, 0, 0, 0, 1] } else { *src_mac };
            Answer::Reply(40 + body, dmac)
        }
        // Echo request to our link-local (lets the router / an operator check the WAN v6 path).
        128 if dst == *ours && icmp[1] == 0 && 40 + plen <= out.len() => {
            ip6_hdr(out, ours, &src, plen, 64);
            out[40..40 + plen].copy_from_slice(icmp);
            out[40] = 129;
            out[42..44].fill(0);
            let c = l4_csum(ours, &src, 58, &out[40..40 + plen]);
            out[42..44].copy_from_slice(&c.to_be_bytes());
            Answer::Reply(40 + plen, *src_mac)
        }
        _ => Answer::None,
    }
}

/// `[P-wan6eth]`: framing, multicast MACs, NS -> NA (incl. DAD), echo, and refusals.
pub fn selftest() -> bool {
    let mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x02];
    let iid = crate::ip6::eui64(&mac);
    let ll = link_local(&iid);
    let peer_mac = [0x00, 0xd0, 0xb4, 0x03, 0xb7, 0x11];
    let peer_ll: [u8; 16] = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x02, 0xd0, 0xb4, 0xff, 0xfe, 0x03, 0xb7, 0x11];
    // RS framed to all-routers
    let mut rs = [0u8; 64];
    let n = crate::ip6::build_rs(&iid, &mut rs);
    let mut f = [0u8; 128];
    let k = eth6(&MAC_ALL_ROUTERS, &mac, &rs[..n], &mut f);
    let framed = k == 14 + n && f[0..6] == MAC_ALL_ROUTERS && f[12..14] == [0x86, 0xdd] && f[14..14 + n] == rs[..n];
    let mm = mcast_mac(&crate::ip6::ALL_DHCP) == Some(MAC_ALL_DHCP) && mcast_mac(&ll).is_none();
    // NS from the router for our link-local
    let mut ns = [0u8; 72];
    let sol = { let mut a = [0xff, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xff, 0, 0, 0]; a[13..16].copy_from_slice(&ll[13..16]); a };
    ip6_hdr(&mut ns, &peer_ll, &sol, 32, 255);
    ns[40] = 135;
    ns[48..64].copy_from_slice(&ll);
    ns[64] = 1;
    ns[65] = 1;
    ns[66..72].copy_from_slice(&peer_mac);
    let c = l4_csum(&peer_ll, &sol, 58, &ns[40..72]);
    ns[42..44].copy_from_slice(&c.to_be_bytes());
    let mut out = [0u8; 256];
    let na_ok = match answer(&ns, &peer_mac, &ll, &mac, &mut out) {
        Answer::Reply(m, d) => m == 72 && d == peer_mac && out[40] == 136 && out[44] == 0x60 && out[48..64] == ll && out[66..72] == mac
            && out[24..40] == peer_ll && l4_csum(&ll, &peer_ll, 58, &out[40..72]) == 0,
        Answer::None => false,
    };
    // the same NS with hop limit 64 (off-link forgery) is refused; a NS for another target is not ours
    let mut bad = ns;
    bad[7] = 64;
    let hop_refused = answer(&bad, &peer_mac, &ll, &mac, &mut out) == Answer::None;
    let mut other = ns;
    other[63] ^= 1;
    let c2 = { other[42] = 0; other[43] = 0; l4_csum(&peer_ll, &sol, 58, &other[40..72]) };
    other[42..44].copy_from_slice(&c2.to_be_bytes());
    let other_ignored = answer(&other, &peer_mac, &ll, &mac, &mut out) == Answer::None;
    // DAD (unspecified source) -> NA to all-nodes without S
    let mut dad = ns;
    dad[8..24].fill(0);
    dad[42] = 0;
    dad[43] = 0;
    let c3 = l4_csum(&[0; 16], &sol, 58, &dad[40..72]);
    dad[42..44].copy_from_slice(&c3.to_be_bytes());
    let dad_ok = matches!(answer(&dad, &peer_mac, &ll, &mac, &mut out), Answer::Reply(_, d) if d == [0x33, 0x33, 0, 0, 0, 1] && out[44] == 0x20);
    // echo request to our link-local -> echo reply with a valid checksum
    let mut er = [0u8; 56];
    ip6_hdr(&mut er, &peer_ll, &ll, 16, 64);
    er[40] = 128;
    er[44..56].copy_from_slice(b"\x12\x34\x00\x01heqk-v6!");
    let c4 = l4_csum(&peer_ll, &ll, 58, &er[40..56]);
    er[42..44].copy_from_slice(&c4.to_be_bytes());
    let echo_ok = matches!(answer(&er, &peer_mac, &ll, &mac, &mut out), Answer::Reply(m, d) if m == 56 && d == peer_mac && out[40] == 129 && out[48..56] == er[48..56] && l4_csum(&ll, &peer_ll, 58, &out[40..56]) == 0);
    let mut corrupt = er;
    corrupt[50] ^= 0xff;
    let csum_refused = answer(&corrupt, &peer_mac, &ll, &mac, &mut out) == Answer::None;
    let pass = framed && mm && na_ok && hop_refused && other_ignored && dad_ok && echo_ok && csum_refused;
    crate::_print(format_args!(
        " [P-wan6eth] {} — G17 IPv6 on an Ethernet WAN: RS framed to 33:33::2={} multicast MACs={} | NS for our link-local -> solicited NA with our MAC={} (hop!=255 refused={} other target ignored={} DAD -> all-nodes={}) | echo to our link-local -> reply={} bad checksum refused={}\n",
        if pass { "PASS" } else { "FAIL" }, framed, mm, na_ok, hop_refused, other_ignored, dad_ok, echo_ok, csum_refused
    ));
    pass
}
