//! IPv6 on the PPPoE WAN — pure builders/parsers (no MMIO, built on every target so QEMU tests it).
//!
//! What the WAN v6 PROBE needs to learn what the ISP provides, nothing more:
//! - ICMPv6 Router Solicitation / Router Advertisement (RFC 4861 §4.1/§4.2, Prefix Information
//!   §4.6.2, MTU §4.6.4) — the WAN /64 and the upstream router;
//! - DHCPv6 prefix delegation (RFC 8415): Solicit (+ Rapid Commit) -> Advertise -> Request -> Reply
//!   with IA_PD / IAPREFIX — the prefix the LAN would be numbered from, and the DNS servers.
//! Packets here are bare IPv6 (no link header): on PPP the session carries them as protocol 0x0057.

/// ff02::2 — all routers.
pub const ALL_ROUTERS: [u8; 16] = [0xff, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
/// ff02::1:2 — all DHCP relay agents and servers.
pub const ALL_DHCP: [u8; 16] = [0xff, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 2];

pub const DHCP6_SOLICIT: u8 = 1;
pub const DHCP6_ADVERTISE: u8 = 2;
pub const DHCP6_REQUEST: u8 = 3;
pub const DHCP6_REPLY: u8 = 7;

/// Modified EUI-64 interface identifier from a MAC (RFC 4291 App. A).
pub fn eui64(mac: &[u8; 6]) -> [u8; 8] {
    [mac[0] ^ 0x02, mac[1], mac[2], 0xff, 0xfe, mac[3], mac[4], mac[5]]
}

/// fe80::<iid>
pub fn link_local(iid: &[u8; 8]) -> [u8; 16] {
    let mut a = [0u8; 16];
    a[0] = 0xfe;
    a[1] = 0x80;
    a[8..16].copy_from_slice(iid);
    a
}

fn sum16(b: &[u8], mut s: u32) -> u32 {
    let mut i = 0;
    while i + 1 < b.len() {
        s += u16::from_be_bytes([b[i], b[i + 1]]) as u32;
        i += 2;
    }
    if i < b.len() {
        s += (b[i] as u32) << 8;
    }
    s
}

fn fold(mut s: u32) -> u16 {
    while s >> 16 != 0 {
        s = (s & 0xffff) + (s >> 16);
    }
    !(s as u16)
}

/// Upper-layer checksum over the IPv6 pseudo-header (RFC 8200 §8.1) + `l4` (checksum field zeroed
/// by the caller when building; when verifying, a correct packet folds to 0).
pub fn l4_csum(src: &[u8; 16], dst: &[u8; 16], nh: u8, l4: &[u8]) -> u16 {
    let mut s = sum16(src, 0);
    s = sum16(dst, s);
    s += (l4.len() as u32 >> 16) + (l4.len() as u32 & 0xffff);
    s += nh as u32;
    fold(sum16(l4, s))
}

fn hdr(out: &mut [u8], src: &[u8; 16], dst: &[u8; 16], nh: u8, plen: usize, hop: u8) {
    out[0] = 0x60;
    out[1] = 0;
    out[2] = 0;
    out[3] = 0;
    out[4..6].copy_from_slice(&(plen as u16).to_be_bytes());
    out[6] = nh;
    out[7] = hop;
    out[8..24].copy_from_slice(src);
    out[24..40].copy_from_slice(dst);
}

fn addr(b: &[u8], o: usize) -> [u8; 16] {
    let mut a = [0u8; 16];
    a.copy_from_slice(&b[o..o + 16]);
    a
}

/// Router Solicitation from fe80::<iid> to ff02::2 (hop limit 255; no source-link-layer option on
/// a point-to-point PPP link). Returns the IPv6 packet length (48).
pub fn build_rs(iid: &[u8; 8], out: &mut [u8]) -> usize {
    let src = link_local(iid);
    hdr(out, &src, &ALL_ROUTERS, 58, 8, 255);
    let icmp = &mut out[40..48];
    icmp.copy_from_slice(&[133, 0, 0, 0, 0, 0, 0, 0]);
    let c = l4_csum(&src, &ALL_ROUTERS, 58, &out[40..48]);
    out[42..44].copy_from_slice(&c.to_be_bytes());
    48
}

/// What one Router Advertisement told us.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Ra {
    pub router: [u8; 16],
    pub lifetime: u16,
    pub managed: bool, // M: addresses via DHCPv6
    pub other: bool,   // O: other config via DHCPv6
    pub has_prefix: bool,
    pub prefix: [u8; 16],
    pub plen: u8,
    pub autonomous: bool, // A: SLAAC allowed on this prefix
    pub valid: u32,
    pub preferred: u32,
    pub mtu: u32,
}

/// Parse a Router Advertisement (bare IPv6). Requires next header ICMPv6 (no extension headers),
/// hop limit 255 (RFC 4861 §6.1.2), a link-local source and a valid checksum.
pub fn parse_ra(ip: &[u8]) -> Option<Ra> {
    if ip.len() < 40 + 16 || ip[0] >> 4 != 6 || ip[6] != 58 || ip[7] != 255 {
        return None;
    }
    let plen = (u16::from_be_bytes([ip[4], ip[5]]) as usize).min(ip.len() - 40);
    let icmp = &ip[40..40 + plen];
    if icmp.len() < 16 || icmp[0] != 134 || icmp[1] != 0 {
        return None;
    }
    let (src, dst) = (addr(ip, 8), addr(ip, 24));
    if src[0] != 0xfe || src[1] & 0xc0 != 0x80 || l4_csum(&src, &dst, 58, icmp) != 0 {
        return None;
    }
    let mut ra = Ra { router: src, lifetime: u16::from_be_bytes([icmp[6], icmp[7]]), managed: icmp[5] & 0x80 != 0, other: icmp[5] & 0x40 != 0, ..Ra::default() };
    let mut o = 16;
    while o + 2 <= icmp.len() {
        let (t, l) = (icmp[o], icmp[o + 1] as usize * 8);
        if l == 0 || o + l > icmp.len() {
            return None; // RFC 4861 §4.6: a zero-length option is invalid -> discard the RA
        }
        let opt = &icmp[o..o + l];
        match t {
            3 if l == 32 && !ra.has_prefix => {
                ra.has_prefix = true;
                ra.plen = opt[2];
                ra.autonomous = opt[3] & 0x40 != 0;
                ra.valid = u32::from_be_bytes([opt[4], opt[5], opt[6], opt[7]]);
                ra.preferred = u32::from_be_bytes([opt[8], opt[9], opt[10], opt[11]]);
                ra.prefix = addr(opt, 16);
            }
            5 if l == 8 => ra.mtu = u32::from_be_bytes([opt[4], opt[5], opt[6], opt[7]]),
            _ => {}
        }
        o += l;
    }
    Some(ra)
}

/// UDP/IPv6 packet (checksum mandatory over IPv6). Returns its length.
pub fn build_udp6(src: &[u8; 16], dst: &[u8; 16], sport: u16, dport: u16, hop: u8, payload: &[u8], out: &mut [u8]) -> usize {
    let ul = 8 + payload.len();
    hdr(out, src, dst, 17, ul, hop);
    out[40..42].copy_from_slice(&sport.to_be_bytes());
    out[42..44].copy_from_slice(&dport.to_be_bytes());
    out[44..46].copy_from_slice(&(ul as u16).to_be_bytes());
    out[46..48].copy_from_slice(&[0, 0]);
    out[48..48 + payload.len()].copy_from_slice(payload);
    let mut c = l4_csum(src, dst, 17, &out[40..40 + ul]);
    if c == 0 {
        c = 0xffff;
    }
    out[46..48].copy_from_slice(&c.to_be_bytes());
    40 + ul
}

fn opt(p: &mut [u8], n: &mut usize, code: u16, data: &[u8]) {
    p[*n..*n + 2].copy_from_slice(&code.to_be_bytes());
    p[*n + 2..*n + 4].copy_from_slice(&(data.len() as u16).to_be_bytes());
    p[*n + 4..*n + 4 + data.len()].copy_from_slice(data);
    *n += 4 + data.len();
}

/// A DHCPv6 client message from fe80::<iid>:546 to ff02::1:2:547 (hop limit 1). Client ID =
/// DUID-LL (type 3, hw type 1, MAC). IA_PD with `iaid`, T1/T2 0 (server's choice), carrying the
/// prefix from an Advertise when Requesting. ORO asks for DNS (23). Returns the IPv6 packet length.
pub fn build_dhcp6(msg: u8, xid: u32, mac: &[u8; 6], iid: &[u8; 8], iaid: u32, server_id: &[u8], pd: Option<(&[u8; 16], u8)>, rapid: bool, out: &mut [u8]) -> usize {
    let mut p = [0u8; 256];
    p[0] = msg;
    p[1..4].copy_from_slice(&xid.to_be_bytes()[1..4]);
    let mut n = 4;
    let mut duid = [0u8; 10];
    duid[0..2].copy_from_slice(&3u16.to_be_bytes());
    duid[2..4].copy_from_slice(&1u16.to_be_bytes());
    duid[4..10].copy_from_slice(mac);
    opt(&mut p, &mut n, 1, &duid);
    if !server_id.is_empty() {
        opt(&mut p, &mut n, 2, &server_id[..server_id.len().min(128)]);
    }
    opt(&mut p, &mut n, 8, &[0, 0]); // elapsed time
    let mut ia = [0u8; 12 + 29];
    ia[0..4].copy_from_slice(&iaid.to_be_bytes());
    let mut ian = 12;
    if let Some((pfx, plen)) = pd {
        ia[12..14].copy_from_slice(&26u16.to_be_bytes()); // IAPREFIX
        ia[14..16].copy_from_slice(&25u16.to_be_bytes());
        // preferred/valid lifetimes 0 = no preference; plen; prefix
        ia[24] = plen;
        ia[25..41].copy_from_slice(pfx);
        ian = 41;
    }
    // IA_NA too (a WAN global address), as fortress's wide-dhcpv6 asks Digi: "send ia-na 0; send ia-pd 0".
    let mut na = [0u8; 12];
    na[0..4].copy_from_slice(&iaid.to_be_bytes());
    opt(&mut p, &mut n, 3, &na);
    opt(&mut p, &mut n, 25, &ia[..ian]);
    opt(&mut p, &mut n, 6, &23u16.to_be_bytes()); // ORO: DNS servers
    if rapid {
        opt(&mut p, &mut n, 14, &[]);
    }
    build_udp6(&link_local(iid), &ALL_DHCP, 546, 547, 1, &p[..n], out)
}

/// What one DHCPv6 server message told us.
#[derive(Clone, Copy, Debug)]
pub struct Dhcp6 {
    pub msg: u8,
    pub server_id: [u8; 64],
    pub sid_len: usize,
    pub rapid: bool,
    pub status: u16, // top-level or IA_PD status code (0 = success / absent)
    pub has_pd: bool,
    pub prefix: [u8; 16],
    pub plen: u8,
    pub preferred: u32,
    pub valid: u32,
    pub has_dns: bool,
    pub dns: [u8; 16],
    /// IA_NA / IAADDR: a WAN global address, if the server assigned one.
    pub has_na: bool,
    pub na: [u8; 16],
}

/// Parse a DHCPv6 server message (bare IPv6, UDP to port 546) for transaction `xid`. Verifies the
/// UDP checksum. Returns None for anything else.
pub fn parse_dhcp6(ip: &[u8], xid: u32) -> Option<Dhcp6> {
    if ip.len() < 48 + 4 || ip[0] >> 4 != 6 || ip[6] != 17 {
        return None;
    }
    let plen = (u16::from_be_bytes([ip[4], ip[5]]) as usize).min(ip.len() - 40);
    let udp = &ip[40..40 + plen];
    if udp.len() < 12 || u16::from_be_bytes([udp[2], udp[3]]) != 546 {
        return None;
    }
    if l4_csum(&addr(ip, 8), &addr(ip, 24), 17, udp) != 0 {
        return None;
    }
    let p = &udp[8..];
    if p[1..4] != xid.to_be_bytes()[1..4] {
        return None;
    }
    let mut d = Dhcp6 { msg: p[0], server_id: [0; 64], sid_len: 0, rapid: false, status: 0, has_pd: false, prefix: [0; 16], plen: 0, preferred: 0, valid: 0, has_dns: false, dns: [0; 16], has_na: false, na: [0; 16] };
    let mut o = 4;
    while o + 4 <= p.len() {
        let (code, l) = (u16::from_be_bytes([p[o], p[o + 1]]), u16::from_be_bytes([p[o + 2], p[o + 3]]) as usize);
        if o + 4 + l > p.len() {
            return None;
        }
        let v = &p[o + 4..o + 4 + l];
        match code {
            2 => {
                d.sid_len = l.min(64);
                d.server_id[..d.sid_len].copy_from_slice(&v[..d.sid_len]);
            }
            13 if l >= 2 => d.status = u16::from_be_bytes([v[0], v[1]]),
            14 => d.rapid = true,
            23 if l >= 16 => {
                d.has_dns = true;
                d.dns.copy_from_slice(&v[..16]);
            }
            3 if l >= 12 => {
                let mut q = 12;
                while q + 4 <= l {
                    let (c2, l2) = (u16::from_be_bytes([v[q], v[q + 1]]), u16::from_be_bytes([v[q + 2], v[q + 3]]) as usize);
                    if q + 4 + l2 > l {
                        break;
                    }
                    if c2 == 5 && l2 >= 24 && !d.has_na {
                        d.has_na = true;
                        d.na.copy_from_slice(&v[q + 4..q + 20]);
                    }
                    q += 4 + l2;
                }
            }
            25 if l >= 12 => {
                let mut q = 12;
                while q + 4 <= l {
                    let (c2, l2) = (u16::from_be_bytes([v[q], v[q + 1]]), u16::from_be_bytes([v[q + 2], v[q + 3]]) as usize);
                    if q + 4 + l2 > l {
                        break;
                    }
                    let w = &v[q + 4..q + 4 + l2];
                    if c2 == 26 && l2 >= 25 && !d.has_pd {
                        d.has_pd = true;
                        d.preferred = u32::from_be_bytes([w[0], w[1], w[2], w[3]]);
                        d.valid = u32::from_be_bytes([w[4], w[5], w[6], w[7]]);
                        d.plen = w[8];
                        d.prefix.copy_from_slice(&w[9..25]);
                    } else if c2 == 13 && l2 >= 2 && d.status == 0 {
                        d.status = u16::from_be_bytes([w[0], w[1]]);
                    }
                    q += 4 + l2;
                }
            }
            _ => {}
        }
        o += 4 + l;
    }
    Some(d)
}
