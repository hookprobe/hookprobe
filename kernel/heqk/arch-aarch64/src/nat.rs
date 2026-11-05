//! M-NAT1 — a bounded, no-alloc IPv4 source-NAT (masquerade) between the WiFi-AP /
//! eth1-LAN side (10.99.0.0/24, heqk = 10.99.0.1) and the end0 WAN lease.
//!
//! Shape (uplink/NAT deep review 2026-09-11, B3/B4/B5): a fixed table of `N` entries
//! keyed on (proto, inside ip, inside port-or-icmp-id); the OUTSIDE port/id is simply
//! `EXT_BASE + index`, so the reverse lookup is O(1) and never needs a hash. Every
//! rewrite recomputes the IPv4 + L4 checksums in full (segments are small — the SDIO
//! data path caps a WiFi-bound frame at ~496 B, so the TCP MSS is clamped on every SYN
//! / SYN-ACK crossing the WiFi leg). TTL is decremented (drop at ≤1). GEM RX frames
//! carry the 4-byte FCS (NCFGR bit 17 not set): the inbound path trims to the IPv4
//! total length before forwarding. Entries expire by `last` (cntpct) and are LRU-
//! evicted when full.

use hal::{inet_csum, pseudo_sum};

const N: usize = 256;
/// First outside port / ICMP id; entry `i` owns `EXT_BASE + i`.
pub const EXT_BASE: u16 = 40000;
/// Largest ethernet frame the WiFi data path can SEND to a station: one byte-mode CMD53
/// (512 B) minus the 16-B SDPCM/BDC header. RX now takes full-MTU frames (chunked remainder
/// reads, proven on metal); TX beyond this must wait for a proven block-mode CMD53 —
/// chunked writes desynchronised the firmware (metal 2026-10-09). Bigger inbound frames are
/// dropped and counted (`in_too_big`); the MSS clamp keeps TCP under it.
#[cfg(not(feature = "wifi-bigtx"))]
pub const WIFI_MAX_FRAME: usize = 496;
/// Bench build: block-mode CMD53 carries full-MTU frames to a station.
#[cfg(feature = "wifi-bigtx")]
pub const WIFI_MAX_FRAME: usize = 1514;
/// MSS advertised to both ends. Kept at the pre-M-NAT4 value for this image as the hedge:
/// TCP stays provably within one 512-B transfer either way, while big UDP (QUIC) is the
/// first traffic to exercise the chunked path. Raise to ~1400 once metal proves chunking.
#[cfg(not(feature = "wifi-bigtx"))]
pub const MSS_CLAMP: u16 = 430;
/// With block-mode TX (the Linux-traced sequence, metal-proven 2026-11-04: 1,773 full-MTU frames
/// to an iPhone, 0 failures) a station takes full 1514-B frames: the standard MSS for a 1500-B
/// MTU. The clamp still lowers larger advertisements; it never raises one.
#[cfg(feature = "wifi-bigtx")]
pub const MSS_CLAMP: u16 = 1460;

/// Inside link ids (`Entry.in_if`): replies go back out the link the flow came in on.
pub const IF_WIFI: u8 = 0;
pub const IF_ETH1: u8 = 1;

#[derive(Clone, Copy)]
struct Entry {
    used: bool,
    proto: u8,
    in_if: u8,
    in_mac: [u8; 6],
    in_ip: [u8; 4],
    in_port: u16, // TCP/UDP src port, or ICMP echo id
    last: u64,    // cntpct of the last packet either way
    /// DNS redirect: the address the client actually queried (the AP's own IP) when the query
    /// was forwarded to the upstream resolver — replies get it back as their source. 0 = none.
    dnat_from: [u8; 4],
}
const EMPTY: Entry = Entry { used: false, proto: 0, in_if: 0, in_mac: [0; 6], in_ip: [0; 4], in_port: 0, last: 0, dnat_from: [0; 4] };
static mut TABLE: [Entry; N] = [EMPTY; N];

#[derive(Default)]
pub struct NatStats {
    pub out_fwd: u32,
    pub in_fwd: u32,
    pub out_drop: u32,     // not IPv4 / TTL / unsupported proto / for us
    pub in_drop: u32,      // no matching entry / not for the lease
    pub in_too_big: u32,   // inbound frame > WIFI_MAX_FRAME after trim (dropped)
    pub mss_clamped: u32,
    pub table_alloc: u32,
    pub table_evict: u32,
    /// DNS queries to the AP address forwarded to the upstream resolver.
    pub dns_redirect: u32,
}

#[inline]
fn ticks_secs(s: u64) -> u64 {
    let f: u64;
    unsafe { core::arch::asm!("mrs {}, cntfrq_el0", out(reg) f, options(nomem, nostack)) };
    f.max(1).saturating_mul(s)
}

/// Idle timeout per proto (seconds) — short, self-reverting (ADR 0023 spirit: state is
/// a bounded cache, never a durable claim).
fn timeout(proto: u8) -> u64 {
    match proto {
        6 => ticks_secs(300),
        17 => ticks_secs(60),
        _ => ticks_secs(30),
    }
}

/// Find or allocate the entry for (proto, in_ip, in_port). Returns the index.
fn lookup_or_alloc(proto: u8, in_if: u8, in_mac: &[u8; 6], in_ip: &[u8; 4], in_port: u16, now: u64, st: &mut NatStats) -> usize {
    let t = unsafe { &mut *core::ptr::addr_of_mut!(TABLE) };
    let mut free: Option<usize> = None;
    let mut oldest = (0usize, u64::MAX);
    for i in 0..N {
        let e = &t[i];
        if e.used {
            if e.proto == proto && e.in_ip == *in_ip && e.in_port == in_port {
                t[i].last = now;
                t[i].in_mac = *in_mac;
                t[i].in_if = in_if;
                return i;
            }
            if now.wrapping_sub(e.last) > timeout(e.proto) && free.is_none() {
                free = Some(i); // expired — reusable
            }
            if e.last < oldest.1 {
                oldest = (i, e.last);
            }
        } else if free.is_none() {
            free = Some(i);
        }
    }
    let i = match free {
        Some(i) => i,
        None => {
            st.table_evict += 1;
            oldest.0
        }
    };
    t[i] = Entry { used: true, proto, in_if, in_mac: *in_mac, in_ip: *in_ip, in_port, last: now, dnat_from: [0; 4] };
    st.table_alloc += 1;
    i
}

fn entry_for_ext(proto: u8, ext: u16, now: u64) -> Option<Entry> {
    let i = (ext as usize).checked_sub(EXT_BASE as usize)?;
    if i >= N {
        return None;
    }
    let t = unsafe { &mut *core::ptr::addr_of_mut!(TABLE) };
    let e = t[i];
    if !e.used || e.proto != proto {
        return None;
    }
    if now.wrapping_sub(e.last) > timeout(proto) {
        return None;
    }
    t[i].last = now;
    Some(e)
}

/// Clamp TCP option MSS (kind 2) on a SYN. `tcp` = the TCP header (+options) slice.
fn clamp_mss(tcp: &mut [u8], st: &mut NatStats) {
    if tcp.len() < 20 || tcp[13] & 0x02 == 0 {
        return; // not a SYN
    }
    let doff = ((tcp[12] >> 4) as usize) * 4;
    if doff < 20 || doff > tcp.len() {
        return;
    }
    let mut p = 20;
    while p < doff {
        match tcp[p] {
            0 => break,
            1 => p += 1,
            2 if p + 4 <= doff => {
                let mss = u16::from_be_bytes([tcp[p + 2], tcp[p + 3]]);
                if mss > MSS_CLAMP {
                    tcp[p + 2..p + 4].copy_from_slice(&MSS_CLAMP.to_be_bytes());
                    st.mss_clamped += 1;
                }
                return;
            }
            _ => {
                if p + 1 >= doff {
                    break;
                }
                let l = tcp[p + 1] as usize;
                if l < 2 {
                    break;
                }
                p += l;
            }
        }
    }
}

/// Recompute the IPv4 header checksum and the L4 checksum (TCP/UDP pseudo-header, ICMP
/// plain) over `f` (a complete ethernet frame, IPv4 at 14). `ip_end` bounds the datagram.
fn fix_csums(f: &mut [u8], ihl: usize, ip_end: usize) {
    let proto = f[23];
    f[24] = 0;
    f[25] = 0;
    let ipc = inet_csum(&f[14..14 + ihl], 0);
    f[24..26].copy_from_slice(&ipc.to_be_bytes());
    let l4 = 14 + ihl;
    if l4 > ip_end {
        return;
    }
    let l4len = (ip_end - l4) as u16;
    let mut sip = [0u8; 4];
    sip.copy_from_slice(&f[26..30]);
    let mut dip = [0u8; 4];
    dip.copy_from_slice(&f[30..34]);
    match proto {
        6 if l4 + 20 <= ip_end => {
            f[l4 + 16] = 0;
            f[l4 + 17] = 0;
            let c = inet_csum(&f[l4..ip_end], pseudo_sum(&sip, &dip, 6, l4len));
            f[l4 + 16..l4 + 18].copy_from_slice(&c.to_be_bytes());
        }
        17 if l4 + 8 <= ip_end => {
            let had = f[l4 + 6] != 0 || f[l4 + 7] != 0;
            if had {
                f[l4 + 6] = 0;
                f[l4 + 7] = 0;
                let mut c = inet_csum(&f[l4..ip_end], pseudo_sum(&sip, &dip, 17, l4len));
                if c == 0 {
                    c = 0xffff;
                }
                f[l4 + 6..l4 + 8].copy_from_slice(&c.to_be_bytes());
            }
        }
        1 if l4 + 8 <= ip_end => {
            f[l4 + 2] = 0;
            f[l4 + 3] = 0;
            let c = inet_csum(&f[l4..ip_end], 0);
            f[l4 + 2..l4 + 4].copy_from_slice(&c.to_be_bytes());
        }
        _ => {}
    }
}

/// Parse an IPv4 frame: (ihl, ip_end bounded by the frame, proto). None if not IPv4 /
/// truncated / fragmented (fragments are not NATed in v1).
fn parse_v4(f: &[u8]) -> Option<(usize, usize, u8)> {
    if f.len() < 34 || f[12] != 0x08 || f[13] != 0x00 || f[14] >> 4 != 4 {
        return None;
    }
    let ihl = ((f[14] & 0x0f) as usize) * 4;
    if ihl < 20 || 14 + ihl > f.len() {
        return None;
    }
    let tot = u16::from_be_bytes([f[16], f[17]]) as usize;
    if tot < ihl {
        return None;
    }
    let ip_end = (14 + tot).min(f.len());
    let flags_frag = u16::from_be_bytes([f[20], f[21]]);
    if flags_frag & 0x3fff != 0 {
        return None; // MF set or a non-zero fragment offset
    }
    Some((ihl, ip_end, f[23]))
}

/// OUTBOUND (inside → WAN): rewrite a client frame into `out` addressed to the gateway,
/// sourced from the lease. Returns the frame length to transmit on end0, or None (not
/// NATable: not IPv4, TTL exhausted, unsupported proto, or destined for our own subnet).
pub fn outbound(f: &[u8], in_if: u8, inside_net: &[u8; 3], wan_ip: &[u8; 4], wan_mac: &[u8; 6], gw_mac: &[u8; 6], out: &mut [u8], now: u64, st: &mut NatStats) -> Option<usize> {
    outbound_redirect(f, in_if, inside_net, None, wan_ip, wan_mac, gw_mac, out, now, st)
}

/// `outbound` plus the AP's DNS service: a UDP query to `dns.0` (the AP's own address, which the
/// AP's DHCP advertises as the resolver) port 53 is forwarded to `dns.1` (the upstream resolver
/// from the WAN lease) through the same SNAT, and the entry remembers it so `inbound` restores
/// the AP address as the reply's source. Every gate before NAT (lease binding, IDS verdict) has
/// already run on the client's original frame.
pub fn outbound_redirect(f: &[u8], in_if: u8, inside_net: &[u8; 3], dns: Option<(&[u8; 4], &[u8; 4])>, wan_ip: &[u8; 4], wan_mac: &[u8; 6], gw_mac: &[u8; 6], out: &mut [u8], now: u64, st: &mut NatStats) -> Option<usize> {
    let (ihl, ip_end, proto) = match parse_v4(f) {
        Some(t) => t,
        None => {
            st.out_drop += 1;
            return None;
        }
    };
    let l4p = 14 + ihl;
    let redirect = match dns {
        Some((ap_ip, resolver)) if proto == 17 && &f[30..34] == &ap_ip[..] && l4p + 4 <= ip_end
            && u16::from_be_bytes([f[l4p + 2], f[l4p + 3]]) == 53 => Some((*ap_ip, *resolver)),
        _ => None,
    };
    if redirect.is_none() && (&f[30..33] == &inside_net[..] || f[30..34] == [255; 4] || f[30] >= 224 || f[22] <= 1) {
        st.out_drop += 1;
        return None; // local subnet / broadcast / multicast / TTL exhausted
    }
    if ip_end > out.len() {
        st.out_drop += 1;
        return None;
    }
    let l4 = 14 + ihl;
    let in_port = match proto {
        6 | 17 if l4 + 8 <= ip_end => u16::from_be_bytes([f[l4], f[l4 + 1]]),
        1 if l4 + 8 <= ip_end && f[l4] == 8 => u16::from_be_bytes([f[l4 + 4], f[l4 + 5]]), // echo request id
        _ => {
            st.out_drop += 1;
            return None;
        }
    };
    let mut in_mac = [0u8; 6];
    in_mac.copy_from_slice(&f[6..12]);
    let mut in_ip = [0u8; 4];
    in_ip.copy_from_slice(&f[26..30]);
    if f[22] <= 1 {
        st.out_drop += 1;
        return None;
    }
    let idx = lookup_or_alloc(proto, in_if, &in_mac, &in_ip, in_port, now, st);
    let ext = EXT_BASE + idx as u16;
    unsafe {
        let t = &mut *core::ptr::addr_of_mut!(TABLE);
        t[idx].dnat_from = match redirect { Some((ap, _)) => ap, None => [0; 4] };
    }

    out[..ip_end].copy_from_slice(&f[..ip_end]);
    out[0..6].copy_from_slice(gw_mac);
    out[6..12].copy_from_slice(wan_mac);
    out[22] -= 1; // TTL
    out[26..30].copy_from_slice(wan_ip);
    if let Some((_, resolver)) = redirect {
        out[30..34].copy_from_slice(&resolver);
        st.dns_redirect += 1;
    }
    match proto {
        6 => {
            out[l4..l4 + 2].copy_from_slice(&ext.to_be_bytes());
            clamp_mss(&mut out[l4..ip_end], st);
        }
        17 => out[l4..l4 + 2].copy_from_slice(&ext.to_be_bytes()),
        _ => out[l4 + 4..l4 + 6].copy_from_slice(&ext.to_be_bytes()),
    }
    fix_csums(out, ihl, ip_end);
    st.out_fwd += 1;
    Some(ip_end)
}

/// INBOUND (WAN → inside): a frame received on end0 for the lease. Rewrites it into `out`
/// addressed to the inside client (from the table) and sourced from that link's MAC
/// (`inside_macs[in_if]`). Returns (frame length, inside link id), or None (not for us /
/// no entry). The CALLER enforces the per-link size cap (the WiFi leg carries ≤
/// `WIFI_MAX_FRAME`; eth1 a full MTU) and counts `in_too_big`.
pub fn inbound(f: &[u8], wan_ip: &[u8; 4], wan_mac: &[u8; 6], inside_macs: [&[u8; 6]; 2], out: &mut [u8], now: u64, st: &mut NatStats) -> Option<(usize, u8)> {
    if f.len() < 14 || (&f[0..6] != &wan_mac[..]) {
        return None; // promiscuous GEM: not addressed to us (no stat — that's the wire's noise)
    }
    let (ihl, ip_end, proto) = match parse_v4(f) {
        Some(t) => t,
        None => return None,
    };
    if &f[30..34] != &wan_ip[..] {
        return None;
    }
    if f[22] <= 1 || ip_end > out.len() {
        st.in_drop += 1;
        return None;
    }
    let l4 = 14 + ihl;
    let ext = match proto {
        6 | 17 if l4 + 8 <= ip_end => u16::from_be_bytes([f[l4 + 2], f[l4 + 3]]),
        1 if l4 + 8 <= ip_end && f[l4] == 0 => u16::from_be_bytes([f[l4 + 4], f[l4 + 5]]), // echo reply id
        _ => {
            st.in_drop += 1;
            return None;
        }
    };
    let e = match entry_for_ext(proto, ext, now) {
        Some(e) => e,
        None => {
            st.in_drop += 1;
            return None;
        }
    };
    let inside_mac = inside_macs[(e.in_if as usize).min(1)];
    // Trim to the IPv4 total length: the GEM hands us the FCS too.
    out[..ip_end].copy_from_slice(&f[..ip_end]);
    out[0..6].copy_from_slice(&e.in_mac);
    out[6..12].copy_from_slice(inside_mac);
    out[22] -= 1;
    out[30..34].copy_from_slice(&e.in_ip);
    match proto {
        6 => {
            out[l4 + 2..l4 + 4].copy_from_slice(&e.in_port.to_be_bytes());
            clamp_mss(&mut out[l4..ip_end], st); // SYN-ACK: keep the client's segments small too
        }
        17 => out[l4 + 2..l4 + 4].copy_from_slice(&e.in_port.to_be_bytes()),
        _ => out[l4 + 4..l4 + 6].copy_from_slice(&e.in_port.to_be_bytes()),
    }
    // DNS redirect: the client asked the AP — the answer must come FROM the AP.
    if e.dnat_from != [0; 4] && proto == 17 && u16::from_be_bytes([f[l4], f[l4 + 1]]) == 53 {
        out[26..30].copy_from_slice(&e.dnat_from);
    }
    fix_csums(out, ihl, ip_end);
    st.in_fwd += 1;
    Some((ip_end, e.in_if))
}
