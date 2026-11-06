//! IPv6 LAN router for the heqk AP — pure (no MMIO), built on every target so QEMU tests it.
//!
//! The LAN /64 is the first subnet of the prefix the ISP delegated over DHCPv6 (IA_PD). This module:
//! - answers Router Solicitations and sends periodic Router Advertisements (RFC 4861 §6.2): the /64
//!   (on-link + autonomous -> SLAAC), MTU 1492 (the PPPoE path), RDNSS (RFC 8106), our link-layer addr;
//! - answers Neighbor Solicitations for the router's own addresses (link-local and prefix::1);
//! - learns client neighbors (IPv6 -> MAC) from the frames they send — inbound packets are only
//!   delivered to a learned neighbor, and every inbound flow must be a reply to one the LAN started;
//! - FORWARDS without NAT, so it is also the FIREWALL: outbound records the flow; inbound passes only
//!   replies to a recorded flow, plus ICMPv6 errors (RFC 4890 §4.3.1: Destination Unreachable, Packet
//!   Too Big, Time Exceeded, Parameter Problem — PMTU discovery breaks without Packet Too Big). Default
//!   deny for everything else inbound. Hop limit is decremented both ways (<= 1 -> drop).
//! The kernel loop only plumbs frames: Wi-Fi -> on_lan -> IDS verdict -> PPPoE; PPPoE -> on_wan -> Wi-Fi.

use crate::ip6::{l4_csum, link_local};

pub const NEIGH_N: usize = 32;
pub const FLOW_N: usize = 256;
/// Idle timeouts (ms): established flows, and anything else.
const FLOW_IDLE_MS: u64 = 600_000;
const NEIGH_IDLE_MS: u64 = 1_800_000;
pub const LAN_MTU: u32 = 1492;

#[derive(Clone, Copy, Default)]
struct Neigh {
    ip: [u8; 16],
    mac: [u8; 6],
    seen: u64,
}

/// One LAN-initiated flow: (local, remote, proto, local port/id, remote port).
#[derive(Clone, Copy, Default)]
struct Flow {
    local: [u8; 16],
    remote: [u8; 16],
    proto: u8,
    lport: u16,
    rport: u16,
    seen: u64,
    used: bool,
}

#[derive(Clone, Copy, Default, Debug)]
pub struct Stats {
    pub ra_tx: u32,
    pub rs_rx: u32,
    pub na_tx: u32,
    pub out_fwd: u32,
    pub in_fwd: u32,
    pub in_icmp_err: u32,
    pub drop_no_flow: u32,
    pub drop_no_neigh: u32,
    pub drop_hop: u32,
    pub drop_src: u32,
    pub drop_bad: u32,
    pub flow_evict: u32,
}

pub enum LanAction {
    /// Send this Ethernet frame back on the LAN (RA / NA).
    Reply(usize),
    /// Forward this bare IPv6 packet to the WAN (hop limit already decremented).
    Forward(usize),
    Drop,
    /// Not IPv6 for us (caller keeps its other paths).
    Ignore,
}

pub enum WanAction {
    /// Deliver this Ethernet frame to a LAN client.
    Deliver(usize),
    Drop,
}

pub struct V6Lan {
    pub up: bool,
    /// LAN /64 (only the first 8 bytes matter).
    pub prefix: [u8; 16],
    pub mac: [u8; 6],
    pub ll: [u8; 16],
    pub gua: [u8; 16],
    pub dns: [u8; 16],
    pub has_dns: bool,
    /// Prefix lifetimes advertised to clients (bounded by the delegation).
    valid: u32,
    preferred: u32,
    neigh: [Neigh; NEIGH_N],
    flows: [Flow; FLOW_N],
    pub stats: Stats,
    last_ra_ms: u64,
    ra_burst: u32,
    /// The flow of the last `Forward` — recorded only when the caller `commit`s it (after policy, the
    /// IDS and a successful send). Peer review SEC-M4: recording it inside on_lan let a BLOCKED
    /// outbound SYN open a 10-minute inbound pinhole.
    pending: Option<([u8; 16], [u8; 16], u8, u16, u16)>,
}

fn addr(b: &[u8], o: usize) -> [u8; 16] {
    let mut a = [0u8; 16];
    a.copy_from_slice(&b[o..o + 16]);
    a
}

fn is_ll(a: &[u8; 16]) -> bool {
    a[0] == 0xfe && a[1] & 0xc0 == 0x80
}

fn is_mc(a: &[u8; 16]) -> bool {
    a[0] == 0xff
}

/// Transport ports of a bare IPv6 packet whose next header is TCP/UDP (no extension headers), or the
/// ICMPv6 echo identifier as both. None for anything else.
fn ports(ip: &[u8]) -> Option<(u8, u16, u16)> {
    let nh = ip[6];
    let l4 = &ip[40..];
    match nh {
        6 | 17 if l4.len() >= 4 => Some((nh, u16::from_be_bytes([l4[0], l4[1]]), u16::from_be_bytes([l4[2], l4[3]]))),
        58 if l4.len() >= 8 && (l4[0] == 128 || l4[0] == 129) => {
            let id = u16::from_be_bytes([l4[4], l4[5]]);
            Some((58, id, id))
        }
        _ => None,
    }
}

impl V6Lan {
    pub const fn new() -> Self {
        V6Lan {
            up: false,
            prefix: [0; 16],
            mac: [0; 6],
            ll: [0; 16],
            gua: [0; 16],
            dns: [0; 16],
            has_dns: false,
            valid: 0,
            preferred: 0,
            neigh: [Neigh { ip: [0; 16], mac: [0; 6], seen: 0 }; NEIGH_N],
            flows: [Flow { local: [0; 16], remote: [0; 16], proto: 0, lport: 0, rport: 0, seen: 0, used: false }; FLOW_N],
            stats: Stats {
                ra_tx: 0, rs_rx: 0, na_tx: 0, out_fwd: 0, in_fwd: 0, in_icmp_err: 0, drop_no_flow: 0,
                drop_no_neigh: 0, drop_hop: 0, drop_src: 0, drop_bad: 0, flow_evict: 0,
            },
            last_ra_ms: 0,
            ra_burst: 0,
            pending: None,
        }
    }

    /// Number the LAN from a delegated prefix: the first /64 of it (subnet id 0), router = prefix::1.
    pub fn configure(&mut self, pd: &[u8; 16], pd_len: u8, valid: u32, mac: &[u8; 6], dns: Option<&[u8; 16]>) {
        if pd_len > 64 {
            self.up = false;
            return;
        }
        let mut p = [0u8; 16];
        p[..8].copy_from_slice(&pd[..8]);
        self.prefix = p;
        self.mac = *mac;
        self.ll = link_local(&crate::ip6::eui64(mac));
        self.gua = p;
        self.gua[15] = 1;
        if let Some(d) = dns {
            self.dns = *d;
            self.has_dns = true;
        }
        // Advertise bounded lifetimes; an "infinite" delegation still gets refreshed RAs.
        self.valid = valid.min(86_400);
        self.preferred = (valid / 2).min(14_400);
        self.up = true;
        self.ra_burst = 0;
        self.last_ra_ms = 0;
    }

    fn on_link(&self, a: &[u8; 16]) -> bool {
        a[..8] == self.prefix[..8]
    }

    fn learn(&mut self, ip: &[u8; 16], mac: &[u8], now: u64) {
        if !(self.on_link(ip) || is_ll(ip)) {
            return;
        }
        let mut slot = 0;
        let mut oldest = u64::MAX;
        for (i, n) in self.neigh.iter().enumerate() {
            if n.ip == *ip {
                slot = i;
                oldest = 0;
                break;
            }
            if n.seen < oldest {
                oldest = n.seen;
                slot = i;
            }
        }
        let n = &mut self.neigh[slot];
        n.ip = *ip;
        n.mac.copy_from_slice(&mac[..6]);
        n.seen = now.max(1);
    }

    fn lookup(&self, ip: &[u8; 16], now: u64) -> Option<[u8; 6]> {
        self.neigh.iter().find(|n| n.seen != 0 && n.ip == *ip && now.wrapping_sub(n.seen) < NEIGH_IDLE_MS).map(|n| n.mac)
    }

    fn flow_note(&mut self, local: &[u8; 16], remote: &[u8; 16], proto: u8, lport: u16, rport: u16, now: u64) {
        let same = |f: &Flow| f.used && f.local == *local && f.remote == *remote && f.proto == proto && f.lport == lport && f.rport == rport;
        let live = |f: &Flow| f.used && now.wrapping_sub(f.seen) < FLOW_IDLE_MS;
        // 1. refresh the existing entry; 2. a free or expired slot; 3. evict the least recently seen.
        let i = if let Some(i) = self.flows.iter().position(|f| same(f)) {
            i
        } else if let Some(i) = self.flows.iter().position(|f| !live(f)) {
            i
        } else {
            self.stats.flow_evict += 1;
            let mut j = 0;
            for (k, f) in self.flows.iter().enumerate() {
                if f.seen < self.flows[j].seen {
                    j = k;
                }
            }
            j
        };
        self.flows[i] = Flow { local: *local, remote: *remote, proto, lport, rport, seen: now.max(1), used: true };
    }

    fn flow_match(&mut self, local: &[u8; 16], remote: &[u8; 16], proto: u8, lport: u16, rport: u16, now: u64) -> bool {
        for f in self.flows.iter_mut() {
            if f.used && f.local == *local && f.remote == *remote && f.proto == proto && f.lport == lport && f.rport == rport
                && now.wrapping_sub(f.seen) < FLOW_IDLE_MS
            {
                f.seen = now.max(1);
                return true;
            }
        }
        false
    }

    /// Ethernet + IPv6 header for an ICMPv6 message from `src` to `dst`; returns the ICMPv6 offset.
    fn icmp_frame(&self, out: &mut [u8], dmac: &[u8; 6], src: &[u8; 16], dst: &[u8; 16], icmp_len: usize) -> usize {
        out[0..6].copy_from_slice(dmac);
        out[6..12].copy_from_slice(&self.mac);
        out[12..14].copy_from_slice(&0x86ddu16.to_be_bytes());
        let ip = &mut out[14..];
        ip[0] = 0x60;
        ip[1..4].copy_from_slice(&[0, 0, 0]);
        ip[4..6].copy_from_slice(&(icmp_len as u16).to_be_bytes());
        ip[6] = 58;
        ip[7] = 255;
        ip[8..24].copy_from_slice(src);
        ip[24..40].copy_from_slice(dst);
        54
    }

    fn finish_icmp(out: &mut [u8], src: &[u8; 16], dst: &[u8; 16], icmp_len: usize) -> usize {
        out[56..58].copy_from_slice(&[0, 0]);
        let c = l4_csum(src, dst, 58, &out[54..54 + icmp_len]);
        out[56..58].copy_from_slice(&c.to_be_bytes());
        54 + icmp_len
    }

    /// A Router Advertisement to `dst` (ff02::1 when unsolicited) as an Ethernet frame.
    pub fn build_ra(&mut self, dmac: &[u8; 6], dst: &[u8; 16], out: &mut [u8]) -> usize {
        let has_dns = self.has_dns;
        let il = 16 + 8 + 32 + 8 + if has_dns { 24 } else { 0 };
        let (ll, valid, preferred, prefix, mac, dns) = (self.ll, self.valid, self.preferred, self.prefix, self.mac, self.dns);
        let o = self.icmp_frame(out, dmac, &ll, dst, il);
        let r = &mut out[o..o + il];
        r.fill(0);
        r[0] = 134;
        r[4] = 64; // cur hop limit for clients
        r[5] = 0; // M=0 O=0: SLAAC; DNS via RDNSS
        r[6..8].copy_from_slice(&1800u16.to_be_bytes()); // router lifetime
        let mut k = 16;
        // Source link-layer address
        r[k] = 1;
        r[k + 1] = 1;
        r[k + 2..k + 8].copy_from_slice(&mac);
        k += 8;
        // Prefix Information: on-link + autonomous
        r[k] = 3;
        r[k + 1] = 4;
        r[k + 2] = 64;
        r[k + 3] = 0xc0;
        r[k + 4..k + 8].copy_from_slice(&valid.to_be_bytes());
        r[k + 8..k + 12].copy_from_slice(&preferred.to_be_bytes());
        r[k + 16..k + 32].copy_from_slice(&prefix);
        k += 32;
        // MTU
        r[k] = 5;
        r[k + 1] = 1;
        r[k + 4..k + 8].copy_from_slice(&LAN_MTU.to_be_bytes());
        k += 8;
        if has_dns {
            r[k] = 25; // RDNSS
            r[k + 1] = 3;
            r[k + 4..k + 8].copy_from_slice(&1800u32.to_be_bytes());
            r[k + 8..k + 24].copy_from_slice(&dns);
        }
        self.stats.ra_tx += 1;
        Self::finish_icmp(out, &ll, dst, il)
    }

    /// Periodic unsolicited RA: 3 fast ones (4 s apart) after configure, then every 60 s.
    pub fn ra_due(&mut self, now: u64) -> bool {
        if !self.up {
            return false;
        }
        let iv = if self.ra_burst < 3 { 4_000 } else { 60_000 };
        if self.last_ra_ms == 0 || now.wrapping_sub(self.last_ra_ms) >= iv {
            self.last_ra_ms = now.max(1);
            self.ra_burst += 1;
            return true;
        }
        false
    }

    /// One Ethernet frame from a LAN client. `out` receives a reply frame or the IPv6 packet to forward.
    pub fn on_lan(&mut self, f: &[u8], now: u64, out: &mut [u8]) -> LanAction {
        if !self.up || f.len() < 54 || f[12] != 0x86 || f[13] != 0xdd || f[14] >> 4 != 6 {
            return LanAction::Ignore;
        }
        let ip = &f[14..];
        let plen = u16::from_be_bytes([ip[4], ip[5]]) as usize;
        // Peer review P1: bound by the caller's output buffer too (an 802.11 MSDU may exceed it).
        if 40 + plen > ip.len() || 14 + 40 + plen > out.len() {
            self.stats.drop_bad += 1;
            return LanAction::Drop;
        }
        let ip = &ip[..40 + plen];
        let (src, dst) = (addr(ip, 8), addr(ip, 24));
        if src != [0; 16] && !is_mc(&src) {
            self.learn(&src, &f[6..12], now);
        }
        // ICMPv6 addressed to us / to the link: RS, NS (hop limit 255 = on-link, RFC 4861).
        if ip[6] == 58 && plen >= 8 && (is_mc(&dst) || dst == self.ll || dst == self.gua) {
            if l4_csum(&src, &dst, 58, &ip[40..]) != 0 {
                self.stats.drop_bad += 1;
                return LanAction::Drop;
            }
            let t = ip[40];
            if t == 133 && ip[7] == 255 {
                self.stats.rs_rx += 1;
                let mut dmac = [0u8; 6];
                dmac.copy_from_slice(&f[6..12]);
                let d = if src == [0; 16] { [0xff, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1] } else { src };
                return LanAction::Reply(self.build_ra(&dmac, &d, out));
            }
            if t == 135 && ip[7] == 255 && plen >= 24 {
                let target = addr(ip, 48);
                if (target == self.ll || target == self.gua) && src != [0; 16] {
                    let mut dmac = [0u8; 6];
                    dmac.copy_from_slice(&f[6..12]);
                    let il = 32;
                    let o = self.icmp_frame(out, &dmac, &target, &src, il);
                    let r = &mut out[o..o + il];
                    r.fill(0);
                    r[0] = 136;
                    r[4] = 0xe0; // Router, Solicited, Override
                    r[8..24].copy_from_slice(&target);
                    r[24] = 2; // Target link-layer address
                    r[25] = 1;
                    r[26..32].copy_from_slice(&self.mac);
                    self.stats.na_tx += 1;
                    return LanAction::Reply(Self::finish_icmp(out, &target, &src, il));
                }
                return LanAction::Drop; // DAD / someone else's address: not ours to answer
            }
            if is_mc(&dst) || dst == self.ll || dst == self.gua {
                return LanAction::Drop; // other ND / echo to the router: not routed
            }
        }
        let special = dst == [0; 16] || dst == { let mut l = [0u8; 16]; l[15] = 1; l } || (dst[..10] == [0u8; 10] && dst[10] == 0xff && dst[11] == 0xff);
        if is_mc(&dst) || is_ll(&dst) || dst == self.gua || self.on_link(&dst) || special {
            return LanAction::Drop; // link-scope / our own /64 / unspecified / loopback / v4-mapped: never to the ISP
        }
        // Forward: only sources from our /64 (anti-spoof), hop limit > 1.
        if !self.on_link(&src) {
            self.stats.drop_src += 1;
            return LanAction::Drop;
        }
        if ip[7] <= 1 {
            self.stats.drop_hop += 1;
            return LanAction::Drop;
        }
        self.pending = None;
        if let Some((proto, sp, dp)) = ports(ip) {
            self.pending = Some((src, dst, proto, sp, dp));
        } else if !(ip[6] == 58) {
            // Extension headers / other protocols: no stateful entry possible -> outbound refused
            // (fail-closed; IPv6 TCP/UDP/ICMPv6 cover the client traffic we serve).
            self.stats.drop_bad += 1;
            return LanAction::Drop;
        }
        let n = ip.len();
        out[..n].copy_from_slice(ip);
        out[7] -= 1;
        self.stats.out_fwd += 1;
        LanAction::Forward(n)
    }

    /// Record the flow of the last `Forward` — call only once it was allowed by policy, passed the IDS
    /// and was sent. A no-op otherwise.
    pub fn commit(&mut self, now: u64) {
        if let Some((l, r, p, sp, dp)) = self.pending.take() {
            self.flow_note(&l, &r, p, sp, dp, now);
        }
    }

    /// One bare IPv6 packet from the WAN. `out` receives the Ethernet frame for the LAN client.
    pub fn on_wan(&mut self, ip: &[u8], now: u64, out: &mut [u8]) -> WanAction {
        if !self.up || ip.len() < 40 || ip[0] >> 4 != 6 {
            return WanAction::Drop;
        }
        let plen = u16::from_be_bytes([ip[4], ip[5]]) as usize;
        if 40 + plen > ip.len() || 14 + 40 + plen > out.len() {
            self.stats.drop_bad += 1;
            return WanAction::Drop;
        }
        let ip = &ip[..40 + plen];
        let (src, dst) = (addr(ip, 8), addr(ip, 24));
        if !self.on_link(&dst) || dst == self.gua {
            self.stats.drop_bad += 1;
            return WanAction::Drop;
        }
        if ip[7] <= 1 {
            self.stats.drop_hop += 1;
            return WanAction::Drop;
        }
        // Firewall: a reply to a LAN-initiated flow, or an ICMPv6 error (RFC 4890 §4.3.1).
        let allowed = match ports(ip) {
            Some((proto, sp, dp)) => self.flow_match(&dst, &src, proto, dp, sp, now),
            None => {
                // ICMPv6 error (RFC 4890 §4.3.1) — admitted only when the packet it quotes is one of OUR
                // LAN host's live flows (peer review SEC-M3: any internet host could push type 1-4 to any
                // learned LAN address). Quoted packet = an IPv6 header at ip[48..] whose SOURCE is the LAN
                // host this error is addressed to.
                let q = 48;
                if ip[6] == 58 && plen >= 8 + 40 + 4 && (1..=4).contains(&ip[40]) && ip.len() >= q + 44 && ip[q] >> 4 == 6 {
                    let (qs, qd) = (addr(ip, q + 8), addr(ip, q + 24));
                    let qnh = ip[q + 6];
                    let ql4 = q + 40;
                    let ok = qs == dst && match qnh {
                        6 | 17 => {
                            let (sp, dp) = (u16::from_be_bytes([ip[ql4], ip[ql4 + 1]]), u16::from_be_bytes([ip[ql4 + 2], ip[ql4 + 3]]));
                            self.flow_match(&qs, &qd, qnh, sp, dp, now)
                        }
                        58 if ip.len() >= ql4 + 8 && ip[ql4] == 128 => {
                            let id = u16::from_be_bytes([ip[ql4 + 4], ip[ql4 + 5]]);
                            self.flow_match(&qs, &qd, 58, id, id, now)
                        }
                        _ => false,
                    };
                    if ok {
                        self.stats.in_icmp_err += 1;
                    }
                    ok
                } else {
                    false
                }
            }
        };
        if !allowed {
            self.stats.drop_no_flow += 1;
            return WanAction::Drop;
        }
        let Some(mac) = self.lookup(&dst, now) else {
            self.stats.drop_no_neigh += 1;
            return WanAction::Drop;
        };
        out[0..6].copy_from_slice(&mac);
        out[6..12].copy_from_slice(&self.mac);
        out[12..14].copy_from_slice(&0x86ddu16.to_be_bytes());
        out[14..14 + ip.len()].copy_from_slice(ip);
        out[14 + 7] -= 1;
        self.stats.in_fwd += 1;
        WanAction::Deliver(14 + ip.len())
    }
}
