//! M-NAT0 — the wired UPLINK: lease an IP over DHCP, resolve + ping the gateway,
//! then ping an internet host, over a raw-frame NIC. Operator topology (2026-09-11):
//! **end0 (RP1 GEM) is ALWAYS the WAN; eth1 (RTL8111H) is the LAN.** So the uplink
//! runs over the GEM — whose datapath is metal-proven (M4 bridge) — and the WiFi-AP
//! + eth1-LAN clients are what M-NAT1+ forward through it. The RTL path is kept as
//! a second `Nic` so the same code can prove `rtl8111::tx_frame` when eth1 has a
//! link partner (it has NEVER transmitted on metal; P9 proved RX only).
//!
//! Every builder/parser is the WiFi STA's (`cyw43.rs`, metal-proven twice) — only
//! the link layer differs: both NICs are polled DMA rings with no dry-read cost, so
//! waits are wall-clock (cntpct) deadlines.
//!
//! Review-driven hardening (2026-09-11, uplink/NAT deep review): the GEM is
//! PROMISCUOUS, so `parse_dhcp_reply` matches xid + chaddr + L2 dst (a stale or
//! foreign OFFER/ACK must never be adopted — that would squat a customer's IP on
//! the fortress LAN); the ring is drained and RSR.BNA recovered before the DISCOVER
//! (nobody polled it since P8); a gratuitous ARP announces the lease and
//! `wan_poll` answers the gateway's ARP probes so the neighbour entry never goes
//! FAILED and blackholes the return traffic.

use crate::cyw43::{build_arp, build_dhcp, build_icmp_echo, parse_dhcp_reply, parse_ping_reply, DhcpResult};
use crate::{gem, rtl8111};

/// Which raw-frame NIC carries the uplink.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Nic {
    /// RP1 GEM `end0` — the WAN. Promiscuous (NCFGR CAF), so the station address
    /// is only what we PUT in our frames; rings are armed by the P8 GEM phase.
    End0,
    /// RTL8111H `eth1` — the LAN port. `set_mac` programs IDR so RXCFG MyPhys
    /// accepts unicast replies.
    Eth1,
}

/// end0's identity — the same LAA the M4 MetalBridge answers ARP for on this wire.
pub const END0_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x02];
/// eth1's identity (the 8111H eFuse MAC reads all-zero on this carrier).
pub const ETH1_MAC: [u8; 6] = [0x02, 0x43, 0x45, 0x48, 0x51, 0x4c];

/// Per-stage wait (dnsmasq / ARP / 8.8.8.8 answer in ms; this bounds the failure case).
const WAIT_MS: u64 = 5_000;
/// Retransmit the lossy request every second of dry polling.
const RETX_MS: u64 = 1_000;

#[inline]
fn cntpct() -> u64 {
    let v: u64;
    unsafe { core::arch::asm!("mrs {}, cntpct_el0", out(reg) v, options(nomem, nostack)) };
    v
}
#[inline]
fn ticks_ms(ms: u64) -> u64 {
    let f: u64;
    unsafe { core::arch::asm!("mrs {}, cntfrq_el0", out(reg) f, options(nomem, nostack)) };
    f.max(1).saturating_mul(ms) / 1000
}

fn nic_ready(nic: Nic) -> bool {
    match nic {
        Nic::End0 => true, // rings armed by cm5_gem_rx_demo (P8) before any P10/P11 work
        Nic::Eth1 => rtl8111::started(),
    }
}
fn nic_link(nic: Nic) -> bool {
    match nic {
        Nic::End0 => gem::phy_link_up(0),
        Nic::Eth1 => rtl8111::link_up(),
    }
}
// ---------------------------------------------------------------- WAN link layer (task #26)
// end0 carries up to two sub-interfaces: the INTERNET one (every WAN mode — DHCP, static, PPPoE — rides
// it, tagged per WAN.TXT `vlan=` / `vlan_outer=`) and an optional MANAGEMENT one (`mgmt_vlan=`). All
// end0 TX/RX goes through nic_tx / nic_rx, so tagging lives here: TX pushes the internet tag stack; RX
// demultiplexes by VLAN — internet frames are untagged and returned, management frames are queued for the
// management stack, anything else (another VLAN, or untagged when the internet is tagged) is DROPPED and
// counted. A frame of the wrong VLAN never reaches a stack.

/// The internet sub-interface's encapsulation (tags only; `pppoe` is informational here).
pub static mut LINK: hal::policy::Encap = hal::policy::Encap { vlan: 0, outer: 0, pcp: 0, pppoe: false };
/// Management sub-interface VLAN (0 = none). Single 802.1Q tag.
pub static mut MGMT_VLAN: u16 = 0;
/// Last time (ms) any frame arrived on the INTERNET sub-interface — WAN liveness for metric failover.
pub static mut WAN_LAST_RX_MS: u64 = 0;
/// [internet rx, mgmt rx, other-VLAN dropped, untagged dropped (internet is tagged), tagged tx, mgmt queue full]
pub static mut LINK_DIAG: [u32; 6] = [0; 6];
const MQ_N: usize = 16;
static mut MGMT_Q: [[u8; 1600]; MQ_N] = [[0; 1600]; MQ_N];
static mut MGMT_QL: [usize; MQ_N] = [0; MQ_N];
static mut MGMT_QH: usize = 0;
static mut MGMT_QN: usize = 0;
static mut TAG_SCRATCH: [u8; 1600] = [0; 1600];

/// Configure the WAN link from WAN.TXT (before any WAN mode comes up). Tags => jumbo gate opened
/// (a tagged full-size frame is 1522/1526 B on the wire).
pub fn link_configure(l: &hal::WanLink) {
    unsafe {
        LINK = hal::policy::Encap { vlan: l.vlan, outer: l.outer, pcp: l.pcp, pppoe: false };
        MGMT_VLAN = l.mgmt.map(|m| m.vlan).unwrap_or(0);
    }
    if l.vlan != 0 || l.mgmt.is_some() {
        gem::enable_vlan_frames();
    }
}

/// Transmit `f` (an untagged Ethernet frame) on end0 with the tag stack `e`.
fn tagged_tx(e: &hal::policy::Encap, f: &[u8]) -> bool {
    if e.tag_len() == 0 {
        return gem::tx_frame(f).is_some();
    }
    if f.len() < 14 || f.len() + e.tag_len() > 1600 {
        return false;
    }
    let sc = unsafe { &mut *core::ptr::addr_of_mut!(TAG_SCRATCH) };
    sc[..12].copy_from_slice(&f[..12]);
    let o = e.push_tags(sc, u16::from_be_bytes([f[12], f[13]]));
    let n = o + f.len() - 14;
    sc[o..n].copy_from_slice(&f[14..]);
    unsafe { LINK_DIAG[4] += 1 };
    gem::tx_frame(&sc[..n]).is_some()
}

/// WAN liveness probe (DHCP / static): an ARP request for the gateway on the internet sub-interface, so a
/// quiet but healthy link still shows traffic (its reply stamps WAN_LAST_RX_MS). PPPoE needs none — its
/// LCP echo does the same.
pub fn wan_probe(up: &UplinkResult) {
    if up.mode == 2 || !up.usable() || up.dhcp.router == [0; 4] {
        return;
    }
    let mut o = [0u8; 64];
    let n = arp_frame(&mut o, 1, &up.mac, &up.dhcp.yiaddr, &[0; 6], &up.dhcp.router, &[0xff; 6]);
    let _ = nic_tx(up.nic, &o[..n]);
}

/// Is the internet sub-interface alive: a usable lease AND a frame received within `window_ms`.
pub fn wan_alive(up: &UplinkResult, window_ms: u64) -> bool {
    up.usable() && ms_now().wrapping_sub(unsafe { WAN_LAST_RX_MS }) < window_ms
}

/// Transmit an untagged Ethernet frame on the MANAGEMENT sub-interface (802.1Q `mgmt_vlan`).
pub fn mgmt_tx(f: &[u8]) -> bool {
    let (v, pcp) = unsafe { (MGMT_VLAN, LINK.pcp) };
    if v == 0 {
        return false;
    }
    tagged_tx(&hal::policy::Encap { vlan: v, outer: 0, pcp, pppoe: false }, f)
}

/// Next queued management-sub-interface frame (untagged), if any.
pub fn mgmt_rx(out: &mut [u8]) -> Option<usize> {
    unsafe {
        if MGMT_QN == 0 {
            return None;
        }
        let i = MGMT_QH;
        let n = MGMT_QL[i].min(out.len());
        out[..n].copy_from_slice(&MGMT_Q[i][..n]);
        MGMT_QH = (MGMT_QH + 1) % MQ_N;
        MGMT_QN -= 1;
        Some(n)
    }
}

/// The management sub-interface's IPv4 stack (static address; DHCP on management is a follow-up).
#[derive(Clone, Copy, Debug)]
pub struct Mgmt {
    pub ip: [u8; 4],
    pub prefix: u8,
    pub gw: [u8; 4],
    pub gw_mac: Option<[u8; 6]>,
    pub mac: [u8; 6],
    last_arp: u64,
    /// Next hops other than the default gateway (routes `via mgmt gw X`): a small ARP cache.
    pub nh: [([u8; 4], [u8; 6]); 4],
    nh_last_arp: u64,
    /// `mgmt=dhcp`: the client state. None = static address.
    pub dhcp: Option<MgmtDhcp>,
    /// [ARP answered, gateway ARP sent, ping answered, ping blocked, ping dropped, handed up (NAT), dropped]
    pub stats: [u32; 7],
}
pub static mut MGMT: Option<Mgmt> = None;

pub fn mgmt_configure(m: &hal::MgmtIf) -> bool {
    match m.stat {
        Some((ip, prefix, gw)) => {
            unsafe { MGMT = Some(Mgmt { ip, prefix, gw, gw_mac: None, mac: END0_MAC, last_arp: 0, nh: [([0; 4], [0; 6]); 4], nh_last_arp: 0, dhcp: None, stats: [0; 7] }) };
            true
        }
        None => {
            // `mgmt=dhcp`: no address until the DORA on the management VLAN completes (mgmt_poll).
            let xid = (cntpct() as u32 ^ 0x6d67_6d74).to_be_bytes();
            unsafe {
                MGMT = Some(Mgmt {
                    ip: [0; 4], prefix: 0, gw: [0; 4], gw_mac: None, mac: END0_MAC, last_arp: 0,
                    nh: [([0; 4], [0; 6]); 4], nh_last_arp: 0,
                    dhcp: Some(MgmtDhcp { phase: 0, xid, offer: [0; 4], server: [0; 4], last_tx: 0, bound_at: 0, lease_s: 0, acks: 0, naks: 0 }),
                    stats: [0; 7],
                })
            };
            true
        }
    }
}

/// DHCP client state of the management sub-interface (`mgmt=dhcp`).
#[derive(Clone, Copy, Debug)]
pub struct MgmtDhcp {
    /// 0 = discovering, 1 = requesting the offer, 2 = bound.
    pub phase: u8,
    xid: [u8; 4],
    offer: [u8; 4],
    server: [u8; 4],
    last_tx: u64,
    bound_at: u64,
    pub lease_s: u32,
    pub acks: u32,
    pub naks: u32,
}

/// Non-blocking DHCP client step for the management sub-interface: (re)transmit DISCOVER/REQUEST every
/// 2 s; renew (REQUEST the bound address) at T1 = lease/2. `rx` = a received management frame, if any.
/// Returns true if `rx` was a DHCP reply consumed here.
fn mgmt_dhcp_step(m: &mut Mgmt, rx: Option<&[u8]>, now: u64) -> bool {
    let Some(mut d) = m.dhcp else { return false };
    let mut consumed = false;
    if let Some(f) = rx {
        let mut r = DhcpResult::new();
        let mt = parse_dhcp_reply(f, &d.xid, &m.mac, &mut r);
        if mt != 0 {
            consumed = true;
            match mt {
                2 if d.phase == 0 => {
                    d.offer = r.yiaddr;
                    d.server = r.server;
                    d.phase = 1;
                    d.last_tx = 0; // REQUEST now
                }
                5 if d.phase >= 1 => {
                    let mask = u32::from_be_bytes(r.mask);
                    m.ip = r.yiaddr;
                    m.prefix = if mask == 0 { 24 } else { mask.count_ones() as u8 };
                    if r.router != m.gw {
                        m.gw_mac = None; // a new gateway: resolve it again
                    }
                    m.gw = r.router;
                    d.lease_s = if r.lease == 0 { 3600 } else { r.lease };
                    d.bound_at = now;
                    d.phase = 2;
                    d.acks += 1;
                }
                6 => {
                    d.naks += 1;
                    d.phase = 0;
                    d.last_tx = 0;
                    m.ip = [0; 4];
                    m.gw_mac = None;
                }
                _ => {}
            }
        }
    }
    // Renewal at T1 (lease/2): REQUEST the bound address again (a NAK restarts DORA).
    if d.phase == 2 && now.wrapping_sub(d.bound_at) >= (d.lease_s as u64 / 2) * 1000 {
        d.phase = 1;
        d.offer = m.ip;
        d.last_tx = 0;
    }
    if d.phase < 2 && (d.last_tx == 0 || now.wrapping_sub(d.last_tx) >= 2000) {
        let mut o = [0u8; 600];
        let none = [0u8; 4];
        let n = if d.phase == 0 { build_dhcp(&mut o, &m.mac, &d.xid, 1, &none, &none) } else { build_dhcp(&mut o, &m.mac, &d.xid, 3, &d.offer, &d.server) };
        let _ = mgmt_tx(&o[..n]);
        d.last_tx = now.max(1);
    }
    m.dhcp = Some(d);
    consumed
}

/// MAC of next hop `ip` on the management sub-interface: the default gateway or a cached one; on a
/// miss an ARP request goes out (at most once a second) and None is returned — the caller drops this
/// packet (TCP retries) rather than queueing.
pub fn mgmt_nexthop(ip: [u8; 4]) -> Option<[u8; 6]> {
    let m = unsafe { (*core::ptr::addr_of_mut!(MGMT)).as_mut()? };
    if ip == m.gw {
        if let Some(g) = m.gw_mac {
            return Some(g);
        }
    }
    if let Some(e) = m.nh.iter().find(|e| e.0 == ip && e.1 != [0; 6]) {
        return Some(e.1);
    }
    let now = ms_now();
    if now.wrapping_sub(m.nh_last_arp) >= 1000 {
        m.nh_last_arp = now;
        let mut o = [0u8; 64];
        let n = arp_frame(&mut o, 1, &m.mac, &m.ip, &[0; 6], &ip, &[0xff; 6]);
        let _ = mgmt_tx(&o[..n]);
        m.stats[1] += 1;
    }
    None
}

pub enum MgmtEvent {
    Idle,
    /// An IPv4 frame for the management address the stack does not answer itself (NAT replies for
    /// routes via mgmt): `buf[..n]`, untagged.
    Frame(usize),
}

fn arp_frame(o: &mut [u8], op: u16, smac: &[u8; 6], sip: &[u8; 4], tmac: &[u8; 6], tip: &[u8; 4], dst: &[u8; 6]) -> usize {
    o[0..6].copy_from_slice(dst);
    o[6..12].copy_from_slice(smac);
    o[12..14].copy_from_slice(&0x0806u16.to_be_bytes());
    o[14..22].copy_from_slice(&[0, 1, 8, 0, 6, 4, 0, op as u8]);
    o[22..28].copy_from_slice(smac);
    o[28..32].copy_from_slice(sip);
    o[32..38].copy_from_slice(tmac);
    o[38..42].copy_from_slice(tip);
    o[42..60].fill(0);
    60
}

/// Service the management sub-interface: ARP, gateway resolution, ping (policy-checked by `decide`).
/// `decide` returns the policy action for a packet arriving on mgmt (Allow / Block / Drop).
pub fn mgmt_poll(buf: &mut [u8], decide: &mut dyn FnMut(&[u8]) -> hal::policy::Act) -> MgmtEvent {
    use hal::policy::Act;
    let Some(m) = (unsafe { (*core::ptr::addr_of_mut!(MGMT)).as_mut() }) else { return MgmtEvent::Idle };
    let mut o = [0u8; 1600];
    let now = ms_now();
    // `mgmt=dhcp`: no address yet (or renewing) — run the client; replies are consumed there.
    if m.dhcp.is_some() {
        let got = mgmt_rx(buf);
        let consumed = mgmt_dhcp_step(m, got.map(|n| &buf[..n]), now);
        if m.ip == [0; 4] {
            return MgmtEvent::Idle; // nothing else is served without an address
        }
        if consumed || got.is_none() {
            return MgmtEvent::Idle;
        }
        // a non-DHCP frame while bound: fall through with it
        return mgmt_frame(m, buf, got.unwrap(), now, decide, &mut o);
    }
    if m.gw_mac.is_none() && m.ip != [0; 4] && now.wrapping_sub(m.last_arp) >= 2000 {
        m.last_arp = now;
        let n = arp_frame(&mut o, 1, &m.mac, &m.ip, &[0; 6], &m.gw, &[0xff; 6]);
        let _ = mgmt_tx(&o[..n]);
        m.stats[1] += 1;
    }
    let Some(n) = mgmt_rx(buf) else { return MgmtEvent::Idle };
    mgmt_frame(m, buf, n, now, decide, &mut o)
}

/// One received management frame (untagged, `buf[..n]`): ARP, ping under `decide`, else handed up.
fn mgmt_frame(m: &mut Mgmt, buf: &mut [u8], n: usize, now: u64, decide: &mut dyn FnMut(&[u8]) -> hal::policy::Act, o: &mut [u8; 1600]) -> MgmtEvent {
    use hal::policy::Act;
    if m.gw_mac.is_none() && m.ip != [0; 4] && now.wrapping_sub(m.last_arp) >= 2000 {
        m.last_arp = now;
        let k = arp_frame(o, 1, &m.mac, &m.ip, &[0; 6], &m.gw, &[0xff; 6]);
        let _ = mgmt_tx(&o[..k]);
        m.stats[1] += 1;
    }
    if n >= 42 && buf[12..14] == [0x08, 0x06] {
        let op = u16::from_be_bytes([buf[20], buf[21]]);
        let (smac, sip, tip) = (&buf[22..28], &buf[28..32], &buf[38..42]);
        if op == 1 && tip == m.ip {
            let (mut sm, mut si) = ([0u8; 6], [0u8; 4]);
            sm.copy_from_slice(smac);
            si.copy_from_slice(sip);
            let k = arp_frame(&mut o[..], 2, &m.mac, &m.ip, &sm, &si, &sm);
            let _ = mgmt_tx(&o[..k]);
            m.stats[0] += 1;
        }
        let mut g = [0u8; 6];
        g.copy_from_slice(smac);
        if sip == m.gw && op == 2 {
            m.gw_mac = Some(g); // replies only: unsolicited ARP must not repoint the gateway (peer review L4)
        } else if op == 2 && sip != m.gw {
            // cache an answered next hop on our subnet (LRU-free: replace a matching or the first free slot)
            let mask: u32 = u32::MAX << (32 - m.prefix as u32);
            let si = [sip[0], sip[1], sip[2], sip[3]];
            if u32::from_be_bytes(si) & mask == u32::from_be_bytes(m.ip) & mask {
                let k = m.nh.iter().position(|e| e.0 == si).or_else(|| m.nh.iter().position(|e| e.1 == [0; 6])).unwrap_or(0);
                m.nh[k] = (si, g);
            }
        }
        return MgmtEvent::Idle;
    }
    if n < 34 || buf[12..14] != [0x08, 0x00] || buf[30..34] != m.ip || buf[0..6] != m.mac {
        m.stats[6] += 1;
        return MgmtEvent::Idle;
    }
    let ihl = ((buf[14] & 0x0f) as usize) * 4;
    let tot = u16::from_be_bytes([buf[16], buf[17]]) as usize;
    // Peer review 2026-11-06 H2: a total length < IHL+8 made the echo-reply checksum slice inverted (a
    // remote panic from the management VLAN). Validate the whole header before touching it.
    if buf[14] >> 4 != 4 || ihl < 20 || tot < ihl + 8 || 14 + tot > n {
        m.stats[6] += 1;
        return MgmtEvent::Idle;
    }
    if buf[23] == 1 && buf[14 + ihl] == 8 {
        match decide(&buf[..n]) {
            Act::Allow => {
                // Echo reply: swap MACs/IPs, type 0, fresh checksums.
                o[..n].copy_from_slice(&buf[..n]);
                o[0..6].copy_from_slice(&buf[6..12]);
                o[6..12].copy_from_slice(&m.mac);
                o[26..30].copy_from_slice(&buf[30..34]);
                o[30..34].copy_from_slice(&buf[26..30]);
                o[22] = 64;
                o[24] = 0;
                o[25] = 0;
                let c = hal::inet_csum(&o[14..14 + ihl], 0);
                o[24..26].copy_from_slice(&c.to_be_bytes());
                let ic = 14 + ihl;
                o[ic] = 0;
                o[ic + 2] = 0;
                o[ic + 3] = 0;
                let c = hal::inet_csum(&o[ic..14 + tot], 0);
                o[ic + 2..ic + 4].copy_from_slice(&c.to_be_bytes());
                let _ = mgmt_tx(&o[..14 + tot]);
                m.stats[2] += 1;
            }
            Act::Block => {
                if let Some(k) = crate::reject::reject4(&buf[..n], &m.ip, &m.mac, &mut o[..]) {
                    let _ = mgmt_tx(&o[..k]);
                }
                m.stats[3] += 1;
            }
            Act::Drop => m.stats[4] += 1,
        }
        return MgmtEvent::Idle;
    }
    m.stats[5] += 1;
    MgmtEvent::Frame(n)
}

fn end0_rx(out: &mut [u8]) -> Option<usize> {
    let (e, mv) = unsafe { (LINK, MGMT_VLAN) };
    // Bounded: a burst of other-VLAN frames must not starve the caller — but large enough that a few
    // management / foreign-VLAN frames do not end the WAN drain early (peer review COR-L2).
    for _ in 0..64 {
        // A GEM descriptor with no length is "no valid frame" (L-13), not a frame.
        let len = gem::poll_rx(out).and_then(|(len, _, _, _, _)| if len > 0 { Some(len) } else { None })?;
        let len = len.min(out.len());
        if e.tag_len() == 0 && mv == 0 {
            unsafe { WAN_LAST_RX_MS = ms_now() };
            return Some(len); // untagged link: the pre-#26 path (+ the liveness stamp)
        }
        let Some((outer, vid, off)) = hal::policy::rx_tags(&out[..len]) else { continue };
        let strip = |out: &mut [u8]| -> usize {
            out.copy_within(off..len, 12);
            len - (off - 12)
        };
        if outer == e.outer && vid == e.vlan {
            unsafe {
                LINK_DIAG[0] += 1;
                WAN_LAST_RX_MS = ms_now();
            }
            return Some(if off == 12 { len } else { strip(out) });
        }
        // Management = a single 802.1Q tag (TPID 0x8100) only — a lone 802.1ad S-tag carrying the same VID is a
        // different (provider) identity and is never management (peer review SEC-L6).
        if mv != 0 && outer == 0 && vid == mv && off == 16 && out[12] == 0x81 && out[13] == 0x00 {
            let n = strip(out);
            unsafe { LINK_DIAG[1] += 1 };
            // Only what the management stack can act on: ARP, or unicast to our MAC. Multicast / IPv6 ND /
            // other hosts' unicast on the management VLAN never occupy the queue (it filled at boot, metal
            // 2026-11-05: mgmtq full=18).
            let is_arp = n >= 14 && out[12] == 0x08 && out[13] == 0x06;
            // DHCP replies may be broadcast (bootp broadcast flag): UDP to port 68.
            let is_dhcp = n >= 42 && out[12] == 0x08 && out[13] == 0x00 && out[23] == 17 && {
                let l4 = 14 + ((out[14] & 0x0f) as usize) * 4;
                l4 + 4 <= n && out[l4 + 2] == 0 && out[l4 + 3] == 68
            };
            if !(is_arp || is_dhcp || out[0..6] == END0_MAC) {
                continue;
            }
            unsafe {
                if MGMT_QN == MQ_N {
                    LINK_DIAG[5] += 1;
                } else {
                    let j = (MGMT_QH + MGMT_QN) % MQ_N;
                    let k = n.min(1600);
                    MGMT_Q[j][..k].copy_from_slice(&out[..k]);
                    MGMT_QL[j] = k;
                    MGMT_QN += 1;
                }
            }
            continue;
        }
        unsafe { LINK_DIAG[if off == 12 { 3 } else { 2 }] += 1 };
    }
    None
}

fn nic_tx(nic: Nic, f: &[u8]) -> bool {
    match nic {
        Nic::End0 => tagged_tx(&unsafe { LINK }, f),
        Nic::Eth1 => rtl8111::tx_frame(f),
    }
}
fn nic_rx(nic: Nic, out: &mut [u8]) -> Option<usize> {
    match nic {
        Nic::End0 => end0_rx(out),
        Nic::Eth1 => rtl8111::rx_next(out),
    }
}

pub struct UplinkResult {
    pub nic: Nic,
    /// WAN mode in use: 0 DHCP, 1 static, 2 PPPoE.
    pub mode: u8,
    /// PPPoE configured but this build has no PPPoE client yet (stage 2).
    pub pppoe_unsupported: bool,
    pub started: bool,
    pub link: bool,
    pub mac: [u8; 6], // the station address in use (IDR read-back on eth1)
    pub mac_ok: bool,
    pub stale_drained: u32, // frames drained off the ring before the DISCOVER
    pub bna_recovered: bool, // RSR.BNA was latched (ring full) and RE was bounced
    pub rsr_before: u32,
    pub tx_err: u32,        // GEM LAST_TX_ERR (TSR at timeout; TGO alone = "timeout, TSR clean")
    pub tx_retried: bool,   // the first DISCOVER timed out and a second tx_frame was attempted
    pub dhcp: DhcpResult,
    pub rx_frames: u32, // every frame drained off the ring during the waits
    pub garp_tx: bool,  // gratuitous ARP announcing the lease
    pub gw_mac: [u8; 6],
    pub arp_tx: bool,
    pub arp_reply: bool,
    pub gw_ping_tx: bool,
    pub gw_ping_reply: bool,
    pub gw_ttl: u8,
    pub inet_ip: [u8; 4],
    pub inet_ping_tx: bool,
    pub inet_ping_reply: bool,
    pub inet_ttl: u8,
}

impl UplinkResult {
    pub fn new(nic: Nic) -> Self {
        UplinkResult {
            nic, mode: 0, pppoe_unsupported: false, started: false, link: false, mac: [0; 6], mac_ok: false,
            stale_drained: 0, bna_recovered: false, rsr_before: 0, tx_err: 0, tx_retried: false,
            dhcp: DhcpResult::new(),
            rx_frames: 0, garp_tx: false, gw_mac: [0; 6], arp_tx: false, arp_reply: false,
            gw_ping_tx: false, gw_ping_reply: false, gw_ttl: 0,
            inet_ip: [0; 4], inet_ping_tx: false, inet_ping_reply: false, inet_ttl: 0,
        }
    }
    /// A usable uplink: leased + gateway resolved (internet reach is reported, not required).
    pub fn usable(&self) -> bool {
        self.dhcp.ack_rx && self.arp_reply
    }
}

/// Drain the NIC's RX ring for up to `wait_ms`, handing every frame to `f` until it
/// returns true. `retx` is re-sent every `RETX_MS` of waiting.
fn rx_wait(out: &mut UplinkResult, retx: &[u8], wait_ms: u64, mut f: impl FnMut(&[u8], &mut UplinkResult) -> bool) -> bool {
    let nic = out.nic;
    let mut buf = [0u8; 2048];
    let start = cntpct();
    let deadline = start + ticks_ms(wait_ms);
    let mut next_retx = start + ticks_ms(RETX_MS);
    loop {
        let now = cntpct();
        if now >= deadline {
            return false;
        }
        if now >= next_retx {
            let _ = nic_tx(nic, retx);
            next_retx = now + ticks_ms(RETX_MS);
        }
        match nic_rx(nic, &mut buf) {
            Some(len) => {
                let n = len.min(buf.len());
                if n < 14 {
                    continue;
                }
                out.rx_frames += 1;
                if f(&buf[..n], out) {
                    return true;
                }
            }
            None => core::hint::spin_loop(),
        }
    }
}

/// Establish the NIC's station address. eth1 programs IDR; end0 is promiscuous so
/// the identity is simply the MAC we source from.
fn establish_mac(nic: Nic, out: &mut UplinkResult) {
    match nic {
        Nic::End0 => {
            out.mac = END0_MAC;
            out.mac_ok = true;
        }
        Nic::Eth1 => {
            out.mac = rtl8111::set_mac(&ETH1_MAC);
            out.mac_ok = out.mac == ETH1_MAC;
        }
    }
}

/// Drain everything sitting in the RX ring (stale broadcast noise since the ring was
/// armed) and, on the GEM, recover a latched buffer-not-available condition.
fn drain_ring(nic: Nic, out: &mut UplinkResult) {
    let mut buf = [0u8; 2048];
    let mut n = 0u32;
    while n < 512 && nic_rx(nic, &mut buf).is_some() {
        n += 1;
    }
    out.stale_drained = n;
    if nic == Nic::End0 {
        let (bna, rsr) = gem::rx_bna_recover();
        out.bna_recovered = bna;
        out.rsr_before = rsr;
    }
}

/// M-NAT0: bring `nic` to a leased, gateway-resolved state and prove internet
/// reach with an ICMP echo to `inet_ip`. Never blocks past the fixed deadlines;
/// every stage's outcome is in `out`.
/// Bring the WAN up in the operator-configured mode (WAN.TXT): DHCP (the default), a static
/// address, or PPPoE (stage 2 — reported as unsupported until it lands).
pub fn bringup_with(nic: Nic, inet_ip: &[u8; 4], mode: &hal::WanMode, out: &mut UplinkResult) {
    match *mode {
        hal::WanMode::Dhcp => bringup(nic, inet_ip, out),
        hal::WanMode::Static { ip, prefix, gw, dns } => {
            out.mode = 1;
            if !prelude(nic, inet_ip, out) {
                return;
            }
            // No DORA: the configured address IS the lease (lease = 0 => never renewed).
            let mask: u32 = u32::MAX << (32 - prefix as u32);
            out.dhcp.yiaddr = ip;
            out.dhcp.router = gw;
            out.dhcp.dns = dns;
            out.dhcp.mask = mask.to_be_bytes();
            out.dhcp.lease = 0;
            out.dhcp.ack_rx = true;
            post_lease(nic, inet_ip, out);
        }
        hal::WanMode::Pppoe { user, user_len, pass, pass_len } => {
            out.mode = 2;
            pppoe_bringup(nic, inet_ip, &user[..user_len as usize], &pass[..pass_len as usize], out);
        }
    }
}

/// The live PPPoE session (engine state: session id, AC, negotiated addresses, LCP state).
static mut PPP: Option<crate::pppoe::Pppoe> = None;
/// Scratch for PPPoE encap/decap (one frame at a time; the WAN path is single-threaded).
static mut PPP_SCRATCH: [u8; 2048] = [0; 2048];

fn ms_now() -> u64 {
    let f: u64;
    unsafe { core::arch::asm!("mrs {}, cntfrq_el0", out(reg) f, options(nomem, nostack)) };
    cntpct().saturating_mul(1000) / f.max(1)
}

/// Snapshot of the PPPoE session for the operator's log:
/// (phase, why, sid, ac_mac, my_ip, peer_ip, dns1, dns2, auth protocol, stats).
pub fn pppoe_info() -> Option<(crate::pppoe::Phase, crate::pppoe::DownWhy, u16, [u8; 6], [u8; 4], [u8; 4], [u8; 4], [u8; 4], u16, crate::pppoe::Stats)> {
    unsafe {
        (*core::ptr::addr_of!(PPP)).as_ref().map(|e| (e.phase, e.why, e.sid, e.ac_mac, e.my_ip, e.peer_ip, e.dns1, e.dns2, e.auth, e.stats))
    }
}

/// PPPoE bring-up: discovery -> LCP -> PAP/CHAP -> IPCP over the NIC (30 s budget), then the
/// negotiated address IS the lease (gateway = the PPP peer, next hop = the AC's MAC, MSS 1452),
/// and the peer + internet probe are pinged THROUGH the session.
fn pppoe_bringup(nic: Nic, inet_ip: &[u8; 4], user: &[u8], pass: &[u8], out: &mut UplinkResult) {
    use crate::pppoe::{Phase, Pppoe, Tx, PPPOE_MSS};
    if !prelude(nic, inet_ip, out) {
        return;
    }
    let seed = cntpct();
    let mut eng = Pppoe::new(out.mac, user, pass, seed as u32, (seed >> 11) as u32 ^ 0x5eed_c0de);
    let mut tx = Tx::new();
    eng.start(ms_now(), &mut tx);
    let deadline = cntpct() + ticks_ms(30_000);
    let mut buf = [0u8; 2048];
    loop {
        for i in 0..tx.n {
            let _ = nic_tx(nic, tx.frame(i));
        }
        tx.clear();
        if matches!(eng.phase, Phase::Open | Phase::Down) || cntpct() >= deadline {
            break;
        }
        match nic_rx(nic, &mut buf) {
            Some(n) if n >= 14 => {
                out.rx_frames += 1;
                eng.rx(&buf[..n.min(buf.len())], ms_now(), &mut tx);
            }
            _ => eng.tick(ms_now(), &mut tx),
        }
    }
    if eng.phase != Phase::Open {
        unsafe { PPP = Some(eng) };
        return;
    }
    out.dhcp.yiaddr = eng.my_ip;
    out.dhcp.router = eng.peer_ip;
    out.dhcp.dns = if eng.dns1 != [0; 4] { eng.dns1 } else { eng.dns2 };
    out.dhcp.mask = [255; 4];
    out.dhcp.lease = 0;
    out.dhcp.ack_rx = true;
    out.gw_mac = eng.ac_mac;
    out.arp_reply = true; // no ARP on a point-to-point link: the AC is the next hop
    crate::nat::set_mss_limit(PPPOE_MSS);
    // Ping the PPP peer, then the internet probe, through the session.
    let none = [0u8; 4];
    let mut small = [0u8; 128];
    let mut enc = [0u8; 160];
    for (k, dst) in [(1u16, eng.peer_ip), (2u16, *inet_ip)] {
        let id = 0x4e31u16;
        let n = build_icmp_echo(&mut small, &out.mac, &eng.ac_mac, &eng.my_ip, &dst, id, k);
        let Some(en) = eng.encap_ipv4(&small[..n], &mut enc) else { continue };
        let sent = nic_tx(nic, &enc[..en]);
        if k == 1 { out.gw_ping_tx = sent } else { out.inet_ping_tx = sent }
        let dl = cntpct() + ticks_ms(if k == 1 { WAIT_MS } else { WAIT_MS * 2 });
        let mut next_retx = cntpct() + ticks_ms(RETX_MS);
        let mut dec = [0u8; 2048];
        while cntpct() < dl {
            // Retransmit every second: the AC may still be configuring its side of the link.
            if cntpct() >= next_retx {
                let _ = nic_tx(nic, &enc[..en]);
                next_retx = cntpct() + ticks_ms(RETX_MS);
            }
            let Some(n) = nic_rx(nic, &mut buf) else { continue };
            let n = n.min(buf.len());
            if let Some(dn) = eng.decap_ipv4(&buf[..n], &mut dec) {
                let mut m = [0u8; 6];
                let (mut ttl, mut src) = (0u8, [0u8; 4]);
                if parse_ping_reply(&dec[..dn], &none, id, &mut m, &mut ttl, &mut src) == 2 && src == dst {
                    if k == 1 { out.gw_ping_reply = true; out.gw_ttl = ttl } else { out.inet_ping_reply = true; out.inet_ttl = ttl }
                    break;
                }
            } else {
                eng.rx(&buf[..n], ms_now(), &mut tx); // LCP echo etc. while we wait
                for i in 0..tx.n {
                    let _ = nic_tx(nic, tx.frame(i));
                }
                tx.clear();
            }
        }
    }
    pppoe_v6_probe(nic, &mut eng, out);
    unsafe { PPP = Some(eng) };
}

/// What the WAN v6 probe learned from the ISP (logged by the caller; nothing is configured from it
/// yet — the LAN side follows once we know what the ISP delegates).
#[derive(Clone, Copy, Debug)]
pub struct Wan6 {
    pub ran: bool,
    pub ip6cp_up: bool,
    pub ip6cp_off: bool,
    pub my_iid: [u8; 8],
    pub peer_iid: [u8; 8],
    pub rs_tx: u32,
    pub ra: Option<crate::ip6::Ra>,
    pub dhcp_tx: u32,
    pub dhcp_rx: u32,
    pub advertise: bool,
    pub reply: bool,
    pub status: u16,
    pub pd: Option<([u8; 16], u8, u32)>,
    pub dns: Option<[u8; 16]>,
    pub na: Option<[u8; 16]>,
    pub v6_frames_rx: u32,
    /// Renewal (RFC 8415 §18.2.4): IA_PD T1 (s), the server that delegated, the transaction, when the
    /// last Reply arrived (ms), Renews sent / Replies to them.
    pub t1: u32,
    pub sid: [u8; 64],
    pub sid_len: usize,
    pub xid: u32,
    pub got_ms: u64,
    pub renew_tx: u32,
    pub renew_ok: u32,
    pub last_renew_ms: u64,
}
pub static mut WAN6: Wan6 = Wan6 { ran: false, ip6cp_up: false, ip6cp_off: false, my_iid: [0; 8], peer_iid: [0; 8], rs_tx: 0, ra: None, dhcp_tx: 0, dhcp_rx: 0, advertise: false, reply: false, status: 0, pd: None, dns: None, na: None, v6_frames_rx: 0, t1: 0, sid: [0; 64], sid_len: 0, xid: 0, got_ms: 0, renew_tx: 0, renew_ok: 0, last_renew_ms: 0 };

/// IPv6 seen on the LIVE session (whole uptime, not just the 12-s probe): every v6 datagram and every
/// Router Advertisement from the ISP — answers "does Digi ever send an RA?" — plus WAN v6 TX outcomes.
/// [v6 rx, RAs rx, v6 tx ok, v6 tx fail]
pub static mut WAN6_LIVE: [u32; 4] = [0; 4];
pub static mut WAN6_FIRST_RA: Option<crate::ip6::Ra> = None;

/// IPv6 over the open PPPoE session — PROBE ONLY (12-s cap, never fatal, IPv4 already works):
/// wait for IPV6CP, Router Solicitation -> Router Advertisement (the WAN /64, M/O flags), then
/// DHCPv6 Solicit with IA_PD (+ Rapid Commit) -> Advertise -> Request -> Reply (the delegated prefix
/// for the LAN, DNS). Results in WAN6 for the [WAN6] log line.
fn pppoe_v6_probe(nic: Nic, eng: &mut crate::pppoe::Pppoe, out: &UplinkResult) {
    use crate::ip6;
    use crate::pppoe::Tx;
    let w = unsafe { &mut *core::ptr::addr_of_mut!(WAN6) };
    // Fresh state per dial (peer review COR-M3): a re-dial used to find reply=true from the last session,
    // skip RS/DHCPv6 entirely, and keep advertising the OLD delegated prefix on the LAN.
    *w = Wan6 { ran: true, ip6cp_up: false, ip6cp_off: false, my_iid: [0; 8], peer_iid: [0; 8], rs_tx: 0, ra: None, dhcp_tx: 0, dhcp_rx: 0, advertise: false, reply: false, status: 0, pd: None, dns: None, na: None, v6_frames_rx: 0, t1: 0, sid: [0; 64], sid_len: 0, xid: 0, got_ms: 0, renew_tx: 0, renew_ok: 0, last_renew_ms: 0 };
    let cap = cntpct() + ticks_ms(12_000);
    let mut buf = [0u8; 2048];
    let mut tx = Tx::new();
    // Service the engine (LCP echo, IPV6CP) on anything that is not session IPv6; return v6 packets.
    // 1. IPV6CP (it started with IPCP; give it up to 5 s more).
    let dl = cntpct() + ticks_ms(5_000);
    while !eng.ip6_up && !eng.ip6_off && cntpct() < dl.min(cap) {
        match nic_rx(nic, &mut buf) {
            Some(n) if n >= 14 => eng.rx(&buf[..n.min(buf.len())], ms_now(), &mut tx),
            _ => eng.tick(ms_now(), &mut tx),
        }
        for i in 0..tx.n {
            let _ = nic_tx(nic, tx.frame(i));
        }
        tx.clear();
    }
    w.ip6cp_up = eng.ip6_up;
    w.ip6cp_off = eng.ip6_off;
    w.my_iid = eng.my_iid;
    w.peer_iid = eng.peer_iid;
    if !eng.ip6_up {
        return;
    }
    let mut pkt = [0u8; 400];
    let mut enc = [0u8; 480];
    let xid = (cntpct() as u32) & 0x00ff_ffff | 0x0100_0000;
    let iaid = u32::from_be_bytes([out.mac[2], out.mac[3], out.mac[4], out.mac[5]]);
    // 2. RS (every 1.5 s, up to 3) until an RA; 3. DHCPv6 (every 2 s, up to 3 rounds).
    let mut next_rs = 0u64;
    let mut next_dhcp = 0u64;
    let mut sid = [0u8; 64];
    let mut sid_len = 0usize;
    let mut adv_pd: Option<([u8; 16], u8)> = None;
    while cntpct() < cap && !w.reply {
        let now = cntpct();
        if w.ra.is_none() && w.rs_tx < 3 && now >= next_rs {
            let n = ip6::build_rs(&eng.my_iid, &mut pkt);
            if let Some(en) = eng.encap_ipv6(&pkt[..n], &mut enc) {
                let _ = nic_tx(nic, &enc[..en]);
                w.rs_tx += 1;
            }
            next_rs = now + ticks_ms(1_500);
        }
        if w.dhcp_tx < 6 && now >= next_dhcp && (w.ra.is_some() || w.rs_tx >= 3) {
            // Solicit (+Rapid Commit) until an Advertise; then Request for the advertised prefix.
            let (msg, pd) = if w.advertise { (ip6::DHCP6_REQUEST, adv_pd) } else { (ip6::DHCP6_SOLICIT, None) };
            let n = ip6::build_dhcp6(msg, xid, &out.mac, &eng.my_iid, iaid, &sid[..sid_len], pd.as_ref().map(|(p, l)| (p, *l)), !w.advertise, &mut pkt);
            if let Some(en) = eng.encap_ipv6(&pkt[..n], &mut enc) {
                let _ = nic_tx(nic, &enc[..en]);
                w.dhcp_tx += 1;
            }
            next_dhcp = now + ticks_ms(2_000);
        }
        let Some(n) = nic_rx(nic, &mut buf) else {
            eng.tick(ms_now(), &mut tx);
            for i in 0..tx.n {
                let _ = nic_tx(nic, tx.frame(i));
            }
            tx.clear();
            continue;
        };
        let n = n.min(buf.len());
        let Some(ip) = eng.decap_ipv6(&buf[..n]) else {
            eng.rx(&buf[..n], ms_now(), &mut tx);
            for i in 0..tx.n {
                let _ = nic_tx(nic, tx.frame(i));
            }
            tx.clear();
            continue;
        };
        w.v6_frames_rx += 1;
        if let Some(ra) = ip6::parse_ra(ip) {
            if w.ra.is_none() {
                w.ra = Some(ra);
                next_dhcp = 0; // DHCPv6 right away
            }
            continue;
        }
        if let Some(d) = ip6::parse_dhcp6(ip, xid) {
            w.dhcp_rx += 1;
            if d.status != 0 {
                w.status = d.status;
            }
            if d.has_dns {
                w.dns = Some(d.dns);
            }
            if d.msg == ip6::DHCP6_ADVERTISE && !w.advertise {
                w.advertise = true;
                sid_len = d.sid_len;
                sid[..sid_len].copy_from_slice(&d.server_id[..sid_len]);
                if d.has_pd {
                    adv_pd = Some((d.prefix, d.plen));
                }
                next_dhcp = 0; // Request now
            } else if d.msg == ip6::DHCP6_REPLY {
                w.reply = true;
                w.t1 = d.t1;
                w.sid_len = sid_len.max(d.sid_len);
                if d.sid_len > 0 {
                    w.sid[..d.sid_len].copy_from_slice(&d.server_id[..d.sid_len]);
                    w.sid_len = d.sid_len;
                } else {
                    w.sid[..sid_len].copy_from_slice(&sid[..sid_len]);
                }
                w.xid = xid;
                w.got_ms = ms_now();
                if d.has_pd {
                    w.pd = Some((d.prefix, d.plen, d.valid));
                }
                if d.has_na {
                    w.na = Some(d.na);
                }
            }
        }
    }
}

/// DHCPv6 prefix-delegation RENEWAL (RFC 8415 §18.2.4; peer review COR-M3): at T1 after the last Reply,
/// send a Renew for the delegated prefix to the server that granted it, repeated at most every 10 s until
/// a Reply refreshes it (pppoe_poll). T1 = 0 (server's choice) -> renew at half the valid lifetime;
/// T1 = infinite (Digi) -> never. Call from the serve loop; cheap when nothing is due.
pub fn wan6_tick(up: &UplinkResult) {
    if up.mode != 2 {
        return;
    }
    let w = unsafe { &mut *core::ptr::addr_of_mut!(WAN6) };
    let Some((pfx, plen, valid)) = w.pd else { return };
    let t1 = if w.t1 == 0 { valid / 2 } else { w.t1 };
    if t1 == u32::MAX || valid == u32::MAX && w.t1 == 0 || w.sid_len == 0 {
        return;
    }
    let now = ms_now();
    if now.wrapping_sub(w.got_ms) < t1 as u64 * 1000 || (w.last_renew_ms != 0 && now.wrapping_sub(w.last_renew_ms) < 10_000) {
        return;
    }
    unsafe {
        let Some(e) = (*core::ptr::addr_of!(PPP)).as_ref() else { return };
        if !e.ip6_up {
            return;
        }
        let iaid = u32::from_be_bytes([up.mac[2], up.mac[3], up.mac[4], up.mac[5]]);
        let mut pkt = [0u8; 400];
        let n = crate::ip6::build_dhcp6(crate::ip6::DHCP6_RENEW, w.xid, &up.mac, &e.my_iid, iaid, &w.sid[..w.sid_len], Some((&pfx, plen)), false, &mut pkt);
        let sc = &mut *core::ptr::addr_of_mut!(PPP_SCRATCH);
        if let Some(en) = e.encap_ipv6(&pkt[..n], sc) {
            let _ = nic_tx(up.nic, &sc[..en]);
            w.renew_tx += 1;
        }
        w.last_renew_ms = now.max(1);
    }
}

/// Send a bare IPv6 packet into the PPPoE session (the LAN v6 router's forward path). PPPoE only.
pub fn wan_tx6(up: &UplinkResult, ip6: &[u8]) -> bool {
    if up.mode != 2 {
        return false;
    }
    unsafe {
        let Some(e) = (*core::ptr::addr_of!(PPP)).as_ref() else { return false };
        let sc = &mut *core::ptr::addr_of_mut!(PPP_SCRATCH);
        let ok = match e.encap_ipv6(ip6, sc) {
            Some(n) => nic_tx(up.nic, &sc[..n]),
            None => false,
        };
        WAN6_LIVE[if ok { 2 } else { 3 }] += 1;
        ok
    }
}

/// Send a WAN frame: as-is (DHCP/static), or wrapped in the PPPoE session (PPPoE).
/// WAN transmit failures split by cause: [0] IPv4 packet larger than the PPPoE MTU (1492) — never
/// reached the GEM; [1] the GEM itself did not complete the transmit; [2] IP length of the last
/// too-big packet; [3] last GEM TSR on failure.
pub static mut WAN_TX_DIAG: [u32; 4] = [0; 4];

pub fn wan_tx(up: &UplinkResult, f: &[u8]) -> bool {
    let ok = if up.mode == 2 {
        unsafe {
            let Some(e) = (*core::ptr::addr_of!(PPP)).as_ref() else { return false };
            let sc = &mut *core::ptr::addr_of_mut!(PPP_SCRATCH);
            match e.encap_ipv4(f, sc) {
                Some(n) => {
                    let r = nic_tx(up.nic, &sc[..n]);
                    if !r {
                        WAN_TX_DIAG[1] += 1;
                        WAN_TX_DIAG[3] = gem::tx_err_take();
                    }
                    return r;
                }
                None => {
                    WAN_TX_DIAG[0] += 1;
                    if f.len() >= 18 {
                        WAN_TX_DIAG[2] = u16::from_be_bytes([f[16], f[17]]) as u32;
                    }
                    false
                }
            }
        }
    } else {
        let r = nic_tx(up.nic, f);
        if !r {
            unsafe {
                WAN_TX_DIAG[1] += 1;
                WAN_TX_DIAG[3] = gem::tx_err_take();
            }
        }
        r
    };
    ok
}

/// PPPoE leg of wan_poll: session IPv4 is unwrapped into an Ethernet/IPv4 frame for the NAT;
/// LCP/discovery frames go to the engine (Echo-Reply, PADT/Terminate). A dropped session makes
/// the uplink unusable so the caller's retry path re-dials.
fn pppoe_poll(up: &mut UplinkResult, buf: &mut [u8]) -> WanEvent {
    use crate::pppoe::{Phase, Tx};
    let nic = up.nic;
    let n = match nic_rx(nic, buf) {
        Some(n) if n >= 14 => n.min(buf.len()),
        _ => {
            // Idle: run the keepalive clock (Echo-Request every 10 s, 3 misses => down => re-dial).
            unsafe {
                if let Some(e) = (*core::ptr::addr_of_mut!(PPP)).as_mut() {
                    let mut tx = Tx::new();
                    e.tick(ms_now(), &mut tx);
                    for i in 0..tx.n {
                        let _ = nic_tx(nic, tx.frame(i));
                    }
                    if e.phase == Phase::Down {
                        up.dhcp.ack_rx = false;
                    }
                }
            }
            return WanEvent::Idle;
        }
    };
    unsafe {
        let Some(e) = (*core::ptr::addr_of_mut!(PPP)).as_mut() else { return WanEvent::Idle };
        let sc = &mut *core::ptr::addr_of_mut!(PPP_SCRATCH);
        if let Some(dn) = e.decap_ipv4(&buf[..n], sc) {
            let k = dn.min(buf.len());
            buf[..k].copy_from_slice(&sc[..k]);
            return WanEvent::Frame(k);
        }
        // Session IPv6 -> an Ethernet/IPv6 frame (dst = us, src = the AC) for the LAN v6 router.
        if let Some(ip6) = e.decap_ipv6(&buf[..n]) {
            WAN6_LIVE[0] += 1;
            // A Reply to our Renew: refresh the delegation (and the T1 clock).
            let w = &mut *core::ptr::addr_of_mut!(WAN6);
            if w.pd.is_some() && w.renew_tx > 0 {
                if let Some(d) = crate::ip6::parse_dhcp6(ip6, w.xid) {
                    if d.msg == crate::ip6::DHCP6_REPLY && d.has_pd && d.status == 0 {
                        w.pd = Some((d.prefix, d.plen, d.valid));
                        w.t1 = d.t1;
                        w.got_ms = ms_now();
                        w.renew_ok += 1;
                        return WanEvent::Idle;
                    }
                }
            }
            if let Some(ra) = crate::ip6::parse_ra(ip6) {
                WAN6_LIVE[1] += 1;
                if WAN6_FIRST_RA.is_none() {
                    WAN6_FIRST_RA = Some(ra);
                }
            }
            let k = (14 + ip6.len()).min(sc.len());
            sc[0..6].copy_from_slice(&e.mac);
            sc[6..12].copy_from_slice(&e.ac_mac);
            sc[12..14].copy_from_slice(&0x86ddu16.to_be_bytes());
            sc[14..k].copy_from_slice(&ip6[..k - 14]);
            let k = k.min(buf.len());
            buf[..k].copy_from_slice(&sc[..k]);
            return WanEvent::Frame(k);
        }
        let mut tx = Tx::new();
        e.rx(&buf[..n], ms_now(), &mut tx);
        for i in 0..tx.n {
            let _ = nic_tx(nic, tx.frame(i));
        }
        if e.phase == Phase::Down {
            up.dhcp.ack_rx = false; // usable() false -> the AP loop re-dials
        }
    }
    WanEvent::Idle
}

/// Common start of every WAN mode: NIC up, link, our MAC, stale ring drained, TX re-armed.
fn prelude(nic: Nic, inet_ip: &[u8; 4], out: &mut UplinkResult) -> bool {
    out.nic = nic;
    out.inet_ip = *inet_ip;
    out.started = nic_ready(nic);
    if !out.started {
        return false;
    }
    out.link = nic_link(nic);
    establish_mac(nic, out);
    out.dhcp.mac = out.mac;
    if !out.link || !out.mac_ok {
        return false;
    }
    drain_ring(nic, out);
    if nic == Nic::End0 {
        // Re-arm the TX ring right before our first frame — exactly what cm5_prod_service
        // does before ITS first transmit (the metal-proven M4 bridge path). Metal 2026-09-11:
        // the P8 diag frames went out fine straight after P8's tx_init, but the first frame
        // sent ~40 s later (after P9/P10) timed out; prod never hit that because it re-inits.
        gem::tx_init();
        let _ = gem::tx_err_take(); // clear any stale latched error
    }
    true
}

pub fn bringup(nic: Nic, inet_ip: &[u8; 4], out: &mut UplinkResult) {
    if !prelude(nic, inet_ip, out) {
        return;
    }
    let mac = out.mac;

    // Per-boot xid from the cycle counter (as wifi_dhcp).
    let xid = (cntpct() as u32).to_be_bytes();
    let none = [0u8; 4];
    let mut pkt = [0u8; 400];

    // --- DISCOVER → OFFER (ours: xid + chaddr + L2 dst matched inside parse_dhcp_reply)
    let n = build_dhcp(&mut pkt, &mac, &xid, 1, &none, &none);
    out.dhcp.discover_tx = nic_tx(nic, &pkt[..n]);
    if !out.dhcp.discover_tx && nic == Nic::End0 {
        // One more try after the timeout path's own TE recovery, with the TSR captured.
        out.tx_err = gem::tx_err_take();
        out.dhcp.discover_tx = nic_tx(nic, &pkt[..n]);
        out.tx_retried = true;
    }
    if !out.dhcp.discover_tx {
        if nic == Nic::End0 && out.tx_err == 0 {
            out.tx_err = gem::tx_err_take();
        }
        return; // the TX primitive never completed
    }
    let disc = pkt;
    out.dhcp.offer_rx = rx_wait(out, &disc[..n], WAIT_MS, |eth, o| parse_dhcp_reply(eth, &xid, &mac, &mut o.dhcp) == 2);
    if !out.dhcp.offer_rx {
        return;
    }

    // --- REQUEST → ACK (a NAK ends this round; the caller may retry the whole DORA)
    let yi = out.dhcp.yiaddr;
    let sv = out.dhcp.server;
    let n = build_dhcp(&mut pkt, &mac, &xid, 3, &yi, &sv);
    out.dhcp.request_tx = nic_tx(nic, &pkt[..n]);
    let req = pkt;
    out.dhcp.ack_rx = rx_wait(out, &req[..n], WAIT_MS, |eth, o| {
        let mt = parse_dhcp_reply(eth, &xid, &mac, &mut o.dhcp);
        mt == 5 || mt == 6
    }) && !out.dhcp.nak_rx;
    if !out.dhcp.ack_rx {
        return;
    }
    post_lease(nic, inet_ip, out);
}

/// After an address is held (DHCP ACK, or a static configuration): announce it, resolve the
/// gateway, ping the gateway and the internet probe host.
fn post_lease(nic: Nic, inet_ip: &[u8; 4], out: &mut UplinkResult) {
    let mac = out.mac;
    let none = [0u8; 4];

    // Announce the lease (gratuitous ARP request: sender IP == target IP == ours) so the
    // segment's neighbour caches learn END0_MAC before any return traffic.
    let ip = out.dhcp.yiaddr;
    let mut small = [0u8; 128];
    let n = build_arp(&mut small, &mac, &ip, &ip);
    out.garp_tx = nic_tx(nic, &small[..n]);

    // --- ARP the gateway
    let gw = out.dhcp.router;
    if gw == [0; 4] {
        return; // no router option — nothing to route through
    }
    let n = build_arp(&mut small, &mac, &ip, &gw);
    out.arp_tx = nic_tx(nic, &small[..n]);
    let arp = small;
    out.arp_reply = rx_wait(out, &arp[..n], WAIT_MS, |eth, o| {
        let mut m = [0u8; 6];
        let (mut ttl, mut src) = (0u8, [0u8; 4]);
        if parse_ping_reply(eth, &gw, 0, &mut m, &mut ttl, &mut src) == 1 {
            o.gw_mac = m;
            true
        } else {
            false
        }
    });
    if !out.arp_reply {
        return;
    }

    // --- ICMP echo the gateway (on-link L3), then the internet host through it.
    let id = 0x4e30u16; // "N0"
    let gw_mac = out.gw_mac;
    let n = build_icmp_echo(&mut small, &mac, &gw_mac, &ip, &gw, id, 1);
    out.gw_ping_tx = nic_tx(nic, &small[..n]);
    let echo = small;
    out.gw_ping_reply = rx_wait(out, &echo[..n], WAIT_MS, |eth, o| {
        let mut m = [0u8; 6];
        let (mut ttl, mut src) = (0u8, [0u8; 4]);
        if parse_ping_reply(eth, &none, id, &mut m, &mut ttl, &mut src) == 2 && src == gw {
            o.gw_ttl = ttl;
            true
        } else {
            false
        }
    });

    let n = build_icmp_echo(&mut small, &mac, &gw_mac, &ip, inet_ip, id, 2);
    out.inet_ping_tx = nic_tx(nic, &small[..n]);
    let echo = small;
    let want = *inet_ip;
    out.inet_ping_reply = rx_wait(out, &echo[..n], WAIT_MS * 2, |eth, o| {
        let mut m = [0u8; 6];
        let (mut ttl, mut src) = (0u8, [0u8; 4]);
        if parse_ping_reply(eth, &none, id, &mut m, &mut ttl, &mut src) == 2 && src == want {
            o.inet_ttl = ttl;
            true
        } else {
            false
        }
    });
}

/// What one WAN poll produced.
pub enum WanEvent {
    Idle,
    ArpReplied,
    GwRefreshed,
    /// A non-ARP frame of `len` bytes is in the buffer (the NAT inbound path decides).
    Frame(usize),
}

/// WAN service for a leased uplink: read at most one frame off the NIC. Answers an ARP
/// request for our leased IP (the gateway's neighbour-cache probe — unanswered, the
/// fortress marks us FAILED within a minute or two and blackholes the return traffic),
/// refreshes `gw_mac` from any ARP the gateway sends, and hands every other frame back
/// for the NAT inbound path.
pub fn wan_poll(up: &mut UplinkResult, buf: &mut [u8]) -> WanEvent {
    if !up.dhcp.ack_rx {
        // Peer review COR-M2: the internet sub-interface is down, but end0 must still be read — the
        // management VLAN (its ARP / ping / replies of `route … via mgmt`, i.e. the failover path)
        // only receives through end0_rx. Internet frames are discarded here (no lease to own them).
        if up.nic == Nic::End0 && unsafe { MGMT_VLAN } != 0 {
            let _ = nic_rx(up.nic, buf);
        }
        return WanEvent::Idle;
    }
    if up.mode == 2 {
        return pppoe_poll(up, buf);
    }
    let nic = up.nic;
    let n = match nic_rx(nic, buf) {
        Some(n) => n.min(buf.len()),
        None => return WanEvent::Idle,
    };
    if n < 14 {
        return WanEvent::Idle;
    }
    if buf[12] != 0x08 || buf[13] != 0x06 {
        return WanEvent::Frame(n);
    }
    if n < 42 {
        return WanEvent::Idle;
    }
    let mac = up.mac;
    let ip = up.dhcp.yiaddr;
    let op = u16::from_be_bytes([buf[20], buf[21]]);
    let mut spa = [0u8; 4];
    spa.copy_from_slice(&buf[28..32]);
    if op == 1 && &buf[38..42] == &ip[..] {
        let mut rmac = [0u8; 6];
        rmac.copy_from_slice(&buf[22..28]);
        let mut reply = [0u8; 64];
        reply[0..6].copy_from_slice(&rmac);
        reply[6..12].copy_from_slice(&mac);
        reply[12] = 0x08;
        reply[13] = 0x06;
        reply[14] = 0x00; reply[15] = 0x01; reply[16] = 0x08; reply[17] = 0x00;
        reply[18] = 6; reply[19] = 4; reply[20] = 0x00; reply[21] = 0x02;
        reply[22..28].copy_from_slice(&mac);
        reply[28..32].copy_from_slice(&ip);
        reply[32..38].copy_from_slice(&rmac);
        reply[38..42].copy_from_slice(&spa);
        if nic_tx(nic, &reply[..60]) {
            return WanEvent::ArpReplied;
        }
        return WanEvent::Idle;
    }
    if spa == up.dhcp.router && buf[22..28] != up.gw_mac {
        up.gw_mac.copy_from_slice(&buf[22..28]); // gateway moved (VRRP/failover)
        return WanEvent::GwRefreshed;
    }
    // A reply from another on-subnet next hop (routes `via wan gw X`, COR-L5): cache it.
    if op == 2 && buf[0..6] == mac && spa != up.dhcp.router {
        let mask = u32::from_be_bytes(up.dhcp.mask);
        if mask != 0 && u32::from_be_bytes(spa) & mask == u32::from_be_bytes(ip) & mask {
            let c = unsafe { &mut *core::ptr::addr_of_mut!(WAN_NH) };
            let k = c.iter().position(|e| e.0 == spa).or_else(|| c.iter().position(|e| e.1 == [0; 6])).unwrap_or(0);
            let mut g = [0u8; 6];
            g.copy_from_slice(&buf[22..28]);
            c[k] = (spa, g);
        }
    }
    WanEvent::Idle
}

/// Next hops on the internet sub-interface other than the default gateway (routes `via wan gw X`).
static mut WAN_NH: [([u8; 4], [u8; 6]); 4] = [([0; 4], [0; 6]); 4];
static mut WAN_NH_LAST_ARP: u64 = 0;

/// MAC of next hop `gw` on the internet sub-interface (peer review COR-L5: `route … via wan gw X` used to
/// silently ignore X). The default gateway is answered directly; another one from the ARP cache, else an
/// ARP request goes out (at most 1/s) and None is returned (the packet is dropped; TCP retries). PPPoE:
/// point-to-point, every packet goes to the AC — the gateway is meaningless, the AC is returned.
pub fn wan_nexthop(up: &UplinkResult, gw: [u8; 4]) -> Option<[u8; 6]> {
    if up.mode == 2 || gw == up.dhcp.router || gw == [0; 4] {
        return Some(up.gw_mac);
    }
    let c = unsafe { &*core::ptr::addr_of!(WAN_NH) };
    if let Some(e) = c.iter().find(|e| e.0 == gw && e.1 != [0; 6]) {
        return Some(e.1);
    }
    let now = ms_now();
    if now.wrapping_sub(unsafe { WAN_NH_LAST_ARP }) >= 1000 {
        unsafe { WAN_NH_LAST_ARP = now };
        let mut o = [0u8; 64];
        let n = arp_frame(&mut o, 1, &up.mac, &up.dhcp.yiaddr, &[0; 6], &gw, &[0xff; 6]);
        let _ = nic_tx(up.nic, &o[..n]);
    }
    None
}

/// LAN-port status for eth1: program its station address and report the link.
/// heqk is the DHCP SERVER on this port (M-NAT1+), never a client.
pub fn eth1_lan_status() -> (bool, bool, [u8; 6]) {
    if !rtl8111::started() {
        return (false, false, [0; 6]);
    }
    let mac = rtl8111::set_mac(&ETH1_MAC);
    (true, rtl8111::link_up(), mac)
}
