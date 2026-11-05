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
fn nic_tx(nic: Nic, f: &[u8]) -> bool {
    match nic {
        Nic::End0 => gem::tx_frame(f).is_some(),
        Nic::Eth1 => rtl8111::tx_frame(f),
    }
}
fn nic_rx(nic: Nic, out: &mut [u8]) -> Option<usize> {
    match nic {
        // A GEM descriptor with no length is "no valid frame" (L-13), not a frame.
        Nic::End0 => gem::poll_rx(out).and_then(|(len, _, _, _, _)| if len > 0 { Some(len) } else { None }),
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
        let mut dec = [0u8; 2048];
        while cntpct() < dl {
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
    unsafe { PPP = Some(eng) };
}

/// Send a WAN frame: as-is (DHCP/static), or wrapped in the PPPoE session (PPPoE).
pub fn wan_tx(up: &UplinkResult, f: &[u8]) -> bool {
    if up.mode == 2 {
        unsafe {
            let Some(e) = (*core::ptr::addr_of!(PPP)).as_ref() else { return false };
            let sc = &mut *core::ptr::addr_of_mut!(PPP_SCRATCH);
            match e.encap_ipv4(f, sc) {
                Some(n) => nic_tx(up.nic, &sc[..n]),
                None => false,
            }
        }
    } else {
        nic_tx(up.nic, f)
    }
}

/// PPPoE leg of wan_poll: session IPv4 is unwrapped into an Ethernet/IPv4 frame for the NAT;
/// LCP/discovery frames go to the engine (Echo-Reply, PADT/Terminate). A dropped session makes
/// the uplink unusable so the caller's retry path re-dials.
fn pppoe_poll(up: &mut UplinkResult, buf: &mut [u8]) -> WanEvent {
    use crate::pppoe::{Phase, Tx};
    let nic = up.nic;
    let n = match nic_rx(nic, buf) {
        Some(n) if n >= 14 => n.min(buf.len()),
        _ => return WanEvent::Idle,
    };
    unsafe {
        let Some(e) = (*core::ptr::addr_of_mut!(PPP)).as_mut() else { return WanEvent::Idle };
        let sc = &mut *core::ptr::addr_of_mut!(PPP_SCRATCH);
        if let Some(dn) = e.decap_ipv4(&buf[..n], sc) {
            let k = dn.min(buf.len());
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
    WanEvent::Idle
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
