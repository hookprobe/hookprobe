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
//! waits are spin-budgeted, not read-budgeted.

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

/// ~5 s of polling at the P9 spin rate (60M spins ≈ 5 s on the A76 busy-poll).
const WAIT_BUDGET: u64 = 60_000_000;
/// Retransmit the lossy request every ~1 s of dry polling.
const RETX_EVERY: u64 = 12_000_000;

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
    pub started: bool,
    pub link: bool,
    pub mac: [u8; 6], // the station address in use (IDR read-back on eth1)
    pub mac_ok: bool,
    pub dhcp: DhcpResult,
    pub rx_frames: u32, // every frame drained off the ring during the waits
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
            nic, started: false, link: false, mac: [0; 6], mac_ok: false, dhcp: DhcpResult::new(),
            rx_frames: 0, gw_mac: [0; 6], arp_tx: false, arp_reply: false,
            gw_ping_tx: false, gw_ping_reply: false, gw_ttl: 0,
            inet_ip: [0; 4], inet_ping_tx: false, inet_ping_reply: false, inet_ttl: 0,
        }
    }
    /// A usable uplink: leased + gateway resolved (internet reach is reported, not required).
    pub fn usable(&self) -> bool {
        self.dhcp.ack_rx && self.arp_reply
    }
}

/// Drain the NIC's RX ring for up to `budget` spins, handing every frame to `f`
/// until it returns true. `retx` is re-sent every `RETX_EVERY` spins.
fn rx_wait(out: &mut UplinkResult, retx: &[u8], budget: u64, mut f: impl FnMut(&[u8], &mut UplinkResult) -> bool) -> bool {
    let nic = out.nic;
    let mut buf = [0u8; 2048];
    let mut spins = 0u64;
    while spins < budget {
        spins += 1;
        if spins % RETX_EVERY == 0 {
            let _ = nic_tx(nic, retx);
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
    false
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

/// M-NAT0: bring `nic` to a leased, gateway-resolved state and prove internet
/// reach with an ICMP echo to `inet_ip`. Never blocks past the fixed spin
/// budgets; every stage's outcome is in `out`.
pub fn bringup(nic: Nic, inet_ip: &[u8; 4], out: &mut UplinkResult) {
    out.nic = nic;
    out.inet_ip = *inet_ip;
    out.started = nic_ready(nic);
    if !out.started {
        return;
    }
    out.link = nic_link(nic);
    establish_mac(nic, out);
    let mac = out.mac;
    out.dhcp.mac = mac;
    if !out.link || !out.mac_ok {
        return;
    }

    // Per-boot xid from the cycle counter (as wifi_dhcp).
    let ctr: u64;
    unsafe { core::arch::asm!("mrs {}, cntpct_el0", out(reg) ctr, options(nomem, nostack)) };
    let xid = (ctr as u32).to_be_bytes();
    let none = [0u8; 4];
    let mut pkt = [0u8; 400];

    // --- DISCOVER → OFFER
    let n = build_dhcp(&mut pkt, &mac, &xid, 1, &none, &none);
    out.dhcp.discover_tx = nic_tx(nic, &pkt[..n]);
    if !out.dhcp.discover_tx {
        return; // the TX primitive never completed
    }
    let disc = pkt;
    out.dhcp.offer_rx = rx_wait(out, &disc[..n], WAIT_BUDGET, |eth, o| parse_dhcp_reply(eth, &mut o.dhcp) == 2);
    if !out.dhcp.offer_rx {
        return;
    }

    // --- REQUEST → ACK
    let yi = out.dhcp.yiaddr;
    let sv = out.dhcp.server;
    let n = build_dhcp(&mut pkt, &mac, &xid, 3, &yi, &sv);
    out.dhcp.request_tx = nic_tx(nic, &pkt[..n]);
    let req = pkt;
    out.dhcp.ack_rx = rx_wait(out, &req[..n], WAIT_BUDGET, |eth, o| parse_dhcp_reply(eth, &mut o.dhcp) == 5);
    if !out.dhcp.ack_rx {
        return;
    }

    // --- ARP the gateway
    let ip = out.dhcp.yiaddr;
    let gw = out.dhcp.router;
    if gw == [0; 4] {
        return; // no router option — nothing to route through
    }
    let mut small = [0u8; 128];
    let n = build_arp(&mut small, &mac, &ip, &gw);
    out.arp_tx = nic_tx(nic, &small[..n]);
    let arp = small;
    out.arp_reply = rx_wait(out, &arp[..n], WAIT_BUDGET, |eth, o| {
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
    out.gw_ping_reply = rx_wait(out, &echo[..n], WAIT_BUDGET, |eth, o| {
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
    out.inet_ping_reply = rx_wait(out, &echo[..n], WAIT_BUDGET * 2, |eth, o| {
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

/// LAN-port status for eth1: program its station address and report the link.
/// heqk is the DHCP SERVER on this port (M-NAT1+), never a client.
pub fn eth1_lan_status() -> (bool, bool, [u8; 6]) {
    if !rtl8111::started() {
        return (false, false, [0; 6]);
    }
    let mac = rtl8111::set_mac(&ETH1_MAC);
    (true, rtl8111::link_up(), mac)
}
