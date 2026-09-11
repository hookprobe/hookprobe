//! M-NAT0 — the wired UPLINK over the RTL8111H (`eth1`, PCIe RC1): give the NIC a
//! station address, lease an IP over DHCP, resolve + ping the gateway, then ping an
//! internet host. This is the FIRST time `rtl8111::tx_frame` transmits on metal —
//! P9 only ever proved RX. Every builder/parser is the WiFi STA's (`cyw43.rs`,
//! metal-proven twice) — only the link layer differs: `tx_frame`/`rx_next` are
//! polled DMA rings with no dry-read cost, so waits are spin-budgeted, not
//! read-budgeted. The result (our IP, the gateway MAC) is what M-NAT1+ forwards the
//! WiFi-AP clients through.

use crate::cyw43::{build_arp, build_dhcp, build_icmp_echo, parse_dhcp_reply, parse_ping_reply, DhcpResult};
use crate::rtl8111::{link_up, rx_next, set_mac, started, tx_frame};

/// Locally-administered station address for eth1 (the 8111H eFuse reads back
/// all-zero on this carrier). Distinct from the GEM (02:00:00:00:00:02) and the
/// WiFi OTP MAC.
pub const ETH1_MAC: [u8; 6] = [0x02, 0x43, 0x45, 0x48, 0x51, 0x4c];

/// ~5 s of polling at the P9 spin rate (60M spins ≈ 5 s on the A76 busy-poll).
const WAIT_BUDGET: u64 = 60_000_000;
/// Retransmit the lossy request every ~1 s of dry polling.
const RETX_EVERY: u64 = 12_000_000;

pub struct UplinkResult {
    pub started: bool,
    pub link: bool,
    pub mac: [u8; 6], // IDR read-back after set_mac
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
    pub fn new() -> Self {
        UplinkResult {
            started: false, link: false, mac: [0; 6], mac_ok: false, dhcp: DhcpResult::new(),
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

/// Drain the eth1 RX ring for up to `budget` spins, handing every frame to `f`
/// until it returns true. `retx` is re-sent every `RETX_EVERY` spins.
fn rx_wait(out: &mut UplinkResult, retx: &[u8], budget: u64, mut f: impl FnMut(&[u8], &mut UplinkResult) -> bool) -> bool {
    let mut buf = [0u8; 2048];
    let mut spins = 0u64;
    while spins < budget {
        spins += 1;
        if spins % RETX_EVERY == 0 {
            let _ = tx_frame(retx);
        }
        match rx_next(&mut buf) {
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

/// M-NAT0: bring the eth1 uplink to a leased, gateway-resolved state and prove
/// internet reach with an ICMP echo to `inet_ip`. Never blocks past the fixed
/// spin budgets; every stage's outcome is in `out`.
pub fn eth1_bringup(inet_ip: &[u8; 4], out: &mut UplinkResult) {
    out.inet_ip = *inet_ip;
    out.started = started();
    if !out.started {
        return;
    }
    out.link = link_up();
    out.mac = set_mac(&ETH1_MAC);
    out.mac_ok = out.mac == ETH1_MAC;
    out.dhcp.mac = ETH1_MAC;
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
    let n = build_dhcp(&mut pkt, &ETH1_MAC, &xid, 1, &none, &none);
    out.dhcp.discover_tx = tx_frame(&pkt[..n]);
    if !out.dhcp.discover_tx {
        return; // tx_frame never completed — the M-NAT0 make-or-break fact
    }
    let disc = pkt;
    out.dhcp.offer_rx = rx_wait(out, &disc[..n], WAIT_BUDGET, |eth, o| parse_dhcp_reply(eth, &mut o.dhcp) == 2);
    if !out.dhcp.offer_rx {
        return;
    }

    // --- REQUEST → ACK
    let yi = out.dhcp.yiaddr;
    let sv = out.dhcp.server;
    let n = build_dhcp(&mut pkt, &ETH1_MAC, &xid, 3, &yi, &sv);
    out.dhcp.request_tx = tx_frame(&pkt[..n]);
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
    let n = build_arp(&mut small, &ETH1_MAC, &ip, &gw);
    out.arp_tx = tx_frame(&small[..n]);
    let arp = small;
    out.arp_reply = rx_wait(out, &arp[..n], WAIT_BUDGET, |eth, o| {
        let mut mac = [0u8; 6];
        let (mut ttl, mut src) = (0u8, [0u8; 4]);
        if parse_ping_reply(eth, &gw, 0, &mut mac, &mut ttl, &mut src) == 1 {
            o.gw_mac = mac;
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
    let n = build_icmp_echo(&mut small, &ETH1_MAC, &gw_mac, &ip, &gw, id, 1);
    out.gw_ping_tx = tx_frame(&small[..n]);
    let echo = small;
    out.gw_ping_reply = rx_wait(out, &echo[..n], WAIT_BUDGET, |eth, o| {
        let mut mac = [0u8; 6];
        let (mut ttl, mut src) = (0u8, [0u8; 4]);
        if parse_ping_reply(eth, &none, id, &mut mac, &mut ttl, &mut src) == 2 && src == gw {
            o.gw_ttl = ttl;
            true
        } else {
            false
        }
    });

    let n = build_icmp_echo(&mut small, &ETH1_MAC, &gw_mac, &ip, inet_ip, id, 2);
    out.inet_ping_tx = tx_frame(&small[..n]);
    let echo = small;
    let want = *inet_ip;
    out.inet_ping_reply = rx_wait(out, &echo[..n], WAIT_BUDGET * 2, |eth, o| {
        let mut mac = [0u8; 6];
        let (mut ttl, mut src) = (0u8, [0u8; 4]);
        if parse_ping_reply(eth, &none, id, &mut mac, &mut ttl, &mut src) == 2 && src == want {
            o.inet_ttl = ttl;
            true
        } else {
            false
        }
    });
}
