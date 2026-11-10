//! ADR 0050 D4 step 3: the WAN control parsers the uplink runs on bytes from the ISP side (DHCPv4 replies, Router
//! Advertisements, DHCPv6). The kernel installs the EL0 network-services parser here once `el0-lansvc` is loaded;
//! the uplink then parses through it. A server fault reads as "not for us / unparseable" — exactly what a
//! malformed frame always meant (the client retries on its own clock). Unset = parse in-kernel with the same `hal`
//! code. The kernel keeps every DECISION (merge, server pin, prefix use).
use hal::dhcpwire::{apply_reply, dhcp_reply_facts, DhcpResult, ReplyFacts};
use hal::ip6::{Dhcp6, Ra};

pub type DhcpReplyFn = fn(&[u8], &[u8; 4], &[u8; 6]) -> Option<ReplyFacts>;
pub type RaFn = fn(&[u8]) -> Option<Option<Ra>>;
pub type Dhcp6Fn = fn(&[u8], u32) -> Option<Option<Dhcp6>>;

pub static mut EL0_DHCP_REPLY: Option<DhcpReplyFn> = None;
pub static mut EL0_RA: Option<RaFn> = None;
pub static mut EL0_DHCP6: Option<Dhcp6Fn> = None;

pub fn dhcp_reply(eth: &[u8], xid: &[u8; 4], mac: &[u8; 6], out: &mut DhcpResult) -> u8 {
    let f = match unsafe { EL0_DHCP_REPLY } {
        Some(h) => h(eth, xid, mac).unwrap_or_default(),
        None => dhcp_reply_facts(eth, xid, mac),
    };
    apply_reply(&f, out)
}

pub fn ra(ip: &[u8]) -> Option<Ra> {
    match unsafe { EL0_RA } {
        Some(h) => h(ip).flatten(),
        None => hal::ip6::parse_ra(ip),
    }
}

pub fn dhcp6(ip: &[u8], xid: u32) -> Option<Dhcp6> {
    match unsafe { EL0_DHCP6 } {
        Some(h) => h(ip, xid).flatten(),
        None => hal::ip6::parse_dhcp6(ip, xid),
    }
}
