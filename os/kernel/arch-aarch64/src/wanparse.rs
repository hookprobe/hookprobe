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

pub type PppoeDiscFn = fn(&[u8], usize) -> Option<hal::pppwire::DiscTags>;
pub static mut EL0_PPPOE_DISC: Option<PppoeDiscFn> = None;

/// D4 step 3b: a PADO / PADS tag walk (a server fault reads as "no tags": host-uniq never matches, frame ignored).
pub fn pppoe_disc(f: &[u8], plen: usize) -> hal::pppwire::DiscTags {
    match unsafe { EL0_PPPOE_DISC } {
        Some(h) => h(f, plen).unwrap_or(hal::pppwire::DISC0),
        None => hal::pppwire::disc_tags(f, plen),
    }
}

pub type LcpFn = fn(&[u8]) -> Option<hal::pppwire::LcpReq>;
pub static mut EL0_LCP: Option<LcpFn> = None;

/// D4 step 3b-ii: an LCP Configure-Request's option classification (a server fault reads as malformed: dropped,
/// the AC retransmits).
pub fn lcp_req(data: &[u8]) -> hal::pppwire::LcpReq {
    match unsafe { EL0_LCP } {
        Some(h) => h(data).unwrap_or(hal::pppwire::LcpReq { malformed: true, ..hal::pppwire::LCP0 }),
        None => hal::pppwire::lcp_classify(data),
    }
}

pub type IpcpFn = fn(u8, &[u8]) -> Option<hal::pppwire::IpcpFacts>;
pub static mut EL0_IPCP: Option<IpcpFn> = None;

/// D4 step 3b-iii: an IPCP Configure-Request / -Nak / -Reject (a server fault reads as malformed / nothing proposed).
pub fn ipcp(code: u8, data: &[u8]) -> hal::pppwire::IpcpFacts {
    match unsafe { EL0_IPCP } {
        Some(h) => h(code, data).unwrap_or(hal::pppwire::IpcpFacts { malformed: true, ..hal::pppwire::IPCP0 }),
        None => hal::pppwire::ipcp_facts(code, data),
    }
}

pub type ChapFn = fn(&[u8]) -> Option<hal::pppwire::ChapChallenge>;
pub static mut EL0_CHAP: Option<ChapFn> = None;
pub type Ip6cpFn = fn(&[u8]) -> Option<hal::pppwire::Ip6cpReq>;
pub static mut EL0_IP6CP: Option<Ip6cpFn> = None;

/// D4 step 3b-iv: a CHAP Challenge's value (a server fault reads as "no challenge": ignored, the AC retransmits).
pub fn chap(data: &[u8]) -> hal::pppwire::ChapChallenge {
    match unsafe { EL0_CHAP } {
        Some(h) => h(data).unwrap_or(hal::pppwire::CHAP0),
        None => hal::pppwire::chap_challenge(data),
    }
}
/// D4 step 3b-iv: an IPv6CP Configure-Request (a server fault reads as malformed: dropped).
pub fn ip6cp(data: &[u8]) -> hal::pppwire::Ip6cpReq {
    match unsafe { EL0_IP6CP } {
        Some(h) => h(data).unwrap_or(hal::pppwire::Ip6cpReq { malformed: true, ..hal::pppwire::IP6CP0 }),
        None => hal::pppwire::ip6cp_req(data),
    }
}

pub type LcpPeerFn = fn(u8, &[u8]) -> Option<hal::pppwire::LcpPeer>;
pub static mut EL0_LCP_PEER: Option<LcpPeerFn> = None;
/// The AC's Nak / Reject of our LCP request (a server fault reads as "nothing suggested": we re-send unchanged and
/// the retransmit bound applies).
pub fn lcp_peer(code: u8, data: &[u8]) -> hal::pppwire::LcpPeer {
    match unsafe { EL0_LCP_PEER } {
        Some(h) => h(code, data).unwrap_or(hal::pppwire::LCPPEER0),
        None => hal::pppwire::lcp_peer(code, data),
    }
}

// ---- ADR 0050 D4 step 5a: the WPA authenticator's station-frame parsing ----
pub type EapolFn = fn(&[u8], &[u8; 6], bool, u64) -> Option<Option<usize>>;
pub static mut EL0_EAPOL: Option<EapolFn> = None;
pub type MfpcFn = fn(&[u8], usize) -> Option<bool>;
pub static mut EL0_MFPC: Option<MfpcFn> = None;

/// An EAPOL-Key from `sta` for this handshake step (a server fault reads as "not ours": the station retransmits).
pub fn eapol_key(e: &[u8], sta: &[u8; 6], secure: bool, replay: u64) -> Option<usize> {
    // The caller hands the rest of the SDPCM receive buffer (metal batch 62: longer than the EL0 input window, so
    // every M2 read as "not ours"). The classification reads at most the key body (113 B) and the 802.1X length
    // span (18 + body length): trim to that, which cannot change the answer.
    let span = if e.len() >= 18 { (18 + u16::from_be_bytes([e[16], e[17]]) as usize).max(113) } else { e.len() };
    let e = &e[..span.min(e.len())];
    match unsafe { EL0_EAPOL } {
        Some(h) => h(e, sta, secure, replay).flatten(),
        None => hal::eapolwire::eapol_key(e, sta, secure, replay),
    }
}
/// M2's RSNE MFP-capable bit (a server fault reads as "not capable": PMF stays off for that station, as before).
pub fn m2_mfpc(m2: &[u8], body_off: usize) -> bool {
    match unsafe { EL0_MFPC } {
        Some(h) => h(m2, body_off).unwrap_or(false),
        None => hal::eapolwire::m2_mfpc(m2, body_off),
    }
}

pub fn dhcp6(ip: &[u8], xid: u32) -> Option<Dhcp6> {
    match unsafe { EL0_DHCP6 } {
        Some(h) => h(ip, xid).flatten(),
        None => hal::ip6::parse_dhcp6(ip, xid),
    }
}
