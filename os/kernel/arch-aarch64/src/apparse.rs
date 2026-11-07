//! Pure parsers for frames the Wi-Fi AP / WAN DHCP paths receive from untrusted peers: the WAN DHCP
//! client's reply parser, the AP DHCP server's request parser, CYW43455 firmware event decoding and the
//! WPA2 authenticator's EAPOL matcher. No MMIO — built on EVERY target so the QEMU `[P-fuzz]` phase can
//! reach them (ADR 0050 D3); `cyw43.rs` / `uplink.rs` use them via re-exports.

// brcmf event codes the authenticator reacts to (bcmevent.h).
pub const WLC_E_DEAUTH_IND: u32 = 6;
pub const WLC_E_ASSOC_IND: u32 = 8;
pub const WLC_E_REASSOC_IND: u32 = 10;
pub const WLC_E_DISASSOC_IND: u32 = 12;

/// Result of the DHCP DORA exchange over WiFi.
pub struct DhcpResult {
    pub mac: [u8; 6],
    pub discover_tx: bool,
    pub offer_rx: bool,
    pub request_tx: bool,
    pub ack_rx: bool,
    pub yiaddr: [u8; 4], // offered/assigned IP (option: BOOTP yiaddr)
    pub server: [u8; 4], // DHCP server id (option 54)
    pub router: [u8; 4], // option 3 (default gateway)
    pub mask: [u8; 4],   // option 1 (subnet mask)
    pub dns: [u8; 4],    // option 6 (first DNS server)
    pub lease: u32,      // option 51 (lease time, seconds)
    pub nak_rx: bool,    // the server NAKed our REQUEST (restart DORA)
    pub frames_seen: u32,
    pub udp68_seen: u32, // UDP frames arriving on client port 68 (OFFER/ACK candidates)
}

impl DhcpResult {
    pub fn new() -> Self {
        DhcpResult {
            mac: [0; 6], discover_tx: false, offer_rx: false, request_tx: false, ack_rx: false,
            yiaddr: [0; 4], server: [0; 4], router: [0; 4], mask: [0; 4], dns: [0; 4], lease: 0,
            nak_rx: false, frames_seen: 0, udp68_seen: 0,
        }
    }
}

/// Parse a received ethernet frame for a DHCP reply TO US: UDP 67->68, BOOTREPLY, and —
/// load-bearing on a promiscuous wired NIC where every other host's OFFER/ACK is also seen —
/// `xid` == ours AND chaddr == `mac` AND the L2 dst is us or broadcast. On a match fills `out`
/// yiaddr + options and returns the DHCP message type (2=OFFER, 5=ACK, 6=NAK), else 0.
pub fn parse_dhcp_reply(eth: &[u8], xid: &[u8; 4], mac: &[u8; 6], out: &mut DhcpResult) -> u8 {
    if eth.len() < 42 + 240 { return 0; }
    if &eth[0..6] != &mac[..] && eth[0..6] != [0xff; 6] { return 0; } // to us or broadcast
    if eth[12] != 0x08 || eth[13] != 0x00 { return 0; }        // IPv4
    let ihl = ((eth[14] & 0x0f) as usize) * 4;
    let l4 = 14 + ihl;
    if eth[23] != 17 { return 0; }                              // UDP
    if l4 + 8 > eth.len() { return 0; }
    let sport = u16::from_be_bytes([eth[l4], eth[l4 + 1]]);
    let dport = u16::from_be_bytes([eth[l4 + 2], eth[l4 + 3]]);
    if sport != 67 || dport != 68 { return 0; }
    out.udp68_seen += 1;
    let b = l4 + 8; // BOOTP start
    if b + 240 > eth.len() || eth[b] != 2 { return 0; }         // BOOTREPLY
    if eth[b + 236] != 0x63 || eth[b + 237] != 0x82 || eth[b + 238] != 0x53 || eth[b + 239] != 0x63 { return 0; }
    if &eth[b + 4..b + 8] != &xid[..] { return 0; }             // our transaction
    if &eth[b + 28..b + 34] != &mac[..] { return 0; }           // our chaddr
    let yi = b + 16;
    let mut yiaddr = [0u8; 4];
    yiaddr.copy_from_slice(&eth[yi..yi + 4]);
    // Walk options (b+240..): [code][len][data], 0xff=end, 0x00=pad.
    let mut p = b + 240;
    let mut mt = 0u8;
    let mut server = [0u8; 4];
    let mut router = [0u8; 4];
    let mut mask = [0u8; 4];
    let mut dns = [0u8; 4];
    let mut lease = 0u32;
    while p + 2 <= eth.len() {
        let code = eth[p];
        if code == 0xff { break; }
        if code == 0x00 { p += 1; continue; }
        let len = eth[p + 1] as usize;
        if p + 2 + len > eth.len() { break; }
        let v = &eth[p + 2..p + 2 + len];
        match code {
            53 if len >= 1 => mt = v[0],
            54 if len >= 4 => server.copy_from_slice(&v[..4]),
            3 if len >= 4 => router.copy_from_slice(&v[..4]),
            1 if len >= 4 => mask.copy_from_slice(&v[..4]),
            6 if len >= 4 => dns.copy_from_slice(&v[..4]), // first DNS server
            51 if len >= 4 => lease = u32::from_be_bytes([v[0], v[1], v[2], v[3]]),
            _ => {}
        }
        p += 2 + len;
    }
    if mt == 6 {
        out.nak_rx = true;
        return mt;
    }
    if mt == 2 || mt == 5 {
        // An ACK must come from the server we REQUESTed from (a second server's stray ACK
        // for our xid is ignored, RFC 2131 §4.4.1).
        if mt == 5 && out.server != [0; 4] && server != [0; 4] && server != out.server { return 0; }
        out.yiaddr = yiaddr;
        if server != [0; 4] { out.server = server; }
        if router != [0; 4] { out.router = router; }
        if mask != [0; 4] { out.mask = mask; }
        if dns != [0; 4] { out.dns = dns; }
        if lease != 0 { out.lease = lease; }
    }
    mt
}

/// Parse a client DHCP (DISCOVER=1 / REQUEST=3). Fills `cmac` (chaddr) + `xid` + `req_ip`
/// (option 50, else ciaddr for a RENEW; zero if neither); returns the DHCP message type,
/// or 0 if not a client DHCP to us.
pub fn parse_client_dhcp(eth: &[u8], cmac: &mut [u8; 6], xid: &mut [u8; 4], req_ip: &mut [u8; 4]) -> u8 {
    if eth.len() < 42 + 240 { return 0; }
    if eth[12] != 0x08 || eth[13] != 0x00 || eth[23] != 17 { return 0; }
    let ihl = ((eth[14] & 0x0f) as usize) * 4;
    let l4 = 14 + ihl;
    if l4 + 8 > eth.len() { return 0; }
    if u16::from_be_bytes([eth[l4], eth[l4 + 1]]) != 68 { return 0; }
    if u16::from_be_bytes([eth[l4 + 2], eth[l4 + 3]]) != 67 { return 0; }
    let b = l4 + 8;
    if b + 240 > eth.len() || eth[b] != 1 { return 0; } // BOOTREQUEST
    if eth[b + 236] != 0x63 || eth[b + 237] != 0x82 || eth[b + 238] != 0x53 || eth[b + 239] != 0x63 { return 0; }
    cmac.copy_from_slice(&eth[b + 28..b + 34]);
    xid.copy_from_slice(&eth[b + 4..b + 8]);
    req_ip.copy_from_slice(&eth[b + 12..b + 16]); // ciaddr (set by a RENEW/REBIND client)
    let mut p = b + 240;
    let mut mt = 0u8;
    while p + 2 <= eth.len() {
        let code = eth[p];
        if code == 0xff { break; }
        if code == 0x00 { p += 1; continue; }
        let len = eth[p + 1] as usize;
        if p + 2 + len > eth.len() { break; }
        if code == 53 && len >= 1 { mt = eth[p + 2]; }
        if code == 50 && len >= 4 { req_ip.copy_from_slice(&eth[p + 2..p + 6]); } // requested IP
        p += 2 + len;
    }
    mt
}

/// Decode a channel-1 event at `doff`: (event type @ev+28, status @ev+32, station addr
/// @ev+48). None if the frame is too short to hold a brcmf_event_msg_be.
pub fn parse_ap_event(rx: &[u8], doff: usize) -> Option<(u32, u32, [u8; 6])> {
    let ev = doff + 4 + (*rx.get(doff + 3)? as usize) * 4;
    if ev + 54 > rx.len() {
        return None;
    }
    let et = u32::from_be_bytes([rx[ev + 28], rx[ev + 29], rx[ev + 30], rx[ev + 31]]);
    let st = u32::from_be_bytes([rx[ev + 32], rx[ev + 33], rx[ev + 34], rx[ev + 35]]);
    let mut sta = [0u8; 6];
    sta.copy_from_slice(&rx[ev + 48..ev + 54]);
    Some((et, st, sta))
}

/// Outcome of one bounded wait for an EAPOL-Key reply from the station.
pub enum KeyWait {
    Got(usize), // an EAPOL-Key frame matching the filter + replay is in the buffer (802.1X len)
    Dry,        // `dry_limit` consecutive dry reads (~1.5 s each): the caller retransmits
    Reassoc,    // the station (re)associated: the caller restarts the handshake
    Deauth,     // the station left
}

/// One SDPCM frame vs the authenticator's wait: `Some` = terminal for this wait (our EAPOL reply —
/// copied into `out` when given — or this station's deauth / reassoc event), `None` = not ours.
pub fn eapol_match(rx: &[u8], ch: u8, doff: usize, sta: &[u8; 6], secure: bool, replay: u64, out: Option<&mut [u8]>) -> Option<KeyWait> {
    let body = 18usize;
    if ch == 1 {
        if let Some((et, _st, who)) = parse_ap_event(rx, doff) {
            if who == *sta {
                if et == WLC_E_DEAUTH_IND || et == WLC_E_DISASSOC_IND {
                    return Some(KeyWait::Deauth);
                }
                if et == WLC_E_ASSOC_IND || et == WLC_E_REASSOC_IND {
                    return Some(KeyWait::Reassoc);
                }
            }
        }
        return None;
    }
    if ch != 2 || doff + 4 > rx.len() {
        return None;
    }
    let eth = doff + 4 + (rx[doff + 3] as usize) * 4;
    if eth + body + 95 > rx.len() {
        return None;
    }
    if u16::from_be_bytes([rx[eth + 12], rx[eth + 13]]) != 0x888E || &rx[eth + 6..eth + 12] != &sta[..] {
        return None;
    }
    let ki = u16::from_be_bytes([rx[eth + body + 1], rx[eth + body + 2]]);
    let pairwise_mic_noack = ki & 0x0008 != 0 && ki & 0x0100 != 0 && ki & 0x0080 == 0;
    if !pairwise_mic_noack || (ki & 0x0200 != 0) != secure {
        return None;
    }
    let mut rc = [0u8; 8];
    rc.copy_from_slice(&rx[eth + body + 5..eth + body + 13]);
    if u64::from_be_bytes(rc) != replay {
        return None; // stale (previous session / previous retransmit)
    }
    let x1 = u16::from_be_bytes([rx[eth + 16], rx[eth + 17]]) as usize;
    let n = 4 + x1;
    if eth + 14 + n > rx.len() {
        return None;
    }
    match out {
        Some(buf) => {
            if n > buf.len() {
                return None; // skipped, never truncated (a truncated MIC span reads as "wrong PSK")
            }
            buf[..n].copy_from_slice(&rx[eth + 14..eth + 14 + n]);
            Some(KeyWait::Got(n))
        }
        None => Some(KeyWait::Got(n)),
    }
}
