//! Client DHCP request parsing (ADR 0050 D4 step 2b): what every Wi-Fi / LAN client sends the device's DHCP server.
//! Pure, allocation-free, bounds-safe — compiled into the kernel (in-kernel fallback) AND into the EL0 LAN-services
//! server (`el0-lansvc`), so the parse that runs on attacker bytes can live outside the kernel without a second copy.
//! Also the WAN DHCP CLIENT's reply parse (D4 step 3): `dhcp_reply_facts` (pure, EL0) + `apply_reply` (kernel merge).

/// Everything the DHCP server needs from one client frame.
#[derive(Clone, Copy)]
pub struct ClientReq {
    /// DHCP message type (1 DISCOVER, 3 REQUEST, 7 RELEASE, 8 INFORM), 0 = not a client DHCP to us.
    pub mt: u8,
    pub cmac: [u8; 6],
    pub xid: [u8; 4],
    /// Option 50, else ciaddr (RENEW); zero if neither.
    pub req_ip: [u8; 4],
    pub id: ClientId,
}
pub const ID0: ClientId = ClientId { host: [0; 32], hlen: 0, vendor: [0; 32], vlen: 0, prl: [0; 24], plen: 0, mt: 0 };
pub const REQ0: ClientReq = ClientReq { mt: 0, cmac: [0; 6], xid: [0; 4], req_ip: [0; 4], id: ID0 };

/// Both parses of one frame (the server's view + the identity it records).
pub fn parse_client(eth: &[u8]) -> ClientReq {
    let mut r = REQ0;
    r.mt = parse_client_dhcp(eth, &mut r.cmac, &mut r.xid, &mut r.req_ip);
    r.id = client_identity(eth);
    r
}

/// Fixed wire record for the EL0 ABI: `mt cmac[6] xid[4] req_ip[4] | host[32] hlen vendor[32] vlen prl[24] plen idmt`.
pub const REC_LEN: usize = 15 + 32 + 1 + 32 + 1 + 24 + 1 + 1;
pub fn encode(r: &ClientReq, o: &mut [u8; REC_LEN]) {
    o[0] = r.mt;
    o[1..7].copy_from_slice(&r.cmac);
    o[7..11].copy_from_slice(&r.xid);
    o[11..15].copy_from_slice(&r.req_ip);
    o[15..47].copy_from_slice(&r.id.host);
    o[47] = r.id.hlen;
    o[48..80].copy_from_slice(&r.id.vendor);
    o[80] = r.id.vlen;
    o[81..105].copy_from_slice(&r.id.prl);
    o[105] = r.id.plen;
    o[106] = r.id.mt;
}
/// Decode + re-validate (the kernel never trusts lengths from EL0: they are clamped to the arrays and the strings
/// re-cleaned, so a compromised server can at worst lie about a client — never overrun the kernel).
pub fn decode(o: &[u8; REC_LEN]) -> ClientReq {
    let mut r = REQ0;
    r.mt = o[0];
    r.cmac.copy_from_slice(&o[1..7]);
    r.xid.copy_from_slice(&o[7..11]);
    r.req_ip.copy_from_slice(&o[11..15]);
    let mut host = [0u8; 32];
    r.id.hlen = clean(&o[15..15 + (o[47] as usize).min(32)], &mut host);
    r.id.host = host;
    let mut vendor = [0u8; 32];
    r.id.vlen = clean(&o[48..48 + (o[80] as usize).min(32)], &mut vendor);
    r.id.vendor = vendor;
    r.id.plen = o[105].min(24);
    r.id.prl[..r.id.plen as usize].copy_from_slice(&o[81..81 + r.id.plen as usize]);
    r.id.mt = o[106];
    r
}

/// What a DHCP client says about itself.
#[derive(Clone, Copy)]
pub struct ClientId {
    pub host: [u8; 32],
    pub hlen: u8,
    pub vendor: [u8; 32],
    pub vlen: u8,
    pub prl: [u8; 24],
    pub plen: u8,
    /// DHCP message type (1 DISCOVER, 3 REQUEST, 7 RELEASE, 8 INFORM), 0 = not a client DHCP.
    pub mt: u8,
}

/// Printable, bounded copy (hostnames/vendor strings are attacker-chosen: only [A-Za-z0-9 ._-]).
pub fn clean(src: &[u8], dst: &mut [u8]) -> u8 {
    let mut n = 0;
    for &c in src {
        if n >= dst.len() {
            break;
        }
        if c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'.' | b' ') {
            dst[n] = c;
            n += 1;
        }
    }
    n as u8
}

/// Parse a client DHCP frame's identity options (12 hostname, 55 parameter list, 60 vendor class) and
/// message type. Bounds-safe; anything malformed yields `mt = 0`.
pub fn client_identity(eth: &[u8]) -> ClientId {
    let mut id = ClientId { host: [0; 32], hlen: 0, vendor: [0; 32], vlen: 0, prl: [0; 24], plen: 0, mt: 0 };
    if eth.len() < 42 + 240 || eth[12] != 0x08 || eth[13] != 0x00 || eth[23] != 17 {
        return id;
    }
    let l4 = 14 + ((eth[14] & 0x0f) as usize) * 4;
    if l4 + 8 + 240 > eth.len() || u16::from_be_bytes([eth[l4], eth[l4 + 1]]) != 68 || u16::from_be_bytes([eth[l4 + 2], eth[l4 + 3]]) != 67 {
        return id;
    }
    let b = l4 + 8;
    if eth[b] != 1 || eth[b + 236..b + 240] != [0x63, 0x82, 0x53, 0x63] {
        return id;
    }
    let mut p = b + 240;
    while p + 2 <= eth.len() {
        let code = eth[p];
        if code == 0xff {
            break;
        }
        if code == 0 {
            p += 1;
            continue;
        }
        let len = eth[p + 1] as usize;
        let Some(v) = eth.get(p + 2..p + 2 + len) else { break };
        match code {
            53 if len >= 1 => id.mt = v[0],
            12 => id.hlen = clean(v, &mut id.host),
            60 => id.vlen = clean(v, &mut id.vendor),
            55 => {
                let n = len.min(id.prl.len());
                id.prl[..n].copy_from_slice(&v[..n]);
                id.plen = n as u8;
            }
            _ => {}
        }
        p += 2 + len;
    }
    id
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


// ---- WAN DHCP client (D4 step 3) ----

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

/// What one frame says as a DHCP reply TO US (pure: no merge, no pin — that is `apply_reply`). `udp68` = a UDP
/// 67->68 frame to us (counted by the caller even when it is not ours); `mt` 0 = not a reply for this xid/chaddr.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ReplyFacts {
    pub udp68: bool,
    pub mt: u8,
    pub yiaddr: [u8; 4],
    pub server: [u8; 4],
    pub router: [u8; 4],
    pub mask: [u8; 4],
    pub dns: [u8; 4],
    pub lease: u32,
}

/// Parse a received ethernet frame for a DHCP reply TO US: UDP 67->68, BOOTREPLY, and —
/// load-bearing on a promiscuous wired NIC where every other host's OFFER/ACK is also seen —
/// `xid` == ours AND chaddr == `mac` AND the L2 dst is us or broadcast.
pub fn dhcp_reply_facts(eth: &[u8], xid: &[u8; 4], mac: &[u8; 6]) -> ReplyFacts {
    let mut f = ReplyFacts::default();
    if eth.len() < 42 + 240 { return f; }
    if eth[0..6] != mac[..] && eth[0..6] != [0xff; 6] { return f; } // to us or broadcast
    if eth[12] != 0x08 || eth[13] != 0x00 { return f; }        // IPv4
    let ihl = ((eth[14] & 0x0f) as usize) * 4;
    let l4 = 14 + ihl;
    if eth[23] != 17 { return f; }                              // UDP
    if l4 + 8 > eth.len() { return f; }
    let sport = u16::from_be_bytes([eth[l4], eth[l4 + 1]]);
    let dport = u16::from_be_bytes([eth[l4 + 2], eth[l4 + 3]]);
    if sport != 67 || dport != 68 { return f; }
    f.udp68 = true;
    let b = l4 + 8; // BOOTP start
    if b + 240 > eth.len() || eth[b] != 2 { return f; }         // BOOTREPLY
    if eth[b + 236] != 0x63 || eth[b + 237] != 0x82 || eth[b + 238] != 0x53 || eth[b + 239] != 0x63 { return f; }
    if eth[b + 4..b + 8] != xid[..] { return f; }             // our transaction
    if eth[b + 28..b + 34] != mac[..] { return f; }           // our chaddr
    let yi = b + 16;
    f.yiaddr.copy_from_slice(&eth[yi..yi + 4]);
    // Walk options (b+240..): [code][len][data], 0xff=end, 0x00=pad.
    let mut p = b + 240;
    while p + 2 <= eth.len() {
        let code = eth[p];
        if code == 0xff { break; }
        if code == 0x00 { p += 1; continue; }
        let len = eth[p + 1] as usize;
        if p + 2 + len > eth.len() { break; }
        let v = &eth[p + 2..p + 2 + len];
        match code {
            53 if len >= 1 => f.mt = v[0],
            54 if len >= 4 => f.server.copy_from_slice(&v[..4]),
            3 if len >= 4 => f.router.copy_from_slice(&v[..4]),
            1 if len >= 4 => f.mask.copy_from_slice(&v[..4]),
            6 if len >= 4 => f.dns.copy_from_slice(&v[..4]), // first DNS server
            51 if len >= 4 => f.lease = u32::from_be_bytes([v[0], v[1], v[2], v[3]]),
            _ => {}
        }
        p += 2 + len;
    }
    f
}

/// Merge the facts into the client state (kernel side): NAK flag, the server pin, nonzero fields only. Returns
/// the DHCP message type (2=OFFER, 5=ACK, 6=NAK) or 0.
pub fn apply_reply(f: &ReplyFacts, out: &mut DhcpResult) -> u8 {
    if f.udp68 {
        out.udp68_seen += 1;
    }
    let mt = f.mt;
    if mt == 6 {
        out.nak_rx = true;
        return mt;
    }
    if mt == 2 || mt == 5 {
        // An ACK must come from the server we REQUESTed from (a second server's stray ACK
        // for our xid is ignored, RFC 2131 §4.4.1).
        if mt == 5 && out.server != [0; 4] && f.server != [0; 4] && f.server != out.server { return 0; }
        out.yiaddr = f.yiaddr;
        if f.server != [0; 4] { out.server = f.server; }
        if f.router != [0; 4] { out.router = f.router; }
        if f.mask != [0; 4] { out.mask = f.mask; }
        if f.dns != [0; 4] { out.dns = f.dns; }
        if f.lease != 0 { out.lease = f.lease; }
    }
    mt
}

/// The original one-call form (unchanged behaviour): facts, then merge.
pub fn parse_dhcp_reply(eth: &[u8], xid: &[u8; 4], mac: &[u8; 6], out: &mut DhcpResult) -> u8 {
    apply_reply(&dhcp_reply_facts(eth, xid, mac), out)
}

/// Fixed wire record for the EL0 ABI.
pub const FACTS_LEN: usize = 2 + 4 * 5 + 4;
pub fn encode_facts(f: &ReplyFacts) -> [u8; FACTS_LEN] {
    let mut o = [0u8; FACTS_LEN];
    o[0] = f.udp68 as u8;
    o[1] = f.mt;
    o[2..6].copy_from_slice(&f.yiaddr);
    o[6..10].copy_from_slice(&f.server);
    o[10..14].copy_from_slice(&f.router);
    o[14..18].copy_from_slice(&f.mask);
    o[18..22].copy_from_slice(&f.dns);
    o[22..26].copy_from_slice(&f.lease.to_le_bytes());
    o
}
pub fn decode_facts(o: &[u8; FACTS_LEN]) -> ReplyFacts {
    let a = |i: usize| -> [u8; 4] { [o[i], o[i + 1], o[i + 2], o[i + 3]] };
    ReplyFacts { udp68: o[0] != 0, mt: o[1], yiaddr: a(2), server: a(6), router: a(10), mask: a(14), dns: a(18), lease: u32::from_le_bytes(a(22)) }
}
