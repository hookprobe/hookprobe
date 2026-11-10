//! PPPoE discovery parsing (ADR 0050 D4 step 3b): the tag walk of a PADO / PADS — bytes any host on the WAN segment
//! can send. Pure, allocation-free: compiled into the kernel (fallback) and into `el0-lansvc`, which runs it in EL0.
//! The PPPoE engine (`arch_aarch64::pppoe`) keeps every decision (host-uniq match, AC MAC, SID, phase).

const TAG_END: u16 = 0x0000;
const TAG_AC_NAME: u16 = 0x0102;
const TAG_HOST_UNIQ: u16 = 0x0103;
const TAG_AC_COOKIE: u16 = 0x0104;
const TAG_RELAY_SID: u16 = 0x0110;
const TAG_SERVICE_NAME_ERR: u16 = 0x0201;
const TAG_AC_SYSTEM_ERR: u16 = 0x0202;
const TAG_GENERIC_ERR: u16 = 0x0203;

/// What a discovery frame's tags say (the LAST occurrence of each tag wins, as before; values clamped).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DiscTags {
    /// The Host-Uniq value; `hu_len` 0xff = longer than 32 bytes (never ours: we send 4).
    pub host_uniq: [u8; 32],
    pub hu_len: u8,
    pub cookie: [u8; 64],
    pub cookie_len: u8,
    pub relay: [u8; 64],
    pub relay_len: u8,
    pub ac_name: [u8; 32],
    pub ac_name_len: u8,
    /// A Service-Name-Error / AC-System-Error / Generic-Error tag was present.
    pub err: bool,
}
pub const DISC0: DiscTags = DiscTags { host_uniq: [0; 32], hu_len: 0, cookie: [0; 64], cookie_len: 0, relay: [0; 64], relay_len: 0, ac_name: [0; 32], ac_name_len: 0, err: false };

fn be16(b: &[u8], o: usize) -> u16 {
    u16::from_be_bytes([b[o], b[o + 1]])
}

/// Walk the discovery tags of Ethernet frame `f` (payload from byte 20, `plen` bytes).
pub fn disc_tags(f: &[u8], plen: usize) -> DiscTags {
    let mut d = DISC0;
    let end = (20 + plen).min(f.len());
    let mut o = 20;
    while o + 4 <= end {
        let (t, l) = (be16(f, o), be16(f, o + 2) as usize);
        let v0 = o + 4;
        if v0 + l > end {
            break;
        }
        let v = &f[v0..v0 + l];
        match t {
            TAG_END => break,
            TAG_HOST_UNIQ => {
                if l <= 32 {
                    d.host_uniq = [0; 32];
                    d.host_uniq[..l].copy_from_slice(v);
                    d.hu_len = l as u8;
                } else {
                    d.hu_len = 0xff;
                }
            }
            TAG_AC_COOKIE => {
                let n = l.min(64);
                d.cookie[..n].copy_from_slice(&v[..n]);
                d.cookie_len = n as u8;
            }
            TAG_RELAY_SID => {
                let n = l.min(64);
                d.relay[..n].copy_from_slice(&v[..n]);
                d.relay_len = n as u8;
            }
            TAG_AC_NAME => {
                let n = l.min(32);
                d.ac_name[..n].copy_from_slice(&v[..n]);
                d.ac_name_len = n as u8;
            }
            TAG_SERVICE_NAME_ERR | TAG_AC_SYSTEM_ERR | TAG_GENERIC_ERR => d.err = true,
            _ => {}
        }
        o = v0 + l;
    }
    d
}

/// Fixed record for the EL0 ABI; `decode` clamps every length (a compromised server cannot overrun the kernel).
pub const DISC_LEN: usize = 32 + 1 + 64 + 1 + 64 + 1 + 32 + 1 + 1;
pub fn encode_disc(d: &DiscTags) -> [u8; DISC_LEN] {
    let mut o = [0u8; DISC_LEN];
    o[..32].copy_from_slice(&d.host_uniq);
    o[32] = d.hu_len;
    o[33..97].copy_from_slice(&d.cookie);
    o[97] = d.cookie_len;
    o[98..162].copy_from_slice(&d.relay);
    o[162] = d.relay_len;
    o[163..195].copy_from_slice(&d.ac_name);
    o[195] = d.ac_name_len;
    o[196] = d.err as u8;
    o
}
pub fn decode_disc(o: &[u8; DISC_LEN]) -> DiscTags {
    let mut d = DISC0;
    d.host_uniq.copy_from_slice(&o[..32]);
    d.hu_len = if o[32] == 0xff { 0xff } else { o[32].min(32) };
    d.cookie.copy_from_slice(&o[33..97]);
    d.cookie_len = o[97].min(64);
    d.relay.copy_from_slice(&o[98..162]);
    d.relay_len = o[162].min(64);
    d.ac_name.copy_from_slice(&o[163..195]);
    d.ac_name_len = o[195].min(32);
    d.err = o[196] != 0;
    d
}

// ---- D4 step 3b-ii: PPP LCP Configure-Request option classification ------------------------------------------

const PPP_PAP: u16 = 0xc023;
const PPP_CHAP: u16 = 0xc223;

/// What the AC's LCP Configure-Request asks for, and what we must answer (RFC 1661): the rejected options (copied
/// out of the request — the engine replies with THESE bytes, never re-reads the frame), a Nak for an auth we cannot
/// do, or Ack with the chosen auth.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LcpReq {
    /// A malformed option list: silently dropped (RFC 1661).
    pub malformed: bool,
    pub auth: u16,
    pub rej: [u8; 128],
    pub nrej: u8,
    pub nak: [u8; 16],
    pub nnak: u8,
}
pub const LCP0: LcpReq = LcpReq { malformed: false, auth: 0, rej: [0; 128], nrej: 0, nak: [0; 16], nnak: 0 };

/// Classify the options of an LCP Configure-Request's data (the bytes after code/id/length).
pub fn lcp_classify(data: &[u8]) -> LcpReq {
    let mut r = LCP0;
    let mut nrej = 0usize;
    let mut o = 0;
    while o + 2 <= data.len() {
        let (t, l) = (data[o], data[o + 1] as usize);
        if l < 2 || o + l > data.len() {
            r.malformed = true;
            return r;
        }
        let opt = &data[o..o + l];
        match t {
            1 | 2 | 5 => {} // MRU, ACCM (meaningless on PPPoE, harmless), Magic
            3 if l >= 4 => {
                let ap = be16(opt, 2);
                if ap == PPP_PAP && l == 4 {
                    r.auth = PPP_PAP;
                } else if ap == PPP_CHAP && l == 5 && opt[4] == 5 {
                    r.auth = PPP_CHAP;
                } else if r.nnak == 0 {
                    // Suggest CHAP-MD5 (RFC 1994) instead.
                    r.nak[..5].copy_from_slice(&[3, 5, 0xc2, 0x23, 5]);
                    r.nnak = 5;
                }
            }
            _ => {
                if nrej + l <= r.rej.len() {
                    r.rej[nrej..nrej + l].copy_from_slice(opt);
                    nrej += l;
                }
            }
        }
        o += l;
    }
    r.nrej = nrej as u8;
    r
}

pub const LCP_LEN: usize = 1 + 2 + 128 + 1 + 16 + 1;
pub fn encode_lcp(r: &LcpReq) -> [u8; LCP_LEN] {
    let mut o = [0u8; LCP_LEN];
    o[0] = r.malformed as u8;
    o[1..3].copy_from_slice(&r.auth.to_le_bytes());
    o[3..131].copy_from_slice(&r.rej);
    o[131] = r.nrej;
    o[132..148].copy_from_slice(&r.nak);
    o[148] = r.nnak;
    o
}
pub fn decode_lcp(o: &[u8; LCP_LEN]) -> LcpReq {
    let mut r = LCP0;
    r.malformed = o[0] != 0;
    let a = u16::from_le_bytes([o[1], o[2]]);
    r.auth = if a == PPP_PAP || a == PPP_CHAP { a } else { 0 };
    r.rej.copy_from_slice(&o[3..131]);
    r.nrej = o[131].min(128);
    r.nak.copy_from_slice(&o[132..148]);
    r.nnak = o[148].min(16);
    r
}

// ---- D4 step 3b-iii: IPCP option parsing (Configure-Request / -Nak / -Reject from the AC) ----------------------

/// What one IPCP control message says. Request: the peer address (option 3) + the options we reject (copied out).
/// Nak: the values the AC proposes (our address, DNS 1/2). Reject: which DNS options the AC refuses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IpcpFacts {
    pub malformed: bool,
    pub peer: Option<[u8; 4]>,
    pub rej: [u8; 64],
    pub nrej: u8,
    pub my_ip: Option<[u8; 4]>,
    pub dns1: Option<[u8; 4]>,
    pub dns2: Option<[u8; 4]>,
    pub rej_dns1: bool,
    pub rej_dns2: bool,
}
pub const IPCP0: IpcpFacts = IpcpFacts { malformed: false, peer: None, rej: [0; 64], nrej: 0, my_ip: None, dns1: None, dns2: None, rej_dns1: false, rej_dns2: false };
pub const CONF_REQ: u8 = 1;
pub const CONF_NAK: u8 = 3;
pub const CONF_REJ: u8 = 4;

pub fn ipcp_facts(code: u8, data: &[u8]) -> IpcpFacts {
    let mut f = IPCP0;
    let mut nrej = 0usize;
    let mut o = 0;
    while o + 2 <= data.len() {
        let (t, l) = (data[o], data[o + 1] as usize);
        if l < 2 || o + l > data.len() {
            // a Request with a malformed list is dropped whole; Nak / Reject keep what parsed before it (as before)
            f.malformed = code == CONF_REQ;
            break;
        }
        let v4 = if l == 6 { Some([data[o + 2], data[o + 3], data[o + 4], data[o + 5]]) } else { None };
        match code {
            CONF_REQ => {
                if t == 3 && l == 6 {
                    f.peer = v4;
                } else if nrej + l <= f.rej.len() {
                    f.rej[nrej..nrej + l].copy_from_slice(&data[o..o + l]);
                    nrej += l;
                }
            }
            CONF_NAK => match (t, v4) {
                (3, Some(v)) => f.my_ip = Some(v),
                (129, Some(v)) => f.dns1 = Some(v),
                (131, Some(v)) => f.dns2 = Some(v),
                _ => {}
            },
            CONF_REJ => match t {
                129 => f.rej_dns1 = true,
                131 => f.rej_dns2 = true,
                _ => {}
            },
            _ => {}
        }
        o += l;
    }
    f.nrej = nrej as u8;
    f
}

pub const IPCP_LEN: usize = 1 + 5 + 64 + 1 + 5 + 5 + 5 + 2;
fn put4(o: &mut [u8], at: usize, v: Option<[u8; 4]>) {
    if let Some(v) = v {
        o[at] = 1;
        o[at + 1..at + 5].copy_from_slice(&v);
    }
}
fn get4(o: &[u8], at: usize) -> Option<[u8; 4]> {
    (o[at] != 0).then(|| [o[at + 1], o[at + 2], o[at + 3], o[at + 4]])
}
pub fn encode_ipcp(f: &IpcpFacts) -> [u8; IPCP_LEN] {
    let mut o = [0u8; IPCP_LEN];
    o[0] = f.malformed as u8;
    put4(&mut o, 1, f.peer);
    o[6..70].copy_from_slice(&f.rej);
    o[70] = f.nrej;
    put4(&mut o, 71, f.my_ip);
    put4(&mut o, 76, f.dns1);
    put4(&mut o, 81, f.dns2);
    o[86] = f.rej_dns1 as u8;
    o[87] = f.rej_dns2 as u8;
    o
}
pub fn decode_ipcp(o: &[u8; IPCP_LEN]) -> IpcpFacts {
    let mut f = IPCP0;
    f.malformed = o[0] != 0;
    f.peer = get4(o, 1);
    f.rej.copy_from_slice(&o[6..70]);
    f.nrej = o[70].min(64);
    f.my_ip = get4(o, 71);
    f.dns1 = get4(o, 76);
    f.dns2 = get4(o, 81);
    f.rej_dns1 = o[86] != 0;
    f.rej_dns2 = o[87] != 0;
    f
}
