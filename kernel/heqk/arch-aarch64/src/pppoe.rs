//! PPPoE client (RFC 2516) + PPP (RFC 1661 LCP, RFC 1334 PAP, RFC 1994 CHAP-MD5, RFC 1332 IPCP,
//! RFC 1877 DNS) for the WAN port. A PURE state machine — frames in, frames out, a millisecond
//! clock for retransmits — no MMIO, so QEMU drives it end to end against a scripted server and the
//! CM5 uplink just shuttles frames to/from the GEM.
//!
//! Scope (IPv4 stage): discovery (PADI/PADO/PADR/PADS, PADT), LCP (MRU 1492, magic, Ack/Nak/
//! Reject of the server's options, Echo-Reply, Terminate, Protocol-Reject for protocols we do not
//! run — e.g. the IPV6CP an ISP opens), PAP or CHAP-MD5, IPCP (address + primary/secondary DNS).
//! IPv6 (IPV6CP + DHCPv6-PD) is the next stage; until then IPV6CP is Protocol-Rejected, which keeps
//! the IPv4 session up (RFC 1661 §5.7).

pub const ETH_DISC: u16 = 0x8863;
pub const ETH_SESS: u16 = 0x8864;
pub const PPP_IP: u16 = 0x0021;
const PPP_LCP: u16 = 0xc021;
const PPP_PAP: u16 = 0xc023;
const PPP_CHAP: u16 = 0xc223;
const PPP_IPCP: u16 = 0x8021;

const CODE_PADI: u8 = 0x09;
const CODE_PADO: u8 = 0x07;
const CODE_PADR: u8 = 0x19;
const CODE_PADS: u8 = 0x65;
const CODE_PADT: u8 = 0xa7;

const TAG_END: u16 = 0x0000;
const TAG_SERVICE_NAME: u16 = 0x0101;
const TAG_AC_NAME: u16 = 0x0102;
const TAG_HOST_UNIQ: u16 = 0x0103;
const TAG_AC_COOKIE: u16 = 0x0104;
const TAG_RELAY_SID: u16 = 0x0110;
const TAG_SERVICE_NAME_ERR: u16 = 0x0201;
const TAG_AC_SYSTEM_ERR: u16 = 0x0202;
const TAG_GENERIC_ERR: u16 = 0x0203;

// PPP control codes (RFC 1661 §5).
const CONF_REQ: u8 = 1;
const CONF_ACK: u8 = 2;
const CONF_NAK: u8 = 3;
const CONF_REJ: u8 = 4;
const TERM_REQ: u8 = 5;
const TERM_ACK: u8 = 6;
const PROTO_REJ: u8 = 8;
const ECHO_REQ: u8 = 9;
const ECHO_REP: u8 = 10;

/// PPPoE MTU on 1500-byte Ethernet: 1500 - 6 (PPPoE header) - 2 (PPP protocol) (RFC 2516 §7).
pub const PPPOE_MTU: u16 = 1492;
/// TCP MSS for PPPoE: MTU - 20 (IP) - 20 (TCP).
pub const PPPOE_MSS: u16 = PPPOE_MTU - 40;

const RETRY_MS: u64 = 2_000;
const MAX_TRIES: u32 = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Idle,
    Discovery,
    Requesting,
    Lcp,
    Auth,
    Ipcp,
    Open,
    Down,
}

/// Why the session is down (for the operator's log).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DownWhy {
    None,
    NoPado,
    NoPads,
    PadsError,
    LcpTimeout,
    AuthRejected,
    AuthUnsupported,
    AuthTimeout,
    IpcpTimeout,
    NoAddress,
    PeerTerminated,
    Padt,
}

/// Up to three control frames produced by one input (a reply plus a new-phase request).
pub struct Tx {
    pub f: [[u8; 256]; 3],
    pub len: [usize; 3],
    pub n: usize,
}

impl Tx {
    pub const fn new() -> Self {
        Tx { f: [[0; 256]; 3], len: [0; 3], n: 0 }
    }
    pub fn clear(&mut self) {
        self.n = 0;
    }
    fn slot(&mut self) -> Option<&mut [u8; 256]> {
        if self.n < 3 {
            Some(&mut self.f[self.n])
        } else {
            None
        }
    }
    fn commit(&mut self, len: usize) {
        if self.n < 3 && len > 0 {
            self.len[self.n] = len;
            self.n += 1;
        }
    }
    pub fn frame(&self, i: usize) -> &[u8] {
        &self.f[i][..self.len[i]]
    }
}

#[derive(Clone, Copy, Default, Debug)]
pub struct Stats {
    pub padi: u32,
    pub pado: u32,
    pub padr: u32,
    pub pads: u32,
    pub lcp_req_tx: u32,
    pub lcp_req_rx: u32,
    pub lcp_nak_rej_tx: u32,
    pub echo_replies: u32,
    pub proto_rejects: u32,
    pub auth_tx: u32,
    pub ipcp_req_tx: u32,
}

pub struct Pppoe {
    pub mac: [u8; 6],
    pub ac_mac: [u8; 6],
    pub sid: u16,
    pub phase: Phase,
    pub why: DownWhy,
    pub stats: Stats,
    /// Negotiated: our address, the peer (gateway) address, resolvers, the auth protocol used.
    pub my_ip: [u8; 4],
    pub peer_ip: [u8; 4],
    pub dns1: [u8; 4],
    pub dns2: [u8; 4],
    pub auth: u16,
    pub ac_name: [u8; 32],
    pub ac_name_len: usize,
    host_uniq: [u8; 4],
    cookie: [u8; 64],
    cookie_len: usize,
    relay: [u8; 64],
    relay_len: usize,
    user: [u8; 64],
    ulen: usize,
    pass: [u8; 64],
    plen: usize,
    // LCP
    lcp_id: u8,
    magic: u32,
    mru: u16,
    send_mru: bool,
    send_magic: bool,
    lcp_ack_rx: bool,
    lcp_ack_tx: bool,
    // IPCP
    ipcp_id: u8,
    want_dns1: bool,
    want_dns2: bool,
    ipcp_ack_rx: bool,
    ipcp_ack_tx: bool,
    // PAP
    pap_id: u8,
    // retransmit
    last_ms: u64,
    tries: u32,
}

fn be16(b: &[u8], o: usize) -> u16 {
    u16::from_be_bytes([b[o], b[o + 1]])
}

impl Pppoe {
    pub fn new(mac: [u8; 6], user: &[u8], pass: &[u8], host_uniq: u32, magic: u32) -> Self {
        let mut u = [0u8; 64];
        let mut p = [0u8; 64];
        let ulen = user.len().min(64);
        let plen = pass.len().min(64);
        u[..ulen].copy_from_slice(&user[..ulen]);
        p[..plen].copy_from_slice(&pass[..plen]);
        Pppoe {
            mac, ac_mac: [0; 6], sid: 0, phase: Phase::Idle, why: DownWhy::None, stats: Stats::default(),
            my_ip: [0; 4], peer_ip: [0; 4], dns1: [0; 4], dns2: [0; 4], auth: 0,
            ac_name: [0; 32], ac_name_len: 0,
            host_uniq: host_uniq.to_be_bytes(), cookie: [0; 64], cookie_len: 0, relay: [0; 64], relay_len: 0,
            user: u, ulen, pass: p, plen,
            lcp_id: 0, magic: if magic == 0 { 0x4845_514b } else { magic }, mru: PPPOE_MTU, send_mru: true, send_magic: true,
            lcp_ack_rx: false, lcp_ack_tx: false,
            ipcp_id: 0, want_dns1: true, want_dns2: true, ipcp_ack_rx: false, ipcp_ack_tx: false,
            pap_id: 0, last_ms: 0, tries: 0,
        }
    }

    /// Begin discovery (PADI).
    pub fn start(&mut self, now_ms: u64, tx: &mut Tx) {
        self.phase = Phase::Discovery;
        self.tries = 0;
        self.send_padi(now_ms, tx);
    }

    fn down(&mut self, why: DownWhy) {
        self.phase = Phase::Down;
        self.why = why;
    }

    // ── discovery ──────────────────────────────────────────────────────────────────────────
    fn disc_hdr(&self, b: &mut [u8], dst: &[u8; 6], code: u8, sid: u16) -> usize {
        b[0..6].copy_from_slice(dst);
        b[6..12].copy_from_slice(&self.mac);
        b[12..14].copy_from_slice(&ETH_DISC.to_be_bytes());
        b[14] = 0x11;
        b[15] = code;
        b[16..18].copy_from_slice(&sid.to_be_bytes());
        20 // payload starts here; length written by the caller
    }

    fn tag(b: &mut [u8], o: usize, t: u16, v: &[u8]) -> usize {
        b[o..o + 2].copy_from_slice(&t.to_be_bytes());
        b[o + 2..o + 4].copy_from_slice(&(v.len() as u16).to_be_bytes());
        b[o + 4..o + 4 + v.len()].copy_from_slice(v);
        o + 4 + v.len()
    }

    fn send_padi(&mut self, now_ms: u64, tx: &mut Tx) {
        let hu = self.host_uniq;
        let me = &*self;
        let Some(b) = tx.slot() else { return };
        let mut o = me.disc_hdr(b, &[0xff; 6], CODE_PADI, 0);
        o = Self::tag(b, o, TAG_SERVICE_NAME, &[]);
        o = Self::tag(b, o, TAG_HOST_UNIQ, &hu);
        let plen = (o - 20) as u16;
        b[18..20].copy_from_slice(&plen.to_be_bytes());
        tx.commit(o.max(60));
        self.stats.padi += 1;
        self.last_ms = now_ms;
    }

    fn send_padr(&mut self, now_ms: u64, tx: &mut Tx) {
        let (hu, ck, ckl, rl, rll, ac) = (self.host_uniq, self.cookie, self.cookie_len, self.relay, self.relay_len, self.ac_mac);
        let me = &*self;
        let Some(b) = tx.slot() else { return };
        let mut o = me.disc_hdr(b, &ac, CODE_PADR, 0);
        o = Self::tag(b, o, TAG_SERVICE_NAME, &[]);
        o = Self::tag(b, o, TAG_HOST_UNIQ, &hu);
        if ckl > 0 {
            o = Self::tag(b, o, TAG_AC_COOKIE, &ck[..ckl]);
        }
        if rll > 0 {
            o = Self::tag(b, o, TAG_RELAY_SID, &rl[..rll]);
        }
        let plen = (o - 20) as u16;
        b[18..20].copy_from_slice(&plen.to_be_bytes());
        tx.commit(o.max(60));
        self.stats.padr += 1;
        self.last_ms = now_ms;
    }

    /// Walk the discovery tags of `f` (payload from 20, `plen` bytes). Returns (host_uniq_ok, error).
    fn read_tags(&mut self, f: &[u8], plen: usize, keep: bool) -> (bool, bool) {
        let end = (20 + plen).min(f.len());
        let mut o = 20;
        let (mut hu_ok, mut err) = (false, false);
        while o + 4 <= end {
            let (t, l) = (be16(f, o), be16(f, o + 2) as usize);
            let v0 = o + 4;
            if v0 + l > end {
                break;
            }
            let v = &f[v0..v0 + l];
            match t {
                TAG_END => break,
                TAG_HOST_UNIQ => hu_ok = v == self.host_uniq,
                TAG_AC_COOKIE if keep => {
                    self.cookie_len = l.min(64);
                    self.cookie[..self.cookie_len].copy_from_slice(&v[..self.cookie_len]);
                }
                TAG_RELAY_SID if keep => {
                    self.relay_len = l.min(64);
                    self.relay[..self.relay_len].copy_from_slice(&v[..self.relay_len]);
                }
                TAG_AC_NAME if keep => {
                    self.ac_name_len = l.min(32);
                    self.ac_name[..self.ac_name_len].copy_from_slice(&v[..self.ac_name_len]);
                }
                TAG_SERVICE_NAME_ERR | TAG_AC_SYSTEM_ERR | TAG_GENERIC_ERR => err = true,
                _ => {}
            }
            o = v0 + l;
        }
        (hu_ok, err)
    }

    // ── session framing ────────────────────────────────────────────────────────────────────
    /// Write a PPPoE session header + PPP protocol into `b`; returns the offset of the PPP payload.
    fn sess_hdr(&self, b: &mut [u8], proto: u16) -> usize {
        b[0..6].copy_from_slice(&self.ac_mac);
        b[6..12].copy_from_slice(&self.mac);
        b[12..14].copy_from_slice(&ETH_SESS.to_be_bytes());
        b[14] = 0x11;
        b[15] = 0;
        b[16..18].copy_from_slice(&self.sid.to_be_bytes());
        b[20..22].copy_from_slice(&proto.to_be_bytes());
        22
    }

    /// Finish a session frame whose PPP payload ends at `end`: fill the PPPoE length.
    fn sess_finish(b: &mut [u8], end: usize) -> usize {
        let plen = (end - 20) as u16; // PPP protocol + payload
        b[18..20].copy_from_slice(&plen.to_be_bytes());
        end.max(60)
    }

    /// One PPP control packet (code, id, data) on `proto`.
    fn send_ctl(&mut self, tx: &mut Tx, proto: u16, code: u8, id: u8, data: &[u8]) {
        let me = &*self;
        let Some(b) = tx.slot() else { return };
        let o = me.sess_hdr(b, proto);
        let len = 4 + data.len();
        if o + len > b.len() {
            return;
        }
        b[o] = code;
        b[o + 1] = id;
        b[o + 2..o + 4].copy_from_slice(&(len as u16).to_be_bytes());
        b[o + 4..o + len].copy_from_slice(data);
        let n = Self::sess_finish(b, o + len);
        tx.commit(n);
    }

    fn send_lcp_req(&mut self, now_ms: u64, tx: &mut Tx) {
        let mut d = [0u8; 16];
        let mut n = 0;
        if self.send_mru {
            d[n..n + 4].copy_from_slice(&[1, 4, (self.mru >> 8) as u8, self.mru as u8]);
            n += 4;
        }
        if self.send_magic {
            d[n] = 5;
            d[n + 1] = 6;
            d[n + 2..n + 6].copy_from_slice(&self.magic.to_be_bytes());
            n += 6;
        }
        self.lcp_id = self.lcp_id.wrapping_add(1);
        let id = self.lcp_id;
        self.send_ctl(tx, PPP_LCP, CONF_REQ, id, &d[..n]);
        self.stats.lcp_req_tx += 1;
        self.last_ms = now_ms;
    }

    fn send_ipcp_req(&mut self, now_ms: u64, tx: &mut Tx) {
        let mut d = [0u8; 18];
        let mut n = 0;
        d[n] = 3;
        d[n + 1] = 6;
        d[n + 2..n + 6].copy_from_slice(&self.my_ip);
        n += 6;
        if self.want_dns1 {
            d[n] = 129;
            d[n + 1] = 6;
            d[n + 2..n + 6].copy_from_slice(&self.dns1);
            n += 6;
        }
        if self.want_dns2 {
            d[n] = 131;
            d[n + 1] = 6;
            d[n + 2..n + 6].copy_from_slice(&self.dns2);
            n += 6;
        }
        self.ipcp_id = self.ipcp_id.wrapping_add(1);
        let id = self.ipcp_id;
        self.send_ctl(tx, PPP_IPCP, CONF_REQ, id, &d[..n]);
        self.stats.ipcp_req_tx += 1;
        self.last_ms = now_ms;
    }

    fn send_pap(&mut self, now_ms: u64, tx: &mut Tx) {
        let mut d = [0u8; 2 + 64 + 64];
        d[0] = self.ulen as u8;
        d[1..1 + self.ulen].copy_from_slice(&self.user[..self.ulen]);
        let o = 1 + self.ulen;
        d[o] = self.plen as u8;
        d[o + 1..o + 1 + self.plen].copy_from_slice(&self.pass[..self.plen]);
        self.pap_id = self.pap_id.wrapping_add(1);
        let id = self.pap_id;
        self.send_ctl(tx, PPP_PAP, 1, id, &d[..o + 1 + self.plen]);
        self.stats.auth_tx += 1;
        self.last_ms = now_ms;
    }

    /// LCP and auth are done -> start IPCP (or open the session once both sides acked).
    fn lcp_maybe_open(&mut self, now_ms: u64, tx: &mut Tx) {
        if self.phase == Phase::Lcp && self.lcp_ack_rx && self.lcp_ack_tx {
            self.tries = 0;
            match self.auth {
                PPP_PAP => {
                    self.phase = Phase::Auth;
                    self.send_pap(now_ms, tx);
                }
                PPP_CHAP => {
                    self.phase = Phase::Auth; // wait for the Challenge
                    self.last_ms = now_ms;
                }
                _ => {
                    self.phase = Phase::Ipcp;
                    self.send_ipcp_req(now_ms, tx);
                }
            }
        }
    }

    fn ipcp_maybe_open(&mut self) {
        if self.phase == Phase::Ipcp && self.ipcp_ack_rx && self.ipcp_ack_tx {
            if self.my_ip == [0; 4] {
                self.down(DownWhy::NoAddress);
            } else {
                self.phase = Phase::Open;
            }
        }
    }

    /// Retransmit / give up on timers. Call regularly with a monotonic millisecond clock.
    pub fn tick(&mut self, now_ms: u64, tx: &mut Tx) {
        if now_ms.wrapping_sub(self.last_ms) < RETRY_MS {
            return;
        }
        match self.phase {
            Phase::Discovery | Phase::Requesting | Phase::Lcp | Phase::Auth | Phase::Ipcp => {}
            _ => return,
        }
        self.tries += 1;
        if self.tries > MAX_TRIES {
            let why = match self.phase {
                Phase::Discovery => DownWhy::NoPado,
                Phase::Requesting => DownWhy::NoPads,
                Phase::Lcp => DownWhy::LcpTimeout,
                Phase::Auth => DownWhy::AuthTimeout,
                _ => DownWhy::IpcpTimeout,
            };
            self.down(why);
            return;
        }
        match self.phase {
            Phase::Discovery => self.send_padi(now_ms, tx),
            Phase::Requesting => self.send_padr(now_ms, tx),
            Phase::Lcp => self.send_lcp_req(now_ms, tx),
            Phase::Auth if self.auth == PPP_PAP => self.send_pap(now_ms, tx),
            Phase::Auth => self.last_ms = now_ms, // CHAP: the server re-challenges
            Phase::Ipcp => self.send_ipcp_req(now_ms, tx),
            _ => {}
        }
    }

    /// Feed one received Ethernet frame. Replies / next requests are appended to `tx`.
    pub fn rx(&mut self, f: &[u8], now_ms: u64, tx: &mut Tx) {
        if f.len() < 20 || f[14] != 0x11 {
            return;
        }
        let et = be16(f, 12);
        let dst_ok = f[0..6] == self.mac || f[0..6] == [0xff; 6];
        if !dst_ok {
            return;
        }
        if et == ETH_DISC {
            let (code, sid, plen) = (f[15], be16(f, 16), be16(f, 18) as usize);
            match (self.phase, code) {
                (Phase::Discovery, CODE_PADO) => {
                    let (hu, err) = self.read_tags(f, plen, true);
                    if hu && !err {
                        self.ac_mac.copy_from_slice(&f[6..12]);
                        self.stats.pado += 1;
                        self.phase = Phase::Requesting;
                        self.tries = 0;
                        self.send_padr(now_ms, tx);
                    }
                }
                (Phase::Requesting, CODE_PADS) if f[6..12] == self.ac_mac => {
                    let (hu, err) = self.read_tags(f, plen, false);
                    if !hu {
                        return;
                    }
                    if err || sid == 0 {
                        self.down(DownWhy::PadsError);
                        return;
                    }
                    self.sid = sid;
                    self.stats.pads += 1;
                    self.phase = Phase::Lcp;
                    self.tries = 0;
                    self.send_lcp_req(now_ms, tx);
                }
                (_, CODE_PADT) if sid == self.sid && sid != 0 && f[6..12] == self.ac_mac => self.down(DownWhy::Padt),
                _ => {}
            }
            return;
        }
        if et != ETH_SESS || self.sid == 0 || be16(f, 16) != self.sid || f[6..12] != self.ac_mac || f.len() < 22 {
            return;
        }
        let plen = (be16(f, 18) as usize).min(f.len() - 20);
        if plen < 2 {
            return;
        }
        let proto = be16(f, 20);
        let p = &f[22..20 + plen];
        match proto {
            PPP_LCP => self.on_lcp(p, now_ms, tx),
            PPP_PAP => self.on_pap(p, now_ms, tx),
            PPP_CHAP => self.on_chap(p, now_ms, tx),
            PPP_IPCP => self.on_ipcp(p, now_ms, tx),
            PPP_IP => {} // data: handled by the caller (decap_ipv4)
            _ => {
                // RFC 1661 §5.7: Protocol-Reject anything we do not run (IPV6CP, CCP, IPv6 ...),
                // only once LCP is opened.
                if matches!(self.phase, Phase::Auth | Phase::Ipcp | Phase::Open) {
                    let mut d = [0u8; 200];
                    d[0..2].copy_from_slice(&proto.to_be_bytes());
                    let k = p.len().min(d.len() - 2);
                    d[2..2 + k].copy_from_slice(&p[..k]);
                    self.lcp_id = self.lcp_id.wrapping_add(1);
                    let id = self.lcp_id;
                    self.send_ctl(tx, PPP_LCP, PROTO_REJ, id, &d[..2 + k]);
                    self.stats.proto_rejects += 1;
                }
            }
        }
    }

    fn ctl(p: &[u8]) -> Option<(u8, u8, &[u8])> {
        if p.len() < 4 {
            return None;
        }
        let len = (be16(p, 2) as usize).min(p.len());
        if len < 4 {
            return None;
        }
        Some((p[0], p[1], &p[4..len]))
    }

    fn on_lcp(&mut self, p: &[u8], now_ms: u64, tx: &mut Tx) {
        let Some((code, id, data)) = Self::ctl(p) else { return };
        match code {
            CONF_REQ => {
                self.stats.lcp_req_rx += 1;
                // Classify every option: Reject unknown/unsupported, Nak an auth we cannot do.
                let mut rej = [0u8; 128];
                let mut nrej = 0;
                let mut nak = [0u8; 16];
                let mut nnak = 0;
                let mut auth = 0u16;
                let mut o = 0;
                while o + 2 <= data.len() {
                    let (t, l) = (data[o], data[o + 1] as usize);
                    if l < 2 || o + l > data.len() {
                        return; // malformed: silently drop (RFC 1661)
                    }
                    let opt = &data[o..o + l];
                    match t {
                        1 | 2 | 5 => {} // MRU, ACCM (meaningless on PPPoE, harmless), Magic
                        3 if l >= 4 => {
                            let ap = be16(opt, 2);
                            if ap == PPP_PAP && l == 4 {
                                auth = PPP_PAP;
                            } else if ap == PPP_CHAP && l == 5 && opt[4] == 5 {
                                auth = PPP_CHAP;
                            } else if nnak == 0 {
                                // Suggest CHAP-MD5 (RFC 1994) instead.
                                nak[..5].copy_from_slice(&[3, 5, 0xc2, 0x23, 5]);
                                nnak = 5;
                            }
                        }
                        _ => {
                            if nrej + l <= rej.len() {
                                rej[nrej..nrej + l].copy_from_slice(opt);
                                nrej += l;
                            }
                        }
                    }
                    o += l;
                }
                if nrej > 0 {
                    self.send_ctl(tx, PPP_LCP, CONF_REJ, id, &rej[..nrej]);
                    self.stats.lcp_nak_rej_tx += 1;
                } else if nnak > 0 {
                    self.send_ctl(tx, PPP_LCP, CONF_NAK, id, &nak[..nnak]);
                    self.stats.lcp_nak_rej_tx += 1;
                } else {
                    self.auth = auth;
                    self.send_ctl(tx, PPP_LCP, CONF_ACK, id, data);
                    self.lcp_ack_tx = true;
                    self.lcp_maybe_open(now_ms, tx);
                }
            }
            CONF_ACK if id == self.lcp_id && self.phase == Phase::Lcp => {
                self.lcp_ack_rx = true;
                self.lcp_maybe_open(now_ms, tx);
            }
            CONF_NAK if id == self.lcp_id && self.phase == Phase::Lcp => {
                let mut o = 0;
                while o + 2 <= data.len() {
                    let (t, l) = (data[o], data[o + 1] as usize);
                    if l < 2 || o + l > data.len() {
                        break;
                    }
                    match t {
                        1 if l == 4 => self.mru = be16(data, o + 2).min(PPPOE_MTU),
                        5 if l == 6 => self.magic = self.magic.rotate_left(7) ^ 0x5a5a_a5a5,
                        _ => {}
                    }
                    o += l;
                }
                self.send_lcp_req(now_ms, tx);
            }
            CONF_REJ if id == self.lcp_id && self.phase == Phase::Lcp => {
                let mut o = 0;
                while o + 2 <= data.len() {
                    let (t, l) = (data[o], data[o + 1] as usize);
                    if l < 2 || o + l > data.len() {
                        break;
                    }
                    match t {
                        1 => self.send_mru = false,
                        5 => self.send_magic = false,
                        _ => {}
                    }
                    o += l;
                }
                self.send_lcp_req(now_ms, tx);
            }
            ECHO_REQ => {
                let mut d = [0u8; 64];
                d[..4].copy_from_slice(&self.magic.to_be_bytes());
                let k = data.len().saturating_sub(4).min(60);
                d[4..4 + k].copy_from_slice(&data[4..4 + k]);
                self.send_ctl(tx, PPP_LCP, ECHO_REP, id, &d[..4 + k]);
                self.stats.echo_replies += 1;
            }
            TERM_REQ => {
                self.send_ctl(tx, PPP_LCP, TERM_ACK, id, &[]);
                self.down(DownWhy::PeerTerminated);
            }
            _ => {}
        }
    }

    fn on_pap(&mut self, p: &[u8], now_ms: u64, tx: &mut Tx) {
        let Some((code, id, _)) = Self::ctl(p) else { return };
        if self.phase != Phase::Auth || self.auth != PPP_PAP || id != self.pap_id {
            return;
        }
        match code {
            2 => {
                self.phase = Phase::Ipcp;
                self.tries = 0;
                self.send_ipcp_req(now_ms, tx);
            }
            3 => self.down(DownWhy::AuthRejected),
            _ => {}
        }
    }

    fn on_chap(&mut self, p: &[u8], now_ms: u64, tx: &mut Tx) {
        let Some((code, id, data)) = Self::ctl(p) else { return };
        if self.phase != Phase::Auth || self.auth != PPP_CHAP {
            return;
        }
        match code {
            1 => {
                // Challenge: value-size, value, name. Response = MD5(id || secret || challenge).
                if data.is_empty() {
                    return;
                }
                let vs = data[0] as usize;
                if 1 + vs > data.len() || vs > 64 {
                    return;
                }
                let mut m = [0u8; 1 + 64 + 64];
                m[0] = id;
                m[1..1 + self.plen].copy_from_slice(&self.pass[..self.plen]);
                m[1 + self.plen..1 + self.plen + vs].copy_from_slice(&data[1..1 + vs]);
                let h = hal::md5(&m[..1 + self.plen + vs]);
                let mut d = [0u8; 1 + 16 + 64];
                d[0] = 16;
                d[1..17].copy_from_slice(&h);
                d[17..17 + self.ulen].copy_from_slice(&self.user[..self.ulen]);
                let n = 17 + self.ulen;
                self.send_ctl(tx, PPP_CHAP, 2, id, &d[..n]);
                self.stats.auth_tx += 1;
                self.last_ms = now_ms;
            }
            3 => {
                self.phase = Phase::Ipcp;
                self.tries = 0;
                self.send_ipcp_req(now_ms, tx);
            }
            4 => self.down(DownWhy::AuthRejected),
            _ => {}
        }
    }

    fn on_ipcp(&mut self, p: &[u8], now_ms: u64, tx: &mut Tx) {
        let Some((code, id, data)) = Self::ctl(p) else { return };
        if !matches!(self.phase, Phase::Ipcp | Phase::Open) {
            return;
        }
        match code {
            CONF_REQ => {
                // The peer's own address (option 3); reject anything else (e.g. VJ compression).
                let mut rej = [0u8; 64];
                let mut nrej = 0;
                let mut peer = self.peer_ip;
                let mut o = 0;
                while o + 2 <= data.len() {
                    let (t, l) = (data[o], data[o + 1] as usize);
                    if l < 2 || o + l > data.len() {
                        return;
                    }
                    if t == 3 && l == 6 {
                        peer.copy_from_slice(&data[o + 2..o + 6]);
                    } else if nrej + l <= rej.len() {
                        rej[nrej..nrej + l].copy_from_slice(&data[o..o + l]);
                        nrej += l;
                    }
                    o += l;
                }
                if nrej > 0 {
                    self.send_ctl(tx, PPP_IPCP, CONF_REJ, id, &rej[..nrej]);
                } else {
                    self.peer_ip = peer;
                    self.send_ctl(tx, PPP_IPCP, CONF_ACK, id, data);
                    self.ipcp_ack_tx = true;
                    self.ipcp_maybe_open();
                }
            }
            CONF_ACK if id == self.ipcp_id => {
                self.ipcp_ack_rx = true;
                self.ipcp_maybe_open();
            }
            CONF_NAK if id == self.ipcp_id => {
                let mut o = 0;
                while o + 2 <= data.len() {
                    let (t, l) = (data[o], data[o + 1] as usize);
                    if l < 2 || o + l > data.len() {
                        break;
                    }
                    if l == 6 {
                        let v = [data[o + 2], data[o + 3], data[o + 4], data[o + 5]];
                        match t {
                            3 => self.my_ip = v,
                            129 => self.dns1 = v,
                            131 => self.dns2 = v,
                            _ => {}
                        }
                    }
                    o += l;
                }
                self.send_ipcp_req(now_ms, tx);
            }
            CONF_REJ if id == self.ipcp_id => {
                let mut o = 0;
                while o + 2 <= data.len() {
                    let (t, l) = (data[o], data[o + 1] as usize);
                    if l < 2 || o + l > data.len() {
                        break;
                    }
                    match t {
                        129 => self.want_dns1 = false,
                        131 => self.want_dns2 = false,
                        _ => {}
                    }
                    o += l;
                }
                self.send_ipcp_req(now_ms, tx);
            }
            TERM_REQ => {
                self.send_ctl(tx, PPP_IPCP, TERM_ACK, id, &[]);
                self.down(DownWhy::PeerTerminated);
            }
            _ => {}
        }
    }

    /// Wrap an Ethernet/IPv4 frame (as the NAT engine builds it) into a PPPoE session frame for
    /// this session: [AC mac][our mac][0x8864][0x11 0 sid len][0x0021][IP ...]. Returns the length.
    pub fn encap_ipv4(&self, eth: &[u8], out: &mut [u8]) -> Option<usize> {
        if eth.len() < 34 || be16(eth, 12) != 0x0800 {
            return None;
        }
        let ip = &eth[14..];
        let tot = (be16(ip, 2) as usize).min(ip.len());
        if tot > PPPOE_MTU as usize || 22 + tot > out.len() {
            return None;
        }
        let o = self.sess_hdr(out, PPP_IP);
        out[o..o + tot].copy_from_slice(&ip[..tot]);
        Some(Self::sess_finish(out, o + tot))
    }

    /// If `f` is an IPv4 packet of this session, rewrite it as an Ethernet/IPv4 frame addressed to
    /// us (src = the AC) in `out` — what the NAT engine expects. Returns the length.
    pub fn decap_ipv4(&self, f: &[u8], out: &mut [u8]) -> Option<usize> {
        if f.len() < 22 + 20 || be16(f, 12) != ETH_SESS || f[14] != 0x11 || be16(f, 16) != self.sid
            || self.sid == 0 || f[6..12] != self.ac_mac || be16(f, 20) != PPP_IP
        {
            return None;
        }
        let plen = (be16(f, 18) as usize).min(f.len() - 20);
        let ip = &f[22..20 + plen];
        if 14 + ip.len() > out.len() {
            return None;
        }
        out[0..6].copy_from_slice(&self.mac);
        out[6..12].copy_from_slice(&self.ac_mac);
        out[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
        out[14..14 + ip.len()].copy_from_slice(ip);
        Some(14 + ip.len())
    }

    /// Send a PADT for this session (orderly shutdown).
    pub fn padt(&self, tx: &mut Tx) {
        let (ac, sid) = (self.ac_mac, self.sid);
        let me = &*self;
        let Some(b) = tx.slot() else { return };
        let o = me.disc_hdr(b, &ac, CODE_PADT, sid);
        b[18..20].copy_from_slice(&0u16.to_be_bytes());
        tx.commit(o.max(60));
    }
}
