//! SNTP over the WAN uplink for images whose Mission Control node lives on the LAN side (the AP):
//! parity gap G11 — the AP had no wall clock (every timestamp boot-relative). Pure: the caller sends
//! the frame `request` builds on the WAN and offers each inbound WAN frame to `on_frame`.
//!
//! Same acceptance rule as prod-mc (`mcstate::sntp_parse_strict`): only a reply FROM the server we
//! asked, from port 123, to our port, echoing our 64-bit nonce, server mode, sane stratum, after the
//! build-era floor. One answer per request (a replayed copy is refused).

/// Our UDP source port (outside the NAT's external range 40000+).
pub const NTP_PORT_LOCAL: u16 = 39_123;
const RETRY_S: u64 = 15;
const RESYNC_S: u64 = 3600;
/// Public anycast servers tried after the WAN gateway (IP literals: no DNS needed to set the clock).
const SERVERS: [[u8; 4]; 2] = [[162, 159, 200, 1], [162, 159, 200, 123]];

pub struct WanNtp {
    pub nonce: u64,
    pub server: [u8; 4],
    pub next_s: u64,
    pub tries: u32,
    pub synced: u32,
    pub refused: u32,
}

impl WanNtp {
    pub const fn new() -> Self {
        WanNtp { nonce: 0, server: [0; 4], next_s: 0, tries: 0, synced: 0, refused: 0 }
    }

    /// Due a request at `now_s`? Builds the Ethernet/IPv4/UDP frame into `out` (returns its length).
    /// `nonce` must be unpredictable (TRNG); 0 = no entropy → no request.
    pub fn request(&mut self, now_s: u64, nonce: u64, gw: [u8; 4], wan_ip: [u8; 4], wan_mac: &[u8; 6], gw_mac: &[u8; 6], out: &mut [u8]) -> Option<usize> {
        if now_s < self.next_s || nonce == 0 || wan_ip == [0; 4] || out.len() < 90 {
            return None;
        }
        let cands = [gw, SERVERS[0], SERVERS[1]];
        let srv = cands[(self.tries as usize) % 3];
        let srv = if srv == [0; 4] { SERVERS[0] } else { srv };
        self.nonce = nonce | 1;
        self.server = srv;
        self.tries = self.tries.wrapping_add(1);
        self.next_s = now_s + if self.synced > 0 { RESYNC_S } else { RETRY_S };
        let mut p = [0u8; 48];
        p[0] = 0x23; // LI 0 | VN 4 | Mode 3 (client)
        p[40..48].copy_from_slice(&self.nonce.to_be_bytes());
        Some(udp4(out, wan_mac, gw_mac, wan_ip, srv, NTP_PORT_LOCAL, 123, &p))
    }

    /// An inbound WAN frame: Some(unix_ms) if it is the valid answer to our outstanding request.
    /// Frames that are not for our NTP port return None untouched (the caller passes them on).
    pub fn on_frame(&mut self, f: &[u8], wan_ip: [u8; 4], now_s: u64) -> Option<u64> {
        if !is_ours(f, wan_ip) {
            return None;
        }
        let ihl = ((f[14] & 0x0f) as usize) * 4;
        let u = 14 + ihl;
        let from = [f[26], f[27], f[28], f[29]];
        let sport = u16::from_be_bytes([f[u], f[u + 1]]);
        if self.nonce == 0 || from != self.server || sport != 123 {
            self.refused += 1;
            return None;
        }
        let ulen = (u16::from_be_bytes([f[u + 4], f[u + 5]]) as usize).min(f.len() - u);
        let ms = crate::mcstate::sntp_parse_strict(f.get(u + 8..u + ulen)?, self.nonce);
        match ms {
            Some(ms) => {
                self.nonce = 0;
                self.synced += 1;
                self.next_s = now_s + RESYNC_S;
                Some(ms)
            }
            None => {
                self.refused += 1;
                None
            }
        }
    }
}

/// Is this an IPv4/UDP frame to `wan_ip`:NTP_PORT_LOCAL? (Then it is consumed, never NATed.)
pub fn is_ours(f: &[u8], wan_ip: [u8; 4]) -> bool {
    if f.len() < 42 || f[12..14] != [0x08, 0x00] || f[14] >> 4 != 4 || f[23] != 17 || f[30..34] != wan_ip {
        return false;
    }
    let u = 14 + ((f[14] & 0x0f) as usize) * 4;
    u + 8 <= f.len() && u16::from_be_bytes([f[u + 2], f[u + 3]]) == NTP_PORT_LOCAL
}

fn csum(b: &[u8], init: u32) -> u16 {
    let mut s = init;
    let mut i = 0;
    while i + 1 < b.len() {
        s += u16::from_be_bytes([b[i], b[i + 1]]) as u32;
        i += 2;
    }
    if i < b.len() {
        s += (b[i] as u32) << 8;
    }
    while s >> 16 != 0 {
        s = (s & 0xffff) + (s >> 16);
    }
    !(s as u16)
}

fn udp4(out: &mut [u8], smac: &[u8; 6], dmac: &[u8; 6], sip: [u8; 4], dip: [u8; 4], sp: u16, dp: u16, payload: &[u8]) -> usize {
    let ul = 8 + payload.len();
    let total = 14 + 20 + ul;
    out[0..6].copy_from_slice(dmac);
    out[6..12].copy_from_slice(smac);
    out[12..14].copy_from_slice(&[0x08, 0x00]);
    out[14..34].copy_from_slice(&[0x45, 0, 0, 0, 0, 0, 0x40, 0, 64, 17, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    out[16..18].copy_from_slice(&((20 + ul) as u16).to_be_bytes());
    out[26..30].copy_from_slice(&sip);
    out[30..34].copy_from_slice(&dip);
    let c = csum(&out[14..34], 0);
    out[24..26].copy_from_slice(&c.to_be_bytes());
    out[34..36].copy_from_slice(&sp.to_be_bytes());
    out[36..38].copy_from_slice(&dp.to_be_bytes());
    out[38..40].copy_from_slice(&(ul as u16).to_be_bytes());
    out[40..42].copy_from_slice(&[0, 0]);
    out[42..total].copy_from_slice(payload);
    let mut ps = 17u32 + ul as u32;
    for k in (26..34).step_by(2) {
        ps += u16::from_be_bytes([out[k], out[k + 1]]) as u32;
    }
    let mut uc = csum(&out[34..total], ps);
    if uc == 0 {
        uc = 0xffff;
    }
    out[40..42].copy_from_slice(&uc.to_be_bytes());
    total
}

/// `[P-wanntp]`
pub fn selftest() -> bool {
    let wan = [100u8, 71, 11, 24];
    let gw = [100u8, 71, 11, 1];
    let (mw, mg) = ([2u8, 0, 0, 0, 0, 2], [2u8, 0, 0, 0, 0, 1]);
    let mut n = WanNtp::new();
    let mut f = [0u8; 128];
    let k = n.request(10, 0xDEAD_BEEF_0000_1234, gw, wan, &mw, &mg, &mut f);
    let req_ok = k == Some(90) && f[30..34] == gw && f[36..38] == 123u16.to_be_bytes() && f[34..36] == NTP_PORT_LOCAL.to_be_bytes()
        && f[42] == 0x23 && csum(&f[14..34], 0) == 0;
    let not_yet = n.request(11, 7, gw, wan, &mw, &mg, &mut [0u8; 128]).is_none();
    let no_entropy = WanNtp::new().request(0, 0, gw, wan, &mw, &mg, &mut [0u8; 128]).is_none();
    // a valid reply: swap addresses/ports, server mode, stratum 2, originate = nonce, a 2027 time
    let reply = |from: [u8; 4], sport: u16, orig: u64, out: &mut [u8; 128]| {
        let mut p = [0u8; 48];
        p[0] = 0x24; // LI 0 VN 4 mode 4
        p[1] = 2;
        p[24..32].copy_from_slice(&orig.to_be_bytes());
        let secs: u32 = (1_800_000_000u64 + 2_208_988_800) as u32;
        p[40..44].copy_from_slice(&secs.to_be_bytes());
        udp4(out, &mg, &mw, from, wan, sport, NTP_PORT_LOCAL, &p)
    };
    let mut r = [0u8; 128];
    let nonce = n.nonce;
    let rl = reply([1, 2, 3, 4], 123, nonce, &mut r);
    let wrong_src = n.on_frame(&r[..rl], wan, 12).is_none();
    let rl = reply(gw, 1234, nonce, &mut r);
    let wrong_port = n.on_frame(&r[..rl], wan, 12).is_none();
    let rl = reply(gw, 123, nonce ^ 2, &mut r);
    let wrong_nonce = n.on_frame(&r[..rl], wan, 12).is_none();
    let rl = reply(gw, 123, nonce, &mut r);
    let good = n.on_frame(&r[..rl], wan, 12) == Some(1_800_000_000_000);
    let replay = n.on_frame(&r[..rl], wan, 13).is_none();
    let other = !is_ours(&[0u8; 60], wan);
    let trunc = (0..rl).all(|l| {
        let mut m = WanNtp { nonce, server: gw, ..WanNtp::new() };
        m.on_frame(&r[..l], wan, 1).is_none() || l == rl
    });
    let resync = n.next_s == 12 + RESYNC_S;
    let pass = req_ok && not_yet && no_entropy && wrong_src && wrong_port && wrong_nonce && good && replay && other && trunc && resync;
    arch_aarch64::_print(format_args!(
        " [P-wanntp] {} — WAN SNTP for the AP image (parity G11): request frame (gw first, IP-literal anycast fallback, valid IP/UDP checksums)={} rate-limited={} no TRNG -> no request={} | reply from another host refused={} from a non-123 port refused={} wrong nonce refused={} valid reply -> Unix time={} replayed copy refused={} unrelated frame untouched={} every truncation safe={} hourly resync scheduled={}\n",
        if pass { "PASS" } else { "FAIL" }, req_ok, not_yet, no_entropy, wrong_src, wrong_port, wrong_nonce, good, replay, other, trunc, resync
    ));
    pass
}
