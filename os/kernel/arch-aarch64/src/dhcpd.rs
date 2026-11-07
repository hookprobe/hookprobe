//! Inside-side DHCP server lease table + client fingerprint (parity gaps G1/G2). Target-independent and
//! pure (time is passed in), so QEMU can regression-test it; the AP/LAN serve path in `cyw43.rs` drives it.
//!
//! Fixes over the first AP server: leases EXPIRE and are RECLAIMED (the old table only grew — the 17th
//! distinct MAC was refused until reboot), DHCPRELEASE is honoured, the pool is 128, "clients" means
//! ACTIVE leases, and each lease keeps what the client told us about itself (hostname opt 12, vendor class
//! opt 60, parameter-request list opt 55) so the device inventory is real. A client always gets the same
//! address back while its slot is not reclaimed (keyed on MAC), and the NAT leg's (MAC, IP) binding check
//! still stops one client sourcing traffic as another.

pub const LEASES: usize = 128;
/// Lease time handed out (option 51).
pub const LEASE_SECS: u64 = 3600;
/// An expired binding is still honoured for forwarding this long (a client renewing late keeps working).
pub const GRACE_SECS: u64 = 600;

#[derive(Clone, Copy)]
pub struct Lease {
    pub used: bool,
    pub mac: [u8; 6],
    pub ip: [u8; 4],
    /// Epoch-less seconds (the caller's monotonic clock). 0 = offered, never acknowledged.
    pub expires: u64,
    pub first: u64,
    pub last: u64,
    pub host: [u8; 32],
    pub hlen: u8,
    pub vendor: [u8; 32],
    pub vlen: u8,
    pub prl: [u8; 24],
    pub plen: u8,
}

pub const LEASE0: Lease = Lease { used: false, mac: [0; 6], ip: [0; 4], expires: 0, first: 0, last: 0, host: [0; 32], hlen: 0, vendor: [0; 32], vlen: 0, prl: [0; 24], plen: 0 };

pub struct ApDhcp {
    pub arp_replies: u32,
    pub discovers: u32,
    pub offers_tx: u32,
    pub requests: u32,
    pub acks_tx: u32,
    pub naks_tx: u32,
    pub releases: u32,
    pub reclaimed: u32,
    pub client_mac: [u8; 6],
    pub leased_ip: [u8; 4],
    pub leases: [Lease; LEASES],
    /// Slots ever used (high-water mark); see `active` for live clients.
    pub nleases: usize,
    pub pool_full: u32,
    /// Current time in seconds (monotonic), set by the caller before each use.
    pub now: u64,
}

impl ApDhcp {
    pub fn new() -> Self {
        ApDhcp {
            arp_replies: 0, discovers: 0, offers_tx: 0, requests: 0, acks_tx: 0, naks_tx: 0, releases: 0, reclaimed: 0,
            client_mac: [0; 6], leased_ip: [0; 4], leases: [LEASE0; LEASES], nleases: 0, pool_full: 0, now: 0,
        }
    }

    fn slot(&self, mac: &[u8; 6]) -> Option<usize> {
        self.leases[..self.nleases].iter().position(|l| l.used && l.mac == *mac)
    }

    /// The address bound to `mac`, if it has one.
    pub fn lease_for(&self, mac: &[u8; 6]) -> Option<[u8; 4]> {
        self.slot(mac).map(|i| self.leases[i].ip)
    }

    fn live(&self, l: &Lease) -> bool {
        l.used && (l.expires == 0 || self.now < l.expires.saturating_add(GRACE_SECS))
    }

    /// The address for `mac`: its binding; else a never-used slot; else the expired slot that has been
    /// idle longest (reclaimed). None = every slot holds a live lease.
    pub fn alloc_for(&mut self, mac: &[u8; 6], pool_base: &[u8; 4]) -> Option<[u8; 4]> {
        if let Some(i) = self.slot(mac) {
            return Some(self.leases[i].ip);
        }
        let room = (255usize.saturating_sub(pool_base[3] as usize)).min(LEASES);
        let i = if self.nleases < room {
            self.nleases += 1;
            self.nleases - 1
        } else {
            // reclaim: an offered-never-acked slot older than a minute, or an expired one; oldest first
            let now = self.now;
            let cand = (0..self.nleases)
                .filter(|&k| {
                    let l = &self.leases[k];
                    !l.used || (l.expires == 0 && now >= l.last + 60) || (l.expires != 0 && now >= l.expires.saturating_add(GRACE_SECS))
                })
                .min_by_key(|&k| self.leases[k].last);
            match cand {
                Some(k) => {
                    self.reclaimed += 1;
                    k
                }
                None => {
                    self.pool_full += 1;
                    return None;
                }
            }
        };
        let mut ip = *pool_base;
        ip[3] = pool_base[3].wrapping_add(i as u8);
        self.leases[i] = Lease { used: true, mac: *mac, ip, expires: 0, first: self.now, last: self.now, ..LEASE0 };
        Some(ip)
    }

    /// The client accepted (ACK sent): the lease runs `LEASE_SECS` from now.
    pub fn commit(&mut self, mac: &[u8; 6]) {
        if let Some(i) = self.slot(mac) {
            let now = self.now;
            let l = &mut self.leases[i];
            l.expires = now + LEASE_SECS;
            l.last = now;
        }
    }

    /// DHCPRELEASE: the address is free at once (the slot keeps its fingerprint until reused).
    pub fn release(&mut self, mac: &[u8; 6]) {
        if let Some(i) = self.slot(mac) {
            self.leases[i].expires = 1;
            self.releases += 1;
        }
    }

    /// Traffic seen from `mac` (keeps `last` current for the inventory).
    pub fn seen(&mut self, mac: &[u8; 6]) {
        if let Some(i) = self.slot(mac) {
            self.leases[i].last = self.now;
        }
    }

    /// Is (mac, ip) a live lease we handed out? The NAT leg's anti-hijack check.
    pub fn binding_ok(&self, mac: &[u8; 6], ip: &[u8; 4]) -> bool {
        self.slot(mac).map_or(false, |i| self.leases[i].ip == *ip && self.live(&self.leases[i]))
    }

    /// Clients holding an unexpired, acknowledged lease.
    pub fn active(&self) -> usize {
        self.leases[..self.nleases].iter().filter(|l| l.used && l.expires > self.now).count()
    }

    /// Record what the client said about itself (from its DISCOVER/REQUEST).
    pub fn note_identity(&mut self, mac: &[u8; 6], id: &ClientId) {
        if let Some(i) = self.slot(mac) {
            let l = &mut self.leases[i];
            if id.hlen > 0 {
                l.host = id.host;
                l.hlen = id.hlen;
            }
            if id.vlen > 0 {
                l.vendor = id.vendor;
                l.vlen = id.vlen;
            }
            if id.plen > 0 {
                l.prl = id.prl;
                l.plen = id.plen;
            }
        }
    }
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
fn clean(src: &[u8], dst: &mut [u8]) -> u8 {
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

/// An honest OS-family guess from the vendor class + parameter-request list ("" = unknown). Rules from the
/// common DHCP fingerprints (fingerbank-lite): exact vendor prefixes first, then distinctive PRL shapes.
pub fn os_guess(vendor: &[u8], prl: &[u8]) -> &'static str {
    let v = vendor;
    if v.starts_with(b"android-dhcp") {
        return "Android";
    }
    if v.starts_with(b"MSFT") {
        return "Windows";
    }
    if v.starts_with(b"dhcpcd") {
        return "Linux (dhcpcd)";
    }
    if v.starts_with(b"udhcp") {
        return "embedded Linux";
    }
    if v.starts_with(b"ubnt") || v.starts_with(b"Ubiquiti") {
        return "Ubiquiti";
    }
    // Apple (iOS/iPadOS/macOS): PRL begins 1,121,3,6,15,108,114,119,252
    if prl.len() >= 6 && prl[..3] == [1, 121, 3] && prl.contains(&252) && prl.contains(&108) {
        return "Apple iOS/macOS";
    }
    if prl.len() >= 4 && prl[..4] == [1, 3, 6, 15] && prl.contains(&252) && prl.contains(&44) {
        return "Windows";
    }
    if prl.len() >= 4 && prl[..4] == [1, 3, 6, 15] && prl.contains(&26) && prl.contains(&119) {
        return "Android";
    }
    if prl.len() >= 3 && prl[..3] == [1, 28, 2] {
        return "Linux";
    }
    ""
}

/// A locally-administered (randomised / private Wi-Fi) MAC.
pub fn mac_is_private(mac: &[u8; 6]) -> bool {
    mac[0] & 0x02 != 0
}

/// `[P-dhcpd]` selftest.
pub fn selftest() -> bool {
    let base = [10u8, 99, 0, 10];
    let mut d = ApDhcp::new();
    d.now = 1000;
    let mac = |i: u8| [0x02, 0, 0, 0, 0, i];
    // same MAC -> same address; distinct MACs -> distinct addresses
    let a = d.alloc_for(&mac(1), &base);
    let b = d.alloc_for(&mac(2), &base);
    let stable = a == Some([10, 99, 0, 10]) && b == Some([10, 99, 0, 11]) && d.alloc_for(&mac(1), &base) == a;
    d.commit(&mac(1));
    d.commit(&mac(2));
    let bind = d.binding_ok(&mac(1), &[10, 99, 0, 10]) && !d.binding_ok(&mac(1), &[10, 99, 0, 11]) && !d.binding_ok(&mac(9), &[10, 99, 0, 10]);
    let active2 = d.active() == 2;
    // fill the pool with live leases: the next MAC is refused (no silent theft of a live lease)
    for i in 3..=LEASES as u8 {
        let _ = d.alloc_for(&mac(i), &base);
        d.commit(&mac(i));
    }
    let full = d.alloc_for(&[0x02, 1, 1, 1, 1, 1], &base).is_none() && d.pool_full == 1;
    // time passes: leases expire + grace -> the oldest-idle slot is reclaimed for a NEW client
    d.now = 1000 + LEASE_SECS + GRACE_SECS + 1;
    d.seen(&mac(5)); // mac 5 keeps talking but its lease is expired too
    let newc = d.alloc_for(&[0x02, 1, 1, 1, 1, 1], &base);
    let reclaim = newc.is_some() && newc != Some([10, 99, 0, 14]) && d.reclaimed == 1 && d.active() == 0;
    // an expired binding beyond grace no longer passes the NAT check
    let expired_bind = !d.binding_ok(&mac(1), &[10, 99, 0, 10]);
    // RELEASE frees at once
    let mut r = ApDhcp::new();
    r.now = 50;
    let _ = r.alloc_for(&mac(1), &base);
    r.commit(&mac(1));
    r.release(&mac(1));
    let released = r.active() == 0 && r.releases == 1;
    // a pool base near .255 never wraps into .0/.255
    let mut h = ApDhcp::new();
    let hb = [10u8, 0, 0, 250];
    let mut last = None;
    for i in 0..10u8 {
        if let Some(ip) = h.alloc_for(&mac(i), &hb) {
            last = Some(ip);
        }
    }
    let nowrap = last == Some([10, 0, 0, 254]) && h.pool_full > 0;
    // identity options parse + sanitise; OS guess
    let mut f = [0u8; 400];
    f[12] = 0x08;
    f[13] = 0x00;
    f[14] = 0x45;
    f[23] = 17;
    f[34..36].copy_from_slice(&68u16.to_be_bytes());
    f[36..38].copy_from_slice(&67u16.to_be_bytes());
    f[42] = 1;
    f[42 + 236..42 + 240].copy_from_slice(&[0x63, 0x82, 0x53, 0x63]);
    let opts: &[u8] = &[53, 1, 3, 12, 11, b'J', b'o', b'h', b'n', b's', b'-', b'i', b'P', b'<', b'>', b'!', 55, 9, 1, 121, 3, 6, 15, 108, 114, 119, 252, 255];
    f[282..282 + opts.len()].copy_from_slice(opts);
    let id = client_identity(&f[..282 + opts.len()]);
    let ident = id.mt == 3 && &id.host[..id.hlen as usize] == b"Johns-iP" && id.plen == 9 && os_guess(&id.vendor[..id.vlen as usize], &id.prl[..id.plen as usize]) == "Apple iOS/macOS";
    let guess = os_guess(b"android-dhcp-14", &[]) == "Android" && os_guess(b"MSFT 5.0", &[]) == "Windows" && os_guess(b"", &[9, 9]) == "";
    let trunc = (0..282 + opts.len()).all(|l| client_identity(&f[..l]).hlen <= 32);
    let private = mac_is_private(&[0x02, 0, 0, 0, 0, 1]) && !mac_is_private(&[0x00, 0x1b, 0x63, 0, 0, 1]);
    let pass = stable && bind && active2 && full && reclaim && expired_bind && released && nowrap && ident && guess && trunc && private;
    crate::_print(format_args!(
        " [P-dhcpd] {} — DHCP server lease table (parity G1/G2): stable per-MAC address={} binding check={} active count={} full pool refuses (no theft of live leases)={} expired lease reclaimed oldest-idle-first={} expired binding fails the NAT check={} RELEASE frees={} pool never wraps past .254={} | client identity (hostname sanitised, PRL)={} OS guess={} every truncation safe={} private-MAC detect={}\n",
        if pass { "PASS" } else { "FAIL" }, stable, bind, active2, full, reclaim, expired_bind, released, nowrap, ident, guess, trunc, private
    ));
    pass
}
