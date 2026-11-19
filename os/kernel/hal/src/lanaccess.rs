// SPDX-License-Identifier: AGPL-3.0-only
//! A-01 (operator decision 2026-11-17): Wi-Fi / LAN clients may not reach **upstream private networks** (the
//! networks beyond the WAN: an ISP router's page, an upstream NAS or printer, the management network) unless the
//! owner made an exception. Pure logic, host-tested; the kernel holds one [`Table`] and one [`Blocks`] ring.
//!
//! * [`upstream_private`]: RFC 1918, IPv4 link-local 169.254/16, IPv6 ULA fc00::/7.
//! * [`Table`]: owner exceptions, each scoped to a device (or any device) × a destination prefix × optional ports,
//!   with an optional expiry (ms on the device clock; 0 = no expiry).
//! * [`Blocks`]: the attributed record of what was refused (device, destination, port, count, first / last seen),
//!   so Mission Control can say *what* was blocked and offer the exception — a bounded ring, oldest evicted.
use crate::policy::{Addr, Prefix};

/// Is `a` an upstream private address: RFC 1918 (10/8, 172.16/12, 192.168/16), 169.254/16, or ULA fc00::/7?
pub fn upstream_private(a: &Addr) -> bool {
    if a.v6 {
        return a.a[0] & 0xfe == 0xfc;
    }
    let (o0, o1) = (a.a[0], a.a[1]);
    o0 == 10 || (o0 == 172 && (16..=31).contains(&o1)) || (o0 == 192 && o1 == 168) || (o0 == 169 && o1 == 254)
}

/// One owner exception.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Exception {
    /// The device it applies to, or `None` = any device.
    pub device: Option<[u8; 6]>,
    pub dst: Prefix,
    /// Destination port range; (0, 0) = every port.
    pub ports: (u16, u16),
    /// Expiry, ms on the device clock; 0 = none.
    pub expires_ms: u64,
}

impl Exception {
    fn covers(&self, mac: &[u8; 6], dst: &Addr, dport: u16, now_ms: u64) -> bool {
        (self.expires_ms == 0 || now_ms < self.expires_ms)
            && self.device.is_none_or(|d| d == *mac)
            && self.dst.contains(dst)
            && (self.ports == (0, 0) || (dport >= self.ports.0 && dport <= self.ports.1))
    }
}

pub const EXC_MAX: usize = 32;

/// The active exceptions.
#[derive(Clone, Copy, Debug)]
pub struct Table {
    pub e: [Exception; EXC_MAX],
    pub n: usize,
}

impl Default for Table {
    fn default() -> Self {
        Self::new()
    }
}

impl Table {
    pub const fn new() -> Self {
        Table { e: [Exception { device: None, dst: Prefix { addr: Addr { v6: false, a: [0; 16] }, len: 0 }, ports: (0, 0), expires_ms: 0 }; EXC_MAX], n: 0 }
    }
    /// Add (or replace an identical scope); false when full. A temporary grant never downgrades an always exception of
    /// the same scope (R3, code review 2026-11-18: it used to give the always one an expiry).
    pub fn add(&mut self, x: Exception) -> bool {
        if let Some(i) = self.e[..self.n].iter().position(|e| e.device == x.device && e.dst == x.dst && e.ports == x.ports) {
            if !(self.e[i].expires_ms == 0 && x.expires_ms != 0) {
                self.e[i] = x;
            }
            return true;
        }
        if self.n == EXC_MAX {
            return false;
        }
        self.e[self.n] = x;
        self.n += 1;
        true
    }
    /// Would [`Table::add`] accept `x` (an identical scope is replaced in place, else a free slot is needed)?
    pub fn has_room(&self, x: &Exception) -> bool {
        self.n < EXC_MAX || self.e[..self.n].iter().any(|e| e.device == x.device && e.dst == x.dst && e.ports == x.ports)
    }
    pub fn clear(&mut self) {
        self.n = 0;
    }
    /// Remove the exception with this scope (device, destination, ports); true if one was there.
    pub fn remove(&mut self, device: Option<[u8; 6]>, dst: Prefix, ports: (u16, u16)) -> bool {
        let Some(i) = self.e[..self.n].iter().position(|e| e.device == device && e.dst == dst && e.ports == ports) else { return false };
        self.e[i] = self.e[self.n - 1];
        self.n -= 1;
        true
    }
    /// Does an unexpired exception cover (device, destination, port)?
    pub fn allows(&self, mac: &[u8; 6], dst: &Addr, dport: u16, now_ms: u64) -> bool {
        self.e[..self.n].iter().any(|e| e.covers(mac, dst, dport, now_ms))
    }
    /// Drop expired entries (the API shows only live ones).
    pub fn prune(&mut self, now_ms: u64) {
        let mut k = 0;
        for i in 0..self.n {
            if self.e[i].expires_ms == 0 || now_ms < self.e[i].expires_ms {
                self.e[k] = self.e[i];
                k += 1;
            }
        }
        self.n = k;
    }
}

/// The owner journal's target bytes for one exception scope (`Kind::LanAccess`): flags (bit 0 any device, bit 1
/// IPv6) ‖ MAC 6 ‖ address 16 ‖ prefix length ‖ ports lo 2 ‖ ports hi 2 ‖ duration s 4 (0 = always).
pub const SCOPE_LEN: usize = 32;

pub fn encode(x: &Exception, dur_s: u32, out: &mut [u8; SCOPE_LEN]) {
    *out = [0; SCOPE_LEN];
    out[0] = (x.device.is_none() as u8) | ((x.dst.addr.v6 as u8) << 1);
    out[1..7].copy_from_slice(&x.device.unwrap_or([0; 6]));
    out[7..23].copy_from_slice(&x.dst.addr.a);
    out[23] = x.dst.len;
    out[24..26].copy_from_slice(&x.ports.0.to_be_bytes());
    out[26..28].copy_from_slice(&x.ports.1.to_be_bytes());
    out[28..32].copy_from_slice(&dur_s.to_be_bytes());
}

/// (the exception without an expiry, its duration in seconds; 0 = always). None = malformed.
pub fn decode(t: &[u8]) -> Option<(Exception, u32)> {
    if t.len() != SCOPE_LEN || t[0] & !3 != 0 {
        return None;
    }
    let v6 = t[0] & 2 != 0;
    let len = t[23];
    if len > if v6 { 128 } else { 32 } {
        return None;
    }
    let mut a = [0u8; 16];
    a.copy_from_slice(&t[7..23]);
    let mut m = [0u8; 6];
    m.copy_from_slice(&t[1..7]);
    let x = Exception {
        device: if t[0] & 1 != 0 { None } else { Some(m) },
        dst: Prefix { addr: Addr { v6, a }, len },
        ports: (u16::from_be_bytes([t[24], t[25]]), u16::from_be_bytes([t[26], t[27]])),
        expires_ms: 0,
    };
    if x.ports.0 > x.ports.1 {
        return None;
    }
    Some((x, u32::from_be_bytes([t[28], t[29], t[30], t[31]])))
}

/// One attributed block.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Block {
    pub mac: [u8; 6],
    pub src: Addr,
    pub dst: Addr,
    pub dport: u16,
    pub proto: u8,
    pub count: u32,
    pub first_ms: u64,
    pub last_ms: u64,
}

pub const BLOCKS_MAX: usize = 32;

/// The ring of attributed blocks: one entry per (device, destination, port, protocol), oldest-seen evicted.
#[derive(Clone, Copy, Debug)]
pub struct Blocks {
    pub b: [Block; BLOCKS_MAX],
    pub n: usize,
}

impl Default for Blocks {
    fn default() -> Self {
        Self::new()
    }
}

impl Blocks {
    pub const fn new() -> Self {
        Blocks { b: [Block { mac: [0; 6], src: Addr { v6: false, a: [0; 16] }, dst: Addr { v6: false, a: [0; 16] }, dport: 0, proto: 0, count: 0, first_ms: 0, last_ms: 0 }; BLOCKS_MAX], n: 0 }
    }
    pub fn record(&mut self, mac: [u8; 6], src: Addr, dst: Addr, dport: u16, proto: u8, now_ms: u64) {
        if let Some(e) = self.b[..self.n].iter_mut().find(|e| e.mac == mac && e.dst == dst && e.dport == dport && e.proto == proto) {
            e.count = e.count.saturating_add(1);
            e.last_ms = now_ms;
            e.src = src; // the device's current address
            return;
        }
        let i = if self.n < BLOCKS_MAX {
            self.n += 1;
            self.n - 1
        } else {
            (0..BLOCKS_MAX).min_by_key(|&i| self.b[i].last_ms).unwrap_or(0)
        };
        self.b[i] = Block { mac, src, dst, dport, proto, count: 1, first_ms: now_ms, last_ms: now_ms };
    }
    /// Forget the blocks an exception now covers (they are resolved, not to be offered again).
    pub fn resolve(&mut self, x: &Exception, now_ms: u64) {
        let mut k = 0;
        for i in 0..self.n {
            if !x.covers(&self.b[i].mac, &self.b[i].dst, self.b[i].dport, now_ms) {
                self.b[k] = self.b[i];
                k += 1;
            }
        }
        self.n = k;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(a: u8, b: u8, c: u8, d: u8) -> Addr {
        Addr::v4([a, b, c, d])
    }
    fn pfx(a: Addr, len: u8) -> Prefix {
        Prefix { addr: a, len }
    }
    const M1: [u8; 6] = [2, 0, 0, 0, 0, 1];
    const M2: [u8; 6] = [2, 0, 0, 0, 0, 2];

    #[test]
    fn private_classes() {
        for a in [v4(10, 1, 2, 3), v4(172, 16, 0, 1), v4(172, 31, 255, 255), v4(192, 168, 1, 50), v4(169, 254, 9, 9)] {
            assert!(upstream_private(&a), "{a:?}");
        }
        for a in [v4(172, 15, 0, 1), v4(172, 32, 0, 1), v4(8, 8, 8, 8), v4(100, 64, 0, 1), v4(192, 169, 0, 1)] {
            assert!(!upstream_private(&a), "{a:?}");
        }
        let mut ula = [0u8; 16];
        ula[0] = 0xfd;
        assert!(upstream_private(&Addr::v6(ula)));
        ula[0] = 0xfc;
        assert!(upstream_private(&Addr::v6(ula)));
        ula[0] = 0x20; // 2000::/3 global
        assert!(!upstream_private(&Addr::v6(ula)));
    }

    #[test]
    fn exceptions_are_scoped_and_expire() {
        let mut t = Table::new();
        // device M1 may reach the printer's IPP / raw ports for 1 h
        assert!(t.add(Exception { device: Some(M1), dst: pfx(v4(192, 168, 1, 50), 32), ports: (631, 631), expires_ms: 3_600_000 }));
        assert!(t.allows(&M1, &v4(192, 168, 1, 50), 631, 10));
        assert!(!t.allows(&M2, &v4(192, 168, 1, 50), 631, 10), "another device");
        assert!(!t.allows(&M1, &v4(192, 168, 1, 50), 22, 10), "another port");
        assert!(!t.allows(&M1, &v4(192, 168, 1, 51), 631, 10), "another host");
        assert!(!t.allows(&M1, &v4(192, 168, 1, 50), 631, 3_600_000), "expired");
        // any device may reach the NAS on every port, no expiry
        assert!(t.add(Exception { device: None, dst: pfx(v4(192, 168, 1, 20), 32), ports: (0, 0), expires_ms: 0 }));
        assert!(t.allows(&M2, &v4(192, 168, 1, 20), 445, u64::MAX - 1));
        t.prune(3_600_000);
        assert_eq!(t.n, 1, "the expired one is gone, the permanent one stays");
        // R3: a temporary grant of the same scope never downgrades the always exception
        assert!(t.add(Exception { device: None, dst: pfx(v4(192, 168, 1, 20), 32), ports: (0, 0), expires_ms: 5 }));
        assert_eq!(t.n, 1);
        assert_eq!(t.e[0].expires_ms, 0, "still always");
        assert!(t.allows(&M2, &v4(192, 168, 1, 20), 445, 10));
        // a temporary one is replaced by a later grant (no duplicates)
        assert!(t.add(Exception { device: Some(M1), dst: pfx(v4(192, 168, 1, 50), 32), ports: (631, 631), expires_ms: 7 }));
        assert!(t.add(Exception { device: Some(M1), dst: pfx(v4(192, 168, 1, 50), 32), ports: (631, 631), expires_ms: 9 }));
        assert_eq!(t.n, 2);
        // room: a full table has room only for a scope already in it
        let mut f = Table::new();
        for i in 0..EXC_MAX as u8 {
            assert!(f.add(Exception { device: None, dst: pfx(v4(10, 0, i, 1), 32), ports: (0, 0), expires_ms: 0 }));
        }
        let fresh = Exception { device: None, dst: pfx(v4(10, 1, 0, 1), 32), ports: (0, 0), expires_ms: 0 };
        assert!(!f.has_room(&fresh));
        assert!(f.has_room(&Exception { dst: pfx(v4(10, 0, 3, 1), 32), ..fresh }));
    }

    #[test]
    fn scope_round_trips_and_removes() {
        let x = Exception { device: Some(M1), dst: pfx(v4(192, 168, 1, 50), 32), ports: (631, 9100), expires_ms: 0 };
        let mut t = [0u8; SCOPE_LEN];
        encode(&x, 3600, &mut t);
        assert_eq!(decode(&t), Some((x, 3600)));
        let any = Exception { device: None, dst: pfx(v4(10, 0, 0, 0), 8), ports: (0, 0), expires_ms: 0 };
        encode(&any, 0, &mut t);
        assert_eq!(decode(&t), Some((any, 0)));
        assert!(decode(&t[..31]).is_none());
        let mut bad = t;
        bad[23] = 33; // a /33
        assert!(decode(&bad).is_none());
        let mut tb = Table::new();
        assert!(tb.add(x) && tb.add(any));
        assert!(tb.remove(Some(M1), pfx(v4(192, 168, 1, 50), 32), (631, 9100)));
        assert!(!tb.remove(Some(M1), pfx(v4(192, 168, 1, 50), 32), (631, 9100)), "already gone");
        assert_eq!(tb.n, 1);
    }

    #[test]
    fn blocks_are_attributed_merged_and_bounded() {
        let mut b = Blocks::new();
        b.record(M1, v4(10, 99, 0, 10), v4(192, 168, 1, 50), 631, 6, 100);
        b.record(M1, v4(10, 99, 0, 10), v4(192, 168, 1, 50), 631, 6, 200);
        assert_eq!(b.n, 1);
        assert_eq!((b.b[0].count, b.b[0].first_ms, b.b[0].last_ms), (2, 100, 200));
        for i in 0..BLOCKS_MAX as u8 + 5 {
            b.record(M2, v4(10, 99, 0, 11), v4(192, 168, 2, i), 80, 6, 1000 + i as u64);
        }
        assert_eq!(b.n, BLOCKS_MAX, "bounded");
        assert!(!b.b[..b.n].iter().any(|e| e.mac == M1), "the oldest-seen entry was evicted");
        // an exception resolves the blocks it covers
        let x = Exception { device: Some(M2), dst: pfx(v4(192, 168, 2, 0), 24), ports: (80, 80), expires_ms: 0 };
        b.resolve(&x, 5000);
        assert_eq!(b.n, 0);
    }
}
