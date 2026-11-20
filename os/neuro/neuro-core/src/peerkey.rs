// SPDX-License-Identifier: AGPL-3.0-only
//! Peer identity for the temporal engine: what the **kernel's data plane** computes before it sends an
//! `EV_FLOW` record (`docs/research/neuro/18` D1b, `20` integration contract).
//!
//! Bit-exact port of `tools/neuro-research/unsw_to_d1.py` (`service_peer_fp`, `service_peer_fp_state`,
//! `SetAssocNames`). `tests/peerkey.rs` checks it against vectors that file generates.
//!
//! The deployed key is **V2 /24**. The peer key is chosen by the first rule that applies:
//! 1. infrastructure class (NTP, STUN, DHCP, LAN discovery, broadcast/multicast): one key per class;
//! 2. local peer (RFC 1918, loopback, link-local, ULA): the exact D1 key;
//! 3. a public address the device resolved by DNS within 24 h: registered domain + port;
//! 4. otherwise the /24 (IPv6: /48) prefix + port.
//!
//! No strings and no allocation. The name table stores a 64-bit FNV *state*, never a name.

use crate::{fingerprint, fnv1a64, peer_key, splitmix64};

/// Streaming FNV-1a 64.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fnv(pub u64);

impl Fnv {
    pub const OFFSET: u64 = 0xCBF2_9CE4_8422_2325;

    pub const fn new() -> Self {
        Fnv(Self::OFFSET)
    }

    pub fn bytes(self, b: &[u8]) -> Self {
        let mut h = self.0;
        for &c in b {
            h = (h ^ c as u64).wrapping_mul(0x0000_0100_0000_01B3);
        }
        Fnv(h)
    }

    /// Decimal digits of `v`, as Python's `"%d" % v`.
    pub fn dec(self, v: u32) -> Self {
        let mut buf = [0u8; 10];
        let mut i = buf.len();
        let mut x = v;
        loop {
            i -= 1;
            buf[i] = b'0' + (x % 10) as u8;
            x /= 10;
            if x == 0 {
                break;
            }
        }
        self.bytes(&buf[i..])
    }

    /// Lower-case hex of `b`, as Python's `bytes.hex()`.
    pub fn hex(self, b: &[u8]) -> Self {
        const H: &[u8; 16] = b"0123456789abcdef";
        let mut s = self;
        for &c in b {
            s = s.bytes(&[H[(c >> 4) as usize], H[(c & 15) as usize]]);
        }
        s
    }

    pub fn fp(self) -> u32 {
        fingerprint(self.0)
    }
}

impl Default for Fnv {
    fn default() -> Self {
        Self::new()
    }
}

/// A peer address. IPv4 is kept as 4 bytes (it is *not* the v4-mapped form when keyed).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ip {
    V4([u8; 4]),
    V6([u8; 16]),
}

impl Ip {
    /// The 16-byte table key: IPv4 as `::ffff:a.b.c.d`.
    pub fn as16(&self) -> [u8; 16] {
        match *self {
            Ip::V4(a) => {
                let mut o = [0u8; 16];
                o[10] = 0xFF;
                o[11] = 0xFF;
                o[12..].copy_from_slice(&a);
                o
            }
            Ip::V6(a) => a,
        }
    }
}

/// Transport, or `Any` when only the port is known (research overlays; the kernel always knows it).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Proto {
    Tcp,
    Udp,
    Any,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Class {
    Ntp,
    Stun,
    Dhcp,
    LanDiscovery,
    BroadcastMulticast,
}

impl Class {
    pub fn name(self) -> &'static [u8] {
        match self {
            Class::Ntp => b"ntp",
            Class::Stun => b"stun",
            Class::Dhcp => b"dhcp",
            Class::LanDiscovery => b"lan-discovery",
            Class::BroadcastMulticast => b"broadcast-multicast",
        }
    }
}

/// Which rule produced a key (reported by the data plane as a counter; not sent to the engine).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rule {
    Exact,
    Class,
    Local,
    Named,
    Prefix,
}

/// Mode of the key. `V2 { plen: 24 }` is the deployed one; the others exist for the research parity tests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Exact,
    V1 { plen: u8 },
    V2 { plen: u8 },
}

pub fn is_local(ip: &Ip) -> bool {
    match *ip {
        Ip::V4([a, b, ..]) => {
            a == 10 || a == 127 || (a == 172 && (16..=31).contains(&b)) || (a == 192 && b == 168) || (a == 169 && b == 254)
        }
        Ip::V6(a) => {
            let mut lo = [0u8; 16];
            lo[15] = 1;
            (a[0] & 0xFE) == 0xFC || (a[0] == 0xFE && a[1] & 0xC0 == 0x80) || a == lo
        }
    }
}

pub fn is_bcast_mcast(ip: &Ip) -> bool {
    match *ip {
        Ip::V4(a) => (224..=239).contains(&a[0]) || a == [255; 4] || (is_local(ip) && a[3] == 255),
        Ip::V6(a) => a[0] == 0xFF,
    }
}

pub fn infra_class(ip: &Ip, port: u16, proto: Proto) -> Option<Class> {
    if is_bcast_mcast(ip) {
        return Some(Class::BroadcastMulticast);
    }
    // (class, udp allowed, tcp allowed)
    let (c, u, t) = match port {
        123 => (Class::Ntp, true, false),
        3478 | 3479 | 5349 | 19302 => (Class::Stun, true, true),
        67 | 68 | 546 | 547 => (Class::Dhcp, true, false),
        5353 | 1900 | 5355 | 137 | 138 => (Class::LanDiscovery, true, false),
        _ => return None,
    };
    match proto {
        Proto::Any => Some(c),
        Proto::Udp if u => Some(c),
        Proto::Tcp if t => Some(c),
        _ => None,
    }
}

/// D1's exact key: IPv4 `fingerprint(peer_key(ip, port))`; IPv6 `fingerprint(fnv1a64(ip16 ‖ port BE))`.
pub fn exact_fp(ip: &Ip, port: u16) -> u32 {
    match *ip {
        Ip::V4(a) => fingerprint(peer_key(u32::from_be_bytes(a), port)),
        Ip::V6(a) => {
            let mut b = [0u8; 18];
            b[..16].copy_from_slice(&a);
            b[16..].copy_from_slice(&port.to_be_bytes());
            fingerprint(fnv1a64(&b))
        }
    }
}

/// The FNV state after `"svc:" ‖ registered domain ‖ ":"`. Computed once per DNS answer; stored in the table.
pub fn svc_state(registered_domain: &[u8]) -> u64 {
    Fnv::new().bytes(b"svc:").bytes(registered_domain).bytes(b":").0
}

/// The peer fingerprint for one new connection. `named` is the table's stored state for (device, address)
/// if the device resolved this address within the window, else `None`.
pub fn peer_fp(mode: Mode, ip: &Ip, port: u16, proto: Proto, named: Option<u64>) -> (u32, Rule) {
    let (infra, plen) = match mode {
        Mode::Exact => return (exact_fp(ip, port), Rule::Exact),
        Mode::V1 { plen } => (false, plen),
        Mode::V2 { plen } => (true, plen),
    };
    if infra {
        if let Some(c) = infra_class(ip, port, proto) {
            return (Fnv::new().bytes(b"cls:").bytes(c.name()).fp(), Rule::Class);
        }
    }
    if is_local(ip) {
        return (exact_fp(ip, port), Rule::Local);
    }
    if let Some(st) = named {
        return (Fnv(st).dec(port as u32).fp(), Rule::Named);
    }
    let f = Fnv::new().bytes(b"net:");
    let f = match *ip {
        Ip::V4(a) if plen == 24 => f.dec(a[0] as u32).bytes(b".").dec(a[1] as u32).bytes(b".").dec(a[2] as u32).bytes(b".0/24"),
        Ip::V4(a) => f.dec(a[0] as u32).bytes(b".").dec(a[1] as u32).bytes(b".0.0/16"),
        Ip::V6(a) => f.hex(&a[..6]).bytes(b"/48"),
    };
    (f.bytes(b":").dec(port as u32).fp(), Rule::Prefix)
}

/// Seconds a DNS answer names its addresses (doc 18).
pub const NAME_WINDOW_S: u32 = 86_400;
pub const WAYS: usize = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NameEntry {
    pub used: bool,
    pub dev: u16,
    pub ip: [u8; 16],
    pub state: u64,
    pub ts: u32,
}

impl NameEntry {
    pub const EMPTY: NameEntry = NameEntry { used: false, dev: 0, ip: [0; 16], state: 0, ts: 0 };
}

/// The kernel-shaped address → service table: ONE table for all devices, `N` entries in 4-way sets keyed by
/// (device, address). A full set evicts the entry with the oldest timestamp (lowest way on ties).
/// `N` must be a multiple of 4 with a power-of-two set count. An entry is 32 B: 4,096 entries = 128 KiB.
pub struct NameTable<const N: usize> {
    e: [NameEntry; N],
}

impl<const N: usize> NameTable<N> {
    const SETS: usize = N / WAYS;
    const _CHECK: () = assert!(N.is_multiple_of(WAYS) && (N / WAYS).is_power_of_two());

    pub const fn new() -> Self {
        let () = Self::_CHECK;
        NameTable { e: [NameEntry::EMPTY; N] }
    }

    fn base(dev: u16, ip16: &[u8; 16]) -> usize {
        let mut k = [0u8; 18];
        k[..2].copy_from_slice(&dev.to_le_bytes());
        k[2..].copy_from_slice(ip16);
        (splitmix64(fnv1a64(&k)) % Self::SETS as u64) as usize * WAYS
    }

    /// A DNS answer to `dev` named `ip`: remember the service state at time `ts` (seconds).
    pub fn insert(&mut self, dev: u16, ip: &Ip, state: u64, ts: u32) {
        let k = ip.as16();
        let b = Self::base(dev, &k);
        let set = &mut self.e[b..b + WAYS];
        let j = set
            .iter()
            .position(|x| x.used && x.dev == dev && x.ip == k)
            .or_else(|| set.iter().position(|x| !x.used))
            .unwrap_or_else(|| {
                let mut v = 0;
                for (i, x) in set.iter().enumerate() {
                    if x.ts < set[v].ts {
                        v = i;
                    }
                }
                v
            });
        set[j] = NameEntry { used: true, dev, ip: k, state, ts };
    }

    /// The stored state if `dev` resolved `ip` within the window ending at `now`.
    pub fn lookup(&self, dev: u16, ip: &Ip, now: u32) -> Option<u64> {
        let k = ip.as16();
        let b = Self::base(dev, &k);
        self.e[b..b + WAYS]
            .iter()
            .find(|x| x.used && x.dev == dev && x.ip == k)
            .and_then(|x| if now >= x.ts && now - x.ts <= NAME_WINDOW_S { Some(x.state) } else { None })
    }
}

impl<const N: usize> Default for NameTable<N> {
    fn default() -> Self {
        Self::new()
    }
}
