//! ADR 0049 D2 — tagged source identity for the source-keyed tiers (parity G24a/G18).
//!
//! The rate / scan / corroboration tables key on a `u64`. IPv4 sources keep their address (`< 2^32`), so
//! IPv4 behaviour is byte-identical. IPv6 sources get their own, non-aliasing spaces:
//!   * `Dev`   (bit 63) — a device on OUR link (Wi-Fi / eth1): hash of its MAC. Survives privacy-address
//!     rotation (RFC 8981): one phone is one key whatever IID it uses.
//!   * `V6Net` (bit 62) — an internet source: hash of its /64. One site controls a /64; keying on the /128
//!     would let a host present a fresh identity per probe.
//!
//! The management floor (`verdict::is_allowlisted`) only ever matches IPv4 keys.
//! IPv6 keys are OBSERVE-ONLY until the ADR 0023 separation matrix has its IPv6 rows on metal.

pub const TAG_DEV: u64 = 1 << 63;
pub const TAG_V6NET: u64 = 1 << 62;
const LOW: u64 = TAG_V6NET - 1; // bits 0..61

fn fnv(b: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &x in b {
        h ^= x as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

/// An IPv4 source (host order).
pub fn v4(ip: u32) -> u64 {
    ip as u64
}

/// A device on our own link, by MAC.
pub fn dev(mac: &[u8; 6]) -> u64 {
    TAG_DEV | (fnv(mac) & LOW).max(1)
}

/// An internet IPv6 source, by its /64.
pub fn v6net(addr: &[u8; 16]) -> u64 {
    TAG_V6NET | (fnv(&addr[..8]) & LOW).max(1)
}

/// G36: an IPv6 internet PEER folded into 240.0.0.0/4 (reserved, never routed, never `is_internal`) so the
/// IPv4-keyed behavioural tables (beacon / brute force) can hold a dual-stack device's IPv6 connections
/// without ever colliding with a real IPv4 address.
pub fn v6_peer(addr: &[u8; 16]) -> u32 {
    0xF000_0000 | ((fnv(addr) as u32) & 0x0FFF_FFFF).max(1)
}

/// Is this an IPv6 key (observe-only)?
pub fn is_v6(k: u64) -> bool {
    k & (TAG_DEV | TAG_V6NET) != 0
}

/// Short label for logs: "v4", "dev", "v6net".
pub fn kind(k: u64) -> &'static str {
    if k & TAG_DEV != 0 {
        "dev"
    } else if k & TAG_V6NET != 0 {
        "v6net"
    } else {
        "v4"
    }
}

// ---- observe-only accounting (until the v6 separation rows are proven on metal) ----

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

/// IPv6 sources seen crossing the scan wall (observe-only), and the last such key.
pub static V6_SCAN_OVER: AtomicU32 = AtomicU32::new(0);
pub static V6_SCAN_CONFIRMED: AtomicU32 = AtomicU32::new(0);
pub static V6_LAST_SCANNER: AtomicU64 = AtomicU64::new(0);

pub fn note_v6_scan(k: u64, confirmed: bool) {
    if V6_LAST_SCANNER.swap(k, Ordering::Relaxed) != k {
        V6_SCAN_OVER.fetch_add(1, Ordering::Relaxed);
        if confirmed {
            V6_SCAN_CONFIRMED.fetch_add(1, Ordering::Relaxed);
        }
    }
}

// ---- [P-v6src]: the ADR 0049 D2 keys + the ADR 0023 IPv6 separation rows (QEMU) ----

/// An Ethernet/IPv6/TCP frame (no checksum needed by the scan tier).
fn tcp6(src: &[u8; 16], dst: &[u8; 16], sport: u16, dport: u16, flags: u8, out: &mut [u8; 74]) -> usize {
    out.fill(0);
    out[12] = 0x86;
    out[13] = 0xdd;
    out[14] = 0x60;
    out[18..20].copy_from_slice(&20u16.to_be_bytes());
    out[20] = 6;
    out[21] = 64;
    out[22..38].copy_from_slice(src);
    out[38..54].copy_from_slice(dst);
    out[54..56].copy_from_slice(&sport.to_be_bytes());
    out[56..58].copy_from_slice(&dport.to_be_bytes());
    out[66] = 0x50;
    out[67] = flags;
    74
}

pub fn selftest() -> bool {
    use crate::rules::flow_scan_observe6 as obs;
    const SYN: u8 = 0x02;
    const ACK: u8 = 0x10;
    const RST: u8 = 0x14;
    const SYNACK: u8 = 0x12;
    let mut f = [0u8; 74];
    // keys: no aliasing between families, /64 stable under IID rotation, MACs distinct
    let a1: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 1, 0, 0, 0xaa, 0, 0, 0, 0, 0, 0, 1];
    let mut a2 = a1;
    a2[15] = 0x77; // same /64, another (privacy) IID
    let mut b1 = a1;
    b1[7] = 2; // another /64
    let keys = v6net(&a1) == v6net(&a2) && v6net(&a1) != v6net(&b1) && dev(&[2, 0, 0, 0, 0, 1]) != dev(&[2, 0, 0, 0, 0, 2])
        && is_v6(v6net(&a1)) && is_v6(dev(&[2, 0, 0, 0, 0, 1])) && !is_v6(v4(0xffff_ffff))
        && v6net(&a1) & TAG_DEV == 0 && dev(&[2, 0, 0, 0, 0, 1]) & TAG_V6NET == 0;
    let lan_host: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x99];
    // Row 1 — WAN sweep WITH answers: a /64 probes 120 ports, rotating its IID every probe, the LAN host
    // answers RST each time -> over the wall and confirmed (rotation does not evade: one /64, one key).
    let scanner = v6net(&a1);
    let mut over = false;
    for p in 0..120u16 {
        let mut s = a1;
        s[15] = (p & 0xff) as u8; // fresh IID per probe
        let k = tcp6(&s, &lan_host, 40000 + p, 1000 + p, SYN, &mut f);
        over |= obs(&f[..k], v6net(&s), dev(&[2, 0, 0, 0, 0, 0x99]));
        let k = tcp6(&lan_host, &s, 1000 + p, 40000 + p, RST, &mut f);
        let _ = obs(&f[..k], dev(&[2, 0, 0, 0, 0, 0x99]), v6net(&s));
    }
    let sweep = over && crate::ratelimit::scan_over_ratelimit(scanner) && crate::ratelimit::scan_confirmed(scanner);
    // Row 2 — one-sided SYNs (no answer ever): another /64 sprays 120 ports -> never counted (ADR 0049 D3).
    let spoof = v6net(&b1);
    let mut one_sided = false;
    for p in 0..120u16 {
        let k = tcp6(&b1, &lan_host, 41000 + p, 2000 + p, SYN, &mut f);
        one_sided |= obs(&f[..k], spoof, dev(&[2, 0, 0, 0, 0, 0x99]));
    }
    let silent = !one_sided && crate::ratelimit::scan_distinct_ports(spoof) == 0;
    // Row 3 — legit busy LAN device: 150 connections to 150 remote services, rotating its temporary
    // address, every one answered SYN-ACK and ACKed -> never over the wall.
    let phone = dev(&[0x02, 0x11, 0x22, 0x33, 0x44, 0x55]);
    let mut legit_fired = false;
    for i in 0..150u16 {
        let mut me = lan_host;
        me[15] = (i & 0xff) as u8;
        let mut svc = b1;
        svc[0] = 0x2a;
        svc[15] = (i % 200) as u8;
        let port = 443 + (i % 120); // distinct remote ports too (CDNs, APIs)
        let k = tcp6(&me, &svc, 50000 + i, port, SYN, &mut f);
        legit_fired |= obs(&f[..k], phone, v6net(&svc));
        let k = tcp6(&svc, &me, port, 50000 + i, SYNACK, &mut f);
        let _ = obs(&f[..k], v6net(&svc), phone);
        let k = tcp6(&me, &svc, 50000 + i, port, ACK, &mut f);
        legit_fired |= obs(&f[..k], phone, v6net(&svc));
    }
    let legit = !legit_fired && !crate::ratelimit::scan_over_ratelimit(phone);
    // Row 4 — IPv6 keys never reach the management floor (IPv4-only by construction).
    let floor = [scanner, spoof, phone].iter().all(|&k| k > u32::MAX as u64); // never representable as an IPv4 floor address
    let pass = keys && sweep && silent && legit && floor;
    arch_aarch64::_print(format_args!(
        " [P-v6src] {} — ADR 0049 D2 IPv6 source identity (observe-only): keys never alias + /64 stable under IID rotation={} | answered v6 sweep (IID rotating each probe) over the wall + confirmed={} | one-sided v6 SYNs never counted={} | legit busy v6 device (150 answered+ACKed flows, rotating temporaries) never fires={} | v6 keys outside the IPv4 management floor={}\n",
        if pass { "PASS" } else { "FAIL" }, keys, sweep, silent, legit, floor
    ));
    pass
}
