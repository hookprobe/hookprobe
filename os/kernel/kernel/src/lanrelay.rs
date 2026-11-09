//! G10 — Wi-Fi station-to-station traffic THROUGH heqk.
//!
//! The AP starts with `ap_isolate` on (the firmware never bridges stations itself — an IDS bypass otherwise; the
//! metal check `tools/diagnostics/cm5-intrabss-check.sh` confirmed the firmware honours it). Until now heqk did
//! not relay either, so two Wi-Fi devices could not talk at all (casting, AirPlay, printers, phone <-> TV) even
//! for `full` devices whose DEVICES.TXT policy says "internet and the LAN". This module is the relay:
//!   * proxy-ARP — a station asking for another live lease gets that station's real MAC (the answer a bridge
//!     would have produced), only if the asker's (MAC, IP) is its lease and BOTH devices' policies allow LAN;
//!   * unicast relay — an IPv4 frame addressed to another live station (dst MAC == the lease holder of dst IP)
//!     goes back out the radio, AFTER the caller's lease-binding and IDS verdict gates (the verdict includes the
//!     segmentation reach gate), and only if both devices' policies allow LAN.
use arch_aarch64::dhcpd::ApDhcp;

static mut STATS: [u64; 6] = [0; 6]; // proxied ARP, relayed frames, refused by policy, refused (not a lease), multicast copies, multicast rate-limited

/// (proxy-ARP answers, frames relayed, refused by device policy, refused: not a live lease / spoofed,
///  multicast discovery copies sent, multicast frames rate-limited)
pub fn stats() -> [u64; 6] {
    unsafe { STATS }
}

fn bump(i: usize) {
    unsafe { STATS[i] += 1 };
}

fn lan_ok(a: &[u8; 6], b: &[u8; 6]) -> bool {
    crate::devpolicy::check(a, crate::devpolicy::Dest::Lan) && crate::devpolicy::check(b, crate::devpolicy::Dest::Lan)
}

/// An ARP request from one station for ANOTHER station's leased address: the proxy answer (length), or 0.
pub fn proxy_arp(frame: &[u8], dh: &ApDhcp, out: &mut [u8]) -> usize {
    if frame.len() < 42 || out.len() < 60 || frame[12..14] != [0x08, 0x06] || frame[20..22] != [0x00, 0x01] {
        return 0;
    }
    let mut smac = [0u8; 6];
    smac.copy_from_slice(&frame[22..28]);
    let mut sip = [0u8; 4];
    sip.copy_from_slice(&frame[28..32]);
    let mut tip = [0u8; 4];
    tip.copy_from_slice(&frame[38..42]);
    let Some(tmac) = dh.mac_for_ip(&tip) else { return 0 }; // not one of our stations: stay silent
    if tmac == smac {
        return 0; // a gratuitous / duplicate-address probe for its own address
    }
    if frame[6..12] != smac || dh.mac_for_ip(&sip) != Some(smac) {
        bump(3); // sender hardware != ARP sender, or the sender's IP is not its lease: never vouch for it
        return 0;
    }
    if !lan_ok(&smac, &tmac) {
        bump(2);
        return 0;
    }
    bump(0);
    arp_reply(out, &tmac, &tip, &smac, &sip)
}

/// An Ethernet ARP reply "`ip` is at `mac`" to (`to_mac`, `to_ip`), padded to the 60-byte minimum.
fn arp_reply(out: &mut [u8], mac: &[u8; 6], ip: &[u8; 4], to_mac: &[u8; 6], to_ip: &[u8; 4]) -> usize {
    out[..60].fill(0);
    out[0..6].copy_from_slice(to_mac);
    out[6..12].copy_from_slice(mac);
    out[12] = 0x08;
    out[13] = 0x06;
    out[14..22].copy_from_slice(&[0, 1, 8, 0, 6, 4, 0, 2]);
    out[22..28].copy_from_slice(mac);
    out[28..32].copy_from_slice(ip);
    out[32..38].copy_from_slice(to_mac);
    out[38..42].copy_from_slice(to_ip);
    60
}

/// Is this (already lease-bound and IDS-passed) IPv4 frame for ANOTHER live station that may receive it?
pub fn relay_target(frame: &[u8], dh: &ApDhcp) -> bool {
    if frame.len() < 34 || frame[12..14] != [0x08, 0x00] {
        return false;
    }
    let mut dmac = [0u8; 6];
    dmac.copy_from_slice(&frame[0..6]);
    let mut smac = [0u8; 6];
    smac.copy_from_slice(&frame[6..12]);
    let mut dip = [0u8; 4];
    dip.copy_from_slice(&frame[30..34]);
    match dh.mac_for_ip(&dip) {
        Some(m) if m == dmac && m != smac => {}
        Some(_) => {
            bump(3);
            return false;
        }
        None => return false, // not a station address: the internet path decides
    }
    if !lan_ok(&smac, &dmac) {
        bump(2);
        return false;
    }
    bump(1);
    true
}

// ---- multicast DISCOVERY relay (mDNS, SSDP, LLMNR — v4 and v6) ----
// The firmware does not repeat one station's multicast to the others under ap_isolate (metal: an SSDP
// announcement from B never reached A), so casting / AirPlay / printer discovery needs heqk to relay it.
// Only these discovery groups, only from a leased sender allowed the LAN, as L2-UNICAST copies to each other
// station allowed the LAN (the multicast-to-unicast technique: the sender never hears its own probe back, which
// mDNS would read as a name conflict), rate-limited so one device cannot turn the AP into an amplifier.

const DISCOVERY_MACS: [[u8; 6]; 6] = [
    [0x01, 0x00, 0x5e, 0x00, 0x00, 0xfb], // mDNS 224.0.0.251
    [0x01, 0x00, 0x5e, 0x7f, 0xff, 0xfa], // SSDP 239.255.255.250
    [0x01, 0x00, 0x5e, 0x00, 0x00, 0xfc], // LLMNR 224.0.0.252
    [0x33, 0x33, 0x00, 0x00, 0x00, 0xfb], // mDNS ff02::fb
    [0x33, 0x33, 0x00, 0x00, 0x00, 0x0c], // SSDP ff02::c
    [0x33, 0x33, 0x00, 0x01, 0x00, 0x03], // LLMNR ff02::1:3
];
const MC_PER_SRC_PER_SEC: u32 = 30;
const MC_COPIES_PER_SEC: u32 = 300;
static mut MC_WIN: u64 = 0;
static mut MC_COPIES: u32 = 0;
static mut MC_SRC: [([u8; 6], u32); 16] = [([0; 6], 0); 16];

pub fn is_discovery_mcast(frame: &[u8]) -> bool {
    frame.len() >= 14 && DISCOVERY_MACS.iter().any(|m| frame[0..6] == m[..])
}

/// IPv6 neighbour discovery between stations: a Neighbour Solicitation to a solicited-node group
/// (33:33:ff:xx:xx:xx) — the IPv6 ARP. Relayed like discovery so stations resolve each other's link-local /
/// ULA / global addresses (mDNS hands out link-local AAAA records: casting often runs over IPv6).
/// (A side-effect relay: the caller still hands the NS to heqk's own IPv6 LAN, which answers for the router.)
pub fn is_ns_mcast(frame: &[u8]) -> bool {
    frame.len() >= 78 && frame[0..3] == [0x33, 0x33, 0xff] && frame[12..14] == [0x86, 0xdd] && frame[20] == 58 && frame[54] == 135
}

/// Is this IPv6 frame unicast to ANOTHER live station (dst MAC = a leased station's MAC) that may receive it?
/// The caller runs the IDS verdict first. (IPv6 has no lease per address; the MAC lease + policy decide.)
pub fn relay_target6(frame: &[u8], dh: &ApDhcp) -> bool {
    if frame.len() < 54 || frame[12..14] != [0x86, 0xdd] || frame[0] & 1 != 0 {
        return false;
    }
    let mut dmac = [0u8; 6];
    dmac.copy_from_slice(&frame[0..6]);
    let mut smac = [0u8; 6];
    smac.copy_from_slice(&frame[6..12]);
    if dmac == smac || dh.lease_for(&dmac).is_none() {
        return false; // not a station: the router path (heqk's own IPv6 LAN) decides
    }
    if dh.lease_for(&smac).is_none() {
        bump(3);
        return false;
    }
    if !lan_ok(&smac, &dmac) {
        bump(2);
        return false;
    }
    bump(1);
    true
}

/// Relay a discovery multicast frame from one station to the others: calls `send` with each L2-unicast copy.
/// The caller has already run the IDS verdict on it. Returns the number of copies sent.
pub fn relay_discovery(frame: &[u8], dh: &ApDhcp, now_s: u64, send: &mut dyn FnMut(&[u8]) -> bool) -> u32 {
    if !(is_discovery_mcast(frame) || is_ns_mcast(frame)) || frame.len() > 1514 {
        return 0;
    }
    let mut smac = [0u8; 6];
    smac.copy_from_slice(&frame[6..12]);
    // a leased sender (IPv4: its source address must be its lease too); allowed the LAN
    let Some(sip) = dh.lease_for(&smac) else { return 0 };
    if frame[12..14] == [0x08, 0x00] && (frame.len() < 34 || frame[26..30] != sip) {
        bump(3);
        return 0;
    }
    if !crate::devpolicy::check(&smac, crate::devpolicy::Dest::Lan) {
        bump(2);
        return 0;
    }
    // rate limits (per second): per source, and copies overall
    unsafe {
        if MC_WIN != now_s {
            MC_WIN = now_s;
            MC_COPIES = 0;
            (*core::ptr::addr_of_mut!(MC_SRC)).iter_mut().for_each(|e| e.1 = 0);
        }
        let t = &mut *core::ptr::addr_of_mut!(MC_SRC);
        let i = t.iter().position(|e| e.0 == smac).or_else(|| t.iter().position(|e| e.1 == 0)).unwrap_or(0);
        if t[i].0 != smac {
            t[i] = (smac, 0);
        }
        if t[i].1 >= MC_PER_SRC_PER_SEC {
            bump(5);
            return 0;
        }
        t[i].1 += 1;
    }
    let mut copy = [0u8; 1514];
    let n = frame.len();
    copy[..n].copy_from_slice(frame);
    let mut sent = 0u32;
    dh.for_each_live(&mut |mac, _| {
        if *mac == smac || !crate::devpolicy::check(mac, crate::devpolicy::Dest::Lan) {
            return;
        }
        if unsafe { MC_COPIES } >= MC_COPIES_PER_SEC {
            return;
        }
        copy[0..6].copy_from_slice(mac);
        if send(&copy[..n]) {
            sent += 1;
            unsafe { MC_COPIES += 1 };
        }
    });
    unsafe { STATS[4] += sent as u64 };
    sent
}

/// `[P-lanrelay]`
pub fn selftest() -> bool {
    let mut dh = ApDhcp::new();
    let (a_mac, a_ip) = ([0x02, 0, 0, 0, 0, 0x0a], [10, 99, 0, 10]);
    let (b_mac, b_ip) = ([0x02, 0, 0, 0, 0, 0x0b], [10, 99, 0, 11]);
    for (i, (m, ip)) in [(a_mac, a_ip), (b_mac, b_ip)].iter().enumerate() {
        dh.leases[i].used = true;
        dh.leases[i].mac = *m;
        dh.leases[i].ip = *ip;
        dh.leases[i].expires = 0;
    }
    dh.nleases = 2;
    let arp = |smac: [u8; 6], hw: [u8; 6], sip: [u8; 4], tip: [u8; 4]| -> [u8; 42] {
        let mut f = [0u8; 42];
        f[0..6].copy_from_slice(&[0xff; 6]);
        f[6..12].copy_from_slice(&hw);
        f[12] = 0x08;
        f[13] = 0x06;
        f[14..22].copy_from_slice(&[0, 1, 8, 0, 6, 4, 0, 1]);
        f[22..28].copy_from_slice(&smac);
        f[28..32].copy_from_slice(&sip);
        f[38..42].copy_from_slice(&tip);
        f
    };
    let mut out = [0u8; 64];
    crate::devpolicy::load_text(b"");
    let n = proxy_arp(&arp(a_mac, a_mac, a_ip, b_ip), &dh, &mut out);
    let proxied = n >= 42 && out[0..6] == a_mac && out[6..12] == b_mac && out[22..28] == b_mac && out[28..32] == b_ip;
    let spoof = proxy_arp(&arp(a_mac, b_mac, a_ip, b_ip), &dh, &mut out) == 0; // hw src != ARP sender
    let squat = proxy_arp(&arp(a_mac, a_mac, [10, 99, 0, 99], b_ip), &dh, &mut out) == 0; // sender IP not its lease
    let unknown = proxy_arp(&arp(a_mac, a_mac, a_ip, [10, 99, 0, 77]), &dh, &mut out) == 0;
    let own = proxy_arp(&arp(a_mac, a_mac, a_ip, a_ip), &dh, &mut out) == 0;
    let mut f = [0u8; 60];
    f[0..6].copy_from_slice(&b_mac);
    f[6..12].copy_from_slice(&a_mac);
    f[12] = 0x08;
    f[14] = 0x45;
    f[26..30].copy_from_slice(&a_ip);
    f[30..34].copy_from_slice(&b_ip);
    let relay = relay_target(&f, &dh);
    let mut wrong = f;
    wrong[0..6].copy_from_slice(&[0x02, 0, 0, 0, 0, 0x0c]); // dst MAC not the holder of dst IP
    let mismatch = !relay_target(&wrong, &dh);
    let mut inet = f;
    inet[30..34].copy_from_slice(&[93, 184, 216, 34]);
    let not_lan = !relay_target(&inet, &dh); // the internet path decides
    // policy: B internet_only -> no proxy answer, no relay
    crate::devpolicy::load_text(b"02:00:00:00:00:0b internet_only\n");
    let pol = proxy_arp(&arp(a_mac, a_mac, a_ip, b_ip), &dh, &mut out) == 0 && !relay_target(&f, &dh);
    crate::devpolicy::load_text(b"");
    // multicast discovery: a third station C; A's mDNS goes to B and C as unicast copies, never back to A
    let c_mac = [0x02, 0, 0, 0, 0, 0x0c];
    dh.leases[2].used = true;
    dh.leases[2].mac = c_mac;
    dh.leases[2].ip = [10, 99, 0, 12];
    dh.nleases = 3;
    let mut m = [0u8; 60];
    m[0..6].copy_from_slice(&[0x01, 0x00, 0x5e, 0x00, 0x00, 0xfb]);
    m[6..12].copy_from_slice(&a_mac);
    m[12] = 0x08;
    m[14] = 0x45;
    m[26..30].copy_from_slice(&a_ip);
    m[30..34].copy_from_slice(&[224, 0, 0, 251]);
    let mut to = [[0u8; 6]; 4];
    let mut k = 0usize;
    let sent = relay_discovery(&m, &dh, 100, &mut |f: &[u8]| {
        if k < 4 {
            to[k].copy_from_slice(&f[0..6]);
            k += 1;
        }
        true
    });
    let mc_fanout = sent == 2 && to[..2].contains(&b_mac) && to[..2].contains(&c_mac) && !to[..k].contains(&a_mac);
    let mut spoofed = m;
    spoofed[26..30].copy_from_slice(&[10, 99, 0, 99]);
    let mc_spoof = relay_discovery(&spoofed, &dh, 100, &mut |_| true) == 0;
    let mut other = m;
    other[0..6].copy_from_slice(&[0x01, 0x00, 0x5e, 0x01, 0x02, 0x03]); // not a discovery group
    let mc_other = relay_discovery(&other, &dh, 100, &mut |_| true) == 0;
    let mut burst = 0u32;
    for _ in 0..100 {
        burst += relay_discovery(&m, &dh, 101, &mut |_| true);
    }
    let mc_rate = burst == MC_PER_SRC_PER_SEC * 2; // 30 frames x 2 receivers, then the source is capped
    crate::devpolicy::load_text(b"02:00:00:00:00:0c internet_only\n");
    let mc_pol = relay_discovery(&m, &dh, 102, &mut |_| true) == 1; // C (internet_only) gets no copy
    crate::devpolicy::load_text(b"");
    // IPv6 between stations: an NS to a solicited-node group fans out; a unicast frame to B's MAC is relayed
    let mut ns = [0u8; 86];
    ns[0..6].copy_from_slice(&[0x33, 0x33, 0xff, 0, 0, 0x0b]);
    ns[6..12].copy_from_slice(&a_mac);
    ns[12] = 0x86;
    ns[13] = 0xdd;
    ns[14] = 0x60;
    ns[20] = 58;
    ns[54] = 135;
    let ns_ok = relay_discovery(&ns, &dh, 103, &mut |_| true) == 2;
    let mut u6 = [0u8; 74];
    u6[0..6].copy_from_slice(&b_mac);
    u6[6..12].copy_from_slice(&a_mac);
    u6[12] = 0x86;
    u6[13] = 0xdd;
    u6[14] = 0x60;
    let mut u6_router = u6;
    u6_router[0..6].copy_from_slice(&[0x02, 0x11, 0x22, 0x33, 0x44, 0x55]); // the AP / unknown: not relayed
    let v6_ok = relay_target6(&u6, &dh) && !relay_target6(&u6_router, &dh);
    unsafe { STATS = [0; 6] };
    let pass = proxied && spoof && squat && unknown && own && relay && mismatch && not_lan && pol && mc_fanout && mc_spoof && mc_other && mc_rate && mc_pol && ns_ok && v6_ok;
    arch_aarch64::_print(format_args!(
        " [P-lanrelay] {} — G10 Wi-Fi station-to-station THROUGH heqk: proxy-ARP with the peer's real MAC={} | refused: spoofed sender={} sender IP not its lease={} unknown target={} own address={} | unicast relay to the lease holder={} wrong dst MAC={} internet dst left to NAT={} | internet_only peer: no ARP, no relay={} | discovery multicast as unicast copies to the other stations, never back={} spoofed sender={} non-discovery group={} per-source rate cap={} internet_only receiver skipped={} | IPv6: NS fan-out={} unicast to a station relayed, router/unknown left alone={}\n",
        if pass { "PASS" } else { "FAIL" }, proxied, spoof, squat, unknown, own, relay, mismatch, not_lan, pol, mc_fanout, mc_spoof, mc_other, mc_rate, mc_pol, ns_ok, v6_ok
    ));
    pass
}
