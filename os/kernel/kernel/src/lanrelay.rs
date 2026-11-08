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

static mut STATS: [u64; 4] = [0; 4]; // proxied ARP, relayed frames, refused by policy, refused (not a lease)

/// (proxy-ARP answers, frames relayed, refused by device policy, refused: not a live lease / spoofed)
pub fn stats() -> [u64; 4] {
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
    unsafe { STATS = [0; 4] };
    let pass = proxied && spoof && squat && unknown && own && relay && mismatch && not_lan && pol;
    arch_aarch64::_print(format_args!(
        " [P-lanrelay] {} — G10 Wi-Fi station-to-station THROUGH heqk: proxy-ARP with the peer's real MAC={} | refused: spoofed sender={} sender IP not its lease={} unknown target={} own address={} | unicast relay to the lease holder={} wrong dst MAC={} internet dst left to NAT={} | internet_only peer: no ARP, no relay={}\n",
        if pass { "PASS" } else { "FAIL" }, proxied, spoof, squat, unknown, own, relay, mismatch, not_lan, pol
    ));
    pass
}
