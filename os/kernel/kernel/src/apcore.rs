//! G0 — the AP data plane, pulled out of the `cm5`-only AP loop in `main.rs` so QEMU can test it.
//!
//! Step 1 (this file): `forward4`, the decision ladder for one client IPv4 frame leaving the LAN (Wi-Fi or
//! eth1): `<if> in` ACL / prefix-lists → route (WAN or management sub-interface, by prefix / source / metric /
//! liveness) → `<egress> out` → session hold (ADR 0053) → per-device policy (G9) → exfil accounting (G3) →
//! Shield (ADR 0052: answer / reject DNS) → SNAT + send, or reject / drop. It was the `fwd4!` macro; the AP
//! loop now calls this with a hardware `ApNic` and the self-test with a recording fake.
//!
//! Nothing here names a driver (cyw43, uplink, rtl8111, gem): every effect goes through `ApNic`, so the
//! code QEMU runs is the code the board runs. Generic over `N: ApNic` (monomorphised, no `dyn` on the
//! hot path) and copy-free (the frame is borrowed; SNAT writes into the caller's scratch buffer).

use arch_aarch64::nat::{self, NatStats};
use hal::policy::{Act, Dir, If, Policy};

/// The management sub-interface as the data plane needs it (a copy — never a reference into a driver static).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MgmtView {
    pub ip: [u8; 4],
    pub mac: [u8; 6],
    pub gw: [u8; 4],
    /// The gateway MAC is resolved (a route via mgmt is usable).
    pub up: bool,
}

/// The WAN lease as the data plane needs it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WanView {
    pub ip: [u8; 4],
    pub mac: [u8; 6],
    pub gw_mac: [u8; 6],
    pub dns: [u8; 4],
}

/// Every effect the data plane has on the outside world.
pub trait ApNic {
    fn ticks(&self) -> u64;
    /// The WAN is usable for routing (link + recent RX + G16 health probes).
    fn wan_up(&self) -> bool;
    fn wan(&self) -> WanView;
    /// ARP-resolved MAC of a WAN next hop (`route … via wan gw X`), None = not resolved yet.
    fn wan_nexthop(&mut self, ip: [u8; 4]) -> Option<[u8; 6]>;
    fn wan_tx(&mut self, f: &[u8]) -> bool;
    fn mgmt(&self) -> Option<MgmtView>;
    fn mgmt_nexthop(&mut self, ip: [u8; 4]) -> Option<[u8; 6]>;
    fn mgmt_tx(&mut self, f: &[u8]) -> bool;
    /// IPv6 packet (no Ethernet header) out the WAN.
    fn wan_tx6(&mut self, ip6: &[u8]) -> bool;
    /// Monotonic counter + its frequency (rate windows).
    fn now(&self) -> u64;
    fn freq(&self) -> u64;
}

/// Per-interface policy counters `[lan, eth1, wan, mgmt]` + forwarding failures (the beat prints them).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FwdCounters {
    pub pol_drop: [u32; 4],
    pub pol_block: [u32; 4],
    pub pol_via_mgmt: u32,
    /// Routed to a next hop whose MAC is not resolved yet (mgmt or a `via wan gw`).
    pub pol_mgmt_nh_miss: u32,
    pub nat_tx_fail: u32,
    /// `lan|eth1 out` blocks after un-NAT act as drops (a reject would have to be re-NATed).
    pub block_as_drop: u32,
}

/// Fixed per-port facts.
pub struct FwdCfg {
    /// The AP's own address (the router address in rejects; Shield's resolver for redirected DNS).
    pub our_ip: [u8; 4],
    /// The MAC replies come from on this port (the BSSID on Wi-Fi, the eth1 MAC on eth1).
    pub me: [u8; 6],
    pub inside_net: [u8; 3],
}

/// One client IPv4 frame from `pif` (`nif` = the NAT inside-interface id). `reply` sends a frame back to the
/// client port (Shield answers, TCP RST / ICMP admin-prohibited). Returns true if the frame was sent onward.
#[allow(clippy::too_many_arguments)]
#[inline]
pub fn forward4<N: ApNic>(
    frame: &[u8],
    pif: If,
    nif: u8,
    cfg: &FwdCfg,
    pol: &mut Policy,
    nst: &mut NatStats,
    c: &mut FwdCounters,
    nbuf: &mut [u8],
    nic: &mut N,
    reply: &mut dyn FnMut(&[u8]) -> bool,
) -> bool {
    let mut act = Act::Allow;
    let mut egress = If::Wan;
    let mut nh_ip: Option<[u8; 4]> = None;
    if let Some(p) = hal::policy::facts(frame) {
        act = pol.check(pif, Dir::In, &p).0;
        if act == Act::Allow {
            let mgmt_up = nic.mgmt().map_or(false, |m| m.up);
            let wan_up = nic.wan_up();
            if let Some(r) = pol.route(&p.src, &p.dst, &|i| match i {
                If::Wan => wan_up,
                If::Mgmt => mgmt_up,
                _ => false,
            }) {
                egress = r.via;
                nh_ip = r.gw.filter(|g| !g.v6).map(|g| [g.a[0], g.a[1], g.a[2], g.a[3]]);
            }
            act = pol.check(egress, Dir::Out, &p).0;
        }
    }
    let pi = pif as usize;
    // answered / refused by Shield, a session hold or a device policy — not an ACL drop
    let mut shield = false;
    // ADR 0053: a session-made, TTL-bound hold on an IPv4 address (either direction)
    if act == Act::Allow && frame.len() >= 34 {
        let (a, b) = (u32::from_be_bytes([frame[26], frame[27], frame[28], frame[29]]), u32::from_be_bytes([frame[30], frame[31], frame[32], frame[33]]));
        if crate::actions::ip_held(a) || crate::actions::ip_held(b) {
            act = Act::Drop;
            shield = true;
        }
    }
    // Parity G9: the device's declared policy (DEVICES.TXT / owner journal). DNS is infrastructure (Shield
    // answers it); everything forwarded here goes to the internet.
    if act == Act::Allow && frame.len() >= 34 {
        let mut smac = [0u8; 6];
        smac.copy_from_slice(&frame[6..12]);
        let dns = frame[23] == 17 && {
            let u = 14 + ((frame[14] & 0x0f) as usize) * 4;
            frame.get(u + 2..u + 4) == Some(&[0, 53][..])
        };
        let d = if dns { crate::devpolicy::Dest::Infra } else { crate::devpolicy::Dest::Internet };
        if !crate::devpolicy::check(&smac, d) {
            act = Act::Drop;
            shield = true;
        }
    }
    // Exfil (parity G3): outbound bytes per inside source, observe-only + cooldown.
    if act == Act::Allow && frame.len() >= 34 {
        let src = u32::from_be_bytes([frame[26], frame[27], frame[28], frame[29]]);
        let dst = u32::from_be_bytes([frame[30], frame[31], frame[32], frame[33]]);
        let _ = crate::rules::exfil_verdict(src, dst, u16::from_be_bytes([frame[16], frame[17]]) as u64);
    }
    // Shield v2 (ADR 0052): every client DNS query (any resolver, UDP and TCP), DoT, DoH names.
    if act == Act::Allow {
        let mut dr = [0u8; 600];
        match crate::shield::on_client_frame(frame, &cfg.me, &mut dr, nic.ticks()) {
            crate::shield::Act::Pass => {}
            crate::shield::Act::Answer(k) => {
                let _ = reply(&dr[..k]);
                act = Act::Drop;
                shield = true;
            }
            crate::shield::Act::Reject => {
                if let Some(k) = arch_aarch64::reject::reject4(frame, &cfg.our_ip, &cfg.me, &mut dr) {
                    let _ = reply(&dr[..k]);
                }
                act = Act::Drop;
                shield = true;
            }
        }
    }
    match act {
        Act::Allow if egress == If::Mgmt => {
            let Some(mg) = nic.mgmt() else { return false };
            match nic.mgmt_nexthop(nh_ip.unwrap_or(mg.gw)) {
                Some(nmac) => {
                    if let Some(k) = nat::outbound_redirect(frame, nif, &cfg.inside_net, None, &mg.ip, &mg.mac, &nmac, nbuf, nic.ticks(), nst) {
                        c.pol_via_mgmt += 1;
                        nic.mgmt_tx(&nbuf[..k])
                    } else {
                        false
                    }
                }
                None => {
                    c.pol_mgmt_nh_miss += 1;
                    false
                }
            }
        }
        Act::Allow => {
            let w = nic.wan();
            // `route … via wan gw X`: X's MAC (ARP-resolved); the default gateway otherwise.
            let gw_mac = match nh_ip {
                Some(g) => match nic.wan_nexthop(g) {
                    Some(mac) => mac,
                    None => {
                        c.pol_mgmt_nh_miss += 1; // counted with the mgmt misses: "next hop unresolved"
                        [0u8; 6]
                    }
                },
                None => w.gw_mac,
            };
            let resolver = if w.dns != [0u8; 4] { w.dns } else { [8u8, 8, 8, 8] };
            if gw_mac == [0u8; 6] {
                false // next hop not resolved yet (ARP sent): drop, TCP retries
            } else if let Some(k) = nat::outbound_redirect(frame, nif, &cfg.inside_net, Some((&cfg.our_ip, &resolver)), &w.ip, &w.mac, &gw_mac, nbuf, nic.ticks(), nst) {
                let ok = nic.wan_tx(&nbuf[..k]);
                if !ok {
                    c.nat_tx_fail += 1;
                }
                ok
            } else {
                false
            }
        }
        Act::Block => {
            c.pol_block[pi] += 1;
            let mut rj = [0u8; 128];
            if let Some(k) = arch_aarch64::reject::reject4(frame, &cfg.our_ip, &cfg.me, &mut rj) {
                let _ = reply(&rj[..k]);
            }
            false
        }
        Act::Drop => {
            if !shield {
                c.pol_drop[pi] += 1;
            }
            false
        }
    }
}

// ---- step 2: the WAN inbound leg ------------------------------------------------------------------------

/// What makes an inbound IPv6 packet "addressed to us" (the WAN address, or our delegated LAN prefix).
#[derive(Clone, Copy, Debug, Default)]
pub struct V6Us {
    pub wan_na: Option<[u8; 16]>,
    pub lan_up: bool,
    pub lan_prefix: [u8; 8],
    /// Source for rejects when the WAN has no address of its own.
    pub gua: [u8; 16],
}

/// The `wan in` reject rate window (RFC 4443 §2.4(f)): at most 20 rejects per second toward the internet.
#[derive(Clone, Copy, Debug, Default)]
pub struct RejWin {
    pub t0: u64,
    pub n: u32,
}

/// Operator policy `wan in` for NEW inbound traffic (no NAT session / no IPv6 flow). Only traffic ADDRESSED TO
/// US is policed (peer review H3: the GEM is promiscuous — never forge resets for other hosts' flows); a
/// `block` beyond 20/s becomes a drop (no reflector).
pub fn wan_in_new<N: ApNic>(f: &[u8], v6: &V6Us, pol: &mut Policy, rej: &mut RejWin, c: &mut FwdCounters, nic: &mut N) {
    let n = f.len();
    let w = nic.wan();
    let to_us = n >= 14 && f[0..6] == w.mac && match f[12..14] {
        [0x08, 0x00] => n >= 34 && f[30..34] == w.ip,
        [0x86, 0xdd] => n >= 54 && (Some({ let mut d = [0u8; 16]; d.copy_from_slice(&f[38..54]); d }) == v6.wan_na || (v6.lan_up && f[38..46] == v6.lan_prefix)),
        _ => false,
    };
    let a = if !to_us { Act::Allow } else { hal::policy::facts(f).map(|p| pol.check(If::Wan, Dir::In, &p).0).unwrap_or(Act::Allow) };
    let t = nic.now();
    if t.wrapping_sub(rej.t0) > nic.freq() {
        rej.t0 = t;
        rej.n = 0;
    }
    let a = if a == Act::Block && rej.n >= 20 { Act::Drop } else { a };
    if a == Act::Block {
        rej.n += 1;
        c.pol_block[If::Wan as usize] += 1;
        let mut rj = [0u8; 1400];
        if f[12] == 0x86 {
            let src6 = v6.wan_na.unwrap_or(v6.gua);
            if let Some(k) = arch_aarch64::reject::reject6(f, &src6, &w.mac, &mut rj) {
                let _ = nic.wan_tx6(&rj[14..k]);
            }
        } else if let Some(k) = arch_aarch64::reject::reject4(f, &w.ip, &w.mac, &mut rj) {
            let _ = nic.wan_tx(&rj[..k]);
        }
    } else if a == Act::Drop {
        c.pol_drop[If::Wan as usize] += 1;
    }
}

/// The fate of one inbound IPv4 WAN frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Wan4 {
    /// From a held address (ADR 0053) — dropped.
    Held,
    /// The IDS dropped it before un-NAT.
    IdsDrop,
    /// No NAT session: new inbound traffic, `wan in` applied.
    New,
    /// `lan|eth1 out` refused it after un-NAT.
    OutDenied,
    /// Too big for the Wi-Fi leg (counted in `nst.in_too_big`).
    TooBig,
    /// Un-NATed into `nbuf[..len]` for the client on `eth1` (else Wi-Fi).
    Deliver { len: usize, eth1: bool },
}

/// One inbound IPv4 frame from the WAN (after the martian floor): session hold → IDS → un-NAT (or `wan in`
/// for new traffic) → `lan|eth1 out` → scan-response credit (ADR 0049 D3) → Shield CNAME check (ADR 0052 D6)
/// → size for the Wi-Fi leg. The caller delivers `Deliver` (queue / eth1 ring stay in the loop for now).
#[allow(clippy::too_many_arguments)]
#[inline]
pub fn wan4<N: ApNic>(f: &[u8], inside_macs: [&[u8; 6]; 2], v6: &V6Us, pol: &mut Policy, rej: &mut RejWin, nst: &mut NatStats, c: &mut FwdCounters, nbuf: &mut [u8], nic: &mut N) -> Wan4 {
    let n = f.len();
    if n >= 34 && f[12] == 0x08 && f[13] == 0x00 && crate::actions::ip_held(u32::from_be_bytes([f[26], f[27], f[28], f[29]])) {
        return Wan4::Held;
    }
    if crate::packet::verdict(f).1 == crate::packet::DROP {
        return Wan4::IdsDrop;
    }
    let w = nic.wan();
    let Some((m, in_if)) = nat::inbound(f, &w.ip, &w.mac, inside_macs, nbuf, nic.now(), nst) else {
        wan_in_new(f, v6, pol, rej, c, nic);
        return Wan4::New;
    };
    let oif = if in_if == nat::IF_ETH1 { If::Eth1 } else { If::Lan };
    let a = hal::policy::facts(&nbuf[..m]).map(|p| pol.check(oif, Dir::Out, &p).0).unwrap_or(Act::Allow);
    if a != Act::Allow {
        c.pol_drop[oif as usize] += 1;
        if a == Act::Block {
            c.block_as_drop += 1;
        }
        return Wan4::OutDenied;
    }
    crate::rules::scan_response_hook(&nbuf[..m]);
    let m = crate::shield::on_reply_frame(nbuf, m, nic.ticks());
    if in_if == nat::IF_ETH1 {
        return Wan4::Deliver { len: m, eth1: true };
    }
    if m > nat::WIFI_MAX_FRAME {
        nst.in_too_big += 1; // the Wi-Fi leg can't carry it (TCP is MSS-clamped; big UDP is lost)
        return Wan4::TooBig;
    }
    Wan4::Deliver { len: m, eth1: false }
}

// ---- [P-apcore] ---------------------------------------------------------------------------------------------

/// A recording fake: every channel keeps a count and the last frame.
pub struct FakeNic {
    pub t: u64,
    pub wan_up: bool,
    pub wan: WanView,
    pub nexthop: Option<[u8; 6]>,
    pub mgmt: Option<MgmtView>,
    pub wan_ok: bool,
    pub wan_n: u32,
    pub mgmt_n: u32,
    pub last: [u8; 1600],
    pub last_len: usize,
}
impl FakeNic {
    fn keep(&mut self, f: &[u8]) {
        let n = f.len().min(1600);
        self.last[..n].copy_from_slice(&f[..n]);
        self.last_len = n;
    }
}
impl ApNic for FakeNic {
    fn ticks(&self) -> u64 {
        self.t
    }
    fn wan_up(&self) -> bool {
        self.wan_up
    }
    fn wan(&self) -> WanView {
        self.wan
    }
    fn wan_nexthop(&mut self, _ip: [u8; 4]) -> Option<[u8; 6]> {
        self.nexthop
    }
    fn wan_tx(&mut self, f: &[u8]) -> bool {
        self.keep(f);
        self.wan_n += 1;
        self.wan_ok
    }
    fn mgmt(&self) -> Option<MgmtView> {
        self.mgmt
    }
    fn mgmt_nexthop(&mut self, _ip: [u8; 4]) -> Option<[u8; 6]> {
        self.mgmt.filter(|m| m.up).map(|_| [0x02, 0x6d, 0, 0, 0, 1])
    }
    fn mgmt_tx(&mut self, f: &[u8]) -> bool {
        self.keep(f);
        self.mgmt_n += 1;
        true
    }
    fn wan_tx6(&mut self, ip6: &[u8]) -> bool {
        self.keep(ip6);
        self.wan_n += 1;
        self.wan_ok
    }
    fn now(&self) -> u64 {
        self.t
    }
    fn freq(&self) -> u64 {
        1000
    }
}

/// Ethernet/IPv4/UDP or TCP test frame from 10.99.0.10 (02:..:0a) to `dst`:`dport`.
fn frame4(proto: u8, dst: [u8; 4], dport: u16, payload: &[u8], out: &mut [u8; 400]) -> usize {
    out.fill(0);
    out[0..6].copy_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]); // the AP
    out[6..12].copy_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x0a]); // the client
    out[12..14].copy_from_slice(&[0x08, 0x00]);
    let l4 = if proto == 6 { 20 } else { 8 };
    let tot = 20 + l4 + payload.len();
    out[14] = 0x45;
    out[16..18].copy_from_slice(&(tot as u16).to_be_bytes());
    out[22] = 64;
    out[23] = proto;
    out[26..30].copy_from_slice(&[10, 99, 0, 10]);
    out[30..34].copy_from_slice(&dst);
    let mut s = 0u32;
    for i in (14..34).step_by(2) {
        s += u16::from_be_bytes([out[i], out[i + 1]]) as u32;
    }
    while s > 0xffff {
        s = (s & 0xffff) + (s >> 16);
    }
    out[24..26].copy_from_slice(&(!(s as u16)).to_be_bytes());
    out[34..36].copy_from_slice(&40000u16.to_be_bytes());
    out[36..38].copy_from_slice(&dport.to_be_bytes());
    if proto == 6 {
        out[46] = 0x50;
        out[47] = 0x02; // SYN
        out[48..50].copy_from_slice(&64240u16.to_be_bytes());
    } else {
        out[38..40].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    }
    out[34 + l4..34 + l4 + payload.len()].copy_from_slice(payload);
    14 + tot
}

pub fn selftest() -> bool {
    let cfg = FwdCfg { our_ip: [10, 99, 0, 1], me: [0x02, 0, 0, 0, 0, 0x01], inside_net: [10, 99, 0] };
    let wan = WanView { ip: [100, 64, 7, 9], mac: [0x02, 0x77, 0, 0, 0, 0x09], gw_mac: [0x02, 0x77, 0, 0, 0, 0x01], dns: [1, 1, 1, 1] };
    let mut nic = FakeNic { t: 1000, wan_up: true, wan, nexthop: Some([0x02, 0x77, 0, 0, 0, 0x02]), mgmt: None, wan_ok: true, wan_n: 0, mgmt_n: 0, last: [0; 1600], last_len: 0 };
    let mut pol = Policy::new();
    let mut nst = NatStats::default();
    let mut c = FwdCounters::default();
    let mut nbuf = [0u8; 2048];
    let mut replies = 0u32;
    let mut rlast = [0u8; 600];
    let mut f = [0u8; 400];
    crate::shield::load_text(b"", b"");
    crate::devpolicy::load_text(b"");
    macro_rules! go {
        ($fr:expr, $pif:expr) => {{
            let mut rep = |r: &[u8]| {
                replies += 1;
                rlast[..r.len().min(600)].copy_from_slice(&r[..r.len().min(600)]);
                true
            };
            forward4($fr, $pif, nat::IF_WIFI, &cfg, &mut pol, &mut nst, &mut c, &mut nbuf, &mut nic, &mut rep)
        }};
    }
    // 1. no policy: a client TCP SYN to 93.184.216.34:443 leaves on the WAN, SNATed to the lease, to the gateway
    let n = frame4(6, [93, 184, 216, 34], 443, &[], &mut f);
    let sent = go!(&f[..n], If::Lan);
    let l = &nic.last;
    let snat = sent && nic.wan_n == 1 && l[0..6] == wan.gw_mac && l[6..12] == wan.mac && l[26..30] == wan.ip && l[30..34] == [93, 184, 216, 34] && nst.out_fwd == 1 && replies == 0;
    // 2. the gateway MAC is not resolved yet: nothing leaves (TCP retries)
    nic.wan.gw_mac = [0; 6];
    let n = frame4(6, [93, 184, 216, 35], 443, &[], &mut f);
    let unresolved = !go!(&f[..n], If::Lan) && nic.wan_n == 1;
    nic.wan.gw_mac = wan.gw_mac;
    // 3. the WAN refuses the frame: counted
    nic.wan_ok = false;
    let n = frame4(6, [93, 184, 216, 36], 443, &[], &mut f);
    let txfail = !go!(&f[..n], If::Lan) && c.nat_tx_fail == 1;
    nic.wan_ok = true;
    // 4. a signed `lan in` block: RST/ICMP back to the client, counted per interface, nothing on the WAN
    let _ = hal::policy::parse_policy(b"HQPOL1\nacl LAN-IN seq 10 block tcp any any 23\nacl LAN-IN seq 20 drop udp any any 9999\nacl LAN-IN default allow\ninterface lan acl in LAN-IN\nroute 0.0.0.0/0 via wan\nroute 0.0.0.0/0 via mgmt gw 192.168.200.1 metric 100\nroute 10.20.0.0/16 via mgmt gw 192.168.200.1\n", &mut pol);
    let wan0 = nic.wan_n;
    let n = frame4(6, [93, 184, 216, 34], 23, &[], &mut f);
    let block = !go!(&f[..n], If::Lan) && c.pol_block[If::Lan as usize] == 1 && replies == 1 && rlast[0..6] == [0x02, 0, 0, 0, 0, 0x0a] && nic.wan_n == wan0;
    let n = frame4(17, [93, 184, 216, 34], 9999, b"x", &mut f);
    let drop = !go!(&f[..n], If::Lan) && c.pol_drop[If::Lan as usize] == 1 && replies == 1 && nic.wan_n == wan0;
    // 5. a route via the management sub-interface: out mgmt (SNAT to the mgmt address) once its gateway is up
    let n = frame4(6, [10, 20, 1, 2], 443, &[], &mut f);
    // the mgmt gateway is not up: the more specific route is unusable, the default via WAN carries it
    let mg_down = go!(&f[..n], If::Lan) && nic.mgmt_n == 0 && nic.wan_n == wan0 + 1;
    nic.mgmt = Some(MgmtView { ip: [192, 168, 200, 146], mac: [0x02, 0x6d, 0, 0, 0, 0x46], gw: [192, 168, 200, 1], up: true });
    let n = frame4(6, [10, 20, 1, 2], 443, &[], &mut f);
    let via_mgmt = go!(&f[..n], If::Lan) && nic.mgmt_n == 1 && c.pol_via_mgmt == 1 && nic.last[26..30] == [192, 168, 200, 146];
    // 6. the WAN is down: the metric-100 default via mgmt takes over (failover), not silently the WAN
    nic.wan_up = false;
    let wan1 = nic.wan_n;
    let n = frame4(6, [93, 184, 216, 34], 443, &[], &mut f);
    let failover = go!(&f[..n], If::Lan) && nic.mgmt_n == 2 && nic.wan_n == wan1;
    nic.wan_up = true;
    nic.mgmt = None;
    pol = Policy::new();
    // 7. Shield: a client DNS query for a blocklisted name is answered here and never leaves
    crate::shield::load_text(b"ads.example\n", b"");
    let q = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03ads\x07example\x00\x00\x01\x00\x01";
    let n = frame4(17, [1, 1, 1, 1], 53, q, &mut f);
    let w0 = nic.wan_n;
    let shield = !go!(&f[..n], If::Lan) && replies == 2 && nic.wan_n == w0 && c.pol_drop == [1, 0, 0, 0]; // an answer is not an ACL drop
    // a clean name is forwarded (to the client's resolver through NAT)
    let q2 = b"\x12\x35\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x04good\x07example\x00\x00\x01\x00\x01";
    let n = frame4(17, [1, 1, 1, 1], 53, q2, &mut f);
    let clean = go!(&f[..n], If::Lan) && nic.wan_n == w0 + 1;
    crate::shield::load_text(b"", b"");
    // 8. a quarantined device (DEVICES.TXT) never reaches the internet; its DNS is not an ACL drop
    crate::devpolicy::load_text(b"02:00:00:00:00:0a quarantine qtest\n");
    let w1 = nic.wan_n;
    let n = frame4(6, [93, 184, 216, 34], 443, &[], &mut f);
    let quarantined = !go!(&f[..n], If::Lan) && nic.wan_n == w1 && c.pol_drop[If::Lan as usize] == 1;
    crate::devpolicy::load_text(b"");
    crate::shield::reset_stats();
    let pass = snat && unresolved && txfail && block && drop && mg_down && via_mgmt && failover && shield && clean && quarantined;
    arch_aarch64::_print(format_args!(
        " [P-apcore] {} — G0 step 1: the AP's client IPv4 forwarding ladder (was the cm5-only fwd4! macro) on a recording fake NIC: SNAT to the WAN lease via the gateway={} unresolved next hop -> nothing sent={} WAN tx failure counted={} `lan in` block -> reject to the client, counted={} drop counted, silent={} mgmt gateway down -> default via WAN={} then SNATs to the mgmt address={} WAN down -> metric failover to mgmt={} Shield answers a blocked name locally={} clean DNS forwarded={} quarantined device never forwarded, not an ACL drop={}\n",
        if pass { "PASS" } else { "FAIL" }, snat, unresolved, txfail, block, drop, mg_down, via_mgmt, failover, shield, clean, quarantined
    ));
    pass
}

/// `[P-apcore-wan]` — step 2: the WAN inbound leg on the same fake NIC.
pub fn wan_selftest() -> bool {
    let cfg = FwdCfg { our_ip: [10, 99, 0, 1], me: [0x02, 0, 0, 0, 0, 0x01], inside_net: [10, 99, 0] };
    let wan = WanView { ip: [100, 64, 7, 9], mac: [0x02, 0x77, 0, 0, 0, 0x09], gw_mac: [0x02, 0x77, 0, 0, 0, 0x01], dns: [1, 1, 1, 1] };
    let mut nic = FakeNic { t: 5000, wan_up: true, wan, nexthop: None, mgmt: None, wan_ok: true, wan_n: 0, mgmt_n: 0, last: [0; 1600], last_len: 0 };
    let mut pol = Policy::new();
    let mut nst = NatStats::default();
    let mut c = FwdCounters::default();
    let mut rej = RejWin::default();
    let v6 = V6Us::default();
    let mut nbuf = [0u8; 2048];
    let mut f = [0u8; 400];
    let (bssid, eth1) = ([0x02, 0, 0, 0, 0, 0x01], [0x02, 0, 0, 0, 0, 0xe1]);
    crate::shield::load_text(b"", b"");
    crate::devpolicy::load_text(b"");
    // open a flow: client 10.99.0.10:40000 -> 93.184.216.34:443 (SYN), learn the mapped port
    let n = frame4(6, [93, 184, 216, 34], 443, &[], &mut f);
    let opened = forward4(&f[..n], If::Lan, nat::IF_WIFI, &cfg, &mut pol, &mut nst, &mut c, &mut nbuf, &mut nic, &mut |_| true);
    let mport = u16::from_be_bytes([nic.last[34], nic.last[35]]);
    // the server's SYN-ACK to the lease
    let reply = |src: [u8; 4], sport: u16, dmac: [u8; 6], dport: u16, out: &mut [u8; 400]| -> usize {
        let k = frame4(6, wan.ip, dport, &[], out);
        out[0..6].copy_from_slice(&dmac);
        out[6..12].copy_from_slice(&wan.gw_mac);
        out[26..30].copy_from_slice(&src);
        out[34..36].copy_from_slice(&sport.to_be_bytes());
        out[47] = 0x12; // SYN-ACK
        out[24] = 0;
        out[25] = 0;
        let mut s = 0u32;
        for i in (14..34).step_by(2) {
            s += u16::from_be_bytes([out[i], out[i + 1]]) as u32;
        }
        while s > 0xffff {
            s = (s & 0xffff) + (s >> 16);
        }
        out[24..26].copy_from_slice(&(!(s as u16)).to_be_bytes());
        k
    };
    let k = reply([93, 184, 216, 34], 443, wan.mac, mport, &mut f);
    let r = wan4(&f[..k], [&bssid, &eth1], &v6, &mut pol, &mut rej, &mut nst, &mut c, &mut nbuf, &mut nic);
    let unnat = opened && matches!(r, Wan4::Deliver { eth1: false, .. }) && nbuf[0..6] == [0x02, 0, 0, 0, 0, 0x0a] && nbuf[30..34] == [10, 99, 0, 10]
        && nbuf[36..38] == 40000u16.to_be_bytes() && nst.in_fwd == 1;
    // unsolicited SYN to the lease with a signed `wan in` block: New + a reject to the sender, counted
    let _ = hal::policy::parse_policy(b"HQPOL1\nacl WAN-IN default block\ninterface wan acl in WAN-IN\nacl LAN-OUT seq 10 block tcp 198.51.100.0/24 any\nacl LAN-OUT default allow\ninterface lan acl out LAN-OUT\n", &mut pol);
    let w0 = nic.wan_n;
    let k = reply([203, 0, 113, 5], 5555, wan.mac, 22, &mut f);
    let newb = wan4(&f[..k], [&bssid, &eth1], &v6, &mut pol, &mut rej, &mut nst, &mut c, &mut nbuf, &mut nic) == Wan4::New
        && c.pol_block[If::Wan as usize] == 1 && nic.wan_n == w0 + 1 && nic.last[30..34] == [203, 0, 113, 5];
    // H3: the same frame NOT addressed to us (another host on a shared segment): never a forged reject
    let k = reply([203, 0, 113, 5], 5555, [0x02, 0x99, 0, 0, 0, 0x99], 22, &mut f);
    let h3 = wan4(&f[..k], [&bssid, &eth1], &v6, &mut pol, &mut rej, &mut nst, &mut c, &mut nbuf, &mut nic) == Wan4::New && nic.wan_n == w0 + 1;
    // reject rate limit: 25 more in the same second -> 19 more rejects (20 total), the rest are drops
    let k = reply([203, 0, 113, 6], 5556, wan.mac, 23, &mut f);
    // (straight into `wan_in_new`: 25 identical SYNs would rightly trip the IDS connection-rate rule first)
    for _ in 0..25 {
        wan_in_new(&f[..k], &v6, &mut pol, &mut rej, &mut c, &mut nic);
    }
    let limited = c.pol_block[If::Wan as usize] == 20 && nic.wan_n == w0 + 20 && c.pol_drop[If::Wan as usize] == 6;
    // a new second: rejects resume
    nic.t += 2000;
    wan_in_new(&f[..k], &v6, &mut pol, &mut rej, &mut c, &mut nic);
    let window = c.pol_block[If::Wan as usize] == 21;
    // `lan out` block after un-NAT acts as a drop (no reject re-NATed toward the internet)
    let n = frame4(6, [198, 51, 100, 7], 443, &[], &mut f);
    let _ = forward4(&f[..n], If::Lan, nat::IF_WIFI, &cfg, &mut pol, &mut nst, &mut c, &mut nbuf, &mut nic, &mut |_| true);
    let mport2 = u16::from_be_bytes([nic.last[34], nic.last[35]]);
    let k = reply([198, 51, 100, 7], 443, wan.mac, mport2, &mut f);
    let d0 = c.pol_drop[If::Lan as usize];
    let outblk = wan4(&f[..k], [&bssid, &eth1], &v6, &mut pol, &mut rej, &mut nst, &mut c, &mut nbuf, &mut nic) == Wan4::OutDenied
        && c.block_as_drop == 1 && c.pol_drop[If::Lan as usize] == d0 + 1;
    crate::shield::reset_stats();
    let pass = unnat && newb && h3 && limited && window && outblk;
    arch_aarch64::_print(format_args!(
        " [P-apcore-wan] {} — G0 step 2: the AP's inbound WAN leg (session hold, IDS, un-NAT, stateful `wan in`, `lan out`, scan credit, Shield CNAME, size) on the fake NIC: a reply to a client flow un-NATs to the client MAC / address / port={} new inbound + `wan in` block -> one reject to the sender, counted={} not addressed to us (shared segment, H3) -> no forged reject={} 20 rejects/s cap, the rest drops={} next second resumes={} `lan out` block after un-NAT acts as a drop={}\n",
        if pass { "PASS" } else { "FAIL" }, unnat, newb, h3, limited, window, outblk
    ));
    pass
}
