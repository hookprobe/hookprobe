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
    /// G19: flows the signed `tunnel` carries whose route said `via mgmt` — sent through the tunnel (or dropped
    /// when it cannot send), never in cleartext out the management interface (routing review 2026-11-11).
    pub g19_over_mgmt_route: u32,
    /// A-03: client frames for one of the device's OWN addresses (management / WAN) refused here, never
    /// routed out to come back as a hairpin through the upstream router.
    pub to_self_refused: u32,
    /// A route's `gw` stopped answering ARP: taken out of route selection (metric failover) until it answers.
    pub nh_dead: u32,
}

// ---- next-hop liveness (routing review 2026-11-11) -----------------------------------------------------------
// A `route … gw X` whose X never answers ARP used to blackhole: the route stayed selected and every packet was
// dropped "next hop unresolved". Now X counts as down once it has stayed unresolved for NH_DEAD_MS (≈3 ARP
// requests at the 1/s limit) and route selection skips it, so the metric failover applies; while down it is
// re-probed at most once a second and comes back as soon as it answers. Single writer: the forwarding path.
// Keyed by (egress, gateway) — a VRF id joins the key with R1 (ADR 0060/0061).
const NH_DEAD_MS: u64 = 3_000;
const NH_SLOTS: usize = 8;
#[derive(Clone, Copy)]
struct NhLive {
    via: u8,
    gw: [u8; 4],
    first_miss_ms: u64,
    dead: bool,
    last_probe_ms: u64,
}
static mut NH: [NhLive; NH_SLOTS] = [NhLive { via: 0xff, gw: [0; 4], first_miss_ms: 0, dead: false, last_probe_ms: 0 }; NH_SLOTS];

fn nh_tab() -> &'static mut [NhLive; NH_SLOTS] {
    unsafe { &mut *core::ptr::addr_of_mut!(NH) }
}
fn nh_is_dead(via: If, gw: [u8; 4]) -> bool {
    nh_tab().iter().any(|e| e.via == via as u8 && e.gw == gw && e.dead)
}
/// Record a next-hop resolution result. Returns true when this call declared the next hop dead.
fn nh_note(via: If, gw: [u8; 4], resolved: bool, now_ms: u64) -> bool {
    let t = nh_tab();
    let i = match t.iter().position(|e| e.via == via as u8 && e.gw == gw) {
        Some(i) => i,
        None if resolved => return false,
        None => {
            // a free slot, else the oldest live entry (a dead one is kept: it must stay out of selection)
            let i = t.iter().position(|e| e.via == 0xff).or_else(|| t.iter().position(|e| !e.dead)).unwrap_or(0);
            t[i] = NhLive { via: via as u8, gw, first_miss_ms: now_ms, dead: false, last_probe_ms: now_ms };
            i
        }
    };
    if resolved {
        t[i].via = 0xff;
        t[i].dead = false;
        return false;
    }
    if !t[i].dead && now_ms.saturating_sub(t[i].first_miss_ms) >= NH_DEAD_MS {
        t[i].dead = true;
        return true;
    }
    false
}
/// Re-probe dead next hops (at most once a second each; the resolver itself rate-limits its ARP requests).
fn nh_probe<N: ApNic>(nic: &mut N, now_ms: u64) {
    for i in 0..NH_SLOTS {
        let e = nh_tab()[i];
        if !e.dead || now_ms.saturating_sub(e.last_probe_ms) < 1000 {
            continue;
        }
        nh_tab()[i].last_probe_ms = now_ms;
        let ok = if e.via == If::Mgmt as u8 { nic.mgmt_nexthop(e.gw).is_some() } else { nic.wan_nexthop(e.gw).is_some() };
        if ok {
            let _ = nh_note(if e.via == If::Mgmt as u8 { If::Mgmt } else { If::Wan }, e.gw, true, now_ms);
        }
    }
}
/// `[P-apcore]` only: pretend the tunnel carries this destination (the real `carries` needs a live tunnel).
#[cfg(feature = "securechannel")]
static mut TEST_CARRY: Option<[u8; 4]> = None;
#[cfg(feature = "securechannel")]
fn g19_carries(dst: [u8; 4]) -> bool {
    (unsafe { TEST_CARRY }) == Some(dst) || crate::g19::carries(dst)
}
fn nh_clear() {
    for e in nh_tab().iter_mut() {
        e.via = 0xff;
        e.dead = false;
    }
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
            let mgmt_up = nic.mgmt().is_some_and(|m| m.up);
            let wan_up = nic.wan_up();
            let now_ms = nic.now().saturating_mul(1000) / nic.freq().max(1);
            nh_probe(nic, now_ms);
            let live = |r: &hal::policy::Route| {
                let up = match r.via {
                    If::Wan => wan_up,
                    If::Mgmt => mgmt_up,
                    _ => false,
                };
                up && !r.gw.filter(|g| !g.v6).is_some_and(|g| nh_is_dead(r.via, [g.a[0], g.a[1], g.a[2], g.a[3]]))
            };
            if let Some(r) = pol.route_live(&p.src, &p.dst, &live) {
                egress = r.via;
                nh_ip = r.gw.filter(|g| !g.v6).map(|g| [g.a[0], g.a[1], g.a[2], g.a[3]]);
            }
            act = pol.check(egress, Dir::Out, &p).0;
        }
    }
    let pi = pif as usize;
    // answered / refused by Shield, a session hold or a device policy — not an ACL drop
    let mut shield = false;
    // A-03 (LAN assessment 2026-11-14): a client frame for one of the device's OWN addresses (the management or
    // WAN address; the AP's own address is excluded below) is never routed out: NATed to that same address and
    // reflected by the upstream router it reached Mission Control as a SYN from the device's own address. The
    // device answers for itself: refused like a policy reject (G12-M — Mission Control is not offered to Wi-Fi).
    // NOT the AP's own address: DNS to it is answered by Shield further down this function (a refusal here broke every
    // client's DNS to the AP — the bench caught it 2026-11-14, the same day).
    let dst4 = [frame.get(30).copied().unwrap_or(0), frame.get(31).copied().unwrap_or(0), frame.get(32).copied().unwrap_or(0), frame.get(33).copied().unwrap_or(0)];
    if act == Act::Allow && frame.len() >= 34 && dst4 != cfg.our_ip && crate::ratelimit::is_local_ip(u32::from_be_bytes(dst4)) {
        let mut dr = [0u8; 600];
        if let Some(k) = arch_aarch64::reject::reject4(frame, &cfg.our_ip, &cfg.me, &mut dr) {
            let _ = reply(&dr[..k]);
        }
        c.to_self_refused += 1;
        act = Act::Drop;
        shield = true;
    }
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
        // G19: a flow the signed `tunnel` policy carries rides the Noise tunnel to the super-PoP (NAT to the inner
        // /32, sealed DATA over UDP 7655) — after every check above (holds, device policy, Shield, IDS).
        #[cfg(feature = "securechannel")]
        Act::Allow if frame.len() >= 34 && g19_carries([frame[30], frame[31], frame[32], frame[33]]) => {
            // routing review 2026-11-11: checked BEFORE the `via mgmt` arm — a carried flow never leaves in
            // cleartext out the management interface; if the tunnel cannot send, the packet is dropped (counted)
            if egress == If::Mgmt {
                c.g19_over_mgmt_route += 1;
            }
            let now_ms = (nic.now().saturating_mul(1000) / nic.freq().max(1)) as i64;
            let ok = crate::g19::send(frame, nif, &cfg.inside_net, nst, nic.ticks(), now_ms, &mut |f| nic.wan_tx(f));
            if !ok {
                c.nat_tx_fail += 1;
            }
            ok
        }
        Act::Allow if egress == If::Mgmt => {
            let Some(mg) = nic.mgmt() else { return false };
            let r = nic.mgmt_nexthop(nh_ip.unwrap_or(mg.gw));
            if let Some(g) = nh_ip {
                let now_ms = nic.now().saturating_mul(1000) / nic.freq().max(1);
                if nh_note(If::Mgmt, g, r.is_some(), now_ms) {
                    c.nh_dead += 1;
                }
            }
            match r {
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
                Some(g) => match {
                    let r = nic.wan_nexthop(g);
                    let now_ms = nic.now().saturating_mul(1000) / nic.freq().max(1);
                    if nh_note(If::Wan, g, r.is_some(), now_ms) {
                        c.nh_dead += 1;
                    }
                    r
                } {
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

// ---- step 3a: the Wi-Fi client IPv4 gate chain ---------------------------------------------------------

/// Mission Control on the AP address (TCP 80/443 to `our_ip`). False when the build serves no Mission Control.
pub fn mc_bound(f: &[u8], our_ip: &[u8; 4]) -> bool {
    if !cfg!(feature = "mcserve") || f.len() < 38 || f[12] != 0x08 || f[13] != 0x00 || f[23] != 6 || &f[30..34] != our_ip {
        return false;
    }
    let ihl = ((f[14] & 0x0f) as usize) * 4;
    let Some(p) = f.get(14 + ihl + 2..14 + ihl + 4) else { return false };
    let dport = u16::from_be_bytes([p[0], p[1]]);
    dport == 80 || dport == 443 || alert_flow(f, our_ip)
}

/// The owner alert webhook's return traffic (TCP from the configured receiver ip:port to the AP): the Mission
/// Control node opened that connection, so its SYN-ACK / response must reach the node — also when Mission
/// Control itself is served only on the management VLAN (metal 2026-11-10: the alert never connected).
pub fn alert_flow(f: &[u8], our_ip: &[u8; 4]) -> bool {
    if !cfg!(feature = "mcserve") || f.len() < 38 || f[12] != 0x08 || f[13] != 0x00 || f[23] != 6 || &f[30..34] != our_ip {
        return false;
    }
    let ihl = ((f[14] & 0x0f) as usize) * 4;
    let Some(p) = f.get(14 + ihl..14 + ihl + 2) else { return false };
    crate::alerthook::get().is_some_and(|h| f[26..30] == h.ip && u16::from_be_bytes([p[0], p[1]]) == h.port)
}

/// The fate of one IPv4 frame from a Wi-Fi client that the AP itself did not answer (not DHCP / ARP for us).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Client4 {
    /// An ICMP echo request to the AP itself — answered on the client's port.
    Echo,
    /// (MAC, IP) is not a lease we handed out — anti-hijack.
    BindDrop,
    /// `net::parse` refused it (truncated / oversize) — fail-closed, not a rule drop.
    Trunc,
    /// The signed rule plane (IDS/IPS) dropped it.
    IdsDrop,
    /// Mission Control, but the device's policy (G9) forbids reaching it.
    McDenied,
    /// For Mission Control on the AP address — the caller hands it to the MC node.
    ToMc,
    /// Station → station (G10): the caller relays the frame on Wi-Fi unchanged.
    Relay,
    /// Through `forward4` (true = sent onward).
    Forwarded(bool),
}

/// Which LAN port a client frame came in on, and what that port may do beyond routing.
#[derive(Clone, Copy, Debug)]
pub struct LanPort {
    pub pif: If,
    pub nif: u8,
    /// Mission Control is served on this port.
    pub mc: bool,
    /// Station-to-station relay applies on this port (Wi-Fi: `ap_isolate` makes heqk the relay).
    pub relay: bool,
}
pub const WIFI_PORT: LanPort = LanPort { pif: If::Lan, nif: nat::IF_WIFI, mc: true, relay: true };
pub const ETH1_PORT: LanPort = LanPort { pif: If::Eth1, nif: nat::IF_ETH1, mc: false, relay: false };

/// Lease binding → parse → IDS → Mission Control (device policy) → station relay → `forward4`, in that order.
#[allow(clippy::too_many_arguments)]
#[inline]
pub fn client4<N: ApNic>(
    frame: &[u8],
    port: LanPort,
    now_s: u64,
    dh: &mut arch_aarch64::dhcpd::ApDhcp,
    cfg: &FwdCfg,
    pol: &mut Policy,
    nst: &mut NatStats,
    c: &mut FwdCounters,
    nbuf: &mut [u8],
    nic: &mut N,
    reply: &mut dyn FnMut(&[u8]) -> bool,
) -> Client4 {
    let mut smac = [0u8; 6];
    smac.copy_from_slice(&frame[6..12]);
    let mut sip = [0u8; 4];
    sip.copy_from_slice(&frame[26..30]);
    dh.now = now_s;
    dh.seen(&smac);
    if !dh.binding_ok(&smac, &sip) {
        return Client4::BindDrop;
    }
    if crate::net::parse(frame).is_none() {
        return Client4::Trunc;
    }
    if crate::packet::verdict(frame).1 == crate::packet::DROP {
        return Client4::IdsDrop;
    }
    if port.mc && mc_bound(frame, &cfg.our_ip) {
        return if crate::devpolicy::check(&smac, crate::devpolicy::Dest::DeviceMgmt) { Client4::ToMc } else { Client4::McDenied };
    }
    // ICMP echo to the AP itself (customers and support ping the router): answered here, after the lease
    // binding and the IDS — one reply per request, same size, back to the asking client only.
    if frame.len() >= 42 && frame[12] == 0x08 && frame[13] == 0x00 && frame[23] == 1 && frame[30..34] == cfg.our_ip {
        let ihl = ((frame[14] & 0x0f) as usize) * 4;
        let l4 = 14 + ihl;
        let tot = u16::from_be_bytes([frame[16], frame[17]]) as usize;
        let n = 14 + tot;
        if frame.get(l4) == Some(&8) && tot >= ihl + 8 && n <= frame.len() && n <= 1514 {
            let mut r = [0u8; 1514];
            r[..n].copy_from_slice(&frame[..n]);
            r[0..6].copy_from_slice(&smac);
            r[6..12].copy_from_slice(&cfg.me);
            r[22] = 64; // TTL
            r[26..30].copy_from_slice(&cfg.our_ip);
            r[30..34].copy_from_slice(&sip);
            r[24] = 0;
            r[25] = 0;
            let c = hal::inet_csum(&r[14..l4], 0);
            r[24..26].copy_from_slice(&c.to_be_bytes());
            r[l4] = 0; // echo reply
            r[l4 + 2] = 0;
            r[l4 + 3] = 0;
            let c = hal::inet_csum(&r[l4..n], 0);
            r[l4 + 2..l4 + 4].copy_from_slice(&c.to_be_bytes());
            let _ = reply(&r[..n]);
            return Client4::Echo;
        }
    }
    if port.relay && crate::lanrelay::relay_target(frame, dh) {
        return Client4::Relay;
    }
    // Phase 4: the per-device behaviour baseline — outbound TCP SYNs / UDP to the internet (observe-only)
    if frame.len() >= 38 && frame[12] == 0x08 && frame[13] == 0x00 && matches!(frame[23], 6 | 17) {
        let ihl = ((frame[14] & 0x0f) as usize) * 4;
        let l4 = 14 + ihl;
        let dst = u32::from_be_bytes([frame[30], frame[31], frame[32], frame[33]]);
        let syn_or_udp = frame[23] == 17 || frame.get(l4 + 13).is_some_and(|&f| f & 0x12 == 0x02);
        if syn_or_udp && frame.len() >= l4 + 4 && !crate::behavioral::is_internal(dst) {
            let dport = u16::from_be_bytes([frame[l4 + 2], frame[l4 + 3]]);
            let single = || {
                dh.leases.iter().find(|l| l.used && l.mac == smac).is_some_and(|l| {
                    let id = crate::devid::classify(&smac, &l.host[..l.hlen as usize], &l.vendor[..l.vlen as usize], &l.prl[..l.plen as usize]);
                    crate::devbase::is_single_purpose(id.category)
                })
            };
            let _ = crate::devbase::observe(u32::from_be_bytes(sip), single, frame[23], dport, now_s);
        }
    }
    Client4::Forwarded(forward4(frame, port.pif, port.nif, cfg, pol, nst, c, nbuf, nic, reply))
}

/// G0 step 5b: the SIEM export's per-beat counters (the beat prints them).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SiemStats {
    pub sent: u32,
    pub lost: u32,
    /// Beats with nothing to send through (no source address or next hop yet).
    pub unrouted: u32,
}

/// G0 step 5b (parity G15): send the detections newer than `cursor` to the signed POLICY.TXT `export syslog` collector
/// (RFC 5424 or OCSF JSON over UDP), at most 32 per beat, via the WAN lease or the management sub-interface; `cursor`
/// advances past every detection handled (sent or lost — a lost UDP datagram is counted, never re-sent). Returns
/// whether a route existed this beat.
#[cfg(feature = "netsvc")]
pub fn siem_export<N: ApNic>(nic: &mut N, ex: &hal::policy::Export, st: &crate::mcstate::McState, cursor: &mut Option<u64>, stats: &mut SiemStats) -> bool {
    let (via_wan, src_ip, src_mac, nh) = match ex.via {
        If::Mgmt => match nic.mgmt() {
            Some(m) => (false, m.ip, m.mac, nic.mgmt_nexthop(ex.ip)),
            None => (false, [0; 4], [0; 6], None),
        },
        _ => {
            let w = nic.wan();
            (true, w.ip, w.mac, (w.gw_mac != [0u8; 6]).then_some(w.gw_mac))
        }
    };
    let Some(dmac) = nh.filter(|_| src_ip != [0; 4]) else {
        stats.unrouted += 1;
        return false;
    };
    let mut sent = 0u32;
    let mut last = *cursor;
    st.for_each_det_after(*cursor, &mut |d, ms| {
        if sent >= 32 {
            return; // bounded per beat; the rest go next beat
        }
        let info = crate::rulecat::lookup_or_generic(d.rule_id);
        let det = crate::siem::Det {
            seq: d.seq, ts_ms: ms, rule_id: crate::rulecat::HEQK_RULE_BAND + d.rule_id as u32, msg: info.msg,
            category: info.category, mitre: info.mitre, severity: info.severity, src: d.src, dst: d.dst,
            dport: d.dport, action: if d.verdict == 2 { "dropped" } else { "observed" },
        };
        let mut msg = [0u8; 700];
        let n = if ex.json { crate::siem::ocsf_json(&det, "heqk-ap", &mut msg) } else { crate::siem::rfc5424(&det, "heqk-ap", &mut msg) };
        let mut fr = [0u8; 760];
        if n > 0 {
            let k = crate::wanntp::udp4(&mut fr, &src_mac, &dmac, src_ip, ex.ip, 40514, ex.port, &msg[..n]);
            let ok = if via_wan { nic.wan_tx(&fr[..k]) } else { nic.mgmt_tx(&fr[..k]) };
            if ok { stats.sent += 1 } else { stats.lost += 1 }
        }
        last = Some(d.seq);
        sent += 1;
    });
    *cursor = last;
    true
}

/// `[P-apcore-siem]` — step 5b on the fake NIC.
#[cfg(feature = "netsvc")]
pub fn siem_selftest() -> bool {
    let wan = WanView { ip: [100, 64, 7, 9], mac: [0x02, 0x77, 0, 0, 0, 0x09], gw_mac: [0x02, 0x77, 0, 0, 0, 0x01], dns: [1, 1, 1, 1] };
    let mut nic = FakeNic { t: 1000, wan_up: true, wan, nexthop: None, mgmt: None, wan_ok: true, wan_n: 0, mgmt_n: 0, last: [0; 1600], last_len: 0 };
    let mut st = crate::mcstate::McState::new();
    st.set_clock(1_800_000_000_000, 0, 1000);
    for i in 0..40u32 {
        st.push_event(&crate::events::Event { ts: i as u64, src: 0x0a63_000a, rule_id: 4, severity: 5, verdict: if i % 2 == 0 { 2 } else { 1 }, class: 0, dst: 0x5db8_d822, dport: 4444 });
    }
    let ex = hal::policy::Export { ip: [192, 168, 200, 10], port: 514, via: If::Wan, json: false };
    let mut cur = None;
    let mut ss = SiemStats::default();
    // 40 new detections: 32 this beat over the WAN to the collector (UDP 514, from the lease), 8 the next, then none
    let b1 = siem_export(&mut nic, &ex, &st, &mut cur, &mut ss) && ss.sent == 32 && nic.wan_n == 32
        && nic.last[0..6] == wan.gw_mac && nic.last[26..30] == wan.ip && nic.last[30..34] == [192, 168, 200, 10] && nic.last[36..38] == 514u16.to_be_bytes();
    let b2 = siem_export(&mut nic, &ex, &st, &mut cur, &mut ss) && ss.sent == 40 && nic.wan_n == 40;
    let b3 = siem_export(&mut nic, &ex, &st, &mut cur, &mut ss) && ss.sent == 40 && nic.wan_n == 40;
    // OCSF JSON when asked
    let mut cur_j = None;
    let exj = hal::policy::Export { json: true, ..ex };
    let _ = siem_export(&mut nic, &exj, &st, &mut cur_j, &mut ss);
    let json = nic.last[42] == b'{';
    // via mgmt with no management sub-interface: unrouted, the cursor does not move (nothing is lost)
    let exm = hal::policy::Export { via: If::Mgmt, ..ex };
    let mut cur_m = None;
    let unrouted = !siem_export(&mut nic, &exm, &st, &mut cur_m, &mut ss) && ss.unrouted == 1 && cur_m.is_none();
    // a failed send is counted as lost and not retried
    nic.wan_ok = false;
    st.push_event(&crate::events::Event { ts: 50, src: 0x0a63_000a, rule_id: 4, severity: 5, verdict: 2, class: 0, dst: 0, dport: 0 });
    let lost = siem_export(&mut nic, &ex, &st, &mut cur, &mut ss) && ss.lost == 1 && siem_export(&mut nic, &ex, &st, &mut cur, &mut ss) && ss.lost == 1;
    let pass = b1 && b2 && b3 && json && unrouted && lost;
    arch_aarch64::_print(format_args!(
        " [P-apcore-siem] {} — G0 step 5b: the SIEM export (parity G15) on the fake NIC: 40 detections -> 32 this beat to the collector over the WAN (UDP, from the lease, via the gateway)={} the other 8 next beat={} then nothing re-sent={} OCSF JSON when asked={} via mgmt without a management interface: unrouted, cursor kept={} a failed send counted lost, not retried={}\n",
        if pass { "PASS" } else { "FAIL" }, b1, b2, b3, json, unrouted, lost
    ));
    pass
}

/// G0 step 4: where one frame received on the management sub-interface goes (after `mgmt_poll` answered ARP / ping).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MgmtOut {
    /// Dropped (`mgmt in` refused it, nothing serves it, or a policy / IDS / size check after un-NAT); counted.
    Dropped,
    /// For the Mission Control node: `mcbuf[..len]` (re-addressed to the node, `mgmt in` and the IDS passed).
    ForMc(usize),
    /// A reply to a flow routed out management, un-NATed for a client: `nbuf[..len]` to eth1.
    ToEth1(usize),
    /// … to a Wi-Fi client: `nbuf[..len]`.
    ToWifi(usize),
}

/// The management sub-interface's inbound path (was inline in the AP loop): stateful like `wan in` — a reply to a flow
/// routed out management (NAT session) is un-NATed, checked against `<lan|eth1> out` and the IDS, and goes to its
/// client; anything else is new inbound traffic for `mgmt in`, and only Mission Control (G12-M, TCP 80 / 443 to the
/// management address, when `mc_on_mgmt`) is served. `mgmt_ip` / `mgmt_mac` = the sub-interface; `inside` = the AP
/// and eth1 MACs (the un-NATed frame's source).
#[allow(clippy::too_many_arguments)]
pub fn on_mgmt_frame(frame: &[u8], mgmt_ip: &[u8; 4], mgmt_mac: &[u8; 6], inside: [&[u8; 6]; 2], node_mac: &[u8; 6], mc_on_mgmt: bool,
    pol: &mut Policy, nst: &mut NatStats, c: &mut FwdCounters, ids_drop_in: &mut u32, nbuf: &mut [u8], mcbuf: &mut [u8], now: u64) -> MgmtOut {
    let Some((mm, in_if)) = nat::inbound(frame, mgmt_ip, mgmt_mac, inside, nbuf, now, nst) else {
        let allow = hal::policy::facts(frame).map(|p| pol.check(If::Mgmt, Dir::In, &p).0).unwrap_or(Act::Drop) == Act::Allow; // unparseable = drop (H2)
        if !allow {
            c.pol_drop[If::Mgmt as usize] += 1;
            return MgmtOut::Dropped;
        }
        // G12-M: Mission Control on the management address (after `mgmt in`)
        if mc_on_mgmt {
            if let Some(l) = crate::mcmgmt::ingress(frame, *mgmt_ip, *node_mac, mcbuf) {
                if crate::packet::verdict(&mcbuf[..l]).1 != crate::packet::DROP {
                    return MgmtOut::ForMc(l);
                }
                *ids_drop_in += 1;
            }
        }
        return MgmtOut::Dropped;
    };
    let oif = if in_if == nat::IF_ETH1 { If::Eth1 } else { If::Lan };
    let a = hal::policy::facts(&nbuf[..mm]).map(|p| pol.check(oif, Dir::Out, &p).0).unwrap_or(Act::Allow);
    if a != Act::Allow {
        c.pol_drop[oif as usize] += 1;
        MgmtOut::Dropped
    } else if crate::packet::verdict(&nbuf[..mm]).1 == crate::packet::DROP {
        *ids_drop_in += 1;
        MgmtOut::Dropped
    } else if in_if == nat::IF_ETH1 {
        MgmtOut::ToEth1(mm)
    } else if mm <= nat::WIFI_MAX_FRAME {
        MgmtOut::ToWifi(mm)
    } else {
        MgmtOut::Dropped
    }
}

/// `[P-apcore-mgmt]` — step 4: the management inbound path on hand-built frames.
pub fn mgmt_selftest() -> bool {
    let mgmt_ip = [192u8, 168, 200, 146];
    let mgmt_mac = [0x02u8, 0x4d, 0, 0, 0, 0x46];
    let ap = [0x02u8, 0, 0, 0, 0, 0x01];
    let lan = [0x02u8, 0x0e, 0, 0, 0, 0x01];
    let node = [0x02u8, 0x0c, 0, 0, 0, 0x01];
    let mut pol = Policy::new();
    let mut nst = NatStats::default();
    let mut c = FwdCounters::default();
    let mut ids = 0u32;
    let (mut nbuf, mut mcbuf) = ([0u8; 2048], [0u8; 1600]);
    let mut f = [0u8; 400];
    // an admin's SYN to the management address :443 (new inbound: `mgmt in`)
    let syn = |dport: u16, f: &mut [u8; 400]| -> usize {
        let n = frame4(6, mgmt_ip, dport, &[], f);
        f[0..6].copy_from_slice(&mgmt_mac);
        f[6..12].copy_from_slice(&[0x02, 0xad, 0, 0, 0, 0x01]);
        f[26..30].copy_from_slice(&[192, 168, 200, 1]);
        n
    };
    let n = syn(443, &mut f);
    let to_mc = matches!(on_mgmt_frame(&f[..n], &mgmt_ip, &mgmt_mac, [&ap, &lan], &node, true, &mut pol, &mut nst, &mut c, &mut ids, &mut nbuf, &mut mcbuf, 1), MgmtOut::ForMc(l) if l == n && mcbuf[0..6] == node);
    // Mission Control not served on management (setup AP / no `mgmt` MC): nothing serves it
    let not_served = on_mgmt_frame(&f[..n], &mgmt_ip, &mgmt_mac, [&ap, &lan], &node, false, &mut pol, &mut nst, &mut c, &mut ids, &mut nbuf, &mut mcbuf, 2) == MgmtOut::Dropped;
    // another port (22): not Mission Control
    let n22 = syn(22, &mut f);
    let other_port = on_mgmt_frame(&f[..n22], &mgmt_ip, &mgmt_mac, [&ap, &lan], &node, true, &mut pol, &mut nst, &mut c, &mut ids, &mut nbuf, &mut mcbuf, 3) == MgmtOut::Dropped;
    // `mgmt in` refusing the admin: dropped and counted on the mgmt column, Mission Control never reached
    hal::policy::parse_policy(b"HQPOL1\nacl MGMT-IN seq 10 drop any any any\ninterface mgmt acl in MGMT-IN\n", &mut pol).ok();
    let n = syn(443, &mut f);
    let refused = on_mgmt_frame(&f[..n], &mgmt_ip, &mgmt_mac, [&ap, &lan], &node, true, &mut pol, &mut nst, &mut c, &mut ids, &mut nbuf, &mut mcbuf, 4) == MgmtOut::Dropped
        && c.pol_drop[If::Mgmt as usize] == 1;
    pol = Policy::new();
    // a reply to a client flow routed out management (NAT session): un-NATed to the Wi-Fi client
    let n = frame4(6, [10, 20, 0, 5], 443, &[], &mut f);
    let mut o = [0u8; 2048];
    let k = nat::outbound_redirect(&f[..n], nat::IF_WIFI, &[10, 99, 0], None, &mgmt_ip, &mgmt_mac, &[0x02, 0xad, 0, 0, 0, 0x01], &mut o, 5, &mut nst).unwrap_or(0);
    let mut r = [0u8; 400];
    r[..k].copy_from_slice(&o[..k]);
    r[0..6].copy_from_slice(&mgmt_mac);
    r[6..12].copy_from_slice(&[0x02, 0xad, 0, 0, 0, 0x01]);
    r[26..30].copy_from_slice(&o[30..34]); // server -> our management address, ports swapped
    r[30..34].copy_from_slice(&o[26..30]);
    r[34..36].copy_from_slice(&o[36..38]);
    r[36..38].copy_from_slice(&o[34..36]);
    r[47] = 0x12; // SYN-ACK
    let replied = k > 0 && matches!(on_mgmt_frame(&r[..k], &mgmt_ip, &mgmt_mac, [&ap, &lan], &node, true, &mut pol, &mut nst, &mut c, &mut ids, &mut nbuf, &mut mcbuf, 6),
        MgmtOut::ToWifi(m) if nbuf[30..34] == [10, 99, 0, 10] && m == k);
    // `lan out` blocking that reply: dropped and counted on the lan column
    hal::policy::parse_policy(b"HQPOL1\nacl LAN-OUT seq 10 drop any any any\ninterface lan acl out LAN-OUT\n", &mut pol).ok();
    let lan_out = on_mgmt_frame(&r[..k], &mgmt_ip, &mgmt_mac, [&ap, &lan], &node, true, &mut pol, &mut nst, &mut c, &mut ids, &mut nbuf, &mut mcbuf, 7) == MgmtOut::Dropped
        && c.pol_drop[If::Lan as usize] == 1;
    let pass = to_mc && not_served && other_port && refused && replied && lan_out;
    arch_aarch64::_print(format_args!(
        " [P-apcore-mgmt] {} — G0 step 4: the management inbound path (was inline in the AP loop): an admin's SYN to :443 -> the Mission Control node={} not served when MC is not on management={} another port not Mission Control={} `mgmt in` drop counted, MC never reached={} a reply to a flow routed out management -> un-NATed to its Wi-Fi client={} `lan out` drop on that reply counted={}\n",
        if pass { "PASS" } else { "FAIL" }, to_mc, not_served, other_port, refused, replied, lan_out
    ));
    pass
}

/// `[P-apcore-lan]` — step 3a on the fake NIC.
pub fn lan_selftest() -> bool {
    use arch_aarch64::dhcpd::ApDhcp;
    let cfg = FwdCfg { our_ip: [10, 99, 0, 1], me: [0x02, 0, 0, 0, 0, 0x01], inside_net: [10, 99, 0] };
    let wan = WanView { ip: [100, 64, 7, 9], mac: [0x02, 0x77, 0, 0, 0, 0x09], gw_mac: [0x02, 0x77, 0, 0, 0, 0x01], dns: [1, 1, 1, 1] };
    let mut nic = FakeNic { t: 9000, wan_up: true, wan, nexthop: None, mgmt: None, wan_ok: true, wan_n: 0, mgmt_n: 0, last: [0; 1600], last_len: 0 };
    let mut pol = Policy::new();
    let mut nst = NatStats::default();
    let mut c = FwdCounters::default();
    let mut nbuf = [0u8; 2048];
    let mut dh = ApDhcp::new();
    let (a_mac, b_mac) = ([0x02, 0, 0, 0, 0, 0x0a], [0x02, 0, 0, 0, 0, 0x0b]);
    dh.now = 100;
    let a_ip = dh.alloc_for(&a_mac, &[10, 99, 0, 10]).unwrap_or([0; 4]);
    dh.commit(&a_mac);
    let b_ip = dh.alloc_for(&b_mac, &[10, 99, 0, 10]).unwrap_or([0; 4]);
    dh.commit(&b_mac);
    crate::shield::load_text(b"", b"");
    crate::devpolicy::load_text(b"");
    let mut f = [0u8; 400];
    let mut go = |fr: &[u8], dh: &mut ApDhcp, nic: &mut FakeNic, pol: &mut Policy| client4(fr, WIFI_PORT, 100, dh, &cfg, pol, &mut nst, &mut c, &mut nbuf, nic, &mut |_| true);
    // A (leased) to the internet: forwarded through NAT
    let n = frame4(6, [93, 184, 216, 34], 443, &[], &mut f);
    f[26..30].copy_from_slice(&a_ip);
    let fwd = go(&f[..n], &mut dh, &mut nic, &mut pol) == Client4::Forwarded(true) && nic.wan_n == 1;
    // the same frame claiming another IP (not its lease): bind drop, nothing sent
    let mut spoof = f;
    spoof[26..30].copy_from_slice(&[10, 99, 0, 77]);
    let bind = go(&spoof[..n], &mut dh, &mut nic, &mut pol) == Client4::BindDrop && nic.wan_n == 1;
    // a truncated frame (IPv4 total length past the end)
    let mut tr = f;
    tr[16..18].copy_from_slice(&1400u16.to_be_bytes());
    let trunc = go(&tr[..n], &mut dh, &mut nic, &mut pol) == Client4::Trunc;
    // Mission Control on the AP address: handed to the MC node — unless the device is internet_only
    let mut mc = f;
    mc[30..34].copy_from_slice(&cfg.our_ip);
    mc[36..38].copy_from_slice(&443u16.to_be_bytes());
    let r = go(&mc[..n], &mut dh, &mut nic, &mut pol);
    let to_mc = if cfg!(feature = "mcserve") { r == Client4::ToMc } else { matches!(r, Client4::Forwarded(_)) }; // no MC in this build
    crate::devpolicy::load_text(b"02:00:00:00:00:0a internet_only
");
    let mc_denied = !cfg!(feature = "mcserve") || go(&mc[..n], &mut dh, &mut nic, &mut pol) == Client4::McDenied;
    crate::devpolicy::load_text(b"");
    // A -> B (both leased, B's MAC as destination): station relay, not the internet path
    let mut ab = f;
    ab[0..6].copy_from_slice(&b_mac);
    ab[30..34].copy_from_slice(&b_ip);
    let w0 = nic.wan_n;
    let relay = go(&ab[..n], &mut dh, &mut nic, &mut pol) == Client4::Relay && nic.wan_n == w0;
    // eth1: the same gates, but no Mission Control and no station relay on the wired port
    let r_eth = client4(&ab[..n], ETH1_PORT, 100, &mut dh, &cfg, &mut pol, &mut nst, &mut c, &mut nbuf, &mut nic, &mut |_| true);
    let eth1 = matches!(r_eth, Client4::Forwarded(_)) && client4(&tr[..n], ETH1_PORT, 100, &mut dh, &cfg, &mut pol, &mut nst, &mut c, &mut nbuf, &mut nic, &mut |_| true) == Client4::Trunc;
    // ping the AP: an echo reply comes back to the client (checksums valid), nothing goes to the WAN
    let mut pg = [0u8; 400];
    let pn = frame4(1, cfg.our_ip, 0, &[0xab; 16], &mut pg);
    pg[26..30].copy_from_slice(&a_ip);
    pg[34] = 8; // echo request
    pg[35] = 0;
    pg[36..38].copy_from_slice(&0u16.to_be_bytes());
    let ck = hal::inet_csum(&pg[34..pn], 0);
    pg[36..38].copy_from_slice(&ck.to_be_bytes());
    let got = core::cell::RefCell::new(([0u8; 128], 0usize));
    let w1 = nic.wan_n;
    let er = client4(&pg[..pn], WIFI_PORT, 100, &mut dh, &cfg, &mut pol, &mut nst, &mut c, &mut nbuf, &mut nic, &mut |fr| {
        let mut g = got.borrow_mut();
        let k = fr.len().min(128);
        g.0[..k].copy_from_slice(&fr[..k]);
        g.1 = fr.len();
        true
    });
    let (rb, rl) = *got.borrow();
    let echo = er == Client4::Echo && nic.wan_n == w1 && rl == pn && rb[34] == 0 && rb[26..30] == cfg.our_ip && rb[30..34] == a_ip
        && rb[0..6] == a_mac && hal::inet_csum(&rb[14..34], 0) == 0 && hal::inet_csum(&rb[34..rl.min(128)], 0) == 0;
    crate::shield::reset_stats();
    let pass = fwd && bind && trunc && to_mc && mc_denied && relay && eth1 && echo;
    arch_aarch64::_print(format_args!(
        " [P-apcore-lan] {} — G0 step 3a: the Wi-Fi client IPv4 gate chain (lease binding -> parse -> IDS -> Mission Control + device policy -> station relay -> forward) on the fake NIC: leased client forwarded through NAT={} a frame claiming another IP dropped (anti-hijack)={} truncated frame fail-closed, not a rule drop={} Mission Control on the AP address handed to the MC node={} internet_only device kept off Mission Control={} station -> station relayed, not sent to the internet={} eth1 port: same gates, no MC / relay, truncation fail-closed={} ping to the AP answered (valid checksums, nothing to the WAN)={}\n",
        if pass { "PASS" } else { "FAIL" }, fwd, bind, trunc, to_mc, mc_denied, relay, eth1, echo
    ));
    pass
}

// ---- step 3c: the Wi-Fi data ladder (which path a client frame takes) -------------------------------------

/// Which handler a Wi-Fi client frame goes to, after the AP's own DHCP / ARP-for-us answer (`act`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WifiPath {
    /// The AP answered it (DHCP / ARP for us) — nothing more.
    Answered,
    /// mDNS / SSDP / LLMNR from a station -> the other stations (G10, IDS first).
    Discovery,
    /// IPv6 station -> station (G10, IDS first).
    StationRelay6,
    /// ARP from a station (proxy-ARP for another station, G10).
    ProxyArp,
    /// IPv6 through the AP's IPv6 router (only when it is up).
    Ipv6,
    /// IPv4 through the client gate chain (`client4`), when an uplink (WAN or management) is usable.
    Ipv4,
    /// Nothing to do with it.
    Ignore,
}

/// The ladder's ORDER is a decision (it was an `else if` chain in the loop): discovery before the IPv6 station
/// relay, the station relay before proxy-ARP, IPv6 only with the router up, IPv4 only with a usable uplink.
pub fn wifi_path(frame: &[u8], act: u8, dh: &arch_aarch64::dhcpd::ApDhcp, v6_up: bool, uplink: bool) -> WifiPath {
    if act != 0 {
        return WifiPath::Answered;
    }
    let et = if frame.len() >= 14 { [frame[12], frame[13]] } else { return WifiPath::Ignore };
    if crate::lanrelay::is_discovery_mcast(frame) {
        WifiPath::Discovery
    } else if crate::lanrelay::relay_target6(frame, dh) {
        WifiPath::StationRelay6
    } else if frame.len() >= 42 && et == [0x08, 0x06] {
        WifiPath::ProxyArp
    } else if frame.len() >= 54 && et == [0x86, 0xdd] && v6_up {
        WifiPath::Ipv6
    } else if uplink && frame.len() >= 34 && et == [0x08, 0x00] {
        WifiPath::Ipv4
    } else {
        WifiPath::Ignore
    }
}

/// `[P-apcore-ladder]` — step 3c.
pub fn ladder_selftest() -> bool {
    use arch_aarch64::dhcpd::ApDhcp;
    let mut dh = ApDhcp::new();
    dh.now = 100;
    let a = [0x02, 0, 0, 0, 0, 0x0a];
    let _ = dh.alloc_for(&a, &[10, 99, 0, 10]);
    dh.commit(&a);
    let mut f = [0u8; 120];
    let eth = |dst: [u8; 6], et: [u8; 2], f: &mut [u8; 120]| {
        f.fill(0);
        f[0..6].copy_from_slice(&dst);
        f[6..12].copy_from_slice(&a);
        f[12..14].copy_from_slice(&et);
    };
    eth([0xff; 6], [0x08, 0x06], &mut f);
    let arp = wifi_path(&f[..60], 0, &dh, true, true) == WifiPath::ProxyArp;
    let answered = wifi_path(&f[..60], b'A', &dh, true, true) == WifiPath::Answered;
    // mDNS to 224.0.0.251:5353 (IPv4 multicast MAC)
    eth([0x01, 0x00, 0x5e, 0, 0, 0xfb], [0x08, 0x00], &mut f);
    f[14] = 0x45;
    f[23] = 17;
    f[26..30].copy_from_slice(&[10, 99, 0, 10]);
    f[30..34].copy_from_slice(&[224, 0, 0, 251]);
    f[34..36].copy_from_slice(&5353u16.to_be_bytes());
    f[36..38].copy_from_slice(&5353u16.to_be_bytes());
    let mdns = wifi_path(&f[..80], 0, &dh, true, true) == WifiPath::Discovery;
    // unicast IPv4 to the internet: client4 when an uplink is usable, ignored otherwise
    eth([0x02, 0, 0, 0, 0, 0x01], [0x08, 0x00], &mut f);
    f[14] = 0x45;
    f[23] = 6;
    f[26..30].copy_from_slice(&[10, 99, 0, 10]);
    f[30..34].copy_from_slice(&[93, 184, 216, 34]);
    let v4 = wifi_path(&f[..60], 0, &dh, true, true) == WifiPath::Ipv4 && wifi_path(&f[..60], 0, &dh, true, false) == WifiPath::Ignore;
    // IPv6 to the internet: the router path only while it is up
    eth([0x02, 0, 0, 0, 0, 0x01], [0x86, 0xdd], &mut f);
    f[14] = 0x60;
    f[20] = 6;
    f[38] = 0x20;
    let v6 = wifi_path(&f[..80], 0, &dh, true, true) == WifiPath::Ipv6 && wifi_path(&f[..80], 0, &dh, false, true) == WifiPath::Ignore;
    let short = wifi_path(&f[..10], 0, &dh, true, true) == WifiPath::Ignore;
    let pass = arp && answered && mdns && v4 && v6 && short;
    arch_aarch64::_print(format_args!(
        " [P-apcore-ladder] {} — G0 step 3c: the Wi-Fi data ladder order (answered -> discovery -> IPv6 station relay -> proxy-ARP -> IPv6 router -> IPv4 gate chain): ARP -> proxy-ARP={} AP-answered stops={} mDNS -> discovery relay={} IPv4 only with a usable uplink={} IPv6 only with the router up={} runt ignored={}\n",
        if pass { "PASS" } else { "FAIL" }, arp, answered, mdns, v4, v6, short
    ));
    pass
}

// ---- step 3b: the Wi-Fi client IPv6 branch --------------------------------------------------------------

/// The fate of one IPv6 frame from a Wi-Fi client (the AP's IPv6 LAN router is up).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(not(feature = "apmode"), allow(dead_code))]
pub enum Client6 {
    /// RS / NS answered by the router: send `v6buf[..len]` back to the client.
    Reply(usize),
    /// Routed out the WAN (true = sent; the flow's inbound pinhole opened).
    Forwarded(bool),
    /// `lan in` / `wan out` block: a reject went back to the client.
    Blocked,
    /// `lan in` / `wan out` drop.
    Dropped,
    /// The IDS dropped it.
    IdsDrop,
    /// Nothing to do (not routable / for us / malformed).
    Ignored,
}

/// The client IPv6 branch: the LAN router (RS/NS/forwarding decision), then `lan in` and `wan out` (IPv6
/// egress is the internet sub-interface — the management VLAN carries no IPv6), the observe-only IPv6
/// detectors keyed on the device (scan shape, JA4, beacon / brute force, IOC — `lease_of` maps the client MAC
/// to its IPv4 lease for attribution), the IDS, and the send. The pinhole opens only after a successful send.
#[allow(clippy::too_many_arguments)]
#[cfg_attr(not(feature = "apmode"), allow(dead_code))]
pub fn client6<N: ApNic>(
    frame: &[u8],
    v6: &mut arch_aarch64::ip6lan::V6Lan,
    now_ms: u64,
    wan_usable: bool,
    me: &[u8; 6],
    pol: &mut Policy,
    c: &mut FwdCounters,
    v6buf: &mut [u8],
    nic: &mut N,
    lease_of: &dyn Fn(&[u8; 6]) -> u32,
    reply: &mut dyn FnMut(&[u8]) -> bool,
) -> Client6 {
    use arch_aarch64::ip6lan::LanAction;
    match v6.on_lan(frame, now_ms, v6buf) {
        LanAction::Reply(k) => Client6::Reply(k),
        LanAction::Forward(k) => {
            let pa = hal::policy::facts(frame)
                .map(|p| {
                    let a = pol.check(If::Lan, Dir::In, &p).0;
                    if a == Act::Allow { (pol.check(If::Wan, Dir::Out, &p).0, If::Wan as usize) } else { (a, If::Lan as usize) }
                })
                .unwrap_or((Act::Allow, 0));
            if frame.len() >= 54 {
                let mut sm = [0u8; 6];
                sm.copy_from_slice(&frame[6..12]);
                let mut d6 = [0u8; 16];
                d6.copy_from_slice(&frame[38..54]);
                let _ = crate::rules::flow_scan_observe6(frame, crate::srckey::dev(&sm), crate::srckey::v6net(&d6));
                // G36: an IPv6-only device (no lease) keys on its 248/5 identity instead of being skipped
                let lease = crate::srckey::v6_attrib(lease_of(&sm), &sm);
                if frame[20] == 6 {
                    if crate::ja4::observe6(frame, lease) {
                        return Client6::IdsDrop; // rule 126 enforcement (Shield-blocked name over a DNS bypass)
                    }
                    crate::rules::behavioral_observe6(frame, lease);
                }
                let _ = crate::rules::ioc_v6_hit(lease, &d6);
            }
            match pa {
                (Act::Allow, _) => {
                    if crate::packet::verdict(frame).1 == crate::packet::DROP {
                        Client6::IdsDrop
                    } else if wan_usable && nic.wan_tx6(&v6buf[..k]) {
                        v6.commit(now_ms);
                        Client6::Forwarded(true)
                    } else {
                        Client6::Forwarded(false)
                    }
                }
                (Act::Block, i) => {
                    c.pol_block[i] += 1;
                    let mut rj = [0u8; 1400];
                    if let Some(r) = arch_aarch64::reject::reject6(frame, &v6.gua, me, &mut rj) {
                        let _ = reply(&rj[..r]);
                    }
                    Client6::Blocked
                }
                (Act::Drop, i) => {
                    c.pol_drop[i] += 1;
                    Client6::Dropped
                }
            }
        }
        _ => Client6::Ignored,
    }
}

// ---- step 3c: station-to-station (G10) ------------------------------------------------------------------

/// The station-to-station branches a client frame can take before routing (G10): discovery multicast
/// (mDNS / SSDP / LLMNR) copied to the other stations, IPv6 station -> station, and ARP for another station
/// (proxy-ARP — the firmware's `ap_isolate` keeps stations from talking directly). Every copy passes the IDS
/// first. Returns true when the frame belonged to one of these branches (whatever was sent).
pub fn station_relay(frame: &[u8], dh: &arch_aarch64::dhcpd::ApDhcp, now_s: u64, send: &mut dyn FnMut(&[u8]) -> bool) -> bool {
    use crate::lanrelay;
    let ids_ok = || crate::packet::verdict(frame).1 != crate::packet::DROP;
    if lanrelay::is_discovery_mcast(frame) {
        if ids_ok() {
            let _ = lanrelay::relay_discovery(frame, dh, now_s, send);
        }
        true
    } else if lanrelay::relay_target6(frame, dh) {
        if ids_ok() {
            // Phase 4 (G36): station-to-station IPv6 connection attempts feed the lateral tier under both
            // devices' IPv4 leases (observe-only).
            if frame.len() >= 54 && frame[20] == 6 {
                let mut sm = [0u8; 6];
                let mut dm = [0u8; 6];
                sm.copy_from_slice(&frame[6..12]);
                dm.copy_from_slice(&frame[0..6]);
                let l = |m: &[u8; 6]| crate::srckey::v6_attrib(dh.lease_for(m).map_or(0, u32::from_be_bytes), m);
                let _ = crate::rules::lateral_observe6(frame, l(&sm), l(&dm));
            }
            let _ = send(frame);
        }
        true
    } else if frame.len() >= 42 && frame[12] == 0x08 && frame[13] == 0x06 {
        let mut ab = [0u8; 64];
        let k = lanrelay::proxy_arp(frame, dh, &mut ab);
        if k > 0 {
            let _ = send(&ab[..k]);
        }
        true
    } else {
        false
    }
}

// ---- AP TX priority (soak 2026-11-10: DNS lost / 2-s tails under a saturating download) -----------------------

/// A frame to a Wi-Fi station that must not wait behind a bulk backlog: ARP, DHCP, DNS answers (UDP from port 53),
/// ICMP / ICMPv6 (incl. neighbour discovery), and TCP segments with NO payload (pure ACK / SYN / FIN / RST — they
/// pace the sender; delaying them throttles every flow). Narrow on purpose: generic small UDP (QUIC, games) stays
/// in order with its flow — reordering it would look like loss to its congestion control.
pub fn tx_priority(f: &[u8]) -> bool {
    if f.len() < 14 {
        return false;
    }
    match u16::from_be_bytes([f[12], f[13]]) {
        0x0806 => true, // ARP
        0x0800 if f.len() >= 34 => {
            let ihl = ((f[14] & 0x0f) as usize) * 4;
            let l4 = 14 + ihl;
            let total = u16::from_be_bytes([f[16], f[17]]) as usize;
            match f[23] {
                1 => true, // ICMP
                17 if f.len() >= l4 + 4 => {
                    let (sp, dp) = (u16::from_be_bytes([f[l4], f[l4 + 1]]), u16::from_be_bytes([f[l4 + 2], f[l4 + 3]]));
                    sp == 53 || sp == 67 || dp == 68
                }
                6 if f.len() >= l4 + 13 && ihl >= 20 => {
                    let thl = ((f[l4 + 12] >> 4) as usize) * 4;
                    total > 0 && total <= ihl + thl // no payload
                }
                _ => false,
            }
        }
        0x86dd if f.len() >= 54 => {
            let plen = u16::from_be_bytes([f[18], f[19]]) as usize;
            match f[20] {
                58 => true, // ICMPv6 (ND, RA, echo)
                17 if f.len() >= 58 => {
                    let (sp, dp) = (u16::from_be_bytes([f[54], f[55]]), u16::from_be_bytes([f[56], f[57]]));
                    sp == 53 || sp == 547 || dp == 546
                }
                6 if f.len() >= 67 => {
                    let thl = ((f[66] >> 4) as usize) * 4;
                    plen > 0 && plen <= thl
                }
                _ => false,
            }
        }
        _ => false,
    }
}

/// `[P-txprio]`: the priority class — exactly the control frames, never bulk or generic small UDP.
pub fn txprio_selftest() -> bool {
    let mut f = [0u8; 1514];
    let v4 = |f: &mut [u8; 1514], proto: u8, total: u16| {
        *f = [0; 1514];
        f[12] = 0x08; f[13] = 0x00; f[14] = 0x45;
        f[16..18].copy_from_slice(&total.to_be_bytes());
        f[23] = proto;
    };
    // DNS answer (UDP src 53)
    v4(&mut f, 17, 80); f[34..36].copy_from_slice(&53u16.to_be_bytes()); f[36..38].copy_from_slice(&40000u16.to_be_bytes());
    let dns = tx_priority(&f[..94]);
    // QUIC-sized UDP from 443: not priority
    f[34..36].copy_from_slice(&443u16.to_be_bytes());
    let quic = !tx_priority(&f[..94]);
    // pure TCP ACK (20 + 20 header, no payload) vs a 1460-byte segment
    v4(&mut f, 6, 40); f[46] = 0x50;
    let ack = tx_priority(&f[..54]);
    v4(&mut f, 6, 1500); f[46] = 0x50;
    let bulk = !tx_priority(&f[..1514]);
    // ARP, ICMP, DHCP offer (dst 68)
    f = [0; 1514]; f[12] = 0x08; f[13] = 0x06;
    let arp = tx_priority(&f[..42]);
    v4(&mut f, 1, 84);
    let icmp = tx_priority(&f[..98]);
    v4(&mut f, 17, 300); f[34..36].copy_from_slice(&67u16.to_be_bytes()); f[36..38].copy_from_slice(&68u16.to_be_bytes());
    let dhcp = tx_priority(&f[..314]);
    // IPv6: ICMPv6 yes, a big TCP segment no, a pure ACK yes
    f = [0; 1514]; f[12] = 0x86; f[13] = 0xdd; f[20] = 58; f[18..20].copy_from_slice(&32u16.to_be_bytes());
    let nd = tx_priority(&f[..86]);
    f[20] = 6; f[18..20].copy_from_slice(&1440u16.to_be_bytes()); f[66] = 0x50;
    let v6bulk = !tx_priority(&f[..1494]);
    f[18..20].copy_from_slice(&20u16.to_be_bytes());
    let v6ack = tx_priority(&f[..74]);
    let pass = dns && quic && ack && bulk && arp && icmp && dhcp && nd && v6bulk && v6ack;
    arch_aarch64::_print(format_args!(
        " [P-txprio] {} — AP TX priority class: DNS answer={} generic small UDP stays bulk={} pure TCP ACK={} full segment stays bulk={} ARP={} ICMP={} DHCP={} ICMPv6={} v6 segment bulk={} v6 ACK={}\n",
        if pass { "PASS" } else { "FAIL" }, dns, quic, ack, bulk, arp, icmp, dhcp, nd, v6bulk, v6ack));
    pass
}

/// `[P-apcore-relay]` — step 3c.
pub fn relay_selftest() -> bool {
    use arch_aarch64::dhcpd::ApDhcp;
    let mut dh = ApDhcp::new();
    let (a_mac, a_ip, b_mac, b_ip) = ([0x02u8, 0, 0, 0, 0, 0x0a], [10u8, 99, 0, 10], [0x02u8, 0, 0, 0, 0, 0x0b], [10u8, 99, 0, 11]);
    dh.now = 100;
    let ok_a = dh.alloc_for(&a_mac, &[10, 99, 0, 10]).is_some();
    dh.commit(&a_mac);
    let ok_b = dh.alloc_for(&b_mac, &[10, 99, 0, 10]).is_some();
    dh.commit(&b_mac);
    let (a_ip, b_ip) = (dh.lease_for(&a_mac).unwrap_or(a_ip), dh.lease_for(&b_mac).unwrap_or(b_ip));
    crate::devpolicy::load_text(b"");
    let sent = core::cell::Cell::new(0u32);
    let last = core::cell::RefCell::new([0u8; 64]);
    let mut send = |f: &[u8]| {
        sent.set(sent.get() + 1);
        let n = f.len().min(64);
        last.borrow_mut()[..n].copy_from_slice(&f[..n]);
        true
    };
    // ARP who-has B from A -> a proxy answer "B is at B's MAC" back to A
    let mut arp = [0u8; 42];
    arp[0..6].copy_from_slice(&[0xff; 6]);
    arp[6..12].copy_from_slice(&a_mac);
    arp[12..14].copy_from_slice(&[0x08, 0x06]);
    arp[14..22].copy_from_slice(&[0, 1, 8, 0, 6, 4, 0, 1]);
    arp[22..28].copy_from_slice(&a_mac);
    arp[28..32].copy_from_slice(&a_ip);
    arp[38..42].copy_from_slice(&b_ip);
    let proxied = station_relay(&arp, &dh, 100, &mut send) && sent.get() == 1 && last.borrow()[22..28] == b_mac && last.borrow()[0..6] == a_mac;
    // an IPv4 unicast frame is none of these branches (the routing path decides)
    let mut v4 = [0u8; 60];
    v4[12] = 0x08;
    v4[14] = 0x45;
    let not_ours = !station_relay(&v4, &dh, 100, &mut send) && sent.get() == 1;
    // mDNS from A (224.0.0.251:5353) -> a copy toward B
    let mut md = [0u8; 80];
    md[0..6].copy_from_slice(&[0x01, 0x00, 0x5e, 0x00, 0x00, 0xfb]);
    md[6..12].copy_from_slice(&a_mac);
    md[12..14].copy_from_slice(&[0x08, 0x00]);
    md[14] = 0x45;
    md[16..18].copy_from_slice(&66u16.to_be_bytes());
    md[22] = 255;
    md[23] = 17;
    md[26..30].copy_from_slice(&a_ip);
    md[30..34].copy_from_slice(&[224, 0, 0, 251]);
    md[34..36].copy_from_slice(&5353u16.to_be_bytes());
    md[36..38].copy_from_slice(&5353u16.to_be_bytes());
    md[38..40].copy_from_slice(&46u16.to_be_bytes());
    let mdns = station_relay(&md, &dh, 100, &mut send) && sent.get() >= 2;
    let pass = ok_a && ok_b && proxied && not_ours && mdns;
    arch_aarch64::_print(format_args!(
        " [P-apcore-relay] {} — G0 step 3c: station-to-station branches (G10) in apcore::station_relay: ARP for another station answered by proxy-ARP={} plain IPv4 left to the routing path={} mDNS copied to the other stations={}\n",
        if pass { "PASS" } else { "FAIL" }, proxied, not_ours, mdns
    ));
    pass
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
    // A-03 refuse-local, with the device's own addresses registered as on metal (AP = slot 0, management = slot 2):
    // DNS to the AP address is still Shield's (answered here, never refused), while a client packet to the management
    // address is refused locally (RST), never routed out. The first A-03 build refused DNS to the AP too.
    crate::ratelimit::set_local_ip(0, u32::from_be_bytes(cfg.our_ip));
    crate::ratelimit::set_local_ip(2, u32::from_be_bytes([192, 168, 200, 146]));
    let (r0, refused0) = (replies, c.to_self_refused);
    let n = frame4(17, cfg.our_ip, 53, q, &mut f);
    let ap_dns = !go!(&f[..n], If::Lan) && replies == r0 + 1 && c.to_self_refused == refused0 && nic.wan_n == w0;
    let n = frame4(6, [192, 168, 200, 146], 443, &[], &mut f);
    let mgmt_refused = !go!(&f[..n], If::Lan) && c.to_self_refused == refused0 + 1 && replies == r0 + 2 && nic.wan_n == w0;
    crate::ratelimit::set_local_ip(0, 0);
    crate::ratelimit::set_local_ip(2, 0);
    let shield = shield && ap_dns && mgmt_refused;
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
    // 9. routing review 2026-11-11: `via wan gw X` with a dead X fails over by metric instead of blackholing, and
    //    comes back once X answers ARP again
    nh_clear();
    let _ = hal::policy::parse_policy(b"HQPOL1\nroute 0.0.0.0/0 via wan gw 100.64.7.254 metric 10\nroute 0.0.0.0/0 via mgmt metric 100\n", &mut pol);
    nic.mgmt = Some(MgmtView { ip: [192, 168, 200, 146], mac: [0x02, 0x6d, 0, 0, 0, 0x46], gw: [192, 168, 200, 1], up: true });
    nic.nexthop = None;
    let (w2, m2) = (nic.wan_n, nic.mgmt_n);
    let n = frame4(6, [93, 184, 216, 34], 443, &[], &mut f);
    nic.t = 10_000;
    let miss1 = !go!(&f[..n], If::Lan);
    nic.t = 11_500;
    let miss2 = !go!(&f[..n], If::Lan) && c.nh_dead == 0;
    nic.t = 13_100; // unresolved for 3.1 s: declared dead (this packet still dropped)
    let declared = !go!(&f[..n], If::Lan) && c.nh_dead == 1;
    nic.t = 13_200; // the metric-100 route via mgmt carries it now
    let failed_over = go!(&f[..n], If::Lan) && nic.mgmt_n == m2 + 1 && nic.wan_n == w2;
    nic.nexthop = Some([0x02, 0x77, 0, 0, 0, 0xfe]);
    nic.t = 14_300; // re-probe (>= 1 s since the last): X answers -> back on the WAN via X
    let back = go!(&f[..n], If::Lan) && nic.wan_n == w2 + 1 && nic.last[0..6] == [0x02, 0x77, 0, 0, 0, 0xfe];
    let nh_ok = miss1 && miss2 && declared && failed_over && back;
    // 10. G19: a flow the signed tunnel carries, routed `via mgmt`, never leaves in cleartext out mgmt — the tunnel
    //     sends it, or (no tunnel here) it is dropped and counted
    #[cfg(feature = "securechannel")]
    let g19_ok = {
        let _ = hal::policy::parse_policy(b"HQPOL1\nroute 203.0.113.0/24 via mgmt\nroute 0.0.0.0/0 via wan\n", &mut pol);
        unsafe { TEST_CARRY = Some([203, 0, 113, 7]) };
        let (m3, w3, pv) = (nic.mgmt_n, nic.wan_n, c.pol_via_mgmt);
        let n = frame4(6, [203, 0, 113, 7], 443, &[], &mut f);
        let r = !go!(&f[..n], If::Lan) && nic.mgmt_n == m3 && nic.wan_n == w3 && c.g19_over_mgmt_route == 1 && c.pol_via_mgmt == pv;
        unsafe { TEST_CARRY = None };
        r
    };
    #[cfg(not(feature = "securechannel"))]
    let g19_ok = true;
    nic.mgmt = None;
    nh_clear();
    pol = Policy::new();
    let pass = snat && unresolved && txfail && block && drop && mg_down && via_mgmt && failover && shield && clean && quarantined && nh_ok && g19_ok;
    arch_aarch64::_print(format_args!(
        " [P-apcore] {} — G0 step 1: the AP's client IPv4 forwarding ladder (was the cm5-only fwd4! macro) on a recording fake NIC: SNAT to the WAN lease via the gateway={} unresolved next hop -> nothing sent={} WAN tx failure counted={} `lan in` block -> reject to the client, counted={} drop counted, silent={} mgmt gateway down -> default via WAN={} then SNATs to the mgmt address={} WAN down -> metric failover to mgmt={} Shield answers a blocked name locally (also to the AP address, while a client packet to the management address is refused locally, A-03)={} clean DNS forwarded={} quarantined device never forwarded, not an ACL drop={} | a dead `via wan gw X` (3 s without ARP) fails over by metric and returns when X answers={} a G19-carried flow routed via mgmt never leaves in cleartext on mgmt={}\n",
        if pass { "PASS" } else { "FAIL" }, snat, unresolved, txfail, block, drop, mg_down, via_mgmt, failover, shield, clean, quarantined, nh_ok, g19_ok
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

// ---------------------------------------------------------------------------------------------------------------
// G0 step 5c: the AP loop's small timing state machines (were inline locals in the loop). The hardware diagnostics
// they trigger (firmware counters, bus clock, sta_info) stay in the loop; these decide only WHEN.

/// The SDPCM wedge detector: deliveries are waiting for TX credit and no Wi-Fi frame has been read for 10 s.
#[derive(Clone, Copy, Debug, Default)]
pub struct WedgeWatch {
    frames: u64,
    since: u64,
    reported: bool,
}

impl WedgeWatch {
    /// One loop iteration. True once per episode (the loop logs it; wifiheal does the escalation). A frame read
    /// re-arms it.
    pub fn step(&mut self, now: u64, freq: u64, queued: usize, wifi_frames: u64) -> bool {
        if queued > 0 && wifi_frames == self.frames && now.wrapping_sub(self.since) > 10 * freq {
            if !self.reported {
                self.reported = true;
                return true;
            }
        } else if wifi_frames != self.frames {
            self.frames = wifi_frames;
            self.since = now;
            self.reported = false;
        }
        false
    }
}

/// What one `CreditEpisode::step` asks the loop to do or log.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CreditEv {
    None,
    /// Credit has been exhausted for > 2 s with deliveries queued: take the one diagnostic snapshot of this episode.
    Snapshot,
    /// Credit came back after a wifiheal kick (stage 2 = the control frame), `ms` after the episode began.
    Unstuck { ms: u64, stage: u8 },
    /// Credit came back after the snapshot was taken.
    Recovered { ms: u64 },
}

/// The TX-credit stall episode (credit <= 2 with deliveries queued) and its counters:
/// `unstick` = [episodes kicked, recovered by itself (> 250 ms), after stage 1 (DEV_INT, unused), after the kick, reached 2 s].
#[derive(Clone, Copy, Debug, Default)]
pub struct CreditEpisode {
    since: u64,
    diag_done: bool,
    stage: u8,
    pub unstick: [u32; 5],
}

impl CreditEpisode {
    /// One loop iteration. `credit_low` = tx_max - tx_seq <= 2; `queued` = deliveries waiting; `kicked` = wifiheal
    /// issued its Kick this iteration.
    pub fn step(&mut self, t: u64, freq: u64, credit_low: bool, queued: bool, kicked: bool) -> CreditEv {
        if credit_low && queued {
            if self.since == 0 {
                self.since = t;
                self.stage = 0;
            } else if kicked {
                if self.stage == 0 {
                    self.unstick[0] += 1;
                    self.stage = 2;
                }
            } else if !self.diag_done && t.wrapping_sub(self.since) > 2 * freq {
                self.unstick[4] += 1;
                self.diag_done = true;
                return CreditEv::Snapshot;
            }
            return CreditEv::None;
        }
        let ms = t.wrapping_sub(self.since) * 1000 / freq.max(1);
        let mut ev = CreditEv::None;
        if self.since != 0 && !self.diag_done && self.stage > 0 {
            self.unstick[self.stage as usize + 1] += 1;
            ev = CreditEv::Unstuck { ms, stage: self.stage };
        } else if self.since != 0 && !self.diag_done && t.wrapping_sub(self.since) > freq / 4 {
            self.unstick[1] += 1;
        }
        self.stage = 0;
        if self.diag_done && self.since != 0 {
            ev = CreditEv::Recovered { ms };
        }
        self.since = 0;
        self.diag_done = false;
        ev
    }
}

/// Parity G16 probe scheduling: one ICMP echo per beat, alternating the gateway and an internet anchor
/// (`WanHealth::target`). A probe still unanswered at the next beat is a failure.
#[derive(Clone, Copy, Debug, Default)]
pub struct WanProbe {
    slot: u32,
    out: Option<(u16, bool)>,
    sent_at: u64,
}

impl WanProbe {
    /// The beat: report the previous probe as failed if it was not answered, then send the next one when the WAN has
    /// a lease and a resolved gateway. Returns `(state change, internet)` of the failure report, if any.
    pub fn beat(&mut self, wh: &mut crate::wanhealth::WanHealth, usable: bool, wan: &WanView, gw_ip: [u8; 4], now: u64,
        tx: &mut dyn FnMut(&[u8]) -> bool) -> Option<(crate::wanhealth::State, bool)> {
        let mut change = None;
        if let Some((_, internet)) = self.out.take() {
            change = wh.report(internet, false, 0).map(|s| (s, internet));
        }
        if usable && wan.gw_mac != [0u8; 6] {
            let (dst, internet) = crate::wanhealth::WanHealth::target(self.slot, gw_ip);
            let mut pf = [0u8; 64];
            let k = crate::wanhealth::echo_request(&mut pf, &wan.mac, &wan.gw_mac, wan.ip, dst, self.slot as u16);
            if tx(&pf[..k]) {
                self.out = Some((self.slot as u16, internet));
                self.sent_at = now;
            }
            self.slot = self.slot.wrapping_add(1);
        }
        change
    }

    /// A WAN frame: if it answers the outstanding probe, report it. Returns `Some((state change, internet, rtt ms))`
    /// when it was our probe's reply (whether or not the state changed), None otherwise.
    pub fn on_frame(&mut self, f: &[u8], wan_ip: [u8; 4], wh: &mut crate::wanhealth::WanHealth, now: u64, freq: u64)
        -> Option<(Option<crate::wanhealth::State>, bool, u16)> {
        let seq = crate::wanhealth::probe_reply(f, wan_ip)?;
        let (_, internet) = self.out.filter(|w| w.0 == seq)?;
        let rtt = (now.wrapping_sub(self.sent_at) / (freq / 1000).max(1)).min(u16::MAX as u64) as u16;
        self.out = None;
        Some((wh.report(internet, true, rtt), internet, rtt))
    }

    /// Whether a frame is a probe reply at all (answered or stale); the loop consumes those.
    pub fn is_reply(f: &[u8], wan_ip: [u8; 4]) -> bool {
        crate::wanhealth::probe_reply(f, wan_ip).is_some()
    }
}

/// `[P-apcore-timers]` (G0 step 5c).
pub fn timers_selftest() -> bool {
    let f = 1000u64;
    // the wedge detector: once per episode, re-armed by a frame read, never with nothing queued
    let mut w = WedgeWatch::default();
    let w1 = !w.step(100, f, 3, 5) && !w.step(5_000, f, 3, 5) && w.step(10_200, f, 3, 5) && !w.step(11_000, f, 3, 5);
    let w2 = !w.step(12_000, f, 3, 6) && !w.step(21_900, f, 3, 6) && w.step(22_100, f, 3, 6);
    let w3 = { let mut e = WedgeWatch::default(); !e.step(100, f, 0, 5) && !e.step(60_000, f, 0, 5) };
    let wedge = w1 && w2 && w3;
    // the credit episode
    let mut c = CreditEpisode::default();
    let c1 = c.step(1_000, f, true, true, false) == CreditEv::None && c.step(3_100, f, true, true, false) == CreditEv::Snapshot
        && c.step(3_200, f, true, true, false) == CreditEv::None && c.step(3_500, f, false, true, false) == CreditEv::Recovered { ms: 2_500 }
        && c.unstick[4] == 1;
    let c2 = c.step(5_000, f, true, true, false) == CreditEv::None && c.step(5_100, f, true, true, true) == CreditEv::None
        && c.unstick[0] == 1 && c.step(5_300, f, true, false, false) == CreditEv::Unstuck { ms: 300, stage: 2 } && c.unstick[3] == 1;
    let c3 = c.step(6_000, f, true, true, false) == CreditEv::None && c.step(6_400, f, false, true, false) == CreditEv::None && c.unstick[1] == 1
        && c.step(7_000, f, true, true, false) == CreditEv::None && c.step(7_100, f, false, true, false) == CreditEv::None && c.unstick[1] == 1;
    let credit = c1 && c2 && c3;
    // WAN-health probes: gateway then anchor, reply matched by seq and timed, an unanswered probe fails at the next beat
    let wan = WanView { ip: [100, 64, 7, 9], mac: [0x02, 0x77, 0, 0, 0, 0x09], gw_mac: [0x02, 0x77, 0, 0, 0, 0x01], dns: [1, 1, 1, 1] };
    let gw = [100, 64, 7, 1];
    let mut wh = crate::wanhealth::WanHealth::new();
    let mut p = WanProbe::default();
    let mut sent = 0u32;
    let mut last = [0u8; 64];
    macro_rules! beat {
        ($usable:expr, $w:expr, $t:expr) => {{
            let mut tx = |fr: &[u8]| { sent += 1; last[..fr.len()].copy_from_slice(fr); true };
            p.beat(&mut wh, $usable, $w, gw, $t, &mut tx)
        }};
    }
    let p1 = beat!(true, &wan, 10_000).is_none();
    let to_gw = last[30..34] == gw && last[0..6] == wan.gw_mac && last[26..30] == wan.ip;
    let mut reply = last;
    reply[34] = 0;
    reply[26..30].copy_from_slice(&gw);
    reply[30..34].copy_from_slice(&wan.ip);
    let mut stale = reply;
    stale[41] ^= 1; // another seq
    let p2 = p.on_frame(&stale, wan.ip, &mut wh, 10_040, f).is_none() && WanProbe::is_reply(&stale, wan.ip);
    let p3 = matches!(p.on_frame(&reply, wan.ip, &mut wh, 10_040, f), Some((_, false, 40))) && wh.probes == 1;
    let p4 = p.on_frame(&reply, wan.ip, &mut wh, 10_050, f).is_none() && wh.probes == 1; // answered once only
    let _ = beat!(true, &wan, 15_000);
    let to_anchor = last[30..34] == crate::wanhealth::ANCHORS[0];
    let _ = beat!(false, &wan, 20_000); // unanswered -> a failure; not usable -> nothing sent
    let p5 = wh.probes == 2 && sent == 2;
    let nogw = WanView { gw_mac: [0; 6], ..wan };
    let _ = beat!(true, &nogw, 25_000);
    let p6 = sent == 2 && wh.probes == 2; // no gateway MAC: nothing sent, nothing outstanding to fail
    let probe = p1 && to_gw && p2 && p3 && p4 && to_anchor && p5 && p6;
    let pass = wedge && credit && probe;
    arch_aarch64::_print(format_args!(
        " [P-apcore-timers] {} — G0 step 5c: the Wi-Fi wedge detector fires once per 10 s episode, re-armed by a frame read, never with nothing queued={} the TX-credit episode (snapshot at 2 s, recovered, kick -> unstuck, self-recovery counted, a < 250 ms blip not)={} WAN-health probes (gateway first, reply matched by seq + timed 40 ms, stale/duplicate ignored, anchor next, unanswered = failure at the next beat, nothing sent without a lease or gateway MAC)={}\n",
        if pass { "PASS" } else { "FAIL" }, wedge, credit, probe
    ));
    pass
}
