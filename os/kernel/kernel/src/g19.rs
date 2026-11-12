//! G19 — the SASE tunnel to the operator's super-PoP (device side). Wire format v1, mirrored from the PoP's
//! authoritative spec (`onboarding/enrollment/superpop/README.md`):
//!
//! * handshake: the existing PQ-hybrid Noise IK (`controlplane`, chunked msg1/msg2) sent UNICAST to `<pop>:7654`
//!   through the WAN gateway; msg1 payload = sha256(device pk), msg2 payload = tenant;
//! * data: UDP 7655, datagram = `"HQT1" ‖ sid(8) ‖ LE64 seq ‖ ciphertext ‖ tag16` (`seal_record` /
//!   `AntiReplayRx::open_record`, RFC 6479 window), AD = `"HQT1" ‖ sid`,
//!   sid = SHA-256("HQ-G19-sid-v1" ‖ handshake_hash)[0..8];
//! * record plaintext = type ‖ body: DATA (one IPv4 packet), KEEPALIVE, ASSIGN (inner_v4 ‖ plen ‖ dns_v4 ‖ mtu LE16),
//!   ADDR_REQ, CLOSE (reason), CAPS (flags; W4: bit 0 = "I follow in-session rekey epochs").
//! * W4 in-session rekey (`securechannel::RecordTx`/`RecordRx`): the seq's high 32 bits are the key epoch; each
//!   side sends CAPS and starts rekeying its own direction only after the PEER's CAPS arrived (an older PoP
//!   ignores CAPS and is never rekeyed at); both sides always follow a peer's epochs.
//!
//! Device duties: ADDR_REQ right after the handshake; NAT the tunnelled LAN flows to the ASSIGNed inner /32 (the
//! existing NAT engine, with the inner address as its "WAN" address); clamp TCP MSS to mtu - 40; KEEPALIVE when
//! idle 15 s; re-handshake after 45 s with nothing heard (the PoP echoes KEEPALIVE) and every 24 h. Standalone
//! by default: no `tunnel` line in the signed POLICY.TXT (or no pinned PoP key in the image) = no tunnel.
#![cfg(feature = "securechannel")]

use crate::securechannel::{RecordRx, RecordTx, RekeyPolicy, Session};

pub const HS_PORT: u16 = 7654;
pub const DATA_PORT: u16 = 7655;
pub const T_DATA: u8 = 0x01;
pub const T_KEEPALIVE: u8 = 0x02;
pub const T_ASSIGN: u8 = 0x03;
pub const T_ADDR_REQ: u8 = 0x04;
pub const T_CLOSE: u8 = 0x05;
/// W4: capability flags (body = 1 byte). Unknown to an older peer, which drops it.
pub const T_CAPS: u8 = 0x06;
pub const CAPS_REKEY: u8 = 0x01;
const MAGIC: &[u8; 4] = b"HQT1";
/// Bytes a sealed record adds around the plaintext: magic + sid + seq + tag.
pub const OVERHEAD: usize = 4 + 8 + 8 + 16;
pub const KEEPALIVE_IDLE_MS: i64 = 15_000;
pub const SILENCE_REHANDSHAKE_MS: i64 = 45_000;
pub const SESSION_MAX_MS: i64 = 24 * 3600 * 1000;

pub fn sid_of(handshake_hash: &[u8; 32]) -> [u8; 8] {
    let mut h = boot_abi::sha256::Hasher::new();
    h.update(b"HQ-G19-sid-v1");
    h.update(handshake_hash);
    let d = h.finish();
    let mut s = [0u8; 8];
    s.copy_from_slice(&d[..8]);
    s
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Assign {
    pub inner: [u8; 4],
    pub plen: u8,
    pub dns: [u8; 4],
    pub mtu: u16,
}

pub fn parse_assign(body: &[u8]) -> Option<Assign> {
    if body.len() != 11 {
        return None;
    }
    let a = Assign { inner: [body[0], body[1], body[2], body[3]], plen: body[4], dns: [body[5], body[6], body[7], body[8]], mtu: u16::from_le_bytes([body[9], body[10]]) };
    // any UNICAST inner address the PoP's pool uses (the bench PoP: 198.18.0.0/15 — 100.64/10 would shadow an ISP's
    // CGNAT space), never 0/8, loopback, multicast / reserved or broadcast; a sane prefix and MTU
    let unicast = a.inner[0] != 0 && a.inner[0] != 127 && a.inner[0] < 224;
    (unicast && (1..=32).contains(&a.plen) && (576..=1500).contains(&a.mtu)).then_some(a)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Act {
    None,
    SendKeepalive,
    Rehandshake,
}

#[derive(Clone, Copy, Default)]
pub struct Stats {
    pub tx_data: u32,
    pub rx_data: u32,
    pub rx_bad: u32,
    pub keepalives: u32,
    pub rehandshakes: u32,
    /// W4: records refused because their key epoch is no longer held (rollback / retired key)
    pub rx_stale: u32,
}

/// One established tunnel session (the transport keys of the Noise handshake).
pub struct Tunnel {
    tx: RecordTx,
    rx: RecordRx,
    pub sid: [u8; 8],
    pub assign: Option<Assign>,
    last_rx_ms: i64,
    last_tx_ms: i64,
    since_ms: i64,
    pub stats: Stats,
}

impl Tunnel {
    pub fn new(sess: Session, now_ms: i64) -> Tunnel {
        Self::with_policy(sess, now_ms, RekeyPolicy::DEFAULT)
    }

    /// The session's keys move into the rekeying record layer; the Session's own copies are wiped.
    pub fn with_policy(mut sess: Session, now_ms: i64, pol: RekeyPolicy) -> Tunnel {
        let sid = sid_of(&sess.handshake_hash);
        let rx = sess.recv.into_record_rx();
        let tx = RecordTx::new(sess.send.clone(), now_ms, pol);
        sess.wipe();
        Tunnel { tx, rx, sid, assign: None, last_rx_ms: now_ms, last_tx_ms: now_ms, since_ms: now_ms, stats: Stats::default() }
    }

    /// (tx epoch, rx epoch, the peer follows rekeys) — epochs and the next sequence are logged, never keys.
    pub fn epochs(&self) -> (u32, u32, bool, u64) {
        (self.tx.epoch(), self.rx.epoch(), self.tx.armed(), self.tx.next_seq())
    }

    fn ad(&self) -> [u8; 12] {
        let mut ad = [0u8; 12];
        ad[..4].copy_from_slice(MAGIC);
        ad[4..].copy_from_slice(&self.sid);
        ad
    }

    /// Seal `type ‖ body` into a data datagram payload (`"HQT1" ‖ sid ‖ seq ‖ ct ‖ tag`).
    pub fn seal(&mut self, ty: u8, body: &[u8], out: &mut [u8], now_ms: i64) -> Option<usize> {
        let mut pt = [0u8; 1600];
        if 1 + body.len() > pt.len() || out.len() < OVERHEAD + 1 + body.len() {
            return None;
        }
        pt[0] = ty;
        pt[1..1 + body.len()].copy_from_slice(body);
        let ad = self.ad();
        out[..4].copy_from_slice(MAGIC);
        out[4..12].copy_from_slice(&self.sid);
        let n = self.tx.seal(&ad, &pt[..1 + body.len()], &mut out[12..], now_ms)?;
        self.last_tx_ms = now_ms;
        if ty == T_DATA {
            self.stats.tx_data += 1;
        }
        Some(12 + n)
    }

    /// Open a data datagram payload: authenticated + inside the replay window -> (type, body length in `out`).
    /// A forgery, a replay or another session's record -> None (counted), and nothing changes.
    pub fn open(&mut self, dg: &[u8], out: &mut [u8], now_ms: i64) -> Option<(u8, usize)> {
        if dg.len() < OVERHEAD + 1 || &dg[..4] != MAGIC || dg[4..12] != self.sid {
            self.stats.rx_bad += 1;
            return None;
        }
        let ad = self.ad();
        let mut pt = [0u8; 1600];
        let n = match self.rx.open(&ad, &dg[12..], &mut pt, now_ms) {
            Ok(n) if n >= 1 && n - 1 <= out.len() => n,
            r => {
                self.stats.rx_bad += 1;
                if r == Err(crate::securechannel::NoiseErr::Stale) {
                    self.stats.rx_stale += 1;
                }
                return None;
            }
        };
        self.last_rx_ms = now_ms;
        let ty = pt[0];
        out[..n - 1].copy_from_slice(&pt[1..n]);
        match ty {
            T_ASSIGN => self.assign = parse_assign(&pt[1..n]).or(self.assign),
            T_DATA => self.stats.rx_data += 1,
            T_CAPS if n == 2 && pt[1] & CAPS_REKEY != 0 => self.tx.arm(),
            _ => {}
        }
        Some((ty, n - 1))
    }

    /// Timers: KEEPALIVE after 15 s without sending; re-handshake after 45 s without hearing anything, or at 24 h.
    pub fn tick(&mut self, now_ms: i64) -> Act {
        self.rx.tick(now_ms); // retire the previous epoch's key after its grace window
        if now_ms - self.last_rx_ms >= SILENCE_REHANDSHAKE_MS || now_ms - self.since_ms >= SESSION_MAX_MS || self.tx.exhausted() {
            self.stats.rehandshakes += 1;
            return Act::Rehandshake;
        }
        if now_ms - self.last_tx_ms >= KEEPALIVE_IDLE_MS {
            self.stats.keepalives += 1;
            return Act::SendKeepalive;
        }
        Act::None
    }

    /// Overwrite the transport keys before the tunnel is dropped (re-handshake / shutdown).
    pub fn wipe(&mut self) {
        self.tx.wipe();
        self.rx.wipe();
    }
}

/// Clamp the TCP MSS option of an outgoing SYN (IPv4 packet, no Ethernet header) to `mss`, fixing the TCP
/// checksum incrementally (RFC 1624). Returns true when it changed the packet.
pub fn clamp_mss(pkt: &mut [u8], mss: u16) -> bool {
    if pkt.len() < 40 || pkt[0] >> 4 != 4 || pkt[9] != 6 {
        return false;
    }
    let ihl = ((pkt[0] & 0x0f) as usize) * 4;
    if pkt.len() < ihl + 20 || pkt[ihl + 13] & 0x02 == 0 {
        return false; // not a SYN
    }
    let thl = ((pkt[ihl + 12] >> 4) as usize) * 4;
    let end = (ihl + thl).min(pkt.len());
    let mut o = ihl + 20;
    while o + 1 < end {
        match pkt[o] {
            0 => break,
            1 => o += 1,
            2 if o + 4 <= end && pkt[o + 1] == 4 => {
                let old = u16::from_be_bytes([pkt[o + 2], pkt[o + 3]]);
                if old <= mss {
                    return false;
                }
                pkt[o + 2..o + 4].copy_from_slice(&mss.to_be_bytes());
                // checksum: ~(~C + ~old + new) (RFC 1624 eq. 3)
                let c = u16::from_be_bytes([pkt[ihl + 16], pkt[ihl + 17]]);
                let mut s = (!c as u32) + (!old as u32 & 0xffff) + mss as u32;
                while s > 0xffff {
                    s = (s & 0xffff) + (s >> 16);
                }
                pkt[ihl + 16..ihl + 18].copy_from_slice(&(!(s as u16)).to_be_bytes());
                return true;
            }
            _ => {
                let l = pkt[o + 1] as usize;
                if l < 2 {
                    break;
                }
                o += l;
            }
        }
    }
    false
}

// ---- runtime (stage 2): one tunnel per device, driven from the AP loop ----------------------------------------

include!(concat!(env!("OUT_DIR"), "/pop_key.rs"));

use crate::controlplane::ControlPlane;

struct Rt {
    cfg: Option<hal::policy::Tunnel>,
    cp_set: bool,
    tun_set: bool,
    wan_ip: [u8; 4],
    wan_mac: [u8; 6],
    gw_mac: [u8; 6],
    handshakes: u32,
    /// the key epochs last logged (tx, rx)
    logged: (u32, u32),
}
static mut RT: Rt = Rt { cfg: None, cp_set: false, tun_set: false, wan_ip: [0; 4], wan_mac: [0; 6], gw_mac: [0; 6], handshakes: 0, logged: (0, 0) };
// Large state lives in zero-initialised statics (.bss, no image bytes); the *_set flags say when it is valid.
static mut CP: core::mem::MaybeUninit<ControlPlane> = core::mem::MaybeUninit::zeroed();
static mut TUN: core::mem::MaybeUninit<Tunnel> = core::mem::MaybeUninit::zeroed();

fn rt() -> &'static mut Rt {
    unsafe { &mut *core::ptr::addr_of_mut!(RT) }
}
fn cp() -> Option<&'static mut ControlPlane> {
    rt().cp_set.then(|| unsafe { (*core::ptr::addr_of_mut!(CP)).assume_init_mut() })
}
fn tun() -> Option<&'static mut Tunnel> {
    rt().tun_set.then(|| unsafe { (*core::ptr::addr_of_mut!(TUN)).assume_init_mut() })
}
fn drop_tun() {
    if let Some(t) = tun() {
        t.wipe();
    }
    rt().tun_set = false;
}

/// Boot: the signed POLICY.TXT `tunnel` line (or none). Returns whether the tunnel will run on this image.
pub fn configure(cfg: Option<hal::policy::Tunnel>) -> bool {
    rt().cfg = cfg;
    enabled()
}
/// A `tunnel` line AND a pinned PoP key: otherwise no tunnel (standalone by default).
pub fn enabled() -> bool {
    rt().cfg.is_some() && POP_PUB.is_some()
}

/// The tunnel is up (handshake done, ASSIGN received) and the signed policy sends `dst` through it.
pub fn carries(dst: [u8; 4]) -> bool {
    match (rt().cfg, tun()) {
        (Some(c), Some(t)) => t.assign.is_some() && c.carries(dst) && dst != c.pop,
        _ => false,
    }
}

/// Every loop iteration (cheap when idle): (re)create the control plane for the current WAN address, drive the
/// handshake, adopt the session, keepalive / re-handshake. `tx` sends a WAN frame.
pub fn tick(now_ms: i64, wan_up: bool, wan_ip: [u8; 4], wan_mac: [u8; 6], gw_mac: [u8; 6], dev_kp: &dyn Fn() -> Option<ed25519_compact::KeyPair>, fresh: &mut dyn FnMut() -> Option<crate::securechannel::InitiatorRandomness>, tx: &mut dyn FnMut(&[u8]) -> bool) {
    let Some(cfg) = rt().cfg else { return };
    let Some(blob) = POP_PUB else { return };
    if !wan_up || wan_ip == [0; 4] || gw_mac == [0; 6] {
        return;
    }
    let r = rt();
    if !r.cp_set || r.wan_ip != wan_ip || r.gw_mac != gw_mac {
        // a new WAN address / gateway: start from scratch (the PoP rebinds the data endpoint anyway)
        drop_tun();
        let mut xpk = [0u8; 32];
        xpk.copy_from_slice(&blob[..32]);
        let (Some(rp), Some(kp)) = (crate::securechannel::ResponderPub::from_provisioned(xpk, &blob[32..]), dev_kp()) else { return };
        let mut c = ControlPlane::new(rp, kp, wan_mac, wan_ip);
        c.set_unicast(gw_mac, cfg.pop);
        unsafe { (*core::ptr::addr_of_mut!(CP)).write(c) };
        r.cp_set = true;
        r.wan_ip = wan_ip;
        r.wan_mac = wan_mac;
        r.gw_mac = gw_mac;
    }
    let Some(c) = cp() else { return };
    if !rt().tun_set {
        c.tick(now_ms, true, fresh);
        while let Some((dg, n)) = c.poll_egress() {
            let _ = tx(&dg[..n]);
        }
        if c.established() {
            if let Some(sess) = c.take_session() {
                unsafe { (*core::ptr::addr_of_mut!(TUN)).write(Tunnel::new(sess, now_ms)) };
                rt().tun_set = true;
                rt().handshakes += 1;
                arch_aarch64::_print(format_args!(" [G19] tunnel to the super-PoP {}.{}.{}.{} up (handshake #{}) — asking for an inner address\n",
                    cfg.pop[0], cfg.pop[1], cfg.pop[2], cfg.pop[3], rt().handshakes));
                rt().logged = (0, 0);
                send_ctl(T_ADDR_REQ, &[], now_ms, tx);
                send_ctl(T_CAPS, &[CAPS_REKEY], now_ms, tx);
            }
        }
        return;
    }
    if let Some(t) = tun() {
        // W4: log key-epoch transitions (epoch numbers + the next sequence; never key material)
        let (te, re, armed, seq) = t.epochs();
        if (te, re) != rt().logged {
            arch_aarch64::_print(format_args!(" [G19] rekey: tx epoch {} rx epoch {} (peer follows rekeys={}, next tx seq {:#x}, stale refused {})\n", te, re, armed, seq, t.stats.rx_stale));
            rt().logged = (te, re);
        }
    }
    let act = tun().map_or(Act::None, |t| t.tick(now_ms));
    match act {
        Act::SendKeepalive => {
            send_ctl(T_KEEPALIVE, &[], now_ms, tx);
            if tun().is_some_and(|t| !t.epochs().2) {
                send_ctl(T_CAPS, &[CAPS_REKEY], now_ms, tx); // the PoP's CAPS not seen yet: offer again
            }
        }
        Act::Rehandshake => {
            arch_aarch64::_print(format_args!(" [G19] nothing heard from the PoP for 45 s (or 24 h elapsed) — re-handshake\n"));
            drop_tun();
            c.restart(now_ms);
        }
        Act::None => {
            if tun().is_some_and(|t| t.assign.is_none() && t.last_tx_ms + 2_000 < now_ms) {
                send_ctl(T_ADDR_REQ, &[], now_ms, tx); // ASSIGN lost: ask again
            }
        }
    }
}

fn send_ctl(ty: u8, body: &[u8], now_ms: i64, tx: &mut dyn FnMut(&[u8]) -> bool) {
    let (Some(cfg), Some(t)) = (rt().cfg, tun()) else { return };
    let mut pl = [0u8; 64];
    let Some(k) = t.seal(ty, body, &mut pl, now_ms) else { return };
    let r = rt();
    let mut f = [0u8; 160];
    let n = crate::netsvc::build_hs_datagram(r.wan_mac, r.wan_ip, r.gw_mac, cfg.pop, DATA_PORT, &pl[..k], &mut f);
    if n > 0 {
        let _ = tx(&f[..n]);
    }
}

/// Outbound: a LAN client frame (Ethernet/IPv4) the policy tunnels. NAT it to the inner /32 (the shared NAT engine),
/// clamp MSS to the tunnel MTU, seal it as DATA and send it to the PoP. False = not sent (the caller counts it).
pub fn send(frame: &[u8], nif: u8, inside_net: &[u8; 3], nst: &mut arch_aarch64::nat::NatStats, ticks: u64, now_ms: i64, tx: &mut dyn FnMut(&[u8]) -> bool) -> bool {
    let (Some(cfg), Some(t)) = (rt().cfg, tun()) else { return false };
    let Some(a) = t.assign else { return false };
    let r = rt();
    let mut nb = [0u8; 1600];
    let Some(k) = arch_aarch64::nat::outbound_redirect(frame, nif, inside_net, None, &a.inner, &r.wan_mac, &r.gw_mac, &mut nb, ticks, nst) else { return false };
    if k <= 14 || k - 14 + 1 + OVERHEAD + 42 > 1600 {
        return false;
    }
    let _ = clamp_mss(&mut nb[14..k], a.mtu.saturating_sub(40));
    let mut pl = [0u8; 1600];
    let Some(m) = t.seal(T_DATA, &nb[14..k], &mut pl, now_ms) else { return false };
    let mut f = [0u8; 1700];
    let n = crate::netsvc::build_hs_datagram(r.wan_mac, r.wan_ip, r.gw_mac, cfg.pop, DATA_PORT, &pl[..m], &mut f);
    n > 0 && tx(&f[..n])
}

/// A WAN frame for the tunnel (handshake on 7654 or data on 7655 from the PoP)?
pub fn wan_wants(f: &[u8]) -> bool {
    let Some(cfg) = rt().cfg else { return false };
    if !rt().cp_set || f.len() < 42 || f[12] != 0x08 || f[13] != 0x00 || f[23] != 17 || f[26..30] != cfg.pop {
        return false;
    }
    crate::netsvc::udp_payload_for_port(f, HS_PORT).is_some() || crate::netsvc::udp_payload_for_port(f, DATA_PORT).is_some()
}

/// Consume a `wan_wants` frame in `buf[..n]`. A DATA packet for us comes back REWRITTEN IN PLACE as an ordinary
/// WAN frame (dst = the real WAN address, checksums fixed): the caller runs it through the usual WAN path (hold,
/// IDS, un-NAT, `lan out`, Shield, delivery). Returns its length; None = consumed (handshake, control, refused).
pub fn wan_ingress(buf: &mut [u8], n: usize, now_ms: i64) -> Option<usize> {
    if let Some(c) = cp() {
        if crate::netsvc::udp_payload_for_port(&buf[..n], HS_PORT).is_some() {
            c.ingress(&buf[..n], now_ms);
            return None;
        }
    }
    let t = tun()?;
    let pl = crate::netsvc::udp_payload_for_port(&buf[..n], DATA_PORT)?;
    let mut tmp = [0u8; 1700];
    let pl_len = pl.len().min(tmp.len());
    tmp[..pl_len].copy_from_slice(&pl[..pl_len]);
    let mut pkt = [0u8; 1600];
    let (ty, len) = t.open(&tmp[..pl_len], &mut pkt, now_ms)?;
    match ty {
        T_DATA => {
            let a = t.assign?;
            if len < 20 || pkt[0] >> 4 != 4 || pkt[16..20] != a.inner || 14 + len > buf.len() {
                return None;
            }
            let r = rt();
            readdress_dst(&mut pkt[..len], r.wan_ip);
            buf[..6].copy_from_slice(&r.wan_mac);
            buf[6..12].copy_from_slice(&r.gw_mac);
            buf[12] = 0x08;
            buf[13] = 0x00;
            buf[14..14 + len].copy_from_slice(&pkt[..len]);
            Some(14 + len)
        }
        T_ASSIGN => {
            if let Some(a) = t.assign {
                arch_aarch64::_print(format_args!(" [G19] inner address {}.{}.{}.{}/{} mtu {} — tunnelled traffic now flows\n", a.inner[0], a.inner[1], a.inner[2], a.inner[3], a.plen, a.mtu));
            }
            None
        }
        T_CLOSE => {
            arch_aarch64::_print(format_args!(" [G19] the PoP closed the tunnel — re-handshake\n"));
            drop_tun();
            if let Some(c) = cp() {
                c.restart(now_ms + 5_000);
            }
            None
        }
        _ => None, // KEEPALIVE echo / ADDR_REQ / CAPS (handled in `open`): liveness only
    }
}

/// Rewrite an IPv4 packet's destination address, fixing the header checksum and the TCP / UDP checksum (RFC 1624).
pub fn readdress_dst(pkt: &mut [u8], new: [u8; 4]) {
    if pkt.len() < 20 {
        return;
    }
    let old = [pkt[16], pkt[17], pkt[18], pkt[19]];
    pkt[16..20].copy_from_slice(&new);
    pkt[10] = 0;
    pkt[11] = 0;
    let ihl = ((pkt[0] & 0x0f) as usize) * 4;
    let mut s: u32 = 0;
    for k in (0..ihl.min(pkt.len())).step_by(2) {
        s += u16::from_be_bytes([pkt[k], pkt[k + 1]]) as u32;
    }
    while s > 0xffff {
        s = (s & 0xffff) + (s >> 16);
    }
    pkt[10..12].copy_from_slice(&(!(s as u16)).to_be_bytes());
    let off = match pkt[9] {
        6 => 16,
        17 => 6,
        _ => return, // ICMP has no pseudo-header
    };
    let c = ihl + off;
    if pkt.len() < c + 2 || (pkt[9] == 17 && pkt[c] == 0 && pkt[c + 1] == 0) {
        return; // UDP without a checksum stays without one
    }
    let mut x = (!u16::from_be_bytes([pkt[c], pkt[c + 1]])) as u32;
    for i in [0usize, 2] {
        x += (!u16::from_be_bytes([old[i], old[i + 1]])) as u32 & 0xffff;
        x += u16::from_be_bytes([new[i], new[i + 1]]) as u32;
    }
    while x > 0xffff {
        x = (x & 0xffff) + (x >> 16);
    }
    pkt[c..c + 2].copy_from_slice(&(!(x as u16)).to_be_bytes());
}

/// Heartbeat / health: (configured, PoP key pinned, up, inner address, data tx, data rx, refused, handshakes).
pub fn status() -> (bool, bool, bool, Option<Assign>, Stats, u32) {
    let up = tun().is_some();
    (rt().cfg.is_some(), POP_PUB.is_some(), up, tun().and_then(|t| t.assign), tun().map(|t| t.stats).unwrap_or_default(), rt().handshakes)
}

/// `[P-g19]` — a real Noise handshake (shared test vectors) gives both ends a session; the device-side tunnel
/// framing interoperates with a PoP built from the responder's session: ADDR_REQ / ASSIGN, DATA both ways,
/// replay + forgery + foreign-sid refused, keepalive / re-handshake timers, the ASSIGN sanity bounds, MSS clamp.
#[cfg(feature = "securechannel-selftest")]
pub fn selftest() -> bool {
    use crate::securechannel::{initiator_read_msg2, initiator_write_msg1, responder_read_msg1, responder_write_msg2};
    let tv = crate::securechannel::test_vectors();
    let fp = boot_abi::sha256::digest(&tv.dev.pk[..]);
    let Some((m1, ipend)) = initiator_write_msg1(&tv.dev, &tv.resp.public(), &tv.irand, &fp) else { return false };
    let Ok(rpend) = responder_read_msg1(&tv.resp, &tv.dev.pk, m1.as_slice()) else { return false };
    let Some((m2, rsess)) = responder_write_msg2(rpend, &tv.rrand, &0x5445_4E41u64.to_le_bytes()) else { return false };
    let Ok((dsess, _tenant)) = initiator_read_msg2(ipend, m2.as_slice()) else { return false };
    let hh = dsess.handshake_hash;
    let mut dev = Tunnel::new(dsess, 0);
    // the PoP side: same sid from the same handshake hash; send = its send cipher, receive through a window
    let mut pop = Tunnel::new(rsess, 0);
    let sid_ok = dev.sid == pop.sid && dev.sid == sid_of(&hh);
    let mut dg = [0u8; 1700];
    let mut out = [0u8; 1600];
    // ADDR_REQ -> PoP; ASSIGN -> device
    let n = dev.seal(T_ADDR_REQ, &[], &mut dg, 10).unwrap_or(0);
    let req = pop.open(&dg[..n], &mut out, 10) == Some((T_ADDR_REQ, 0));
    let asg = [100u8, 64, 0, 2, 32, 1, 1, 1, 1, 0x64, 0x05]; // 100.64.0.2/32 dns 1.1.1.1 mtu 1380
    let n = pop.seal(T_ASSIGN, &asg, &mut dg, 20).unwrap_or(0);
    let assigned = dev.open(&dg[..n], &mut out, 20).is_some() && dev.assign == Some(Assign { inner: [100, 64, 0, 2], plen: 32, dns: [1, 1, 1, 1], mtu: 1380 });
    // DATA both ways; a replay and a flipped byte are refused, the window is untouched
    let pkt = [0x45u8, 0, 0, 20, 0, 0, 0, 0, 64, 17, 0, 0, 100, 64, 0, 2, 8, 8, 8, 8];
    let n = dev.seal(T_DATA, &pkt, &mut dg, 30).unwrap_or(0);
    let up = pop.open(&dg[..n], &mut out, 30) == Some((T_DATA, 20)) && out[..20] == pkt;
    let replay = pop.open(&dg[..n], &mut out, 31).is_none();
    let mut forged = dg;
    forged[n - 1] ^= 1;
    let forgery = pop.open(&forged[..n], &mut out, 32).is_none();
    let mut other = dg;
    other[4] ^= 0xff;
    let foreign = pop.open(&other[..n], &mut out, 33).is_none();
    let n = pop.seal(T_DATA, &pkt, &mut dg, 40).unwrap_or(0);
    let down = dev.open(&dg[..n], &mut out, 40) == Some((T_DATA, 20));
    // timers
    let t_ka = dev.tick(40 + KEEPALIVE_IDLE_MS) == Act::SendKeepalive;
    let t_quiet = dev.tick(40 + SILENCE_REHANDSHAKE_MS) == Act::Rehandshake;
    // ASSIGN sanity: a non-unicast inner / bad MTU / wrong length refused; the bench pool (198.18/15) accepted
    let bounds = parse_assign(&[224, 0, 0, 2, 32, 1, 1, 1, 1, 0x64, 0x05]).is_none()
        && parse_assign(&[127, 0, 0, 2, 32, 1, 1, 1, 1, 0x64, 0x05]).is_none()
        && parse_assign(&[198, 18, 0, 2, 32, 1, 1, 1, 1, 0x64, 0x05]).is_some()
        && parse_assign(&[100, 64, 0, 2, 32, 1, 1, 1, 1, 0x10, 0x00]).is_none()
        && parse_assign(&asg[..10]).is_none();
    // MSS clamp on a SYN with MSS 1460 -> 1340, checksum stays valid (recomputed from scratch)
    let mut syn = [0u8; 44];
    syn[0] = 0x45;
    syn[2..4].copy_from_slice(&44u16.to_be_bytes());
    syn[9] = 6;
    syn[12..16].copy_from_slice(&[100, 64, 0, 2]);
    syn[16..20].copy_from_slice(&[8, 8, 8, 8]);
    syn[32] = 0x60; // data offset 6 (24 bytes)
    syn[33] = 0x02; // SYN
    syn[40..44].copy_from_slice(&[2, 4, 0x05, 0xb4]);
    let tcp_sum = |p: &[u8]| -> u16 {
        let mut s: u32 = 0;
        for k in (12..20).step_by(2) {
            s += u16::from_be_bytes([p[k], p[k + 1]]) as u32;
        }
        s += 6 + 24;
        for k in (20..44).step_by(2) {
            if k == 36 {
                continue;
            }
            s += u16::from_be_bytes([p[k], p[k + 1]]) as u32;
        }
        while s > 0xffff {
            s = (s & 0xffff) + (s >> 16);
        }
        !(s as u16)
    };
    let c0 = tcp_sum(&syn);
    syn[36..38].copy_from_slice(&c0.to_be_bytes());
    let clamped = clamp_mss(&mut syn, 1340) && u16::from_be_bytes([syn[42], syn[43]]) == 1340 && u16::from_be_bytes([syn[36], syn[37]]) == tcp_sum(&syn);
    // DATA inbound is re-addressed inner -> WAN address: IP + UDP + TCP checksums stay valid (full recompute)
    let l4sum = |p: &[u8], proto: u8, csum_at: usize| -> u16 {
        let ln = p.len() - 20;
        let mut s: u32 = 0;
        for k in (12..20).step_by(2) {
            s += u16::from_be_bytes([p[k], p[k + 1]]) as u32;
        }
        s += proto as u32 + ln as u32;
        let mut k = 20;
        while k < p.len() {
            if k != csum_at {
                s += u16::from_be_bytes([p[k], *p.get(k + 1).unwrap_or(&0)]) as u32;
            }
            k += 2;
        }
        while s > 0xffff {
            s = (s & 0xffff) + (s >> 16);
        }
        !(s as u16)
    };
    let ipsum = |p: &[u8]| -> u16 {
        let mut s: u32 = 0;
        for k in (0..20).step_by(2) {
            if k != 10 {
                s += u16::from_be_bytes([p[k], p[k + 1]]) as u32;
            }
        }
        while s > 0xffff {
            s = (s & 0xffff) + (s >> 16);
        }
        !(s as u16)
    };
    let mut ok_re = true;
    for (proto, at) in [(17u8, 26usize), (6u8, 36usize)] {
        let mut p = [0u8; 48];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&48u16.to_be_bytes());
        p[9] = proto;
        p[12..16].copy_from_slice(&[93, 184, 216, 34]);
        p[16..20].copy_from_slice(&[100, 64, 0, 2]);
        for (i, b) in p[20..].iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(37) ^ 0x5a;
        }
        if proto == 6 {
            p[32] = 0x50;
        }
        let hs = ipsum(&p);
        p[10..12].copy_from_slice(&hs.to_be_bytes());
        let c = l4sum(&p, proto, at);
        p[at..at + 2].copy_from_slice(&c.to_be_bytes());
        readdress_dst(&mut p, [10, 100, 0, 135]);
        ok_re &= p[16..20] == [10, 100, 0, 135] && u16::from_be_bytes([p[10], p[11]]) == ipsum(&p)
            && u16::from_be_bytes([p[at], p[at + 1]]) == l4sum(&p, proto, at);
    }
    let pass = sid_ok && req && assigned && up && replay && forgery && foreign && down && t_ka && t_quiet && bounds && clamped && ok_re;
    arch_aarch64::_print(format_args!(
        " [P-g19] {} — G19 SASE tunnel, device side (PoP wire v1): sid agrees={} ADDR_REQ={} ASSIGN 100.64.0.2/32 mtu 1380={} DATA up={} down={} | replay refused={} forgery refused={} foreign sid refused={} | keepalive after 15 s={} re-handshake after 45 s silence={} ASSIGN bounds={} MSS clamp + checksum={} DATA re-addressed with valid IP/UDP/TCP checksums={}\n",
        if pass { "PASS" } else { "FAIL" }, sid_ok, req, assigned, up, down, replay, forgery, foreign, t_ka, t_quiet, bounds, clamped, ok_re));
    pass
}

/// `[P-g19-rekey]` (W4) — rekey + session continuity on the tunnel (in-process loopback: the device `Tunnel` against
/// a PoP built from the responder's session, the shared test vectors). Without CAPS nobody rekeys (an older PoP
/// keeps working); after the CAPS exchange DATA keeps flowing both ways across several epochs (small thresholds);
/// a captured pre-rekey record is refused after the grace window; the receiver logs epochs, never keys; a
/// re-handshake (new session) starts again at epoch 0 with a fresh sid — no key or nonce state survives it.
#[cfg(feature = "securechannel-selftest")]
pub fn rekey_selftest() -> bool {
    use crate::securechannel::{initiator_read_msg2, initiator_write_msg1, responder_read_msg1, responder_write_msg2, REKEY_GRACE_MS};
    let tv = crate::securechannel::test_vectors();
    let fp = boot_abi::sha256::digest(&tv.dev.pk[..]);
    let mk = |irand: &crate::securechannel::InitiatorRandomness| -> Option<(Session, Session)> {
        let (m1, ipend) = initiator_write_msg1(&tv.dev, &tv.resp.public(), irand, &fp)?;
        let rpend = responder_read_msg1(&tv.resp, &tv.dev.pk, m1.as_slice()).ok()?;
        let (m2, rsess) = responder_write_msg2(rpend, &tv.rrand, &0x5445_4E41u64.to_le_bytes())?;
        let (dsess, _) = initiator_read_msg2(ipend, m2.as_slice()).ok()?;
        Some((dsess, rsess))
    };
    let Some((dsess, rsess)) = mk(&tv.irand) else { return false };
    let pol = RekeyPolicy { max_records: 3, max_bytes: 1 << 30, max_ms: 600_000 };
    let mut dev = Tunnel::with_policy(dsess, 0, pol);
    let mut pop = Tunnel::with_policy(rsess, 0, pol);
    let (mut dg, mut out) = ([0u8; 1700], [0u8; 1600]);
    let pkt = [0x45u8, 0, 0, 20, 0, 0, 0, 0, 64, 17, 0, 0, 100, 64, 0, 2, 8, 8, 8, 8];
    // one DATA record each way at time t; true when both arrive intact
    let both = |dev: &mut Tunnel, pop: &mut Tunnel, t: i64, keep: &mut Option<([u8; 1700], usize)>| -> bool {
        let (mut dg, mut out) = ([0u8; 1700], [0u8; 1600]);
        let n = dev.seal(T_DATA, &pkt, &mut dg, t).unwrap_or(0);
        if keep.is_none() {
            *keep = Some((dg, n));
        }
        let up = pop.open(&dg[..n], &mut out, t) == Some((T_DATA, 20)) && out[..20] == pkt;
        let n = pop.seal(T_DATA, &pkt, &mut dg, t).unwrap_or(0);
        up && dev.open(&dg[..n], &mut out, t) == Some((T_DATA, 20))
    };
    // (1) no CAPS: 8 records each way, nobody rekeys
    let mut first = None;
    let mut flow = (0..8).all(|k| both(&mut dev, &mut pop, k, &mut first));
    let no_caps = flow && dev.epochs().0 == 0 && pop.epochs().0 == 0 && !dev.epochs().2;
    // (2) CAPS both ways -> both senders armed
    let n = dev.seal(T_CAPS, &[CAPS_REKEY], &mut dg, 10).unwrap_or(0);
    let mut caps = pop.open(&dg[..n], &mut out, 10) == Some((T_CAPS, 1));
    let n = pop.seal(T_CAPS, &[CAPS_REKEY], &mut dg, 11).unwrap_or(0);
    caps &= dev.open(&dg[..n], &mut out, 11) == Some((T_CAPS, 1)) && dev.epochs().2 && pop.epochs().2;
    // (3) 10 more records each way at 3 per epoch: continuity across epochs, both receivers follow
    let mut ignore = None;
    flow &= (20..30).all(|k| both(&mut dev, &mut pop, k, &mut ignore));
    let (dte, dre, _, dseq) = dev.epochs();
    let (pte, pre, _, _) = pop.epochs();
    let epochs = dte >= 3 && pte >= 3 && dre == pte && pre == dte;
    // (4) the very first (epoch-0) record captured on the wire: after the grace window it is refused as stale
    let (r0, n0) = first.unwrap_or(([0; 1700], 0));
    let t_late = 30 + REKEY_GRACE_MS + 1;
    let _ = pop.tick(t_late);
    let stale = pop.open(&r0[..n0], &mut out, t_late).is_none() && pop.stats.rx_stale >= 1;
    // (5) the time threshold alone moves an idle tunnel's epoch (keepalive after 10 min)
    let n = dev.seal(T_KEEPALIVE, &[], &mut dg, t_late + 600_000).unwrap_or(0);
    let timed = dev.epochs().0 == dte + 1 && pop.open(&dg[..n], &mut out, t_late + 600_000) == Some((T_KEEPALIVE, 0)) && pop.epochs().1 == dte + 1;
    // (6) re-handshake: a NEW session (fresh ephemerals) starts at epoch 0, unarmed, with a different sid; the old
    //     tunnel's records do not open on it
    let old_sid = dev.sid;
    let n_old = dev.seal(T_DATA, &pkt, &mut dg, t_late + 600_001).unwrap_or(0);
    let old_rec = dg;
    dev.wipe();
    pop.wipe();
    let irand2 = crate::securechannel::InitiatorRandomness::from_test_seeds(
        boot_abi::sha256::digest(b"HEQK-W4-eph-x"),
        boot_abi::sha256::digest(b"HEQK-W4-eph-d"),
        boot_abi::sha256::digest(b"HEQK-W4-eph-z"),
        boot_abi::sha256::digest(b"HEQK-W4-encaps-m"),
    );
    let fresh = match mk(&irand2) {
        Some((d2, r2)) => {
            let (mut dev2, mut pop2) = (Tunnel::with_policy(d2, 0, pol), Tunnel::with_policy(r2, 0, pol));
            let mut sid2 = old_rec;
            sid2[4..12].copy_from_slice(&dev2.sid);
            dev2.sid != old_sid
                && dev2.epochs() == (0, 0, false, 0)
                && pop2.open(&sid2[..n_old], &mut out, 0).is_none()
                && both(&mut dev2, &mut pop2, 1, &mut None)
        }
        None => false,
    };
    let pass = no_caps && caps && flow && epochs && stale && timed && fresh;
    arch_aarch64::_print(format_args!(
        " [P-g19-rekey] {} — G19 tunnel in-session rekey: no CAPS -> nobody rekeys (an older PoP keeps working)={} CAPS exchange arms both senders={} DATA continues both ways across epochs={} both receivers follow (device tx/rx epoch {}/{}, PoP {}/{}, next device seq {:#x})={} the captured epoch-0 record refused after the grace window={} the time threshold alone rekeys an idle tunnel={} a re-handshake starts at epoch 0 with a new sid, old records refused={}\n",
        if pass { "PASS" } else { "FAIL" }, no_caps, caps, flow, dte, dre, pte, pre, dseq, epochs, stale, timed, fresh));
    pass
}
