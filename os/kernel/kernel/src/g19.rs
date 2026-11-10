//! G19 — the SASE tunnel to the operator's super-PoP (device side). Wire format v1, mirrored from the PoP's
//! authoritative spec (`onboarding/enrollment/superpop/README.md`):
//!
//! * handshake: the existing PQ-hybrid Noise IK (`controlplane`, chunked msg1/msg2) sent UNICAST to `<pop>:7654`
//!   through the WAN gateway; msg1 payload = sha256(device pk), msg2 payload = tenant;
//! * data: UDP 7655, datagram = `"HQT1" ‖ sid(8) ‖ LE64 seq ‖ ciphertext ‖ tag16` (`seal_record` /
//!   `AntiReplayRx::open_record`, RFC 6479 window), AD = `"HQT1" ‖ sid`,
//!   sid = SHA-256("HQ-G19-sid-v1" ‖ handshake_hash)[0..8];
//! * record plaintext = type ‖ body: DATA (one IPv4 packet), KEEPALIVE, ASSIGN (inner_v4 ‖ plen ‖ dns_v4 ‖ mtu LE16),
//!   ADDR_REQ, CLOSE (reason).
//!
//! Device duties: ADDR_REQ right after the handshake; NAT the tunnelled LAN flows to the ASSIGNed inner /32 (the
//! existing NAT engine, with the inner address as its "WAN" address); clamp TCP MSS to mtu - 40; KEEPALIVE when
//! idle 15 s; re-handshake after 45 s with nothing heard (the PoP echoes KEEPALIVE) and every 24 h. Standalone
//! by default: no `tunnel` line in the signed POLICY.TXT (or no pinned PoP key in the image) = no tunnel.
#![cfg(feature = "securechannel")]

use crate::securechannel::{AntiReplayRx, Session};

pub const HS_PORT: u16 = 7654;
pub const DATA_PORT: u16 = 7655;
pub const T_DATA: u8 = 0x01;
pub const T_KEEPALIVE: u8 = 0x02;
pub const T_ASSIGN: u8 = 0x03;
pub const T_ADDR_REQ: u8 = 0x04;
pub const T_CLOSE: u8 = 0x05;
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
    // inner address from the CGNAT pool (100.64.0.0/10), a sane prefix and MTU
    let cgnat = a.inner[0] == 100 && (64..128).contains(&a.inner[1]);
    (cgnat && (1..=32).contains(&a.plen) && (576..=1500).contains(&a.mtu)).then_some(a)
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
}

/// One established tunnel session (the transport keys of the Noise handshake).
pub struct Tunnel {
    sess: Session,
    rx: AntiReplayRx,
    pub sid: [u8; 8],
    pub assign: Option<Assign>,
    last_rx_ms: i64,
    last_tx_ms: i64,
    since_ms: i64,
    pub stats: Stats,
}

impl Tunnel {
    pub fn new(sess: Session, now_ms: i64) -> Tunnel {
        let sid = sid_of(&sess.handshake_hash);
        let rx = sess.recv.into_anti_replay();
        Tunnel { sess, rx, sid, assign: None, last_rx_ms: now_ms, last_tx_ms: now_ms, since_ms: now_ms, stats: Stats::default() }
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
        let n = self.sess.send.seal_record(&ad, &pt[..1 + body.len()], &mut out[12..])?;
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
        let n = match self.rx.open_record(&ad, &dg[12..], &mut pt) {
            Ok(n) if n >= 1 && n - 1 <= out.len() => n,
            _ => {
                self.stats.rx_bad += 1;
                return None;
            }
        };
        self.last_rx_ms = now_ms;
        let ty = pt[0];
        out[..n - 1].copy_from_slice(&pt[1..n]);
        match ty {
            T_ASSIGN => self.assign = parse_assign(&pt[1..n]).or(self.assign),
            T_DATA => self.stats.rx_data += 1,
            _ => {}
        }
        Some((ty, n - 1))
    }

    /// Timers: KEEPALIVE after 15 s without sending; re-handshake after 45 s without hearing anything, or at 24 h.
    pub fn tick(&mut self, now_ms: i64) -> Act {
        if now_ms - self.last_rx_ms >= SILENCE_REHANDSHAKE_MS || now_ms - self.since_ms >= SESSION_MAX_MS {
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
        self.sess.wipe();
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
    let mut dev = Tunnel::new(dsess, 0);
    // the PoP side: same sid from the same handshake hash; send = its send cipher, receive through a window
    let mut pop = Tunnel::new(rsess, 0);
    let sid_ok = dev.sid == pop.sid && dev.sid == sid_of(&dev.sess.handshake_hash);
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
    // ASSIGN sanity: not CGNAT / bad MTU / wrong length refused
    let bounds = parse_assign(&[10, 0, 0, 2, 32, 1, 1, 1, 1, 0x64, 0x05]).is_none()
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
    let pass = sid_ok && req && assigned && up && replay && forgery && foreign && down && t_ka && t_quiet && bounds && clamped;
    arch_aarch64::_print(format_args!(
        " [P-g19] {} — G19 SASE tunnel, device side (PoP wire v1): sid agrees={} ADDR_REQ={} ASSIGN 100.64.0.2/32 mtu 1380={} DATA up={} down={} | replay refused={} forgery refused={} foreign sid refused={} | keepalive after 15 s={} re-handshake after 45 s silence={} ASSIGN bounds={} MSS clamp + checksum={}\n",
        if pass { "PASS" } else { "FAIL" }, sid_ok, req, assigned, up, down, replay, forgery, foreign, t_ka, t_quiet, bounds, clamped));
    pass
}
