//! End-to-end harness: a simulated DEVICE built from the kernel's real initiator code talks to the
//! PoP core in-process (no sockets/TUN). Shared by `cargo test` and `superpop selftest`.

use crate::entropy::OsEntropy;
use crate::pop::{Config, Device, Out, Pop, SESSION_IDLE_MS};
use crate::securechannel::{
    hs_chunk, initiator_read_msg2, initiator_write_msg1, AntiReplayRx, CipherState, HsReasm, InitiatorRandomness,
    NoiseErr, RecordRx, RecordTx, RekeyPolicy, ResponderStatic, Session,
};
use crate::wire::{self, Assign, Msg, Sid};
use boot_abi::sha256;
use ed25519_compact::{KeyPair, Seed};
use std::net::SocketAddr;

macro_rules! ensure {
    ($c:expr, $($m:tt)*) => { if !$c { return Err(format!($($m)*)); } };
}

pub const TENANT: u64 = 0x5445_4E41;

pub fn responder() -> ResponderStatic {
    ResponderStatic::from_seeds(
        &sha256::digest(b"G19-TEST-pop-x25519"),
        &sha256::digest(b"G19-TEST-pop-mlkem-d"),
        &sha256::digest(b"G19-TEST-pop-mlkem-z"),
    )
}

pub fn dev_kp(tag: &[u8]) -> KeyPair {
    KeyPair::from_seed(Seed::new(sha256::digest(tag)))
}

pub fn addr(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

/// The device side of one established tunnel session.
pub struct Dev {
    pub sid: Sid,
    send: CipherState,
    rx: AntiReplayRx,
}

impl Dev {
    pub fn seal(&mut self, m: &Msg<'_>) -> Vec<u8> {
        let mut pt = [0u8; wire::MAX_PT];
        let n = wire::encode(m, &mut pt).unwrap();
        let mut dg = vec![0u8; wire::MAX_DGRAM];
        dg[..4].copy_from_slice(&wire::MAGIC);
        dg[4..wire::HDR_LEN].copy_from_slice(&self.sid);
        let rl = self.send.seal_record(&wire::ad(&self.sid), &pt[..n], &mut dg[wire::HDR_LEN..]).unwrap();
        dg.truncate(wire::HDR_LEN + rl);
        dg
    }
    /// Open a PoP datagram; returns the decoded plaintext bytes.
    pub fn open(&mut self, dg: &[u8]) -> Result<Vec<u8>, String> {
        let (sid, rec) = wire::parse_dgram(dg).ok_or("not a G19 datagram")?;
        if sid != self.sid {
            return Err("wrong sid".into());
        }
        let mut pt = [0u8; wire::MAX_PT + 16];
        let n = self.rx.open_record(&wire::ad(&sid), rec, &mut pt).map_err(|e| format!("open: {e:?}"))?;
        Ok(pt[..n].to_vec())
    }
}

/// Run the device handshake against `pop` from `from`; `claim_fp` overrides the msg1 payload.
pub fn handshake(pop: &mut Pop, kp: &KeyPair, from: SocketAddr, now: u64, claim_fp: Option<[u8; 32]>) -> Result<Dev, String> {
    handshake_session(pop, kp, from, now, claim_fp).map(Dev::from_session)
}

/// The handshake, returning the device's raw Noise session.
pub fn handshake_session(pop: &mut Pop, kp: &KeyPair, from: SocketAddr, now: u64, claim_fp: Option<[u8; 32]>) -> Result<Session, String> {
    let resp_pub = responder().public();
    let mut ent = OsEntropy;
    let rnd = InitiatorRandomness::from_entropy(&mut ent).map_err(|e| format!("{e:?}"))?;
    let fp = claim_fp.unwrap_or_else(|| sha256::digest(kp.pk.as_ref()));
    let (msg1, pend) = initiator_write_msg1(kp, &resp_pub, &rnd, &fp).ok_or("msg1")?;
    let mut outs = Vec::new();
    let mut chunks = Vec::new();
    hs_chunk(msg1.as_slice(), |c| {
        chunks.push(c.to_vec());
        true
    });
    for c in chunks {
        outs.extend(pop.on_hs(from, &c, now, &mut ent));
    }
    if outs.is_empty() {
        return Err("no msg2 (refused)".into());
    }
    let mut re = HsReasm::new();
    let mut total = None;
    for o in outs {
        match o {
            Out::Hs(to, c) if to == from => total = re.feed(&c).map_err(|_| "msg2 reasm")?.or(total),
            other => return Err(format!("unexpected handshake output {other:?}")),
        }
    }
    let total = total.ok_or("msg2 incomplete")?;
    let (mut session, payload2) = initiator_read_msg2(pend, &re.message()[..total]).map_err(|e| format!("msg2: {e:?}"))?;
    if payload2.as_slice() != TENANT.to_le_bytes() {
        return Err("tenant mismatch in msg2".into());
    }
    let _ = &mut session;
    Ok(session)
}

/// W4: a device with the kernel's rekeying record layer (as heqk's G19 tunnel runs it).
pub struct RDev {
    pub sid: Sid,
    tx: RecordTx,
    rx: RecordRx,
}

impl RDev {
    pub fn from_session(mut session: Session, pol: RekeyPolicy) -> RDev {
        let sid = wire::sid_from_handshake_hash(&session.handshake_hash);
        let rx = session.recv.into_record_rx();
        let tx = RecordTx::new(session.send.clone(), 0, pol);
        session.wipe();
        RDev { sid, tx, rx }
    }
    pub fn seal(&mut self, m: &Msg<'_>, now: u64) -> Vec<u8> {
        let mut pt = [0u8; wire::MAX_PT];
        let n = wire::encode(m, &mut pt).unwrap();
        let mut dg = vec![0u8; wire::MAX_DGRAM];
        dg[..4].copy_from_slice(&wire::MAGIC);
        dg[4..wire::HDR_LEN].copy_from_slice(&self.sid);
        let rl = self.tx.seal(&wire::ad(&self.sid), &pt[..n], &mut dg[wire::HDR_LEN..], now as i64).unwrap();
        dg.truncate(wire::HDR_LEN + rl);
        dg
    }
    pub fn open(&mut self, dg: &[u8], now: u64) -> Result<Vec<u8>, NoiseErr> {
        let (_, rec) = wire::parse_dgram(dg).ok_or(NoiseErr::Truncated)?;
        let mut pt = [0u8; wire::MAX_PT + 16];
        let n = self.rx.open(&wire::ad(&self.sid), rec, &mut pt, now as i64)?;
        if wire::decode(&pt[..n]) == Some(Msg::Caps(wire::CAPS_REKEY)) {
            self.tx.arm();
        }
        Ok(pt[..n].to_vec())
    }
}

/// W4 interop: a rekeying device against this PoP. Until CAPS nobody rekeys; after the CAPS exchange both
/// directions move through several key epochs (small thresholds) with every record delivered; a captured
/// pre-rekey record is refused (stale) on both sides; a legacy device (no CAPS) is never rekeyed at.
pub fn rekey_scenario() -> Result<(), String> {
    let pol = RekeyPolicy { max_records: 3, max_bytes: 1 << 30, max_ms: 600_000 };
    let mut pop = new_pop();
    pop.rekey = pol;
    let a = dev_kp(b"G19-TEST-device-A");
    let from = addr("10.0.0.5:40001");
    let mut dev = RDev::from_session(handshake_session(&mut pop, &a, addr("10.0.0.5:7654"), 1_000, None)?, pol);
    let (_, dg) = one_data(pop.on_data(from, &dev.seal(&Msg::AddrReq, 1_010), 1_010))?;
    ensure!(matches!(wire::decode(&dev.open(&dg, 1_010).map_err(|e| format!("{e:?}"))?), Some(Msg::Assign(_))), "no ASSIGN");
    let pkt = ipv4([100, 64, 0, 2], [9, 9, 9, 9], b"rekey");
    let reply = ipv4([9, 9, 9, 9], [100, 64, 0, 2], b"rekey back");
    // unarmed: no epoch moves on either side
    let first = dev.seal(&Msg::Data(&pkt), 1_020);
    ensure!(pop.on_data(from, &first, 1_020) == vec![Out::Tun(pkt.clone())], "pre-CAPS DATA lost");
    let (_, first_down) = one_data(pop.on_tun(&reply))?;
    ensure!(dev.open(&first_down, 1_021).is_ok(), "pre-CAPS reply lost");
    for t in 0..5 {
        ensure!(pop.on_data(from, &dev.seal(&Msg::Data(&pkt), 1_030 + t), 1_030 + t).len() == 1, "unarmed DATA lost");
    }
    ensure!(dev.tx.epoch() == 0 && dev.rx.epoch() == 0, "rekeyed without CAPS");
    // CAPS exchange
    let (_, dg) = one_data(pop.on_data(from, &dev.seal(&Msg::Caps(wire::CAPS_REKEY), 1_100), 1_100))?;
    ensure!(dev.open(&dg, 1_100).map_err(|e| format!("{e:?}"))? == [wire::T_CAPS, wire::CAPS_REKEY], "no CAPS reply");
    ensure!(dev.tx.armed() && pop.stats.caps_rekey == 1, "CAPS did not arm both sides");
    // continuity across epochs, both directions
    for t in 0..12u64 {
        let now = 1_200 + t;
        ensure!(pop.on_data(from, &dev.seal(&Msg::Data(&pkt), now), now) == vec![Out::Tun(pkt.clone())], "DATA lost at {t} (epoch {})", dev.tx.epoch());
        let (_, dg) = one_data(pop.on_tun(&reply))?;
        ensure!(wire::decode(&dev.open(&dg, now).map_err(|e| format!("down {t}: {e:?}"))?) == Some(Msg::Data(&reply)), "reply lost at {t}");
    }
    ensure!(dev.tx.epoch() >= 3 && dev.rx.epoch() >= 3, "epochs did not move: tx {} rx {}", dev.tx.epoch(), dev.rx.epoch());
    // a captured epoch-0 record is stale on both sides
    let bad = pop.stats.records_bad;
    ensure!(pop.on_data(from, &first, 1_300).is_empty() && pop.stats.records_bad == bad + 1, "pre-rekey record accepted by the PoP");
    ensure!(dev.open(&first_down, 1_300) == Err(NoiseErr::Stale), "pre-rekey record accepted by the device");
    // a legacy device (no CAPS) on the same PoP is never rekeyed at
    let b = dev_kp(b"G19-TEST-device-B");
    let bfrom = addr("10.0.0.6:40001");
    let mut old = handshake(&mut pop, &b, addr("10.0.0.6:7654"), 2_000, None)?;
    let _ = one_data(pop.on_data(bfrom, &old.seal(&Msg::AddrReq), 2_000))?;
    let breply = ipv4([9, 9, 9, 9], [100, 64, 0, 3], b"legacy");
    for _ in 0..10 {
        let (_, dg) = one_data(pop.on_tun(&breply))?;
        ensure!(wire::decode(&old.open(&dg)?) == Some(Msg::Data(&breply)), "legacy device lost a reply");
    }
    Ok(())
}

impl Dev {
    /// The device's tunnel state from an established Noise session (keys move; recv key wiped).
    pub fn from_session(mut session: crate::securechannel::Session) -> Dev {
        let sid = wire::sid_from_handshake_hash(&session.handshake_hash);
        let rx = session.recv.into_anti_replay();
        session.recv.wipe();
        Dev { sid, send: session.send, rx }
    }
}

pub fn ipv4(src: [u8; 4], dst: [u8; 4], payload: &[u8]) -> Vec<u8> {
    let total = 20 + payload.len();
    let mut p = vec![0u8; total];
    p[0] = 0x45;
    p[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    p[8] = 64;
    p[9] = 17;
    p[12..16].copy_from_slice(&src);
    p[16..20].copy_from_slice(&dst);
    p[20..].copy_from_slice(payload);
    p
}

fn one_data(outs: Vec<Out>) -> Result<(SocketAddr, Vec<u8>), String> {
    match <[Out; 1]>::try_from(outs) {
        Ok([Out::Data(to, b)]) => Ok((to, b)),
        Ok([o]) => Err(format!("expected one data datagram, got {o:?}")),
        Err(v) => Err(format!("expected one output, got {}", v.len())),
    }
}


pub fn new_pop() -> Pop {
    let a = dev_kp(b"G19-TEST-device-A");
    let b = dev_kp(b"G19-TEST-device-B");
    let cfg = Config { tenant: TENANT, ..Config::default() };
    Pop::new(
        responder(),
        cfg,
        vec![Device::new("dev-a", a.pk, [100, 64, 0, 2]), Device::new("dev-b", b.pk, [100, 64, 0, 3])],
    )
    .unwrap()
}

pub fn scenario() -> Result<(), String> {
    let mut pop = new_pop();
    let a = dev_kp(b"G19-TEST-device-A");
    let hs_from = addr("10.0.0.5:7654");
    let data_from = addr("10.0.0.5:40001");

    // 1. handshake → established, tenant delivered.
    let mut dev = handshake(&mut pop, &a, hs_from, 1_000, None)?;
    ensure!(pop.stats.handshakes_ok == 1 && pop.session_count() == 1, "handshake not counted");

    // 2. no data endpoint yet: return traffic has nowhere to go.
    ensure!(pop.on_tun(&ipv4([9, 9, 9, 9], [100, 64, 0, 2], b"early")).is_empty(), "sent before endpoint known");

    // 3. ADDR_REQ → ASSIGN to the data source.
    let (to, dg) = one_data(pop.on_data(data_from, &dev.seal(&Msg::AddrReq), 1_100))?;
    ensure!(to == data_from, "ASSIGN sent to {to}");
    let pt = dev.open(&dg)?;
    ensure!(
        wire::decode(&pt) == Some(Msg::Assign(Assign { inner: [100, 64, 0, 2], plen: 32, dns: [1, 1, 1, 1], mtu: wire::DEFAULT_MTU })),
        "bad ASSIGN {pt:?}"
    );

    // 4. DATA with the assigned source → exactly that packet to the TUN.
    let pkt = ipv4([100, 64, 0, 2], [9, 9, 9, 9], b"hello pop");
    let dg_data = dev.seal(&Msg::Data(&pkt));
    ensure!(pop.on_data(data_from, &dg_data, 1_200) == vec![Out::Tun(pkt.clone())], "DATA not delivered to TUN");

    // 5. anti-spoof, no device→device, replay rejected.
    ensure!(pop.on_data(data_from, &dev.seal(&Msg::Data(&ipv4([100, 64, 0, 9], [9, 9, 9, 9], b"x"))), 1_210).is_empty(), "spoofed src passed");
    ensure!(pop.stats.spoofed == 1, "spoof not counted");
    ensure!(pop.on_data(data_from, &dev.seal(&Msg::Data(&ipv4([100, 64, 0, 2], [100, 64, 0, 3], b"x"))), 1_220).is_empty(), "d2d passed");
    ensure!(pop.stats.d2d_dropped == 1, "d2d not counted");
    let bad_before = pop.stats.records_bad;
    ensure!(pop.on_data(data_from, &dg_data, 1_230).is_empty(), "replay accepted");
    ensure!(pop.stats.records_bad == bad_before + 1, "replay not counted");

    // 6. return traffic sealed to the device's endpoint, opens to the same packet.
    let reply = ipv4([9, 9, 9, 9], [100, 64, 0, 2], b"hello device");
    let (to, dg) = one_data(pop.on_tun(&reply))?;
    ensure!(to == data_from, "reply sent to {to}");
    ensure!(wire::decode(&dev.open(&dg)?) == Some(Msg::Data(&reply)), "reply payload differs");

    // 7. roaming / NAT rebinding: an authenticated record from a new address moves the endpoint.
    let roamed = addr("203.0.113.77:5555");
    let (to, dg) = one_data(pop.on_data(roamed, &dev.seal(&Msg::Keepalive), 1_300))?;
    ensure!(to == roamed && wire::decode(&dev.open(&dg)?) == Some(Msg::Keepalive), "keepalive not echoed to new endpoint");
    ensure!(pop.stats.rebinds == 1, "rebind not counted");
    let (to, _) = one_data(pop.on_tun(&reply))?;
    ensure!(to == roamed, "return traffic still going to the old endpoint");

    // 8. an injected datagram from an attacker address with a forged record does not rebind.
    let mut forged = dev.seal(&Msg::Keepalive);
    let last = forged.len() - 1;
    forged[last] ^= 1;
    ensure!(pop.on_data(addr("198.51.100.1:1"), &forged, 1_310).is_empty(), "forged record answered");
    let (to, _) = one_data(pop.on_tun(&reply))?;
    ensure!(to == roamed, "forged record moved the endpoint");

    // 9. a device not on the allowlist gets nothing (no keys ⇒ no CLOSE possible).
    let rogue = dev_kp(b"G19-TEST-rogue");
    ensure!(handshake(&mut pop, &rogue, addr("10.0.0.99:7654"), 1_400, None).is_err(), "rogue device accepted");
    ensure!(pop.stats.handshakes_refused == 1, "rogue refusal not counted");

    // 10. an allowed key claiming another fingerprint is refused (review Q2-H1).
    ensure!(handshake(&mut pop, &a, addr("10.0.0.5:7654"), 1_500, Some([0xAA; 32])).is_err(), "fp mismatch accepted");

    // 11. re-handshake replaces the session; the old sid is dead.
    let old = dev.seal(&Msg::Keepalive);
    let mut dev2 = handshake(&mut pop, &a, hs_from, 1_600, None)?;
    ensure!(dev2.sid != dev.sid, "sid not fresh per session");
    ensure!(pop.session_count() == 1, "old session not replaced");
    let unknown = pop.stats.unknown_sid;
    ensure!(pop.on_data(data_from, &old, 1_610).is_empty() && pop.stats.unknown_sid == unknown + 1, "old sid still live");
    let (_, dg) = one_data(pop.on_data(data_from, &dev2.seal(&Msg::AddrReq), 1_620))?;
    ensure!(matches!(wire::decode(&dev2.open(&dg)?), Some(Msg::Assign(_))), "new session not usable");

    // 12. idle expiry.
    pop.gc(1_620 + SESSION_IDLE_MS + 1);
    ensure!(pop.session_count() == 0, "idle session not expired");
    ensure!(pop.on_tun(&reply).is_empty(), "expired session still routed");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn end_to_end_scenario() {
        scenario().unwrap();
    }

    #[test]
    fn rekey_interop() {
        rekey_scenario().unwrap();
    }

    #[test]
    fn handshake_rate_limit_per_source() {
        let mut pop = new_pop();
        let rogue = dev_kp(b"G19-TEST-rogue");
        let src = addr("10.9.9.9:7654");
        for i in 0..10 {
            let _ = handshake(&mut pop, &rogue, src, 1_000 + i, None);
        }
        assert_eq!(pop.stats.handshakes_refused, 6, "only the per-window budget is processed");
        assert_eq!(pop.stats.handshakes_ratelimited, 4);
        // the window rolls over
        let a = dev_kp(b"G19-TEST-device-A");
        assert!(handshake(&mut pop, &a, src, 1_000 + 61_000, None).is_ok());
    }

    #[test]
    fn config_rejects_bad_allowlists() {
        let a = dev_kp(b"G19-TEST-device-A");
        let cfg = || Config { tenant: TENANT, ..Config::default() };
        assert!(Pop::new(responder(), cfg(), vec![Device::new("x", a.pk, [192, 168, 1, 2])]).is_err(), "outside pool");
        assert!(Pop::new(
            responder(),
            cfg(),
            vec![Device::new("x", a.pk, [100, 64, 0, 2]), Device::new("y", dev_kp(b"other").pk, [100, 64, 0, 2])]
        )
        .is_err(), "duplicate inner");
        assert!(Pop::new(responder(), cfg(), vec![Device::new("x", a.pk, [100, 64, 0, 2]), Device::new("y", a.pk, [100, 64, 0, 3])]).is_err(), "duplicate key");
    }
}
