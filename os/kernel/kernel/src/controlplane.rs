//! M4.5 control-plane INITIATOR — the on-device half of the full PQ-hybrid Noise handshake,
//! carried over a SMOLTCP-FREE, hand-framed UDP transport that rides the sensor's SINGLE GEM
//! drain (RX tee) + single `gem::tx_frame` path (the Linux-`macb` single-ring-owner discipline,
//! metal-proven 2026-09-08). There is NO persistent smoltcp socket: `InitiatorPending`/`Session`
//! own every field by value, so the handshake state lives in plain struct fields with zero
//! no_std self-referential-lifetime hazard.
//!
//! Flow (os-architect design 2026-09-08): `tick` (from the heartbeat) starts the handshake when
//! the link is up — `initiator_write_msg1` → the ~2480 B msg1 is chunked (`hs_chunk`) into
//! BROADCAST UDP datagrams (dst ff.. / 255.255.255.255:7654 — avoids ARP; the responder replies
//! unicast to our MAC, caught by `is_for_heqk`), pre-built into an egress buffer that is the
//! RETRANSMIT source (re-emitting the SAME bytes — rebuilding msg1 would orphan the ephemerals).
//! `poll_egress` hands one datagram per call to the drain loop's TX. `ingress` (teed from the
//! drain) reassembles the msg2 datagrams (`HsReasm`) and completes with `initiator_read_msg2` →
//! a live `Session`. Bounded attempts → `Failed` (air-gap: no responder ⇒ sensor unaffected).
#![cfg(feature = "securechannel")]

use crate::netsvc::{build_hs_datagram, is_for_heqk, udp_payload_for_port};
use crate::securechannel::{
    hs_chunk, initiator_read_msg2, initiator_write_msg1, HsReasm, InitiatorPending,
    InitiatorRandomness, ResponderPub, Session, HS_MAX_CHUNKS,
};
use ed25519_compact::KeyPair;

/// The control-plane UDP port (device ⟷ MSSP).
pub const HS_PORT: u16 = 7654;
/// Max on-wire datagram = eth(14)+ip(20)+udp(8)+[chunk-hdr(4)+chunk(≤1024)].
const DGRAM_CAP: usize = 14 + 20 + 8 + 4 + 1024;
/// Retransmit interval + attempt cap (bounded — the air-gap invariant as code).
const RETX_MS: i64 = 500;
const MAX_ATTEMPTS: u8 = 4;
/// A transport session lives at most this long, then the device re-handshakes with FRESH ephemerals
/// (X25519 + ML-KEM from the TRNG) — post-compromise healing + forward secrecy for long uptimes (BOI
/// review Q1 M2: a key used to live until reboot). Counter-based too: well before the 2^64 nonce wall.
pub const SESSION_MAX_MS: i64 = 24 * 3600 * 1000;
pub const SESSION_MAX_RECORDS: u64 = 1 << 32;
/// A failed handshake (no responder in budget) is retried with capped exponential backoff — it used to
/// stay Failed until reboot, so an MSSP outage at boot left the device air-gapped for its whole uptime.
const RETRY_BASE_MS: i64 = 30_000;
const RETRY_MAX_MS: i64 = 3_600_000;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CpState {
    Idle,
    SentMsg1,
    Established,
    Failed,
}

/// The on-device control-plane handshake initiator. All fields owned by value (no borrows).
pub struct ControlPlane {
    state: CpState,
    pending: Option<InitiatorPending>,
    reasm: HsReasm,
    session: Option<Session>,
    resp_pub: ResponderPub,
    dev_kp: KeyPair,
    our_mac: [u8; 6],
    our_ip: [u8; 4],
    device_fp: [u8; 32],
    // Precomputed msg1 datagrams — the RETRANSMIT buffer (never rebuilt while pending).
    egress: [[u8; DGRAM_CAP]; HS_MAX_CHUNKS],
    egress_len: [u16; HS_MAX_CHUNKS],
    egress_n: u8,
    egress_cursor: u8,
    attempts: u8,
    last_tx_ms: i64,
    /// for-heqk UDP:7654 frames ingested (heartbeat diagnostic).
    pub seen: u32,
    /// The tenant the MSSP assigned in msg2's payload (LE u64) — authenticated by the handshake,
    /// so the device never hard-codes it. `None` until Established (or if msg2 carried none).
    tenant: Option<u64>,
    /// The responder's L2/L3 address, learned from the msg2 datagrams — exports go UNICAST to
    /// it rather than broadcast across the LAN.
    peer_mac: [u8; 6],
    peer_ip: [u8; 4],
    established_at_ms: i64,
    next_try_ms: i64,
    fails: u32,
    /// completed sessions retired by the lifetime / record-count rekey
    pub rekeys: u32,
}

impl ControlPlane {
    pub fn new(resp_pub: ResponderPub, dev_kp: KeyPair, our_mac: [u8; 6], our_ip: [u8; 4]) -> Self {
        let device_fp = boot_abi::sha256::digest(&dev_kp.pk[..]);
        ControlPlane {
            state: CpState::Idle,
            pending: None,
            reasm: HsReasm::new(),
            session: None,
            resp_pub,
            dev_kp,
            our_mac,
            our_ip,
            device_fp,
            egress: [[0u8; DGRAM_CAP]; HS_MAX_CHUNKS],
            egress_len: [0u16; HS_MAX_CHUNKS],
            egress_n: 0,
            egress_cursor: 0,
            attempts: 0,
            last_tx_ms: 0,
            seen: 0,
            tenant: None,
            peer_mac: [0xff; 6],
            peer_ip: [255, 255, 255, 255],
            established_at_ms: 0,
            next_try_ms: 0,
            fails: 0,
            rekeys: 0,
        }
    }

    /// G19: send the handshake UNICAST to `ip` through the next hop `mac` (the WAN gateway) instead of a LAN
    /// broadcast. Takes effect at the next msg1.
    pub fn set_unicast(&mut self, mac: [u8; 6], ip: [u8; 4]) {
        self.peer_mac = mac;
        self.peer_ip = ip;
    }

    /// G19: hand the established transport session to the tunnel (the control plane keeps no copy).
    pub fn take_session(&mut self) -> Option<Session> {
        self.session.take()
    }

    /// G19: start over — a fresh handshake (fresh ephemerals) at the next tick (re-handshake on silence / 24 h).
    pub fn restart(&mut self, now_ms: i64) {
        if let Some(mut s) = self.session.take() {
            s.wipe();
        }
        self.pending = None;
        self.state = CpState::Idle;
        self.next_try_ms = now_ms;
    }

    /// The MSSP-assigned tenant (from the authenticated msg2 payload), once Established.
    pub fn tenant(&self) -> Option<u64> {
        self.tenant
    }

    /// The responder's (MAC, IPv4), learned from msg2 — the unicast export destination.
    pub fn peer(&self) -> ([u8; 6], [u8; 4]) {
        (self.peer_mac, self.peer_ip)
    }

    /// The provisioned MSSP's X25519 static public key (recorded in the device's `Enrollment`).
    pub fn resp_x_pk(&self) -> [u8; 32] {
        self.resp_pub.x_pk()
    }

    /// Our own (MAC, IPv4) on the control-plane link.
    pub fn local(&self) -> ([u8; 6], [u8; 4]) {
        (self.our_mac, self.our_ip)
    }

    pub fn state(&self) -> CpState {
        self.state
    }
    pub fn established(&self) -> bool {
        self.state == CpState::Established
    }
    /// Mutable access to the completed transport (for the reach-policy fetch).
    pub fn session_mut(&mut self) -> Option<&mut Session> {
        self.session.as_mut()
    }

    /// This device's fingerprint (`sha256(dev.pk)`) — the C14 binding the reach policy is signed
    /// for. The segmentation-arming path builds an `Enrollment` around it.
    pub fn device_fp(&self) -> [u8; 32] {
        self.device_fp
    }

    /// Is this frame for the control plane (for-heqk AND UDP:7654)?
    pub fn wants(&self, frame: &[u8]) -> bool {
        is_for_heqk(frame, self.our_mac, self.our_ip) && udp_payload_for_port(frame, HS_PORT).is_some()
    }

    /// Build msg1 + pre-chunk it into the egress datagram buffer, and move to SentMsg1. The drawn
    /// ephemerals survive inside `self.pending` across the msg1→msg2 gap (owned, no lifetime).
    fn start(&mut self, rnd: &InitiatorRandomness) -> bool {
        let (msg1, ipend) = match initiator_write_msg1(&self.dev_kp, &self.resp_pub, rnd, &self.device_fp) {
            Some(x) => x,
            None => return false,
        };
        let (mac, ip) = (self.our_mac, self.our_ip);
        // broadcast on the local segment (MSSP enrollment), or unicast via a next hop (G19 super-PoP: set_unicast)
        let (dst_mac, dst_ip) = (self.peer_mac, self.peer_ip);
        self.egress_n = 0;
        let ok = hs_chunk(msg1.as_slice(), |framed| {
            let i = self.egress_n as usize;
            if i >= HS_MAX_CHUNKS {
                return false;
            }
            let n = build_hs_datagram(mac, ip, dst_mac, dst_ip, HS_PORT, framed, &mut self.egress[i]);
            self.egress_len[i] = n as u16;
            self.egress_n += 1;
            true
        });
        if !ok {
            return false;
        }
        self.pending = Some(ipend);
        self.reasm.reset();
        self.egress_cursor = 0;
        self.state = CpState::SentMsg1;
        true
    }

    /// Every failure path: Failed + capped exponential backoff (30 s, 60 s, ... 1 h) before the next attempt.
    fn fail(&mut self, now_ms: i64) {
        self.pending = None;
        self.state = CpState::Failed;
        self.fails = self.fails.saturating_add(1);
        let back = RETRY_BASE_MS.saturating_mul(1i64 << (self.fails.min(8) - 1)).min(RETRY_MAX_MS);
        self.next_try_ms = now_ms + back;
    }

    /// Heartbeat driver: start a handshake when the link is up (fresh ephemerals from `fresh` — called ONLY
    /// when a new msg1 is built, never for a retransmit); bounded retransmit of msg1; retry a failed
    /// handshake with backoff; retire an Established session after SESSION_MAX_MS / SESSION_MAX_RECORDS.
    pub fn tick(&mut self, now_ms: i64, link_up: bool, fresh: &mut dyn FnMut() -> Option<InitiatorRandomness>) {
        match self.state {
            CpState::Idle => {
                if link_up && now_ms >= self.next_try_ms {
                    match fresh() {
                        Some(rnd) if self.start(&rnd) => {
                            self.attempts = 1;
                            self.last_tx_ms = now_ms;
                        }
                        _ => self.next_try_ms = now_ms + RETRY_BASE_MS, // no entropy / build failed: try later
                    }
                }
            }
            CpState::Failed => {
                if now_ms >= self.next_try_ms {
                    self.pending = None;
                    self.state = CpState::Idle;
                }
            }
            CpState::Established => {
                let used = self.session.as_ref().map_or(0, |s| s.send.counter().max(s.recv.counter()));
                if now_ms - self.established_at_ms >= SESSION_MAX_MS || used >= SESSION_MAX_RECORDS {
                    if let Some(mut s) = self.session.take() {
                        s.wipe();
                    }
                    self.rekeys += 1;
                    self.state = CpState::Idle;
                    self.next_try_ms = now_ms;
                }
            }
            CpState::SentMsg1 => {
                if now_ms - self.last_tx_ms >= RETX_MS {
                    if self.attempts >= MAX_ATTEMPTS {
                        // no responder in budget (air-gap: the sensor is unaffected) — back off, then retry
                        self.fail(now_ms);
                    } else {
                        // Retransmit the SAME datagrams (never rebuild msg1 — that orphans pending).
                        self.egress_cursor = 0;
                        self.attempts += 1;
                        self.last_tx_ms = now_ms;
                    }
                }
            }
            _ => {}
        }
    }

    /// Return the next un-sent msg1 datagram (the drain loop TXes it via gem::tx_frame).
    pub fn poll_egress(&mut self) -> Option<([u8; DGRAM_CAP], usize)> {
        if self.state != CpState::SentMsg1 || self.egress_cursor >= self.egress_n {
            return None;
        }
        let i = self.egress_cursor as usize;
        self.egress_cursor += 1;
        Some((self.egress[i], self.egress_len[i] as usize))
    }

    /// Feed one teed frame. On a complete msg2 → `initiator_read_msg2` → Established (live Session).
    pub fn ingress(&mut self, frame: &[u8], now_ms: i64) {
        if self.state != CpState::SentMsg1 {
            return;
        }
        let payload = match udp_payload_for_port(frame, HS_PORT) {
            Some(p) => p,
            None => return,
        };
        self.seen += 1;
        match self.reasm.feed(payload) {
            Ok(Some(_len)) => {
                let ipend = match self.pending.take() {
                    Some(p) => p,
                    None => {
                        self.fail(now_ms);
                        return;
                    }
                };
                match initiator_read_msg2(ipend, self.reasm.message()) {
                    Ok((session, p2)) => {
                        let p2 = p2.as_slice();
                        if p2.len() == 8 {
                            let mut t = [0u8; 8];
                            t.copy_from_slice(p2);
                            self.tenant = Some(u64::from_le_bytes(t));
                        }
                        if frame.len() >= 30 {
                            self.peer_mac.copy_from_slice(&frame[6..12]);
                            self.peer_ip.copy_from_slice(&frame[26..30]);
                        }
                        if let Some(mut old) = self.session.replace(session) {
                            old.wipe();
                        }
                        self.state = CpState::Established;
                        self.established_at_ms = now_ms;
                        self.fails = 0;
                    }
                    Err(_) => self.fail(now_ms), // a rejected msg2: back off too (never a tight re-handshake loop)
                }
            }
            Ok(None) => {} // more datagrams expected
            Err(()) => self.reasm.reset(), // malformed framing — drop + wait for a clean msg2
        }
    }
}

/// ONE-SHOT: dump the DEV-provisioning MSSP public blob (x_pk ‖ k_ek = 1216 B) as hex, so it can
/// be baked into the device image (`include_bytes!`) byte-identically to what the kernel's ml-kem
/// emits. The host MSSP-sim regenerates the private half from the SAME seeds. Dev/test only.
#[cfg(feature = "securechannel-selftest")]
#[allow(dead_code)]
pub fn dump_provisioned_blob() {
    use boot_abi::sha256;
    let resp = crate::securechannel::ResponderStatic::from_seeds(
        &sha256::digest(b"HEQK-DEV-PROV-mssp-x25519"),
        &sha256::digest(b"HEQK-DEV-PROV-mssp-mlkem-d"),
        &sha256::digest(b"HEQK-DEV-PROV-mssp-mlkem-z"),
    );
    let p = resp.public();
    arch_aarch64::_print(format_args!("[PROVBLOB-BEGIN]"));
    for b in p.x_pk().iter() {
        arch_aarch64::_print(format_args!("{:02x}", b));
    }
    for b in p.k_ek_bytes().iter() {
        arch_aarch64::_print(format_args!("{:02x}", b));
    }
    arch_aarch64::_print(format_args!("[PROVBLOB-END]\n"));
}

/// The [P19-controlplane] QEMU gate: drive the `ControlPlane` INITIATOR through a FULL PQ-hybrid
/// handshake against an IN-KERNEL responder over the exact hand-framed UDP + chunk transport it
/// runs on metal (msg1 chunked into datagrams → responder reassembles + answers msg2 → datagrams
/// → `ingress` reassembles → live Session). Asserts the crossed transport keys match + the state
/// machine reaches Established. Deterministic (test vectors); no smoltcp, no hardware.
#[cfg(feature = "securechannel-selftest")]
pub fn cp_selftest() {
    use crate::securechannel::{responder_read_msg1, responder_write_msg2};
    macro_rules! kprint { ($($t:tt)*) => { arch_aarch64::_print(format_args!($($t)*)) }; }
    let yn = |b: bool| if b { "PASS" } else { "FAIL" };

    let tv = crate::securechannel::test_vectors();
    let resp_pub = tv.resp.public();
    let dev_pk = tv.dev.pk; // needed by the responder to authenticate the device
    let cp_mac = [0x02u8, 0, 0, 0, 0, 0x02];
    let resp_mac = [0x02u8, 0, 0, 0, 0, 0x03];
    let mut cp = ControlPlane::new(resp_pub, tv.dev, cp_mac, [10, 200, 0, 2]);

    // (1) start → msg1 chunked into egress datagrams. (`fresh` hands out the test randomness once.)
    let mut first = Some(tv.irand);
    cp.tick(0, true, &mut || first.take());
    let started = cp.state() == CpState::SentMsg1;

    // (2) drain cp's msg1 datagrams → the responder reassembles the ~2480 B msg1.
    let mut r_reasm = HsReasm::new();
    let mut msg1_dgrams = 0u32;
    let mut msg1_complete = false;
    while let Some((dg, n)) = cp.poll_egress() {
        msg1_dgrams += 1;
        if let Some(framed) = udp_payload_for_port(&dg[..n], HS_PORT) {
            if let Ok(Some(_)) = r_reasm.feed(framed) {
                msg1_complete = true;
            }
        }
    }

    // (3) responder authenticates the device + writes msg2.
    let msg2_ok = if msg1_complete {
        match responder_read_msg1(&tv.resp, &dev_pk, r_reasm.message()) {
            Ok(rpend) => match responder_write_msg2(rpend, &tv.rrand, &0x5445_4E41u64.to_le_bytes()) {
                Some((msg2, rsession)) => {
                    // (4) chunk msg2 into UNICAST-to-cp datagrams → cp.ingress reassembles.
                    hs_chunk(msg2.as_slice(), |framed| {
                        let mut dg = [0u8; DGRAM_CAP];
                        let n = build_hs_datagram(resp_mac, [10, 200, 0, 1], cp_mac, [10, 200, 0, 2], HS_PORT, framed, &mut dg);
                        cp.ingress(&dg[..n], 1);
                        true
                    });
                    // (5) Established + crossed keys match the responder's.
                    let established = cp.established();
                    let keys = match cp.session_mut() {
                        Some(s) => {
                            s.send.key_for_test() == rsession.recv.key_for_test()
                                && s.recv.key_for_test() == rsession.send.key_for_test()
                        }
                        None => false,
                    };
                    // (6) the MSSP-assigned tenant (msg2 payload) + the responder's address were
                    //     learned from the authenticated handshake (unicast export destination).
                    let learned = cp.tenant() == Some(0x5445_4E41) && cp.peer() == (resp_mac, [10, 200, 0, 1]);
                    (established, keys && learned)
                }
                None => (false, false),
            },
            Err(_) => (false, false),
        }
    } else {
        (false, false)
    };

    // (7) REKEY: the session is retired at SESSION_MAX_MS (key wiped) and a SECOND handshake runs with FRESH
    //     ephemerals, giving different transport keys. (8) BACKOFF: an unanswered handshake fails, waits,
    //     and is retried — it used to stay Failed until reboot.
    let k1 = cp.session_mut().map(|s| s.send.key_for_test());
    let t_day = SESSION_MAX_MS + 1;
    cp.tick(t_day, true, &mut || None); // retire: Established -> Idle (no new msg1 in this tick)
    let retired = cp.state() == CpState::Idle && cp.session_mut().is_none() && cp.rekeys == 1;
    let irand2 = crate::securechannel::InitiatorRandomness::from_test_seeds(
        boot_abi::sha256::digest(b"HEQK-rekey-eph-x25519"),
        boot_abi::sha256::digest(b"HEQK-rekey-eph-mlkem-d"),
        boot_abi::sha256::digest(b"HEQK-rekey-eph-mlkem-z"),
        boot_abi::sha256::digest(b"HEQK-rekey-encaps-es-m"),
    );
    let mut second = Some(irand2);
    cp.tick(t_day, true, &mut || second.take());
    let mut r2 = HsReasm::new();
    let mut m1 = false;
    while let Some((dg, n)) = cp.poll_egress() {
        if let Some(framed) = udp_payload_for_port(&dg[..n], HS_PORT) {
            if let Ok(Some(_)) = r2.feed(framed) {
                m1 = true;
            }
        }
    }
    let mut rekeyed = false;
    if m1 {
        if let Ok(rpend) = responder_read_msg1(&tv.resp, &dev_pk, r2.message()) {
            if let Some((msg2, rs)) = responder_write_msg2(rpend, &tv.rrand, &0x5445_4E41u64.to_le_bytes()) {
                hs_chunk(msg2.as_slice(), |framed| {
                    let mut dg = [0u8; DGRAM_CAP];
                    let n = build_hs_datagram(resp_mac, [10, 200, 0, 1], cp_mac, [10, 200, 0, 2], HS_PORT, framed, &mut dg);
                    cp.ingress(&dg[..n], t_day + 10);
                    true
                });
                rekeyed = cp.established()
                    && cp.session_mut().map_or(false, |s| Some(s.send.key_for_test()) != k1 && s.send.key_for_test() == rs.recv.key_for_test());
            }
        }
    }
    // backoff: a third handshake nobody answers -> Failed after MAX_ATTEMPTS, no retry before 30 s, retry after
    let t3 = t_day + 2 * SESSION_MAX_MS;
    cp.tick(t3, true, &mut || None); // retire session 2
    let mut third = Some(crate::securechannel::InitiatorRandomness::from_test_seeds(
        boot_abi::sha256::digest(b"HEQK-b-x"), boot_abi::sha256::digest(b"HEQK-b-d"),
        boot_abi::sha256::digest(b"HEQK-b-z"), boot_abi::sha256::digest(b"HEQK-b-m"),
    ));
    cp.tick(t3, true, &mut || third.take());
    let mut t = t3;
    for _ in 0..MAX_ATTEMPTS + 1 {
        t += RETX_MS;
        cp.tick(t, true, &mut || None);
    }
    let failed = cp.state() == CpState::Failed;
    cp.tick(t + 1_000, true, &mut || None);
    let held = cp.state() == CpState::Failed; // still backing off
    cp.tick(t + RETRY_BASE_MS + 1, true, &mut || None);
    let retried = cp.state() == CpState::Idle; // ready to try again (a fresh draw on the next tick)
    let lifecycle = retired && rekeyed && failed && held && retried;

    let pass = started && msg1_complete && msg2_ok.0 && msg2_ok.1 && lifecycle;
    kprint!(" [P19-controlplane] {} — smoltcp-FREE hand-framed Noise handshake over the single-drain transport: msg1-chunked({} dgrams)+started={} responder-reassembled-msg1={} Established={} crossed-keys-match+tenant/peer-learned={} | session lifecycle: retired at 24 h with key wiped={} re-handshake with FRESH ephemerals -> new keys={} unanswered handshake fails={} backs off={} retries={}\n",
        yn(pass), msg1_dgrams, yn(started), yn(msg1_complete), yn(msg2_ok.0), yn(msg2_ok.1), yn(retired), yn(rekeyed), yn(failed), yn(held), yn(retried));
}
