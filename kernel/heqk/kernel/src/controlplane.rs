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
        }
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
        self.egress_n = 0;
        let ok = hs_chunk(msg1.as_slice(), |framed| {
            let i = self.egress_n as usize;
            if i >= HS_MAX_CHUNKS {
                return false;
            }
            let n = build_hs_datagram(mac, ip, [0xff; 6], [255, 255, 255, 255], HS_PORT, framed, &mut self.egress[i]);
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

    /// Heartbeat driver: start the handshake when link is up; bounded retransmit of msg1.
    pub fn tick(&mut self, now_ms: i64, link_up: bool, rnd: &InitiatorRandomness) {
        match self.state {
            CpState::Idle => {
                if link_up && self.start(rnd) {
                    self.attempts = 1;
                    self.last_tx_ms = now_ms;
                }
            }
            CpState::SentMsg1 => {
                if now_ms - self.last_tx_ms >= RETX_MS {
                    if self.attempts >= MAX_ATTEMPTS {
                        self.state = CpState::Failed; // no responder in-budget (air-gap: sensor unaffected)
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
    pub fn ingress(&mut self, frame: &[u8], _now_ms: i64) {
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
                        self.state = CpState::Failed;
                        return;
                    }
                };
                match initiator_read_msg2(ipend, self.reasm.message()) {
                    Ok((session, _p2)) => {
                        self.session = Some(session);
                        self.state = CpState::Established;
                    }
                    Err(_) => self.state = CpState::Failed,
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

    // (1) start → msg1 chunked into egress datagrams.
    cp.tick(0, true, &tv.irand);
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
            Ok(rpend) => match responder_write_msg2(rpend, &tv.rrand, b"TENANT42") {
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
                    (established, keys)
                }
                None => (false, false),
            },
            Err(_) => (false, false),
        }
    } else {
        (false, false)
    };

    let pass = started && msg1_complete && msg2_ok.0 && msg2_ok.1;
    kprint!(" [P19-controlplane] {} — smoltcp-FREE hand-framed Noise handshake over the single-drain transport: msg1-chunked({} dgrams)+started={} responder-reassembled-msg1={} Established={} crossed-keys-match={}\n",
        yn(pass), msg1_dgrams, yn(started), yn(msg1_complete), yn(msg2_ok.0), yn(msg2_ok.1));
}
