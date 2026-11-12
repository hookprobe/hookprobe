//! Host build of the kernel's secure-channel module (`securechannel.rs`, via `#[path]`, not a copy) for fuzzing the
//! datagram record layer: `RecordRx::open` (key epoch from the sequence, per-epoch replay windows, authenticated
//! epoch advance, previous-key retirement) and the legacy `AntiReplayRx::open_record`. The deterministic test
//! handshake (the kernel's own test vectors) supplies real crossed transport keys.
#![allow(dead_code, unused_imports)]

#[path = "../../../../onboarding/enrollment/responder-sim/src/entropy.rs"]
pub mod entropy;
#[path = "../../../../os/kernel/kernel/src/securechannel.rs"]
pub mod securechannel;

use securechannel::*;

/// (device session, responder session) from one deterministic handshake.
pub fn sessions() -> (Session, Session) {
    let tv = test_vectors();
    let (m1, ip) = initiator_write_msg1(&tv.dev, &tv.resp.public(), &tv.irand, b"fuzz").expect("msg1");
    let rp = responder_read_msg1(&tv.resp, &tv.dev.pk, m1.as_slice()).expect("read msg1");
    let (m2, rs) = responder_write_msg2(rp, &tv.rrand, b"fuzz").expect("msg2");
    let (is, _) = initiator_read_msg2(ip, m2.as_slice()).expect("read msg2");
    (is, rs)
}
