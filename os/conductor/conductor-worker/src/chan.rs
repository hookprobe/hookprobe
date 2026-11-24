// SPDX-License-Identifier: AGPL-3.0-only
//! The worker's channel to its paired device: heqk's own PQ-hybrid Noise handshake
//! (`Noise_HTP2hybrid_25519+MLKEM768_ChaChaPoly_SHA256`, the kernel's `securechannel.rs` linked as is),
//! carried over TCP with length-prefixed frames, then AEAD records with anti-replay.
//!
//! The device is the initiator and authenticates with its channel identity (SRK-derived Ed25519); the
//! worker is the responder with its pinned static (X25519 ‖ ML-KEM-768). The handshake hash is the session
//! binding every HP-EXEC capability must name, so a capability captured on one session is useless on another.

use crate::entropy::EntropySource;
use crate::securechannel::{
    initiator_read_msg2, initiator_write_msg1, responder_read_msg1_with, responder_write_msg2, InitiatorRandomness,
    NoiseErr, RecordRx, RecordTx, RekeyPolicy, ResponderPub, ResponderRandomness, ResponderStatic, HS_MSG_MAX,
};
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::time::Instant;

/// Associated data of every Conductor record (domain separation from other users of the channel code).
pub const AD: &[u8] = b"hookprobe/conductor/chan/v1";
/// Largest plaintext message (an EXEC: 398 B capability + an 8 KiB request frame, with room to spare).
pub const MAX_MSG: usize = 16 * 1024;
const AEAD_OVERHEAD: usize = 8 + 16;
/// The responder's msg2 payload: names the service so a Conductor worker can never be mistaken for a PoP.
pub const SERVICE: &[u8] = b"hookprobe-conductor-worker/v1";

/// Message kinds inside the encrypted channel.
pub mod kind {
    pub const QUOTE_REQ: u8 = 1;
    pub const EXEC: u8 = 2;
    pub const EPOCH: u8 = 3;
    pub const BYE: u8 = 4;
    pub const QUOTE: u8 = 0x81;
    pub const RESPONSE: u8 = 0x82;
    pub const REFUSE: u8 = 0x83;
    pub const EPOCH_OK: u8 = 0x84;
}

#[derive(Debug)]
pub enum ChanError {
    Io(io::Error),
    Noise(NoiseErr),
    TooLarge,
    Entropy,
    Handshake,
}

impl From<io::Error> for ChanError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

impl std::fmt::Display for ChanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

fn write_frame(s: &mut TcpStream, b: &[u8]) -> io::Result<()> {
    let n = u32::try_from(b.len()).map_err(|_| io::Error::other("frame too large"))?;
    let mut out = Vec::with_capacity(4 + b.len());
    out.extend_from_slice(&n.to_le_bytes());
    out.extend_from_slice(b);
    s.write_all(&out)
}

fn read_frame(s: &mut TcpStream, max: usize) -> Result<Vec<u8>, ChanError> {
    let mut n = [0u8; 4];
    s.read_exact(&mut n)?;
    let n = u32::from_le_bytes(n) as usize;
    if n > max {
        return Err(ChanError::TooLarge);
    }
    let mut b = vec![0u8; n];
    s.read_exact(&mut b)?;
    Ok(b)
}

pub struct Chan {
    stream: TcpStream,
    tx: RecordTx,
    rx: RecordRx,
    /// The handshake transcript hash: HP-EXEC's `session_binding`.
    pub binding: [u8; 32],
    start: Instant,
}

impl Chan {
    fn now(&self) -> i64 {
        i64::try_from(self.start.elapsed().as_millis()).unwrap_or(i64::MAX)
    }

    /// Worker side: accept a handshake from the ONE paired device identity.
    pub fn accept(
        mut stream: TcpStream,
        resp: &ResponderStatic,
        paired_identity: &[u8; 32],
        ent: &mut dyn EntropySource,
    ) -> Result<Chan, ChanError> {
        let msg1 = read_frame(&mut stream, HS_MSG_MAX)?;
        let pend = responder_read_msg1_with(resp, |id| boot_abi::kdf::ct_eq(id, paired_identity), &msg1).map_err(ChanError::Noise)?;
        let rnd = ResponderRandomness::from_entropy(ent).map_err(|_| ChanError::Entropy)?;
        let (msg2, session) = responder_write_msg2(pend, &rnd, SERVICE).ok_or(ChanError::Handshake)?;
        write_frame(&mut stream, msg2.as_slice())?;
        let tx = RecordTx::new(session.send.clone(), 0, RekeyPolicy::DEFAULT);
        let rx = session.recv.into_record_rx();
        Ok(Chan { stream, tx, rx, binding: session.handshake_hash, start: Instant::now() })
    }

    /// Device side (the device simulator and tests): initiate to a pinned worker.
    pub fn connect(
        mut stream: TcpStream,
        device: &ed25519_compact::KeyPair,
        worker: &ResponderPub,
        ent: &mut dyn EntropySource,
    ) -> Result<Chan, ChanError> {
        let rnd = InitiatorRandomness::from_entropy(ent).map_err(|_| ChanError::Entropy)?;
        let (msg1, pend) = initiator_write_msg1(device, worker, &rnd, b"").ok_or(ChanError::Handshake)?;
        write_frame(&mut stream, msg1.as_slice())?;
        let msg2 = read_frame(&mut stream, HS_MSG_MAX)?;
        let (session, payload) = initiator_read_msg2(pend, &msg2).map_err(ChanError::Noise)?;
        if payload.as_slice() != SERVICE {
            return Err(ChanError::Handshake);
        }
        let tx = RecordTx::new(session.send.clone(), 0, RekeyPolicy::DEFAULT);
        let rx = session.recv.into_record_rx();
        Ok(Chan { stream, tx, rx, binding: session.handshake_hash, start: Instant::now() })
    }

    pub fn send(&mut self, kind: u8, payload: &[u8]) -> Result<(), ChanError> {
        if payload.len() >= MAX_MSG {
            return Err(ChanError::TooLarge);
        }
        let mut pt = Vec::with_capacity(1 + payload.len());
        pt.push(kind);
        pt.extend_from_slice(payload);
        let mut out = vec![0u8; pt.len() + AEAD_OVERHEAD];
        let now = self.now();
        let n = self.tx.seal(AD, &pt, &mut out, now).ok_or(ChanError::Handshake)?;
        out.truncate(n);
        write_frame(&mut self.stream, &out)?;
        Ok(())
    }

    pub fn recv(&mut self) -> Result<(u8, Vec<u8>), ChanError> {
        let rec = read_frame(&mut self.stream, MAX_MSG + AEAD_OVERHEAD)?;
        let mut pt = vec![0u8; rec.len()];
        let now = self.now();
        let n = self.rx.open(AD, &rec, &mut pt, now).map_err(ChanError::Noise)?;
        pt.truncate(n);
        if pt.is_empty() {
            return Err(ChanError::Handshake);
        }
        let kind = pt.remove(0);
        Ok((kind, pt))
    }

    pub fn set_timeout(&self, d: Option<std::time::Duration>) -> io::Result<()> {
        self.stream.set_read_timeout(d)?;
        self.stream.set_write_timeout(d)
    }
}

/// Raw access for adversarial tests (send bytes that bypass the record layer).
impl Chan {
    pub fn raw_stream(&mut self) -> &mut TcpStream {
        &mut self.stream
    }
}
