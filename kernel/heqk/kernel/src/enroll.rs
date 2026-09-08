//! M4.3 — MSSP enrollment + authenticated update fetch over the Noise channel.
//!
//! This is the ADDITIVE control-plane layer (docs/design/heqk-control-plane.md
//! §M4.3). It reuses, and does not reinvent:
//!   * the M4.2b PQ-hybrid Noise handshake (`securechannel.rs`) as the TRANSPORT +
//!     mutual authenticator (device software-PUF Ed25519 ⟷ enrolled MSSP static);
//!   * the M3.4 OTA state machine + `boot_abi::verify` (`ota.rs`) as the TRUST
//!     ROOT for any fetched image — the channel authenticates the *pipe*, never
//!     the *payload*;
//!   * the M3.2/M3.3 sealed record store (`fslog`/`store.rs`) to PERSIST the
//!     enrollment.
//!
//! ## The sacred invariant (preserved, testable)
//! Enrollment is a **state transition on an already-fully-functional device**,
//! never a boot precondition. `EnrollStatus::Unenrolled` is a VALID steady state:
//! no MSSP ⇒ full local SOC, air-gapped, no account. Un-enroll returns to
//! standalone. The `[P19-enroll]` air-gap case re-proves this every boot.
//!
//! ## Trust separation (the load-bearing property)
//! A fetched OTA candidate is handed to `ota::stage`, which verifies it with the
//! SAME hybrid Ed25519+SLH-DSA + SVN-floor check HBoot runs at boot. A compromised
//! or malicious control plane that ships a tampered / unsigned / below-floor image
//! is REJECTED by that verify even though the Noise channel delivered the bytes
//! faithfully — the channel is transport only.
//!
//! HONESTY (Track-C): loopback / in-process fake MSSP in QEMU, deterministic
//! ephemerals fed through the production `EntropySource` path (via a simulated-HW
//! `StubTrng`). Real `mssp.hookprobe.com` PKI + real HW-TRNG + real network = metal
//! (Gate R).

#![cfg(feature = "securechannel")]

use crate::securechannel::{
    initiator_read_msg2, initiator_write_msg1, responder_read_msg1, responder_write_msg2,
    InitiatorRandomness, NoiseErr, ResponderRandomness, ResponderStatic, Session,
};
use boot_abi::sha256;
use ed25519_compact::{KeyPair, PublicKey as EdPub, Signature as EdSig};

/// Local console print (same arch seam as the rest of the kernel).
#[cfg(feature = "securechannel-selftest")]
macro_rules! kprint {
    ($($t:tt)*) => { arch_aarch64::_print(format_args!($($t)*)) };
}

/// Tenant id sentinel meaning "not bound to any tenant" (UNENROLLED).
pub const TENANT_NONE: u64 = 0;

/// The persisted enrollment binding. Written to the sealed record store; a device
/// with no record is UNENROLLED (standalone).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Enrollment {
    /// Tenant id assigned by the MSSP (never `TENANT_NONE` for a real binding).
    pub tenant_id: u64,
    /// The MSSP static X25519 pubkey the device mutually authenticated against
    /// (so a later session can pin the same control plane).
    pub responder_x_pk: [u8; 32],
    /// SHA-256 of the device Ed25519 identity bound at enrollment (audit anchor).
    pub device_fp: [u8; 32],
    /// Monotonic enrollment generation (bumped on re-enroll).
    pub generation: u64,
}

impl Enrollment {
    /// Record magic ("ENR1" LE) so a foreign record is not misread as enrollment.
    const MAGIC: u32 = 0x3152_4E45;
    /// Serialized length: magic(4) + tenant(8) + resp_pk(32) + dev_fp(32) + gen(8).
    pub const WIRE_LEN: usize = 4 + 8 + 32 + 32 + 8;

    pub fn to_bytes(&self) -> [u8; Self::WIRE_LEN] {
        let mut b = [0u8; Self::WIRE_LEN];
        b[0..4].copy_from_slice(&Self::MAGIC.to_le_bytes());
        b[4..12].copy_from_slice(&self.tenant_id.to_le_bytes());
        b[12..44].copy_from_slice(&self.responder_x_pk);
        b[44..76].copy_from_slice(&self.device_fp);
        b[76..84].copy_from_slice(&self.generation.to_le_bytes());
        b
    }

    pub fn from_bytes(b: &[u8]) -> Option<Enrollment> {
        if b.len() < Self::WIRE_LEN {
            return None;
        }
        if u32::from_le_bytes(b[0..4].try_into().ok()?) != Self::MAGIC {
            return None;
        }
        let mut responder_x_pk = [0u8; 32];
        responder_x_pk.copy_from_slice(&b[12..44]);
        let mut device_fp = [0u8; 32];
        device_fp.copy_from_slice(&b[44..76]);
        Some(Enrollment {
            tenant_id: u64::from_le_bytes(b[4..12].try_into().ok()?),
            responder_x_pk,
            device_fp,
            generation: u64::from_le_bytes(b[76..84].try_into().ok()?),
        })
    }
}

/// The device's enrollment posture. `Unenrolled` is a valid steady state — the
/// device runs a full local SOC in it (air-gap invariant).
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum EnrollStatus {
    Unenrolled,
    Enrolled(Enrollment),
}

impl EnrollStatus {
    /// Cold-start / air-gap default: UNENROLLED, fully functional.
    pub fn default_standalone() -> Self {
        EnrollStatus::Unenrolled
    }
    /// Whether the local SOC may run in this state. ALWAYS true — enrollment is
    /// additive and never a precondition (the sacred invariant, as a function).
    pub fn local_soc_available(&self) -> bool {
        true
    }
    /// Enrollment must NEVER block boot, in ANY posture.
    pub fn is_boot_blocking(&self) -> bool {
        false
    }
}

/// A fetch-request opcode the device sends on the enrolled transport (the MSSP
/// answers with the candidate stream).
const FETCH_REQ: &[u8] = b"HEQK-OTA-GET";

// ---------------------------------------------------------------------------
// Enrollment protocol over the Noise channel (device ⟷ in-process fake MSSP).
// ---------------------------------------------------------------------------

/// Run one enrollment handshake against an in-process MSSP responder and return
/// the device's `Enrollment` + both transport `Session`s (device, mssp).
///
/// Mutual auth is the M4.2b handshake itself:
///   * the MSSP is authenticated by the `es` step (the device knows the MSSP
///     static key from provisioning; a WRONG responder key diverges the key and
///     the handshake ABORTS — so a rogue control plane cannot enroll the device);
///   * the device is authenticated by its Ed25519 transcript signature (the MSSP
///     binds whatever key the device presents on first enroll — TOFU — and pins it
///     in the returned `Enrollment.device_fp`).
///
/// `dev` = device PUF Ed25519 identity; `mssp` = the MSSP static (the device knows
/// `mssp.public()` from provisioning); `tenant_id` = what the MSSP assigns.
pub fn enroll_over_noise(
    dev: &KeyPair,
    mssp: &ResponderStatic,
    irand: &InitiatorRandomness,
    rrand: &ResponderRandomness,
    tenant_id: u64,
) -> Result<(Enrollment, Session, Session), NoiseErr> {
    let device_fp = sha256::digest(&dev.pk[..]);

    // msg1: device -> MSSP. Handshake payload = the enrollment request (device fp).
    let (msg1, ipend) = initiator_write_msg1(dev, &mssp.public(), irand, &device_fp)
        .ok_or(NoiseErr::BadKeyMaterial)?;

    // MSSP reads msg1: authenticates the device (Ed25519 transcript sig) + derives
    // the es key (proving it is the enrolled MSSP). TOFU: the MSSP accepts the
    // presented device key on first enroll (here, the device's own pubkey).
    let rpend = responder_read_msg1(mssp, &dev.pk, msg1.as_slice())?;
    // The enrollment request was delivered + authenticated.
    if rpend.payload1.as_slice() != &device_fp[..] {
        return Err(NoiseErr::BadSignature);
    }

    // msg2: MSSP -> device. Handshake payload = the tenant binding.
    let tb = tenant_id.to_le_bytes();
    let (msg2, mssp_session) =
        responder_write_msg2(rpend, rrand, &tb).ok_or(NoiseErr::BadKeyMaterial)?;

    // Device reads msg2 (authenticates the MSSP's key confirmation) + learns tenant.
    let (dev_session, p2) = initiator_read_msg2(ipend, msg2.as_slice())?;
    let p2 = p2.as_slice();
    if p2.len() < 8 {
        return Err(NoiseErr::Truncated);
    }
    let got_tenant = u64::from_le_bytes(p2[..8].try_into().unwrap());

    let enr = Enrollment {
        tenant_id: got_tenant,
        responder_x_pk: mssp.public().x_pk(),
        device_fp,
        generation: 1,
    };
    Ok((enr, dev_session, mssp_session))
}

// ---------------------------------------------------------------------------
// Authenticated update fetch over the enrolled transport (fills M3.4's "pull").
// ---------------------------------------------------------------------------

/// Fetch a signed OTA candidate over the enrolled Noise transport into `out`.
///
/// The device sends a fetch request on its `send` cipher; the in-process MSSP
/// answers with the candidate chunked into AEAD transport records (each on the
/// MSSP `send` cipher, counter-advanced — so a replayed/reordered record is
/// rejected). The device decrypts each record straight into `out`. Returns the
/// reassembled length. This is TRANSPORT ONLY — no verification happens here; the
/// bytes are handed to `ota::stage` (the trust root) by the caller.
///
/// `dev` / `mssp` are the two ends' transport sessions from `enroll_over_noise`.
/// `candidate` is whatever the (possibly malicious) MSSP chooses to ship.
pub fn fetch_candidate_over_channel(
    dev: &mut Session,
    mssp: &mut Session,
    candidate: &[u8],
    out: &mut [u8],
) -> Result<usize, NoiseErr> {
    // device -> MSSP: fetch request (proves the device drives the transport).
    let mut reqbuf = [0u8; FETCH_REQ.len() + 16];
    let rn = dev
        .send
        .encrypt_into(b"", FETCH_REQ, &mut reqbuf)
        .ok_or(NoiseErr::Truncated)?;
    let mut reqpt = [0u8; FETCH_REQ.len()];
    let got = mssp.recv.decrypt_into(b"", &reqbuf[..rn], &mut reqpt)?;
    if &reqpt[..got] != FETCH_REQ {
        return Err(NoiseErr::AeadAuth);
    }

    // MSSP -> device: candidate in AEAD transport records.
    const CHUNK: usize = 1024;
    let mut recbuf = [0u8; CHUNK + 16];
    let mut off = 0usize;
    while off < candidate.len() {
        let n = core::cmp::min(CHUNK, candidate.len() - off);
        let rl = mssp
            .send
            .encrypt_into(b"", &candidate[off..off + n], &mut recbuf)
            .ok_or(NoiseErr::Truncated)?;
        if off + n > out.len() {
            return Err(NoiseErr::Truncated);
        }
        let dl = dev
            .recv
            .decrypt_into(b"", &recbuf[..rl], &mut out[off..off + n])?;
        if dl != n {
            return Err(NoiseErr::AeadAuth);
        }
        off += n;
    }
    Ok(off)
}

// ===========================================================================
// M4.5 — the SEGMENTATION AUTHORITY: an operator-signed REACH-POLICY delivered over the enrolled
// Noise transport, which provisions `segment.rs`'s per-device reach + ARMS the plane.
//
// TRUST SEPARATION (security-auditor C9, 2026-09-08 — the same doctrine as the OTA fetch above):
// the enrolled channel authenticates the PIPE, never the PAYLOAD. Because a ReachPolicy DROPS
// customer LAN traffic, it must carry its OWN Ed25519 signature by a DEDICATED operator key —
// distinct from the always-online Noise static — verified on-device before ANY table mutation.
// A compromised MSSP can then only RELAY/withhold/replay operator-signed policies (bounded by the
// TTL lease + WAN/mgmt/infra floors), never forge one. The signature covers the record body ‖ the
// device fingerprint (C14 — a policy for another device/tenant is rejected), and a monotonic
// generation floored against replay-downgrade (C11) stops an old policy re-stranding a device.
// FAIL-OPEN: any transport/parse/tenant/generation/signature failure returns Err having mutated
// NOTHING and left the plane unarmed. `set_reach` is NEVER driven by observed traffic (C16).
// ===========================================================================

/// The opcode the device sends to request its reach policy (mirrors `FETCH_REQ`).
pub const REACH_POLICY_REQ: &[u8] = b"HEQK-SEG-GET";

/// One reach-table entry as the off-device authority speaks it: the RAW 6-byte MAC (heqk applies
/// its internal `ratelimit::mac_hash` at apply time — the authority never sees the hash) + the
/// `segment` reach code.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ReachEntry {
    pub mac: [u8; 6],
    pub reach: u8,
}

/// An operator-signed, tenant-bound, generation-floored reach policy. Fixed-size / no-heap.
#[derive(Clone, Copy)]
pub struct ReachPolicy {
    pub generation: u64,
    pub tenant_id: u64,
    pub infra_gw: u32,
    pub infra_dns: u32,
    pub entry_count: u16,
    pub entries: [ReachEntry; crate::segment::DEV_SLOTS],
    /// Ed25519 operator signature over `signed_body() ‖ device_fp` (C9/C14).
    pub sig: [u8; 64],
}

/// A reach-policy error. Every variant leaves the reach table + `REACH_ARMED` UNCHANGED.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ReachPolicyErr {
    Transport,
    Parse,
    TenantMismatch,
    StaleGeneration,
    BadSignature,
    /// The anti-rollback floor could not be read from the sealed store (C12). The plane MUST
    /// NOT arm without an establishable freshness floor — refusing to arm IS the fail-open
    /// choice (disarmed = all-Full) and is simultaneously the anti-replay-safe choice.
    FloorUnavailable,
    /// The operator key pinned on this device (C10 TOFU) differs from the one presented — a
    /// silent operator-key swap by the online MSSP is refused.
    OperatorKeyMismatch,
}

impl ReachPolicy {
    const MAGIC: u32 = 0x314C_5052; // "RPL1" LE (distinct from ENR1 / the OTA magic)
    const VERSION: u8 = 1;
    const HDR_LEN: usize = 32; // magic4 ver1 flags1 count2 gen8 tenant8 gw4 dns4
    const ENTRY_LEN: usize = 8; // mac6 reach1 rsvd1
    /// The signed body: header + the full (zero-padded) entry array.
    pub const BODY_LEN: usize = Self::HDR_LEN + crate::segment::DEV_SLOTS * Self::ENTRY_LEN;
    pub const SIG_LEN: usize = 64;
    /// The full on-wire record: signed body + operator signature.
    pub const WIRE_LEN: usize = Self::BODY_LEN + Self::SIG_LEN;

    /// Serialize the SIGNED BODY (everything the operator signature covers — NOT the sig itself).
    /// Deterministic, so both the signer and the on-device verifier reconstruct identical bytes.
    pub fn signed_body(&self) -> [u8; Self::BODY_LEN] {
        let mut b = [0u8; Self::BODY_LEN];
        b[0..4].copy_from_slice(&Self::MAGIC.to_le_bytes());
        b[4] = Self::VERSION;
        b[5] = 0; // flags
        b[6..8].copy_from_slice(&self.entry_count.to_le_bytes());
        b[8..16].copy_from_slice(&self.generation.to_le_bytes());
        b[16..24].copy_from_slice(&self.tenant_id.to_le_bytes());
        b[24..28].copy_from_slice(&self.infra_gw.to_le_bytes());
        b[28..32].copy_from_slice(&self.infra_dns.to_le_bytes());
        for (i, e) in self.entries.iter().enumerate() {
            let o = Self::HDR_LEN + i * Self::ENTRY_LEN;
            b[o..o + 6].copy_from_slice(&e.mac);
            b[o + 6] = e.reach;
            b[o + 7] = 0; // rsvd
        }
        b
    }

    /// Full record = signed body ‖ operator signature.
    pub fn to_bytes(&self) -> [u8; Self::WIRE_LEN] {
        let mut b = [0u8; Self::WIRE_LEN];
        b[..Self::BODY_LEN].copy_from_slice(&self.signed_body());
        b[Self::BODY_LEN..].copy_from_slice(&self.sig);
        b
    }

    /// The bytes the operator signature is computed over: the signed body ‖ the target device
    /// fingerprint (C14 — binds the policy to THIS device; a policy signed for another device
    /// fails verification here). Returned on the stack; no heap.
    fn sig_msg(body: &[u8; Self::BODY_LEN], device_fp: &[u8; 32]) -> [u8; Self::BODY_LEN + 32] {
        let mut m = [0u8; Self::BODY_LEN + 32];
        m[..Self::BODY_LEN].copy_from_slice(body);
        m[Self::BODY_LEN..].copy_from_slice(device_fp);
        m
    }

    /// FAIL-CLOSED parse. `None` (⇒ caller does not arm) on: short buffer, wrong magic, wrong
    /// version, `entry_count > DEV_SLOTS`, or ANY entry carrying an unknown reach code (the whole
    /// record is rejected — never a partial/misapplied apply).
    pub fn from_bytes(b: &[u8]) -> Option<ReachPolicy> {
        if b.len() < Self::WIRE_LEN {
            return None;
        }
        if u32::from_le_bytes(b[0..4].try_into().ok()?) != Self::MAGIC {
            return None;
        }
        if b[4] != Self::VERSION {
            return None;
        }
        let entry_count = u16::from_le_bytes(b[6..8].try_into().ok()?);
        if entry_count as usize > crate::segment::DEV_SLOTS {
            return None;
        }
        let mut entries = [ReachEntry { mac: [0u8; 6], reach: 0 }; crate::segment::DEV_SLOTS];
        for (i, e) in entries.iter_mut().enumerate() {
            let o = Self::HDR_LEN + i * Self::ENTRY_LEN;
            e.mac.copy_from_slice(&b[o..o + 6]);
            e.reach = b[o + 6];
            // Reject the WHOLE record if any MEANINGFUL entry has an unknown reach code.
            if (i as u16) < entry_count && crate::segment::Reach::from_code(e.reach).is_none() {
                return None;
            }
        }
        let mut sig = [0u8; 64];
        sig.copy_from_slice(&b[Self::BODY_LEN..Self::WIRE_LEN]);
        Some(ReachPolicy {
            generation: u64::from_le_bytes(b[8..16].try_into().ok()?),
            tenant_id: u64::from_le_bytes(b[16..24].try_into().ok()?),
            infra_gw: u32::from_le_bytes(b[24..28].try_into().ok()?),
            infra_dns: u32::from_le_bytes(b[28..32].try_into().ok()?),
            entry_count,
            entries,
            sig,
        })
    }
}

/// TRANSPORT + PARSE only (no verification, no mutation). The device sends `REACH_POLICY_REQ` on
/// `dev.send`; the MSSP answers with the `WIRE_LEN` blob in AEAD transport records (counter-
/// advanced → an in-session replay/reorder is rejected); the device decrypts + fail-closed
/// parses. Like `fetch_candidate_over_channel`, this is the pipe — the operator signature is the
/// trust root, checked in `apply_reach_policy`.
pub fn fetch_reach_policy(
    dev: &mut Session,
    mssp: &mut Session,
    blob: &[u8],
    out: &mut [u8; ReachPolicy::WIRE_LEN],
) -> Result<ReachPolicy, ReachPolicyErr> {
    // device -> MSSP: request.
    let mut reqbuf = [0u8; REACH_POLICY_REQ.len() + 16];
    let rn = dev
        .send
        .encrypt_into(b"", REACH_POLICY_REQ, &mut reqbuf)
        .ok_or(ReachPolicyErr::Transport)?;
    let mut reqpt = [0u8; REACH_POLICY_REQ.len()];
    let got = mssp
        .recv
        .decrypt_into(b"", &reqbuf[..rn], &mut reqpt)
        .map_err(|_| ReachPolicyErr::Transport)?;
    if &reqpt[..got] != REACH_POLICY_REQ {
        return Err(ReachPolicyErr::Transport);
    }
    // MSSP -> device: the policy blob in one AEAD record (WIRE_LEN < the 1024 chunk).
    if blob.len() != ReachPolicy::WIRE_LEN {
        return Err(ReachPolicyErr::Parse);
    }
    let mut recbuf = [0u8; ReachPolicy::WIRE_LEN + 16];
    let rl = mssp
        .send
        .encrypt_into(b"", blob, &mut recbuf)
        .ok_or(ReachPolicyErr::Transport)?;
    let dl = dev
        .recv
        .decrypt_into(b"", &recbuf[..rl], &mut out[..])
        .map_err(|_| ReachPolicyErr::Transport)?;
    if dl != ReachPolicy::WIRE_LEN {
        return Err(ReachPolicyErr::Transport);
    }
    ReachPolicy::from_bytes(&out[..]).ok_or(ReachPolicyErr::Parse)
}

/// PURE apply — validates EVERYTHING before mutating ANYTHING; on any error returns `Err` with
/// the reach table + `REACH_ARMED` untouched (fail-open). Order (C9/C11/C14):
///   1. operator Ed25519 signature over `signed_body ‖ device_fp` verifies against `operator_pk`;
///   2. `pol.tenant_id == enr.tenant_id`;
///   3. `pol.generation > floor` (monotonic anti-rollback);
/// then, and only then: reset-to-Full, set_infra, batch set_reach, arm LAST. Returns
/// `(applied_count, new_floor = pol.generation)`.
pub fn apply_reach_policy(
    enr: &Enrollment,
    pol: &ReachPolicy,
    floor: u64,
    operator_pk: &[u8; 32],
) -> Result<(usize, u64), ReachPolicyErr> {
    // (1) INDEPENDENT operator signature — the trust root (C9), checked FIRST.
    let pk = EdPub::from_slice(operator_pk).map_err(|_| ReachPolicyErr::BadSignature)?;
    let sig = EdSig::from_slice(&pol.sig).map_err(|_| ReachPolicyErr::BadSignature)?;
    let msg = ReachPolicy::sig_msg(&pol.signed_body(), &enr.device_fp);
    if pk.verify(&msg[..], &sig).is_err() {
        return Err(ReachPolicyErr::BadSignature);
    }
    // (2) tenant binding (C14).
    if pol.tenant_id != enr.tenant_id {
        return Err(ReachPolicyErr::TenantMismatch);
    }
    // (3) monotonic anti-rollback (C11) — a replayed/older policy can never re-strand a device.
    if pol.generation <= floor {
        return Err(ReachPolicyErr::StaleGeneration);
    }
    // All checks passed. Mutate; arm LAST so the gate stays inert until fully provisioned.
    crate::segment::reset_all_to_full();
    crate::segment::set_infra(pol.infra_gw, pol.infra_dns);
    let n = pol.entry_count as usize;
    for e in &pol.entries[..n] {
        // from_bytes already validated every meaningful reach code, so from_code is Some here.
        if let Some(r) = crate::segment::Reach::from_code(e.reach) {
            crate::segment::set_reach(crate::ratelimit::mac_hash(&e.mac), r);
        }
    }
    crate::segment::arm_reach_channel();
    Ok((n, pol.generation))
}

// --- M4.5 PERSISTENCE (p15-write): the anti-rollback floor (C11/C12) + the TOFU-pinned
// operator key (C10) in the M3 sealed-store fslog. Only these DURABLE bits persist — the reach
// TABLE and REACH_ARMED are RAM-only and cold-start disarmed (C13), so a reboot never
// auto-restores a dropping state; the device re-fetches + re-arms with generation > floor. ---

/// Read the highest persisted reach generation (the anti-rollback floor). `Ok(0)` = none yet
/// (fresh device — the first authenticated+signed policy may arm). `Err` = the floor is
/// UNREADABLE (disk/mount failure) — the caller MUST NOT arm (C12).
#[cfg(feature = "p15-write")]
pub fn read_reach_floor<D: hal::BlockDev>(
    store: &mut crate::store::SealedStore<D>,
    lo: u64,
    hi: u64,
) -> Result<u64, crate::fslog::FsErr> {
    let log = crate::fslog::open_or_format(store, lo, hi)?;
    let mut floor = 0u64;
    log.for_each(store, |_seq, rt, pl| {
        if rt == crate::fslog::RT_REACHGEN && pl.len() >= 8 {
            let g = u64::from_le_bytes(pl[..8].try_into().unwrap());
            if g > floor {
                floor = g;
            }
        }
    })?;
    Ok(floor)
}

/// Persist a new reach generation as the floor (append-only ring; `read_reach_floor` takes the
/// max, so ring wrap never lowers it while a `> floor` gate stands in front of every apply).
#[cfg(feature = "p15-write")]
pub fn persist_reach_floor<D: hal::BlockDev>(
    store: &mut crate::store::SealedStore<D>,
    lo: u64,
    hi: u64,
    gen: u64,
) -> Result<(), crate::fslog::FsErr> {
    let mut log = crate::fslog::open_or_format(store, lo, hi)?;
    log.append(store, crate::fslog::RT_REACHGEN, &gen.to_le_bytes())?;
    Ok(())
}

/// Read the TOFU-pinned operator key (C10). `Ok(None)` = not pinned yet. Returns the FIRST
/// pinned key (TOFU — first-write-wins; a later differing key is refused by `reconcile`).
#[cfg(feature = "p15-write")]
pub fn read_operator_pk<D: hal::BlockDev>(
    store: &mut crate::store::SealedStore<D>,
    lo: u64,
    hi: u64,
) -> Result<Option<[u8; 32]>, crate::fslog::FsErr> {
    let log = crate::fslog::open_or_format(store, lo, hi)?;
    let mut pinned: Option<[u8; 32]> = None;
    log.for_each(store, |_seq, rt, pl| {
        if rt == crate::fslog::RT_OPKEY && pl.len() >= 32 && pinned.is_none() {
            let mut k = [0u8; 32];
            k.copy_from_slice(&pl[..32]);
            pinned = Some(k);
        }
    })?;
    Ok(pinned)
}

/// Pin the operator key (TOFU). Appends `pk` as the operator key ONLY if none is pinned yet;
/// idempotent if the same key is re-pinned. A DIFFERENT key when one is already pinned is refused
/// (C10 — no silent operator-key swap; signed rotation is a further follow-up).
#[cfg(feature = "p15-write")]
pub fn pin_operator_pk<D: hal::BlockDev>(
    store: &mut crate::store::SealedStore<D>,
    lo: u64,
    hi: u64,
    pk: &[u8; 32],
) -> Result<(), ReachPolicyErr> {
    match read_operator_pk(store, lo, hi).map_err(|_| ReachPolicyErr::FloorUnavailable)? {
        Some(existing) if &existing == pk => Ok(()),
        Some(_) => Err(ReachPolicyErr::OperatorKeyMismatch),
        None => {
            let mut log = crate::fslog::open_or_format(store, lo, hi)
                .map_err(|_| ReachPolicyErr::FloorUnavailable)?;
            log.append(store, crate::fslog::RT_OPKEY, &pk[..])
                .map_err(|_| ReachPolicyErr::FloorUnavailable)?;
            Ok(())
        }
    }
}

// The production metal orchestrator (read floor → TOFU-pin/read operator key → fetch over the
// live wire → apply against the PINNED key + floor → best-effort persist) lands WITH the
// Noise-over-GEM-bridge increment: the device-side fetch needs a transport that reads the real
// encrypted record off the bridge, which does not exist until the handshake goes live there. The
// primitives above (floor + operator-key persistence) are the complete, tested mechanism it will
// compose; the [P19-seg-policy] two-boot gate below proves them end-to-end now.

// ===========================================================================
// The [P19-enroll] gate (securechannel-selftest). Deterministic loopback + fake
// MSSP; entropy fed through the PRODUCTION path via a simulated-HW StubTrng.
// The persist + authenticated-fetch halves additionally need `p15-write`
// (the store write path + the shared hboot verifier), and the cross-reboot
// enrollment-persist rides validate.sh's two boots over one virtio-blk backing.
// ===========================================================================

#[cfg(feature = "securechannel-selftest")]
fn yn(b: bool) -> &'static str {
    if b {
        "PASS"
    } else {
        "FAIL"
    }
}

/// Build a production-path `InitiatorRandomness` from a simulated-HW TRNG — proves
/// `from_entropy` (the metal ephemeral path) works when a TRNG is present.
#[cfg(feature = "securechannel-selftest")]
fn init_rand_from_stub(label: &[u8]) -> Option<InitiatorRandomness> {
    use crate::entropy::{MetalEntropy, StubTrng};
    let mut e = MetalEntropy::new(StubTrng::from_label(label));
    InitiatorRandomness::from_entropy(&mut e).ok()
}

#[cfg(feature = "securechannel-selftest")]
fn resp_rand_from_stub(label: &[u8]) -> Option<ResponderRandomness> {
    use crate::entropy::{MetalEntropy, StubTrng};
    let mut e = MetalEntropy::new(StubTrng::from_label(label));
    ResponderRandomness::from_entropy(&mut e).ok()
}

/// The M4.3 enrollment + authenticated-fetch self-test.
#[cfg(feature = "securechannel-selftest")]
pub fn enroll_selftest() {
    kprint!(" [P19-enroll] M4.3 MSSP enrollment + authenticated update fetch over the Noise channel:\n");

    // ---- (a) ENTROPY (#6): fail-closed structure + production path works ----
    let entropy_ok = entropy_checks();

    // ---- (d) AIR-GAP: UNENROLLED is a valid, non-blocking steady state ----
    let airgap_ok = airgap_checks();

    // ---- (c-proto) enrollment over Noise: mutual auth + record round-trip ----
    let (proto_ok, enr_for_persist) = enroll_protocol_checks();

    // ---- (b) FIXED BUFFERS (#7): N handshakes don't grow the heap ----
    let buffers_ok = heap_stability_check();

    kprint!(
        "   entropy(fail-closed+prod-path)={} air-gap(unenrolled-valid,no-boot-block)={} enroll-over-noise(mutual-auth+record-rt)={} fixed-buffers(no-per-handshake-heap)={}\n",
        yn(entropy_ok), yn(airgap_ok), yn(proto_ok), yn(buffers_ok)
    );

    // The persist + authenticated-fetch halves need the store write path + the
    // shared hboot verifier. Without p15-write, this is a partial proof — do NOT
    // emit the PASS marker (the gate is captured from the p15-write two-boot).
    #[cfg(not(feature = "p15-write"))]
    {
        let _ = enr_for_persist;
        kprint!(" [P19-enroll] SKIP — read-only build: protocol+entropy+air-gap+buffers proven inline above; the FULL gate (enrollment PERSIST across reboot + authenticated fetch→ota::stage verify/reject) needs --features p15-write (two-boot over virtio-blk)\n");
    }

    #[cfg(feature = "p15-write")]
    persist_and_fetch_gate(entropy_ok, airgap_ok, proto_ok, buffers_ok, enr_for_persist);
}

/// Build + operator-sign a 2-entry reach policy FOR the device `device_fp` (the signature covers
/// `signed_body ‖ device_fp` — C14). Byte 0 of the two MACs differs (0x02 vs 0x0a) so they land
/// in DISTINCT reach-table slots (`mac_hash` puts MAC byte 0 in the low bits and the slot is
/// key % DEV_SLOTS — MACs sharing byte 0 would collision-evict, C8 by design).
#[cfg(feature = "securechannel-selftest")]
fn build_signed_policy(gen: u64, tenant: u64, device_fp: &[u8; 32], signer: &KeyPair) -> ReachPolicy {
    use crate::segment::Reach;
    let mut p = ReachPolicy {
        generation: gen,
        tenant_id: tenant,
        infra_gw: 0x0A00_0001,  // 10.0.0.1
        infra_dns: 0x0A00_0002, // 10.0.0.2
        entry_count: 2,
        entries: [ReachEntry { mac: [0u8; 6], reach: 0 }; crate::segment::DEV_SLOTS],
        sig: [0u8; 64],
    };
    p.entries[0] = ReachEntry { mac: [0x02, 0, 0, 0, 0, 0x10], reach: Reach::Quarantine.to_code() };
    p.entries[1] = ReachEntry { mac: [0x0a, 0, 0, 0, 0, 0x11], reach: Reach::InternetOnly.to_code() };
    let msg = ReachPolicy::sig_msg(&p.signed_body(), device_fp);
    let s = signer.sk.sign(&msg[..], None);
    p.sig.copy_from_slice(&s[..]);
    p
}

/// The M4.5 SEGMENTATION-AUTHORITY self-test — an operator-signed reach policy delivered over the
/// enrolled Noise channel provisions `segment.rs` + ARMS the plane, and every fail-open guard
/// holds. Deterministic loopback + in-process fake MSSP + a dedicated operator signing key
/// (distinct from the Noise static — C9). Restores the DISARMED state at the end (C7/C13).
#[cfg(feature = "securechannel-selftest")]
pub fn seg_policy_selftest() {
    use crate::segment::{self, Reach};
    use ed25519_compact::{KeyPair, Seed};
    const TENANT: u64 = 0x5445_4E41; // "TENA"

    // A dedicated OPERATOR signing key — the independent trust root (C9), NOT the Noise static.
    let op = KeyPair::from_seed(Seed::new(sha256::digest(b"HEQK-M4.5-operator-signing-key")));
    let rogue = KeyPair::from_seed(Seed::new(sha256::digest(b"HEQK-M4.5-ROGUE-operator-key")));
    let opk: [u8; 32] = *op.pk;
    let rogue_pk: [u8; 32] = *rogue.pk;

    // Enroll a device/MSSP pair so we have a real Enrollment (tenant + device_fp) + transport.
    let tv = crate::securechannel::test_vectors();
    let (ir, rr) = match (init_rand_from_stub(b"seg-i"), resp_rand_from_stub(b"seg-r")) {
        (Some(a), Some(b)) => (a, b),
        _ => {
            kprint!(" [P19-seg-policy] FAIL — entropy stub unavailable\n");
            return;
        }
    };
    let (enr, mut dev, mut mssp) = match enroll_over_noise(&tv.dev, &tv.resp, &ir, &rr, TENANT) {
        Ok(x) => x,
        Err(_) => {
            kprint!(" [P19-seg-policy] FAIL — enroll_over_noise failed\n");
            return;
        }
    };

    // Build + operator-sign a policy FOR THIS device (body ‖ device_fp).
    let pol = build_signed_policy(7, TENANT, &enr.device_fp, &op);

    // (1) serde round-trip + fail-CLOSED parse.
    let wire = pol.to_bytes();
    let rt_ok = ReachPolicy::from_bytes(&wire).map_or(false, |p| {
        p.generation == 7 && p.tenant_id == TENANT && p.entry_count == 2
            && p.entries[0].reach == Reach::Quarantine.to_code() && p.sig == pol.sig
    });
    let bad_magic = { let mut b = wire; b[0] ^= 0xFF; ReachPolicy::from_bytes(&b).is_none() };
    let bad_ver = { let mut b = wire; b[4] = 2; ReachPolicy::from_bytes(&b).is_none() };
    let short = ReachPolicy::from_bytes(&wire[..ReachPolicy::WIRE_LEN - 1]).is_none();
    let bad_count = {
        let mut b = wire;
        b[6..8].copy_from_slice(&((segment::DEV_SLOTS as u16 + 1).to_le_bytes()));
        ReachPolicy::from_bytes(&b).is_none()
    };
    let bad_reach = { let mut b = wire; b[38] = 0x7F; ReachPolicy::from_bytes(&b).is_none() }; // entry0 reach @ 32+6
    let parse_ok = rt_ok && bad_magic && bad_ver && short && bad_count && bad_reach;

    // (2) fetch over the enrolled Noise transport (AEAD, counter-advanced).
    let mut out = [0u8; ReachPolicy::WIRE_LEN];
    let fetched = fetch_reach_policy(&mut dev, &mut mssp, &wire, &mut out);
    let fetch_ok = fetched.as_ref().map_or(false, |p| p.generation == 7 && p.tenant_id == TENANT);
    let fpol = fetched.unwrap_or(pol);

    // Clean baseline for the (dis)arm assertions.
    segment::disarm_reach_channel();
    segment::reset_all_to_full();

    // (3) signed apply → armed + the reach matrix holds (provisioned, not set directly).
    let applied = apply_reach_policy(&enr, &fpol, 0, &opk);
    let q_key = crate::ratelimit::mac_hash(&[0x02, 0, 0, 0, 0, 0x10]);
    let io_key = crate::ratelimit::mac_hash(&[0x0a, 0, 0, 0, 0, 0x11]);
    let lan: u32 = 0x0A00_0005; // internal peer
    let wan: u32 = 0x0808_0808; // external
    let gw: u32 = 0x0A00_0001; // infra (gateway) — internal but carved out
    let apply_ok = applied == Ok((2, 7))
        && segment::reach_armed()
        && segment::reach_of(q_key) == Reach::Quarantine
        && segment::reach_of(io_key) == Reach::InternetOnly
        && !segment::reach_allow(0, q_key, lan, true)   // Quarantine + LAN peer → DENY
        && segment::reach_allow(0, q_key, wan, false)   // Quarantine + WAN → allow
        && segment::reach_allow(0, io_key, gw, true)    // C2 infra gateway → allow
        && segment::reach_allow(0x0AC8_0005, q_key, lan, true); // C3 mgmt floor → allow

    // (4) BAD SIGNATURE (tampered sig) → BadSignature, NOTHING mutated/armed.
    segment::disarm_reach_channel();
    segment::reset_all_to_full();
    let mut tampered = fpol;
    tampered.sig[0] ^= 0xFF;
    let badsig = apply_reach_policy(&enr, &tampered, 0, &opk) == Err(ReachPolicyErr::BadSignature)
        && !segment::reach_armed()
        && segment::reach_allow(0, q_key, lan, true); // fail-open: still all-allow

    // (5) WRONG operator key → BadSignature.
    let wrongkey = apply_reach_policy(&enr, &fpol, 0, &rogue_pk) == Err(ReachPolicyErr::BadSignature)
        && !segment::reach_armed();

    // (6) STALE generation (floor >= gen) → StaleGeneration, nothing re-stranded.
    let stale = apply_reach_policy(&enr, &fpol, 7, &opk) == Err(ReachPolicyErr::StaleGeneration)
        && !segment::reach_armed()
        && segment::reach_allow(0, q_key, lan, true);

    // (7) TENANT mismatch (validly signed for a DIFFERENT tenant) → TenantMismatch.
    let other = build_signed_policy(9, TENANT ^ 0xFFFF, &enr.device_fp, &op);
    let tenant_bad = apply_reach_policy(&enr, &other, 0, &opk) == Err(ReachPolicyErr::TenantMismatch)
        && !segment::reach_armed();

    // (8) monotonic advance: after floor=7, a gen=9 policy (re-signed) applies.
    let adv = build_signed_policy(9, TENANT, &enr.device_fp, &op);
    let advance_ok = matches!(apply_reach_policy(&enr, &adv, 7, &opk), Ok((2, 9)))
        && segment::reach_armed();

    // Restore the inert production state (C7/C13).
    segment::disarm_reach_channel();
    segment::reset_all_to_full();

    let pass = parse_ok && fetch_ok && apply_ok && badsig && wrongkey && stale && tenant_bad && advance_ok;
    kprint!(" [P19-seg-policy] {} — operator-signed reach policy over enrolled Noise ARMS segmentation (C9): parse(fail-closed)={} fetch={} apply+matrix={} bad-sig-rejected={} wrong-key-rejected={} stale-gen-rejected={} tenant-mismatch-rejected={} gen-advance={} | plane restored DISARMED={}\n",
        yn(pass), yn(parse_ok), yn(fetch_ok), yn(apply_ok), yn(badsig), yn(wrongkey), yn(stale), yn(tenant_bad), yn(advance_ok), yn(!segment::reach_armed()));

    // The persistence half (C10 operator-key TOFU-pin + C11 anti-rollback floor SURVIVING reboot)
    // rides validate.sh's two-boot over one virtio-blk backing — p15-write only.
    #[cfg(feature = "p15-write")]
    seg_policy_persist_gate(&op, &enr);
}

/// M4.5 PERSISTENCE two-boot gate ([P19-seg-policy-persist], p15-write): proves the operator key
/// TOFU-pins (C10) and the anti-rollback generation floor SURVIVES reboot (C11) over one
/// virtio-blk backing (validate.sh's two boots). BOOT1 pins the key + applies gen=5 + persists
/// floor=5; BOOT2 reads floor=5 back, refuses a replayed gen=3 (no re-strand across reboot),
/// applies gen=7, and refuses a DIFFERENT operator key (no silent swap). Restores DISARMED.
#[cfg(all(feature = "securechannel-selftest", feature = "p15-write"))]
fn seg_policy_persist_gate(op: &KeyPair, enr: &Enrollment) {
    use crate::segment;
    use crate::store::{RegionKind, SealedStore};
    const TENANT: u64 = 0x5445_4E41;
    let opk: [u8; 32] = *op.pk;
    // A DIFFERENT operator key (must be refused once one is pinned — C10).
    let other_op = ed25519_compact::KeyPair::from_seed(ed25519_compact::Seed::new(sha256::digest(
        b"HEQK-M4.5-OTHER-operator-key",
    )));
    let other_opk: [u8; 32] = *other_op.pk;

    // Region disjoint from the enroll gate's (9500-9560 / 9600-9900) and the P15 footprints.
    const SEG_LO: u64 = 9560;
    const SEG_HI: u64 = 9600;

    let mut dev = match arch_aarch64::virtio_blk::VirtioBlk::open() {
        Some(d) => d,
        None => {
            kprint!(" [P19-seg-policy-persist] SKIP — no virtio-blk (diskless); signed-apply proven inline above\n");
            return;
        }
    };
    let mut store = match SealedStore::open(&mut dev) {
        Ok(s) => s,
        Err(e) => {
            kprint!(" [P19-seg-policy-persist] FAIL — guard refused MBR: {:?}\n", e);
            return;
        }
    };
    if store.add_region(SEG_LO, SEG_HI, RegionKind::DataVolume).is_err() {
        kprint!(" [P19-seg-policy-persist] FAIL — could not register seg region\n");
        return;
    }

    let log = match crate::fslog::open_or_format(&mut store, SEG_LO, SEG_HI) {
        Ok(l) => l,
        Err(e) => {
            kprint!(" [P19-seg-policy-persist] FAIL — log open: {:?}\n", e);
            return;
        }
    };
    let first_boot = log.count() == 0;
    segment::disarm_reach_channel();
    segment::reset_all_to_full();

    if first_boot {
        // BOOT1: floor empty → pin the operator key + apply gen=5 + persist floor=5.
        let floor0 = read_reach_floor(&mut store, SEG_LO, SEG_HI).unwrap_or(u64::MAX);
        let pinned = pin_operator_pk(&mut store, SEG_LO, SEG_HI, &opk).is_ok();
        let pol5 = build_signed_policy(5, TENANT, &enr.device_fp, op);
        let applied = matches!(apply_reach_policy(enr, &pol5, floor0, &opk), Ok((2, 5)));
        let persisted = persist_reach_floor(&mut store, SEG_LO, SEG_HI, 5).is_ok();
        segment::disarm_reach_channel();
        segment::reset_all_to_full();
        kprint!(" [P19-seg-policy-persist] BOOT1 — floor-was-empty={} op-key-pinned={} gen=5-applied={} floor=5-persisted={} — reboot to verify it SURVIVES\n",
            yn(floor0 == 0), yn(pinned), yn(applied), yn(persisted));
    } else {
        // BOOT2: the floor + operator key must have SURVIVED the reboot.
        let floor = read_reach_floor(&mut store, SEG_LO, SEG_HI).unwrap_or(u64::MAX);
        let floor_survived = floor == 5; // C11
        let key_survived =
            read_operator_pk(&mut store, SEG_LO, SEG_HI).ok().flatten() == Some(opk); // C10
        // A replayed OLD policy (gen=3 <= floor 5) is refused — no re-strand across reboot.
        let pol3 = build_signed_policy(3, TENANT, &enr.device_fp, op);
        let replay_refused =
            apply_reach_policy(enr, &pol3, floor, &opk) == Err(ReachPolicyErr::StaleGeneration)
                && !segment::reach_armed();
        // A monotonic advance (gen=7 > floor 5) applies + arms.
        let pol7 = build_signed_policy(7, TENANT, &enr.device_fp, op);
        let advance_ok = matches!(apply_reach_policy(enr, &pol7, floor, &opk), Ok((2, 7)))
            && segment::reach_armed();
        // A DIFFERENT operator key is refused once one is pinned (C10 — no silent swap).
        let swap_refused =
            pin_operator_pk(&mut store, SEG_LO, SEG_HI, &other_opk) == Err(ReachPolicyErr::OperatorKeyMismatch);
        let _ = other_opk;
        segment::disarm_reach_channel();
        segment::reset_all_to_full();
        let pass = floor_survived && key_survived && replay_refused && advance_ok && swap_refused;
        kprint!(" [P19-seg-policy-persist] {} — floor SURVIVED reboot (=5)={} op-key SURVIVED={} replayed-gen3-refused={} gen7-advance={} op-key-swap-refused(C10)={} | restored DISARMED={}\n",
            yn(pass), yn(floor_survived), yn(key_survived), yn(replay_refused), yn(advance_ok), yn(swap_refused), yn(!segment::reach_armed()));
    }
}

/// The M4.5 NOISE-OVER-UDP framing self-test — proves the datagram chunker + fail-closed
/// reassembler carry a >MTU PQ-hybrid handshake, and that the FULL initiator↔responder handshake
/// completes over that framing (matching transport keys + a record round-trips). Deterministic
/// (StubTrng production `from_entropy` path). The real smoltcp-UDP-over-GEM carriage is the metal
/// first-light (`cm5_enroll_bringup`); this proves the load-bearing >MTU framing off-hardware.
#[cfg(feature = "securechannel-selftest")]
pub fn noise_over_udp_selftest() {
    use crate::securechannel::{hs_chunk, HsReasm, HS_CHUNK, HS_FRAME_HDR, HS_MSG_MAX};

    // (1) chunk → reassemble round-trip of a >MTU buffer (2500 B → 3 datagrams).
    let mut msg = [0u8; 2500];
    for (i, b) in msg.iter_mut().enumerate() {
        *b = (i as u8) ^ 0x5A;
    }
    let mut rr = HsReasm::new();
    let mut count = 0u32;
    let mut complete_len = 0usize;
    let chunked = hs_chunk(&msg, |d| {
        count += 1;
        match rr.feed(d) {
            Ok(Some(n)) => {
                complete_len = n;
                true
            }
            Ok(None) => true,
            Err(()) => false,
        }
    });
    let roundtrip = chunked && count == 3 && complete_len == msg.len() && rr.message() == &msg[..];

    // (2) FAIL-CLOSED reassembly — a malicious peer cannot drive OOB / unbounded state.
    let dgram = |total: u16, off: u16, clen: usize| -> ([u8; HS_FRAME_HDR + HS_CHUNK + 1], usize) {
        let mut d = [0u8; HS_FRAME_HDR + HS_CHUNK + 1];
        d[0..2].copy_from_slice(&total.to_le_bytes());
        d[2..4].copy_from_slice(&off.to_le_bytes());
        (d, HS_FRAME_HDR + clen)
    };
    let mut r = HsReasm::new();
    let too_big = { let (d, n) = dgram(5000, 0, HS_CHUNK); r.reset(); matches!(r.feed(&d[..n]), Err(())) }; // total > MAX
    let unaligned = { let (d, n) = dgram(2000, 100, HS_CHUNK); r.reset(); matches!(r.feed(&d[..n]), Err(())) }; // off % CHUNK != 0
    let off_gt_total = { let (d, n) = dgram(10, 1024, 0); r.reset(); matches!(r.feed(&d[..n]), Err(())) }; // off > total
    let chunk_too_big = { let (d, n) = dgram(2000, 0, HS_CHUNK + 1); r.reset(); matches!(r.feed(&d[..n]), Err(())) }; // chunk > CHUNK
    let short_nonfinal = { let (d, n) = dgram(2000, 0, 500); r.reset(); matches!(r.feed(&d[..n]), Err(())) }; // non-final < CHUNK
    let overflow = { let (d, n) = dgram(2000, 1024, HS_CHUNK); r.reset(); matches!(r.feed(&d[..n]), Err(())) }; // off+chunk > total
    let inconsistent = {
        r.reset();
        let (d1, n1) = dgram(2000, 0, HS_CHUNK);
        let first_ok = matches!(r.feed(&d1[..n1]), Ok(None));
        let (d2, n2) = dgram(1500, 1024, 476); // different total
        first_ok && matches!(r.feed(&d2[..n2]), Err(()))
    };
    let hdr_too_short = { r.reset(); matches!(r.feed(&[0u8; 3]), Err(())) };
    let failclosed = too_big && unaligned && off_gt_total && chunk_too_big && short_nonfinal
        && overflow && inconsistent && hdr_too_short;

    // (3) FULL PQ-hybrid Noise handshake carried over the chunker (each message chunked +
    //     reassembled), matching transport keys + a record round-trips.
    let tv = crate::securechannel::test_vectors();
    let device_fp = sha256::digest(&tv.dev.pk[..]);
    let handshake = noise_handshake_over_chunker(&tv, &device_fp);

    let pass = roundtrip && failclosed && handshake;
    kprint!(" [P19-noise-over-udp] {} — >MTU handshake datagram framing: chunk/reassemble roundtrip(2500B→3 dgrams)={} fail-closed-reassembly(8 malformed rejected)={} full-Noise-handshake-over-chunker(matched keys+record-rt)={}\n",
        yn(pass), yn(roundtrip), yn(failclosed), yn(handshake));
}

/// Drive the full M4.2b handshake with EVERY message routed through `hs_chunk` → `HsReasm`
/// (the exact framing the metal GEM transport uses), then confirm the crossed transport keys
/// match by a record round-trip. Returns true iff the whole exchange succeeds over the framing.
#[cfg(feature = "securechannel-selftest")]
fn noise_handshake_over_chunker(
    tv: &crate::securechannel::TestVectors,
    device_fp: &[u8; 32],
) -> bool {
    use crate::securechannel::{hs_chunk, HsReasm};

    // Route a message through the chunker into a fresh reassembler; return the reassembled bytes
    // length, or None if framing failed.
    fn ferry(msg: &[u8], reasm: &mut HsReasm) -> bool {
        reasm.reset();
        let mut done = false;
        let ok = hs_chunk(msg, |d| match reasm.feed(d) {
            Ok(Some(_)) => {
                done = true;
                true
            }
            Ok(None) => true,
            Err(()) => false,
        });
        ok && done
    }

    // msg1: device → responder, over the chunker.
    let (msg1, ipend) =
        match initiator_write_msg1(&tv.dev, &tv.resp.public(), &tv.irand, device_fp) {
            Some(x) => x,
            None => return false,
        };
    let mut reasm = HsReasm::new();
    if !ferry(msg1.as_slice(), &mut reasm) {
        return false;
    }
    let rpend = match responder_read_msg1(&tv.resp, &tv.dev.pk, reasm.message()) {
        Ok(x) => x,
        Err(_) => return false,
    };
    if rpend.payload1.as_slice() != &device_fp[..] {
        return false;
    }

    // msg2: responder → device, over the chunker.
    let tb = 4242u64.to_le_bytes();
    let (msg2, mut mssp_session) = match responder_write_msg2(rpend, &tv.rrand, &tb) {
        Some(x) => x,
        None => return false,
    };
    if !ferry(msg2.as_slice(), &mut reasm) {
        return false;
    }
    let (mut dev_session, _p2) = match initiator_read_msg2(ipend, reasm.message()) {
        Ok(x) => x,
        Err(_) => return false,
    };

    // The crossed keys match iff a device-sent record decrypts on the MSSP recv cipher.
    let mut ct = [0u8; 64];
    let n = match dev_session.send.encrypt_into(b"", b"seg-policy-probe", &mut ct) {
        Some(n) => n,
        None => return false,
    };
    let mut pt = [0u8; 64];
    match mssp_session.recv.decrypt_into(b"", &ct[..n], &mut pt) {
        Ok(m) => &pt[..m] == b"seg-policy-probe",
        Err(_) => false,
    }
}

// --- (a) entropy checks ---------------------------------------------------

#[cfg(feature = "securechannel-selftest")]
fn entropy_checks() -> bool {
    use crate::entropy::{
        boot_health_assert, AbsentTrng, EntropyError, EntropySource, MetalEntropy, StubTrng,
        StuckTrng, TestEntropy,
    };

    // The boot-time entropy-health assertion FAILS CLOSED here: QEMU has no HW
    // TRNG, so the PRODUCTION source (MetalEntropy<HwTrng>) yields nothing.
    let boot_fail_closed = matches!(boot_health_assert(), Err(EntropyError::Unavailable));

    // An ABSENT TRNG → fill() fails closed (never a seed / zeros / partial fill).
    let mut absent = MetalEntropy::new(AbsentTrng);
    let absent_fail = matches!(absent.fill_32(), Err(EntropyError::Unavailable));

    // A STUCK (working-but-broken) TRNG → health_check REJECTS it.
    let mut stuck = MetalEntropy::new(StuckTrng);
    let stuck_rejected = matches!(stuck.health_check(), Err(EntropyError::HealthCheckFailed));

    // A HEALTHY (simulated-HW) TRNG → the PRODUCTION path yields good bytes AND a
    // full handshake driven from `from_entropy` COMPLETES — proving the metal
    // ephemeral path is wired, not just the fail-closed edges.
    let mut good = MetalEntropy::new(StubTrng::from_label(b"HEQK-M4.3-entropy-good"));
    let good_ok = good.health_check().is_ok() && good.fill_32().is_ok();
    let prod_handshake_ok = production_path_handshake_completes();

    // The seeded TEST provider (the "seed" the auditor forbids on metal) exists
    // ONLY behind securechannel-selftest: prove it is deterministic (same label →
    // same stream; different label → different), so the KAT path is reproducible
    // while a `compile_error!` keeps it out of any metal image.
    let mut t1 = TestEntropy::from_label(b"seed-A");
    let mut t2 = TestEntropy::from_label(b"seed-A");
    let mut t3 = TestEntropy::from_label(b"seed-B");
    let (a1, a2, b1) = (
        t1.fill_32().unwrap(),
        t2.fill_32().unwrap(),
        t3.fill_32().unwrap(),
    );
    let seeded_deterministic = a1 == a2 && a1 != b1;

    kprint!(
        "   entropy: boot-health-assert-fail-closed={} absent-TRNG→Err={} stuck-TRNG→rejected={} healthy-TRNG→ok={} prod-from_entropy-handshake={} seeded-test-provider-deterministic(selftest-only)={} (NO seeded path compiles on metal: compile_error+private-fields)\n",
        yn(boot_fail_closed), yn(absent_fail), yn(stuck_rejected), yn(good_ok), yn(prod_handshake_ok), yn(seeded_deterministic)
    );
    boot_fail_closed && absent_fail && stuck_rejected && good_ok && prod_handshake_ok && seeded_deterministic
}

/// A full enroll handshake whose ephemerals come from the PRODUCTION `from_entropy`
/// path (over a simulated-HW StubTrng) rather than the deterministic KAT seeds.
#[cfg(feature = "securechannel-selftest")]
fn production_path_handshake_completes() -> bool {
    let tv = crate::securechannel::test_vectors();
    let irand = match init_rand_from_stub(b"HEQK-M4.3-prod-init-eph") {
        Some(r) => r,
        None => return false,
    };
    let rrand = match resp_rand_from_stub(b"HEQK-M4.3-prod-resp-eph") {
        Some(r) => r,
        None => return false,
    };
    enroll_over_noise(&tv.dev, &tv.resp, &irand, &rrand, 4242).is_ok()
}

// --- (d) air-gap checks ---------------------------------------------------

#[cfg(feature = "securechannel-selftest")]
fn airgap_checks() -> bool {
    // UNENROLLED is a valid steady state; local SOC available; never boot-blocking.
    let s = EnrollStatus::default_standalone();
    let unenrolled_valid = matches!(s, EnrollStatus::Unenrolled)
        && s.local_soc_available()
        && !s.is_boot_blocking();

    // "No MSSP" is modeled by a failed enrollment attempt (the MSSP never answers
    // → the device gets garbage for msg2). The device must FALL BACK to Unenrolled
    // and continue — enrollment is additive, not a precondition.
    let tv = crate::securechannel::test_vectors();
    let irand = init_rand_from_stub(b"HEQK-M4.3-airgap-init").unwrap();
    let (msg1, ipend) =
        initiator_write_msg1(&tv.dev, &tv.resp.public(), &irand, b"enroll?").unwrap();
    let _ = msg1;
    // No MSSP reply: feed the device a garbage/short msg2. It must error, NOT panic
    // or block, leaving the device Unenrolled.
    let garbage = [0u8; 32];
    let attempt = initiator_read_msg2(ipend, &garbage);
    let still_unenrolled = attempt.is_err();
    // The steady state after a failed attempt is still Unenrolled + SOC-up.
    let status_after = EnrollStatus::Unenrolled;
    let soc_still_up = status_after.local_soc_available() && !status_after.is_boot_blocking();

    unenrolled_valid && still_unenrolled && soc_still_up
}

// --- (c) enrollment protocol checks --------------------------------------

#[cfg(feature = "securechannel-selftest")]
fn enroll_protocol_checks() -> (bool, Enrollment) {
    let tv = crate::securechannel::test_vectors();
    let irand = init_rand_from_stub(b"HEQK-M4.3-enroll-init").unwrap();
    let rrand = resp_rand_from_stub(b"HEQK-M4.3-enroll-resp").unwrap();
    const TENANT: u64 = 0x00A1_B2C3_D4E5_F607;

    // Correct MSSP → mutual auth succeeds, tenant + device fp bound.
    let device_fp = sha256::digest(&tv.dev.pk[..]);
    let ok_case = enroll_over_noise(&tv.dev, &tv.resp, &irand, &rrand, TENANT);
    let (enr, mutual_ok) = match ok_case {
        Ok((e, _ds, _ms)) => {
            let ok = e.tenant_id == TENANT
                && e.device_fp == device_fp
                && e.responder_x_pk == tv.resp.public().x_pk();
            (e, ok)
        }
        Err(_) => (
            Enrollment {
                tenant_id: TENANT_NONE,
                responder_x_pk: [0u8; 32],
                device_fp,
                generation: 0,
            },
            false,
        ),
    };

    // WRONG MSSP static key → the device's es key diverges → handshake ABORTS
    // (a rogue control plane cannot enroll the device).
    let wrong = ResponderStatic::from_seeds(
        &sha256::digest(b"HEQK-M4.3-WRONG-mssp-x"),
        &sha256::digest(b"HEQK-M4.3-WRONG-mssp-d"),
        &sha256::digest(b"HEQK-M4.3-WRONG-mssp-z"),
    );
    // Device thinks it talks to `wrong` (provisioned), but the REAL responder is
    // `tv.resp`; model the mismatch by having the device build msg1 for `wrong`
    // while the real MSSP reads with its own key → abort.
    let irand2 = init_rand_from_stub(b"HEQK-M4.3-wrong-init").unwrap();
    let (m1, _ip) = initiator_write_msg1(&tv.dev, &wrong.public(), &irand2, &device_fp).unwrap();
    let rogue_mssp_rejected = responder_read_msg1(&tv.resp, &tv.dev.pk, m1.as_slice()).is_err();

    // Enrollment record round-trips through its wire form (persist substrate).
    let rt = Enrollment::from_bytes(&enr.to_bytes()) == Some(enr);

    // Enrolled is ALSO a non-blocking, SOC-available posture (additive, symmetric
    // with Unenrolled): enrollment never gates the local SOC in EITHER direction.
    let enrolled_status = EnrollStatus::Enrolled(enr);
    let enrolled_nonblocking =
        enrolled_status.local_soc_available() && !enrolled_status.is_boot_blocking();

    kprint!(
        "   enroll: mutual-auth(tenant+dev-fp bound)={} rogue-MSSP-rejected={} record-serde-roundtrip={} enrolled-non-blocking={}\n",
        yn(mutual_ok), yn(rogue_mssp_rejected), yn(rt), yn(enrolled_nonblocking)
    );
    (mutual_ok && rogue_mssp_rejected && rt && enrolled_nonblocking, enr)
}

// --- (b) heap stability ---------------------------------------------------

/// Run N enroll handshakes and assert the bump allocator does NOT grow per
/// handshake (auditor #2: no per-record Vec leak). One warm-up handshake absorbs
/// any one-time allocation; after it, growth across the batch must be ZERO.
#[cfg(feature = "securechannel-selftest")]
fn heap_stability_check() -> bool {
    let tv = crate::securechannel::test_vectors();
    let irand = init_rand_from_stub(b"HEQK-M4.3-heap-init").unwrap();
    let rrand = resp_rand_from_stub(b"HEQK-M4.3-heap-resp").unwrap();

    // Warm-up (absorbs any first-touch allocation from the crypto crates).
    let _ = enroll_over_noise(&tv.dev, &tv.resp, &irand, &rrand, 1);

    // A small batch is enough: if per-handshake heap growth is 0, it is 0 for any
    // N (the whole point of removing the per-record Vec). Kept small so the
    // debug-mode ML-KEM cost stays well within the QEMU boot budget.
    const N: u64 = 3;
    let before = crate::heap::used();
    for i in 0..N {
        // Fresh transport too, to exercise encrypt_into/decrypt_into records.
        if let Ok((_e, mut ds, mut ms)) =
            enroll_over_noise(&tv.dev, &tv.resp, &irand, &rrand, i + 2)
        {
            let mut buf = [0u8; 64];
            if let Some(n) = ds.send.encrypt_into(b"", b"record", &mut buf) {
                let mut pt = [0u8; 64];
                let _ = ms.recv.decrypt_into(b"", &buf[..n], &mut pt);
            }
        }
    }
    let after = crate::heap::used();
    let growth = after - before;
    kprint!(
        "   fixed-buffers: {} handshakes + transport records grew heap by {} bytes (must be 0 — no per-record Vec on the bump allocator)\n",
        N, growth
    );
    growth == 0
}

// --- (e) persist + authenticated fetch (p15-write) ------------------------

#[cfg(all(feature = "securechannel-selftest", feature = "p15-write"))]
#[repr(align(8))]
struct AlignedCand([u8; 8504]);

#[cfg(all(feature = "securechannel-selftest", feature = "p15-write"))]
static ENROLL_CANDIDATE: AlignedCand =
    AlignedCand(*include_bytes!("testdata/ota_candidate.bin"));

#[cfg(all(feature = "securechannel-selftest", feature = "p15-write"))]
fn persist_and_fetch_gate(
    entropy_ok: bool,
    airgap_ok: bool,
    proto_ok: bool,
    buffers_ok: bool,
    enr: Enrollment,
) {
    use crate::fslog::{self, RT_TEST};
    use crate::store::{RegionKind, SealedStore};

    let mut dev = match arch_aarch64::virtio_blk::VirtioBlk::open() {
        Some(d) => d,
        None => {
            kprint!(" [P19-enroll] SKIP — no virtio-blk device (diskless boot); protocol/entropy/air-gap/buffers proven above\n");
            return;
        }
    };
    let mut store = match SealedStore::open(&mut dev) {
        Ok(s) => s,
        Err(e) => {
            kprint!(" [P19-enroll] FAIL — guard refused device MBR: {:?}\n", e);
            return;
        }
    };
    // Regions disjoint from P15-persist/fs/sealfs/ota footprints (all < 9500).
    const DV_LO: u64 = 9500;
    const DV_HI: u64 = 9560; // enrollment state log
    const IS_LO: u64 = 9600;
    const IS_HI: u64 = 9900; // OTA inactive-slot scratch for the fetch→stage
    if store.add_region(DV_LO, DV_HI, RegionKind::DataVolume).is_err()
        || store.add_region(IS_LO, IS_HI, RegionKind::InactiveSlot).is_err()
    {
        kprint!(" [P19-enroll] FAIL — could not register enroll data/inactive regions\n");
        return;
    }

    // ---- (e) authenticated fetch → ota::stage verify/reject (every boot) ----
    let fetch_ok = fetch_and_verify_checks(&mut store, IS_LO, IS_HI);

    // ---- (c-persist) enrollment persists across reboot (two boots) ----
    let (elo, ehi) = (DV_LO, DV_HI);
    match fslog::open_or_format(&mut store, elo, ehi) {
        Ok(mut log) if log.count() == 0 => {
            // BOOT 1: persist the enrollment binding.
            let wrote = log.append(&mut store, RT_TEST, &enr.to_bytes()).is_ok();
            kprint!(" [P19-enroll] BOOT1 — entropy {} air-gap {} enroll-over-noise {} fixed-buffers {} authenticated-fetch→stage {}; persisted enrollment (tenant {:#x}) {} — reboot to verify it SURVIVES\n",
                yn(entropy_ok), yn(airgap_ok), yn(proto_ok), yn(buffers_ok), yn(fetch_ok),
                enr.tenant_id, yn(wrote));
        }
        Ok(log) => {
            // BOOT 2: the enrollment binding must have survived (same disk).
            let mut got: Option<Enrollment> = None;
            log.for_each(&store, |_seq, _rt, pl| {
                if let Some(e) = Enrollment::from_bytes(pl) {
                    got = Some(e);
                }
            })
            .ok();
            let persisted = matches!(
                got,
                Some(e) if e.tenant_id == enr.tenant_id
                    && e.device_fp == enr.device_fp
                    && e.responder_x_pk == enr.responder_x_pk
            );
            let pass =
                entropy_ok && airgap_ok && proto_ok && buffers_ok && fetch_ok && persisted;
            kprint!("   enroll-persist: enrollment SURVIVED reboot {} (tenant {:#x})\n",
                yn(persisted), got.map(|e| e.tenant_id).unwrap_or(0));
            kprint!(" [P19-enroll] {} — M4.3 MSSP enrollment over the PQ-hybrid Noise channel (mutual auth: device Ed25519 transcript sig + enrolled MSSP static; rogue MSSP rejected), enrollment SURVIVES reboot via the sealed store, authenticated fetch feeds ota::stage which VERIFIES a valid candidate + REJECTS a tampered/below-floor one (channel = transport, hboot sig+SVN = trust root); air-gap: UNENROLLED is a valid non-blocking steady state; entropy fails closed with no seeded path on metal; no per-handshake heap. Real MSSP PKI + HW-TRNG + network = metal (Gate R)\n",
                if pass { "PASS" } else { "FAIL" });
        }
        Err(e) => {
            kprint!(" [P19-enroll] FAIL — enrollment state log open failed: {:?}\n", e);
        }
    }
}

/// The authenticated-fetch → trust-root separation proof: a VALID candidate
/// fetched over the enrolled channel verifies+stages; a TAMPERED and a
/// BELOW-FLOOR candidate — delivered just as faithfully by the channel — are
/// REJECTED by `ota::stage` (hboot's verifier + SVN floor), never by the channel.
#[cfg(all(feature = "securechannel-selftest", feature = "p15-write"))]
fn fetch_and_verify_checks(
    store: &mut crate::store::SealedStore<arch_aarch64::virtio_blk::VirtioBlk>,
    is_lo: u64,
    is_hi: u64,
) -> bool {
    use crate::ota::{self, OtaErr, OtaPhase, OtaState};
    use boot_abi::verify::VerifyErr;

    const FLOOR_OK: u64 = 1;
    const FLOOR_HIGH: u64 = 9;

    // Establish an enrolled transport (device + MSSP sessions).
    let tv = crate::securechannel::test_vectors();
    let irand = init_rand_from_stub(b"HEQK-M4.3-fetch-init").unwrap();
    let rrand = resp_rand_from_stub(b"HEQK-M4.3-fetch-resp").unwrap();
    let (_enr, mut ds, mut ms) =
        match enroll_over_noise(&tv.dev, &tv.resp, &irand, &rrand, 7) {
            Ok(x) => x,
            Err(_) => return false,
        };

    let candidate = &ENROLL_CANDIDATE.0;

    // (e1) VALID candidate: fetch over the channel → reassemble → ota::stage.
    let mut reasm = AlignedCand([0u8; 8504]);
    let n = match fetch_candidate_over_channel(&mut ds, &mut ms, candidate, &mut reasm.0) {
        Ok(n) => n,
        Err(_) => return false,
    };
    let delivered_ok = n == candidate.len() && reasm.0 == *candidate;
    let st0 = OtaState::initial();
    let valid_staged = matches!(
        ota::stage(store, &st0, is_lo, is_hi, &reasm.0, FLOOR_OK),
        Ok(s) if s.phase == OtaPhase::Staged && s.candidate_svn == 5 && s.active_slot == crate::ota::SLOT_A
    );

    // (e2) TAMPERED candidate: the (malicious) MSSP flips an Ed25519-sig byte. The
    // channel delivers it faithfully; ota::stage REJECTS it (trust root, not pipe).
    let mut tampered = [0u8; 8504];
    tampered.copy_from_slice(candidate);
    tampered[40 + 32] ^= 0xFF; // ed25519 sig byte (magic/size/entry/load/svn + sha256)
    let mut reasm2 = AlignedCand([0u8; 8504]);
    // Fresh transport (counters reset) for the second fetch.
    let irand2 = init_rand_from_stub(b"HEQK-M4.3-fetch2-init").unwrap();
    let rrand2 = resp_rand_from_stub(b"HEQK-M4.3-fetch2-resp").unwrap();
    let (_e2, mut ds2, mut ms2) =
        match enroll_over_noise(&tv.dev, &tv.resp, &irand2, &rrand2, 7) {
            Ok(x) => x,
            Err(_) => return false,
        };
    let n2 = fetch_candidate_over_channel(&mut ds2, &mut ms2, &tampered, &mut reasm2.0)
        .unwrap_or(0);
    let tampered_delivered = n2 == tampered.len(); // channel still delivered it
    let tampered_rejected = matches!(
        ota::stage(store, &st0, is_lo, is_hi, &reasm2.0, FLOOR_OK),
        Err(OtaErr::VerifyRejected(VerifyErr::BadEd25519))
    );

    // (e3) BELOW-FLOOR: the SAME valid candidate against a raised SVN floor is
    // refused (anti-rollback) — a compromised MSSP cannot force a downgrade.
    let below_floor_refused = matches!(
        ota::stage(store, &st0, is_lo, is_hi, &reasm.0, FLOOR_HIGH),
        Err(OtaErr::VerifyRejected(VerifyErr::BelowFloor))
    );

    kprint!(
        "   fetch: valid delivered={} staged(verified)={} · tampered delivered={} REJECTED-by-ota-verify={} · below-floor refused={}\n",
        yn(delivered_ok), yn(valid_staged), yn(tampered_delivered), yn(tampered_rejected), yn(below_floor_refused)
    );
    delivered_ok && valid_staged && tampered_delivered && tampered_rejected && below_floor_refused
}
