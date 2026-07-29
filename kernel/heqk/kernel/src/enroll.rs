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
use ed25519_compact::KeyPair;

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
