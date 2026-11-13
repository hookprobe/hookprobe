//! HQMGMT1 owner-signed command envelopes (hsh spec R6 = D, operator 2026-11-12): the ONE verifier every privileged
//! management operation goes through, whatever the carrier — the management ABI (`mgmtabi`: config confirm / rollback
//! / stage, from the web console and Mission Control) and Mission Control's own owner endpoints (factory reset, owner
//! key rotation, upload activate / rollback). The device holds only the PUBLIC half of the owner key K_own (the
//! anchor); the session that carries an envelope never authorises anything.
//!
//! Replay: a per-boot EPOCH (8 bytes from the hardware TRNG on the CM5, drawn on first use) + a RAM sequence floor.
//! An envelope whose signature verifies for this device and this boot consumes its sequence (the floor rises to it).
//! The floor need not persist: a reboot draws a new epoch, so every envelope signed for an earlier boot no longer
//! matches (no eMMC write per operation, nothing to roll back). No TRNG word = no epoch = every privileged operation
//! refused (fail-closed). Every refusal is journaled; an accepted operation is journaled by its own handler.

use hal::mgmtabi as m;

static mut EPOCH: Option<[u8; 8]> = None;
static mut FLOOR: u64 = 0;

/// 8 bytes for the boot epoch: the CM5 TRNG (fail-closed); QEMU has none, so a hash of the cycle counter stands in
/// (QEMU-only — the CM5 build takes the TRNG branch).
fn rand8() -> Option<[u8; 8]> {
    #[cfg(feature = "cm5")]
    {
        arch_aarch64::rng200::next_word_strict().map(|w| w.to_le_bytes())
    }
    #[cfg(not(feature = "cm5"))]
    {
        let c: u64;
        unsafe { core::arch::asm!("mrs {}, cntpct_el0", out(reg) c, options(nomem, nostack)) };
        let mut h = boot_abi::sha256::Hasher::new();
        h.update(b"heqk-qemu-mgmt-epoch");
        h.update(&c.to_le_bytes());
        h.update(&unsafe { FLOOR }.to_le_bytes());
        Some(h.finish()[..8].try_into().unwrap())
    }
}

/// This boot's epoch (drawn once; None = no entropy: privileged operations are refused).
pub fn epoch() -> Option<[u8; 8]> {
    unsafe {
        let e = &mut *core::ptr::addr_of_mut!(EPOCH);
        if e.is_none() {
            *e = rand8();
        }
        *e
    }
}
/// The lowest sequence the next envelope may carry.
pub fn next_seq() -> u64 {
    unsafe { FLOOR + 1 }
}

/// Every refusal the verifier can give (static, so the HTTP layer can name it).
pub const REASONS: [&str; 12] = [
    "refused: needs an owner-signed envelope",
    "refused: no owner key enrolled",
    "refused: malformed envelope",
    "refused: signature is not the owner key's",
    "refused: envelope is for another device",
    "refused: no entropy for the boot epoch",
    "refused: envelope from another boot",
    "refused: replayed or stale sequence",
    "refused: envelope is for another operation",
    "refused: something else is on trial",
    "refused: something else is in force",
    "refused: envelope binds another target",
];
#[cfg_attr(not(feature = "mcserve"), allow(dead_code))]
pub const ON_TRIAL: &str = REASONS[9];
#[cfg_attr(not(feature = "mcserve"), allow(dead_code))]
pub const IN_FORCE: &str = REASONS[10];
pub const OTHER_TARGET: &str = REASONS[11];

/// Decode a carrier's envelope: exactly 2 * ENV_LEN hex digits (either case), nothing else.
pub fn unhex(h: &[u8], out: &mut [u8; m::ENV_LEN]) -> bool {
    if h.len() != 2 * m::ENV_LEN {
        return false;
    }
    let v = |c: u8| (c as char).to_digit(16).map(|d| d as u8);
    for (o, p) in out.iter_mut().zip(h.chunks(2)) {
        match (v(p[0]), v(p[1])) {
            (Some(a), Some(b)) => *o = a << 4 | b,
            _ => return false,
        }
    }
    true
}
/// The `envelope=` field of a urlencoded form (hex needs no decoding). false = absent or not well formed.
pub fn from_form(body: &[u8], out: &mut [u8; m::ENV_LEN]) -> bool {
    body.split(|&b| b == b'&').find_map(|kv| kv.strip_prefix(b"envelope=")).is_some_and(|v| unhex(v, out))
}

/// A key's fingerprint as envelopes carry it in `arg`: SHA-256(public key)[..8], little-endian.
pub fn fp8(pk: &[u8; 32]) -> u64 {
    u64::from_le_bytes(boot_abi::sha256::digest(pk)[..8].try_into().unwrap())
}

/// Verify `env` for (`msg`, `arg`): structure, the enrolled owner key's signature, this device, this boot, a fresh
/// sequence (consumed once the signature verifies for this device and boot), then the operation and its argument.
/// The caller checks what `generation` / `digest` must bind (it knows its target). NOT journaled here.
pub fn verify(msg: u16, arg: u64, env: &[u8]) -> Result<m::Envelope, &'static str> {
    if env.is_empty() {
        return Err(REASONS[0]);
    }
    let owner = crate::anchor::owner().ok_or(REASONS[1])?;
    let (e, sig) = m::Envelope::parse(env).ok_or(REASONS[2])?;
    let signed = m::envelope_msg(&e.body());
    let ok = match (ed25519_compact::PublicKey::from_slice(&owner), ed25519_compact::Signature::from_slice(&sig)) {
        (Ok(k), Ok(s)) => k.verify(&signed[..], &s).is_ok(),
        _ => false,
    };
    if !ok {
        return Err(REASONS[3]);
    }
    if e.device_id != crate::config_device_id() {
        return Err(REASONS[4]);
    }
    let ep = epoch().ok_or(REASONS[5])?;
    if e.epoch != ep {
        return Err(REASONS[6]);
    }
    if e.seq <= unsafe { FLOOR } {
        return Err(REASONS[7]);
    }
    unsafe { FLOOR = e.seq }; // consumed: valid signature, this device, this boot
    if e.msg != msg || e.arg != arg {
        return Err(REASONS[8]);
    }
    Ok(e)
}

/// Verify + the exact binding (`generation`, `digest`) for an operation whose target the caller knows before it acts.
/// A refusal is journaled here (`op` names the operation); success is journaled by the caller with its outcome.
pub fn authorise(msg: u16, arg: u64, generation: u64, digest: &[u8; 32], env: &[u8], tag: [u8; 4], now_ms: u64) -> Result<(), &'static str> {
    let r = verify(msg, arg, env).and_then(|e| if e.generation == generation && &e.digest == digest { Ok(()) } else { Err(OTHER_TARGET) });
    if let Err(why) = r {
        journal(msg, false, generation, why, tag, now_ms);
    }
    r
}

fn op(msg: u16) -> (&'static str, &'static str) {
    match msg {
        m::CFG_CONFIRM => ("config", "confirm"),
        m::CFG_ROLLBACK => ("config", "rollback"),
        m::CFG_STAGE => ("config", "stage"),
        m::UPLOAD_ACTIVATE => ("upload", "activate"),
        m::UPLOAD_ROLLBACK => ("upload", "rollback"),
        m::OWNER_FACTORY_RESET => ("owner", "factory-reset"),
        m::ANCHOR_ROTATE => ("anchor", "rotate"),
        #[cfg(feature = "wifiheal-bench")]
        m::WIFI_HEAL_TEST => ("wifi", "heal-test"),
        #[cfg(feature = "artstore-bench")]
        m::ARTSTORE_TAMPER_TEST => ("artstore", "tamper-test"),
        _ => ("mgmt", "?"),
    }
}

/// One owner-journal record for a privileged operation (allowed or refused), the same for every client.
pub fn journal(msg: u16, ok: bool, gen: u64, why: &str, tag: [u8; 4], now_ms: u64) {
    let (ty, name) = op(msg);
    let mut b = [0u8; 64];
    let n = {
        use core::fmt::Write;
        let mut w = crate::mcstate::JsonBuf::new(&mut b);
        let _ = write!(w, "{} gen {} {}", name, gen, why);
        w.len
    };
    let _ = crate::ownerapi::audit_artifact(ty, if ok { 1 } else { 2 }, &b[..n], tag, now_ms);
    unsafe {
        JOURNALED += 1;
        LAST_JOURNAL = (msg, ok);
    }
}
static mut JOURNALED: u64 = 0;
static mut LAST_JOURNAL: (u16, bool) = (0, false);
/// Self-tests: how many privileged requests were journaled, and the last one (message, allowed).
#[allow(dead_code)]
pub fn journaled() -> (u64, u16, bool) {
    unsafe { (JOURNALED, LAST_JOURNAL.0, LAST_JOURNAL.1) }
}

/// Self-tests: a fresh epoch / floor (the next real envelope must use what the device then reports).
#[cfg_attr(feature = "cm5", allow(dead_code))]
pub fn test_reset() {
    unsafe {
        FLOOR = 0;
        EPOCH = None;
    }
}

/// Self-tests only: an envelope for THIS device and boot at the next sequence, signed with a TEST key the self-test
/// passes in (the device never holds the real K_own), as 312 hex digits for a form field.
#[allow(dead_code)]
pub fn test_sign_hex(k: &ed25519_compact::KeyPair, msg: u16, arg: u64, generation: u64, digest: [u8; 32], out: &mut [u8; 2 * m::ENV_LEN]) {
    let e = m::Envelope { msg, device_id: crate::config_device_id(), epoch: epoch().unwrap_or([0; 8]), seq: next_seq(), arg, generation, digest };
    let body = e.body();
    let sig = k.sk.sign(&m::envelope_msg(&body)[..], Some(ed25519_compact::Noise::from_slice(&[7u8; 16]).unwrap()));
    const H: &[u8; 16] = b"0123456789abcdef";
    for (i, v) in body.iter().chain(sig.iter()).enumerate() {
        out[2 * i] = H[(v >> 4) as usize];
        out[2 * i + 1] = H[(v & 15) as usize];
    }
}
