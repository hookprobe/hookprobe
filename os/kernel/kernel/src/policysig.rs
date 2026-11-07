//! ADR 0049 D1 — the operator's signature over POLICY.TXT, verified BEFORE the policy is parsed.
//!
//! `POLICY.SIG` (fixed 512 B on the FAT boot partition, next to POLICY.TXT):
//!   [0..8)   "HQPSIG1\0"
//!   [8..16)  generation, u64 LE (anti-rollback: must be >= the image's floor)
//!   [16..48) sha256(POLICY.TXT — all 4096 bytes as stored)
//!   [48..112) Ed25519 signature over  "HQPOL1" || generation LE || sha256
//!   rest     zero
//!
//! The verifying key is the OPERATOR's (never the vendor boot key): it is compiled into the signed kernel
//! image by the factory (`HEQK_POLICY_PUBKEY`), so rewriting the card cannot change it without breaking the
//! boot signature. No key compiled in = a standalone device: an unsigned POLICY.TXT is accepted (ADR 0049
//! D1: standalone stays first-class), and the boot line says so.

pub const SIG_8_3: &[u8; 11] = b"POLICY  SIG";
pub const SIG_FILE_LEN: usize = 512;
const MAGIC: &[u8; 8] = b"HQPSIG1\0";

include!(concat!(env!("OUT_DIR"), "/policy_key.rs")); // POLICY_PUBKEY: Option<[u8; 32]>, POLICY_GEN_FLOOR: u64

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SigErr {
    /// A key is compiled in but there is no POLICY.SIG.
    Missing,
    Malformed,
    /// The file's digest is not the digest of this POLICY.TXT (the text was changed after signing).
    DigestMismatch,
    BadSignature,
    /// generation < the image's floor (an older signed policy replayed).
    RolledBack { gen: u64, floor: u64 },
}

/// The message the operator signs.
fn signed_message(gen: u64, digest: &[u8; 32]) -> [u8; 6 + 8 + 32] {
    let mut m = [0u8; 46];
    m[..6].copy_from_slice(b"HQPOL1");
    m[6..14].copy_from_slice(&gen.to_le_bytes());
    m[14..].copy_from_slice(digest);
    m
}

/// Verify `sig` over `policy` with `key`, enforcing `floor`. Returns the generation.
pub fn verify(policy: &[u8], sig: &[u8], key: &[u8; 32], floor: u64) -> Result<u64, SigErr> {
    if sig.len() < 112 || &sig[..8] != MAGIC {
        return Err(SigErr::Malformed);
    }
    let gen = u64::from_le_bytes(sig[8..16].try_into().map_err(|_| SigErr::Malformed)?);
    let mut want = [0u8; 32];
    want.copy_from_slice(&sig[16..48]);
    let digest = boot_abi::sha256::digest(policy);
    if digest != want {
        return Err(SigErr::DigestMismatch);
    }
    let pk = ed25519_compact::PublicKey::from_slice(key).map_err(|_| SigErr::Malformed)?;
    let s = ed25519_compact::Signature::from_slice(&sig[48..112]).map_err(|_| SigErr::Malformed)?;
    pk.verify(&signed_message(gen, &digest)[..], &s).map_err(|_| SigErr::BadSignature)?;
    if gen < floor {
        return Err(SigErr::RolledBack { gen, floor });
    }
    Ok(gen)
}

/// `[P-policy-sig]` — valid accepted; tampered text, wrong key, rolled-back generation, malformed and
/// truncated files refused. Pure; deterministic test key.
pub fn selftest() -> bool {
    use ed25519_compact::{KeyPair, Seed};
    let kp = KeyPair::from_seed(Seed::new([0x4f; 32]));
    let other = KeyPair::from_seed(Seed::new([0x50; 32]));
    let mut pol = [0u8; 4096];
    let txt = b"HQPOL1\nacl LAN-IN seq 10 block tcp any 1.1.1.1/32 80\nacl LAN-IN default allow\ninterface lan acl in LAN-IN\n";
    pol[..txt.len()].copy_from_slice(txt);
    let make = |k: &KeyPair, gen: u64, p: &[u8]| {
        let d = boot_abi::sha256::digest(p);
        let s = k.sk.sign(&signed_message(gen, &d)[..], None);
        let mut f = [0u8; SIG_FILE_LEN];
        f[..8].copy_from_slice(MAGIC);
        f[8..16].copy_from_slice(&gen.to_le_bytes());
        f[16..48].copy_from_slice(&d);
        f[48..112].copy_from_slice(s.as_ref());
        f
    };
    let pk: [u8; 32] = *kp.pk;
    let good = make(&kp, 7, &pol);
    let ok = verify(&pol, &good, &pk, 5) == Ok(7);
    let mut tampered = pol;
    tampered[40] ^= 1; // one byte of the policy changed after signing
    let t = verify(&tampered, &good, &pk, 5) == Err(SigErr::DigestMismatch);
    let w = verify(&pol, &make(&other, 7, &pol), &pk, 5) == Err(SigErr::BadSignature);
    let rb = verify(&pol, &make(&kp, 3, &pol), &pk, 5) == Err(SigErr::RolledBack { gen: 3, floor: 5 });
    let mut forged_gen = good;
    forged_gen[8] = 9; // bump the generation without re-signing
    let fg = verify(&pol, &forged_gen, &pk, 5) == Err(SigErr::BadSignature);
    let mal = verify(&pol, &[0u8; SIG_FILE_LEN], &pk, 0) == Err(SigErr::Malformed)
        && verify(&pol, &good[..100], &pk, 0) == Err(SigErr::Malformed);
    let pass = ok && t && w && rb && fg && mal;
    arch_aarch64::_print(format_args!(
        " [P-policy-sig] {} — POLICY.TXT signed by the operator key, verified BEFORE parsing (ADR 0049 D1): valid={} text-tampered-after-signing refused={} wrong key refused={} rolled-back generation refused={} generation edited without re-signing refused={} malformed/truncated refused={} (image key: {})\n",
        if pass { "PASS" } else { "FAIL" }, ok, t, w, rb, fg, mal,
        if POLICY_PUBKEY.is_some() { "operator key compiled in" } else { "none — standalone, unsigned accepted" }
    ));
    pass
}
