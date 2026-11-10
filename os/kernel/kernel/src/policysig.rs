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

#[cfg_attr(not(feature = "cm5"), allow(dead_code))]
pub const SIG_8_3: &[u8; 11] = b"POLICY  SIG";
pub const SIG_FILE_LEN: usize = 512;
const MAGIC: &[u8; 8] = b"HQPSIG1\0";

include!(concat!(env!("OUT_DIR"), "/policy_key.rs")); // POLICY_PUBKEY: Option<[u8; 32]>, POLICY_GEN_FLOOR: u64

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(not(feature = "cm5"), allow(dead_code))]
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

/// WAN.SIG (audit 2026-11-10 finding 11): the operator's signature over WAN.TXT, same 512-B layout as the other
/// signed packs — "HQNSIG1\0" | gen u64 LE | len u64 LE | sha256(WAN.TXT[..len]) | Ed25519(key, "HQWAN1" | gen | len |
/// sha256) | 0-pad. Distinct tag: no other pack's signature verifies as WAN.
#[cfg_attr(not(feature = "cm5"), allow(dead_code))]
pub const WAN_SIG_8_3: &[u8; 11] = b"WAN     SIG";

/// Verify a WAN.SIG over the stored WAN.TXT bytes. Returns the generation.
pub fn verify_wan(body: &[u8], sig: &[u8], key: &[u8; 32]) -> Result<u64, SigErr> {
    if sig.len() < 120 || &sig[..8] != b"HQNSIG1\0" {
        return Err(SigErr::Malformed);
    }
    let gen = u64::from_le_bytes(sig[8..16].try_into().unwrap());
    let len = u64::from_le_bytes(sig[16..24].try_into().unwrap()) as usize;
    if len > body.len() {
        return Err(SigErr::Malformed);
    }
    let d = boot_abi::sha256::digest(&body[..len]);
    if d[..] != sig[24..56] {
        return Err(SigErr::DigestMismatch);
    }
    let mut m = [0u8; 54];
    m[..6].copy_from_slice(b"HQWAN1");
    m[6..14].copy_from_slice(&gen.to_le_bytes());
    m[14..22].copy_from_slice(&(len as u64).to_le_bytes());
    m[22..].copy_from_slice(&d);
    let pk = ed25519_compact::PublicKey::from_slice(key).map_err(|_| SigErr::Malformed)?;
    let s = ed25519_compact::Signature::from_slice(&sig[56..120]).map_err(|_| SigErr::Malformed)?;
    pk.verify(&m[..], &s).map_err(|_| SigErr::BadSignature)?;
    Ok(gen)
}

/// `[P-wansig]`: a signed WAN.TXT verifies; a changed byte, another pack's signature, another key are refused.
pub fn wansig_selftest() -> bool {
    let kp = ed25519_compact::KeyPair::from_seed(ed25519_compact::Seed::new([0x57; 32]));
    let other = ed25519_compact::KeyPair::from_seed(ed25519_compact::Seed::new([0x58; 32]));
    let mut body = [0u8; 512];
    let txt = b"mode=dhcp\nmgmt_floor=10.200.0.0/24\n";
    body[..txt.len()].copy_from_slice(txt);
    let mk = |magic: &[u8; 8], tag: &[u8; 6], kp: &ed25519_compact::KeyPair| crate::artstore::test_sig(magic, tag, 3, &body[..txt.len()], kp);
    let good = verify_wan(&body, &mk(b"HQNSIG1\0", b"HQWAN1", &kp), &kp.pk) == Ok(3);
    let mut tampered = body;
    tampered[txt.len() - 3] = b'5'; // mgmt_floor widened after signing
    let tamper = verify_wan(&tampered, &mk(b"HQNSIG1\0", b"HQWAN1", &kp), &kp.pk) == Err(SigErr::DigestMismatch);
    let cross = verify_wan(&body, &mk(b"HQNSIG1\0", b"HQWIF1", &kp), &kp.pk) == Err(SigErr::BadSignature);
    let wrongkey = verify_wan(&body, &mk(b"HQNSIG1\0", b"HQWAN1", &other), &kp.pk) == Err(SigErr::BadSignature);
    // SEC 2026-11-10 (peer finding): lines APPENDED after the signed length still verify (the digest covers
    // [..len]) — so the parsers must read exactly [..len]: the appended override is invisible there, while the old
    // whole-sector parse would have applied it. And a key given twice is refused outright.
    let signed = b"HQWAN1\nmode=dhcp\n";
    let mut sector = [0u8; 512];
    sector[..signed.len()].copy_from_slice(signed);
    let extra = b"mode=static\nip=203.0.113.9/30\ngw=203.0.113.10\nvlan=4000\n";
    sector[signed.len()..signed.len() + extra.len()].copy_from_slice(extra);
    let ssig = crate::artstore::test_sig(b"HQNSIG1\0", b"HQWAN1", 4, signed, &kp);
    let still_verifies = verify_wan(&sector, &ssig, &kp.pk) == Ok(4);
    let len = u64::from_le_bytes(ssig[16..24].try_into().unwrap()) as usize;
    let appended = still_verifies && len == signed.len()
        && hal::parse_wan_cfg(&sector[..len]) == Ok(hal::WanMode::Dhcp)
        && hal::parse_wan_link(&sector[..len]).is_ok_and(|l| l.vlan == 0)
        && hal::parse_wan_cfg(&sector) == Err(hal::WanCfgErr::Duplicate);
    let dup = hal::parse_wan_cfg(b"HQWAN1\nmode=dhcp\nmode=static\n") == Err(hal::WanCfgErr::Duplicate)
        && hal::parse_wan_link(b"HQWAN1\nvlan=100\n# x\nvlan = 4000\n") == Err(hal::WanCfgErr::Duplicate)
        && hal::parse_wan_cfg(b"HQWAN1\nmode=dhcp\nvlan=100\nmgmt_vlan=200\n") == Ok(hal::WanMode::Dhcp);
    let pass = good && tamper && cross && wrongkey && appended && dup;
    arch_aarch64::_print(format_args!(
        " [P-wansig] {} — WAN.TXT signature (audit finding 11): signed file verifies={} a widened mgmt_floor after signing refused={} a WIFI-tagged signature refused={} another key refused={} | lines appended after the signed length never reach the parser={} a key given twice is refused={}\n",
        if pass { "PASS" } else { "FAIL" }, good, tamper, cross, wrongkey, appended, dup));
    pass
}

/// The operator key the signed-pack loaders verify against: the one compiled into the signed image.
/// `[P-artstore]` swaps in its own key for the duration of the self-test (boot, before any network
/// service starts) and restores it; nothing else writes it.
static mut TEST_KEY: Option<[u8; 32]> = None;
pub fn key() -> Option<[u8; 32]> {
    // The device-pinned anchor (crate::anchor) wins over the image's compiled key once the boot installed it.
    unsafe { TEST_KEY }.or(match crate::anchor::effective() {
        Some(k) => k,
        None => POLICY_PUBKEY,
    })
}

/// The POLICY generation floor: the image's compiled floor or the device's persisted one, whichever is higher.
pub fn floor() -> u64 {
    POLICY_GEN_FLOOR.max(crate::anchor::policy_floor())
}
/// ADR 0058 D3: the key that verifies the owner's CONFIGURATION files (WAN.TXT, WIFI.TXT, POLICY.TXT): the enrolled
/// owner key once there is one, else the vendor/pinned key above (`key()`). Vendor content packs keep `key()`.
pub fn config_key() -> Option<[u8; 32]> {
    unsafe { TEST_KEY }.or(crate::anchor::owner()).or_else(key)
}
/// The keys a configuration file may verify with, by where it was read from: a copy from the artifact store (an
/// upload) only with the owner configuration key; the factory baseline on the boot partition also with the vendor
/// key until the owner replaces it — enrolling never locks the device out of its shipped WAN / Wi-Fi / POLICY
/// (operator rule 7). Nothing remote writes the boot partition (OTA writes only the kernel slots).
pub fn config_keys(from_store: bool) -> [Option<[u8; 32]>; 2] {
    let first = config_key();
    let vendor = if from_store || unsafe { TEST_KEY }.is_some() || crate::anchor::owner().is_none() { None } else { key() };
    [first, vendor.filter(|v| Some(*v) != first)]
}
pub fn selftest_key(k: Option<[u8; 32]>) {
    unsafe { TEST_KEY = k };
}
