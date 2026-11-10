//! Device-pinned policy trust anchor (ADR 0049 D1 TOFU, audit 2026-11-10 §2.1 #1).
//!
//! The operator key that authorises POLICY.TXT and every signed pack is compiled into the image by the
//! factory. Without a pin, whoever builds the NEXT image (an OS update) could replace that key and with it
//! the customer's firewall. Here the first key a device sees is PINNED in the DataVolume `Header` region,
//! and from then on the pinned key is the one every verifier uses:
//!
//! | pinned | image key | effective key | action |
//! |---|---|---|---|
//! | none | K | K | pin K (trust on first use) |
//! | none | none | none | standalone device (unsigned files accepted, ADR 0049 D1) |
//! | K | K | K | keep |
//! | K | J ≠ K | **K** | keep K, report the conflict — the image's key is ignored |
//! | K | none | **K** | keep K — never a downgrade to unsigned |
//!
//! ADR 0058 D3 (operator 2026-11-10, rule 3): the OWNER's public key is enrolled at initial provisioning and from
//! then on verifies the owner's CONFIGURATION files (WAN.TXT, WIFI.TXT, POLICY.TXT); the vendor key above keeps
//! verifying vendor content packs (blocklist, IOC, rules, OUI, devices). Enrollment is one-shot (owner session +
//! re-authentication + proof of possession: a signature by the new key over `HQENR1 ‖ key`); after it only a
//! rotation signed by the enrolled owner key (`HQROT1 ‖ new key ‖ generation`, generation strictly increasing)
//! replaces it. The private key never reaches the device. A factory reflash rewrites the DataVolume and so resets
//! both pins (physical access = the owner's own action).
//!
//! The record also carries the POLICY generation floor: max(compiled floor, persisted floor), raised
//! whenever a newer signed policy is accepted, so an older signed POLICY.TXT cannot come back after a
//! reboot or an image update.
//!
//! Storage: two sectors written alternately (`seq` decides; a torn write leaves the older one), each
//! `HQANCH2\0 | seq | flags | key[32] | policy_floor | owner[32] | owner_gen | sha256(all of the above)`
//! (`HQANCH1` records — no owner fields — still decode).

use hal::BlockDev;

const MAGIC: &[u8; 8] = b"HQANCH1\0";
const MAGIC2: &[u8; 8] = b"HQANCH2\0";
const MAGIC3: &[u8; 8] = b"HQANCH3\0";
const HAS_KEY: u64 = 1;
const HAS_OWNER: u64 = 2;

/// What is pinned on this device.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Anchor {
    pub key: Option<[u8; 32]>,
    pub policy_floor: u64,
    pub seq: u64,
    /// ADR 0058 D3: the owner's enrolled configuration key (None until enrolled).
    pub owner: Option<[u8; 32]>,
    /// Rotation generation of the owner key (1 at enrollment).
    pub owner_gen: u64,
    /// ADR 0059 Phase 0.3: WAN / WIFI generation floors (record v3).
    pub cfg: CfgGens,
}

/// Per-type configuration generations (ADR 0059 Phase 0.3, H1). `cur` = the generation last accepted at boot;
/// `floor` = the lowest one still allowed. Accepting a NEWER generation moves the floor to the previous one, so a
/// one-step rollback (the other A/B half, or the boot baseline it replaced) stays possible while any OLDER signed
/// file replayed from the card is refused. cfgd (Phase 2) replaces this with "commit raises the floor to LKG".
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CfgGens {
    pub wan_cur: u64,
    pub wan_floor: u64,
    pub wifi_cur: u64,
    pub wifi_floor: u64,
    /// ADR 0059 step 3: the generation of the last COMMITTED HQCFG1 bundle (cfgd); a new bundle must be above it.
    pub cfg_floor: u64,
}
impl CfgGens {
    pub const ZERO: CfgGens = CfgGens { wan_cur: 0, wan_floor: 0, wifi_cur: 0, wifi_floor: 0, cfg_floor: 0 };
}

/// Self-tests only: put the RAM generation state back.
pub fn test_set_cfg(c: CfgGens) {
    unsafe { CFG = c };
}

/// cfgd committed a bundle: persist its generation as the bundle floor (never lowers it).
pub fn commit_cfg_floor(g: u64) {
    let mut n = cfg_gens();
    if g <= n.cfg_floor {
        return;
    }
    n.cfg_floor = g;
    unsafe { CFG = n };
    #[cfg(all(feature = "cm5", feature = "p15-write"))]
    if let Some((mut dev, lo)) = header_dev() {
        if let Some(p) = load(&dev, lo) {
            let _ = store(&mut dev, lo, Some(p), Anchor { cfg: n, ..p });
        }
    }
}

/// The pure acceptance rule: `Err` = below the floor (a replay); `Ok((cur, floor))` = the new pair.
pub fn accept_gen(cur: u64, floor: u64, g: u64) -> Result<(u64, u64), ()> {
    if g < floor {
        return Err(());
    }
    if cur == 0 {
        return Ok((g, g)); // first accepted generation: nothing older may come back
    }
    if g > cur {
        return Ok((g, floor.max(cur)));
    }
    Ok((g, floor)) // the same generation, or a rollback within the window
}

/// The boot decision (pure — `[P-anchor]` covers every row of the table above).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    /// Nothing pinned yet and the image carries a key: pin it.
    Pin([u8; 32]),
    /// Use the pinned key (the image agrees, or carries none).
    Keep([u8; 32]),
    /// The image carries a DIFFERENT key: keep the pinned one, report the conflict.
    Conflict { pinned: [u8; 32] },
    /// Standalone: no key anywhere.
    Standalone,
}

impl Decision {
    pub fn effective(self) -> Option<[u8; 32]> {
        match self {
            Decision::Pin(k) | Decision::Keep(k) => Some(k),
            Decision::Conflict { pinned } => Some(pinned),
            Decision::Standalone => None,
        }
    }
}

pub fn decide(pinned: Option<[u8; 32]>, image: Option<[u8; 32]>) -> Decision {
    match (pinned, image) {
        (None, Some(k)) => Decision::Pin(k),
        (None, None) => Decision::Standalone,
        (Some(p), Some(k)) if p != k => Decision::Conflict { pinned: p },
        (Some(p), _) => Decision::Keep(p),
    }
}

fn encode(a: &Anchor) -> [u8; 512] {
    let mut s = [0u8; 512];
    s[..8].copy_from_slice(MAGIC2);
    s[8..16].copy_from_slice(&a.seq.to_le_bytes());
    let flags = if a.key.is_some() { HAS_KEY } else { 0 } | if a.owner.is_some() { HAS_OWNER } else { 0 };
    s[16..24].copy_from_slice(&flags.to_le_bytes());
    if let Some(k) = a.key {
        s[24..56].copy_from_slice(&k);
    }
    s[56..64].copy_from_slice(&a.policy_floor.to_le_bytes());
    if let Some(k) = a.owner {
        s[64..96].copy_from_slice(&k);
    }
    s[96..104].copy_from_slice(&a.owner_gen.to_le_bytes());
    s[..8].copy_from_slice(MAGIC3);
    s[104..112].copy_from_slice(&a.cfg.wan_cur.to_le_bytes());
    s[112..120].copy_from_slice(&a.cfg.wan_floor.to_le_bytes());
    s[120..128].copy_from_slice(&a.cfg.wifi_cur.to_le_bytes());
    s[128..136].copy_from_slice(&a.cfg.wifi_floor.to_le_bytes());
    s[136..144].copy_from_slice(&a.cfg.cfg_floor.to_le_bytes());
    let h = boot_abi::sha256::digest(&s[..144]);
    s[144..176].copy_from_slice(&h);
    s
}

fn decode(s: &[u8; 512]) -> Option<Anchor> {
    let u = |o: usize| u64::from_le_bytes(s[o..o + 8].try_into().unwrap());
    let v3 = &s[..8] == MAGIC3;
    let v2 = v3 || &s[..8] == MAGIC2;
    let ok = if v3 {
        boot_abi::sha256::digest(&s[..144])[..] == s[144..176]
    } else if v2 {
        boot_abi::sha256::digest(&s[..104])[..] == s[104..136]
    } else {
        &s[..8] == MAGIC && boot_abi::sha256::digest(&s[..64])[..] == s[64..96]
    };
    if !ok {
        return None;
    }
    let key = (u(16) & HAS_KEY != 0).then(|| s[24..56].try_into().unwrap());
    let owner = (v2 && u(16) & HAS_OWNER != 0).then(|| s[64..96].try_into().unwrap());
    let cfg = if v3 { CfgGens { wan_cur: u(104), wan_floor: u(112), wifi_cur: u(120), wifi_floor: u(128), cfg_floor: u(136) } } else { CfgGens::ZERO };
    Some(Anchor { key, policy_floor: u(56), seq: u(8), owner, owner_gen: if v2 { u(96) } else { 0 }, cfg })
}

/// The owner-enrollment proof of possession: the NEW key signs `HQENR1 ‖ key`.
pub fn enroll_msg(k: &[u8; 32]) -> [u8; 38] {
    let mut m = [0u8; 38];
    m[..6].copy_from_slice(b"HQENR1");
    m[6..].copy_from_slice(k);
    m
}
/// The rotation message the CURRENT owner key signs: `HQROT1 ‖ new key ‖ generation`.
pub fn rotate_msg(k: &[u8; 32], gen: u64) -> [u8; 46] {
    let mut m = [0u8; 46];
    m[..6].copy_from_slice(b"HQROT1");
    m[6..38].copy_from_slice(k);
    m[38..].copy_from_slice(&gen.to_le_bytes());
    m
}
fn ed_ok(pk: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> bool {
    match (ed25519_compact::PublicKey::from_slice(pk), ed25519_compact::Signature::from_slice(sig)) {
        (Ok(p), Ok(s)) => p.verify(msg, &s).is_ok(),
        _ => false,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OwnerErr {
    /// Already enrolled: only a rotation signed by the enrolled key replaces it.
    AlreadyEnrolled,
    /// Nothing enrolled yet: rotate has nothing to rotate from.
    NotEnrolled,
    /// The new key's proof of possession does not verify.
    BadProof,
    /// The rotation is not signed by the enrolled owner key.
    BadRotation,
    /// The rotation generation is not above the current one.
    StaleGeneration,
    /// The new key equals the vendor key or the current owner key.
    SameKey,
}

/// Pure enrollment check (`[P-anchor]`): returns the record to persist.
pub fn check_enroll(cur: Anchor, k: &[u8; 32], proof: &[u8; 64]) -> Result<Anchor, OwnerErr> {
    if cur.owner.is_some() {
        return Err(OwnerErr::AlreadyEnrolled);
    }
    if cur.key == Some(*k) {
        return Err(OwnerErr::SameKey);
    }
    if !ed_ok(k, &enroll_msg(k), proof) {
        return Err(OwnerErr::BadProof);
    }
    Ok(Anchor { owner: Some(*k), owner_gen: 1, ..cur })
}

/// Pure rotation check: signed by the enrolled owner key, generation strictly increasing, and the new key proves
/// possession too.
pub fn check_rotate(cur: Anchor, k: &[u8; 32], gen: u64, sig: &[u8; 64], proof: &[u8; 64]) -> Result<Anchor, OwnerErr> {
    let Some(old) = cur.owner else { return Err(OwnerErr::NotEnrolled) };
    if old == *k || cur.key == Some(*k) {
        return Err(OwnerErr::SameKey);
    }
    if gen <= cur.owner_gen {
        return Err(OwnerErr::StaleGeneration);
    }
    if !ed_ok(&old, &rotate_msg(k, gen), sig) {
        return Err(OwnerErr::BadRotation);
    }
    if !ed_ok(k, &enroll_msg(k), proof) {
        return Err(OwnerErr::BadProof);
    }
    Ok(Anchor { owner: Some(*k), owner_gen: gen, ..cur })
}

/// The newest valid record in the two sectors at `lo` (None = never written / both torn).
pub fn load<D: BlockDev>(d: &D, lo: u64) -> Option<Anchor> {
    let mut best: Option<Anchor> = None;
    for i in 0..2 {
        let mut s = [0u8; 512];
        if d.read_block(lo + i, &mut s).is_ok() {
            if let Some(a) = decode(&s) {
                if best.map_or(true, |b| a.seq > b.seq) {
                    best = Some(a);
                }
            }
        }
    }
    best
}

/// Write `a` (with seq = previous + 1) into the OLDER of the two sectors, then read it back.
pub fn store<D: BlockDev>(d: &mut D, lo: u64, prev: Option<Anchor>, mut a: Anchor) -> bool {
    a.seq = prev.map_or(1, |p| p.seq + 1);
    let slot = a.seq % 2;
    let s = encode(&a);
    if d.write_block(lo + slot, &s).is_err() {
        return false;
    }
    let mut r = [0u8; 512];
    d.read_block(lo + slot, &mut r).is_ok() && r == s
}

static mut EFFECTIVE: Option<Option<[u8; 32]>> = None;
static mut FLOOR: u64 = 0;
static mut OWNER: Option<[u8; 32]> = None;
static mut CFG: CfgGens = CfgGens::ZERO;

/// The WAN / WIFI generation state installed at boot (all zero = nothing accepted yet / no DataVolume).
pub fn cfg_gens() -> CfgGens {
    unsafe { CFG }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum CfgTy {
    Wan,
    Wifi,
}

/// ADR 0059 Phase 0.3: check a verified WAN / WIFI generation against its floor and, when accepted, persist the
/// new (cur, floor). Err = a replay below the floor (the caller refuses the file). A persist failure keeps the
/// RAM state (the floor still applies this boot) and is reported by the caller's log.
pub fn accept_cfg(t: CfgTy, g: u64, from_store: bool) -> Result<(), u64> {
    let c = cfg_gens();
    let (cur, floor) = match t {
        CfgTy::Wan => (c.wan_cur, c.wan_floor),
        CfgTy::Wifi => (c.wifi_cur, c.wifi_floor),
    };
    // peer review 2026-11-10: the one-step rollback window applies only to the STORE (an owner-authenticated
    // rollback); a file on the card must be at least the generation already in force (a card writer cannot replay
    // even the immediately previous signed file). The stored floor itself is unchanged by this check.
    if !from_store && cur != 0 && g < cur {
        return Err(cur);
    }
    let (ncur, nfloor) = accept_gen(cur, floor, g).map_err(|_| floor)?;
    if (ncur, nfloor) == (cur, floor) {
        return Ok(());
    }
    let mut n = c;
    match t {
        CfgTy::Wan => (n.wan_cur, n.wan_floor) = (ncur, nfloor),
        CfgTy::Wifi => (n.wifi_cur, n.wifi_floor) = (ncur, nfloor),
    }
    unsafe { CFG = n };
    #[cfg(all(feature = "cm5", feature = "p15-write"))]
    if let Some((mut dev, lo)) = header_dev() {
        let prev = load(&dev, lo);
        if let Some(p) = prev {
            let _ = store(&mut dev, lo, prev, Anchor { cfg: n, ..p });
        }
    }
    Ok(())
}
static mut OWNER_GEN: u64 = 0;

/// The enrolled owner configuration key (ADR 0058 D3) and its rotation generation.
pub fn owner() -> Option<[u8; 32]> {
    unsafe { OWNER }
}
pub fn owner_gen() -> u64 {
    unsafe { OWNER_GEN }
}
pub fn install_owner(k: Option<[u8; 32]>, gen: u64) {
    unsafe {
        OWNER = k;
        OWNER_GEN = gen;
    }
}

/// Install the boot decision: from now on `policysig::key()` returns the effective key.
pub fn install(dec: Decision, floor: u64) {
    unsafe {
        EFFECTIVE = Some(dec.effective());
        FLOOR = floor;
    }
}

/// The effective key once `install` ran (None before — the caller falls back to the compiled key).
pub fn effective() -> Option<Option<[u8; 32]>> {
    unsafe { *core::ptr::addr_of!(EFFECTIVE) }
}

/// The persisted POLICY generation floor (0 before `install`).
pub fn policy_floor() -> u64 {
    unsafe { FLOOR }
}

/// `[P-anchor]`: the decision table, the record round trip, A/B sectors and a torn newest copy.
pub fn selftest() -> bool {
    struct Mem([[u8; 512]; 2]);
    impl BlockDev for Mem {
        fn block_count(&self) -> u64 {
            2
        }
        fn read_block(&self, lba: u64, b: &mut [u8; 512]) -> Result<(), hal::BlockErr> {
            *b = *self.0.get(lba as usize).ok_or(hal::BlockErr::OutOfRange)?;
            Ok(())
        }
        fn write_block(&mut self, lba: u64, b: &[u8; 512]) -> Result<(), hal::BlockErr> {
            *self.0.get_mut(lba as usize).ok_or(hal::BlockErr::OutOfRange)? = *b;
            Ok(())
        }
    }
    let (k, j) = ([7u8; 32], [9u8; 32]);
    let table = decide(None, Some(k)) == Decision::Pin(k)
        && decide(None, None) == Decision::Standalone
        && decide(Some(k), Some(k)) == Decision::Keep(k)
        && decide(Some(k), Some(j)) == Decision::Conflict { pinned: k }
        && decide(Some(k), Some(j)).effective() == Some(k)
        && decide(Some(k), None) == Decision::Keep(k);
    let mut m = Mem([[0; 512]; 2]);
    let empty = load(&m, 0).is_none();
    let a1 = Anchor { key: Some(k), policy_floor: 3, seq: 0, owner: None, owner_gen: 0, cfg: CfgGens::ZERO };
    let w1 = store(&mut m, 0, None, a1);
    let r1 = load(&m, 0);
    let w2 = store(&mut m, 0, r1, Anchor { key: Some(k), policy_floor: 5, seq: 0, owner: None, owner_gen: 0, cfg: CfgGens::ZERO });
    let r2 = load(&m, 0);
    let round = w1 && w2 && r1.map(|a| (a.key, a.policy_floor, a.seq)) == Some((Some(k), 3, 1))
        && r2.map(|a| (a.policy_floor, a.seq)) == Some((5, 2));
    // a torn newest copy (seq 2 lives in sector 0) falls back to the older record
    m.0[0][30] ^= 1;
    let torn = load(&m, 0).map(|a| a.policy_floor) == Some(3);
    // an HQANCH1 record (before ADR 0058 D3) still decodes, with no owner
    let mut v1 = [0u8; 512];
    v1[..8].copy_from_slice(MAGIC);
    v1[8..16].copy_from_slice(&4u64.to_le_bytes());
    v1[16..24].copy_from_slice(&HAS_KEY.to_le_bytes());
    v1[24..56].copy_from_slice(&k);
    v1[56..64].copy_from_slice(&6u64.to_le_bytes());
    let h = boot_abi::sha256::digest(&v1[..64]);
    v1[64..96].copy_from_slice(&h);
    let compat = decode(&v1) == Some(Anchor { key: Some(k), policy_floor: 6, seq: 4, owner: None, owner_gen: 0, cfg: CfgGens::ZERO });
    // ADR 0058 D3 owner key: enroll needs the new key's proof; one-shot; rotation signed by the enrolled key,
    // generation strictly increasing; the vendor key and the POLICY floor are carried unchanged
    let kp = |b: u8| ed25519_compact::KeyPair::from_seed(ed25519_compact::Seed::new([b; 32]));
    let sign = |p: &ed25519_compact::KeyPair, m: &[u8]| -> [u8; 64] { *p.sk.sign(m, Some(ed25519_compact::Noise::from_slice(&[5u8; 16]).unwrap())) };
    let (o1, o2, x) = (kp(0x51), kp(0x52), kp(0x53));
    let (p1, p2): ([u8; 32], [u8; 32]) = (*o1.pk, *o2.pk);
    let base = Anchor { key: Some(k), policy_floor: 5, seq: 2, owner: None, owner_gen: 0, cfg: CfgGens::ZERO };
    let proof1 = sign(&o1, &enroll_msg(&p1));
    let e = check_enroll(base, &p1, &proof1);
    let enroll = e == Ok(Anchor { owner: Some(p1), owner_gen: 1, ..base })
        && check_enroll(base, &p1, &sign(&x, &enroll_msg(&p1))) == Err(OwnerErr::BadProof)
        && check_enroll(base, &k, &proof1) == Err(OwnerErr::SameKey)
        && e.is_ok_and(|a| check_enroll(a, &p2, &sign(&o2, &enroll_msg(&p2))) == Err(OwnerErr::AlreadyEnrolled));
    let cur = e.unwrap_or(base);
    let proof2 = sign(&o2, &enroll_msg(&p2));
    let rot = check_rotate(cur, &p2, 2, &sign(&o1, &rotate_msg(&p2, 2)), &proof2);
    let rotate = rot == Ok(Anchor { owner: Some(p2), owner_gen: 2, ..cur })
        && check_rotate(cur, &p2, 2, &sign(&x, &rotate_msg(&p2, 2)), &proof2) == Err(OwnerErr::BadRotation)
        && check_rotate(cur, &p2, 1, &sign(&o1, &rotate_msg(&p2, 1)), &proof2) == Err(OwnerErr::StaleGeneration)
        && check_rotate(cur, &p2, 3, &sign(&o1, &rotate_msg(&p2, 2)), &proof2) == Err(OwnerErr::BadRotation)
        && check_rotate(cur, &p2, 2, &sign(&o1, &rotate_msg(&p2, 2)), &proof1) == Err(OwnerErr::BadProof)
        && check_rotate(base, &p2, 2, &sign(&o1, &rotate_msg(&p2, 2)), &proof2) == Err(OwnerErr::NotEnrolled);
    // the owner fields survive the A/B store and a later floor raise
    let mut m2 = Mem([[0; 512]; 2]);
    let w3 = store(&mut m2, 0, None, cur);
    let r3 = load(&m2, 0);
    let w4 = store(&mut m2, 0, r3, Anchor { policy_floor: 9, ..r3.unwrap_or(cur) });
    let persist = w3 && w4 && load(&m2, 0).is_some_and(|a| a.owner == Some(p1) && a.owner_gen == 1 && a.key == Some(k) && a.policy_floor == 9);
    // which key verifies a configuration file: a store copy only the owner key; the boot-partition baseline also
    // the vendor key once an owner is enrolled (never a lock-out); nothing enrolled = the vendor key as before
    let saved = (owner(), owner_gen());
    install_owner(None, 0);
    let v = crate::policysig::key();
    let before = crate::policysig::config_keys(true) == [v, None] && crate::policysig::config_keys(false) == [v, None];
    install_owner(Some(p1), 1);
    let after = crate::policysig::config_keys(true) == [Some(p1), None] && crate::policysig::config_keys(false) == [Some(p1), v];
    install_owner(saved.0, saved.1);
    let scope = before && after;
    // ADR 0059 Phase 0.3: WAN / WIFI generation floors — the first accepted generation is its own floor; a newer one
    // moves the floor to the previous (one-step rollback stays possible); anything older is a replay; v3 record round
    // trip, and a v2 record decodes with no floors
    let rule = accept_gen(0, 0, 5) == Ok((5, 5)) && accept_gen(5, 5, 6) == Ok((6, 5)) && accept_gen(6, 5, 5) == Ok((5, 5))
        && accept_gen(6, 5, 4) == Err(()) && accept_gen(6, 5, 9) == Ok((9, 6)) && accept_gen(9, 6, 9) == Ok((9, 6));
    let g3 = CfgGens { wan_cur: 9, wan_floor: 6, wifi_cur: 3, wifi_floor: 3, cfg_floor: 4 };
    let mut m3 = Mem([[0; 512]; 2]);
    let w5 = store(&mut m3, 0, None, Anchor { cfg: g3, ..cur });
    let v3 = w5 && load(&m3, 0).is_some_and(|a| a.cfg == g3 && a.owner == Some(p1) && a.policy_floor == cur.policy_floor);
    let mut v2r = [0u8; 512];
    v2r[..8].copy_from_slice(MAGIC2);
    v2r[16..24].copy_from_slice(&HAS_KEY.to_le_bytes());
    v2r[24..56].copy_from_slice(&k);
    let h2 = boot_abi::sha256::digest(&v2r[..104]);
    v2r[104..136].copy_from_slice(&h2);
    let v2compat = decode(&v2r).is_some_and(|a| a.key == Some(k) && a.cfg == CfgGens::ZERO);
    // the store path keeps the one-step rollback window; a file on the card must be >= the generation in force
    let saved = cfg_gens();
    unsafe { CFG = CfgGens { wan_cur: 6, wan_floor: 5, ..CfgGens::ZERO } };
    let card = accept_cfg(CfgTy::Wan, 5, false) == Err(6);
    let store_rb = accept_cfg(CfgTy::Wan, 5, true).is_ok() && cfg_gens().wan_floor == 5;
    unsafe { CFG = saved };
    let floors = rule && v3 && v2compat && card && store_rb;
    let owner_ok = compat && enroll && rotate && persist && scope && floors;
    let pass = table && empty && round && torn && owner_ok;
    arch_aarch64::_print(format_args!(
        " [P-anchor] {} — device-pinned policy trust anchor (ADR 0049 D1 TOFU): first key pinned, same key kept, a DIFFERENT image key ignored in favour of the pin, no key in the image never downgrades to unsigned={} ; sealed A/B record round trip (key + persisted POLICY floor)={} ; torn newest copy falls back to the older={} ; ADR 0058 D3 owner key: HQANCH1 compat={} enroll (proof of possession, one-shot, not the vendor key)={} rotate (signed by the enrolled key, generation up, new key proves possession)={} persisted with the vendor key + floor={} key scope (store copy = owner key only, boot-partition baseline also vendor)={} ; ADR 0059 0.3 WAN/WIFI floors: rule (first=floor, newer moves floor to previous, older refused)={} v3 record={} v2 decodes with no floors={}\n",
        if pass { "PASS" } else { "FAIL" }, table, empty && round, torn, compat, enroll, rotate, persist, scope, rule, v3, v2compat));
    pass
}

/// CM5 boot: read the pinned anchor from the DataVolume `Header` region, decide against the image's
/// compiled key, pin on first use, install the result. Without a DataVolume (no persistence in this
/// image or card) nothing can be pinned and the image key is used as before.
#[cfg(all(feature = "cm5", feature = "p15-write"))]
pub fn boot(image: Option<[u8; 32]>) -> (Decision, Option<Anchor>, bool) {
    let fallback = || {
        let d = decide(None, image);
        install(d, 0);
        (d, None, false)
    };
    let Some((mut dev, lo)) = header_dev() else { return fallback() };
    let prev = load(&dev, lo);
    let d = decide(prev.and_then(|a| a.key), image);
    let floor = prev.map_or(0, |a| a.policy_floor);
    let mut wrote = false;
    if let Decision::Pin(k) = d {
        wrote = store(&mut dev, lo, prev, Anchor { key: Some(k), policy_floor: floor, seq: 0, owner: prev.and_then(|a| a.owner), owner_gen: prev.map_or(0, |a| a.owner_gen), cfg: prev.map_or(CfgGens::ZERO, |a| a.cfg) });
    }
    install(d, floor);
    install_owner(prev.and_then(|a| a.owner), prev.map_or(0, |a| a.owner_gen));
    unsafe { CFG = prev.map_or(CfgGens::ZERO, |a| a.cfg) };
    (d, prev, wrote)
}

/// A newer signed POLICY generation was accepted: persist it as the floor (never lowers it).
#[cfg(all(feature = "cm5", feature = "p15-write"))]
pub fn raise_policy_floor(gen: u64) -> bool {
    let Some((mut dev, lo)) = header_dev() else { return false };
    let prev = load(&dev, lo);
    let cur = prev.map_or(0, |a| a.policy_floor);
    if gen <= cur {
        return true;
    }
    let key = prev.and_then(|a| a.key).or_else(|| effective().flatten());
    let ok = store(&mut dev, lo, prev, Anchor { key, policy_floor: gen, seq: 0, owner: prev.and_then(|a| a.owner), owner_gen: prev.map_or(0, |a| a.owner_gen), cfg: prev.map_or(CfgGens::ZERO, |a| a.cfg) });
    if ok {
        unsafe { FLOOR = gen };
    }
    ok
}

/// ADR 0058 D3: enroll (rotate = None) or rotate (Some((gen, sig))) the owner key and persist it. The vendor key
/// and the POLICY floor are carried unchanged.
#[cfg(all(feature = "cm5", feature = "p15-write"))]
pub fn set_owner(k: &[u8; 32], proof: &[u8; 64], rotate: Option<(u64, [u8; 64])>) -> Result<u64, &'static str> {
    let Some((mut dev, lo)) = header_dev() else { return Err("no DataVolume: nothing can be pinned on this card") };
    let prev = load(&dev, lo);
    let cur = prev.unwrap_or(Anchor { key: effective().flatten(), policy_floor: policy_floor(), seq: 0, owner: None, owner_gen: 0, cfg: cfg_gens() });
    let next = match rotate {
        None => check_enroll(cur, k, proof),
        Some((gen, sig)) => check_rotate(cur, k, gen, &sig, proof),
    }
    .map_err(owner_err)?;
    if !store(&mut dev, lo, prev, next) {
        return Err("anchor write / readback failed — nothing changed");
    }
    install_owner(next.owner, next.owner_gen);
    Ok(next.owner_gen)
}

/// Forget the owner key; the vendor key and the POLICY floor (anti-rollback) stay. Idempotent. NOT called by the
/// token-authorised factory reset (ADR 0059 Phase 0.6); kept for the owner-signed reset (HQRST1, Phase 2).
#[cfg(all(feature = "cm5", feature = "p15-write"))]
#[allow(dead_code)]
pub fn clear_owner() -> Result<bool, &'static str> {
    let Some((mut dev, lo)) = header_dev() else { return Err("no DataVolume") };
    let prev = load(&dev, lo);
    let Some(cur) = prev.filter(|a| a.owner.is_some()) else { return Ok(false) };
    if !store(&mut dev, lo, prev, Anchor { owner: None, owner_gen: 0, ..cur }) {
        return Err("anchor write / readback failed");
    }
    install_owner(None, 0);
    Ok(true)
}

pub fn owner_err(e: OwnerErr) -> &'static str {
    match e {
        OwnerErr::AlreadyEnrolled => "an owner key is already enrolled (rotate it with a signature by that key)",
        OwnerErr::NotEnrolled => "no owner key enrolled yet (enroll first)",
        OwnerErr::BadProof => "the new key's proof of possession does not verify",
        OwnerErr::BadRotation => "the rotation is not signed by the enrolled owner key",
        OwnerErr::StaleGeneration => "the rotation generation must be above the current one",
        OwnerErr::SameKey => "the new key must differ from the vendor key and the current owner key",
    }
}

/// An eMMC handle whose only writable sectors are the two anchor sectors (its own Gate-2 window).
#[cfg(all(feature = "cm5", feature = "p15-write"))]
fn header_dev() -> Option<(arch_aarch64::emmc::Emmc, u64)> {
    let mut dev = arch_aarch64::emmc::Emmc::probe().ok()?;
    let mut mbr = [0u8; 512];
    dev.read_block(0, &mut mbr).ok()?;
    let dv = crate::datavol::DataVol::from_mbr(&mbr)?;
    let (lo, _) = dv.region(crate::datavol::Region::Header);
    let (blo, bhi) = dv.bounds();
    dev.set_data_volume(blo, bhi);
    if dev.arm_write_window(lo, lo + 2) != (lo, lo + 2) {
        return None;
    }
    Some((dev, lo))
}
