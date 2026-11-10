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
//! Rotation (a new key signed by the pinned one) is an operator decision and not built. A factory reflash
//! rewrites the DataVolume and so resets the pin (physical access = the owner's own action).
//!
//! The record also carries the POLICY generation floor: max(compiled floor, persisted floor), raised
//! whenever a newer signed policy is accepted, so an older signed POLICY.TXT cannot come back after a
//! reboot or an image update.
//!
//! Storage: two sectors written alternately (`seq` decides; a torn write leaves the older one), each
//! `HQANCH1\0 | seq | flags | key[32] | policy_floor | sha256(all of the above)`.

use hal::BlockDev;

const MAGIC: &[u8; 8] = b"HQANCH1\0";
const HAS_KEY: u64 = 1;

/// What is pinned on this device.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Anchor {
    pub key: Option<[u8; 32]>,
    pub policy_floor: u64,
    pub seq: u64,
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
    s[..8].copy_from_slice(MAGIC);
    s[8..16].copy_from_slice(&a.seq.to_le_bytes());
    s[16..24].copy_from_slice(&(if a.key.is_some() { HAS_KEY } else { 0 }).to_le_bytes());
    if let Some(k) = a.key {
        s[24..56].copy_from_slice(&k);
    }
    s[56..64].copy_from_slice(&a.policy_floor.to_le_bytes());
    let h = boot_abi::sha256::digest(&s[..64]);
    s[64..96].copy_from_slice(&h);
    s
}

fn decode(s: &[u8; 512]) -> Option<Anchor> {
    if &s[..8] != MAGIC || boot_abi::sha256::digest(&s[..64])[..] != s[64..96] {
        return None;
    }
    let u = |o: usize| u64::from_le_bytes(s[o..o + 8].try_into().unwrap());
    let key = (u(16) & HAS_KEY != 0).then(|| s[24..56].try_into().unwrap());
    Some(Anchor { key, policy_floor: u(56), seq: u(8) })
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
    let a1 = Anchor { key: Some(k), policy_floor: 3, seq: 0 };
    let w1 = store(&mut m, 0, None, a1);
    let r1 = load(&m, 0);
    let w2 = store(&mut m, 0, r1, Anchor { key: Some(k), policy_floor: 5, seq: 0 });
    let r2 = load(&m, 0);
    let round = w1 && w2 && r1.map(|a| (a.key, a.policy_floor, a.seq)) == Some((Some(k), 3, 1))
        && r2.map(|a| (a.policy_floor, a.seq)) == Some((5, 2));
    // a torn newest copy (seq 2 lives in sector 0) falls back to the older record
    m.0[0][30] ^= 1;
    let torn = load(&m, 0).map(|a| a.policy_floor) == Some(3);
    let pass = table && empty && round && torn;
    arch_aarch64::_print(format_args!(
        " [P-anchor] {} — device-pinned policy trust anchor (ADR 0049 D1 TOFU): first key pinned, same key kept, a DIFFERENT image key ignored in favour of the pin, no key in the image never downgrades to unsigned={} ; sealed A/B record round trip (key + persisted POLICY floor)={} ; torn newest copy falls back to the older={}\n",
        if pass { "PASS" } else { "FAIL" }, table, empty && round, torn));
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
        wrote = store(&mut dev, lo, prev, Anchor { key: Some(k), policy_floor: floor, seq: 0 });
    }
    install(d, floor);
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
    let ok = store(&mut dev, lo, prev, Anchor { key, policy_floor: gen, seq: 0 });
    if ok {
        unsafe { FLOOR = gen };
    }
    ok
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
