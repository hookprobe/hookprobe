//! ADR 0056 D5 — the artifact store: signed data packs uploaded to a running device live here, in the
//! DataVolume `Store` region (datavol.rs), never over the boot-FAT copy.
//!
//! Layout inside the Store region (sectors, relative to its start):
//!
//! | Offset | What |
//! |---|---|
//! | 0, 1 | manifest, two alternating copies (highest valid `seq` wins; a torn write leaves the other) |
//! | 64 .. 64 + HALF | half A: per type, 1 signature sector + the file's sectors (at its cap) |
//! | 64 + HALF .. 64 + 2*HALF | half B: the same layout |
//!
//! Activation (ADR 0056 D5) writes the INACTIVE half of a type, reads it back, commits a new manifest
//! (one sector — atomic on eMMC), then reloads the module through its REAL boot loader. The loaders find
//! the pack through `locate`, which prefers the store's committed slot when its signed generation is >= the
//! boot-FAT copy's (a reflash with a newer generation always wins back). A loader refusal after the
//! commit (e.g. tampered at rest) disables the store entry for this boot and reloads from FAT.
//!
//! Nothing here is trusted: the signature (verified by each module's own verifier) is the authority.

use hal::{BlockDev, BlockErr};

/// The pack types a running device accepts (ADR 0056 D2, phase 1 — POLICY / os_image are not here yet).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Ty {
    Block = 0,
    Allow = 1,
    Ioc = 2,
    Rules = 3,
    Oui = 4,
    Devices = 5,
    /// ADR 0058: owner/operator-signed runtime configuration — STAGED (applies at the next boot, verified again
    /// by its boot loader); appended after the packs so existing slot offsets never move.
    Wan = 6,
    Wifi = 7,
    Policy = 8,
    /// ADR 0059 step 2: the HQCFG1 configuration bundle (wan + wifi + policy in ONE signed unit) — staged; cfgd
    /// runs it as a health-checked trial (step 3).
    Config = 9,
}
pub const NTY: usize = 10;
pub const ALL: [Ty; NTY] = [Ty::Block, Ty::Allow, Ty::Ioc, Ty::Rules, Ty::Oui, Ty::Devices, Ty::Wan, Ty::Wifi, Ty::Policy, Ty::Config];
/// Types at or past this index live in the SECOND manifest pair (store sectors 2/3, "HQSTMAN2"): the first
/// manifest sector holds 6 entries; each group commits atomically on its own sector.
pub const G1_FIRST: usize = 6;
fn group(t: Ty) -> usize {
    if (t as usize) < G1_FIRST { 0 } else { 1 }
}
impl Ty {
    /// Staged types apply at the next boot (their loaders run once, at boot) — never hot-reloaded.
    pub fn staged(self) -> bool {
        matches!(self, Ty::Wan | Ty::Wifi | Ty::Policy | Ty::Config)
    }
}

pub struct TyInfo {
    pub name: &'static str,
    pub txt: &'static [u8; 11],
    pub sig: &'static [u8; 11],
    pub magic: &'static [u8; 8],
    /// Largest file the type's loader reads (bytes).
    pub cap: u64,
}

const TYPES: [TyInfo; NTY] = [
    TyInfo { name: "shield_block", txt: b"BLOCK   TXT", sig: b"BLOCK   SIG", magic: b"HQBSIG1\0", cap: 16 << 20 },
    TyInfo { name: "shield_allow", txt: b"ALLOW   TXT", sig: b"ALLOW   SIG", magic: b"HQASIG1\0", cap: 16 << 20 },
    TyInfo { name: "ioc", txt: b"IOC     TXT", sig: b"IOC     SIG", magic: b"HQISIG1\0", cap: 16 << 20 },
    TyInfo { name: "rules", txt: b"RULES   BIN", sig: b"RULES   SIG", magic: b"HQRSIG1\0", cap: 64 << 10 },
    TyInfo { name: "oui", txt: b"OUI     TXT", sig: b"OUI     SIG", magic: b"HQOSIG1\0", cap: 4 << 20 },
    TyInfo { name: "devices", txt: b"DEVICES TXT", sig: b"DEVICES SIG", magic: b"HQDSIG1\0", cap: 16 << 10 },
    TyInfo { name: "wan", txt: b"WAN     TXT", sig: b"WAN     SIG", magic: b"HQNSIG1\0", cap: 512 },
    TyInfo { name: "wifi", txt: b"WIFI    TXT", sig: b"WIFI    SIG", magic: b"HQWSIG1\0", cap: 1024 },
    TyInfo { name: "policy", txt: b"POLICY  TXT", sig: b"POLICY  SIG", magic: b"HQPSIG1\0", cap: hal::policy::POLICY_FILE_LEN as u64 },
    TyInfo { name: "config", txt: b"CONFIG  BIN", sig: b"CONFIG  SIG", magic: b"HQCSIG1\0", cap: crate::cfgbundle::MAX_BUNDLE as u64 },
];

impl Ty {
    pub fn info(self) -> &'static TyInfo {
        &TYPES[self as usize]
    }
    pub fn from_name(s: &str) -> Option<Ty> {
        ALL.iter().copied().find(|t| t.info().name == s)
    }
    pub fn from_u8(v: u8) -> Option<Ty> {
        ALL.get(v as usize).copied()
    }
    fn data_sect(self) -> u64 {
        self.info().cap.div_ceil(512)
    }
    /// Sector offset of this type's slot inside a half (signature sector first, then data).
    fn off(self) -> u64 {
        ALL[..self as usize].iter().map(|t| 1 + t.data_sect()).sum()
    }
}

pub const MAN_SECT: u64 = 64;
/// Sectors per half (fits every type at its cap: ~52 MiB of the 56 MiB the registry reserves per half).
pub fn half_span(store: (u64, u64)) -> u64 {
    (store.1 - store.0 - MAN_SECT) / 2
}
fn need_per_half() -> u64 {
    ALL.iter().map(|t| 1 + t.data_sect()).sum()
}

/// One manifest entry: which half is active for a type (0 none, 1 A, 2 B) + what it holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Entry {
    pub half: u8,
    pub gen: u64,
    pub len: u64,
    pub digest: [u8; 32],
    /// ADR 0059 step 3 (cfgd): STATE_ACTIVE (committed / last-known-good) or STATE_PENDING (on trial).
    pub state: u8,
    /// Boots started while PENDING (a second boot while PENDING reverts).
    pub trials: u8,
    /// Sealed at rest (design heqk-sealed-config-live-apply §2): the slot holds an HQKSEAL1 blob under the per-type
    /// configuration key and `digest` is the hash of the SEALED image. Once set, a plaintext slot of this type is
    /// refused (no downgrade). Manifest byte `o+3`; an older manifest decodes as 0.
    pub sealed: u8,
}
pub const STATE_ACTIVE: u8 = 0;
pub const STATE_PENDING: u8 = 1;
pub const E0: Entry = Entry { half: 0, gen: 0, len: 0, digest: [0; 32], state: STATE_ACTIVE, trials: 0, sealed: 0 };

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Manifest {
    /// Commit sequence of group 0 (the packs, sectors 0/1).
    pub seq: u64,
    /// Commit sequence of group 1 (the staged configuration types, sectors 2/3).
    pub seq2: u64,
    pub e: [Entry; NTY],
}
pub const MAN0: Manifest = Manifest { seq: 0, seq2: 0, e: [E0; NTY] };
const MAGIC: &[u8; 8] = b"HQSTMAN1";
const MAGIC2: &[u8; 8] = b"HQSTMAN2";

impl Manifest {
    fn range(g: usize) -> core::ops::Range<usize> {
        if g == 0 { 0..G1_FIRST } else { G1_FIRST..NTY }
    }
    fn encode_g(&self, g: usize) -> [u8; 512] {
        let mut s = [0u8; 512];
        s[..8].copy_from_slice(if g == 0 { MAGIC } else { MAGIC2 });
        s[8..16].copy_from_slice(&(if g == 0 { self.seq } else { self.seq2 }).to_le_bytes());
        for (k, i) in Self::range(g).enumerate() {
            let e = &self.e[i];
            let o = 16 + k * 56;
            s[o] = e.half;
            s[o + 1] = e.state;
            s[o + 2] = e.trials;
            s[o + 3] = e.sealed;
            s[o + 8..o + 16].copy_from_slice(&e.gen.to_le_bytes());
            s[o + 16..o + 24].copy_from_slice(&e.len.to_le_bytes());
            s[o + 24..o + 56].copy_from_slice(&e.digest);
        }
        let d = boot_abi::sha256::digest(&s[..480]);
        s[480..].copy_from_slice(&d);
        s
    }
    /// Decode group `g` of a sector into `m` (its entries + seq). None = not a valid manifest of that group.
    fn decode_g(s: &[u8; 512], g: usize, m: &mut Manifest) -> Option<()> {
        if &s[..8] != (if g == 0 { MAGIC } else { MAGIC2 }) || boot_abi::sha256::digest(&s[..480])[..] != s[480..] {
            return None;
        }
        let seq = u64::from_le_bytes(s[8..16].try_into().ok()?);
        let mut e = [E0; NTY];
        for (k, i) in Self::range(g).enumerate() {
            let o = 16 + k * 56;
            e[i].half = s[o];
            e[i].state = s[o + 1];
            e[i].trials = s[o + 2];
            e[i].sealed = s[o + 3];
            if e[i].half > 2 || e[i].state > STATE_PENDING || e[i].sealed > 1 {
                return None;
            }
            e[i].gen = u64::from_le_bytes(s[o + 8..o + 16].try_into().ok()?);
            e[i].len = u64::from_le_bytes(s[o + 16..o + 24].try_into().ok()?);
            e[i].digest.copy_from_slice(&s[o + 24..o + 56]);
        }
        for i in Self::range(g) {
            m.e[i] = e[i];
        }
        if g == 0 { m.seq = seq } else { m.seq2 = seq }
        Some(())
    }
    fn decode(s: &[u8; 512]) -> Option<Manifest> {
        let mut m = MAN0;
        Self::decode_g(s, 0, &mut m)?;
        Some(m)
    }
}

/// [P-fuzz]: the manifest decoder on arbitrary sector content.
pub fn fuzz_decode(s: &[u8; 512]) -> bool {
    Manifest::decode(s).is_some()
}

/// The Store region of this device (from the MBR's 0xDA DataVolume), if any.
pub fn store_region<D: BlockDev + ?Sized>(dev: &D) -> Option<(u64, u64)> {
    let mut mbr = [0u8; 512];
    dev.read_block(0, &mut mbr).ok()?;
    let r = crate::datavol::DataVol::from_mbr(&mbr)?.region(crate::datavol::Region::Store);
    (half_span(r) >= need_per_half()).then_some(r)
}

/// The committed manifest (MAN0 when the store was never written).
pub fn read_manifest<D: BlockDev + ?Sized>(dev: &D, store: (u64, u64)) -> Manifest {
    let mut out = MAN0;
    let mut s = [0u8; 512];
    for g in 0..2usize {
        // each group: the higher valid seq of its two alternating copies
        let mut best: Option<Manifest> = None;
        for k in 0..2u64 {
            let mut m = MAN0;
            if dev.read_block(store.0 + 2 * g as u64 + k, &mut s).is_ok() && Manifest::decode_g(&s, g, &mut m).is_some() {
                let seq = if g == 0 { m.seq } else { m.seq2 };
                if best.as_ref().map_or(true, |b| seq >= if g == 0 { b.seq } else { b.seq2 }) {
                    best = Some(m);
                }
            }
        }
        if let Some(b) = best {
            for i in Manifest::range(g) {
                out.e[i] = b.e[i];
            }
            if g == 0 { out.seq = b.seq } else { out.seq2 = b.seq2 }
        }
    }
    out
}

/// Absolute LBA of a type's slot in `half` (1 = A, 2 = B): (signature sector, first data sector).
pub fn slot(store: (u64, u64), t: Ty, half: u8) -> (u64, u64) {
    let base = store.0 + MAN_SECT + (half as u64 - 1) * half_span(store) + t.off();
    (base, base + 1)
}

/// Types whose store copy failed its loader this boot (RAM only): `locate` falls back to FAT.
static mut DISABLED: u16 = 0;
pub fn disable(t: Ty) {
    unsafe { DISABLED |= 1 << t as u8 };
}
fn disabled(t: Ty) -> bool {
    unsafe { DISABLED & (1 << t as u8) != 0 }
}

/// Signed generation in a signature sector (all pack formats: magic(8) | gen u64 LE | ...).
fn sig_gen<D: BlockDev + ?Sized>(dev: &D, lba: u64, magic: &[u8; 8]) -> Option<u64> {
    let mut s = [0u8; 512];
    dev.read_block(lba, &mut s).ok()?;
    (&s[..8] == magic).then(|| u64::from_le_bytes(s[8..16].try_into().unwrap()))
}

/// The store's committed slot for a type, if it is at least as new as the boot-FAT copy:
/// `Some((sig_lba, data_lba, data_sect))`. Touches only the small FAT `.SIG` file (never walks the
/// pack's own cluster chain — a 4 MiB OUI.TXT walk costs seconds on the eMMC).
/// ADR 0059 Phase 0.4 (H2): types whose ACTIVE store half was refused this boot and that now read the OTHER half
/// (the previous generation) before falling back to the boot-partition baseline. RAM only.
static mut OTHER: u16 = 0;
fn use_other(t: Ty) -> bool {
    unsafe { OTHER & (1 << t as u8) != 0 }
}

fn store_copy<D: BlockDev>(dev: &D, p1: u64, t: Ty) -> Option<(u64, u64, u64)> {
    if disabled(t) {
        return None;
    }
    let store = store_region(dev)?;
    let mut e = read_manifest(dev, store).e[t as usize];
    if e.half == 0 {
        return None;
    }
    if use_other(t) {
        // the previous generation: whatever its signature sector says (the loader verifies it, the floor applies)
        e.half = if e.half == 1 { 2 } else { 1 };
        let mut sec = [0u8; 512];
        dev.read_block(slot(store, t, e.half).0, &mut sec).ok()?;
        if &sec[..8] != t.info().magic {
            return None;
        }
        e.gen = u64::from_le_bytes(sec[8..16].try_into().unwrap());
    }
    let i = t.info();
    let fat_gen = if p1 != 0 { crate::fat::locate_contiguous(dev, p1, i.sig).and_then(|(l, _)| sig_gen(dev, l, i.magic)) } else { None };
    if e.gen < fat_gen.unwrap_or(0) {
        return None;
    }
    let (s, d) = slot(store, t, e.half);
    Some((s, d, t.data_sect()))
}

/// The loaders' file lookup (replaces `fat::locate_contiguous` for the pack files): the store's committed
/// slot when it is at least as new as the boot-FAT copy, else the FAT file. Same `(lba, sectors)` shape.
pub fn locate<D: BlockDev>(dev: &D, p1: u64, name: &[u8; 11]) -> Option<(u64, u64)> {
    if let Some(t) = ALL.iter().copied().find(|t| name == t.info().txt || name == t.info().sig) {
        if let Some((s, d, n)) = store_copy(dev, p1, t) {
            return Some(if name == t.info().sig { (s, 1) } else { (d, n) });
        }
    }
    if p1 != 0 { crate::fat::locate_contiguous(dev, p1, name) } else { None }
}

/// The active generation of a type (store or FAT), 0 if none — the anti-rollback floor for an upload.
pub fn active_gen<D: BlockDev>(dev: &D, p1: u64, t: Ty) -> u64 {
    // HQCSIG1 carries no generation at [8..16] (alg | total_len | digest — the generation lives inside the signed
    // bundle): the manifest records it at activation. Metal batch 61: reading [8..16] gave a garbage "active"
    // generation that refused every newer bundle.
    if t == Ty::Config {
        return match locate(dev, p1, t.info().sig) {
            Some(_) => entry(dev, t).map(|e| e.gen).unwrap_or(0),
            None => 0,
        };
    }
    match locate(dev, p1, t.info().sig) {
        Some((s, _)) => sig_gen(dev, s, t.info().magic).unwrap_or(0),
        None => 0,
    }
}
pub fn from_store<D: BlockDev>(dev: &D, p1: u64, t: Ty) -> bool {
    store_copy(dev, p1, t).is_some()
}

// ---- verification (each module's OWN verifier — ADR 0056 D4: no second verifier) ----------------------

static mut VBUF: [u8; 65536] = [0; 65536];

/// Verify a pack whose signature sector is `sig` and whose bytes start at `data_lba` (at most `cap`
/// bytes readable). Ok((generation, length)).
pub fn verify<D: BlockDev + ?Sized>(dev: &D, t: Ty, sig: &[u8; 512], data_lba: u64, key: &[u8; 32]) -> Result<(u64, u64), crate::shield::LoadErr> {
    use crate::shield::LoadErr;
    let cap = t.info().cap;
    let mut digest_of = |len: u64| -> Option<[u8; 32]> {
        if len > cap {
            return None;
        }
        let mut h = boot_abi::sha256::Hasher::new();
        crate::store::stream_blocks(dev, data_lba, len, &mut |c| h.update(c))?;
        Some(h.finish())
    };
    match t {
        Ty::Block => crate::shield::check_sig(b"HQBSIG1\0", b"HQBLK1", sig, key, &mut digest_of),
        Ty::Allow => crate::shield::check_sig(b"HQASIG1\0", b"HQALW1", sig, key, &mut digest_of),
        Ty::Ioc => crate::ioc::check_sig(sig, key, &mut digest_of),
        Ty::Oui => crate::oui::check_sig(sig, key, &mut digest_of),
        Ty::Wan | Ty::Wifi | Ty::Policy => {
            let mut buf = [0u8; hal::policy::POLICY_FILE_LEN];
            let n = (cap as usize).min(buf.len());
            let mut sec = [0u8; 512];
            for k in 0..n / 512 {
                dev.read_block(data_lba + k as u64, &mut sec).map_err(|_| LoadErr::Io)?;
                buf[k * 512..k * 512 + 512].copy_from_slice(&sec);
            }
            match t {
                Ty::Wan => crate::policysig::verify_wan(&buf[..n], sig, key).map(|g| (g, u64::from_le_bytes(sig[16..24].try_into().unwrap()))).map_err(|_| LoadErr::BadSignature),
                Ty::Wifi => crate::wificfg::check_sig(sig, key, &buf[..n]).map(|(g, l)| (g, l as u64)).ok_or(LoadErr::BadSignature),
                _ => {
                    let r = crate::policysig::verify(&buf[..n], sig, key, crate::policysig::floor()).map(|g| (g, n as u64)).map_err(|_| LoadErr::BadSignature);
                    if r.is_ok() {
                        check_policy_parses(&buf[..n]);
                    }
                    r
                }
            }
        }
        Ty::Config => {
            // ADR 0059 step 2: the bundle is exactly total_len bytes (from the HQCSIG1); cfgbundle verifies it whole
            let len = u32::from_le_bytes([sig[9], sig[10], sig[11], sig[12]]) as usize;
            if len > cap as usize || len < crate::cfgbundle::HDR {
                return Err(LoadErr::BadSignature);
            }
            let buf = unsafe { &mut *core::ptr::addr_of_mut!(VBUF) };
            let mut sec = [0u8; 512];
            for k in 0..len.div_ceil(512) {
                dev.read_block(data_lba + k as u64, &mut sec).map_err(|_| LoadErr::Io)?;
                buf[k * 512..k * 512 + 512].copy_from_slice(&sec);
            }
            let v = crate::cfgbundle::verify(&buf[..len], sig, key, &crate::config_device_id(), 0).map_err(|_| LoadErr::BadSignature)?;
            // ADR 0059 D7: remember whether this bundle keeps a management path (upload finish refuses it if not)
            let ok = crate::cfgd::keeps_mgmt_path(v.section(crate::cfgbundle::KIND_POLICY));
            unsafe { CONFIG_MGMT_OK = ok };
            // step 8: which subsystems this bundle changes (only LIVE_CAPABLE ones are applied without a reboot)
            unsafe {
                CONFIG_CHANGES = crate::cfgd::changes_vs(
                    v.section(crate::cfgbundle::KIND_POLICY),
                    v.section(crate::cfgbundle::KIND_WAN),
                    v.section(crate::cfgbundle::KIND_WIFI),
                )
            };
            // Q3: does this bundle carry a secret (a Wi-Fi section, or a WAN section with a PPPoE password)?
            unsafe { CONFIG_SECRET = v.section(crate::cfgbundle::KIND_WIFI).is_some() || v.section(crate::cfgbundle::KIND_WAN).is_some_and(wan_has_secret) };
            unsafe { POLICY_REFUSED = None };
            if let Some(sec) = v.section(crate::cfgbundle::KIND_POLICY) {
                let mut f = [0u8; 4096];
                if crate::cfgbundle::policy_file(sec, &mut f) {
                    check_policy_parses(&f);
                } else {
                    unsafe { POLICY_REFUSED = Some(hal::policy::PolicyErr::Full(0)) };
                }
            }
            Ok((v.generation, len as u64))
        }
        Ty::Devices | Ty::Rules => {
            let buf = unsafe { &mut *core::ptr::addr_of_mut!(VBUF) };
            let n = (cap as usize).min(buf.len());
            let mut sec = [0u8; 512];
            for k in 0..n / 512 {
                dev.read_block(data_lba + k as u64, &mut sec).map_err(|_| LoadErr::Io)?;
                buf[k * 512..k * 512 + 512].copy_from_slice(&sec);
            }
            let len = u64::from_le_bytes(sig[16..24].try_into().unwrap());
            if t == Ty::Devices {
                crate::devpolicy::check_sig(sig, key, &buf[..n]).map(|g| (g, len))
            } else {
                crate::rulepack::check_sig(sig, key, &buf[..n]).map(|(g, l)| (g, l as u64)).ok_or(LoadErr::BadSignature)
            }
        }
    }
}

/// Reload one module through its real boot loader. Err = the loader refused the active copy.
pub fn reload<D: BlockDev>(dev: &D, t: Ty) -> Result<(), ()> {
    let ok = match t {
        Ty::Block | Ty::Allow => {
            let i = crate::shield::load(dev);
            i.refused.is_none()
        }
        Ty::Ioc => crate::ioc::load(dev).file != 2,
        Ty::Rules => crate::rulepack::load(dev).file != 2,
        Ty::Oui => crate::oui::load(dev).file != 2,
        Ty::Devices => crate::devpolicy::load(dev).file != 2,
        // ADR 0058: staged — its boot loader verifies it again at the next boot (a refusal there falls back)
        Ty::Wan | Ty::Wifi | Ty::Policy | Ty::Config => true,
    };
    if ok { Ok(()) } else { Err(()) }
}

/// Boot: a store copy its loader refused (tampered / torn at rest) is disabled for this boot and the module
/// reloaded from the boot-FAT copy. Returns true when it fell back.
pub fn boot_fallback<D: BlockDev>(dev: &D, p1: u64, t: Ty, refused: bool) -> bool {
    if refused && fallback_step(dev, p1, t) {
        if reload(dev, t).is_err() && fallback_step(dev, p1, t) {
            let _ = reload(dev, t);
        }
        return true;
    }
    false
}

/// One step down the boot order after the copy just read was refused (ADR 0059 Phase 0.4): the active store half
/// -> the OTHER store half (the previous generation, if it carries a signature) -> the boot-partition baseline.
/// Returns true when there is something new to try (the caller re-runs its loader), false when nothing is left.
pub fn fallback_step<D: BlockDev>(dev: &D, p1: u64, t: Ty) -> bool {
    if !from_store(dev, p1, t) {
        return false; // already on the boot partition (or nothing at all)
    }
    if !use_other(t) {
        unsafe { OTHER |= 1 << t as u8 };
        if from_store(dev, p1, t) {
            return true; // the other half exists: try it
        }
    }
    disable(t);
    true
}

// ---- activation (write build) ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActErr {
    NoStore,
    Io,
    Readback,
    /// The module's loader refused the new copy after commit — rolled back to the previous one.
    LoaderRefused,
    /// Rollback: no other half, or it does not verify.
    NothingToRollBack,
}

/// Where `activate` reads the pack's bytes from: device sectors (disk staging) or a RAM container body.
#[derive(Clone, Copy)]
pub enum Src<'a> {
    Lba(u64),
    Ram(&'a [u8]),
}

/// Copy a verified pack (`sig` + `len` bytes at `src_lba` — the staging area) into the inactive half of
/// type `t`, read it back, commit the manifest, reload the module. On a loader refusal the previous
/// manifest is re-committed and the module reloaded again (rollback). `dev` must already have its write
/// window armed over the Store region.
pub fn activate<D: BlockDev>(dev: &mut D, t: Ty, sig: &[u8; 512], src_lba: u64, gen: u64, len: u64, digest: &[u8; 32]) -> Result<Manifest, ActErr> {
    activate_from(dev, t, sig, Src::Lba(src_lba), gen, len, digest)
}
/// `activate` with the bytes from `src` (a RAM-staged upload: `Src::Ram(file bytes)`).
pub fn activate_from<D: BlockDev>(dev: &mut D, t: Ty, sig: &[u8; 512], src: Src, gen: u64, len: u64, digest: &[u8; 32]) -> Result<Manifest, ActErr> {
    let store = store_region(dev).ok_or(ActErr::NoStore)?;
    let old = read_manifest(dev, store);
    let cur = old.e[t as usize].half;
    let half = if cur == 1 { 2 } else { 1 };
    let (sl, dl) = slot(store, t, half);
    let n = len.div_ceil(512);
    let mut sec = [0u8; 512];
    for k in 0..n {
        match src {
            Src::Lba(l) => dev.read_block(l + k, &mut sec).map_err(|_| ActErr::Io)?,
            Src::Ram(r) => {
                let o = (k * 512) as usize;
                let e = (o + 512).min(r.len());
                sec = [0; 512];
                if o < e {
                    sec[..e - o].copy_from_slice(&r[o..e]);
                }
            }
        }
        dev.write_block(dl + k, &sec).map_err(|_| ActErr::Io)?;
    }
    dev.write_block(sl, sig).map_err(|_| ActErr::Io)?;
    // read back through the device: the digest of what is now in the slot
    let mut h = boot_abi::sha256::Hasher::new();
    let mut left = len;
    for k in 0..n {
        dev.read_block(dl + k, &mut sec).map_err(|_| ActErr::Io)?;
        let take = left.min(512) as usize;
        h.update(&sec[..take]);
        left -= take as u64;
    }
    let mut back = [0u8; 512];
    dev.read_block(sl, &mut back).map_err(|_| ActErr::Io)?;
    if h.finish() != *digest || back != *sig {
        return Err(ActErr::Readback);
    }
    let g = group(t);
    let mut m = old;
    if g == 0 { m.seq = old.seq + 1 } else { m.seq2 = old.seq2 + 1 }
    // a new configuration bundle starts as a cfgd TRIAL (PENDING); everything else is committed at once
    let state = if t == Ty::Config { STATE_PENDING } else { STATE_ACTIVE };
    m.e[t as usize] = Entry { half, gen, len, digest: *digest, state, trials: 0, sealed: 0 };
    commit(dev, store, &m, g)?;
    unsafe { DISABLED &= !(1 << t as u8) };
    if reload(dev, t).is_err() {
        let mut back = old;
        if g == 0 { back.seq = m.seq + 1 } else { back.seq2 = m.seq2 + 1 }
        let _ = commit(dev, store, &back, g);
        let _ = reload(dev, t);
        return Err(ActErr::LoaderRefused);
    }
    Ok(m)
}

fn commit<D: BlockDev + ?Sized>(dev: &mut D, store: (u64, u64), m: &Manifest, g: usize) -> Result<(), ActErr> {
    let s = m.encode_g(g);
    let lba = store.0 + 2 * g as u64 + ((if g == 0 { m.seq } else { m.seq2 }) & 1);
    dev.write_block(lba, &s).map_err(|_| ActErr::Io)?;
    let mut back = [0u8; 512];
    dev.read_block(lba, &mut back).map_err(|_| ActErr::Io)?;
    if back != s {
        return Err(ActErr::Readback);
    }
    Ok(())
}

static mut CONFIG_MGMT_OK: bool = true;
static mut CONFIG_CHANGES: u8 = 0xff;
/// Step 8: the subsystems the last `config` bundle `verify` saw would change.
pub fn config_changes() -> u8 {
    unsafe { CONFIG_CHANGES }
}
static mut CONFIG_SECRET: bool = false;
/// Q3: whether the last `config` bundle `verify` saw carries a secret.
pub fn config_secret() -> bool {
    unsafe { CONFIG_SECRET }
}
/// Q3: a WAN body that carries the PPPoE password.
pub fn wan_has_secret(b: &[u8]) -> bool {
    b.windows(11).any(|w| w == b"pppoe_pass=")
}
/// Routing review 2026-11-11: a staged POLICY (per-file, or a bundle's policy section) must PARSE, not only verify —
/// a signed policy the parser refuses would put the device into the management lockdown at the next boot.
/// The result of the last `verify` that carried a policy (None = parses / no policy).
static mut POLICY_REFUSED: Option<hal::policy::PolicyErr> = None;
static mut PSCRATCH: hal::policy::Policy = hal::policy::Policy::new();
fn check_policy_parses(file: &[u8]) {
    let p = unsafe { &mut *core::ptr::addr_of_mut!(PSCRATCH) };
    *p = hal::policy::Policy::new();
    let r = hal::policy::parse_policy(file, p).err().filter(|e| *e != hal::policy::PolicyErr::Unsigned);
    unsafe { POLICY_REFUSED = r };
}
/// Why the last staged policy would be refused at boot (upload finish refuses it now).
pub fn policy_refused() -> Option<hal::policy::PolicyErr> {
    unsafe { POLICY_REFUSED }
}
/// The management-path invariant of the last `config` bundle `verify` saw (ADR 0059 D7).
pub fn config_mgmt_ok() -> bool {
    unsafe { CONFIG_MGMT_OK }
}

/// ADR 0059 step 3 (cfgd): rewrite one entry's trial state / half and commit its manifest group.
pub fn set_entry<D: BlockDev + ?Sized>(dev: &mut D, t: Ty, f: impl FnOnce(&mut Entry)) -> Result<Entry, ActErr> {
    let store = store_region(dev).ok_or(ActErr::NoStore)?;
    let mut m = read_manifest(dev, store);
    f(&mut m.e[t as usize]);
    let g = group(t);
    if g == 0 { m.seq += 1 } else { m.seq2 += 1 }
    commit(dev, store, &m, g)?;
    Ok(m.e[t as usize])
}

/// The type's current entry (E0 = nothing committed).
pub fn entry<D: BlockDev + ?Sized>(dev: &D, t: Ty) -> Option<Entry> {
    let store = store_region(dev)?;
    Some(read_manifest(dev, store).e[t as usize])
}

/// Read a half's signature sector + verify it with the type's verifier: (gen, len, data_lba).
pub fn verify_half<D: BlockDev + ?Sized>(dev: &D, t: Ty, half: u8, key: &[u8; 32]) -> Option<(u64, u64, u64)> {
    let store = store_region(dev)?;
    let (sl, dl) = slot(store, t, half);
    let p = Plain::new(dev);
    let mut sig = [0u8; 512];
    p.read_block(sl, &mut sig).ok()?;
    let (g, l) = verify(&p, t, &sig, dl, key).ok()?;
    Some((g, l, dl))
}

/// ADR 0058: re-activate the OTHER half of a type (the previous generation), after verifying it again with the
/// type's own verifier. Staged types apply at the next boot; packs reload now (rolled back on refusal). POLICY can
/// never go below its persisted generation floor (its verifier refuses — `policysig::floor`).
pub fn rollback<D: BlockDev>(dev: &mut D, t: Ty, key: &[u8; 32]) -> Result<u64, ActErr> {
    let store = store_region(dev).ok_or(ActErr::NoStore)?;
    let old = read_manifest(dev, store);
    let cur = old.e[t as usize].half;
    if cur == 0 {
        return Err(ActErr::NothingToRollBack);
    }
    let other = if cur == 1 { 2 } else { 1 };
    let (sl, dl) = slot(store, t, other);
    let sealed = t.staged() && seal_magic_at(&*dev, sl);
    let (gen, len) = {
        let p = Plain::new(&*dev);
        let mut sig = [0u8; 512];
        p.read_block(sl, &mut sig).map_err(|_| ActErr::Io)?;
        verify(&p, t, &sig, dl, key).map_err(|_| ActErr::NothingToRollBack)?
    };
    // the manifest digest of a sealed slot is the hash of the SEALED image (never the plaintext digest, F-a)
    let (from, n) = if sealed { (sl, (crate::seal::SEAL_HDR_LEN + SIG_KEEP) as u64 + len) } else { (dl, len) };
    let mut h = boot_abi::sha256::Hasher::new();
    crate::store::stream_blocks(&*dev, from, n, &mut |c| h.update(c)).ok_or(ActErr::Io)?;
    let g = group(t);
    let mut m = old;
    if g == 0 { m.seq = old.seq + 1 } else { m.seq2 = old.seq2 + 1 }
    m.e[t as usize] = Entry { half: other, gen, len, digest: h.finish(), state: STATE_ACTIVE, trials: 0, sealed: sealed as u8 };
    commit(dev, store, &m, g)?;
    unsafe { DISABLED &= !(1 << t as u8) };
    if reload(dev, t).is_err() {
        let mut back = old;
        if g == 0 { back.seq = m.seq + 1 } else { back.seq2 = m.seq2 + 1 }
        let _ = commit(dev, store, &back, g);
        let _ = reload(dev, t);
        return Err(ActErr::LoaderRefused);
    }
    Ok(gen)
}

// ---- configuration sealed at rest (design the repo-root design doc heqk-sealed-config-live-apply §2, step 2) ----------------
// A staged slot holds `[HQKSEAL1 header 128][ct(sig[..128] ‖ data[..len])]` from its signature sector on, under
// `seal::cfg_key(SRK, type)` + `seal::cfg_policy(device_id)`. `Plain` is the read-only view the loaders read through:
// the seal's MAC is checked before anything is decrypted, then the type's OWN signature verifier runs on the plaintext
// as before. A seal that does not authenticate, or a plaintext slot of a type the manifest marks sealed, reads as zeros
// (every loader refuses it and the fallback chain applies: other half -> boot partition -> default).

/// Signature bytes kept inside the seal (every config signature format ends by byte 120).
const SIG_KEEP: usize = 128;
/// The largest staged slot (CONFIG: 1 signature sector + 32 data sectors) — the seal / unseal work buffer.
const SLOT_MAX: usize = (1 + crate::cfgbundle::MAX_BUNDLE.div_ceil(512)) * 512;
const _: () = assert!(crate::seal::SEAL_INPLACE_MAX_PT >= SIG_KEEP + crate::cfgbundle::MAX_BUNDLE);
/// One buffer for `activate_sealed` and the single-entry `Plain` cache (activation invalidates the cache).
static mut SEALBUF: [u8; SLOT_MAX] = [0; SLOT_MAX];
/// The cache key: (type, half, the raw seal header) — a rewritten slot has a new nonce / tag.
static mut CKEY: (u8, u8, [u8; 128]) = (0xff, 0, [0; 128]);
/// 0 = empty, 1 = authenticated plaintext of CLEN bytes at SEALBUF[128..], 2 = refused.
static mut CSTATE: u8 = 0;
static mut CLEN: usize = 0;

/// The seal context: None = the device's own (SRK + device id from the HBoot handoff, read on use — no second copy
/// of the SRK is kept here); Some(x) = set explicitly (self-tests).
static mut SEAL_OVR: Option<Option<([u8; 32], u64)>> = None;
pub fn set_cfg_seal(srk: Option<[u8; 32]>, device_id: u64) {
    unsafe {
        SEAL_OVR = Some(srk.map(|k| (k, device_id)));
        CSTATE = 0;
    }
}
/// Back to the device's own seal context (end of a self-test).
pub fn clear_cfg_seal() {
    unsafe {
        SEAL_OVR = None;
        CSTATE = 0;
    }
}
fn seal_ctx() -> Option<([u8; 32], u64)> {
    match unsafe { SEAL_OVR } {
        Some(x) => x,
        None => crate::cfg_seal_source(),
    }
}
/// Is there a device key to seal configuration under (no SRK = blank OTP: never a synthetic key)?
pub fn cfg_seal_available() -> bool {
    seal_ctx().is_some()
}

fn seal_magic_at<D: BlockDev + ?Sized>(dev: &D, lba: u64) -> bool {
    let mut s = [0u8; 512];
    dev.read_block(lba, &mut s).is_ok() && &s[..8] == crate::seal::SEAL_MAGIC
}

/// Seal a verified staged container (`plain` = its 512-byte signature sector ‖ the file, `len` file bytes) into the
/// INACTIVE half of `t`, read it back, commit the manifest entry (sealed, digest = sha256 of the sealed image; a
/// CONFIG bundle starts PENDING like `activate`). `dev` must have its write window armed over the Store region.
pub fn activate_sealed<D: BlockDev + ?Sized>(dev: &mut D, t: Ty, plain: &[u8], gen: u64, len: u64) -> Result<Manifest, ActErr> {
    let store = store_region(&*dev).ok_or(ActErr::NoStore)?;
    let old = read_manifest(&*dev, store);
    let half = if old.e[t as usize].half == 1 { 2 } else { 1 };
    let digest = seal_write(dev, store, t, plain, gen, len, half)?;
    let g = group(t);
    let mut m = old;
    if g == 0 { m.seq = old.seq + 1 } else { m.seq2 = old.seq2 + 1 }
    let state = if t == Ty::Config { STATE_PENDING } else { STATE_ACTIVE };
    m.e[t as usize] = Entry { half, gen, len, digest, state, trials: 0, sealed: 1 };
    commit(dev, store, &m, g)?;
    unsafe {
        DISABLED &= !(1 << t as u8);
        OTHER &= !(1 << t as u8);
    }
    Ok(m)
}

/// Seal `plain` (signature sector ‖ `len` file bytes; never SEALBUF itself) into `half` of `t`, read it back, zero the
/// rest of the slot (a longer previous plaintext must not survive behind a shorter seal). Returns sha256(sealed image).
fn seal_write<D: BlockDev + ?Sized>(dev: &mut D, store: (u64, u64), t: Ty, plain: &[u8], gen: u64, len: u64, half: u8) -> Result<[u8; 32], ActErr> {
    let (srk, devid) = seal_ctx().ok_or(ActErr::NoStore)?;
    let n = len as usize;
    if !t.staged() || len > t.info().cap || plain.len() < 512 + n {
        return Err(ActErr::Io);
    }
    let (sl, _) = slot(store, t, half);
    let b = unsafe {
        CSTATE = 0;
        &mut *core::ptr::addr_of_mut!(SEALBUF)
    };
    const H: usize = crate::seal::SEAL_HDR_LEN;
    b[H..H + SIG_KEEP].copy_from_slice(&plain[..SIG_KEEP]);
    b[H + SIG_KEEP..H + SIG_KEEP + n].copy_from_slice(&plain[512..512 + n]);
    let key = crate::seal::cfg_key(&srk, t as u8);
    let r = crate::seal::seal_in_place(&key, &crate::seal::cfg_policy(devid), b, SIG_KEEP + n, gen);
    let blob = match r {
        Ok(l) => l,
        Err(_) => {
            b.fill(0);
            return Err(ActErr::Io);
        }
    };
    let nsec = blob.div_ceil(512);
    b[blob..nsec * 512].fill(0);
    let digest = boot_abi::sha256::digest(&b[..blob]);
    let mut sec = [0u8; 512];
    for k in 0..nsec {
        sec.copy_from_slice(&b[k * 512..k * 512 + 512]);
        dev.write_block(sl + k as u64, &sec).map_err(|_| ActErr::Io)?;
    }
    for k in 0..nsec {
        dev.read_block(sl + k as u64, &mut sec).map_err(|_| ActErr::Io)?;
        if sec[..] != b[k * 512..k * 512 + 512] {
            return Err(ActErr::Readback);
        }
    }
    zero_span(dev, sl, nsec as u64, 1 + t.data_sect())?;
    Ok(digest)
}

/// The read-only plaintext view of a device (see the section comment). Writes are refused.
pub struct Plain<'a, D: BlockDev + ?Sized> {
    dev: &'a D,
    store: Option<(u64, u64)>,
    /// Staged types the manifest marks sealed (bit = type).
    sealed: u16,
}
impl<'a, D: BlockDev + ?Sized> Plain<'a, D> {
    pub fn new(dev: &'a D) -> Self {
        let store = store_region(dev);
        let mut sealed = 0u16;
        if let Some(st) = store {
            let m = read_manifest(dev, st);
            for t in ALL {
                if t.staged() && m.e[t as usize].sealed == 1 {
                    sealed |= 1 << t as u8;
                }
            }
        }
        unsafe { CSTATE = 0 }; // each view authenticates its slots again (nothing stale across views)
        Plain { dev, store, sealed }
    }
}
/// The staged slot `lba` falls in: (type, half, sector index in the slot, the slot's signature LBA).
fn staged_slot(store: (u64, u64), lba: u64) -> Option<(Ty, u8, u64, u64)> {
    let base = store.0 + MAN_SECT;
    let span = half_span(store);
    let rel = lba.checked_sub(base)?;
    let half = rel / span;
    if half > 1 {
        return None;
    }
    let o = rel % span;
    ALL[G1_FIRST..].iter().copied().find(|t| (t.off()..t.off() + 1 + t.data_sect()).contains(&o)).map(|t| (t, half as u8 + 1, o - t.off(), lba - (o - t.off())))
}
/// Authenticate + decrypt a sealed slot into the cache (once per (type, half, header)). true = plaintext cached.
fn unseal_slot(dev: &dyn Fn(u64, &mut [u8]) -> bool, t: Ty, half: u8, sl: u64, hdr: &[u8; 512]) -> bool {
    unsafe {
        let k = &*core::ptr::addr_of!(CKEY);
        if CSTATE != 0 && k.0 == t as u8 && k.1 == half && k.2[..] == hdr[..128] {
            return CSTATE == 1;
        }
        let b = &mut *core::ptr::addr_of_mut!(SEALBUF);
        let n = (1 + t.data_sect() as usize) * 512;
        let ok = match seal_ctx() {
            Some((srk, devid)) if dev(sl, &mut b[..n]) => {
                match crate::seal::unseal_in_place(&crate::seal::cfg_key(&srk, t as u8), &crate::seal::cfg_policy(devid), &mut b[..n]) {
                    Ok((l, _)) if l >= SIG_KEEP => {
                        CLEN = l;
                        true
                    }
                    _ => false,
                }
            }
            _ => false,
        };
        if !ok {
            b.fill(0);
        }
        let mut h = [0u8; 128];
        h.copy_from_slice(&hdr[..128]);
        CKEY = (t as u8, half, h);
        CSTATE = if ok { 1 } else { 2 };
        ok
    }
}
impl<D: BlockDev + ?Sized> BlockDev for Plain<'_, D> {
    fn block_count(&self) -> u64 {
        self.dev.block_count()
    }
    fn read_block(&self, lba: u64, buf: &mut [u8; 512]) -> Result<(), BlockErr> {
        let Some((t, half, k, sl)) = self.store.and_then(|st| staged_slot(st, lba)) else {
            return self.dev.read_block(lba, buf);
        };
        let mut hdr = [0u8; 512];
        self.dev.read_block(sl, &mut hdr)?;
        if &hdr[..8] != crate::seal::SEAL_MAGIC {
            if self.sealed & (1 << t as u8) != 0 {
                *buf = [0; 512]; // a plaintext slot where the manifest says sealed: a downgrade, refused
                return Ok(());
            }
            return self.dev.read_block(lba, buf);
        }
        let rd = |l: u64, out: &mut [u8]| self.dev.read_blocks(l, out).is_ok();
        *buf = [0; 512];
        if unseal_slot(&rd, t, half, sl, &hdr) {
            // signature sector = the kept signature bytes; data sector k = data[(k-1)*512..], zero-padded
            let b = unsafe { &*core::ptr::addr_of!(SEALBUF) };
            let pt = &b[crate::seal::SEAL_HDR_LEN..crate::seal::SEAL_HDR_LEN + unsafe { CLEN }];
            let (from, to) = if k == 0 { (0, SIG_KEEP) } else { (SIG_KEEP + (k as usize - 1) * 512, SIG_KEEP + k as usize * 512) };
            let to = to.min(pt.len());
            if from < to {
                buf[..to - from].copy_from_slice(&pt[from..to]);
            }
        }
        Ok(())
    }
    fn write_block(&mut self, _lba: u64, _buf: &[u8; 512]) -> Result<(), BlockErr> {
        Err(BlockErr::WriteRefused)
    }
}

// ---- step 5: one-time migration to sealed at rest, the scrub, the at-rest report (design §2.5 / §2.6) ----------
// At boot, with a device key: every staged entry still plaintext + ACTIVE (a PENDING trial migrates once it resolves)
// is verified with its own verifier, sealed into its INACTIVE half, verified again through `Plain`, and only then the
// manifest flips to it (one atomic sector). A crash before that commit leaves the verified plaintext in force and the
// next boot retries; after it, the old plaintext half and stale Staging uploads are zeroed (idempotent, every boot:
// data sectors first, the signature sector last, so a torn scrub keeps its magic and is found again). Without a device
// key nothing is sealed or deleted — plaintext secrets are only reported (Q3). The boot never blocks on a failure.

/// What `GET /api/config` reports as `at_rest`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AtRest {
    pub device_key: bool,
    /// Every present staged entry is sealed.
    pub sealed: bool,
    /// No secret-bearing configuration (a PPPoE password, any Wi-Fi config) is stored in plaintext.
    pub secrets_protected: bool,
    /// Entries migrated this boot.
    pub migrated: u8,
}
static mut AT_REST: AtRest = AtRest { device_key: false, sealed: true, secrets_protected: true, migrated: 0 };
pub fn at_rest() -> AtRest {
    let mut a = unsafe { AT_REST };
    a.device_key = cfg_seal_available();
    a
}

/// Zero sectors `base + from .. base + to` that are not zero yet (ascending).
fn zero_span<D: BlockDev + ?Sized>(dev: &mut D, base: u64, from: u64, to: u64) -> Result<(), ActErr> {
    let mut s = [0u8; 512];
    for l in base + from..base + to {
        dev.read_block(l, &mut s).map_err(|_| ActErr::Io)?;
        if s.iter().any(|&b| b != 0) {
            dev.write_block(l, &[0; 512]).map_err(|_| ActErr::Io)?;
        }
    }
    Ok(())
}
/// Zero a plaintext container at `sl` (signature sector + `t`'s data sectors): the data first, the magic last.
fn zero_container<D: BlockDev + ?Sized>(dev: &mut D, sl: u64, t: Ty) -> Result<(), ActErr> {
    zero_span(dev, sl, 1, 1 + t.data_sect())?;
    zero_span(dev, sl, 0, 1)
}

/// Does `half` of `t` hold a PLAINTEXT container carrying a secret (read raw — reporting only, nothing is parsed)?
fn plain_secret<D: BlockDev + ?Sized>(dev: &D, store: (u64, u64), t: Ty, half: u8) -> bool {
    let (sl, dl) = slot(store, t, half);
    let mut s = [0u8; 512];
    if dev.read_block(sl, &mut s).is_err() || &s[..8] != t.info().magic {
        return false;
    }
    match t {
        Ty::Wifi => true,
        Ty::Wan | Ty::Config => {
            let mut w = [0u8; 522];
            for k in 0..t.data_sect() {
                w.copy_within(512.., 0);
                if dev.read_block(dl + k, &mut s).is_err() {
                    return true; // unreadable: do not claim it is clean
                }
                w[10..].copy_from_slice(&s);
                // a bundle's section table (count at 44, {kind, rsv, len u16} from 48): a Wi-Fi section is a secret
                if wan_has_secret(&w) || (t == Ty::Config && k == 0 && (0..(s[44] as usize).min(8)).any(|i| s[48 + 4 * i] == crate::cfgbundle::KIND_WIFI)) {
                    return true;
                }
            }
            false
        }
        _ => false,
    }
}

/// Recompute the at-rest report from the store (after the migration, and after every staged activation / rollback).
pub fn refresh<D: BlockDev + ?Sized>(dev: &D, migrated: Option<u8>) -> AtRest {
    let mut a = at_rest();
    if let Some(n) = migrated {
        a.migrated = n;
    }
    if let Some(store) = store_region(dev) {
        let m = read_manifest(dev, store);
        a.sealed = ALL[G1_FIRST..].iter().all(|&t| m.e[t as usize].half == 0 || m.e[t as usize].sealed == 1);
        a.secrets_protected = !ALL[G1_FIRST..].iter().any(|&t| plain_secret(dev, store, t, 1) || plain_secret(dev, store, t, 2));
    }
    unsafe { AT_REST = a };
    a
}

/// Seal one plaintext ACTIVE entry into its inactive half and commit it (see the section comment).
fn migrate_one<D: BlockDev + ?Sized>(dev: &mut D, store: (u64, u64), t: Ty, e: Entry) -> Result<(), ActErr> {
    let key = key_for(t).ok_or(ActErr::NothingToRollBack)?;
    let (sl, dl) = slot(store, t, e.half);
    let mut sig = [0u8; 512];
    dev.read_block(sl, &mut sig).map_err(|_| ActErr::Io)?;
    // its own verifier first (a copy that does not verify is left to the normal boot fallback)
    let (g, l) = verify(&*dev, t, &sig, dl, &key).map_err(|_| ActErr::NothingToRollBack)?;
    let n = l.max(e.len).min(t.info().cap) as usize;
    let other = if e.half == 1 { 2 } else { 1 };
    let buf = unsafe { &mut *core::ptr::addr_of_mut!(VBUF) };
    buf[..512].copy_from_slice(&sig);
    let mut r = Ok(());
    let mut sec = [0u8; 512];
    for k in 0..n.div_ceil(512) {
        if dev.read_block(dl + k as u64, &mut sec).is_err() {
            r = Err(ActErr::Io);
            break;
        }
        buf[512 + k * 512..1024 + k * 512].copy_from_slice(&sec);
    }
    let digest = r.and_then(|_| seal_write(dev, store, t, &buf[..512 + n], e.gen, n as u64, other));
    for b in buf[..512 + n.div_ceil(512) * 512].iter_mut() {
        unsafe { core::ptr::write_volatile(b, 0) }; // the plaintext (it may hold a secret) leaves RAM
    }
    sec.fill(0);
    let digest = digest?;
    // the sealed copy must verify to the same signed (generation, length) through the loaders' view before it counts
    if !verify_half(&*dev, t, other, &key).is_some_and(|(g2, l2, _)| g2 == g && l2 == l) {
        return Err(ActErr::Readback);
    }
    let mut m = read_manifest(&*dev, store);
    m.seq2 += 1;
    m.e[t as usize] = Entry { half: other, digest, sealed: 1, ..e };
    commit(dev, store, &m, group(t))?;
    unsafe {
        DISABLED &= !(1 << t as u8);
        OTHER &= !(1 << t as u8);
    }
    Ok(())
}

/// Scrub a sealed entry's slots: a plaintext container in either half is zeroed, and a sealed half's sectors past
/// its sealed image. Returns whether anything plaintext was found.
fn scrub_type<D: BlockDev + ?Sized>(dev: &mut D, store: (u64, u64), t: Ty) -> Result<bool, ActErr> {
    let mut found = false;
    for half in [1u8, 2] {
        let (sl, _) = slot(store, t, half);
        let mut s = [0u8; 512];
        dev.read_block(sl, &mut s).map_err(|_| ActErr::Io)?;
        if &s[..8] == t.info().magic {
            found = true;
            zero_container(dev, sl, t)?;
        } else if &s[..8] == crate::seal::SEAL_MAGIC {
            let blob = crate::seal::SEAL_HDR_LEN as u64 + u32::from_le_bytes(s[68..72].try_into().unwrap()) as u64;
            zero_span(dev, sl, blob.div_ceil(512).max(1), 1 + t.data_sect())?;
        }
    }
    Ok(found)
}

/// The older group-1 manifest copy still naming a plaintext entry that is now sealed (it carries the plaintext
/// digest, F-a): rewrite it with the current entries.
fn scrub_manifest<D: BlockDev + ?Sized>(dev: &mut D, store: (u64, u64)) -> Result<bool, ActErr> {
    let cur = read_manifest(&*dev, store);
    let mut s = [0u8; 512];
    for k in 0..2u64 {
        let mut m = MAN0;
        if dev.read_block(store.0 + 2 + k, &mut s).is_ok() && Manifest::decode_g(&s, 1, &mut m).is_some() && m.seq2 != cur.seq2
            && ALL[G1_FIRST..].iter().any(|&t| cur.e[t as usize].sealed == 1 && m.e[t as usize].sealed == 0 && m.e[t as usize].half != 0)
        {
            let mut n = cur;
            n.seq2 += 1;
            commit(dev, store, &n, 1)?;
            return Ok(true);
        }
    }
    Ok(false)
}

/// Stale uploads in the Staging region from before RAM staging (step 3): a staged-type container there is zeroed.
fn scrub_staging<D: BlockDev + ?Sized>(dev: &mut D) -> Result<bool, ActErr> {
    let mut s = [0u8; 512];
    dev.read_block(0, &mut s).map_err(|_| ActErr::Io)?;
    let Some(dv) = crate::datavol::DataVol::from_mbr(&s) else { return Ok(false) };
    let (lo, _) = dv.region(crate::datavol::Region::Staging);
    dev.read_block(lo, &mut s).map_err(|_| ActErr::Io)?;
    match ALL[G1_FIRST..].iter().find(|t| &s[..8] == t.info().magic) {
        Some(&t) => zero_container(dev, lo, t).map(|_| true),
        None => Ok(false),
    }
}

/// The boot step (before cfgd): migrate, scrub, report. `dev` must be write-armed over Store ∪ Staging.
pub fn migrate<D: BlockDev + ?Sized>(dev: &mut D, log: bool) -> AtRest {
    let mut n = 0u8;
    if let Some(store) = store_region(&*dev) {
        let key = cfg_seal_available();
        for t in ALL[G1_FIRST..].iter().copied() {
            let e = read_manifest(&*dev, store).e[t as usize];
            if key && e.half != 0 && e.sealed == 0 && e.state == STATE_ACTIVE {
                match migrate_one(dev, store, t, e) {
                    Ok(()) => {
                        n += 1;
                        if log {
                            arch_aarch64::_print(format_args!(" [CFGSEAL] migrated {} generation {} to sealed at rest\n", t.info().name, e.gen));
                        }
                    }
                    Err(x) if log => arch_aarch64::_print(format_args!(" [CFGSEAL] {} generation {} NOT migrated ({:?}) — the signed plaintext stays in force; retried next boot\n", t.info().name, e.gen, x)),
                    Err(_) => {}
                }
            }
            if key && read_manifest(&*dev, store).e[t as usize].sealed == 1 {
                match scrub_type(dev, store, t) {
                    Ok(true) if log => arch_aarch64::_print(format_args!(" [CFGSEAL] scrubbed the plaintext {} copy (best effort: eMMC wear levelling may keep old pages)\n", t.info().name)),
                    Err(x) if log => arch_aarch64::_print(format_args!(" [CFGSEAL] scrub of {} failed ({:?}) — retried next boot\n", t.info().name, x)),
                    _ => {}
                }
            }
        }
        if key {
            if let Err(x) = scrub_manifest(dev, store) {
                if log {
                    arch_aarch64::_print(format_args!(" [CFGSEAL] manifest scrub failed ({:?}) — retried next boot\n", x));
                }
            }
        }
        match scrub_staging(dev) {
            Ok(true) if log => arch_aarch64::_print(format_args!(" [CFGSEAL] scrubbed a stale plaintext upload from the Staging region\n")),
            Err(x) if log => arch_aarch64::_print(format_args!(" [CFGSEAL] Staging scrub failed ({:?}) — retried next boot\n", x)),
            _ => {}
        }
    }
    let a = refresh(&*dev, Some(n));
    if log && !a.secrets_protected {
        arch_aarch64::_print(format_args!(" [CFGSEAL] secrets NOT protected at rest ({})\n", if a.device_key { "a plaintext entry is not migrated yet" } else { "no device key" }));
    }
    a
}

/// CM5 boot glue: an eMMC handle write-armed over Store ∪ Staging only, used once (before `cfgd::boot_device`).
#[cfg_attr(not(feature = "cm5"), allow(dead_code))]
pub fn migrate_device() -> AtRest {
    #[cfg(all(feature = "cm5", feature = "p15-write"))]
    if let Ok(mut dev) = arch_aarch64::emmc::Emmc::probe() {
        let mut mbr = [0u8; 512];
        if dev.read_block(0, &mut mbr).is_ok() {
            if let Some(dv) = crate::datavol::DataVol::from_mbr(&mbr) {
                let (blo, bhi) = dv.bounds();
                dev.set_data_volume(blo, bhi);
                let (lo, _) = dv.region(crate::datavol::Region::Store);
                let (_, hi) = dv.region(crate::datavol::Region::Staging);
                if dev.arm_write_window(lo, hi) == (lo, hi) {
                    return migrate(&mut dev, true);
                }
            }
        }
    }
    at_rest()
}

// ---- [P-artstore] ------------------------------------------------------------------------------------------

/// The key that verifies type `t`: the owner's configuration key for WAN / Wi-Fi / POLICY (ADR 0058 D3), the
/// vendor key for content packs.
pub fn key_for(t: Ty) -> Option<[u8; 32]> {
    if t.staged() { crate::policysig::config_key() } else { crate::policysig::key() }
}

/// A sparse RAM disk for the self-tests: reads of never-written sectors are zero.
pub struct SparseDisk {
    pub lba: [u64; 192],
    pub data: [[u8; 512]; 192],
    pub n: usize,
    pub size: u64,
    /// Crash injection: the write with this index (0 = the first after `writes` was reset) and every later one fail.
    pub fail_writes_from: u64,
    pub writes: u64,
}
impl SparseDisk {
    pub const fn new(size: u64) -> SparseDisk {
        SparseDisk { lba: [0; 192], data: [[0; 512]; 192], n: 0, size, fail_writes_from: u64::MAX, writes: 0 }
    }
}
impl BlockDev for SparseDisk {
    fn block_count(&self) -> u64 {
        self.size
    }
    fn read_block(&self, lba: u64, buf: &mut [u8; 512]) -> Result<(), BlockErr> {
        if lba >= self.size {
            return Err(BlockErr::OutOfRange);
        }
        *buf = match self.lba[..self.n].iter().position(|&l| l == lba) {
            Some(i) => self.data[i],
            None => [0; 512],
        };
        Ok(())
    }
    fn write_block(&mut self, lba: u64, buf: &[u8; 512]) -> Result<(), BlockErr> {
        if lba >= self.size || self.writes >= self.fail_writes_from {
            return Err(BlockErr::WriteRefused);
        }
        self.writes += 1;
        match self.lba[..self.n].iter().position(|&l| l == lba) {
            Some(i) => self.data[i] = *buf,
            None if self.n < self.lba.len() => {
                self.lba[self.n] = lba;
                self.data[self.n] = *buf;
                self.n += 1;
            }
            None => return Err(BlockErr::WriteRefused),
        }
        Ok(())
    }
}

pub static mut TEST_DISK: SparseDisk = SparseDisk::new(0);

/// A test disk with an MBR whose p2 is a 0xDA DataVolume of the registry's minimum size.
pub fn test_disk() -> &'static mut SparseDisk {
    let d = unsafe { &mut *core::ptr::addr_of_mut!(TEST_DISK) };
    *d = SparseDisk::new(crate::datavol::MIN_SECT + 300_000);
    let mut mbr = [0u8; 512];
    mbr[510] = 0x55;
    mbr[511] = 0xAA;
    let e = 446 + 16;
    mbr[e + 4] = 0xDA;
    mbr[e + 8..e + 12].copy_from_slice(&(200_000u32).to_le_bytes());
    mbr[e + 12..e + 16].copy_from_slice(&(crate::datavol::MIN_SECT as u32).to_le_bytes());
    let _ = d.write_block(0, &mbr);
    d
}

/// Sign a pack the way tools/policy-sign.py does (self-test key) — the device never signs in production.
pub fn test_sig(magic: &[u8; 8], tag: &[u8; 6], gen: u64, body: &[u8], kp: &ed25519_compact::KeyPair) -> [u8; 512] {
    let d = boot_abi::sha256::digest(body);
    let mut m = [0u8; 54];
    m[..6].copy_from_slice(tag);
    m[6..14].copy_from_slice(&gen.to_le_bytes());
    m[14..22].copy_from_slice(&(body.len() as u64).to_le_bytes());
    m[22..].copy_from_slice(&d);
    let s = kp.sk.sign(&m[..], Some(ed25519_compact::Noise::from_slice(&[7u8; 16]).unwrap()));
    let mut sig = [0u8; 512];
    sig[..8].copy_from_slice(magic);
    sig[8..16].copy_from_slice(&gen.to_le_bytes());
    sig[16..24].copy_from_slice(&(body.len() as u64).to_le_bytes());
    sig[24..56].copy_from_slice(&d);
    sig[56..120].copy_from_slice(&s[..]);
    sig
}

pub fn selftest() -> bool {
    let kp = ed25519_compact::KeyPair::from_seed(ed25519_compact::Seed::new([0x42; 32]));
    let key: [u8; 32] = *kp.pk;
    crate::policysig::selftest_key(Some(key));
    let d = test_disk();
    let store = store_region(d);
    let fits = store.is_some_and(|s| half_span(s) >= need_per_half() && slot(s, Ty::Devices, 2).1 + Ty::Devices.data_sect() <= s.1);
    let Some(store) = store else {
        crate::policysig::selftest_key(None);
        arch_aarch64::_print(format_args!(" [P-artstore] FAIL — no store region\n"));
        return false;
    };
    // a signed DEVICES pack staged at some LBA outside the store
    let body = b"02:00:00:00:00:61 quarantine art-test\n";
    let sig = test_sig(b"HQDSIG1\0", b"HQDEV1", 7, body, &kp);
    let stage = store.1 + 10;
    let mut sec = [0u8; 512];
    sec[..body.len()].copy_from_slice(body);
    let _ = d.write_block(stage, &sec);
    let ver = verify(d, Ty::Devices, &sig, stage, &key) == Ok((7, body.len() as u64));
    let mut bad = sig;
    bad[60] ^= 1;
    let ver_bad = verify(d, Ty::Devices, &bad, stage, &key).is_err();
    let other = kp_other();
    let ver_wrong_key = verify(d, Ty::Devices, &sig, stage, &other).is_err();
    // nothing committed: locate has no store copy, the active generation is 0
    let empty = read_manifest(d, store) == MAN0 && active_gen(d, 0, Ty::Devices) == 0 && locate(d, 0, b"DEVICES TXT").is_none();
    // activate: A half, manifest seq 1, the loader (devpolicy) sees the device
    let dig = boot_abi::sha256::digest(body);
    let a1 = activate(d, Ty::Devices, &sig, stage, 7, body.len() as u64, &dig);
    let m1 = read_manifest(d, store);
    let act = a1.is_ok() && m1.seq == 1 && m1.e[Ty::Devices as usize].half == 1 && crate::devpolicy::policy_of(&[2, 0, 0, 0, 0, 0x61]) == crate::devpolicy::Pol::Quarantine
        && active_gen(d, 0, Ty::Devices) == 7 && locate(d, 0, b"DEVICES SIG") == Some((slot(store, Ty::Devices, 1).0, 1));
    // a second activation goes to the OTHER half; the first stays intact until the commit
    let body2 = b"02:00:00:00:00:62 lan_only art-test-2\n";
    let sig2 = test_sig(b"HQDSIG1\0", b"HQDEV1", 8, body2, &kp);
    let mut sec2 = [0u8; 512];
    sec2[..body2.len()].copy_from_slice(body2);
    let _ = d.write_block(stage, &sec2);
    let a2 = activate(d, Ty::Devices, &sig2, stage, 8, body2.len() as u64, &boot_abi::sha256::digest(body2));
    let m2 = read_manifest(d, store);
    let ab = a2.is_ok() && m2.seq == 2 && m2.e[Ty::Devices as usize].half == 2 && crate::devpolicy::policy_of(&[2, 0, 0, 0, 0, 0x62]) == crate::devpolicy::Pol::LanOnly;
    // torn manifest write: the newest copy corrupt -> the older copy (seq 1, half A) is what boots
    let mut s = [0u8; 512];
    let _ = d.read_block(store.0 + (m2.seq & 1), &mut s);
    s[100] ^= 0xff;
    let _ = d.write_block(store.0 + (m2.seq & 1), &s);
    let torn = read_manifest(d, store).seq == 1 && read_manifest(d, store).e[Ty::Devices as usize].half == 1;
    // rollback: a copy the loader refuses (digest in the manifest fine, but the signature sector does not
    // verify) re-commits the previous manifest
    let r = activate(d, Ty::Devices, &bad, stage, 9, body2.len() as u64, &boot_abi::sha256::digest(body2));
    let m3 = read_manifest(d, store);
    let rollback = r == Err(ActErr::LoaderRefused) && m3.e[Ty::Devices as usize].half == 1 && m3.e[Ty::Devices as usize].gen == 7
        && crate::devpolicy::policy_of(&[2, 0, 0, 0, 0, 0x61]) == crate::devpolicy::Pol::Quarantine;
    // ADR 0058 owner rollback: the other half now holds the pack the loader refused, so a rollback to it is
    // refused (manifest unchanged); after a fresh valid gen 8, rollback re-verifies half A (gen 7) and
    // re-activates it; a type with nothing committed has nothing to roll back to
    let rb_bad = self::rollback(d, Ty::Devices, &key) == Err(ActErr::NothingToRollBack) && read_manifest(d, store).e[Ty::Devices as usize].half == 1;
    let a8 = activate(d, Ty::Devices, &sig2, stage, 8, body2.len() as u64, &boot_abi::sha256::digest(body2)).is_ok()
        && read_manifest(d, store).e[Ty::Devices as usize].half == 2;
    let rb1 = self::rollback(d, Ty::Devices, &key);
    let rb_ok = rb1 == Ok(7) && read_manifest(d, store).e[Ty::Devices as usize].half == 1
        && crate::devpolicy::policy_of(&[2, 0, 0, 0, 0, 0x61]) == crate::devpolicy::Pol::Quarantine;
    let rb_none = self::rollback(d, Ty::Wan, &key) == Err(ActErr::NothingToRollBack);
    let owner_rb = rb_bad && a8 && rb_ok && rb_none;
    if !owner_rb {
        arch_aarch64::_print(format_args!(" [P-artstore] debug rollback: bad-half-refused={} fresh-gen8={} rb={:?} none={}\n", rb_bad, a8, rb1, rb_none));
    }
    // ADR 0058 staged config type: a signed WAN.TXT activates into manifest group 1 (group 0 untouched),
    // locate() prefers the store copy, a wrong-key copy is refused before any write
    let seq0 = read_manifest(d, store).seq;
    let wbody = b"mode=dhcp\n";
    let wsig = test_sig(b"HQNSIG1\0", b"HQWAN1", 3, wbody, &kp);
    let mut ws = [0u8; 512];
    ws[..wbody.len()].copy_from_slice(wbody);
    let _ = d.write_block(stage, &ws);
    let wver = verify(d, Ty::Wan, &wsig, stage, &key) == Ok((3, wbody.len() as u64)) && verify(d, Ty::Wan, &wsig, stage, &other).is_err();
    let wa = activate(d, Ty::Wan, &wsig, stage, 3, wbody.len() as u64, &boot_abi::sha256::digest(wbody));
    let wm = read_manifest(d, store);
    let staged_ok = wver && wa.is_ok() && Ty::Wan.staged() && !Ty::Devices.staged() && wm.seq == seq0 && wm.seq2 == 1
        && wm.e[Ty::Wan as usize].half == 1 && wm.e[Ty::Wan as usize].gen == 3 && active_gen(d, 0, Ty::Wan) == 3
        && locate(d, 0, b"WAN     TXT") == Some((slot(store, Ty::Wan, 1).1, Ty::Wan.data_sect()));
    if !staged_ok {
        arch_aarch64::_print(format_args!(" [P-artstore] debug wan: ver={} act={:?} seq {}->{} seq2={} half={} gen={} active={} locate={:?}\n",
            wver, wa.is_ok(), seq0, wm.seq, wm.seq2, wm.e[Ty::Wan as usize].half, wm.e[Ty::Wan as usize].gen, active_gen(d, 0, Ty::Wan), locate(d, 0, b"WAN     TXT")));
    }
    // design heqk-sealed-config-live-apply step 2: a WAN with a PPPoE password sealed at rest
    let (sealed_ok, sealed_dbg) = sealed_selftest(d, store, &kp, &key);
    if !sealed_ok {
        arch_aarch64::_print(format_args!(" [P-artstore] debug sealed: {:?}\n", sealed_dbg));
    }
    // tampered at rest: boot fallback disables the store copy for this boot
    let (_, dl) = slot(store, Ty::Devices, 1);
    let _ = d.read_block(dl, &mut s);
    s[0] ^= 1;
    let _ = d.write_block(dl, &s);
    // ADR 0059 Phase 0.4: the active half (gen 7) tampered -> the OTHER half (gen 8, valid) loads, not the FAT copy;
    // the other half tampered too -> only then the boot partition
    let refused = crate::devpolicy::load(d).file == 2;
    let other_ok = boot_fallback(d, 0, Ty::Devices, refused) && locate(d, 0, b"DEVICES TXT") == Some((slot(store, Ty::Devices, 2).1, Ty::Devices.data_sect()))
        && crate::devpolicy::policy_of(&[2, 0, 0, 0, 0, 0x62]) == crate::devpolicy::Pol::LanOnly;
    let (_, dl2) = slot(store, Ty::Devices, 2);
    let _ = d.read_block(dl2, &mut s);
    s[0] ^= 1;
    let _ = d.write_block(dl2, &s);
    let refused2 = crate::devpolicy::load(d).file == 2;
    let fell_back = other_ok && refused2 && boot_fallback(d, 0, Ty::Devices, refused2) && locate(d, 0, b"DEVICES TXT").is_none();
    if !fell_back {
        arch_aarch64::_print(format_args!(" [P-artstore] debug fallback: other-half={} refused2={}\n", other_ok, refused2));
    }
    unsafe {
        DISABLED = 0;
        OTHER = 0;
    }
    crate::policysig::selftest_key(None);
    crate::devpolicy::load_text(b"");
    let pass = fits && ver && ver_bad && ver_wrong_key && empty && act && ab && torn && rollback && owner_rb && staged_ok && fell_back && sealed_ok;
    arch_aarch64::_print(format_args!(
        " [P-artstore] {} — ADR 0056 D5 artifact store (DataVolume Store region, A/B slot per pack type, two-copy manifest): every type fits a half at its cap={} module's own verifier accepts the signed pack={} tampered / wrong-key refused={} empty store -> FAT={} activate: A half + manifest + live reload through the real loader={} next activation -> the other half={} torn manifest -> previous copy={} loader refusal rolls back={} owner rollback to the verified other half (ADR 0058)={} staged WAN.TXT in manifest group 1, store preferred={} tampered-at-rest active half -> the previous half, then FAT (ADR 0059 0.4)={} sealed WAN at rest: no secret / no plaintext digest on disk={} Plain view: seal MAC then the WAN verifier={} flipped ciphertext byte -> half reads as zeros (refused)={} plaintext slot under sealed=1 refused (no downgrade)={} old manifest decodes sealed=0, sealed>1 rejected={}\n",
        if pass { "PASS" } else { "FAIL" }, fits, ver, ver_bad && ver_wrong_key, empty, act, ab, torn, rollback, owner_rb, staged_ok, fell_back,
        sealed_dbg[0], sealed_dbg[1], sealed_dbg[2], sealed_dbg[3], sealed_dbg[4]
    ));
    pass
}

/// Is `needle` anywhere on the sparse disk (within a sector)?
pub fn on_disk(d: &SparseDisk, needle: &[u8]) -> bool {
    d.data[..d.n].iter().any(|s| s.windows(needle.len()).any(|w| w == needle))
}

/// [P-artstore] sealed-at-rest checks (step 2). The WAN slot holds a plaintext gen 3 in half A on entry.
fn sealed_selftest(d: &mut SparseDisk, store: (u64, u64), kp: &ed25519_compact::KeyPair, key: &[u8; 32]) -> (bool, [bool; 5]) {
    set_cfg_seal(Some([0x5c; 32]), 0x0123_4567_89ab_cdef);
    let body = b"mode=pppoe\npppoe_user=art\npppoe_pass=s3cret\n";
    let sig = test_sig(b"HQNSIG1\0", b"HQWAN1", 4, body, kp);
    let mut cont = [0u8; 1024];
    cont[..512].copy_from_slice(&sig);
    cont[512..512 + body.len()].copy_from_slice(body);
    let len = body.len() as u64;
    let pdig = boot_abi::sha256::digest(body);
    let a = activate_sealed(d, Ty::Wan, &cont[..512 + body.len()], 4, len);
    let e = read_manifest(d, store).e[Ty::Wan as usize];
    let at_rest = a.is_ok() && e.sealed == 1 && e.half == 2 && e.gen == 4 && e.digest != pdig && !on_disk(d, b"s3cret") && !on_disk(d, &pdig);
    // the loaders' view: the signature sector + the file come back, the WAN verifier accepts them
    let (s2, d2) = slot(store, Ty::Wan, 2);
    let view = {
        let p = Plain::new(&*d);
        let (mut sg, mut ds) = ([0u8; 512], [0u8; 512]);
        let _ = p.read_block(s2, &mut sg);
        let _ = p.read_block(d2, &mut ds);
        sg[..SIG_KEEP] == sig[..SIG_KEEP] && sg[SIG_KEEP..].iter().all(|&b| b == 0) && ds[..body.len()] == body[..]
            && verify(&p, Ty::Wan, &sg, d2, key) == Ok((4, len)) && active_gen(&p, 0, Ty::Wan) == 4
            && locate(&p, 0, b"WAN     TXT") == Some((d2, Ty::Wan.data_sect()))
    } && verify_half(&*d, Ty::Wan, 2, key).is_some_and(|(g, l, _)| g == 4 && l == len);
    // one flipped ciphertext byte: the seal MAC fails, the half reads as zeros (refused); restored, it verifies again
    // (a small WAN seals into the slot's FIRST sector — header 128 + signature 128 + data — so flip a byte INSIDE
    // that sealed image; the following sectors are unauthenticated zero padding the view never serves)
    let mut s = [0u8; 512];
    let _ = d.read_block(s2, &mut s);
    s[crate::seal::SEAL_HDR_LEN + 140] ^= 0x40;
    let _ = d.write_block(s2, &s);
    let zeros = {
        let p = Plain::new(&*d);
        let mut sg = [0xffu8; 512];
        let _ = p.read_block(s2, &mut sg);
        sg.iter().all(|&b| b == 0)
    };
    let flipped = zeros && verify_half(&*d, Ty::Wan, 2, key).is_none();
    s[crate::seal::SEAL_HDR_LEN + 140] ^= 0x40;
    let _ = d.write_block(s2, &s);
    let flipped = flipped && verify_half(&*d, Ty::Wan, 2, key).is_some();
    // half A still holds the plaintext gen 3: with the manifest marked sealed it is refused, so is a rollback to it
    let downgrade = verify_half(&*d, Ty::Wan, 1, key).is_none() && rollback(d, Ty::Wan, key) == Err(ActErr::NothingToRollBack)
        && read_manifest(d, store).e[Ty::Wan as usize].half == 2;
    // manifest byte o+3: an old manifest (0) decodes sealed=0; a value > 1 is not a manifest
    let mut m = MAN0;
    m.e[Ty::Wan as usize].half = 1;
    let mut sct = m.encode_g(1);
    let mut out = MAN0;
    let old = Manifest::decode_g(&sct, 1, &mut out).is_some() && out.e[Ty::Wan as usize].sealed == 0;
    sct[16 + 3] = 2;
    let dg = boot_abi::sha256::digest(&sct[..480]);
    sct[480..].copy_from_slice(&dg);
    let manifest = old && Manifest::decode_g(&sct, 1, &mut out).is_none();
    clear_cfg_seal();
    let r = [at_rest, view, flipped, downgrade, manifest];
    (r.iter().all(|&x| x), r)
}

fn kp_other() -> [u8; 32] {
    *ed25519_compact::KeyPair::from_seed(ed25519_compact::Seed::new([0x43; 32])).pk
}

// ---- [P-cfgseal] (design heqk-sealed-config-live-apply step 5) -------------------------------------------------------

const CS_BODY: &[u8] = b"mode=pppoe\npppoe_user=cs\npppoe_pass=cs-s3cret\n";
const CS_SECRET: &[u8] = b"cs-s3cret";

/// A fresh test disk as an older device left it: plaintext WAN gen 2 (half A) and gen 3 (half B, active), plus a
/// stale plaintext WAN upload at the start of the Staging region. Returns (disk, store, staging start).
fn cs_setup(kp: &ed25519_compact::KeyPair) -> (&'static mut SparseDisk, (u64, u64), u64) {
    let d = test_disk();
    let dig = boot_abi::sha256::digest(CS_BODY);
    let mut sig = [0u8; 512];
    for g in [2u64, 3] {
        sig = test_sig(b"HQNSIG1\0", b"HQWAN1", g, CS_BODY, kp);
        let _ = activate_from(d, Ty::Wan, &sig, Src::Ram(CS_BODY), g, CS_BODY.len() as u64, &dig);
    }
    let mut mbr = [0u8; 512];
    let _ = d.read_block(0, &mut mbr);
    let lo = crate::datavol::DataVol::from_mbr(&mbr).map_or(0, |v| v.region(crate::datavol::Region::Staging).0);
    let mut sec = [0u8; 512];
    sec[..CS_BODY.len()].copy_from_slice(CS_BODY);
    let _ = d.write_block(lo, &sig);
    let _ = d.write_block(lo + 1, &sec);
    let store = store_region(d).unwrap_or((0, 0));
    unsafe {
        DISABLED = 0;
        OTHER = 0;
    }
    d.writes = 0;
    (d, store, lo)
}

/// The WAN loaders' path (locate -> Plain -> the WAN verifier) yields generation `gen` with the original body.
fn cs_loads(d: &SparseDisk, key: &[u8; 32], gen: u64) -> bool {
    let p = Plain::new(d);
    let (Some((sl, _)), Some((dl, _))) = (locate(&p, 0, b"WAN     SIG"), locate(&p, 0, b"WAN     TXT")) else { return false };
    let (mut sg, mut ds) = ([0u8; 512], [0u8; 512]);
    p.read_block(sl, &mut sg).is_ok() && p.read_block(dl, &mut ds).is_ok() && verify(&p, Ty::Wan, &sg, dl, key) == Ok((gen, CS_BODY.len() as u64))
        && ds[..CS_BODY.len()] == *CS_BODY
}

pub fn cfgseal_selftest() -> bool {
    let saved = unsafe { AT_REST };
    let kp = ed25519_compact::KeyPair::from_seed(ed25519_compact::Seed::new([0x42; 32]));
    let key: [u8; 32] = *kp.pk;
    crate::policysig::selftest_key(Some(key));
    set_cfg_seal(Some([0x6d; 32]), 0x5eed_0005);
    let wan = Ty::Wan as usize;
    let zero = |d: &SparseDisk, l: u64| {
        let mut s = [0xffu8; 512];
        d.read_block(l, &mut s).is_ok() && s.iter().all(|&b| b == 0)
    };
    // (a) + (e): the plaintext ACTIVE WAN migrates into the other half; no secret / plaintext digest left anywhere
    let (d, store, stg) = cs_setup(&kp);
    let before = read_manifest(d, store).e[wan];
    let r = migrate(d, false);
    let e = read_manifest(d, store).e[wan];
    let a = before.half == 2 && before.sealed == 0 && r.migrated == 1 && r.sealed && r.secrets_protected && r.device_key
        && e.sealed == 1 && e.half == 1 && e.gen == 3 && e.len == before.len && e.state == STATE_ACTIVE
        && !on_disk(d, CS_SECRET) && !on_disk(d, &boot_abi::sha256::digest(CS_BODY)) && cs_loads(d, &key, 3);
    let st = zero(d, stg) && zero(d, stg + 1);
    // a second boot is a no-op (idempotent, nothing written)
    d.writes = 0;
    let again = migrate(d, false).migrated == 0 && d.writes == 0 && cs_loads(d, &key, 3);
    let total = {
        let (d, _, _) = cs_setup(&kp);
        let _ = migrate(d, false);
        d.writes
    };
    // (b) a power cut at EVERY write of the migration, then a fresh boot: always a verified configuration
    let mut bad = u64::MAX;
    for k in 0..total {
        let (d, store, _) = cs_setup(&kp);
        d.fail_writes_from = k;
        let _ = migrate(d, false);
        d.fail_writes_from = u64::MAX;
        unsafe {
            DISABLED = 0;
            OTHER = 0;
        }
        let e = read_manifest(d, store).e[wan];
        let mid = cs_loads(d, &key, 3) && ((e.sealed == 0 && e.half == 2) || (e.sealed == 1 && e.half == 1));
        let r2 = migrate(d, false);
        let e2 = read_manifest(d, store).e[wan];
        let after = cs_loads(d, &key, 3) && e2.sealed == 1 && e2.half == 1 && r2.secrets_protected && !on_disk(d, CS_SECRET);
        if !(mid && after) {
            bad = k;
            break;
        }
    }
    let crash = total >= 5 && bad == u64::MAX;
    // (c) a PENDING configuration bundle is left alone (it migrates once its trial resolves)
    let (d, store, _) = cs_setup(&kp);
    let _ = set_entry(d, Ty::Config, |x| {
        x.half = 1;
        x.gen = 5;
        x.state = STATE_PENDING;
    });
    let r = migrate(d, false);
    let c = read_manifest(d, store).e[Ty::Config as usize];
    let pend = r.migrated == 1 && c.half == 1 && c.sealed == 0 && c.state == STATE_PENDING && c.gen == 5;
    // (d) no device key: nothing sealed, nothing deleted, reported unprotected; a non-config Staging upload stays
    set_cfg_seal(None, 0);
    let (d, store, stg) = cs_setup(&kp);
    let other = test_sig(b"HQDSIG1\0", b"HQDEV1", 1, b"x\n", &kp);
    let _ = d.write_block(stg, &other);
    let r = migrate(d, false);
    let mut s = [0u8; 512];
    let _ = d.read_block(stg, &mut s);
    let e = read_manifest(d, store).e[wan];
    let nokey = r.migrated == 0 && !r.device_key && !r.secrets_protected && !r.sealed && e.sealed == 0 && e.half == 2
        && on_disk(d, CS_SECRET) && cs_loads(d, &key, 3);
    let keep = s == other;
    clear_cfg_seal();
    crate::policysig::selftest_key(None);
    unsafe {
        DISABLED = 0;
        OTHER = 0;
        AT_REST = saved;
    }
    let pass = a && st && again && crash && pend && nokey && keep;
    arch_aarch64::_print(format_args!(
        " [P-cfgseal] {} — configuration sealed at rest, step 5 (migration + scrub): a plaintext ACTIVE WAN with pppoe_pass= migrates to sealed=1 on the other half, no secret / plaintext digest left on disk, the loader path returns the same configuration={} stale plaintext Staging upload zeroed={} second boot is a no-op={} power cut at every one of {} migration writes then a fresh boot -> always the verified original or the sealed copy, never nothing / a mix={}{} PENDING bundle not migrated={} no device key: nothing migrated or deleted, secrets_protected=false={} non-config Staging content kept={}\n",
        if pass { "PASS" } else { "FAIL" }, a, st, again, total, crash, if bad != u64::MAX { " (first bad write index logged)" } else { "" }, pend, nokey, keep
    ));
    if bad != u64::MAX {
        arch_aarch64::_print(format_args!(" [P-cfgseal] debug crash at write {}\n", bad));
    }
    pass
}
