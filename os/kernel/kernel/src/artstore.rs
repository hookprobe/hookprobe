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
}
pub const NTY: usize = 6;
pub const ALL: [Ty; NTY] = [Ty::Block, Ty::Allow, Ty::Ioc, Ty::Rules, Ty::Oui, Ty::Devices];

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
}
const E0: Entry = Entry { half: 0, gen: 0, len: 0, digest: [0; 32] };

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Manifest {
    pub seq: u64,
    pub e: [Entry; NTY],
}
pub const MAN0: Manifest = Manifest { seq: 0, e: [E0; NTY] };
const MAGIC: &[u8; 8] = b"HQSTMAN1";

impl Manifest {
    fn encode(&self) -> [u8; 512] {
        let mut s = [0u8; 512];
        s[..8].copy_from_slice(MAGIC);
        s[8..16].copy_from_slice(&self.seq.to_le_bytes());
        for (i, e) in self.e.iter().enumerate() {
            let o = 16 + i * 56;
            s[o] = e.half;
            s[o + 8..o + 16].copy_from_slice(&e.gen.to_le_bytes());
            s[o + 16..o + 24].copy_from_slice(&e.len.to_le_bytes());
            s[o + 24..o + 56].copy_from_slice(&e.digest);
        }
        let d = boot_abi::sha256::digest(&s[..480]);
        s[480..].copy_from_slice(&d);
        s
    }
    fn decode(s: &[u8; 512]) -> Option<Manifest> {
        if &s[..8] != MAGIC || boot_abi::sha256::digest(&s[..480])[..] != s[480..] {
            return None;
        }
        let mut m = MAN0;
        m.seq = u64::from_le_bytes(s[8..16].try_into().ok()?);
        for (i, e) in m.e.iter_mut().enumerate() {
            let o = 16 + i * 56;
            e.half = s[o];
            if e.half > 2 {
                return None;
            }
            e.gen = u64::from_le_bytes(s[o + 8..o + 16].try_into().ok()?);
            e.len = u64::from_le_bytes(s[o + 16..o + 24].try_into().ok()?);
            e.digest.copy_from_slice(&s[o + 24..o + 56]);
        }
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
    let mut best = MAN0;
    let mut s = [0u8; 512];
    for k in 0..2 {
        if dev.read_block(store.0 + k, &mut s).is_ok() {
            if let Some(m) = Manifest::decode(&s) {
                if m.seq >= best.seq {
                    best = m;
                }
            }
        }
    }
    best
}

/// Absolute LBA of a type's slot in `half` (1 = A, 2 = B): (signature sector, first data sector).
pub fn slot(store: (u64, u64), t: Ty, half: u8) -> (u64, u64) {
    let base = store.0 + MAN_SECT + (half as u64 - 1) * half_span(store) + t.off();
    (base, base + 1)
}

/// Types whose store copy failed its loader this boot (RAM only): `locate` falls back to FAT.
static mut DISABLED: u8 = 0;
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
fn store_copy<D: BlockDev>(dev: &D, p1: u64, t: Ty) -> Option<(u64, u64, u64)> {
    if disabled(t) {
        return None;
    }
    let store = store_region(dev)?;
    let e = read_manifest(dev, store).e[t as usize];
    if e.half == 0 {
        return None;
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
        let mut sec = [0u8; 512];
        let mut left = len;
        let mut k = 0;
        while left > 0 {
            dev.read_block(data_lba + k, &mut sec).ok()?;
            let take = left.min(512) as usize;
            h.update(&sec[..take]);
            left -= take as u64;
            k += 1;
        }
        Some(h.finish())
    };
    match t {
        Ty::Block => crate::shield::check_sig(b"HQBSIG1\0", b"HQBLK1", sig, key, &mut digest_of),
        Ty::Allow => crate::shield::check_sig(b"HQASIG1\0", b"HQALW1", sig, key, &mut digest_of),
        Ty::Ioc => crate::ioc::check_sig(sig, key, &mut digest_of),
        Ty::Oui => crate::oui::check_sig(sig, key, &mut digest_of),
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
    };
    if ok { Ok(()) } else { Err(()) }
}

/// Boot: a store copy its loader refused (tampered / torn at rest) is disabled for this boot and the module
/// reloaded from the boot-FAT copy. Returns true when it fell back.
pub fn boot_fallback<D: BlockDev>(dev: &D, p1: u64, t: Ty, refused: bool) -> bool {
    if refused && from_store(dev, p1, t) {
        disable(t);
        let _ = reload(dev, t);
        return true;
    }
    false
}

// ---- activation (write build) ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActErr {
    NoStore,
    Io,
    Readback,
    /// The module's loader refused the new copy after commit — rolled back to the previous one.
    LoaderRefused,
}

/// Copy a verified pack (`sig` + `len` bytes at `src_lba` — the staging area) into the inactive half of
/// type `t`, read it back, commit the manifest, reload the module. On a loader refusal the previous
/// manifest is re-committed and the module reloaded again (rollback). `dev` must already have its write
/// window armed over the Store region.
pub fn activate<D: BlockDev>(dev: &mut D, t: Ty, sig: &[u8; 512], src_lba: u64, gen: u64, len: u64, digest: &[u8; 32]) -> Result<Manifest, ActErr> {
    let store = store_region(dev).ok_or(ActErr::NoStore)?;
    let old = read_manifest(dev, store);
    let cur = old.e[t as usize].half;
    let half = if cur == 1 { 2 } else { 1 };
    let (sl, dl) = slot(store, t, half);
    let n = len.div_ceil(512);
    let mut sec = [0u8; 512];
    for k in 0..n {
        dev.read_block(src_lba + k, &mut sec).map_err(|_| ActErr::Io)?;
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
    let mut m = old;
    m.seq = old.seq + 1;
    m.e[t as usize] = Entry { half, gen, len, digest: *digest };
    commit(dev, store, &m)?;
    unsafe { DISABLED &= !(1 << t as u8) };
    if reload(dev, t).is_err() {
        let mut back = old;
        back.seq = m.seq + 1;
        let _ = commit(dev, store, &back);
        let _ = reload(dev, t);
        return Err(ActErr::LoaderRefused);
    }
    Ok(m)
}

fn commit<D: BlockDev + ?Sized>(dev: &mut D, store: (u64, u64), m: &Manifest) -> Result<(), ActErr> {
    let s = m.encode();
    dev.write_block(store.0 + (m.seq & 1), &s).map_err(|_| ActErr::Io)?;
    let mut back = [0u8; 512];
    dev.read_block(store.0 + (m.seq & 1), &mut back).map_err(|_| ActErr::Io)?;
    if back != s {
        return Err(ActErr::Readback);
    }
    Ok(())
}

// ---- [P-artstore] ------------------------------------------------------------------------------------------

/// A sparse RAM disk for the self-tests: reads of never-written sectors are zero.
pub struct SparseDisk {
    pub lba: [u64; 192],
    pub data: [[u8; 512]; 192],
    pub n: usize,
    pub size: u64,
    pub fail_writes_from: u64,
}
impl SparseDisk {
    pub const fn new(size: u64) -> SparseDisk {
        SparseDisk { lba: [0; 192], data: [[0; 512]; 192], n: 0, size, fail_writes_from: u64::MAX }
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
        if lba >= self.size || lba >= self.fail_writes_from {
            return Err(BlockErr::WriteRefused);
        }
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
    let fits = store.map_or(false, |s| half_span(s) >= need_per_half() && slot(s, Ty::Devices, 2).1 + Ty::Devices.data_sect() <= s.1);
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
    // tampered at rest: boot fallback disables the store copy for this boot
    let (_, dl) = slot(store, Ty::Devices, 1);
    let _ = d.read_block(dl, &mut s);
    s[0] ^= 1;
    let _ = d.write_block(dl, &s);
    let refused = crate::devpolicy::load(d).file == 2;
    let fell_back = boot_fallback(d, 0, Ty::Devices, refused) && locate(d, 0, b"DEVICES TXT").is_none();
    unsafe { DISABLED = 0 };
    crate::policysig::selftest_key(None);
    crate::devpolicy::load_text(b"");
    let pass = fits && ver && ver_bad && ver_wrong_key && empty && act && ab && torn && rollback && fell_back;
    arch_aarch64::_print(format_args!(
        " [P-artstore] {} — ADR 0056 D5 artifact store (DataVolume Store region, A/B slot per pack type, two-copy manifest): every type fits a half at its cap={} module's own verifier accepts the signed pack={} tampered / wrong-key refused={} empty store -> FAT={} activate: A half + manifest + live reload through the real loader={} next activation -> the other half={} torn manifest -> previous copy={} loader refusal rolls back={} tampered-at-rest falls back to FAT={}\n",
        if pass { "PASS" } else { "FAIL" }, fits, ver, ver_bad && ver_wrong_key, empty, act, ab, torn, rollback, fell_back
    ));
    pass
}

fn kp_other() -> [u8; 32] {
    *ed25519_compact::KeyPair::from_seed(ed25519_compact::Seed::new([0x43; 32])).pk
}
