//! Discovery D3 — the full IEEE OUI registry as an operator-signed data file (OUI.TXT on the boot partition).
//!
//! The 846 curated OUIs compiled into `fpdb` (legacy Fingerbank parity) name the vendors that matter most and
//! stay first; this pack is the long tail (~40 000 MA-L assignments), loaded at boot so the vendor of almost
//! any wired / non-randomised device is known without growing the boot image (≤ 5 MiB budget).
//!
//! Format (IEEE / nmap-mac-prefixes style, one assignment per line, sorted by prefix):
//!   `AABBCC Vendor Name`      — `#` comments and blank lines ignored; anything else is skipped and counted.
//! OUI.SIG = the shared operator signature format with its own domain ("HQOUI1"), so no other signed file
//! (BLOCK / IOC / POLICY …) ever verifies as an OUI pack. Lookups are read-only after boot.
use crate::policysig::POLICY_PUBKEY;
use hal::BlockDev;

pub const MAX_FILE: u64 = 4 << 20;
const CAP: usize = 65_536; // IEEE MA-L: 40 455 on 2026-11-08, growing ~1.5 k a year
const ARENA: usize = 1 << 20; // de-duplicated vendor names (20 134 distinct on 2026-11-08, ~0.5 MB)
const HASH: usize = 65_536; // name de-dup table (power of two, > 2x distinct names)
const NAME_MAX: usize = 96;

static mut KEYS: [u32; CAP] = [0; CAP];
static mut NAMES: [u32; CAP] = [0; CAP]; // offset into ARENA_B of a (len u8, bytes) record
static mut ARENA_B: [u8; ARENA] = [0; ARENA];
static mut DEDUP: [u32; HASH] = [0; HASH]; // offset + 1 of a name in ARENA_B; 0 = empty
static mut N: usize = 0;
static mut USED: usize = 0;
static mut INFO: Info = Info { file: 0, signed: false, generation: 0, skipped: 0, truncated: 0, refused: None };

#[derive(Clone, Copy, Default)]
pub struct Info {
    /// 0 absent, 1 loaded, 2 refused
    pub file: u8,
    pub signed: bool,
    pub generation: u64,
    pub skipped: u32,
    pub truncated: u32,
    pub refused: Option<crate::shield::LoadErr>,
}

pub fn info() -> Info {
    unsafe { INFO }
}

pub fn len() -> usize {
    unsafe { N }
}

fn reset() {
    unsafe {
        N = 0;
        USED = 0;
        (*core::ptr::addr_of_mut!(DEDUP)).fill(0);
    }
}

fn fnv(b: &[u8]) -> u32 {
    let mut h: u32 = 0x811c_9dc5;
    for &x in b {
        h ^= x as u32;
        h = h.wrapping_mul(0x0100_0193);
    }
    h
}

fn name_at(off: usize) -> &'static [u8] {
    let a = unsafe { &*core::ptr::addr_of!(ARENA_B) };
    let l = a[off] as usize;
    &a[off + 1..off + 1 + l]
}

/// Intern a vendor name; None when the arena is full.
fn intern(name: &[u8]) -> Option<u32> {
    let a = unsafe { &mut *core::ptr::addr_of_mut!(ARENA_B) };
    let d = unsafe { &mut *core::ptr::addr_of_mut!(DEDUP) };
    let mut i = fnv(name) as usize & (HASH - 1);
    for _ in 0..HASH {
        match d[i] {
            0 => {
                let used = unsafe { USED };
                if used + 1 + name.len() > ARENA {
                    return None;
                }
                a[used] = name.len() as u8;
                a[used + 1..used + 1 + name.len()].copy_from_slice(name);
                d[i] = used as u32 + 1;
                unsafe { USED = used + 1 + name.len() };
                return Some(used as u32);
            }
            o if name_at(o as usize - 1) == name => return Some(o - 1),
            _ => i = (i + 1) & (HASH - 1),
        }
    }
    None
}

fn hex(c: u8) -> Option<u32> {
    match c {
        b'0'..=b'9' => Some((c - b'0') as u32),
        b'a'..=b'f' => Some((c - b'a' + 10) as u32),
        b'A'..=b'F' => Some((c - b'A' + 10) as u32),
        _ => None,
    }
}

struct Builder {
    line: [u8; 160],
    ll: usize,
    long: bool,
    last: u32,
    skipped: u32,
    truncated: u32,
}

impl Builder {
    fn new() -> Self {
        Builder { line: [0; 160], ll: 0, long: false, last: 0, skipped: 0, truncated: 0 }
    }

    fn feed(&mut self, b: &[u8]) {
        for &c in b {
            if c == b'\n' {
                if self.long {
                    self.skipped += 1;
                } else {
                    let l = self.line;
                    self.one(&l[..self.ll]);
                }
                self.ll = 0;
                self.long = false;
            } else if self.ll < self.line.len() {
                self.line[self.ll] = c;
                self.ll += 1;
            } else {
                self.long = true;
            }
        }
    }

    fn end(&mut self) {
        if self.ll > 0 && !self.long {
            let l = self.line;
            self.one(&l[..self.ll]);
        }
        self.ll = 0;
    }

    fn one(&mut self, l: &[u8]) {
        let l = trim(l);
        if l.is_empty() || l[0] == b'#' {
            return;
        }
        if l.len() < 8 || l[6] != b' ' && l[6] != b'\t' {
            self.skipped += 1;
            return;
        }
        let mut k = 0u32;
        for &c in &l[..6] {
            match hex(c) {
                Some(v) => k = (k << 4) | v,
                None => {
                    self.skipped += 1;
                    return;
                }
            }
        }
        let name = trim(&l[7..]);
        let name = &name[..name.len().min(NAME_MAX)];
        // sorted, strictly increasing: a binary search over what we keep must stay correct
        let n = unsafe { N };
        if name.is_empty() || (n > 0 && k <= self.last) || core::str::from_utf8(name).is_err() {
            self.skipped += 1;
            return;
        }
        if n >= CAP {
            self.truncated += 1;
            return;
        }
        let Some(off) = intern(name) else {
            self.truncated += 1;
            return;
        };
        unsafe {
            KEYS[n] = k;
            NAMES[n] = off;
            N = n + 1;
        }
        self.last = k;
    }
}

fn trim(mut s: &[u8]) -> &[u8] {
    while let [b' ' | b'\t' | b'\r', rest @ ..] = s {
        s = rest;
    }
    while let [rest @ .., b' ' | b'\t' | b'\r'] = s {
        s = rest;
    }
    s
}

/// The registered vendor of a (non-randomised) MAC, "" when unknown or randomised.
pub fn vendor(mac: &[u8; 6]) -> &'static str {
    if mac[0] & 0x02 != 0 {
        return "";
    }
    let k = ((mac[0] as u32) << 16) | ((mac[1] as u32) << 8) | mac[2] as u32;
    let n = unsafe { N };
    let all = unsafe { &*core::ptr::addr_of!(KEYS) };
    let keys = &all[..n];
    match keys.binary_search(&k) {
        Ok(i) => core::str::from_utf8(name_at(unsafe { NAMES[i] } as usize)).unwrap_or(""),
        Err(_) => "",
    }
}

/// Parse a pack held in memory (selftest / tests).
pub fn load_text(t: &[u8]) -> (u32, u32) {
    reset();
    let mut b = Builder::new();
    b.feed(t);
    b.end();
    (b.skipped, b.truncated)
}

fn signed_message(gen: u64, len: u64, digest: &[u8; 32]) -> [u8; 54] {
    let mut m = [0u8; 54];
    m[..6].copy_from_slice(b"HQOUI1");
    m[6..14].copy_from_slice(&gen.to_le_bytes());
    m[14..22].copy_from_slice(&len.to_le_bytes());
    m[22..].copy_from_slice(digest);
    m
}

fn check_sig(sig: &[u8], key: &[u8; 32], digest_of: &mut dyn FnMut(u64) -> Option<[u8; 32]>) -> Result<(u64, u64), crate::shield::LoadErr> {
    use crate::shield::LoadErr;
    if sig.len() < 120 || &sig[..8] != b"HQOSIG1\0" {
        return Err(LoadErr::SigMalformed);
    }
    let gen = u64::from_le_bytes(sig[8..16].try_into().unwrap());
    let len = u64::from_le_bytes(sig[16..24].try_into().unwrap());
    if len > MAX_FILE {
        return Err(LoadErr::TooBig);
    }
    let mut want = [0u8; 32];
    want.copy_from_slice(&sig[24..56]);
    let d = digest_of(len).ok_or(LoadErr::Io)?;
    if d != want {
        return Err(LoadErr::DigestMismatch);
    }
    let pk = ed25519_compact::PublicKey::from_slice(key).map_err(|_| LoadErr::SigMalformed)?;
    let s = ed25519_compact::Signature::from_slice(&sig[56..120]).map_err(|_| LoadErr::SigMalformed)?;
    pk.verify(&signed_message(gen, len, &d)[..], &s).map_err(|_| LoadErr::BadSignature)?;
    Ok((gen, len))
}

fn stream<D: BlockDev>(dev: &D, lba: u64, len: u64, f: &mut dyn FnMut(&[u8])) -> Option<()> {
    let mut sec = [0u8; 512];
    let mut left = len;
    let mut k = 0u64;
    while left > 0 {
        dev.read_block(lba + k, &mut sec).ok()?;
        let take = left.min(512) as usize;
        f(&sec[..take]);
        left -= take as u64;
        k += 1;
    }
    Some(())
}

/// Boot: OUI.TXT (+ OUI.SIG when an operator key is compiled in). A refused pack is not loaded; the curated
/// `fpdb` vendors keep working either way.
pub fn load<D: BlockDev>(dev: &D) -> Info {
    reset();
    let mut info = Info::default();
    let mut sec = [0u8; 512];
    let p1 = if dev.read_block(0, &mut sec).is_ok() { crate::store::parse_mbr(&sec)[0].start } else { 0 };
    if p1 != 0 {
        if let Some((lba, nsec)) = crate::fat::locate_contiguous(dev, p1, b"OUI     TXT") {
            let cap = nsec * 512;
            let r = match POLICY_PUBKEY {
                Some(key) => {
                    let mut sig = [0u8; 512];
                    if crate::fat::locate_contiguous(dev, p1, b"OUI     SIG").and_then(|(l, _)| dev.read_block(l, &mut sig).ok()).is_none() {
                        Err(crate::shield::LoadErr::SigMissing)
                    } else {
                        let mut dig = |len: u64| -> Option<[u8; 32]> {
                            if len > cap {
                                return None;
                            }
                            let mut h = boot_abi::sha256::Hasher::new();
                            stream(dev, lba, len, &mut |c| h.update(c))?;
                            Some(h.finish())
                        };
                        check_sig(&sig, &key, &mut dig).map(|(g, l)| (g, l, true))
                    }
                }
                None => Ok((0, cap.min(MAX_FILE), false)),
            };
            match r {
                Ok((g, len, signed)) => {
                    let mut b = Builder::new();
                    if stream(dev, lba, len, &mut |c| b.feed(c)).is_some() {
                        b.end();
                        info = Info { file: 1, signed, generation: g, skipped: b.skipped, truncated: b.truncated, refused: None };
                    } else {
                        reset();
                        info.file = 2;
                        info.refused = Some(crate::shield::LoadErr::Io);
                    }
                }
                Err(e) => {
                    info.file = 2;
                    info.refused = Some(e);
                }
            }
        }
    }
    unsafe { INFO = info };
    info
}

/// `[P-oui]`
pub fn selftest() -> bool {
    use ed25519_compact::{KeyPair, Seed};
    let text = b"# IEEE MA-L (test)\n00000C Cisco Systems, Inc\n000393 Apple, Inc.\n0003FF Microsoft Corporation\n001B63 Apple, Inc.\n001B60 Out Of Order\nZZZZZZ Not Hex\n0050F2\n3C5AB4 Google, Inc.\nB827EB Raspberry Pi Foundation\n";
    let (skipped, truncated) = load_text(text);
    let parsed = len() == 6 && skipped == 3 && truncated == 0;
    let found = vendor(&[0x00, 0x03, 0x93, 1, 2, 3]) == "Apple, Inc." && vendor(&[0xb8, 0x27, 0xeb, 0, 0, 1]) == "Raspberry Pi Foundation"
        && vendor(&[0x00, 0x00, 0x0c, 9, 9, 9]) == "Cisco Systems, Inc";
    let unknown = vendor(&[0x00, 0x00, 0x0d, 0, 0, 0]).is_empty() && vendor(&[0xff, 0xff, 0xff, 0, 0, 0]).is_empty();
    let random = vendor(&[0x02, 0x03, 0x93, 1, 2, 3]).is_empty(); // locally administered: no vendor
    // two "Apple, Inc." lines share one arena record
    let dedup = unsafe { NAMES[1] == NAMES[3] };
    // signature: valid / tampered body / an IOC-domain signature presented as OUI.SIG
    let kp = KeyPair::from_seed(Seed::new([0x0e; 32]));
    let pk: [u8; 32] = *kp.pk;
    let d = boot_abi::sha256::digest(text);
    let mk = |tag: &[u8; 6]| -> [u8; 512] {
        let mut m = [0u8; 54];
        m[..6].copy_from_slice(tag);
        m[6..14].copy_from_slice(&3u64.to_le_bytes());
        m[14..22].copy_from_slice(&(text.len() as u64).to_le_bytes());
        m[22..].copy_from_slice(&d);
        let s = kp.sk.sign(&m[..], None);
        let mut sig = [0u8; 512];
        sig[..8].copy_from_slice(b"HQOSIG1\0");
        sig[8..16].copy_from_slice(&3u64.to_le_bytes());
        sig[16..24].copy_from_slice(&(text.len() as u64).to_le_bytes());
        sig[24..56].copy_from_slice(&d);
        sig[56..120].copy_from_slice(&s[..]);
        sig
    };
    let good = mk(b"HQOUI1");
    let ok_sig = check_sig(&good, &pk, &mut |_| Some(d)).is_ok();
    let mut bad_body = d;
    bad_body[0] ^= 1;
    let tampered = check_sig(&good, &pk, &mut |_| Some(bad_body)).is_err();
    let foreign = check_sig(&mk(b"HQIOC1"), &pk, &mut |_| Some(d)).is_err();
    // hostile input: overlong lines, binary junk — never a panic, never an out-of-order table
    load_text(&[0xffu8; 4000]);
    let junk_safe = len() == 0;
    let mut long = [b'A'; 600];
    long[599] = b'\n';
    let (sk2, _) = load_text(&long);
    let long_safe = len() == 0 && sk2 == 1;
    reset();
    let pass = parsed && found && unknown && random && dedup && ok_sig && tampered && foreign && junk_safe && long_safe;
    arch_aarch64::_print(format_args!(
        " [P-oui] {} — full IEEE OUI registry as a signed data file (OUI.TXT/OUI.SIG, own signature domain): parsed + junk/out-of-order skipped={} lookup={} unknown stays unknown={} randomised MAC no vendor={} names de-duplicated={} signature ok={} tampered refused={} foreign-domain refused={} hostile input safe={}\n",
        if pass { "PASS" } else { "FAIL" }, parsed, found, unknown, random, dedup, ok_sig, tampered, foreign, junk_safe && long_safe
    ));
    pass
}
