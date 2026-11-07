//! Shield — the AP's DNS blocklist ("refuse a NAME, never a PACKET", ADR 0023).
//!
//! `BLOCK.TXT` on the FAT boot partition: one domain per line (`#` comments; hosts-file lines such as
//! `0.0.0.0 ads.example` are accepted — the last token is the domain). A listed domain blocks itself
//! and every subdomain (label-boundary suffix match: `ads.example` blocks `x.ads.example`, never
//! `notads.example`). Stored as a sorted table of 64-bit FNV-1a hashes — bounded memory, no heap,
//! O(labels · log n) per query.
//!
//! Trust (ADR 0049 D1, same operator key as POLICY.TXT): when the image carries an operator key, the
//! file is accepted only with a valid `BLOCK.SIG`, checked BEFORE the parser sees a byte:
//!   [0..8)    "HQBSIG1\0"
//!   [8..16)   generation u64 LE
//!   [16..24)  length of BLOCK.TXT in bytes, u64 LE
//!   [24..56)  sha256(BLOCK.TXT[..length])
//!   [56..120) Ed25519 over "HQBLK1" || generation LE || length LE || sha256
//! A refused or missing signature leaves Shield OFF (nothing blocked) — a tampered list must not be
//! able to black-hole legitimate names. Without an operator key (standalone) the file is accepted as is.

use crate::policysig::POLICY_PUBKEY;
use hal::BlockDev;

pub const TXT_8_3: &[u8; 11] = b"BLOCK   TXT";
pub const SIG_8_3: &[u8; 11] = b"BLOCK   SIG";
const MAGIC: &[u8; 8] = b"HQBSIG1\0";
/// Domains kept (512 KiB of hashes). A longer list is truncated and the boot line says so.
pub const CAP: usize = 65_536;
/// Largest BLOCK.TXT read (bytes).
pub const MAX_FILE: u64 = 4 << 20;

static mut HASHES: [u64; CAP] = [0; CAP];
static mut LEN: usize = 0;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LoadErr {
    NoPartition,
    TooBig,
    SigMissing,
    SigMalformed,
    DigestMismatch,
    BadSignature,
    Io,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Loaded {
    pub domains: usize,
    pub truncated: usize,
    pub generation: u64,
    pub signed: bool,
}

fn fnv(name: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in name {
        h ^= b.to_ascii_lowercase() as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

/// Number of domains in the active list (0 = Shield off).
pub fn len() -> usize {
    unsafe { LEN }
}

fn table() -> &'static [u64] {
    unsafe { &(&*core::ptr::addr_of!(HASHES))[..LEN] }
}

/// Is `name` (dotted, any case, optional trailing dot) or any parent domain listed?
pub fn blocked(name: &[u8]) -> bool {
    let t = table();
    if t.is_empty() {
        return false;
    }
    let mut n = name;
    if let Some((&b'.', rest)) = n.split_last() {
        n = rest;
    }
    let mut start = 0usize;
    loop {
        let suf = &n[start..];
        // a bare TLD is never matched (a list entry "com" must not black-hole a whole TLD)
        if !suf.contains(&b'.') {
            return false;
        }
        if t.binary_search(&fnv(suf)).is_ok() {
            return true;
        }
        match suf.iter().position(|&c| c == b'.') {
            Some(p) => start += p + 1,
            None => return false,
        }
    }
}

/// The domain on one list line, or None (blank, comment, invalid).
fn line_domain(line: &[u8]) -> Option<&[u8]> {
    let line = match line.iter().position(|&c| c == b'#') {
        Some(p) => &line[..p],
        None => line,
    };
    let tok = line.split(|c| c.is_ascii_whitespace()).filter(|t| !t.is_empty()).last()?;
    let tok = tok.strip_suffix(b".").unwrap_or(tok);
    if tok.len() < 3 || tok.len() > 253 || !tok.contains(&b'.') || tok.starts_with(b".") || tok.contains(&b'/') {
        return None;
    }
    if !tok.iter().all(|&c| c.is_ascii_alphanumeric() || c == b'-' || c == b'.' || c == b'_') {
        return None;
    }
    // hosts-file noise
    if tok.eq_ignore_ascii_case(b"localhost.localdomain") || tok.iter().all(|&c| c.is_ascii_digit() || c == b'.') {
        return None;
    }
    Some(tok)
}

/// Line-assembling parser fed in chunks (the file is streamed sector by sector).
struct Builder {
    line: [u8; 300],
    ll: usize,
    overlong: bool,
    n: usize,
    dropped: usize,
}

impl Builder {
    fn new() -> Self {
        Builder { line: [0; 300], ll: 0, overlong: false, n: 0, dropped: 0 }
    }
    fn end_line(&mut self) {
        if !self.overlong {
            if let Some(d) = line_domain(&self.line[..self.ll]) {
                if self.n < CAP {
                    unsafe { (*core::ptr::addr_of_mut!(HASHES))[self.n] = fnv(d) };
                    self.n += 1;
                } else {
                    self.dropped += 1;
                }
            }
        }
        self.ll = 0;
        self.overlong = false;
    }
    fn feed(&mut self, chunk: &[u8]) {
        for &c in chunk {
            if c == b'\n' || c == b'\r' {
                self.end_line();
            } else if c == 0 {
                // padding after the text
            } else if self.ll < self.line.len() {
                self.line[self.ll] = c;
                self.ll += 1;
            } else {
                self.overlong = true;
            }
        }
    }
    /// Sort + dedup the table and make it live.
    fn finish(mut self) -> (usize, usize) {
        self.end_line();
        let t = unsafe { &mut (&mut *core::ptr::addr_of_mut!(HASHES))[..self.n] };
        t.sort_unstable();
        let mut w = 0usize;
        for r in 0..t.len() {
            if w == 0 || t[r] != t[w - 1] {
                t[w] = t[r];
                w += 1;
            }
        }
        unsafe { LEN = w };
        (w, self.dropped)
    }
}

/// Load a list from memory (selftests).
pub fn load_text(text: &[u8]) -> (usize, usize) {
    unsafe { LEN = 0 };
    let mut b = Builder::new();
    b.feed(text);
    b.finish()
}

fn signed_message(gen: u64, len: u64, digest: &[u8; 32]) -> [u8; 6 + 8 + 8 + 32] {
    let mut m = [0u8; 54];
    m[..6].copy_from_slice(b"HQBLK1");
    m[6..14].copy_from_slice(&gen.to_le_bytes());
    m[14..22].copy_from_slice(&len.to_le_bytes());
    m[22..].copy_from_slice(digest);
    m
}

/// Check BLOCK.SIG's signature + digest. `digest` is computed by the caller over the first `len`
/// bytes of the file. Returns (generation, length).
fn check_sig(sig: &[u8], key: &[u8; 32], digest_of: &mut dyn FnMut(u64) -> Option<[u8; 32]>) -> Result<(u64, u64), LoadErr> {
    if sig.len() < 120 || &sig[..8] != MAGIC {
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

/// Stream `len` bytes of a contiguous file at `lba` through `f`.
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

/// BLOCK.TXT (+ BLOCK.SIG when an operator key is compiled in) from the boot partition. None = no list.
pub fn load<D: BlockDev>(dev: &D) -> Option<Result<Loaded, LoadErr>> {
    unsafe { LEN = 0 };
    let mut sec = [0u8; 512];
    dev.read_block(0, &mut sec).ok()?;
    let p1 = crate::store::parse_mbr(&sec)[0].start;
    if p1 == 0 {
        return None;
    }
    let (lba, nsec) = crate::fat::locate_contiguous(dev, p1, TXT_8_3)?;
    let cap = nsec * 512;
    let (gen, len, signed) = match POLICY_PUBKEY {
        Some(key) => {
            let mut sig = [0u8; 512];
            if crate::fat::locate_contiguous(dev, p1, SIG_8_3).and_then(|(l, _)| dev.read_block(l, &mut sig).ok()).is_none() {
                return Some(Err(LoadErr::SigMissing));
            }
            let mut digest_of = |len: u64| -> Option<[u8; 32]> {
                if len > cap {
                    return None;
                }
                let mut h = boot_abi::sha256::Hasher::new();
                stream(dev, lba, len, &mut |c| h.update(c))?;
                Some(h.finish())
            };
            match check_sig(&sig, &key, &mut digest_of) {
                Ok((g, l)) => (g, l, true),
                Err(e) => return Some(Err(e)),
            }
        }
        None => (0, cap.min(MAX_FILE), false),
    };
    let mut b = Builder::new();
    if stream(dev, lba, len, &mut |c| b.feed(c)).is_none() {
        return Some(Err(LoadErr::Io));
    }
    let (domains, truncated) = b.finish();
    Some(Ok(Loaded { domains, truncated, generation: gen, signed }))
}

/// `[P-dnsblock]` — list parsing (comments, hosts-file lines, case, trailing dot, junk), label-boundary
/// suffix matching, the bare-TLD guard, the signature check (valid / tampered / wrong key / bumped
/// generation), and the blocked-query answer frame (A -> 0.0.0.0, other types -> NODATA, valid
/// checksums, non-DNS and malformed frames untouched). Leaves the table empty.
pub fn selftest() -> bool {
    use ed25519_compact::{KeyPair, Seed};
    let text = b"# test list\n0.0.0.0 Ads.Tracker.example\nmalware.test.\n127.0.0.1 localhost.localdomain\n\ncom\n1.2.3.4\nbad/entry.example\ntelemetry.vendor.example # trailing comment\n";
    let (n, dropped) = load_text(text);
    let parse_ok = n == 3 && dropped == 0;
    let m = blocked(b"ads.tracker.example") && blocked(b"x.y.ADS.tracker.example.") && blocked(b"malware.test")
        && blocked(b"cdn.telemetry.vendor.example");
    let not = !blocked(b"notads.tracker.example") && !blocked(b"tracker.example") && !blocked(b"example.com")
        && !blocked(b"test") && !blocked(b"good.example");

    // signature over the exact bytes
    let kp = KeyPair::from_seed(Seed::new([0x61; 32]));
    let other = KeyPair::from_seed(Seed::new([0x62; 32]));
    let pk: [u8; 32] = *kp.pk;
    let sign = |k: &KeyPair, gen: u64, body: &[u8]| {
        let d = boot_abi::sha256::digest(body);
        let s = k.sk.sign(&signed_message(gen, body.len() as u64, &d)[..], None);
        let mut f = [0u8; 512];
        f[..8].copy_from_slice(MAGIC);
        f[8..16].copy_from_slice(&gen.to_le_bytes());
        f[16..24].copy_from_slice(&(body.len() as u64).to_le_bytes());
        f[24..56].copy_from_slice(&d);
        f[56..120].copy_from_slice(s.as_ref());
        f
    };
    let body: &[u8] = text;
    fn dig(b: &[u8]) -> impl FnMut(u64) -> Option<[u8; 32]> + '_ {
        move |len: u64| if len as usize <= b.len() { Some(boot_abi::sha256::digest(&b[..len as usize])) } else { None }
    }
    let good = sign(&kp, 4, body);
    let ok = check_sig(&good, &pk, &mut dig(body)) == Ok((4, body.len() as u64));
    let mut tampered = [0u8; 256];
    tampered[..body.len()].copy_from_slice(body);
    tampered[20] ^= 0x20;
    let t = check_sig(&good, &pk, &mut dig(&tampered[..body.len()])) == Err(LoadErr::DigestMismatch);
    let w = check_sig(&sign(&other, 4, body), &pk, &mut dig(body)) == Err(LoadErr::BadSignature);
    let mut bumped = good;
    bumped[8] = 9;
    let bg = check_sig(&bumped, &pk, &mut dig(body)) == Err(LoadErr::BadSignature);
    let mal = check_sig(&[0u8; 512], &pk, &mut dig(body)) == Err(LoadErr::SigMalformed);

    // answer frames
    let ap_mac = [2u8, 0, 0, 0, 0, 1];
    let mut q = [0u8; 200];
    let qa = crate::dnssink::test_query_frame(b"ads.tracker.example", 1, &mut q);
    let mut out = [0u8; 600];
    let a_ok = crate::dnssink::block_reply_frame(&q[..qa], &ap_mac, &mut out, &blocked).map_or(false, |k| {
        crate::dnssink::reply_frame_ok(&q[..qa], &out[..k], &ap_mac) && out[k - 4..k] == [0, 0, 0, 0] && out[42 + 6..42 + 8] == 1u16.to_be_bytes()
    });
    let qaaaa = crate::dnssink::test_query_frame(b"ads.tracker.example", 28, &mut q);
    let aaaa_ok = crate::dnssink::block_reply_frame(&q[..qaaaa], &ap_mac, &mut out, &blocked).map_or(false, |k| {
        crate::dnssink::reply_frame_ok(&q[..qaaaa], &out[..k], &ap_mac) && out[42 + 6..42 + 8] == [0, 0] && out[42 + 3] & 0x0f == 0
    });
    let qg = crate::dnssink::test_query_frame(b"good.example", 1, &mut q);
    let pass_ok = crate::dnssink::block_reply_frame(&q[..qg], &ap_mac, &mut out, &blocked).is_none();
    let mut tcp = q;
    tcp[23] = 6;
    let tcp_ok = crate::dnssink::block_reply_frame(&tcp[..qa], &ap_mac, &mut out, &blocked).is_none();
    let trunc_ok = (0..qa).all(|l| crate::dnssink::block_reply_frame(&q[..l], &ap_mac, &mut out, &blocked).is_none());

    unsafe { LEN = 0 };
    let empty_ok = !blocked(b"ads.tracker.example");
    let pass = parse_ok && m && not && ok && t && w && bg && mal && a_ok && aaaa_ok && pass_ok && tcp_ok && trunc_ok && empty_ok;
    arch_aarch64::_print(format_args!(
        " [P-dnsblock] {} — Shield DNS blocklist: parse (comments, hosts lines, case, trailing dot, junk/TLD/IP refused) n={} ok={} | suffix match on label boundaries={} non-matches pass={} | BLOCK.SIG valid={} tampered refused={} wrong key refused={} generation bumped refused={} malformed refused={} | answer A->0.0.0.0={} AAAA->NODATA={} benign untouched={} non-UDP untouched={} every truncation refused={} | empty list blocks nothing={}\n",
        if pass { "PASS" } else { "FAIL" }, n, parse_ok, m, not, ok, t, w, bg, mal, a_ok, aaaa_ok, pass_ok, tcp_ok, trunc_ok, empty_ok
    ));
    pass
}
