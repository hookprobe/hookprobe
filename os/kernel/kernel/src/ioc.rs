//! Threat-intel IOC pack (parity gap G7) — replaces the 4-CIDR stub as the source of `ioc_match`.
//!
//! `IOC.TXT` on the boot partition, operator-signed (`IOC.SIG`, magic HQISIG1 / tag HQIOC1 — never
//! interchangeable with BLOCK/ALLOW/POLICY signatures). Lines (comments `#`):
//!   `1.2.3.4`  `10.66.66.0/24`  `ip 1.2.3.4`  `cidr 1.2.3.0/24`  `domain evil.example`  `evil.example`
//! optionally followed by `exp=<unix seconds>` (the entry stops matching after that time once the wall
//! clock is set — HYDRA never deleted expired IOCs). Feeds (Spamhaus DROP, Feodo, SSLBL, URLhaus …) are
//! compiled into this format OFF-device; on-device refresh rides the MSSP channel later.
//!
//! Matching is OBSERVE-ONLY (ADR 0023: identity-based intel never drops a packet): an IP hit raises
//! `ioc_match` through the existing rule-302 path, a domain hit raises it from Shield.

use hal::BlockDev;

pub const V4_CAP: usize = 65_536;
pub const DOM_CAP: usize = 65_536;
pub const MAX_FILE: u64 = 16 << 20;

/// (network, prefix len, expiry unix s or 0)
#[derive(Clone, Copy)]
struct P4 {
    net: u32,
    len: u8,
    exp: u32,
}
const P0: P4 = P4 { net: 0, len: 0, exp: 0 };
static mut V4: [P4; V4_CAP] = [P0; V4_CAP];
static mut V4N: usize = 0;
/// Bitmask of prefix lengths present (bit L set = some /L entry exists).
static mut LENS: u64 = 0;
/// IPv6 IOC prefixes (G24a: the pack was IPv4-only, so a C2 reachable over IPv6 never matched).
pub const V6_CAP: usize = 16_384;
#[derive(Clone, Copy)]
struct P6 {
    net: u128,
    len: u8,
    exp: u32,
}
const Q0: P6 = P6 { net: 0, len: 0, exp: 0 };
static mut V6: [P6; V6_CAP] = [Q0; V6_CAP];
static mut V6N: usize = 0;
/// Prefix lengths present, bit L of the 129-bit set (lengths 0..=128).
static mut LENS6: [u64; 3] = [0; 3];
static mut DOM: [(u64, u32); DOM_CAP] = [(0, 0); DOM_CAP];
static mut DOMN: usize = 0;
/// Wall clock (unix s) for expiry; 0 = unknown → expiry not enforced (honest: we cannot tell).
static mut NOW_UNIX: u32 = 0;

#[derive(Clone, Copy, Debug, Default)]
#[cfg_attr(not(feature = "cm5"), allow(dead_code))]
pub struct Info {
    pub file: u8, // 0 none, 1 loaded, 2 refused
    pub signed: bool,
    pub generation: u64,
    pub skipped: u32,
    pub truncated: u32,
    pub refused: Option<crate::shield::LoadErr>,
}
static mut INFO: Info = Info { file: 0, signed: false, generation: 0, skipped: 0, truncated: 0, refused: None };

pub fn info() -> Info {
    unsafe { INFO }
}
pub fn v4_len() -> usize {
    unsafe { V4N }
}
pub fn v6_len() -> usize {
    unsafe { V6N }
}
pub fn dom_len() -> usize {
    unsafe { DOMN }
}
/// Set the wall clock used for expiry (call when SNTP syncs).
pub fn set_now_unix(t: u32) {
    unsafe { NOW_UNIX = t };
}

fn fnv(name: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in name {
        h ^= b.to_ascii_lowercase() as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

fn live(exp: u32) -> bool {
    let now = unsafe { NOW_UNIX };
    exp == 0 || now == 0 || now < exp
}

fn mask6(len: u8) -> u128 {
    if len == 0 { 0 } else { u128::MAX << (128 - len as u32) }
}

/// Is this IPv6 address inside a live IOC prefix? Longest prefix first.
pub fn ip6_listed(a: &[u8; 16]) -> bool {
    let (t, lens) = unsafe { (&(&*core::ptr::addr_of!(V6))[..V6N], LENS6) };
    if t.is_empty() {
        return false;
    }
    let ip = u128::from_be_bytes(*a);
    for len in (0..=128u8).rev() {
        if lens[len as usize / 64] & (1u64 << (len % 64)) == 0 {
            continue;
        }
        let key = (ip & mask6(len), len);
        if let Ok(i) = t.binary_search_by(|p| (p.net, p.len).cmp(&key)) {
            if live(t[i].exp) {
                return true;
            }
        }
    }
    false
}

/// RFC 4291 text form (hex groups, one `::`, optional /len). No embedded IPv4, no zone.
fn parse_v6(s: &[u8]) -> Option<(u128, u8)> {
    let (addr, len) = match s.iter().position(|&c| c == b'/') {
        Some(p) => (&s[..p], core::str::from_utf8(&s[p + 1..]).ok()?.parse::<u8>().ok().filter(|&l| l <= 128)?),
        None => (s, 128u8),
    };
    if !addr.contains(&b':') || addr.len() > 39 {
        return None;
    }
    let group = |g: &[u8]| -> Option<u16> {
        if g.is_empty() || g.len() > 4 || !g.iter().all(|c| c.is_ascii_hexdigit()) {
            return None;
        }
        u16::from_str_radix(core::str::from_utf8(g).ok()?, 16).ok()
    };
    let mut head = [0u16; 8];
    let mut tail = [0u16; 8];
    let (mut nh, mut nt) = (0usize, 0usize);
    let dbl = addr.windows(2).position(|w| w == b"::");
    let (left, right): (&[u8], &[u8]) = match dbl {
        Some(p) => {
            if addr[p + 2..].windows(2).any(|w| w == b"::") {
                return None; // two "::"
            }
            (&addr[..p], &addr[p + 2..])
        }
        None => (addr, &[]),
    };
    if !left.is_empty() {
        for g in left.split(|&c| c == b':') {
            if nh == 8 {
                return None;
            }
            head[nh] = group(g)?;
            nh += 1;
        }
    }
    if !right.is_empty() {
        for g in right.split(|&c| c == b':') {
            if nt == 8 {
                return None;
            }
            tail[nt] = group(g)?;
            nt += 1;
        }
    }
    if (dbl.is_some() && nh + nt > 7) || (dbl.is_none() && nh != 8) {
        return None;
    }
    let mut g = [0u16; 8];
    g[..nh].copy_from_slice(&head[..nh]);
    g[8 - nt..].copy_from_slice(&tail[..nt]);
    let mut v = 0u128;
    for x in g {
        v = (v << 16) | x as u128;
    }
    Some((v & mask6(len), len))
}

fn mask(len: u8) -> u32 {
    if len == 0 { 0 } else { u32::MAX << (32 - len as u32) }
}

/// Is `ip` inside a live IOC prefix? Longest prefix first.
pub fn ip_listed(ip: u32) -> bool {
    let (t, lens) = unsafe { (&(&*core::ptr::addr_of!(V4))[..V4N], LENS) };
    if t.is_empty() {
        return false;
    }
    for len in (0..=32u8).rev() {
        if lens & (1u64 << len) == 0 {
            continue;
        }
        let key = (ip & mask(len), len);
        if let Ok(i) = t.binary_search_by(|p| (p.net, p.len).cmp(&key)) {
            if live(t[i].exp) {
                return true;
            }
        }
    }
    false
}

/// Is `name` (or a parent domain) a live IOC domain?
pub fn domain_listed(name: &[u8]) -> bool {
    let t = unsafe { &(&*core::ptr::addr_of!(DOM))[..DOMN] };
    if t.is_empty() {
        return false;
    }
    let name = name.strip_suffix(b".").unwrap_or(name);
    let mut start = 0usize;
    loop {
        let suf = &name[start..];
        if !suf.contains(&b'.') {
            return false;
        }
        if let Ok(i) = t.binary_search_by(|e| e.0.cmp(&fnv(suf))) {
            if live(t[i].1) {
                return true;
            }
        }
        match suf.iter().position(|&c| c == b'.') {
            Some(p) => start += p + 1,
            None => return false,
        }
    }
}

fn parse_v4(s: &[u8]) -> Option<(u32, u8)> {
    let (addr, len) = match s.iter().position(|&c| c == b'/') {
        Some(p) => (&s[..p], core::str::from_utf8(&s[p + 1..]).ok()?.parse::<u8>().ok().filter(|&l| l <= 32)?),
        None => (s, 32u8),
    };
    let mut v = 0u32;
    let mut parts = 0;
    for t in addr.split(|&c| c == b'.') {
        if t.is_empty() || t.len() > 3 || !t.iter().all(|c| c.is_ascii_digit()) {
            return None;
        }
        let o: u32 = core::str::from_utf8(t).ok()?.parse().ok()?;
        if o > 255 {
            return None;
        }
        v = (v << 8) | o;
        parts += 1;
    }
    if parts != 4 {
        return None;
    }
    Some((v & mask(len), len))
}

fn valid_domain(d: &[u8]) -> Option<&[u8]> {
    let d = d.strip_suffix(b".").unwrap_or(d);
    if d.len() < 3 || d.len() > 253 || !d.contains(&b'.') || d.starts_with(b".") || d.windows(2).any(|w| w == b"..") {
        return None;
    }
    if !d.iter().all(|&c| c.is_ascii_alphanumeric() || c == b'-' || c == b'.' || c == b'_') || d.iter().all(|&c| c.is_ascii_digit() || c == b'.') {
        return None;
    }
    Some(d)
}

enum Line<'a> {
    Skip,
    V4(u32, u8, u32),
    V6(u128, u8, u32),
    Dom(&'a [u8], u32),
    /// a JA4 TLS-client fingerprint (hash in the domain table's "ja4:" namespace)
    Ja4(u64, u32),
    Bad,
}

/// Hash of a JA4 IOC: its own namespace inside the domain table (never collides with a name).
fn ja4_key(v: &[u8]) -> u64 {
    let mut h: u64 = 0x6a61_343a_0000_0001; // "ja4:" seed
    for &b in v {
        h ^= b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

/// A well-formed JA4 string: 36 chars [a-z0-9_], '_' at 10 and 23.
fn valid_ja4(v: &[u8]) -> bool {
    v.len() == 36 && v[10] == b'_' && v[23] == b'_' && v.iter().all(|&c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_')
}

/// Is this TLS client fingerprint a live IOC? (rule 125)
pub fn ja4_listed(ja4: &[u8]) -> bool {
    let t = unsafe { &(&*core::ptr::addr_of!(DOM))[..DOMN] };
    !t.is_empty() && t.binary_search_by(|e| e.0.cmp(&ja4_key(ja4))).is_ok_and(|i| live(t[i].1))
}

fn parse_line(line: &[u8]) -> Line<'_> {
    let line = match line.iter().position(|&c| c == b'#') {
        Some(p) => &line[..p],
        None => line,
    };
    let mut toks = line.split(|c| c.is_ascii_whitespace()).filter(|t| !t.is_empty());
    let Some(mut first) = toks.next() else { return Line::Skip };
    let mut kind = 0u8; // 0 auto, 1 ip, 2 domain
    match first {
        b"ip" | b"cidr" | b"ipv4" | b"ipv6" => kind = 1,
        b"domain" | b"host" => kind = 2,
        b"ja4" => kind = 3,
        _ => {}
    }
    if kind != 0 {
        let Some(n) = toks.next() else { return Line::Bad };
        first = n;
    }
    let mut exp = 0u32;
    for t in toks {
        match t.strip_prefix(b"exp=").and_then(|v| core::str::from_utf8(v).ok()?.parse::<u32>().ok()) {
            Some(e) => exp = e,
            None => return Line::Bad,
        }
    }
    if kind == 3 {
        return if valid_ja4(first) { Line::Ja4(ja4_key(first), exp) } else { Line::Bad };
    }
    if kind != 2 {
        if let Some((n, l)) = parse_v4(first) {
            return Line::V4(n, l, exp);
        }
        if let Some((n, l)) = parse_v6(first) {
            return Line::V6(n, l, exp);
        }
        if kind == 1 {
            return Line::Bad;
        }
    }
    match valid_domain(first) {
        Some(d) => Line::Dom(d, exp),
        None => Line::Bad,
    }
}

struct Builder {
    line: [u8; 300],
    ll: usize,
    over: bool,
    skipped: u32,
    truncated: u32,
}

impl Builder {
    fn new() -> Self {
        Builder { line: [0; 300], ll: 0, over: false, skipped: 0, truncated: 0 }
    }
    fn end(&mut self) {
        if self.over {
            self.skipped += 1;
        } else if self.ll > 0 {
            match parse_line(&self.line[..self.ll]) {
                Line::Skip => {}
                Line::Bad => self.skipped += 1,
                Line::V4(n, l, e) => unsafe {
                    if V4N < V4_CAP {
                        (*core::ptr::addr_of_mut!(V4))[V4N] = P4 { net: n, len: l, exp: e };
                        V4N += 1;
                        LENS |= 1u64 << l;
                    } else {
                        self.truncated += 1;
                    }
                },
                Line::V6(n, l, e) => unsafe {
                    if V6N < V6_CAP {
                        (*core::ptr::addr_of_mut!(V6))[V6N] = P6 { net: n, len: l, exp: e };
                        V6N += 1;
                        LENS6[l as usize / 64] |= 1u64 << (l % 64);
                    } else {
                        self.truncated += 1;
                    }
                },
                Line::Ja4(k, e) => unsafe {
                    if DOMN < DOM_CAP {
                        (*core::ptr::addr_of_mut!(DOM))[DOMN] = (k, e);
                        DOMN += 1;
                    } else {
                        self.truncated += 1;
                    }
                },
                Line::Dom(d, e) => unsafe {
                    if DOMN < DOM_CAP {
                        (*core::ptr::addr_of_mut!(DOM))[DOMN] = (fnv(d), e);
                        DOMN += 1;
                    } else {
                        self.truncated += 1;
                    }
                },
            }
        }
        self.ll = 0;
        self.over = false;
    }
    fn feed(&mut self, chunk: &[u8]) {
        for &c in chunk {
            if c == b'\n' || c == b'\r' {
                self.end();
            } else if c == 0 {
            } else if self.ll < self.line.len() {
                self.line[self.ll] = c;
                self.ll += 1;
            } else {
                self.over = true;
            }
        }
    }
}

fn seal() {
    unsafe {
        let v = &mut (&mut *core::ptr::addr_of_mut!(V4))[..V4N];
        v.sort_unstable_by_key(|a| (a.net, a.len));
        let mut w = 0;
        for r in 0..v.len() {
            if w == 0 || (v[r].net, v[r].len) != (v[w - 1].net, v[w - 1].len) {
                v[w] = v[r];
                w += 1;
            } else if v[r].exp == 0 || (v[w - 1].exp != 0 && v[r].exp > v[w - 1].exp) {
                v[w - 1].exp = v[r].exp; // duplicate: keep the longest-lived
            }
        }
        V4N = w;
        let v6 = &mut (&mut *core::ptr::addr_of_mut!(V6))[..V6N];
        v6.sort_unstable_by_key(|a| (a.net, a.len));
        let mut w = 0;
        for r in 0..v6.len() {
            if w == 0 || (v6[r].net, v6[r].len) != (v6[w - 1].net, v6[w - 1].len) {
                v6[w] = v6[r];
                w += 1;
            } else if v6[r].exp == 0 || (v6[w - 1].exp != 0 && v6[r].exp > v6[w - 1].exp) {
                v6[w - 1].exp = v6[r].exp;
            }
        }
        V6N = w;
        let d = &mut (&mut *core::ptr::addr_of_mut!(DOM))[..DOMN];
        d.sort_unstable_by_key(|e| e.0);
        let mut w = 0;
        for r in 0..d.len() {
            if w == 0 || d[r].0 != d[w - 1].0 {
                d[w] = d[r];
                w += 1;
            }
        }
        DOMN = w;
    }
}

fn reset() {
    unsafe {
        V4N = 0;
        V6N = 0;
        LENS6 = [0; 3];
        DOMN = 0;
        LENS = 0;
    }
}

/// Load from memory (selftests). Returns (skipped, truncated).
pub fn load_text(t: &[u8]) -> (u32, u32) {
    reset();
    let mut b = Builder::new();
    b.feed(t);
    b.end();
    seal();
    (b.skipped, b.truncated)
}

fn stream<D: BlockDev>(dev: &D, lba: u64, len: u64, f: &mut dyn FnMut(&[u8])) -> Option<()> {
    crate::store::stream_blocks(dev, lba, len, f)
}

fn signed_message(gen: u64, len: u64, digest: &[u8; 32]) -> [u8; 54] {
    let mut m = [0u8; 54];
    m[..6].copy_from_slice(b"HQIOC1");
    m[6..14].copy_from_slice(&gen.to_le_bytes());
    m[14..22].copy_from_slice(&len.to_le_bytes());
    m[22..].copy_from_slice(digest);
    m
}

pub(crate) fn check_sig(sig: &[u8], key: &[u8; 32], digest_of: &mut dyn FnMut(u64) -> Option<[u8; 32]>) -> Result<(u64, u64), crate::shield::LoadErr> {
    use crate::shield::LoadErr;
    if sig.len() < 120 || &sig[..8] != b"HQISIG1\0" {
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

/// Boot: IOC.TXT (+ IOC.SIG when an operator key is compiled in). A refused pack is not loaded.
pub fn load<D: BlockDev>(dev: &D) -> Info {
    crate::blocklist::seed_off(); // a device: only the signed pack is threat intel from here on
    reset();
    let mut info = Info::default();
    let mut sec = [0u8; 512];
    let p1 = if dev.read_block(0, &mut sec).is_ok() { crate::store::parse_mbr(&sec)[0].start } else { 0 };
    if p1 != 0 {
        if let Some((lba, nsec)) = crate::artstore::locate(dev, p1, b"IOC     TXT") {
            let cap = nsec * 512;
            let r = match crate::policysig::key() {
                Some(key) => {
                    let mut sig = [0u8; 512];
                    if crate::artstore::locate(dev, p1, b"IOC     SIG").and_then(|(l, _)| dev.read_block(l, &mut sig).ok()).is_none() {
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
    seal();
    unsafe { INFO = info };
    info
}

/// `[P-ioc]`
pub fn selftest() -> bool {
    use ed25519_compact::{KeyPair, Seed};
    let text = b"# test pack\n203.0.113.7\ncidr 198.51.100.0/24\nip 192.0.2.5 exp=1700000000\n10.66.0.0/16\nbad.example exp=1900000000\ndomain c2.evil.test\n10.0.0.0/33\n300.1.1.1\nip notanip\nfoo exp=zz\n";
    let (skipped, _) = load_text(text);
    let parsed = v4_len() == 4 && dom_len() == 2 && skipped == 4;
    set_now_unix(0);
    let lpm = ip_listed(0xCB00_7107) && !ip_listed(0xCB00_7108) && ip_listed(0xC633_64FE) && ip_listed(0x0A42_1234) && !ip_listed(0x0A43_0001);
    let expiry_unknown_clock = ip_listed(0xC000_0205); // clock unknown: not enforced
    set_now_unix(1_800_000_000);
    let expired = !ip_listed(0xC000_0205) && ip_listed(0xCB00_7107);
    let doms = domain_listed(b"bad.example") && domain_listed(b"x.c2.evil.test") && !domain_listed(b"evil.test") && !domain_listed(b"notbad.example");
    set_now_unix(1_950_000_000);
    let dom_exp = !domain_listed(b"bad.example") && domain_listed(b"c2.evil.test");
    set_now_unix(0);
    // signature: valid / tampered / BLOCK.SIG presented as IOC.SIG
    let kp = KeyPair::from_seed(Seed::new([0x71; 32]));
    let pk: [u8; 32] = *kp.pk;
    let body: &[u8] = text;
    let d = boot_abi::sha256::digest(body);
    let mut sig = [0u8; 512];
    sig[..8].copy_from_slice(b"HQISIG1\0");
    sig[8..16].copy_from_slice(&5u64.to_le_bytes());
    sig[16..24].copy_from_slice(&(body.len() as u64).to_le_bytes());
    sig[24..56].copy_from_slice(&d);
    sig[56..120].copy_from_slice(kp.sk.sign(&signed_message(5, body.len() as u64, &d)[..], None).as_ref());
    let mut dig = |len: u64| if len as usize <= body.len() { Some(boot_abi::sha256::digest(&body[..len as usize])) } else { None };
    let sig_ok = check_sig(&sig, &pk, &mut dig) == Ok((5, body.len() as u64));
    let mut bad = sig;
    bad[60] ^= 1;
    let sig_bad = check_sig(&bad, &pk, &mut dig).is_err();
    let mut wrong = sig;
    wrong[..8].copy_from_slice(b"HQBSIG1\0");
    let sig_x = check_sig(&wrong, &pk, &mut dig).is_err();
    // G24a: IPv6 entries — full, ::-compressed and /len forms; junk (two '::', 9 groups, 5-hex group, /129) refused
    let (sk6, _) = load_text(b"ip 2001:db8:bad::7\ncidr 2001:db8:c2::/48\n2001:0db8:0000:0000:0000:0000:0000:0042 exp=1700000000\nipv6 ::1\n2001:db8::1::2\n1:2:3:4:5:6:7:8:9\n2001:db8:12345::1\nip 2001:db8::/129\n");
    let a6 = |s: [u16; 8]| -> [u8; 16] {
        let mut b = [0u8; 16];
        for (i, g) in s.iter().enumerate() {
            b[2 * i..2 * i + 2].copy_from_slice(&g.to_be_bytes());
        }
        b
    };
    set_now_unix(0);
    let v6 = v6_len() == 4 && sk6 == 4
        && ip6_listed(&a6([0x2001, 0xdb8, 0xbad, 0, 0, 0, 0, 7])) && !ip6_listed(&a6([0x2001, 0xdb8, 0xbad, 0, 0, 0, 0, 8]))
        && ip6_listed(&a6([0x2001, 0xdb8, 0xc2, 0xffff, 1, 2, 3, 4])) && !ip6_listed(&a6([0x2001, 0xdb8, 0xc3, 0, 0, 0, 0, 1]))
        && ip6_listed(&a6([0, 0, 0, 0, 0, 0, 0, 1]))
        && ip6_listed(&a6([0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x42])) // clock unknown: expiry not enforced
        && { set_now_unix(1_800_000_000); let e = !ip6_listed(&a6([0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x42])); set_now_unix(0); e };
    reset();
    let empty = !ip_listed(0xCB00_7107) && !domain_listed(b"bad.example") && !ip6_listed(&a6([0, 0, 0, 0, 0, 0, 0, 1]));
    let pass = parsed && lpm && expiry_unknown_clock && expired && doms && dom_exp && sig_ok && sig_bad && sig_x && empty && v6;
    arch_aarch64::_print(format_args!(
        " [P-ioc] {} — signed IOC pack (parity G7, replaces the 4-CIDR stub; observe-only): parse (ip / cidr / domain / bare, exp=, junk refused) ok={} | longest-prefix match={} expiry not enforced without a wall clock={} expired entry stops matching={} | domains incl. subdomains, label-boundary={} domain expiry={} | IOC.SIG ok={} tampered refused={} other-file signature refused={} | empty pack matches nothing={} | IPv6 prefixes (::, /len, expiry, junk refused)={}\n",
        if pass { "PASS" } else { "FAIL" }, parsed, lpm, expiry_unknown_clock, expired, doms, dom_exp, sig_ok, sig_bad, sig_x, empty, v6
    ));
    pass
}
