//! Shield v2 — DNS protection on the heqk AP (ADR 0052; dnsXai model, its bugs not repeated).
//!
//! Pure, `no_std`, allocation-free. Every client DNS query the AP forwards passes `on_client_frame`; every
//! DNS reply on its way back to a client passes `on_reply_frame` (CNAME cloaking). Lists come from the boot
//! partition (BLOCK.TXT / ALLOW.TXT, operator-signed). Decisions, in order (ADR 0052 D4):
//!   1. SYSTEM floor (captive/connectivity checks, NTP, OCSP) — always allowed, cannot be removed;
//!   2. encrypted-DNS / bypass controls (DDR, Firefox canary, iCloud Private Relay, DoH hostnames);
//!   3. the LONGEST matching rule between ALLOW and BLOCK (ties -> allow);
//!   4. otherwise allowed.
//! Blocked names get NXDOMAIN for every QTYPE (+ Extended DNS Error 15 "Blocked" when the query used
//! EDNS), no SOA (nothing negatively cached). No ML/keyword rule ever blocks.

#[cfg(feature = "netsvc")]
use crate::mcstate::JsonBuf;
use crate::policysig::POLICY_PUBKEY;
#[cfg(feature = "netsvc")]
use core::fmt::Write;
use hal::BlockDev;

// ---------------------------------------------------------------------------------------------------
// Lists

pub const BLOCK_CAP: usize = 262_144;
pub const ALLOW_CAP: usize = 16_384;
pub const MAX_FILE: u64 = 16 << 20;

static mut BLOCK: [u64; BLOCK_CAP] = [0; BLOCK_CAP];
static mut BLEN: usize = 0;
static mut ALLOW: [u64; ALLOW_CAP] = [0; ALLOW_CAP];
static mut ALEN: usize = 0;

/// Operator policy (directives `#! key=value` inside the signed BLOCK.TXT).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Policy {
    /// true = DoT (TCP/853) refused and known DoH hostnames answered NXDOMAIN (default).
    pub encrypted_dns_block: bool,
    /// true = iCloud Private Relay hostnames answered NXDOMAIN; false = answered normally and reported (default).
    pub private_relay_block: bool,
}
const POLICY_DEFAULT: Policy = Policy { encrypted_dns_block: true, private_relay_block: false };
static mut POLICY: Policy = POLICY_DEFAULT;

/// What the boot loader found (shown in /api/dns and the boot line).
#[derive(Clone, Copy, Debug, Default)]
pub struct LoadInfo {
    pub block_file: u8, // 0 none, 1 loaded, 2 refused
    pub allow_file: u8,
    pub signed: bool,
    pub generation: u64,
    pub refused: Option<LoadErr>,
    pub skipped_lines: u32,
    pub truncated: u32,
}
static mut INFO: LoadInfo = LoadInfo { block_file: 0, allow_file: 0, signed: false, generation: 0, refused: None, skipped_lines: 0, truncated: 0 };

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LoadErr {
    SigMissing,
    SigMalformed,
    DigestMismatch,
    BadSignature,
    TooBig,
    Io,
}

fn fnv(name: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in name {
        h ^= b.to_ascii_lowercase() as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

fn block_table() -> &'static [u64] {
    unsafe { &(&*core::ptr::addr_of!(BLOCK))[..BLEN] }
}
fn allow_table() -> &'static [u64] {
    unsafe { &(&*core::ptr::addr_of!(ALLOW))[..ALEN] }
}
pub fn block_len() -> usize {
    unsafe { BLEN }
}
pub fn allow_len() -> usize {
    unsafe { ALEN }
}
pub fn policy() -> Policy {
    unsafe { POLICY }
}
pub fn info() -> LoadInfo {
    unsafe { INFO }
}

/// One list line → (domain, is_allow). Formats: bare, hosts (`0.0.0.0 d`), adblock `||d^`, `@@||d^`, `*.d`.
/// Returns Err(()) for a line that is not blank/comment but cannot be used (counted as skipped).
fn parse_line(line: &[u8]) -> Result<Option<(&[u8], bool)>, ()> {
    let line = trim(line);
    if line.is_empty() || line[0] == b'#' || line[0] == b'!' || line[0] == b'[' {
        return Ok(None);
    }
    let (mut body, mut allow) = (line, false);
    if let Some(r) = body.strip_prefix(b"@@") {
        body = r;
        allow = true;
    }
    if let Some(r) = body.strip_prefix(b"||") {
        // adblock: ||domain^  (any $options -> skipped: a network-filter option we do not implement)
        let end = r.iter().position(|&c| c == b'^').ok_or(())?;
        if r.get(end + 1..).map_or(false, |t| !trim(t).is_empty()) {
            return Err(());
        }
        return valid_domain(&r[..end]).map(|d| Some((d, allow))).ok_or(());
    }
    if allow {
        return Err(()); // `@@` without `||`
    }
    // strip a trailing comment
    if let Some(p) = body.iter().position(|&c| c == b'#') {
        body = trim(&body[..p]);
    }
    let mut toks = body.split(|c| c.is_ascii_whitespace()).filter(|t| !t.is_empty());
    let first = toks.next().ok_or(())?;
    let dom = if matches!(first, b"0.0.0.0" | b"127.0.0.1" | b"::" | b"::1" | b"0:0:0:0:0:0:0:0") {
        let d = toks.next().ok_or(())?;
        if matches!(d, b"localhost" | b"localhost.localdomain" | b"local" | b"broadcasthost" | b"ip6-localhost" | b"ip6-loopback" | b"0.0.0.0") {
            return Ok(None);
        }
        d
    } else {
        if toks.next().is_some() {
            return Err(());
        }
        first
    };
    let dom = dom.strip_prefix(b"*.").unwrap_or(dom);
    valid_domain(dom).map(|d| Some((d, false))).ok_or(())
}

fn trim(s: &[u8]) -> &[u8] {
    let a = s.iter().position(|c| !c.is_ascii_whitespace()).unwrap_or(s.len());
    let b = s.iter().rposition(|c| !c.is_ascii_whitespace()).map_or(a, |p| p + 1);
    &s[a..b]
}

/// A usable domain: ≥ 2 labels, LDH(+underscore), not an IP literal, ≤ 253.
fn valid_domain(d: &[u8]) -> Option<&[u8]> {
    let d = d.strip_suffix(b".").unwrap_or(d);
    if d.len() < 3 || d.len() > 253 || !d.contains(&b'.') || d.starts_with(b".") || d.ends_with(b".") || d.windows(2).any(|w| w == b"..") {
        return None;
    }
    if !d.iter().all(|&c| c.is_ascii_alphanumeric() || c == b'-' || c == b'.' || c == b'_') {
        return None;
    }
    if d.iter().all(|&c| c.is_ascii_digit() || c == b'.') {
        return None;
    }
    Some(d)
}

/// Directive `#! key=value` → policy.
fn directive(line: &[u8], p: &mut Policy) {
    let Some(rest) = trim(line).strip_prefix(b"#!") else { return };
    let rest = trim(rest);
    let Some(eq) = rest.iter().position(|&c| c == b'=') else { return };
    let (k, v) = (trim(&rest[..eq]), trim(&rest[eq + 1..]));
    match k {
        b"encrypted_dns" => p.encrypted_dns_block = v != b"allow",
        b"private_relay" => p.private_relay_block = v == b"block",
        _ => {}
    }
}

/// Streams list text (any chunking) into the tables. `allow_only` = ALLOW.TXT (every entry is an allow).
struct Builder {
    line: [u8; 300],
    ll: usize,
    overlong: bool,
    allow_only: bool,
    skipped: u32,
    truncated: u32,
    policy: Policy,
}

impl Builder {
    fn new(allow_only: bool, policy: Policy) -> Self {
        Builder { line: [0; 300], ll: 0, overlong: false, allow_only, skipped: 0, truncated: 0, policy }
    }
    fn end_line(&mut self) {
        if self.overlong {
            self.skipped += 1;
        } else if self.ll > 0 {
            let l = &self.line[..self.ll];
            if !self.allow_only && l.starts_with(b"#!") {
                directive(l, &mut self.policy);
            } else {
                match parse_line(l) {
                    Ok(Some((d, allow))) => {
                        let allow = allow || self.allow_only;
                        let h = fnv(d);
                        unsafe {
                            if allow {
                                if ALEN < ALLOW_CAP {
                                    (*core::ptr::addr_of_mut!(ALLOW))[ALEN] = h;
                                    ALEN += 1;
                                } else {
                                    self.truncated += 1;
                                }
                            } else if BLEN < BLOCK_CAP {
                                (*core::ptr::addr_of_mut!(BLOCK))[BLEN] = h;
                                BLEN += 1;
                            } else {
                                self.truncated += 1;
                            }
                        }
                    }
                    Ok(None) => {}
                    Err(()) => self.skipped += 1,
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
            } else if self.ll < self.line.len() {
                self.line[self.ll] = c;
                self.ll += 1;
            } else {
                self.overlong = true;
            }
        }
    }
    fn finish(mut self) -> (u32, u32, Policy) {
        self.end_line();
        (self.skipped, self.truncated, self.policy)
    }
}

fn sort_dedup(t: &mut [u64]) -> usize {
    t.sort_unstable();
    let mut w = 0usize;
    for r in 0..t.len() {
        if w == 0 || t[r] != t[w - 1] {
            t[w] = t[r];
            w += 1;
        }
    }
    w
}

fn seal_tables() {
    unsafe {
        BLEN = sort_dedup(&mut (&mut *core::ptr::addr_of_mut!(BLOCK))[..BLEN]);
        ALEN = sort_dedup(&mut (&mut *core::ptr::addr_of_mut!(ALLOW))[..ALEN]);
    }
}

fn reset_tables() {
    unsafe {
        BLEN = 0;
        ALEN = 0;
        POLICY = POLICY_DEFAULT;
    }
}

/// Load lists from memory (selftests). Returns (skipped, truncated).
pub fn load_text(block: &[u8], allow: &[u8]) -> (u32, u32) {
    reset_tables();
    let mut b = Builder::new(false, POLICY_DEFAULT);
    b.feed(block);
    let (s1, t1, p) = b.finish();
    let mut a = Builder::new(true, p);
    a.feed(allow);
    let (s2, t2, _) = a.finish();
    unsafe { POLICY = p };
    seal_tables();
    (s1 + s2, t1 + t2)
}

// ---- signatures (ADR 0049 D1 key) ------------------------------------------------------------------
// FILE.SIG (512 B): magic(8) | gen u64 | len u64 | sha256(file[..len]) | Ed25519(tag(6)|gen|len|sha256)

fn signed_message(tag: &[u8; 6], gen: u64, len: u64, digest: &[u8; 32]) -> [u8; 54] {
    let mut m = [0u8; 54];
    m[..6].copy_from_slice(tag);
    m[6..14].copy_from_slice(&gen.to_le_bytes());
    m[14..22].copy_from_slice(&len.to_le_bytes());
    m[22..].copy_from_slice(digest);
    m
}

fn check_sig(magic: &[u8; 8], tag: &[u8; 6], sig: &[u8], key: &[u8; 32], digest_of: &mut dyn FnMut(u64) -> Option<[u8; 32]>) -> Result<(u64, u64), LoadErr> {
    if sig.len() < 120 || &sig[..8] != magic {
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
    pk.verify(&signed_message(tag, gen, len, &d)[..], &s).map_err(|_| LoadErr::BadSignature)?;
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

/// Verify (when an operator key is compiled in) and stream one list file into a builder.
/// Ok(None) = no such file.
fn load_one<D: BlockDev>(dev: &D, p1: u64, txt: &[u8; 11], sig83: &[u8; 11], magic: &[u8; 8], tag: &[u8; 6], b: &mut Builder) -> Result<Option<(u64, bool)>, LoadErr> {
    let Some((lba, nsec)) = crate::fat::locate_contiguous(dev, p1, txt) else { return Ok(None) };
    let cap = nsec * 512;
    let (gen, len, signed) = match POLICY_PUBKEY {
        Some(key) => {
            let mut sig = [0u8; 512];
            if crate::fat::locate_contiguous(dev, p1, sig83).and_then(|(l, _)| dev.read_block(l, &mut sig).ok()).is_none() {
                return Err(LoadErr::SigMissing);
            }
            let mut digest_of = |len: u64| -> Option<[u8; 32]> {
                if len > cap {
                    return None;
                }
                let mut h = boot_abi::sha256::Hasher::new();
                stream(dev, lba, len, &mut |c| h.update(c))?;
                Some(h.finish())
            };
            let (g, l) = check_sig(magic, tag, &sig, &key, &mut digest_of)?;
            (g, l, true)
        }
        None => (0, cap.min(MAX_FILE), false),
    };
    stream(dev, lba, len, &mut |c| b.feed(c)).ok_or(LoadErr::Io)?;
    Ok(Some((gen, signed)))
}

/// Boot: BLOCK.TXT (+ directives) then ALLOW.TXT. A refused file is not loaded; the other still is.
pub fn load<D: BlockDev>(dev: &D) -> LoadInfo {
    reset_tables();
    let mut info = LoadInfo::default();
    let mut sec = [0u8; 512];
    let p1 = if dev.read_block(0, &mut sec).is_ok() { crate::store::parse_mbr(&sec)[0].start } else { 0 };
    if p1 != 0 {
        let mut b = Builder::new(false, POLICY_DEFAULT);
        let pol = match load_one(dev, p1, b"BLOCK   TXT", b"BLOCK   SIG", b"HQBSIG1\0", b"HQBLK1", &mut b) {
            Ok(Some((g, s))) => {
                info.block_file = 1;
                info.generation = g;
                info.signed = s;
                let (sk, tr, p) = b.finish();
                info.skipped_lines += sk;
                info.truncated += tr;
                p
            }
            Ok(None) => POLICY_DEFAULT,
            Err(e) => {
                info.block_file = 2;
                info.refused = Some(e);
                reset_tables();
                POLICY_DEFAULT
            }
        };
        let (bl, al) = unsafe { (BLEN, ALEN) };
        let mut a = Builder::new(true, pol);
        match load_one(dev, p1, b"ALLOW   TXT", b"ALLOW   SIG", b"HQASIG1\0", b"HQALW1", &mut a) {
            Ok(Some(_)) => {
                info.allow_file = 1;
                let (sk, tr, _) = a.finish();
                info.skipped_lines += sk;
                info.truncated += tr;
            }
            Ok(None) => {}
            Err(e) => {
                info.allow_file = 2;
                info.refused.get_or_insert(e);
                unsafe {
                    BLEN = bl;
                    ALEN = al;
                }
            }
        }
        unsafe { POLICY = pol };
    }
    seal_tables();
    unsafe { INFO = info };
    info
}

// ---------------------------------------------------------------------------------------------------
// Decisions

/// Always allowed (suffix match on a label boundary). Connectivity/captive-portal checks, time, revocation.
const FLOOR: &[&[u8]] = &[
    b"captive.apple.com", b"connectivitycheck.gstatic.com", b"connectivitycheck.android.com", b"clients3.google.com",
    b"clients1.google.com", b"msftconnecttest.com", b"msftncsi.com", b"detectportal.firefox.com", b"nmcheck.gnome.org",
    b"connectivity-check.ubuntu.com", b"network-test.debian.org", b"time.apple.com", b"time.windows.com",
    b"pool.ntp.org", b"time.google.com", b"ocsp.apple.com", b"ocsp2.apple.com", b"crl.apple.com", b"ocsp.digicert.com",
    b"crl3.digicert.com", b"ocsp.pki.goog", b"ocsp.sectigo.com", b"r3.o.lencr.org", b"x1.c.lencr.org",
    b"ocsp.globalsign.com", b"hookprobe.com",
];
const RELAY: &[&[u8]] = &[b"mask.icloud.com", b"mask-h2.icloud.com", b"mask-api.icloud.com"];
const DOH: &[&[u8]] = &[
    b"dns.google", b"dns.google.com", b"cloudflare-dns.com", b"one.one.one.one", b"dns.quad9.net", b"doh.opendns.com",
    b"dns.nextdns.io", b"dns.adguard-dns.com", b"dns.adguard.com", b"doh.cleanbrowsing.org", b"dns.mullvad.net",
    b"doh.dns.sb", b"dns.controld.com", b"doh.libredns.gr",
];

fn suffix_in(name: &[u8], list: &[&[u8]]) -> bool {
    list.iter().any(|&s| name == s || (name.len() > s.len() && name.ends_with(s) && name[name.len() - s.len() - 1] == b'.'))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Verdict {
    Allowed = 0,
    Floor = 1,
    AllowRule = 2,
    Blocked = 3,
    BlockedCname = 4,
    Ddr = 5,
    Canary = 6,
    RelaySeen = 7,
    RelayBlocked = 8,
    DohSeen = 9,
    DohBlocked = 10,
    DotRefused = 11,
    Tcp53Refused = 12,
}

impl Verdict {
    pub fn name(self) -> &'static str {
        ["allowed", "floor", "allow-rule", "blocked", "blocked-cname", "ddr", "canary", "relay-seen", "relay-blocked", "doh-seen", "doh-blocked", "dot-refused", "tcp53-refused"][self as usize]
    }
    /// Answered by the AP instead of forwarded.
    pub fn answered(self) -> bool {
        matches!(self, Verdict::Blocked | Verdict::Ddr | Verdict::Canary | Verdict::RelayBlocked | Verdict::DohBlocked)
    }
    fn bypass(self) -> bool {
        matches!(self, Verdict::Ddr | Verdict::Canary | Verdict::RelaySeen | Verdict::RelayBlocked | Verdict::DohSeen | Verdict::DohBlocked | Verdict::DotRefused)
    }
}

/// The decision for a normalised (lowercase, no trailing dot) name.
pub fn decide(name: &[u8]) -> Verdict {
    let name = name.strip_suffix(b".").unwrap_or(name);
    if name.is_empty() {
        return Verdict::Allowed;
    }
    if suffix_in(name, FLOOR) {
        return Verdict::Floor;
    }
    if name == b"resolver.arpa" || name.ends_with(b".resolver.arpa") {
        return Verdict::Ddr;
    }
    if name == b"use-application-dns.net" {
        return Verdict::Canary;
    }
    let p = policy();
    if suffix_in(name, RELAY) {
        return if p.private_relay_block { Verdict::RelayBlocked } else { Verdict::RelaySeen };
    }
    if suffix_in(name, DOH) {
        return if p.encrypted_dns_block { Verdict::DohBlocked } else { Verdict::DohSeen };
    }
    // longest match between ALLOW and BLOCK (ties -> allow); a bare TLD never matches
    let (bt, at) = (block_table(), allow_table());
    if bt.is_empty() && at.is_empty() {
        return Verdict::Allowed;
    }
    let mut start = 0usize;
    loop {
        let suf = &name[start..];
        if !suf.contains(&b'.') {
            return Verdict::Allowed;
        }
        let h = fnv(suf);
        if at.binary_search(&h).is_ok() {
            return Verdict::AllowRule;
        }
        if bt.binary_search(&h).is_ok() {
            return Verdict::Blocked;
        }
        match suf.iter().position(|&c| c == b'.') {
            Some(p) => start += p + 1,
            None => return Verdict::Allowed,
        }
    }
}

// ---------------------------------------------------------------------------------------------------
// DNS wire helpers

/// A decoded name (lowercase dotted, no trailing dot). Compression-aware for responses; `allow_ptr` false
/// for questions in queries (a pointer there is malformed).
fn read_name(msg: &[u8], mut o: usize, out: &mut [u8; 256], allow_ptr: bool) -> Option<(usize, usize)> {
    let mut w = 0usize;
    let mut end: Option<usize> = None;
    let mut jumps = 0;
    loop {
        let len = *msg.get(o)? as usize;
        if len & 0xC0 == 0xC0 {
            if !allow_ptr || jumps >= 16 {
                return None;
            }
            let p = ((len & 0x3F) << 8) | *msg.get(o + 1)? as usize;
            if end.is_none() {
                end = Some(o + 2);
            }
            if p >= o {
                return None; // pointers only go backwards (no loops)
            }
            o = p;
            jumps += 1;
            continue;
        }
        if len & 0xC0 != 0 {
            return None;
        }
        if len == 0 {
            return Some((w, end.unwrap_or(o + 1)));
        }
        let lab = msg.get(o + 1..o + 1 + len)?;
        if w != 0 {
            *out.get_mut(w)? = b'.';
            w += 1;
        }
        if w + len > 253 {
            return None;
        }
        for (i, &c) in lab.iter().enumerate() {
            out[w + i] = c.to_ascii_lowercase();
        }
        w += len;
        o += 1 + len;
    }
}

/// A parsed client query: the DNS message slice bounds + question facts.
struct Q {
    name: [u8; 256],
    nl: usize,
    qtype: u16,
    qend: usize, // end of the question inside the DNS message
    edns: bool,
}

fn parse_query(dns: &[u8]) -> Option<Q> {
    if dns.len() < 12 + 5 || dns[2] & 0xf8 != 0 || u16::from_be_bytes([dns[4], dns[5]]) != 1 {
        return None; // not a standard query with one question
    }
    let mut name = [0u8; 256];
    let (nl, o) = read_name(dns, 12, &mut name, false)?;
    let qend = o + 4;
    if qend > dns.len() {
        return None;
    }
    let qtype = u16::from_be_bytes([dns[o], dns[o + 1]]);
    // EDNS: ARCOUNT ≥ 1 and the first additional RR is a root-named OPT (type 41)
    let edns = u16::from_be_bytes([dns[10], dns[11]]) >= 1 && dns.get(qend) == Some(&0) && dns.get(qend + 1..qend + 3) == Some(&[0, 41]);
    Some(Q { name, nl, qtype, qend, edns })
}

fn csum(b: &[u8], init: u32) -> u16 {
    let mut s = init;
    let mut i = 0;
    while i + 1 < b.len() {
        s += u16::from_be_bytes([b[i], b[i + 1]]) as u32;
        i += 2;
    }
    if i < b.len() {
        s += (b[i] as u32) << 8;
    }
    while s >> 16 != 0 {
        s = (s & 0xffff) + (s >> 16);
    }
    !(s as u16)
}

/// Recompute the IPv4 header checksum and the UDP checksum of an Ethernet/IPv4(no options)/UDP frame.
fn fix_udp4(f: &mut [u8], udp_len: usize) {
    f[24] = 0;
    f[25] = 0;
    let c = csum(&f[14..34], 0);
    f[24..26].copy_from_slice(&c.to_be_bytes());
    f[40] = 0;
    f[41] = 0;
    let mut ps = 17u32 + udp_len as u32;
    for k in (26..34).step_by(2) {
        ps += u16::from_be_bytes([f[k], f[k + 1]]) as u32;
    }
    let mut uc = csum(&f[34..34 + udp_len], ps);
    if uc == 0 {
        uc = 0xffff;
    }
    f[40..42].copy_from_slice(&uc.to_be_bytes());
}

/// Build the AP's own answer to a client query frame: NXDOMAIN (+EDE 15 when the query used EDNS) or
/// NODATA (`nodata`). Sent back as if from the resolver the client asked.
fn answer_frame(f: &[u8], u: usize, dns: &[u8], q: &Q, nodata: bool, me: &[u8; 6], out: &mut [u8]) -> Option<usize> {
    let opt = if q.edns && !nodata { 11 + 6 } else if q.edns { 11 } else { 0 };
    let dlen = q.qend + opt;
    let total = 42 + dlen;
    if total > out.len() {
        return None;
    }
    out[0..6].copy_from_slice(&f[6..12]);
    out[6..12].copy_from_slice(me);
    out[12..14].copy_from_slice(&[0x08, 0x00]);
    out[14..34].copy_from_slice(&[0x45, 0, 0, 0, 0, 0, 0x40, 0, 64, 17, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    out[16..18].copy_from_slice(&((20 + 8 + dlen) as u16).to_be_bytes());
    out[26..30].copy_from_slice(&f[30..34]);
    out[30..34].copy_from_slice(&f[26..30]);
    out[34..36].copy_from_slice(&f[u + 2..u + 4]);
    out[36..38].copy_from_slice(&f[u..u + 2]);
    out[38..40].copy_from_slice(&((8 + dlen) as u16).to_be_bytes());
    let d = &mut out[42..42 + dlen];
    d[..q.qend].copy_from_slice(&dns[..q.qend]);
    d[2] = 0x80 | (dns[2] & 0x01); // QR, RD echoed
    d[3] = 0x80 | if nodata { 0 } else { 3 }; // RA | RCODE
    d[6..8].copy_from_slice(&[0, 0]); // ANCOUNT
    d[8..10].copy_from_slice(&[0, 0]); // NSCOUNT (no SOA: nothing negatively cached)
    d[10..12].copy_from_slice(&((opt > 0) as u16).to_be_bytes());
    if opt > 0 {
        let o = q.qend;
        d[o] = 0;
        d[o + 1..o + 3].copy_from_slice(&41u16.to_be_bytes());
        d[o + 3..o + 5].copy_from_slice(&1232u16.to_be_bytes());
        d[o + 5..o + 9].copy_from_slice(&[0, 0, 0, 0]);
        d[o + 9..o + 11].copy_from_slice(&((opt - 11) as u16).to_be_bytes());
        if opt > 11 {
            // EDE (RFC 8914): option 15, length 2, INFO-CODE 15 "Blocked"
            d[o + 11..o + 17].copy_from_slice(&[0, 15, 0, 2, 0, 15]);
        }
    }
    fix_udp4(out, 8 + dlen);
    Some(total)
}

// ---------------------------------------------------------------------------------------------------
// Frame entry points

pub enum Act {
    /// Forward as usual.
    Pass,
    /// Send `out[..n]` back to the client; do not forward.
    Answer(usize),
    /// Refuse (TCP RST / ICMP) via the caller's reject builder; do not forward.
    Reject,
}

/// A client frame on its way out (Ethernet/IPv4). `now` = cntpct ticks.
pub fn on_client_frame(f: &[u8], me: &[u8; 6], out: &mut [u8], now: u64) -> Act {
    if f.len() < 14 + 20 + 8 || f[12..14] != [0x08, 0x00] || f[14] >> 4 != 4 {
        return Act::Pass;
    }
    let ihl = ((f[14] & 0x0f) as usize) * 4;
    let tot = u16::from_be_bytes([f[16], f[17]]) as usize;
    if ihl < 20 || tot < ihl + 8 || 14 + tot > f.len() || u16::from_be_bytes([f[20], f[21]]) & 0x1fff != 0 {
        return Act::Pass; // malformed or a non-first fragment: not ours to judge
    }
    let u = 14 + ihl;
    let client = u32::from_be_bytes([f[26], f[27], f[28], f[29]]);
    let dport = u16::from_be_bytes([f[u + 2], f[u + 3]]);
    match (f[23], dport) {
        (17, 53) => {
            let ulen = u16::from_be_bytes([f[u + 4], f[u + 5]]) as usize;
            if ulen < 8 + 12 || u + ulen > 14 + tot {
                stat_unparsable();
                return Act::Pass;
            }
            let dns = &f[u + 8..u + ulen];
            let Some(q) = parse_query(dns) else {
                stat_unparsable();
                return Act::Pass;
            };
            let v = decide(&q.name[..q.nl]);
            record(now, client, q.qtype, &q.name[..q.nl], v);
            // Parity G8: DGA / lookalike / tunnel scoring on names Shield let through — detection only.
            if v == Verdict::Allowed && crate::dga::score(&q.name[..q.nl]) >= crate::dga::DGA_THRESHOLD {
                st().dga += 1;
                let _ = crate::rules::shield_dga_verdict(client);
            }
            if v.answered() {
                if let Some(n) = answer_frame(f, u, dns, &q, v == Verdict::Ddr, me, out) {
                    return Act::Answer(n);
                }
            }
            Act::Pass
        }
        (6, 853) => {
            if !policy().encrypted_dns_block {
                if f[u + 13] & 0x12 == 0x02 {
                    record(now, client, 0, b"(DoT tcp/853)", Verdict::DohSeen);
                }
                return Act::Pass;
            }
            if f[u + 13] & 0x12 == 0x02 {
                record(now, client, 0, b"(DoT tcp/853)", Verdict::DotRefused);
            }
            Act::Reject
        }
        (6, 53) => {
            // DNS over TCP: the first data segment carries len(2) + query
            let doff = ((f[u + 12] >> 4) as usize) * 4;
            let p = u + doff;
            if doff < 20 || p + 2 + 17 > 14 + tot {
                return Act::Pass;
            }
            let dl = u16::from_be_bytes([f[p], f[p + 1]]) as usize;
            let dns = &f[p + 2..(p + 2 + dl).min(14 + tot)];
            let Some(q) = parse_query(dns) else { return Act::Pass };
            let v = decide(&q.name[..q.nl]);
            if v.answered() {
                record(now, client, q.qtype, &q.name[..q.nl], Verdict::Tcp53Refused);
                return Act::Reject;
            }
            record(now, client, q.qtype, &q.name[..q.nl], v);
            Act::Pass
        }
        _ => Act::Pass,
    }
}

/// A DNS reply on its way back to a client (`buf[..len]`, Ethernet/IPv4/UDP src 53, already un-NATed).
/// If its answer chain CNAMEs into a blocked name (and the queried name itself is not allowed by a rule
/// or the floor), it is rewritten in place to NXDOMAIN. Returns the (possibly shorter) frame length.
pub fn on_reply_frame(buf: &mut [u8], len: usize, now: u64) -> usize {
    let f = &buf[..len.min(buf.len())];
    if f.len() < 42 + 12 || f[12..14] != [0x08, 0x00] || f[14] != 0x45 || f[23] != 17 {
        return len;
    }
    let tot = u16::from_be_bytes([f[16], f[17]]) as usize;
    if 14 + tot > f.len() || u16::from_be_bytes([f[34], f[35]]) != 53 {
        return len;
    }
    let ulen = u16::from_be_bytes([f[38], f[39]]) as usize;
    if ulen < 8 + 12 || 34 + ulen > 14 + tot {
        return len;
    }
    let dns = &f[42..34 + ulen];
    if dns[2] & 0x80 == 0 || dns[3] & 0x0f != 0 || u16::from_be_bytes([dns[4], dns[5]]) != 1 {
        return len; // not a successful response with one question
    }
    let an = u16::from_be_bytes([dns[6], dns[7]]) as usize;
    if an == 0 || block_table().is_empty() {
        return len;
    }
    let mut qn = [0u8; 256];
    let Some((qnl, o)) = read_name(dns, 12, &mut qn, true) else { return len };
    let qend = o + 4;
    if qend > dns.len() {
        return len;
    }
    let qv = decide(&qn[..qnl]);
    if matches!(qv, Verdict::Floor | Verdict::AllowRule) {
        return len;
    }
    let mut p = qend;
    let mut hit = false;
    for _ in 0..an.min(32) {
        let mut nm = [0u8; 256];
        let Some((_, e)) = read_name(dns, p, &mut nm, true) else { return len };
        let Some(h) = dns.get(e..e + 10) else { return len };
        let (ty, rdl) = (u16::from_be_bytes([h[0], h[1]]), u16::from_be_bytes([h[8], h[9]]) as usize);
        let rd = e + 10;
        if rd + rdl > dns.len() {
            return len;
        }
        if ty == 5 {
            let mut tgt = [0u8; 256];
            if let Some((tl, _)) = read_name(dns, rd, &mut tgt, true) {
                if decide(&tgt[..tl]) == Verdict::Blocked {
                    hit = true;
                    break;
                }
            }
        }
        p = rd + rdl;
    }
    if !hit {
        return len;
    }
    let client = u32::from_be_bytes([f[30], f[31], f[32], f[33]]);
    let qtype = u16::from_be_bytes([dns[qend - 4], dns[qend - 3]]);
    record(now, client, qtype, &qn[..qnl], Verdict::BlockedCname);
    // rewrite: header flags RCODE=3, counts 0/0/0, truncate after the question
    let d = &mut buf[42..];
    d[3] = (d[3] & 0xf0) | 3;
    d[6..12].copy_from_slice(&[0, 0, 0, 0, 0, 0]);
    let nul = 8 + qend;
    buf[16..18].copy_from_slice(&((20 + nul) as u16).to_be_bytes());
    buf[38..40].copy_from_slice(&(nul as u16).to_be_bytes());
    fix_udp4(buf, nul);
    34 + nul
}

// ---------------------------------------------------------------------------------------------------
// Visibility (ADR 0052 D7)

const NC: usize = 14;
const C_UNPARSABLE: usize = 13;
const RING: usize = 256;
const TOPK: usize = 32;
const CLIENTS: usize = 64;
const NAME_MAX: usize = 64;

#[derive(Clone, Copy)]
struct Ent {
    t: u64,
    client: u32,
    qtype: u16,
    v: u8,
    nl: u8,
    name: [u8; NAME_MAX],
}
const ENT0: Ent = Ent { t: 0, client: 0, qtype: 0, v: 0, nl: 0, name: [0; NAME_MAX] };

#[derive(Clone, Copy)]
struct Top {
    h: u64,
    count: u32,
    err: u32,
    nl: u8,
    name: [u8; NAME_MAX],
}
const TOP0: Top = Top { h: 0, count: 0, err: 0, nl: 0, name: [0; NAME_MAX] };

#[derive(Clone, Copy)]
struct Cli {
    ip: u32,
    queries: u32,
    blocked: u32,
    bypass: u32,
    last_bypass: u8,
}
const CLI0: Cli = Cli { ip: 0, queries: 0, blocked: 0, bypass: 0, last_bypass: 0 };

struct Stats {
    c: [u64; NC],
    ring: [Ent; RING],
    rhead: usize,
    rlen: usize,
    top: [Top; TOPK],
    ntop: usize,
    cli: [Cli; CLIENTS],
    ncli: usize,
    last_blocked: Ent,
    dga: u64,
}
static mut ST: Stats = Stats { c: [0; NC], ring: [ENT0; RING], rhead: 0, rlen: 0, top: [TOP0; TOPK], ntop: 0, cli: [CLI0; CLIENTS], ncli: 0, last_blocked: ENT0, dga: 0 };

fn st() -> &'static mut Stats {
    unsafe { &mut *core::ptr::addr_of_mut!(ST) }
}

fn stat_unparsable() {
    st().c[C_UNPARSABLE] += 1;
}

pub fn reset_stats() {
    let s = st();
    s.c = [0; NC];
    s.rhead = 0;
    s.rlen = 0;
    s.ntop = 0;
    s.ncli = 0;
    s.last_blocked = ENT0;
    s.dga = 0;
}

fn record(t: u64, client: u32, qtype: u16, name: &[u8], v: Verdict) {
    let s = st();
    s.c[v as usize] += 1;
    let nl = name.len().min(NAME_MAX);
    let mut e = Ent { t, client, qtype, v: v as u8, nl: nl as u8, name: [0; NAME_MAX] };
    e.name[..nl].copy_from_slice(&name[..nl]);
    s.ring[(s.rhead + s.rlen) % RING] = e;
    if s.rlen < RING {
        s.rlen += 1;
    } else {
        s.rhead = (s.rhead + 1) % RING;
    }
    let blocked = matches!(v, Verdict::Blocked | Verdict::BlockedCname | Verdict::Tcp53Refused);
    if blocked {
        s.last_blocked = e;
        // space-saving top-K
        let h = fnv(name);
        if let Some(t) = s.top[..s.ntop].iter_mut().find(|t| t.h == h) {
            t.count += 1;
        } else if s.ntop < TOPK {
            s.top[s.ntop] = Top { h, count: 1, err: 0, nl: nl as u8, name: e.name };
            s.ntop += 1;
        } else {
            let m = (0..TOPK).min_by_key(|&i| s.top[i].count).unwrap_or(0);
            let base = s.top[m].count;
            s.top[m] = Top { h, count: base + 1, err: base, nl: nl as u8, name: e.name };
        }
    }
    // per client
    let i = match s.cli[..s.ncli].iter().position(|c| c.ip == client) {
        Some(i) => i,
        None if s.ncli < CLIENTS => {
            s.cli[s.ncli] = Cli { ip: client, ..CLI0 };
            s.ncli += 1;
            s.ncli - 1
        }
        None => {
            let m = (0..CLIENTS).min_by_key(|&i| s.cli[i].queries).unwrap_or(0);
            s.cli[m] = Cli { ip: client, ..CLI0 };
            m
        }
    };
    let c = &mut s.cli[i];
    c.queries += 1;
    if blocked {
        c.blocked += 1;
    }
    if v.bypass() {
        c.bypass += 1;
        c.last_bypass = v as u8;
    }
}

/// Totals for the Shield tile: (queries, blocked incl. CNAME/TCP, bypass signals).
pub fn totals() -> (u64, u64, u64) {
    let c = &st().c;
    let q: u64 = c[..C_UNPARSABLE].iter().sum();
    let b = c[Verdict::Blocked as usize] + c[Verdict::BlockedCname as usize] + c[Verdict::Tcp53Refused as usize];
    let by = c[Verdict::Ddr as usize] + c[Verdict::Canary as usize] + c[Verdict::RelaySeen as usize] + c[Verdict::RelayBlocked as usize]
        + c[Verdict::DohSeen as usize] + c[Verdict::DohBlocked as usize] + c[Verdict::DotRefused as usize];
    (q, b, by)
}

/// The last blocked name and its client (heartbeat).
pub fn last_blocked(out: &mut [u8; NAME_MAX]) -> (usize, u32) {
    let e = st().last_blocked;
    out[..e.nl as usize].copy_from_slice(&e.name[..e.nl as usize]);
    (e.nl as usize, e.client)
}

/// Queries Shield let through that scored as DGA / lookalike / tunnel (detections raised).
pub fn dga_hits() -> u64 {
    st().dga
}

pub fn counter(v: Verdict) -> u64 {
    st().c[v as usize]
}

#[cfg(feature = "netsvc")]
fn ip4(w: &mut JsonBuf, ip: u32) {
    let _ = write!(w, "\"{}.{}.{}.{}\"", ip >> 24, (ip >> 16) & 0xff, (ip >> 8) & 0xff, ip & 0xff);
}

/// `GET /api/dns`. `epoch` converts cntpct ticks to epoch ms.
#[cfg(feature = "netsvc")]
pub fn render(out: &mut JsonBuf, epoch: &dyn Fn(u64) -> u64, recent: usize) {
    let s = st();
    let i = info();
    let p = policy();
    let _ = write!(out, "{{\"lists\":{{\"blocked_domains\":{},\"allowed_domains\":{},\"block_file\":\"{}\",\"allow_file\":\"{}\",\"signed\":{},\"generation\":{},\"skipped_lines\":{},\"truncated\":{},\"refused\":",
        block_len(), allow_len(), ["none", "loaded", "refused"][i.block_file as usize % 3], ["none", "loaded", "refused"][i.allow_file as usize % 3],
        i.signed, i.generation, i.skipped_lines, i.truncated);
    match i.refused {
        Some(e) => {
            let _ = write!(out, "\"{:?}\"", e);
        }
        None => out.raw("null"),
    }
    let _ = write!(out, "}},\"policy\":{{\"encrypted_dns\":\"{}\",\"private_relay\":\"{}\"}},\"counters\":{{",
        if p.encrypted_dns_block { "block" } else { "allow" }, if p.private_relay_block { "block" } else { "report" });
    for k in 0..NC {
        let name = if k == C_UNPARSABLE { "unparsable" } else { [Verdict::Allowed, Verdict::Floor, Verdict::AllowRule, Verdict::Blocked, Verdict::BlockedCname, Verdict::Ddr, Verdict::Canary, Verdict::RelaySeen, Verdict::RelayBlocked, Verdict::DohSeen, Verdict::DohBlocked, Verdict::DotRefused, Verdict::Tcp53Refused][k].name() };
        let _ = write!(out, "{}\"{}\":{}", if k > 0 { "," } else { "" }, name, s.c[k]);
    }
    out.raw("},\"top_blocked\":[");
    let mut idx = [0usize; TOPK];
    for k in 0..s.ntop {
        idx[k] = k;
    }
    idx[..s.ntop].sort_unstable_by(|&a, &b| s.top[b].count.cmp(&s.top[a].count));
    for (n, &k) in idx[..s.ntop].iter().enumerate() {
        let t = &s.top[k];
        out.raw(if n > 0 { ",{\"name\":" } else { "{\"name\":" });
        out.string(core::str::from_utf8(&t.name[..t.nl as usize]).unwrap_or("?"));
        let _ = write!(out, ",\"count\":{},\"max_overcount\":{}}}", t.count, t.err);
    }
    out.raw("],\"clients\":[");
    for (n, c) in s.cli[..s.ncli].iter().enumerate() {
        out.raw(if n > 0 { ",{\"ip\":" } else { "{\"ip\":" });
        ip4(out, c.ip);
        let _ = write!(out, ",\"queries\":{},\"blocked\":{},\"bypass\":{}", c.queries, c.blocked, c.bypass);
        if c.bypass > 0 {
            let _ = write!(out, ",\"last_bypass\":\"{}\"", [Verdict::Allowed, Verdict::Floor, Verdict::AllowRule, Verdict::Blocked, Verdict::BlockedCname, Verdict::Ddr, Verdict::Canary, Verdict::RelaySeen, Verdict::RelayBlocked, Verdict::DohSeen, Verdict::DohBlocked, Verdict::DotRefused, Verdict::Tcp53Refused][c.last_bypass as usize % 13].name());
        }
        out.raw("}");
    }
    out.raw("],\"recent\":[");
    let n = recent.min(s.rlen);
    let mut k = 0usize;
    for j in 0..n {
        let e = &s.ring[(s.rhead + s.rlen - 1 - j) % RING];
        let m = out.mark();
        out.raw(if k > 0 { ",{\"ts\":" } else { "{\"ts\":" });
        let ms = epoch(e.t);
        let _ = write!(out, "{}.{:03},\"client\":", ms / 1000, ms % 1000);
        ip4(out, e.client);
        let _ = write!(out, ",\"qtype\":{},\"name\":", e.qtype);
        out.string(core::str::from_utf8(&e.name[..e.nl as usize]).unwrap_or("?"));
        let vn = [Verdict::Allowed, Verdict::Floor, Verdict::AllowRule, Verdict::Blocked, Verdict::BlockedCname, Verdict::Ddr, Verdict::Canary, Verdict::RelaySeen, Verdict::RelayBlocked, Verdict::DohSeen, Verdict::DohBlocked, Verdict::DotRefused, Verdict::Tcp53Refused][e.v as usize % 13].name();
        let _ = write!(out, ",\"verdict\":\"{}\"}}", vn);
        if out.overflow || out.len + 48 > out.capacity() {
            out.rewind(m);
            break;
        }
        k += 1;
    }
    let _ = write!(out, "],\"recent_count\":{},\"dga_suspects\":{}}}", k, s.dga);
}

// ---------------------------------------------------------------------------------------------------
// [P-shield]

/// Test helper: an Ethernet/IPv4/UDP query client 10.99.0.10:5353 -> `dst`:53.
pub fn test_query(name: &[u8], qtype: u16, edns: bool, dst: [u8; 4], out: &mut [u8]) -> usize {
    let mut d = [0u8; 320];
    d[0..2].copy_from_slice(&0x1234u16.to_be_bytes());
    d[2] = 0x01;
    d[5] = 1;
    d[11] = edns as u8;
    let mut o = 12;
    for label in name.split(|&c| c == b'.') {
        d[o] = label.len() as u8;
        d[o + 1..o + 1 + label.len()].copy_from_slice(label);
        o += 1 + label.len();
    }
    d[o] = 0;
    o += 1;
    d[o..o + 4].copy_from_slice(&[(qtype >> 8) as u8, qtype as u8, 0, 1]);
    o += 4;
    if edns {
        d[o..o + 11].copy_from_slice(&[0, 0, 41, 0x04, 0xd0, 0, 0, 0, 0, 0, 0]);
        o += 11;
    }
    let total = 42 + o;
    out[..14].copy_from_slice(&[2, 0, 0, 0, 0, 1, 0xaa, 0xbb, 0xcc, 0, 0, 0x10, 0x08, 0x00]);
    out[14..34].copy_from_slice(&[0x45, 0, 0, 0, 0, 1, 0x40, 0, 64, 17, 0, 0, 10, 99, 0, 10, 0, 0, 0, 0]);
    out[30..34].copy_from_slice(&dst);
    out[16..18].copy_from_slice(&((20 + 8 + o) as u16).to_be_bytes());
    out[34..36].copy_from_slice(&5353u16.to_be_bytes());
    out[36..38].copy_from_slice(&53u16.to_be_bytes());
    out[38..40].copy_from_slice(&((8 + o) as u16).to_be_bytes());
    out[42..total].copy_from_slice(&d[..o]);
    fix_udp4(out, 8 + o);
    total
}

fn frame_ok(r: &[u8]) -> bool {
    if r.len() < 54 {
        return false;
    }
    let ulen = u16::from_be_bytes([r[38], r[39]]) as usize;
    let mut ps = 17u32 + ulen as u32;
    for k in (26..34).step_by(2) {
        ps += u16::from_be_bytes([r[k], r[k + 1]]) as u32;
    }
    csum(&r[14..34], 0) == 0 && 34 + ulen == r.len() && csum(&r[34..34 + ulen], ps) == 0
}

/// A reply frame from `src`:53 to the client carrying `qname` CNAME -> `target` (+ an A record).
fn test_cname_reply(qname: &[u8], target: &[u8], out: &mut [u8]) -> usize {
    let mut d = [0u8; 400];
    d[0..2].copy_from_slice(&0x1234u16.to_be_bytes());
    d[2] = 0x81;
    d[3] = 0x80;
    d[5] = 1;
    d[7] = 2;
    let mut o = 12;
    for label in qname.split(|&c| c == b'.') {
        d[o] = label.len() as u8;
        d[o + 1..o + 1 + label.len()].copy_from_slice(label);
        o += 1 + label.len();
    }
    d[o] = 0;
    o += 1;
    d[o..o + 4].copy_from_slice(&[0, 1, 0, 1]);
    o += 4;
    // CNAME RR: name = ptr to question
    let rdl_at;
    d[o..o + 12].copy_from_slice(&[0xC0, 0x0C, 0, 5, 0, 1, 0, 0, 0, 60, 0, 0]);
    rdl_at = o + 10;
    o += 12;
    let tstart = o;
    for label in target.split(|&c| c == b'.') {
        d[o] = label.len() as u8;
        d[o + 1..o + 1 + label.len()].copy_from_slice(label);
        o += 1 + label.len();
    }
    d[o] = 0;
    o += 1;
    let tl = (o - tstart) as u16;
    d[rdl_at..rdl_at + 2].copy_from_slice(&tl.to_be_bytes());
    // A RR for the target (ptr to target)
    d[o..o + 16].copy_from_slice(&[0xC0, tstart as u8, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 93, 184, 216, 34]);
    o += 16;
    let total = 42 + o;
    out[..14].copy_from_slice(&[0xaa, 0xbb, 0xcc, 0, 0, 0x10, 2, 0, 0, 0, 0, 1, 0x08, 0x00]);
    out[14..34].copy_from_slice(&[0x45, 0, 0, 0, 0, 1, 0x40, 0, 60, 17, 0, 0, 1, 1, 1, 1, 10, 99, 0, 10]);
    out[16..18].copy_from_slice(&((20 + 8 + o) as u16).to_be_bytes());
    out[34..36].copy_from_slice(&53u16.to_be_bytes());
    out[36..38].copy_from_slice(&5353u16.to_be_bytes());
    out[38..40].copy_from_slice(&((8 + o) as u16).to_be_bytes());
    out[42..total].copy_from_slice(&d[..o]);
    fix_udp4(out, 8 + o);
    total
}

pub fn selftest() -> bool {
    use ed25519_compact::{KeyPair, Seed};
    let block = b"# Shield test list\n#! private_relay=block\n0.0.0.0 Ads.Tracker.example\n127.0.0.1 localhost\n||metrics.vendor.example^\n||opt.example^$third-party\n@@||good.ads.example^\nexample.org.\n*.wild.example\nads.example\ncom\n1.2.3.4\nbad/entry.example\nsome junk line here\ntracker.cdn.example\n";
    let allow = b"# allow\nexample.net\nads.example.net\n";
    let (skipped, _) = load_text(block, allow);
    let parse_ok = block_len() == 6 && allow_len() == 3 && skipped == 5 && policy().private_relay_block;
    // precedence
    use Verdict::*;
    let prec = decide(b"ads.tracker.example") == Blocked
        && decide(b"x.y.ADS.Tracker.Example.") == Blocked
        && decide(b"metrics.vendor.example") == Blocked
        && decide(b"opt.example") == Allowed // $option line skipped
        && decide(b"good.ads.example") == AllowRule // more specific allow beats ads.example
        && decide(b"other.ads.example") == Blocked
        && decide(b"z.wild.example") == Blocked
        && decide(b"example.org") == Blocked
        && decide(b"notads.example") == Allowed
        && decide(b"com") == Allowed
        && decide(b"captive.apple.com") == Floor
        && decide(b"x.pool.ntp.org") == Floor
        && decide(b"_dns.resolver.arpa") == Ddr
        && decide(b"use-application-dns.net") == Canary
        && decide(b"mask.icloud.com") == RelayBlocked
        && decide(b"dns.google") == DohBlocked
        && decide(b"example.net") == AllowRule;
    // answers
    reset_stats();
    let me = [2u8, 0, 0, 0, 0, 1];
    let mut q = [0u8; 400];
    let mut out = [0u8; 600];
    let n = test_query(b"ads.tracker.example", 1, true, [8, 8, 8, 8], &mut q);
    let nx_ede = match on_client_frame(&q[..n], &me, &mut out, 1) {
        Act::Answer(k) => frame_ok(&out[..k]) && out[26..30] == [8, 8, 8, 8] && out[30..34] == [10, 99, 0, 10]
            && out[45] & 0x0f == 3 && out[48..50] == [0, 0] && out[52..54] == [0, 1] && out[k - 6..k] == [0, 15, 0, 2, 0, 15],
        _ => false,
    };
    let n = test_query(b"ads.tracker.example", 65, false, [10, 99, 0, 1], &mut q);
    let nx_https = matches!(on_client_frame(&q[..n], &me, &mut out, 2), Act::Answer(k) if frame_ok(&out[..k]) && out[45] & 0x0f == 3 && out[52..54] == [0, 0]);
    let n = test_query(b"_dns.resolver.arpa", 64, false, [1, 1, 1, 1], &mut q);
    let ddr = matches!(on_client_frame(&q[..n], &me, &mut out, 3), Act::Answer(k) if frame_ok(&out[..k]) && out[45] & 0x0f == 0 && out[48..50] == [0, 0]);
    let n = test_query(b"use-application-dns.net", 1, false, [10, 99, 0, 1], &mut q);
    let canary = matches!(on_client_frame(&q[..n], &me, &mut out, 4), Act::Answer(k) if out[45] & 0x0f == 3 && frame_ok(&out[..k]));
    let n = test_query(b"example.com", 1, true, [10, 99, 0, 1], &mut q);
    let pass = matches!(on_client_frame(&q[..n], &me, &mut out, 5), Act::Pass);
    let n = test_query(b"captive.apple.com", 1, false, [10, 99, 0, 1], &mut q);
    let floor = matches!(on_client_frame(&q[..n], &me, &mut out, 6), Act::Pass);
    let trunc = (0..n).all(|l| !matches!(on_client_frame(&q[..l], &me, &mut out, 7), Act::Answer(_)));
    // DoT + TCP/53
    let mut t = [0u8; 120];
    t[..14].copy_from_slice(&[2, 0, 0, 0, 0, 1, 0xaa, 0xbb, 0xcc, 0, 0, 0x10, 0x08, 0x00]);
    t[14..34].copy_from_slice(&[0x45, 0, 0, 40, 0, 1, 0x40, 0, 64, 6, 0, 0, 10, 99, 0, 10, 1, 1, 1, 1]);
    t[34..36].copy_from_slice(&40000u16.to_be_bytes());
    t[36..38].copy_from_slice(&853u16.to_be_bytes());
    t[46] = 0x50;
    t[47] = 0x02; // SYN
    let dot = matches!(on_client_frame(&t[..54], &me, &mut out, 8), Act::Reject);
    let mut tq = [0u8; 200];
    let qn = test_query(b"metrics.vendor.example", 1, false, [1, 1, 1, 1], &mut q);
    let dl = qn - 42;
    tq[..54].copy_from_slice(&t[..54]);
    tq[36..38].copy_from_slice(&53u16.to_be_bytes());
    tq[47] = 0x18; // PSH|ACK
    tq[54..56].copy_from_slice(&(dl as u16).to_be_bytes());
    tq[56..56 + dl].copy_from_slice(&q[42..qn]);
    tq[16..18].copy_from_slice(&((20 + 20 + 2 + dl) as u16).to_be_bytes());
    let tcp53 = matches!(on_client_frame(&tq[..56 + dl], &me, &mut out, 9), Act::Reject);
    // CNAME cloaking
    let mut r = [0u8; 600];
    let rn = test_cname_reply(b"shop.example.com", b"tracker.cdn.example", &mut r);
    let nl = on_reply_frame(&mut r, rn, 10);
    let cname = nl < rn && frame_ok(&r[..nl]) && r[45] & 0x0f == 3 && r[48..54] == [0, 0, 0, 0, 0, 0];
    let rn2 = test_cname_reply(b"shop.example.com", b"cdn.good.example", &mut r);
    let cname_clean = on_reply_frame(&mut r, rn2, 11) == rn2;
    // stats: top-K (space-saving), per-client, ring
    reset_stats();
    for i in 0..40u32 {
        let nm: &[u8] = if i % 4 == 0 { b"metrics.vendor.example" } else { b"ads.tracker.example" };
        record(i as u64, 0x0A63_000A, 1, nm, Blocked);
    }
    for i in 0..40u8 {
        let mut nm = *b"zz00.ads.example";
        nm[2] = b'a' + i / 10;
        nm[3] = b'0' + i % 10;
        record(100, 0x0A63_000B, 1, &nm, Blocked);
    }
    let s = st();
    let top = s.top[..s.ntop].iter().find(|t| &t.name[..t.nl as usize] == b"ads.tracker.example").map_or(0, |t| t.count) >= 30
        && s.ntop == TOPK;
    let cli = s.ncli == 2 && s.cli[0].blocked == 40 && s.cli[1].blocked == 40;
    let ring = s.rlen == 80;
    #[cfg(feature = "netsvc")]
    let json = {
        let mut jb = [0u8; 16384];
        let mut w = JsonBuf::new(&mut jb);
        render(&mut w, &|t| t * 1000, 5);
        let j = core::str::from_utf8(w.bytes()).unwrap_or("");
        !w.overflow && j.starts_with("{\"lists\":{\"blocked_domains\":6") && j.contains("\"recent_count\":5,\"dga_suspects\":") && j.contains("\"private_relay\":\"block\"")
    };
    #[cfg(not(feature = "netsvc"))]
    let json = true;
    // signatures
    let kp = KeyPair::from_seed(Seed::new([0x61; 32]));
    let pk: [u8; 32] = *kp.pk;
    let sign = |tag: &[u8; 6], magic: &[u8; 8], gen: u64, body: &[u8]| {
        let d = boot_abi::sha256::digest(body);
        let s = kp.sk.sign(&signed_message(tag, gen, body.len() as u64, &d)[..], None);
        let mut f = [0u8; 512];
        f[..8].copy_from_slice(magic);
        f[8..16].copy_from_slice(&gen.to_le_bytes());
        f[16..24].copy_from_slice(&(body.len() as u64).to_le_bytes());
        f[24..56].copy_from_slice(&d);
        f[56..120].copy_from_slice(s.as_ref());
        f
    };
    fn dig(b: &[u8]) -> impl FnMut(u64) -> Option<[u8; 32]> + '_ {
        move |len: u64| if len as usize <= b.len() { Some(boot_abi::sha256::digest(&b[..len as usize])) } else { None }
    }
    let body: &[u8] = block;
    let good = sign(b"HQBLK1", b"HQBSIG1\0", 3, body);
    let sig_ok = check_sig(b"HQBSIG1\0", b"HQBLK1", &good, &pk, &mut dig(body)) == Ok((3, body.len() as u64));
    let mut tampered = [0u8; 512];
    tampered[..body.len()].copy_from_slice(body);
    tampered[40] ^= 0x20;
    let sig_t = check_sig(b"HQBSIG1\0", b"HQBLK1", &good, &pk, &mut dig(&tampered[..body.len()])) == Err(LoadErr::DigestMismatch);
    // a BLOCK signature presented as ALLOW.SIG is refused (domain separation)
    let mut swapped = good;
    swapped[..8].copy_from_slice(b"HQASIG1\0");
    let sig_x = check_sig(b"HQASIG1\0", b"HQALW1", &swapped, &pk, &mut dig(body)) == Err(LoadErr::BadSignature);

    reset_tables();
    reset_stats();
    let empty = decide(b"ads.tracker.example") == Allowed && decide(b"_dns.resolver.arpa") == Ddr;
    let pass_all = parse_ok && prec && nx_ede && nx_https && ddr && canary && pass && floor && trunc && dot && tcp53 && cname && cname_clean && top && cli && ring && json && sig_ok && sig_t && sig_x && empty;
    arch_aarch64::_print(format_args!(
        " [P-shield] {} — Shield v2 (ADR 0052): lists (hosts/adblock/@@/bare/wildcard, junk+TLD+IP+$option refused, directives) ok={} | precedence floor>bypass>longest-match ok={} | NXDOMAIN+EDE15={} HTTPS-type NXDOMAIN={} DDR NODATA={} Firefox canary={} benign pass={} floor pass={} every truncation safe={} | DoT refused={} TCP/53 blocked name refused={} | CNAME cloak rewritten={} clean CNAME untouched={} | top-K={} per-client={} ring={} /api/dns json={} | BLOCK.SIG ok={} tampered refused={} cross-file signature refused={} | empty lists still answer DDR={}\n",
        if pass_all { "PASS" } else { "FAIL" }, parse_ok, prec, nx_ede, nx_https, ddr, canary, pass, floor, trunc, dot, tcp53, cname, cname_clean, top, cli, ring, json, sig_ok, sig_t, sig_x, empty
    ));
    pass_all
}
