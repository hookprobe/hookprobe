//! HQCFG1 configuration bundle verification (ADR 0059 step 2; assessment §B.4). Pure: no I/O, no heap — the
//! caller hands in the received bytes (cfgd reads them into its one 16 KiB static buffer) and the 512-byte HQCSIG1.
//!
//! Byte layout (little-endian), agreed byte-for-byte with `os/kernel/tools/hqcfg.py` and the browser builder through
//! the shared vectors `os/kernel/tools/vectors/hqcfg-vectors.json`:
//!
//! ```text
//! bundle  "HQCFG1\0\0" | schema u16 ((major<<8)|minor, 1.0 = 0x0100) | flags u16 (bit0 device-bound)
//!         | generation u64 | device_id[16] | signer_key_id[8] = sha256(pk)[..8]
//!         | section_count u8 | reserved[3] = 0 | count x {kind u8, rsv u8 = 0, len u16} | bodies (no padding)
//! sig     512 B: "HQCSIG1\0" | alg u8 = 1 | total_len u32 | sha256(bundle) | Ed25519(pk, "HQCFG1-SIG" || sha256)
//!         | zero pad (bytes 109..512 must be 0)
//! ```
//!
//! Refused (whole bundle, nothing applied): any byte outside the signed length, a signature that is not over these
//! exact bytes, an unknown major schema or flag, another device (bound), another signer, a generation not ABOVE the
//! floor, a section kind outside schema 1.0 (wan 1, wifi 4, policy 5), sections out of order or repeated, a section
//! overrunning, bytes after the last section, and non-canonical text: only 0x20-0x7E + LF, every line LF-terminated,
//! no blank lines, no trailing spaces; wan / wifi `key=value` each key once; policy each statement once (semantic
//! duplicates: the same (list, seq), a second default, a repeated interface binding or route).
//! Lengths come from the section table only. The PPPoE password and the Wi-Fi PSK travel inside the signed region in
//! clear (protected at rest only once the secrets section ships).

pub const MAGIC: &[u8; 8] = b"HQCFG1\0\0";
pub const SIG_MAGIC: &[u8; 8] = b"HQCSIG1\0";
pub const SIG_TAG: &[u8; 10] = b"HQCFG1-SIG";
pub const SCHEMA_MAJOR: u16 = 1;
pub const MAX_BUNDLE: usize = 16 << 10;
pub const HDR: usize = 48;
pub const KIND_WAN: u8 = 1;
pub const KIND_WIFI: u8 = 4;
pub const KIND_POLICY: u8 = 5;
/// Section caps (the device's own file limits): WAN.TXT one sector, WIFI.TXT 1 KiB, POLICY.TXT 4096 incl. "HQPOL1\n".
const CAP_WAN: usize = 512 - 7;
const CAP_WIFI: usize = 1024;
const CAP_POLICY: usize = 4096 - 7;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CfgErr {
    SigMagic,
    SigAlg,
    SigPadding,
    TotalLen,
    LengthMismatch,
    Digest,
    Signature,
    Magic,
    Schema,
    Flag,
    OtherDevice,
    SignerKeyId,
    NotNewer { gen: u64, floor: u64 },
    Reserved,
    TableOverrun,
    UnknownKind(u8),
    Order,
    SectionOverrun,
    TrailingBytes,
    SectionTooLong(u8),
    NonCanonical(u8),
    Duplicate(u8),
    /// A policy route forwarding could never honour (routing review 2026-11-11): `via lan|eth1`, or an IPv6 route
    /// other than `via wan` without a gateway. Refused at stage time, the same rule as `hal::policy`.
    UnsupportedRoute,
}

/// The route rule shared with `hal::policy::parse_policy`, `hqcfg.py` and the browser builder.
fn route_unsupported(ln: &[u8]) -> bool {
    let mut it = ln.split(|&b| b == b' ');
    if it.next() != Some(&b"route"[..]) {
        return false;
    }
    let v6 = it.next().is_some_and(|d| d.contains(&b':'));
    let (mut via, mut gw, mut prev): (&[u8], bool, &[u8]) = (b"", false, b"");
    for w in it {
        if prev == b"via" {
            via = w;
        }
        if w == b"gw" {
            gw = true;
        }
        prev = w;
    }
    via == b"lan" || via == b"eth1" || (v6 && (via != b"wan" || gw))
}

/// A verified bundle: borrowed sections (kind, body) of the caller's buffer.
#[derive(Clone, Copy, Debug)]
pub struct Verified<'a> {
    pub schema: u16,
    pub flags: u16,
    pub generation: u64,
    pub device_id: [u8; 16],
    pub key_id: [u8; 8],
    secs: [(u8, usize, usize); 3],
    n: usize,
    buf: &'a [u8],
}

impl<'a> Verified<'a> {
    pub fn sections(&self) -> impl Iterator<Item = (u8, &'a [u8])> + '_ {
        let b = self.buf;
        self.secs[..self.n].iter().map(move |&(k, o, l)| (k, &b[o..o + l]))
    }
    pub fn section(&self, kind: u8) -> Option<&'a [u8]> {
        let b = self.buf;
        self.secs[..self.n].iter().find(|s| s.0 == kind).map(|&(_, o, l)| &b[o..o + l])
    }
}

pub fn key_id(pk: &[u8; 32]) -> [u8; 8] {
    let d = boot_abi::sha256::digest(pk);
    let mut k = [0u8; 8];
    k.copy_from_slice(&d[..8]);
    k
}

/// Verify `buf` (exactly the received bytes) against `sig` and the configuration key `pk`. `device_id` = this
/// device's id (a bound bundle must match it); `floor` = the generation already in force (accept only above it).
pub fn verify<'a>(buf: &'a [u8], sig: &[u8; 512], pk: &[u8; 32], device_id: &[u8; 16], floor: u64) -> Result<Verified<'a>, CfgErr> {
    if &sig[..8] != SIG_MAGIC {
        return Err(CfgErr::SigMagic);
    }
    if sig[8] != 1 {
        return Err(CfgErr::SigAlg);
    }
    if sig[109..].iter().any(|&b| b != 0) {
        return Err(CfgErr::SigPadding);
    }
    let total = u32::from_le_bytes([sig[9], sig[10], sig[11], sig[12]]) as usize;
    if !(HDR..=MAX_BUNDLE).contains(&total) {
        return Err(CfgErr::TotalLen);
    }
    if total != buf.len() {
        return Err(CfgErr::LengthMismatch);
    }
    let d = boot_abi::sha256::digest(buf);
    if d[..] != sig[13..45] {
        return Err(CfgErr::Digest);
    }
    let mut m = [0u8; 42];
    m[..10].copy_from_slice(SIG_TAG);
    m[10..].copy_from_slice(&d);
    let ok = match (ed25519_compact::PublicKey::from_slice(pk), ed25519_compact::Signature::from_slice(&sig[45..109])) {
        (Ok(p), Ok(s)) => p.verify(&m[..], &s).is_ok(),
        _ => false,
    };
    if !ok {
        return Err(CfgErr::Signature);
    }
    // ---- the bytes are the signer's; now the envelope rules ----
    if &buf[..8] != MAGIC {
        return Err(CfgErr::Magic);
    }
    let schema = u16::from_le_bytes([buf[8], buf[9]]);
    let flags = u16::from_le_bytes([buf[10], buf[11]]);
    let generation = u64::from_le_bytes(buf[12..20].try_into().unwrap());
    let mut dev = [0u8; 16];
    dev.copy_from_slice(&buf[20..36]);
    let mut kid = [0u8; 8];
    kid.copy_from_slice(&buf[36..44]);
    if schema >> 8 != SCHEMA_MAJOR {
        return Err(CfgErr::Schema);
    }
    if generation <= floor {
        return Err(CfgErr::NotNewer { gen: generation, floor });
    }
    if kid != key_id(pk) {
        return Err(CfgErr::SignerKeyId);
    }
    if flags & 1 != 0 && dev != *device_id {
        return Err(CfgErr::OtherDevice);
    }
    if flags & !1 != 0 {
        return Err(CfgErr::Flag);
    }
    let count = buf[44] as usize;
    if buf[45..48] != [0, 0, 0] {
        return Err(CfgErr::Reserved);
    }
    let mut off = HDR + 4 * count;
    if off > total {
        return Err(CfgErr::TableOverrun);
    }
    let mut v = Verified { schema, flags, generation, device_id: dev, key_id: kid, secs: [(0, 0, 0); 3], n: 0, buf };
    let mut last = 0u8;
    for i in 0..count {
        let t = HDR + 4 * i;
        let (kind, rsv, len) = (buf[t], buf[t + 1], u16::from_le_bytes([buf[t + 2], buf[t + 3]]) as usize);
        let cap = match kind {
            KIND_WAN => CAP_WAN,
            KIND_WIFI => CAP_WIFI,
            KIND_POLICY => CAP_POLICY,
            _ => return Err(CfgErr::UnknownKind(kind)),
        };
        if rsv != 0 {
            return Err(CfgErr::UnknownKind(kind));
        }
        if kind <= last {
            return Err(CfgErr::Order);
        }
        last = kind;
        if off + len > total {
            return Err(CfgErr::SectionOverrun);
        }
        if len > cap {
            return Err(CfgErr::SectionTooLong(kind));
        }
        let body = &buf[off..off + len];
        canonical(kind, body)?;
        if v.n == 3 {
            return Err(CfgErr::Order); // unreachable with 3 strictly ascending known kinds
        }
        v.secs[v.n] = (kind, off, len);
        v.n += 1;
        off += len;
    }
    if off != total {
        return Err(CfgErr::TrailingBytes);
    }
    Ok(v)
}

/// The identity of one canonical line for the duplicate rule (wan / wifi: the key; policy: the statement's
/// semantic key as in `hqcfg.py canonical`).
#[derive(Clone, Copy)]
enum Key<'a> {
    Parts([&'a [u8]; 4], usize),
    Words(&'a [u8]),
}

fn words_eq(line: &[u8], parts: &[&[u8]]) -> bool {
    let mut it = line.split(|&b| b == b' ');
    for p in parts {
        if it.next() != Some(*p) {
            return false;
        }
    }
    it.next().is_none()
}

impl<'a> Key<'a> {
    fn eq(&self, o: &Key<'a>) -> bool {
        match (self, o) {
            (Key::Words(a), Key::Words(b)) => a == b,
            (Key::Parts(a, n), Key::Parts(b, m)) => n == m && a[..*n] == b[..*m],
            (Key::Words(l), Key::Parts(p, n)) | (Key::Parts(p, n), Key::Words(l)) => words_eq(l, &p[..*n]),
        }
    }
}

fn line_key(kind: u8, ln: &[u8]) -> Result<Key<'_>, CfgErr> {
    if kind != KIND_POLICY {
        let eq = ln.iter().position(|&b| b == b'=').ok_or(CfgErr::NonCanonical(kind))?;
        return Ok(Key::Words(&ln[..eq]));
    }
    let mut w = [&b""[..]; 4];
    let mut n = 0usize;
    let mut via: &[u8] = b"";
    let mut prev: &[u8] = b"";
    for (i, x) in ln.split(|&b| b == b' ').enumerate() {
        if i < 4 {
            w[i] = x;
        }
        if prev == b"via" {
            via = x;
        }
        prev = x;
        n = i + 1;
    }
    Ok(if (w[0] == b"acl" || w[0] == b"prefix-list") && n > 3 && w[2] == b"seq" {
        Key::Parts([w[0], w[1], b"seq", w[3]], 4)
    } else if w[0] == b"acl" && n > 2 && w[2] == b"default" {
        Key::Parts([b"acl", w[1], b"default", b""], 3)
    } else if w[0] == b"interface" && n >= 4 {
        Key::Parts([w[0], w[1], w[2], w[3]], 4)
    } else if w[0] == b"route" && n > 1 {
        // (dst, from, via): two routes to the same destination through DIFFERENT next hops are legitimate failover
        // (metric-ordered, e.g. 0.0.0.0/0 via wan metric 10 + via mgmt metric 100) — only a repeat through the same
        // interface is a duplicate (metal batch 59 finding)
        Key::Parts([b"route", w[1], if n > 3 && w[2] == b"from" { w[3] } else { b"any" }, via], 4)
    } else {
        Key::Words(ln)
    })
}

/// Canonical section text (see the module doc).
pub fn canonical(kind: u8, body: &[u8]) -> Result<(), CfgErr> {
    if body.is_empty() || *body.last().unwrap() != b'\n' {
        return Err(CfgErr::NonCanonical(kind));
    }
    let text = &body[..body.len() - 1];
    for (i, ln) in text.split(|&b| b == b'\n').enumerate() {
        if ln.is_empty() || ln.last() == Some(&b' ') || ln.iter().any(|&c| !(0x20..=0x7e).contains(&c)) {
            return Err(CfgErr::NonCanonical(kind));
        }
        if kind == KIND_POLICY && route_unsupported(ln) {
            return Err(CfgErr::UnsupportedRoute);
        }
        let k = line_key(kind, ln)?;
        // bounded: a section is at most ~4 KiB, so at most ~2k lines
        if text.split(|&b| b == b'\n').take(i).any(|p| line_key(kind, p).is_ok_and(|pk| pk.eq(&k))) {
            return Err(CfgErr::Duplicate(kind));
        }
    }
    Ok(())
}

/// POLICY.TXT as the existing policy loader expects it: "HQPOL1\n" + the section, padded with '\n' to 4096.
pub fn policy_file(sec: &[u8], out: &mut [u8; 4096]) -> bool {
    if sec.len() + 7 > out.len() {
        return false;
    }
    out.fill(b'\n');
    out[..7].copy_from_slice(b"HQPOL1\n");
    out[7..7 + sec.len()].copy_from_slice(sec);
    true
}

// ---- [P-cfgbundle] ------------------------------------------------------------------------------------------

#[cfg(not(feature = "cm5"))]
mod vectors {
    include!("testdata/hqcfg_vectors.rs");
}

/// The shared vectors (QEMU build only — they would cost image bytes on CM5): every case's verdict matches the
/// contract, and the valid full bundle yields the expected section ranges.
#[cfg(not(feature = "cm5"))]
pub fn selftest() -> bool {
    use vectors::*;
    let mut agree = 0usize;
    let mut bad: Option<&str> = None;
    for c in CASES.iter() {
        let mut sig = [0u8; 512];
        let ok_sig = c.sig.len() == 512;
        if ok_sig {
            sig.copy_from_slice(c.sig);
        }
        let got = ok_sig && verify(c.bundle, &sig, &PK, &c.device, c.floor).is_ok();
        if got == c.accept {
            agree += 1;
        } else if bad.is_none() {
            bad = Some(c.name);
        }
    }
    let full = CASES.iter().find(|c| c.name == "valid-wan-wifi-policy");
    let ranges = full.is_some_and(|c| {
        let mut sig = [0u8; 512];
        sig.copy_from_slice(c.sig);
        verify(c.bundle, &sig, &PK, &[0u8; 16], 0).is_ok_and(|v| {
            v.generation == GEN_FULL
                && v.sections().zip(SECTIONS_FULL.iter()).all(|((k, b), &(ek, eo, el))| {
                    k == ek && b.len() == el && b.as_ptr() as usize - c.bundle.as_ptr() as usize == eo
                })
                && v.sections().count() == SECTIONS_FULL.len()
        })
    });
    // a policy section becomes the loader's 4096-byte file; a duplicated wan key is refused by `canonical`
    let mut pf = [0u8; 4096];
    let pol = policy_file(b"acl A seq 10 allow any any any\n", &mut pf) && pf[..7] == *b"HQPOL1\n" && pf[4095] == b'\n';
    let dup = canonical(KIND_WAN, b"mode=dhcp\nmode=static\n") == Err(CfgErr::Duplicate(KIND_WAN))
        && canonical(KIND_POLICY, b"acl A default drop\nacl A default allow\n") == Err(CfgErr::Duplicate(KIND_POLICY))
        && canonical(KIND_WAN, b"mode=dhcp\r\n") == Err(CfgErr::NonCanonical(KIND_WAN))
        && canonical(KIND_POLICY, b"route 0.0.0.0/0 via wan metric 10\nroute 0.0.0.0/0 via mgmt gw 192.168.200.1 metric 100\n").is_ok()
        && canonical(KIND_POLICY, b"route 0.0.0.0/0 via wan metric 10\nroute 0.0.0.0/0 via wan metric 20\n") == Err(CfgErr::Duplicate(KIND_POLICY));
    let pass = agree == CASES.len() && ranges && pol && dup;
    arch_aarch64::_print(format_args!(
        " [P-cfgbundle] {} — ADR 0059 HQCFG1 bundle + HQCSIG1 (pure, no heap): the shared vectors (hqcfg.py / browser) agree {}/{}{}{} | full bundle sections at the agreed ranges={} | policy section -> 4096-B POLICY.TXT={} | duplicate keys / statements and CR refused, failover routes via different interfaces allowed={}\n",
        if pass { "PASS" } else { "FAIL" }, agree, CASES.len(), if bad.is_some() { " first mismatch: " } else { "" }, bad.unwrap_or(""), ranges, pol, dup
    ));
    pass
}
