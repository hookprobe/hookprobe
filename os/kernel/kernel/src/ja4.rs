//! Passive TLS client fingerprint (FoxIO JA4) + SNI from a ClientHello — detection + device identity.
//!
//! Ported from the linux-tier `napse-capture` dpi.rs (whose JA4 was cross-checked against the FoxIO
//! reference implementation, including its two documented reference-vs-prose choices: JA4_a's extension
//! count includes SNI/ALPN, and the ALPN field collapses to "99" when the first byte is non-ASCII), to a
//! no_std, fixed-buffer form: at most 64 ciphers / 32 extensions / 32 signature algorithms are kept (a
//! longer hello is still fingerprinted, flagged `truncated`). Nothing allocates; every read is bounded.
//! Legacy V1's JA3 capture was never started; this runs inline on every TLS ClientHello heqk forwards.

const EXT_SNI: u16 = 0x0000;
const EXT_SIGALGS: u16 = 0x000d;
const EXT_ALPN: u16 = 0x0010;
const EXT_SUPPORTED_VERSIONS: u16 = 0x002b;

fn grease(v: u16) -> bool {
    (v >> 8) == (v & 0xff) && (v & 0x0f) == 0x0a
}

fn be16(p: &[u8], i: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*p.get(i)?, *p.get(i + 1)?]))
}

/// One parsed ClientHello.
pub struct Hello {
    /// e.g. `t13d0204h2_62ed6f6ca7ad_3953dc75acc4` (always 36 bytes).
    pub ja4: [u8; 36],
    /// Server name (sanitised: [a-z0-9.-]), 0-length when absent.
    pub sni: [u8; 64],
    pub sni_len: u8,
    /// More ciphers / extensions than the fixed buffers keep.
    pub truncated: bool,
}

impl Hello {
    pub fn ja4_str(&self) -> &str {
        core::str::from_utf8(&self.ja4).unwrap_or("")
    }
    pub fn sni_str(&self) -> &str {
        core::str::from_utf8(&self.sni[..self.sni_len as usize]).unwrap_or("")
    }
}

/// Fixed-capacity u16 list.
struct L<const N: usize> {
    v: [u16; N],
    n: usize,
    over: bool,
}
impl<const N: usize> L<N> {
    const fn new() -> Self {
        L { v: [0; N], n: 0, over: false }
    }
    fn push(&mut self, x: u16) {
        if self.n < N {
            self.v[self.n] = x;
            self.n += 1;
        } else {
            self.over = true;
        }
    }
    fn s(&self) -> &[u16] {
        &self.v[..self.n]
    }
}

fn sort(v: &mut [u16]) {
    for i in 1..v.len() {
        let mut j = i;
        while j > 0 && v[j - 1] > v[j] {
            v.swap(j - 1, j);
            j -= 1;
        }
    }
}

const HEX: &[u8; 16] = b"0123456789abcdef";

/// Comma-joined 4-hex-digit list into `out` at `n`; returns the new length.
fn join_hex4(xs: &[u16], out: &mut [u8], mut n: usize) -> usize {
    for (i, &x) in xs.iter().enumerate() {
        if i > 0 && n < out.len() {
            out[n] = b',';
            n += 1;
        }
        for sh in [12, 8, 4, 0] {
            if n < out.len() {
                out[n] = HEX[((x >> sh) & 0xf) as usize];
                n += 1;
            }
        }
    }
    n
}

/// First 12 lowercase hex chars of SHA-256(input), or "000000000000" for an empty input.
fn trunc12(input: &[u8], out: &mut [u8]) {
    if input.is_empty() {
        out[..12].copy_from_slice(b"000000000000");
        return;
    }
    let d = boot_abi::sha256::digest(input);
    for i in 0..6 {
        out[2 * i] = HEX[(d[i] >> 4) as usize];
        out[2 * i + 1] = HEX[(d[i] & 0xf) as usize];
    }
}

/// Parse a TLS record carrying a ClientHello (the first TCP payload of a connection) and fingerprint it.
pub fn client_hello(p: &[u8]) -> Option<Hello> {
    // record: type 22, version(2), len(2); handshake type 1 (client_hello), len(3), client_version(2), random(32)
    if p.len() < 43 || p[0] != 22 || p[5] != 1 {
        return None;
    }
    let legacy = be16(p, 9)?;
    let mut i = 43;
    i += 1 + *p.get(i)? as usize; // session id
    let cs_len = be16(p, i)? as usize;
    i += 2;
    let cs_end = i.checked_add(cs_len)?;
    if cs_end > p.len() {
        return None;
    }
    let mut ciphers = L::<64>::new();
    while i + 2 <= cs_end {
        let c = be16(p, i)?;
        if !grease(c) {
            ciphers.push(c);
        }
        i += 2;
    }
    i = cs_end;
    i += 1 + *p.get(i)? as usize; // compression methods
    let _ = be16(p, i)?;
    i += 2;
    let mut exts = L::<32>::new();
    let mut sigs = L::<32>::new();
    let mut vers = L::<16>::new();
    let mut sni_present = false;
    let mut h = Hello { ja4: [b'0'; 36], sni: [0; 64], sni_len: 0, truncated: false };
    let mut alpn: Option<(usize, usize)> = None; // (start, len) of the first ALPN protocol id
    while i + 4 <= p.len() {
        let et = be16(p, i)?;
        let el = be16(p, i + 2)? as usize;
        i += 4;
        if i + el > p.len() {
            break;
        }
        let e = &p[i..i + el];
        if !grease(et) {
            exts.push(et);
        }
        match et {
            EXT_SNI => {
                sni_present = true;
                if el >= 5 {
                    let nl = be16(e, 3)? as usize;
                    if 5 + nl <= e.len() {
                        let mut k = 0;
                        for &c in &e[5..5 + nl] {
                            if k >= h.sni.len() {
                                break;
                            }
                            let c = c.to_ascii_lowercase();
                            if c.is_ascii_alphanumeric() || c == b'.' || c == b'-' {
                                h.sni[k] = c;
                                k += 1;
                            }
                        }
                        h.sni_len = k as u8;
                    }
                }
            }
            EXT_SIGALGS if el >= 2 => {
                let mut j = 2;
                while j + 2 <= e.len() {
                    let s = be16(e, j)?;
                    if !grease(s) {
                        sigs.push(s);
                    }
                    j += 2;
                }
            }
            EXT_ALPN if el >= 3 => {
                let pl = e[2] as usize;
                if be16(e, 0)? > 0 && 3 + pl <= e.len() {
                    alpn = Some((i + 3, pl));
                }
            }
            EXT_SUPPORTED_VERSIONS if el >= 1 => {
                let ll = e[0] as usize;
                let mut j = 1;
                while j + 2 <= e.len() && j - 1 < ll {
                    vers.push(be16(e, j)?);
                    j += 2;
                }
            }
            _ => {}
        }
        i += el;
    }
    h.truncated = ciphers.over || exts.over || sigs.over;
    // JA4_a: t <version> <d|i> <cipher count> <ext count> <alpn>
    let ver = vers.s().iter().copied().filter(|v| !grease(*v)).max().unwrap_or(legacy);
    let vc: &[u8; 2] = match ver {
        0x0002 => b"s2",
        0x0300 => b"s3",
        0x0301 => b"10",
        0x0302 => b"11",
        0x0303 => b"12",
        0x0304 => b"13",
        _ => b"00",
    };
    h.ja4[0] = b't';
    h.ja4[1..3].copy_from_slice(vc);
    h.ja4[3] = if sni_present { b'd' } else { b'i' };
    let cc = ciphers.n.min(99);
    let ec = exts.n.min(99);
    h.ja4[4] = b'0' + (cc / 10) as u8;
    h.ja4[5] = b'0' + (cc % 10) as u8;
    h.ja4[6] = b'0' + (ec / 10) as u8;
    h.ja4[7] = b'0' + (ec % 10) as u8;
    let (a0, a1) = match alpn {
        Some((s, l)) if l > 0 => {
            if p[s] > 0x7f {
                (b'9', b'9')
            } else {
                (p[s], p[s + l - 1])
            }
        }
        _ => (b'0', b'0'),
    };
    h.ja4[8] = a0;
    h.ja4[9] = a1;
    h.ja4[10] = b'_';
    // JA4_b: sorted ciphers
    let mut sc = [0u16; 64];
    sc[..ciphers.n].copy_from_slice(ciphers.s());
    sort(&mut sc[..ciphers.n]);
    let mut buf = [0u8; 64 * 5 + 1 + 32 * 5];
    let n = join_hex4(&sc[..ciphers.n], &mut buf, 0);
    trunc12(&buf[..n], &mut h.ja4[11..23]);
    h.ja4[23] = b'_';
    // JA4_c: sorted extensions without SNI/ALPN, then "_" + signature algorithms in wire order
    let mut se = [0u16; 32];
    let mut m = 0;
    for &x in exts.s() {
        if x != EXT_SNI && x != EXT_ALPN {
            se[m] = x;
            m += 1;
        }
    }
    sort(&mut se[..m]);
    let mut n = join_hex4(&se[..m], &mut buf, 0);
    if sigs.n > 0 && n < buf.len() {
        buf[n] = b'_';
        n = join_hex4(sigs.s(), &mut buf, n + 1);
    }
    trunc12(&buf[..n], &mut h.ja4[24..36]);
    Some(h)
}

/// `[P-ja4]`: the linux-tier / FoxIO-reference vector, GREASE handling, and hostile input.
pub fn selftest() -> bool {
    // the exact ClientHello of linux-tier dpi.rs `client_hello_record()`
    fn ext(t: u16, d: &[u8], out: &mut [u8], n: &mut usize) {
        out[*n..*n + 2].copy_from_slice(&t.to_be_bytes());
        out[*n + 2..*n + 4].copy_from_slice(&(d.len() as u16).to_be_bytes());
        out[*n + 4..*n + 4 + d.len()].copy_from_slice(d);
        *n += 4 + d.len();
    }
    let build = |grease_too: bool, out: &mut [u8; 256]| -> usize {
        let mut exts = [0u8; 128];
        let mut en = 0;
        if grease_too {
            ext(0x1a1a, &[], &mut exts, &mut en);
        }
        ext(0x0000, b"\x00\x0e\x00\x00\x0bexample.com", &mut exts, &mut en);
        ext(0x002b, b"\x02\x03\x04", &mut exts, &mut en);
        ext(0x000d, b"\x00\x02\x04\x03", &mut exts, &mut en);
        ext(0x0010, b"\x00\x03\x02h2", &mut exts, &mut en);
        let mut body = [0u8; 200];
        let mut b = 0;
        body[0..2].copy_from_slice(&0x0303u16.to_be_bytes());
        b += 2 + 32; // random
        body[b] = 0; // session id length
        b += 1;
        let cs: &[u16] = if grease_too { &[0x2a2a, 0x1302, 0x1301] } else { &[0x1302, 0x1301] };
        body[b..b + 2].copy_from_slice(&((cs.len() * 2) as u16).to_be_bytes());
        b += 2;
        for c in cs {
            body[b..b + 2].copy_from_slice(&c.to_be_bytes());
            b += 2;
        }
        body[b] = 1;
        body[b + 1] = 0;
        b += 2;
        body[b..b + 2].copy_from_slice(&(en as u16).to_be_bytes());
        b += 2;
        body[b..b + en].copy_from_slice(&exts[..en]);
        b += en;
        out[0] = 22;
        out[1..3].copy_from_slice(&0x0301u16.to_be_bytes());
        out[3..5].copy_from_slice(&((4 + b) as u16).to_be_bytes());
        out[5] = 1;
        out[6] = 0;
        out[7..9].copy_from_slice(&(b as u16).to_be_bytes());
        out[9..9 + b].copy_from_slice(&body[..b]);
        9 + b
    };
    let mut rec = [0u8; 256];
    let n = build(false, &mut rec);
    let kat = client_hello(&rec[..n]).is_some_and(|h| h.ja4_str() == "t13d0204h2_62ed6f6ca7ad_3953dc75acc4" && h.sni_str() == "example.com" && !h.truncated);
    // GREASE in ciphers and extensions changes nothing
    let mut rg = [0u8; 256];
    let ng = build(true, &mut rg);
    let gr = client_hello(&rg[..ng]).is_some_and(|h| h.ja4_str() == "t13d0204h2_62ed6f6ca7ad_3953dc75acc4");
    // hostile input: every truncation, a non-handshake record, garbage — never a panic, never a wrong Some
    let mut safe = true;
    for cut in 0..n {
        if let Some(h) = client_hello(&rec[..cut]) {
            safe &= h.ja4[0] == b't';
        }
    }
    let mut junk = rec;
    junk[0] = 23;
    safe &= client_hello(&junk[..n]).is_none() && client_hello(&[0xff; 300]).is_none();
    // IPv6 leg: the same hello inside Ethernet/IPv6/TCP is fingerprinted under its v6 source + lease.
    let mut f = [0u8; 74 + 256];
    f[12] = 0x86;
    f[13] = 0xdd;
    f[14] = 0x60;
    f[18..20].copy_from_slice(&((20 + n) as u16).to_be_bytes());
    f[20] = 6;
    f[21] = 64;
    f[22] = 0x20;
    f[23] = 0x01;
    f[37] = 0x77; // src 2001::77
    f[66] = 0x50; // TCP data offset 5
    f[67] = 0x18;
    f[74..74 + n].copy_from_slice(&rec[..n]);
    let before = hellos();
    observe6(&f[..74 + n], 0x0a63_0042);
    let mut seen6 = false;
    for_each(&mut |e| seen6 |= e.client6[0] == 0x20 && e.client6[15] == 0x77 && e.client == 0x0a63_0042);
    let v6 = hellos() == before + 1 && seen6;
    // leave the live table as it was: the device's /api/tls must never show a selftest client
    for e in unsafe { (*core::ptr::addr_of_mut!(SEEN)).iter_mut() } {
        if e.client6[0] == 0x20 && e.client6[15] == 0x77 && e.client == 0x0a63_0042 {
            *e = S0;
        }
    }
    unsafe { HELLOS = before };
    let pass = kat && gr && safe && v6;
    arch_aarch64::_print(format_args!(
        " [P-ja4] {} — passive TLS ClientHello fingerprint (FoxIO JA4, linux-tier/reference vector) t13d0204h2_62ed6f6ca7ad_3953dc75acc4 + SNI={} | GREASE ignored={} | every truncation + non-handshake + garbage safe={} | IPv6 client fingerprinted={}\n",
        if pass { "PASS" } else { "FAIL" }, kat, gr, safe, v6
    ));
    pass
}


// ---- observation: the last TLS clients seen (per client + fingerprint), served at /api/tls ----

#[derive(Clone, Copy)]
pub struct Seen {
    /// IPv4 client (for an IPv6 client: the same device's IPv4 lease, 0 if it has none)
    pub client: u32,
    /// IPv6 client address (all-zero for an IPv4 observation)
    pub client6: [u8; 16],
    pub ja4: [u8; 36],
    pub sni: [u8; 64],
    pub sni_len: u8,
    pub count: u32,
    pub first_ms: u64,
    pub last_ms: u64,
    pub ioc: bool,
    pub bypass: bool,
}
const S0: Seen = Seen { client: 0, client6: [0; 16], ja4: [0; 36], sni: [0; 64], sni_len: 0, count: 0, first_ms: 0, last_ms: 0, ioc: false, bypass: false };
const RING: usize = 64;
static mut SEEN: [Seen; RING] = [S0; RING];
static mut HELLOS: u64 = 0;

fn ms() -> u64 {
    let (c, f) = (crate::clock::ticks(), crate::clock::freq());
    c.saturating_mul(1000) / f.max(1)
}

/// Every forwarded TCP segment from `src`: if its payload is a TLS ClientHello, fingerprint + record it.
/// Rule 125 (a known-bad JA4 from the signed IOC pack) and rule 126 (SNI is a name Shield blocks — the
/// device reached it without Shield: DoH, a hard-coded IP or a stale answer) fire observe-only.
/// Cost on every other segment: two byte compares.
pub fn observe(payload: &[u8], src: u32) {
    observe_at(payload, src, [0; 16]);
}

/// An IPv6 TCP frame from a LAN client (Ethernet/IPv6, no extension headers on the TLS path). `attrib` is the
/// device's IPv4 lease (by MAC) so detections land on the device the owner knows; 0 when it has none.
pub fn observe6(frame: &[u8], attrib: u32) {
    let Some(m) = crate::net::parse(frame) else { return };
    if m.ethertype != crate::net::ETHERTYPE_IPV6 || m.ip_proto != crate::net::IPPROTO_TCP || frame.len() < 38 {
        return;
    }
    let Some(&off) = frame.get(m.l4_off + 12) else { return };
    let pay = m.l4_off + ((off >> 4) as usize) * 4;
    if pay >= frame.len() {
        return;
    }
    let mut s6 = [0u8; 16];
    s6.copy_from_slice(&frame[22..38]);
    observe_at(&frame[pay..], attrib, s6);
}

fn observe_at(payload: &[u8], src: u32, src6: [u8; 16]) {
    if payload.len() < 43 || payload[0] != 22 || payload[5] != 1 {
        return;
    }
    let Some(h) = client_hello(payload) else { return };
    unsafe { HELLOS += 1 };
    let ioc = crate::ioc::ja4_listed(&h.ja4);
    let bypass = h.sni_len > 0 && crate::shield::decide(&h.sni[..h.sni_len as usize]) == crate::shield::Verdict::Blocked;
    let now = ms();
    let t = unsafe { &mut *core::ptr::addr_of_mut!(SEEN) };
    let slot = t.iter().position(|e| e.count > 0 && e.client == src && e.client6 == src6 && e.ja4 == h.ja4 && e.sni[..e.sni_len as usize] == h.sni[..h.sni_len as usize])
        .or_else(|| t.iter().position(|e| e.count == 0))
        .unwrap_or_else(|| (0..RING).min_by_key(|&i| t[i].last_ms).unwrap_or(0));
    let e = &mut t[slot];
    if e.count == 0 || e.client != src || e.client6 != src6 || e.ja4 != h.ja4 {
        *e = Seen { client: src, client6: src6, ja4: h.ja4, sni: h.sni, sni_len: h.sni_len, count: 0, first_ms: now, last_ms: now, ioc, bypass };
    }
    e.count = e.count.saturating_add(1);
    e.last_ms = now;
    if ioc {
        crate::rules::tls_ioc_verdict(src);
    }
    if bypass {
        crate::rules::tls_bypass_verdict(src);
    }
}

pub fn hellos() -> u64 {
    unsafe { HELLOS }
}

/// Visit the ring, most recent first.
pub fn for_each(f: &mut dyn FnMut(&Seen)) {
    let t = unsafe { &*core::ptr::addr_of!(SEEN) };
    let mut idx: [usize; RING] = core::array::from_fn(|i| i);
    idx.sort_unstable_by_key(|&i| core::cmp::Reverse(t[i].last_ms));
    for &i in idx.iter() {
        if t[i].count > 0 {
            f(&t[i]);
        }
    }
}
