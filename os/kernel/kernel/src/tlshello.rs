//! Pure TLS ClientHello parser + JA4 fingerprint (moved verbatim from `ja4.rs`; SEC-02). Every byte is from the
//! network; no kernel state, so the host libFuzzer harness (`tools/fuzz/heqk-kernel`) compiles this same file.
//! `ja4.rs` re-exports it.

pub const EXT_SNI: u16 = 0x0000;
pub const EXT_SIGALGS: u16 = 0x000d;
pub const EXT_ALPN: u16 = 0x0010;
pub const EXT_SUPPORTED_VERSIONS: u16 = 0x002b;

pub fn grease(v: u16) -> bool {
    (v >> 8) == (v & 0xff) && (v & 0x0f) == 0x0a
}

pub fn be16(p: &[u8], i: usize) -> Option<u16> {
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
pub struct L<const N: usize> {
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

pub fn sort(v: &mut [u16]) {
    for i in 1..v.len() {
        let mut j = i;
        while j > 0 && v[j - 1] > v[j] {
            v.swap(j - 1, j);
            j -= 1;
        }
    }
}

pub const HEX: &[u8; 16] = b"0123456789abcdef";

/// Comma-joined 4-hex-digit list into `out` at `n`; returns the new length.
pub fn join_hex4(xs: &[u16], out: &mut [u8], mut n: usize) -> usize {
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
pub fn trunc12(input: &[u8], out: &mut [u8]) {
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
