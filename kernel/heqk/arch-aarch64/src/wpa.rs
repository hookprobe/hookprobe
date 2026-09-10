//! WPA2-PSK PMK derivation — PBKDF2-HMAC-SHA1(passphrase, ssid, 4096, 32).
//!
//! IEEE 802.11i mandates this exact (legacy) KDF for the WPA2 PMK. The Raspberry-Pi
//! CYW43455 brcmfmac firmware expects the RAW 32-byte PMK (WLC_SET_WSEC_PMK, flags=0)
//! — its in-firmware supplicant (idsup) then runs the 4-way handshake; it does NOT do
//! passphrase→PBKDF2 itself (a passphrase set returns BADARG). heqk has no SHA-1
//! anywhere else (it is deprecated), so a minimal one lives here and is used ONLY for
//! this legacy WPA KDF — never for any security-critical hashing (heqk uses SHA-256 +
//! the PQC-hybrid chain for that).

/// Streaming SHA-1 (FIPS 180-4). Legacy, WPA-KDF only.
#[derive(Clone)]
struct Sha1 {
    h: [u32; 5],
    buf: [u8; 64],
    len: usize,
    total: u64,
}

impl Sha1 {
    fn new() -> Self {
        Sha1 {
            h: [0x6745_2301, 0xEFCD_AB89, 0x98BA_DCFE, 0x1032_5476, 0xC3D2_E1F0],
            buf: [0; 64],
            len: 0,
            total: 0,
        }
    }

    fn block(h: &mut [u32; 5], b: &[u8; 64]) {
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([b[i * 4], b[i * 4 + 1], b[i * 4 + 2], b[i * 4 + 3]]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let (mut a, mut bb, mut c, mut d, mut e) = (h[0], h[1], h[2], h[3], h[4]);
        for (i, &wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((bb & c) | ((!bb) & d), 0x5A82_7999u32),
                20..=39 => (bb ^ c ^ d, 0x6ED9_EBA1),
                40..=59 => ((bb & c) | (bb & d) | (c & d), 0x8F1B_BCDC),
                _ => (bb ^ c ^ d, 0xCA62_C1D6),
            };
            let t = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(wi);
            e = d;
            d = c;
            c = bb.rotate_left(30);
            bb = a;
            a = t;
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(bb);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
    }

    fn update(&mut self, mut data: &[u8]) {
        self.total = self.total.wrapping_add(data.len() as u64);
        if self.len > 0 {
            while self.len < 64 && !data.is_empty() {
                self.buf[self.len] = data[0];
                self.len += 1;
                data = &data[1..];
            }
            if self.len == 64 {
                let b = self.buf;
                Sha1::block(&mut self.h, &b);
                self.len = 0;
            }
        }
        while data.len() >= 64 {
            let mut b = [0u8; 64];
            b.copy_from_slice(&data[..64]);
            Sha1::block(&mut self.h, &b);
            data = &data[64..];
        }
        for &x in data {
            self.buf[self.len] = x;
            self.len += 1;
        }
    }

    fn finish(mut self) -> [u8; 20] {
        let bits = self.total.wrapping_mul(8);
        self.buf[self.len] = 0x80;
        self.len += 1;
        if self.len > 56 {
            while self.len < 64 {
                self.buf[self.len] = 0;
                self.len += 1;
            }
            let b = self.buf;
            Sha1::block(&mut self.h, &b);
            self.len = 0;
        }
        while self.len < 56 {
            self.buf[self.len] = 0;
            self.len += 1;
        }
        self.buf[56..64].copy_from_slice(&bits.to_be_bytes());
        let b = self.buf;
        Sha1::block(&mut self.h, &b);
        let mut out = [0u8; 20];
        for i in 0..5 {
            out[i * 4..i * 4 + 4].copy_from_slice(&self.h[i].to_be_bytes());
        }
        out
    }
}

/// HMAC-SHA1(key, msg). WPA keys (passphrases) are <=63 B < the 64-B block, but the
/// >block branch is kept for correctness.
fn hmac_sha1(key: &[u8], msg: &[u8]) -> [u8; 20] {
    let mut k = [0u8; 64];
    if key.len() > 64 {
        let mut kh = Sha1::new();
        kh.update(key);
        k[..20].copy_from_slice(&kh.finish());
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..64 {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }
    let mut inner = Sha1::new();
    inner.update(&ipad);
    inner.update(msg);
    let ih = inner.finish();
    let mut outer = Sha1::new();
    outer.update(&opad);
    outer.update(&ih);
    outer.finish()
}

/// The WPA2 PMK: PBKDF2-HMAC-SHA1(passphrase, ssid, 4096, 32). `ssid` <= 32 B.
pub fn wpa_pmk(passphrase: &[u8], ssid: &[u8]) -> [u8; 32] {
    let sl = ssid.len().min(32);
    let mut out = [0u8; 32];
    // dkLen 32 needs 2 SHA-1 (20-B) blocks: T1 || T2[..12].
    for block in 1u32..=2 {
        let mut salt = [0u8; 36];
        salt[..sl].copy_from_slice(&ssid[..sl]);
        salt[sl..sl + 4].copy_from_slice(&block.to_be_bytes());
        let mut u = hmac_sha1(passphrase, &salt[..sl + 4]);
        let mut t = u;
        for _ in 1..4096 {
            u = hmac_sha1(passphrase, &u);
            for i in 0..20 {
                t[i] ^= u[i];
            }
        }
        let off = ((block - 1) * 20) as usize;
        let n = (32 - off).min(20);
        out[off..off + n].copy_from_slice(&t[..n]);
    }
    out
}

/// WPA2 PRF (IEEE 802.11i §8.5.1.1) built on HMAC-SHA1: `out` = the first out.len()
/// bytes of HMAC-SHA1(key, label || 0x00 || data || i) for i = 0,1,2,…
fn prf(key: &[u8], label: &[u8], data: &[u8], out: &mut [u8]) {
    let mut msg = [0u8; 160]; // label(<=32) + 1 + data(<=76) + 1
    let base = label.len() + 1 + data.len();
    msg[..label.len()].copy_from_slice(label);
    msg[label.len()] = 0x00;
    msg[label.len() + 1..base].copy_from_slice(data);
    let mut i = 0u8;
    let mut pos = 0;
    while pos < out.len() {
        msg[base] = i;
        let d = hmac_sha1(key, &msg[..base + 1]);
        let take = (out.len() - pos).min(20);
        out[pos..pos + take].copy_from_slice(&d[..take]);
        pos += take;
        i += 1;
    }
}

/// Derive the WPA2 PTK for CCMP (384 bits = KCK[16] ‖ KEK[16] ‖ TK[16]).
/// PTK = PRF-384(PMK, "Pairwise key expansion",
///   min(AA,SPA) ‖ max(AA,SPA) ‖ min(ANonce,SNonce) ‖ max(ANonce,SNonce)).
pub fn wpa_ptk(
    pmk: &[u8; 32],
    aa: &[u8; 6],
    spa: &[u8; 6],
    anonce: &[u8; 32],
    snonce: &[u8; 32],
) -> [u8; 48] {
    let mut data = [0u8; 76];
    // min/max of the two MACs (lexicographic).
    let (lo_m, hi_m) = if aa <= spa { (aa, spa) } else { (spa, aa) };
    data[0..6].copy_from_slice(lo_m);
    data[6..12].copy_from_slice(hi_m);
    // min/max of the two nonces.
    let (lo_n, hi_n): (&[u8; 32], &[u8; 32]) = if anonce <= snonce {
        (anonce, snonce)
    } else {
        (snonce, anonce)
    };
    data[12..44].copy_from_slice(lo_n);
    data[44..76].copy_from_slice(hi_n);
    let mut ptk = [0u8; 48];
    prf(pmk, b"Pairwise key expansion", &data, &mut ptk);
    ptk
}

/// EAPOL-Key MIC for Key Descriptor Version 2 (HMAC-SHA1-128): the first 16 bytes of
/// HMAC-SHA1(KCK, eapol_frame) where the frame's MIC field is zeroed before hashing.
pub fn wpa_mic_sha1(kck: &[u8; 16], eapol: &[u8]) -> [u8; 16] {
    let full = hmac_sha1(kck, eapol);
    let mut mic = [0u8; 16];
    mic.copy_from_slice(&full[..16]);
    mic
}

/// Known-answer test (IEEE 802.11i): PBKDF2-HMAC-SHA1("password","IEEE",4096,32)
/// = f42c6fc52df0ebef9ebb4b90b38a5f902e83fe1b135a70e23aed762e9710a12e. Proves the
/// SHA-1/HMAC/PBKDF2 chain on-device before a real PMK is ever trusted.
pub fn wpa_pmk_selftest() -> bool {
    const KAT: [u8; 32] = [
        0xf4, 0x2c, 0x6f, 0xc5, 0x2d, 0xf0, 0xeb, 0xef, 0x9e, 0xbb, 0x4b, 0x90, 0xb3, 0x8a, 0x5f,
        0x90, 0x2e, 0x83, 0xfe, 0x1b, 0x13, 0x5a, 0x70, 0xe2, 0x3a, 0xed, 0x76, 0x2e, 0x97, 0x10,
        0xa1, 0x2e,
    ];
    wpa_pmk(b"password", b"IEEE") == KAT
}
