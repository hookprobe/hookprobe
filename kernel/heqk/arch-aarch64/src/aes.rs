//! Minimal AES-128 (encrypt/decrypt) + NIST AES Key Wrap unwrap (RFC 3394), used ONLY for
//! the WPA2 GTK: the 4-way-handshake M3 delivers the GTK KDE wrapped with the KEK (AES key
//! wrap) for key-descriptor version 2. heqk's CCMP is done in the CYW43455 firmware; this
//! software AES exists solely to unwrap that one key blob. Byte-oriented, no AES-NI, no_std.
//! KAT-verified (FIPS-197 + RFC 3394) — see `aes_selftest`.

const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

const RCON: [u8; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

/// Inverse S-box, derived once from SBOX (avoids a second 256-byte table transcription error).
fn inv_sbox(x: u8) -> u8 {
    // linear scan; only used in the 10-round inverse cipher of one 16-byte unwrap block ×~3.
    let mut i = 0usize;
    while i < 256 {
        if SBOX[i] == x {
            return i as u8;
        }
        i += 1;
    }
    0
}

fn xtime(a: u8) -> u8 {
    let h = (a >> 7) & 1;
    (a << 1) ^ (0x1b * h)
}
fn mul(a: u8, b: u8) -> u8 {
    let mut a = a;
    let mut b = b;
    let mut p = 0u8;
    let mut i = 0;
    while i < 8 {
        if b & 1 != 0 {
            p ^= a;
        }
        a = xtime(a);
        b >>= 1;
        i += 1;
    }
    p
}

/// Expand a 16-byte key to 11 round keys (176 bytes).
fn expand(key: &[u8; 16]) -> [u8; 176] {
    let mut rk = [0u8; 176];
    rk[..16].copy_from_slice(key);
    let mut i = 16;
    let mut r = 0;
    while i < 176 {
        let mut t = [rk[i - 4], rk[i - 3], rk[i - 2], rk[i - 1]];
        if i % 16 == 0 {
            t = [
                SBOX[t[1] as usize] ^ RCON[r],
                SBOX[t[2] as usize],
                SBOX[t[3] as usize],
                SBOX[t[0] as usize],
            ];
            r += 1;
        }
        for j in 0..4 {
            rk[i + j] = rk[i - 16 + j] ^ t[j];
        }
        i += 4;
    }
    rk
}

fn add_rk(s: &mut [u8; 16], rk: &[u8], off: usize) {
    for i in 0..16 {
        s[i] ^= rk[off + i];
    }
}

/// AES-128 encrypt one 16-byte block in place.
fn encrypt_block(rk: &[u8; 176], s: &mut [u8; 16]) {
    add_rk(s, rk, 0);
    for round in 1..10 {
        for b in s.iter_mut() {
            *b = SBOX[*b as usize];
        }
        shift_rows(s);
        mix_columns(s);
        add_rk(s, rk, round * 16);
    }
    for b in s.iter_mut() {
        *b = SBOX[*b as usize];
    }
    shift_rows(s);
    add_rk(s, rk, 160);
}

/// AES-128 decrypt one 16-byte block in place.
fn decrypt_block(rk: &[u8; 176], s: &mut [u8; 16]) {
    add_rk(s, rk, 160);
    for round in (1..10).rev() {
        inv_shift_rows(s);
        for b in s.iter_mut() {
            *b = inv_sbox(*b);
        }
        add_rk(s, rk, round * 16);
        inv_mix_columns(s);
    }
    inv_shift_rows(s);
    for b in s.iter_mut() {
        *b = inv_sbox(*b);
    }
    add_rk(s, rk, 0);
}

// State is column-major (AES standard): s[r + 4*c].
fn shift_rows(s: &mut [u8; 16]) {
    let t = *s;
    // row r shifted left by r
    for r in 1..4 {
        for c in 0..4 {
            s[r + 4 * c] = t[r + 4 * ((c + r) % 4)];
        }
    }
}
fn inv_shift_rows(s: &mut [u8; 16]) {
    let t = *s;
    for r in 1..4 {
        for c in 0..4 {
            s[r + 4 * c] = t[r + 4 * ((c + 4 - r) % 4)];
        }
    }
}
fn mix_columns(s: &mut [u8; 16]) {
    for c in 0..4 {
        let o = 4 * c;
        let a0 = s[o];
        let a1 = s[o + 1];
        let a2 = s[o + 2];
        let a3 = s[o + 3];
        s[o] = mul(a0, 2) ^ mul(a1, 3) ^ a2 ^ a3;
        s[o + 1] = a0 ^ mul(a1, 2) ^ mul(a2, 3) ^ a3;
        s[o + 2] = a0 ^ a1 ^ mul(a2, 2) ^ mul(a3, 3);
        s[o + 3] = mul(a0, 3) ^ a1 ^ a2 ^ mul(a3, 2);
    }
}
fn inv_mix_columns(s: &mut [u8; 16]) {
    for c in 0..4 {
        let o = 4 * c;
        let a0 = s[o];
        let a1 = s[o + 1];
        let a2 = s[o + 2];
        let a3 = s[o + 3];
        s[o] = mul(a0, 14) ^ mul(a1, 11) ^ mul(a2, 13) ^ mul(a3, 9);
        s[o + 1] = mul(a0, 9) ^ mul(a1, 14) ^ mul(a2, 11) ^ mul(a3, 13);
        s[o + 2] = mul(a0, 13) ^ mul(a1, 9) ^ mul(a2, 14) ^ mul(a3, 11);
        s[o + 3] = mul(a0, 11) ^ mul(a1, 13) ^ mul(a2, 9) ^ mul(a3, 14);
    }
}

/// NIST AES Key Wrap UNWRAP (RFC 3394) with a 128-bit KEK. `wrapped` is n+1 64-bit blocks;
/// output is n 64-bit blocks (the plaintext key). Returns Some(len) with the plaintext in
/// `out`, or None if the integrity check (default IV 0xA6A6A6A6A6A6A6A6) fails. Used to
/// unwrap the WPA2 GTK from EAPOL M3 key data (KEK = PTK[16..32]).
pub fn aes_unwrap(kek: &[u8; 16], wrapped: &[u8], out: &mut [u8]) -> Option<usize> {
    if wrapped.len() < 16 || wrapped.len() % 8 != 0 {
        return None;
    }
    let n = wrapped.len() / 8 - 1; // number of 64-bit key blocks
    if out.len() < n * 8 {
        return None;
    }
    let rk = expand(kek);
    let mut a = [0u8; 8];
    a.copy_from_slice(&wrapped[0..8]);
    // R[1..=n] = wrapped[1..]
    for i in 0..n {
        out[i * 8..i * 8 + 8].copy_from_slice(&wrapped[(i + 1) * 8..(i + 2) * 8]);
    }
    // 6 rounds, j = 5..0, i = n..1
    let mut j = 6i32;
    while j > 0 {
        j -= 1;
        let mut i = n;
        while i >= 1 {
            let t = (n as u64) * (j as u64) + (i as u64);
            let mut blk = [0u8; 16];
            // A ^ t
            let mut av = u64::from_be_bytes(a);
            av ^= t;
            blk[0..8].copy_from_slice(&av.to_be_bytes());
            blk[8..16].copy_from_slice(&out[(i - 1) * 8..i * 8]);
            decrypt_block(&rk, &mut blk);
            a.copy_from_slice(&blk[0..8]);
            out[(i - 1) * 8..i * 8].copy_from_slice(&blk[8..16]);
            i -= 1;
        }
    }
    // integrity: A must equal the default IV.
    for &b in &a {
        if b != 0xA6 {
            return None;
        }
    }
    Some(n * 8)
}

/// KAT: FIPS-197 AES-128 encrypt/decrypt + RFC 3394 AES-128 key-unwrap.
pub fn aes_selftest() -> bool {
    // FIPS-197 C.1
    let key = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ];
    let pt = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff,
    ];
    let ct = [
        0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5,
        0x5a,
    ];
    let rk = expand(&key);
    let mut b = pt;
    encrypt_block(&rk, &mut b);
    if b != ct {
        return false;
    }
    decrypt_block(&rk, &mut b);
    if b != pt {
        return false;
    }
    // RFC 3394 §4.1 — 128-bit KEK, 128-bit key data.
    let wrapped = [
        0x1f, 0xa6, 0x8b, 0x0a, 0x81, 0x12, 0xb4, 0x47, 0xae, 0xf3, 0x4b, 0xd8, 0xfb, 0x5a, 0x7b,
        0x82, 0x9d, 0x3e, 0x86, 0x23, 0x71, 0xd2, 0xcf, 0xe5,
    ];
    let mut out = [0u8; 16];
    match aes_unwrap(&key, &wrapped, &mut out) {
        Some(16) => out == pt,
        _ => false,
    }
}
