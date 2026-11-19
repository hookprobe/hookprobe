// SPDX-License-Identifier: AGPL-3.0-only
//! HMAC-DRBG (NIST SP 800-90A Rev. 1 §10.1.2, HMAC-SHA-256), for `el0-wpa` (operator decision D-c, 2026-11-16):
//! the kernel keeps the hardware RNG and feeds fresh TRNG entropy to this DRBG at initialisation and on reseed; the
//! security server draws every secret random value (SAE scalars / masks, group keys) from it. An unseeded DRBG, or
//! one past its reseed interval, refuses to generate — the caller fails closed and asks the kernel for entropy.
//! No allocation; the state wipes itself.

use boot_abi::kdf::hmac_sha256;

/// Generate calls between reseeds (SP 800-90A allows 2^48; a short interval keeps fresh kernel entropy flowing).
pub const RESEED_INTERVAL: u64 = 1 << 16;
/// Minimum entropy input in bytes (security strength 256 bits).
pub const SEED_MIN: usize = 32;
/// Largest provided-data input (entropy ‖ nonce ‖ personalisation, or additional input) in bytes.
pub const INPUT_MAX: usize = 160;
/// Largest single request in bytes (SP 800-90A: 2^19 bits; far above any use here).
pub const OUT_MAX: usize = 1024;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DrbgErr {
    /// Never instantiated, or wiped: the kernel must seed it.
    Unseeded,
    /// The reseed interval is spent: the kernel must reseed it.
    NeedReseed,
    /// Too little entropy, an input or request too large.
    BadInput,
}

#[derive(Clone, Copy)]
pub struct HmacDrbg {
    k: [u8; 32],
    v: [u8; 32],
    ctr: u64,
    seeded: bool,
}

/// HMAC-SHA-256(key, a ‖ b ‖ c ‖ d) through one bounded buffer (the KDF has no multi-part form for 4 parts).
fn hmac4(key: &[u8; 32], a: &[u8], b: &[u8], c: &[u8], d: &[u8]) -> [u8; 32] {
    let mut m = [0u8; 32 + 1 + INPUT_MAX];
    let n = a.len() + b.len() + c.len() + d.len();
    let mut o = 0;
    for p in [a, b, c, d] {
        m[o..o + p.len()].copy_from_slice(p);
        o += p.len();
    }
    let r = hmac_sha256(key, &m[..n]);
    crate::wpaauth::wipe(&mut m);
    r
}

impl HmacDrbg {
    pub const fn new() -> Self {
        HmacDrbg { k: [0; 32], v: [0; 32], ctr: 0, seeded: false }
    }

    pub fn seeded(&self) -> bool {
        self.seeded
    }

    /// HMAC_DRBG_Update(provided_data = p1 ‖ p2 ‖ p3).
    fn update(&mut self, p1: &[u8], p2: &[u8], p3: &[u8]) {
        self.k = hmac4(&self.k, &self.v, &[0x00], p1, &[p2, p3].concat_into());
        self.v = hmac_sha256(&self.k, &self.v);
        if !(p1.is_empty() && p2.is_empty() && p3.is_empty()) {
            self.k = hmac4(&self.k, &self.v, &[0x01], p1, &[p2, p3].concat_into());
            self.v = hmac_sha256(&self.k, &self.v);
        }
    }

    /// Instantiate from `entropy` (>= `SEED_MIN` bytes), a `nonce` and a personalisation string.
    pub fn instantiate(&mut self, entropy: &[u8], nonce: &[u8], pers: &[u8]) -> Result<(), DrbgErr> {
        if entropy.len() < SEED_MIN || entropy.len() + nonce.len() + pers.len() > INPUT_MAX {
            return Err(DrbgErr::BadInput);
        }
        self.k = [0x00; 32];
        self.v = [0x01; 32];
        self.update(entropy, nonce, pers);
        self.ctr = 1;
        self.seeded = true;
        Ok(())
    }

    /// Reseed with fresh `entropy` (>= `SEED_MIN` bytes) and optional additional input.
    pub fn reseed(&mut self, entropy: &[u8], addl: &[u8]) -> Result<(), DrbgErr> {
        if !self.seeded {
            return Err(DrbgErr::Unseeded);
        }
        if entropy.len() < SEED_MIN || entropy.len() + addl.len() > INPUT_MAX {
            return Err(DrbgErr::BadInput);
        }
        self.update(entropy, addl, &[]);
        self.ctr = 1;
        Ok(())
    }

    /// Fill `out` (<= `OUT_MAX` bytes). Fails closed: nothing is written when unseeded or past the interval.
    pub fn generate(&mut self, out: &mut [u8], addl: &[u8]) -> Result<(), DrbgErr> {
        if !self.seeded {
            return Err(DrbgErr::Unseeded);
        }
        if self.ctr > RESEED_INTERVAL {
            return Err(DrbgErr::NeedReseed);
        }
        if out.len() > OUT_MAX || addl.len() > INPUT_MAX {
            return Err(DrbgErr::BadInput);
        }
        if !addl.is_empty() {
            self.update(addl, &[], &[]);
        }
        let mut o = 0;
        while o < out.len() {
            self.v = hmac_sha256(&self.k, &self.v);
            let n = (out.len() - o).min(32);
            out[o..o + n].copy_from_slice(&self.v[..n]);
            o += n;
        }
        self.update(addl, &[], &[]);
        self.ctr += 1;
        Ok(())
    }

    /// Back to unseeded, every byte of state zeroed.
    pub fn wipe(&mut self) {
        crate::wpaauth::wipe(&mut self.k);
        crate::wpaauth::wipe(&mut self.v);
        self.ctr = 0;
        self.seeded = false;
    }
}

impl Default for HmacDrbg {
    fn default() -> Self {
        Self::new()
    }
}

/// `[a, b].concat_into()`: two slices joined in a bounded stack buffer (no allocation).
trait ConcatInto {
    fn concat_into(&self) -> Joined;
}
struct Joined {
    b: [u8; INPUT_MAX],
    n: usize,
}
impl core::ops::Deref for Joined {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.b[..self.n]
    }
}
impl Drop for Joined {
    fn drop(&mut self) {
        crate::wpaauth::wipe(&mut self.b);
    }
}
impl ConcatInto for [&[u8]; 2] {
    fn concat_into(&self) -> Joined {
        let mut j = Joined { b: [0; INPUT_MAX], n: 0 };
        for p in self.iter() {
            let m = p.len().min(INPUT_MAX - j.n);
            j.b[j.n..j.n + m].copy_from_slice(&p[..m]);
            j.n += m;
        }
        j
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> [u8; 32] {
        let mut o = [0u8; 32];
        for i in 0..32 {
            o[i] = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
        }
        o
    }

    #[test]
    fn unseeded_and_bad_input_fail_closed() {
        let mut d = HmacDrbg::new();
        let mut out = [0xAAu8; 32];
        assert_eq!(d.generate(&mut out, &[]), Err(DrbgErr::Unseeded));
        assert_eq!(out, [0xAA; 32]);
        assert_eq!(d.instantiate(&[1; 16], &[], &[]), Err(DrbgErr::BadInput));
        assert!(!d.seeded());
        assert_eq!(d.reseed(&[1; 32], &[]), Err(DrbgErr::Unseeded));
    }

    #[test]
    fn reseed_interval_and_wipe() {
        let mut d = HmacDrbg::new();
        d.instantiate(&[7; 32], b"n", b"p").unwrap();
        d.ctr = RESEED_INTERVAL + 1;
        let mut out = [0u8; 16];
        assert_eq!(d.generate(&mut out, &[]), Err(DrbgErr::NeedReseed));
        d.reseed(&[8; 32], &[]).unwrap();
        assert!(d.generate(&mut out, &[]).is_ok());
        d.wipe();
        assert!(!d.seeded() && d.k == [0; 32] && d.v == [0; 32]);
        assert_eq!(d.generate(&mut out, &[]), Err(DrbgErr::Unseeded));
    }

    #[test]
    fn different_seeds_differ_and_outputs_advance() {
        let (mut a, mut b) = (HmacDrbg::new(), HmacDrbg::new());
        a.instantiate(&[1; 32], &[], &[]).unwrap();
        b.instantiate(&[2; 32], &[], &[]).unwrap();
        let (mut x, mut y, mut z) = ([0u8; 32], [0u8; 32], [0u8; 32]);
        a.generate(&mut x, &[]).unwrap();
        b.generate(&mut y, &[]).unwrap();
        a.generate(&mut z, &[]).unwrap();
        assert_ne!(x, y);
        assert_ne!(x, z);
    }

    // Expected values from an independent Python implementation of SP 800-90A §10.1.2 (hmac + hashlib, see
    // tools/ci/drbg_vectors.py): instantiate(entropy = 00..1f, nonce = 20..27, pers = ""), generate 32 B twice.
    #[test]
    fn matches_independent_reference() {
        let e: [u8; 32] = core::array::from_fn(|i| i as u8);
        let n: [u8; 8] = core::array::from_fn(|i| 0x20 + i as u8);
        let mut d = HmacDrbg::new();
        d.instantiate(&e, &n, &[]).unwrap();
        let (mut a, mut b) = ([0u8; 32], [0u8; 32]);
        d.generate(&mut a, &[]).unwrap();
        d.generate(&mut b, &[]).unwrap();
        assert_eq!(a, hex(REF_A));
        assert_eq!(b, hex(REF_B));
        // with a reseed and additional input
        d.reseed(&[0x5a; 32], b"addl").unwrap();
        let mut c = [0u8; 32];
        d.generate(&mut c, b"more").unwrap();
        assert_eq!(c, hex(REF_C));
    }
    const REF_A: &str = "3f56de71d4c5155cea215d45b6a8a161e623ca06345ce68c29c8cb3326c64595";
    const REF_B: &str = "10e253d3fdba1d8df09dec9c985d65d1cedfad604eed968a448c2164872b0725";
    const REF_C: &str = "14aacae0d5d0c8ec7f8557418ac00de8551025ab1be0db9793467e2e1133e6a8";
}
