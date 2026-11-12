//! WPA3-SAE (IEEE 802.11-2020 §12.4, group 19 = NIST P-256), the AP-side responder heqk runs on the host because
//! the CYW43455 RPi firmware forwards SAE Authentication frames (event 188 `EXT_AUTH_FRAME_RX`) instead of running
//! SAE itself (batch 37). Hunting-and-pecking PWE (the default every client supports), constant-iteration loop
//! (k = 40, blinded with a stub password after the hit, as hostapd), anti-reflection and range checks on the peer
//! commit, KCK/PMK/PMKID per §12.4.5.4, confirm per §12.4.5.5. no_std, no allocation. Checked against the
//! IEEE 802.11-2020 Annex J.10 vectors (the same ones hostapd's module tests use).
#![no_std]

use p256::elliptic_curve::ops::Reduce;
use p256::elliptic_curve::point::{AffineCoordinates, DecompressPoint};
use p256::elliptic_curve::sec1::{FromSec1Point, Sec1Point, ToSec1Point};
use p256::elliptic_curve::{Field, PrimeField};
use p256::{AffinePoint, FieldBytes, NistP256, ProjectivePoint, Scalar, U256};

/// The P-256 base-field element (p256 0.14 no longer re-exports it; the curve names it via FieldArithmetic).
type FieldElement = <NistP256 as p256::elliptic_curve::hazmat::FieldArithmetic>::FieldElement;
type EncodedPoint = Sec1Point<NistP256>;
use sha2::{Digest, Sha256};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq, ConstantTimeLess};

/// The H2E password element base (precomputed per SSID + passphrase).
pub type PT = ProjectivePoint;

pub const GROUP_P256: u16 = 19;
/// Minimum hunting-and-pecking iterations (hostapd `dragonfly_min_pwe_loop_iter`: 40 for ECC groups).
const K_ITER: u8 = 40;

/// P-256 prime, big-endian.
const P_BE: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff,
];

pub fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut k = [0u8; 64];
    if key.len() > 64 {
        k[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..64 {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }
    let mut h = Sha256::new();
    h.update(ipad);
    for p in parts {
        h.update(p);
    }
    let inner = h.finalize();
    let mut o = Sha256::new();
    o.update(opad);
    o.update(inner);
    o.finalize().into()
}

/// IEEE 802.11 KDF-Hash-Length with SHA-256 (hostapd `sha256_prf_bits`): out = HMAC(K, i_le16 ‖ label ‖ ctx ‖ L_le16)…
pub fn kdf_sha256(key: &[u8], label: &[u8], ctx: &[&[u8]], out: &mut [u8]) {
    let bits = (out.len() * 8) as u16;
    let mut i = 1u16;
    let mut pos = 0;
    while pos < out.len() {
        let mut parts: [&[u8]; 8] = [&[]; 8];
        let ib = i.to_le_bytes();
        let lb = bits.to_le_bytes();
        parts[0] = &ib;
        parts[1] = label;
        let n = ctx.len().min(5);
        parts[2..2 + n].copy_from_slice(&ctx[..n]);
        parts[2 + n] = &lb;
        let h = hmac_sha256(key, &parts[..3 + n]);
        let take = (out.len() - pos).min(32);
        out[pos..pos + take].copy_from_slice(&h[..take]);
        pos += take;
        i += 1;
    }
}

fn max_min(a: &[u8; 6], b: &[u8; 6]) -> [u8; 12] {
    let mut o = [0u8; 12];
    let (hi, lo) = if a > b { (a, b) } else { (b, a) };
    o[..6].copy_from_slice(hi);
    o[6..].copy_from_slice(lo);
    o
}

/// Hunting-and-pecking PWE for P-256 (§12.4.4.2.2). `None` only if no candidate within 200 iterations (never in practice).
pub fn pwe_hnp(password: &[u8], a: &[u8; 6], b: &[u8; 6]) -> Option<ProjectivePoint> {
    if password.is_empty() || password.len() > 128 {
        return None;
    }
    let key = max_min(a, b);
    let mut stub = [0u8; 128];
    // a fixed, password-independent stub keeps the post-hit iterations the same shape (the value never matters)
    for (i, s) in stub.iter_mut().enumerate() {
        *s = (i as u8).wrapping_mul(0x9d) ^ 0x5a;
    }
    let mut found = Choice::from(0);
    let mut x_sel = [0u8; 32];
    let mut odd_sel = Choice::from(0);
    let mut counter: u8 = 1;
    loop {
        let mut pw = [0u8; 128];
        for i in 0..password.len() {
            pw[i] = u8::conditional_select(&password[i], &stub[i], found);
        }
        let seed = hmac_sha256(&key, &[&pw[..password.len()], &[counter]]);
        let mut val = [0u8; 32];
        kdf_sha256(&seed, b"SAE Hunting and Pecking", &[&P_BE], &mut val);
        // in range (val < p) and x^3 - 3x + b a quadratic residue <=> the point decompresses
        let in_range = Choice::from(be_lt(&val, &P_BE) as u8);
        let fb = FieldBytes::from(val);
        let odd = Choice::from(seed[31] & 1);
        let cand = AffinePoint::decompress(&fb, odd);
        let ok = in_range & cand.is_some() & !found;
        for i in 0..32 {
            x_sel[i] = u8::conditional_select(&x_sel[i], &val[i], ok);
        }
        odd_sel = Choice::conditional_select(&odd_sel, &odd, ok);
        found |= ok;
        if counter >= K_ITER && bool::from(found) {
            break;
        }
        if counter == 200 {
            return None;
        }
        counter += 1;
    }
    // y with LSB(y) == LSB(pwd-seed): decompress picks exactly that parity
    let p: Option<AffinePoint> = AffinePoint::decompress(&FieldBytes::from(x_sel), odd_sel).into();
    p.map(ProjectivePoint::from)
}

fn be_lt(a: &[u8; 32], b: &[u8; 32]) -> bool {
    // constant-time big-endian a < b
    let ua = U256::from_be_slice(a);
    let ub = U256::from_be_slice(b);
    bool::from(ua.ct_lt(&ub))
}

// ---------------------------------------------------------------------------------------------------------------
// SAE hash-to-element (H2E, IEEE 802.11-2020 §12.4.4.2.3) — what current wpa_supplicant / phones use first (commit
// status 126). PT = SSWU(u1) + SSWU(u2) from HKDF(ssid, password [‖ identifier]); PWE = val · PT with
// val = HKDF-Extract(0^32, MAX(mac) ‖ MIN(mac)) mod (q − 1) + 1. Mirrors hostapd's sae_derive_pt_ecc / sswu.
// ---------------------------------------------------------------------------------------------------------------

fn hkdf_expand(prk: &[u8; 32], info: &[u8], out: &mut [u8]) {
    let mut t = [0u8; 32];
    let mut tl = 0usize;
    let mut pos = 0;
    let mut i = 1u8;
    while pos < out.len() {
        t = hmac_sha256(prk, &[&t[..tl], info, &[i]]);
        tl = 32;
        let n = (out.len() - pos).min(32);
        out[pos..pos + n].copy_from_slice(&t[..n]);
        pos += n;
        i += 1;
    }
}

/// 2^256 mod p (p = 2^256 - 2^224 + 2^192 + 2^96 - 1).
const R256_BE: [u8; 32] = [
    0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
];

fn fe(b: &[u8; 32]) -> FieldElement {
    // b < p by construction at every call site
    Option::from(FieldElement::from_repr(FieldBytes::from(*b))).unwrap_or(FieldElement::ZERO)
}

/// A 48-byte big-endian value reduced mod p: hi(16)·2^256 + lo(32).
fn reduce48(v: &[u8; 48]) -> FieldElement {
    let mut hi = [0u8; 32];
    hi[16..].copy_from_slice(&v[..16]);
    let mut lo = [0u8; 32];
    lo.copy_from_slice(&v[16..]);
    let lo_u = U256::from_be_slice(&lo);
    let p_u = U256::from_be_slice(&P_BE);
    let ge = !lo_u.ct_lt(&p_u);
    let red = lo_u.wrapping_sub(&p_u);
    let lo_sel = U256::conditional_select(&lo_u, &red, ge);
    let mut lb = [0u8; 32];
    lb.copy_from_slice(&lo_sel.to_be_bytes());
    fe(&hi) * fe(&R256_BE) + fe(&lb)
}

/// Simplified SWU for P-256 (z = -10), constant shape as hostapd's sswu().
fn sswu(u: &FieldElement) -> Option<ProjectivePoint> {
    let a = -FieldElement::from(3u64);
    let b = fe(&[
        0x5a, 0xc6, 0x35, 0xd8, 0xaa, 0x3a, 0x93, 0xe7, 0xb3, 0xeb, 0xbd, 0x55, 0x76, 0x98, 0x86, 0xbc, 0x65, 0x1d, 0x06, 0xb0,
        0xcc, 0x53, 0xb0, 0xf6, 0x3b, 0xce, 0x3c, 0x3e, 0x27, 0xd2, 0x60, 0x4b,
    ]);
    let z = -FieldElement::from(10u64);
    let u2 = u.square();
    let t1 = z * u2;
    let m = t1.square() + t1;
    let m_zero = m.is_zero();
    let t = Option::<FieldElement>::from(m.invert()).unwrap_or(FieldElement::ZERO);
    let x1a = b * Option::<FieldElement>::from((z * a).invert())?;
    let x1b = (-b) * Option::<FieldElement>::from(a.invert())? * (FieldElement::ONE + t);
    let x1 = FieldElement::conditional_select(&x1b, &x1a, m_zero);
    let gx1 = x1.square() * x1 + a * x1 + b;
    let x2 = z * u2 * x1;
    let gx2 = x2.square() * x2 + a * x2 + b;
    let is_qr = gx1.sqrt().is_some();
    let v = FieldElement::conditional_select(&gx2, &gx1, is_qr);
    let x = FieldElement::conditional_select(&x2, &x1, is_qr);
    let y = Option::<FieldElement>::from(v.sqrt())?;
    let flip = !(u.is_odd().ct_eq(&y.is_odd()));
    let y = FieldElement::conditional_select(&y, &(-y), flip);
    let e = EncodedPoint::from_affine_coordinates(&x.to_repr(), &y.to_repr(), false);
    let p: Option<AffinePoint> = AffinePoint::from_sec1_point(&e).into();
    p.map(ProjectivePoint::from)
}

/// PT for (ssid, password [, identifier]) on group 19.
pub fn derive_pt(ssid: &[u8], password: &[u8], identifier: Option<&[u8]>) -> Option<ProjectivePoint> {
    let seed = match identifier {
        Some(id) => hmac_sha256(ssid, &[password, id]),
        None => hmac_sha256(ssid, &[password]),
    };
    let mut v = [0u8; 48];
    hkdf_expand(&seed, b"SAE Hash to Element u1 P1", &mut v);
    let p1 = sswu(&reduce48(&v))?;
    hkdf_expand(&seed, b"SAE Hash to Element u2 P2", &mut v);
    let p2 = sswu(&reduce48(&v))?;
    Some(p1 + p2)
}

/// PWE = val · PT, val = HKDF-Extract(0^32, MAX(a,b) ‖ MIN(a,b)) mod (q − 1) + 1.
pub fn pwe_from_pt(pt: &ProjectivePoint, a: &[u8; 6], b: &[u8; 6]) -> Option<ProjectivePoint> {
    let h = hmac_sha256(&[0u8; 32], &[&max_min(a, b)]);
    // q - 1
    let q_m1 = U256::from_be_hex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550");
    let hv = U256::from_be_slice(&h);
    let ge = !hv.ct_lt(&q_m1);
    let red = U256::conditional_select(&hv, &hv.wrapping_sub(&q_m1), ge).wrapping_add(&U256::ONE);
    let mut vb = [0u8; 32];
    vb.copy_from_slice(&red.to_be_bytes());
    let val = scalar_from_be(&vb)?;
    Some(pt * &val)
}

/// A 32-byte big-endian value as FieldBytes (p256 0.14 / hybrid-array: no `from_slice`).
fn fb32(b: &[u8]) -> FieldBytes {
    let mut a = [0u8; 32];
    a.copy_from_slice(&b[..32]);
    FieldBytes::from(a)
}

pub fn scalar_from_be(b: &[u8; 32]) -> Option<Scalar> {
    Option::from(Scalar::from_repr(FieldBytes::from(*b)))
}

pub fn encode_element(p: &ProjectivePoint) -> Option<[u8; 64]> {
    let e = p.to_affine().to_sec1_point(false);
    let (x, y) = (e.x()?, e.y()?);
    let mut o = [0u8; 64];
    o[..32].copy_from_slice(x);
    o[32..].copy_from_slice(y);
    Some(o)
}

pub fn decode_element(b: &[u8; 64]) -> Option<ProjectivePoint> {
    let (mut x, mut y) = ([0u8; 32], [0u8; 32]);
    x.copy_from_slice(&b[..32]);
    y.copy_from_slice(&b[32..]);
    let e = EncodedPoint::from_affine_coordinates(&FieldBytes::from(x), &FieldBytes::from(y), false);
    let a: Option<AffinePoint> = AffinePoint::from_sec1_point(&e).into();
    a.map(ProjectivePoint::from)
}


/// IEEE 802.11 PTK for an SHA-256 AKM (SAE, AKM 8; §12.7.1.7.2): KDF-SHA256(PMK, "Pairwise key expansion",
/// Min(AA,SPA) ‖ Max(AA,SPA) ‖ Min(ANonce,SNonce) ‖ Max(ANonce,SNonce)), 384 bits = KCK 16 ‖ KEK 16 ‖ TK 16 (CCMP).
pub fn ptk_sha256(pmk: &[u8; 32], aa: &[u8; 6], spa: &[u8; 6], anonce: &[u8; 32], snonce: &[u8; 32]) -> [u8; 48] {
    let (a1, a2) = if aa < spa { (aa, spa) } else { (spa, aa) };
    let (n1, n2) = if anonce < snonce { (anonce, snonce) } else { (snonce, anonce) };
    let mut out = [0u8; 48];
    kdf_sha256(pmk, b"Pairwise key expansion", &[a1, a2, n1, n2], &mut out);
    out
}

/// AES-128-CMAC (RFC 4493) over `msg` with a caller-supplied block cipher (`enc` encrypts one block in place under
/// the key) — the EAPOL-Key MIC for key-descriptor version 0 with AKM 8 (SAE).
pub fn aes_cmac(enc: &dyn Fn(&mut [u8; 16]), msg: &[u8]) -> [u8; 16] {
    fn dbl(b: &[u8; 16]) -> [u8; 16] {
        let mut o = [0u8; 16];
        for i in 0..16 {
            o[i] = (b[i] << 1) | if i < 15 { b[i + 1] >> 7 } else { 0 };
        }
        if b[0] & 0x80 != 0 {
            o[15] ^= 0x87;
        }
        o
    }
    let mut l = [0u8; 16];
    enc(&mut l);
    let k1 = dbl(&l);
    let k2 = dbl(&k1);
    let n = if msg.is_empty() { 1 } else { msg.len().div_ceil(16) };
    let complete = !msg.is_empty() && msg.len() % 16 == 0;
    let mut x = [0u8; 16];
    for i in 0..n {
        let mut blk = [0u8; 16];
        let start = i * 16;
        if i + 1 < n {
            blk.copy_from_slice(&msg[start..start + 16]);
        } else {
            let rem = &msg[start.min(msg.len())..];
            blk[..rem.len()].copy_from_slice(rem);
            if complete {
                for j in 0..16 {
                    blk[j] ^= k1[j];
                }
            } else {
                blk[rem.len()] = 0x80;
                for j in 0..16 {
                    blk[j] ^= k2[j];
                }
            }
        }
        for j in 0..16 {
            x[j] ^= blk[j];
        }
        enc(&mut x);
    }
    x
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SaeErr {
    /// Unsupported finite cyclic group (answer with status 77).
    Group,
    /// Malformed / out-of-range / reflected commit (silently drop or status 1).
    BadCommit,
    /// K is the point at infinity.
    Identity,
    /// The peer's confirm does not verify (drop).
    BadConfirm,
    NoPwe,
}

/// One SAE exchange, AP side.
pub struct Sae {
    pwe: ProjectivePoint,
    rand: Scalar,
    pub own_scalar: [u8; 32],
    pub own_element: [u8; 64],
    peer_scalar: [u8; 32],
    peer_element: [u8; 64],
    kck: [u8; 32],
    pub pmk: [u8; 32],
    pub pmkid: [u8; 16],
    pub send_confirm: u16,
    pub h2e: bool,
    /// H2E keyseed salt = the peer's Rejected Groups list (empty: 32 zero bytes).
    salt: [u8; 32],
    salt_len: usize,
}

impl Sae {
    /// Prepare our commit: `rand`, `mask` are 32 random bytes each (reduced, retried by the caller if they give
    /// a zero / one scalar — §12.4.5.2: 1 < rand, mask < r, and the commit scalar must be > 1).
    pub fn new(password: &[u8], own: &[u8; 6], peer: &[u8; 6], rand_b: &[u8; 32], mask_b: &[u8; 32]) -> Result<Sae, SaeErr> {
        let pwe = pwe_hnp(password, own, peer).ok_or(SaeErr::NoPwe)?;
        Sae::with_pwe(pwe, rand_b, mask_b)
    }

    /// H2E: our side from a precomputed PT.
    pub fn new_h2e(pt: &ProjectivePoint, own: &[u8; 6], peer: &[u8; 6], rand_b: &[u8; 32], mask_b: &[u8; 32]) -> Result<Sae, SaeErr> {
        let pwe = pwe_from_pt(pt, own, peer).ok_or(SaeErr::NoPwe)?;
        let mut s = Sae::with_pwe(pwe, rand_b, mask_b)?;
        s.h2e = true;
        Ok(s)
    }

    fn with_pwe(pwe: ProjectivePoint, rand_b: &[u8; 32], mask_b: &[u8; 32]) -> Result<Sae, SaeErr> {
        let rand = <Scalar as Reduce<FieldBytes>>::reduce(&fb32(rand_b));
        let mask = <Scalar as Reduce<FieldBytes>>::reduce(&fb32(mask_b));
        let one = Scalar::ONE;
        let commit = rand + mask;
        if bool::from(rand.is_zero() | mask.is_zero() | commit.is_zero()) || rand == one || mask == one || commit == one {
            return Err(SaeErr::BadCommit);
        }
        let elem = -(pwe * mask);
        let own_element = encode_element(&elem).ok_or(SaeErr::BadCommit)?;
        let mut own_scalar = [0u8; 32];
        own_scalar.copy_from_slice(&commit.to_repr());
        Ok(Sae { pwe, rand, own_scalar, own_element, peer_scalar: [0; 32], peer_element: [0; 64], kck: [0; 32], pmk: [0; 32], pmkid: [0; 16], send_confirm: 0, h2e: false, salt: [0; 32], salt_len: 0 })
    }

    /// Process the peer's commit (scalar ‖ element, group already checked): derive K, KCK, PMK, PMKID.
    pub fn process_commit(&mut self, scalar: &[u8; 32], element: &[u8; 64]) -> Result<(), SaeErr> {
        // §12.4.5.4: 1 < scalar < r, element on the curve, and not a reflection of our own commit
        let s = scalar_from_be(scalar).ok_or(SaeErr::BadCommit)?;
        if bool::from(s.is_zero()) || s == Scalar::ONE {
            return Err(SaeErr::BadCommit);
        }
        let e = decode_element(element).ok_or(SaeErr::BadCommit)?;
        if bool::from(scalar.ct_eq(&self.own_scalar) & element.ct_eq(&self.own_element)) {
            return Err(SaeErr::BadCommit);
        }
        let k = (self.pwe * s + e) * self.rand;
        if bool::from(k.ct_eq(&ProjectivePoint::IDENTITY)) {
            return Err(SaeErr::Identity);
        }
        let kx = k.to_affine().x();
        let keyseed = if self.h2e && self.salt_len > 0 { hmac_sha256(&self.salt[..self.salt_len], &[&kx]) } else { hmac_sha256(&[0u8; 32], &[&kx]) };
        let own = scalar_from_be(&self.own_scalar).ok_or(SaeErr::BadCommit)?;
        let sum = (own + s).to_repr();
        let mut keys = [0u8; 64];
        kdf_sha256(&keyseed, b"SAE KCK and PMK", &[&sum], &mut keys);
        self.kck.copy_from_slice(&keys[..32]);
        self.pmk.copy_from_slice(&keys[32..]);
        self.pmkid.copy_from_slice(&sum[..16]);
        self.peer_scalar = *scalar;
        self.peer_element = *element;
        Ok(())
    }

    /// H2E: the peer's Rejected Groups (the u16 list as sent) — the keyseed salt.
    pub fn set_rejected_groups(&mut self, list: &[u8]) {
        let n = list.len().min(32);
        self.salt[..n].copy_from_slice(&list[..n]);
        self.salt_len = n;
    }

    /// Our confirm (send-confirm ‖ confirm) — the counter advances each call (§12.4.8.6.6).
    pub fn confirm(&mut self) -> (u16, [u8; 32]) {
        if self.send_confirm < 0xffff {
            self.send_confirm += 1;
        }
        let sc = self.send_confirm.to_le_bytes();
        (self.send_confirm, hmac_sha256(&self.kck, &[&sc, &self.own_scalar, &self.own_element, &self.peer_scalar, &self.peer_element]))
    }

    /// Verify the peer's confirm (peer-send-confirm ‖ confirm).
    pub fn check_confirm(&self, peer_sc: u16, confirm: &[u8; 32]) -> Result<(), SaeErr> {
        let sc = peer_sc.to_le_bytes();
        let want = hmac_sha256(&self.kck, &[&sc, &self.peer_scalar, &self.peer_element, &self.own_scalar, &self.own_element]);
        if bool::from(want.ct_eq(confirm)) { Ok(()) } else { Err(SaeErr::BadConfirm) }
    }
}

// ---------------------------------------------------------------------------------------------------------------
// The AP-side responder over 802.11 Authentication frame BODIES (alg 3 = SAE): a small table of peers.
// ---------------------------------------------------------------------------------------------------------------

pub const AUTH_ALG_SAE: u16 = 3;
pub const ST_SUCCESS: u16 = 0;
pub const ST_UNSPECIFIED: u16 = 1;
pub const ST_UNSUPPORTED_GROUP: u16 = 77;
/// SAE-H2E commit (status 126): not offered by this AP (no RSNXE H2E bit), answered "unsupported group" + 19.
pub const ST_SAE_HASH_TO_ELEMENT: u16 = 126;
pub const PEERS: usize = 8;
/// A peer whose exchange stalls is forgotten after this long (also the Accepted PMK lifetime for the 4-way).
pub const PEER_TTL_MS: u64 = 30_000;

/// An Authentication frame body to send: alg 3 ‖ seq ‖ status ‖ payload.
#[derive(Clone, Copy)]
pub struct Out {
    pub body: [u8; 6 + 2 + 32 + 64],
    pub len: usize,
}
impl Out {
    fn new(seq: u16, status: u16) -> Out {
        let mut o = Out { body: [0; 104], len: 6 };
        o.body[0..2].copy_from_slice(&AUTH_ALG_SAE.to_le_bytes());
        o.body[2..4].copy_from_slice(&seq.to_le_bytes());
        o.body[4..6].copy_from_slice(&status.to_le_bytes());
        o
    }
    fn put(&mut self, b: &[u8]) {
        self.body[self.len..self.len + b.len()].copy_from_slice(b);
        self.len += b.len();
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Event {
    None,
    /// Dropped silently (malformed, reflected, unknown peer's confirm, table full, bad confirm).
    Dropped(&'static str),
    /// Our commit went out (the peer's commit was valid).
    Committed,
    /// Confirm verified; our confirm went out; `pmk` is ready for the 4-way handshake.
    Accepted,
    /// Refused with a status (unsupported group, H2E).
    Refused(u16),
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum St {
    Free,
    Committed,
    Accepted,
}

struct Peer {
    mac: [u8; 6],
    st: St,
    t_ms: u64,
    sae: Option<Sae>,
}

pub struct SaeAp {
    peers: [Peer; PEERS],
}

impl SaeAp {
    pub const fn new() -> SaeAp {
        const P: Peer = Peer { mac: [0; 6], st: St::Free, t_ms: 0, sae: None };
        SaeAp { peers: [P; PEERS] }
    }

    fn slot(&mut self, mac: &[u8; 6], now: u64, create: bool) -> Option<usize> {
        for (i, p) in self.peers.iter_mut().enumerate() {
            if p.st != St::Free && now.saturating_sub(p.t_ms) > PEER_TTL_MS {
                p.st = St::Free;
                p.sae = None;
            }
            let _ = i;
        }
        if let Some(i) = self.peers.iter().position(|p| p.st != St::Free && p.mac == *mac) {
            return Some(i);
        }
        if !create {
            return None;
        }
        let i = self.peers.iter().position(|p| p.st == St::Free)?;
        self.peers[i].mac = *mac;
        self.peers[i].t_ms = now;
        Some(i)
    }

    /// The PMK of a peer that completed SAE (Accepted) within the TTL — what the 4-way uses (AKM 8).
    pub fn pmk_for(&mut self, mac: &[u8; 6], now: u64) -> Option<[u8; 32]> {
        let i = self.slot(mac, now, false)?;
        let p = &self.peers[i];
        if p.st == St::Accepted { p.sae.as_ref().map(|s| s.pmk) } else { None }
    }

    /// The PMKID of a peer that completed SAE (for the firmware's `auth_status`).
    pub fn pmkid_for(&mut self, mac: &[u8; 6], now: u64) -> Option<[u8; 16]> {
        let i = self.slot(mac, now, false)?;
        let p = &self.peers[i];
        if p.st == St::Accepted { p.sae.as_ref().map(|s| s.pmkid) } else { None }
    }

    /// Forget a peer (it left / its 4-way finished).
    pub fn forget(&mut self, mac: &[u8; 6]) {
        for p in self.peers.iter_mut() {
            if p.mac == *mac {
                p.st = St::Free;
                p.sae = None;
            }
        }
    }

    /// Forget every peer (the BSS is re-started with new settings).
    pub fn forget_all(&mut self) {
        for p in self.peers.iter_mut() {
            p.st = St::Free;
            p.sae = None;
        }
    }

    pub fn active(&self) -> usize {
        self.peers.iter().filter(|p| p.st != St::Free).count()
    }

    /// One received SAE Authentication frame body from `peer` (we are `own`), walked in-kernel by `hal::saewire`
    /// then answered by `on_msg` — the host-test / fallback entry. The AP's live path walks the body in el0-lansvc
    /// (ADR 0050 D4 step 5c) and calls `on_msg` with the checked record.
    pub fn on_frame(
        &mut self,
        now: u64,
        own: &[u8; 6],
        peer: &[u8; 6],
        pt: Option<&ProjectivePoint>,
        password: &[u8],
        body: &[u8],
        rnd: &mut dyn FnMut() -> Option<[u8; 32]>,
        out: &mut [Option<Out>; 2],
    ) -> Event {
        let m = hal::saewire::parse(body, pt.is_some());
        self.on_msg(now, own, peer, pt, password, &m, rnd, out)
    }

    /// One checked SAE frame (`hal::saewire::Msg`) from `peer`. `rnd` yields 32 random bytes (fail-closed: `None`
    /// drops the frame). Returns what happened and the frame(s) to send. Every secret (password, PWE / PT, rand,
    /// KCK, PMK) stays here; the peer scalar and element are re-validated by the curve library before use.
    pub fn on_msg(
        &mut self,
        now: u64,
        own: &[u8; 6],
        peer: &[u8; 6],
        pt: Option<&ProjectivePoint>,
        password: &[u8],
        m: &hal::saewire::Msg,
        rnd: &mut dyn FnMut() -> Option<[u8; 32]>,
        out: &mut [Option<Out>; 2],
    ) -> Event {
        use hal::saewire as w;
        out[0] = None;
        out[1] = None;
        match m.kind {
            w::K_REFUSE_GROUP => {
                let mut o = Out::new(1, ST_UNSUPPORTED_GROUP);
                o.put(&GROUP_P256.to_le_bytes());
                out[0] = Some(o);
                Event::Refused(ST_UNSUPPORTED_GROUP)
            }
            w::K_COMMIT => {
                let h2e = m.h2e;
                if h2e && pt.is_none() {
                    // re-checked here: H2E only when this AP offers it
                    let mut o = Out::new(1, ST_UNSUPPORTED_GROUP);
                    o.put(&GROUP_P256.to_le_bytes());
                    out[0] = Some(o);
                    return Event::Refused(ST_UNSUPPORTED_GROUP);
                }
                let rej_len = (m.rej_len as usize).min(32);
                let rejected = m.rej;
                let sc = m.scalar;
                let el = m.element;
                let Some(i) = self.slot(peer, now, true) else { return Event::Dropped("peer table full") };
                // a retransmitted commit in Committed resends our commit (same values); a new one restarts
                if self.peers[i].st == St::Committed {
                    if let Some(s) = self.peers[i].sae.as_ref() {
                        if s.peer_scalar == sc && s.peer_element == el {
                            let mut o = Out::new(1, if s.h2e { ST_SAE_HASH_TO_ELEMENT } else { ST_SUCCESS });
                            o.put(&GROUP_P256.to_le_bytes());
                            o.put(&s.own_scalar);
                            o.put(&s.own_element);
                            out[0] = Some(o);
                            return Event::Committed;
                        }
                    }
                }
                let mut sae = None;
                for _ in 0..4 {
                    let (Some(r), Some(mk)) = (rnd(), rnd()) else { return Event::Dropped("no entropy") };
                    let made = match (h2e, pt) {
                        (true, Some(p)) => Sae::new_h2e(p, own, peer, &r, &mk),
                        _ => Sae::new(password, own, peer, &r, &mk),
                    };
                    match made {
                        Ok(s) => {
                            sae = Some(s);
                            break;
                        }
                        Err(SaeErr::BadCommit) => continue,
                        Err(_) => return Event::Dropped("no PWE"),
                    }
                }
                let Some(mut s) = sae else { return Event::Dropped("rand") };
                if rej_len > 0 {
                    s.set_rejected_groups(&rejected[..rej_len]);
                }
                if s.process_commit(&sc, &el).is_err() {
                    self.peers[i].st = St::Free;
                    return Event::Dropped("bad peer commit");
                }
                let mut o = Out::new(1, if h2e { ST_SAE_HASH_TO_ELEMENT } else { ST_SUCCESS });
                o.put(&GROUP_P256.to_le_bytes());
                o.put(&s.own_scalar);
                o.put(&s.own_element);
                out[0] = Some(o);
                let Some(i) = self.slot(peer, now, true) else { return Event::Dropped("peer table full") };
                self.peers[i].sae = Some(s);
                self.peers[i].st = St::Committed;
                self.peers[i].t_ms = now;
                Event::Committed
            }
            w::K_CONFIRM => {
                let Some(i) = self.slot(peer, now, false) else { return Event::Dropped("confirm from an unknown peer") };
                let psc = m.send_confirm;
                let c = m.confirm;
                let p = &mut self.peers[i];
                let Some(s) = p.sae.as_mut() else { return Event::Dropped("no state") };
                if s.check_confirm(psc, &c).is_err() {
                    // wrong password (or forged): forget the peer, never answer
                    p.st = St::Free;
                    p.sae = None;
                    return Event::Dropped("confirm does not verify");
                }
                let (sc, conf) = s.confirm();
                let mut o = Out::new(2, ST_SUCCESS);
                o.put(&sc.to_le_bytes());
                o.put(&conf);
                out[0] = Some(o);
                p.st = St::Accepted;
                p.t_ms = now;
                Event::Accepted
            }
            _ => Event::Dropped(w::reason(m.reason)),
        }
    }
}

fn unhex<const N: usize>(h: &str) -> [u8; N] {
    let b = h.as_bytes();
    let mut o = [0u8; N];
    let v = |c: u8| match c { b'0'..=b'9' => c - b'0', b'a'..=b'f' => c - b'a' + 10, _ => 0 };
    for i in 0..N {
        o[i] = v(b[2 * i]) << 4 | v(b[2 * i + 1]);
    }
    o
}

/// Known-answer self-test for the kernel (`[P-sae]`): (Annex J.10 commit + KCK/PMK/PMKID, responder end to end
/// incl. wrong-password drop, PTK-SHA256 = hostapd's sha256_prf, H2E PWE = the Annex J.10 H2E vector).
pub fn selftest() -> (bool, bool, bool, bool) {
    let a1 = [0x4d, 0x3f, 0x2f, 0xff, 0xe3, 0x87];
    let a2 = [0xa5, 0xd8, 0xaa, 0x95, 0x8e, 0x3c];
    let j10 = (|| {
        let mut s = Sae::new(b"mekmitasdigoat", &a1, &a2, &unhex("992465fd3daa3c60aa6565b7f62a2a7f2e12dd12f198faf4fbed89d7ff1ace94"),
            &unhex("9507a90f777a044d6a0830b91ea3d5dd70bece44e1acffb86983b5e1bf9fb322")).ok()?;
        let ok_commit = s.own_scalar == unhex::<32>("2e2c0f0db52440ad146d967114ce005ce1eab0aa2c2e5c2871b774f6c2575c65")
            && s.own_element == unhex::<64>("d5ad9e00829707aa36ba8b859738fc961d08243505f47c035376d7ac4bc8d7b95083bf43827d0fc31ed778dd3671fd21a46d1091d64b6f9a1e1272621325dbe1");
        s.process_commit(&unhex("591b96f3397fb945100848e7b550543b6720d88337ee93fc49fd6df7e08b5223"),
            &unhex("e71b9bb048d3873f20556953a96c91536fd8ee6ca9b4a68a148b056a909be03e83ae208f60f8ef5537858074db06687032399862999b511e0a1552a5fea317c2")).ok()?;
        Some(ok_commit && s.kck == unhex::<32>("1e733f6d9bd53256287304338831b09a39406d121017073a5c30db36f36cb81a")
            && s.pmk == unhex::<32>("4e4dfab1a2dd8ac1a91790f953faaa452ae5c6873ab75b63605ba663f8a7fe59")
            && s.pmkid == unhex::<16>("8747a600eea3f9f22475df58ca1e5498"))
    })().unwrap_or(false);
    let e2e = (|| {
        let ap = [0x76u8, 0x0d, 0x02, 0xf8, 0xd2, 0xda];
        let sta = [0xa8u8, 0x29, 0x48, 0x33, 0x73, 0x52];
        let mut tab = SaeAp::new();
        let mut ctr = 0u8;
        let mut rnd = || { ctr = ctr.wrapping_add(1); Some([ctr; 32]) };
        let mut st = Sae::new(b"bench passphrase", &sta, &ap, &[0x31; 32], &[0x47; 32]).ok()?;
        let mut c = [0u8; 104];
        c[0] = 3; c[2] = 1; c[6] = 19;
        c[8..40].copy_from_slice(&st.own_scalar);
        c[40..104].copy_from_slice(&st.own_element);
        let mut out = [None, None];
        if tab.on_frame(0, &ap, &sta, None, b"bench passphrase", &c, &mut rnd, &mut out) != Event::Committed { return None; }
        let a = out[0]?;
        st.process_commit(a.body[8..40].try_into().ok()?, a.body[40..104].try_into().ok()?).ok()?;
        let (sc, cf) = st.confirm();
        let mut k = [0u8; 40];
        k[0] = 3; k[2] = 2;
        k[6..8].copy_from_slice(&sc.to_le_bytes());
        k[8..40].copy_from_slice(&cf);
        if tab.on_frame(1, &ap, &sta, None, b"bench passphrase", &k, &mut rnd, &mut out) != Event::Accepted { return None; }
        let r = out[0]?;
        st.check_confirm(u16::from_le_bytes([r.body[6], r.body[7]]), r.body[8..40].try_into().ok()?).ok()?;
        let agreed = tab.pmk_for(&sta, 2) == Some(st.pmk);
        // wrong password: the confirm is dropped, never answered, no PMK
        let mut bad = Sae::new(b"wrong passphrase", &sta, &ap, &[0x31; 32], &[0x47; 32]).ok()?;
        c[8..40].copy_from_slice(&bad.own_scalar);
        c[40..104].copy_from_slice(&bad.own_element);
        tab.on_frame(100_000, &ap, &sta, None, b"bench passphrase", &c, &mut rnd, &mut out);
        let a = out[0]?;
        bad.process_commit(a.body[8..40].try_into().ok()?, a.body[40..104].try_into().ok()?).ok()?;
        let (sc, cf) = bad.confirm();
        k[6..8].copy_from_slice(&sc.to_le_bytes());
        k[8..40].copy_from_slice(&cf);
        let refused = matches!(tab.on_frame(100_001, &ap, &sta, None, b"bench passphrase", &k, &mut rnd, &mut out), Event::Dropped(_))
            && out[0].is_none() && tab.pmk_for(&sta, 100_002).is_none();
        Some(agreed && refused)
    })().unwrap_or(false);
    let mut pmk = [0u8; 32];
    for (i, b) in pmk.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(7).wrapping_add(1);
    }
    let ptk = ptk_sha256(&pmk, &[2, 0, 0, 0, 0, 2], &[2, 0, 0, 0, 0, 1], &[0x22; 32], &[0x11; 32])
        == unhex::<48>("cf21e9431a8dcc0ad82d9d24d5cc78ae09fdc8c229a8dab15b01b77837462e7844590a2f8762bfccbb930287a8342347");
    let h2e = derive_pt(b"byteme", b"mekmitasdigoat", Some(b"psk4internet"))
        .and_then(|pt| pwe_from_pt(&pt, &[0x00, 0x09, 0x5b, 0x66, 0xec, 0x1e], &[0x00, 0x0b, 0x6b, 0xd9, 0x02, 0x46]))
        .and_then(|p| encode_element(&p))
        .is_some_and(|e| e == unhex::<64>("c93049b9e64000f848201649e999f2b5c22dea69b5632c9df4d633b8aa1f6c1e73634e94b53d82e7383a8d258199d9dc1a5ee8269d060382ccbf33e614ff59a0"));
    (j10, e2e, ptk, h2e)
}

/// ADR 0050 D4 step 5c (`[P-sae]`): the curve-library-free station-frame checks in `hal::saewire` (what el0-lansvc
/// runs) agree with this crate's own: element on the curve <=> `decode_element`, scalar in range <=> `scalar_from_be`
/// and not 0 / 1, over real commit elements and corrupted ones; malformed commits (another group, scalar = r, element
/// off the curve, truncated, oversized) are refused and leave no peer state.
pub fn wire_selftest() -> bool {
    use hal::saewire as w;
    let (a, b) = ([2u8, 0, 0, 0, 0, 1], [2u8, 0, 0, 0, 0, 2]);
    let mut ok = true;
    for k in 1..4u8 {
        let Ok(s) = Sae::new(b"wire selftest", &a, &b, &[k.wrapping_mul(17).wrapping_add(3); 32], &[k.wrapping_mul(29).wrapping_add(5); 32]) else { return false };
        let mut e = s.own_element;
        ok &= w::on_curve(&e) && decode_element(&e).is_some();
        e[(k as usize * 13) % 64] ^= 1 << k;
        ok &= w::on_curve(&e) == decode_element(&e).is_some();
        let sc = s.own_scalar;
        let lib = |x: &[u8; 32]| scalar_from_be(x).is_some_and(|v| !bool::from(v.is_zero()) && v != Scalar::ONE);
        ok &= w::scalar_in_range(&sc) == lib(&sc);
        let mut one = [0u8; 32];
        one[31] = 1;
        ok &= !w::scalar_in_range(&one) && !lib(&one) && !w::scalar_in_range(&[0xff; 32]) && !lib(&[0xff; 32]);
    }
    let Ok(st) = Sae::new(b"wire selftest", &b, &a, &[0x31; 32], &[0x47; 32]) else { return false };
    let mut c = [0u8; 104];
    c[0] = 3;
    c[2] = 1;
    c[6] = 19;
    c[8..40].copy_from_slice(&st.own_scalar);
    c[40..104].copy_from_slice(&st.own_element);
    let mut tab = SaeAp::new();
    let mut ctr = 0u8;
    let mut rnd = || {
        ctr = ctr.wrapping_add(1);
        Some([ctr; 32])
    };
    let mut out = [None, None];
    let mut refused = |body: &[u8], tab: &mut SaeAp| -> bool {
        let e = tab.on_frame(0, &a, &b, None, b"wire selftest", body, &mut rnd, &mut out);
        matches!(e, Event::Dropped(_) | Event::Refused(_)) && tab.active() == 0
    };
    let mut g = c;
    g[6] = 20;
    let mut sr = c;
    sr[8..40].copy_from_slice(&[0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51]);
    let mut eo = c;
    eo[103] ^= 1;
    let mut big = [0u8; 2100];
    big[..104].copy_from_slice(&c);
    ok &= refused(&g, &mut tab) && refused(&sr, &mut tab) && refused(&eo, &mut tab) && refused(&c[..90], &mut tab) && refused(&big, &mut tab);
    ok && w::parse(&c, false).kind == w::K_COMMIT
}

#[cfg(test)]
mod tests {
    #[test]
    fn pmksa_cache() {
        assert!(super::pmksa_selftest());
    }
    use super::*;
    fn hx(s: &str) -> [u8; 32] {
        let mut o = [0u8; 32];
        for i in 0..32 {
            o[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
        }
        o
    }
    // IEEE Std 802.11-2020 Annex J.10 (hostapd common_module_tests.c sae_tests)
    const A1: [u8; 6] = [0x4d, 0x3f, 0x2f, 0xff, 0xe3, 0x87];
    const A2: [u8; 6] = [0xa5, 0xd8, 0xaa, 0x95, 0x8e, 0x3c];
    #[test]
    fn kernel_selftest() {
        assert_eq!(selftest(), (true, true, true, true));
        assert!(wire_selftest());
    }
    #[test]
    fn annex_j10() {
        let rand = hx("992465fd3daa3c60aa6565b7f62a2a7f2e12dd12f198faf4fbed89d7ff1ace94");
        let mask = hx("9507a90f777a044d6a0830b91ea3d5dd70bece44e1acffb86983b5e1bf9fb322");
        let mut s = Sae::new(b"mekmitasdigoat", &A1, &A2, &rand, &mask).unwrap();
        // local commit = group(1300) ‖ scalar ‖ element
        assert_eq!(s.own_scalar, hx("2e2c0f0db52440ad146d967114ce005ce1eab0aa2c2e5c2871b774f6c2575c65"));
        assert_eq!(&s.own_element[..32], &hx("d5ad9e00829707aa36ba8b859738fc961d08243505f47c035376d7ac4bc8d7b9"));
        assert_eq!(&s.own_element[32..], &hx("5083bf43827d0fc31ed778dd3671fd21a46d1091d64b6f9a1e1272621325dbe1"));
        let ps = hx("591b96f3397fb945100848e7b550543b6720d88337ee93fc49fd6df7e08b5223");
        let mut pe = [0u8; 64];
        pe[..32].copy_from_slice(&hx("e71b9bb048d3873f20556953a96c91536fd8ee6ca9b4a68a148b056a909be03e"));
        pe[32..].copy_from_slice(&hx("83ae208f60f8ef5537858074db06687032399862999b511e0a1552a5fea317c2"));
        s.process_commit(&ps, &pe).unwrap();
        assert_eq!(s.kck, hx("1e733f6d9bd53256287304338831b09a39406d121017073a5c30db36f36cb81a"));
        assert_eq!(s.pmk, hx("4e4dfab1a2dd8ac1a91790f953faaa452ae5c6873ab75b63605ba663f8a7fe59"));
        assert_eq!(&s.pmkid[..], &hx("8747a600eea3f9f22475df58ca1e549800000000000000000000000000000000")[..16]);
    }

    #[test]
    fn cmac_rfc4493() {
        use aes::cipher::{BlockEncrypt, KeyInit};
        let key = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c];
        let c = aes::Aes128::new(&key.into());
        let enc = |b: &mut [u8; 16]| c.encrypt_block(b.into());
        let m: [u8; 64] = {
            let h = "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710";
            let mut o = [0u8; 64];
            for i in 0..64 { o[i] = u8::from_str_radix(&h[i * 2..i * 2 + 2], 16).unwrap(); }
            o
        };
        let t = |n: usize, want: &str| {
            let got = aes_cmac(&enc, &m[..n]);
            let mut w = [0u8; 16];
            for i in 0..16 { w[i] = u8::from_str_radix(&want[i * 2..i * 2 + 2], 16).unwrap(); }
            assert_eq!(got, w, "len {}", n);
        };
        t(0, "bb1d6929e95937287fa37d129b756746");
        t(16, "070a16b46b4d4144f79bdd9dd04a287c");
        t(40, "dfa66747de9ae63030ca32611497c827");
        t(64, "51f0bebf7e3b9d92fc49741779363cfe");
    }
    #[test]
    fn ptk_sha256_matches_hostapd() {
        // reference computed by hostapd 2.11's own sha256_prf (src/crypto/sha256-prf.c) on the same inputs
        let mut pmk = [0u8; 32];
        for i in 0..32 { pmk[i] = (i as u8).wrapping_mul(7).wrapping_add(1); }
        let p = ptk_sha256(&pmk, &[2, 0, 0, 0, 0, 2], &[2, 0, 0, 0, 0, 1], &[0x22; 32], &[0x11; 32]);
        let want = "cf21e9431a8dcc0ad82d9d24d5cc78ae09fdc8c229a8dab15b01b77837462e7844590a2f8762bfccbb930287a8342347";
        let mut w = [0u8; 48];
        for i in 0..48 { w[i] = u8::from_str_radix(&want[i * 2..i * 2 + 2], 16).unwrap(); }
        assert_eq!(p, w);
    }
    #[test]
    fn ap_responder_end_to_end() {
        let ap = [0x76u8, 0x0d, 0x02, 0xf8, 0xd2, 0xda];
        let sta = [0xa8u8, 0x29, 0x48, 0x33, 0x73, 0x52];
        let mut tab = SaeAp::new();
        let mut ctr = 0u8;
        let mut rnd = || { ctr = ctr.wrapping_add(1); Some([ctr; 32]) };
        // the station side (a plain Sae with its own randomness)
        let mut st = Sae::new(b"bench passphrase", &sta, &ap, &[0x31; 32], &[0x47; 32]).unwrap();
        let mut commit = [0u8; 104];
        commit[0..2].copy_from_slice(&3u16.to_le_bytes());
        commit[2..4].copy_from_slice(&1u16.to_le_bytes());
        commit[6..8].copy_from_slice(&19u16.to_le_bytes());
        commit[8..40].copy_from_slice(&st.own_scalar);
        commit[40..104].copy_from_slice(&st.own_element);
        let mut out = [None, None];
        assert_eq!(tab.on_frame(0, &ap, &sta, None, b"bench passphrase", &commit, &mut rnd, &mut out), Event::Committed);
        let ac = out[0].unwrap();
        assert_eq!(ac.len, 104);
        let mut ps = [0u8; 32]; ps.copy_from_slice(&ac.body[8..40]);
        let mut pe = [0u8; 64]; pe.copy_from_slice(&ac.body[40..104]);
        // a retransmitted commit gets the same commit back
        assert_eq!(tab.on_frame(5, &ap, &sta, None, b"bench passphrase", &commit, &mut rnd, &mut out), Event::Committed);
        assert_eq!(&out[0].unwrap().body[8..40], &ps[..]);
        st.process_commit(&ps, &pe).unwrap();
        let (sc, c) = st.confirm();
        let mut conf = [0u8; 40];
        conf[0..2].copy_from_slice(&3u16.to_le_bytes());
        conf[2..4].copy_from_slice(&2u16.to_le_bytes());
        conf[6..8].copy_from_slice(&sc.to_le_bytes());
        conf[8..40].copy_from_slice(&c);
        assert_eq!(tab.on_frame(10, &ap, &sta, None, b"bench passphrase", &conf, &mut rnd, &mut out), Event::Accepted);
        let ar = out[0].unwrap();
        let apsc = u16::from_le_bytes([ar.body[6], ar.body[7]]);
        let mut apc = [0u8; 32]; apc.copy_from_slice(&ar.body[8..40]);
        assert!(st.check_confirm(apsc, &apc).is_ok());
        assert_eq!(tab.pmk_for(&sta, 20), Some(st.pmk));
        assert_eq!(tab.pmk_for(&sta, 20 + PEER_TTL_MS + 1), None);
        // wrong password: commit answered, confirm dropped, no PMK
        let mut bad = Sae::new(b"wrong passphrase", &sta, &ap, &[0x31; 32], &[0x47; 32]).unwrap();
        commit[8..40].copy_from_slice(&bad.own_scalar);
        commit[40..104].copy_from_slice(&bad.own_element);
        assert_eq!(tab.on_frame(100_000, &ap, &sta, None, b"bench passphrase", &commit, &mut rnd, &mut out), Event::Committed);
        let ac = out[0].unwrap();
        ps.copy_from_slice(&ac.body[8..40]); pe.copy_from_slice(&ac.body[40..104]);
        bad.process_commit(&ps, &pe).unwrap();
        let (sc, c) = bad.confirm();
        conf[6..8].copy_from_slice(&sc.to_le_bytes());
        conf[8..40].copy_from_slice(&c);
        assert!(matches!(tab.on_frame(100_010, &ap, &sta, None, b"bench passphrase", &conf, &mut rnd, &mut out), Event::Dropped(_)));
        assert!(out[0].is_none());
        assert_eq!(tab.pmk_for(&sta, 100_020), None);
        // another group / H2E: refused with 77 + our group
        commit[6..8].copy_from_slice(&20u16.to_le_bytes());
        assert_eq!(tab.on_frame(200_000, &ap, &sta, None, b"bench passphrase", &commit, &mut rnd, &mut out), Event::Refused(77));
        assert_eq!(&out[0].unwrap().body[4..8], &[77, 0, 19, 0]);
        // a confirm from a peer that never committed is dropped
        assert!(matches!(tab.on_frame(200_001, &ap, &[2, 2, 2, 2, 2, 2], None, b"x", &conf, &mut rnd, &mut out), Event::Dropped(_)));
    }
    #[test]
    fn h2e_pwe_vector() {
        // hostapd common_module_tests.c (IEEE 802.11-2020 Annex J.10 H2E): ssid byteme, pw mekmitasdigoat, id psk4internet
        let pt = derive_pt(b"byteme", b"mekmitasdigoat", Some(b"psk4internet")).unwrap();
        let pwe = pwe_from_pt(&pt, &[0x00, 0x09, 0x5b, 0x66, 0xec, 0x1e], &[0x00, 0x0b, 0x6b, 0xd9, 0x02, 0x46]).unwrap();
        let e = encode_element(&pwe).unwrap();
        assert_eq!(&e[..32], &hx("c93049b9e64000f848201649e999f2b5c22dea69b5632c9df4d633b8aa1f6c1e"));
        assert_eq!(&e[32..], &hx("73634e94b53d82e7383a8d258199d9dc1a5ee8269d060382ccbf33e614ff59a0"));
    }
    #[test]
    fn h2e_responder() {
        let ap = [0x76u8, 0x0d, 0x02, 0xf8, 0xd2, 0xda];
        let sta = [0xa8u8, 0x29, 0x48, 0x33, 0x73, 0x52];
        let pt = derive_pt(b"HookProbe-Setup", b"bench passphrase", None).unwrap();
        let mut tab = SaeAp::new();
        let mut ctr = 0u8;
        let mut rnd = || { ctr = ctr.wrapping_add(1); Some([ctr; 32]) };
        let mut st = Sae::new_h2e(&pt, &sta, &ap, &[0x31; 32], &[0x47; 32]).unwrap();
        // group 19 commit with status 126 and a Rejected Groups element naming group 20
        let mut c = [0u8; 109];
        c[0] = 3; c[2] = 1; c[4] = 126; c[6] = 19;
        c[8..40].copy_from_slice(&st.own_scalar);
        c[40..104].copy_from_slice(&st.own_element);
        c[104..109].copy_from_slice(&[255, 3, 92, 20, 0]);
        st.set_rejected_groups(&[20, 0]);
        let mut out = [None, None];
        assert_eq!(tab.on_frame(0, &ap, &sta, Some(&pt), b"bench passphrase", &c, &mut rnd, &mut out), Event::Committed);
        let a = out[0].unwrap();
        assert_eq!(u16::from_le_bytes([a.body[4], a.body[5]]), 126);
        st.process_commit(a.body[8..40].try_into().unwrap(), a.body[40..104].try_into().unwrap()).unwrap();
        let (sc, cf) = st.confirm();
        let mut k = [0u8; 40];
        k[0] = 3; k[2] = 2;
        k[6..8].copy_from_slice(&sc.to_le_bytes());
        k[8..40].copy_from_slice(&cf);
        assert_eq!(tab.on_frame(1, &ap, &sta, Some(&pt), b"bench passphrase", &k, &mut rnd, &mut out), Event::Accepted);
        assert_eq!(tab.pmk_for(&sta, 2), Some(st.pmk));
        // a forged rejection of group 19 (which we support) is refused
        c[104..109].copy_from_slice(&[255, 3, 92, 19, 0]);
        assert!(matches!(tab.on_frame(50_000, &ap, &[2, 0, 0, 0, 0, 9], Some(&pt), b"bench passphrase", &c, &mut rnd, &mut out), Event::Dropped(_)));
    }
    #[test]
    fn two_sides_agree() {
        let a = [2u8, 0, 0, 0, 0, 1];
        let b = [2u8, 0, 0, 0, 0, 2];
        let mut x = Sae::new(b"correct horse", &a, &b, &[7u8; 32], &[9u8; 32]).unwrap();
        let mut y = Sae::new(b"correct horse", &b, &a, &[11u8; 32], &[13u8; 32]).unwrap();
        let (xs, xe, ys, ye) = (x.own_scalar, x.own_element, y.own_scalar, y.own_element);
        x.process_commit(&ys, &ye).unwrap();
        y.process_commit(&xs, &xe).unwrap();
        assert_eq!(x.pmk, y.pmk);
        assert_eq!(x.pmkid, y.pmkid);
        let (sc, c) = x.confirm();
        assert!(y.check_confirm(sc, &c).is_ok());
        let (sc2, c2) = y.confirm();
        assert!(x.check_confirm(sc2, &c2).is_ok());
        assert!(x.check_confirm(sc2 + 1, &c2).is_err());
        // a wrong password: same exchange, different PMK and the confirm fails
        let mut z = Sae::new(b"wrong horse", &b, &a, &[11u8; 32], &[13u8; 32]).unwrap();
        let mut x2 = Sae::new(b"correct horse", &a, &b, &[7u8; 32], &[9u8; 32]).unwrap();
        let (zs, ze) = (z.own_scalar, z.own_element);
        x2.process_commit(&zs, &ze).unwrap();
        z.process_commit(&xs, &xe).unwrap();
        let (sc3, c3) = z.confirm();
        assert!(x2.check_confirm(sc3, &c3).is_err());
        // reflection refused
        let mut r = Sae::new(b"correct horse", &a, &b, &[7u8; 32], &[9u8; 32]).unwrap();
        let (rs, re) = (r.own_scalar, r.own_element);
        assert_eq!(r.process_commit(&rs, &re), Err(SaeErr::BadCommit));
    }
}

// ---------------------------------------------------------------------------------------------------------------
// The AP's PMKSA cache (IEEE 802.11-2020 12.6.10.3): a station that completed SAE may later associate with
// open-system authentication + its PMKID (PMKSA caching). Station MAC -> PMK + PMKID (the SAE PMKID, 12.4.5.4) +
// expiry; filled on SAE Accepted. Bounded, static, wiped on removal, never logged.
// ---------------------------------------------------------------------------------------------------------------

pub const PMKSA_N: usize = 8;
/// hostapd's dot11RSNAConfigPMKLifetime default (12 h).
pub const PMKSA_LIFETIME_MS: u64 = 43_200_000;

struct Pmksa {
    mac: [u8; 6],
    pmkid: [u8; 16],
    pmk: [u8; 32],
    /// 0 = free
    exp: u64,
}

pub struct PmksaCache {
    e: [Pmksa; PMKSA_N],
}

#[inline(never)]
fn wipe(p: &mut Pmksa) {
    // volatile whole-array stores: the wipe is never elided
    unsafe {
        core::ptr::write_volatile(&mut p.pmk, [0; 32]);
        core::ptr::write_volatile(&mut p.pmkid, [0; 16]);
    }
    p.exp = 0;
}

impl PmksaCache {
    pub const fn new() -> PmksaCache {
        const E: Pmksa = Pmksa { mac: [0; 6], pmkid: [0; 16], pmk: [0; 32], exp: 0 };
        PmksaCache { e: [E; PMKSA_N] }
    }

    /// Cache the PMKSA of `mac` (one per station: a newer SAE replaces it); full -> the entry closest to expiry goes.
    #[inline(never)]
    pub fn add(&mut self, mac: &[u8; 6], pmkid: &[u8; 16], pmk: &[u8; 32], now: u64) {
        // this station's entry, else a free / expired one, else the one closest to expiry
        let mut i = 0;
        for (k, p) in self.e.iter().enumerate() {
            if p.exp != 0 && p.mac == *mac {
                i = k;
                break;
            }
            if p.exp <= now || p.exp < self.e[i].exp {
                i = k;
            }
        }
        let p = &mut self.e[i];
        wipe(p);
        p.mac = *mac;
        p.pmkid = *pmkid;
        p.pmk = *pmk;
        p.exp = now.saturating_add(PMKSA_LIFETIME_MS).max(1);
    }

    /// The PMK cached for (`mac`, `pmkid`) if unexpired (an expired entry is wiped here). The PMKID is public (the
    /// station sends it in the clear), so a plain comparison is fine.
    #[inline(never)]
    pub fn get(&mut self, mac: &[u8; 6], pmkid: &[u8; 16], now: u64) -> Option<[u8; 32]> {
        for p in self.e.iter_mut() {
            if p.exp != 0 && p.mac == *mac && p.pmkid == *pmkid {
                if p.exp <= now {
                    wipe(p);
                    return None;
                }
                return Some(p.pmk);
            }
        }
        None
    }

    /// Cache the PMKSA of a peer `tab` just Accepted (its SAE PMK + PMKID).
    #[inline(never)]
    pub fn add_accepted(&mut self, tab: &SaeAp, mac: &[u8; 6], now: u64) {
        if let Some(s) = tab.peers.iter().find(|p| p.st == St::Accepted && p.mac == *mac).and_then(|p| p.sae.as_ref()) {
            self.add(mac, &s.pmkid, &s.pmk, now);
        }
    }

    /// Forget the PMKSA of one station (its cached PMK did not verify: it must redo SAE).
    pub fn remove(&mut self, mac: &[u8; 6]) {
        for p in self.e.iter_mut().filter(|p| p.mac == *mac) {
            wipe(p);
        }
    }

    /// Forget every PMKSA (the passphrase or SSID changed: an old PMK must never key again).
    #[inline(never)]
    pub fn clear(&mut self) {
        for p in self.e.iter_mut() {
            wipe(p);
        }
    }

    pub fn len(&self) -> usize {
        self.e.iter().filter(|p| p.exp != 0).count()
    }
}

/// `[P-pmksa]`: the PMKSA cache — hit on (MAC, PMKID); miss on another MAC / PMKID; expiry; replace per station;
/// bounded eviction; clear wipes; the SAE PMKID that fills it is the Annex J.10 one (12.4.5.4).
pub fn pmksa_selftest() -> bool {
    let (a, b) = ([2u8, 0, 0, 0, 0, 1], [2u8, 0, 0, 0, 0, 2]);
    let mut c = PmksaCache::new();
    let mut ok = true;
    c.add(&a, &[1; 16], &[0x11; 32], 1000);
    ok &= c.get(&a, &[1; 16], 2000) == Some([0x11; 32]);
    ok &= c.get(&b, &[1; 16], 2000).is_none() && c.get(&a, &[2; 16], 2000).is_none();
    ok &= c.get(&a, &[1; 16], 1000 + PMKSA_LIFETIME_MS).is_none() && c.len() == 0;
    c.add(&a, &[1; 16], &[0x11; 32], 0);
    c.add(&a, &[3; 16], &[0x33; 32], 5);
    ok &= c.len() == 1 && c.get(&a, &[1; 16], 6).is_none() && c.get(&a, &[3; 16], 6) == Some([0x33; 32]);
    for k in 0..(PMKSA_N as u8 + 3) {
        c.add(&[4, 0, 0, 0, 0, k], &[k; 16], &[k; 32], 10 + k as u64);
    }
    ok &= c.len() == PMKSA_N && c.get(&[4, 0, 0, 0, 0, PMKSA_N as u8 + 2], &[PMKSA_N as u8 + 2; 16], 100).is_some();
    c.remove(&[4, 0, 0, 0, 0, PMKSA_N as u8 + 2]);
    ok &= c.len() == PMKSA_N - 1 && c.get(&[4, 0, 0, 0, 0, PMKSA_N as u8 + 2], &[PMKSA_N as u8 + 2; 16], 100).is_none();
    c.clear();
    ok &= c.len() == 0 && c.e.iter().all(|p| p.pmk == [0; 32] && p.pmkid == [0; 16]);
    // the PMKID SAE yields (what the station's RSNE then names): Annex J.10
    let j10 = (|| {
        let mut s = Sae::new(b"mekmitasdigoat", &[0x4d, 0x3f, 0x2f, 0xff, 0xe3, 0x87], &[0xa5, 0xd8, 0xaa, 0x95, 0x8e, 0x3c],
            &unhex("992465fd3daa3c60aa6565b7f62a2a7f2e12dd12f198faf4fbed89d7ff1ace94"), &unhex("9507a90f777a044d6a0830b91ea3d5dd70bece44e1acffb86983b5e1bf9fb322")).ok()?;
        s.process_commit(&unhex("591b96f3397fb945100848e7b550543b6720d88337ee93fc49fd6df7e08b5223"),
            &unhex("e71b9bb048d3873f20556953a96c91536fd8ee6ca9b4a68a148b056a909be03e83ae208f60f8ef5537858074db06687032399862999b511e0a1552a5fea317c2")).ok()?;
        let mut c = PmksaCache::new();
        c.add(&a, &s.pmkid, &s.pmk, 0);
        Some(c.get(&a, &unhex::<16>("8747a600eea3f9f22475df58ca1e5498"), 1) == Some(s.pmk))
    })().unwrap_or(false);
    ok && j10
}
