//! ADR 0050 D4 step 5c: the WPA3-SAE responder's walk over what a station sends — the body of an 802.11
//! Authentication frame (algorithm 3), Commit or Confirm — attacker-shaped bytes from anyone in radio range. Pure,
//! allocation-free, no curve library: compiled into `el0-lansvc` (the live path) and into the kernel (the fallback
//! when the EL0 server is absent, ADR 0050 D5). It checks everything the station controls and returns ONE fixed
//! record (`encode` / `decode`):
//! - algorithm, transaction sequence, status code, finite cyclic group (19 = P-256 only);
//! - Commit length rules and the trailing element walk (H2E Rejected Groups, with the downgrade check);
//! - the peer scalar range 1 < s < r and the peer element (x, y < p and y² = x³ − 3x + b, i.e. on the curve);
//! - Confirm format (status 0, send-confirm ‖ 32-byte confirm).
//!
//! No secret enters here: the password, PWE / PT, our rand, the KCK and the PMK stay in the kernel's `sae` state
//! machine, which re-validates the scalar and element with the curve library before any use and verifies the
//! confirm under its own KCK. No anti-clogging token is ever requested by this AP, so a commit carrying one
//! fails the length rules exactly as before.

pub const ALG_SAE: u16 = 3;
pub const GROUP_P256: u16 = 19;
pub const ST_SUCCESS: u16 = 0;
pub const ST_UNSUPPORTED_GROUP: u16 = 77;
/// SAE-H2E commit status (hash-to-element).
pub const ST_H2E: u16 = 126;
/// Largest Authentication frame body examined. A legitimate SAE body is under 300 B (commit 104 B + Rejected Groups
/// + a token container); anything longer is refused whole, never truncated into something that parses.
pub const BODY_MAX: usize = 512;

// record kinds
pub const K_DROP: u8 = 0;
pub const K_COMMIT: u8 = 1;
pub const K_CONFIRM: u8 = 2;
/// Answer "unsupported group" (status 77) naming group 19.
pub const K_REFUSE_GROUP: u8 = 3;

// drop reasons
pub const R_NOT_SAE: u8 = 1;
pub const R_COMMIT_STATUS: u8 = 2;
pub const R_COMMIT_LEN: u8 = 3;
pub const R_ELEM_LEN: u8 = 4;
pub const R_REJ_GROUPS: u8 = 5;
pub const R_SCALAR: u8 = 6;
pub const R_ELEMENT: u8 = 7;
pub const R_CONFIRM_FMT: u8 = 8;
pub const R_SEQ: u8 = 9;
pub const R_TOO_LONG: u8 = 10;
/// Set by the kernel only: the EL0 server faulted on this frame.
pub const R_FAULT: u8 = 11;
/// Set by the kernel only: a record from EL0 that cannot be right.
pub const R_BAD_RECORD: u8 = 12;

pub fn reason(r: u8) -> &'static str {
    match r {
        R_NOT_SAE => "not SAE",
        R_COMMIT_STATUS => "commit status",
        R_COMMIT_LEN => "commit length",
        R_ELEM_LEN => "commit element length",
        R_REJ_GROUPS => "rejected groups list names a supported group",
        R_SCALAR => "peer scalar out of range",
        R_ELEMENT => "peer element not on the curve",
        R_CONFIRM_FMT => "confirm format",
        R_SEQ => "sequence",
        R_TOO_LONG => "body too long",
        R_FAULT => "EL0 SAE parser fault: attempt rejected, station state forgotten",
        R_BAD_RECORD => "EL0 SAE record malformed: attempt rejected",
        _ => "dropped",
    }
}

/// The checked facts of one SAE Authentication frame body.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Msg {
    pub kind: u8,
    pub reason: u8,
    /// Commit: status 126 (hash-to-element).
    pub h2e: bool,
    pub rej_len: u8,
    /// Confirm: the peer's send-confirm counter.
    pub send_confirm: u16,
    pub scalar: [u8; 32],
    pub element: [u8; 64],
    /// Commit (H2E): the Rejected Groups list as sent (the keyseed salt).
    pub rej: [u8; 32],
    pub confirm: [u8; 32],
}
pub const MSG0: Msg = Msg { kind: K_DROP, reason: 0, h2e: false, rej_len: 0, send_confirm: 0, scalar: [0; 32], element: [0; 64], rej: [0; 32], confirm: [0; 32] };

pub fn dropped(r: u8) -> Msg {
    Msg { reason: r, ..MSG0 }
}

/// One SAE Authentication frame body (alg ‖ seq ‖ status ‖ payload). `h2e_ok` = this AP offers hash-to-element.
pub fn parse(body: &[u8], h2e_ok: bool) -> Msg {
    if body.len() > BODY_MAX {
        return dropped(R_TOO_LONG);
    }
    if body.len() < 6 || u16::from_le_bytes([body[0], body[1]]) != ALG_SAE {
        return dropped(R_NOT_SAE);
    }
    let seq = u16::from_le_bytes([body[2], body[3]]);
    let status = u16::from_le_bytes([body[4], body[5]]);
    let rest = &body[6..];
    match seq {
        1 => {
            let h2e = status == ST_H2E;
            if (h2e && !h2e_ok) || (rest.len() >= 2 && u16::from_le_bytes([rest[0], rest[1]]) != GROUP_P256) {
                return Msg { kind: K_REFUSE_GROUP, ..MSG0 };
            }
            if status != ST_SUCCESS && !h2e {
                return dropped(R_COMMIT_STATUS);
            }
            // group ‖ scalar ‖ element [‖ H2E: Rejected Groups / token container elements]
            if rest.len() < 2 + 32 + 64 || (!h2e && rest.len() != 2 + 32 + 64) {
                return dropped(R_COMMIT_LEN);
            }
            let mut m = Msg { kind: K_COMMIT, h2e, ..MSG0 };
            let mut ei = 98;
            while ei + 2 <= rest.len() {
                let (id, l) = (rest[ei], rest[ei + 1] as usize);
                if ei + 2 + l > rest.len() {
                    return dropped(R_ELEM_LEN);
                }
                if id == 255 && l >= 1 && rest[ei + 2] == 92 {
                    let g = &rest[ei + 3..ei + 2 + l];
                    // downgrade protection: a "rejected" group we actually support means a forged rejection
                    if g.len() % 2 != 0 || g.len() > 32 || g.chunks(2).any(|c| u16::from_le_bytes([c[0], c[1]]) == GROUP_P256) {
                        return dropped(R_REJ_GROUPS);
                    }
                    m.rej = [0; 32];
                    m.rej[..g.len()].copy_from_slice(g);
                    m.rej_len = g.len() as u8;
                }
                ei += 2 + l;
            }
            m.scalar.copy_from_slice(&rest[2..34]);
            m.element.copy_from_slice(&rest[34..98]);
            if !scalar_in_range(&m.scalar) {
                return dropped(R_SCALAR);
            }
            if !on_curve(&m.element) {
                return dropped(R_ELEMENT);
            }
            m
        }
        2 => {
            if status != ST_SUCCESS || rest.len() != 2 + 32 {
                return dropped(R_CONFIRM_FMT);
            }
            let mut m = Msg { kind: K_CONFIRM, send_confirm: u16::from_le_bytes([rest[0], rest[1]]), ..MSG0 };
            m.confirm.copy_from_slice(&rest[2..34]);
            m
        }
        _ => dropped(R_SEQ),
    }
}

// ---- the fixed record (EL0 → kernel) ----
/// kind ‖ reason ‖ h2e ‖ rej_len ‖ send_confirm u16 LE ‖ 2 pad ‖ scalar 32 ‖ element 64 ‖ rej 32 ‖ confirm 32.
pub const REC_LEN: usize = 8 + 32 + 64 + 32 + 32;

pub fn encode(m: &Msg) -> [u8; REC_LEN] {
    let mut o = [0u8; REC_LEN];
    o[0] = m.kind;
    o[1] = m.reason;
    o[2] = m.h2e as u8;
    o[3] = m.rej_len;
    o[4..6].copy_from_slice(&m.send_confirm.to_le_bytes());
    o[8..40].copy_from_slice(&m.scalar);
    o[40..104].copy_from_slice(&m.element);
    o[104..136].copy_from_slice(&m.rej);
    o[136..168].copy_from_slice(&m.confirm);
    o
}

/// The kernel's decode: every field the kernel relies on is re-checked (kind, the Rejected Groups length / content);
/// a record that cannot be right reads as a drop. The scalar and element are re-validated by the curve library.
pub fn decode(o: &[u8; REC_LEN]) -> Msg {
    let mut m = MSG0;
    m.kind = o[0];
    m.reason = o[1];
    m.h2e = o[2] != 0;
    m.rej_len = o[3];
    m.send_confirm = u16::from_le_bytes([o[4], o[5]]);
    m.scalar.copy_from_slice(&o[8..40]);
    m.element.copy_from_slice(&o[40..104]);
    m.rej.copy_from_slice(&o[104..136]);
    m.confirm.copy_from_slice(&o[136..168]);
    let rl = m.rej_len as usize;
    let rej_bad = rl > 32 || rl % 2 != 0 || m.rej[..rl.min(32)].chunks(2).any(|c| u16::from_le_bytes([c[0], c[1]]) == GROUP_P256);
    if m.kind > K_REFUSE_GROUP || (m.kind == K_COMMIT && rej_bad) {
        return dropped(R_BAD_RECORD);
    }
    m
}

// ---- P-256 checks on public values (no secret, so plain variable-time arithmetic is fine) ----
type U = [u64; 4]; // little-endian limbs

const P: U = [0xffff_ffff_ffff_ffff, 0x0000_0000_ffff_ffff, 0x0000_0000_0000_0000, 0xffff_ffff_0000_0001];
const B: U = [0x3bce_3c3e_27d2_604b, 0x651d_06b0_cc53_b0f6, 0xb3eb_bd55_7698_86bc, 0x5ac6_35d8_aa3a_93e7];
/// The group order r (n) of P-256, big-endian.
const R_BE: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xbc, 0xe6, 0xfa, 0xad,
    0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
];

fn from_be(b: &[u8]) -> U {
    let mut u = [0u64; 4];
    for (i, l) in u.iter_mut().enumerate() {
        let o = 32 - 8 * (i + 1);
        *l = u64::from_be_bytes([b[o], b[o + 1], b[o + 2], b[o + 3], b[o + 4], b[o + 5], b[o + 6], b[o + 7]]);
    }
    u
}
fn lt(a: &U, b: &U) -> bool {
    for i in (0..4).rev() {
        if a[i] != b[i] {
            return a[i] < b[i];
        }
    }
    false
}
fn add(a: &U, b: &U) -> (U, bool) {
    let mut r = [0u64; 4];
    let mut c = false;
    for i in 0..4 {
        let (s1, c1) = a[i].overflowing_add(b[i]);
        let (s2, c2) = s1.overflowing_add(c as u64);
        r[i] = s2;
        c = c1 || c2;
    }
    (r, c)
}
fn sub(a: &U, b: &U) -> U {
    let mut r = [0u64; 4];
    let mut br = false;
    for i in 0..4 {
        let (d1, b1) = a[i].overflowing_sub(b[i]);
        let (d2, b2) = d1.overflowing_sub(br as u64);
        r[i] = d2;
        br = b1 || b2;
    }
    r
}
/// (a + b) mod p for a, b < p.
fn add_p(a: &U, b: &U) -> U {
    let (s, c) = add(a, b);
    if c || !lt(&s, &P) { sub(&s, &P) } else { s }
}
/// (a − b) mod p for a, b < p.
fn sub_p(a: &U, b: &U) -> U {
    if lt(a, b) { add(&sub(a, b), &P).0 } else { sub(a, b) }
}
/// (a · b) mod p by double-and-add over b's bits (a, b < p).
fn mul_p(a: &U, b: &U) -> U {
    let mut r = [0u64; 4];
    for i in (0..256).rev() {
        r = add_p(&r, &r);
        if (b[i / 64] >> (i % 64)) & 1 == 1 {
            r = add_p(&r, a);
        }
    }
    r
}

/// Is the uncompressed element (x ‖ y, big-endian) a point on P-256 (both coordinates reduced)? The point at
/// infinity has no such encoding, so it is refused too.
pub fn on_curve(e: &[u8; 64]) -> bool {
    let (x, y) = (from_be(&e[..32]), from_be(&e[32..]));
    if !lt(&x, &P) || !lt(&y, &P) {
        return false;
    }
    let lhs = mul_p(&y, &y);
    let x3 = mul_p(&mul_p(&x, &x), &x);
    let three_x = add_p(&add_p(&x, &x), &x);
    let rhs = add_p(&sub_p(&x3, &three_x), &B);
    lhs == rhs
}

/// 1 < s < r (§12.4.5.4).
pub fn scalar_in_range(s: &[u8; 32]) -> bool {
    let gt1 = s[..31].iter().any(|&b| b != 0) || s[31] > 1;
    gt1 && lt(&from_be(s), &from_be(&R_BE))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn hx<const N: usize>(s: &str) -> [u8; N] {
        let mut o = [0u8; N];
        for i in 0..N {
            o[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
        }
        o
    }
    // IEEE 802.11-2020 Annex J.10 peer commit
    const PS: &str = "591b96f3397fb945100848e7b550543b6720d88337ee93fc49fd6df7e08b5223";
    const PE: &str = "e71b9bb048d3873f20556953a96c91536fd8ee6ca9b4a68a148b056a909be03e83ae208f60f8ef5537858074db06687032399862999b511e0a1552a5fea317c2";
    fn commit() -> [u8; 104] {
        let mut c = [0u8; 104];
        c[0] = 3;
        c[2] = 1;
        c[6] = 19;
        c[8..40].copy_from_slice(&hx::<32>(PS));
        c[40..104].copy_from_slice(&hx::<64>(PE));
        c
    }
    #[test]
    fn curve_checks() {
        // the generator
        let g = hx::<64>("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5");
        assert!(on_curve(&g));
        assert!(on_curve(&hx::<64>(PE)));
        let mut bad = g;
        bad[63] ^= 1;
        assert!(!on_curve(&bad));
        assert!(!on_curve(&[0; 64]));
        assert!(!on_curve(&[0xff; 64]));
        assert!(scalar_in_range(&hx::<32>(PS)));
        assert!(!scalar_in_range(&[0; 32]));
        let mut one = [0u8; 32];
        one[31] = 1;
        assert!(!scalar_in_range(&one));
        one[31] = 2;
        assert!(scalar_in_range(&one));
        assert!(!scalar_in_range(&R_BE));
        let mut rm1 = R_BE;
        rm1[31] -= 1;
        assert!(scalar_in_range(&rm1));
        assert!(!scalar_in_range(&[0xff; 32]));
    }
    #[test]
    fn frames() {
        let c = commit();
        let m = parse(&c, false);
        assert_eq!(m.kind, K_COMMIT);
        assert_eq!(decode(&encode(&m)), m);
        let mut g = c;
        g[6] = 20;
        assert_eq!(parse(&g, false).kind, K_REFUSE_GROUP);
        let mut h = c;
        h[4] = 126;
        assert_eq!(parse(&h, false).kind, K_REFUSE_GROUP);
        assert_eq!(parse(&c[..103], false).reason, R_COMMIT_LEN);
        let mut s = c;
        s[8..40].copy_from_slice(&R_BE);
        assert_eq!(parse(&s, false).reason, R_SCALAR);
        let mut e = c;
        e[103] ^= 1;
        assert_eq!(parse(&e, false).reason, R_ELEMENT);
        let mut big = [0u8; 3000];
        big[..104].copy_from_slice(&c);
        assert_eq!(parse(&big, false).reason, R_TOO_LONG);
        // H2E with a Rejected Groups element naming 20; a forged one naming 19
        let mut x = [0u8; 109];
        x[..104].copy_from_slice(&c);
        x[4] = 126;
        x[104..].copy_from_slice(&[255, 3, 92, 20, 0]);
        let m = parse(&x, true);
        assert!(m.kind == K_COMMIT && m.h2e && m.rej_len == 2 && m.rej[..2] == [20, 0]);
        x[107] = 19;
        assert_eq!(parse(&x, true).reason, R_REJ_GROUPS);
        x[105] = 9;
        assert_eq!(parse(&x, true).reason, R_ELEM_LEN);
        let mut k = [0u8; 40];
        k[0] = 3;
        k[2] = 2;
        k[6] = 7;
        k[8] = 0xaa;
        let m = parse(&k, false);
        assert!(m.kind == K_CONFIRM && m.send_confirm == 7 && m.confirm[0] == 0xaa);
        assert_eq!(parse(&k[..39], false).reason, R_CONFIRM_FMT);
        k[2] = 3;
        assert_eq!(parse(&k, false).reason, R_SEQ);
        assert_eq!(parse(&[3, 0, 1], false).reason, R_NOT_SAE);
        // a record a faulty server could return is re-checked
        let mut r = encode(&parse(&c, false));
        r[3] = 33;
        assert_eq!(decode(&r).reason, R_BAD_RECORD);
        r[3] = 2;
        r[104] = 19;
        assert_eq!(decode(&r).reason, R_BAD_RECORD);
        r[0] = 9;
        assert_eq!(decode(&r).reason, R_BAD_RECORD);
    }
}
