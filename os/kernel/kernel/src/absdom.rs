//! Abstract domain for the BPF verifier (`bpf::verify_prevail`), factored out as
//! MODULAR, individually-specified transfer functions — the Agni lesson (P16(a)):
//! Linux's verifier had 27 latent soundness bugs, several in individually-unsound
//! abstract operators masked by a shared pass. Keeping each operator small and
//! separately specified lets the offline soundness harness (`tools/verifier-
//! harness`) check that each one OVER-APPROXIMATES the concrete BPF semantics.
//!
//! Each scalar carries BOTH an interval `[lo,hi]` AND a **tnum** (tristate: bit-
//! level known/unknown). tnum is strictly more precise for bitwise/mask/shift ops
//! (header masks, CIDR prefixes, TCP-flag tests) — PREVAIL and the Windows eBPF
//! verifier LACK it and over-approximate those (their `LSH → ⊤`, so a variable
//! header offset `(ihl & 0xf) << 2` added to a packet pointer becomes unbounded ⇒
//! rejected). With tnum HEQK keeps it bounded ⇒ accepted, with a tight min_len.
//!
//! Pure integer logic, NO dependencies (only `core`), so the no_std kernel
//! (`mod absdom`) and the std harness (`#[path] mod absdom`) compile the SAME
//! source — the harness tests the real operators, no drift.

// ===========================================================================
// tnum — tristate numbers (CGO'22, arXiv:2105.05398). `mask` bit = 1 ⇒ that bit
// is UNKNOWN; where mask = 0 the bit is known and equals the `value` bit.
// Invariant: value & mask == 0. Every operator is harness-checked (Agni-style).
// ===========================================================================
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Tnum {
    pub value: u64,
    pub mask: u64,
}
#[inline]
pub const fn tnum_const(v: u64) -> Tnum {
    Tnum { value: v, mask: 0 }
}
pub const TNUM_UNKNOWN: Tnum = Tnum { value: 0, mask: u64::MAX };

/// γ: does the tnum denote the concrete `c`? (all KNOWN bits must match).
#[inline]
pub fn tnum_contains(t: Tnum, c: u64) -> bool {
    (c & !t.mask) == (t.value & !t.mask)
}
/// Refine a tnum to an unsigned interval: [known-bits, known-bits|unknowns].
#[inline]
pub fn tnum_range(t: Tnum) -> (u64, u64) {
    (t.value, t.value | t.mask)
}
#[inline]
pub fn tnum_and(a: Tnum, b: Tnum) -> Tnum {
    let alpha = a.value | a.mask;
    let beta = b.value | b.mask;
    let v = a.value & b.value;
    Tnum { value: v, mask: alpha & beta & !v }
}
#[inline]
pub fn tnum_or(a: Tnum, b: Tnum) -> Tnum {
    let v = a.value | b.value;
    let mu = a.mask | b.mask;
    Tnum { value: v, mask: mu & !v }
}
#[inline]
pub fn tnum_xor(a: Tnum, b: Tnum) -> Tnum {
    let v = a.value ^ b.value;
    let mu = a.mask | b.mask;
    Tnum { value: v & !mu, mask: mu }
}
#[inline]
pub fn tnum_lshift(a: Tnum, n: u32) -> Tnum {
    let n = n & 63;
    Tnum { value: a.value << n, mask: a.mask << n }
}
#[inline]
pub fn tnum_add(a: Tnum, b: Tnum) -> Tnum {
    let sm = a.mask.wrapping_add(b.mask);
    let sv = a.value.wrapping_add(b.value);
    let sigma = sm.wrapping_add(sv);
    let chi = sigma ^ sv;
    let mu = chi | a.mask | b.mask;
    Tnum { value: sv & !mu, mask: mu }
}
/// Join (⊔) of two tnums at a control-flow merge: a bit stays known only if it is
/// known AND equal in both; everything else becomes unknown.
#[inline]
pub fn tnum_join(a: Tnum, b: Tnum) -> Tnum {
    let mu = a.mask | b.mask | (a.value ^ b.value);
    Tnum { value: a.value & !mu, mask: mu }
}

/// A register's abstract value.
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Abs {
    /// Never written on this path — reading it is a verifier error.
    Uninit,
    /// A value in `[lo, hi]` with bit-level knowledge `t` — NOT a valid load base.
    Scalar { lo: i64, hi: i64, t: Tnum },
    /// The packet base + a byte offset in `[lo, hi]` — the only valid load base.
    Pkt { lo: i64, hi: i64 },
}

/// A scalar of fully-unknown value (⊤).
pub const S_TOP: Abs = Abs::Scalar { lo: i64::MIN, hi: i64::MAX, t: TNUM_UNKNOWN };

/// The tnum of an abstract value (⊤ for non-scalars).
#[inline]
pub fn tnum_of(a: Abs) -> Tnum {
    match a {
        Abs::Scalar { t, .. } => t,
        _ => TNUM_UNKNOWN,
    }
}

/// Build a Scalar from a tnum, tightening the interval from the tnum's unsigned
/// range when it is provably within i64-positive bounds (the masked/shifted small
/// values the detection rules produce); otherwise keep the interval wide but
/// retain the bit precision.
#[inline]
pub fn scalar_from_tnum(t: Tnum) -> Abs {
    let (lo, hi) = tnum_range(t);
    if hi <= i64::MAX as u64 {
        Abs::Scalar { lo: lo as i64, hi: hi as i64, t }
    } else {
        Abs::Scalar { lo: i64::MIN, hi: i64::MAX, t }
    }
}

#[inline]
pub fn sat_add(a: i64, b: i64) -> i64 {
    a.saturating_add(b)
}

/// Join (⊔) at a control-flow merge: widen to cover both incoming states.
pub fn join(a: Abs, b: Abs) -> Abs {
    match (a, b) {
        (Abs::Uninit, Abs::Uninit) => Abs::Uninit,
        (Abs::Uninit, _) | (_, Abs::Uninit) => Abs::Uninit,
        (Abs::Pkt { lo: l1, hi: h1 }, Abs::Pkt { lo: l2, hi: h2 }) => {
            Abs::Pkt { lo: l1.min(l2), hi: h1.max(h2) }
        }
        (Abs::Scalar { lo: l1, hi: h1, t: t1 }, Abs::Scalar { lo: l2, hi: h2, t: t2 }) => {
            Abs::Scalar { lo: l1.min(l2), hi: h1.max(h2), t: tnum_join(t1, t2) }
        }
        _ => S_TOP,
    }
}

/// Error from a binary-register transfer (`add_x`).
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum XErr {
    Uninit,
    NonScalar,
}

// --- transfer functions: each individually specified + harness-checked --------

/// `MOV64_K`: `dst = imm` — an exactly-known singleton.
#[inline]
pub fn mov_k(imm: i64) -> Abs {
    Abs::Scalar { lo: imm, hi: imm, t: tnum_const(imm as u64) }
}

/// `ADD64_K`: `dst += imm`. Shifts a Pkt offset or a Scalar (interval + tnum).
#[inline]
pub fn add_k(dst: Abs, imm: i64) -> Option<Abs> {
    match dst {
        Abs::Pkt { lo, hi } => Some(Abs::Pkt { lo: sat_add(lo, imm), hi: sat_add(hi, imm) }),
        Abs::Scalar { lo, hi, t } => Some(Abs::Scalar {
            lo: sat_add(lo, imm),
            hi: sat_add(hi, imm),
            t: tnum_add(t, tnum_const(imm as u64)),
        }),
        Abs::Uninit => None,
    }
}

/// `ADD64_X`: `dst += src`. Pkt widened by a Scalar offset stays Pkt; Scalar +
/// Scalar adds intervals and tnums; pointer + pointer is illegal.
#[inline]
pub fn add_x(dst: Abs, src: Abs) -> Result<Abs, XErr> {
    match (dst, src) {
        (Abs::Uninit, _) | (_, Abs::Uninit) => Err(XErr::Uninit),
        (Abs::Pkt { lo, hi }, Abs::Scalar { lo: a, hi: b, .. }) => {
            Ok(Abs::Pkt { lo: sat_add(lo, a), hi: sat_add(hi, b) })
        }
        (Abs::Scalar { lo, hi, t: t1 }, Abs::Scalar { lo: a, hi: b, t: t2 }) => {
            Ok(Abs::Scalar { lo: sat_add(lo, a), hi: sat_add(hi, b), t: tnum_add(t1, t2) })
        }
        _ => Err(XErr::NonScalar),
    }
}

/// `AND64_K`: `dst &= imm`. tnum makes this EXACT (bit-level), so a masked value
/// is a tight, bounded scalar — the key precision over PREVAIL/Windows.
#[inline]
pub fn and_k(dst: Abs, imm: i64) -> Abs {
    if imm < 0 {
        return S_TOP; // negative mask keeps the sign bit — conservative
    }
    scalar_from_tnum(tnum_and(tnum_of(dst), tnum_const(imm as u64)))
}

/// `LSH64_K`: `dst <<= sh`. With tnum the result stays BOUNDED (interval alone
/// would go to ⊤ — the imprecision that makes variable-offset rules unverifiable).
#[inline]
pub fn lsh_k(dst: Abs, sh: u32) -> Abs {
    scalar_from_tnum(tnum_lshift(tnum_of(dst), sh))
}

/// `OR64_X`: `dst |= src`. tnum tracks the known bits (interval would be ⊤).
#[inline]
pub fn or_x(dst: Abs, src: Abs) -> Abs {
    scalar_from_tnum(tnum_or(tnum_of(dst), tnum_of(src)))
}

/// The abstract value of a `w`-byte packet load result: value in `[0, 2^(8w)-1]`,
/// low `8w` bits unknown, all higher bits known-zero (the tnum that lets a later
/// mask+shift on this value stay bounded).
#[inline]
pub fn load_result(w: i64) -> Abs {
    let maxv: u64 = if w >= 8 { u64::MAX } else { (1u64 << (8 * w)) - 1 };
    let hi = if maxv <= i64::MAX as u64 { maxv as i64 } else { i64::MAX };
    Abs::Scalar { lo: 0, hi, t: Tnum { value: 0, mask: maxv } }
}
