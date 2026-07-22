//! Abstract domain for the BPF verifier (`bpf::verify_prevail`), factored out as
//! MODULAR, individually-specified transfer functions — the Agni lesson (P16(a)):
//! Linux's verifier had 27 latent soundness bugs, several in individually-unsound
//! abstract operators masked by a shared pass. Keeping each operator small and
//! separately specified lets the offline soundness harness (`tools/verifier-
//! harness`) check that each one OVER-APPROXIMATES the concrete BPF semantics.
//!
//! Pure integer logic, NO dependencies (only `core`), so the no_std kernel
//! (`mod absdom`) and the std harness (`#[path] mod absdom`) compile the SAME
//! source — the harness tests the real operators, no drift.

/// A register's abstract value.
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Abs {
    /// Never written on this path — reading it is a verifier error.
    Uninit,
    /// A value in the interval `[lo, hi]` — NOT a valid load base.
    Scalar { lo: i64, hi: i64 },
    /// The packet base + a byte offset in `[lo, hi]` — the only valid load base.
    Pkt { lo: i64, hi: i64 },
}

/// A scalar of fully-unknown value (⊤): loads from it are rejected, and adding it
/// to a packet pointer makes the offset unbounded ⇒ that pointer's loads too.
pub const S_TOP: Abs = Abs::Scalar { lo: i64::MIN, hi: i64::MAX };

/// Saturating add — the interval arithmetic clamps at the i64 bounds rather than
/// wrapping, so an offset that could overflow becomes ⊤-ish (huge) and its loads
/// are rejected. The soundness harness checks this over-approximates on the
/// bounded ranges the verifier actually meets (load results, offsets, immediates).
#[inline]
pub fn sat_add(a: i64, b: i64) -> i64 {
    a.saturating_add(b)
}

/// Join (⊔) at a control-flow merge: widen to cover both incoming states. Init
/// on one path + uninit on another ⇒ uninit (reading is unsafe); a Pkt/Scalar mix
/// loses pointer-ness ⇒ ⊤.
pub fn join(a: Abs, b: Abs) -> Abs {
    match (a, b) {
        (Abs::Uninit, Abs::Uninit) => Abs::Uninit,
        (Abs::Uninit, _) | (_, Abs::Uninit) => Abs::Uninit,
        (Abs::Pkt { lo: l1, hi: h1 }, Abs::Pkt { lo: l2, hi: h2 }) => {
            Abs::Pkt { lo: l1.min(l2), hi: h1.max(h2) }
        }
        (Abs::Scalar { lo: l1, hi: h1 }, Abs::Scalar { lo: l2, hi: h2 }) => {
            Abs::Scalar { lo: l1.min(l2), hi: h1.max(h2) }
        }
        _ => S_TOP,
    }
}

/// Error from a binary-register transfer (`add_x`).
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum XErr {
    /// An operand register was uninitialized.
    Uninit,
    /// The result would be a non-scalar (e.g. pointer + pointer).
    NonScalar,
}

// --- transfer functions: each individually specified + harness-checked --------

/// `MOV64_K`: `dst = imm` — a singleton scalar interval.
#[inline]
pub fn mov_k(imm: i64) -> Abs {
    Abs::Scalar { lo: imm, hi: imm }
}

/// `ADD64_K`: `dst += imm` (a constant). Shifts a Pkt offset or a Scalar interval
/// by `imm`; `Uninit` ⇒ None (the caller reports the error).
#[inline]
pub fn add_k(dst: Abs, imm: i64) -> Option<Abs> {
    match dst {
        Abs::Pkt { lo, hi } => Some(Abs::Pkt { lo: sat_add(lo, imm), hi: sat_add(hi, imm) }),
        Abs::Scalar { lo, hi } => Some(Abs::Scalar { lo: sat_add(lo, imm), hi: sat_add(hi, imm) }),
        Abs::Uninit => None,
    }
}

/// `ADD64_X`: `dst += src`. A Pkt pointer widened by a Scalar offset stays a Pkt;
/// Scalar + Scalar adds the intervals; pointer + pointer is illegal.
#[inline]
pub fn add_x(dst: Abs, src: Abs) -> Result<Abs, XErr> {
    match (dst, src) {
        (Abs::Uninit, _) | (_, Abs::Uninit) => Err(XErr::Uninit),
        (Abs::Pkt { lo, hi }, Abs::Scalar { lo: a, hi: b }) => {
            Ok(Abs::Pkt { lo: sat_add(lo, a), hi: sat_add(hi, b) })
        }
        (Abs::Scalar { lo, hi }, Abs::Scalar { lo: a, hi: b }) => {
            Ok(Abs::Scalar { lo: sat_add(lo, a), hi: sat_add(hi, b) })
        }
        _ => Err(XErr::NonScalar),
    }
}

/// `AND64_K`: `dst &= imm`. For a non-negative mask `m`, the result is in `[0, m]`
/// (masking can only clear bits); a negative mask keeps the sign bit ⇒ ⊤.
#[inline]
pub fn and_k(imm: i64) -> Abs {
    if imm >= 0 {
        Abs::Scalar { lo: 0, hi: imm }
    } else {
        S_TOP
    }
}

/// `LSH64_K`: a left shift by a variable-in-range amount is conservatively ⊤.
#[inline]
pub fn lsh_k() -> Abs {
    S_TOP
}

/// `OR64_X`: bitwise-or of two intervals is conservatively ⊤.
#[inline]
pub fn or_x() -> Abs {
    S_TOP
}
