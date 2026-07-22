//! P16 — offline soundness harness for the BPF verifier's abstract operators
//! (the Agni lesson: Linux's verifier shipped 27 latent soundness bugs, several
//! in individually-unsound abstract operators). It compiles the REAL operators
//! (`kernel/src/absdom.rs`, the SAME source the kernel uses — no drift) and checks
//! that each one OVER-APPROXIMATES the concrete BPF semantics: for every abstract
//! input, every concrete value it denotes maps to a concrete result the abstract
//! output still denotes. If an operator ever excludes a reachable concrete result,
//! an unsafe program could slip past the verifier — exactly the bug class Agni
//! found. A deliberately-unsound operator is included to prove the harness catches
//! unsoundness. Host-side (std), CI/dev-time; build with rustc (see validate.sh).
//!
//! Scope (stated honestly): two tiers. (1) SAMPLED over the verifier-REACHABLE
//! domain — scalar loads (0..2^32-1), packet offsets, i32 immediates. (2) NEW:
//! EXHAUSTIVE/COMPLETE over a reduced bit-width (every tnum, every pair, fully
//! concretized) — a real proof on that domain, not a sample. For the
//! bit-independent operators (and/or/xor/lshift) width-w soundness generalizes to
//! full 64-bit width by bit symmetry; carry-coupled add is proven up to width w.
//! The only step beyond this is a full-64-bit SMT/Kani proof (tools not present).

#[path = "../kernel/src/absdom.rs"]
mod absdom;
use absdom::*;

/// Concretization γ: does the abstract value denote the concrete `v`?
fn contains(a: Abs, v: i64) -> bool {
    match a {
        Abs::Uninit => false,
        Abs::Scalar { lo, hi, .. } | Abs::Pkt { lo, hi } => lo <= v && v <= hi,
    }
}

/// Sample concrete values across `[lo, hi]` (endpoints + interior points).
fn samples(lo: i64, hi: i64) -> Vec<i64> {
    let mut s = vec![lo, hi];
    let step = ((hi - lo) / 7).max(1);
    let mut x = lo;
    while x < hi {
        s.push(x);
        x = x.saturating_add(step);
    }
    s.sort();
    s.dedup();
    s
}

/// Interval endpoints the verifier actually meets (packet offsets / lengths).
const PTS: &[i64] = &[0, 1, 2, 4, 12, 14, 34, 42, 47, 255, 1500, 65535, 100_000];
const IMMS: &[i64] = &[-8, -1, 0, 1, 4, 13, 42, 1000];

/// ADD64_K: for `dst ∈ [lo,hi]`, every concrete `c+imm` must be in `add_k(...)`.
fn check_add_k() -> usize {
    let mut bad = 0;
    for &lo in PTS {
        for &hi in PTS {
            if hi < lo {
                continue;
            }
            for &imm in IMMS {
                for base in [Abs::Scalar { lo, hi, t: TNUM_UNKNOWN }, Abs::Pkt { lo, hi }] {
                    let out = add_k(base, imm).unwrap();
                    for c in samples(lo, hi) {
                        if !contains(out, c + imm) {
                            bad += 1;
                        }
                    }
                }
            }
        }
    }
    bad
}

/// ADD64_X (Pkt + Scalar): every concrete `p+s` must be in the widened offset.
fn check_add_x() -> usize {
    let mut bad = 0;
    for &plo in PTS {
        for &phi in PTS {
            if phi < plo {
                continue;
            }
            for &slo in &[0i64, 1, 14, 255] {
                for &shi in &[0i64, 1, 14, 255, 65535] {
                    if shi < slo {
                        continue;
                    }
                    let out = add_x(Abs::Pkt { lo: plo, hi: phi }, Abs::Scalar { lo: slo, hi: shi, t: TNUM_UNKNOWN }).unwrap();
                    for p in samples(plo, phi) {
                        for s in samples(slo, shi) {
                            if !contains(out, p + s) {
                                bad += 1;
                            }
                        }
                    }
                }
            }
        }
    }
    bad
}

/// AND64_K interval soundness: for a fully-unknown input, `x & imm` must be in
/// `and_k(⊤, imm)`. (Bit-level precision is covered by the tnum_and check.)
fn check_and_k() -> usize {
    let mut bad = 0;
    for &imm in &[0i64, 1, 3, 6, 0xff, 0xffff, 0x7fff_ffff] {
        let out = and_k(S_TOP, imm);
        for &x in &[0i64, 1, 2, imm, (imm - 1).max(0), 0x1234, u32::MAX as i64, 0x7fff_ffff] {
            let concrete = ((x as u64) & (imm as u64)) as i64;
            if !contains(out, concrete) {
                bad += 1;
            }
        }
    }
    bad
}

// --- tnum soundness (Agni-style) ---------------------------------------------
// A representative grid of tnums (known bits + unknown-bit masks) over a mix of
// low and wide bit positions.
fn tnum_grid() -> Vec<Tnum> {
    let mut g = Vec::new();
    let pats: &[u64] = &[0, 1, 2, 6, 0x0f, 0x08, 0xff, 0x0800, 0xffff, 0xC0A8_0000];
    for &value in pats {
        for &mask in pats {
            // Invariant: value & mask == 0 (a bit can't be both known and unknown).
            g.push(Tnum { value: value & !mask, mask });
        }
    }
    g
}
// Concrete values consistent with a tnum: known bits fixed, a spread of unknowns.
fn tnum_samples(t: Tnum) -> Vec<u64> {
    let mut s = vec![t.value, t.value | t.mask];
    let mut bit = 0;
    while bit < 64 {
        if t.mask & (1u64 << bit) != 0 {
            s.push(t.value | (1u64 << bit));
        }
        bit += 1;
    }
    s.truncate(24);
    s
}
// Check a binary tnum op over-approximates the concrete op: for every consistent
// (x,y), concrete(x,y) must be denoted by the abstract result.
fn check_tnum2(op_abs: fn(Tnum, Tnum) -> Tnum, op_conc: fn(u64, u64) -> u64) -> usize {
    let mut bad = 0;
    let g = tnum_grid();
    for &a in &g {
        for &b in &g {
            let out = op_abs(a, b);
            for &x in &tnum_samples(a) {
                for &y in &tnum_samples(b) {
                    if !tnum_contains(out, op_conc(x, y)) {
                        bad += 1;
                    }
                }
            }
        }
    }
    bad
}
// A deliberately-unsound tnum AND (claims too many known bits) — must be caught.
fn bad_tnum_and(a: Tnum, b: Tnum) -> Tnum {
    let t = tnum_and(a, b);
    Tnum { value: t.value, mask: t.mask & (t.mask >> 1) } // wrongly narrows the unknowns
}

// --- EXHAUSTIVE tnum soundness over a reduced bit-width (Agni's "exhaustive, not
// sampled" property, made runnable without SMT) ------------------------------
// Enumerate EVERY tnum over `w` bits (each bit ∈ {known-0, known-1, unknown} ⇒
// 3^w tnums) and, for each pair, EVERY consistent concrete (x,y). This is a
// COMPLETE proof of soundness on the w-bit domain — no operator can hide an
// unsound case the way sampling can. For the bit-independent operators
// (and/or/xor/lshift) each bit position is symmetric and independent, so w-bit
// soundness generalizes to full 64-bit width; for carry-coupled tnum_add it is
// a complete proof up to width w (full width still wants the SMT/Kani step).
fn tnums_of_width(w: u32) -> Vec<Tnum> {
    let mut out = vec![Tnum { value: 0, mask: 0 }];
    for bit in 0..w {
        let b = 1u64 << bit;
        let mut next = Vec::with_capacity(out.len() * 3);
        for t in &out {
            next.push(*t); // bit known-0
            next.push(Tnum { value: t.value | b, mask: t.mask }); // known-1
            next.push(Tnum { value: t.value, mask: t.mask | b }); // unknown
        }
        out = next;
    }
    out
}
// Every concrete value a tnum denotes within `w` bits (2^popcount(mask) of them).
fn concrete_of(t: Tnum, w: u32) -> Vec<u64> {
    let bits: Vec<u32> = (0..w).filter(|&i| t.mask & (1u64 << i) != 0).collect();
    let mut out = Vec::with_capacity(1 << bits.len());
    for combo in 0u64..(1u64 << bits.len()) {
        let mut v = t.value;
        for (j, &bit) in bits.iter().enumerate() {
            if combo & (1u64 << j) != 0 {
                v |= 1u64 << bit;
            }
        }
        out.push(v);
    }
    out
}
fn check_tnum2_exhaustive(op_abs: fn(Tnum, Tnum) -> Tnum, op_conc: fn(u64, u64) -> u64, w: u32) -> usize {
    let ts = tnums_of_width(w);
    let mut bad = 0;
    for &a in &ts {
        let ax = concrete_of(a, w);
        for &b in &ts {
            let out = op_abs(a, b);
            let by = concrete_of(b, w);
            for &x in &ax {
                for &y in &by {
                    if !tnum_contains(out, op_conc(x, y)) {
                        bad += 1;
                    }
                }
            }
        }
    }
    bad
}
// Exhaustive unary check for tnum_lshift over the w-bit domain and all shifts.
fn check_lshift_exhaustive(w: u32) -> usize {
    let ts = tnums_of_width(w);
    let mut bad = 0;
    for &a in &ts {
        for n in 0..=w {
            let out = tnum_lshift(a, n);
            for &x in &concrete_of(a, w) {
                if !tnum_contains(out, x << n) {
                    bad += 1;
                }
            }
        }
    }
    bad
}

fn main() {
    println!("== HEQK BPF verifier — abstract-operator soundness harness (P16 / Agni)");
    println!("   scope: verifier-reachable domain (loads 0..2^32, packet offsets, i32 imms)");
    let a = check_add_k();
    let b = check_add_x();
    let c = check_and_k();
    for (name, n) in [("ADD64_K", a), ("ADD64_X", b), ("AND64_K", c)] {
        println!("   {name}: {}", if n == 0 { "SOUND (over-approximates)" } else { "UNSOUND!" });
    }
    // tnum operators (bitwise precision beyond PREVAIL/Windows) — soundness.
    let ta = check_tnum2(tnum_and, |x, y| x & y);
    let to = check_tnum2(tnum_or, |x, y| x | y);
    let tx = check_tnum2(tnum_xor, |x, y| x ^ y);
    let td = check_tnum2(tnum_add, |x, y| x.wrapping_add(y));
    for (name, n) in [("tnum_and", ta), ("tnum_or", to), ("tnum_xor", tx), ("tnum_add", td)] {
        println!("   {name}: {}", if n == 0 { "SOUND (over-approximates)" } else { "UNSOUND!" });
    }
    let caught = check_tnum2(bad_tnum_and, |x, y| x & y);
    println!("   control: injected-unsound tnum_and -> {caught} counterexample(s) CAUGHT by the harness");

    // EXHAUSTIVE (complete) soundness over a reduced bit-width — a real proof on
    // that domain, not a sample. W=6 ⇒ every one of 3^6 tnums and every pair,
    // fully concretized (~16^6 checks/op, ~sub-second in release).
    const W: u32 = 6;
    let ea = check_tnum2_exhaustive(tnum_and, |x, y| x & y, W);
    let eo = check_tnum2_exhaustive(tnum_or, |x, y| x | y, W);
    let ex = check_tnum2_exhaustive(tnum_xor, |x, y| x ^ y, W);
    let ed = check_tnum2_exhaustive(tnum_add, |x, y| x.wrapping_add(y), W);
    let el = check_lshift_exhaustive(W);
    let ecaught = check_tnum2_exhaustive(bad_tnum_and, |x, y| x & y, W);
    for (name, n) in [("and", ea), ("or", eo), ("xor", ex), ("add", ed), ("lshift", el)] {
        println!(
            "   EXHAUSTIVE tnum_{name} (complete over {W}-bit domain): {}",
            if n == 0 { "PROVEN SOUND" } else { "UNSOUND!" }
        );
    }
    println!("   EXHAUSTIVE control: injected-unsound op -> {ecaught} counterexample(s) CAUGHT (exhaustive)");

    let exhaustive_unsound = ea + eo + ex + ed + el;
    let prod_unsound = a + b + c + ta + to + tx + td + exhaustive_unsound;
    let ok = prod_unsound == 0 && caught > 0 && ecaught > 0;
    println!(
        "[P16-verifier] {} — production operators sound on the reachable domain; harness catches injected unsoundness",
        if ok { "PASS" } else { "FAIL" }
    );
    std::process::exit(if ok { 0 } else { 1 });
}
