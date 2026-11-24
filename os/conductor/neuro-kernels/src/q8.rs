// SPDX-License-Identifier: AGPL-3.0-only
//! 8-bit weights (`Q8_0`), integer only, in two layouts that compute the same numbers bit for bit.
//!
//! **GGUF layout.** A block is 34 bytes: a binary16 scale `d` (little-endian bits) followed by 32 signed
//! bytes `q`; the weight is `d · q`. Rows are consecutive blocks, exactly as llama.cpp stores them.
//!
//! **Packed layout** ([`pack`]). Rows in groups of four; per group and block of 32 columns, one 144-byte
//! record: the four rows' 32 weights (128 bytes), then the four scales pre-decoded to an integer mantissa
//! and exponent (`i16 mw[4]`, `i16 nsw[4]`, value = `mw · 2^nsw`). Records are 16-byte aligned, so every
//! load is aligned, and the scale arithmetic for four rows is a handful of vector instructions. The packing
//! is lossless: [`unpack_row`] reproduces the GGUF bytes exactly (binary16 −0 included), so a packed model
//! can be checked against the GGUF file's hash. Size: 144 bytes per 128 weights (+5.9 % over GGUF).
//!
//! **Activations** are quantised as llama.cpp's CPU path does for `Q8_0`: per block of 32, scale
//! `amax / 127`, `q = round(x / scale)`, here from 64-bit fixed point ([`hp`](crate::hp)); the scale is an
//! integer mantissa `cm` (2^14 ≤ cm < 2^16) and exponent `ce`.
//!
//! **One output row** = `Σ_b dot_b · mw_b · cm_b · 2^(ce_b − sw_b)`, with `dot_b` the int32 dot product of
//! block `b` (SDOT on NEON). Each block term is computed exactly (`|dot · mw| < 2^31`, `|· cm| < 2^46`) and
//! placed on a per-call grid `2^-K` with one rounding (half up), then summed in an i64:
//! `K = L − ce_max − wexp`, `L = 16 − ⌈log2(blocks)⌉`, `wexp` the matrix's largest weight exponent (from
//! [`wexp_gguf`] or [`wexp_packed`], computed once at admission). Every term is then below `2^(46+L)` and
//! the sum below `2^62`, so nothing can overflow, for any input. Each term is rounded once, to below
//! 2^-(47+L) of the largest term the call could produce: about 2^-55 relative for a Qwen3 row.

/// Columns per block and bytes per GGUF block.
pub const QK: usize = 32;
pub const BLOCK_BYTES: usize = 34;
/// Bytes per packed record (4 rows × 32 weights + 4 mantissas + 4 exponents).
pub const P_BLOCK: usize = 144;
/// Largest supported row length (columns).
pub const MAX_COLS: usize = 32 * 1024;
/// Exponent marker for a binary16 −0 in the packed layout (its mantissa is 0).
const NEG_ZERO: i16 = -25;

/// Bytes of one GGUF row of `cols` columns.
pub const fn row_bytes(cols: usize) -> usize {
    cols / QK * BLOCK_BYTES
}

/// Bytes of a packed matrix (rows padded to a multiple of four).
pub const fn packed_bytes(rows: usize, cols: usize) -> usize {
    rows.div_ceil(4) * (cols / QK) * P_BLOCK
}

/// binary16 bits → `(mantissa, shift)` with value = mantissa · 2^-shift. Infinity and NaN decode to 0
/// (admission refuses them; see [`scales_finite`]).
#[inline]
pub fn half_parts(bits: u16) -> (i32, i32) {
    let e = i32::from((bits >> 10) & 0x1f);
    let f = i32::from(bits & 0x3ff);
    let (m, s) = match e {
        0 => (f, 24),
        31 => (0, 0),
        _ => (1024 + f, 25 - e),
    };
    (if bits & 0x8000 != 0 { -m } else { m }, s)
}

/// True if every block scale in `w` is finite (no infinity or NaN). An admission-time check.
pub fn scales_finite(w: &[u8]) -> bool {
    w.chunks_exact(BLOCK_BYTES).all(|b| match b {
        [lo, hi, ..] => (u16::from_le_bytes([*lo, *hi]) >> 10) & 0x1f != 31,
        _ => false,
    })
}

/// Round-half-away-from-zero division of an i128 by 2^s (s ≤ 126).
#[inline]
fn rshift_round_128(v: i128, s: u32) -> i128 {
    if s == 0 {
        return v;
    }
    let half = 1i128 << (s - 1);
    if v >= 0 {
        (v + half) >> s
    } else {
        -((-v + half) >> s)
    }
}

/// Activations quantised per block: `x ≈ q · m · 2^e` (in the fixed-point unit of the input).
#[derive(Clone, Copy, Debug)]
pub struct Act<'a> {
    pub q: &'a [i8],
    pub scale: &'a [(i32, i32)],
}

/// Quantise `x` (any fixed-point unit, here 2^-16) per block of 32. `q.len() == x.len()`,
/// `scale.len() == x.len() / 32`. Returns false (changing nothing) on a length mismatch.
pub fn quantize(x: &[i64], q: &mut [i8], scale: &mut [(i32, i32)]) -> bool {
    if x.len() % QK != 0 || x.len() > MAX_COLS || q.len() != x.len() || scale.len() != x.len() / QK {
        return false;
    }
    for ((xb, qb), sc) in x.chunks_exact(QK).zip(q.chunks_exact_mut(QK)).zip(scale.iter_mut()) {
        let amax = xb.iter().map(|v| v.unsigned_abs()).max().unwrap_or(0);
        if amax == 0 {
            qb.fill(0);
            *sc = (0, 0);
            continue;
        }
        let a = i128::from(amax);
        for (o, &v) in qb.iter_mut().zip(xb) {
            // round(v · 127 / amax), |result| ≤ 127
            let num = i128::from(v) * 127;
            let r = if num >= 0 { (num + a / 2) / a } else { -((-num + a / 2) / a) };
            *o = r.clamp(-127, 127) as i8;
        }
        // scale = amax / 127 = m · 2^e with 2^14 ≤ m < 2^16 (amax · 2^t < 2^22, so m < 33,026).
        let b = 64 - amax.leading_zeros() as i32; // bit length, 1..=64
        let t = 22 - b;
        let m = if t >= 0 {
            let num = a << t;
            (num + 63) / 127
        } else {
            let den = 127i128 << (-t);
            (a + den / 2) / den
        };
        *sc = (m as i32, -t);
    }
    true
}

/// Largest weight exponent (`−shift` of the binary16 scale) of a GGUF-layout matrix; −25 if all scales are 0.
pub fn wexp_gguf(w: &[u8]) -> i32 {
    w.chunks_exact(BLOCK_BYTES).fold(-25, |m, b| match b {
        [lo, hi, ..] => {
            let (mw, sw) = half_parts(u16::from_le_bytes([*lo, *hi]));
            if mw == 0 { m } else { m.max(-sw) }
        }
        _ => m,
    })
}

/// Largest weight exponent of a packed matrix (same value as [`wexp_gguf`] on the matrix it was packed from).
pub fn wexp_packed(w: &[u8]) -> i32 {
    w.chunks_exact(P_BLOCK).fold(-25, |m, rec| (0..4).fold(m, |m, l| if rd16(rec, 128 + 2 * l) == 0 { m } else { m.max(i32::from(rd16(rec, 136 + 2 * l))) }))
}

/// The grid exponent `K` for one call with a matrix whose largest weight exponent is `wexp`.
pub fn grid(x: &Act, wexp: i32) -> i32 {
    let wexp = wexp.clamp(-25, 5);
    let blocks = x.scale.len().max(1);
    let l = 16 - (usize::BITS - (blocks - 1).leading_zeros()) as i32; // 16 − ⌈log2(blocks)⌉
    match x.scale.iter().filter(|s| s.0 != 0).map(|s| s.1).max() {
        Some(ce_max) => l - ce_max - wexp,
        None => 0,
    }
}

/// Exponent of block `b` on the grid, floored so every shift fits a signed byte (NEON shift operand).
#[inline(always)]
fn eb(e: i32, k: i32) -> i32 {
    (e + k).max(-100)
}

/// One block term on the grid: `round_half_up(dot · mw · cm · 2^s)`, exactly as NEON `SRSHL` computes it.
#[inline(always)]
fn term(dot: i32, mw: i32, cm: i32, s: i32) -> i64 {
    // |dot| ≤ 516,128 and |mw| ≤ 2,047: |p| < 2^31. 0 ≤ cm < 2^16: |t| < 2^46. The wrapping forms never
    // wrap; they drop overflow checks in the innermost loop. s ≤ L ≤ 16 for every non-zero term.
    let p = dot.wrapping_mul(mw);
    let t = i64::from(p).wrapping_mul(i64::from(cm));
    if s >= 0 {
        t.wrapping_shl(s as u32)
    } else if s <= -64 {
        0
    } else {
        let n = (-s) as u32;
        (t + (1i64 << (n - 1))) >> n
    }
}

/// Grid sum → output unit, rounding half up, saturating.
#[inline(always)]
fn finish(acc: i64, k: i32) -> i64 {
    let v = i128::from(acc);
    let r = if k > 0 { (v + (1i128 << (k - 1))) >> k } else { v << (-k).min(60) };
    r.clamp(i128::from(i64::MIN), i128::from(i64::MAX)) as i64
}

fn ok(w: &[u8], x: &Act) -> bool {
    let n = x.q.len();
    n % QK == 0 && n <= MAX_COLS && x.scale.len() == n / QK && w.len() == row_bytes(n)
}

fn act_ok(x: &Act) -> bool {
    let n = x.q.len();
    n > 0 && n % QK == 0 && n <= MAX_COLS && x.scale.len() == n / QK
}

fn row_k(w: &[u8], x: &Act, k: i32) -> i64 {
    let mut acc: i64 = 0;
    for ((blk, xq), &(cm, e)) in w.chunks_exact(BLOCK_BYTES).zip(x.q.chunks_exact(QK)).zip(x.scale) {
        if let [lo, hi, qs @ ..] = blk {
            let dot: i32 = qs.iter().zip(xq).map(|(&a, &b)| i32::from(a as i8) * i32::from(b)).sum();
            let (mw, sw) = half_parts(u16::from_le_bytes([*lo, *hi]));
            acc = acc.wrapping_add(term(dot, mw, cm, eb(e, k) - sw)); // |sum| < 2^62
        }
    }
    finish(acc, k)
}

/// Reference: one GGUF-layout row times quantised activations, in the activations' unit.
pub fn row_scalar(w: &[u8], x: &Act, wexp: i32) -> Option<i64> {
    if !ok(w, x) {
        return None;
    }
    Some(row_k(w, x, grid(x, wexp)))
}

/// One row with the selected implementation. Same contract and bit-identical result as [`row_scalar`].
pub fn row(simd: crate::Simd, w: &[u8], x: &Act, wexp: i32) -> Option<i64> {
    if !ok(w, x) {
        return None;
    }
    let k = grid(x, wexp);
    if simd.is_neon() {
        #[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
        // SAFETY: lengths checked above; the `Simd` token carries the CPU-feature promise.
        return Some(unsafe { neon::row(w, x, k) });
    }
    Some(row_k(w, x, k))
}

/// Reference for four consecutive GGUF-layout rows (`w` holds 4 rows).
pub fn rows4_scalar(w: &[u8], x: &Act, wexp: i32, out: &mut [i64; 4]) -> bool {
    let rb = row_bytes(x.q.len());
    if rb == 0 || w.len() != 4 * rb || !ok(w.get(..rb).unwrap_or(&[]), x) {
        return false;
    }
    let k = grid(x, wexp);
    for (o, wr) in out.iter_mut().zip(w.chunks_exact(rb)) {
        *o = row_k(wr, x, k);
    }
    true
}

fn rows4_k(simd: crate::Simd, w: &[u8], rb: usize, x: &Act, k: i32, out: &mut [i64; 4]) {
    if simd.is_neon() {
        #[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
        {
            // SAFETY: callers checked w.len() == 4·rb and the activations; the token carries the CPU promise.
            unsafe { neon::rows4(w, rb, x, k, out) };
            return;
        }
    }
    for (o, wr) in out.iter_mut().zip(w.chunks_exact(rb)) {
        *o = row_k(wr, x, k);
    }
}

/// Four consecutive GGUF-layout rows with the selected implementation; bit-identical to [`rows4_scalar`].
pub fn rows4(simd: crate::Simd, w: &[u8], x: &Act, wexp: i32, out: &mut [i64; 4]) -> bool {
    let rb = row_bytes(x.q.len());
    if rb == 0 || w.len() != 4 * rb || !ok(w.get(..rb).unwrap_or(&[]), x) {
        return false;
    }
    rows4_k(simd, w, rb, x, grid(x, wexp), out);
    true
}

/// A whole GGUF-layout matrix (`rows` consecutive rows): `sink(row, value)` for each row, four rows at a
/// time, then the remainder. Returns false (calling nothing) if the lengths do not fit.
pub fn matvec(simd: crate::Simd, w: &[u8], rows: usize, x: &Act, wexp: i32, mut sink: impl FnMut(usize, i64)) -> bool {
    let rb = row_bytes(x.q.len());
    if rb == 0 || rows.checked_mul(rb) != Some(w.len()) || !ok(w.get(..rb).unwrap_or(&[]), x) {
        return false;
    }
    let k = grid(x, wexp);
    let mut groups = w.chunks_exact(4 * rb);
    let mut r = 0usize;
    for g in groups.by_ref() {
        let mut o = [0i64; 4];
        rows4_k(simd, g, rb, x, k, &mut o);
        for v in o {
            sink(r, v);
            r += 1;
        }
    }
    for wr in groups.remainder().chunks_exact(rb) {
        let v = if simd.is_neon() { row(simd, wr, x, wexp).unwrap_or(0) } else { row_k(wr, x, k) };
        sink(r, v);
        r += 1;
    }
    true
}

/// Dequantise one GGUF-layout row into fixed point with `frac` fraction bits (embedding lookup).
pub fn dequant_row(w: &[u8], frac: u32, out: &mut [i64]) -> bool {
    if out.len() % QK != 0 || w.len() != row_bytes(out.len()) || frac > 40 {
        return false;
    }
    for (blk, ob) in w.chunks_exact(BLOCK_BYTES).zip(out.chunks_exact_mut(QK)) {
        if let [lo, hi, qs @ ..] = blk {
            let (m, s) = half_parts(u16::from_le_bytes([*lo, *hi]));
            dequant_block(m, s, qs, frac, ob);
        }
    }
    true
}

fn dequant_block(m: i32, s: i32, qs: &[u8], frac: u32, ob: &mut [i64]) {
    let e = frac as i32 - s;
    for (o, &q) in ob.iter_mut().zip(qs) {
        let v = i128::from(m) * i128::from(q as i8);
        *o = (if e >= 0 { v << e } else { rshift_round_128(v, (-e) as u32) }) as i64;
    }
}

// ------------------------------------------------------------------------------------------ packed layout

fn rd16(b: &[u8], i: usize) -> i16 {
    match b.get(i..i + 2) {
        Some([x, y]) => i16::from_le_bytes([*x, *y]),
        _ => 0,
    }
}

/// Canonical packed scale: what [`pack`] can produce, and nothing else.
fn canonical(mw: i16, nsw: i16) -> bool {
    let m = mw.unsigned_abs();
    match m {
        0 => nsw == -24 || nsw == NEG_ZERO,
        1..=1023 => nsw == -24,
        1024..=2047 => (-24..=5).contains(&nsw),
        _ => false,
    }
}

/// Pack a GGUF-layout matrix (`rows × cols`) into `out` (`packed_bytes(rows, cols)` long). Refuses (false,
/// `out` unspecified) wrong lengths and infinite or NaN scales.
pub fn pack(gguf: &[u8], rows: usize, cols: usize, out: &mut [u8]) -> bool {
    let rb = row_bytes(cols);
    if cols == 0 || cols % QK != 0 || cols > MAX_COLS || rows.checked_mul(rb) != Some(gguf.len()) || out.len() != packed_bytes(rows, cols) || !scales_finite(gguf) {
        return false;
    }
    let nb = cols / QK;
    for (gi, grec) in out.chunks_exact_mut(nb * P_BLOCK).enumerate() {
        for (b, rec) in grec.chunks_exact_mut(P_BLOCK).enumerate() {
            rec.fill(0);
            for lane in 0..4 {
                let r = gi * 4 + lane;
                let (mw, nsw, qs): (i16, i16, &[u8]) = match gguf.get(r * rb + b * BLOCK_BYTES..r * rb + (b + 1) * BLOCK_BYTES) {
                    Some([lo, hi, qs @ ..]) => {
                        let bits = u16::from_le_bytes([*lo, *hi]);
                        let (m, s) = half_parts(bits);
                        let nsw = if m == 0 && bits & 0x8000 != 0 { NEG_ZERO } else { -s as i16 };
                        (m as i16, nsw, qs)
                    }
                    _ => (0, -24, &[]), // padding row: zero weights, scale +0
                };
                if let Some(d) = rec.get_mut(32 * lane..32 * lane + qs.len()) {
                    d.copy_from_slice(qs);
                }
                if let Some(d) = rec.get_mut(128 + 2 * lane..130 + 2 * lane) {
                    d.copy_from_slice(&mw.to_le_bytes());
                }
                if let Some(d) = rec.get_mut(136 + 2 * lane..138 + 2 * lane) {
                    d.copy_from_slice(&nsw.to_le_bytes());
                }
            }
        }
    }
    true
}

/// Admission check for a packed matrix from storage: right length and every scale canonical. After this
/// the overflow proof holds (|mw| ≤ 2,047, exponent ≥ −24 and ≤ 5).
pub fn packed_valid(w: &[u8], rows: usize, cols: usize) -> bool {
    if cols == 0 || cols % QK != 0 || cols > MAX_COLS || w.len() != packed_bytes(rows, cols) {
        return false;
    }
    w.chunks_exact(P_BLOCK).all(|rec| (0..4).all(|l| canonical(rd16(rec, 128 + 2 * l), rd16(rec, 136 + 2 * l))))
}

/// Reconstruct GGUF row `r` (its exact bytes) from a packed matrix: the provenance check (hash the result
/// against the GGUF file). Returns false on wrong lengths or a non-canonical scale.
pub fn unpack_row(w: &[u8], rows: usize, cols: usize, r: usize, out: &mut [u8]) -> bool {
    let nb = cols / QK;
    if r >= rows || out.len() != row_bytes(cols) || w.len() != packed_bytes(rows, cols) || cols == 0 || cols % QK != 0 {
        return false;
    }
    let (g, lane) = (r / 4, r % 4);
    for (b, ob) in out.chunks_exact_mut(BLOCK_BYTES).enumerate() {
        let Some(rec) = w.get((g * nb + b) * P_BLOCK..(g * nb + b + 1) * P_BLOCK) else { return false };
        let (mw, nsw) = (rd16(rec, 128 + 2 * lane), rd16(rec, 136 + 2 * lane));
        if !canonical(mw, nsw) {
            return false;
        }
        let m = mw.unsigned_abs();
        let sign: u16 = if mw < 0 || nsw == NEG_ZERO { 0x8000 } else { 0 };
        let bits = match m {
            0..=1023 => sign | m,
            _ => sign | (((25 + nsw) as u16) << 10) | (m - 1024),
        };
        if let (Some(d), Some(q)) = (ob.get_mut(..2), rec.get(32 * lane..32 * lane + 32)) {
            d.copy_from_slice(&bits.to_le_bytes());
            if let Some(dq) = ob.get_mut(2..) {
                dq.copy_from_slice(q);
            }
        }
    }
    true
}

/// Dequantise row `r` of a packed matrix (embedding lookup).
pub fn packed_dequant_row(w: &[u8], rows: usize, r: usize, frac: u32, out: &mut [i64]) -> bool {
    let cols = out.len();
    if cols == 0 || cols % QK != 0 || r >= rows || w.len() != packed_bytes(rows, cols) || frac > 40 {
        return false;
    }
    let (nb, g, lane) = (cols / QK, r / 4, r % 4);
    for (b, ob) in out.chunks_exact_mut(QK).enumerate() {
        let Some(rec) = w.get((g * nb + b) * P_BLOCK..(g * nb + b + 1) * P_BLOCK) else { return false };
        let (mw, nsw) = (i32::from(rd16(rec, 128 + 2 * lane)), i32::from(rd16(rec, 136 + 2 * lane)));
        dequant_block(mw, -nsw, rec.get(32 * lane..32 * lane + 32).unwrap_or(&[]), frac, ob);
    }
    true
}

fn rows4_packed_k(rec_group: &[u8], x: &Act, k: i32, out: &mut [i64; 4]) {
    let mut acc = [0i64; 4];
    for (rec, (xq, &(cm, e))) in rec_group.chunks_exact(P_BLOCK).zip(x.q.chunks_exact(QK).zip(x.scale)) {
        let ebk = eb(e, k);
        for (lane, a) in acc.iter_mut().enumerate() {
            let w = rec.get(32 * lane..32 * lane + 32).unwrap_or(&[]);
            let dot: i32 = w.iter().zip(xq).map(|(&p, &q)| i32::from(p as i8) * i32::from(q)).sum();
            let (mw, nsw) = (i32::from(rd16(rec, 128 + 2 * lane)), i32::from(rd16(rec, 136 + 2 * lane)));
            *a = a.wrapping_add(term(dot, mw, cm, ebk + nsw));
        }
    }
    for (o, a) in out.iter_mut().zip(acc) {
        *o = finish(a, k);
    }
}

/// A whole packed matrix: `sink(row, value)` for each of the `rows` real rows (padding rows are skipped).
/// Bit-identical to [`matvec`] on the GGUF layout it was packed from. Returns false (calling nothing) if
/// the lengths do not fit. Run [`packed_valid`] once at admission.
pub fn matvec_packed(simd: crate::Simd, w: &[u8], rows: usize, x: &Act, wexp: i32, mut sink: impl FnMut(usize, i64)) -> bool {
    let cols = x.q.len();
    if !act_ok(x) || w.len() != packed_bytes(rows, cols) {
        return false;
    }
    let k = grid(x, wexp);
    let gb = cols / QK * P_BLOCK;
    for (g, grp) in w.chunks_exact(gb).enumerate() {
        let mut o = [0i64; 4];
        if simd.is_neon() {
            #[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
            // SAFETY: grp is one group of cols/32 records; activations checked; the token carries the promise.
            unsafe {
                neon::rows4_packed(grp, x, k, &mut o)
            };
        } else {
            rows4_packed_k(grp, x, k, &mut o);
        }
        for (lane, v) in o.into_iter().enumerate() {
            let r = 4 * g + lane;
            if r < rows {
                sink(r, v);
            }
        }
    }
    true
}

/// Four packed rows (one group) by the scalar reference, for differential tests.
pub fn rows4_packed_scalar(group: &[u8], x: &Act, wexp: i32, out: &mut [i64; 4]) -> bool {
    if !act_ok(x) || group.len() != x.q.len() / QK * P_BLOCK {
        return false;
    }
    rows4_packed_k(group, x, grid(x, wexp), out);
    true
}

#[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
mod neon {
    use super::*;
    use core::arch::aarch64::*;

    /// # Safety
    /// `ok(w, x)` holds, and the CPU has NEON + DotProd with FP/SIMD enabled.
    #[target_feature(enable = "neon,dotprod")]
    pub unsafe fn row(w: &[u8], x: &Act, k: i32) -> i64 {
        let blocks = x.q.len() / QK;
        let (mut wp, mut xp) = (w.as_ptr(), x.q.as_ptr());
        let mut acc: i64 = 0;
        for b in 0..blocks {
            let (mw, sw) = half_parts(u16::from_le_bytes([*wp, *wp.add(1)]));
            let w0 = vld1q_s8(wp.add(2).cast::<i8>());
            let w1 = vld1q_s8(wp.add(18).cast::<i8>());
            let d = vdotq_s32(vdotq_s32(vdupq_n_s32(0), w0, vld1q_s8(xp)), w1, vld1q_s8(xp.add(16)));
            let (cm, e) = *x.scale.get_unchecked(b);
            acc = acc.wrapping_add(term(vaddvq_s32(d), mw, cm, eb(e, k) - sw));
            wp = wp.add(BLOCK_BYTES);
            xp = xp.add(QK);
        }
        finish(acc, k)
    }

    /// Four GGUF-layout rows at `w`, `w + rb`, `w + 2rb`, `w + 3rb`.
    ///
    /// # Safety
    /// `w.len() == 4 * rb`, `ok(row, x)` holds for each row, and the CPU has NEON + DotProd with FP/SIMD enabled.
    #[target_feature(enable = "neon,dotprod")]
    pub unsafe fn rows4(w: &[u8], rb: usize, x: &Act, k: i32, out: &mut [i64; 4]) {
        let blocks = x.q.len() / QK;
        let base = w.as_ptr();
        let mut xp = x.q.as_ptr();
        let mut acc = [0i64; 4];
        let zero = vdupq_n_s32(0);
        for b in 0..blocks {
            let x0 = vld1q_s8(xp);
            let x1 = vld1q_s8(xp.add(16));
            let p = base.add(b * BLOCK_BYTES);
            let ps = [p, p.add(rb), p.add(2 * rb), p.add(3 * rb)];
            let d0 = vdotq_s32(vdotq_s32(zero, vld1q_s8(ps[0].add(2).cast()), x0), vld1q_s8(ps[0].add(18).cast()), x1);
            let d1 = vdotq_s32(vdotq_s32(zero, vld1q_s8(ps[1].add(2).cast()), x0), vld1q_s8(ps[1].add(18).cast()), x1);
            let d2 = vdotq_s32(vdotq_s32(zero, vld1q_s8(ps[2].add(2).cast()), x0), vld1q_s8(ps[2].add(18).cast()), x1);
            let d3 = vdotq_s32(vdotq_s32(zero, vld1q_s8(ps[3].add(2).cast()), x0), vld1q_s8(ps[3].add(18).cast()), x1);
            let s = vpaddq_s32(vpaddq_s32(d0, d1), vpaddq_s32(d2, d3));
            let mut dots = [0i32; 4];
            vst1q_s32(dots.as_mut_ptr(), s);
            let (cm, e) = *x.scale.get_unchecked(b);
            let ebk = eb(e, k);
            for ((a, &d), q) in acc.iter_mut().zip(&dots).zip(ps) {
                let (mw, sw) = half_parts(u16::from_le_bytes([*q, *q.add(1)]));
                *a = a.wrapping_add(term(d, mw, cm, ebk - sw));
            }
            xp = xp.add(QK);
        }
        for (o, a) in out.iter_mut().zip(acc) {
            *o = finish(a, k);
        }
    }

    /// One packed group: four rows, `x.q.len() / 32` records of 144 bytes.
    ///
    /// # Safety
    /// `g.len() == x.q.len() / 32 * 144`, `x.scale.len() == x.q.len() / 32`, and the CPU has NEON + DotProd
    /// with FP/SIMD enabled.
    #[target_feature(enable = "neon,dotprod")]
    pub unsafe fn rows4_packed(g: &[u8], x: &Act, k: i32, out: &mut [i64; 4]) {
        let blocks = x.q.len() / QK;
        let (mut p, mut xp) = (g.as_ptr(), x.q.as_ptr());
        let zero = vdupq_n_s32(0);
        let (mut acc01, mut acc23) = (vdupq_n_s64(0), vdupq_n_s64(0));
        for b in 0..blocks {
            let x0 = vld1q_s8(xp);
            let x1 = vld1q_s8(xp.add(16));
            let w = p.cast::<i8>();
            let d0 = vdotq_s32(vdotq_s32(zero, vld1q_s8(w), x0), vld1q_s8(w.add(16)), x1);
            let d1 = vdotq_s32(vdotq_s32(zero, vld1q_s8(w.add(32)), x0), vld1q_s8(w.add(48)), x1);
            let d2 = vdotq_s32(vdotq_s32(zero, vld1q_s8(w.add(64)), x0), vld1q_s8(w.add(80)), x1);
            let d3 = vdotq_s32(vdotq_s32(zero, vld1q_s8(w.add(96)), x0), vld1q_s8(w.add(112)), x1);
            let d = vpaddq_s32(vpaddq_s32(d0, d1), vpaddq_s32(d2, d3));
            // Scales: mw[4] then nsw[4] as i16.
            let sc = vld1q_s16(p.add(128).cast());
            let mw = vmovl_s16(vget_low_s16(sc));
            let nsw = vmovl_high_s16(sc);
            let (cm, e) = *x.scale.get_unchecked(b);
            let sh = vaddq_s32(nsw, vdupq_n_s32(eb(e, k)));
            let pr = vmulq_s32(d, mw); // exact: |dot · mw| < 2^31
            let t01 = vmull_n_s32(vget_low_s32(pr), cm);
            let t23 = vmull_high_n_s32(pr, cm);
            // SRSHL: left shift for s ≥ 0, rounding (half up) right shift for s < 0, 0 for s ≤ −64.
            acc01 = vaddq_s64(acc01, vrshlq_s64(t01, vmovl_s32(vget_low_s32(sh))));
            acc23 = vaddq_s64(acc23, vrshlq_s64(t23, vmovl_high_s32(sh)));
            p = p.add(P_BLOCK);
            xp = xp.add(QK);
        }
        let a = [vgetq_lane_s64::<0>(acc01), vgetq_lane_s64::<1>(acc01), vgetq_lane_s64::<0>(acc23), vgetq_lane_s64::<1>(acc23)];
        for (o, v) in out.iter_mut().zip(a) {
            *o = finish(v, k);
        }
    }
}
