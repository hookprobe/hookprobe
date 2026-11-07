//! Int8 dot-product kernels — the DGA classifier's hot loop
//! (base-tier-build-ticket.md Phase 4, must-fix #2).
//!
//! Three tiers, selected at COMPILE TIME via `cfg`/Cargo feature (wasm has no runtime
//! CPU-feature-detection API, unlike native code, so there is no "check the host, then
//! branch" option — the choice is baked in when the `.wasm` is built):
//!
//! 1. **`dot_relaxed`** (feature `relaxed-dot`, wasm32 only) — uses the EXPLICIT
//!    `core::arch::wasm32::i32x4_relaxed_dot_i8x16_i7x16_add` intrinsic. **Must-fix #2**:
//!    plain `core::simd` portable SIMD does **not** emit the
//!    `i32x4.relaxed_dot_i8x16_i7x16_add_s` opcode — this crate never routes the hot
//!    loop through `core::simd`, only through this explicit `core::arch::wasm32` call.
//!    Only ever compiled by `sdot-gate.sh` into the SEPARATE `dga-lm.relaxed.wasm`
//!    artifact behind `--features relaxed-dot`; the co-located `dga-lm.wasm` the shared
//!    AOT pipeline (`builder/refresh-aot.sh --precompile all`) precompiles for every
//!    device is built WITHOUT this feature and so NEVER contains this opcode — kept out
//!    of that shared pipeline's blast radius by construction (see `sdot-gate.sh`'s doc
//!    header for why: whether Cranelift's aarch64 backend has a safe/complete lowering
//!    for this op on non-dotprod silicon has NOT been verified on real hardware, so this
//!    crate does not bet the shared per-module pipeline on it).
//! 2. **`dot_simd128`** (wasm32, always compiled — the DEFAULT/baseline tier) — standard
//!    (non-relaxed, finalized) WASM SIMD widening-multiply-add
//!    (`i16x8_extmul_{low,high}_i8x16` + `i32x4_dot_i16x8`). This is the "A72 NEON
//!    widening-multiply fallback path" the ticket calls for: Cranelift lowers these
//!    STANDARD ops to SMULL/SMLAL-equivalent NEON sequences on any aarch64 target,
//!    dotprod ISA extension or not — correct and portable everywhere, no RUSTFLAGS or
//!    target-feature build flag needed (see the note below). THIS is what ships in the
//!    co-located baseline `dga-lm.wasm`.
//! 3. **`dot_scalar`** — plain Rust, always available (any target). Used as the
//!    correctness oracle in tests, and as the fallback on non-wasm32 hosts (`cargo test`
//!    runs natively, where `core::arch::wasm32` does not exist at all).
//!
//! ## Build flags — the baseline is correct with no flags; SIMD/SDOT acceleration is gated
//!
//! `core::arch::wasm32`'s SIMD intrinsics are `#[target_feature(enable = "...")]`-gated
//! SAFE functions (this crate builds every `v128` operand via the safe `i8x16(...)`
//! lane-literal constructor, never an `unsafe` `v128_load`, so `#![forbid(unsafe_code)]`
//! holds for the whole file). The baseline module (`dga-lm.wasm`, the `dot_simd128` tier)
//! COMPILES AND IS CORRECT with no special RUSTFLAGS — that is exactly what the shared
//! `builder/refresh-aot.sh --precompile all` pipeline builds for every device, and its
//! correctness is covered by the tests below.
//!
//! Whether the wasm32 backend actually EMITS the `simd128` / `relaxed-simd` opcodes (vs.
//! scalarizing them) is deliberately NOT assumed here: wasm historically needs
//! `-C target-feature=+simd128` (and `+relaxed-simd` for the A76 tier) for the backend to
//! emit v128 ops at all, and that behaviour can vary by toolchain version. So this crate
//! never *claims* the acceleration — it *verifies* it. `tools/sdot-gate/sdot-gate.sh`
//! builds the `relaxed-dot` tier with `-C target-feature=+simd128,+relaxed-simd` and
//! disassembles the output to confirm (a) the `.wat` carries the relaxed-dot opcode and
//! (b) the `.a76.cwasm` carries an `SDOT` instruction — and DROPS the throughput claim
//! (never the module itself; the portable tier still ships and is correct) if a
//! disassembler is unavailable or the opcode does not appear (must-fix #2, ADR 0021 D7).
//! This is why `modules/dga-lm/Cargo.toml`'s `relaxed-dot` feature is documented as
//! *also* requiring those RUSTFLAGS — the two files now agree.
//!
//! All three tiers are functionally identical (verified in `tests` below): dot(a, b) =
//! Σ aᵢ·bᵢ for two equal-length `i8` slices, accumulated as `i32`. Callers never see
//! which tier ran — `dot_i8` picks the best compiled-in tier via `cfg` cascading.
//!
//! **Determinism note (ADR 0021 D7 / C9):** the relaxed-dot tier is, by the WebAssembly
//! Relaxed SIMD proposal's own definition, allowed to differ in its INTERMEDIATE
//! rounding across hosts for inputs at exactly `i8::MIN` (-128). `model.rs`'s
//! quantization clamps every weight AND activation to `[-127, 127]` specifically to
//! avoid that edge case — with that clamp, `dot_relaxed`'s result is bit-identical to
//! the portable/scalar tiers on every host Wasmtime targets today (verified in
//! `tests::relaxed_matches_scalar_when_clamped`, only compiled with `--features
//! relaxed-dot`). dga-lm is advisory/observe-only (C9) regardless, so even a residual
//! host-dependent LSB would never affect an enforcement decision — recorded for
//! honesty, not because it is load-bearing.
//!
//! `#![forbid(unsafe_code)]` (see `lib.rs`) holds for this whole file: every kernel
//! below is 100% safe Rust — no raw pointers, no `unsafe fn`, no `unsafe` block.

/// Build a `v128` from a 16-element `i8` slice via the safe lane-literal constructor
/// (never a raw-pointer `v128_load`, which is `unsafe`). `a.len()` must be exactly 16 —
/// callers always pass a `chunks_exact(16)` chunk, so this is an invariant, not a
/// general contract.
#[cfg(target_arch = "wasm32")]
fn load16(a: &[i8]) -> core::arch::wasm32::v128 {
    use core::arch::wasm32::i8x16;
    debug_assert_eq!(a.len(), 16);
    i8x16(
        a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8], a[9], a[10], a[11], a[12], a[13],
        a[14], a[15],
    )
}

/// Reference scalar dot product. Always correct, always available, the oracle every
/// other tier is tested against.
pub fn dot_scalar(a: &[i8], b: &[i8]) -> i32 {
    debug_assert_eq!(a.len(), b.len());
    a.iter()
        .zip(b.iter())
        .map(|(&x, &y)| (x as i32) * (y as i32))
        .sum()
}

/// Standard (non-relaxed) WASM SIMD widening-multiply-add — the A72/portable NEON
/// fallback tier (see the module doc). `a.len()`/`b.len()` must be a multiple of 16 —
/// the model only ever calls this with 64-element windows (4 chunks of 16 lanes; see
/// `model::WINDOW_LEN`).
#[cfg(target_arch = "wasm32")]
pub fn dot_simd128(a: &[i8], b: &[i8]) -> i32 {
    use core::arch::wasm32::*;
    debug_assert_eq!(a.len(), b.len());
    debug_assert_eq!(a.len() % 16, 0);

    let mut acc = i32x4_splat(0);
    for (ca, cb) in a.chunks_exact(16).zip(b.chunks_exact(16)) {
        let va = load16(ca);
        let vb = load16(cb);
        // Widen both halves (8 lanes each) i8 -> i16, multiply, giving two i16x8
        // products; feed each into i32x4_dot_i16x8 (pairwise-sum-of-products) — itself
        // a STANDARD (non-relaxed) SIMD op, stable since Rust 1.54 — the exact
        // "widening multiply + pairwise add" shape that lowers to SMULL/SMLAL on
        // aarch64 without the dotprod ISA extension.
        let lo_a = i16x8_extend_low_i8x16(va);
        let lo_b = i16x8_extend_low_i8x16(vb);
        let hi_a = i16x8_extend_high_i8x16(va);
        let hi_b = i16x8_extend_high_i8x16(vb);
        acc = i32x4_add(acc, i32x4_dot_i16x8(lo_a, lo_b));
        acc = i32x4_add(acc, i32x4_dot_i16x8(hi_a, hi_b));
    }
    i32x4_extract_lane::<0>(acc)
        + i32x4_extract_lane::<1>(acc)
        + i32x4_extract_lane::<2>(acc)
        + i32x4_extract_lane::<3>(acc)
}

/// A76-tier relaxed-dot kernel. Only compiled with `--features relaxed-dot` (see
/// `sdot-gate.sh`) — the EXPLICIT intrinsic must-fix #2 requires.
/// `i32x4_relaxed_dot_i8x16_i7x16_add(a, b, acc)` computes
/// `acc[i] + Σ a[4i..4i+4]·b[4i..4i+4]` per lane (16 int8 lanes in, 4 int32 lanes out) —
/// the single-instruction SDOT shape on aarch64 dotprod hardware.
#[cfg(all(target_arch = "wasm32", feature = "relaxed-dot"))]
pub fn dot_relaxed(a: &[i8], b: &[i8]) -> i32 {
    use core::arch::wasm32::*;
    debug_assert_eq!(a.len(), b.len());
    debug_assert_eq!(a.len() % 16, 0);

    let mut acc = i32x4_splat(0);
    for (ca, cb) in a.chunks_exact(16).zip(b.chunks_exact(16)) {
        let va = load16(ca);
        let vb = load16(cb);
        // THE explicit relaxed-dot intrinsic (must-fix #2) — NOT `core::simd`.
        acc = i32x4_relaxed_dot_i8x16_i7x16_add(va, vb, acc);
    }
    i32x4_extract_lane::<0>(acc)
        + i32x4_extract_lane::<1>(acc)
        + i32x4_extract_lane::<2>(acc)
        + i32x4_extract_lane::<3>(acc)
}

/// Dispatcher — picks the best compiled-in tier. `model.rs` only ever calls this; it
/// never has to know which tier is underneath.
#[cfg(all(target_arch = "wasm32", feature = "relaxed-dot"))]
pub fn dot_i8(a: &[i8], b: &[i8]) -> i32 {
    dot_relaxed(a, b)
}

#[cfg(all(target_arch = "wasm32", not(feature = "relaxed-dot")))]
pub fn dot_i8(a: &[i8], b: &[i8]) -> i32 {
    dot_simd128(a, b)
}

#[cfg(not(target_arch = "wasm32"))]
pub fn dot_i8(a: &[i8], b: &[i8]) -> i32 {
    dot_scalar(a, b)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_vectors() -> (Vec<i8>, Vec<i8>) {
        // 64 elements (4x16 lanes) — the model's WINDOW_LEN. Values clamped to
        // [-127, 127] (never -128 — see the module doc's determinism note).
        let a: Vec<i8> = (0..64).map(|i| (i * 7 % 255 - 127).clamp(-127, 127) as i8).collect();
        let b: Vec<i8> = (0..64).map(|i| (i * 13 % 255 - 127).clamp(-127, 127) as i8).collect();
        (a, b)
    }

    #[test]
    fn scalar_matches_naive_sum() {
        let (a, b) = sample_vectors();
        let expected: i64 = a.iter().zip(b.iter()).map(|(&x, &y)| x as i64 * y as i64).sum();
        assert_eq!(dot_scalar(&a, &b) as i64, expected);
    }

    #[test]
    fn dispatcher_matches_scalar_oracle() {
        let (a, b) = sample_vectors();
        assert_eq!(dot_i8(&a, &b), dot_scalar(&a, &b));
    }

    #[cfg(target_arch = "wasm32")]
    #[test]
    fn simd128_matches_scalar_oracle() {
        let (a, b) = sample_vectors();
        assert_eq!(dot_simd128(&a, &b), dot_scalar(&a, &b));
    }

    #[cfg(all(target_arch = "wasm32", feature = "relaxed-dot"))]
    #[test]
    fn relaxed_matches_scalar_when_clamped() {
        let (a, b) = sample_vectors();
        assert_eq!(dot_relaxed(&a, &b), dot_scalar(&a, &b));
    }

    #[test]
    fn zero_vectors_dot_to_zero() {
        let z = vec![0i8; 64];
        assert_eq!(dot_i8(&z, &z), 0);
    }
}
