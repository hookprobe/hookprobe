// SPDX-License-Identifier: AGPL-3.0-only
//! The job vocabulary core 0 may send a worker (S1). Small and closed on purpose: the compute
//! engine (S2) is added as a new op, never as a function pointer from the kernel (a worker must not
//! execute kernel code).

/// One request from core 0.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Job {
    pub id: u32,
    pub op: u32,
    pub a: u64,
    pub b: u64,
}

/// One result to core 0.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Done {
    pub id: u32,
    pub status: u32,
    pub value: u64,
}

pub mod op {
    /// value = a ^ b.
    pub const ECHO: u32 = 1;
    /// value = wrapping sum of `b` u64 words at address `a` (must lie in the granted window).
    pub const SUM64: u32 = 2;
    /// value = FNV-1a 64 over `b` bytes at address `a` (must lie in the granted window).
    pub const FNV64: u32 = 3;
    /// Deliberate `brk`: the worker's own vectors must contain it (fault-containment gate).
    pub const FAULT: u32 = 0xDEAD;
    /// `mmu-probe` feature only: value = the u64 at address `a`, with NO window check (MMU-boundary proof).
    pub const PROBE_READ: u32 = 0xBAD0;
    /// `mmu-probe` feature only: write `b` to address `a`, with NO window check (MMU-boundary proof).
    pub const PROBE_WRITE: u32 = 0xBAD1;
    /// S1c: a bounded busy job. `a` = iterations of a small integer loop, `b` = budget in counter ticks. value =
    /// the loop's checksum when it finishes in budget; status DEADLINE (value = iterations done) when it does not.
    pub const SPIN: u32 = 4;
    /// S2: y = W·x over int8 (i32 accumulate). `a` = address of a [`GemvParams`](super::GemvParams) block in the
    /// granted window; W and x must lie in the window too. value = [`hash_i32`](super::hash_i32) of y.
    pub const GEMV_I8: u32 = 0x10;
}

/// How a GEMV_I8 job is computed. Every path must give byte-identical y (integer arithmetic, wrapping).
pub mod path {
    /// In the worker executive itself (softfloat build, scalar code): the reference on a worker.
    pub const SCALAR: u32 = 0;
    /// In the hard-float worker engine, NEON SMULL/SADALP.
    pub const NEON: u32 = 1;
    /// In the hard-float worker engine, SDOT (only where ID_AA64ISAR0_EL1.DP >= 1).
    pub const SDOT: u32 = 2;
}

/// Largest GEMV the S2a probe accepts (rows of y live on the worker's stack).
pub const GEMV_MAX_ROWS: u32 = 256;
pub const GEMV_MAX_COLS: u32 = 4096;

/// Parameters of a GEMV_I8 job, placed by core 0 in the granted window. Shared by the worker executive and the
/// hard-float engine image (both compile this crate), so the layout cannot drift.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GemvParams {
    /// Address of W: `rows * cols` int8, row-major.
    pub w: u64,
    /// Address of x: `cols` int8.
    pub x: u64,
    pub rows: u32,
    /// A multiple of 16.
    pub cols: u32,
    pub path: u32,
    pub _pad: u32,
}

/// The engine image's entry point (C ABI, integers and pointers only, so a softfloat caller and a hard-float
/// callee agree): computes `rows` outputs into `out` and returns a [`status`] code.
pub type EngineEntry = unsafe extern "C" fn(op: u32, params: *const GemvParams, out: *mut i32, out_len: usize) -> u32;

/// Reference GEMV: y[r] = sum over c of W[r][c] * x[c], wrapping i32.
pub fn gemv_i8_scalar(w: &[i8], x: &[i8], rows: usize, cols: usize, y: &mut [i32]) -> bool {
    if w.len() < rows * cols || x.len() < cols || y.len() < rows {
        return false;
    }
    for (r, out) in y.iter_mut().take(rows).enumerate() {
        let row = &w[r * cols..(r + 1) * cols];
        *out = row.iter().zip(x).fold(0i32, |acc, (&a, &b)| acc.wrapping_add(i32::from(a) * i32::from(b)));
    }
    true
}

/// FNV-1a 64 over y as little-endian i32 bytes: the value a GEMV job returns, compared bit for bit.
pub fn hash_i32(y: &[i32]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for v in y {
        for b in v.to_le_bytes() {
            h ^= u64::from(b);
            h = h.wrapping_mul(0x0000_0100_0000_01b3);
        }
    }
    h
}

pub mod status {
    pub const OK: u32 = 0;
    pub const UNKNOWN_OP: u32 = 1;
    /// Address range outside the window core 0 granted, misaligned, or overflowing.
    pub const OUT_OF_WINDOW: u32 = 2;
    /// The requested path needs something this core or image lacks (e.g. SDOT without DotProd, or no engine).
    pub const UNSUPPORTED: u32 = 3;
    /// Parameters out of range (rows, cols, alignment).
    pub const BAD_PARAMS: u32 = 4;
    /// The job ran out of its time budget and stopped (S1c).
    pub const DEADLINE: u32 = 5;
}

/// `[addr, addr + len)` lies inside `[base, base + size)` without overflow, and `addr` is aligned.
pub fn in_window(addr: u64, len: u64, align: u64, base: u64, size: u64) -> bool {
    let Some(end) = addr.checked_add(len) else { return false };
    let Some(wend) = base.checked_add(size) else { return false };
    align != 0 && addr % align == 0 && addr >= base && end <= wend
}

pub fn fnv64(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in bytes {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

pub fn sum64(words: &[u64]) -> u64 {
    words.iter().fold(0u64, |s, &w| s.wrapping_add(w))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn window_bounds() {
        assert!(in_window(0x1000, 16, 8, 0x1000, 0x100));
        assert!(in_window(0x10f0, 16, 8, 0x1000, 0x100));
        assert!(!in_window(0x10f8, 16, 8, 0x1000, 0x100), "past the end");
        assert!(!in_window(0x0ff8, 16, 8, 0x1000, 0x100), "before the start");
        assert!(!in_window(0x1004, 8, 8, 0x1000, 0x100), "misaligned");
        assert!(!in_window(u64::MAX - 4, 16, 1, 0, u64::MAX), "overflow");
        assert!(!in_window(0x1000, 8, 0, 0x1000, 0x100), "zero alignment");
    }

    #[test]
    fn gemv_reference() {
        let w: [i8; 32] = core::array::from_fn(|i| (i as i8).wrapping_mul(37).wrapping_sub(64));
        let x: [i8; 16] = core::array::from_fn(|i| 127 - (i as i8) * 15);
        let mut y = [0i32; 2];
        assert!(gemv_i8_scalar(&w, &x, 2, 16, &mut y));
        let want0: i32 = (0..16).map(|c| i32::from(w[c]) * i32::from(x[c])).sum();
        let want1: i32 = (0..16).map(|c| i32::from(w[16 + c]) * i32::from(x[c])).sum();
        assert_eq!(y, [want0, want1]);
        assert!(!gemv_i8_scalar(&w, &x, 3, 16, &mut [0; 3]), "W too short");
        assert_ne!(hash_i32(&[1, 2]), hash_i32(&[2, 1]));
        assert_eq!(core::mem::size_of::<GemvParams>(), 32);
    }

    #[test]
    fn fnv_known_answer() {
        assert_eq!(fnv64(b""), 0xcbf2_9ce4_8422_2325);
        assert_eq!(fnv64(b"a"), 0xaf63_dc4c_8601_ec8c);
    }
}
