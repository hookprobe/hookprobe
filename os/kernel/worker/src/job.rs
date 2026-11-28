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
}

pub mod status {
    pub const OK: u32 = 0;
    pub const UNKNOWN_OP: u32 = 1;
    /// Address range outside the window core 0 granted, misaligned, or overflowing.
    pub const OUT_OF_WINDOW: u32 = 2;
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
    fn fnv_known_answer() {
        assert_eq!(fnv64(b""), 0xcbf2_9ce4_8422_2325);
        assert_eq!(fnv64(b"a"), 0xaf63_dc4c_8601_ec8c);
    }
}
