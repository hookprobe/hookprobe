// SPDX-License-Identifier: AGPL-3.0-only
//! Entropy on x86_64: RDSEED (the conditioned ENTROPY source, not the RDRAND DRBG), health-checked and
//! FAIL-CLOSED. No timer, counter, fixed-seed or RDRAND fallback — the same rule as heqk's HwTrng on every
//! target. The policy itself is ADR 0068's to ratify; this is the mechanism the port will hand to it.

use crate::io::cpuid;
use core::arch::asm;

pub enum Health {
    Pass { samples: usize, retries: u32 },
    Absent,
    Fail(&'static str),
}

/// One RDSEED with a bounded retry budget (RDSEED may legitimately underflow and return CF=0).
fn rdseed64(retries: &mut u32) -> Option<u64> {
    for _ in 0..1024 {
        let v: u64;
        let ok: u8;
        unsafe { asm!("rdseed {v}", "setc {ok}", v = out(reg) v, ok = out(reg_byte) ok, options(nomem, nostack)) };
        if ok == 1 {
            return Some(v);
        }
        *retries += 1;
        core::hint::spin_loop();
    }
    None
}

/// Startup health test: N samples, each must arrive within the retry budget; no stuck-at-0/1 value; no two
/// consecutive samples equal (repetition-count test, SP 800-90B §4.4.1 cut-off 2 at 64-bit width); and every
/// bit position must toggle at least once across the run.
pub fn health(n: usize) -> Health {
    let (_, b7, _, _) = cpuid(7, 0);
    if b7 & (1 << 18) == 0 {
        return Health::Absent;
    }
    let mut retries = 0u32;
    let mut prev: Option<u64> = None;
    let (mut ones, mut zeros) = (0u64, 0u64);
    for _ in 0..n {
        let Some(v) = rdseed64(&mut retries) else { return Health::Fail("retry budget exhausted") };
        if v == 0 || v == u64::MAX {
            return Health::Fail("stuck value");
        }
        if prev == Some(v) {
            return Health::Fail("repetition");
        }
        prev = Some(v);
        ones |= v;
        zeros |= !v;
    }
    if ones != u64::MAX || zeros != u64::MAX {
        return Health::Fail("a bit position never toggled");
    }
    Health::Pass { samples: n, retries }
}
