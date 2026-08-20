//! BCM2712 hardware TRNG (iproc rng200) — the STRICT, fail-closed leaf for the
//! kernel's production entropy source (`kernel::entropy::HwTrng`).
//!
//! # Why this exists next to `hboot/src/rng.rs`
//!
//! HBoot already drives this exact block, but with DELIBERATELY different
//! semantics: boot-robustness is paramount there, so `hboot::rng` folds
//! `CNTPCT_EL0` in unconditionally and degrades to counter-derived bytes when
//! the FIFO starves — a wedged TRNG must never deadlock the boot chain.
//!
//! That behaviour is exactly WRONG for the crypto path. `kernel/src/entropy.rs`
//! calls it out by name: a `#[cfg(cm5)]` shortcut to a timer/counter "would be
//! the seeded slip". The M4.2b security review's condition #6 requires that no
//! seeded path can reach metal — a device with a dead TRNG must REFUSE to run,
//! not run weak. So this leaf shares the register map (transcribed from Linux
//! `drivers/char/hw_random/iproc-rng200.c`, same source HBoot used) and NOTHING
//! of the fallback policy:
//!
//!   * every read is `Option` — the FIFO either yields a genuine word or `None`;
//!   * `CNTPCT` is never mixed in, never consulted, never a substitute;
//!   * a latched NIST/master failure yields `None` (the block self-reported that
//!     its output is not random — treat it as absent, not as entropy);
//!   * every hardware spin stays bounded, so a dead TRNG costs a brief delay and
//!     then fails closed rather than hanging the kernel.
//!
//! # Addressing
//!
//! The rng200 is a Device-memory block at CPU-phys `0x10_7D20_8000` (device-tree
//! `rng@7d208000`, child→parent `+0x10_0000_0000`). That address is GB 65, which
//! `mmu_cm5`'s identity map already covers as Device-nGnRnE ("GB 4..511
//! Device-nGnRnE — SoC (GB 64/65)"), so the kernel reaches it at VA == PA with no
//! additional mapping. `cfg(feature = "cm5")` gates the whole module: on QEMU the
//! block does not exist and `HwTrng` keeps failing closed by construction.

const RNG_BASE: usize = 0x10_7D20_8000;

const RNG_CTRL: usize = 0x00;
const RNG_TOTAL_BIT_COUNT: usize = 0x0C;
const RNG_TOTAL_BIT_COUNT_THRESHOLD: usize = 0x10;
const RNG_INT_STATUS: usize = 0x18;
const RNG_FIFO_DATA: usize = 0x20;
const RNG_FIFO_COUNT: usize = 0x24;

const CTRL_ENABLE_MASK: u32 = 0x0000_1FFF; // RBGEN field (bit0 enable + rate bits)
const CTRL_DIV: u32 = 0x3 << 13; // ~1 MHz sample clock
const INT_MASTER_FAIL: u32 = 0x8000_0000;
const INT_NIST_FAIL: u32 = 0x0000_0020;

// Bounded spin budgets — generous for a healthy TRNG, small enough that a dead
// one costs only a brief delay before we fail closed.
const WARMUP_SPINS: u32 = 2_000_000;
const FIFO_SPINS: u32 = 1_000_000;

#[inline(always)]
unsafe fn r(off: usize) -> u32 {
    core::ptr::read_volatile((RNG_BASE + off) as *const u32)
}
#[inline(always)]
unsafe fn w(off: usize, v: u32) {
    core::ptr::write_volatile((RNG_BASE + off) as *mut u32, v);
}

/// Initialise the rng200 if it isn't already running. Idempotent and bounded.
///
/// Returns `false` if the block latched a NIST/master failure that did not
/// clear — the hardware is telling us its output is not random, so every
/// subsequent read must fail closed rather than hand back suspect bits.
unsafe fn init() -> bool {
    // Clear any latched NIST/master failure (write-1-to-clear) so a prior
    // lockout doesn't leave the FIFO permanently starved.
    let st = r(RNG_INT_STATUS);
    if st & (INT_MASTER_FAIL | INT_NIST_FAIL) != 0 {
        w(RNG_INT_STATUS, INT_MASTER_FAIL | INT_NIST_FAIL);
        // Re-read: a failure bit that survives write-1-to-clear is a live fault,
        // not a stale latch. Refuse.
        if r(RNG_INT_STATUS) & (INT_MASTER_FAIL | INT_NIST_FAIL) != 0 {
            return false;
        }
    }
    if r(RNG_CTRL) & CTRL_ENABLE_MASK != 0 {
        return true; // already enabled by an earlier boot stage (HBoot/VideoCore)
    }
    w(RNG_TOTAL_BIT_COUNT_THRESHOLD, 0x0004_0000); // discard less-random warm-up bits
    w(RNG_FIFO_COUNT, 2 << 8); // FIFO fill threshold
    w(RNG_CTRL, CTRL_DIV | CTRL_ENABLE_MASK); // enable the ring-oscillator RBG
    let mut spin = 0u32;
    while r(RNG_TOTAL_BIT_COUNT) <= 16 && spin < WARMUP_SPINS {
        spin += 1;
    }
    // Never warmed up within budget => treat as absent.
    spin < WARMUP_SPINS
}

/// One 32-bit word straight from the TRNG FIFO, or `None`.
///
/// `None` means exactly one thing: the hardware did not produce a genuine random
/// word. There is no substitute value — the caller fails closed.
unsafe fn fifo_word() -> Option<u32> {
    let mut spin = 0u32;
    while r(RNG_FIFO_COUNT) & 0xFF == 0 {
        if spin >= FIFO_SPINS {
            return None;
        }
        spin += 1;
    }
    // A failure latched WHILE we were draining invalidates this word too.
    if r(RNG_INT_STATUS) & (INT_MASTER_FAIL | INT_NIST_FAIL) != 0 {
        return None;
    }
    Some(r(RNG_FIFO_DATA))
}

/// The production entropy read: one 64-bit word of genuine hardware randomness,
/// or `None` if the TRNG is absent, wedged, or self-reporting failure.
///
/// Both halves must come from the FIFO; a partial read is discarded rather than
/// padded, so a half-dead FIFO cannot smuggle a predictable 32 bits into a key.
pub fn next_word_strict() -> Option<u64> {
    unsafe {
        if !init() {
            return None;
        }
        let lo = fifo_word()? as u64;
        let hi = fifo_word()? as u64;
        Some((hi << 32) | lo)
    }
}
