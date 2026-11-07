//! BCM2712 hardware TRNG (iproc rng200) — real per-boot entropy for attestation.
//!
//! Before this, the attestation nonce was a compile-time constant
//! (`boot_abi::CHALLENGE_NONCE`), so every quote from every device was
//! byte-identical and a captured quote replayed forever (audit finding B-2).
//! This reads the BCM2712's on-die rng200 (same iproc TRNG family as the
//! BCM2711's `bcm2711-rng200`) to mint a FRESH nonce each boot — the signed
//! quote is now non-deterministic and per-boot unique.
//!
//! Reachable bare-metal with NO VideoCore mailbox: the rng200 is a BCM2712
//! Device-memory block at CPU-phys `0x10_7D20_8000` (device-tree
//! `rng@7d208000`, child→parent `+0x10_0000_0000`). HBoot's EL2 identity map
//! already covers it (GB65, Device-nGnRnE). Register map + init/read sequence
//! transcribed from Linux `drivers/char/hw_random/iproc-rng200.c`.
//!
//! Boot-robustness is paramount — this runs inside the boot chain. Every
//! hardware spin is BOUNDED and the physical counter (CNTPCT_EL0) is folded in
//! unconditionally, so a wedged, locked-out, or absent TRNG degrades to
//! counter-derived entropy: it never deadlocks the boot and never yields
//! all-zeros. `fill` reports how many genuine TRNG words it obtained so the
//! console shows whether the silicon RNG is live.

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

// Bounded spin budgets — generous enough for a healthy TRNG, small enough that
// a dead one costs only a brief delay before the counter fallback kicks in.
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

#[inline(always)]
fn cntpct() -> u64 {
    let v: u64;
    unsafe { core::arch::asm!("mrs {}, cntpct_el0", out(reg) v, options(nomem, nostack)) };
    v
}

/// Initialise the rng200 if it isn't already running. Idempotent and bounded.
unsafe fn init() {
    // Clear any latched NIST/master failure (write-1-to-clear) so a prior
    // lockout doesn't leave the FIFO permanently starved.
    let st = r(RNG_INT_STATUS);
    if st & (INT_MASTER_FAIL | INT_NIST_FAIL) != 0 {
        w(RNG_INT_STATUS, INT_MASTER_FAIL | INT_NIST_FAIL);
    }
    if r(RNG_CTRL) & CTRL_ENABLE_MASK != 0 {
        return; // already enabled by an earlier boot stage (VideoCore firmware)
    }
    w(RNG_TOTAL_BIT_COUNT_THRESHOLD, 0x0004_0000); // discard less-random warm-up bits
    w(RNG_FIFO_COUNT, 2 << 8); // FIFO fill threshold
    w(RNG_CTRL, CTRL_DIV | CTRL_ENABLE_MASK); // enable the ring-oscillator RBG
    let mut spin = 0u32;
    while r(RNG_TOTAL_BIT_COUNT) <= 16 && spin < WARMUP_SPINS {
        spin += 1;
    }
}

/// Read one word: `(value, true)` from the TRNG FIFO, or `(counter, false)` if
/// the FIFO does not fill within the bounded budget (never blocks the boot).
unsafe fn next_word() -> (u32, bool) {
    let mut spin = 0u32;
    while r(RNG_FIFO_COUNT) & 0xFF == 0 {
        if spin >= FIFO_SPINS {
            let c = cntpct();
            return ((c as u32) ^ ((c >> 32) as u32).rotate_left(spin & 31), false);
        }
        spin += 1;
    }
    (r(RNG_FIFO_DATA), true)
}

/// Fill `dest` with hardware entropy, folding the physical counter in
/// unconditionally (defense-in-depth). Returns the count of genuine TRNG words
/// obtained — a bring-up readout of whether the silicon RNG is live.
pub fn fill(dest: &mut [u8]) -> u32 {
    unsafe {
        init();
        let seed = cntpct();
        let mut real = 0u32;
        let mut i = 0usize;
        while i < dest.len() {
            let (word, live) = next_word();
            if live {
                real += 1;
            }
            let mixed = word ^ (seed.rotate_left((i as u32).wrapping_mul(7)) as u32);
            let b = mixed.to_le_bytes();
            let n = core::cmp::min(4, dest.len() - i);
            dest[i..i + n].copy_from_slice(&b[..n]);
            i += n;
        }
        real
    }
}

/// A fresh 32-byte attestation nonce for this boot, plus the count of genuine
/// TRNG words that backed it (8 = fully hardware-random).
pub fn hw_nonce() -> ([u8; 32], u32) {
    let mut n = [0u8; 32];
    let live = fill(&mut n);
    (n, live)
}
