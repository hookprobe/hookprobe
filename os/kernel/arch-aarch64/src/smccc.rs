//! SMCCC over the HVC conduit (feature `smccc`) — the arm64-cloud tier's firmware interface:
//! PSCI power control and the SMCCC TRNG (Arm DEN0098). OCI Ampere A1, measured 2026-11-09:
//! PSCI over HVC (ACPI FADT), and the hypervisor's SMCCC TRNG is live (Linux `smccc_trng`).
//! The QEMU model (`virt`, no EL2/EL3) also routes PSCI over HVC.
//!
//! Why this exists on the cloud tier:
//! * heqk's QEMU exits used semihosting (`hlt #0xf000`). On a real cloud VM that is an
//!   undefined instruction — the first exit or kernel fault would re-fault inside the fault
//!   handler. Power-off / reset must be PSCI.
//! * The cloud VM has no on-chip RNG (no RNDR, no RNG200, no virtio-rng); its only hardware
//!   entropy is the hypervisor's SMCCC TRNG.
//!
//! SAFETY OF PROBING: with no EL2 present (the QEMU model) an HVC carrying a NON-PSCI function
//! id is an UNDEFINED instruction. So nothing but PSCI ids is issued until
//! `PSCI_FEATURES(SMCCC_VERSION)` says SMCCC >= 1.1 is implemented (the Linux
//! `psci_init_smccc` procedure); after that, unknown ids return NOT_SUPPORTED (-1) safely.
//!
//! TODO(oci-a1 port step 4): take the conduit (HVC vs SMC) from the ACPI FADT ARM boot
//! flags instead of assuming HVC.

use core::sync::atomic::{AtomicU8, Ordering};

const PSCI_VERSION: u32 = 0x8400_0000;
const PSCI_SYSTEM_OFF: u32 = 0x8400_0008;
const PSCI_SYSTEM_RESET: u32 = 0x8400_0009;
const PSCI_FEATURES: u32 = 0x8400_000A;
const SMCCC_VERSION: u32 = 0x8000_0000;
const TRNG_VERSION: u32 = 0x8400_0050;
const TRNG_RND64: u32 = 0xC400_0053;

/// One SMCCC call over HVC: function id + 3 args -> x0..x3. All of x0..x17 are treated as
/// clobbered (SMCCC 1.0 allows it; 1.1+ preserves x4..x17 — clobbering is always correct).
fn hvc(fid: u32, a1: u64, a2: u64, a3: u64) -> [u64; 4] {
    let (mut x0, mut x1, mut x2, mut x3) = (fid as u64, a1, a2, a3);
    unsafe {
        core::arch::asm!(
            "hvc #0",
            inout("x0") x0, inout("x1") x1, inout("x2") x2, inout("x3") x3,
            out("x4") _, out("x5") _, out("x6") _, out("x7") _, out("x8") _, out("x9") _,
            out("x10") _, out("x11") _, out("x12") _, out("x13") _, out("x14") _,
            out("x15") _, out("x16") _, out("x17") _,
            options(nostack),
        );
    }
    [x0, x1, x2, x3]
}

/// PSCI version as (major, minor). PSCI ids are safe on every supported target.
pub fn psci_version() -> (u16, u16) {
    let v = hvc(PSCI_VERSION, 0, 0, 0)[0] as u32;
    ((v >> 16) as u16, v as u16)
}

// 0 = not probed, 1 = SMCCC >= 1.1 present, 2 = absent.
static SMCCC11: AtomicU8 = AtomicU8::new(0);

/// True if the conduit implements SMCCC >= 1.1, i.e. non-PSCI function ids are safe to issue.
pub fn smccc_1_1() -> bool {
    match SMCCC11.load(Ordering::Relaxed) {
        1 => return true,
        2 => return false,
        _ => {}
    }
    // PSCI_FEATURES is itself a PSCI call (safe). Only if it reports SMCCC_VERSION as
    // implemented do we issue SMCCC_VERSION.
    let ok = (hvc(PSCI_FEATURES, SMCCC_VERSION as u64, 0, 0)[0] as i64) == 0
        && (hvc(SMCCC_VERSION, 0, 0, 0)[0] as i64) >= 0x1_0001;
    SMCCC11.store(if ok { 1 } else { 2 }, Ordering::Relaxed);
    ok
}

/// SMCCC TRNG version (major, minor), or None if absent / unsafe to probe.
pub fn trng_version() -> Option<(u16, u16)> {
    if !smccc_1_1() {
        return None;
    }
    let v = hvc(TRNG_VERSION, 0, 0, 0)[0] as i64;
    if v < 0 {
        return None; // NOT_SUPPORTED
    }
    Some(((v >> 16) as u16, v as u16))
}

/// One 64-bit word of hypervisor TRNG entropy (TRNG_RND64, 64 bits requested: returned in
/// x3). STRICT: `None` on absent, NOT_SUPPORTED, INVALID_PARAMETERS or NO_ENTROPY — never a
/// counter or constant (the entropy module's fail-closed contract). Bounded retry on
/// NO_ENTROPY (-3), which the spec allows to be transient.
pub fn trng_word() -> Option<u64> {
    trng_version()?;
    for _ in 0..16 {
        let r = hvc(TRNG_RND64, 64, 0, 0);
        match r[0] as i64 {
            0 => return Some(r[3]),
            -3 => continue, // NO_ENTROPY: try again, bounded
            _ => return None,
        }
    }
    None
}

/// PSCI SYSTEM_OFF. Does not return; if the call is refused, park (never fall through).
pub fn system_off() -> ! {
    let _ = hvc(PSCI_SYSTEM_OFF, 0, 0, 0);
    park()
}

/// PSCI SYSTEM_RESET. Does not return; if the call is refused, park (never fall through).
pub fn system_reset() -> ! {
    let _ = hvc(PSCI_SYSTEM_RESET, 0, 0, 0);
    park()
}

fn park() -> ! {
    unsafe { core::arch::asm!("msr daifset, #0xf", options(nomem, nostack)) };
    loop {
        unsafe { core::arch::asm!("wfi", options(nomem, nostack)) };
    }
}
