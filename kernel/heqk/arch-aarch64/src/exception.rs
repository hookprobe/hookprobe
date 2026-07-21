use crate::{semihosting, Pl011};
use core::fmt::Write;

const VEC_NAMES: [&str; 16] = [
    "Sync/SP0", "IRQ/SP0", "FIQ/SP0", "SError/SP0",
    "Sync/SPx", "IRQ/SPx", "FIQ/SPx", "SError/SPx",
    "Sync/Lower64", "IRQ/Lower64", "FIQ/Lower64", "SError/Lower64",
    "Sync/Lower32", "IRQ/Lower32", "FIQ/Lower32", "SError/Lower32",
];

/// Common exception handler for the vectors NOT used in normal operation (IRQs
/// go to `irq_entry`, EL0 sync to `lower_sync_entry`). Reaching here means an
/// **unexpected kernel (EL1) fault** — a bug — so it reports and exits with a
/// FAILURE code (never 0), so a crash can never masquerade as a clean run.
#[no_mangle]
pub extern "C" fn rust_exception(idx: u64, esr: u64, elr: u64, far: u64) -> ! {
    let mut u = Pl011;
    let name = VEC_NAMES.get(idx as usize).copied().unwrap_or("?");
    let ec = (esr >> 26) & 0x3f; // Exception Class
    let _ = writeln!(u, "\n[EXCEPTION] {} (idx={}) — UNEXPECTED KERNEL FAULT", name, idx);
    let _ = writeln!(u, "  ESR_EL1={:#018x}  EC={:#04x}", esr, ec);
    let _ = writeln!(u, "  ELR_EL1={:#018x}  FAR_EL1={:#018x}", elr, far);
    semihosting::exit(1) // a kernel fault is a FAILURE, not a success
}
