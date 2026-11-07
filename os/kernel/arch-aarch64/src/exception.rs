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
    // QEMU: exit with FAILURE so a crash never masquerades as a clean run.
    #[cfg(not(feature = "cm5"))]
    semihosting::exit(1);
    // Real silicon: semihosting is an undefined instruction with no debugger. Never
    // continue in a corrupt state — and never sit silently either: by this point
    // hboot's trial watchdog is already disarmed (the boot was committed), so a
    // WFE-park would hang the box until someone power-cycles it. Fail CLOSED
    // instead: give the UART time to drain the diagnostic, then reset through the
    // EL2 gate (`hvc #0` → reset_platform, the proven path — EL1 PM writes are
    // ignored). A persistent fault becomes a visible reboot loop on the console.
    #[cfg(feature = "cm5")]
    {
        let _ = &semihosting::exit; // keep the import referenced
        unsafe { core::arch::asm!("msr daifset, #0xf", options(nomem, nostack)) };
        for _ in 0..50_000_000u64 {
            core::hint::spin_loop();
        }
        unsafe { core::arch::asm!("hvc #0", options(noreturn)) }
    }
}
