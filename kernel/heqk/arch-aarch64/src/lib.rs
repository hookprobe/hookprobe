#![no_std]
//! aarch64 implementation of the HookProbe HAL, plus the low-level boot stub
//! and exception/IRQ vector table. This is the ONE crate allowed to know the
//! architecture; `kernel` talks to it only through `hal` traits (plus the boot
//! seam: our `_start` calls `kmain`, and `irq_entry` calls `handle_irq`).

use core::arch::global_asm;
use core::fmt::{self, Write};

mod uart;
mod exception;
pub mod bpf_jit;
pub mod gic;
pub mod mmu;
pub mod semihosting;
pub mod syscall;
pub mod thread;
pub mod timer;
pub mod virtio;

pub use gic::Gic;
pub use mmu::Mmu;
pub use timer::GenericTimer;
pub use uart::Pl011;

// _start (boot stub), __vectors / irq_entry / lower_sync_entry, and the EL0
// entry/resume glue.
#[cfg(not(feature = "cm5"))]
global_asm!(include_str!("boot.s"));
#[cfg(feature = "cm5")]
global_asm!(include_str!("boot_cm5.s")); // adds an early dependency-free UART marker
global_asm!(include_str!("vectors.s"));
global_asm!(include_str!("syscall.s"));

/// Current Exception Level (1, 2, or 3) from `CurrentEL`.
#[inline]
pub fn current_el() -> u64 {
    let el: u64;
    unsafe { core::arch::asm!("mrs {}, CurrentEL", out(reg) el) };
    (el >> 2) & 0b11
}

/// Obtain the early debug console.
pub fn console() -> Pl011 {
    Pl011
}

/// Unmask IRQs at the CPU (PSTATE.I = 0).
#[inline]
pub fn enable_irqs() {
    unsafe { core::arch::asm!("msr daifclr, #2") };
}

/// Mask IRQs at the CPU (PSTATE.I = 1) — short critical sections (e.g. IPC).
#[inline]
pub fn disable_irqs() {
    unsafe { core::arch::asm!("msr daifset, #2") };
}

/// Formatted output to the early console (backs the kernel's `kprint!`).
pub fn _print(args: fmt::Arguments) {
    let mut u = Pl011;
    let _ = u.write_fmt(args);
}

/// Entry point for the kernel's `#[panic_handler]`.
pub fn on_panic(info: &core::panic::PanicInfo) -> ! {
    let mut u = Pl011;
    let _ = writeln!(u, "\n[PANIC] {}", info);
    semihosting::exit(1)
}
