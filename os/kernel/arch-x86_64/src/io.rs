// SPDX-License-Identifier: AGPL-3.0-only
//! Port I/O, MSRs, CPUID, the COM1 console and the QEMU exit port.

use core::arch::asm;
use core::fmt;

#[inline]
pub fn outb(port: u16, v: u8) {
    unsafe { asm!("out dx, al", in("dx") port, in("al") v, options(nomem, nostack, preserves_flags)) };
}

#[inline]
pub fn inb(port: u16) -> u8 {
    let v: u8;
    unsafe { asm!("in al, dx", out("al") v, in("dx") port, options(nomem, nostack, preserves_flags)) };
    v
}

#[inline]
pub fn rdmsr(msr: u32) -> u64 {
    let (lo, hi): (u32, u32);
    unsafe { asm!("rdmsr", in("ecx") msr, out("eax") lo, out("edx") hi, options(nomem, nostack, preserves_flags)) };
    ((hi as u64) << 32) | lo as u64
}

#[inline]
pub fn wrmsr(msr: u32, v: u64) {
    unsafe {
        asm!("wrmsr", in("ecx") msr, in("eax") v as u32, in("edx") (v >> 32) as u32, options(nostack, preserves_flags))
    };
}

/// CPUID leaf/subleaf → (eax, ebx, ecx, edx).
pub fn cpuid(leaf: u32, sub: u32) -> (u32, u32, u32, u32) {
    let r = core::arch::x86_64::__cpuid_count(leaf, sub);
    (r.eax, r.ebx, r.ecx, r.edx)
}

#[inline]
pub fn rdtsc() -> u64 {
    let (lo, hi): (u32, u32);
    unsafe { asm!("rdtsc", out("eax") lo, out("edx") hi, options(nomem, nostack, preserves_flags)) };
    ((hi as u64) << 32) | lo as u64
}

// ---- COM1 (16550) — the console before and after ExitBootServices ----
const COM1: u16 = 0x3F8;

pub fn serial_init() {
    outb(COM1 + 1, 0x00); // interrupts off
    outb(COM1 + 3, 0x80); // DLAB
    outb(COM1, 0x01); // divisor 1 = 115200
    outb(COM1 + 1, 0x00);
    outb(COM1 + 3, 0x03); // 8N1
    outb(COM1 + 2, 0xC7); // FIFO on, cleared
    outb(COM1 + 4, 0x0B); // RTS/DSR
}

fn serial_putb(b: u8) {
    let mut spins = 0u32;
    while inb(COM1 + 5) & 0x20 == 0 && spins < 100_000 {
        spins += 1;
    }
    outb(COM1, b);
}

pub struct Serial;

impl fmt::Write for Serial {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for b in s.bytes() {
            if b == b'\n' {
                serial_putb(b'\r');
            }
            serial_putb(b);
        }
        Ok(())
    }
}

#[macro_export]
macro_rules! kprintln {
    ($($a:tt)*) => {{
        use core::fmt::Write as _;
        let _ = writeln!($crate::io::Serial, $($a)*);
    }};
}

// ---- QEMU isa-debug-exit (iobase 0xf4): process exit status = (v << 1) | 1 ----
pub const EXIT_PASS: u8 = 0x10; // → 33
pub const EXIT_FAIL: u8 = 0x11; // → 35

pub fn qemu_exit(v: u8) -> ! {
    outb(0xF4, v);
    // No debug-exit device (real hardware or a different VM): stop here.
    loop {
        unsafe { asm!("cli; hlt", options(nomem, nostack)) };
    }
}
