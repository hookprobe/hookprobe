// SPDX-License-Identifier: AGPL-3.0-only
//! Local APIC — x2APIC (MSR interface) when the CPU has it, xAPIC (MMIO) otherwise — and the I/O APIC.
//! The legacy 8259 PICs are masked so only the APICs deliver; every I/O APIC input starts masked.

use crate::cpu::{SPURIOUS_VECTOR, TIMER_VECTOR};
use crate::io::{cpuid, outb, rdmsr, wrmsr};
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

static BASE: AtomicU64 = AtomicU64::new(0);
static X2: AtomicBool = AtomicBool::new(false);

const SVR: u32 = 0xF0;
const EOI: u32 = 0xB0;
const LVT_TIMER: u32 = 0x320;
const TIMER_INIT: u32 = 0x380;
const TIMER_DIV: u32 = 0x3E0;
const IA32_APIC_BASE: u32 = 0x1B;

/// xAPIC MMIO offset `reg` ↔ x2APIC MSR 0x800 + reg/16 (Intel SDM vol. 3 §11.12.1.2).
fn write(reg: u32, v: u32) {
    if X2.load(Ordering::Relaxed) {
        wrmsr(0x800 + (reg >> 4), v as u64);
    } else {
        unsafe { core::ptr::write_volatile((BASE.load(Ordering::Relaxed) + reg as u64) as *mut u32, v) };
    }
}

pub fn eoi() {
    write(EOI, 0);
}

pub struct Lapic {
    pub base: u64,
    pub x2apic: bool,
}

/// Enable the local APIC (x2APIC mode if CPUID says so; never with `force_xapic`) and start a periodic timer.
pub fn init_timer(initial_count: u32, force_xapic: bool) -> Lapic {
    outb(0x21, 0xFF); // mask both 8259s
    outb(0xA1, 0xFF);
    let (_, _, c1, _) = cpuid(1, 0);
    let x2 = c1 & (1 << 21) != 0 && !force_xapic;
    let mut msr = rdmsr(IA32_APIC_BASE);
    let base = msr & 0xF_FFFF_F000;
    BASE.store(base, Ordering::Relaxed);
    msr |= 1 << 11; // global enable (xAPIC first: the only legal path into x2APIC)
    wrmsr(IA32_APIC_BASE, msr);
    if x2 {
        wrmsr(IA32_APIC_BASE, msr | (1 << 10));
    }
    X2.store(x2, Ordering::Relaxed);
    write(SVR, 0x100 | SPURIOUS_VECTOR as u32);
    write(TIMER_DIV, 0x3); // divide by 16
    write(LVT_TIMER, (1 << 17) | TIMER_VECTOR as u32); // periodic
    write(TIMER_INIT, initial_count);
    Lapic { base, x2apic: x2 }
}

pub fn stop_timer() {
    write(LVT_TIMER, 1 << 16); // masked
    write(TIMER_INIT, 0);
}

/// x2APIC ID (MSR 0x802) or xAPIC ID (MMIO 0x20 bits 31:24).
pub fn id() -> u32 {
    if X2.load(Ordering::Relaxed) {
        rdmsr(0x802) as u32
    } else {
        unsafe { core::ptr::read_volatile((BASE.load(Ordering::Relaxed) + 0x20) as *const u32) >> 24 }
    }
}

/// I/O APIC at `addr`: returns (version, redirection entries) after masking every input.
pub fn ioapic_mask_all(addr: u32) -> (u8, u32) {
    let sel = addr as u64 as *mut u32;
    let win = (addr as u64 + 0x10) as *mut u32;
    let rd = |r: u32| unsafe {
        core::ptr::write_volatile(sel, r);
        core::ptr::read_volatile(win)
    };
    let wr = |r: u32, v: u32| unsafe {
        core::ptr::write_volatile(sel, r);
        core::ptr::write_volatile(win, v);
    };
    let ver = rd(0x01);
    let entries = ((ver >> 16) & 0xFF) + 1;
    for i in 0..entries.min(240) {
        let lo = rd(0x10 + 2 * i);
        wr(0x10 + 2 * i, lo | (1 << 16)); // mask
    }
    (ver as u8, entries)
}
