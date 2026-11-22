// SPDX-License-Identifier: AGPL-3.0-only
//! Local APIC (xAPIC, MMIO) timer; the legacy 8259 PICs are masked so only the LAPIC delivers.

use crate::cpu::{SPURIOUS_VECTOR, TIMER_VECTOR};
use crate::io::{outb, rdmsr};
use core::sync::atomic::{AtomicU64, Ordering};

static BASE: AtomicU64 = AtomicU64::new(0);

const SVR: u64 = 0xF0;
const EOI: u64 = 0xB0;
const LVT_TIMER: u64 = 0x320;
const TIMER_INIT: u64 = 0x380;
const TIMER_DIV: u64 = 0x3E0;

fn write(reg: u64, v: u32) {
    unsafe { core::ptr::write_volatile((BASE.load(Ordering::Relaxed) + reg) as *mut u32, v) };
}

pub fn eoi() {
    write(EOI, 0);
}

/// Returns the LAPIC physical base (it lies in the uncached 3..4 GiB identity window).
pub fn init_timer(initial_count: u32) -> u64 {
    outb(0x21, 0xFF); // mask both 8259s
    outb(0xA1, 0xFF);
    let base = rdmsr(0x1B) & 0xF_FFFF_F000; // IA32_APIC_BASE
    BASE.store(base, Ordering::Relaxed);
    write(SVR, 0x100 | SPURIOUS_VECTOR as u32); // APIC software-enable
    write(TIMER_DIV, 0x3); // divide by 16
    write(LVT_TIMER, (1 << 17) | TIMER_VECTOR as u32); // periodic
    write(TIMER_INIT, initial_count);
    base
}

pub fn stop_timer() {
    write(LVT_TIMER, 1 << 16); // masked
    write(TIMER_INIT, 0);
}
