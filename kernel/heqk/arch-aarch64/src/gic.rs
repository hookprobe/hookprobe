//! GICv2 (ARM Generic Interrupt Controller) — the QEMU `virt` default.
//! Distributor at 0x0800_0000, CPU interface at 0x0801_0000.

use core::ptr::{read_volatile, write_volatile};

const GICD: usize = 0x0800_0000; // Distributor
const GICC: usize = 0x0801_0000; // CPU interface

const GICD_CTLR: usize = GICD + 0x000;
const GICD_ISENABLER: usize = GICD + 0x100; // one bit per intid
const GICC_CTLR: usize = GICC + 0x000;
const GICC_PMR: usize = GICC + 0x004; // priority mask
const GICC_IAR: usize = GICC + 0x00C; // interrupt acknowledge
const GICC_EOIR: usize = GICC + 0x010; // end of interrupt

#[inline]
unsafe fn w(addr: usize, v: u32) {
    write_volatile(addr as *mut u32, v);
}
#[inline]
unsafe fn r(addr: usize) -> u32 {
    read_volatile(addr as *const u32)
}

/// The GICv2 as a HAL `IrqController`.
pub struct Gic;

impl hal::IrqController for Gic {
    fn init(&self) {
        unsafe {
            w(GICD_CTLR, 1); // enable distributor (group 0)
            w(GICC_PMR, 0xF0); // allow all priorities
            w(GICC_CTLR, 1); // enable CPU interface
        }
    }
    fn enable(&self, intid: u32) {
        unsafe {
            let reg = GICD_ISENABLER + ((intid / 32) as usize) * 4;
            w(reg, 1 << (intid % 32));
        }
    }
    fn ack(&self) -> u32 {
        unsafe { r(GICC_IAR) & 0x3FF }
    }
    fn eoi(&self, intid: u32) {
        unsafe { w(GICC_EOIR, intid) }
    }
}
