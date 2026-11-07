//! GICv2 (ARM Generic Interrupt Controller). QEMU `virt`: GICD 0x0800_0000 /
//! GICC 0x0801_0000. CM5/BCM2712 GIC-400 (also GICv2): GICD 0x10_7FFF_9000 /
//! GICC 0x10_7FFF_A000 — same register layout, different base (Device-mapped).

use core::ptr::{read_volatile, write_volatile};

#[cfg(not(feature = "cm5"))]
const GICD: usize = 0x0800_0000; // QEMU virt Distributor
#[cfg(not(feature = "cm5"))]
const GICC: usize = 0x0801_0000; // QEMU virt CPU interface
#[cfg(feature = "cm5")]
const GICD: usize = 0x10_7FFF_9000; // BCM2712 GIC-400 Distributor
#[cfg(feature = "cm5")]
const GICC: usize = 0x10_7FFF_A000; // BCM2712 GIC-400 CPU interface

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

impl Gic {
    /// Enable a **shared peripheral interrupt (SPI)** — needed for RP1/mip-
    /// forwarded interrupts (e.g. the GEM RX at INTID 166). Unlike the timer PPI
    /// (ISENABLER alone), an SPI resets to no-target/level: route it to CPU0, set
    /// an edge trigger (mip forwards edge), and a priority below the PMR mask.
    pub fn enable_spi(&self, intid: u32) {
        unsafe {
            // Priority (one byte per intid) below PMR (0xF0).
            write_volatile((GICD + 0x400 + intid as usize) as *mut u8, 0xA0);
            // Target CPU0 (one byte per intid; SPIs reset to no CPU on GIC-400).
            write_volatile((GICD + 0x800 + intid as usize) as *mut u8, 0x01);
            // Edge-triggered: 2 cfg bits per intid, bit[1]=1 == edge.
            let icfg = GICD + 0xC00 + ((intid / 16) as usize) * 4;
            let shift = (intid % 16) * 2;
            let v = (r(icfg) & !(0b11 << shift)) | (0b10 << shift);
            w(icfg, v);
            // Enable.
            w(GICD_ISENABLER + ((intid / 32) as usize) * 4, 1 << (intid % 32));
        }
    }
}

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
