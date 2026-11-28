// SPDX-License-Identifier: AGPL-3.0-only
//! GICv2 doorbell (QEMU `virt` and the BCM2712 GIC-400 share the layout; the bases come from the
//! boot context, never from a build flag in this crate).
//!
//! Worker side: enable one SGI in this CPU's banked distributor registers and CPU interface, then
//! sleep in `wfi` with interrupts MASKED. A pending interrupt wakes `wfi` whatever `PSTATE.I` says,
//! so the worker never takes an IRQ exception: it acknowledges the SGI by polling `GICC_IAR`.
//! Core-0 side: [`send_sgi`] writes `GICD_SGIR` with the worker's CPU-interface mask.

use core::ptr::{read_volatile, write_volatile};

const GICD_ISENABLER0: usize = 0x100;
const GICD_IPRIORITYR: usize = 0x400;
const GICD_ITARGETSR0: usize = 0x800;
const GICD_SGIR: usize = 0xF00;
const GICC_CTLR: usize = 0x000;
const GICC_PMR: usize = 0x004;
const GICC_IAR: usize = 0x00C;
const GICC_EOIR: usize = 0x010;

/// Enable SGI `sgi` (0..16) for this CPU and return this CPU's interface mask (one bit), read from
/// the banked `GICD_ITARGETSR0`, which core 0 must use as the SGI target.
///
/// # Safety
/// `gicd`/`gicc` must be the device-mapped GICv2 bases; call once on the worker core.
pub unsafe fn enable_doorbell(gicd: usize, gicc: usize, sgi: u32) -> u8 {
    let sgi = (sgi & 0xF) as usize;
    unsafe {
        // Priority (banked for SGIs/PPIs) above the mask, so the SGI is signalled to this CPU.
        write_volatile((gicd + GICD_IPRIORITYR + sgi) as *mut u8, 0xA0);
        write_volatile((gicd + GICD_ISENABLER0) as *mut u32, 1 << sgi);
        write_volatile((gicc + GICC_PMR) as *mut u32, 0xF0);
        write_volatile((gicc + GICC_CTLR) as *mut u32, 1);
        // Byte 0 of the banked ITARGETSR0 reads back this CPU's own interface mask.
        let mask = read_volatile((gicd + GICD_ITARGETSR0) as *const u32) as u8;
        core::arch::asm!("dsb sy", "isb", options(nostack));
        mask
    }
}

/// Enable a private peripheral interrupt (PPI 16..31, e.g. this core's timer) in this CPU's banked distributor
/// registers, with the same priority as the doorbell.
///
/// # Safety
/// `gicd` must be the device-mapped GICv2 distributor base; call on the worker core.
pub unsafe fn enable_ppi(gicd: usize, intid: u32) {
    let id = (intid & 0x1F) as usize;
    unsafe {
        write_volatile((gicd + GICD_IPRIORITYR + id) as *mut u8, 0xA0);
        write_volatile((gicd + GICD_ISENABLER0) as *mut u32, 1 << id);
        core::arch::asm!("dsb sy", "isb", options(nostack));
    }
}

/// Sleep until an interrupt is pending, then acknowledge everything pending. `on_irq(intid)` runs between the
/// acknowledge and the end-of-interrupt, so a level-sensitive source (the timer) can be re-armed before EOI.
///
/// # Safety
/// After [`enable_doorbell`] on this core.
pub unsafe fn wait(gicc: usize, mut on_irq: impl FnMut(u32)) {
    unsafe {
        core::arch::asm!("wfi", options(nomem, nostack));
        loop {
            let iar = read_volatile((gicc + GICC_IAR) as *const u32);
            if iar & 0x3FF >= 1020 {
                break; // 1023 spurious: nothing (more) pending
            }
            on_irq(iar & 0x3FF);
            write_volatile((gicc + GICC_EOIR) as *mut u32, iar);
        }
    }
}

/// Core 0: ring the doorbell of the CPU interface(s) in `target_mask`.
///
/// # Safety
/// `gicd` must be the device-mapped GICv2 distributor base.
pub unsafe fn send_sgi(gicd: usize, target_mask: u8, sgi: u32) {
    unsafe {
        core::arch::asm!("dsb ishst", options(nostack)); // ring data before the doorbell
        write_volatile((gicd + GICD_SGIR) as *mut u32, (u32::from(target_mask) << 16) | (sgi & 0xF));
    }
}
