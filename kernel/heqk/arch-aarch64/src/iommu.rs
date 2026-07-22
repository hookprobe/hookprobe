//! P14 seed — BCM2712 custom IOMMU (`brcm,bcm2712-iommu`) for PCIe DMA
//! containment. Closes the audit finding that the external PCIe RC (pcie1/RTL)
//! maps a **64 GiB inbound window** (`rtl8111` RC_BAR1 size code 0x15) straight
//! to DRAM with no translation — any endpoint DMA can reach all of RAM.
//!
//! The BCM2712 IOMMU is a tiny 128-byte MMIO register file (NOT an ARM SMMUv3):
//! one global translation context per block, no stream/requester-IDs — so
//! per-device isolation is impossible, but WHOLE-BLOCK containment is achievable.
//! Block↔master routing is fixed in silicon and moves by stepping:
//!   * external PCIe0/1 (RTL): iommu2 @ 0x10_0000_5100 (D0) or iommu8 @ 0x5400 (C1)
//!   * RP1 (pcie2, the GEM datapath):                    iommu5 @ 0x10_0000_5280
//! `probe()` reads DEBUG_INFO to confirm which block is live + its current state
//! (read-only, safe on metal). `fence()` arms an address-ceiling so any inbound
//! DMA above `granted_top` raises a hardware abort — the smallest containment
//! (no page tables). Sources: raspberrypi/linux drivers/iommu/bcm2712-iommu.c +
//! bcm2712.dtsi; RPi-forum t=391572 (njh: "no groups/regions/requester IDs").

use core::ptr::{read_volatile, write_volatile};

/// External PCIe0/1 IOMMU — D0 stepping (CM5 is typically D0).
pub const IOMMU2_BASE: usize = 0x10_0000_5100;
/// External PCIe0/1 IOMMU — older C1 stepping (probe both, use whichever is live).
pub const IOMMU8_BASE: usize = 0x10_0000_5400;
/// RP1 (pcie2) IOMMU — the RP1 GEM Ethernet inbound DMA path.
pub const IOMMU5_BASE: usize = 0x10_0000_5280;

// Register offsets within the 0x80 window (from bcm2712-iommu.c).
const CTRL: usize = 0x00; // ENABLE=bit0, TLB_CLEAR=bit2, BYPASS=bit8, aborts, STATS
const ADDR_CAP: usize = 0x14; // ENABLE=bit31 | ((top>>SHIFT)-1) — hard address ceiling
const BYPASS_START: usize = 0x1C; // ENABLE=bit31, INVERT=bit30
const BYPASS_END: usize = 0x20;
const DEBUG_INFO: usize = 0x38; // version / capabilities

// CTRL bits.
const CTRL_ENABLE: u32 = 1 << 0;
const CTRL_CAP_EXCEEDED_ABORT_EN: u32 = 1 << 3; // abort on ADDR_CAP violation
const CTRL_BYPASS: u32 = 1 << 8;
const ADDR_CAP_ENABLE: u32 = 1 << 31;

/// Address-cap granularity shift. The aperture math in the driver is
/// `(top >> SHIFT) - 1`; page granularity (12) matches the 4 KiB PTE model.
/// ⚠️ Confirm on metal (read back ADDR_CAP after `fence`) before relying on the
/// exact ceiling — this is the one bit-layout the offline investigation could not
/// pin down.
const ADDR_CAP_SHIFT: u32 = 12;

#[inline]
unsafe fn r(base: usize, off: usize) -> u32 {
    read_volatile((base + off) as *const u32)
}
#[inline]
unsafe fn w(base: usize, off: usize, v: u32) {
    write_volatile((base + off) as *mut u32, v);
}

/// A read-only snapshot of an IOMMU block's identity + current state.
#[derive(Clone, Copy)]
pub struct IommuInfo {
    pub debug_info: u32,
    pub ctrl: u32,
    pub addr_cap: u32,
    /// Heuristic: DEBUG_INFO looks like a real block (not all-ones / all-zero bus error).
    pub present: bool,
    pub enabled: bool,
    pub bypass: bool,
}

/// Read a block's DEBUG_INFO + control state (safe, read-only — no side effects).
pub fn probe(base: usize) -> IommuInfo {
    unsafe {
        let debug_info = r(base, DEBUG_INFO);
        let ctrl = r(base, CTRL);
        let addr_cap = r(base, ADDR_CAP);
        let present = debug_info != 0xFFFF_FFFF && debug_info != 0;
        IommuInfo {
            debug_info,
            ctrl,
            addr_cap,
            present,
            enabled: ctrl & CTRL_ENABLE != 0,
            bypass: ctrl & CTRL_BYPASS != 0,
        }
    }
}

/// Arm an address-ceiling FENCE (smallest containment, no page tables): any
/// inbound DMA to a physical address >= `granted_top` raises a hardware abort.
/// Disables transparent bypass so nothing above the cap passes untranslated.
/// Returns the read-back (ADDR_CAP, CTRL) so the caller can confirm it took.
///
/// SAFETY/RISK: this is on the INBOUND DMA path of whatever masters route through
/// `base`. For iommu2 (external PCIe/RTL) that is safe while the RTL link is down
/// and HEQK drives no ISP/HEVC; for iommu5 (RP1/GEM) the ceiling MUST sit above
/// the live GEM ring + buffer PAs or the datapath breaks. Confirm ADDR_CAP_SHIFT
/// on metal via the read-back before trusting the exact ceiling.
pub fn fence(base: usize, granted_top: usize) -> (u32, u32) {
    unsafe {
        // No transparent bypass range.
        w(base, BYPASS_START, 0);
        w(base, BYPASS_END, 0);
        // Ceiling: abort above `granted_top`.
        let cap = ADDR_CAP_ENABLE | (((granted_top as u64 >> ADDR_CAP_SHIFT) as u32).wrapping_sub(1));
        w(base, ADDR_CAP, cap);
        // Enable with cap-exceeded abort; no bypass, no page tables.
        w(base, CTRL, CTRL_ENABLE | CTRL_CAP_EXCEEDED_ABORT_EN);
        core::arch::asm!("dsb sy");
        (r(base, ADDR_CAP), r(base, CTRL))
    }
}
