//! GICv3 backend (feature `gicv3`) — the arm64-cloud tier: OCI Ampere A1 (measured
//! 2026-11-09: GICv3, single security state, virt timer PPI 27) and its QEMU model
//! `virt,gic-version=3` (os/kernel/tools/oci-a1/run-oci-a1.sh). Same API as the GICv2 driver
//! (`gic.rs`), so nothing above the HAL changes.
//!
//! Differences from v2 that matter:
//! * The CPU interface is SYSTEM REGISTERS (ICC_*_EL1), not MMIO — the GICv2 GICC frame at
//!   0x0801_0000 does not exist (that is exactly where the unmodified kernel faulted).
//! * SGIs/PPIs (INTID < 32) are configured in the boot CPU's REDISTRIBUTOR, SPIs in the
//!   distributor with affinity routing (GICD_IROUTER).
//! * The guest sees a single security state (GICD_CTLR.DS=1), where Group 0 is signalled as
//!   FIQ — every interrupt we enable is put in Group 1 (NS) so it arrives as IRQ.
//!
//! Base addresses: QEMU `virt` layout, which the OCI model reproduces. TODO(oci-a1 port step
//! 2): take GICD/GICR from the ACPI MADT that efiboot hands over instead of constants.

use core::ptr::{read_volatile, write_volatile};

const GICD: usize = 0x0800_0000;
const GICR_BASE: usize = 0x080A_0000;
const GICR_STRIDE: usize = 0x2_0000; // RD_base (64 KiB) + SGI_base (64 KiB) per CPU
const GICR_MAX: usize = 512;

// Distributor
const GICD_CTLR: usize = 0x0000;
const GICD_IGROUPR: usize = 0x0080;
const GICD_ISENABLER: usize = 0x0100;
const GICD_IPRIORITYR: usize = 0x0400;
const GICD_ICFGR: usize = 0x0C00;
const GICD_IROUTER: usize = 0x6000;
const CTLR_RWP: u32 = 1 << 31;
const CTLR_ENABLE_G1: u32 = 1 << 1; // DS=1 layout: bit1 = EnableGrp1
const CTLR_ARE: u32 = 1 << 4;

// Redistributor (RD_base) and its SGI_base frame
const GICR_TYPER: usize = 0x0008;
const GICR_WAKER: usize = 0x0014;
const SGI: usize = 0x1_0000;
const GICR_IGROUPR0: usize = SGI + 0x0080;
const GICR_ISENABLER0: usize = SGI + 0x0100;
const GICR_IPRIORITYR: usize = SGI + 0x0400;

const PRIO: u8 = 0xA0; // below the PMR mask (0xF0), same as the v2 driver

#[inline]
unsafe fn w(addr: usize, v: u32) {
    write_volatile(addr as *mut u32, v);
}
#[inline]
unsafe fn r(addr: usize) -> u32 {
    read_volatile(addr as *const u32)
}

fn mpidr_aff() -> u64 {
    let m: u64;
    unsafe { core::arch::asm!("mrs {}, mpidr_el1", out(reg) m) };
    // Aff3 | Aff2.Aff1.Aff0 packed as GICR_TYPER[63:32] / GICD_IROUTER expect.
    ((m >> 32) & 0xff) << 24 | (m & 0x00ff_ffff)
}

/// The boot CPU's redistributor: walk the frames until GICR_TYPER.Affinity matches.
fn my_gicr() -> usize {
    let me = mpidr_aff();
    let mut rd = GICR_BASE;
    for _ in 0..GICR_MAX {
        let typer = unsafe { read_volatile((rd + GICR_TYPER) as *const u64) };
        if (typer >> 32) == me {
            return rd;
        }
        if typer & (1 << 4) != 0 {
            break; // Last
        }
        rd += GICR_STRIDE;
    }
    GICR_BASE // single-CPU boot: frame 0
}

fn gicd_wait_rwp() {
    for _ in 0..1_000_000 {
        if unsafe { r(GICD + GICD_CTLR) } & CTLR_RWP == 0 {
            return;
        }
    }
}

/// The GICv3 as a HAL `IrqController`.
pub struct Gic;

impl Gic {
    /// Enable a shared peripheral interrupt: Group 1, priority, edge, routed to this CPU.
    pub fn enable_spi(&self, intid: u32) {
        let i = intid as usize;
        unsafe {
            let g = GICD + GICD_IGROUPR + (i / 32) * 4;
            w(g, r(g) | 1 << (i % 32));
            write_volatile((GICD + GICD_IPRIORITYR + i) as *mut u8, PRIO);
            let icfg = GICD + GICD_ICFGR + (i / 16) * 4;
            let shift = (i % 16) * 2;
            w(icfg, (r(icfg) & !(0b11 << shift)) | (0b10 << shift));
            write_volatile((GICD + GICD_IROUTER + i * 8) as *mut u64, mpidr_aff());
            w(GICD + GICD_ISENABLER + (i / 32) * 4, 1 << (i % 32));
        }
    }
}

impl hal::IrqController for Gic {
    fn init(&self) {
        unsafe {
            // Distributor: affinity routing on, then Group 1 enabled.
            w(GICD + GICD_CTLR, CTLR_ARE);
            gicd_wait_rwp();
            w(GICD + GICD_CTLR, CTLR_ARE | CTLR_ENABLE_G1);
            gicd_wait_rwp();

            // Redistributor: wake it (clear ProcessorSleep, wait ChildrenAsleep == 0).
            let rd = my_gicr();
            w(rd + GICR_WAKER, r(rd + GICR_WAKER) & !(1 << 1));
            for _ in 0..1_000_000 {
                if r(rd + GICR_WAKER) & (1 << 2) == 0 {
                    break;
                }
            }

            // CPU interface via system registers.
            // ICC_SRE_EL1.SRE = 1 (system-register interface).
            let mut sre: u64;
            core::arch::asm!("mrs {}, S3_0_C12_C12_5", out(reg) sre);
            sre |= 1;
            core::arch::asm!("msr S3_0_C12_C12_5, {}", "isb", in(reg) sre);
            core::arch::asm!("msr S3_0_C4_C6_0, {}", in(reg) 0xF0u64); // ICC_PMR_EL1
            core::arch::asm!("msr S3_0_C12_C12_3, {}", in(reg) 0u64); // ICC_BPR1_EL1
            core::arch::asm!("msr S3_0_C12_C12_7, {}", "isb", in(reg) 1u64); // ICC_IGRPEN1_EL1
        }
    }

    fn enable(&self, intid: u32) {
        if intid >= 32 {
            return self.enable_spi(intid);
        }
        let rd = my_gicr();
        unsafe {
            w(rd + GICR_IGROUPR0, r(rd + GICR_IGROUPR0) | 1 << intid);
            write_volatile((rd + GICR_IPRIORITYR + intid as usize) as *mut u8, PRIO);
            w(rd + GICR_ISENABLER0, 1 << intid);
        }
    }

    fn ack(&self) -> u32 {
        let iar: u64;
        unsafe { core::arch::asm!("mrs {}, S3_0_C12_C12_0", out(reg) iar) }; // ICC_IAR1_EL1
        // Same contract as v2: 10-bit INTID, 1023 = spurious.
        (iar as u32) & 0x3FF
    }

    fn eoi(&self, intid: u32) {
        unsafe { core::arch::asm!("msr S3_0_C12_C12_1, {}", in(reg) intid as u64) }; // ICC_EOIR1_EL1
    }
}
