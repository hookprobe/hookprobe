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
const GICR_STRIDE: usize = 0x2_0000; // RD_base + SGI_base (2 x 64 KiB) per CPU
const GICR_STRIDE_VLPI: usize = 0x4_0000; // GICv4 (GICR_TYPER.VLPIS): + VLPI_base + reserved
const GICR_MAX: usize = 512;

/// SPI trigger mode. GICv2-era heqk forced edge (the CM5 GEM/RP1 mip forwards edge); on the
/// cloud the PL011 (SPI 33 on OCI A1) and PCIe INTx are LEVEL.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Trigger {
    Level,
    Edge,
}

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

fn mpidr() -> u64 {
    let m: u64;
    unsafe { core::arch::asm!("mrs {}, mpidr_el1", out(reg) m) };
    m
}

/// Affinity in the GICR_TYPER[63:32] layout: Aff3[31:24] | Aff2[23:16] | Aff1[15:8] | Aff0[7:0].
fn typer_aff() -> u64 {
    let m = mpidr();
    ((m >> 32) & 0xff) << 24 | (m & 0x00ff_ffff)
}

/// Affinity in the GICD_IROUTER layout: Aff3[39:32] | IRM[31]=0 (targeted) | Aff2..Aff0[23:0].
/// (Distinct from the GICR_TYPER packing — putting Aff3 in [31:24] would set IRM on a
/// host with a non-zero Aff3 and silently switch to 1-of-N routing.)
fn irouter_aff() -> u64 {
    let m = mpidr();
    ((m >> 32) & 0xff) << 32 | (m & 0x00ff_ffff)
}

/// The boot CPU's redistributor: walk the frames until GICR_TYPER.Affinity matches. The
/// frame stride doubles on GICv4 (VLPIS). `None` if not found (reported by the caller).
fn my_gicr() -> Option<usize> {
    let me = typer_aff();
    let mut rd = GICR_BASE;
    for _ in 0..GICR_MAX {
        let typer = unsafe { read_volatile((rd + GICR_TYPER) as *const u64) };
        if (typer >> 32) == me {
            return Some(rd);
        }
        if typer & (1 << 4) != 0 {
            break; // Last
        }
        rd += if typer & (1 << 1) != 0 { GICR_STRIDE_VLPI } else { GICR_STRIDE };
    }
    None
}

static GICR_WARNED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// `my_gicr()` with a one-time loud fallback to frame 0 (single-CPU boot) instead of a
/// silent one.
fn gicr_or_warn() -> usize {
    my_gicr().unwrap_or_else(|| {
        if !GICR_WARNED.swap(true, core::sync::atomic::Ordering::Relaxed) {
            crate::_print(format_args!(
                " gicv3: WARN no redistributor matches MPIDR aff {:#x}; using frame 0 @ {:#x}\n",
                typer_aff(), GICR_BASE
            ));
        }
        GICR_BASE
    })
}

/// Wait for a GICD_CTLR write to take effect. False on timeout (reported by the caller).
fn gicd_wait_rwp() -> bool {
    for _ in 0..1_000_000 {
        if unsafe { r(GICD + GICD_CTLR) } & CTLR_RWP == 0 {
            return true;
        }
    }
    false
}

/// The GICv3 as a HAL `IrqController`.
pub struct Gic;

impl Gic {
    /// Enable a shared peripheral interrupt EDGE-triggered — API parity with the GICv2
    /// driver's `enable_spi` (its only caller is the CM5 GEM path, whose mip forwards edge).
    /// Cloud devices should use `enable_spi_trigger(intid, Trigger::Level)` or `enable()`.
    pub fn enable_spi(&self, intid: u32) {
        self.enable_spi_trigger(intid, Trigger::Edge);
    }

    /// Enable a shared peripheral interrupt: Group 1, priority, `trigger`, routed to this CPU.
    pub fn enable_spi_trigger(&self, intid: u32, trigger: Trigger) {
        let i = intid as usize;
        if !(32..1020).contains(&i) {
            return; // not an SPI
        }
        unsafe {
            let g = GICD + GICD_IGROUPR + (i / 32) * 4;
            w(g, r(g) | 1 << (i % 32));
            write_volatile((GICD + GICD_IPRIORITYR + i) as *mut u8, PRIO);
            let icfg = GICD + GICD_ICFGR + (i / 16) * 4;
            let shift = (i % 16) * 2;
            let mode = if trigger == Trigger::Edge { 0b10 } else { 0b00 };
            w(icfg, (r(icfg) & !(0b11 << shift)) | (mode << shift));
            write_volatile((GICD + GICD_IROUTER + i * 8) as *mut u64, irouter_aff());
            w(GICD + GICD_ISENABLER + (i / 32) * 4, 1 << (i % 32));
        }
    }
}

impl hal::IrqController for Gic {
    fn init(&self) {
        unsafe {
            // Distributor: affinity routing on, then Group 1 enabled.
            w(GICD + GICD_CTLR, CTLR_ARE);
            let ok1 = gicd_wait_rwp();
            w(GICD + GICD_CTLR, CTLR_ARE | CTLR_ENABLE_G1);
            let ok2 = gicd_wait_rwp();
            if !(ok1 && ok2) {
                crate::_print(format_args!(" gicv3: WARN GICD_CTLR.RWP never cleared (distributor @ {:#x})\n", GICD));
            }

            // Redistributor: wake it (clear ProcessorSleep, wait ChildrenAsleep == 0).
            let rd = gicr_or_warn();
            w(rd + GICR_WAKER, r(rd + GICR_WAKER) & !(1 << 1));
            let mut awake = false;
            for _ in 0..1_000_000 {
                if r(rd + GICR_WAKER) & (1 << 2) == 0 {
                    awake = true;
                    break;
                }
            }
            if !awake {
                crate::_print(format_args!(" gicv3: WARN redistributor @ {:#x} did not wake (ChildrenAsleep)\n", rd));
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
            // Cloud default: level (PL011, PCIe INTx). Edge users call enable_spi().
            return self.enable_spi_trigger(intid, Trigger::Level);
        }
        let rd = gicr_or_warn();
        unsafe {
            w(rd + GICR_IGROUPR0, r(rd + GICR_IGROUPR0) | 1 << intid);
            write_volatile((rd + GICR_IPRIORITYR + intid as usize) as *mut u8, PRIO);
            w(rd + GICR_ISENABLER0, 1 << intid);
        }
    }

    fn ack(&self) -> u32 {
        let iar: u64;
        unsafe { core::arch::asm!("mrs {}, S3_0_C12_C12_0", out(reg) iar) }; // ICC_IAR1_EL1
        // GICv3 INTIDs are 24-bit here (ICC_CTLR_EL1.IDbits): LPIs/ITS-MSIs start at 8192, so
        // the GICv2 10-bit mask would alias e.g. 8192 -> 0 (an SGI). Spurious stays 1023.
        (iar as u32) & 0x00FF_FFFF
    }

    fn eoi(&self, intid: u32) {
        unsafe { core::arch::asm!("msr S3_0_C12_C12_1, {}", in(reg) intid as u64) }; // ICC_EOIR1_EL1
    }
}
