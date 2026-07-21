//! P7e — EL1↔EL2 isolation via stage-2 translation (audit B-3).
//!
//! HBoot stays resident at EL2 (the HVC reboot/fault gate). Without isolation
//! the EL1 kernel can read/write HBoot's EL2 code, page tables, and stack —
//! undermining the trust hierarchy the whole attestation chain rests on. This
//! installs a **stage-2** identity map (IPA=PA) for the EL1&0 regime that
//! EXCLUDES HBoot's own footprint, so any EL1 access to it takes a stage-2
//! Translation fault straight to EL2 (caught by `lower64_sync_gate`). Stage-2
//! applies only to EL1/EL0 — EL2's own accesses are untouched, so enabling it
//! can't pull the rug from under the resident boot manager.
//!
//! Register values (Cortex-A76 = ARMv8.2-A, no FEAT_S2FWB) from the Arm ARM
//! (DDI0487 D8/D19) + Linux KVM/Xen: VTCR_EL2=0x8002_3559 (39-bit IPA, 4KB,
//! start level 1, WB/IS walks, 40-bit PA), single 4KB L1 table (no
//! concatenation). Stage-2 leaf attrs: MemAttr[5:2] direct-encoded (0xF=Normal
//! WB, 0x0=Device), S2AP[7:6]=0b11 (EL1 RW), AF, SH=IS, XN[54] for Device.

/// HBoot's protected physical footprint: code+rodata+data+bss+page-tables
/// (0x200000..~0x400000) and the EL2 stack (grows down from 0x800000). The
/// resident HVC gate keeps the EL2 stack live, so the whole span is excluded.
const HOLE_LO: u64 = 0x0020_0000;
const HOLE_HI: u64 = 0x0080_0000;

const GB: u64 = 1 << 30;
const M2: u64 = 2 << 20; // 2 MiB

// Stage-2 leaf descriptor lower attributes (bits[1:0]=0b01 = block).
const S2_NORMAL: u64 = 0x7C1; // block | MemAttr=0xF(WB) | S2AP=0b11(RW) | SH=IS | AF
const S2_DEVICE: u64 = (1 << 54) | 0x4C1; // XN | block | MemAttr=0x0(Device-nGnRnE) | S2AP=RW | AF
const TABLE: u64 = 0b11;

#[repr(align(4096))]
struct Table([u64; 512]);
static mut S2_L1: Table = Table([0; 512]);
static mut S2_L2_GB0: Table = Table([0; 512]);

/// Build the stage-2 table and program VTCR_EL2/VTTBR_EL2 (+ stage-2 TLBI).
/// Stage-2 is not yet ACTIVE — `hboot_launch_el1` sets HCR_EL2.VM right before
/// `eret`. Call once, just before launching the kernel.
pub fn enable() {
    let l1 = core::ptr::addr_of_mut!(S2_L1) as *mut u64;
    let l2 = core::ptr::addr_of_mut!(S2_L2_GB0) as *mut u64;
    unsafe {
        // GB0 (0..1 GiB) = L2 of 2 MiB Normal-WB blocks, HBoot hole INVALID.
        for i in 0..512u64 {
            let pa = i * M2;
            let desc = if pa >= HOLE_LO && pa < HOLE_HI {
                0 // invalid leaf → EL1 access faults to EL2
            } else {
                pa | S2_NORMAL
            };
            core::ptr::write_volatile(l2.add(i as usize), desc);
        }
        // L1[0] → L2 (GB0); GB1..3 = Normal-WB (DRAM); GB4..511 = Device (MMIO,
        // incl. RP1 @112 GiB and BCM2712 periph @64 GiB) — matches stage-1's
        // Normal/Device split (belt-and-suspenders vs stage-1 mis-attribution).
        core::ptr::write_volatile(l1, (l2 as u64) | TABLE);
        for i in 1..512u64 {
            let pa = i * GB;
            let desc = if i < 4 { pa | S2_NORMAL } else { pa | S2_DEVICE };
            core::ptr::write_volatile(l1.add(i as usize), desc);
        }

        let vtcr: u64 = 0x8002_3559; // 39-bit IPA, SL0=1, 4KB, WB/IS, PS=40b, RES1
        let vttbr: u64 = l1 as u64; // VMID=0, 4KB-aligned L1 base
        core::arch::asm!(
            "dsb ish",                 // table writes observable to the walker
            "msr vtcr_el2, {vtcr}",
            "msr vttbr_el2, {vttbr}",
            "isb",
            "tlbi vmalls12e1is",       // flush stale stage-1&2 for this VMID
            "dsb ish",
            "isb",
            vtcr = in(reg) vtcr,
            vttbr = in(reg) vttbr,
            options(nostack),
        );
    }
}
