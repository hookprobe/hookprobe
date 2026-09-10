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
// MemAttr[5:2] is DIRECT-encoded in stage-2 (not MAIR-indexed): 0xF = Normal
// Inner+Outer WB (bits 2..5 = 0x3C), 0x0 = Device-nGnRnE.  NOTE: 0x7C1 (an
// earlier value) has MemAttr=0x0 → Device, which — with no FEAT_S2FWB on A76,
// so stage-1∩stage-2 = most-restrictive — would mis-map all EL1 DRAM as Device
// and break atomics/instruction-fetch. Normal-WB MUST be 0x7FD.
const S2_NORMAL: u64 = 0x7FD; // block | MemAttr=0xF(WB) | S2AP=0b11(RW) | SH=IS | AF
const S2_DEVICE: u64 = (1 << 54) | 0x4C1; // XN | block | MemAttr=0x0(Device-nGnRnE) | S2AP=RW | AF
// L3 leaf is a PAGE descriptor (bits[1:0]=0b11), not a block (0b01) — same attrs as S2_DEVICE.
const S2_DEVICE_PAGE: u64 = (1 << 54) | 0x4C3;
const TABLE: u64 = 0b11;

// SEC-2 / V3 — the VC-mailbox page carve. MBOX = 0x10_7C01_3880 lives in GB block 65
// (Device MMIO). To deny a compromised EL1 kernel the OTP re-read (and thus the
// deterministic SRK/AK), split L1[65] -> L2 (2 MiB Device) -> L3 (4 KiB Device) and mark
// ONLY the 4 KiB page holding the mailbox [0x10_7C01_3000, 0x10_7C01_4000) INVALID for EL1.
// Everything else in GB65 stays mapped; EL1's only mailbox path is the whitelisted `hvc #2`
// proxy. (The eMMC is at 0x10_00FF_F000 = GB64, untouched.)
const MBOX_GB: u64 = 65; // 0x10_4000_0000 .. 0x10_8000_0000
const MBOX_L2_IDX: u64 = 480; // 2 MiB block @ 0x10_7C00_0000 within GB65
const MBOX_L3_IDX: u64 = 19; // 4 KiB page @ 0x10_7C01_3000 within that block (holds MBOX)

#[repr(align(4096))]
struct Table([u64; 512]);
static mut S2_L1: Table = Table([0; 512]);
static mut S2_L2_GB0: Table = Table([0; 512]);
static mut S2_L2_GB65: Table = Table([0; 512]);
static mut S2_L3_MBOX: Table = Table([0; 512]);

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

        // --- SEC-2 mailbox-page carve: GB65 -> L2 (2 MiB Device) -> L3 (4 KiB Device),
        // one page INVALID. Overrides the L1[65] Device block just written above. ---
        let l2_65 = core::ptr::addr_of_mut!(S2_L2_GB65) as *mut u64;
        let l3_mb = core::ptr::addr_of_mut!(S2_L3_MBOX) as *mut u64;
        let gb65_base = MBOX_GB * GB;
        let blk_base = gb65_base + MBOX_L2_IDX * M2; // 2 MiB block holding the mailbox
        // L3: 512 x 4 KiB Device pages, EXCEPT the mailbox page (invalid -> EL1 faults to EL2).
        for k in 0..512u64 {
            let pa = blk_base + k * 0x1000;
            let desc = if k == MBOX_L3_IDX { 0 } else { pa | S2_DEVICE_PAGE };
            core::ptr::write_volatile(l3_mb.add(k as usize), desc);
        }
        // L2 for GB65: 512 x 2 MiB Device blocks, EXCEPT the mailbox block -> the L3 table.
        for j in 0..512u64 {
            let pa = gb65_base + j * M2;
            let desc = if j == MBOX_L2_IDX { (l3_mb as u64) | TABLE } else { pa | S2_DEVICE };
            core::ptr::write_volatile(l2_65.add(j as usize), desc);
        }
        // Redirect L1[65] from the 1 GiB Device block to the carved L2 table.
        core::ptr::write_volatile(l1.add(MBOX_GB as usize), (l2_65 as u64) | TABLE);

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
