//! P7a — stage-1 MMU on real BCM2712 silicon (identity map, 40-bit PA space).
//!
//! The CM5 addresses peripherals above 32 bits: the RP1 window (incl. the
//! console UART) is at 0x1C_0000_0000 and the SoC blocks at 0x10_xx_xxxx_xxxx.
//! So the boot map must cover a 39-bit VA space (512 GiB) with 1 GiB L1 blocks:
//!   GB 0..3     Normal cacheable  — kernel @0x1000000, stack, BootInfo, RAM
//!   GB 4..511   Device-nGnRnE     — SoC (GB 64/65) + RP1 (GB 112) peripherals
//! The map is identity (VA==PA), so enabling translation is seamless and the
//! console keeps working. One extra block (GB `ALIAS_GB`) aliases physical GB0
//! as Normal memory, giving a VA!=PA read-back that proves the walk is live.

use core::ptr::addr_of_mut;

const VALID: u64 = 1 << 0;
const BLOCK: u64 = 0b01; // L1 block descriptor (bits[1:0] = 01)
const AF: u64 = 1 << 10; // access flag (fault if 0)
const SH_IS: u64 = 0b11 << 8; // inner shareable (normal memory)
const AP_RW_EL1: u64 = 0b00 << 6; // EL1 read/write
const PXN: u64 = 1 << 53; // privileged execute-never
const UXN: u64 = 1 << 54; // unprivileged execute-never
const ATTR_DEVICE: u64 = 0 << 2; // MAIR index 0 = Device-nGnRnE
const ATTR_NORMAL: u64 = 1 << 2; // MAIR index 1 = Normal WB cacheable

const GB: u64 = 1 << 30;
const NORMAL_GBS: u64 = 4; // GB 0..3 = RAM
/// Unused VA (GB 256 = 256 GiB) aliased onto physical GB0 for the VA!=PA proof.
pub const ALIAS_GB: u64 = 256;
pub const ALIAS_VA: usize = (ALIAS_GB * GB) as usize;

#[repr(align(4096))]
struct Table([u64; 512]);
static mut L1: Table = Table([0; 512]);

#[inline]
fn normal_block(pa: u64) -> u64 {
    pa | AF | SH_IS | AP_RW_EL1 | ATTR_NORMAL | BLOCK | VALID
}
#[inline]
fn device_block(pa: u64) -> u64 {
    // MMIO is never executable (PXN|UXN).
    pa | AF | AP_RW_EL1 | ATTR_DEVICE | BLOCK | VALID | PXN | UXN
}

/// Build the identity table, program MAIR/TCR/TTBR0, and enable the MMU +
/// caches. Returns with translation live and the (identity-mapped) console
/// still reachable.
pub fn enable_identity() {
    let l1 = addr_of_mut!(L1) as *mut u64;
    unsafe {
        for i in 0..512u64 {
            let pa = i * GB;
            let desc = if i < NORMAL_GBS { normal_block(pa) } else { device_block(pa) };
            core::ptr::write_volatile(l1.add(i as usize), desc);
        }
        // Alias GB256 -> physical GB0 as Normal memory (VA!=PA, same bytes).
        core::ptr::write_volatile(l1.add(ALIAS_GB as usize), normal_block(0));
    }

    // MAIR: attr0 = Device-nGnRnE (0x00), attr1 = Normal WB RW-alloc (0xFF).
    let mair: u64 = (0xFF << 8) | 0x00;

    // TCR_EL1: T0SZ=25 (39-bit VA), 4 KiB granule, inner-shareable WB walks,
    // TTBR1 disabled, IPS=40-bit PA.
    let t0sz: u64 = 25;
    let irgn0: u64 = 0b01 << 8; // WB WA
    let orgn0: u64 = 0b01 << 10; // WB WA
    let sh0: u64 = 0b11 << 12; // inner shareable
    let tg0: u64 = 0b00 << 14; // 4 KiB
    let epd1: u64 = 1 << 23; // no TTBR1 walks
    let ips: u64 = 0b010 << 32; // 40-bit physical address size
    let tcr = t0sz | irgn0 | orgn0 | sh0 | tg0 | epd1 | ips;

    unsafe {
        core::arch::asm!(
            "msr mair_el1, {mair}",
            "msr tcr_el1,  {tcr}",
            "msr ttbr0_el1, {ttbr}",
            "dsb ish",
            "tlbi vmalle1",
            "dsb ish",
            "isb",
            // Turn on MMU (M), data cache (C), instruction cache (I).
            "mrs {tmp}, sctlr_el1",
            "orr {tmp}, {tmp}, #(1 << 0)",   // M
            "orr {tmp}, {tmp}, #(1 << 2)",   // C
            "orr {tmp}, {tmp}, #(1 << 12)",  // I
            "msr sctlr_el1, {tmp}",
            "isb",
            mair = in(reg) mair,
            tcr = in(reg) tcr,
            ttbr = in(reg) l1 as u64,
            tmp = out(reg) _,
        );
    }
}

/// True if stage-1 translation (SCTLR_EL1.M) is enabled.
pub fn enabled() -> bool {
    let sctlr: u64;
    unsafe { core::arch::asm!("mrs {}, sctlr_el1", out(reg) sctlr) };
    sctlr & 1 != 0
}
