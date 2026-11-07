//! EL2 identity MMU for HBoot — enabled early so HBoot's crypto runs CACHED.
//!
//! HBoot runs at EL2 with the MMU off, which forces all data accesses to be
//! non-cacheable. SLH-DSA-128s *signing* (the attestation quote) is millions of
//! hash ops; uncached that is minutes. Turning on an identity map with a data
//! cache brings it to seconds (and speeds the boot signature verify too).
//!
//! Same layout as the kernel's EL1 map (39-bit VA, 1 GiB blocks: GB0..3 Normal
//! cacheable = HBoot code/stack/payload/RAM; GB4..511 Device = peripherals incl.
//! the console UART at GB112). EL2 sysregs (TCR_EL2/MAIR_EL2/TTBR0_EL2/SCTLR_EL2,
//! non-VHE) differ from EL1 in the TCR PS-field position and RES1 bits.

use core::ptr::addr_of_mut;

const VALID: u64 = 1 << 0;
const BLOCK: u64 = 0b01;
const AF: u64 = 1 << 10;
const SH_IS: u64 = 0b11 << 8;
const PXN: u64 = 1 << 53; // privileged execute-never (device memory)
const UXN: u64 = 1 << 54;
const ATTR_DEVICE: u64 = 0 << 2;
const ATTR_NORMAL: u64 = 1 << 2;
const GB: u64 = 1 << 30;
const NORMAL_GBS: u64 = 4;

#[repr(align(4096))]
struct Table([u64; 512]);
static mut L1: Table = Table([0; 512]);

/// Clean the D-cache by VA over [base, base+len) to the Point of Coherency, so
/// bytes HBoot wrote (cached) are visible to a consumer reading non-cacheably —
/// e.g. the kernel reading its relocated image / BootInfo at EL1 before it turns
/// its own MMU on. Call before handing off.
pub fn clean_dcache_range(base: usize, len: usize) {
    const LINE: usize = 64; // BCM2712 A76 cache line
    let start = base & !(LINE - 1);
    let end = base + len;
    let mut a = start;
    while a < end {
        unsafe { core::arch::asm!("dc cvac, {}", in(reg) a) };
        a += LINE;
    }
    unsafe { core::arch::asm!("dsb sy") };
}

/// Build the identity table and enable the EL2 MMU + caches. Idempotent-safe to
/// call once at HBoot entry, before any crypto.
pub fn enable_identity_el2() {
    let l1 = addr_of_mut!(L1) as *mut u64;
    unsafe {
        for i in 0..512u64 {
            let pa = i * GB;
            let desc = if i < NORMAL_GBS {
                pa | AF | SH_IS | ATTR_NORMAL | BLOCK | VALID
            } else {
                pa | AF | ATTR_DEVICE | BLOCK | VALID | PXN | UXN // MMIO never executable
            };
            core::ptr::write_volatile(l1.add(i as usize), desc);
        }
    }

    let mair: u64 = (0xFF << 8) | 0x00; // attr0 Device-nGnRnE, attr1 Normal WB

    // TCR_EL2 (non-VHE, TTBR0 only): T0SZ=25, 4KiB granule, WB inner-shareable
    // walks, PS=40-bit at [18:16]; bits 23 and 31 are RES1 in TCR_EL2.
    let t0sz: u64 = 25;
    let irgn0: u64 = 0b01 << 8;
    let orgn0: u64 = 0b01 << 10;
    let sh0: u64 = 0b11 << 12;
    let tg0: u64 = 0b00 << 14;
    let ps: u64 = 0b010 << 16; // 40-bit PA
    let res1: u64 = (1 << 23) | (1 << 31);
    let tcr = t0sz | irgn0 | orgn0 | sh0 | tg0 | ps | res1;

    unsafe {
        core::arch::asm!(
            "msr mair_el2, {mair}",
            "msr tcr_el2,  {tcr}",
            "msr ttbr0_el2, {ttbr}",
            "dsb sy",
            "tlbi alle2",
            "dsb sy",
            "isb",
            "mrs {tmp}, sctlr_el2",
            "orr {tmp}, {tmp}, #(1 << 0)",   // M
            "orr {tmp}, {tmp}, #(1 << 2)",   // C
            "orr {tmp}, {tmp}, #(1 << 12)",  // I
            "msr sctlr_el2, {tmp}",
            "isb",
            mair = in(reg) mair,
            tcr = in(reg) tcr,
            ttbr = in(reg) l1 as u64,
            tmp = out(reg) _,
        );
    }
}
