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
const BLOCK: u64 = 0b01; // L1/L2 block descriptor (bits[1:0] = 01)
const TABLE: u64 = 0b11; // L1/L2 table pointer (VALID | bit1)
const PAGE: u64 = 0b11; // L3 page descriptor (VALID | bit1)
const AF: u64 = 1 << 10; // access flag (fault if 0)
const SH_IS: u64 = 0b11 << 8; // inner shareable (normal memory)
const AP_RW_EL1: u64 = 0b00 << 6; // EL1 read/write
const AP_RO_EL1: u64 = 0b10 << 6; // EL1 read-only (+ executable when !PXN)
const PXN: u64 = 1 << 53; // privileged execute-never
const UXN: u64 = 1 << 54; // unprivileged execute-never
const ATTR_DEVICE: u64 = 0 << 2; // MAIR index 0 = Device-nGnRnE
const ATTR_NORMAL: u64 = 1 << 2; // MAIR index 1 = Normal WB cacheable
const ATTR_NC: u64 = 2 << 2; // MAIR index 2 = Normal Non-Cacheable

const GB: u64 = 1 << 30;
const M2: u64 = 2 << 20; // 2 MiB (L2 block size)
const NORMAL_GBS: u64 = 4; // GB 0..3 = RAM
/// Unused VA (GB 256 = 256 GiB) aliased onto physical GB0 for the VA!=PA proof.
pub const ALIAS_GB: u64 = 256;
pub const ALIAS_VA: usize = (ALIAS_GB * GB) as usize;
/// GB 257 aliases physical GB0 as Normal **Non-Cacheable** — a coherent-DMA
/// window for the GEM descriptor rings (matching Linux's dma_alloc_coherent).
/// Descriptor bytes are accessed ONLY through this alias so the CPU never caches
/// them; the GEM's status writeback is then always visible (no clean-clobber).
pub const NC_ALIAS_GB: u64 = 257;
pub const NC_ALIAS_VA: usize = (NC_ALIAS_GB * GB) as usize;

#[repr(align(4096))]
struct Table([u64; 512]);
static mut L1: Table = Table([0; 512]);
// P7b W^X: GB0 is split into an L2 table of 2 MiB RW+PXN blocks, except the
// kernel's 2 MiB block which uses an L3 table (per-page: .text RO+X, rest RW+PXN).
static mut L2_GB0: Table = Table([0; 512]);
static mut L3_KERN: Table = Table([0; 512]);

#[inline]
fn normal_block(pa: u64) -> u64 {
    pa | AF | SH_IS | AP_RW_EL1 | ATTR_NORMAL | BLOCK | VALID
}
#[inline]
fn normal_rw_block(pa: u64) -> u64 {
    // Data RAM: Normal RW + non-executable (PXN|UXN) — W^X for everything but .text.
    pa | AF | SH_IS | AP_RW_EL1 | ATTR_NORMAL | BLOCK | VALID | PXN | UXN
}
#[inline]
fn text_page(pa: u64) -> u64 {
    // Kernel .text: Normal RO + EL1-executable (UXN, NOT PXN). L3 page.
    pa | AF | SH_IS | AP_RO_EL1 | ATTR_NORMAL | PAGE | UXN
}
#[inline]
fn data_page(pa: u64) -> u64 {
    // Data/stack: Normal RW + non-executable. L3 page.
    pa | AF | SH_IS | AP_RW_EL1 | ATTR_NORMAL | PAGE | PXN | UXN
}
#[inline]
fn device_block(pa: u64) -> u64 {
    // MMIO is never executable (PXN|UXN).
    pa | AF | AP_RW_EL1 | ATTR_DEVICE | BLOCK | VALID | PXN | UXN
}
#[inline]
fn normal_nc_block(pa: u64) -> u64 {
    // Normal Non-Cacheable, data-only (PXN|UXN) — the DMA-coherent descriptor window.
    pa | AF | SH_IS | AP_RW_EL1 | ATTR_NC | BLOCK | VALID | PXN | UXN
}

/// P7b — build GB0 as a W^X map: L2 of 2 MiB RW+PXN blocks, with the kernel's
/// 2 MiB block an L3 table (`.text` RO+X, everything else RW+PXN). Writes L1[0].
fn build_wx_gb0() {
    extern "C" {
        static __text_start: u8;
        static __text_end: u8;
    }
    let ts = unsafe { core::ptr::addr_of!(__text_start) as u64 };
    let te = unsafe { core::ptr::addr_of!(__text_end) as u64 };
    let l2 = addr_of_mut!(L2_GB0) as *mut u64;
    let l3 = addr_of_mut!(L3_KERN) as *mut u64;
    let kern_blk = (ts / M2) as usize; // GB0 base = 0
    let blk_base = kern_blk as u64 * M2;
    unsafe {
        // L3 for the kernel's 2 MiB block.
        for p in 0..512u64 {
            let pa = blk_base + p * 0x1000;
            let desc = if pa >= ts && pa < te { text_page(pa) } else { data_page(pa) };
            core::ptr::write_volatile(l3.add(p as usize), desc);
        }
        // L2: 2 MiB RW+PXN blocks, except the kernel block -> the L3 table.
        for b in 0..512u64 {
            let desc = if b as usize == kern_blk {
                (l3 as u64) | TABLE
            } else {
                normal_rw_block(b * M2)
            };
            core::ptr::write_volatile(l2.add(b as usize), desc);
        }
        // Install GB0 = the L2 table.
        core::ptr::write_volatile(addr_of_mut!(L1) as *mut u64, (l2 as u64) | TABLE);
    }
}

/// Read back the effective descriptor for a VA (L2 block or L3 page) — W^X proof.
pub fn page_desc(va: usize) -> u64 {
    let i1 = (va >> 30) & 0x1FF;
    let i2 = (va >> 21) & 0x1FF;
    let i3 = (va >> 12) & 0x1FF;
    let l1 = addr_of_mut!(L1) as *const u64;
    let e1 = unsafe { core::ptr::read_volatile(l1.add(i1)) };
    if e1 & VALID == 0 {
        return 0;
    }
    if e1 & 0b10 == 0 {
        return e1; // 1 GiB block
    }
    let l2 = (e1 & 0xFFFF_FFFF_F000) as *const u64;
    let e2 = unsafe { core::ptr::read_volatile(l2.add(i2)) };
    if e2 & VALID == 0 || e2 & 0b10 == 0 {
        return e2; // invalid or 2 MiB block
    }
    let l3 = (e2 & 0xFFFF_FFFF_F000) as *const u64;
    unsafe { core::ptr::read_volatile(l3.add(i3)) }
}

/// Build the identity table, program MAIR/TCR/TTBR0, and enable the MMU +
/// caches. Returns with translation live and the (identity-mapped) console
/// still reachable.
pub fn enable_identity() {
    let l1 = addr_of_mut!(L1) as *mut u64;
    unsafe {
        // GB1..3 = Normal RW + non-exec (data RAM); GB4..511 = Device. GB0 is
        // built separately with W^X below (start the loop at 1).
        for i in 1..512u64 {
            let pa = i * GB;
            let desc = if i < NORMAL_GBS { normal_rw_block(pa) } else { device_block(pa) };
            core::ptr::write_volatile(l1.add(i as usize), desc);
        }
        // Alias GB256 -> physical GB0 as Normal memory (VA!=PA proof; WXN makes it
        // non-exec). Alias GB257 -> Normal Non-Cacheable (GEM descriptor window).
        core::ptr::write_volatile(l1.add(ALIAS_GB as usize), normal_block(0));
        core::ptr::write_volatile(l1.add(NC_ALIAS_GB as usize), normal_nc_block(0));
    }
    build_wx_gb0(); // GB0 = W^X map (kernel .text RO+X, rest RW+PXN); writes L1[0]

    // MAIR: attr0 = Device-nGnRnE (0x00), attr1 = Normal WB RW-alloc (0xFF),
    // attr2 = Normal Non-Cacheable (0x44).
    let mair: u64 = (0x44 << 16) | (0xFF << 8) | 0x00;

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
            "orr {tmp}, {tmp}, #(1 << 19)",  // WXN — writable => execute-never (W^X)
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
