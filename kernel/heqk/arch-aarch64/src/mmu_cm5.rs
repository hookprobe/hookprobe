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
const AP_RW_EL0: u64 = 0b01 << 6; // EL0+EL1 read/write
const AP_RO_EL1: u64 = 0b10 << 6; // EL1 read-only (+ executable when !PXN)
const AP_RO_EL0: u64 = 0b11 << 6; // EL0+EL1 read-only (+ EL0-executable when !UXN)
const PXN: u64 = 1 << 53; // privileged execute-never
const UXN: u64 = 1 << 54; // unprivileged execute-never
const NG: u64 = 1 << 11; // non-global — the entry is tagged by the current ASID
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

// P7c step 3b — EL0 user window at GB5 (0x1_4000_0000), an unused-on-CM5 GB. Its
// first 2 MiB block is L3-mapped so an isolated EL0 driver gets code/stack/device
// pages there. L2_USER[0] -> L3_USER; the driver's pages fill L3_USER slots.
pub const USER_GB: u64 = 5;
pub const USER_VA_BASE: usize = (USER_GB * GB) as usize; // 0x1_4000_0000
static mut L2_USER: Table = Table([0; 512]);
static mut L3_USER: Table = Table([0; 512]);

// P8 — JIT code window at GB6 (0x1_8000_0000), an unused-on-CM5 GB. Its first
// 2 MiB block is L3-mapped so the BPF JIT can install EL1 RO+X code pages on
// metal — so the detection datapath runs NATIVE code, not just the interpreter.
pub const JITCODE_GB: u64 = 6;
pub const JITCODE_VA_BASE: usize = (JITCODE_GB * GB) as usize; // 0x1_8000_0000
static mut L2_JIT: Table = Table([0; 512]);
static mut L3_JIT: Table = Table([0; 512]);

// B-9 close (JIT half): a dedicated, L3-mapped 2 MiB block in GB0 for JIT code
// FRAMES. Because it's per-page (not a 2 MiB block), each JIT page's writable
// identity alias can be SEALED read-only after the code is emitted — so no
// writable alias of executable code survives (full W^X). 896 MiB, its own block.
const JITPOOL_BASE: u64 = 0x3800_0000;
const JITPOOL_BLK: usize = (JITPOOL_BASE / M2) as usize; // GB0 2 MiB block index (448)
static mut L3_JITPOOL: Table = Table([0; 512]);
// EL0 driver code + stack live in these Normal-RAM frames (also visible via the
// GB0 identity map as RW+PXN — same cacheable type, so no attribute mismatch).
#[repr(align(4096))]
struct Page([u8; 4096]);
static mut EL0_CODE: Page = Page([0; 4096]);
static mut EL0_STACK: Page = Page([0; 4096]);

/// Physical address of the EL0 driver code frame (kernel copies the stub here).
pub fn el0_code_pa() -> usize {
    addr_of_mut!(EL0_CODE) as usize
}
/// Physical address of the EL0 driver stack frame.
pub fn el0_stack_pa() -> usize {
    addr_of_mut!(EL0_STACK) as usize
}

#[inline]
fn user_page(pa: u64, ap: u64, attr: u64, xn: u64) -> u64 {
    pa | AF | SH_IS | ap | attr | PAGE | xn
}
/// L3 index of a VA within the GB5 user window's first 2 MiB block.
#[inline]
fn user_l3_idx(va: usize) -> usize {
    (va >> 12) & 0x1FF
}
/// Map an EL0 RO+X code page at `va` (in the GB5 user window) → phys `pa`.
pub fn map_user_code(va: usize, pa: usize) {
    write_user_l3(va, user_page(pa as u64, AP_RO_EL0, ATTR_NORMAL, PXN)); // EL0 exec, EL1 non-exec
}
/// Map an EL0 RW data/stack page.
pub fn map_user_data(va: usize, pa: usize) {
    write_user_l3(va, user_page(pa as u64, AP_RW_EL0, ATTR_NORMAL, PXN | UXN));
}
/// Map an EL0 device-MMIO window (a driver's capability to touch one device).
pub fn map_user_device(va: usize, pa: usize) {
    write_user_l3(va, user_page(pa as u64, AP_RW_EL0, ATTR_DEVICE, PXN | UXN));
}
/// Map an EL0 Normal-Non-Cacheable window (a driver's coherent view of the DMA
/// descriptor ring — EL0 can't do cache maintenance, so NC keeps it coherent).
pub fn map_user_nc(va: usize, pa: usize) {
    write_user_l3(va, user_page(pa as u64, AP_RW_EL0, ATTR_NC, PXN | UXN));
}
/// AUDIT L-14: is `va` actually inside the GB5 EL0 grant window, and page-aligned?
///
/// `user_l3_idx` is `(va >> 12) & 0x1FF` with no range check, so passing any other
/// VA silently installs the mapping at an unrelated L3 slot — i.e. the grant appears
/// at a VA the caller never intended, while the intended VA stays unmapped. Every
/// current caller uses `USER_VA_BASE + n*0x1000`, so this is latent today; it stops
/// being latent the moment range-mappers are added.
#[inline]
fn user_va_ok(va: usize) -> bool {
    va >= USER_VA_BASE && va < USER_VA_BASE + M2 as usize && (va & 0xFFF) == 0
}
fn write_user_l3(va: usize, desc: u64) {
    if !user_va_ok(va) {
        // Fail closed: refuse to install a grant at an aliased slot.
        return;
    }
    let l3 = addr_of_mut!(L3_USER) as *mut u64;
    unsafe {
        core::ptr::write_volatile(l3.add(user_l3_idx(va)), desc);
        core::arch::asm!("dsb ish");
        core::arch::asm!("tlbi vaae1is, {}", in(reg) (va >> 12) as u64);
        core::arch::asm!("dsb ish");
        core::arch::asm!("isb");
    }
}

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
    let l3j = addr_of_mut!(L3_JITPOOL) as *mut u64;
    let kern_blk = (ts / M2) as usize; // GB0 base = 0
    let blk_base = kern_blk as u64 * M2;
    unsafe {
        // L3 for the kernel's 2 MiB block.
        for p in 0..512u64 {
            let pa = blk_base + p * 0x1000;
            let desc = if pa >= ts && pa < te { text_page(pa) } else { data_page(pa) };
            core::ptr::write_volatile(l3.add(p as usize), desc);
        }
        // L3 for the JIT-pool block: RW+PXN data pages (emit here, then seal RO).
        for p in 0..512u64 {
            core::ptr::write_volatile(l3j.add(p as usize), data_page(JITPOOL_BASE + p * 0x1000));
        }
        // L2: 2 MiB RW+PXN blocks, except the kernel + JIT-pool blocks -> L3 tables.
        for b in 0..512u64 {
            let desc = if b as usize == kern_blk {
                (l3 as u64) | TABLE
            } else if b as usize == JITPOOL_BLK {
                (l3j as u64) | TABLE
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
        // GB5 = the EL0 user window: L1[5] -> L2_USER -> L3_USER (both empty now;
        // an EL0 driver's pages are filled into L3_USER at run time). Overwrites
        // the (unused) GB5 device block before the MMU turns on — no BBM needed.
        let l2u = addr_of_mut!(L2_USER) as *mut u64;
        let l3u = addr_of_mut!(L3_USER) as *mut u64;
        core::ptr::write_volatile(l2u.add(0), (l3u as u64) | TABLE);
        core::ptr::write_volatile(l1.add(USER_GB as usize), (l2u as u64) | TABLE);
        // GB6 = the JIT code window: L1[6] -> L2_JIT -> L3_JIT (empty now; the JIT
        // fills L3_JIT slots at run time). Overwrites the unused GB6 device block.
        let l2j = addr_of_mut!(L2_JIT) as *mut u64;
        let l3j = addr_of_mut!(L3_JIT) as *mut u64;
        core::ptr::write_volatile(l2j.add(0), (l3j as u64) | TABLE);
        core::ptr::write_volatile(l1.add(JITCODE_GB as usize), (l2j as u64) | TABLE);
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
    // P7c-4c: AS=1 (16-bit ASIDs) so TTBR0[63:48] selects the address space and a
    // context switch between per-driver ASIDs needs NO TLB flush (non-global user
    // entries are ASID-tagged). Kernel/device blocks are global (nG=0) — shared.
    let asbit: u64 = 1 << 36;
    let tcr = t0sz | irgn0 | orgn0 | sh0 | tg0 | epd1 | ips | asbit;

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

// ===========================================================================
// P7c-4c — per-address-space MMU on CM5: a runtime frame allocator, cloned L1s
// with their OWN GB5 user tables, ASID assignment, and TTBR0 switching. This is
// the CM5 port of the QEMU `mmu.rs` mechanism (new_addr_space/map_user_*_in/
// switch_ttbr0), so an isolated EL0 driver can run as a *preemptible scheduled
// TCB in its own ASID* on metal (not the cooperative `enter_user` loop). The
// scheduler switches TTBR0 on each tick; ASID-tagged (nG) user entries make the
// switch flush-free. Kernel/device/alias blocks are shared (global) via the L1
// copy, so the driver AS sees the same console/RAM/peripheral map.
// ===========================================================================

use core::sync::atomic::{AtomicU16, AtomicUsize, Ordering};

// Runtime frame pool: a high, unused window of GB0 RAM (Normal WB, mapped RW+PXN
// as data by the W^X L2). 768 MiB..896 MiB — well above the kernel image, its
// BSS/stack, the static packet/GEM pools, and the aliases. 4 KiB granularity.
const POOL_BASE: usize = 0x3000_0000; // 768 MiB
const POOL_END: usize = 0x3800_0000; // 896 MiB (128 MiB of tables/frames)
static FRAME_NEXT: AtomicUsize = AtomicUsize::new(POOL_BASE);
static NEXT_ASID: AtomicU16 = AtomicU16::new(1); // ASID 0 = the kernel/global space

/// Allocate a zeroed 4 KiB physical frame from the CM5 runtime pool, or 0 if the
/// pool is exhausted. Frames are Normal-WB cacheable (fine for page tables — the
/// walker does cacheable walks — and for EL0 code/data mapped through user L3).
pub fn alloc_frame() -> usize {
    let f = FRAME_NEXT.fetch_add(0x1000, Ordering::Relaxed);
    if f + 0x1000 > POOL_END {
        return 0;
    }
    unsafe {
        let p = f as *mut u64;
        for i in 0..512 {
            core::ptr::write_volatile(p.add(i), 0);
        }
        core::arch::asm!("dsb ish");
    }
    f
}

#[inline]
fn user_page_ng(pa: u64, ap: u64, attr: u64, xn: u64) -> u64 {
    // Like `user_page`, but non-global (ASID-tagged) so a no-flush TTBR0 switch
    // between driver address spaces keeps their user entries apart in the TLB.
    pa | AF | SH_IS | ap | attr | PAGE | xn | NG
}

/// The kernel/global address space's TTBR0 value (kernel L1 root | ASID 0).
pub fn kernel_ttbr0() -> u64 {
    addr_of_mut!(L1) as u64
}

/// Write a raw TTBR0_EL1 value (root | ASID<<48) + isb. The scheduler calls this
/// on each context switch to enter the next thread's address space.
pub fn set_ttbr0_raw(ttbr0: u64) {
    unsafe {
        core::arch::asm!("msr ttbr0_el1, {}", in(reg) ttbr0);
        core::arch::asm!("isb");
    }
}

/// Switch the active address space: TTBR0_EL1 = root | (asid<<48), isb. No flush.
pub fn switch_ttbr0(l1_root: usize, asid: u16) {
    set_ttbr0_raw(l1_root as u64 | ((asid as u64) << 48));
}

/// Create a fresh address space: a new L1 that copies the kernel's 512 entries
/// (so kernel/device/alias/W^X mappings are shared, global) but installs its OWN
/// GB5 user tables (L2->L3) so its EL0 pages are private. Returns (l1_root_pa,
/// asid), or (0,0) on pool exhaustion.
pub fn new_addr_space() -> (usize, u16) {
    let l1 = alloc_frame();
    if l1 == 0 {
        return (0, 0);
    }
    let src = addr_of_mut!(L1) as *const u64;
    let dst = l1 as *mut u64;
    unsafe {
        for i in 0..512 {
            core::ptr::write_volatile(dst.add(i), core::ptr::read_volatile(src.add(i)));
        }
    }
    // Give this AS its own GB5 user window (private L2->L3).
    let l2u = alloc_frame();
    let l3u = alloc_frame();
    if l2u == 0 || l3u == 0 {
        return (0, 0);
    }
    unsafe {
        core::ptr::write_volatile((l2u as *mut u64).add(0), (l3u as u64) | TABLE);
        core::ptr::write_volatile(dst.add(USER_GB as usize), (l2u as u64) | TABLE);
        core::arch::asm!("dsb ish");
    }
    let asid = NEXT_ASID.fetch_add(1, Ordering::Relaxed) & 0xFFFF;
    (l1, asid)
}

/// Locate an address space's private GB5 user L3 table from its L1 root.
fn user_l3_of(l1_root: usize) -> *mut u64 {
    let l1 = l1_root as *const u64;
    let e1 = unsafe { core::ptr::read_volatile(l1.add(USER_GB as usize)) };
    let l2 = (e1 & 0xFFFF_FFFF_F000) as *const u64;
    let e2 = unsafe { core::ptr::read_volatile(l2.add(0)) };
    (e2 & 0xFFFF_FFFF_F000) as *mut u64
}

/// Write an EL0 page into a specific address space's private user table (ASID-
/// tagged / non-global). `va` must be in the GB5 user window's first 2 MiB block.
fn map_user_in(l1_root: usize, va: usize, desc: u64) -> bool {
    if l1_root == 0 {
        return false;
    }
    // CORE-5/A9: apply the SAME GB5-window range check as write_user_l3 — the L-14
    // fix landed only on the single-AS path, leaving this per-ASID grant path able to
    // wrap an out-of-window VA (user_l3_idx = (va>>12)&0x1FF) to a wrong L3 slot,
    // silently granting a page at a VA the caller never intended.
    if !user_va_ok(va) {
        return false;
    }
    let l3 = user_l3_of(l1_root);
    if l3.is_null() {
        return false;
    }
    unsafe {
        core::ptr::write_volatile(l3.add(user_l3_idx(va)), desc);
        core::arch::asm!("dsb ish");
        // CORE-5: invalidate any stale TLB entry for this VA (was missing here).
        core::arch::asm!("tlbi vaae1is, {}", in(reg) (va >> 12) as u64);
        core::arch::asm!("dsb ish");
        core::arch::asm!("isb");
    }
    true
}

/// Map an EL0 RO+X code page into a specific address space (EL0 exec, EL1 non-exec).
pub fn map_user_code_in(l1_root: usize, va: usize, pa: usize) -> bool {
    map_user_in(l1_root, va, user_page_ng(pa as u64, AP_RO_EL0, ATTR_NORMAL, PXN))
}
/// Map an EL0 RW data/stack page into a specific address space.
pub fn map_user_data_in(l1_root: usize, va: usize, pa: usize) -> bool {
    map_user_in(l1_root, va, user_page_ng(pa as u64, AP_RW_EL0, ATTR_NORMAL, PXN | UXN))
}
/// Map an EL0 device-MMIO window into a specific address space (a driver's cap).
pub fn map_user_device_in(l1_root: usize, va: usize, pa: usize) -> bool {
    map_user_in(l1_root, va, user_page_ng(pa as u64, AP_RW_EL0, ATTR_DEVICE, PXN | UXN))
}
/// Map an EL0 Normal-Non-Cacheable (coherent DMA-ring) window into a specific AS.
pub fn map_user_nc_in(l1_root: usize, va: usize, pa: usize) -> bool {
    map_user_in(l1_root, va, user_page_ng(pa as u64, AP_RW_EL0, ATTR_NC, PXN | UXN))
}

static JITPOOL_NEXT: AtomicUsize = AtomicUsize::new(JITPOOL_BASE as usize);

/// Allocate a zeroed JIT code FRAME from the sealed pool. Its GB0 identity page
/// starts RW+PXN so the JIT can emit into it; call `jit_seal` after emit to drop
/// the writable alias. Returns 0 if the pool (512 pages) is exhausted.
pub fn jit_alloc_frame() -> usize {
    let f = JITPOOL_NEXT.fetch_add(0x1000, Ordering::Relaxed);
    if f + 0x1000 > (JITPOOL_BASE + M2) as usize {
        return 0;
    }
    unsafe {
        let p = f as *mut u64;
        for i in 0..512 {
            core::ptr::write_volatile(p.add(i), 0);
        }
        core::arch::asm!("dsb ish");
    }
    f
}

/// SEAL a JIT code frame (B-9): flip its GB0 identity page from RW+PXN to RO+PXN,
/// so the ONLY writable path to the code is gone. Combined with the GB6 RO+X exec
/// mapping, the executable code has NO writable alias anywhere — full W^X.
pub fn jit_seal(pa: usize) {
    let idx = (pa >> 12) & 0x1FF;
    let desc = pa as u64 | AF | SH_IS | AP_RO_EL1 | ATTR_NORMAL | PAGE | PXN | UXN;
    let l3 = addr_of_mut!(L3_JITPOOL) as *mut u64;
    unsafe {
        core::ptr::write_volatile(l3.add(idx), desc);
        core::arch::asm!("dsb ish");
        core::arch::asm!("tlbi vaae1is, {}", in(reg) (pa >> 12) as u64);
        core::arch::asm!("dsb ish");
        core::arch::asm!("isb");
    }
}

static JIT_VA_NEXT: AtomicUsize = AtomicUsize::new(JITCODE_VA_BASE);

/// P8 — map a freshly-written code frame as an EL1 **RO+X** page in the GB6 JIT
/// window and return its executable VA (or 0 if the window is full). The BPF JIT
/// writes the code through the frame's GB0 identity alias (RW), then calls this to
/// get a read-only + EL1-executable view: RO ⇒ not writable ⇒ WXN permits exec;
/// UXN keeps EL0 out; not-PXN ⇒ EL1 executes it. The writable GB0 alias remains a
/// documented W^X defense-in-depth residual (B-9), same as the QEMU JIT path.
pub fn map_kernel_code_page(pa: usize) -> usize {
    let va = JIT_VA_NEXT.fetch_add(0x1000, Ordering::Relaxed);
    if va >= JITCODE_VA_BASE + M2 as usize {
        return 0; // 2 MiB window exhausted (512 code pages)
    }
    // EL1 read-only + EL1-executable (UXN, NOT PXN), Normal-WB cacheable.
    let desc = pa as u64 | AF | SH_IS | AP_RO_EL1 | ATTR_NORMAL | PAGE | UXN;
    let l3 = addr_of_mut!(L3_JIT) as *mut u64;
    unsafe {
        core::ptr::write_volatile(l3.add((va >> 12) & 0x1FF), desc);
        core::arch::asm!("dsb ish");
        core::arch::asm!("tlbi vaae1is, {}", in(reg) (va >> 12) as u64);
        core::arch::asm!("dsb ish");
        core::arch::asm!("isb");
    }
    va
}
