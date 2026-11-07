//! P1b — aarch64 stage-1 MMU + a physical frame allocator.
//!
//! 4 KiB granule, 39-bit VA (T0SZ=25), TTBR0 only. Boot uses an identity map of
//! two 1 GiB L1 blocks — GB0 (0..1G) = Device (covers UART 0x0900_0000 + GIC
//! 0x0800_0000), GB1 (1..2G) = Normal cacheable (the 512 MiB RAM at 0x4000_0000).
//! Because the map is identity, turning the MMU on is seamless. Fine-grained
//! 4 KiB mappings (via `map_page`) use the still-free L1 slots (e.g. GB3).

use core::ptr::{addr_of, addr_of_mut, read_volatile, write_volatile};
use core::sync::atomic::{AtomicU16, AtomicUsize, Ordering};

const RAM_BASE: usize = 0x4000_0000;
const RAM_END: usize = RAM_BASE + 512 * 1024 * 1024; // -m 512M
const PAGE: usize = 4096;

/// Kernel-owned L1 slot-1 window (RAM/text). `new_addr_space` copies all 512 L1
/// entries, so a per-TCB L1 SHARES the kernel's L2/L3 tables for this region; an EL0
/// user mapping landing here would overwrite a live kernel `.text`/`.data` PTE for
/// EVERY address space. All EL0 user-map primitives refuse a VA in this window
/// (defense-in-depth behind `elf::user_span_ok`; parity with the CM5 `user_va_ok`
/// discipline). No legitimate EL0 image maps into kernel RAM — user VAs live at
/// slot 2 (0x8000_0000..) / slot 0 device windows, never slot 1.
const KERN_VA_LO: usize = RAM_BASE; // 0x4000_0000 (L1 slot 1 base)
const KERN_VA_HI: usize = 0x8000_0000; // end of L1 slot 1

/// May an EL0 user mapping target `va`? False for any VA inside the kernel's shared
/// RAM/text tables (slot 1). Fail-closed: a user map to a kernel VA is refused.
#[inline]
fn user_va_permitted(va: usize) -> bool {
    !(va >= KERN_VA_LO && va < KERN_VA_HI)
}

// Descriptor bits.
const VALID: u64 = 1 << 0;
const TABLE: u64 = 1 << 1; // L1/L2 table (VALID|TABLE); L3 page also sets bit1
const AF: u64 = 1 << 10; // access flag (fault if 0)
const SH_IS: u64 = 0b11 << 8; // inner shareable
const AP_RW_EL1: u64 = 0b00 << 6; // EL1 read/write, EL0 no access
const AP_RW_EL0: u64 = 0b01 << 6; // EL0+EL1 read/write
const AP_RO_EL1: u64 = 0b10 << 6; // EL1 read-only (+ executable: W^X for JIT code)
const AP_RO_EL0: u64 = 0b11 << 6; // EL0+EL1 read-only (+ EL0 executable: W^X user code)
const UXN: u64 = 1 << 54; // Unprivileged eXecute-Never (non-exec at EL0)
const PXN: u64 = 1 << 53; // Privileged eXecute-Never (non-exec at EL1)
const BLOCK: u64 = 0b01; // L1/L2 block
const PAGE_DESC: u64 = 0b11; // L3 page
const ADDR_MASK: u64 = 0x0000_FFFF_FFFF_F000; // output address [47:12]
// MAIR attribute indices.
const ATTR_DEVICE: u64 = 0; // Device-nGnRnE
const ATTR_NORMAL: u64 = 1; // Normal WB cacheable

#[repr(align(4096))]
struct Table([u64; 512]);
static mut L1: Table = Table([0; 512]);

static FRAME_NEXT: AtomicUsize = AtomicUsize::new(0);
// P7c — next ASID to hand out (0 = the kernel/identity address space).
static NEXT_ASID: AtomicU16 = AtomicU16::new(1);
// LIFO free list: head PA (0 = empty); each freed frame's first word links to next.
static FRAME_FREE: AtomicUsize = AtomicUsize::new(0);

#[inline]
fn l1_ptr() -> *mut u64 {
    addr_of_mut!(L1) as *mut u64
}

fn align_up(x: usize, a: usize) -> usize {
    (x + a - 1) & !(a - 1)
}

fn zero_frame(pa: usize) {
    let p = pa as *mut u64;
    for i in 0..(PAGE / 8) {
        unsafe { write_volatile(p.add(i), 0) };
    }
}

fn block_desc(base: usize, attr: u64, sh: u64, ap: u64) -> u64 {
    base as u64 | (attr << 2) | AF | sh | ap | BLOCK
}

/// The MMU as a HAL implementation.
pub struct Mmu;

impl Mmu {
    fn get_or_create_table(&self, table: *mut u64, idx: usize) -> Option<*mut u64> {
        let e = unsafe { read_volatile(table.add(idx)) };
        if e & VALID == 0 {
            let f = self.alloc_frame_raw();
            if f == 0 {
                return None;
            }
            unsafe { write_volatile(table.add(idx), f as u64 | VALID | TABLE) };
            Some(f as *mut u64)
        } else if e & TABLE == 0 {
            // Existing entry is a BLOCK descriptor, not a table pointer. Returning
            // (e & ADDR_MASK) would treat the block's physical base as a page table
            // and write L3 descriptors into live RAM (corruption + forged mappings).
            // We don't implement implicit block-splitting — refuse.
            None
        } else {
            Some((e & ADDR_MASK) as *mut u64)
        }
    }

    fn alloc_frame_raw(&self) -> usize {
        // Reuse a freed frame first (LIFO), else bump the watermark.
        loop {
            let head = FRAME_FREE.load(Ordering::Acquire);
            if head == 0 {
                break;
            }
            let next = unsafe { read_volatile(head as *const usize) };
            if FRAME_FREE
                .compare_exchange_weak(head, next, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                zero_frame(head);
                return head;
            }
        }
        loop {
            let cur = FRAME_NEXT.load(Ordering::Relaxed);
            if cur + PAGE > RAM_END {
                return 0;
            }
            if FRAME_NEXT
                .compare_exchange_weak(cur, cur + PAGE, Ordering::SeqCst, Ordering::Relaxed)
                .is_ok()
            {
                zero_frame(cur);
                return cur;
            }
        }
    }
}

impl hal::Mmu for Mmu {
    fn init(&self) {
        // Frame allocator: everything from just past the loaded image/stack up to
        // the end of RAM. `__stack_top` is exported by the linker script.
        extern "C" {
            static __stack_top: u8;
        }
        let free_start = align_up(unsafe { addr_of!(__stack_top) as usize }, PAGE);
        FRAME_NEXT.store(free_start, Ordering::Relaxed);

        // Identity map: GB0 = device (MMIO), GB1 = normal RAM — both EL1-only.
        // GB1 is built with W^X (P7b): kernel `.text` RO+X, all other RAM RW+PXN.
        let l1 = l1_ptr();
        unsafe {
            // Device/MMIO must never be executable (PXN|UXN).
            write_volatile(l1.add(0), block_desc(0, ATTR_DEVICE, 0, AP_RW_EL1) | PXN | UXN);
        }
        self.build_wx_ram(RAM_BASE, 1); // GB1 (L1 slot 1) = W^X RAM
    }

    fn enable(&self) {
        unsafe {
            let ips: u64;
            core::arch::asm!("mrs {}, id_aa64mmfr0_el1", out(reg) ips);
            let ips = (ips & 0xF).min(5); // PARange, clamp to 48-bit

            let mair: u64 = 0x00 | (0xFF << 8); // attr0 Device-nGnRnE, attr1 Normal WB
            let tcr: u64 = 25            // T0SZ = 39-bit VA
                | (1 << 8)               // IRGN0 = WBWA
                | (1 << 10)              // ORGN0 = WBWA
                | (0b11 << 12)           // SH0 = inner shareable
                | (0b00 << 14)           // TG0 = 4 KiB
                | (1 << 23)              // EPD1 = disable TTBR1 walks
                | (ips << 32)            // IPS = physical address size
                | (1 << 36); // AS = 16-bit ASID
            let ttbr0 = l1_ptr() as u64; // ASID 0

            core::arch::asm!("msr mair_el1, {}", in(reg) mair);
            core::arch::asm!("msr tcr_el1, {}", in(reg) tcr);
            core::arch::asm!("msr ttbr0_el1, {}", in(reg) ttbr0);
            core::arch::asm!("dsb ish");
            core::arch::asm!("isb");
            let mut sctlr: u64;
            core::arch::asm!("mrs {}, sctlr_el1", out(reg) sctlr);
            // M | C | I, plus WXN (bit 19): any writable page is forced execute-
            // never — the hardware W^X backstop on top of the per-page PXN (P7b).
            sctlr |= (1 << 0) | (1 << 2) | (1 << 12) | (1 << 19);
            core::arch::asm!("msr sctlr_el1, {}", in(reg) sctlr);
            core::arch::asm!("isb");
        }
    }

    fn enabled(&self) -> bool {
        let sctlr: u64;
        unsafe { core::arch::asm!("mrs {}, sctlr_el1", out(reg) sctlr) };
        sctlr & 1 != 0
    }

    fn alloc_frame(&self) -> usize {
        self.alloc_frame_raw()
    }

    fn map_page(&self, va: usize, pa: usize, device: bool) -> bool {
        let attr = if device { ATTR_DEVICE } else { ATTR_NORMAL };
        self.map(va, pa, attr, AP_RW_EL1, true, true) // EL1 data: UXN + PXN
    }
}

impl Mmu {
    /// P7b — build one 1 GiB RAM region (`gb_base`, installed at L1 slot `l1_idx`)
    /// as a W^X map, using the kernel's linked `[__text_start,__text_end)` range.
    /// Thin wrapper over `build_wx_ram_range` (below), which does the real work.
    fn build_wx_ram(&self, gb_base: usize, l1_idx: usize) {
        extern "C" {
            static __text_start: u8;
            static __text_end: u8;
        }
        let text_start = unsafe { addr_of!(__text_start) as usize };
        let text_end = unsafe { addr_of!(__text_end) as usize };
        self.build_wx_ram_range(gb_base, l1_idx, text_start, text_end);
    }

    /// P-wx — generalized W^X RAM builder. Builds the 1 GiB region at `gb_base`
    /// (installed at L1 slot `l1_idx`) as 512 × 2 MiB blocks: **every** block that
    /// OVERLAPS the executable range `[text_start, text_end)` is expanded into an
    /// L3 table so each 4 KiB page is mapped INDIVIDUALLY — code pages RO+X, any
    /// data / pre-image pages sharing that block RW+PXN; every block that does NOT
    /// overlap the text range stays a plain 2 MiB Normal RW+PXN block.
    ///
    /// This removes the old single-2-MiB-block ceiling (the previous code only
    /// L3-mapped the ONE block holding `text_start`; the moment `.text` grew past
    /// 2 MiB — real drivers, a larger detection catalogue, a wasmi Wasm host — code
    /// in the 2nd+ block landed in a PXN block and instruction-aborted at first
    /// fetch, exactly what killed the wasmi/P1b integration).
    ///
    /// W^X stays STRICT at PAGE granularity: within a boundary block, a code page
    /// is RO+X and a data page is RW+PXN — never both, for any page. `__text_end`
    /// is `ALIGN(4096)` in the linker script (and `__text_start` is page-aligned),
    /// so the code/data split always lands on a page boundary — no page ever
    /// straddles the boundary, so no 2 MiB alignment of `.text` is required (which
    /// would waste up to ~2 MiB of RAM per image on a 512 MiB edge box). SCTLR.WXN
    /// (set in `enable`) is the hardware backstop on top of this per-page PXN.
    /// Built with the MMU off (identity), so there is no break-before-make.
    fn build_wx_ram_range(&self, gb_base: usize, l1_idx: usize, text_start: usize, text_end: usize) {
        const M2: usize = 2 << 20; // 2 MiB
        let l2 = self.alloc_frame_raw();
        if l2 == 0 {
            return;
        }
        for b in 0..512usize {
            let base = gb_base + b * M2;
            let blk_end = base + M2;
            // Does this 2 MiB block OVERLAP the executable range? Half-open
            // intersection test: [base,blk_end) ∩ [text_start,text_end) non-empty.
            let overlaps_text = text_start < blk_end && text_end > base;
            if overlaps_text {
                let l3 = self.alloc_frame_raw();
                if l3 == 0 {
                    return;
                }
                for p in 0..512usize {
                    let va = base + p * PAGE;
                    // Code page: RO + EL1-executable (UXN, not PXN). Else RW + non-exec.
                    let (ap, xn) = if va >= text_start && va < text_end {
                        (AP_RO_EL1, UXN)
                    } else {
                        (AP_RW_EL1, UXN | PXN)
                    };
                    let desc =
                        (va as u64 & ADDR_MASK) | (ATTR_NORMAL << 2) | AF | SH_IS | ap | xn | PAGE_DESC;
                    unsafe { write_volatile((l3 as *mut u64).add(p), desc) };
                }
                unsafe { write_volatile((l2 as *mut u64).add(b), l3 as u64 | VALID | TABLE) };
            } else {
                // Plain RAM: 2 MiB Normal RW + non-executable block.
                let desc = block_desc(base, ATTR_NORMAL, SH_IS, AP_RW_EL1) | PXN | UXN;
                unsafe { write_volatile((l2 as *mut u64).add(b), desc) };
            }
        }
        unsafe { write_volatile(l1_ptr().add(l1_idx), l2 as u64 | VALID | TABLE) };
    }

    /// P-wx — PROVE the multi-block W^X generalization. Today the kernel's real
    /// `.text` is ~1.2 MiB = one 2 MiB block, so P7b (which reads back the real
    /// kernel descriptors) only exercises the single-block path. This selftest
    /// builds a SYNTHETIC executable range that deliberately SPANS THREE 2 MiB
    /// blocks into an unused L1 slot (VA 2 GiB — dev=slot0, RAM=slot1, map_page
    /// scratch=slot3, so slot2 is free), then reads the REAL page descriptors back
    /// through the same table walk P7b uses, and confirms:
    ///   (1) a code page in the 2nd (middle, fully-text) block is RO+X,
    ///   (2) a code page in the 3rd (LAST) text block is RO+X — proving text in the
    ///       2nd+ block is executable (the fetch that used to abort),
    ///   (3) data pages BEFORE `ts` (boundary block 0), AT/AFTER `te` (boundary
    ///       block 2), and in a block BEYOND text (plain block 3) are all RW+NX,
    ///   (4) STRICT W^X: sweeping EVERY page of the three L3 blocks, none is ever
    ///       both writable AND EL1-executable.
    /// Uses the REAL `build_wx_ram_range` builder + the REAL `page_desc` walker —
    /// not just the decision logic — so it is faithful for the metal / wasmi case.
    pub fn wx_multiblock_selftest(&self) -> bool {
        const M2: usize = 2 << 20;
        let gb = 0x8000_0000usize; // VA 2 GiB — L1 slot 2 (unused)
        let l1_idx = 2usize;
        // Executable range crossing block boundaries: 1 MiB into block 0 .. 1 MiB
        // into block 2 — so block 0 is a partial boundary block, block 1 is fully
        // text, block 2 is a partial boundary block, and block 3+ is plain data.
        let ts = gb + 0x10_0000;
        let te = gb + 2 * M2 + 0x10_0000;
        self.build_wx_ram_range(gb, l1_idx, ts, te);
        unsafe {
            core::arch::asm!("dsb ish");
            core::arch::asm!("isb");
        }
        let ap = |d: u64| (d >> 6) & 3;
        let pxn = |d: u64| (d >> 53) & 1;
        // EL1-writable AP encodings: 0b00 (EL1 RW) or 0b01 (EL0+EL1 RW).
        let writable = |d: u64| ap(d) == 0b00 || ap(d) == 0b01;
        let executable = |d: u64| pxn(d) == 0; // EL1-executable (PXN clear)
        let mid = self.page_desc(gb + M2 + 0x1000); // block 1 code
        let last = self.page_desc(gb + 2 * M2 + 0x1000); // block 2 (last) code, below te
        let pre = self.page_desc(gb + 0x1000); // block 0 data, below ts
        let post = self.page_desc(te); // block 2 data, at te
        let beyond = self.page_desc(gb + 3 * M2); // block 3, plain RW block beyond text
        let attrs_ok = ap(mid) == 0b10 && pxn(mid) == 0
            && ap(last) == 0b10 && pxn(last) == 0
            && ap(pre) == 0b00 && pxn(pre) == 1
            && ap(post) == 0b00 && pxn(post) == 1
            && ap(beyond) == 0b00 && pxn(beyond) == 1;
        // Strict W^X sweep over every page of the three L3-mapped blocks.
        let mut wx_strict = true;
        for b in 0..3usize {
            for p in 0..512usize {
                let d = self.page_desc(gb + b * M2 + p * PAGE);
                if d & VALID != 0 && writable(d) && executable(d) {
                    wx_strict = false;
                }
            }
        }
        // Tear down the synthetic slot so the (unbacked) VA never lingers. We only
        // ever read the tables, never touched VA 2 GiB, so this is pure hygiene;
        // the 3 scratch table frames leak — a bounded one-time boot cost.
        unsafe {
            write_volatile(l1_ptr().add(l1_idx), 0);
            core::arch::asm!("dsb ish");
            core::arch::asm!("tlbi vmalle1is");
            core::arch::asm!("dsb ish");
            core::arch::asm!("isb");
        }
        attrs_ok && wx_strict
    }

    /// Read back the L3 page descriptor for a VA (for W^X proof). Returns the raw
    /// descriptor, or 0 if not L3-mapped. AP bits [7:6], PXN bit 53, UXN bit 54.
    pub fn page_desc(&self, va: usize) -> u64 {
        let i1 = (va >> 30) & 0x1FF;
        let i2 = (va >> 21) & 0x1FF;
        let i3 = (va >> 12) & 0x1FF;
        let l1 = l1_ptr();
        let e1 = unsafe { read_volatile(l1.add(i1)) };
        if e1 & VALID == 0 || e1 & TABLE == 0 {
            return 0;
        }
        let l2 = (e1 & ADDR_MASK) as *const u64;
        let e2 = unsafe { read_volatile(l2.add(i2)) };
        if e2 & VALID == 0 {
            return 0;
        }
        if e2 & TABLE == 0 {
            return e2; // 2 MiB block — AP/PXN bits are in the same positions as a page
        }
        let l3 = (e2 & ADDR_MASK) as *const u64;
        unsafe { read_volatile(l3.add(i3)) }
    }

    /// Common page mapper (4 KiB, L3) into the GLOBAL kernel address space.
    fn map(&self, va: usize, pa: usize, attr: u64, ap: u64, uxn: bool, pxn: bool) -> bool {
        self.map_in_root(l1_ptr(), va, pa, attr, ap, uxn, pxn)
    }

    /// Page mapper into an explicit L1 root (a specific address space).
    /// `uxn` = non-executable at EL0, `pxn` = non-executable at EL1.
    fn map_in_root(&self, l1: *mut u64, va: usize, pa: usize, attr: u64, ap: u64, uxn: bool, pxn: bool) -> bool {
        let i1 = (va >> 30) & 0x1FF;
        let i2 = (va >> 21) & 0x1FF;
        let i3 = (va >> 12) & 0x1FF;
        let l2 = match self.get_or_create_table(l1, i1) {
            Some(t) => t,
            None => return false,
        };
        let l3 = match self.get_or_create_table(l2, i2) {
            Some(t) => t,
            None => return false,
        };
        let xn = if uxn { UXN } else { 0 } | if pxn { PXN } else { 0 };
        let desc = (pa as u64 & ADDR_MASK) | (attr << 2) | AF | SH_IS | ap | xn | PAGE_DESC;
        unsafe {
            write_volatile(l3.add(i3), desc);
            core::arch::asm!("dsb ish");
            core::arch::asm!("tlbi vaae1is, {}", in(reg) (va >> 12) as u64);
            core::arch::asm!("dsb ish");
            core::arch::asm!("isb");
        }
        true
    }

    /// P7c — create a fresh address space: a new L1 that SHARES the kernel's
    /// identity/kernel mappings (copied) but has its own user (high-VA) tables,
    /// tagged with a unique 16-bit ASID. Returns (l1_root_pa, asid). ASID-tagged
    /// TLB entries mean switching between address spaces needs NO full flush.
    pub fn new_addr_space(&self) -> (usize, u16) {
        let l1 = self.alloc_frame_raw();
        if l1 == 0 {
            return (0, 0);
        }
        let src = l1_ptr();
        for i in 0..512 {
            unsafe { write_volatile((l1 as *mut u64).add(i), read_volatile(src.add(i))) };
        }
        let asid = (NEXT_ASID.fetch_add(1, Ordering::Relaxed) & 0xFFFF) as u16;
        (l1, asid)
    }

    /// Map an EL0 RW data page into a specific address space (its own tables for
    /// unmapped-in-kernel high VAs; shared kernel tables otherwise).
    pub fn map_user_data_in(&self, l1_root: usize, va: usize, pa: usize) -> bool {
        if !user_va_permitted(va) {
            return false;
        }
        self.map_in_root(l1_root as *mut u64, va, pa, ATTR_NORMAL, AP_RW_EL0, true, true)
    }

    /// Map an EL0 RO+X code page into a specific address space.
    pub fn map_user_code_in(&self, l1_root: usize, va: usize, pa: usize) -> bool {
        if !user_va_permitted(va) {
            return false;
        }
        self.map_in_root(l1_root as *mut u64, va, pa, ATTR_NORMAL, AP_RO_EL0, false, true)
    }

    /// Map an EL0 RO+NX data page into a specific address space (a read-only ELF data
    /// segment: readable, non-writable, NON-executable — the rodata leg of W^X). Mirrors
    /// `map_user_data_in` but with AP_RO_EL0 and UXN set (uxn=true forces non-exec).
    pub fn map_user_data_ro_in(&self, l1_root: usize, va: usize, pa: usize) -> bool {
        if !user_va_permitted(va) {
            return false;
        }
        self.map_in_root(l1_root as *mut u64, va, pa, ATTR_NORMAL, AP_RO_EL0, true, true)
    }

    /// Map an EL0 device-MMIO window into a specific address space (a driver's
    /// capability to touch exactly one device — Device memory, EL0 RW, non-exec).
    pub fn map_user_device_in(&self, l1_root: usize, va: usize, pa: usize) -> bool {
        if !user_va_permitted(va) {
            return false;
        }
        self.map_in_root(l1_root as *mut u64, va, pa, ATTR_DEVICE, AP_RW_EL0, true, true)
    }

    /// The kernel/global address-space L1 root (ASID 0).
    pub fn kernel_l1(&self) -> usize {
        l1_ptr() as usize
    }

    /// Switch the active address space: `TTBR0_EL1 = l1_root | (asid << 48)`,
    /// then `isb`. No TLB flush — the ASID tag keeps the two spaces' entries apart.
    pub fn switch_ttbr0(&self, l1_root: usize, asid: u16) {
        self.set_ttbr0_raw(l1_root as u64 | ((asid as u64) << 48));
    }

    /// Write a raw TTBR0_EL1 value (root | ASID<<48) + `isb`. The scheduler uses
    /// this to enter each thread's address space on context switch.
    pub fn set_ttbr0_raw(&self, ttbr0: u64) {
        unsafe {
            core::arch::asm!("msr ttbr0_el1, {}", in(reg) ttbr0);
            core::arch::asm!("isb");
        }
    }

    /// The kernel/global address space's TTBR0 value (kernel L1 | ASID 0).
    pub fn kernel_ttbr0(&self) -> u64 {
        l1_ptr() as u64
    }

    /// User CODE page: EL0 read-only + EL0-executable (**W^X**), EL1-non-exec
    /// (PXN — the kernel can never execute user-writable-derived memory).
    pub fn map_user_code_page(&self, va: usize, pa: usize) -> bool {
        if !user_va_permitted(va) {
            return false;
        }
        self.map(va, pa, ATTR_NORMAL, AP_RO_EL0, false, true)
    }

    /// User DATA/stack page: EL0 read/write, non-executable at both EL0 and EL1.
    pub fn map_user_data_page(&self, va: usize, pa: usize) -> bool {
        if !user_va_permitted(va) {
            return false;
        }
        self.map(va, pa, ATTR_NORMAL, AP_RW_EL0, true, true)
    }

    /// User DATA page, READ-ONLY: EL0 read-only, non-executable at both levels.
    /// CORE-1: the attribute a Frame cap lacking the `W` right maps to — EL0 can
    /// read the frame but any write faults.
    pub fn map_user_data_ro_page(&self, va: usize, pa: usize) -> bool {
        if !user_va_permitted(va) {
            return false;
        }
        self.map(va, pa, ATTR_NORMAL, AP_RO_EL0, true, true)
    }

    /// CORE-1 — invalidate the L3 leaf for `va` in the GLOBAL kernel root (write an
    /// invalid descriptor + tlbi), the primitive `caps::revoke` uses to sever a Frame
    /// cap's EL0 authority. Returns false if `va` has no L3 leaf to clear (nothing to
    /// do). The L1/L2 table pointers are left intact — only the leaf mapping is removed.
    pub fn unmap_user_page(&self, va: usize) -> bool {
        let i1 = (va >> 30) & 0x1FF;
        let i2 = (va >> 21) & 0x1FF;
        let i3 = (va >> 12) & 0x1FF;
        let l1 = l1_ptr();
        let e1 = unsafe { read_volatile(l1.add(i1)) };
        if e1 & VALID == 0 || e1 & TABLE == 0 {
            return false;
        }
        let l2 = (e1 & ADDR_MASK) as *mut u64;
        let e2 = unsafe { read_volatile(l2.add(i2)) };
        // Must be a table pointer (not a block) to have a per-page leaf to clear.
        if e2 & VALID == 0 || e2 & TABLE == 0 {
            return false;
        }
        let l3 = (e2 & ADDR_MASK) as *mut u64;
        unsafe {
            write_volatile(l3.add(i3), 0); // invalid descriptor — EL0 access now faults
            core::arch::asm!("dsb ish");
            core::arch::asm!("tlbi vaae1is, {}", in(reg) (va >> 12) as u64);
            core::arch::asm!("dsb ish");
            core::arch::asm!("isb");
        }
        true
    }

    /// User DEVICE-MMIO window: an isolated EL0 driver's capability to touch its
    /// hardware — Device memory, EL0 read/write, non-executable (UXN+PXN). This
    /// is what lets a driver run in user space with *only* the device granted.
    pub fn map_user_device_page(&self, va: usize, pa: usize) -> bool {
        self.map(va, pa, ATTR_DEVICE, AP_RW_EL0, true, true)
    }

    /// JIT CODE page: EL1 read-only + EL1-executable — **W^X** for compiled code
    /// (EL0-non-exec). NB: the frame is still writable via its identity alias;
    /// full W^X needs kernel-page block-splitting (deferred, see buildPlan).
    pub fn map_code_page(&self, va: usize, pa: usize) -> bool {
        self.map(va, pa, ATTR_NORMAL, AP_RO_EL1, true, false)
    }

    /// Return a frame to the allocator's free list (LIFO reuse).
    pub fn free_frame(&self, pa: usize) {
        // Sanity: only page-aligned frames within the allocator's watermark are
        // valid to free. Rejecting others turns a double-free / wild-free bug
        // into a no-op instead of list corruption + later frame aliasing.
        if pa & (PAGE - 1) != 0 || pa < RAM_BASE || pa >= FRAME_NEXT.load(Ordering::Relaxed) {
            return;
        }
        loop {
            let head = FRAME_FREE.load(Ordering::Relaxed);
            // Reject an obvious double-free (frame already at the list head).
            if head == pa {
                return;
            }
            unsafe { write_volatile(pa as *mut usize, head) };
            if FRAME_FREE
                .compare_exchange_weak(head, pa, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                return;
            }
        }
    }
}

/// Reserve a contiguous physical region (page-aligned) from the frame allocator,
/// e.g. to back a capability Untyped with real memory. Returns base, or 0 = OOM.
pub fn reserve_region(bytes: usize) -> usize {
    let n = align_up(bytes, PAGE);
    loop {
        let cur = FRAME_NEXT.load(Ordering::Relaxed);
        if cur + n > RAM_END {
            return 0;
        }
        if FRAME_NEXT
            .compare_exchange_weak(cur, cur + n, Ordering::SeqCst, Ordering::Relaxed)
            .is_ok()
        {
            // Zero before handing out: reserved RAM backs DMA rings and cap
            // Untypeds; stale contents must not leak to a device or a new cap.
            for i in 0..(n / 8) {
                unsafe { write_volatile((cur as *mut u64).add(i), 0) };
            }
            return cur;
        }
    }
}

/// Make freshly-written code visible to the instruction fetcher (clean D-cache
/// to PoU over the range, invalidate I-cache). Needed after copying user code.
pub fn sync_instruction_cache(base: usize, len: usize) {
    let mut a = base & !63;
    let end = base + len;
    while a < end {
        unsafe { core::arch::asm!("dc cvau, {}", in(reg) a) };
        a += 64;
    }
    unsafe {
        core::arch::asm!("dsb ish");
        core::arch::asm!("ic iallu");
        core::arch::asm!("dsb ish");
        core::arch::asm!("isb");
    }
}
