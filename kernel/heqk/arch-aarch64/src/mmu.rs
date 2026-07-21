//! P1b — aarch64 stage-1 MMU + a physical frame allocator.
//!
//! 4 KiB granule, 39-bit VA (T0SZ=25), TTBR0 only. Boot uses an identity map of
//! two 1 GiB L1 blocks — GB0 (0..1G) = Device (covers UART 0x0900_0000 + GIC
//! 0x0800_0000), GB1 (1..2G) = Normal cacheable (the 512 MiB RAM at 0x4000_0000).
//! Because the map is identity, turning the MMU on is seamless. Fine-grained
//! 4 KiB mappings (via `map_page`) use the still-free L1 slots (e.g. GB3).

use core::ptr::{addr_of, addr_of_mut, read_volatile, write_volatile};
use core::sync::atomic::{AtomicUsize, Ordering};

const RAM_BASE: usize = 0x4000_0000;
const RAM_END: usize = RAM_BASE + 512 * 1024 * 1024; // -m 512M
const PAGE: usize = 4096;

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
    /// as an L2 table of 2 MiB Normal RW+PXN blocks, EXCEPT the 2 MiB block that
    /// holds the kernel image, which becomes an L3 table with **W^X**: pages in
    /// `[__text_start,__text_end)` are RO+X (EL1 code), everything else RW+PXN.
    /// Built with the MMU off (identity), so there is no break-before-make.
    fn build_wx_ram(&self, gb_base: usize, l1_idx: usize) {
        extern "C" {
            static __text_start: u8;
            static __text_end: u8;
        }
        let text_start = unsafe { addr_of!(__text_start) as usize };
        let text_end = unsafe { addr_of!(__text_end) as usize };
        const M2: usize = 2 << 20; // 2 MiB
        let l2 = self.alloc_frame_raw();
        if l2 == 0 {
            return;
        }
        // Which 2 MiB block within this GB holds the kernel .text.
        let kern_blk = (text_start - gb_base) / M2;
        for b in 0..512usize {
            let base = gb_base + b * M2;
            if b == kern_blk {
                let l3 = self.alloc_frame_raw();
                if l3 == 0 {
                    return;
                }
                for p in 0..512usize {
                    let va = base + p * PAGE;
                    // Kernel .text: RO + EL1-executable (UXN, not PXN). Else RW + non-exec.
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

    /// Common page mapper (4 KiB, L3), with explicit access permission + XN.
    /// `uxn` = non-executable at EL0, `pxn` = non-executable at EL1.
    fn map(&self, va: usize, pa: usize, attr: u64, ap: u64, uxn: bool, pxn: bool) -> bool {
        let i1 = (va >> 30) & 0x1FF;
        let i2 = (va >> 21) & 0x1FF;
        let i3 = (va >> 12) & 0x1FF;
        let l1 = l1_ptr();
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

    /// User CODE page: EL0 read-only + EL0-executable (**W^X**), EL1-non-exec
    /// (PXN — the kernel can never execute user-writable-derived memory).
    pub fn map_user_code_page(&self, va: usize, pa: usize) -> bool {
        self.map(va, pa, ATTR_NORMAL, AP_RO_EL0, false, true)
    }

    /// User DATA/stack page: EL0 read/write, non-executable at both EL0 and EL1.
    pub fn map_user_data_page(&self, va: usize, pa: usize) -> bool {
        self.map(va, pa, ATTR_NORMAL, AP_RW_EL0, true, true)
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
