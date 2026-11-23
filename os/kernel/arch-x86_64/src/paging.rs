// SPDX-License-Identifier: AGPL-3.0-only
//! heqk's own 4-level page tables (replacing the firmware's after ExitBootServices).
//!
//! Kernel: identity map of 0..4 GiB in 2 MiB pages, SUPERVISOR only (no U bit at the PDPT level, so no user
//! access is possible whatever the lower levels say). Caching follows the firmware memory map: write-back where a
//! 2 MiB page overlaps RAM, uncached everywhere else (LAPIC, IOAPIC, PCIe ECAM, BARs).
//! User window at 256 GiB (PML4[0] → PDPT[256]): one RX code page and one RW+NX stack page, the only pages a CPL3
//! context can touch. The kernel writes them through their identity (supervisor) alias, so SMAP stays on.

use crate::io::{cpuid, rdmsr, wrmsr};
use core::arch::asm;

const P: u64 = 1;
const RW: u64 = 1 << 1;
const US: u64 = 1 << 2;
const PWT: u64 = 1 << 3;
const PCD: u64 = 1 << 4;
const PS: u64 = 1 << 7;
const NX: u64 = 1 << 63;

pub const USER_BASE: u64 = 256 << 30; // 0x40_0000_0000
pub const USER_CODE: u64 = USER_BASE;
pub const USER_STACK_TOP: u64 = USER_BASE + 0x2000;

#[repr(C, align(4096))]
struct Table([u64; 512]);
const EMPTY: Table = Table([0; 512]);

static mut PML4: Table = EMPTY;
static mut PDPT: Table = EMPTY;
static mut PD_K: [Table; 4] = [EMPTY, EMPTY, EMPTY, EMPTY];
static mut PD_U: Table = EMPTY;
static mut PT_U: Table = EMPTY;

#[repr(C, align(4096))]
pub struct Page(pub [u8; 4096]);
pub static mut USER_CODE_PAGE: Page = Page([0; 4096]);
static mut USER_STACK_PAGE: Page = Page([0; 4096]);

pub struct Features {
    pub nx: bool,
    pub smep: bool,
    pub smap: bool,
}

pub fn features() -> Features {
    let (_, b7, _, _) = cpuid(7, 0);
    let (_, _, _, d81) = cpuid(0x8000_0001, 0);
    Features { nx: d81 & (1 << 20) != 0, smep: b7 & (1 << 7) != 0, smap: b7 & (1 << 20) != 0 }
}

/// Does the 2 MiB page at `pa` overlap any RAM-type descriptor of the firmware map? (loader/boot/runtime code+data,
/// conventional, ACPI reclaim/NVS, persistent). Anything else — MMIO, ECAM, holes — is mapped uncached.
fn overlaps_ram(map: &[u8], dsz: usize, pa: u64) -> bool {
    let (lo, hi) = (pa, pa + (2 << 20));
    let mut off = 0;
    while dsz >= 40 && off + dsz <= map.len() {
        let d = &map[off..off + dsz];
        off += dsz;
        let ty = u32::from_le_bytes(d[0..4].try_into().unwrap());
        if !matches!(ty, 1..=7 | 9 | 10 | 14) {
            continue;
        }
        let s = u64::from_le_bytes(d[8..16].try_into().unwrap());
        let e = s.saturating_add(u64::from_le_bytes(d[24..32].try_into().unwrap()).saturating_mul(4096));
        if s < hi && e > lo {
            return true;
        }
    }
    false
}

/// Build the tables, switch CR3, and turn on NX / SMEP / SMAP where the CPU has them. Returns what is active.
/// Caching comes from the firmware memory map: a 2 MiB page is write-back only if it overlaps RAM; every other
/// page (LAPIC, IOAPIC, PCIe ECAM, BARs, holes) is uncached, so device registers are never cached.
pub fn install(map: &[u8], dsz: usize) -> (Features, usize) {
    let f = features();
    let nx = if f.nx { NX } else { 0 };
    let mut uc_pages = 0;
    unsafe {
        if f.nx {
            wrmsr(0xC000_0080, rdmsr(0xC000_0080) | (1 << 11)); // EFER.NXE (before any NX entry is used)
        }
        let pd_k = &raw mut PD_K;
        for g in 0..4u64 {
            for i in 0..512u64 {
                let pa = (g << 30) | (i << 21);
                let mmio = if overlaps_ram(map, dsz, pa) {
                    0
                } else {
                    uc_pages += 1;
                    PCD | PWT
                };
                (*pd_k)[g as usize].0[i as usize] = pa | P | RW | PS | mmio;
            }
            (*(&raw mut PDPT)).0[g as usize] = (&raw const (*pd_k)[g as usize]) as u64 | P | RW;
        }
        (*(&raw mut PT_U)).0[0] = (&raw const USER_CODE_PAGE) as u64 | P | US; // RX
        (*(&raw mut PT_U)).0[1] = (&raw const USER_STACK_PAGE) as u64 | P | RW | US | nx; // RW, never executable
        (*(&raw mut PD_U)).0[0] = (&raw const PT_U) as u64 | P | RW | US;
        (*(&raw mut PDPT)).0[256] = (&raw const PD_U) as u64 | P | RW | US;
        (*(&raw mut PML4)).0[0] = (&raw const PDPT) as u64 | P | RW | US;

        asm!("mov cr3, {}", in(reg) &raw const PML4 as u64, options(nostack, preserves_flags));
        let mut cr0: u64;
        asm!("mov {}, cr0", out(reg) cr0, options(nomem, nostack, preserves_flags));
        cr0 |= 1 << 16; // WP: supervisor writes honour read-only pages too
        asm!("mov cr0, {}", in(reg) cr0, options(nostack, preserves_flags));
        let mut cr4: u64;
        asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack, preserves_flags));
        if f.smep {
            cr4 |= 1 << 20;
        }
        if f.smap {
            cr4 |= 1 << 21;
        }
        asm!("mov cr4, {}", in(reg) cr4, options(nostack, preserves_flags));
    }
    (f, uc_pages)
}

/// Copy a user program into the user code page (through its supervisor identity alias).
pub fn load_user_code(code: &[u8]) {
    unsafe {
        assert!(code.len() <= 4096);
        let page = (&raw mut USER_CODE_PAGE) as *mut u8;
        core::ptr::write_bytes(page, 0xCC, 4096); // int3 padding: falling off the end traps
        core::ptr::copy_nonoverlapping(code.as_ptr(), page, code.len());
    }
}

const ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;

/// Identity-map a device MMIO range (e.g. a 64-bit BAR that firmware placed above 4 GiB) as SUPERVISOR,
/// uncached, never-executable 2 MiB pages. Missing intermediate tables come from the frame allocator.
/// Refuses a range overlapping the user window. (Callers pass firmware-assigned BARs, which never overlap RAM.)
pub fn map_mmio(frames: &mut crate::frames::Frames, pa: u64, len: u64) -> Result<(), &'static str> {
    if len == 0 || pa.checked_add(len).is_none() || pa + len > (1 << 46) {
        return Err("MMIO range out of bounds");
    }
    let (lo, hi) = (pa & !((2 << 20) - 1), (pa + len + (2 << 20) - 1) & !((2 << 20) - 1));
    if lo < USER_BASE + (1 << 30) && hi > USER_BASE {
        return Err("MMIO range overlaps the user window");
    }
    let nx = if features().nx { NX } else { 0 };
    let mut a = lo;
    while a < hi {
        unsafe {
            let pml4 = (&raw mut PML4) as *mut u64;
            let e4 = pml4.add(((a >> 39) & 511) as usize);
            if *e4 & P == 0 {
                *e4 = frames.alloc().ok_or("no frame for a PDPT")? | P | RW; // supervisor: no US bit
            }
            let pdpt = (*e4 & ADDR_MASK) as *mut u64;
            let e3 = pdpt.add(((a >> 30) & 511) as usize);
            if *e3 & P == 0 {
                *e3 = frames.alloc().ok_or("no frame for a PD")? | P | RW;
            } else if *e3 & PS != 0 {
                return Err("1 GiB page in the way");
            }
            let pd = (*e3 & ADDR_MASK) as *mut u64;
            let e2 = pd.add(((a >> 21) & 511) as usize);
            *e2 = a | P | RW | PS | PCD | PWT | nx;
            asm!("invlpg [{}]", in(reg) a, options(nostack, preserves_flags));
        }
        a += 2 << 20;
    }
    Ok(())
}
