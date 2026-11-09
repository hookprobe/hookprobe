//! PCIe configuration access over ECAM (feature `pci`) — the arm64-cloud tier (OCI Ampere A1
//! and its QEMU model). Minimal by design: enumerate, read BARs (as firmware assigned them),
//! walk capabilities, enable memory decode + bus mastering. No BAR (re)allocation, no
//! bridge programming: edk2 has already done both before ExitBootServices, and the
//! efiboot probe shows the assignment.
//!
//! ECAM location: QEMU `virt` highmem layout (0x40_1000_0000, buses 0..255), which the OCI
//! model reproduces. TODO(oci-a1 port step 4): take it from the ACPI MCFG handed over by
//! efiboot instead of this constant.
//!
//! Everything read from config space is DEVICE-supplied: capability pointers are bounded
//! and loop-guarded, BAR indices checked.

use crate::mmu::Mmu;
use core::ptr::{read_volatile, write_volatile};

const ECAM_PA: usize = 0x40_1000_0000;
const BUS_LAST: u8 = 255;

#[derive(Clone, Copy)]
pub struct Bdf {
    pub bus: u8,
    pub dev: u8,
    pub func: u8,
}

pub struct Ecam {
    va: usize,
}

/// Physical address of function `b`'s 4 KiB configuration page (for granting it, alone, to an
/// isolated EL0 driver).
pub fn config_page_pa(b: Bdf) -> usize {
    ECAM_PA + ((b.bus as usize) << 20) + ((b.dev as usize) << 15) + ((b.func as usize) << 12)
}

impl Ecam {
    /// Map the ECAM window. `None` if the MMU refuses (fail-closed).
    pub fn open() -> Option<Ecam> {
        let mmu = Mmu;
        let va = mmu.map_mmio(ECAM_PA)?;
        // The 256-bus window is 256 MiB; make sure its end is mapped too (it may straddle a
        // 1 GiB boundary on other layouts).
        let end = ECAM_PA + ((BUS_LAST as usize + 1) << 20) - 1;
        let va_end = mmu.map_mmio(end)?;
        if va_end - va != end - ECAM_PA {
            return None; // straddles two non-contiguous windows: not supported
        }
        Some(Ecam { va })
    }

    fn addr(&self, b: Bdf, off: usize) -> usize {
        self.va + ((b.bus as usize) << 20) + ((b.dev as usize) << 15) + ((b.func as usize) << 12) + (off & 0xffc)
    }

    pub fn r32(&self, b: Bdf, off: usize) -> u32 {
        unsafe { read_volatile(self.addr(b, off) as *const u32) }
    }

    pub fn r8(&self, b: Bdf, off: usize) -> u8 {
        (self.r32(b, off & !3) >> ((off & 3) * 8)) as u8
    }

    /// Write the 16-bit Command register only (a 32-bit write would also hit the RW1C
    /// Status bits).
    pub fn set_command(&self, b: Bdf, v: u16) {
        unsafe { write_volatile(self.addr(b, 4) as *mut u16, v) };
    }

    pub fn command(&self, b: Bdf) -> u16 {
        self.r32(b, 4) as u16
    }

    /// First function matching (vendor, device), scanning every bus/device/function.
    pub fn find(&self, vendor: u16, device: u16) -> Option<Bdf> {
        for bus in 0..=BUS_LAST {
            for dev in 0..32u8 {
                for func in 0..8u8 {
                    let b = Bdf { bus, dev, func };
                    let id = self.r32(b, 0);
                    if id as u16 == 0xffff {
                        if func == 0 {
                            break;
                        }
                        continue;
                    }
                    if id as u16 == vendor && (id >> 16) as u16 == device {
                        return Some(b);
                    }
                    if func == 0 && self.r8(b, 0x0e) & 0x80 == 0 {
                        break;
                    }
                }
            }
        }
        None
    }

    /// Physical address of memory BAR `n` (handles 64-bit BARs). `None` for I/O BARs,
    /// unassigned BARs, or an out-of-range index.
    pub fn bar(&self, b: Bdf, n: u8) -> Option<u64> {
        if n > 5 {
            return None;
        }
        let lo = self.r32(b, 0x10 + n as usize * 4);
        if lo & 1 != 0 {
            return None;
        }
        let mut pa = (lo & !0xf) as u64;
        if (lo >> 1) & 3 == 2 {
            if n == 5 {
                return None;
            }
            pa |= (self.r32(b, 0x10 + (n as usize + 1) * 4) as u64) << 32;
        }
        if pa == 0 {
            None
        } else {
            Some(pa)
        }
    }

    /// Call `f(cap_offset, cap_id)` for each capability (bounded walk).
    pub fn caps(&self, b: Bdf, mut f: impl FnMut(usize, u8)) {
        if (self.r32(b, 4) >> 16) & 0x10 == 0 {
            return;
        }
        let mut p = (self.r8(b, 0x34) & 0xfc) as usize;
        let mut guard = 0;
        while p >= 0x40 && guard < 48 {
            let h = self.r32(b, p);
            f(p, h as u8);
            p = ((h >> 8) & 0xfc) as usize;
            guard += 1;
        }
    }
}
