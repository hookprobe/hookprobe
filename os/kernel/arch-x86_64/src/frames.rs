// SPDX-License-Identifier: AGPL-3.0-only
//! Physical frame allocator, built ONCE from the memory map captured at ExitBootServices.
//!
//! Only EfiConventionalMemory and the reclaimable boot-services ranges are used — never loader code/data (this
//! image, its statics, the page tables, the saved map itself), ACPI, MMIO or reserved memory. 4 KiB frames are
//! handed out from a fixed table of free ranges (no heap). Frames below 1 MiB are never used (legacy/firmware).

#[derive(Clone, Copy, Default)]
struct Range {
    next: u64, // next free frame address
    end: u64,  // exclusive
}

pub struct Frames {
    ranges: [Range; 256],
    n: usize,
    pub total: u64,
    pub handed_out: u64,
    pub dropped: usize, // usable ranges that did not fit the table (reported, never silent)
}

const MT_BOOT_CODE: u32 = 3;
const MT_BOOT_DATA: u32 = 4;
const MT_CONVENTIONAL: u32 = 7;

impl Frames {
    /// `map`: the raw UEFI descriptors (`dsz` bytes each) exactly as returned by GetMemoryMap.
    pub fn from_map(map: &[u8], dsz: usize) -> Frames {
        let mut f = Frames { ranges: [Range::default(); 256], n: 0, total: 0, handed_out: 0, dropped: 0 };
        let mut off = 0;
        while dsz >= 40 && off + dsz <= map.len() {
            let d = &map[off..off + dsz];
            let ty = u32::from_le_bytes(d[0..4].try_into().unwrap());
            let pa = u64::from_le_bytes(d[8..16].try_into().unwrap());
            let pages = u64::from_le_bytes(d[24..32].try_into().unwrap());
            off += dsz;
            if !matches!(ty, MT_CONVENTIONAL | MT_BOOT_CODE | MT_BOOT_DATA) || pages == 0 {
                continue;
            }
            let start = pa.max(0x10_0000);
            let end = pa.saturating_add(pages.saturating_mul(4096)).min(1 << 32); // the X1 identity map covers 0-4 GiB
            if end <= start {
                continue;
            }
            // The firmware splits contiguous RAM by type (boot data next to conventional, …): merge back-to-back.
            if f.n > 0 && f.ranges[f.n - 1].end == start {
                f.ranges[f.n - 1].end = end;
            } else if f.n == f.ranges.len() {
                f.dropped += 1;
                continue;
            } else {
                f.ranges[f.n] = Range { next: start, end };
                f.n += 1;
            }
            f.total += (end - start) / 4096;
        }
        f
    }

    /// One zeroed 4 KiB frame (identity-mapped, so its physical address is usable directly).
    pub fn alloc(&mut self) -> Option<u64> {
        for r in self.ranges[..self.n].iter_mut() {
            if r.next + 4096 <= r.end {
                let pa = r.next;
                r.next += 4096;
                self.handed_out += 1;
                unsafe { core::ptr::write_bytes(pa as *mut u8, 0, 4096) };
                return Some(pa);
            }
        }
        None
    }

    pub fn ranges(&self) -> usize {
        self.n
    }
}
