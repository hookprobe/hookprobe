// SPDX-License-Identifier: AGPL-3.0-only
//! Bounded ACPI walk for x86_64: RSDP → XSDT → MADT (LAPIC / x2APIC / IOAPIC / interrupt overrides) and MCFG (PCIe
//! ECAM). Firmware tables are untrusted input: every table is signature-, length- and checksum-checked before a
//! field is read, reads are unaligned-safe, and every list is capped. (The RSDP/XSDT part mirrors efiboot's.)

use core::ptr::read_unaligned;

unsafe fn rd<T: Copy>(p: *const u8, off: usize) -> T {
    read_unaligned(p.add(off) as *const T)
}

fn checksum_ok(p: *const u8, len: usize) -> bool {
    let mut s: u8 = 0;
    for i in 0..len {
        s = s.wrapping_add(unsafe { *p.add(i) });
    }
    s == 0
}

#[derive(Clone, Copy)]
pub struct Sdt {
    pub sig: [u8; 4],
    pub ptr: *const u8,
    pub len: usize,
}

pub struct Tables {
    pub list: [Option<Sdt>; 32],
    pub count: usize,
}

impl Tables {
    pub fn find(&self, sig: &[u8; 4]) -> Option<Sdt> {
        self.list[..self.count].iter().flatten().find(|t| &t.sig == sig).copied()
    }
}

/// RSDP (ACPI ≥ 2.0; XSDT required) → the list of tables, each length- and checksum-verified.
pub fn tables(rsdp: *const u8) -> Result<Tables, &'static str> {
    unsafe {
        if rsdp.is_null() || core::slice::from_raw_parts(rsdp, 8) != b"RSD PTR " {
            return Err("bad RSDP signature");
        }
        if rd::<u8>(rsdp, 15) < 2 {
            return Err("ACPI 1.0 RSDP (no XSDT)");
        }
        let rlen: u32 = rd(rsdp, 20);
        if !checksum_ok(rsdp, rlen.clamp(36, 64) as usize) {
            return Err("RSDP checksum");
        }
        let xsdt = rd::<u64>(rsdp, 24) as *const u8;
        if xsdt.is_null() || core::slice::from_raw_parts(xsdt, 4) != b"XSDT" {
            return Err("bad XSDT signature");
        }
        let xlen = rd::<u32>(xsdt, 4) as usize;
        if !(36..=4096).contains(&xlen) || !checksum_ok(xsdt, xlen) {
            return Err("XSDT length/checksum");
        }
        const NONE: Option<Sdt> = None;
        let mut t = Tables { list: [NONE; 32], count: 0 };
        for i in 0..((xlen - 36) / 8).min(32) {
            let p = rd::<u64>(xsdt, 36 + i * 8) as *const u8;
            if p.is_null() {
                continue;
            }
            let len = rd::<u32>(p, 4) as usize;
            if !(36..=(1 << 20)).contains(&len) || !checksum_ok(p, len) {
                continue; // a corrupt table is skipped, never half-read
            }
            let mut sig = [0u8; 4];
            sig.copy_from_slice(core::slice::from_raw_parts(p, 4));
            t.list[t.count] = Some(Sdt { sig, ptr: p, len });
            t.count += 1;
        }
        Ok(t)
    }
}

#[derive(Clone, Copy, Default)]
pub struct IoApic {
    pub id: u8,
    pub addr: u32,
    pub gsi_base: u32,
}

#[derive(Default)]
pub struct Madt {
    pub lapic_addr: u64,
    pub cpus: usize,  // enabled processors (type 0 + type 9)
    pub x2apic_entries: usize,
    pub ioapics: [IoApic; 4],
    pub n_ioapic: usize,
    pub overrides: usize, // interrupt source overrides (type 2)
    pub has_8259: bool,   // flags bit 0: PCAT_COMPAT
}

/// MADT ("APIC"): local APICs (0), I/O APICs (1), interrupt source overrides (2), LAPIC address override (5),
/// local x2APICs (9). Only ENABLED (or online-capable) processors count.
pub fn madt(t: &Sdt) -> Madt {
    let mut m = Madt { lapic_addr: unsafe { rd::<u32>(t.ptr, 36) } as u64, ..Default::default() };
    m.has_8259 = unsafe { rd::<u32>(t.ptr, 40) } & 1 != 0;
    let mut off = 44;
    while off + 2 <= t.len {
        let (ty, l) = unsafe { (rd::<u8>(t.ptr, off), rd::<u8>(t.ptr, off + 1) as usize) };
        if l < 2 || off + l > t.len {
            break;
        }
        unsafe {
            match ty {
                0 if l >= 8 => {
                    if rd::<u32>(t.ptr, off + 4) & 0b11 != 0 {
                        m.cpus += 1;
                    }
                }
                1 if l >= 12 && m.n_ioapic < m.ioapics.len() => {
                    m.ioapics[m.n_ioapic] =
                        IoApic { id: rd(t.ptr, off + 2), addr: rd(t.ptr, off + 4), gsi_base: rd(t.ptr, off + 8) };
                    m.n_ioapic += 1;
                }
                2 if l >= 10 => m.overrides += 1,
                5 if l >= 12 => m.lapic_addr = rd(t.ptr, off + 4),
                9 if l >= 16 => {
                    m.x2apic_entries += 1;
                    if rd::<u32>(t.ptr, off + 8) & 0b11 != 0 {
                        m.cpus += 1;
                    }
                }
                _ => {}
            }
        }
        off += l;
    }
    m
}

#[derive(Clone, Copy, Default)]
pub struct Ecam {
    pub base: u64,
    pub segment: u16,
    pub bus_start: u8,
    pub bus_end: u8,
}

/// MCFG: the first ECAM allocation (segment group 0 on every target we run on).
pub fn mcfg(t: &Sdt) -> Option<Ecam> {
    if t.len < 44 + 16 {
        return None;
    }
    unsafe {
        let e = Ecam {
            base: rd(t.ptr, 44),
            segment: rd(t.ptr, 52),
            bus_start: rd(t.ptr, 54),
            bus_end: rd(t.ptr, 55),
        };
        (e.base != 0 && e.bus_end >= e.bus_start).then_some(e)
    }
}
