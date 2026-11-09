//! Bounded ACPI walk — exactly the tables the arm64-cloud port needs (ACPI 6.x layouts):
//! RSDP -> XSDT -> {MADT(APIC), GTDT, MCFG, SPCR}. All reads are unaligned-safe and every
//! table is length-checked before a field is touched (firmware tables are untrusted input).

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

pub struct Sdt {
    pub sig: [u8; 4],
    pub ptr: *const u8,
    pub len: usize,
}

pub struct Tables {
    pub list: [Option<Sdt>; 32],
    pub count: usize,
    pub rsdp_rev: u8,
}

impl Tables {
    pub fn find(&self, sig: &[u8; 4]) -> Option<&Sdt> {
        self.list[..self.count].iter().flatten().find(|t| &t.sig == sig)
    }
}

/// Parse RSDP (ACPI >= 2.0, XSDT required — the OCI/edk2 case) into the XSDT table list.
pub fn tables(rsdp: *const u8) -> Result<Tables, &'static str> {
    unsafe {
        if core::slice::from_raw_parts(rsdp, 8) != b"RSD PTR " {
            return Err("bad RSDP signature");
        }
        let rev: u8 = rd(rsdp, 15);
        if rev < 2 {
            return Err("ACPI 1.0 RSDP (no XSDT)");
        }
        let rlen: u32 = rd(rsdp, 20);
        if !checksum_ok(rsdp, rlen.min(64) as usize) {
            return Err("RSDP checksum");
        }
        let xsdt = rd::<u64>(rsdp, 24) as *const u8;
        if core::slice::from_raw_parts(xsdt, 4) != b"XSDT" {
            return Err("bad XSDT signature");
        }
        let xlen = rd::<u32>(xsdt, 4) as usize;
        if !(36..=4096).contains(&xlen) || !checksum_ok(xsdt, xlen) {
            return Err("XSDT length/checksum");
        }
        const NONE: Option<Sdt> = None;
        let mut t = Tables { list: [NONE; 32], count: 0, rsdp_rev: rev };
        for i in 0..((xlen - 36) / 8).min(32) {
            let p = rd::<u64>(xsdt, 36 + i * 8) as *const u8;
            if p.is_null() {
                continue;
            }
            let len = rd::<u32>(p, 4) as usize;
            if len < 36 || len > (1 << 20) {
                continue;
            }
            let mut sig = [0u8; 4];
            sig.copy_from_slice(core::slice::from_raw_parts(p, 4));
            t.list[t.count] = Some(Sdt { sig, ptr: p, len });
            t.count += 1;
        }
        Ok(t)
    }
}

#[derive(Default)]
pub struct Gic {
    pub version: u8,
    pub gicd: u64,
    pub gicr: [u64; 4],
    pub gicr_len: [u32; 4],
    pub n_gicr: usize,
    pub n_gicc: usize,
    pub n_its: usize,
    pub gicc_mpidr0: u64,
}

/// MADT: GIC distributor (type 0xC), redistributor ranges (0xE), CPU interfaces (0xB), ITS (0xF).
pub fn madt(t: &Sdt) -> Gic {
    let mut g = Gic::default();
    let mut off = 44;
    while off + 2 <= t.len {
        let (ty, l) = unsafe { (rd::<u8>(t.ptr, off), rd::<u8>(t.ptr, off + 1) as usize) };
        if l < 2 || off + l > t.len {
            break;
        }
        unsafe {
            match ty {
                0x0B if l >= 76 => {
                    if g.n_gicc == 0 {
                        g.gicc_mpidr0 = rd(t.ptr, off + 68);
                    }
                    g.n_gicc += 1;
                }
                0x0C if l >= 24 => {
                    g.gicd = rd(t.ptr, off + 8);
                    g.version = rd(t.ptr, off + 20);
                }
                0x0E if l >= 16 => {
                    if g.n_gicr < 4 {
                        g.gicr[g.n_gicr] = rd(t.ptr, off + 4);
                        g.gicr_len[g.n_gicr] = rd(t.ptr, off + 12);
                    }
                    g.n_gicr += 1;
                }
                0x0F => g.n_its += 1,
                _ => {}
            }
        }
        off += l;
    }
    g
}

/// GTDT: (non-secure EL1 physical timer GSIV, virtual timer GSIV).
pub fn gtdt(t: &Sdt) -> Option<(u32, u32)> {
    if t.len < 72 {
        return None;
    }
    unsafe { Some((rd(t.ptr, 56), rd(t.ptr, 64))) }
}

/// SPCR: (interface type, MMIO base). Type 0x03 = ARM PL011, 0x0E = ARM SBSA generic UART.
pub fn spcr(t: &Sdt) -> Option<(u8, u64)> {
    if t.len < 52 {
        return None;
    }
    unsafe { Some((rd(t.ptr, 36), rd(t.ptr, 44))) }
}

/// MCFG: first ECAM segment (base, segment, start bus, end bus).
pub fn mcfg(t: &Sdt) -> Option<(u64, u16, u8, u8)> {
    if t.len < 60 {
        return None;
    }
    unsafe { Some((rd(t.ptr, 44), rd(t.ptr, 52), rd(t.ptr, 54), rd(t.ptr, 55))) }
}
