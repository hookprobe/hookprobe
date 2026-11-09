//! Stage 2: hand the machine to an embedded heqk ELF, reproducing the state QEMU `-kernel`
//! gives it today (EL1, MMU + caches off, PT_LOAD segments at their physical addresses, x0 =
//! 0, branch to e_entry) so the CURRENT kernel can be measured on the cloud device model
//! unmodified. The ACPI/RSDP hand-off and a signed A/B payload read from the ESP are the next
//! steps — this is the baseline harness.
//!
//! Order matters: parse + bounds-check the ELF -> claim EXACTLY its physical range from the
//! firmware (refuse, never overwrite, if any of it is taken) -> load -> ExitBootServices ->
//! clean the image to PoC -> MMU, D- and I-cache off -> branch.

use crate::efi::*;
use core::fmt::Write;

static PAYLOAD: &[u8] = include_bytes!(env!("HEQK_IMAGE_PATH"));

const ALLOCATE_ADDRESS: u32 = 2;
const LOADER_DATA: u32 = 2;
const PT_LOAD: u32 = 1;
const EM_AARCH64: u16 = 183;

fn rd16(e: &[u8], o: usize) -> Option<u16> {
    e.get(o..o + 2).map(|b| u16::from_le_bytes([b[0], b[1]]))
}
fn rd32(e: &[u8], o: usize) -> Option<u32> {
    e.get(o..o + 4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}
fn rd64(e: &[u8], o: usize) -> Option<u64> {
    e.get(o..o + 8).map(|b| {
        let mut a = [0u8; 8];
        a.copy_from_slice(b);
        u64::from_le_bytes(a)
    })
}

struct Seg {
    off: u64,
    pa: u64,
    filesz: u64,
    memsz: u64,
}

/// Iterate PT_LOAD segments; every field bounds-checked (the payload is untrusted input even
/// though it is embedded at build time).
fn segments(e: &[u8], mut f: impl FnMut(Seg)) -> Result<u64, &'static str> {
    if e.get(0..4) != Some(b"\x7fELF".as_slice()) || e.get(4) != Some(&2) || e.get(5) != Some(&1) {
        return Err("not ELF64 little-endian");
    }
    if rd16(e, 18) != Some(EM_AARCH64) {
        return Err("not aarch64");
    }
    let entry = rd64(e, 24).ok_or("truncated header")?;
    let phoff = rd64(e, 32).ok_or("truncated header")? as usize;
    let phentsz = rd16(e, 54).ok_or("truncated header")? as usize;
    let phnum = rd16(e, 56).ok_or("truncated header")? as usize;
    if phentsz < 56 || phnum == 0 || phnum > 16 {
        return Err("bad program headers");
    }
    for i in 0..phnum {
        let ph = phoff.checked_add(i * phentsz).ok_or("overflow")?;
        if rd32(e, ph).ok_or("truncated phdr")? != PT_LOAD {
            continue;
        }
        let s = Seg {
            off: rd64(e, ph + 8).ok_or("truncated phdr")?,
            pa: rd64(e, ph + 24).ok_or("truncated phdr")?,
            filesz: rd64(e, ph + 32).ok_or("truncated phdr")?,
            memsz: rd64(e, ph + 40).ok_or("truncated phdr")?,
        };
        if s.memsz < s.filesz || s.off.checked_add(s.filesz).map_or(true, |x| x > e.len() as u64) {
            return Err("segment out of file bounds");
        }
        s.pa.checked_add(s.memsz).ok_or("overflow")?;
        f(s);
    }
    Ok(entry)
}

/// (lowest page, span bytes, entry) of the image.
fn elf_span(e: &[u8]) -> Result<(u64, u64, u64), &'static str> {
    let (mut lo, mut hi) = (u64::MAX, 0u64);
    let entry = segments(e, |s| {
        lo = lo.min(s.pa);
        hi = hi.max(s.pa + s.memsz);
    })?;
    if lo == u64::MAX || !(lo..hi).contains(&entry) || hi - lo > (256 << 20) {
        return Err("no PT_LOAD / entry outside image / image > 256 MiB");
    }
    let lo = lo & !0xfff;
    Ok((lo, (hi - lo + 0xfff) & !0xfff, entry))
}

core::arch::global_asm!(
    ".global efiboot_jump",
    "efiboot_jump:", // x0 = base, x1 = length (bytes), x2 = entry
    "msr daifset, #0xf",
    "mov x9, x2",
    // D-cache line size from CTR_EL0.DminLine (log2 words); clean+invalidate image to PoC.
    "mrs x3, ctr_el0",
    "ubfx x3, x3, #16, #4",
    "mov x4, #4",
    "lsl x4, x4, x3",
    "add x2, x0, x1",
    "sub x5, x4, #1",
    "bic x1, x0, x5",
    "1: dc civac, x1",
    "add x1, x1, x4",
    "cmp x1, x2",
    "b.lo 1b",
    "dsb sy",
    // SCTLR_EL1: M (bit 0), C (bit 2), I (bit 12) off — UEFI ran identity-mapped, so the
    // next fetch after the MMU goes off is the same physical address.
    "mrs x3, sctlr_el1",
    "bic x3, x3, #1",
    "bic x3, x3, #4",
    "bic x3, x3, #0x1000",
    "msr sctlr_el1, x3",
    "isb",
    "ic iallu",
    "tlbi vmalle1",
    "dsb sy",
    "isb",
    "mov x0, xzr",
    "mov x1, xzr",
    "mov x2, xzr",
    "mov x3, xzr",
    "br x9",
);

extern "C" {
    fn efiboot_jump(base: u64, len: u64, entry: u64) -> !;
}

static mut MMAP: [u8; 32768] = [0; 32768];

pub fn boot(image: Handle, bs: &BootServices, c: &mut ConOut) -> Status {
    let (lo, span, entry) = match elf_span(PAYLOAD) {
        Ok(v) => v,
        Err(e) => {
            let _ = write!(c, "[efiboot] REFUSE payload: {}\n", e);
            return 1;
        }
    };
    let mut pa = lo;
    let s = (bs.allocate_pages)(ALLOCATE_ADDRESS, LOADER_DATA, (span / 4096) as usize, &mut pa);
    if s != SUCCESS {
        let _ = write!(c, "[efiboot] REFUSE: {:#x}+{:#x} not free ({:#x})\n", lo, span, s);
        return s;
    }
    // Validated above; the range is now ours.
    let _ = segments(PAYLOAD, |s| unsafe {
        core::ptr::copy_nonoverlapping(PAYLOAD.as_ptr().add(s.off as usize), s.pa as *mut u8, s.filesz as usize);
        core::ptr::write_bytes((s.pa + s.filesz) as *mut u8, 0, (s.memsz - s.filesz) as usize);
    });
    let _ = write!(c, "[efiboot] heqk ELF {} B -> [{:#x}, {:#x}) entry {:#x}; ExitBootServices + jump (EL1, MMU off)\n",
        PAYLOAD.len(), lo, lo + span, entry);

    // ExitBootServices needs the CURRENT map key; any allocation between the two calls
    // invalidates it, so retry a few times. No console output after the first attempt.
    let buf = core::ptr::addr_of_mut!(MMAP) as *mut u8;
    for _ in 0..4 {
        let (mut size, mut key, mut dsz, mut dver) = (32768usize, 0usize, 0usize, 0u32);
        if (bs.get_memory_map)(&mut size, buf, &mut key, &mut dsz, &mut dver) != SUCCESS {
            continue;
        }
        if (bs.exit_boot_services)(image, key) == SUCCESS {
            unsafe { efiboot_jump(lo, span, entry) }
        }
    }
    let _ = write!(c, "[efiboot] ExitBootServices failed\n");
    1
}
