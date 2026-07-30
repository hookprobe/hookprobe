//! M5.1 (Track C) — a MINIMAL, bounds-safe ELF64/aarch64 STATIC loader: the
//! userspace-server substrate beachhead. It replaces the raw
//! `copy_nonoverlapping(stub..stub_end)` path (how every EL0 task is created today —
//! hand-written asm stubs) with "parse a real ELF image → map its PT_LOAD segments →
//! run it", INHERITING the M5.0 enforced-capability mechanism: every segment is mapped
//! through the CORE-1 `map_frame_cap_in` path (has_rights-gated + W^X-enforced +
//! revocation-tracked), and the loaded task drives the real cap-gated syscall path
//! (SYS_CALL over an Endpoint cap resolved from its OWN per-TCB CSpace).
//!
//! SCOPE (ADR 0044 D5 — honest): a STATIC single-/few-segment ET_EXEC/ET_DYN parser.
//! NOT a dynamic loader, NO relocations, NO shared libraries / interpreter (PT_INTERP
//! ignored — a beachhead loads only static images), NOT the Wasm host (M5.2), NOT the
//! signed catalogue (M5.3). Those are the multi-year road. QEMU-green kernel primitive,
//! not a running SOC.
//!
//! SECURITY POSTURE — FAIL CLOSED. An untrusted/malformed ELF is REFUSED, never
//! partially mapped: every offset/size is validated against the image length with
//! overflow-safe arithmetic; segments that are oversize, out-of-bounds, overlapping,
//! misaligned, or that request W+X (W^X) are rejected BEFORE a single frame is mapped.
//! `parse()` is a pure function (no MMU) so the bounds-safety + W^X proofs are
//! deterministic and pre-scheduler; `load_into()` does the (MMU-touching) mapping only
//! over an already-validated `ParsedElf`.

#![allow(dead_code)]

// ---- ELF64 constants (see the System V gABI + the aarch64 ELF supplement) ----
const EI_NIDENT: usize = 16;
const EHDR_SZ: usize = 64; // sizeof(Elf64_Ehdr)
const PHDR_SZ: usize = 56; // sizeof(Elf64_Phdr); e_phentsize MUST equal this
const ELFCLASS64: u8 = 2; // e_ident[EI_CLASS]
const ELFDATA2LSB: u8 = 1; // e_ident[EI_DATA] — little-endian (aarch64)
const EV_CURRENT: u8 = 1; // e_ident[EI_VERSION]
const ET_EXEC: u16 = 2;
const ET_DYN: u16 = 3;
const EM_AARCH64: u16 = 183;

/// Program-header type: a loadable segment. Every other p_type (PT_DYNAMIC/PT_INTERP/…)
/// is IGNORED by this static beachhead loader.
pub const PT_LOAD: u32 = 1;

/// Segment permission flags (p_flags).
pub const PF_X: u32 = 1;
pub const PF_W: u32 = 2;
pub const PF_R: u32 = 4;

/// 4 KiB page (the only granule this loader maps at).
const PAGE: usize = 0x1000;

/// Beachhead bounds — a loaded segment may not exceed this, and the image may hold at
/// most `MAX_SEGMENTS` PT_LOADs. Keeps the loader's memory + slot use bounded and makes
/// a hostile "gigantic segment" ELF a cheap REFUSAL, never an allocation storm.
///
/// M5.3 raised the ceiling (NOT the safety): the REAL wasmi EL0 Wasm-host image
/// (el0-wasmhost) is a 3-PT_LOAD ET_EXEC whose R+X `.text` measures ~326 KiB (wasmi 0.32,
/// opt-level=z + LTO). 64 KiB was fine for the hand-rolled fixtures but far too small for a
/// real interpreter. The cap is widened to 2 MiB / 8 segments — still a hard, bounded
/// refusal for a hostile "gigantic segment" ELF, and every bounds/overflow/overlap/W^X
/// check below is UNCHANGED. The MMU multi-block-W^X fix (build_wx_ram_range) already
/// removed the old ~2 MiB `.text` block ceiling this larger image would otherwise hit.
pub const MAX_SEG_BYTES: usize = 2 * 1024 * 1024; // 512 pages (was 64 KiB — M5.3 widened)
pub const MAX_SEGMENTS: usize = 8; // (was 4 — M5.3: real images carry text/rodata/data/bss)

/// EL0 USER VA WINDOW — every loadable segment span AND the entry point MUST lie
/// wholly inside this range. This is the invariant the CM5 mapper enforces via
/// `user_va_ok` and the QEMU mapper previously did NOT: without it, a crafted ELF
/// whose `p_vaddr`/`e_entry` names a KERNEL VA (e.g. a `.text` page at 0x4008_0000,
/// L1 slot 1) would, on the QEMU per-AS map path — whose L1 SHARES the kernel's L2/L3
/// tables for the RAM region — overwrite a live kernel PTE for EVERY address space
/// (kernel-integrity DoS + an EL0 mapping planted at a kernel VA). Pinning the window
/// in the pure `parse()` refuses that image before a single frame is mapped. The
/// window is L1 slot 2 [0x8000_0000, 0xC000_0000): it holds every real EL0 image the
/// beachhead loads (the asm fixtures at 0x8A00_0000.., the wasmi host at 0x9000_0000..)
/// and excludes the kernel RAM/text region and the low device/identity region.
pub const USER_VA_LO: usize = 0x8000_0000;
pub const USER_VA_HI: usize = 0xC000_0000;

/// Is `[va, va+len)` wholly inside the EL0 user VA window (and non-wrapping)?
#[inline]
fn user_span_ok(va: usize, len: usize) -> bool {
    match va.checked_add(len) {
        Some(end) => va >= USER_VA_LO && end <= USER_VA_HI,
        None => false,
    }
}

#[inline]
fn page_up(n: usize) -> usize {
    (n + (PAGE - 1)) & !(PAGE - 1)
}

/// A validated PT_LOAD segment (all fields already bounds-checked by `parse`).
#[derive(Clone, Copy)]
pub struct Segment {
    pub vaddr: usize,
    pub offset: usize,
    pub filesz: usize,
    pub memsz: usize,
    pub flags: u32,
}
const EMPTY_SEG: Segment = Segment { vaddr: 0, offset: 0, filesz: 0, memsz: 0, flags: 0 };

impl Segment {
    #[inline]
    pub fn readable(&self) -> bool {
        self.flags & PF_R != 0
    }
    #[inline]
    pub fn writable(&self) -> bool {
        self.flags & PF_W != 0
    }
    #[inline]
    pub fn executable(&self) -> bool {
        self.flags & PF_X != 0
    }
}

/// The parsed, VALIDATED image: entry point + the bounded PT_LOAD list.
pub struct ParsedElf {
    pub entry: usize,
    pub segs: [Segment; MAX_SEGMENTS],
    pub nsegs: usize,
}

/// Why an ELF was REFUSED. Distinct variants so the (b)/(c) self-tests can assert the
/// EXACT failure a given malformation must produce (a fail-closed loader must reject for
/// the RIGHT reason, not by accident).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ElfError {
    TooShort,          // image smaller than the ELF header (or a phdr runs off the end)
    BadMagic,          // e_ident[0..4] != 0x7f 'E' 'L' 'F'
    NotElf64,          // EI_CLASS != ELFCLASS64
    NotLsb,            // EI_DATA != ELFDATA2LSB
    BadVersion,        // EI_VERSION / e_version != EV_CURRENT
    BadType,           // e_type not ET_EXEC/ET_DYN
    BadMachine,        // e_machine != EM_AARCH64
    BadPhEntSize,      // e_phentsize != 56
    PhdrsOutOfBounds,  // e_phoff + e_phnum*56 exceeds the image
    ZeroSegments,      // no PT_LOAD segments at all
    TooManySegments,   // more PT_LOADs than MAX_SEGMENTS (or phnum absurdly large)
    MemszLessThanFilesz, // p_memsz < p_filesz — malformed
    SegmentOutOfBounds,  // [p_offset, p_offset+p_filesz) not within the image
    SegmentTooLarge,     // p_memsz exceeds MAX_SEG_BYTES
    Unaligned,           // p_vaddr not page-aligned (beachhead simplification)
    WxViolation,         // p_flags requests WRITE and EXECUTE together (W^X)
    Overlap,             // two PT_LOAD vaddr ranges overlap
    EntryNotExecutable,  // e_entry falls outside every executable segment
    IntegerOverflow,     // an offset/size add or multiply would overflow
    VaOutOfWindow,       // a segment span or e_entry lands outside the EL0 user VA window
}

// -------- little-endian field readers: bounds-checked, NEVER panic/OOB --------
#[inline]
fn rd_u16(img: &[u8], off: usize) -> Result<u16, ElfError> {
    let s = img.get(off..off + 2).ok_or(ElfError::TooShort)?;
    Ok(u16::from_le_bytes([s[0], s[1]]))
}
#[inline]
fn rd_u32(img: &[u8], off: usize) -> Result<u32, ElfError> {
    let s = img.get(off..off + 4).ok_or(ElfError::TooShort)?;
    Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}
#[inline]
fn rd_u64(img: &[u8], off: usize) -> Result<u64, ElfError> {
    let s = img.get(off..off + 8).ok_or(ElfError::TooShort)?;
    Ok(u64::from_le_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]]))
}

/// Parse + VALIDATE an ELF64/aarch64 image. Pure (no MMU). Returns the entry + the
/// bounded, bounds-checked PT_LOAD list, or the EXACT `ElfError` for a refusal. Every
/// arithmetic on an untrusted length uses checked ops — a malformed/hostile image can
/// only ever be REFUSED here, never read out of bounds.
pub fn parse(img: &[u8]) -> Result<ParsedElf, ElfError> {
    let len = img.len();
    if len < EHDR_SZ {
        return Err(ElfError::TooShort);
    }
    // e_ident
    if &img[0..4] != b"\x7fELF" {
        return Err(ElfError::BadMagic);
    }
    if img[4] != ELFCLASS64 {
        return Err(ElfError::NotElf64);
    }
    if img[5] != ELFDATA2LSB {
        return Err(ElfError::NotLsb);
    }
    if img[6] != EV_CURRENT {
        return Err(ElfError::BadVersion);
    }
    let e_type = rd_u16(img, 16)?;
    if e_type != ET_EXEC && e_type != ET_DYN {
        return Err(ElfError::BadType);
    }
    let e_machine = rd_u16(img, 18)?;
    if e_machine != EM_AARCH64 {
        return Err(ElfError::BadMachine);
    }
    if rd_u32(img, 20)? != EV_CURRENT as u32 {
        return Err(ElfError::BadVersion);
    }
    let e_entry = rd_u64(img, 24)? as usize;
    let e_phoff = rd_u64(img, 32)? as usize;
    let e_phentsize = rd_u16(img, 54)? as usize;
    let e_phnum = rd_u16(img, 56)? as usize;

    if e_phentsize != PHDR_SZ {
        return Err(ElfError::BadPhEntSize);
    }
    if e_phnum == 0 {
        return Err(ElfError::ZeroSegments);
    }
    // Bound phnum BEFORE the multiply so a crafted 0xFFFF can't stress the arithmetic;
    // and the phdr table must lie wholly within the image (overflow-safe).
    if e_phnum > 128 {
        return Err(ElfError::TooManySegments);
    }
    let ph_bytes = e_phnum.checked_mul(PHDR_SZ).ok_or(ElfError::IntegerOverflow)?;
    let ph_end = e_phoff.checked_add(ph_bytes).ok_or(ElfError::IntegerOverflow)?;
    if ph_end > len {
        return Err(ElfError::PhdrsOutOfBounds);
    }

    let mut segs = [EMPTY_SEG; MAX_SEGMENTS];
    let mut nsegs = 0usize;
    for i in 0..e_phnum {
        // Safe: ph_end <= len guarantees each phdr's 56 bytes are in-image.
        let base = e_phoff + i * PHDR_SZ;
        let p_type = rd_u32(img, base)?;
        if p_type != PT_LOAD {
            continue; // beachhead: only PT_LOAD is mapped; everything else ignored
        }
        let p_flags = rd_u32(img, base + 4)?;
        let p_offset = rd_u64(img, base + 8)? as usize;
        let p_vaddr = rd_u64(img, base + 16)? as usize;
        // p_paddr (base+24) ignored.
        let p_filesz = rd_u64(img, base + 32)? as usize;
        let p_memsz = rd_u64(img, base + 40)? as usize;
        // p_align (base+48) read but not trusted; we require page alignment below.

        // ---- STRICT, fail-closed validation of THIS segment ----
        if p_memsz < p_filesz {
            return Err(ElfError::MemszLessThanFilesz);
        }
        // The on-disk bytes [p_offset, p_offset+p_filesz) must be wholly in-image.
        let f_end = p_offset.checked_add(p_filesz).ok_or(ElfError::IntegerOverflow)?;
        if f_end > len {
            return Err(ElfError::SegmentOutOfBounds);
        }
        // The virtual span must not overflow the address space.
        let _v_end = p_vaddr.checked_add(p_memsz).ok_or(ElfError::IntegerOverflow)?;
        if p_memsz > MAX_SEG_BYTES {
            return Err(ElfError::SegmentTooLarge);
        }
        // W^X: a segment may be writable OR executable, NEVER both.
        if (p_flags & PF_W != 0) && (p_flags & PF_X != 0) {
            return Err(ElfError::WxViolation);
        }
        // Beachhead simplification: require page-aligned vaddr so one segment maps to a
        // whole number of pages from its base (no intra-page split of two segments).
        if p_vaddr & (PAGE - 1) != 0 {
            return Err(ElfError::Unaligned);
        }
        // VA-WINDOW: the segment's mapped span (rounded up to whole pages, exactly what
        // `load_into` maps) must lie inside the EL0 user window — never a kernel VA.
        if !user_span_ok(p_vaddr, page_up(p_memsz).max(PAGE)) {
            return Err(ElfError::VaOutOfWindow);
        }
        if nsegs >= MAX_SEGMENTS {
            return Err(ElfError::TooManySegments);
        }
        segs[nsegs] = Segment {
            vaddr: p_vaddr,
            offset: p_offset,
            filesz: p_filesz,
            memsz: p_memsz,
            flags: p_flags,
        };
        nsegs += 1;
    }
    if nsegs == 0 {
        return Err(ElfError::ZeroSegments);
    }

    // No two loadable segments may cover overlapping pages (bounded O(n^2), n<=4). An
    // overlap would let one segment's frame alias another's — a partial-map/aliasing
    // leak this loader must refuse.
    for a in 0..nsegs {
        let sa = segs[a].vaddr;
        let ea = sa.checked_add(page_up(segs[a].memsz)).ok_or(ElfError::IntegerOverflow)?;
        for b in (a + 1)..nsegs {
            let sb = segs[b].vaddr;
            let eb = sb.checked_add(page_up(segs[b].memsz)).ok_or(ElfError::IntegerOverflow)?;
            if sa < eb && sb < ea {
                return Err(ElfError::Overlap);
            }
        }
    }

    // The entry point must land inside an EXECUTABLE segment — otherwise the first
    // instruction fetch would fault (or, worse, execute data).
    let entry_ok = (0..nsegs).any(|i| {
        let s = &segs[i];
        s.executable() && e_entry >= s.vaddr && e_entry < s.vaddr + s.memsz
    });
    if !entry_ok {
        return Err(ElfError::EntryNotExecutable);
    }
    // Belt-and-suspenders: e_entry itself must be in the EL0 user window (guaranteed by
    // the per-segment window check + entry-in-exec-segment above, asserted directly so a
    // future change to either can't silently re-open a kernel-VA entry point).
    if !user_span_ok(e_entry, 1) {
        return Err(ElfError::VaOutOfWindow);
    }

    Ok(ParsedElf { entry: e_entry, segs, nsegs })
}

/// The result of loading: the entry VA + the physical base of the first WRITABLE
/// segment page (so the spawner can read back a result the loaded task wrote — the
/// beachhead's observability hook; a real loader keeps the full segment→frame map).
#[derive(Clone, Copy)]
pub struct Loaded {
    pub entry: usize,
    pub writable_pa: usize,
}

/// Load a VALIDATED image into address space `l1_root` (a per-TCB VSpace from
/// `new_addr_space`). For each PT_LOAD: allocate frame(s), ZERO them (so `memsz>filesz`
/// gives a zeroed `.bss` tail), copy the file bytes, then MAP each page through the
/// enforced CORE-1 capability path (`map_frame_cap_in`) with rights DERIVED from the
/// segment — `W` for a writable data segment, `R`(+exec) for a code segment — so W^X is
/// enforced at the mapping boundary too. `#[cfg(not(cm5))]`: QEMU beachhead only (the
/// per-AS EL0 mapping backend used here is the QEMU path).
#[cfg(not(feature = "cm5"))]
pub fn load_into(parsed: &ParsedElf, img: &[u8], l1_root: usize) -> Result<Loaded, &'static str> {
    use crate::caps::{CapSpace, ObjType, R, W};
    use hal::Mmu as _; // bring the `alloc_frame` trait method into scope
    let mmu = arch_aarch64::Mmu;
    let mut writable_pa = 0usize;

    for si in 0..parsed.nsegs {
        let seg = parsed.segs[si];
        // Defense in depth: refuse W+X here too (parse already did — never trust one gate).
        if seg.writable() && seg.executable() {
            return Err("elf: W^X violation at load");
        }
        let npages = (page_up(seg.memsz).max(PAGE)) / PAGE;
        for p in 0..npages {
            let frame = mmu.alloc_frame();
            if frame == 0 {
                return Err("elf: out of frames");
            }
            // Zero the whole page first: this is the `.bss` tail (memsz>filesz) AND
            // scrubs any stale bytes before EL0 can read the page.
            unsafe { core::ptr::write_bytes(frame as *mut u8, 0, PAGE) };
            // How many file bytes land in THIS page.
            let page_file_off = p * PAGE;
            if page_file_off < seg.filesz {
                let copy = (seg.filesz - page_file_off).min(PAGE);
                let start = seg.offset + page_file_off;
                let src = img.get(start..start + copy).ok_or("elf: source slice OOB")?;
                unsafe {
                    core::ptr::copy_nonoverlapping(src.as_ptr(), frame as *mut u8, copy);
                }
            }
            let va = seg.vaddr + page_file_off;

            // ENFORCED-CAP MAPPING: wrap the freshly-allocated frame in a Frame cap
            // naming its PA with segment-derived rights, then map it through the
            // has_rights-gated + W^X-enforced `map_frame_cap_in`. A per-page throwaway
            // CSpace keeps the invocation isolated (its `mapped_va` bookkeeping is
            // vestigial once dropped; the PTE lives in the task's L1). This is the
            // confused-deputy fix: EL0 memory authority flows through a rights-checked
            // capability invocation, not an ad-hoc kernel map call.
            let rights = if seg.writable() { R | W } else { R };
            let need = if seg.writable() { W } else { R };
            let mut cs = CapSpace::empty();
            let slot = cs
                .install_object(ObjType::Frame, rights, frame, 0, 0)
                .map_err(|_| "elf: no cap slot")?;
            cs.map_frame_cap_in(l1_root, slot, va, need, seg.executable())?;

            // Make copied instructions visible to the fetcher for an executable page.
            if seg.executable() {
                arch_aarch64::mmu::sync_instruction_cache(frame, PAGE);
            }
            if seg.writable() && writable_pa == 0 {
                writable_pa = frame; // first writable page — the result read-back hook
            }
        }
    }
    Ok(Loaded { entry: parsed.entry, writable_pa })
}
