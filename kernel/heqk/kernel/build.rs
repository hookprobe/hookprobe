// Pass the right linker script to the final link:
//   hboot  -> linker-hboot.ld  (0x1000000, launched by HBoot)
//   cm5    -> linker-cm5.ld    (0x200000, firmware-direct)
//   else   -> linker.ld        (QEMU virt)
fn main() {
    let dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let script = if std::env::var("CARGO_FEATURE_HBOOT").is_ok() {
        "linker-hboot.ld"
    } else if std::env::var("CARGO_FEATURE_CM5").is_ok() {
        "linker-cm5.ld"
    } else {
        "linker.ld"
    };
    println!("cargo:rustc-link-arg=-T{dir}/{script}");
    println!("cargo:rerun-if-changed=linker.ld");
    println!("cargo:rerun-if-changed=linker-cm5.ld");
    println!("cargo:rerun-if-changed=linker-hboot.ld");
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_CM5");
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_HBOOT");

    // M5.1 (Track C) — generate the ELF fixture the ELF-loader beachhead loads +
    // runs (kernel/src/elf.rs, [P-elf] gate). It is EMITTED here (no committed binary,
    // no external cross-toolchain) and `include_bytes!`d by the kernel. See gen_fixture.
    gen_fixture_elf(&std::env::var("OUT_DIR").unwrap());
    println!("cargo:rerun-if-changed=build.rs");
}

// A minimal, real ELF64/aarch64 ET_EXEC image with TWO PT_LOAD segments — the M5.1
// fixture. Segment 0 (R+X) is a tiny position-fixed EL0 CLIENT: it SYS_CALLs (24)
// through its Endpoint{W} cap at CPtr 0 with message ELF_MSG, then stores the reply
// (returned in x0) to its RW data segment, then SYS_TASK_EXITs (22). Segment 1 (R+W,
// filesz=0/memsz=8) is a zero-filled `.bss` result word the loader maps RW and the
// kernel reads back. The instruction words are hand-encoded aarch64 (asm in comments);
// the VAs + ELF_MSG MUST match the constants in main.rs (kept in sync there).
fn gen_fixture_elf(out_dir: &str) {
    const CODE_VA: u64 = 0x8A00_0000; // entry / R+X segment base  (== main.rs ELF_CODE_VA)
    const DATA_VA: u64 = 0x8A01_0000; // R+W result segment base   (== main.rs ELF_DATA_VA)
    const ELF_MSG: u16 = 0x1E1F; //     message word the client sends (== main.rs ELF_MSG)

    // --- EL0 client machine code (aarch64, little-endian) ---
    let code: [u32; 9] = [
        0xD2800000, // movz x0, #0                 ; CPtr 0 = Endpoint{W}
        0xD2800001 | ((ELF_MSG as u32) << 5), // movz x1, #ELF_MSG          ; message word
        0xD2800308, // movz x8, #24                ; SYS_CALL
        0xD4000001, // svc  #0                     ; send + block; reply -> x0
        0xD2B14021, // movz x1, #0x8A01, lsl #16   ; x1 = DATA_VA (0x8A01_0000)
        0xF9000020, // str  x0, [x1]               ; *DATA_VA = reply word
        0xD28002C8, // movz x8, #22                ; SYS_TASK_EXIT
        0xD4000001, // svc  #0
        0x14000000, // b .                         ; self-loop (never reached)
    ];
    let code_bytes: Vec<u8> = code.iter().flat_map(|w| w.to_le_bytes()).collect();

    const EHDR: usize = 64;
    const PHDR: usize = 56;
    let phoff: u64 = EHDR as u64;
    let phnum: u16 = 2;
    let code_off: u64 = EHDR as u64 + (phnum as u64) * PHDR as u64; // 176
    let code_len = code_bytes.len() as u64; // 36

    let mut e = vec![0u8; code_off as usize];
    // ---- Elf64_Ehdr ----
    e[0..4].copy_from_slice(b"\x7fELF");
    e[4] = 2; // EI_CLASS = ELFCLASS64
    e[5] = 1; // EI_DATA  = ELFDATA2LSB
    e[6] = 1; // EI_VERSION = EV_CURRENT
    put16(&mut e, 16, 2); // e_type    = ET_EXEC
    put16(&mut e, 18, 183); // e_machine = EM_AARCH64
    put32(&mut e, 20, 1); // e_version = EV_CURRENT
    put64(&mut e, 24, CODE_VA); // e_entry
    put64(&mut e, 32, phoff); // e_phoff
    put64(&mut e, 40, 0); // e_shoff
    put32(&mut e, 48, 0); // e_flags
    put16(&mut e, 52, EHDR as u16); // e_ehsize
    put16(&mut e, 54, PHDR as u16); // e_phentsize
    put16(&mut e, 56, phnum); // e_phnum
    put16(&mut e, 58, 0); // e_shentsize
    put16(&mut e, 60, 0); // e_shnum
    put16(&mut e, 62, 0); // e_shstrndx
    // ---- Phdr[0]: code, R+X ----
    let p0 = EHDR;
    put32(&mut e, p0, 1); // p_type  = PT_LOAD
    put32(&mut e, p0 + 4, 4 | 1); // p_flags = PF_R | PF_X
    put64(&mut e, p0 + 8, code_off); // p_offset
    put64(&mut e, p0 + 16, CODE_VA); // p_vaddr
    put64(&mut e, p0 + 24, CODE_VA); // p_paddr
    put64(&mut e, p0 + 32, code_len); // p_filesz
    put64(&mut e, p0 + 40, code_len); // p_memsz
    put64(&mut e, p0 + 48, 0x1000); // p_align
    // ---- Phdr[1]: data/bss result word, R+W (filesz 0 -> zero-filled) ----
    let p1 = EHDR + PHDR;
    put32(&mut e, p1, 1); // p_type  = PT_LOAD
    put32(&mut e, p1 + 4, 4 | 2); // p_flags = PF_R | PF_W
    put64(&mut e, p1 + 8, 0); // p_offset (filesz 0)
    put64(&mut e, p1 + 16, DATA_VA); // p_vaddr
    put64(&mut e, p1 + 24, DATA_VA); // p_paddr
    put64(&mut e, p1 + 32, 0); // p_filesz
    put64(&mut e, p1 + 40, 8); // p_memsz (one result word)
    put64(&mut e, p1 + 48, 0x1000); // p_align
    // ---- code bytes at code_off ----
    e.extend_from_slice(&code_bytes);

    let path = std::path::Path::new(out_dir).join("fixture_client.elf");
    std::fs::write(path, &e).expect("write fixture ELF");
}

fn put16(b: &mut [u8], off: usize, v: u16) {
    b[off..off + 2].copy_from_slice(&v.to_le_bytes());
}
fn put32(b: &mut [u8], off: usize, v: u32) {
    b[off..off + 4].copy_from_slice(&v.to_le_bytes());
}
fn put64(b: &mut [u8], off: usize, v: u64) {
    b[off..off + 8].copy_from_slice(&v.to_le_bytes());
}
