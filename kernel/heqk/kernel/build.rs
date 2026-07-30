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

    // M5.2 (Track C) — generate the SIGNED .wasm fixture the Wasm-host beachhead
    // verifies-then-runs (kernel/src/wasmhost.rs, [P-wasm] gate). Hand-assembled wasm
    // bytes + an Ed25519 signature over them, all EMITTED here (no committed binary,
    // no wat2wasm/external toolchain). See gen_fixture_wasm.
    gen_fixture_wasm(&std::env::var("OUT_DIR").unwrap());
    println!("cargo:rerun-if-changed=build.rs");
}

// A minimal, real WebAssembly (MVP) module + its Ed25519 signature — the M5.2 fixture.
// The module exports ONE detection-shaped predicate `classify(port: i32) -> i32` that
// returns 1 iff `port == 4444` (the known-bad backdoor port of rule 1 "block-port-4444"
// in rules.rs), else 0 — so the proof is tied to the real detection domain, not a toy
// `add`. It is MEMORYLESS (no linear memory, no imports) so the interpreter needs only a
// few KiB of heap. We ALSO sign it here (Ed25519, deterministic from a fixed dev seed —
// no RNG) and emit the 32-byte pubkey + 64-byte signature; the kernel VERIFIES with its
// always-on `ed25519-compact` BEFORE the bytes ever reach the interpreter (fail-closed).
//
// SIGNATURE HONESTY (reported): heqk's REAL per-artifact hybrid is Ed25519 + SLH-DSA-
// SHA2-128s (boot-abi::verify, image-level) — NOT ML-DSA-65 (which is NOT on heqk; only
// named as roadmap in securechannel.rs). This beachhead verifies with the Ed25519 leg —
// the kernel's ALWAYS-ON primitive (attest_svc uses the identical `ed25519-compact`) —
// so the base TCB is untouched; fips205/SLH-DSA is deliberately kept OUT of the default
// kernel (it rides `boot-abi/otaverify`, only under p15-write) and is added as the PQ
// co-leg at catalogue-parity time (M5.3), not for a one-module sliver.
fn gen_fixture_wasm(out_dir: &str) {
    // (module
    //   (func (export "classify") (param i32) (result i32)
    //     local.get 0   i32.const 4444   i32.eq))
    // 4444 = i32.const, signed-LEB128 -> 0xDC 0x22. Verified valid + correct
    // (classify(4444)=1, classify(443)=0) under wasmi before hardcoding.
    let wasm: &[u8] = &[
        0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, // \0asm, version 1
        // type section: 1 type, (i32) -> (i32)
        0x01, 0x06, 0x01, 0x60, 0x01, 0x7f, 0x01, 0x7f,
        // function section: 1 func, type 0
        0x03, 0x02, 0x01, 0x00,
        // export section: "classify" -> func 0
        0x07, 0x0c, 0x01, 0x08, b'c', b'l', b'a', b's', b's', b'i', b'f', b'y', 0x00, 0x00,
        // code section: body = local.get 0; i32.const 4444; i32.eq; end
        0x0a, 0x0a, 0x01, 0x08, 0x00, 0x20, 0x00, 0x41, 0xdc, 0x22, 0x46, 0x0b,
    ];

    // Deterministic Ed25519 keypair from a FIXED dev seed (no RNG; reproducible).
    // The PRIVATE half exists only here at build time; only the public key +
    // signature are emitted, and both are emitted TOGETHER so they always match
    // (a tampered module fails the signature — that is the (b) sub-proof).
    use ed25519_compact::{KeyPair, Seed};
    let seed = Seed::new([0x5au8; 32]);
    let kp = KeyPair::from_seed(seed);
    let sig = kp.sk.sign(wasm, None); // Ed25519 over the artifact bytes (ADR-0016-shaped)

    let dir = std::path::Path::new(out_dir);
    std::fs::write(dir.join("fixture_classify.wasm"), wasm).expect("write fixture wasm");
    std::fs::write(dir.join("fixture_classify.pk"), kp.pk.as_ref()).expect("write fixture pk");
    std::fs::write(dir.join("fixture_classify.sig"), sig.as_ref()).expect("write fixture sig");
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
