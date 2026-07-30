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

    // M5.3 (Track C) — the REAL wasmi runtime in an EL0 SERVER. Two build outputs, ONLY
    // under `wasmhost` (and not cm5): (1) a SIGNED trapping module fixture for the (c)
    // wasmi-trap-isolation proof; (2) the EL0 Wasm-host BINARY — a separate no_std crate
    // that links wasmi 0.32, compiled to an aarch64 ELF by a NESTED `cargo build` in a
    // clean env and embedded via include_bytes!. wasmi's ~326 KiB .text lives in THAT EL0
    // image, NOT the kernel TCB (ADR 0044 D4 #2). See build_el0_wasmhost.
    if std::env::var("CARGO_FEATURE_WASMHOST").is_ok() && std::env::var("CARGO_FEATURE_CM5").is_err()
    {
        gen_fixture_trap_wasm(&std::env::var("OUT_DIR").unwrap());
        gen_fixture_detect_wasm(&std::env::var("OUT_DIR").unwrap());
        build_el0_wasmhost(&dir, &std::env::var("OUT_DIR").unwrap());
    }
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

// M5.3 (c) — a SIGNED, memoryless module whose exported `classify(port)` body is a single
// `unreachable` — so calling it TRAPS inside wasmi. Same (i32)->(i32) type + "classify"
// export as the good fixture, so the EL0 host loads + instantiates it identically; the trap
// only fires on call. The EL0 wasmi host catches wasmi's trap (call returns Err) and sends
// the fail-closed sentinel over IPC — proving a module trap is CONTAINED at EL0 by wasmi
// itself, kernel untouched. Signed with the SAME dev seed as the good fixture (the kernel
// verifies it — it IS signed — then hands it to a SECOND EL0 host).
fn gen_fixture_trap_wasm(out_dir: &str) {
    // (module (func (export "classify") (param i32) (result i32) unreachable))
    // code body = [locals=0x00, unreachable=0x00, end=0x0b] -> body_size 3.
    let wasm: &[u8] = &[
        0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, // \0asm, version 1
        0x01, 0x06, 0x01, 0x60, 0x01, 0x7f, 0x01, 0x7f, // type: (i32)->(i32)
        0x03, 0x02, 0x01, 0x00, // function: 1 func, type 0
        0x07, 0x0c, 0x01, 0x08, b'c', b'l', b'a', b's', b's', b'i', b'f', b'y', 0x00, 0x00, // export
        0x0a, 0x05, 0x01, 0x03, 0x00, 0x00, 0x0b, // code: body = unreachable; end
    ];
    use ed25519_compact::{KeyPair, Seed};
    let kp = KeyPair::from_seed(Seed::new([0x5au8; 32]));
    let sig = kp.sk.sign(wasm, None);
    let dir = std::path::Path::new(out_dir);
    std::fs::write(dir.join("fixture_trap.wasm"), wasm).expect("write trap wasm");
    std::fs::write(dir.join("fixture_trap.pk"), kp.pk.as_ref()).expect("write trap pk");
    std::fs::write(dir.join("fixture_trap.sig"), sig.as_ref()).expect("write trap sig");
}

// M5.3 — compile the EL0 Wasm-host crate (../el0-wasmhost) to an aarch64 ELF and copy it to
// OUT_DIR/el0_wasmhost.elf for the kernel to include_bytes!. It is a DETACHED workspace
// built by a NESTED `cargo build` — run in a CLEAN env (the parent build-script env would
// otherwise leak CARGO_ENCODED_RUSTFLAGS / CARGO_FEATURE_* / OUT_DIR into the child and
// corrupt it) with its OWN target dir (no lock contention with the parent kernel build).
// Fail-CLOSED: any failure PANICS the kernel build — a `wasmhost` kernel that can't produce
// its EL0 host must not link a stale/absent image.
fn build_el0_wasmhost(kernel_manifest_dir: &str, out_dir: &str) {
    use std::path::Path;
    use std::process::Command;

    let crate_dir = Path::new(kernel_manifest_dir).join("../el0-wasmhost");
    let crate_dir = crate_dir.canonicalize().expect("el0-wasmhost dir missing");
    let manifest = crate_dir.join("Cargo.toml");
    let nested_target = Path::new(out_dir).join("el0host-target");

    // Rebuild if any of the EL0 host's sources change.
    println!("cargo:rerun-if-changed={}", manifest.display());
    println!("cargo:rerun-if-changed={}", crate_dir.join("src/main.rs").display());
    println!("cargo:rerun-if-changed={}", crate_dir.join("link.ld").display());
    println!("cargo:rerun-if-changed={}", crate_dir.join("build.rs").display());
    println!("cargo:rerun-if-changed={}", crate_dir.join(".cargo/config.toml").display());

    let mut cmd = Command::new("cargo");
    cmd.arg("build")
        .arg("--release")
        .arg("--manifest-path")
        .arg(&manifest)
        .arg("--target-dir")
        .arg(&nested_target)
        .current_dir(&crate_dir);

    // CLEAN env: drop every parent-build-script var that would confuse the child cargo/rustc,
    // keeping PATH/HOME/rustup so the nightly toolchain + registry resolve normally.
    for (k, _) in std::env::vars() {
        let leak = k == "RUSTFLAGS"
            || k == "CARGO_ENCODED_RUSTFLAGS"
            || k == "RUSTC"
            || k == "RUSTC_WRAPPER"
            || k == "RUSTC_WORKSPACE_WRAPPER"
            || k == "RUSTDOC"
            || k == "CARGO"
            || k == "CARGO_TARGET_DIR"
            || k == "CARGO_BUILD_TARGET"
            || k == "OUT_DIR"
            || k == "TARGET"
            || k == "HOST"
            || k == "NUM_JOBS"
            || k == "CARGO_MANIFEST_DIR"
            || k == "CARGO_MANIFEST_LINKS"
            || k == "CARGO_PRIMARY_PACKAGE"
            || k.starts_with("CARGO_FEATURE_")
            || k.starts_with("CARGO_CFG_")
            || k.starts_with("CARGO_PKG_");
        if leak {
            cmd.env_remove(k);
        }
    }

    let status = cmd.status().expect("failed to invoke nested cargo for el0-wasmhost");
    if !status.success() {
        panic!("el0-wasmhost nested build FAILED (status {status}) — wasmhost kernel cannot ship without its EL0 Wasm host");
    }

    let produced = nested_target
        .join("aarch64-unknown-none-softfloat/release/el0-wasmhost");
    let dest = Path::new(out_dir).join("el0_wasmhost.elf");
    std::fs::copy(&produced, &dest).unwrap_or_else(|e| {
        panic!("el0-wasmhost ELF not found at {}: {e}", produced.display())
    });
}

// M5.4 (Track C) — the DETECTION-shaped `.wasm` fixture the [P-wasm-parity] gate runs at
// PARITY with the in-kernel `rules::run_l4` (ADR 0044 D4 #4, at small scale). Unlike the
// M5.2/M5.3 MEMORYLESS `classify(port)` module, this one:
//   * has LINEAR MEMORY (1 page) it owns + exports,
//   * imports a BESPOKE MINIMAL host ABI — `hp_input(ptr,cap)->len` (read the input L4
//     header into linear memory) and `hp_emit(verdict)` (emit the verdict),
//   * does REAL detection: reads the big-endian dst-port from mem[2..4] (mirroring
//     THREAT_RULE's R1+2/R1+3) and LOOPS the blocked-port corpus {4444, 23, 31337} held in
//     linear memory (== rules.rs RULES, all FindingClass::Signature) — DROP(2) on a match,
//     else PASS(1) — and defensively TRAPs (`unreachable`) on a <4-byte header.
//
// The bytes below are the EXACT output of `wat::parse_str` on the WAT in the comment,
// with custom (name) sections stripped — GENERATED + VERIFIED through the SAME wasmi 0.32
// the EL0 host links (all 8 parity verdicts == rules.rs, `emitted`==return, malformed
// header traps-contained) before hardcoding, so no `wat`/wasm-tools build-dep is pulled
// into the kernel graph (the M5.2/M5.3 hand-assembled-fixture convention). WAT:
//   (module
//     (import "hp" "hp_input" (func $hp_input (param i32 i32) (result i32)))
//     (import "hp" "hp_emit"  (func $hp_emit  (param i32)))
//     (memory (export "memory") 1)
//     (data (i32.const 256) "\03\00\00\00\5c\11\00\00\17\00\00\00\69\7a\00\00") ;; 3; 4444; 23; 31337
//     (func (export "detect") (result i32)
//       (local $len i32) (local $dport i32) (local $i i32) (local $count i32) (local $verdict i32)
//       (local.set $len (call $hp_input (i32.const 0) (i32.const 64)))
//       (if (i32.lt_u (local.get $len) (i32.const 4)) (then unreachable))
//       (local.set $dport (i32.or (i32.shl (i32.load8_u (i32.const 2)) (i32.const 8))
//                                 (i32.load8_u (i32.const 3))))
//       (local.set $verdict (i32.const 1))
//       (local.set $count (i32.load (i32.const 256)))
//       (local.set $i (i32.const 0))
//       (block $done (loop $lp
//         (br_if $done (i32.ge_u (local.get $i) (local.get $count)))
//         (if (i32.eq (local.get $dport)
//               (i32.load (i32.add (i32.const 260) (i32.mul (local.get $i) (i32.const 4)))))
//           (then (local.set $verdict (i32.const 2)) (br $done)))
//         (local.set $i (i32.add (local.get $i) (i32.const 1))) (br $lp)))
//       (call $hp_emit (local.get $verdict))
//       (local.get $verdict)))
//
// Signed with the SAME dev seed as the other fixtures (kernel verifies the Ed25519 leg of
// heqk's hybrid — NOT ML-DSA-65 — before any byte reaches the EL0 wasmi host, fail-closed).
fn gen_fixture_detect_wasm(out_dir: &str) {
    let wasm: &[u8] = &[
        0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x0f, 0x03, 0x60,
        0x02, 0x7f, 0x7f, 0x01, 0x7f, 0x60, 0x01, 0x7f, 0x00, 0x60, 0x00, 0x01,
        0x7f, 0x02, 0x1c, 0x02, 0x02, 0x68, 0x70, 0x08, 0x68, 0x70, 0x5f, 0x69,
        0x6e, 0x70, 0x75, 0x74, 0x00, 0x00, 0x02, 0x68, 0x70, 0x07, 0x68, 0x70,
        0x5f, 0x65, 0x6d, 0x69, 0x74, 0x00, 0x01, 0x03, 0x02, 0x01, 0x02, 0x05,
        0x03, 0x01, 0x00, 0x01, 0x07, 0x13, 0x02, 0x06, 0x6d, 0x65, 0x6d, 0x6f,
        0x72, 0x79, 0x02, 0x00, 0x06, 0x64, 0x65, 0x74, 0x65, 0x63, 0x74, 0x00,
        0x02, 0x0a, 0x6c, 0x01, 0x6a, 0x01, 0x05, 0x7f, 0x41, 0x00, 0x41, 0xc0,
        0x00, 0x10, 0x00, 0x21, 0x00, 0x20, 0x00, 0x41, 0x04, 0x49, 0x04, 0x40,
        0x00, 0x0b, 0x41, 0x02, 0x2d, 0x00, 0x00, 0x41, 0x08, 0x74, 0x41, 0x03,
        0x2d, 0x00, 0x00, 0x72, 0x21, 0x01, 0x41, 0x01, 0x21, 0x04, 0x41, 0x80,
        0x02, 0x28, 0x02, 0x00, 0x21, 0x03, 0x41, 0x00, 0x21, 0x02, 0x02, 0x40,
        0x03, 0x40, 0x20, 0x02, 0x20, 0x03, 0x4f, 0x0d, 0x01, 0x20, 0x01, 0x41,
        0x84, 0x02, 0x20, 0x02, 0x41, 0x04, 0x6c, 0x6a, 0x28, 0x02, 0x00, 0x46,
        0x04, 0x40, 0x41, 0x02, 0x21, 0x04, 0x0c, 0x02, 0x0b, 0x20, 0x02, 0x41,
        0x01, 0x6a, 0x21, 0x02, 0x0c, 0x00, 0x0b, 0x0b, 0x20, 0x04, 0x10, 0x01,
        0x20, 0x04, 0x0b, 0x0b, 0x17, 0x01, 0x00, 0x41, 0x80, 0x02, 0x0b, 0x10,
        0x03, 0x00, 0x00, 0x00, 0x5c, 0x11, 0x00, 0x00, 0x17, 0x00, 0x00, 0x00,
        0x69, 0x7a, 0x00, 0x00,
    ];
    use ed25519_compact::{KeyPair, Seed};
    let kp = KeyPair::from_seed(Seed::new([0x5au8; 32]));
    let sig = kp.sk.sign(wasm, None);
    let dir = std::path::Path::new(out_dir);
    std::fs::write(dir.join("fixture_detect.wasm"), wasm).expect("write detect wasm");
    std::fs::write(dir.join("fixture_detect.pk"), kp.pk.as_ref()).expect("write detect pk");
    std::fs::write(dir.join("fixture_detect.sig"), sig.as_ref()).expect("write detect sig");
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
