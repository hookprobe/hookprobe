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

    // ADR 0047 D2 — the on-device Mission Control UI. Under `mcserve` the static UI build
    // (ui/dist, built with PUBLIC_API_BASE='' so it calls the device it was served from) is
    // embedded into the image and served by http.rs. Other builds get an empty table.
    gen_ui_assets(&dir, &std::env::var("OUT_DIR").unwrap());

    // M5.2 (Track C) — generate the SIGNED .wasm fixture the Wasm-host beachhead
    // verifies-then-runs (kernel/src/wasmhost.rs, [P-wasm] gate). Hand-assembled wasm
    // bytes + an Ed25519 signature over them, all EMITTED here (no committed binary,
    // no wat2wasm/external toolchain). See gen_fixture_wasm.
    gen_fixture_wasm(&std::env::var("OUT_DIR").unwrap());

    // DET-2 (Track C) — the SIGNED dynamic-rule fixture the per-rule authenticity gate
    // verifies ([P8-det2]). A minimal VALID BPF rule (R0=PASS; EXIT) + an Ed25519 signature
    // over its bytecode under the pinned rule-signing root — the gate a future dynamic rule
    // source (HYDRA-synced field updates) MUST pass BEFORE verify_prevail. See gen_fixture_rule.
    gen_fixture_rule(&std::env::var("OUT_DIR").unwrap());

    // M5.3 (Track C) — the REAL wasmi runtime in an EL0 SERVER. Two build outputs, ONLY
    // under `wasmhost` (and not cm5): (1) a SIGNED trapping module fixture for the (c)
    // wasmi-trap-isolation proof; (2) the EL0 Wasm-host BINARY — a separate no_std crate
    // that links wasmi 0.32, compiled to an aarch64 ELF by a NESTED `cargo build` in a
    // clean env and embedded via include_bytes!. wasmi's ~326 KiB .text lives in THAT EL0
    // image, NOT the kernel TCB (ADR 0044 D4 #2). See build_el0_wasmhost.
    // M5.5 (Track C, U5): the EL0 wasmi host now builds for CM5 too — the on-device Wasm
    // host is a real CM5 target (ADR 0044 Track C M5). Previously !cm5-only.
    if std::env::var("CARGO_FEATURE_WASMHOST").is_ok()
    {
        gen_fixture_trap_wasm(&std::env::var("OUT_DIR").unwrap());
        gen_fixture_detect_wasm(&std::env::var("OUT_DIR").unwrap());
        build_el0_wasmhost(&dir, &std::env::var("OUT_DIR").unwrap());
        build_wasip1_fixture(&dir, &std::env::var("OUT_DIR").unwrap());
    }
    gen_policy_key(&std::env::var("OUT_DIR").unwrap());
    if std::env::var("CARGO_FEATURE_MCTLS").is_ok() {
        build_el0_tlshost(&dir, &std::env::var("OUT_DIR").unwrap());
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

// DET-2 — emit a minimal VALID BPF rule (R0=PASS; EXIT, 2 insns = 16 LE bytes) + an Ed25519
// signature over its bytecode under the PINNED rule-signing root (dev seed [0xd2;32], distinct
// from the wasm module root). The kernel's per-rule authenticity gate (rules::rule_sig_ok)
// verifies this signature BEFORE verify_prevail — the gate a future DYNAMIC rule source
// (HYDRA-synced field updates from storage/network) must pass; tampered/unsigned => refused.
fn gen_fixture_rule(out_dir: &str) {
    // insn(op,dst,src,off,imm) = op | dst<<8 | src<<12 | (off as u16 as u64)<<16 | (imm as u32 as u64)<<32
    let mov: u64 = 0xb7 | (1u64 << 32); // MOV64_K R0, 1  (R0 = PASS)
    let exit: u64 = 0x95; //               EXIT
    let mut prog = Vec::with_capacity(16);
    prog.extend_from_slice(&mov.to_le_bytes());
    prog.extend_from_slice(&exit.to_le_bytes());

    use ed25519_compact::{KeyPair, Seed};
    let kp = KeyPair::from_seed(Seed::new([0xd2u8; 32]));
    let sig = kp.sk.sign(&prog, None);
    let dir = std::path::Path::new(out_dir);
    std::fs::write(dir.join("fixture_rule.bin"), &prog).expect("write rule fixture");
    std::fs::write(dir.join("fixture_rule.pk"), kp.pk.as_ref()).expect("write rule pk");
    std::fs::write(dir.join("fixture_rule.sig"), sig.as_ref()).expect("write rule sig");
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
    // M5.5 — a CM5 kernel gets the SYNCHRONOUS-EXCURSION host (syncabi: link-cm5.ld GB5 window).
    let feat = std::env::var("CARGO_FEATURE_CM5").is_ok().then_some("syncabi");
    build_el0_crate(kernel_manifest_dir, out_dir, "el0-wasmhost", "el0host-target", feat, "el0_wasmhost.elf");
}

// ADR 0050 D2 / ADR 0051 — the EL0 TLS server (el0-tlshost) for Mission Control HTTPS, built the same way.
fn build_el0_tlshost(kernel_manifest_dir: &str, out_dir: &str) {
    let feat = std::env::var("CARGO_FEATURE_CM5").is_ok().then_some("cm5");
    build_el0_crate(kernel_manifest_dir, out_dir, "el0-tlshost", "el0tls-target", feat, "el0_tlshost.elf");
    // its provider + shared ABI are sources of the image too
    let dir = std::path::Path::new(kernel_manifest_dir);
    println!("cargo:rerun-if-changed={}", dir.join("../tlsprov/src/lib.rs").display());
    println!("cargo:rerun-if-changed={}", dir.join("../hal/src/tlsabi.rs").display());
}

fn build_el0_crate(kernel_manifest_dir: &str, out_dir: &str, name: &str, tdir: &str, feature: Option<&str>, dest_name: &str) {
    use std::path::Path;
    use std::process::Command;

    let crate_dir = Path::new(kernel_manifest_dir).join("..").join(name);
    let crate_dir = crate_dir.canonicalize().unwrap_or_else(|_| panic!("{name} dir missing"));
    let manifest = crate_dir.join("Cargo.toml");
    let nested_target = Path::new(out_dir).join(tdir);

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
    if let Some(f) = feature {
        cmd.arg("--features").arg(f);
    }

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

    let status = cmd.status().unwrap_or_else(|_| panic!("failed to invoke nested cargo for {name}"));
    if !status.success() {
        panic!("{name} nested build FAILED (status {status}) — the kernel cannot ship without its EL0 image");
    }

    let produced = nested_target.join("aarch64-unknown-none-softfloat/release").join(name);
    let dest = Path::new(out_dir).join(dest_name);
    std::fs::copy(&produced, &dest).unwrap_or_else(|e| {
        panic!("{name} ELF not found at {}: {e}", produced.display())
    });
}

// A2 (M5.5) — build the REAL wasm32-wasip1 detection module (wasip1-fixture) via a NESTED
// cargo build in a CLEAN env, Ed25519-SIGN its bytes (kernel = trust root, same as the
// M5.2/M5.3 fixtures) and emit fixture_wasip1.{wasm,pk,sig} for the EL0 wasip1 host to run.
// A genuine wasip1 command binary (stdin/stdout, imports fd_read/fd_write/environ_*/proc_exit)
// — the production module shape, run THROUGH wasmi in an isolated EL0 task.
fn build_wasip1_fixture(kernel_manifest_dir: &str, out_dir: &str) {
    use std::path::Path;
    use std::process::Command;

    let crate_dir = Path::new(kernel_manifest_dir).join("../wasip1-fixture");
    let crate_dir = crate_dir.canonicalize().expect("wasip1-fixture dir missing");
    let manifest = crate_dir.join("Cargo.toml");
    let nested_target = Path::new(out_dir).join("wasip1-target");

    println!("cargo:rerun-if-changed={}", manifest.display());
    println!("cargo:rerun-if-changed={}", crate_dir.join("src/main.rs").display());

    let mut cmd = Command::new("cargo");
    cmd.arg("build")
        .arg("--release")
        .arg("--target")
        .arg("wasm32-wasip1")
        .arg("--manifest-path")
        .arg(&manifest)
        .arg("--target-dir")
        .arg(&nested_target)
        .current_dir(&crate_dir);
    // CLEAN env: drop parent build-script vars that would confuse the child cargo/rustc.
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
    let status = cmd.status().expect("failed to invoke nested cargo for wasip1-fixture");
    if !status.success() {
        panic!("wasip1-fixture nested build FAILED (status {status}) — wasmhost kernel cannot ship without its signed wasip1 fixture");
    }
    let produced = nested_target.join("wasm32-wasip1/release/wasip1-fixture.wasm");
    let wasm = std::fs::read(&produced)
        .unwrap_or_else(|e| panic!("wasip1-fixture wasm not found at {}: {e}", produced.display()));

    // Sign the module bytes with the PINNED module-signing root seed (the SAME [0x5a;32] the
    // classify/detect fixtures use) — verify_module pins the presented key to TRUSTED_MODULE_PK
    // (== FIXTURE_PK), so a per-fixture key would be rejected as a confused-deputy.
    use ed25519_compact::{KeyPair, Seed};
    let kp = KeyPair::from_seed(Seed::new([0x5au8; 32]));
    let sig = kp.sk.sign(&wasm, None);
    let dir = Path::new(out_dir);
    std::fs::write(dir.join("fixture_wasip1.wasm"), &wasm).expect("write wasip1 wasm");
    std::fs::write(dir.join("fixture_wasip1.pk"), kp.pk.as_ref()).expect("write wasip1 pk");
    std::fs::write(dir.join("fixture_wasip1.sig"), sig.as_ref()).expect("write wasip1 sig");

    // A2+ — the SECOND catalogue module (DNS-RPZ), signed with the SAME pinned root key.
    let produced2 = nested_target.join("wasm32-wasip1/release/wasip1-dnsrpz.wasm");
    let wasm2 = std::fs::read(&produced2)
        .unwrap_or_else(|e| panic!("wasip1-dnsrpz wasm not found at {}: {e}", produced2.display()));
    let sig2 = kp.sk.sign(&wasm2, None);
    std::fs::write(dir.join("fixture_wasip1_dnsrpz.wasm"), &wasm2).expect("write dnsrpz wasm");
    std::fs::write(dir.join("fixture_wasip1_dnsrpz.pk"), kp.pk.as_ref()).expect("write dnsrpz pk");
    std::fs::write(dir.join("fixture_wasip1_dnsrpz.sig"), sig2.as_ref()).expect("write dnsrpz sig");
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

/// Emit `$OUT_DIR/ui_assets.rs` = `pub static UI_ASSETS: &[Asset] = &[...]` (`include_bytes!` of
/// every file under the UI dist dir). `HEQK_UI_DIST` overrides the default `<repo>/ui/dist`.
fn gen_ui_assets(manifest_dir: &str, out_dir: &str) {
    use std::fmt::Write as _;
    println!("cargo:rerun-if-env-changed=HEQK_UI_DIST");
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_MCSERVE");
    let out = std::path::Path::new(out_dir).join("ui_assets.rs");
    let mut src = String::from("pub static UI_ASSETS: &[Asset] = &[\n");
    if std::env::var("CARGO_FEATURE_MCSERVE").is_ok() {
        let dist = std::env::var("HEQK_UI_DIST")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|_| std::path::Path::new(manifest_dir).join("../../../ui/dist"));
        let dist = dist.canonicalize().unwrap_or_else(|_| {
            panic!("mcserve embeds the Mission Control UI but {} does not exist — build it first: \
                    (cd ui && npm ci && PUBLIC_API_BASE='' npm run build)", dist.display())
        });
        println!("cargo:rerun-if-changed={}", dist.display());
        let mut files = Vec::new();
        let mut stack = vec![dist.clone()];
        while let Some(d) = stack.pop() {
            for e in std::fs::read_dir(&d).unwrap() {
                let p = e.unwrap().path();
                if p.is_dir() { stack.push(p) } else { files.push(p) }
            }
        }
        files.sort();
        for f in files {
            let rel = f.strip_prefix(&dist).unwrap().to_string_lossy().replace('\\', "/");
            let ctype = match f.extension().and_then(|e| e.to_str()).unwrap_or("") {
                "html" => "text/html; charset=utf-8",
                "js" | "mjs" => "text/javascript",
                "css" => "text/css",
                "svg" => "image/svg+xml",
                "json" | "webmanifest" => "application/json",
                "png" => "image/png",
                "ico" => "image/x-icon",
                "woff2" => "font/woff2",
                "txt" => "text/plain; charset=utf-8",
                _ => "application/octet-stream",
            };
            let _ = writeln!(src, "    Asset {{ path: {:?}, ctype: {:?}, body: include_bytes!({:?}) }},", rel, ctype, f.display().to_string());
        }
    }
    src.push_str("];\n");
    std::fs::write(out, src).unwrap();
}

// ADR 0049 D1 — the OPERATOR's POLICY.TXT signing key, baked into the (boot-signed) image by the factory:
// HEQK_POLICY_PUBKEY = 64 hex chars (Ed25519 public key); HEQK_POLICY_GEN_FLOOR = minimum generation.
// Unset = a standalone image (unsigned POLICY.TXT accepted). A malformed key FAILS the build (never a
// silently unsigned image when the operator asked for signing).
fn gen_policy_key(out_dir: &str) {
    println!("cargo:rerun-if-env-changed=HEQK_POLICY_PUBKEY");
    println!("cargo:rerun-if-env-changed=HEQK_POLICY_GEN_FLOOR");
    let key = match std::env::var("HEQK_POLICY_PUBKEY") {
        Ok(h) if !h.trim().is_empty() => {
            let h = h.trim();
            assert!(h.len() == 64 && h.bytes().all(|c| c.is_ascii_hexdigit()), "HEQK_POLICY_PUBKEY must be 64 hex chars");
            let b: Vec<String> = (0..32).map(|i| format!("0x{}", &h[i * 2..i * 2 + 2])).collect();
            format!("Some([{}])", b.join(", "))
        }
        _ => "None".to_string(),
    };
    let floor: u64 = std::env::var("HEQK_POLICY_GEN_FLOOR").ok().map(|v| v.trim().parse().expect("HEQK_POLICY_GEN_FLOOR: u64")).unwrap_or(0);
    let src = format!("pub const POLICY_PUBKEY: Option<[u8; 32]> = {key};\npub const POLICY_GEN_FLOOR: u64 = {floor};\n");
    std::fs::write(std::path::Path::new(out_dir).join("policy_key.rs"), src).expect("write policy_key.rs");
}
