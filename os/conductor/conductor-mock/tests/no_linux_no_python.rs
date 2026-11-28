// SPDX-License-Identifier: AGPL-3.0-only
//! The rule, enforced: nothing here depends on Linux, Python or any ML framework.
//! 1. Every tracked source under os/conductor is Rust (plus manifests, linker scripts, docs).
//! 2. The device-side crates are `no_std` and never name std, alloc, libc or a POSIX API.
//! 3. The device binary's manifest depends only on conductor-core.
use std::path::{Path, PathBuf};

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().to_path_buf()
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    for e in std::fs::read_dir(dir).unwrap().flatten() {
        let p = e.path();
        let name = p.file_name().unwrap().to_string_lossy().to_string();
        if name == "target" || name == ".git" {
            continue;
        }
        if p.is_dir() {
            walk(&p, out);
        } else {
            out.push(p);
        }
    }
}

#[test]
fn only_rust_sources() {
    let mut files = vec![];
    walk(&root(), &mut files);
    let allowed = ["rs", "toml", "lock", "md", "ld"];
    let bad: Vec<_> = files
        .iter()
        .filter(|p| {
            let ext = p.extension().and_then(|e| e.to_str()).unwrap_or("");
            let name = p.file_name().unwrap().to_string_lossy();
            !(allowed.contains(&ext) || name == ".gitignore")
        })
        .collect();
    assert!(bad.is_empty(), "non-Rust files in os/conductor (no Python, no shell, no notebooks): {bad:?}");
}

#[test]
fn device_crates_are_freestanding() {
    let banned = ["f32", "f64", "std::", "extern crate std", "extern crate alloc", "alloc::", "libc", "pthread", "mmap", "/proc", "/dev/", "python", "torch"];
    for (krate, entry) in [("conductor-core", "src/lib.rs"), ("runtime-proof", "src/lib.rs"), ("el0-harness", "src/main.rs"), ("neuro-engine", "src/lib.rs"), ("el0-engine", "src/main.rs"), ("neuro-kernels", "src/lib.rs"), ("neon-proof", "src/main.rs"), ("neuro-hnx", "src/lib.rs"), ("neuro-lm", "src/lib.rs"), ("neuro-gguf", "src/lib.rs"), ("neuro-contract", "src/lib.rs"), ("conductor-p0", "src/lib.rs"), ("engine-entry", "src/lib.rs")] {
        let dir = root().join(krate);
        let head = std::fs::read_to_string(dir.join(entry)).unwrap();
        assert!(head.contains("#![no_std]"), "{krate} must be no_std");
        let mut files = vec![];
        walk(&dir.join("src"), &mut files);
        for f in files {
            for (n, line) in std::fs::read_to_string(&f).unwrap().lines().enumerate() {
                let code = line.split("//").next().unwrap_or("");
                for b in banned {
                    assert!(!code.contains(b), "{}:{}: `{b}` in a device crate", f.display(), n + 1);
                }
            }
        }
    }
}

#[test]
fn device_binary_depends_only_on_conductor_core() {
    let m = std::fs::read_to_string(root().join("el0-harness/Cargo.toml")).unwrap();
    let deps: Vec<&str> = m.split("[dependencies]").nth(1).unwrap().split("\n[").next().unwrap().lines().filter(|l| l.contains('=')).collect();
    assert_eq!(deps.len(), 1, "{deps:?}");
    assert!(deps[0].starts_with("conductor-core") && !deps[0].contains("signer"), "the device binary carries no signing code");
}

/// Crates whose code runs on a compute-role worker core (ADR 0060 S2). Since S1b a worker core has the kernel's
/// `.data` and `.bss` unmapped, so a writable global in any of them is an MMU fault that parks the core.
const WORKER_CORE_CRATES: [&str; 10] = ["neuro-kernels", "neuro-lm", "neuro-contract", "neuro-gguf", "neuro-engine", "neuro-hnx", "conductor-p0", "engine-entry", "conductor-core", "conductor-worker"];

/// Is this line (comments removed) a writable global? Returns what was found.
fn writable_global(code: &str) -> Option<&'static str> {
    for w in ["static mut", "thread_local", "lazy_static", "OnceCell", "OnceLock", "LazyLock", "LazyCell"] {
        if code.contains(w) {
            return Some(w);
        }
    }
    let t = code.trim_start();
    let item = ["static ", "pub static ", "pub(crate) static ", "pub(super) static "].iter().any(|p| t.starts_with(p));
    if item {
        // An immutable `static` lands in `.rodata` unless its type can change behind a shared reference.
        for w in ["Atomic", "Cell", "Mutex", "RwLock"] {
            if t.contains(w) {
                return Some(w);
            }
        }
    }
    None
}

#[test]
fn worker_core_crates_have_no_writable_globals() {
    // The rule recognises what it must refuse, and lets a read-only table through.
    for bad in ["static mut X: u8 = 0;", "    static N: AtomicU32 = AtomicU32::new(0);", "pub static C: Cell<u8> = Cell::new(0);", "pub(crate) static M: Mutex<u8> = Mutex::new(0);", "thread_local! {", "static O: OnceCell<u8> = OnceCell::new();"] {
        assert!(writable_global(bad).is_some(), "{bad}");
    }
    for fine in ["pub static ATTACK_IDS: [u32; 867] = [", "const N: usize = 4;", "fn f(x: &'static [u8]) -> &'static str {", "let cancel = AtomicBool::new(false);", "pub progress: &'a AtomicU32,"] {
        assert!(writable_global(fine).is_none(), "{fine}");
    }
    for krate in WORKER_CORE_CRATES {
        let mut files = vec![];
        walk(&root().join(krate).join("src"), &mut files);
        assert!(!files.is_empty(), "{krate}");
        for f in files {
            for (n, line) in std::fs::read_to_string(&f).unwrap().lines().enumerate() {
                let code = line.split("//").next().unwrap_or("");
                if let Some(w) = writable_global(code) {
                    panic!("{}:{}: `{w}`: a writable global faults on a worker core", f.display(), n + 1);
                }
            }
        }
    }
}

#[test]
fn worker_core_crates_bring_in_no_other_code_with_globals() {
    // Third-party code on this path was read once for writable globals (none on a bare-metal aarch64 target).
    // So the set is pinned: a new dependency, a new version or a new feature has to be read again.
    let allowed = [("sha2", "{ version = \"=0.10.9\", default-features = false }"), ("ed25519-compact", "{ version = \"=2.3.1\", default-features = false }")];
    // sha2 keeps a writable flag (`cpufeatures`: a static AtomicU8) only where it detects CPU features at run
    // time: on aarch64 that is the `asm` feature, which pulls in `sha2-asm`. It must stay off.
    let lock = std::fs::read_to_string(root().join("Cargo.lock")).unwrap();
    assert!(!lock.contains("name = \"sha2-asm\""), "sha2's `asm` feature is on: its feature flag is a writable global");
    for krate in WORKER_CORE_CRATES {
        let m = std::fs::read_to_string(root().join(krate).join("Cargo.toml")).unwrap();
        let deps = m.split("\n[dependencies]").nth(1).map(|d| d.split("\n[").next().unwrap()).unwrap_or("");
        for line in deps.lines().filter(|l| l.contains('=') && !l.trim_start().starts_with('#')) {
            let (name, spec) = line.split_once('=').unwrap();
            let (name, spec) = (name.trim(), spec.trim());
            if spec.contains("path = \"../") {
                let dep = spec.split("path = \"../").nth(1).unwrap().split('"').next().unwrap();
                assert!(WORKER_CORE_CRATES.contains(&dep), "{krate} depends on {dep}, which is not checked for writable globals");
                continue;
            }
            assert!(allowed.iter().any(|(n, s)| *n == name && spec.starts_with(s)), "{krate}: `{line}` is not a reviewed dependency of worker-core code");
        }
    }
}
