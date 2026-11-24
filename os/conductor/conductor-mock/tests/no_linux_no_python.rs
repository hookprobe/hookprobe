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
    let banned = ["std::", "extern crate std", "extern crate alloc", "alloc::", "libc", "pthread", "mmap", "/proc", "/dev/", "python", "torch"];
    for (krate, entry) in [("conductor-core", "src/lib.rs"), ("runtime-proof", "src/lib.rs"), ("el0-harness", "src/main.rs"), ("neuro-engine", "src/lib.rs"), ("el0-engine", "src/main.rs")] {
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
