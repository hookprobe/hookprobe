// SPDX-License-Identifier: AGPL-3.0-only
//! Build script: (1) the dev-key fingerprint block-list (os/build/heqk-dev-key-fingerprints.txt, the registry
//! heqk-boot-key-check.sh enforces) compiled in as `DEV_KEY_FPS`, so the stub can report `release=0` when its own
//! trust root is a development key; (2) the bare-metal linker script for the stub binary.
use std::fmt::Write as _;

fn main() {
    let dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let reg = format!("{dir}/../../build/heqk-dev-key-fingerprints.txt");
    println!("cargo:rerun-if-changed={reg}");
    let text = std::fs::read_to_string(&reg).unwrap_or_else(|e| panic!("dev-key registry {reg}: {e} (fail-closed)"));
    let mut out = String::from("/// SHA-256 fingerprints of every development signing key (generated from heqk-dev-key-fingerprints.txt).\npub const DEV_KEY_FPS: &[[u8; 32]] = &[\n");
    let mut n = 0;
    for line in text.lines() {
        let s = line.trim();
        if s.is_empty() || s.starts_with('#') {
            continue;
        }
        let fp = s.split_whitespace().next().unwrap().to_ascii_lowercase();
        assert!(fp.len() == 64 && fp.bytes().all(|b| b.is_ascii_hexdigit()), "bad fingerprint line in {reg}: {s}");
        out.push_str("    [");
        for i in 0..32 {
            write!(out, "0x{},", &fp[2 * i..2 * i + 2]).unwrap();
        }
        out.push_str("],\n");
        n += 1;
    }
    assert!(n > 0, "{reg} lists no fingerprints (fail-closed)");
    out.push_str("];\n");
    std::fs::write(format!("{}/dev_key_fps.rs", std::env::var("OUT_DIR").unwrap()), out).unwrap();

    // The stub image: linked at KERNEL_LOAD_PA like the kernel's HBoot payload (bins only, bare metal only).
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("none") {
        println!("cargo:rustc-link-arg-bins=-T{dir}/linker.ld");
        println!("cargo:rustc-link-arg-bins=--gc-sections");
    }
    println!("cargo:rerun-if-changed=linker.ld");
}
