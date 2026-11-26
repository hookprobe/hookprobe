// SPDX-License-Identifier: AGPL-3.0-only
// m5probe is linked at 0 as a PIE and applies its own R_AARCH64_RELATIVE relocations at entry
// (src/entry.s), so U-Boot's booti may place it at any 2 MiB-aligned address (kernel_addr_r
// differs between the M5 and QEMU). --apply-dynamic-relocs also writes the link-time values into
// the file, so the Image header fields read by U-Boot before relocation are correct.
fn main() {
    let dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    println!("cargo:rustc-link-arg-bin=m5probe=-T{dir}/linker.ld");
    println!("cargo:rustc-link-arg-bin=m5probe=--pie");
    println!("cargo:rustc-link-arg-bin=m5probe=--no-dynamic-linker");
    println!("cargo:rustc-link-arg-bin=m5probe=--apply-dynamic-relocs");
    println!("cargo:rustc-link-arg-bin=m5probe=-znotext");
    println!("cargo:rerun-if-changed=linker.ld");
    println!("cargo:rerun-if-changed=src/entry.s");
}
