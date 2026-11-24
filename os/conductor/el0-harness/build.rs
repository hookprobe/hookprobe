// SPDX-License-Identifier: AGPL-3.0-only
fn main() {
    let dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    println!("cargo:rustc-link-arg=-T{dir}/link.ld");
    println!("cargo:rustc-link-arg=-zmax-page-size=4096");
    println!("cargo:rustc-link-arg=--gc-sections");
    println!("cargo:rerun-if-changed=link.ld");
}
