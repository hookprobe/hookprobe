// SPDX-License-Identifier: AGPL-3.0-only
fn main() {
    let dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let script = if std::env::var("CARGO_FEATURE_CM5").is_ok() { "link-cm5.ld" } else { "link.ld" };
    println!("cargo:rustc-link-arg=-T{dir}/{script}");
    // 4 KiB segments in the FILE too (lld's aarch64 default is 64 KiB: 64 KiB of padding before the first
    // PT_LOAD, embedded in every kernel image). The loader needs only page-aligned vaddrs.
    println!("cargo:rustc-link-arg=-zmax-page-size=4096");
    println!("cargo:rustc-link-arg=--gc-sections");
    println!("cargo:rerun-if-changed=link.ld");
    println!("cargo:rerun-if-changed=link-cm5.ld");
}
