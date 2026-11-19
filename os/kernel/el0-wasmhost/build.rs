// SPDX-License-Identifier: AGPL-3.0-only
// Pass the fixed-VA EL0 link map to the final link, as an ABSOLUTE path so the nested
// build (invoked by the kernel's build.rs from an arbitrary CWD) always resolves it.
fn main() {
    let dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    // M5.5 — the CM5 sync-excursion build (`syncabi`) links at the GB5 EL0 user window
    // (0x1_4000_0000, mmu_cm5's single-AS 2 MiB window) instead of the QEMU 0x9000_0000 map,
    // so the whole image fits one L3 table the CM5 mapper can reach. Same 3-PT_LOAD layout.
    let script = if std::env::var("CARGO_FEATURE_SYNCABI").is_ok() { "link-cm5.ld" } else { "link.ld" };
    println!("cargo:rustc-link-arg=-T{dir}/{script}");
    // 4 KiB segments in the FILE too (lld's aarch64 default is 64 KiB: 64 KiB of padding before the first
    // PT_LOAD, embedded in every kernel image). The loader needs only page-aligned vaddrs.
    println!("cargo:rustc-link-arg=-zmax-page-size=4096");
    println!("cargo:rustc-link-arg=--gc-sections");
    println!("cargo:rerun-if-changed=link.ld");
    println!("cargo:rerun-if-changed=link-cm5.ld");
}
