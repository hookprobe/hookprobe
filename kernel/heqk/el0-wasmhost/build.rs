// Pass the fixed-VA EL0 link map to the final link, as an ABSOLUTE path so the nested
// build (invoked by the kernel's build.rs from an arbitrary CWD) always resolves it.
fn main() {
    let dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    // M5.5 — the CM5 sync-excursion build (`syncabi`) links at the GB5 EL0 user window
    // (0x1_4000_0000, mmu_cm5's single-AS 2 MiB window) instead of the QEMU 0x9000_0000 map,
    // so the whole image fits one L3 table the CM5 mapper can reach. Same 3-PT_LOAD layout.
    let script = if std::env::var("CARGO_FEATURE_SYNCABI").is_ok() { "link-cm5.ld" } else { "link.ld" };
    println!("cargo:rustc-link-arg=-T{dir}/{script}");
    println!("cargo:rustc-link-arg=--gc-sections");
    println!("cargo:rerun-if-changed=link.ld");
    println!("cargo:rerun-if-changed=link-cm5.ld");
}
