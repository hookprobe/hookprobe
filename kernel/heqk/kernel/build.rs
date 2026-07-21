// Pass the right linker script to the final link. The `cm5` feature links at
// the Pi firmware's load address (0x80000); default links for QEMU virt.
fn main() {
    let dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let script = if std::env::var("CARGO_FEATURE_CM5").is_ok() {
        "linker-cm5.ld"
    } else {
        "linker.ld"
    };
    println!("cargo:rustc-link-arg=-T{dir}/{script}");
    println!("cargo:rerun-if-changed=linker.ld");
    println!("cargo:rerun-if-changed=linker-cm5.ld");
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_CM5");
}
