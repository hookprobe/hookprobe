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
}
