fn main() {
    let dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let script = if std::env::var("CARGO_FEATURE_CM5").is_ok() { "link-cm5.ld" } else { "link.ld" };
    println!("cargo:rustc-link-arg=-T{dir}/{script}");
    println!("cargo:rustc-link-arg=--gc-sections");
    println!("cargo:rerun-if-changed=link.ld");
    println!("cargo:rerun-if-changed=link-cm5.ld");
}
