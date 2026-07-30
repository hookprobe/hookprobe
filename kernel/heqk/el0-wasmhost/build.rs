// Pass the fixed-VA EL0 link map to the final link, as an ABSOLUTE path so the nested
// build (invoked by the kernel's build.rs from an arbitrary CWD) always resolves it.
fn main() {
    let dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    println!("cargo:rustc-link-arg=-T{dir}/link.ld");
    println!("cargo:rustc-link-arg=--gc-sections");
    println!("cargo:rerun-if-changed=link.ld");
}
