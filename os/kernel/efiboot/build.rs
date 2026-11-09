// HEQK_IMAGE=<raw heqk kernel binary> embeds a payload and turns efiboot from the read-only
// probe into a loader (cfg `heqk_payload`). Unset -> probe only (nothing to load).
fn main() {
    println!("cargo::rustc-check-cfg=cfg(heqk_payload)");
    println!("cargo:rerun-if-env-changed=HEQK_IMAGE");
    if let Ok(p) = std::env::var("HEQK_IMAGE") {
        let p = std::fs::canonicalize(&p).expect("HEQK_IMAGE: no such file");
        println!("cargo:rerun-if-changed={}", p.display());
        println!("cargo:rustc-env=HEQK_IMAGE_PATH={}", p.display());
        println!("cargo:rustc-cfg=heqk_payload");
    }
}
