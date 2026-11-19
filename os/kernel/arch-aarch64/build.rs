// SPDX-License-Identifier: AGPL-3.0-only
//! ADR 0065 step 4g S3d: `el0_keys` = the `el0-keys` AND `wpa3` features. In such a build every Wi-Fi key (PMK, SAE PT,
//! PTK, GTK, IGTK) is made and kept by el0-wpa: the in-kernel authenticator, SAE responder and group-key generation are
//! not compiled in (the kernel never holds a derived key — operator decision 2026-11-15, design D-b).
fn main() {
    println!("cargo:rustc-check-cfg=cfg(el0_keys)");
    if std::env::var_os("CARGO_FEATURE_EL0_KEYS").is_some() && std::env::var_os("CARGO_FEATURE_WPA3").is_some() {
        println!("cargo:rustc-cfg=el0_keys");
    }
}
