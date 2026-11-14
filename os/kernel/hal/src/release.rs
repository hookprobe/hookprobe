//! The HookProbe OS release identity: the one source for the kernel boot banner, `/api/system`, `hsh version`
//! and Mission Control (which reads `/api/system`).
//!
//! Version scheme (ADR 0012 amendment, operator 2026-11-14): releases are shown as `v<major>.<minor>-<n>` with a
//! codename, e.g. `v0.0-26 "Zamolxis"`. Cargo and npm need SemVer, so manifests carry the same numbers as
//! `<major>.<minor>.<n>` (`0.0.26`). Cutting a release changes this file and every HookProbe `version` field
//! together; `tools/ci/release_check.py` (gate g0) fails if any of them disagree.

/// Product name.
pub const PRODUCT: &str = "HookProbe OS";
/// Display version, `<major>.<minor>-<n>`.
pub const VERSION: &str = "0.0-26";
/// Release codename.
pub const CODENAME: &str = "Zamolxis";
/// The same release in SemVer form, as written in every Cargo.toml / package.json.
pub const SEMVER: &str = "0.0.26";

const fn bytes_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}

/// `VERSION` and `SEMVER` name the same release: identical except that the last separator is `-` in one and `.`
/// in the other, exactly once.
const fn display_matches_semver(display: &[u8], semver: &[u8]) -> bool {
    if display.len() != semver.len() {
        return false;
    }
    let (mut i, mut swaps) = (0, 0);
    while i < display.len() {
        if display[i] != semver[i] {
            if display[i] == b'-' && semver[i] == b'.' {
                swaps += 1;
            } else {
                return false;
            }
        }
        i += 1;
    }
    swaps == 1
}

// This crate's own Cargo version must be the release SemVer, so a manifest cannot drift from the identity above.
const _: () = assert!(bytes_eq(SEMVER.as_bytes(), env!("CARGO_PKG_VERSION").as_bytes()));
const _: () = assert!(display_matches_semver(VERSION.as_bytes(), SEMVER.as_bytes()));
