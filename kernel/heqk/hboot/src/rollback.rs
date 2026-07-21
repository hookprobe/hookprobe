//! Anti-rollback security-version floor.
//!
//! HBoot refuses to boot any image whose signed `svn` is below `MIN_SVN`. The
//! floor is embedded in HBoot itself — HBoot is already the root of trust, so
//! an attacker who could rewrite this value has already defeated secure boot.
//!
//! To advance the floor, bump `MIN_SVN`, rebuild + reflash HBoot, and ship
//! images at the new `svn`. Old validly-signed images (lower svn) then refuse
//! to boot — that is the anti-rollback guarantee.
//!
//! Limitation (documented on purpose): this floor is a COMPILE-TIME constant,
//! not a hardware monotonic counter, so advancing it is a manual reflash rather
//! than an automatic per-boot latch. When HBoot grows a secure-storage driver
//! (eMMC RPMB or BCM2712 OTP/eFuse), only the SOURCE of this value changes —
//! the header `svn`, the signature binding, and the `svn >= floor` comparison
//! all stay exactly as they are.

/// Minimum acceptable security version number. Bump when shipping a release
/// that fixes a vulnerability you never want an attacker to roll back past.
pub const MIN_SVN: u64 = 1;
