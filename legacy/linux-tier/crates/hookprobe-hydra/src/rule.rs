//! HYDRA's reserved `rule_id` band (ADR 0027 D-numbering).
//!
//! Every other engine in this workspace uses a small, hand-enumerated `rule_id` per FIXED
//! detection (NAPSE `1,000,001`–`1,000,025` + `napse-capture`'s `1,000,003/012/013/014/030–033/
//! 040/041`; `hookprobe_evidence::host_edr` `1,000,100`–`1,000,118`; the resource-shed `1,000,050`;
//! the supply-chain bands `9,1xx,xxx`/`9,2xx,xxx`; Sigma `2,000,000,000+`; YARA `3,000,000,000+` —
//! all checked against the tree, 2026-07-08, see `docs/adr/0026-sigma-yara-detection.md` §D5).
//!
//! HYDRA's indicators are open-ended and pluggable (any bundled feed's IP/domain/hash/JA3 value),
//! not a fixed enum — exactly the same shape Sigma/YARA rules are, which is why this reserves its
//! OWN numeric space **one band above YARA's**, using the SAME FNV-1a-then-mask idiom
//! `hookprobe_evidence::sid()`/Sigma/YARA already use for deterministic, collision-free-in-practice
//! ids: **`4,000,000,000 + (fnv1a(indicator_value) & 0x0FFFFFFF)`**. Deterministic per indicator
//! value — the same indicator always gets the same `rule_id`, so `hookprobe-evidence --stats`'s
//! per-rule_id breakdown groups repeat sightings of the SAME indicator together, exactly like
//! Sigma/YARA's own per-rule ids do for repeat rule fires.
pub const HYDRA_RULE_ID_BASE: i64 = 4_000_000_000;

/// FNV-1a 64-bit — the SAME fixed algorithm `hookprobe_evidence::sid()` uses (deterministic across
/// a Rust-toolchain rebuild; `std`'s `DefaultHasher` is explicitly NOT stable across releases and
/// would silently break rule_id stability across a version bump). Reimplemented here rather than
/// imported: this is a small, independent idiom each engine (Sigma/YARA/HYDRA) applies to ITS OWN
/// identifying string, not shared state — see ADR 0026 §D5's identical reasoning for Sigma/YARA.
fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in bytes {
        h ^= *b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

/// Deterministic `rule_id` for one indicator VALUE (not its type/family — the same IP seen as
/// both `ip` type here and, hypothetically, re-tagged later keeps the same id, since it's the
/// same real-world indicator). Masked to 28 bits so `HYDRA_RULE_ID_BASE + mask` never overflows
/// into the NEXT reserved band (`0x0FFFFFFF` = 268,435,455 < `1,000,000,000`, matching Sigma/
/// YARA's own mask width exactly).
pub fn hydra_rule_id(indicator_value: &str) -> i64 {
    HYDRA_RULE_ID_BASE + (fnv1a64(indicator_value.as_bytes()) & 0x0FFF_FFFF) as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hydra_rule_id_is_deterministic_and_in_band() {
        let a = hydra_rule_id("162.243.103.246");
        let b = hydra_rule_id("162.243.103.246");
        assert_eq!(a, b, "same indicator value -> same rule_id, every call");
        assert!(a >= HYDRA_RULE_ID_BASE, "never below the reserved band floor");
        assert!(a < HYDRA_RULE_ID_BASE + 0x1000_0000, "never spills into the next band");
    }

    #[test]
    fn hydra_rule_id_differs_per_indicator_in_practice() {
        let ip = hydra_rule_id("162.243.103.246");
        let domain = hydra_rule_id("hookprobe-ioc-test.invalid");
        let hash = hydra_rule_id("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f");
        assert_ne!(ip, domain);
        assert_ne!(domain, hash);
        assert_ne!(ip, hash);
    }

    #[test]
    fn hydra_band_does_not_collide_with_any_other_reserved_band() {
        // Every other reserved band this workspace's tree carries, as of 2026-07-08 (see this
        // module's doc comment for the full audit) — a HYDRA id must never fall inside any of them.
        let hydra = hydra_rule_id("some-indicator-value");
        assert!(!(1_000_000..1_000_200).contains(&hydra), "napse/host-edr/resource-shed band");
        assert!(!(9_100_000..9_300_000).contains(&hydra), "supply-chain bands");
        assert!(!(2_000_000_000..3_000_000_000).contains(&hydra), "Sigma's band");
        assert!(!(3_000_000_000..4_000_000_000).contains(&hydra), "YARA's band");
        assert!(hydra >= 4_000_000_000, "HYDRA's own band floor");
    }
}
