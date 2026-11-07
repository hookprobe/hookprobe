//! The `hookprobe-ioc-v1` feed format (ADR 0027) — see `security/threat-intel/README.md` for the
//! format's justification (a flat STIX/MISP-lite normalization, not either format verbatim).
use std::collections::HashMap;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// The indicator types this feed format supports. An unrecognized `ioc_type` string in the feed is
/// NOT an error — it is skipped at load time with a printed warning (the SAME skip-with-a-reason
/// contract `modules/sigma`/`modules/yara-scan` hold to for their own unsupported constructs),
/// never silently misinterpreted as one of these.
///
/// **2026-07-09 (detection-surface expansion, roadmap item B)**: `Ja4`/`Ja4s` extend the original
/// four (`Ip`/`Domain`/`Sha256`/`Ja3`) — the modern FoxIO JA4+ TLS-fingerprint suite
/// (`napse_loader::dpi` now computes `ja4`/`ja4s` alongside the legacy `ja3`, see that module's
/// doc), so a threat-intel feed that ships modern C2 JA4/JA4S fingerprints (JA3 is increasingly
/// evadable — trivial cipher-list reordering changes it; JA4's canonicalized sort makes it more
/// resilient) can now actually fire. `Ja4h` (the HTTP-client fingerprint) is deliberately NOT added
/// here yet: nothing in this crate's `matcher` module matches against it today (HTTP client
/// fingerprints are a much higher false-positive surface for a THREAT-INTEL feed specifically — the
/// same browser/library produces the same JA4H for benign and malicious traffic alike far more
/// often than a TLS fingerprint does), so adding the enum variant now would be dead code exactly
/// like `match_hash` was before this same change — left as a documented, honest gap.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IocType {
    Ip,
    Domain,
    Sha256,
    Ja3,
    Ja4,
    Ja4s,
}

impl IocType {
    pub fn as_str(&self) -> &'static str {
        match self {
            IocType::Ip => "ip",
            IocType::Domain => "domain",
            IocType::Sha256 => "sha256",
            IocType::Ja3 => "ja3",
            IocType::Ja4 => "ja4",
            IocType::Ja4s => "ja4s",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        match s {
            "ip" => Some(IocType::Ip),
            "domain" => Some(IocType::Domain),
            "sha256" => Some(IocType::Sha256),
            "ja3" => Some(IocType::Ja3),
            "ja4" => Some(IocType::Ja4),
            "ja4s" => Some(IocType::Ja4s),
            _ => None,
        }
    }
}

/// One indicator, exactly as the feed's own JSON shape carries it (see
/// `security/threat-intel/README.md`'s worked example). `mitre`/`note` are honestly optional —
/// empty string when the feed didn't carry one, never fabricated.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Indicator {
    pub value: String,
    pub ioc_type: IocType,
    #[serde(default)]
    pub family: String,
    #[serde(default)]
    pub source: String,
    #[serde(default)]
    pub confidence: f64,
    #[serde(default)]
    pub first_seen: String,
    #[serde(default = "default_true")]
    pub active: bool,
    #[serde(default)]
    pub mitre: String,
    #[serde(default)]
    pub tlp: String,
    #[serde(default)]
    pub note: String,
}

fn default_true() -> bool {
    true
}

/// The whole bundled feed document + a value-indexed lookup table built once at load time (O(1)
/// matching per flow candidate rather than an O(n) scan of every indicator per flow — the point of
/// indexing, given a device may see thousands of flows per matcher pass).
#[derive(Debug, Clone)]
pub struct IocFeed {
    pub format: String,
    pub generated: String,
    pub source_summary: String,
    pub indicators: Vec<Indicator>,
    /// `value -> index into indicators`, built once. Values are matched byte-exact and
    /// case-preserved (domains/hashes in this v1 feed are already lower-case; see the matcher's own
    /// doc comment for why no case-folding is applied at match time).
    index: HashMap<String, usize>,
}

impl IocFeed {
    /// Parse a `hookprobe-ioc-v1` document. Unrecognized `ioc_type` entries are dropped with a
    /// printed warning (stderr) — never silently miscounted as a supported type, never fatal to the
    /// rest of the feed (one bad entry does not lose every other indicator).
    pub fn parse(json: &str) -> Result<Self> {
        #[derive(Deserialize)]
        struct RawFeed {
            format: String,
            generated: String,
            #[serde(default)]
            source_summary: String,
            indicators: Vec<serde_json::Value>,
        }
        let raw: RawFeed = serde_json::from_str(json).context("parsing hookprobe-ioc-v1 feed JSON")?;
        let mut indicators = Vec::with_capacity(raw.indicators.len());
        for (i, entry) in raw.indicators.into_iter().enumerate() {
            let ioc_type_str = entry["ioc_type"].as_str().unwrap_or("");
            if IocType::parse(ioc_type_str).is_none() {
                eprintln!(
                    "hookprobe-hydra: skipping feed entry #{i} — unrecognized ioc_type {ioc_type_str:?} \
                     (supported: ip, domain, sha256, ja3, ja4, ja4s)"
                );
                continue;
            }
            match serde_json::from_value::<Indicator>(entry) {
                Ok(ind) if ind.value.is_empty() => {
                    eprintln!("hookprobe-hydra: skipping feed entry #{i} — empty indicator value");
                }
                Ok(ind) => indicators.push(ind),
                Err(e) => eprintln!("hookprobe-hydra: skipping feed entry #{i} — malformed ({e})"),
            }
        }
        let mut index = HashMap::with_capacity(indicators.len());
        for (i, ind) in indicators.iter().enumerate() {
            index.entry(ind.value.clone()).or_insert(i);
        }
        Ok(Self { format: raw.format, generated: raw.generated, source_summary: raw.source_summary, indicators, index })
    }

    pub fn load(path: &std::path::Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading bundled IOC feed {path:?}"))?;
        Self::parse(&text)
    }

    /// Exact-value lookup — this v1 feed does no CIDR-range expansion for IPs and no wildcard/
    /// suffix matching for domains (see `security/threat-intel/README.md`'s honest-limits section).
    /// `None` for a value the feed doesn't carry OR a value that matched but is marked `active:
    /// false` upstream — a stale/retired indicator is deliberately NOT fired on (still counted in
    /// `self.indicators` for feed-freshness bookkeeping, just never turned into an alert).
    pub fn lookup(&self, value: &str) -> Option<&Indicator> {
        self.index.get(value).map(|&i| &self.indicators[i]).filter(|ind| ind.active)
    }

    pub fn len(&self) -> usize {
        self.indicators.len()
    }
    pub fn is_empty(&self) -> bool {
        self.indicators.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_feed_json() -> &'static str {
        r#"{
            "format": "hookprobe-ioc-v1",
            "generated": "2026-07-08",
            "source_summary": "test fixture",
            "indicators": [
                {"value":"1.2.3.4","ioc_type":"ip","family":"Emotet","source":"test","confidence":0.9,"first_seen":"2022-01-01","active":true,"mitre":"T1071.001","tlp":"clear"},
                {"value":"stale-bad.example","ioc_type":"domain","family":"Old","source":"test","confidence":0.5,"active":false},
                {"value":"unknowntype.example","ioc_type":"carrier-pigeon","family":"nonsense"},
                {"value":"","ioc_type":"ip","family":"empty-value-skip"}
            ]
        }"#
    }

    #[test]
    fn parses_valid_entries_skips_unrecognized_type_and_empty_value() {
        let feed = IocFeed::parse(sample_feed_json()).unwrap();
        // 4 entries in the doc; 1 unrecognized type + 1 empty value skipped -> 2 real indicators.
        assert_eq!(feed.len(), 2);
        assert_eq!(feed.format, "hookprobe-ioc-v1");
    }

    /// A regression guard on the REAL shipped artifact (`security/threat-intel/snapshots/`), not
    /// just this module's own synthetic fixtures (mirroring `hookprobe-exploit`'s own tests, which
    /// deliberately use SEPARATE synthetic fixtures for unit coverage — see that crate's
    /// `tests/fixtures/` vs `security/exploitability/snapshots/`): if a future edit to the bundled
    /// feed ever breaks its JSON shape or drops below the documented canary set, this test catches
    /// it at `cargo test` time, not on a real device.
    #[test]
    fn the_real_bundled_seed_feed_parses_and_contains_the_documented_canaries() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../security/threat-intel/snapshots/ioc-feed-2026-07-08.json");
        let feed = IocFeed::load(&path).expect("the shipped bundled feed must parse cleanly");
        assert_eq!(feed.format, "hookprobe-ioc-v1");
        assert!(feed.len() >= 9, "3 real Feodo Tracker IPs + 6 HookProbe canary indicators (ip/domain/sha256/ja3/ja4/ja4s)");
        assert!(feed.lookup("hookprobe-ioc-test.invalid").is_some(), "the RFC 2606 domain canary");
        // roadmap-B JA4 activation: the seed MUST ship a ja4 + ja4s canary or the whole
        // compute→match pipeline is data-starved and can never fire in production (audit GAP-1).
        // These values are the repo's own FoxIO golden vectors (dpi.rs reference tests), so the
        // matcher is provably exercised end-to-end against a real computed fingerprint.
        assert!(feed.lookup("t13d0204h2_62ed6f6ca7ad_3953dc75acc4").is_some(), "the ja4 client canary");
        assert!(feed.lookup("t1303h2_1302_02a34fb8a812").is_some(), "the ja4s server canary");
        assert!(
            feed.lookup("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f").is_some(),
            "the EICAR sha256 canary"
        );
        assert!(feed.lookup("50.16.16.211").is_some(), "an active real Feodo Tracker QakBot C2 IP");
        // the offline-status Emotet IP is intentionally `active:false` — it stays IN the feed
        // (feed.len() counts it) but must never fire (see lookup()'s own doc comment).
        assert!(feed.lookup("162.243.103.246").is_none(), "reported offline — kept, but must not fire");
    }

    #[test]
    fn lookup_matches_active_indicators_and_never_fires_a_retired_one() {
        let feed = IocFeed::parse(sample_feed_json()).unwrap();
        let hit = feed.lookup("1.2.3.4").expect("active indicator matches");
        assert_eq!(hit.family, "Emotet");
        assert_eq!(hit.ioc_type, IocType::Ip);

        assert!(feed.lookup("stale-bad.example").is_none(), "active:false must never fire, even though it's IN the feed");
        assert!(feed.lookup("no-such-value.example").is_none());
    }
}
