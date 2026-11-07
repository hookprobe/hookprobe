//! The matcher (ADR 0027): feed indicator × real evidence-graph data → an enriched detection.
//!
//! `scan_flow_candidates` is the LIVE path — matches IP/domain/JA3/JA4/JA4S indicators against
//! `hookprobe_evidence::EvidenceGraph::ioc_flow_candidates`'s output (every flow since HYDRA's own
//! watermark, plus whatever SNI/HTTP-Host/JA3/JA4/JA4S the SAME flow's Application pivot resolved).
//! `scan_file_candidates` (2026-07-09) is the file-hash counterpart — matches every file-write
//! event carrying a real `sha256` (`hookprobe_evidence::EvidenceGraph::ioc_file_candidates`)
//! against `match_hash`, which used to be the TYPE-COMPLETE-BUT-NOT-LIVE-WIRED path (no host event
//! carried a file hash) and is now called from `main.rs`'s live pass alongside the flow scan.
use std::collections::HashSet;

use serde::Deserialize;

use crate::feed::{Indicator, IocFeed, IocType};
use crate::rule::hydra_rule_id;

/// One flow (+ resolved Application pivot) candidate, exactly as
/// `hookprobe_evidence::EvidenceGraph::ioc_flow_candidates` serializes it.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct FlowCandidate {
    pub ts: f64,
    pub src_ip: String,
    pub dst_ip: String,
    pub dst_port: i64,
    #[serde(default)]
    pub sni: String,
    #[serde(default)]
    pub http_host: String,
    #[serde(default)]
    pub ja3: String,
    /// The modern FoxIO JA4 TLS-CLIENT fingerprint (2026-07-09) — empty when the flow's
    /// Application pivot never resolved a ClientHello (or resolved one before this field existed).
    #[serde(default)]
    pub ja4: String,
    /// The JA4S TLS-SERVER fingerprint — empty when no ServerHello was captured for this flow (see
    /// `napse_loader::dpi::parse_tls_server_hello`'s doc comment on when/why it may be missing even
    /// for a real TLS connection).
    #[serde(default)]
    pub ja4s: String,
}

/// One host file-write event carrying a real content hash, exactly as
/// `hookprobe_evidence::EvidenceGraph::ioc_file_candidates` serializes it.
#[derive(Debug, Clone, Deserialize)]
pub struct FileCandidate {
    pub ts: f64,
    pub device_ip: String,
    pub sha256: String,
}

/// One confirmed indicator match — everything [`Hit::to_ioc_match_json`] needs to render the exact
/// JSON line `hookprobe_evidence::EvidenceGraph::ingest_ioc_match` expects.
#[derive(Debug, Clone)]
pub struct Hit {
    pub ts: f64,
    /// Which field of the candidate matched: `"src_ip"`/`"dst_ip"`/`"sni"`/`"http_host"`/`"ja3"`/
    /// `"ja4"`/`"ja4s"`/`"sha256"`. Carried through into the rendered `rule_msg` — never hidden
    /// from the operator.
    pub matched_field: &'static str,
    pub src_ip: String,
    pub dst_ip: String,
    pub dst_port: i64,
    pub indicator: Indicator,
}

impl Hit {
    /// `1` (`confidence < 0.5`) / `2` (`< 0.85`) / `3` (`>= 0.85`) — the SAME 3-tier severity
    /// banding every other producer in this workspace applies to its own confidence/score value
    /// (see `ingest_dns_verdict`'s `verdict == "malicious"` 2-tier split, `ingest_aegis_verdict`'s
    /// level→severity map): never a made-up 1–10 scale, just this crate's own honest tri-level cut.
    pub fn severity(&self) -> i64 {
        if self.indicator.confidence >= 0.85 {
            3
        } else if self.indicator.confidence >= 0.5 {
            2
        } else {
            1
        }
    }

    fn rule_msg(&self) -> String {
        let family = if self.indicator.family.is_empty() { "unknown" } else { &self.indicator.family };
        let source = if self.indicator.source.is_empty() { "unspecified" } else { &self.indicator.source };
        format!(
            "HYDRA IOC match: {} ({}, family={family}, source={source}) via {}",
            self.indicator.value,
            self.indicator.ioc_type.as_str(),
            self.matched_field,
        )
    }

    /// The exact JSON line `hookprobe_evidence::EvidenceGraph::ingest_ioc_match` reads: the SAME
    /// detection-shaped fields `ingest_detection` already understands
    /// (`rule_id`/`rule_msg`/`category`/`severity`/`mitre`/`src_ip`/`dst_ip`/`dst_port`/
    /// `confidence`) plus HYDRA's own `indicator`/`ioc_type`/`ioc_family` extras.
    pub fn to_ioc_match_json(&self) -> String {
        serde_json::json!({
            "ts": self.ts,
            "rule_id": hydra_rule_id(&self.indicator.value),
            "rule_msg": self.rule_msg(),
            "category": "threat_intel",
            "severity": self.severity(),
            "mitre": self.indicator.mitre,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "dst_port": self.dst_port,
            "confidence": self.indicator.confidence,
            "indicator": self.indicator.value,
            "ioc_type": self.indicator.ioc_type.as_str(),
            "ioc_family": self.indicator.family,
        })
        .to_string()
    }
}

/// The live matcher: scan every flow candidate for an IP (either direction), domain (SNI or
/// HTTP-Host), or JA3 match. A flow can produce MORE THAN ONE `Hit` (e.g. its dst_ip AND its SNI
/// both happen to be listed) — every real match is surfaced, never silently deduped away.
///
/// **Attribution convention (mirrors the existing NAPSE/dnsxai shapes, never invented):**
/// - **outbound** IP match (`dst_ip` is the indicator): `src_ip` = the LAN device that connected
///   OUT, `dst_ip` = the matched indicator — the SAME shape `1_000_040` (C2 beaconing) already uses.
/// - **inbound** IP match (`src_ip` is the indicator): `src_ip` = the attacker, `dst_ip` = the
///   LAN device targeted — the SAME shape `1_000_003`/`1_000_001` (port-scan/brute-force) use.
/// - **domain** match: the domain value rides in `dst_ip` — the SAME convention
///   `ingest_dns_verdict` already uses for a DNS-layer domain detection.
/// - **JA3/JA4/JA4S** match: `dst_ip`/`dst_port` stay the flow's real destination (none of the
///   three is itself an address); the fingerprint rides in `indicator`/`rule_msg` only. Kept as
///   THREE independent checks (not a single "any TLS fingerprint" loop) so a flow whose JA3 AND
///   JA4 both happen to be listed produces two distinct `Hit`s — the SAME "every real match
///   surfaces, never silently deduped" discipline this function's own doc already states.
pub fn scan_flow_candidates(feed: &IocFeed, candidates: &[FlowCandidate]) -> Vec<Hit> {
    let mut hits = Vec::new();
    for c in candidates {
        if !c.dst_ip.is_empty() {
            if let Some(ind) = feed.lookup(&c.dst_ip) {
                if ind.ioc_type == IocType::Ip {
                    hits.push(Hit {
                        ts: c.ts,
                        matched_field: "dst_ip",
                        src_ip: c.src_ip.clone(),
                        dst_ip: c.dst_ip.clone(),
                        dst_port: c.dst_port,
                        indicator: ind.clone(),
                    });
                }
            }
        }
        if !c.src_ip.is_empty() {
            if let Some(ind) = feed.lookup(&c.src_ip) {
                if ind.ioc_type == IocType::Ip {
                    hits.push(Hit {
                        ts: c.ts,
                        matched_field: "src_ip",
                        src_ip: c.src_ip.clone(),
                        dst_ip: c.dst_ip.clone(),
                        dst_port: c.dst_port,
                        indicator: ind.clone(),
                    });
                }
            }
        }
        let mut seen_domains: HashSet<&str> = HashSet::new();
        for (field_name, domain) in [("sni", c.sni.as_str()), ("http_host", c.http_host.as_str())] {
            if domain.is_empty() || !seen_domains.insert(domain) {
                continue;
            }
            if let Some(ind) = feed.lookup(domain) {
                if ind.ioc_type == IocType::Domain {
                    hits.push(Hit {
                        ts: c.ts,
                        matched_field: field_name,
                        src_ip: c.src_ip.clone(),
                        dst_ip: domain.to_string(),
                        dst_port: c.dst_port,
                        indicator: ind.clone(),
                    });
                }
            }
        }
        if !c.ja3.is_empty() {
            if let Some(ind) = feed.lookup(&c.ja3) {
                if ind.ioc_type == IocType::Ja3 {
                    hits.push(Hit {
                        ts: c.ts,
                        matched_field: "ja3",
                        src_ip: c.src_ip.clone(),
                        dst_ip: c.dst_ip.clone(),
                        dst_port: c.dst_port,
                        indicator: ind.clone(),
                    });
                }
            }
        }
        // 2026-07-09 detection-surface expansion: the modern JA4 (TLS client) / JA4S (TLS server)
        // fingerprints, matched the SAME way JA3 is above — a distinct field, a distinct `IocType`,
        // the flow's real destination kept in dst_ip/dst_port.
        if !c.ja4.is_empty() {
            if let Some(ind) = feed.lookup(&c.ja4) {
                if ind.ioc_type == IocType::Ja4 {
                    hits.push(Hit {
                        ts: c.ts,
                        matched_field: "ja4",
                        src_ip: c.src_ip.clone(),
                        dst_ip: c.dst_ip.clone(),
                        dst_port: c.dst_port,
                        indicator: ind.clone(),
                    });
                }
            }
        }
        if !c.ja4s.is_empty() {
            if let Some(ind) = feed.lookup(&c.ja4s) {
                if ind.ioc_type == IocType::Ja4s {
                    hits.push(Hit {
                        ts: c.ts,
                        matched_field: "ja4s",
                        src_ip: c.src_ip.clone(),
                        dst_ip: c.dst_ip.clone(),
                        dst_port: c.dst_port,
                        indicator: ind.clone(),
                    });
                }
            }
        }
    }
    hits
}

/// The file-hash counterpart to [`scan_flow_candidates`] (2026-07-09): every real (non-empty)
/// `sha256` candidate matched via [`match_hash`], every real match surfaced (a device can legitimately
/// see more than one malware-hash IOC file drop in one HYDRA pass — no arbitrary "first match only").
pub fn scan_file_candidates(feed: &IocFeed, candidates: &[FileCandidate]) -> Vec<Hit> {
    candidates
        .iter()
        .filter_map(|c| match_hash(feed, &c.sha256, c.ts, &c.device_ip))
        .collect()
}

/// Match one host-event file hash against the feed. **Live-wired as of 2026-07-09** — called from
/// [`scan_file_candidates`], which `main.rs`'s live pass now runs alongside the flow scan, fed by
/// `hookprobe_evidence::EvidenceGraph::ioc_file_candidates` (`files.sha256`, populated by
/// `hookprobe-fanotify`'s content-hash-on-write). Before this the `files` table carried no hash
/// column at all — see ADR 0027's original honest-limits note, now closed.
pub fn match_hash(feed: &IocFeed, sha256: &str, ts: f64, device_ip: &str) -> Option<Hit> {
    let ind = feed.lookup(sha256)?;
    if ind.ioc_type != IocType::Sha256 {
        return None;
    }
    Some(Hit {
        ts,
        matched_field: "sha256",
        src_ip: device_ip.to_string(),
        dst_ip: sha256.to_string(),
        dst_port: 0,
        indicator: ind.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn feed() -> IocFeed {
        IocFeed::parse(
            r#"{
                "format": "hookprobe-ioc-v1", "generated": "2026-07-08", "source_summary": "test",
                "indicators": [
                    {"value":"162.243.103.246","ioc_type":"ip","family":"Emotet","source":"abuse.ch","confidence":0.9,"active":true,"mitre":"T1071.001"},
                    {"value":"evil-c2.example","ioc_type":"domain","family":"CobaltStrike","source":"test","confidence":0.8,"active":true},
                    {"value":"e7d705a3286e19ea42f587b344ee6865","ioc_type":"ja3","family":"canary","source":"test","confidence":0.7,"active":true},
                    {"value":"275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f","ioc_type":"sha256","family":"eicar","source":"test","confidence":1.0,"active":true},
                    {"value":"9.9.9.9","ioc_type":"ip","family":"retired","source":"test","confidence":0.4,"active":false},
                    {"value":"t13d0204h2_62ed6f6ca7ad_3953dc75acc4","ioc_type":"ja4","family":"c2-client","source":"test","confidence":0.8,"active":true},
                    {"value":"t1303h2_1302_02a34fb8a812","ioc_type":"ja4s","family":"c2-server","source":"test","confidence":0.75,"active":true}
                ]
            }"#,
        )
        .unwrap()
    }

    fn candidate(src: &str, dst: &str, port: i64, sni: &str, http_host: &str, ja3: &str) -> FlowCandidate {
        FlowCandidate {
            ts: 1500.0,
            src_ip: src.to_string(),
            dst_ip: dst.to_string(),
            dst_port: port,
            sni: sni.to_string(),
            http_host: http_host.to_string(),
            ja3: ja3.to_string(),
            ..Default::default()
        }
    }

    fn candidate_ja4(src: &str, dst: &str, port: i64, ja4: &str, ja4s: &str) -> FlowCandidate {
        FlowCandidate {
            ts: 1500.0,
            src_ip: src.to_string(),
            dst_ip: dst.to_string(),
            dst_port: port,
            ja4: ja4.to_string(),
            ja4s: ja4s.to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn outbound_ip_match_attributes_our_device_as_src_and_indicator_as_dst() {
        let hits = scan_flow_candidates(&feed(), &[candidate("10.66.0.5", "162.243.103.246", 8080, "", "", "")]);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].matched_field, "dst_ip");
        assert_eq!(hits[0].src_ip, "10.66.0.5");
        assert_eq!(hits[0].dst_ip, "162.243.103.246");
        assert_eq!(hits[0].indicator.family, "Emotet");
        assert_eq!(hits[0].severity(), 3); // confidence 0.9 -> tier 3
    }

    #[test]
    fn inbound_ip_match_attributes_attacker_as_src_and_our_device_as_dst() {
        let hits = scan_flow_candidates(&feed(), &[candidate("162.243.103.246", "10.66.0.9", 445, "", "", "")]);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].matched_field, "src_ip");
        assert_eq!(hits[0].src_ip, "162.243.103.246");
        assert_eq!(hits[0].dst_ip, "10.66.0.9");
    }

    #[test]
    fn domain_match_via_sni_rides_in_dst_ip_the_same_convention_ingest_dns_verdict_uses() {
        let hits = scan_flow_candidates(&feed(), &[candidate("10.66.0.5", "104.20.20.20", 443, "evil-c2.example", "", "")]);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].matched_field, "sni");
        assert_eq!(hits[0].dst_ip, "evil-c2.example", "the matched domain, not the flow's real IP");
        assert_eq!(hits[0].indicator.family, "CobaltStrike");
    }

    #[test]
    fn domain_match_via_http_host_also_fires() {
        let hits = scan_flow_candidates(&feed(), &[candidate("10.66.0.5", "104.20.20.20", 80, "", "evil-c2.example", "")]);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].matched_field, "http_host");
    }

    #[test]
    fn ja3_match_fires_with_the_flows_real_destination_kept() {
        let hits = scan_flow_candidates(
            &feed(),
            &[candidate("10.66.0.5", "203.0.113.9", 443, "", "", "e7d705a3286e19ea42f587b344ee6865")],
        );
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].matched_field, "ja3");
        assert_eq!(hits[0].dst_ip, "203.0.113.9", "ja3 isn't itself an address — the real dst_ip stays");
    }

    #[test]
    fn benign_flow_produces_no_hits() {
        let hits = scan_flow_candidates(&feed(), &[candidate("10.66.0.5", "8.8.8.8", 443, "example.com", "", "")]);
        assert!(hits.is_empty());
    }

    #[test]
    fn retired_inactive_indicator_never_fires_even_on_an_exact_value_match() {
        let hits = scan_flow_candidates(&feed(), &[candidate("10.66.0.5", "9.9.9.9", 443, "", "", "")]);
        assert!(hits.is_empty(), "active:false must never produce an alert");
    }

    #[test]
    fn a_flow_can_produce_more_than_one_hit_when_more_than_one_field_matches() {
        let hits = scan_flow_candidates(
            &feed(),
            &[candidate("10.66.0.5", "162.243.103.246", 443, "evil-c2.example", "", "")],
        );
        assert_eq!(hits.len(), 2, "both the dst_ip AND the sni matched — neither is silently dropped");
    }

    #[test]
    fn match_hash_fires_on_the_bundled_eicar_canary_and_ignores_wrong_type() {
        let f = feed();
        let hit = match_hash(&f, "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", 100.0, "10.66.0.5")
            .expect("the bundled EICAR sha256 canary matches");
        assert_eq!(hit.matched_field, "sha256");
        assert_eq!(hit.indicator.family, "eicar");
        // a value that IS in the feed but under a DIFFERENT type must not cross-fire as a hash hit.
        assert!(match_hash(&f, "162.243.103.246", 100.0, "10.66.0.5").is_none());
        assert!(match_hash(&f, "not-in-the-feed", 100.0, "10.66.0.5").is_none());
    }

    // ---- 2026-07-09 detection-surface expansion: JA4/JA4S flow matching + file-hash scanning ----

    #[test]
    fn ja4_match_fires_with_the_flows_real_destination_kept() {
        let hits = scan_flow_candidates(
            &feed(),
            &[candidate_ja4("10.66.0.5", "203.0.113.9", 443, "t13d0204h2_62ed6f6ca7ad_3953dc75acc4", "")],
        );
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].matched_field, "ja4");
        assert_eq!(hits[0].dst_ip, "203.0.113.9", "ja4 isn't itself an address — the real dst_ip stays");
        assert_eq!(hits[0].indicator.family, "c2-client");
    }

    #[test]
    fn ja4s_match_fires_independently_of_ja4() {
        let hits = scan_flow_candidates(
            &feed(),
            &[candidate_ja4("10.66.0.5", "203.0.113.9", 443, "", "t1303h2_1302_02a34fb8a812")],
        );
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].matched_field, "ja4s");
        assert_eq!(hits[0].indicator.family, "c2-server");
    }

    #[test]
    fn a_flow_with_both_ja4_and_ja4s_listed_produces_two_hits() {
        let hits = scan_flow_candidates(
            &feed(),
            &[candidate_ja4(
                "10.66.0.5", "203.0.113.9", 443,
                "t13d0204h2_62ed6f6ca7ad_3953dc75acc4", "t1303h2_1302_02a34fb8a812",
            )],
        );
        assert_eq!(hits.len(), 2, "both JA4 and JA4S matched — neither is silently dropped");
        let fields: HashSet<&str> = hits.iter().map(|h| h.matched_field).collect();
        assert!(fields.contains("ja4") && fields.contains("ja4s"));
    }

    #[test]
    fn a_ja3_only_feed_entry_never_cross_fires_as_a_ja4_hit_even_on_the_same_flow() {
        // The JA3 canary and the JA4 canary in `feed()` are DIFFERENT string values on purpose —
        // this proves type-tagging (not just string equality) gates the match: a flow whose ja4
        // field happens to equal some OTHER indicator's ja3 value must not fire.
        let hits = scan_flow_candidates(
            &feed(),
            &[candidate_ja4("10.66.0.5", "203.0.113.9", 443, "e7d705a3286e19ea42f587b344ee6865", "")],
        );
        assert!(hits.is_empty(), "a ja3-typed indicator value placed in the ja4 field must not fire");
    }

    fn file_candidate(device_ip: &str, sha256: &str) -> FileCandidate {
        FileCandidate { ts: 900.0, device_ip: device_ip.to_string(), sha256: sha256.to_string() }
    }

    #[test]
    fn scan_file_candidates_fires_on_the_bundled_eicar_canary() {
        let hits = scan_file_candidates(
            &feed(),
            &[file_candidate("10.66.0.9", "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")],
        );
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].matched_field, "sha256");
        assert_eq!(hits[0].src_ip, "10.66.0.9");
        assert_eq!(hits[0].dst_ip, "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f");
        assert_eq!(hits[0].indicator.family, "eicar");
    }

    #[test]
    fn scan_file_candidates_surfaces_every_match_and_skips_benign_files() {
        let hits = scan_file_candidates(
            &feed(),
            &[
                file_candidate("10.66.0.9", "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"),
                file_candidate("10.66.0.9", "0000000000000000000000000000000000000000000000000000000000000000"),
                file_candidate("10.66.0.10", "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"),
            ],
        );
        assert_eq!(hits.len(), 2, "the two eicar-hash file drops fire, the benign one doesn't");
        assert!(hits.iter().all(|h| h.matched_field == "sha256"));
    }

    #[test]
    fn to_ioc_match_json_round_trips_the_fields_ingest_ioc_match_reads() {
        let hits = scan_flow_candidates(&feed(), &[candidate("10.66.0.5", "162.243.103.246", 8080, "", "", "")]);
        let line = hits[0].to_ioc_match_json();
        let v: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(v["indicator"], "162.243.103.246");
        assert_eq!(v["ioc_type"], "ip");
        assert_eq!(v["ioc_family"], "Emotet");
        assert_eq!(v["category"], "threat_intel");
        assert_eq!(v["src_ip"], "10.66.0.5");
        assert_eq!(v["dst_ip"], "162.243.103.246");
        assert!(v["rule_id"].as_i64().unwrap() >= crate::rule::HYDRA_RULE_ID_BASE);
    }

    /// roadmap-B activation proof (audit GAP-1): the OTHER matcher tests use the synthetic `feed()`
    /// fixture — this one loads the REAL SHIPPED seed feed and proves a JA4/JA4S flow fires a hit
    /// against it. Before GAP-1 the shipped feed carried zero ja4/ja4s indicators, so this test
    /// would have returned no hits even though every unit of matcher logic passed. It is the
    /// end-to-end guard that the compute→feed→match pipeline is actually connected in production.
    #[test]
    fn the_real_shipped_feed_fires_on_the_ja4_and_ja4s_canaries() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../security/threat-intel/snapshots/ioc-feed-2026-07-08.json");
        let feed = crate::feed::IocFeed::load(&path).expect("the shipped seed feed must parse");

        let ja4_hits = scan_flow_candidates(
            &feed,
            &[candidate_ja4("10.66.0.5", "203.0.113.9", 443, "t13d0204h2_62ed6f6ca7ad_3953dc75acc4", "")],
        );
        assert_eq!(ja4_hits.len(), 1, "the shipped feed's ja4 canary must fire");
        assert_eq!(ja4_hits[0].matched_field, "ja4");

        let ja4s_hits = scan_flow_candidates(
            &feed,
            &[candidate_ja4("10.66.0.5", "203.0.113.9", 443, "", "t1303h2_1302_02a34fb8a812")],
        );
        assert_eq!(ja4s_hits.len(), 1, "the shipped feed's ja4s canary must fire");
        assert_eq!(ja4s_hits[0].matched_field, "ja4s");
    }
}
