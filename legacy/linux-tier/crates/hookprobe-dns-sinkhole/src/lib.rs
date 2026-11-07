//! # `hookprobe-dns-sinkhole` — DNS sinkhole / RPZ enforcement (roadmap A1)
//!
//! **The safest possible attack-block.** Every other enforcement primitive in this workspace
//! (`decide()`/nft quarantine — ADR 0018/0023) drops a *packet*, which risks a genuine customer
//! connection if the classification is ever wrong. This module refuses a *name* instead:
//! per-query, instantly reversible (a TTL expiry or an allowlist edit un-refuses it on the next
//! lookup), and it can NEVER intercept or drop an in-flight legitimate connection — a browser
//! that already resolved a domain and is mid-TLS-handshake is completely unaffected. That is
//! exactly the enforcement-separation invariant (ADR 0023): "a legitimate customer connection
//! must ALWAYS pass." A DNS sinkhole doesn't even get close to that line — it never touches the
//! packet path `decide()`/`hookprobe-manifest::scan_responder`/`napse-quarantine` own.
//!
//! ## Signal sources (both already exist; this module wires their DEAD END to a real effect)
//!
//! 1. **`modules/dnsxai`** — the DGA/tunnel/lookalike classifier's `Verdict::Malicious` output
//!    (V1's `BLOCK_INSTANT` band, score >= 0.60). Today it only reaches
//!    `/var/lib/hookprobe/dns-verdicts` (consumed by `hookprobe-evidence --dns-verdicts` for
//!    investigation) with **zero wire effect** — the domain that scored "malicious" is resolved
//!    exactly like any other. This module is the first consumer that actually acts on it.
//! 2. **`crates/hookprobe-hydra`** — the bundled `hookprobe-ioc-v1` feed's `domain`-typed
//!    indicators (ADR 0027). Reused directly via [`hookprobe_hydra::feed::IocFeed`], never
//!    reimplemented, so this crate can never drift from HYDRA's own load-time rules
//!    (unrecognized `ioc_type` skipped, `active:false` retired-but-kept, empty value skipped).
//!
//! ## FP-safety: the allowlist ALWAYS wins
//!
//! A bad feed entry or an over-eager heuristic must never be able to take out a legitimate
//! domain (imagine a false-positive dictionary-DGA hit on a real corporate domain, or a stale
//! HYDRA IOC that was never retired). [`Allowlist`] is checked LAST, after every source has been
//! merged — see [`build_sinkhole_set`]'s doc. It layers a small built-in safety net
//! ([`BUILTIN_NEVER_SINKHOLE`]) under an operator-owned, never-generated override file
//! (`/etc/hookprobe/dns-sinkhole-allowlist.yaml`).
//!
//! ## Fail toward NOT sinkholing
//!
//! Every parser in this module returns `None`/skips on malformed input rather than panicking or
//! guessing — the same "err toward not dropping" discipline
//! `hookprobe_manifest::scan_responder::decide()` applies to the packet-drop path. An empty or
//! unreadable feed/verdict stream degrades to "sinkhole nothing new," never to a malformed
//! artifact a real resolver might mis-load.
//!
//! ## Honest integration gap
//!
//! This device's actually-wired LAN resolver is **`systemd-resolved`**
//! (`crates/hookprobe-manifest/src/lan.rs`: DHCP hands out the gateway, a `resolved.conf.d`
//! drop-in makes `systemd-resolved` listen there) — and `systemd-resolved` has **no RPZ / domain
//! blocklist support at all**, unlike BIND/Unbound/Knot (RPZ) or dnsmasq (`address=/domain/`).
//! This module therefore ships the **artifact + apply hook**, tool-gated exactly like this
//! codebase's existing OVS/nft steps in `network-apply.sh` ("if the tool isn't installed, log a
//! named gap and skip — never hard-fail the rest of the apply"): the generated RPZ zone loads
//! into any RPZ-capable resolver an operator installs; the dnsmasq artifact is a drop-in
//! `address=/domain/` blocklist. See `docs/adr/0033-dns-sinkhole-rpz.md` for the full decision.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, HashSet};

pub mod render;

// ─── Signal sources ────────────────────────────────────────────────────────────

/// Domains protected even with NO operator config (`Allowlist::new(&[])` still refuses these).
/// Mirrors `modules/dnsxai`'s own `BENIGN_ALLOWLIST` safety net — deliberately DUPLICATED, not
/// imported (that const isn't `pub`, and the two lists serve different purposes: dnsxai's
/// suppresses a *scoring* false positive, this one is a *hard floor* an operator config can only
/// ADD to, never remove from). Kept small and tightly scoped to genuinely catastrophic false
/// positives — OS control-plane / package-mirror / time-sync / root DNS-adjacent infra where a
/// false positive would be a self-inflicted, fleet-wide outage — NOT a general reputation list,
/// so it stays auditable at a glance.
pub const BUILTIN_NEVER_SINKHOLE: &[&str] = &[
    // This OS's own control plane: sinkholing it would self-DoS enrollment/updates fleet-wide.
    "hookprobe.com",
    "mssp.hookprobe.com",
    // Base-OS package mirrors (bootc/apt): sinkholing these blocks security updates.
    "debian.org",
    "deb.debian.org",
    "security.debian.org",
    "ubuntu.com",
    "archive.ubuntu.com",
    "security.ubuntu.com",
    // Time sync: a false positive here cascades into TLS-clock-skew failures everywhere else.
    "ntp.org",
    "pool.ntp.org",
    // High-traffic root infra a false positive on would be maximally disruptive and maximally
    // implausible to be genuinely malicious.
    "google.com",
    "cloudflare.com",
    "github.com",
    "microsoft.com",
    "apple.com",
    "amazon.com",
];

/// Where a sinkhole candidate's evidence came from — carried through into the RPZ/dnsmasq
/// comment AND the evidence-graph response's `detail` (XAI: never hide "why" from the operator,
/// same discipline `matcher::Hit::rule_msg` / `dnsxai::ClassifyResult::reasons` already hold to).
#[derive(Debug, Clone, PartialEq)]
pub enum SinkholeSource {
    /// `modules/dnsxai`'s `Verdict::Malicious` (V1's `BLOCK_INSTANT`, score >= 0.60).
    DnsxaiBlockInstant { score: f32, reasons: Vec<String>, src_ip: Option<String> },
    /// A HYDRA bundled-feed `domain`-typed, `active:true` indicator.
    HydraIoc { family: String, source: String, confidence: f64, mitre: String },
}

/// One domain slated for sinkholing, with EVERY source that flagged it. A domain can be both a
/// dnsxai `BLOCK_INSTANT` verdict AND a HYDRA IOC — both are surfaced, never silently deduped
/// away (the same "don't hide a second signal" discipline
/// `matcher::scan_flow_candidates`/`Hit` already applies to a flow matching >1 indicator field).
#[derive(Debug, Clone, PartialEq)]
pub struct SinkholeEntry {
    pub domain: String,
    pub sources: Vec<SinkholeSource>,
}

/// Parse one dnsxai verdict JSON line (`/var/lib/hookprobe/dns-verdicts` — the exact shape
/// `modules/dnsxai/src/main.rs::format_verdict_json` emits). Returns `None` for anything that
/// isn't a `verdict:"malicious"` line: the safest-possible block only acts on dnsxai's own
/// highest-confidence tier (`BLOCK_INSTANT`) — a `"suspicious"` verdict belongs in
/// `ANALYZE_BACKGROUND` (investigation), never a DNS refusal, matching V1's own tier semantics
/// (see `dnsxai::Verdict`'s doc comment). Malformed/truncated/non-JSON input degrades to `None`,
/// never a panic — a corrupt line in a 100k-line verdict tail must not abort the whole pass.
pub fn parse_dnsxai_block_instant(line: &str) -> Option<(String, SinkholeSource)> {
    let v: serde_json::Value = serde_json::from_str(line.trim()).ok()?;
    let domain = v.get("domain")?.as_str()?.trim();
    if domain.is_empty() {
        return None;
    }
    let verdict = v.get("verdict").and_then(|x| x.as_str()).unwrap_or("");
    if verdict != "malicious" {
        return None;
    }
    let score = v.get("score").and_then(|x| x.as_f64()).unwrap_or(0.0) as f32;
    let reasons: Vec<String> = v
        .get("reasons")
        .and_then(|x| x.as_array())
        .map(|a| a.iter().filter_map(|r| r.as_str().map(str::to_string)).collect())
        .unwrap_or_default();
    let src_ip = v.get("src_ip").and_then(|x| x.as_str()).map(str::to_string);
    Some((domain.to_string(), SinkholeSource::DnsxaiBlockInstant { score, reasons, src_ip }))
}

/// Every active `domain`-typed indicator in a HYDRA `IocFeed` — the second signal source. Reuses
/// `hookprobe_hydra::feed::IocFeed` unmodified (its own `parse`/`load` already skip malformed
/// entries with a printed warning, never fatal to the rest of the feed) — this function is a
/// thin, total (never panics, never returns `Result`) projection: `IocFeed::indicators` is
/// already-validated data by the time it reaches here.
pub fn hydra_domain_indicators(feed: &hookprobe_hydra::feed::IocFeed) -> Vec<(String, SinkholeSource)> {
    feed.indicators
        .iter()
        .filter(|i| i.ioc_type == hookprobe_hydra::feed::IocType::Domain && i.active && !i.value.is_empty())
        .map(|i| {
            (
                i.value.clone(),
                SinkholeSource::HydraIoc {
                    family: i.family.clone(),
                    source: i.source.clone(),
                    confidence: i.confidence,
                    mitre: i.mitre.clone(),
                },
            )
        })
        .collect()
}

// ─── Allowlist (the FP-safety valve) ───────────────────────────────────────────

/// Operator-declared, never-generated config: domains that must NEVER be sinkholed no matter
/// what a feed/detector says. Parsed from `/etc/hookprobe/dns-sinkhole-allowlist.yaml` — the
/// SAME "operator declares intent in a `/etc/hookprobe/*.yaml` file the reconciler only reads,
/// never overwrites" convention `LanIntent`/`WifiIntent`/`NacIntent` already use
/// (`crates/hookprobe-manifest`), just for content policy instead of network topology.
#[derive(Debug, Clone, Default, serde::Deserialize)]
#[serde(default)]
pub struct AllowlistConfig {
    pub domains: Vec<String>,
}

impl AllowlistConfig {
    pub fn parse(yaml: &str) -> anyhow::Result<Self> {
        Ok(serde_yaml::from_str(yaml)?)
    }
}

/// The resolved allowlist: [`BUILTIN_NEVER_SINKHOLE`] + whatever the operator's own file adds.
/// Case-folded once at construction (DNS names are case-insensitive; a feed/detector's casing
/// must never matter for an allowlist decision).
#[derive(Debug, Clone)]
pub struct Allowlist {
    domains: HashSet<String>,
}

impl Allowlist {
    pub fn new(operator_domains: &[String]) -> Self {
        let mut domains: HashSet<String> =
            BUILTIN_NEVER_SINKHOLE.iter().map(|s| s.to_ascii_lowercase()).collect();
        domains.extend(
            operator_domains
                .iter()
                .map(|s| s.trim().trim_end_matches('.').to_ascii_lowercase())
                .filter(|s| !s.is_empty()),
        );
        Self { domains }
    }

    /// `true` iff `domain`, or any of its PARENT domains, is on the allowlist — an allowlisted
    /// `hookprobe.com` also protects `mssp.hookprobe.com`/`foo.bar.hookprobe.com`/etc, so an
    /// operator doesn't have to enumerate every subdomain by hand. This is checked LAST, after
    /// every source has been merged (see [`build_sinkhole_set`]) — allowlist ALWAYS wins,
    /// unconditionally, regardless of source, confidence, or how many sources agree.
    pub fn is_allowed(&self, domain: &str) -> bool {
        let d = domain.trim().trim_end_matches('.').to_ascii_lowercase();
        if d.is_empty() {
            return false;
        }
        if self.domains.contains(&d) {
            return true;
        }
        let mut rest = d.as_str();
        while let Some((_, tail)) = rest.split_once('.') {
            if self.domains.contains(tail) {
                return true;
            }
            rest = tail;
        }
        false
    }
}

// ─── Build the sinkhole set ─────────────────────────────────────────────────────

/// Merge both signal sources into the final sinkhole set, applying the allowlist LAST — the core
/// FP-safety contract this module exists to guarantee: no matter how many sources flag a domain,
/// or how confident they are, an allowlisted domain never makes it into the output. Malformed
/// dnsxai verdict lines are skipped (never fatal); an empty/unreadable HYDRA feed degrades to
/// "no HYDRA-sourced domains this pass" (the caller is expected to have already logged that —
/// see `main.rs`), never a panic here.
pub fn build_sinkhole_set<'a>(
    dnsxai_verdict_lines: impl Iterator<Item = &'a str>,
    hydra_domain_iocs: &[(String, SinkholeSource)],
    allowlist: &Allowlist,
) -> Vec<SinkholeEntry> {
    let mut by_domain: BTreeMap<String, Vec<SinkholeSource>> = BTreeMap::new();
    for line in dnsxai_verdict_lines {
        if let Some((domain, source)) = parse_dnsxai_block_instant(line) {
            by_domain.entry(domain).or_default().push(source);
        }
    }
    for (domain, source) in hydra_domain_iocs {
        by_domain.entry(domain.clone()).or_default().push(source.clone());
    }
    by_domain
        .into_iter()
        .filter(|(domain, _)| !allowlist.is_allowed(domain))
        .map(|(domain, sources)| SinkholeEntry { domain, sources })
        .collect()
}

// ─── Evidence-graph track & trace (reversible, TTL-able) ───────────────────────

/// One evidence-graph response-event JSON line for a NEWLY-sinkholed domain — the SAME shape
/// `hookprobe-evidence --responses` already ingests via `ingest_response`
/// (`hookprobe_manifest::scan_responder::render_response_json`'s identical field contract:
/// `ts/rule_id/src_ip/dst_ip/dst_port/action/mechanism/target/detail/ttl_secs/status`).
///
/// `rule_id`/`src_ip`/`dst_ip`/`dst_port` are deliberately chosen to match the natural key of
/// the ORIGINATING detection so `ingest_response`'s EXISTING rule_id/src_ip/dst_ip/dst_port/
/// ±600s linking wires the `responded_with` edge automatically — no new evidence-graph linking
/// code needed:
/// - A dnsxai-sourced entry uses `rule_id: 0` (matching `ingest_dns_verdict`'s own hardcoded
///   `rule_id` for every dnsxai detection) and `dst_ip: <domain>` (matching that same ingest
///   path's `dst_ip = domain` convention).
/// - A HYDRA-only entry (never yet seen on a live flow, so no dnsxai verdict exists for it) uses
///   `rule_id: hydra_rule_id(domain)` (matching `matcher::Hit`'s own domain-match convention:
///   `dst_ip` carries the matched domain) — best-effort; a domain sinkholed purely from a feed
///   IOC that HYDRA's matcher hasn't independently fired on yet still gets an unlinked response
///   node (same documented "still ingests unlinked" degrade path `ingest_response`'s own doc
///   comment describes for a response with no matching detection yet).
///
/// `src_ip` is honestly empty when no dnsxai verdict named a requesting device — never a
/// fabricated value (same optional-field convention `ingest_dns_verdict`/`l2_responder` already
/// use). `action: "sinkhole"` / `mechanism: "dns_rpz"` are NEW, distinct values — never reuses
/// `"quarantine"`/`"nft"`, so a DNS-layer name refusal can never be confused with a packet drop
/// in the evidence graph or the operator's Investigate view.
pub fn render_response_json(entry: &SinkholeEntry, ttl_secs: u64, now: f64) -> String {
    let (rule_id, src_ip) = entry
        .sources
        .iter()
        .find_map(|s| match s {
            SinkholeSource::DnsxaiBlockInstant { src_ip, .. } => Some((0i64, src_ip.clone().unwrap_or_default())),
            _ => None,
        })
        .unwrap_or_else(|| (hookprobe_hydra::rule::hydra_rule_id(&entry.domain), String::new()));

    let reasons = source_reasons(entry);
    serde_json::json!({
        "ts": now,
        "rule_id": rule_id,
        "src_ip": src_ip,
        "dst_ip": entry.domain,
        "dst_port": 53,
        "action": "sinkhole",
        "mechanism": "dns_rpz",
        "target": entry.domain,
        "detail": format!("DNS sinkhole: {} — {}", entry.domain, reasons.join(" | ")),
        "ttl_secs": ttl_secs,
        "status": "active",
    })
    .to_string()
}

/// The REVERT counterpart — emitted when a previously-sinkholed domain drops out of the current
/// pass (allowlist edit, HYDRA indicator retired, the triggering dnsxai verdict aged out of the
/// tail window). Mirrors `scan_responder::render_shed_revert_json`'s shape exactly: a DISTINCT
/// `action` value (`"sinkhole_revert"`, never a reused `"sinkhole"`) + `status: "reverted"` — an
/// operator scanning the responses stream sees an explicit, first-class "this stopped" record,
/// never a silent disappearance they could mistake for "nothing ever happened."
pub fn render_revert_json(domain: &str, now: f64) -> String {
    serde_json::json!({
        "ts": now,
        "rule_id": 0,
        "src_ip": "",
        "dst_ip": domain,
        "dst_port": 53,
        "action": "sinkhole_revert",
        "mechanism": "dns_rpz",
        "target": domain,
        "detail": format!(
            "DNS sinkhole released: {domain} — no longer matched by any active signal \
             (allowlisted, HYDRA indicator retired, or the triggering dnsxai verdict aged out)"
        ),
        "ttl_secs": 0,
        "status": "reverted",
    })
    .to_string()
}

fn source_reasons(entry: &SinkholeEntry) -> Vec<String> {
    entry
        .sources
        .iter()
        .map(|s| match s {
            SinkholeSource::DnsxaiBlockInstant { score, reasons, .. } => {
                if reasons.is_empty() {
                    format!("dnsxai BLOCK_INSTANT score={score:.2}")
                } else {
                    format!("dnsxai BLOCK_INSTANT score={score:.2} ({})", reasons.join("; "))
                }
            }
            SinkholeSource::HydraIoc { family, source, confidence, .. } => {
                format!("HYDRA IOC family={family} source={source} confidence={confidence:.2}")
            }
        })
        .collect()
}

// ─── State diff (drives the reversible/TTL-able revert path) ──────────────────

/// The outcome of comparing this pass's sinkhole set against the previous pass's on-disk state
/// (`domain -> first_sinkholed_ts`): which domains are new (need a fresh, first-class evidence
/// response) and which have dropped out (need an explicit revert record) — plus the state to
/// persist for the NEXT pass. Kept as a pure function (no I/O) so it's fully unit-testable; the
/// binary owns reading/writing the state file.
#[derive(Debug, Clone, PartialEq)]
pub struct StateDiff {
    pub newly_added: Vec<SinkholeEntry>,
    pub reverted_domains: Vec<String>,
    pub next_state: BTreeMap<String, f64>,
}

/// Diff `entries` (this pass's full sinkhole set) against `prev_state` (last pass's persisted
/// `domain -> first_sinkholed_ts` map). A domain already in `prev_state` keeps its ORIGINAL
/// `first_sinkholed_ts` (so the evidence timeline reflects when it was FIRST blocked, not every
/// regeneration) and does not appear in `newly_added` again — this is what makes repeated timer
/// runs idempotent for the evidence graph (no duplicate response nodes every 5 minutes for a
/// domain that's still actively sinkholed).
pub fn diff_state(entries: &[SinkholeEntry], prev_state: &BTreeMap<String, f64>, now: f64) -> StateDiff {
    let mut next_state = BTreeMap::new();
    let mut newly_added = Vec::new();
    for e in entries {
        match prev_state.get(&e.domain) {
            Some(&ts) => {
                next_state.insert(e.domain.clone(), ts);
            }
            None => {
                next_state.insert(e.domain.clone(), now);
                newly_added.push(e.clone());
            }
        }
    }
    let current: HashSet<&str> = entries.iter().map(|e| e.domain.as_str()).collect();
    let reverted_domains: Vec<String> =
        prev_state.keys().filter(|d| !current.contains(d.as_str())).cloned().collect();
    StateDiff { newly_added, reverted_domains, next_state }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hookprobe_hydra::feed::IocFeed;

    fn hydra_feed_with_domain(domain: &str, active: bool) -> IocFeed {
        IocFeed::parse(&format!(
            r#"{{"format":"hookprobe-ioc-v1","generated":"2026-07-09","source_summary":"test",
                "indicators":[{{"value":"{domain}","ioc_type":"domain","family":"CobaltStrike",
                "source":"test","confidence":0.9,"active":{active},"mitre":"T1071.001"}}]}}"#
        ))
        .unwrap()
    }

    // ── dnsxai verdict parsing ──────────────────────────────────────────────

    #[test]
    fn parses_a_malicious_verdict_line() {
        let line = r#"{"domain":"kq3v9z7x1p2w.com","score":0.8300,"verdict":"malicious","reasons":["high_entropy:4.10"],"src_ip":"10.66.0.20"}"#;
        let (domain, source) = parse_dnsxai_block_instant(line).expect("malicious verdict parses");
        assert_eq!(domain, "kq3v9z7x1p2w.com");
        match source {
            SinkholeSource::DnsxaiBlockInstant { score, reasons, src_ip } => {
                assert!((score - 0.83).abs() < 1e-3);
                assert_eq!(reasons, vec!["high_entropy:4.10".to_string()]);
                assert_eq!(src_ip, Some("10.66.0.20".to_string()));
            }
            _ => panic!("expected DnsxaiBlockInstant"),
        }
    }

    #[test]
    fn suspicious_and_benign_verdicts_are_never_sinkhole_candidates() {
        // The safest-possible block only acts on the HIGHEST confidence tier (BLOCK_INSTANT) —
        // "suspicious" belongs in investigation, never a DNS refusal.
        assert!(parse_dnsxai_block_instant(
            r#"{"domain":"example.tk","score":0.4500,"verdict":"suspicious","reasons":[]}"#
        )
        .is_none());
        assert!(parse_dnsxai_block_instant(
            r#"{"domain":"google.com","score":0.0000,"verdict":"benign","reasons":[]}"#
        )
        .is_none());
    }

    #[test]
    fn malformed_or_empty_lines_degrade_to_none_never_panic() {
        assert!(parse_dnsxai_block_instant("").is_none());
        assert!(parse_dnsxai_block_instant("not json at all").is_none());
        assert!(parse_dnsxai_block_instant(r#"{"domain":"","verdict":"malicious"}"#).is_none());
        assert!(parse_dnsxai_block_instant(r#"{"verdict":"malicious"}"#).is_none(), "missing domain field");
        assert!(parse_dnsxai_block_instant(r#"{"domain":"evil.example"#).is_none(), "truncated JSON");
        assert!(parse_dnsxai_block_instant("\0\0\0garbage\x01\x02").is_none());
    }

    #[test]
    fn a_verdict_line_missing_src_ip_still_parses_with_no_fabricated_ip() {
        let (domain, source) =
            parse_dnsxai_block_instant(r#"{"domain":"evil.example","score":0.7,"verdict":"malicious","reasons":[]}"#)
                .unwrap();
        assert_eq!(domain, "evil.example");
        match source {
            SinkholeSource::DnsxaiBlockInstant { src_ip, .. } => assert_eq!(src_ip, None),
            _ => panic!(),
        }
    }

    // ── HYDRA domain indicators ─────────────────────────────────────────────

    #[test]
    fn hydra_domain_indicators_only_pulls_active_domain_type() {
        let feed = IocFeed::parse(
            r#"{"format":"hookprobe-ioc-v1","generated":"2026-07-09","source_summary":"test",
                "indicators":[
                    {"value":"evil-c2.example","ioc_type":"domain","family":"CobaltStrike","source":"test","confidence":0.8,"active":true},
                    {"value":"retired.example","ioc_type":"domain","family":"Old","source":"test","confidence":0.5,"active":false},
                    {"value":"1.2.3.4","ioc_type":"ip","family":"Emotet","source":"test","confidence":0.9,"active":true}
                ]}"#,
        )
        .unwrap();
        let domains = hydra_domain_indicators(&feed);
        assert_eq!(domains.len(), 1, "only the active domain-typed indicator");
        assert_eq!(domains[0].0, "evil-c2.example");
    }

    // ── Allowlist ────────────────────────────────────────────────────────────

    #[test]
    fn builtin_allowlist_protects_control_plane_and_update_infra_with_no_operator_config() {
        let allow = Allowlist::new(&[]);
        assert!(allow.is_allowed("hookprobe.com"));
        assert!(allow.is_allowed("mssp.hookprobe.com"), "subdomain of an allowlisted domain");
        assert!(allow.is_allowed("deb.debian.org"));
        assert!(!allow.is_allowed("totally-not-on-any-list.example"));
    }

    #[test]
    fn operator_allowlist_adds_to_but_never_replaces_the_builtin_floor() {
        let allow = Allowlist::new(&["my-corp-vpn.example".to_string()]);
        assert!(allow.is_allowed("my-corp-vpn.example"), "operator addition");
        assert!(allow.is_allowed("hookprobe.com"), "builtin floor still active");
    }

    #[test]
    fn allowlist_is_case_insensitive_and_tolerates_trailing_dot() {
        let allow = Allowlist::new(&["Example.COM".to_string()]);
        assert!(allow.is_allowed("example.com"));
        assert!(allow.is_allowed("EXAMPLE.COM."));
        assert!(allow.is_allowed("sub.example.com"));
    }

    #[test]
    fn empty_or_malformed_allowlist_domain_entries_are_ignored_not_a_wildcard() {
        let allow = Allowlist::new(&["".to_string(), "   ".to_string()]);
        assert!(!allow.is_allowed("evil.example"), "a blank entry must never allow everything");
    }

    // ── build_sinkhole_set: the FP-safety contract ──────────────────────────

    #[test]
    fn allowlist_wins_over_both_sources_even_when_both_agree() {
        let feed = hydra_feed_with_domain("hookprobe.com", true);
        let hydra = hydra_domain_indicators(&feed);
        let dnsxai_lines =
            [r#"{"domain":"hookprobe.com","score":0.9,"verdict":"malicious","reasons":["lookalike:hookprobe"]}"#];
        let allow = Allowlist::new(&[]); // hookprobe.com is on the BUILTIN floor
        let entries = build_sinkhole_set(dnsxai_lines.iter().copied(), &hydra, &allow);
        assert!(entries.is_empty(), "allowlisted domain must never appear, even hit by BOTH sources");
    }

    #[test]
    fn a_domain_hit_by_both_sources_carries_both_as_separate_entries() {
        let feed = hydra_feed_with_domain("evil-c2.example", true);
        let hydra = hydra_domain_indicators(&feed);
        let dnsxai_lines =
            [r#"{"domain":"evil-c2.example","score":0.7,"verdict":"malicious","reasons":["high_entropy:4.2"]}"#];
        let allow = Allowlist::new(&[]);
        let entries = build_sinkhole_set(dnsxai_lines.iter().copied(), &hydra, &allow);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].sources.len(), 2, "both sources surfaced, never deduped away");
    }

    #[test]
    fn a_malformed_dnsxai_stream_and_an_empty_hydra_feed_degrade_to_an_empty_set_never_a_panic() {
        let malformed = ["not json", "", r#"{"domain":"x","verdict":"suspicious"}"#];
        let allow = Allowlist::new(&[]);
        let entries = build_sinkhole_set(malformed.iter().copied(), &[], &allow);
        assert!(entries.is_empty(), "malformed/non-malicious input must degrade to NOT sinkholing anything");
    }

    #[test]
    fn retired_hydra_indicator_never_becomes_a_sinkhole_candidate() {
        let feed = hydra_feed_with_domain("stale-c2.example", false);
        let hydra = hydra_domain_indicators(&feed);
        assert!(hydra.is_empty());
        let entries = build_sinkhole_set(std::iter::empty(), &hydra, &Allowlist::new(&[]));
        assert!(entries.is_empty());
    }

    // ── evidence-graph response rendering ───────────────────────────────────

    #[test]
    fn response_json_links_to_the_originating_dnsxai_detection_by_natural_key() {
        let entry = SinkholeEntry {
            domain: "kq3v9z7x1p2w.com".to_string(),
            sources: vec![SinkholeSource::DnsxaiBlockInstant {
                score: 0.83,
                reasons: vec!["high_entropy:4.10".to_string()],
                src_ip: Some("10.66.0.20".to_string()),
            }],
        };
        let json = render_response_json(&entry, 3600, 1000.0);
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["rule_id"], 0, "matches ingest_dns_verdict's own hardcoded rule_id");
        assert_eq!(v["src_ip"], "10.66.0.20");
        assert_eq!(v["dst_ip"], "kq3v9z7x1p2w.com", "matches ingest_dns_verdict's dst_ip=domain convention");
        assert_eq!(v["dst_port"], 53);
        assert_eq!(v["action"], "sinkhole");
        assert_eq!(v["mechanism"], "dns_rpz");
        assert_eq!(v["status"], "active");
        assert_eq!(v["ttl_secs"], 3600);
        assert!(v["detail"].as_str().unwrap().contains("high_entropy:4.10"), "XAI reason surfaced");
    }

    #[test]
    fn response_json_for_a_hydra_only_entry_uses_the_hydra_rule_id_convention() {
        let entry = SinkholeEntry {
            domain: "evil-c2.example".to_string(),
            sources: vec![SinkholeSource::HydraIoc {
                family: "CobaltStrike".to_string(),
                source: "test".to_string(),
                confidence: 0.8,
                mitre: "T1071.001".to_string(),
            }],
        };
        let json = render_response_json(&entry, 3600, 1000.0);
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["rule_id"], hookprobe_hydra::rule::hydra_rule_id("evil-c2.example"));
        assert_eq!(v["src_ip"], "", "no device known for a feed-only sinkhole — never fabricated");
        assert!(v["detail"].as_str().unwrap().contains("CobaltStrike"));
    }

    #[test]
    fn revert_json_is_a_distinct_action_never_reusing_the_active_shape() {
        let json = render_revert_json("evil-c2.example", 2000.0);
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["action"], "sinkhole_revert");
        assert_eq!(v["status"], "reverted");
        assert_ne!(v["action"], "sinkhole", "must never be confused with the active record");
    }

    // ── state diff: reversible / TTL-able ───────────────────────────────────

    #[test]
    fn new_domains_are_newly_added_and_dropped_domains_are_reverted() {
        let mut prev = BTreeMap::new();
        prev.insert("still-bad.example".to_string(), 500.0);
        prev.insert("now-fine.example".to_string(), 500.0); // e.g. allowlisted since last pass

        let entries = vec![
            SinkholeEntry { domain: "still-bad.example".to_string(), sources: vec![] },
            SinkholeEntry { domain: "brand-new-bad.example".to_string(), sources: vec![] },
        ];
        let diff = diff_state(&entries, &prev, 1000.0);
        assert_eq!(diff.newly_added.len(), 1);
        assert_eq!(diff.newly_added[0].domain, "brand-new-bad.example");
        assert_eq!(diff.reverted_domains, vec!["now-fine.example".to_string()]);
        assert_eq!(diff.next_state.get("still-bad.example"), Some(&500.0), "original first-seen ts preserved");
        assert_eq!(diff.next_state.get("brand-new-bad.example"), Some(&1000.0));
        assert!(!diff.next_state.contains_key("now-fine.example"));
    }

    #[test]
    fn a_repeat_pass_with_no_changes_produces_no_new_or_reverted_records() {
        let mut prev = BTreeMap::new();
        prev.insert("still-bad.example".to_string(), 500.0);
        let entries = vec![SinkholeEntry { domain: "still-bad.example".to_string(), sources: vec![] }];
        let diff = diff_state(&entries, &prev, 1000.0);
        assert!(diff.newly_added.is_empty(), "no duplicate response every timer tick");
        assert!(diff.reverted_domains.is_empty());
    }

    #[test]
    fn empty_state_and_empty_entries_is_a_true_no_op() {
        let diff = diff_state(&[], &BTreeMap::new(), 1000.0);
        assert!(diff.newly_added.is_empty());
        assert!(diff.reverted_domains.is_empty());
        assert!(diff.next_state.is_empty());
    }
}
