//! HYDRA — the IOC/threat-intel enrichment half of Intelligence (ADR 0027).
//!
//! `hookprobe-exploit` (ADR 0024) already answers "which component on THIS device is
//! known-exploitable and reachable right now" (the CVE lens). This crate answers the OTHER
//! question Intelligence needs: "has anything on THIS device's real traffic ever touched a
//! known-bad indicator" — matching a small, bundled, dated IOC feed
//! (`security/threat-intel/snapshots/ioc-feed-*.json`) against the evidence graph's own flow/
//! application data (real dst-IPs, TLS SNI / HTTP Host, JA3 — everything `ingest_flow` already
//! records), producing enriched detections through the SAME
//! `hookprobe_evidence::EvidenceGraph::ingest_detection` path every other engine uses.
//!
//! Standalone/air-gapped by default: the bundled feed is the baseline; a live STIX/TAXII/MISP
//! fetch is an ADDITIVE enrollment feature, not built in this first version (see the crate's own
//! README/ADR 0027 for the honest scope).
#![forbid(unsafe_code)]

pub mod feed;
pub mod matcher;
pub mod rule;
pub mod verdict;

pub use feed::{Indicator, IocFeed, IocType};
pub use matcher::{scan_flow_candidates, Hit};
pub use rule::hydra_rule_id;
pub use verdict::{assess, Corroboration, HydraThreat, HydraTrustPolicy, HydraVerdict};
