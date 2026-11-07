//! L3/L4 network/transport probes (ADR 0020 D8 Phase-1b) — replay THIS session's proven ADR 0018
//! attacks against `napse_loader::portscan::PortScanTracker` / `confirm::HandshakeTracker` /
//! `hookprobe_manifest::scan_responder::decide` / `napse-quarantine`'s bounded enforced set. Every
//! probe here REQUIRES a `ValidatedTarget` token from `target_guard::validate_l3[_literal]` —
//! there is no other way to reach the send path (contract #2).
pub mod roadmap;
pub mod syn_scan;
