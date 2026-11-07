//! L2 link-layer probes (ADR 0020 D8 Phase-1b) — validates against `napse_loader::l2guard`'s
//! `MacFloodTracker`/`ArpGuard`/`BroadcastStormTracker`/`MalformedFrameGate` (already wired into
//! `napse-dpi`, ADR 0020 Phase-1a defensive). Every probe here REQUIRES a `ValidatedL2Scope` token
//! from `target_guard::validate_l2` — there is no other way to reach the send path (contract #2).
pub mod mac_flood;
pub mod roadmap;
