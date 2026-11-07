//! L7 application probes — ADR 0020 D8 Phase-2/Phase-3, ROADMAP in this pass.
//!
//! The Mission Control read-API (`crates/hookprobe-api`) exists today, so this is the closest-to-
//! buildable L7 surface — but the ADR scopes the read-API/RBAC-bypass fuzzer to phase-2/3 ("gate
//! only what ships" — the write/plan surface `l7_app/rbac-bypass` would validate is only partly
//! built), and D4 draws an explicit split: the RELEASE-BLOCKING L7 probes must be Rust in this same
//! engine (reproducible, dependency-light); a Python/`schemathesis`-class exploratory fuzzer is
//! PERMITTED for developer-time exploration but is advisory-only, never a RED gate by itself. Ño
//! Python fuzzer harness is added here either, to keep this pass's scope to what ADR 0020 §"Build,
//! in this order" actually asked for (ROE + netns DUT + evidence loop + Gate R + L1-L7 *declared*,
//! L2-L4 *built*). Both the Rust `read-api-fuzz`/`rbac-bypass` probes and the Python exploratory
//! harness are named here as the next concrete step, not implemented.
#![forbid(unsafe_code)]
