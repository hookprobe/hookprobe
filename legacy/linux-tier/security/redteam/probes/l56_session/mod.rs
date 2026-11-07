//! L5/L6 session/presentation probes — ADR 0020 D8 Phase-2/Phase-3, ROADMAP in this pass.
//!
//! - **Dashboard TLS downgrade (L5, phase-2):** validates the local Mission Control dashboard's TLS
//!   (ADR 0001). Not built in this pass — the read-API's TLS termination story is itself still
//!   settling; probing it now would test a moving target.
//! - **HTP session forgery/no-FS (L5, ROADMAP):** ADR 0004's evolved X25519+ML-KEM/PUF handshake is
//!   **design-only** in this repo today. Per ADR 0020 D1/D8: "there is nothing here to attack yet.
//!   Do NOT fabricate HTP probe results." No function exists for this — not even a stub that
//!   returns `Err` — because even naming a fake `htp_session_forgery()` function risks implying a
//!   target exists to probe. When HTP's handshake actually lands, this module gains its first real
//!   probe function then, not before.
//! - **Module-signing downgrade / artifact swap (L6, phase-2):** the mechanisms exist and are
//!   unit-tested (ADR 0016/0017's `verify_artifact_digests`/`verify_executable_binding`); the
//!   harness's live "attacker swaps the payload on a running/staged image" campaign is phase-2 —
//!   not built in this pass (scoped out to keep Phase-1b to the L2-L4 probes the ADR asked for
//!   first).
#![forbid(unsafe_code)]
