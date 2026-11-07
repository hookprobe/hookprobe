//! redteam-engine — the ADR 0020 adversarial-resilience harness. A dev/CI-only tool: NEVER staged
//! into a shipped image, NEVER in the module registry (ADR 0020 D2). Every module below that has no
//! reason to touch a raw socket is `forbid(unsafe_code)`; the `probes` modules that DO need one
//! follow the same convention `modules/napse-capture/loader` already uses (unsafe, checked, no
//! blanket crate-level forbid) -- see each probe file's own doc comment.
//!
//! Module map (mirrors ADR 0020 D2's directory tree; `probes` are declared here with an explicit
//! `#[path]` so the ADR's literal `security/redteam/probes/...` directory layout is preserved on
//! disk while still being compiled as part of this ONE crate — the crate boundary the ADR wants
//! ["a native engine keeps ROE enforcement in-process, ahead of the socket"], not a directory
//! convention):
//!   - `roe`          — parse + validate `rules-of-engagement.yaml` (D3).
//!   - `topology`      — condition-2 veth/netns assertion via `ip -j` (a netlink client).
//!   - `limiter`       — condition-1 `limits:` enforcement, fail-closed.
//!   - `kill_switch`   — condition-5 sentinel-file + SIGTERM trap.
//!   - `target_guard`  — ties the above together; the ONLY way a probe gets a send token.
//!   - `findings`      — the `attack_run`/`finding` JSON shapes (D6) this engine emits.
//!   - `campaign`       — pre-fire audit + verdict computation (D5).
//!   - `probes::*`      — the offensive probe implementations (Phase 1b, gated on all of the above).
//!
//! NOTE: `forbid(unsafe_code)` is applied PER-MODULE (each file's own `#![forbid(unsafe_code)]`
//! inner attribute), not once at this crate root -- a crate-root `forbid` cannot be locally
//! overridden by a nested `allow`, and `probes::sockets` legitimately needs `unsafe` for its raw
//! AF_PACKET calls (same convention `modules/napse-capture/loader` uses: checked libc calls, no
//! blanket crate-level forbid). See `probes/sockets.rs`'s own doc comment.

pub mod campaign;
pub mod findings;
pub mod kill_switch;
pub mod limiter;
pub mod roe;
pub mod target_guard;
pub mod topology;

// Shared packet-crafting/raw-socket helpers for the probes below (kept as their own top-level
// modules — see each file's own doc comment for why `unsafe` lives ONLY in `sockets`).
#[path = "../../probes/packet.rs"]
pub mod packet;
#[path = "../../probes/sockets.rs"]
pub mod sockets;

#[path = "../../probes/l2_link/mod.rs"]
pub mod l2_link;
#[path = "../../probes/l34_net/mod.rs"]
pub mod l34_net;
#[path = "../../probes/l56_session/mod.rs"]
pub mod l56_session;
#[path = "../../probes/l7_app/mod.rs"]
pub mod l7_app;
