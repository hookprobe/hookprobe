//! `hookprobe-planner` — the AEGIS BYO-LLM planner (ADR 0025).
//!
//! **The invariant this whole crate exists to protect (CLAUDE.md, contract C9): the AI planner is
//! ASSISTIVE and NEVER in the enforcement path.** It PROPOSES a plan-as-diff; the deterministic
//! reconciler (`hookprobe_manifest::aegis::reconcile_network`, unchanged, still works with zero
//! model configured) and an explicit human approval are what turn a proposal into anything real.
//! See `schema`'s module doc for exactly how that boundary is enforced structurally, not just by
//! instruction to the model.
//!
//! Module map:
//! - [`config`] — env-var-driven BYO-LLM endpoint config; `LlmConfig::from_env() -> None` is the
//!   honest, air-gap-default "no model configured" state.
//! - [`adapter`] — the OpenAI-compatible `chat/completions` HTTP client. No vendor hardcoded.
//! - [`schema`] — the C9 structural boundary types (`RawLlmOutput`, `PlannerResponse`, …).
//! - [`diff`] — a small LCS diff over `Vec<String>` plan lines.
//! - [`plan`] — ties it together: `propose()` is the one entry point `main.rs`'s HTTP handlers call.
#![forbid(unsafe_code)]

pub mod adapter;
pub mod config;
pub mod diff;
pub mod plan;
pub mod schema;

pub use adapter::{Adapter, AdapterError};
pub use config::LlmConfig;
pub use plan::{propose, PlanContext};
pub use schema::{ArtifactPreview, DiffLine, Explanation, PlannerResponse, ProposedChange, RawLlmOutput};
