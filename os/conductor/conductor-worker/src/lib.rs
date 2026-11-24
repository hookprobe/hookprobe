// SPDX-License-Identifier: AGPL-3.0-only
//! The Conductor reference worker (C2).
//!
//! It runs on the owner's GPU box, serves ONE paired heqk device, and holds no authority of its own:
//! it executes only device-signed, single-use HP-EXEC capabilities bound to the live channel session,
//! answers data-free SLO quotes, signs its results, and keeps no cross-job state except the replay
//! high-water mark and the revocation epoch (persisted before any work starts, ADR 0069 pattern).
//!
//! The inference engine (llama.cpp `llama-server`, vLLM, Ollama: any OpenAI-compatible server) runs on the
//! same box and must listen on loopback only; the worker refuses any other engine address. Offloading
//! (MoE experts in RAM, KV tiers, speculative decoding) happens inside the engine: only requests and
//! tokens cross the network.

#[path = "../../../../onboarding/enrollment/responder-sim/src/entropy.rs"]
#[allow(dead_code)]
pub mod entropy;
#[path = "../../../kernel/kernel/src/securechannel.rs"]
#[allow(dead_code, clippy::all)]
pub mod securechannel;

pub mod chan;
pub mod engine;
pub mod files;
pub mod http;
pub mod pairio;
pub mod quote;
pub mod serve;
