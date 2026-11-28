// SPDX-License-Identifier: AGPL-3.0-only
//! HookProbe Conductor, C0: the device-side logic for directing remote compute.
//!
//! heqk keeps the authority (identity, keys, policy, evidence, capability issuance, verification, ledger);
//! remote workers only compute. This crate is the protocol and the harness state machine, written
//! sans-IO: the harness consumes [`harness::Event`]s and emits [`harness::Action`]s, and whoever hosts it
//! (the EL0 shim on heqk, the mock on the build host) performs every I/O. It holds no key, opens no
//! socket and allocates nothing.
//!
//! Status: C0 spike (design review v2). The wire formats are PROTOTYPES built from primitives heqk already
//! ships (SHA-256, Ed25519). They are not a production protocol. Published by operator decision under
//! ADR 0067 D12 (2026-11-24).
#![no_std]
#![forbid(unsafe_code)]
#![deny(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation
)]

pub mod abi;
pub mod buf;
pub mod chain;
pub mod durable;
pub mod cap;
pub mod class;
pub mod crypto;
pub mod frame;
pub mod harness;
pub mod job;
pub mod json;
pub mod lease;
pub mod ledger;
pub mod pairing;
pub mod limits;
pub mod place;
pub mod quorum;
pub mod tools;
pub mod verify;
pub mod window;
pub mod wire;
pub mod worker;

#[cfg(feature = "signer")]
pub mod signer;
