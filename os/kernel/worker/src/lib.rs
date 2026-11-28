// SPDX-License-Identifier: AGPL-3.0-only
//! heqk worker-core executive (ADR 0060 amendment, stage S1).
//!
//! Cores 1..n run this crate and nothing else. They never execute kernel code: the crate has no
//! dependencies, so it cannot name a kernel `static`, and the kernel's single-core contract
//! (`ARCHITECTURE.md`) stays true for everything that runs on core 0. A worker talks to core 0
//! only through:
//! * two single-producer/single-consumer [`ring::Ring`]s (jobs in, results out), whose endpoints
//!   are handed out once by [`ring::Ring::split`], so each side exists exactly once;
//! * a read-only data window core 0 grants at start (`Ctx::window_*`); a job that points outside
//!   it is refused, never executed;
//! * a GICv2 SGI doorbell, taken with interrupts masked (`wfi` wakes on a pending interrupt
//!   whatever `PSTATE.I` says), so a worker has no IRQ path at all.
//!
//! A worker fault (any exception) is handled by the vectors in `arch-aarch64/src/smp.rs`: the
//! core records ESR and parks; core 0 and the other workers carry on.
#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

pub mod exec;
pub mod job;
pub mod ring;

#[cfg(target_arch = "aarch64")]
pub mod gic;
