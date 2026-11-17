//! Sealed evidence export (ADR 0066): the part of "export the sealed evidence log over the
//! enrolled PQ channel" that does not need the kernel, as a pure `no_std` library.
//!
//! The pipeline, one module per step:
//!
//! 1. [`slot`]: parse one 512-byte slot of the fslog ring (framing digest + ring placement).
//! 2. [`record`]: open the HQKSEAL1 payload through the caller's [`record::SealOpener`] and check
//!    the evidence layout. Anything that fails is rejected and counted, never exported.
//! 3. [`anon`]: turn each event into an export record. Internal addresses and raw MAC octets are
//!    removed; the record type has no field that could carry a payload.
//! 4. [`qsecbit`]: a sliding-window summary of the QSECBIT score that rides in every frame.
//! 5. [`wire`]: the HQX3 frame and ack codecs. `parse` re-checks the privacy rules, so a receiver
//!    refuses a frame that carries an internal address.
//! 6. [`queue`]: the synced cursor, in-flight batches, cumulative acks, ack timeouts and the
//!    offline backoff. Nothing in it can delete local evidence.
//! 7. [`exporter`]: ties the steps together over a [`exporter::SlotSource`] (the log) and a
//!    [`exporter::Transport`] (the sealed Noise session).
//!
//! What this crate deliberately does not do: open the sealed session, decrypt with the device key,
//! or persist the cursor. Those stay in the kernel behind the traits above (ADR 0066, "Kernel
//! interface").
#![no_std]
#![forbid(unsafe_code)]

#[cfg(test)]
extern crate std;

pub mod anon;
pub mod exporter;
pub mod qsecbit;
pub mod queue;
pub mod record;
pub mod slot;
pub mod wire;

#[cfg(test)]
mod testutil;
