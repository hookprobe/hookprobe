//! MAC-flood probe (ADR 0020 D8 Phase-1b, L2) — sends bare Ethernet frames with a fast-incrementing,
//! locally-administered source MAC on every frame, exercising `napse_loader::l2guard::
//! MacFloodTracker` (already wired into `napse-dpi`'s live capture loop). Verify-fired is done by
//! the CALLER (the CLI): read the DUT's `events` stream for an `l2_mac_flood` alert emitted after
//! this probe's `start_ts` — this module only sends; it never reads DUT telemetry itself (keeps the
//! send path and the verify-fired path independently auditable).
//!
//! Needs `unsafe` (raw AF_PACKET send, via `sockets::send_frame`) — same convention as
//! `modules/napse-capture/loader`'s own capture bin: checked libc calls, no blanket crate-level
//! `forbid(unsafe_code)` (the crate root's `#![forbid(unsafe_code)]` in `engine/src/lib.rs` does NOT
//! apply across the `#[path]`-included `probes` tree's individual files that need it — Rust's
//! `forbid` is enforced per lexical scope from the attribute's own crate-root position, and this
//! module intentionally sits outside that scope by not re-asserting it here).
use crate::kill_switch::KillSwitch;
use crate::limiter::Limiter;
use crate::packet::build_eth_frame;
use crate::sockets::{iface_mac, open_afpacket_tx, send_frame};
use crate::target_guard::ValidatedL2Scope;
use anyhow::Result;

pub struct MacFloodStats {
    pub frames_sent: u32,
    pub aborted_reason: Option<String>,
}

/// Craft a locally-administered (bit 1 of the first octet set — never a real vendor OUI, so this
/// probe's traffic is trivially distinguishable from anything a genuine device would ever emit) MAC
/// derived deterministically from `counter`, so a campaign is reproducible given the same
/// `repro_seed`-derived starting counter.
pub fn synthetic_src_mac(counter: u32) -> [u8; 6] {
    let b = counter.to_be_bytes();
    [0x02, 0x00, b[0], b[1], b[2], b[3]]
}

/// Fire `frame_count` frames (bounded further by `limiter`/`kill_switch`, whichever is smaller) at
/// `dst_mac` (broadcast, `ff:ff:ff:ff:ff:ff`, by convention for a flood) over `scope`'s iface. This
/// function's ONLY way to run is with an already-validated `ValidatedL2Scope` — there is no other
/// public constructor for that type (see `target_guard.rs`).
pub fn run(scope: &ValidatedL2Scope, limiter: &Limiter, kill_switch: &KillSwitch, frame_count: u32, dst_mac: [u8; 6], start_counter: u32) -> Result<MacFloodStats> {
    let sock = open_afpacket_tx(scope.iface())?;
    let _own_mac = iface_mac(scope.iface())?; // sanity: interface is real and readable
    let mut sent = 0u32;
    for i in 0..frame_count {
        if kill_switch.tripped() {
            return Ok(MacFloodStats { frames_sent: sent, aborted_reason: Some("kill-switch tripped".into()) });
        }
        let src = synthetic_src_mac(start_counter.wrapping_add(i));
        let frame = build_eth_frame(dst_mac, src, 0x0800, b"redteam-mac-flood-probe");
        if let Err(e) = limiter.admit(frame.len() as u64) {
            return Ok(MacFloodStats { frames_sent: sent, aborted_reason: Some(e.to_string()) });
        }
        send_frame(&sock, &frame)?;
        sent += 1;
    }
    Ok(MacFloodStats { frames_sent: sent, aborted_reason: None })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn synthetic_macs_are_locally_administered_and_distinct() {
        let a = synthetic_src_mac(1);
        let b = synthetic_src_mac(2);
        assert_eq!(a[0] & 0x02, 0x02, "locally-administered bit must be set");
        assert_ne!(a, b, "consecutive counters must produce distinct source MACs");
    }
}
