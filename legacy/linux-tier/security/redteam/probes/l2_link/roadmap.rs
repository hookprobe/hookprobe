//! Declared-but-not-yet-built L2 probes (ADR 0020 D1/D8 honesty rule: "a probe class for a
//! component that does not exist yet is declared, marked ROADMAP, and never emits a synthetic
//! PASS"). Each function here returns `Err` unconditionally — a caller that wires one into a
//! campaign gets a loud, honest failure, never a fabricated finding.
#![forbid(unsafe_code)]

use anyhow::{bail, Result};

/// Asymmetric/malformed ARP spoofing — validates `napse_loader::l2guard::ArpGuard`'s flip-flop /
/// gratuitous-ARP detectors. NOT YET IMPLEMENTED as a send-path probe (Phase-1b follow-up: the
/// packet-crafting is straightforward given `packet.rs`'s helpers, but was not built in this pass —
/// tracked here rather than silently absent).
pub fn arp_spoof() -> Result<()> {
    bail!("arp_spoof: ROADMAP -- not yet implemented (Phase-1b follow-up); ArpGuard exists and is unit-tested (l2guard.rs) but has no on-wire probe yet")
}

/// Broadcast/LLDP/DHCP amplification — validates `napse_loader::l2guard::BroadcastStormTracker`.
/// NOT YET IMPLEMENTED.
pub fn broadcast_amplification() -> Result<()> {
    bail!("broadcast_amplification: ROADMAP -- not yet implemented (Phase-1b follow-up)")
}

/// Frame/VLAN fuzzing — validates `napse_loader::l2guard::MalformedFrameGate` /
/// `napse_loader::dpi::frame_anomaly_reason`. NOT YET IMPLEMENTED.
pub fn frame_vlan_fuzz() -> Result<()> {
    bail!("frame_vlan_fuzz: ROADMAP -- not yet implemented (Phase-1b follow-up)")
}

/// 802.11 frame-source forgery — per ADR 0020 D1/D8: needs a REAL RADIO lab rig; a netns/veth DUT
/// is structurally incapable of testing this (ADR 0018 residual #1). Always ROADMAP, never built
/// against a netns DUT — this function exists only so the probe matrix names the gap explicitly.
pub fn wifi_80211_frame_forgery() -> Result<()> {
    bail!("wifi_80211_frame_forgery: ROADMAP, requires real-radio lab rig -- structurally out of scope for a netns/veth DUT (ADR 0020 D1)")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_roadmap_probe_errs_never_fabricates_a_pass() {
        assert!(arp_spoof().is_err());
        assert!(broadcast_amplification().is_err());
        assert!(frame_vlan_fuzz().is_err());
        assert!(wifi_80211_frame_forgery().is_err());
    }
}
