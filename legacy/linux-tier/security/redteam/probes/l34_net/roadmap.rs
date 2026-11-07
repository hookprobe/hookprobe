//! Declared-but-not-yet-built L3/L4 probes (ADR 0020 D1/D8 honesty rule — see
//! `l2_link/roadmap.rs`'s doc comment for the same discipline applied here).
#![forbid(unsafe_code)]

use anyhow::{bail, Result};

/// WAN-ingress spoof of the gateway/resolver.
///
/// Validates `scan_responder::is_wan_ingress_martian` and the ADR 0018 Q5 regression (a LAN
/// attacker scanning the gateway/resolver evades detection, marked martian). NOT YET IMPLEMENTED:
/// this attack is defined by the WAN-vs-LAN interface distinction
/// (`is_wan_ingress_martian(src_ip, dst_ip, wan_self_ips)` needs a genuinely WAN-classified
/// ingress interface), which the current single-subnet `dut/netns-dut.sh` topology does not model
/// (it stands up one flat `10.99.0.0/24` veth pair, not a dual-homed WAN+LAN DUT). Building this
/// probe for real needs a second veth pair (a synthetic WAN leg) added to the DUT harness; tracked
/// here as the honest gap rather than faked against the wrong topology.
pub fn wan_ingress_spoof() -> Result<()> {
    bail!(
        "wan_ingress_spoof: ROADMAP -- needs a dual-homed WAN+LAN netns DUT topology, which \
         dut/netns-dut.sh does not yet provide (single flat /24 today); scan_responder::\
         is_wan_ingress_martian is unit-tested directly (crates/hookprobe-manifest/src/\
         scan_responder.rs) but has no on-wire probe against this DUT yet"
    )
}

/// IP fragmentation overlap/reassembly attacks — validates the DUT's fragment-reassembly path
/// (not yet a named component in `napse_loader::dpi`). NOT YET IMPLEMENTED.
pub fn frag_overlap() -> Result<()> {
    bail!("frag_overlap: ROADMAP -- not yet implemented (no named fragment-reassembly detector to validate against yet)")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roadmap_probes_never_fabricate_a_pass() {
        assert!(wan_ingress_spoof().is_err());
        assert!(frag_overlap().is_err());
    }
}
