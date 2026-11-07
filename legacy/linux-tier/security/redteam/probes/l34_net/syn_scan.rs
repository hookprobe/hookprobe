//! SYN-only port-scan fan-out + SYN-flood state-exhaustion probes (ADR 0020 D8 Phase-1b, D5's Gate
//! R thresholds table) — validates `napse_loader::portscan::PortScanTracker` (distinct-port
//! fan-out threshold), `napse_loader::confirm::HandshakeTracker` (the confirmation gate: an
//! off-path spoofer can never complete the 3-way handshake), and
//! `hookprobe_manifest::scan_responder::{decide, reconcile_quarantine}`'s bounded enforced set
//! (`DEFAULT_MAX_QUARANTINE_ENTRIES`, ADR 0018 D6). Verify-fired is the CALLER's job (read the DUT's
//! `events`/response stream after the probe returns) — this module only sends.
use crate::kill_switch::KillSwitch;
use crate::limiter::Limiter;
use crate::packet::build_eth_ipv4_tcp_frame;
use crate::sockets::{open_afpacket_tx, send_frame};
use crate::target_guard::ValidatedTarget;
use anyhow::Result;
use std::net::IpAddr;

pub struct ScanStats {
    pub frames_sent: u32,
    pub aborted_reason: Option<String>,
}

fn ipv4_octets(ip: IpAddr) -> Result<[u8; 4]> {
    match ip {
        IpAddr::V4(v4) => Ok(v4.octets()),
        IpAddr::V6(_) => anyhow::bail!("syn_scan: IPv6 targets not yet supported"),
    }
}

/// Fan out ONE SYN-only segment to each of `dst_ports`, from a single (real, un-spoofed) source —
/// the "SYN-only fan-out portscan" row of the ADR 0020 D5 threshold table. This is the BENIGN /
/// non-spoofed shape: a real, completed source should be `confirmed` by `HandshakeTracker` for
/// every OTHER connection it makes, but this probe deliberately sends SYN-only (never completes the
/// handshake) so the fan-out itself is what should trip `PortScanTracker`'s threshold — proving the
/// detector fires on volume/pattern, independent of confirmation state.
pub fn run_fan_out_scan(
    target: &ValidatedTarget,
    limiter: &Limiter,
    kill_switch: &KillSwitch,
    src_mac: [u8; 6],
    src_ip: [u8; 4],
    dst_mac: [u8; 6],
    dst_ports: &[u16],
) -> Result<ScanStats> {
    let sock = open_afpacket_tx(target.iface())?;
    let dst_ip = ipv4_octets(target.ip())?;
    let mut sent = 0u32;
    for (i, &port) in dst_ports.iter().enumerate() {
        if kill_switch.tripped() {
            return Ok(ScanStats { frames_sent: sent, aborted_reason: Some("kill-switch tripped".into()) });
        }
        let frame = build_eth_ipv4_tcp_frame(
            dst_mac, src_mac, src_ip, dst_ip,
            40000 + (i as u16 % 20000), port,
            1, i as u16, true, false, false, // SYN-only
        );
        if let Err(e) = limiter.admit(frame.len() as u64) {
            return Ok(ScanStats { frames_sent: sent, aborted_reason: Some(e.to_string()) });
        }
        send_frame(&sock, &frame)?;
        sent += 1;
    }
    Ok(ScanStats { frames_sent: sent, aborted_reason: None })
}

/// SYN-flood / L4 state-exhaustion — validates `scan_responder::reconcile_quarantine`'s
/// `DEFAULT_MAX_QUARANTINE_ENTRIES` bound (ADR 0018 D6): sends SYN-only segments from
/// `distinct_sources` DIFFERENT (forged) source IPs, each of which should be OBSERVED but never
/// CONFIRMED (an off-path spoofer cannot complete a validated handshake — `confirm.rs`), and the RED
/// Gate-R threshold this maps to is "the confirmation tracker or quarantine set grows UNBOUNDED
/// under flood" (an OOM/budget breach), not merely "detections fired." Source IPs are chosen from
/// the SAME already-in-scope DUT CIDR as the validated target — spoofing the SOURCE field is the
/// entire point of this attack class; `target_guard` validates the DESTINATION only (by design: a
/// forged source is attacker-controlled input the DUT's own defenses must reject, not something the
/// harness's own scope contract is meant to constrain).
pub fn run_state_exhaustion(
    target: &ValidatedTarget,
    limiter: &Limiter,
    kill_switch: &KillSwitch,
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    distinct_sources: u32,
    dst_port: u16,
) -> Result<ScanStats> {
    let sock = open_afpacket_tx(target.iface())?;
    let dst_ip = ipv4_octets(target.ip())?;
    let mut sent = 0u32;
    for i in 0..distinct_sources {
        if kill_switch.tripped() {
            return Ok(ScanStats { frames_sent: sent, aborted_reason: Some("kill-switch tripped".into()) });
        }
        // Vary the low two octets of the forged source within the DUT's own /24 -- stays within
        // the declared 10.99.0.0/24 scope (never escapes to a real network) while still exercising
        // "many distinct source IPs" against the confirmation/quarantine state machines.
        let src_ip = [10, 99, ((i >> 8) & 0xff) as u8, (i & 0xff) as u8];
        let frame = build_eth_ipv4_tcp_frame(
            dst_mac, src_mac, src_ip, dst_ip,
            40000 + (i as u16 % 20000), dst_port,
            1, i as u16, true, false, false,
        );
        if let Err(e) = limiter.admit(frame.len() as u64) {
            return Ok(ScanStats { frames_sent: sent, aborted_reason: Some(e.to_string()) });
        }
        send_frame(&sock, &frame)?;
        sent += 1;
    }
    Ok(ScanStats { frames_sent: sent, aborted_reason: None })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_octets_extracts_correctly() {
        let ip: IpAddr = "10.99.0.2".parse().unwrap();
        assert_eq!(ipv4_octets(ip).unwrap(), [10, 99, 0, 2]);
    }

    #[test]
    fn ipv6_target_is_rejected_honestly() {
        let ip: IpAddr = "::1".parse().unwrap();
        assert!(ipv4_octets(ip).is_err());
    }
}
