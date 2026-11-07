//! `target_guard` — the single most important control in ADR 0020 (D3). Runs BEFORE the first byte
//! of any probe leaves the process: before raw-socket creation, before any AF_PACKET/AF_XDP send,
//! before any TCP connect. A probe can only ever obtain a send path by first exchanging its intent
//! for a `ValidatedTarget` (L3/L4) or `ValidatedL2Scope` (L2/broadcast) token from this module --
//! both types have private fields and no public constructor, so the type system itself enforces
//! contract #2 ("no raw socket without a validated target"): there is no code path in this crate
//! that can construct one without passing every check below.
#![forbid(unsafe_code)]

use crate::kill_switch::KillSwitch;
use crate::roe::{parse_cidr_literal, ResolvedTarget, Roe};
use crate::topology::{assert_l2_veth_topology, Topology};
use anyhow::{bail, Result};
use std::net::IpAddr;

/// An L3/L4-validated destination: resolve-then-assert has already happened, and the exact IP
/// bytes are captured HERE, once (condition 3: no re-lookup ever happens between this and `send()`
/// -- there is nothing to re-look-up, this struct already IS the concrete numeric destination).
#[derive(Debug, Clone)]
pub struct ValidatedTarget {
    ip: IpAddr,
    iface: String,
}

impl ValidatedTarget {
    pub fn ip(&self) -> IpAddr {
        self.ip
    }
    pub fn iface(&self) -> &str {
        &self.iface
    }
}

/// An L2/broadcast-validated egress scope: the topology assertion (condition 2) has already passed
/// for this exact (iface, netns) pair. L2 probes take this instead of a `ValidatedTarget` because a
/// broadcast/multicast frame carries no unicast IP destination for the L3 check to examine.
#[derive(Debug, Clone)]
pub struct ValidatedL2Scope {
    iface: String,
    netns: String,
}

impl ValidatedL2Scope {
    pub fn iface(&self) -> &str {
        &self.iface
    }
    pub fn netns(&self) -> &str {
        &self.netns
    }
}

pub struct TargetGuard {
    roe: Roe,
    resolved: Vec<ResolvedTarget>,
    topo: Box<dyn Topology + Send + Sync>,
    kill_switch: KillSwitch,
}

/// RFC1918 / CGNAT / loopback / link-local ONLY — a routable/public destination is ALWAYS refused
/// (`hard_deny.any_public_ip`). This is deliberately conservative: anything not affirmatively
/// private is treated as public (fail closed on an unrecognized range, never fail open).
pub fn is_private_scope(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            v4.is_loopback()
                || v4.is_link_local()
                || o[0] == 10
                || (o[0] == 172 && (16..=31).contains(&o[1]))
                || (o[0] == 192 && o[1] == 168)
                || (o[0] == 100 && (64..=127).contains(&o[1])) // CGNAT 100.64.0.0/10
        }
        IpAddr::V6(v6) => v6.is_loopback() || v6.is_unique_local() || v6.is_unicast_link_local(),
    }
}

impl TargetGuard {
    pub fn new(roe: Roe, topo: Box<dyn Topology + Send + Sync>) -> Result<Self> {
        let resolved = roe.resolved_targets()?;
        let kill_switch = KillSwitch::new(roe.kill_switch.file.clone());
        Ok(Self { roe, resolved, topo, kill_switch })
    }

    pub fn kill_switch(&self) -> &KillSwitch {
        &self.kill_switch
    }

    pub fn roe(&self) -> &Roe {
        &self.roe
    }

    /// Condition-checked L3/L4 validation. `ip` and `iface` MUST already be numeric/literal (the
    /// caller -- a probe -- never resolves a name; if it has a name it is already in violation and
    /// this function has nothing to protect against a caller that skipped `parse_cidr_literal`
    /// itself, which is exactly why `ValidatedTarget` has no public constructor other than this).
    pub fn validate_l3(&self, ip: IpAddr, iface: &str) -> Result<ValidatedTarget> {
        if self.kill_switch.tripped() {
            bail!("kill-switch tripped -- refusing to validate any further targets");
        }
        if self.roe.hard_deny.any_public_ip && !is_private_scope(ip) {
            bail!("target {ip} is not an RFC1918/CGNAT/loopback/link-local address -- refusing (hard_deny.any_public_ip)");
        }
        let matched = self
            .resolved
            .iter()
            .find(|t| t.cidr.contains(ip) && t.interface.as_deref() == Some(iface));
        let Some(_matched) = matched else {
            bail!(
                "target {ip} on iface {iface:?} is NOT within any allowed_targets entry -- default-deny, refusing"
            );
        };
        Ok(ValidatedTarget { ip, iface: iface.to_string() })
    }

    /// Same as `validate_l3` but the destination bytes are supplied as a literal string (e.g. from
    /// a probe's own CLI arg) -- parsed here via `parse_cidr_literal`'s single-IP form, which is a
    /// hard `Err` for anything that isn't already numeric. There is NO code path anywhere in this
    /// crate that calls a DNS resolver; this function is the only place a string ever becomes an
    /// `IpAddr`, and it does so exactly once, immediately before validation, never again before send.
    pub fn validate_l3_literal(&self, ip_literal: &str, iface: &str) -> Result<ValidatedTarget> {
        let parsed = parse_cidr_literal(ip_literal)?;
        self.validate_l3(parsed.network, iface)
    }

    /// Condition-2 L2/broadcast validation: `iface` must be a ROE-declared veth whose peer is
    /// netlink-verified resident in `netns`, and `netns` must have no default route. This is the
    /// ONLY way a probe can obtain a `ValidatedL2Scope` -- there is no other constructor.
    pub fn validate_l2(&self, iface: &str, netns: &str) -> Result<ValidatedL2Scope> {
        if self.kill_switch.tripped() {
            bail!("kill-switch tripped -- refusing to validate any further L2 scope");
        }
        if !self.roe.require_isolation.network_namespace || !self.roe.require_isolation.l2_egress_must_be_veth {
            bail!("ROE does not require netns+veth isolation -- refusing all L2 probes (condition 2 is mandatory)");
        }
        let declared = self
            .resolved
            .iter()
            .any(|t| t.interface.as_deref() == Some(iface) || t.netns.as_deref() == Some(netns));
        if !declared {
            bail!("iface {iface:?} / netns {netns:?} is not a declared ROE scope entry -- refusing");
        }
        assert_l2_veth_topology(self.topo.as_ref(), iface, netns)?;
        Ok(ValidatedL2Scope { iface: iface.to_string(), netns: netns.to_string() })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::topology::LinkInfo;
    use std::collections::HashMap;

    const ROE_YAML: &str = r#"
version: 1
mode: dut-self-test
allowed_targets:
  - cidr: 10.99.0.0/24
    interface: veth-dut
  - netns: hookprobe-dut
allowed_target_files: []
limits:
  max_pps_per_probe: 50000
  max_frames_per_campaign: 5000000
  max_bytes_per_campaign: 4294967296
  max_wall_clock_seconds: 300
  max_concurrency: 4
kill_switch:
  file: /nonexistent/redteam-test-kill-switch/STOP
  signal: SIGTERM
hard_deny:
  any_public_ip: true
  wan_interface: true
  dns_resolution: true
require_isolation:
  network_namespace: true
  l2_egress_must_be_veth: true
"#;

    struct FakeTopo {
        links: HashMap<String, LinkInfo>,
        netns: HashMap<String, (Vec<i64>, Vec<String>)>,
    }
    impl Topology for FakeTopo {
        fn link_info(&self, iface: &str) -> Result<LinkInfo> {
            self.links.get(iface).cloned().ok_or_else(|| anyhow::anyhow!("no such iface"))
        }
        fn netns_ifindexes(&self, netns: &str) -> Result<Vec<i64>> {
            Ok(self.netns.get(netns).map(|x| x.0.clone()).unwrap_or_default())
        }
        fn netns_exists(&self, netns: &str) -> Result<bool> {
            Ok(self.netns.contains_key(netns))
        }
        fn netns_routes(&self, netns: &str) -> Result<Vec<String>> {
            Ok(self.netns.get(netns).map(|x| x.1.clone()).unwrap_or_default())
        }
    }

    fn good_topo() -> FakeTopo {
        let mut links = HashMap::new();
        links.insert("veth-dut".to_string(), LinkInfo { ifindex: 10, kind: Some("veth".to_string()), iflink: 11 });
        let mut netns = HashMap::new();
        netns.insert("hookprobe-dut".to_string(), (vec![1, 11], vec!["10.99.0.0/24 dev veth-dut-peer".to_string()]));
        FakeTopo { links, netns }
    }

    fn guard() -> TargetGuard {
        let roe = Roe::parse(ROE_YAML).unwrap();
        TargetGuard::new(roe, Box::new(good_topo())).unwrap()
    }

    #[test]
    fn accepts_an_in_scope_target() {
        let g = guard();
        assert!(g.validate_l3_literal("10.99.0.42", "veth-dut").is_ok());
    }

    #[test]
    fn refuses_a_public_ip() {
        let g = guard();
        assert!(g.validate_l3_literal("8.8.8.8", "veth-dut").is_err());
    }

    #[test]
    fn refuses_an_out_of_cidr_private_ip() {
        // 192.168.1.1 IS private, but it's not in the DECLARED allowed_targets CIDR -- default-deny.
        let g = guard();
        assert!(g.validate_l3_literal("192.168.1.1", "veth-dut").is_err());
    }

    #[test]
    fn refuses_the_wrong_interface() {
        let g = guard();
        assert!(g.validate_l3_literal("10.99.0.42", "eth0").is_err());
    }

    #[test]
    fn refuses_a_hostname_it_cannot_parse() {
        let g = guard();
        assert!(g.validate_l3_literal("dut.example.com", "veth-dut").is_err());
    }

    #[test]
    fn refuses_wan_looking_interface_names_too_by_default_deny() {
        // "wan0" is not a declared scope entry at all -- default-deny catches it regardless of
        // whether it's literally the WAN uplink; there is no allowlist path for it.
        let g = guard();
        assert!(g.validate_l3_literal("10.99.0.5", "wan0").is_err());
    }

    #[test]
    fn l2_validation_passes_with_correct_topology() {
        let g = guard();
        assert!(g.validate_l2("veth-dut", "hookprobe-dut").is_ok());
    }

    #[test]
    fn l2_validation_refuses_undeclared_netns() {
        let g = guard();
        assert!(g.validate_l2("veth-dut", "some-other-netns").is_err());
    }

    #[test]
    fn l2_validation_refuses_broken_topology() {
        let roe = Roe::parse(ROE_YAML).unwrap();
        let mut topo = good_topo();
        // simulate a config drift: the interface is no longer actually a veth on this host.
        topo.links.insert("veth-dut".to_string(), LinkInfo { ifindex: 10, kind: Some("ether".to_string()), iflink: 10 });
        let g = TargetGuard::new(roe, Box::new(topo)).unwrap();
        assert!(g.validate_l2("veth-dut", "hookprobe-dut").is_err());
    }

    #[test]
    fn kill_switch_blocks_further_validation() {
        let g = guard();
        assert!(g.validate_l3_literal("10.99.0.42", "veth-dut").is_ok());
        g.kill_switch().trip();
        assert!(g.validate_l3_literal("10.99.0.42", "veth-dut").is_err());
        assert!(g.validate_l2("veth-dut", "hookprobe-dut").is_err());
    }

    #[test]
    fn private_scope_classification() {
        assert!(is_private_scope("10.0.0.1".parse().unwrap()));
        assert!(is_private_scope("192.168.1.1".parse().unwrap()));
        assert!(is_private_scope("172.16.0.1".parse().unwrap()));
        assert!(is_private_scope("100.64.0.1".parse().unwrap()));
        assert!(is_private_scope("127.0.0.1".parse().unwrap()));
        assert!(!is_private_scope("8.8.8.8".parse().unwrap()));
        assert!(!is_private_scope("1.1.1.1".parse().unwrap()));
    }
}
