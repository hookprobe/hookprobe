//! Rules-of-engagement loader (ADR 0020 D3) — parses `rules-of-engagement.yaml` and enforces, AT
//! LOAD TIME, the shape the six threat-model conditions require. A missing/malformed file, or one
//! that fails any of these checks, is a hard `Err` — the caller (target_guard / the campaign
//! runner) MUST refuse to start on `Err`, never fall back to a permissive default. There is no
//! `--force` anywhere in this crate; if you are looking for one, stop — it does not exist by design
//! (ADR 0020 D3 contract #1).
#![forbid(unsafe_code)]

use anyhow::{bail, Context, Result};
use serde::Deserialize;
use std::net::IpAddr;
use std::path::Path;

#[derive(Debug, Clone, Deserialize)]
pub struct AllowedTarget {
    pub cidr: Option<String>,
    pub interface: Option<String>,
    pub netns: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Limits {
    pub max_pps_per_probe: u64,
    pub max_frames_per_campaign: u64,
    pub max_bytes_per_campaign: u64,
    pub max_wall_clock_seconds: u64,
    pub max_concurrency: u32,
}

#[derive(Debug, Clone, Deserialize)]
pub struct KillSwitch {
    pub file: String,
    pub signal: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct HardDeny {
    pub any_public_ip: bool,
    pub wan_interface: bool,
    pub dns_resolution: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RequireIsolation {
    pub network_namespace: bool,
    pub l2_egress_must_be_veth: bool,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct Hil {
    #[serde(default)]
    pub enabled: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Roe {
    pub version: u32,
    pub mode: String,
    pub allowed_targets: Vec<AllowedTarget>,
    #[serde(default)]
    pub allowed_target_files: Vec<String>,
    pub limits: Limits,
    pub kill_switch: KillSwitch,
    pub hard_deny: HardDeny,
    pub require_isolation: RequireIsolation,
    #[serde(default)]
    pub hil: Hil,
}

/// A parsed, in-scope CIDR entry: the numeric network + prefix length. Computed once at load time
/// from the ROE's literal `cidr:` string — NEVER re-derived from a name (there is no name to derive
/// it from; condition 3 guarantees every `cidr:` entry is already a literal, checked here).
#[derive(Debug, Clone, Copy)]
pub struct ParsedCidr {
    pub network: IpAddr,
    pub prefix_len: u8,
}

impl ParsedCidr {
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.network, ip) {
            (IpAddr::V4(net), IpAddr::V4(addr)) => {
                let mask: u32 = if self.prefix_len == 0 {
                    0
                } else {
                    u32::MAX << (32 - self.prefix_len)
                };
                (u32::from(net) & mask) == (u32::from(addr) & mask)
            }
            (IpAddr::V6(net), IpAddr::V6(addr)) => {
                let mask: u128 = if self.prefix_len == 0 {
                    0
                } else {
                    u128::MAX << (128 - self.prefix_len)
                };
                (u128::from(net) & mask) == (u128::from(addr) & mask)
            }
            _ => false,
        }
    }
}

/// One resolved-and-validated allow-listed scope entry: a CIDR (parsed once, numerically, from the
/// literal string in the file — condition 3) plus the interface/netns it is pinned to.
#[derive(Debug, Clone)]
pub struct ResolvedTarget {
    pub cidr: ParsedCidr,
    pub interface: Option<String>,
    pub netns: Option<String>,
}

impl Roe {
    /// Load + fully validate a ROE file. Every failure mode here is fail-closed: `Err` means "the
    /// engine must not fire a single probe," full stop.
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("ROE file not found or unreadable: {}", path.display()))?;
        let roe: Roe = serde_yaml::from_str(&text)
            .with_context(|| format!("ROE file is malformed YAML: {}", path.display()))?;
        roe.validate()?;
        Ok(roe)
    }

    /// Load from an in-memory string (used by tests + anywhere the caller already has the bytes,
    /// e.g. read once and hashed for the pre-fire `attack_run` audit — see `roe_hash`).
    pub fn parse(text: &str) -> Result<Self> {
        let roe: Roe = serde_yaml::from_str(text).context("ROE is malformed YAML")?;
        roe.validate()?;
        Ok(roe)
    }

    /// The load-time shape checks the six threat-model conditions require (ADR 0020 D3). This is
    /// deliberately paranoid: a boolean field that is merely ABSENT from the YAML would deserialize
    /// via `Default` in a naive schema, silently defeating the condition it names — so every
    /// safety-relevant field here is a REQUIRED (non-`Option`, non-`#[serde(default)]`) field in the
    /// struct, and this function additionally asserts the VALUE, not just the presence.
    fn validate(&self) -> Result<()> {
        if self.version != 1 {
            bail!("ROE version {} unsupported (expected 1)", self.version);
        }
        if self.mode != "dut-self-test" {
            bail!(
                "ROE mode {:?} is not 'dut-self-test' -- the ONLY supported mode; refusing to start",
                self.mode
            );
        }
        if self.allowed_targets.is_empty() {
            bail!("ROE allowed_targets is empty -- default-deny means nothing is in scope; refusing to start");
        }
        for t in &self.allowed_targets {
            if t.cidr.is_none() && t.netns.is_none() {
                bail!("ROE allowed_targets entry has neither cidr nor netns -- malformed scope entry");
            }
            if let Some(cidr) = &t.cidr {
                parse_cidr_literal(cidr).with_context(|| {
                    format!(
                        "ROE allowed_targets cidr {cidr:?} is not a valid IP/CIDR LITERAL \
                         (condition 3: DNS names are FORBIDDEN here, always)"
                    )
                })?;
            }
        }
        // Condition 1: a missing OR zero limit is itself a refuse-to-start.
        let l = &self.limits;
        if l.max_pps_per_probe == 0
            || l.max_frames_per_campaign == 0
            || l.max_bytes_per_campaign == 0
            || l.max_wall_clock_seconds == 0
            || l.max_concurrency == 0
        {
            bail!("ROE limits: block has a zero field -- condition 1 requires every limit to be a real, positive ceiling");
        }
        // Condition 3: dns_resolution must be the literal `true` (i.e. the hard-deny is ACTIVE).
        if !self.hard_deny.dns_resolution {
            bail!("ROE hard_deny.dns_resolution must be true -- DNS resolution is ALWAYS forbidden (condition 3)");
        }
        if !self.hard_deny.any_public_ip {
            bail!("ROE hard_deny.any_public_ip must be true -- routable/public targets are ALWAYS forbidden");
        }
        if !self.hard_deny.wan_interface {
            bail!("ROE hard_deny.wan_interface must be true -- a WAN-classified interface is ALWAYS forbidden");
        }
        // Condition 2: topology isolation must be required, not merely advised.
        if !self.require_isolation.network_namespace {
            bail!("ROE require_isolation.network_namespace must be true -- condition 2");
        }
        if !self.require_isolation.l2_egress_must_be_veth {
            bail!("ROE require_isolation.l2_egress_must_be_veth must be true -- condition 2");
        }
        if self.kill_switch.file.trim().is_empty() {
            bail!("ROE kill_switch.file is empty -- condition 5 needs a real sentinel path");
        }
        Ok(())
    }

    /// The resolved, ready-to-check scope list — CIDRs parsed ONCE, numerically (condition 3: no
    /// re-lookup ever happens between this and a later `send()`).
    pub fn resolved_targets(&self) -> Result<Vec<ResolvedTarget>> {
        self.allowed_targets
            .iter()
            .filter_map(|t| {
                t.cidr.as_ref().map(|c| {
                    let cidr = parse_cidr_literal(c)?;
                    Ok(ResolvedTarget {
                        cidr,
                        interface: t.interface.clone(),
                        netns: t.netns.clone(),
                    })
                })
            })
            .collect()
    }

    /// Deterministic hash of the loaded ROE's own bytes — recorded on the pre-fire `attack_run`
    /// audit node (ADR 0020 D3 contract #5 / D6) so a campaign is forever traceable to the EXACT
    /// scope contract it ran under. FNV-1a (same fixed, non-toolchain-dependent algorithm
    /// `hookprobe-evidence::sid` uses) -- deliberately not `DefaultHasher` (unstable across
    /// releases) and not a crypto hash (no signing claim is made here, only content-identity).
    pub fn hash_of(text: &str) -> String {
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        for b in text.as_bytes() {
            h ^= *b as u64;
            h = h.wrapping_mul(0x0000_0100_0000_01b3);
        }
        format!("{h:016x}")
    }
}

/// Parse a numeric IP/CIDR literal string ("10.99.0.0/24" or a bare IP, defaulting to a /32 or
/// /128 host route). Returns `Err` for ANYTHING that is not already numeric -- there is
/// deliberately no fallback to a resolver anywhere in this function or its callers (condition 3).
pub fn parse_cidr_literal(s: &str) -> Result<ParsedCidr> {
    let (addr_part, prefix_part) = match s.split_once('/') {
        Some((a, p)) => (a, Some(p)),
        None => (s, None),
    };
    let addr: IpAddr = addr_part
        .parse()
        .with_context(|| format!("{addr_part:?} is not a numeric IP literal (DNS names are forbidden)"))?;
    let max_prefix = if addr.is_ipv4() { 32u8 } else { 128u8 };
    let prefix_len = match prefix_part {
        Some(p) => p
            .parse::<u8>()
            .with_context(|| format!("{p:?} is not a valid prefix length"))?,
        None => max_prefix,
    };
    if prefix_len > max_prefix {
        bail!("prefix length {prefix_len} exceeds {max_prefix} for {addr}");
    }
    Ok(ParsedCidr { network: addr, prefix_len })
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD: &str = r#"
version: 1
mode: dut-self-test
allowed_targets:
  - cidr: 10.99.0.0/24
    interface: veth-dut
allowed_target_files: []
limits:
  max_pps_per_probe: 50000
  max_frames_per_campaign: 5000000
  max_bytes_per_campaign: 4294967296
  max_wall_clock_seconds: 300
  max_concurrency: 4
kill_switch:
  file: /run/redteam/STOP
  signal: SIGTERM
hard_deny:
  any_public_ip: true
  wan_interface: true
  dns_resolution: true
require_isolation:
  network_namespace: true
  l2_egress_must_be_veth: true
"#;

    #[test]
    fn parses_a_well_formed_roe() {
        let roe = Roe::parse(GOOD).expect("well-formed ROE must parse");
        assert_eq!(roe.mode, "dut-self-test");
        assert_eq!(roe.resolved_targets().unwrap().len(), 1);
    }

    #[test]
    fn refuses_wrong_mode() {
        let bad = GOOD.replace("dut-self-test", "production-yolo");
        assert!(Roe::parse(&bad).is_err(), "a non-dut-self-test mode must refuse to start");
    }

    #[test]
    fn refuses_dns_resolution_false() {
        let bad = GOOD.replace("dns_resolution: true", "dns_resolution: false");
        assert!(Roe::parse(&bad).is_err(), "hard_deny.dns_resolution=false must refuse to start");
    }

    #[test]
    fn refuses_hostname_as_target() {
        let bad = GOOD.replace("10.99.0.0/24", "dut.example.com");
        assert!(Roe::parse(&bad).is_err(), "a hostname target must be a hard parse error (condition 3)");
    }

    #[test]
    fn refuses_zero_limit() {
        let bad = GOOD.replace("max_pps_per_probe: 50000", "max_pps_per_probe: 0");
        assert!(Roe::parse(&bad).is_err(), "a zero limit is itself a refuse-to-start (condition 1)");
    }

    #[test]
    fn refuses_missing_isolation() {
        let bad = GOOD.replace("l2_egress_must_be_veth: true", "l2_egress_must_be_veth: false");
        assert!(Roe::parse(&bad).is_err(), "condition 2 must be enforced true");
    }

    #[test]
    fn refuses_empty_allowed_targets() {
        let bad = GOOD.replace(
            "allowed_targets:\n  - cidr: 10.99.0.0/24\n    interface: veth-dut",
            "allowed_targets: []",
        );
        assert!(Roe::parse(&bad).is_err(), "default-deny: an empty scope is a refuse-to-start, not 'nothing in scope'");
    }

    #[test]
    fn refuses_malformed_yaml() {
        assert!(Roe::parse("not: [valid, yaml: {{{").is_err());
    }

    #[test]
    fn cidr_contains_works() {
        let c = parse_cidr_literal("10.99.0.0/24").unwrap();
        assert!(c.contains("10.99.0.42".parse().unwrap()));
        assert!(!c.contains("10.100.0.1".parse().unwrap()));
        assert!(!c.contains("192.168.1.1".parse().unwrap()));
    }

    #[test]
    fn bare_ip_is_a_host_route() {
        let c = parse_cidr_literal("10.99.0.2").unwrap();
        assert!(c.contains("10.99.0.2".parse().unwrap()));
        assert!(!c.contains("10.99.0.3".parse().unwrap()));
    }

    #[test]
    fn hash_is_deterministic() {
        assert_eq!(Roe::hash_of(GOOD), Roe::hash_of(GOOD));
        assert_ne!(Roe::hash_of(GOOD), Roe::hash_of("different"));
    }
}
