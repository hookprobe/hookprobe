//! Shared management-path allowlist predicate.
//!
//! This is the SINGLE source of truth for "must this address never be quarantined/blocked by a
//! reflex or responder, because doing so would blackhole the operator's own management path?".
//!
//! It is deliberately factored out of `hookprobe-manifest::scan_responder` (which defined this
//! logic first, for the scan-responder's own quarantine reflex) into its own dependency-free
//! crate so that **`aegis-guard`'s reflex engine can reuse the exact same predicate** without
//! either (a) duplicating the logic — the two enforcement paths would be free to silently drift
//! on what counts as "protected", which is exactly the class of bug this crate exists to prevent
//! — or (b) pulling `hookprobe-manifest`'s much heavier dependency tree (serde, sha2/sha3,
//! ed25519-dalek, ml-dsa, ...) into `aegis-guard`, a capability-sandboxed Wasm module that
//! commits to zero external dependencies.
//!
//! # 2026-07 audit context
//! The live device logged aegis-guard `DISCONNECT`/`block_ip` reflex verdicts targeting the
//! operator's OWN mgmt gateway (`10.200.0.1`) during a benign pentest audit — the exact
//! self-lockout hazard `scan_responder::ProtectPolicy`/`protect_reason` already guards against
//! for the scan-responder's quarantine path. This crate makes that same safety valve available
//! to `aegis-guard::evaluate_reflex` (see that crate for the actual downgrade).

#![forbid(unsafe_code)]

// ---------------------------------------------------------------------------
// SOURCE CLASSIFICATION — LAN vs WAN.
// ---------------------------------------------------------------------------

/// Where a source address sits relative to this device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceKind {
    /// RFC1918 / link-local / CGNAT-shared / loopback — the LAN side (e.g. the `10.66.0.0/24`
    /// clients, the `10.200.0.0/28` mgmt subnet).
    Lan,
    /// Anything else — the public internet (WAN side).
    Wan,
}
impl SourceKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            SourceKind::Lan => "lan",
            SourceKind::Wan => "wan",
        }
    }
}

/// Parse a dotted-quad IPv4 address into its 4 octets, or `None` for anything else (IPv6,
/// hostnames, garbage).
fn ipv4_octets(ip: &str) -> Option<[u8; 4]> {
    let parts: Vec<u8> = ip.split('.').map(|p| p.parse().ok()).collect::<Option<Vec<u8>>>()?;
    if parts.len() != 4 {
        return None;
    }
    Some([parts[0], parts[1], parts[2], parts[3]])
}

/// Classify a source address. Unparseable input (IPv6, garbage) classifies `Wan` — the
/// conservative default: it's the tighter enforcement path and never mistakes an unrecognized
/// address for a trusted LAN client.
pub fn classify_source(ip: &str) -> SourceKind {
    let Some(o) = ipv4_octets(ip) else { return SourceKind::Wan };
    let is_lan = o[0] == 10                              // RFC1918 10/8
        || (o[0] == 172 && (16..=31).contains(&o[1]))     // RFC1918 172.16/12
        || (o[0] == 192 && o[1] == 168)                   // RFC1918 192.168/16
        || (o[0] == 169 && o[1] == 254)                   // link-local 169.254/16
        || (o[0] == 100 && (64..=127).contains(&o[1]))    // CGNAT-shared 100.64/10
        || o[0] == 127; // loopback 127/8
    if is_lan {
        SourceKind::Lan
    } else {
        SourceKind::Wan
    }
}

// ---------------------------------------------------------------------------
// Safety valve — addresses an enforcement path must NEVER quarantine/block.
// ---------------------------------------------------------------------------

/// Addresses an enforcement reflex must NEVER quarantine/block (fail-safe against
/// self-lockout): the admin/mgmt subnet, the gateway, and this device's own WAN address(es). A
/// finding against one of these is logged, never enforced.
///
/// Callers (the scan-responder wrapper, the aegis-guard reflex caller) MUST additionally
/// populate `ips` at runtime with the RESOLVED default gateway and configured DNS resolver(s) of
/// the live uplink — a WAN attacker spoofing exactly those addresses to trigger self-enforcement
/// against this device's own upstream is a concrete DoS. This struct only carries the policy;
/// resolving the live values is the caller's job.
#[derive(Debug, Clone)]
pub struct ProtectPolicy {
    /// CIDRs that are entirely protected (e.g. the mgmt subnet).
    pub cidrs: Vec<String>,
    /// Exact-match protected addresses (gateway, gateway aliases, the current WAN IP, the WAN
    /// default gateway, configured DNS resolvers).
    pub ips: Vec<String>,
    /// Known-good MAC(s) for the LAN-side addresses in `ips`/`cidrs` (lowercase colon-hex). When
    /// non-empty, a LAN-classified source claiming a protected IP is ONLY treated as protected
    /// if its OBSERVED frame MAC is in this set; an on-link impostor spoofing the gateway's IP
    /// from a DIFFERENT MAC does NOT get the mgmt exemption. Left empty by default (no MAC
    /// binding configured yet) preserves IP-only matching for backward compatibility.
    pub lan_macs: Vec<String>,
}
impl Default for ProtectPolicy {
    /// The two addresses named in the runbook: the mgmt subnet `10.200.0.0/28` and the LAN
    /// gateway `10.66.0.1`. The WAN's own (dynamic) address, the WAN default gateway, and DNS
    /// resolvers are added by the caller at runtime since none of those are static constants.
    fn default() -> Self {
        ProtectPolicy {
            cidrs: vec!["10.200.0.0/28".to_string()],
            ips: vec!["10.66.0.1".to_string()],
            lan_macs: Vec::new(),
        }
    }
}

/// Minimal IPv4-in-CIDR test. Returns `false` (never matches) on any malformed input rather than
/// erroring — a safety check that can't parse its input must fail toward "don't claim this is
/// protected", so callers only rely on the explicit `cidrs`/`ips` list, never on this silently
/// matching more than intended.
fn ipv4_in_cidr(ip: &str, cidr: &str) -> bool {
    let (net, plen) = cidr.split_once('/').unwrap_or((cidr, "32"));
    let Ok(prefix) = plen.parse::<u32>() else { return false };
    if prefix > 32 {
        return false;
    }
    let to_u32 = |s: &str| -> Option<u32> {
        let octs: Vec<u32> = s.split('.').map(|p| p.parse().ok()).collect::<Option<Vec<u32>>>()?;
        if octs.len() != 4 {
            return None;
        }
        Some((octs[0] << 24) | (octs[1] << 16) | (octs[2] << 8) | octs[3])
    };
    let (Some(ip_n), Some(net_n)) = (to_u32(ip), to_u32(net)) else { return false };
    let mask: u32 = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
    (ip_n & mask) == (net_n & mask)
}

/// `Some(reason)` if `ip` must NEVER be quarantined/blocked under `policy`; `None` if it's a
/// normal (enforceable) address.
///
/// `observed_mac` is the OBSERVED frame MAC captured at detection time (never an ARP resolution
/// of `ip`, which is exactly as spoofable as `ip` itself). For a [`SourceKind::Lan`] source, if
/// `policy.lan_macs` is configured (non-empty), the IP/CIDR match alone is NOT sufficient — the
/// observed MAC must also be one of `lan_macs`, otherwise this is an on-link impostor spoofing
/// the protected IP from the wrong hardware address, and the mgmt fail-safe does not apply to it
/// (it falls through to normal enforcement evaluation). A WAN source has no MAC to bind (routed)
/// — matching stays IP/CIDR-only, as before.
pub fn protect_reason(ip: &str, observed_mac: Option<&str>, policy: &ProtectPolicy) -> Option<String> {
    let ip_match = if policy.ips.iter().any(|p| p == ip) {
        Some(format!("{ip} is an allowlisted management/gateway/WAN address"))
    } else {
        policy
            .cidrs
            .iter()
            .find(|c| ipv4_in_cidr(ip, c))
            .map(|cidr| format!("{ip} is in the protected management subnet {cidr}"))
    };
    let base_reason = ip_match?;

    if classify_source(ip) == SourceKind::Lan && !policy.lan_macs.is_empty() {
        let mac_ok = observed_mac.is_some_and(|m| policy.lan_macs.iter().any(|k| k.eq_ignore_ascii_case(m)));
        if !mac_ok {
            // The claimed IP is protected, but the hardware address making the claim is not the
            // known-good one for it — refuse the exemption (this is what makes the allowlist
            // MAC-bound rather than trusting the spoofable IP alone).
            return None;
        }
    }
    // NOTE: the exact suffix "NOT quarantined" is relied on by `hookprobe-manifest::scan_responder`
    // tests (it's surfaced verbatim in evidence/response records) — keep it stable. Callers using
    // this predicate outside the quarantine context (e.g. `aegis-guard`'s reflex engine) build
    // their OWN wrapping reason string around this one rather than expecting different wording here.
    Some(format!("{base_reason} — scan logged, NOT quarantined"))
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_source_defaults_unparseable_input_to_wan() {
        assert_eq!(classify_source("not-an-ip"), SourceKind::Wan);
        assert_eq!(classify_source("::1"), SourceKind::Wan, "IPv6 not handled here → Wan (conservative)");
        assert_eq!(classify_source("10.200.0.4"), SourceKind::Lan, "the mgmt subnet, also 10/8");
        assert_eq!(classify_source("8.8.8.8"), SourceKind::Wan);
    }

    #[test]
    fn cidr_match_is_conservative_on_malformed_input() {
        assert!(!ipv4_in_cidr("not-an-ip", "10.0.0.0/8"));
        assert!(!ipv4_in_cidr("10.0.0.1", "not-a-cidr/8"));
        assert!(!ipv4_in_cidr("10.0.0.1", "10.0.0.0/99"));
    }

    #[test]
    fn protects_management_subnet_and_gateway() {
        let p = ProtectPolicy::default();
        assert!(protect_reason("10.200.0.5", None, &p).is_some(), "mgmt subnet /28 must be protected");
        assert!(protect_reason("10.200.0.15", None, &p).is_some(), "still inside /28 (last host)");
        assert!(protect_reason("10.200.0.16", None, &p).is_none(), "just OUTSIDE the /28");
        assert!(protect_reason("10.66.0.1", None, &p).is_some(), "gateway is protected");
        assert!(protect_reason("203.0.113.7", None, &p).is_none(), "a normal external address is NOT protected");
    }

    #[test]
    fn protects_operator_supplied_wan_ip() {
        let p = ProtectPolicy {
            cidrs: vec!["10.200.0.0/28".into()],
            ips: vec!["10.66.0.1".into(), "198.51.100.44".into()],
            lan_macs: Vec::new(),
        };
        assert!(protect_reason("198.51.100.44", None, &p).is_some(), "the live WAN IP, once supplied, is protected");
    }

    #[test]
    fn protect_reason_requires_the_bound_mac_once_lan_macs_is_configured() {
        let p = ProtectPolicy {
            cidrs: vec![],
            ips: vec!["10.66.0.1".into()],
            lan_macs: vec!["aa:bb:cc:dd:ee:ff".into()],
        };
        assert!(protect_reason("10.66.0.1", Some("aa:bb:cc:dd:ee:ff"), &p).is_some(), "the REAL gateway mac is exempted");
        assert!(
            protect_reason("10.66.0.1", Some("11:22:33:44:55:66"), &p).is_none(),
            "an impostor claiming the gateway's IP from a DIFFERENT mac must NOT be exempted"
        );
        assert!(protect_reason("10.66.0.1", None, &p).is_none(), "no observed mac at all must NOT be exempted either");
    }

    #[test]
    fn protect_reason_stays_ip_only_when_lan_macs_is_not_configured() {
        let p = ProtectPolicy::default();
        assert!(protect_reason("10.66.0.1", Some("11:22:33:44:55:66"), &p).is_some());
        assert!(protect_reason("10.66.0.1", None, &p).is_some());
    }

    #[test]
    fn protect_reason_never_mac_binds_a_wan_source() {
        let p = ProtectPolicy {
            cidrs: vec![],
            ips: vec!["198.51.100.44".into()],
            lan_macs: vec!["aa:bb:cc:dd:ee:ff".into()],
        };
        assert!(protect_reason("198.51.100.44", None, &p).is_some());
    }
}
