//! The heqk detection-rule CATALOGUE as operator-facing metadata: message, category, MITRE
//! ATT&CK id and canonical severity (1=CRITICAL … 5=INFO, the scale the UI and every evidence
//! producer use). Pure, dependency-free: the on-device Mission Control server and the
//! `hookprobe-evidence` export ingest both compile THIS file (`#[path]`), so a rule's meaning can
//! never drift between what the device shows and what an aggregator stores.
//!
//! Keep in step with the rule ids in `rules.rs` (the detection logic). Unknown ids are still
//! rendered (`lookup_or_generic`), never silently dropped.

/// Operator-facing rule id = `HEQK_RULE_BAND + kernel rule id`. A fresh range (napse 1_000_0xx,
/// l2guard 1_000_03x, host-EDR 1_000_1xx, HYDRA 4_000_000_001, supply-chain 9_xxx).
pub const HEQK_RULE_BAND: u32 = 1_200_000;

pub const SEV_CRITICAL: u8 = 1;
pub const SEV_HIGH: u8 = 2;
pub const SEV_MEDIUM: u8 = 3;
pub const SEV_LOW: u8 = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuleInfo {
    pub msg: &'static str,
    pub category: &'static str,
    pub mitre: &'static str,
    pub severity: u8,
}

const fn r(msg: &'static str, category: &'static str, mitre: &'static str, severity: u8) -> RuleInfo {
    RuleInfo { msg, category, mitre, severity }
}

/// Metadata for a known heqk rule id.
pub fn lookup(id: u16) -> Option<RuleInfo> {
    Some(match id {
        1 => r("Known C2 port 4444", "signature", "T1571", SEV_HIGH),
        2 => r("Telnet (23) access", "signature", "T1021", SEV_MEDIUM),
        3 => r("Backdoor port 31337", "signature", "T1571", SEV_HIGH),
        101 => r("Malformed ARP", "malformed_frame", "", SEV_LOW),
        102 => r("ARP spoofing", "arp_spoof", "T1557.002", SEV_HIGH),
        110 => r("L2 structural anomaly", "malformed_frame", "", SEV_LOW),
        111 => r("MAC flood", "mac_flood", "T1498", SEV_MEDIUM),
        112 => r("Broadcast storm", "bcast_storm", "T1498", SEV_MEDIUM),
        113 => r("Port scan", "port_scan", "T1046", SEV_MEDIUM),
        114 => r("New-connection rate shed", "resource_shed", "T1499", SEV_MEDIUM),
        115 => r("Resource-exhaustion shed", "resource_shed", "T1499", SEV_MEDIUM),
        116 => r("Beaconing", "beaconing", "T1071", SEV_MEDIUM),
        117 => r("Lateral movement", "lateral_movement", "T1021", SEV_HIGH),
        118 => r("Bulk exfiltration", "exfiltration", "T1048", SEV_HIGH),
        119 => r("DNS tunneling / DGA", "dns_dga", "T1071.004", SEV_MEDIUM),
        120 => r("Truncated / unparseable frame", "malformed_frame", "", SEV_LOW),
        121 => r("Rogue IPv6 router advertisement", "rogue_ra", "T1557", SEV_HIGH),
        122 => r("IPv6 RA flood", "ra_flood", "T1498", SEV_MEDIUM),
        123 => r("Unparseable IPv6 (evasion attempt)", "evasion", "", SEV_LOW),
        201 => r("TCP NULL scan", "port_scan", "T1046", SEV_MEDIUM),
        202 => r("TCP FIN scan", "port_scan", "T1046", SEV_MEDIUM),
        203 => r("TCP Xmas scan", "port_scan", "T1046", SEV_MEDIUM),
        204 => r("TCP SYN-FIN scan", "port_scan", "T1046", SEV_MEDIUM),
        301 => r("SYN flood", "syn_flood", "T1498.001", SEV_HIGH),
        302 => r("Blocklisted IP", "ioc_match", "", SEV_HIGH),
        _ => return None,
    })
}

/// `lookup`, or a generic MEDIUM entry for an id this catalogue does not know yet.
pub fn lookup_or_generic(id: u16) -> RuleInfo {
    lookup(id)
        .or_else(|| {
            // parity G6: a signed rule-pack rule (names + severity points from RULES.BIN)
            crate::rulepack::lookup(id).map(|(name, pts)| r(name, "rule_pack", "", match pts { 7.. => SEV_CRITICAL, 5..=6 => SEV_HIGH, 3..=4 => SEV_MEDIUM, _ => SEV_LOW }))
        })
        .unwrap_or(r("heqk rule (uncatalogued)", "heqk", "", SEV_MEDIUM))
}

/// heqk rule ids whose event `src` is a src-MAC hash, never an IPv4 address (IPv6 RA rules —
/// see `events::Event::src`).
pub fn src_is_mac_hash(id: u16) -> bool {
    matches!(id, 121 | 122 | 123)
}
