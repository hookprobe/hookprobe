//! HYDRA threat-feed → blocklist parsing. Turns threat-intel CIDR feeds (Spamhaus DROP/EDROP,
//! FireHOL, Emerging Threats, Feodo, …) into LPM-trie keys for the BPF `blocklist` map that
//! napse_detect.bpf.c drops on (ADR 0005). PURE + tested; the map update (open the pinned map,
//! batch-insert) is the feature-gated glue in `bpf.rs`.
//!
//! Feed formats handled: plain `1.2.3.0/24`, bare `1.2.3.4` (→ /32), Spamhaus DROP
//! `1.2.3.0/24 ; SBL123`, and comment/blank lines (`;` or `#`). IPv6 lines are skipped (v4 map).

use std::net::Ipv4Addr;

/// One parsed prefix: the network octets (wire order) + prefix length in bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct V4Prefix {
    pub octets: [u8; 4],
    pub prefixlen: u8,
}

impl V4Prefix {
    /// Serialize to the kernel LPM_TRIE key layout `struct { u32 prefixlen; u8 addr[4]; }`:
    /// prefixlen is a native-endian u32 scalar; the address bytes stay in network (wire) order so
    /// the trie compares them MSB-first. Matches `lpm_v4_key` in napse_detect.h.
    pub fn to_lpm_key(&self) -> [u8; 8] {
        let mut k = [0u8; 8];
        k[0..4].copy_from_slice(&(self.prefixlen as u32).to_ne_bytes());
        k[4..8].copy_from_slice(&self.octets);
        k
    }
}

/// Parse one feed line → a prefix, or None for comments/blank/IPv6/garbage. Tolerant by design:
/// threat feeds are messy, and a bad line must never abort the sync.
pub fn parse_line(line: &str) -> Option<V4Prefix> {
    // strip inline comment (Spamhaus "cidr ; SBLxxxx") and trim
    let head = line.split(&[';', '#'][..]).next().unwrap_or("").trim();
    if head.is_empty() {
        return None;
    }
    // take the first whitespace-separated token (some feeds have "cidr country ...")
    let tok = head.split_whitespace().next()?;
    if tok.contains(':') {
        return None; // IPv6 — not in the v4 map
    }
    let (addr_s, plen) = match tok.split_once('/') {
        Some((a, p)) => (a, p.parse::<u8>().ok()?),
        None => (tok, 32),
    };
    if plen > 32 {
        return None;
    }
    let ip: Ipv4Addr = addr_s.parse().ok()?;
    Some(V4Prefix { octets: ip.octets(), prefixlen: plen })
}

/// Parse a whole feed body → deduplicated prefixes (order-preserving on first sight).
pub fn parse_feed(body: &str) -> Vec<V4Prefix> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for line in body.lines() {
        if let Some(p) = parse_line(line) {
            if seen.insert((p.octets, p.prefixlen)) {
                out.push(p);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_plain_and_spamhaus_and_bare() {
        assert_eq!(parse_line("185.220.101.0/24"), Some(V4Prefix { octets: [185, 220, 101, 0], prefixlen: 24 }));
        assert_eq!(parse_line("1.2.3.0/24 ; SBL12345"), Some(V4Prefix { octets: [1, 2, 3, 0], prefixlen: 24 }));
        assert_eq!(parse_line("9.9.9.9"), Some(V4Prefix { octets: [9, 9, 9, 9], prefixlen: 32 }));
    }

    #[test]
    fn skips_comments_v6_garbage() {
        assert_eq!(parse_line("; comment"), None);
        assert_eq!(parse_line("# FireHOL level1"), None);
        assert_eq!(parse_line(""), None);
        assert_eq!(parse_line("2001:db8::/32"), None); // IPv6
        assert_eq!(parse_line("not-an-ip/24"), None);
        assert_eq!(parse_line("1.2.3.0/99"), None); // bad prefix
    }

    #[test]
    fn lpm_key_layout_is_prefixlen_then_wire_addr() {
        let k = V4Prefix { octets: [185, 220, 101, 0], prefixlen: 24 }.to_lpm_key();
        assert_eq!(&k[0..4], &24u32.to_ne_bytes()); // prefixlen scalar
        assert_eq!(&k[4..8], &[185, 220, 101, 0]); // address in wire order
    }

    #[test]
    fn feed_dedups() {
        let body = "1.1.1.0/24\n; a comment\n1.1.1.0/24\n2.2.2.2\n";
        let p = parse_feed(body);
        assert_eq!(p.len(), 2); // dup /24 collapsed
    }
}
