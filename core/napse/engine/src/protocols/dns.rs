//! # DNS Protocol Parser
//!
//! Parses DNS queries and responses from raw UDP/TCP payloads. Extracts
//! query names, types, response codes, answers, and TTLs. Detects mDNS
//! traffic (port 5353 / 224.0.0.251) and tags with ecosystem identifiers
//! (Apple, Google, Samsung, Amazon).
//!
//! Output is compatible with Zeek `dns.log` fields.
//!
//! ## Wire Format Reference
//!
//! ```text
//!  0                   1
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |         Transaction ID        |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |         Flags                 |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |         QDCOUNT               |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |         ANCOUNT               |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |         NSCOUNT               |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |         ARCOUNT               |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```

use crate::conntrack::FlowKey;
use crate::protocols::{Direction, ProtocolEvent, ProtocolParser};

/// Minimum DNS header length in bytes.
const DNS_HEADER_LEN: usize = 12;

/// mDNS multicast port.
const MDNS_PORT: u16 = 5353;

/// mDNS IPv4 multicast address.
const MDNS_MULTICAST_V4: &str = "224.0.0.251";

/// mDNS IPv6 multicast address.
const MDNS_MULTICAST_V6: &str = "ff02::fb";

// ---------------------------------------------------------------------------
// DNS event
// ---------------------------------------------------------------------------

/// Parsed DNS event carrying query/response details.
#[derive(Debug, Clone)]
pub struct DnsEvent {
    /// DNS transaction ID.
    pub trans_id: u16,
    /// Query name (e.g., "example.com").
    pub query: String,
    /// Query type numeric value (1=A, 28=AAAA, 12=PTR, etc.).
    pub qtype: u16,
    /// Query type name string.
    pub qtype_name: String,
    /// Response code numeric value.
    pub rcode: u16,
    /// Response code name string.
    pub rcode_name: String,
    /// Answer records (string representations).
    pub answers: Vec<String>,
    /// TTL values for each answer.
    pub ttls: Vec<u32>,
    /// Whether this is a query (`true`) or response (`false`).
    pub is_query: bool,
    /// Whether this is mDNS traffic.
    pub is_mdns: bool,
    /// Ecosystem tag if detected (e.g., "apple", "google").
    pub ecosystem: String,
    /// Packet timestamp.
    pub ts: f64,
}

// ---------------------------------------------------------------------------
// Query type mapping
// ---------------------------------------------------------------------------

/// Map a DNS query type number to its mnemonic name.
fn qtype_to_name(qtype: u16) -> &'static str {
    match qtype {
        1 => "A",
        2 => "NS",
        5 => "CNAME",
        6 => "SOA",
        12 => "PTR",
        15 => "MX",
        16 => "TXT",
        28 => "AAAA",
        33 => "SRV",
        35 => "NAPTR",
        41 => "OPT",
        43 => "DS",
        46 => "RRSIG",
        47 => "NSEC",
        48 => "DNSKEY",
        52 => "TLSA",
        65 => "HTTPS",
        255 => "ANY",
        256 => "URI",
        257 => "CAA",
        _ => "UNKNOWN",
    }
}

/// Map a DNS response code to its mnemonic name.
fn rcode_to_name(rcode: u16) -> &'static str {
    match rcode {
        0 => "NOERROR",
        1 => "FORMERR",
        2 => "SERVFAIL",
        3 => "NXDOMAIN",
        4 => "NOTIMP",
        5 => "REFUSED",
        6 => "YXDOMAIN",
        7 => "YXRRSET",
        8 => "NXRRSET",
        9 => "NOTAUTH",
        10 => "NOTZONE",
        _ => "UNKNOWN",
    }
}

// ---------------------------------------------------------------------------
// DnsParser
// ---------------------------------------------------------------------------

/// DNS protocol parser.
///
/// Stateless parser that processes individual DNS messages from UDP payloads
/// (or TCP with length prefix stripped). Detects mDNS based on port and
/// multicast address.
pub struct DnsParser;

impl DnsParser {
    /// Create a new DNS parser.
    pub fn new() -> Self {
        Self
    }

    /// Check if a flow is mDNS traffic.
    fn is_mdns_flow(flow: &FlowKey) -> bool {
        flow.src_port == MDNS_PORT
            || flow.dst_port == MDNS_PORT
            || flow.dst_ip == MDNS_MULTICAST_V4
            || flow.dst_ip == MDNS_MULTICAST_V6
    }

    /// Parse a single DNS message from raw bytes.
    ///
    /// Returns `None` if the payload is too short or malformed.
    fn parse_message(&self, payload: &[u8], is_mdns: bool, ts: f64) -> Option<DnsEvent> {
        if payload.len() < DNS_HEADER_LEN {
            return None;
        }

        let trans_id = u16::from_be_bytes([payload[0], payload[1]]);
        let flags = u16::from_be_bytes([payload[2], payload[3]]);
        let qr = (flags >> 15) & 1; // 0 = query, 1 = response
        let rcode = flags & 0x000F;
        let qdcount = u16::from_be_bytes([payload[4], payload[5]]);
        let ancount = u16::from_be_bytes([payload[6], payload[7]]);

        let is_query = qr == 0;

        // Parse the question section
        let mut offset = DNS_HEADER_LEN;
        let mut query = String::new();
        let mut qtype: u16 = 0;

        if qdcount > 0 {
            match parse_dns_name(payload, offset) {
                Some((name, new_offset)) => {
                    query = name;
                    offset = new_offset;

                    // Read QTYPE and QCLASS (4 bytes)
                    if offset + 4 <= payload.len() {
                        qtype = u16::from_be_bytes([payload[offset], payload[offset + 1]]);
                        offset += 4; // skip QTYPE + QCLASS
                    }
                }
                None => return None,
            }
        }

        // Parse answer section (for responses)
        let mut answers = Vec::new();
        let mut ttls = Vec::new();

        if !is_query {
            for _ in 0..ancount {
                match parse_rr(payload, offset) {
                    Some((rdata_str, ttl, new_offset)) => {
                        answers.push(rdata_str);
                        ttls.push(ttl);
                        offset = new_offset;
                    }
                    None => break,
                }
            }
        }

        // Detect ecosystem from mDNS query names
        let ecosystem = if is_mdns {
            detect_ecosystem(&query)
        } else {
            String::new()
        };

        Some(DnsEvent {
            trans_id,
            query,
            qtype,
            qtype_name: qtype_to_name(qtype).to_string(),
            rcode,
            rcode_name: rcode_to_name(rcode).to_string(),
            answers,
            ttls,
            is_query,
            is_mdns,
            ecosystem,
            ts,
        })
    }
}

impl ProtocolParser for DnsParser {
    fn parse(
        &self,
        flow: &FlowKey,
        _direction: Direction,
        payload: &[u8],
        ts: f64,
    ) -> Vec<ProtocolEvent> {
        let is_mdns = Self::is_mdns_flow(flow);

        match self.parse_message(payload, is_mdns, ts) {
            Some(event) => vec![ProtocolEvent::Dns(event)],
            None => vec![],
        }
    }

    fn timeout(&self) -> f64 {
        30.0 // DNS connections are short-lived
    }

    fn protocol_id(&self) -> &'static str {
        "dns"
    }
}

// ---------------------------------------------------------------------------
// Ecosystem detection (for mDNS)
// ---------------------------------------------------------------------------

/// Detect the device ecosystem from an mDNS query or service name.
///
/// Returns a lowercase ecosystem tag or an empty string if unknown.
fn detect_ecosystem(query: &str) -> String {
    let q = query.to_lowercase();

    // Apple ecosystem
    if q.contains("_airplay._tcp")
        || q.contains("_raop._tcp")
        || q.contains("_companion-link._tcp")
        || q.contains("_homekit._tcp")
        || q.contains("_airprint._tcp")
        || q.contains("_airdrop._tcp")
        || q.contains("_apple-mobdev2._tcp")
        || q.contains("_sleep-proxy._udp")
        || q.contains("_rdlink._tcp")
    {
        return "apple".to_string();
    }

    // Google ecosystem
    if q.contains("_googlecast._tcp")
        || q.contains("_googlezone._tcp")
        || q.contains("_googlerpc._tcp")
    {
        return "google".to_string();
    }

    // Samsung ecosystem
    if q.contains("_smartthings._tcp") || q.contains("_samsungtv._tcp") {
        return "samsung".to_string();
    }

    // Amazon ecosystem
    if q.contains("_amzn-wplay._tcp")
        || q.contains("_alexa._tcp")
        || q.contains("_amzn-alexa._tcp")
    {
        return "amazon".to_string();
    }

    String::new()
}

// ---------------------------------------------------------------------------
// DNS name / RR parsing helpers
// ---------------------------------------------------------------------------

/// Parse a DNS domain name from the wire format.
///
/// Handles label compression (pointer bytes). Returns the decoded name
/// and the new offset past the name in the original buffer.
fn parse_dns_name(buf: &[u8], start: usize) -> Option<(String, usize)> {
    let mut labels = Vec::new();
    let mut offset = start;
    let mut jumped = false;
    let mut return_offset = 0;
    let mut safety = 0;

    loop {
        if offset >= buf.len() || safety > 128 {
            return None;
        }
        safety += 1;

        let len_byte = buf[offset];

        if len_byte == 0 {
            // End of name
            if !jumped {
                return_offset = offset + 1;
            }
            break;
        }

        // Check for compression pointer (top 2 bits set)
        if len_byte & 0xC0 == 0xC0 {
            if offset + 1 >= buf.len() {
                return None;
            }
            let pointer = ((len_byte as usize & 0x3F) << 8) | buf[offset + 1] as usize;
            if !jumped {
                return_offset = offset + 2;
                jumped = true;
            }
            offset = pointer;
            continue;
        }

        // Regular label
        let label_len = len_byte as usize;
        offset += 1;
        if offset + label_len > buf.len() {
            return None;
        }

        let label = String::from_utf8_lossy(&buf[offset..offset + label_len]).to_string();
        labels.push(label);
        offset += label_len;
    }

    if !jumped {
        return_offset = offset + 1; // skip the zero terminator
    }

    let name = if labels.is_empty() {
        ".".to_string()
    } else {
        labels.join(".")
    };

    Some((name, return_offset))
}

/// Parse a DNS resource record.
///
/// Returns a string representation of the RDATA, the TTL, and the
/// new offset past this RR.
fn parse_rr(buf: &[u8], start: usize) -> Option<(String, u32, usize)> {
    // Parse the name
    let (_, offset) = parse_dns_name(buf, start)?;

    // Need at least TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2) = 10 bytes
    if offset + 10 > buf.len() {
        return None;
    }

    let rtype = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
    // let rclass = u16::from_be_bytes([buf[offset + 2], buf[offset + 3]]);
    let ttl = u32::from_be_bytes([
        buf[offset + 4],
        buf[offset + 5],
        buf[offset + 6],
        buf[offset + 7],
    ]);
    let rdlength = u16::from_be_bytes([buf[offset + 8], buf[offset + 9]]) as usize;
    let rdata_start = offset + 10;

    if rdata_start + rdlength > buf.len() {
        return None;
    }

    let rdata_str = match rtype {
        1 if rdlength == 4 => {
            // A record
            format!(
                "{}.{}.{}.{}",
                buf[rdata_start],
                buf[rdata_start + 1],
                buf[rdata_start + 2],
                buf[rdata_start + 3]
            )
        }
        28 if rdlength == 16 => {
            // AAAA record
            let mut parts = Vec::new();
            for i in (0..16).step_by(2) {
                parts.push(format!(
                    "{:x}",
                    u16::from_be_bytes([buf[rdata_start + i], buf[rdata_start + i + 1]])
                ));
            }
            parts.join(":")
        }
        5 | 2 | 12 | 15 => {
            // CNAME, NS, PTR, MX - contains a domain name
            parse_dns_name(buf, rdata_start)
                .map(|(name, _)| name)
                .unwrap_or_else(|| "<parse error>".to_string())
        }
        _ => {
            // Generic hex dump for unknown types
            format!("<type={} len={}>", rtype, rdlength)
        }
    };

    Some((rdata_str, ttl, rdata_start + rdlength))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_qtype_to_name() {
        assert_eq!(qtype_to_name(1), "A");
        assert_eq!(qtype_to_name(28), "AAAA");
        assert_eq!(qtype_to_name(12), "PTR");
        assert_eq!(qtype_to_name(33), "SRV");
        assert_eq!(qtype_to_name(9999), "UNKNOWN");
    }

    #[test]
    fn test_rcode_to_name() {
        assert_eq!(rcode_to_name(0), "NOERROR");
        assert_eq!(rcode_to_name(3), "NXDOMAIN");
        assert_eq!(rcode_to_name(99), "UNKNOWN");
    }

    #[test]
    fn test_detect_ecosystem_apple() {
        assert_eq!(detect_ecosystem("_airplay._tcp.local"), "apple");
        assert_eq!(detect_ecosystem("_raop._tcp.local"), "apple");
        assert_eq!(detect_ecosystem("_homekit._tcp.local"), "apple");
    }

    #[test]
    fn test_detect_ecosystem_google() {
        assert_eq!(detect_ecosystem("_googlecast._tcp.local"), "google");
    }

    #[test]
    fn test_detect_ecosystem_samsung() {
        assert_eq!(detect_ecosystem("_samsungtv._tcp.local"), "samsung");
    }

    #[test]
    fn test_detect_ecosystem_amazon() {
        assert_eq!(detect_ecosystem("_amzn-wplay._tcp.local"), "amazon");
    }

    #[test]
    fn test_detect_ecosystem_unknown() {
        assert_eq!(detect_ecosystem("_http._tcp.local"), "");
    }

    #[test]
    fn test_is_mdns_flow() {
        let flow = FlowKey::new(
            "192.168.1.10".into(),
            "224.0.0.251".into(),
            5353,
            5353,
            17,
        );
        assert!(DnsParser::is_mdns_flow(&flow));

        let flow2 = FlowKey::new("192.168.1.10".into(), "8.8.8.8".into(), 54321, 53, 17);
        assert!(!DnsParser::is_mdns_flow(&flow2));
    }

    #[test]
    fn test_parse_dns_name_simple() {
        // Encode "example.com" in DNS wire format:
        // \x07example\x03com\x00
        let buf = b"\x07example\x03com\x00";
        let (name, offset) = parse_dns_name(buf, 0).unwrap();
        assert_eq!(name, "example.com");
        assert_eq!(offset, buf.len());
    }

    #[test]
    fn test_parse_dns_name_root() {
        let buf = b"\x00";
        let (name, _) = parse_dns_name(buf, 0).unwrap();
        assert_eq!(name, ".");
    }

    #[test]
    fn test_parser_too_short() {
        let parser = DnsParser::new();
        let flow = FlowKey::new("10.0.0.1".into(), "8.8.8.8".into(), 12345, 53, 17);
        let events = parser.parse(&flow, Direction::Originator, b"short", 1000.0);
        assert!(events.is_empty());
    }
}
