//! # mDNS Protocol Parser
//!
//! Specialised parser for Multicast DNS (mDNS) traffic on port 5353.
//! Extends the generic DNS parser with service type classification,
//! ecosystem detection, and query/response pairing for Device-to-Device
//! (D2D) affinity scoring.
//!
//! ## Ecosystem Detection
//!
//! Identifies device ecosystem membership based on mDNS service types:
//!
//! | Ecosystem | Service Types |
//! |-----------|--------------|
//! | **Apple** | `_airplay._tcp`, `_raop._tcp`, `_companion-link._tcp`, `_homekit._tcp`, `_airprint._tcp`, `_airdrop._tcp`, `_apple-mobdev2._tcp`, `_sleep-proxy._udp`, `_rdlink._tcp` |
//! | **Google** | `_googlecast._tcp`, `_googlezone._tcp`, `_googlerpc._tcp` |
//! | **Samsung** | `_smartthings._tcp`, `_samsungtv._tcp` |
//! | **Amazon** | `_amzn-wplay._tcp`, `_alexa._tcp`, `_amzn-alexa._tcp` |
//!
//! ## D2D Affinity
//!
//! Query/response pairing links the querying device (by MAC) to the
//! responding device. Repeated pairings build affinity scores used by
//! the Fortress Ecosystem Bubble system.

use std::collections::HashMap;
use std::sync::Mutex;

use crate::conntrack::FlowKey;
use crate::protocols::{Direction, ProtocolEvent, ProtocolParser};

// ---------------------------------------------------------------------------
// Ecosystem service type constants
// ---------------------------------------------------------------------------

/// Apple ecosystem mDNS service types.
pub const APPLE_SERVICES: &[&str] = &[
    "_airplay._tcp",
    "_raop._tcp",
    "_companion-link._tcp",
    "_homekit._tcp",
    "_airprint._tcp",
    "_airdrop._tcp",
    "_apple-mobdev2._tcp",
    "_sleep-proxy._udp",
    "_rdlink._tcp",
    "_apple-midi._udp",
    "_rfb._tcp",           // Apple Screen Sharing
    "_daap._tcp",          // iTunes DAAP
    "_dpap._tcp",          // iPhoto
    "_touch-able._tcp",    // Apple Remote
    "_apple-pairable._tcp",
];

/// Google ecosystem mDNS service types.
pub const GOOGLE_SERVICES: &[&str] = &[
    "_googlecast._tcp",
    "_googlezone._tcp",
    "_googlerpc._tcp",
    "_googlechrome._tcp",
    "_android._tcp",
];

/// Samsung ecosystem mDNS service types.
pub const SAMSUNG_SERVICES: &[&str] = &[
    "_smartthings._tcp",
    "_samsungtv._tcp",
    "_samsung-espresso._tcp",
    "_smartview._tcp",
];

/// Amazon ecosystem mDNS service types.
pub const AMAZON_SERVICES: &[&str] = &[
    "_amzn-wplay._tcp",
    "_alexa._tcp",
    "_amzn-alexa._tcp",
    "_amzn-hk._tcp",
    "_fire-tv._tcp",
];

/// Common IoT / smart home service types.
pub const IOT_SERVICES: &[&str] = &[
    "_hap._tcp",           // HomeKit Accessory Protocol
    "_hue._tcp",           // Philips Hue
    "_matter._tcp",        // Matter/Thread
    "_mqtt._tcp",          // MQTT
    "_ozmo._tcp",          // Sonos
    "_spotify-connect._tcp",
];

// ---------------------------------------------------------------------------
// mDNS event
// ---------------------------------------------------------------------------

/// mDNS-specific event with D2D affinity data.
#[derive(Debug, Clone)]
pub struct MdnsEvent {
    /// The mDNS query or answer name.
    pub name: String,
    /// The service type (e.g., "_airplay._tcp").
    pub service_type: String,
    /// Detected ecosystem ("apple", "google", "samsung", "amazon", "iot", "").
    pub ecosystem: String,
    /// Whether this is a query (true) or response (false).
    pub is_query: bool,
    /// Source MAC address (for D2D pairing).
    pub source_mac: String,
    /// Source IP address.
    pub source_ip: String,
    /// DNS record type (PTR=12, SRV=33, TXT=16, A=1, AAAA=28).
    pub record_type: u16,
    /// Record type name.
    pub record_type_name: String,
    /// Instance name (for SRV/TXT records).
    pub instance_name: String,
    /// Target host (for SRV records).
    pub target_host: String,
    /// Port number (for SRV records).
    pub port: u16,
    /// TXT record key-value pairs.
    pub txt_records: HashMap<String, String>,
    /// Packet timestamp.
    pub ts: f64,
}

// ---------------------------------------------------------------------------
// Query/Response pairing state
// ---------------------------------------------------------------------------

/// Tracks outstanding mDNS queries for pairing with responses.
#[derive(Debug)]
struct QueryState {
    /// Source IP of the querier.
    source_ip: String,
    /// Query service type.
    service_type: String,
    /// Timestamp of the query.
    ts: f64,
}

// ---------------------------------------------------------------------------
// MdnsParser
// ---------------------------------------------------------------------------

/// mDNS protocol parser with ecosystem detection and D2D affinity.
///
/// Builds on DNS parsing with additional service-type classification
/// and query/response correlation for device relationship detection.
pub struct MdnsParser {
    /// Outstanding queries indexed by service type for response pairing.
    /// Key: service_type, Value: list of pending queries.
    pending_queries: Mutex<HashMap<String, Vec<QueryState>>>,
    /// Maximum age (seconds) for pending queries before eviction.
    query_max_age: f64,
}

impl MdnsParser {
    /// Create a new mDNS parser.
    pub fn new() -> Self {
        Self {
            pending_queries: Mutex::new(HashMap::new()),
            query_max_age: 10.0, // mDNS queries are typically answered within seconds
        }
    }

    /// Detect the ecosystem for a given service type string.
    pub fn detect_ecosystem(service_type: &str) -> &'static str {
        let st = service_type.to_lowercase();

        for svc in APPLE_SERVICES {
            if st.contains(svc) {
                return "apple";
            }
        }
        for svc in GOOGLE_SERVICES {
            if st.contains(svc) {
                return "google";
            }
        }
        for svc in SAMSUNG_SERVICES {
            if st.contains(svc) {
                return "samsung";
            }
        }
        for svc in AMAZON_SERVICES {
            if st.contains(svc) {
                return "amazon";
            }
        }
        for svc in IOT_SERVICES {
            if st.contains(svc) {
                return "iot";
            }
        }

        ""
    }

    /// Extract the service type from an mDNS name.
    ///
    /// e.g., "Living Room._airplay._tcp.local" -> "_airplay._tcp"
    pub fn extract_service_type(name: &str) -> String {
        // Look for _service._proto pattern
        let parts: Vec<&str> = name.split('.').collect();

        for i in 0..parts.len().saturating_sub(1) {
            if parts[i].starts_with('_') && parts.get(i + 1).map_or(false, |p| p.starts_with('_')) {
                return format!("{}.{}", parts[i], parts[i + 1]);
            }
        }

        String::new()
    }

    /// Extract the instance name from an mDNS name.
    ///
    /// e.g., "Living Room._airplay._tcp.local" -> "Living Room"
    pub fn extract_instance_name(name: &str) -> String {
        let parts: Vec<&str> = name.split('.').collect();

        // Find where the service type starts
        for i in 0..parts.len() {
            if parts[i].starts_with('_') {
                if i > 0 {
                    return parts[..i].join(".");
                }
                break;
            }
        }

        String::new()
    }

    /// Record a query for later pairing with a response.
    fn record_query(&self, service_type: &str, source_ip: &str, ts: f64) {
        if service_type.is_empty() {
            return;
        }

        let mut queries = self.pending_queries.lock().unwrap();

        // Evict old queries
        for entries in queries.values_mut() {
            entries.retain(|q| ts - q.ts < self.query_max_age);
        }

        queries
            .entry(service_type.to_string())
            .or_insert_with(Vec::new)
            .push(QueryState {
                source_ip: source_ip.to_string(),
                service_type: service_type.to_string(),
                ts,
            });
    }

    /// Try to pair a response with a pending query.
    ///
    /// Returns the querier's IP if a match is found.
    fn pair_response(&self, service_type: &str, ts: f64) -> Vec<String> {
        if service_type.is_empty() {
            return Vec::new();
        }

        let mut queries = self.pending_queries.lock().unwrap();

        if let Some(entries) = queries.get_mut(service_type) {
            let paired: Vec<String> = entries
                .iter()
                .filter(|q| ts - q.ts < self.query_max_age)
                .map(|q| q.source_ip.clone())
                .collect();

            // Remove paired queries
            entries.retain(|q| ts - q.ts >= self.query_max_age);

            paired
        } else {
            Vec::new()
        }
    }

    /// Parse an mDNS message from raw UDP payload.
    fn parse_message(&self, flow: &FlowKey, payload: &[u8], ts: f64) -> Vec<MdnsEvent> {
        let mut events = Vec::new();

        // Minimum DNS header length
        if payload.len() < 12 {
            return events;
        }

        let flags = u16::from_be_bytes([payload[2], payload[3]]);
        let qr = (flags >> 15) & 1;
        let is_query = qr == 0;

        let qdcount = u16::from_be_bytes([payload[4], payload[5]]);
        let ancount = u16::from_be_bytes([payload[6], payload[7]]);

        let mut offset = 12;

        // Parse question section
        for _ in 0..qdcount {
            match parse_mdns_name(payload, offset) {
                Some((name, new_offset)) => {
                    offset = new_offset;
                    if offset + 4 > payload.len() {
                        break;
                    }
                    let qtype = u16::from_be_bytes([payload[offset], payload[offset + 1]]);
                    offset += 4; // QTYPE + QCLASS

                    let service_type = Self::extract_service_type(&name);
                    let ecosystem = Self::detect_ecosystem(&service_type);
                    let instance_name = Self::extract_instance_name(&name);

                    if is_query {
                        self.record_query(&service_type, &flow.src_ip, ts);
                    }

                    events.push(MdnsEvent {
                        name: name.clone(),
                        service_type: service_type.clone(),
                        ecosystem: ecosystem.to_string(),
                        is_query,
                        source_mac: String::new(), // TODO: resolve from ARP table
                        source_ip: flow.src_ip.clone(),
                        record_type: qtype,
                        record_type_name: qtype_name(qtype).to_string(),
                        instance_name,
                        target_host: String::new(),
                        port: 0,
                        txt_records: HashMap::new(),
                        ts,
                    });
                }
                None => break,
            }
        }

        // Parse answer section
        for _ in 0..ancount {
            match parse_mdns_rr(payload, offset) {
                Some((name, rtype, rdata, new_offset)) => {
                    offset = new_offset;

                    let service_type = Self::extract_service_type(&name);
                    let ecosystem = Self::detect_ecosystem(&service_type);
                    let instance_name = Self::extract_instance_name(&name);

                    // Try to pair with pending queries
                    if !is_query {
                        let _queriers = self.pair_response(&service_type, ts);
                        // TODO: Emit D2D affinity events for each paired querier
                    }

                    events.push(MdnsEvent {
                        name: name.clone(),
                        service_type: service_type.clone(),
                        ecosystem: ecosystem.to_string(),
                        is_query: false,
                        source_mac: String::new(),
                        source_ip: flow.src_ip.clone(),
                        record_type: rtype,
                        record_type_name: qtype_name(rtype).to_string(),
                        instance_name,
                        target_host: rdata.clone(),
                        port: 0, // TODO: extract from SRV RDATA
                        txt_records: HashMap::new(), // TODO: parse TXT RDATA
                        ts,
                    });
                }
                None => break,
            }
        }

        events
    }
}

impl ProtocolParser for MdnsParser {
    fn parse(
        &self,
        flow: &FlowKey,
        _direction: Direction,
        payload: &[u8],
        ts: f64,
    ) -> Vec<ProtocolEvent> {
        self.parse_message(flow, payload, ts)
            .into_iter()
            .map(ProtocolEvent::Mdns)
            .collect()
    }

    fn timeout(&self) -> f64 {
        60.0 // mDNS conversations are short
    }

    fn protocol_id(&self) -> &'static str {
        "mdns"
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// DNS query type to name mapping (subset relevant to mDNS).
fn qtype_name(qtype: u16) -> &'static str {
    match qtype {
        1 => "A",
        12 => "PTR",
        16 => "TXT",
        28 => "AAAA",
        33 => "SRV",
        47 => "NSEC",
        255 => "ANY",
        _ => "OTHER",
    }
}

/// Parse an mDNS domain name from wire format.
///
/// Same as DNS name parsing but allows for mDNS-specific quirks.
fn parse_mdns_name(buf: &[u8], start: usize) -> Option<(String, usize)> {
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
            if !jumped {
                return_offset = offset + 1;
            }
            break;
        }

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
        return_offset = offset + 1;
    }

    let name = labels.join(".");
    Some((name, return_offset))
}

/// Parse an mDNS resource record, returning (name, type, rdata_string, new_offset).
fn parse_mdns_rr(buf: &[u8], start: usize) -> Option<(String, u16, String, usize)> {
    let (name, offset) = parse_mdns_name(buf, start)?;

    if offset + 10 > buf.len() {
        return None;
    }

    let rtype = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
    let _rclass = u16::from_be_bytes([buf[offset + 2], buf[offset + 3]]);
    let _ttl = u32::from_be_bytes([buf[offset + 4], buf[offset + 5], buf[offset + 6], buf[offset + 7]]);
    let rdlength = u16::from_be_bytes([buf[offset + 8], buf[offset + 9]]) as usize;

    let rdata_start = offset + 10;
    if rdata_start + rdlength > buf.len() {
        return None;
    }

    let rdata_str = match rtype {
        1 if rdlength == 4 => {
            format!(
                "{}.{}.{}.{}",
                buf[rdata_start],
                buf[rdata_start + 1],
                buf[rdata_start + 2],
                buf[rdata_start + 3]
            )
        }
        12 | 5 => {
            // PTR, CNAME - contains a domain name
            parse_mdns_name(buf, rdata_start)
                .map(|(n, _)| n)
                .unwrap_or_default()
        }
        _ => format!("<type={} len={}>", rtype, rdlength),
    };

    Some((name, rtype, rdata_str, rdata_start + rdlength))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_ecosystem() {
        assert_eq!(MdnsParser::detect_ecosystem("_airplay._tcp"), "apple");
        assert_eq!(MdnsParser::detect_ecosystem("_raop._tcp"), "apple");
        assert_eq!(MdnsParser::detect_ecosystem("_googlecast._tcp"), "google");
        assert_eq!(MdnsParser::detect_ecosystem("_samsungtv._tcp"), "samsung");
        assert_eq!(MdnsParser::detect_ecosystem("_amzn-wplay._tcp"), "amazon");
        assert_eq!(MdnsParser::detect_ecosystem("_hap._tcp"), "iot");
        assert_eq!(MdnsParser::detect_ecosystem("_http._tcp"), "");
    }

    #[test]
    fn test_extract_service_type() {
        assert_eq!(
            MdnsParser::extract_service_type("Living Room._airplay._tcp.local"),
            "_airplay._tcp"
        );
        assert_eq!(
            MdnsParser::extract_service_type("_googlecast._tcp.local"),
            "_googlecast._tcp"
        );
        assert_eq!(
            MdnsParser::extract_service_type("example.com"),
            ""
        );
    }

    #[test]
    fn test_extract_instance_name() {
        assert_eq!(
            MdnsParser::extract_instance_name("Living Room._airplay._tcp.local"),
            "Living Room"
        );
        assert_eq!(
            MdnsParser::extract_instance_name("Dad's MacBook._companion-link._tcp.local"),
            "Dad's MacBook"
        );
        assert_eq!(
            MdnsParser::extract_instance_name("_airplay._tcp.local"),
            ""
        );
    }

    #[test]
    fn test_query_response_pairing() {
        let parser = MdnsParser::new();

        // Record a query
        parser.record_query("_airplay._tcp", "192.168.1.10", 1000.0);

        // Pair with response
        let queriers = parser.pair_response("_airplay._tcp", 1001.0);
        assert_eq!(queriers.len(), 1);
        assert_eq!(queriers[0], "192.168.1.10");

        // Second pairing should return empty (already consumed)
        let queriers = parser.pair_response("_airplay._tcp", 1002.0);
        assert!(queriers.is_empty());
    }

    #[test]
    fn test_query_expiry() {
        let parser = MdnsParser::new();

        // Record a query
        parser.record_query("_airplay._tcp", "192.168.1.10", 1000.0);

        // Try to pair after expiry (default 10s)
        let queriers = parser.pair_response("_airplay._tcp", 1020.0);
        assert!(queriers.is_empty());
    }

    #[test]
    fn test_parse_too_short() {
        let parser = MdnsParser::new();
        let flow = FlowKey::new("192.168.1.10".into(), "224.0.0.251".into(), 5353, 5353, 17);
        let events = parser.parse(&flow, Direction::Originator, b"short", 1000.0);
        assert!(events.is_empty());
    }

    #[test]
    fn test_qtype_name() {
        assert_eq!(qtype_name(12), "PTR");
        assert_eq!(qtype_name(33), "SRV");
        assert_eq!(qtype_name(16), "TXT");
        assert_eq!(qtype_name(999), "OTHER");
    }
}
