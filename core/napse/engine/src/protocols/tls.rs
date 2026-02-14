//! # TLS Protocol Parser
//!
//! Parses TLS ClientHello and ServerHello messages to extract fingerprinting
//! data. Computes JA3 and JA3S hashes for client/server identification and
//! threat detection.
//!
//! ## Capabilities
//!
//! - **SNI Extraction**: Server Name Indication from ClientHello
//! - **JA3 Fingerprinting**: MD5(SSLVersion,Ciphers,Extensions,EllipticCurves,ECPointFormats)
//! - **JA3S Fingerprinting**: MD5(SSLVersion,Cipher,Extensions) from ServerHello
//! - **Certificate Chain**: Subject, issuer, and validity from server certificates
//! - **GREASE Filtering**: Removes GREASE values per RFC 8701
//! - **Malicious JA3 Database**: Known C2 framework fingerprints
//!
//! ## Wire Format Reference
//!
//! ```text
//! TLS Record:
//!   Content Type (1 byte): 22 = Handshake
//!   Version (2 bytes)
//!   Length (2 bytes)
//!
//! Handshake:
//!   Type (1 byte): 1 = ClientHello, 2 = ServerHello, 11 = Certificate
//!   Length (3 bytes)
//!   ...
//! ```

use std::collections::HashMap;
use std::fmt::Write;
use std::sync::Mutex;

use md5::{Digest, Md5};

use crate::conntrack::FlowKey;
use crate::protocols::{Direction, ProtocolEvent, ProtocolParser};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// TLS content type for Handshake messages.
const TLS_HANDSHAKE: u8 = 22;

/// Handshake type: ClientHello.
const CLIENT_HELLO: u8 = 1;

/// Handshake type: ServerHello.
const SERVER_HELLO: u8 = 2;

/// Handshake type: Certificate.
const CERTIFICATE: u8 = 11;

/// Minimum TLS record header size.
const TLS_RECORD_HEADER_LEN: usize = 5;

/// Minimum ClientHello length after handshake type + length.
const MIN_CLIENT_HELLO_LEN: usize = 38;

// ---------------------------------------------------------------------------
// GREASE values (RFC 8701)
// ---------------------------------------------------------------------------

/// GREASE cipher suite and extension values to filter out.
///
/// These are randomly injected by clients to test server tolerance of
/// unknown values and should be excluded from JA3 fingerprints.
const GREASE_VALUES: [u16; 16] = [
    0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A, 0x8A8A, 0x9A9A, 0xAAAA,
    0xBABA, 0xCACA, 0xDADA, 0xEAEA, 0xFAFA,
];

/// Check if a value is a GREASE value.
fn is_grease(val: u16) -> bool {
    GREASE_VALUES.contains(&val)
}

// ---------------------------------------------------------------------------
// Known malicious JA3 hashes
// ---------------------------------------------------------------------------

/// Database of known malicious JA3 fingerprints.
///
/// These hashes are associated with common offensive security tools and
/// malware command-and-control frameworks.
const MALICIOUS_JA3_DB: &[(&str, &str)] = &[
    ("51c64c77e60f3980eea90869b68c58a8", "CobaltStrike"),
    ("72a589da586844d7f0818ce684948eea", "CobaltStrike"),
    ("a0e9f5d64349fb13191bc781f81f42e1", "CobaltStrike"),
    ("b742b407517bac9536a77a7b0fee28e9", "Metasploit"),
    ("e7d705a3286e19ea42f587b344ee6865", "Metasploit"),
    ("3b5074b1b5d032e5620f69f9f700ff0e", "Empire"),
    ("2d7607e8b1bbc4f45b6061bd3909fdb0", "TrickBot"),
    ("6734f37431670b3ab4292b8f60f29984", "Emotet"),
    ("4d7a28d6f2263ed61de88ca66eb011e3", "Emotet"),
    ("c12f54a3f91dc7bafd92cb59fe009a35", "AsyncRAT"),
    ("fc54e0d16d9764783542f0146a98b300", "SolarWinds_SUNBURST"),
];

// ---------------------------------------------------------------------------
// TLS event
// ---------------------------------------------------------------------------

/// Events produced by the TLS parser.
#[derive(Debug, Clone)]
pub struct TlsEvent {
    /// TLS version string (e.g., "TLSv1.2", "TLSv1.3").
    pub version: String,
    /// TLS version numeric (e.g., 0x0303 for TLS 1.2).
    pub version_num: u16,
    /// Selected cipher suite name or hex string.
    pub cipher: String,
    /// Server Name Indication (from ClientHello).
    pub server_name: String,
    /// JA3 hash (ClientHello fingerprint).
    pub ja3: String,
    /// Raw JA3 string before hashing.
    pub ja3_raw: String,
    /// JA3S hash (ServerHello fingerprint).
    pub ja3s: String,
    /// Raw JA3S string before hashing.
    pub ja3s_raw: String,
    /// Certificate subject (from Certificate message).
    pub subject: String,
    /// Certificate issuer.
    pub issuer: String,
    /// Certificate validity start (Unix epoch).
    pub not_valid_before: f64,
    /// Certificate validity end (Unix epoch).
    pub not_valid_after: f64,
    /// Whether the JA3 hash matches a known malicious fingerprint.
    pub is_malicious_ja3: bool,
    /// Tag for the matched malicious JA3 (e.g., "CobaltStrike").
    pub malicious_ja3_tag: String,
    /// Whether this event is from ClientHello, ServerHello, or Certificate.
    pub event_type: TlsEventType,
    /// Packet timestamp.
    pub ts: f64,
}

/// Which TLS handshake message produced this event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsEventType {
    ClientHello,
    ServerHello,
    Certificate,
}

// ---------------------------------------------------------------------------
// TlsParser
// ---------------------------------------------------------------------------

/// TLS protocol parser for fingerprinting and certificate extraction.
///
/// Parses ClientHello, ServerHello, and Certificate handshake messages.
/// Maintains per-flow state to correlate ClientHello with ServerHello.
pub struct TlsParser {
    /// Per-flow JA3 state: maps community_id -> pending ClientHello data.
    flow_state: Mutex<HashMap<String, PendingTls>>,
}

/// Pending TLS handshake data for a flow.
#[derive(Debug, Clone)]
struct PendingTls {
    ja3: String,
    ja3_raw: String,
    server_name: String,
    client_version: u16,
}

impl TlsParser {
    /// Create a new TLS parser.
    pub fn new() -> Self {
        Self {
            flow_state: Mutex::new(HashMap::new()),
        }
    }

    /// Parse a TLS ClientHello message.
    ///
    /// Extracts SNI, cipher suites, extensions, elliptic curves, and
    /// EC point formats. Computes the JA3 fingerprint hash.
    fn parse_client_hello(&self, payload: &[u8], ts: f64) -> Option<TlsEvent> {
        if payload.len() < MIN_CLIENT_HELLO_LEN {
            return None;
        }

        let mut offset = 0;

        // Client version (2 bytes)
        let version = u16::from_be_bytes([payload[offset], payload[offset + 1]]);
        offset += 2;

        // Random (32 bytes)
        offset += 32;

        // Session ID
        if offset >= payload.len() {
            return None;
        }
        let session_id_len = payload[offset] as usize;
        offset += 1 + session_id_len;

        if offset + 2 > payload.len() {
            return None;
        }

        // Cipher Suites
        let cipher_suites_len = u16::from_be_bytes([payload[offset], payload[offset + 1]]) as usize;
        offset += 2;

        if offset + cipher_suites_len > payload.len() {
            return None;
        }

        let mut cipher_suites = Vec::new();
        let cs_end = offset + cipher_suites_len;
        while offset + 1 < cs_end {
            let cs = u16::from_be_bytes([payload[offset], payload[offset + 1]]);
            if !is_grease(cs) {
                cipher_suites.push(cs);
            }
            offset += 2;
        }
        offset = cs_end;

        // Compression Methods
        if offset >= payload.len() {
            return None;
        }
        let comp_len = payload[offset] as usize;
        offset += 1 + comp_len;

        // Extensions
        let mut extensions = Vec::new();
        let mut elliptic_curves = Vec::new();
        let mut ec_point_formats = Vec::new();
        let mut server_name = String::new();

        if offset + 2 <= payload.len() {
            let ext_total_len =
                u16::from_be_bytes([payload[offset], payload[offset + 1]]) as usize;
            offset += 2;

            let ext_end = (offset + ext_total_len).min(payload.len());
            while offset + 4 <= ext_end {
                let ext_type = u16::from_be_bytes([payload[offset], payload[offset + 1]]);
                let ext_len =
                    u16::from_be_bytes([payload[offset + 2], payload[offset + 3]]) as usize;
                offset += 4;

                if !is_grease(ext_type) {
                    extensions.push(ext_type);
                }

                let ext_data_end = (offset + ext_len).min(payload.len());

                match ext_type {
                    // SNI (Server Name Indication)
                    0x0000 => {
                        server_name = self.parse_sni(&payload[offset..ext_data_end]);
                    }
                    // Supported Groups (Elliptic Curves)
                    0x000A => {
                        elliptic_curves =
                            self.parse_u16_list(&payload[offset..ext_data_end], true);
                    }
                    // EC Point Formats
                    0x000B => {
                        ec_point_formats =
                            self.parse_u8_list(&payload[offset..ext_data_end]);
                    }
                    _ => {}
                }

                offset = ext_data_end;
            }
        }

        // Build JA3 string: SSLVersion,Ciphers,Extensions,EllipticCurves,ECPointFormats
        let ja3_raw = format!(
            "{},{},{},{},{}",
            version,
            join_u16(&cipher_suites),
            join_u16(&extensions),
            join_u16(&elliptic_curves),
            join_u16_from_u8(&ec_point_formats),
        );

        let ja3 = md5_hex(&ja3_raw);

        // Check malicious JA3 database
        let (is_malicious, tag) = check_malicious_ja3(&ja3);

        Some(TlsEvent {
            version: version_to_string(version),
            version_num: version,
            cipher: String::new(), // Populated from ServerHello
            server_name,
            ja3,
            ja3_raw,
            ja3s: String::new(),
            ja3s_raw: String::new(),
            subject: String::new(),
            issuer: String::new(),
            not_valid_before: 0.0,
            not_valid_after: 0.0,
            is_malicious_ja3: is_malicious,
            malicious_ja3_tag: tag,
            event_type: TlsEventType::ClientHello,
            ts,
        })
    }

    /// Parse a TLS ServerHello message.
    ///
    /// Extracts the selected cipher suite and extensions. Computes JA3S.
    fn parse_server_hello(&self, payload: &[u8], ts: f64) -> Option<TlsEvent> {
        if payload.len() < 38 {
            return None;
        }

        let mut offset = 0;

        // Server version
        let version = u16::from_be_bytes([payload[offset], payload[offset + 1]]);
        offset += 2;

        // Random (32 bytes)
        offset += 32;

        // Session ID
        if offset >= payload.len() {
            return None;
        }
        let session_id_len = payload[offset] as usize;
        offset += 1 + session_id_len;

        if offset + 2 > payload.len() {
            return None;
        }

        // Selected Cipher Suite (single value)
        let cipher = u16::from_be_bytes([payload[offset], payload[offset + 1]]);
        offset += 2;

        // Compression Method (1 byte)
        if offset >= payload.len() {
            return None;
        }
        offset += 1;

        // Extensions
        let mut extensions = Vec::new();
        if offset + 2 <= payload.len() {
            let ext_total_len =
                u16::from_be_bytes([payload[offset], payload[offset + 1]]) as usize;
            offset += 2;

            let ext_end = (offset + ext_total_len).min(payload.len());
            while offset + 4 <= ext_end {
                let ext_type = u16::from_be_bytes([payload[offset], payload[offset + 1]]);
                let ext_len =
                    u16::from_be_bytes([payload[offset + 2], payload[offset + 3]]) as usize;
                offset += 4;

                if !is_grease(ext_type) {
                    extensions.push(ext_type);
                }

                offset = (offset + ext_len).min(payload.len());
            }
        }

        // Build JA3S string: SSLVersion,Cipher,Extensions
        let ja3s_raw = format!("{},{},{}", version, cipher, join_u16(&extensions));
        let ja3s = md5_hex(&ja3s_raw);

        Some(TlsEvent {
            version: version_to_string(version),
            version_num: version,
            cipher: format!("0x{:04X}", cipher),
            server_name: String::new(),
            ja3: String::new(),
            ja3_raw: String::new(),
            ja3s,
            ja3s_raw,
            subject: String::new(),
            issuer: String::new(),
            not_valid_before: 0.0,
            not_valid_after: 0.0,
            is_malicious_ja3: false,
            malicious_ja3_tag: String::new(),
            event_type: TlsEventType::ServerHello,
            ts,
        })
    }

    /// Parse a TLS Certificate message.
    ///
    /// Extracts subject, issuer, and validity period from the first
    /// certificate in the chain.
    fn parse_certificate(&self, payload: &[u8], ts: f64) -> Option<TlsEvent> {
        // TODO: Implement X.509 certificate parsing.
        // This requires ASN.1 DER decoding which is non-trivial.
        // For the scaffold, return a placeholder event.

        if payload.len() < 7 {
            return None;
        }

        // Certificate chain total length (3 bytes)
        let _total_len = ((payload[0] as usize) << 16)
            | ((payload[1] as usize) << 8)
            | (payload[2] as usize);

        // TODO: Parse individual certificates in the chain
        // Each certificate is preceded by a 3-byte length field.
        // Use an ASN.1 parser (e.g., `der-parser` or `x509-parser` crate)
        // to extract subject, issuer, and validity.

        Some(TlsEvent {
            version: String::new(),
            version_num: 0,
            cipher: String::new(),
            server_name: String::new(),
            ja3: String::new(),
            ja3_raw: String::new(),
            ja3s: String::new(),
            ja3s_raw: String::new(),
            subject: String::new(),    // TODO: Extract from X.509
            issuer: String::new(),     // TODO: Extract from X.509
            not_valid_before: 0.0,     // TODO: Extract from X.509
            not_valid_after: 0.0,      // TODO: Extract from X.509
            is_malicious_ja3: false,
            malicious_ja3_tag: String::new(),
            event_type: TlsEventType::Certificate,
            ts,
        })
    }

    /// Parse the SNI extension data.
    fn parse_sni(&self, data: &[u8]) -> String {
        // SNI extension format:
        //   Server Name list length (2 bytes)
        //   Name Type (1 byte, 0 = host_name)
        //   Host Name length (2 bytes)
        //   Host Name (variable)
        if data.len() < 5 {
            return String::new();
        }

        let _list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
        let name_type = data[2];

        if name_type != 0 {
            return String::new();
        }

        let name_len = u16::from_be_bytes([data[3], data[4]]) as usize;
        if 5 + name_len > data.len() {
            return String::new();
        }

        String::from_utf8_lossy(&data[5..5 + name_len]).to_string()
    }

    /// Parse a list of u16 values with a 2-byte length prefix, filtering GREASE.
    fn parse_u16_list(&self, data: &[u8], filter_grease: bool) -> Vec<u16> {
        if data.len() < 2 {
            return Vec::new();
        }

        let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
        let mut result = Vec::new();
        let mut offset = 2;
        let end = (2 + list_len).min(data.len());

        while offset + 1 < end {
            let val = u16::from_be_bytes([data[offset], data[offset + 1]]);
            if !filter_grease || !is_grease(val) {
                result.push(val);
            }
            offset += 2;
        }

        result
    }

    /// Parse a list of u8 values with a 1-byte length prefix.
    fn parse_u8_list(&self, data: &[u8]) -> Vec<u8> {
        if data.is_empty() {
            return Vec::new();
        }

        let list_len = data[0] as usize;
        let end = (1 + list_len).min(data.len());
        data[1..end].to_vec()
    }
}

impl ProtocolParser for TlsParser {
    fn parse(
        &self,
        flow: &FlowKey,
        direction: Direction,
        payload: &[u8],
        ts: f64,
    ) -> Vec<ProtocolEvent> {
        let mut events = Vec::new();

        // Check for TLS record header
        if payload.len() < TLS_RECORD_HEADER_LEN {
            return events;
        }

        let content_type = payload[0];
        if content_type != TLS_HANDSHAKE {
            return events;
        }

        let _record_version = u16::from_be_bytes([payload[1], payload[2]]);
        let record_len = u16::from_be_bytes([payload[3], payload[4]]) as usize;

        if payload.len() < TLS_RECORD_HEADER_LEN + 4 {
            return events;
        }

        let handshake_type = payload[5];
        let _handshake_len = ((payload[6] as usize) << 16)
            | ((payload[7] as usize) << 8)
            | (payload[8] as usize);

        let handshake_data = &payload[9..payload.len().min(TLS_RECORD_HEADER_LEN + record_len)];

        match handshake_type {
            CLIENT_HELLO if direction == Direction::Originator => {
                if let Some(event) = self.parse_client_hello(handshake_data, ts) {
                    events.push(ProtocolEvent::Tls(event));
                }
            }
            SERVER_HELLO if direction == Direction::Responder => {
                if let Some(event) = self.parse_server_hello(handshake_data, ts) {
                    events.push(ProtocolEvent::Tls(event));
                }
            }
            CERTIFICATE if direction == Direction::Responder => {
                if let Some(event) = self.parse_certificate(handshake_data, ts) {
                    events.push(ProtocolEvent::Tls(event));
                }
            }
            _ => {}
        }

        events
    }

    fn timeout(&self) -> f64 {
        300.0
    }

    fn protocol_id(&self) -> &'static str {
        "tls"
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Convert a TLS version number to a human-readable string.
fn version_to_string(version: u16) -> String {
    match version {
        0x0300 => "SSLv3".to_string(),
        0x0301 => "TLSv1.0".to_string(),
        0x0302 => "TLSv1.1".to_string(),
        0x0303 => "TLSv1.2".to_string(),
        0x0304 => "TLSv1.3".to_string(),
        v => format!("0x{:04X}", v),
    }
}

/// Join a slice of u16 values into a dash-separated string.
fn join_u16(values: &[u16]) -> String {
    values
        .iter()
        .map(|v| v.to_string())
        .collect::<Vec<_>>()
        .join("-")
}

/// Join a slice of u8 values into a dash-separated string (as u16 for JA3 format).
fn join_u16_from_u8(values: &[u8]) -> String {
    values
        .iter()
        .map(|v| (*v as u16).to_string())
        .collect::<Vec<_>>()
        .join("-")
}

/// Compute the MD5 hex digest of a string.
fn md5_hex(input: &str) -> String {
    let digest = Md5::digest(input.as_bytes());
    let mut hex = String::with_capacity(32);
    for byte in digest.iter() {
        write!(hex, "{:02x}", byte).unwrap();
    }
    hex
}

/// Check if a JA3 hash matches a known malicious fingerprint.
///
/// Returns `(is_malicious, tag)`.
fn check_malicious_ja3(ja3: &str) -> (bool, String) {
    for (hash, tag) in MALICIOUS_JA3_DB {
        if ja3 == *hash {
            return (true, tag.to_string());
        }
    }
    (false, String::new())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_grease_detection() {
        assert!(is_grease(0x0A0A));
        assert!(is_grease(0xFAFA));
        assert!(!is_grease(0x0035)); // TLS_RSA_WITH_AES_256_CBC_SHA
        assert!(!is_grease(0x1301)); // TLS_AES_128_GCM_SHA256
    }

    #[test]
    fn test_version_to_string() {
        assert_eq!(version_to_string(0x0303), "TLSv1.2");
        assert_eq!(version_to_string(0x0304), "TLSv1.3");
        assert_eq!(version_to_string(0x0300), "SSLv3");
    }

    #[test]
    fn test_md5_hex() {
        // MD5 of empty string
        assert_eq!(md5_hex(""), "d41d8cd98f00b204e9800998ecf8427e");
    }

    #[test]
    fn test_malicious_ja3_lookup() {
        let (is_mal, tag) = check_malicious_ja3("51c64c77e60f3980eea90869b68c58a8");
        assert!(is_mal);
        assert_eq!(tag, "CobaltStrike");

        let (is_mal, _) = check_malicious_ja3("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        assert!(!is_mal);
    }

    #[test]
    fn test_join_u16() {
        assert_eq!(join_u16(&[49195, 49199, 49196]), "49195-49199-49196");
        assert_eq!(join_u16(&[]), "");
    }

    #[test]
    fn test_parse_sni() {
        let parser = TlsParser::new();
        // Construct SNI extension data: list_len(2) + type(1) + name_len(2) + name
        let name = b"example.com";
        let mut data = Vec::new();
        let entry_len = 1 + 2 + name.len();
        data.extend_from_slice(&(entry_len as u16).to_be_bytes());
        data.push(0x00); // host_name type
        data.extend_from_slice(&(name.len() as u16).to_be_bytes());
        data.extend_from_slice(name);

        assert_eq!(parser.parse_sni(&data), "example.com");
    }

    #[test]
    fn test_parser_too_short() {
        let parser = TlsParser::new();
        let flow = FlowKey::new("10.0.0.1".into(), "10.0.0.2".into(), 12345, 443, 6);
        let events = parser.parse(&flow, Direction::Originator, b"short", 1000.0);
        assert!(events.is_empty());
    }
}
