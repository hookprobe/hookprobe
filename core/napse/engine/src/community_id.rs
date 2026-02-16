//! # Community-ID v1 Flow Hashing
//!
//! Implementation of the Community-ID v1 flow hashing specification for
//! deterministic, transport-agnostic flow identification. Produces the same
//! hash regardless of which endpoint is the source vs destination.
//!
//! Spec: <https://github.com/corelight/community-id-spec>
//!
//! The resulting string has the format `1:<base64(sha1(seed + fields))>`.
//!
//! ## Field ordering
//!
//! For TCP/UDP/SCTP, the canonical ordering is determined by comparing
//! `(src_ip, src_port)` against `(dst_ip, dst_port)` lexicographically.
//! For ICMP, a type-based mapping is used to determine the "lower" side.
//!
//! ## Example
//!
//! ```rust
//! use napse_engine::community_id::compute_community_id;
//!
//! let cid = compute_community_id(
//!     "192.168.1.100",
//!     "93.184.216.34",
//!     12345,
//!     443,
//!     6, // TCP
//!     0, // default seed
//! );
//! // Returns something like "1:abc123...=="
//! ```

use sha1::Digest;
use std::net::IpAddr;

/// ICMP type-to-code mapping for canonical direction.
///
/// Maps ICMP types to their "reverse" counterparts. For example,
/// Echo Request (8) maps to Echo Reply (0). The side with the
/// lower type value is considered the "source" for hashing.
const ICMP_TYPE_MAP: [(u8, u8); 8] = [
    (0, 8),   // Echo Reply -> Echo Request
    (3, 11),  // Dest Unreachable -> Time Exceeded (both one-way)
    (8, 0),   // Echo Request -> Echo Reply
    (11, 3),  // Time Exceeded -> Dest Unreachable
    (12, 12), // Parameter Problem (self-paired)
    (13, 14), // Timestamp -> Timestamp Reply
    (14, 13), // Timestamp Reply -> Timestamp
    (15, 16), // Information Request -> Information Reply
];

/// Compute the Community-ID v1 hash for a network flow.
///
/// # Arguments
///
/// * `src_ip` - Source IP address as a string (IPv4 or IPv6)
/// * `dst_ip` - Destination IP address as a string (IPv4 or IPv6)
/// * `src_port` - Source port (or ICMP type)
/// * `dst_port` - Destination port (or ICMP code)
/// * `proto` - IP protocol number (6=TCP, 17=UDP, 1=ICMP, 58=ICMPv6, etc.)
/// * `seed` - Community-ID seed value (default 0)
///
/// # Returns
///
/// A string in the format `"1:<base64-sha1>"` or an empty string if the
/// input addresses cannot be parsed.
pub fn compute_community_id(
    src_ip: &str,
    dst_ip: &str,
    src_port: u16,
    dst_port: u16,
    proto: u8,
    seed: u16,
) -> String {
    let src_addr = match src_ip.parse::<IpAddr>() {
        Ok(addr) => addr,
        Err(_) => return String::new(),
    };
    let dst_addr = match dst_ip.parse::<IpAddr>() {
        Ok(addr) => addr,
        Err(_) => return String::new(),
    };

    // Determine canonical ordering (is_one_way for ICMP, lexicographic otherwise)
    let (lo_ip, hi_ip, lo_port, hi_port) =
        canonical_order(src_addr, dst_addr, src_port, dst_port, proto);

    // Build the hash input buffer
    let mut buf = Vec::with_capacity(40);

    // Seed (2 bytes, network byte order)
    buf.extend_from_slice(&seed.to_be_bytes());

    // Source IP bytes
    match lo_ip {
        IpAddr::V4(v4) => buf.extend_from_slice(&v4.octets()),
        IpAddr::V6(v6) => buf.extend_from_slice(&v6.octets()),
    }

    // Destination IP bytes
    match hi_ip {
        IpAddr::V4(v4) => buf.extend_from_slice(&v4.octets()),
        IpAddr::V6(v6) => buf.extend_from_slice(&v6.octets()),
    }

    // Protocol (1 byte)
    buf.push(proto);

    // Padding (1 byte)
    buf.push(0);

    // Ports (2 bytes each, network byte order)
    buf.extend_from_slice(&lo_port.to_be_bytes());
    buf.extend_from_slice(&hi_port.to_be_bytes());

    // SHA-1 hash
    let hash = sha1_hash(&buf);

    // Base64 encode and format
    let encoded = base64_encode(&hash);
    format!("1:{encoded}")
}

/// Determine the canonical ordering for Community-ID.
///
/// Returns `(lower_ip, higher_ip, lower_port, higher_port)` where "lower"
/// is determined by comparing `(ip, port)` tuples. For ICMP, the type
/// mapping is consulted first.
fn canonical_order(
    src_ip: IpAddr,
    dst_ip: IpAddr,
    src_port: u16,
    dst_port: u16,
    proto: u8,
) -> (IpAddr, IpAddr, u16, u16) {
    // For ICMP (proto 1) and ICMPv6 (proto 58), use type-based ordering
    if proto == 1 || proto == 58 {
        return canonical_order_icmp(src_ip, dst_ip, src_port, dst_port);
    }

    // Lexicographic comparison: first by IP, then by port
    let src_tuple = (ip_to_bytes(&src_ip), src_port);
    let dst_tuple = (ip_to_bytes(&dst_ip), dst_port);

    if src_tuple <= dst_tuple {
        (src_ip, dst_ip, src_port, dst_port)
    } else {
        (dst_ip, src_ip, dst_port, src_port)
    }
}

/// Canonical ordering for ICMP flows using type mapping.
fn canonical_order_icmp(
    src_ip: IpAddr,
    dst_ip: IpAddr,
    icmp_type: u16,
    icmp_code: u16,
) -> (IpAddr, IpAddr, u16, u16) {
    // Look up the reverse type
    let type_u8 = icmp_type as u8;
    let reverse_type = ICMP_TYPE_MAP
        .iter()
        .find(|(t, _)| *t == type_u8)
        .map(|(_, r)| *r as u16);

    match reverse_type {
        Some(rev) if icmp_type < rev => (src_ip, dst_ip, icmp_type, icmp_code),
        Some(rev) if icmp_type > rev => (dst_ip, src_ip, rev, icmp_code),
        _ => {
            // Same type for both directions or unknown; use IP ordering
            if ip_to_bytes(&src_ip) <= ip_to_bytes(&dst_ip) {
                (src_ip, dst_ip, icmp_type, icmp_code)
            } else {
                (dst_ip, src_ip, icmp_type, icmp_code)
            }
        }
    }
}

/// Convert an IP address to a byte vector for comparison.
fn ip_to_bytes(ip: &IpAddr) -> Vec<u8> {
    match ip {
        IpAddr::V4(v4) => v4.octets().to_vec(),
        IpAddr::V6(v6) => v6.octets().to_vec(),
    }
}

/// Compute SHA-1 hash of the input bytes.
///
/// Community-ID v1 spec mandates SHA-1. This is not used for cryptographic
/// security — only for deterministic flow hashing compatible with other
/// cross-tool flow correlation standard.
fn sha1_hash(data: &[u8]) -> [u8; 20] {
    let digest = sha1::Sha1::digest(data);
    let mut result = [0u8; 20];
    result.copy_from_slice(&digest);
    result
}

/// Base64-encode a byte slice (standard alphabet, with padding).
fn base64_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut result = String::with_capacity((data.len() + 2) / 3 * 4);
    let chunks = data.chunks(3);

    for chunk in chunks {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };

        let triple = (b0 << 16) | (b1 << 8) | b2;

        result.push(ALPHABET[((triple >> 18) & 0x3F) as usize] as char);
        result.push(ALPHABET[((triple >> 12) & 0x3F) as usize] as char);

        if chunk.len() > 1 {
            result.push(ALPHABET[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }

        if chunk.len() > 2 {
            result.push(ALPHABET[(triple & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
    }

    result
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_community_id_tcp_basic() {
        // A basic TCP flow should produce a non-empty Community-ID
        let cid = compute_community_id("192.168.1.1", "10.0.0.1", 12345, 80, 6, 0);
        assert!(!cid.is_empty());
        assert!(cid.starts_with("1:"));
    }

    #[test]
    fn test_community_id_symmetric() {
        // Swapping src/dst should produce the same Community-ID
        let cid1 = compute_community_id("192.168.1.1", "10.0.0.1", 12345, 80, 6, 0);
        let cid2 = compute_community_id("10.0.0.1", "192.168.1.1", 80, 12345, 6, 0);
        assert_eq!(cid1, cid2);
    }

    #[test]
    fn test_community_id_different_flows() {
        let cid1 = compute_community_id("192.168.1.1", "10.0.0.1", 12345, 80, 6, 0);
        let cid2 = compute_community_id("192.168.1.1", "10.0.0.1", 12345, 443, 6, 0);
        assert_ne!(cid1, cid2);
    }

    #[test]
    fn test_community_id_invalid_ip() {
        let cid = compute_community_id("not_an_ip", "10.0.0.1", 12345, 80, 6, 0);
        assert!(cid.is_empty());
    }

    #[test]
    fn test_community_id_udp() {
        let cid = compute_community_id("192.168.1.1", "8.8.8.8", 54321, 53, 17, 0);
        assert!(cid.starts_with("1:"));
    }

    #[test]
    fn test_community_id_ipv6() {
        let cid = compute_community_id("::1", "fe80::1", 12345, 80, 6, 0);
        assert!(cid.starts_with("1:"));
    }

    #[test]
    fn test_base64_encode() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
    }
}
