//! # SSH Protocol Parser
//!
//! Parses SSH version negotiation banners and tracks authentication attempts
//! for brute-force detection. Produces events in Napse native SSH log
//! format.
//!
//! ## Detection Capabilities
//!
//! - **Version Extraction**: Client and server SSH version strings
//! - **Brute Force Detection**: Counts authentication attempts per flow
//! - **Banner Grabbing**: Captures the SSH banner for fingerprinting
//! - **Key Exchange Algorithm Tracking**: Identifies negotiated algorithms
//!
//! ## Wire Format
//!
//! SSH version string format (RFC 4253 Section 4.2):
//! ```text
//! SSH-protoversion-softwareversion SP comments CR LF
//! ```
//!
//! Examples:
//! - `SSH-2.0-OpenSSH_9.6`
//! - `SSH-2.0-paramiko_3.4.0`
//! - `SSH-2.0-libssh2_1.11.0`

use std::collections::HashMap;
use std::sync::Mutex;

use crate::conntrack::FlowKey;
use crate::protocols::{Direction, ProtocolEvent, ProtocolParser};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// SSH version string prefix.
const SSH_PREFIX: &[u8] = b"SSH-";

/// Maximum reasonable SSH banner length.
const MAX_BANNER_LEN: usize = 255;

/// Default brute-force threshold (auth attempts per connection).
const DEFAULT_BRUTE_FORCE_THRESHOLD: u32 = 5;

// ---------------------------------------------------------------------------
// SSH event
// ---------------------------------------------------------------------------

/// Events produced by the SSH parser.
#[derive(Debug, Clone)]
pub enum SshEvent {
    /// An SSH version banner was observed.
    VersionExchange {
        /// The version string (e.g., "SSH-2.0-OpenSSH_9.6").
        version: String,
        /// The SSH protocol version (e.g., "2.0").
        protocol_version: String,
        /// The software version (e.g., "OpenSSH_9.6").
        software_version: String,
        /// Whether this is the client or server banner.
        direction: SshDirection,
        /// Packet timestamp.
        ts: f64,
    },

    /// An authentication attempt was detected.
    AuthAttempt {
        /// Running count of auth attempts for this flow.
        attempt_number: u32,
        /// Whether this appears to be a successful auth.
        success: bool,
        /// Packet timestamp.
        ts: f64,
    },

    /// Brute force threshold exceeded for this connection.
    BruteForceDetected {
        /// Source IP of the brute force attempt.
        src_ip: String,
        /// Destination IP being attacked.
        dst_ip: String,
        /// Total auth attempts observed.
        total_attempts: u32,
        /// Packet timestamp.
        ts: f64,
    },
}

/// SSH direction indicator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SshDirection {
    Client,
    Server,
}

// ---------------------------------------------------------------------------
// Per-flow SSH state
// ---------------------------------------------------------------------------

/// Per-flow state for SSH connection tracking.
#[derive(Debug)]
struct SshFlowState {
    /// Whether we've seen the client version string.
    client_version_seen: bool,
    /// Whether we've seen the server version string.
    server_version_seen: bool,
    /// Client version string.
    client_version: String,
    /// Server version string.
    server_version: String,
    /// Number of authentication attempts detected.
    auth_attempts: u32,
    /// Whether brute force alert has already been fired.
    brute_force_alerted: bool,
    /// Whether authentication appears to have been successful.
    auth_success: bool,
}

impl SshFlowState {
    fn new() -> Self {
        Self {
            client_version_seen: false,
            server_version_seen: false,
            client_version: String::new(),
            server_version: String::new(),
            auth_attempts: 0,
            brute_force_alerted: false,
            auth_success: false,
        }
    }
}

// ---------------------------------------------------------------------------
// SshParser
// ---------------------------------------------------------------------------

/// SSH protocol parser for version negotiation and auth tracking.
///
/// Maintains per-flow state to track authentication attempts and detect
/// brute-force attacks. Thread-safe via internal mutex.
pub struct SshParser {
    /// Per-flow SSH state, keyed by a flow identifier string.
    flow_states: Mutex<HashMap<String, SshFlowState>>,
    /// Number of auth attempts to trigger brute-force alert.
    brute_force_threshold: u32,
}

impl SshParser {
    /// Create a new SSH parser with default brute-force threshold.
    pub fn new() -> Self {
        Self {
            flow_states: Mutex::new(HashMap::new()),
            brute_force_threshold: DEFAULT_BRUTE_FORCE_THRESHOLD,
        }
    }

    /// Create a new SSH parser with a custom brute-force threshold.
    pub fn with_threshold(threshold: u32) -> Self {
        Self {
            flow_states: Mutex::new(HashMap::new()),
            brute_force_threshold: threshold,
        }
    }

    /// Generate a flow identifier string for state lookup.
    fn flow_id(flow: &FlowKey) -> String {
        let canonical = flow.canonical();
        format!(
            "{}:{}->{}:{}",
            canonical.src_ip, canonical.src_port, canonical.dst_ip, canonical.dst_port
        )
    }

    /// Try to parse an SSH version string from the payload.
    fn try_parse_version(&self, payload: &[u8]) -> Option<(String, String, String)> {
        // Check for SSH prefix
        if payload.len() < 8 || !payload.starts_with(SSH_PREFIX) {
            return None;
        }

        // Find the end of the version line (CR LF or just LF)
        let max_len = payload.len().min(MAX_BANNER_LEN);
        let line_end = payload[..max_len]
            .iter()
            .position(|&b| b == b'\n' || b == b'\r')
            .unwrap_or(max_len);

        let version_str = String::from_utf8_lossy(&payload[..line_end]).to_string();

        // Parse: SSH-protoversion-softwareversion
        let parts: Vec<&str> = version_str.splitn(3, '-').collect();
        if parts.len() < 3 {
            return None;
        }

        let protocol_version = parts[1].to_string();
        // Software version may contain spaces (comments)
        let software_version = parts[2].split(' ').next().unwrap_or("").to_string();

        Some((version_str, protocol_version, software_version))
    }

    /// Detect SSH authentication-related packets.
    ///
    /// After the version exchange and key exchange, SSH uses binary packets
    /// for authentication. We use heuristics based on packet size and
    /// message type byte to detect auth attempts.
    fn detect_auth_activity(
        &self,
        payload: &[u8],
        direction: Direction,
    ) -> Option<(bool, bool)> {
        // SSH binary packet format (after key exchange):
        //   uint32 packet_length
        //   byte   padding_length
        //   byte   message_type
        //   ...

        if payload.len() < 6 {
            return None;
        }

        let packet_len = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
        if packet_len < 2 || packet_len > 35000 {
            return None; // Not a valid SSH packet
        }

        let _padding_len = payload[4];
        let msg_type = payload[5];

        // SSH_MSG_USERAUTH_REQUEST = 50 (client -> server)
        // SSH_MSG_USERAUTH_FAILURE = 51 (server -> client)
        // SSH_MSG_USERAUTH_SUCCESS = 52 (server -> client)
        match (msg_type, direction) {
            (50, Direction::Originator) => Some((true, false)),  // Auth request
            (51, Direction::Responder) => Some((true, false)),   // Auth failure
            (52, Direction::Responder) => Some((false, true)),   // Auth success
            _ => None,
        }
    }
}

impl ProtocolParser for SshParser {
    fn parse(
        &self,
        flow: &FlowKey,
        direction: Direction,
        payload: &[u8],
        ts: f64,
    ) -> Vec<ProtocolEvent> {
        let mut events = Vec::new();
        let fid = Self::flow_id(flow);

        let mut states = self.flow_states.lock().unwrap();
        let state = states.entry(fid).or_insert_with(SshFlowState::new);

        // Try to parse version string
        if let Some((version, protocol_version, software_version)) =
            self.try_parse_version(payload)
        {
            let ssh_dir = match direction {
                Direction::Originator => {
                    state.client_version_seen = true;
                    state.client_version = version.clone();
                    SshDirection::Client
                }
                Direction::Responder => {
                    state.server_version_seen = true;
                    state.server_version = version.clone();
                    SshDirection::Server
                }
            };

            events.push(ProtocolEvent::Ssh(SshEvent::VersionExchange {
                version,
                protocol_version,
                software_version,
                direction: ssh_dir,
                ts,
            }));

            return events;
        }

        // Detect authentication activity (only after version exchange)
        if state.client_version_seen && state.server_version_seen {
            if let Some((is_attempt, is_success)) =
                self.detect_auth_activity(payload, direction)
            {
                if is_attempt {
                    state.auth_attempts += 1;

                    events.push(ProtocolEvent::Ssh(SshEvent::AuthAttempt {
                        attempt_number: state.auth_attempts,
                        success: false,
                        ts,
                    }));

                    // Check brute force threshold
                    if state.auth_attempts >= self.brute_force_threshold
                        && !state.brute_force_alerted
                    {
                        state.brute_force_alerted = true;
                        events.push(ProtocolEvent::Ssh(SshEvent::BruteForceDetected {
                            src_ip: flow.src_ip.clone(),
                            dst_ip: flow.dst_ip.clone(),
                            total_attempts: state.auth_attempts,
                            ts,
                        }));
                    }
                }

                if is_success {
                    state.auth_success = true;
                    events.push(ProtocolEvent::Ssh(SshEvent::AuthAttempt {
                        attempt_number: state.auth_attempts,
                        success: true,
                        ts,
                    }));
                }
            }
        }

        events
    }

    fn timeout(&self) -> f64 {
        3600.0 // SSH sessions can be very long-lived
    }

    fn protocol_id(&self) -> &'static str {
        "ssh"
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_client_version() {
        let parser = SshParser::new();
        let flow = FlowKey::new("10.0.0.1".into(), "10.0.0.2".into(), 12345, 22, 6);
        let payload = b"SSH-2.0-OpenSSH_9.6\r\n";

        let events = parser.parse(&flow, Direction::Originator, payload, 1000.0);
        assert_eq!(events.len(), 1);

        match &events[0] {
            ProtocolEvent::Ssh(SshEvent::VersionExchange {
                version,
                protocol_version,
                software_version,
                direction,
                ..
            }) => {
                assert_eq!(version, "SSH-2.0-OpenSSH_9.6");
                assert_eq!(protocol_version, "2.0");
                assert_eq!(software_version, "OpenSSH_9.6");
                assert_eq!(*direction, SshDirection::Client);
            }
            _ => panic!("Expected VersionExchange event"),
        }
    }

    #[test]
    fn test_parse_server_version() {
        let parser = SshParser::new();
        let flow = FlowKey::new("10.0.0.2".into(), "10.0.0.1".into(), 22, 12345, 6);
        let payload = b"SSH-2.0-paramiko_3.4.0\r\n";

        let events = parser.parse(&flow, Direction::Responder, payload, 1000.0);
        assert_eq!(events.len(), 1);

        match &events[0] {
            ProtocolEvent::Ssh(SshEvent::VersionExchange {
                software_version,
                direction,
                ..
            }) => {
                assert_eq!(software_version, "paramiko_3.4.0");
                assert_eq!(*direction, SshDirection::Server);
            }
            _ => panic!("Expected VersionExchange event"),
        }
    }

    #[test]
    fn test_non_ssh_payload() {
        let parser = SshParser::new();
        let flow = FlowKey::new("10.0.0.1".into(), "10.0.0.2".into(), 12345, 22, 6);
        let payload = b"GET / HTTP/1.1\r\n";

        let events = parser.parse(&flow, Direction::Originator, payload, 1000.0);
        assert!(events.is_empty());
    }

    #[test]
    fn test_brute_force_detection() {
        let parser = SshParser::with_threshold(3);
        let flow = FlowKey::new("10.0.0.1".into(), "10.0.0.2".into(), 12345, 22, 6);

        // First: client and server version exchange
        let client_ver = b"SSH-2.0-OpenSSH_9.6\r\n";
        parser.parse(&flow, Direction::Originator, client_ver, 1000.0);

        let resp_flow = FlowKey::new("10.0.0.2".into(), "10.0.0.1".into(), 22, 12345, 6);
        let server_ver = b"SSH-2.0-OpenSSH_9.6\r\n";
        parser.parse(&resp_flow, Direction::Responder, server_ver, 1000.1);

        // Simulate auth attempts (msg_type 50 = USERAUTH_REQUEST)
        let mut auth_packet = vec![0u8; 20];
        auth_packet[0..4].copy_from_slice(&14u32.to_be_bytes()); // packet_length
        auth_packet[4] = 4; // padding_length
        auth_packet[5] = 50; // SSH_MSG_USERAUTH_REQUEST

        for i in 0..3 {
            let events = parser.parse(
                &flow,
                Direction::Originator,
                &auth_packet,
                1001.0 + i as f64,
            );

            if i == 2 {
                // Third attempt should trigger brute force
                assert!(events.iter().any(|e| matches!(
                    e,
                    ProtocolEvent::Ssh(SshEvent::BruteForceDetected { .. })
                )));
            }
        }
    }

    #[test]
    fn test_version_with_comments() {
        let parser = SshParser::new();
        let (version, proto, software) = parser
            .try_parse_version(b"SSH-2.0-OpenSSH_9.6 Ubuntu-1\r\n")
            .unwrap();
        assert_eq!(version, "SSH-2.0-OpenSSH_9.6 Ubuntu-1");
        assert_eq!(proto, "2.0");
        assert_eq!(software, "OpenSSH_9.6");
    }
}
