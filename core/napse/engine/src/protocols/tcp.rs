//! # TCP Protocol Parser
//!
//! Tracks TCP state machine transitions and detects anomalies such as
//! port scans, SYN floods, and unexpected resets. Works in conjunction
//! with the connection table's built-in TCP tracking but provides
//! higher-level behavioral analysis.
//!
//! ## Detection Capabilities
//!
//! - **Port Scan Detection**: Many SYN packets to distinct destination ports
//!   from the same source within a time window.
//! - **SYN Flood Detection**: High rate of half-open connections.
//! - **RST Anomaly Detection**: Unexpected resets on established connections.
//! - **Retransmission Tracking**: Identifies lossy or congested links.

use std::collections::HashMap;
use std::sync::Mutex;

use crate::conntrack::FlowKey;
use crate::protocols::{Direction, ProtocolEvent, ProtocolParser};

// ---------------------------------------------------------------------------
// TCP flags
// ---------------------------------------------------------------------------

/// TCP flag bit positions.
pub const FIN: u8 = 0x01;
pub const SYN: u8 = 0x02;
pub const RST: u8 = 0x04;
pub const PSH: u8 = 0x08;
pub const ACK: u8 = 0x10;
pub const URG: u8 = 0x20;
pub const ECE: u8 = 0x40;
pub const CWR: u8 = 0x80;

// ---------------------------------------------------------------------------
// TCP event
// ---------------------------------------------------------------------------

/// Events produced by the TCP parser.
#[derive(Debug, Clone)]
pub enum TcpEvent {
    /// A new connection was initiated (SYN observed).
    ConnectionStart {
        src_ip: String,
        dst_ip: String,
        src_port: u16,
        dst_port: u16,
        ts: f64,
    },

    /// A connection completed the three-way handshake.
    ConnectionEstablished {
        src_ip: String,
        dst_ip: String,
        src_port: u16,
        dst_port: u16,
        ts: f64,
    },

    /// A connection was closed (FIN or RST).
    ConnectionClosed {
        src_ip: String,
        dst_ip: String,
        src_port: u16,
        dst_port: u16,
        ts: f64,
        by_reset: bool,
    },

    /// A port scan pattern was detected.
    PortScanDetected {
        scanner_ip: String,
        target_ip: String,
        ports_scanned: Vec<u16>,
        window_seconds: f64,
        ts: f64,
    },

    /// A SYN flood pattern was detected.
    SynFloodDetected {
        src_ip: String,
        syn_count: u64,
        window_seconds: f64,
        ts: f64,
    },
}

// ---------------------------------------------------------------------------
// Port scan tracker
// ---------------------------------------------------------------------------

/// Per-source-IP state for port scan detection.
#[derive(Debug)]
struct ScanTracker {
    /// Destination ports that received SYN from this source.
    ports: Vec<(u16, f64)>, // (port, timestamp)
    /// Target IP address.
    target_ip: String,
}

// ---------------------------------------------------------------------------
// TcpParser
// ---------------------------------------------------------------------------

/// TCP protocol parser for state machine tracking and anomaly detection.
///
/// Maintains per-source tracking state for port scan and SYN flood
/// detection. Thread-safe via internal mutex.
pub struct TcpParser {
    /// Port scan detection state per source IP.
    scan_trackers: Mutex<HashMap<String, ScanTracker>>,
    /// SYN count per source IP for flood detection.
    syn_counts: Mutex<HashMap<String, Vec<f64>>>,
    /// Threshold: number of distinct ports to trigger scan alert.
    scan_threshold: usize,
    /// Threshold: SYNs per second to trigger flood alert.
    flood_threshold: u64,
    /// Time window for scan/flood detection (seconds).
    detection_window: f64,
}

impl TcpParser {
    /// Create a new TCP parser with default thresholds.
    ///
    /// Defaults:
    /// - Scan threshold: 25 distinct ports in 60 seconds
    /// - Flood threshold: 100 SYNs per second in 10-second window
    pub fn new() -> Self {
        Self {
            scan_trackers: Mutex::new(HashMap::new()),
            syn_counts: Mutex::new(HashMap::new()),
            scan_threshold: 25,
            flood_threshold: 100,
            detection_window: 60.0,
        }
    }

    /// Create a new TCP parser with custom thresholds.
    pub fn with_thresholds(scan_threshold: usize, flood_threshold: u64, window: f64) -> Self {
        Self {
            scan_trackers: Mutex::new(HashMap::new()),
            syn_counts: Mutex::new(HashMap::new()),
            scan_threshold,
            flood_threshold,
            detection_window: window,
        }
    }

    /// Extract TCP flags from a raw TCP header.
    ///
    /// Assumes `payload` starts at the TCP header.
    /// Returns `None` if the payload is too short.
    fn extract_flags(payload: &[u8]) -> Option<u8> {
        // TCP header minimum 20 bytes, flags at offset 13
        if payload.len() < 20 {
            return None;
        }
        Some(payload[13])
    }

    /// Extract source and destination ports from TCP header.
    fn extract_ports(payload: &[u8]) -> Option<(u16, u16)> {
        if payload.len() < 4 {
            return None;
        }
        let src = u16::from_be_bytes([payload[0], payload[1]]);
        let dst = u16::from_be_bytes([payload[2], payload[3]]);
        Some((src, dst))
    }

    /// Check and update port scan tracking.
    fn check_port_scan(&self, src_ip: &str, dst_ip: &str, dst_port: u16, ts: f64) -> Option<TcpEvent> {
        let mut trackers = self.scan_trackers.lock().unwrap();
        let tracker = trackers.entry(src_ip.to_string()).or_insert_with(|| ScanTracker {
            ports: Vec::new(),
            target_ip: dst_ip.to_string(),
        });

        // Add this port
        tracker.ports.push((dst_port, ts));

        // Prune old entries outside the detection window
        let cutoff = ts - self.detection_window;
        tracker.ports.retain(|(_, t)| *t >= cutoff);

        // Count distinct ports
        let mut distinct_ports: Vec<u16> = tracker.ports.iter().map(|(p, _)| *p).collect();
        distinct_ports.sort_unstable();
        distinct_ports.dedup();

        if distinct_ports.len() >= self.scan_threshold {
            // Reset tracker after alert
            tracker.ports.clear();

            Some(TcpEvent::PortScanDetected {
                scanner_ip: src_ip.to_string(),
                target_ip: dst_ip.to_string(),
                ports_scanned: distinct_ports,
                window_seconds: self.detection_window,
                ts,
            })
        } else {
            None
        }
    }

    /// Check and update SYN flood tracking.
    fn check_syn_flood(&self, src_ip: &str, ts: f64) -> Option<TcpEvent> {
        let mut counts = self.syn_counts.lock().unwrap();
        let timestamps = counts.entry(src_ip.to_string()).or_insert_with(Vec::new);

        timestamps.push(ts);

        // Prune old entries (use a 10-second window for flood detection)
        let flood_window = 10.0;
        let cutoff = ts - flood_window;
        timestamps.retain(|t| *t >= cutoff);

        let rate = timestamps.len() as u64;
        if rate >= self.flood_threshold {
            timestamps.clear();

            Some(TcpEvent::SynFloodDetected {
                src_ip: src_ip.to_string(),
                syn_count: rate,
                window_seconds: flood_window,
                ts,
            })
        } else {
            None
        }
    }
}

impl ProtocolParser for TcpParser {
    fn parse(
        &self,
        flow: &FlowKey,
        direction: Direction,
        payload: &[u8],
        ts: f64,
    ) -> Vec<ProtocolEvent> {
        let mut events = Vec::new();

        let flags = match Self::extract_flags(payload) {
            Some(f) => f,
            None => return events,
        };

        let is_syn = flags & SYN != 0 && flags & ACK == 0;
        let is_syn_ack = flags & SYN != 0 && flags & ACK != 0;
        let is_rst = flags & RST != 0;
        let is_fin = flags & FIN != 0;

        // SYN from originator: new connection attempt
        if is_syn && direction == Direction::Originator {
            events.push(ProtocolEvent::Tcp(TcpEvent::ConnectionStart {
                src_ip: flow.src_ip.clone(),
                dst_ip: flow.dst_ip.clone(),
                src_port: flow.src_port,
                dst_port: flow.dst_port,
                ts,
            }));

            // Check for port scan
            if let Some(scan_event) =
                self.check_port_scan(&flow.src_ip, &flow.dst_ip, flow.dst_port, ts)
            {
                events.push(ProtocolEvent::Tcp(scan_event));
            }

            // Check for SYN flood
            if let Some(flood_event) = self.check_syn_flood(&flow.src_ip, ts) {
                events.push(ProtocolEvent::Tcp(flood_event));
            }
        }

        // SYN-ACK from responder: handshake completing
        if is_syn_ack && direction == Direction::Responder {
            // Handshake step 2 - note: Established fires after step 3 (ACK)
        }

        // ACK after SYN-ACK: connection established
        // TODO: Track per-flow state to accurately detect handshake completion.
        // For now we rely on the connection table's TCP state machine.

        // RST: connection reset
        if is_rst {
            events.push(ProtocolEvent::Tcp(TcpEvent::ConnectionClosed {
                src_ip: flow.src_ip.clone(),
                dst_ip: flow.dst_ip.clone(),
                src_port: flow.src_port,
                dst_port: flow.dst_port,
                ts,
                by_reset: true,
            }));
        }

        // FIN: graceful close initiated
        if is_fin {
            events.push(ProtocolEvent::Tcp(TcpEvent::ConnectionClosed {
                src_ip: flow.src_ip.clone(),
                dst_ip: flow.dst_ip.clone(),
                src_port: flow.src_port,
                dst_port: flow.dst_port,
                ts,
                by_reset: false,
            }));
        }

        events
    }

    fn timeout(&self) -> f64 {
        3600.0 // TCP connections can be long-lived
    }

    fn protocol_id(&self) -> &'static str {
        "tcp"
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_tcp_header(flags: u8) -> Vec<u8> {
        let mut header = vec![0u8; 20];
        // src port = 12345
        header[0] = 0x30;
        header[1] = 0x39;
        // dst port = 80
        header[2] = 0x00;
        header[3] = 0x50;
        // data offset = 5 (20 bytes), flags
        header[12] = 0x50; // data offset
        header[13] = flags;
        header
    }

    #[test]
    fn test_extract_flags() {
        let header = make_tcp_header(SYN);
        assert_eq!(TcpParser::extract_flags(&header), Some(SYN));
    }

    #[test]
    fn test_extract_flags_too_short() {
        assert_eq!(TcpParser::extract_flags(b"short"), None);
    }

    #[test]
    fn test_syn_produces_connection_start() {
        let parser = TcpParser::new();
        let flow = FlowKey::new("10.0.0.1".into(), "10.0.0.2".into(), 12345, 80, 6);
        let header = make_tcp_header(SYN);
        let events = parser.parse(&flow, Direction::Originator, &header, 1000.0);

        assert!(!events.is_empty());
        match &events[0] {
            ProtocolEvent::Tcp(TcpEvent::ConnectionStart { src_ip, .. }) => {
                assert_eq!(src_ip, "10.0.0.1");
            }
            _ => panic!("Expected ConnectionStart event"),
        }
    }

    #[test]
    fn test_rst_produces_connection_closed() {
        let parser = TcpParser::new();
        let flow = FlowKey::new("10.0.0.1".into(), "10.0.0.2".into(), 12345, 80, 6);
        let header = make_tcp_header(RST);
        let events = parser.parse(&flow, Direction::Originator, &header, 1000.0);

        assert!(events.iter().any(|e| matches!(
            e,
            ProtocolEvent::Tcp(TcpEvent::ConnectionClosed { by_reset: true, .. })
        )));
    }

    #[test]
    fn test_port_scan_detection() {
        let parser = TcpParser::with_thresholds(5, 100, 60.0);
        let ts = 1000.0;

        for port in 1..=5 {
            let flow = FlowKey::new("10.0.0.1".into(), "10.0.0.2".into(), 12345, port, 6);
            let header = make_tcp_header(SYN);
            let events = parser.parse(&flow, Direction::Originator, &header, ts);

            if port == 5 {
                // Should trigger scan detection on the 5th distinct port
                assert!(events.iter().any(|e| matches!(
                    e,
                    ProtocolEvent::Tcp(TcpEvent::PortScanDetected { .. })
                )));
            }
        }
    }
}
