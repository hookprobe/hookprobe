//! # Connection Tracking
//!
//! High-performance connection tracking table using lock-free concurrent
//! hashmaps ([`DashMap`]). Tracks bidirectional flows, maintains TCP state,
//! detects application-layer protocols, and computes Community-ID v1 hashes.
//!
//! ## Design
//!
//! - Flows are identified by a [`FlowKey`] (5-tuple: src/dst IP, src/dst port, protocol).
//! - Each [`Connection`] tracks bytes, packets, duration, TCP state, and app protocol.
//! - Expired flows are periodically reaped and converted to [`ConnectionRecord`] events.
//! - Community-ID is computed once at flow creation for cross-tool correlation.

use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use dashmap::DashMap;
use serde::{Deserialize, Serialize};

use crate::community_id::compute_community_id;
use crate::ConnectionRecord;

// ---------------------------------------------------------------------------
// Flow Key
// ---------------------------------------------------------------------------

/// A 5-tuple identifying a network flow.
///
/// For TCP/UDP this is (src_ip, dst_ip, src_port, dst_port, proto).
/// For ICMP the ports represent type and code.
#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlowKey {
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    /// IP protocol number (6=TCP, 17=UDP, 1=ICMP, etc.)
    pub proto: u8,
}

impl FlowKey {
    /// Create a new FlowKey.
    pub fn new(src_ip: String, dst_ip: String, src_port: u16, dst_port: u16, proto: u8) -> Self {
        Self {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            proto,
        }
    }

    /// Return the canonical (bidirectional) key so that both directions
    /// of a flow map to the same entry.
    pub fn canonical(&self) -> Self {
        if (&self.src_ip, self.src_port) <= (&self.dst_ip, self.dst_port) {
            self.clone()
        } else {
            Self {
                src_ip: self.dst_ip.clone(),
                dst_ip: self.src_ip.clone(),
                src_port: self.dst_port,
                dst_port: self.src_port,
                proto: self.proto,
            }
        }
    }

    /// True if this key's source matches the canonical source (i.e. the
    /// packet is from the originator).
    pub fn is_originator(&self) -> bool {
        let canon = self.canonical();
        self.src_ip == canon.src_ip && self.src_port == canon.src_port
    }
}

impl fmt::Display for FlowKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let proto_name = match self.proto {
            1 => "icmp",
            6 => "tcp",
            17 => "udp",
            _ => "other",
        };
        write!(
            f,
            "{}:{} -> {}:{} ({})",
            self.src_ip, self.src_port, self.dst_ip, self.dst_port, proto_name
        )
    }
}

// ---------------------------------------------------------------------------
// TCP State Machine
// ---------------------------------------------------------------------------

/// TCP connection state, following RFC 793 state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TcpState {
    /// Waiting for a connection request (server-side initial state).
    Listen,
    /// Sent SYN, awaiting SYN-ACK.
    SynSent,
    /// Received SYN, sent SYN-ACK, awaiting ACK.
    SynReceived,
    /// Connection is open and data may flow.
    Established,
    /// Sent FIN, awaiting ACK of FIN.
    FinWait1,
    /// Received ACK of FIN, awaiting peer FIN.
    FinWait2,
    /// Received FIN, sent ACK, awaiting application close.
    CloseWait,
    /// Both sides have sent FIN, awaiting final ACK.
    Closing,
    /// Received FIN after sending FIN, awaiting ACK.
    LastAck,
    /// Waiting for enough time to pass to be sure remote received ACK.
    TimeWait,
    /// Connection is fully closed.
    Closed,
}

impl TcpState {
    /// Return the Napse native connection state string.
    pub fn to_conn_state(&self, saw_orig: bool, saw_resp: bool) -> &'static str {
        match self {
            TcpState::Established => "SF",
            TcpState::SynSent if !saw_resp => "S0",
            TcpState::SynReceived => "S1",
            TcpState::FinWait1 | TcpState::FinWait2 | TcpState::Closing => "S2",
            TcpState::CloseWait | TcpState::LastAck => "S3",
            TcpState::Closed | TcpState::TimeWait => "SF",
            _ if !saw_orig && !saw_resp => "OTH",
            _ => "OTH",
        }
    }
}

impl Default for TcpState {
    fn default() -> Self {
        TcpState::Listen
    }
}

impl fmt::Display for TcpState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            TcpState::Listen => "LISTEN",
            TcpState::SynSent => "SYN_SENT",
            TcpState::SynReceived => "SYN_RECEIVED",
            TcpState::Established => "ESTABLISHED",
            TcpState::FinWait1 => "FIN_WAIT_1",
            TcpState::FinWait2 => "FIN_WAIT_2",
            TcpState::CloseWait => "CLOSE_WAIT",
            TcpState::Closing => "CLOSING",
            TcpState::LastAck => "LAST_ACK",
            TcpState::TimeWait => "TIME_WAIT",
            TcpState::Closed => "CLOSED",
        };
        write!(f, "{s}")
    }
}

// ---------------------------------------------------------------------------
// Application Protocol
// ---------------------------------------------------------------------------

/// Detected application-layer protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AppProtocol {
    Unknown,
    DNS,
    HTTP,
    HTTPS,
    TLS,
    SSH,
    DHCP,
    SMTP,
    FTP,
    SMB,
    MQTT,
    Modbus,
    DNP3,
    QUIC,
    RDP,
    MDNS,
    SSDP,
    NTP,
}

impl AppProtocol {
    /// Guess the application protocol from well-known port numbers.
    ///
    /// This is a heuristic; actual protocol identification should be done
    /// by the protocol parsers after inspecting payload.
    pub fn from_port(port: u16) -> Self {
        match port {
            22 => AppProtocol::SSH,
            25 | 465 | 587 => AppProtocol::SMTP,
            53 => AppProtocol::DNS,
            67 | 68 => AppProtocol::DHCP,
            80 | 8080 | 8000 => AppProtocol::HTTP,
            123 => AppProtocol::NTP,
            443 | 8443 => AppProtocol::HTTPS,
            445 => AppProtocol::SMB,
            1883 | 8883 => AppProtocol::MQTT,
            3389 => AppProtocol::RDP,
            5353 => AppProtocol::MDNS,
            1900 => AppProtocol::SSDP,
            502 => AppProtocol::Modbus,
            20000 => AppProtocol::DNP3,
            21 | 20 => AppProtocol::FTP,
            _ => AppProtocol::Unknown,
        }
    }

    /// Return the Napse native service name string.
    pub fn as_service_str(&self) -> &'static str {
        match self {
            AppProtocol::Unknown => "-",
            AppProtocol::DNS => "dns",
            AppProtocol::HTTP => "http",
            AppProtocol::HTTPS => "ssl",
            AppProtocol::TLS => "ssl",
            AppProtocol::SSH => "ssh",
            AppProtocol::DHCP => "dhcp",
            AppProtocol::SMTP => "smtp",
            AppProtocol::FTP => "ftp",
            AppProtocol::SMB => "smb",
            AppProtocol::MQTT => "mqtt",
            AppProtocol::Modbus => "modbus",
            AppProtocol::DNP3 => "dnp3",
            AppProtocol::QUIC => "quic",
            AppProtocol::RDP => "rdp",
            AppProtocol::MDNS => "dns",
            AppProtocol::SSDP => "ssdp",
            AppProtocol::NTP => "ntp",
        }
    }
}

impl Default for AppProtocol {
    fn default() -> Self {
        AppProtocol::Unknown
    }
}

impl fmt::Display for AppProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_service_str())
    }
}

// ---------------------------------------------------------------------------
// Connection
// ---------------------------------------------------------------------------

/// A tracked network connection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Connection {
    /// The 5-tuple key (canonical form).
    pub key: FlowKey,
    /// Community-ID v1 hash for cross-tool correlation.
    pub community_id: String,
    /// Unique connection identifier.
    pub uid: String,
    /// TCP state (only meaningful for TCP flows).
    pub state: TcpState,
    /// Detected application-layer protocol.
    pub protocol: AppProtocol,
    /// Connection start timestamp (Unix epoch seconds).
    pub start_ts: f64,
    /// Last packet timestamp.
    pub last_ts: f64,
    /// Total bytes sent by originator.
    pub orig_bytes: u64,
    /// Total bytes sent by responder.
    pub resp_bytes: u64,
    /// Packets sent by originator.
    pub orig_pkts: u64,
    /// Packets sent by responder.
    pub resp_pkts: u64,
    /// Whether we have seen originator traffic.
    pub saw_orig: bool,
    /// Whether we have seen responder traffic.
    pub saw_resp: bool,
    /// Whether this connection has been exported as a log record.
    pub exported: bool,
}

impl Connection {
    /// Create a new connection from a flow key and timestamp.
    pub fn new(key: FlowKey, ts: f64) -> Self {
        let community_id = compute_community_id(
            &key.src_ip,
            &key.dst_ip,
            key.src_port,
            key.dst_port,
            key.proto,
            0,
        );

        let uid = generate_uid();

        let protocol = AppProtocol::from_port(key.dst_port)
            .max_by_relevance(AppProtocol::from_port(key.src_port));

        Self {
            key,
            community_id,
            uid,
            state: TcpState::Listen,
            protocol,
            start_ts: ts,
            last_ts: ts,
            orig_bytes: 0,
            resp_bytes: 0,
            orig_pkts: 0,
            resp_pkts: 0,
            saw_orig: false,
            saw_resp: false,
            exported: false,
        }
    }

    /// Duration of the connection in seconds.
    pub fn duration(&self) -> f64 {
        self.last_ts - self.start_ts
    }

    /// Convert to a Python-visible [`ConnectionRecord`].
    pub fn to_record(&self) -> ConnectionRecord {
        let proto_str = match self.key.proto {
            1 => "icmp",
            6 => "tcp",
            17 => "udp",
            _ => "other",
        };

        ConnectionRecord {
            uid: self.uid.clone(),
            community_id: self.community_id.clone(),
            src_ip: self.key.src_ip.clone(),
            dst_ip: self.key.dst_ip.clone(),
            src_port: self.key.src_port,
            dst_port: self.key.dst_port,
            proto: proto_str.to_string(),
            service: self.protocol.as_service_str().to_string(),
            duration: self.duration(),
            orig_bytes: self.orig_bytes,
            resp_bytes: self.resp_bytes,
            orig_pkts: self.orig_pkts,
            resp_pkts: self.resp_pkts,
            conn_state: self
                .state
                .to_conn_state(self.saw_orig, self.saw_resp)
                .to_string(),
            ts: self.start_ts,
        }
    }
}

impl AppProtocol {
    /// Return the more specific of two protocol guesses.
    fn max_by_relevance(self, other: Self) -> Self {
        if self != AppProtocol::Unknown {
            self
        } else {
            other
        }
    }
}

// ---------------------------------------------------------------------------
// Connection Table
// ---------------------------------------------------------------------------

/// Concurrent connection tracking table.
///
/// Uses [`DashMap`] for lock-free concurrent access from multiple threads.
/// Flows are keyed by their canonical [`FlowKey`].
pub struct ConnectionTable {
    /// Active connections indexed by canonical flow key.
    connections: DashMap<FlowKey, Connection>,
    /// Default flow timeout in seconds.
    timeout_secs: f64,
    /// TCP-specific established timeout in seconds.
    tcp_established_timeout_secs: f64,
    /// TCP-specific half-open timeout in seconds.
    tcp_half_open_timeout_secs: f64,
}

impl ConnectionTable {
    /// Create a new connection table with default timeouts.
    ///
    /// Default timeouts:
    /// - General: 300 seconds (5 minutes)
    /// - TCP established: 3600 seconds (1 hour)
    /// - TCP half-open: 30 seconds
    pub fn new() -> Self {
        Self {
            connections: DashMap::new(),
            timeout_secs: 300.0,
            tcp_established_timeout_secs: 3600.0,
            tcp_half_open_timeout_secs: 30.0,
        }
    }

    /// Create a new connection table with custom timeouts.
    pub fn with_timeouts(general: f64, tcp_established: f64, tcp_half_open: f64) -> Self {
        Self {
            connections: DashMap::new(),
            timeout_secs: general,
            tcp_established_timeout_secs: tcp_established,
            tcp_half_open_timeout_secs: tcp_half_open,
        }
    }

    /// Insert or retrieve a connection for the given flow key.
    ///
    /// If the flow already exists, returns a reference to it.
    /// If not, creates a new [`Connection`] and inserts it.
    pub fn insert(&self, key: FlowKey, ts: f64) -> Connection {
        let canonical = key.canonical();
        self.connections
            .entry(canonical.clone())
            .or_insert_with(|| Connection::new(canonical, ts))
            .clone()
    }

    /// Look up an existing connection by flow key.
    ///
    /// Returns `None` if the flow is not tracked.
    pub fn lookup(&self, key: &FlowKey) -> Option<Connection> {
        let canonical = key.canonical();
        self.connections.get(&canonical).map(|c| c.clone())
    }

    /// Update flow counters for a packet.
    ///
    /// # Arguments
    /// * `key` - The (non-canonical) flow key from the packet
    /// * `payload_len` - Payload byte count
    /// * `ts` - Packet timestamp
    /// * `tcp_flags` - TCP flags byte (0 for non-TCP)
    pub fn update_flow(&self, key: &FlowKey, payload_len: u64, ts: f64, tcp_flags: u8) {
        let canonical = key.canonical();
        let is_orig = key.is_originator();

        if let Some(mut conn) = self.connections.get_mut(&canonical) {
            conn.last_ts = ts;

            if is_orig {
                conn.orig_bytes += payload_len;
                conn.orig_pkts += 1;
                conn.saw_orig = true;
            } else {
                conn.resp_bytes += payload_len;
                conn.resp_pkts += 1;
                conn.saw_resp = true;
            }

            // Update TCP state machine if this is a TCP flow
            if canonical.proto == 6 {
                update_tcp_state(&mut conn, tcp_flags, is_orig);
            }
        }
    }

    /// Expire connections that have been idle beyond their timeout.
    ///
    /// Returns the expired connections as [`ConnectionRecord`] values
    /// for logging. Removes them from the table.
    pub fn expire_flows(&self, now: f64) -> Vec<ConnectionRecord> {
        let mut expired = Vec::new();

        self.connections.retain(|_key, conn| {
            let idle = now - conn.last_ts;
            let timeout = self.timeout_for(conn);

            if idle > timeout {
                expired.push(conn.to_record());
                false // remove
            } else {
                true // keep
            }
        });

        expired
    }

    /// Convert all active connections to log records without removing them.
    ///
    /// Useful for periodic snapshots or shutdown flushing.
    pub fn to_log_records(&self) -> Vec<ConnectionRecord> {
        self.connections
            .iter()
            .map(|entry| entry.value().to_record())
            .collect()
    }

    /// Return the number of active connections.
    pub fn len(&self) -> usize {
        self.connections.len()
    }

    /// Return true if the table is empty.
    pub fn is_empty(&self) -> bool {
        self.connections.is_empty()
    }

    /// Determine the appropriate timeout for a connection.
    fn timeout_for(&self, conn: &Connection) -> f64 {
        if conn.key.proto == 6 {
            match conn.state {
                TcpState::Established => self.tcp_established_timeout_secs,
                TcpState::Listen | TcpState::SynSent | TcpState::SynReceived => {
                    self.tcp_half_open_timeout_secs
                }
                TcpState::Closed | TcpState::TimeWait => 10.0, // Quick cleanup
                _ => self.timeout_secs,
            }
        } else {
            self.timeout_secs
        }
    }
}

impl Default for ConnectionTable {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// TCP state machine transitions
// ---------------------------------------------------------------------------

/// TCP flag bit masks.
const TCP_FIN: u8 = 0x01;
const TCP_SYN: u8 = 0x02;
const TCP_RST: u8 = 0x04;
const TCP_ACK: u8 = 0x10;

/// Update TCP state based on observed flags.
fn update_tcp_state(conn: &mut Connection, flags: u8, is_orig: bool) {
    let has_syn = flags & TCP_SYN != 0;
    let has_ack = flags & TCP_ACK != 0;
    let has_fin = flags & TCP_FIN != 0;
    let has_rst = flags & TCP_RST != 0;

    // RST from either side -> Closed
    if has_rst {
        conn.state = TcpState::Closed;
        return;
    }

    conn.state = match conn.state {
        TcpState::Listen if has_syn && is_orig => TcpState::SynSent,
        TcpState::SynSent if has_syn && has_ack && !is_orig => TcpState::SynReceived,
        TcpState::SynReceived if has_ack && is_orig => TcpState::Established,
        TcpState::Established if has_fin && is_orig => TcpState::FinWait1,
        TcpState::Established if has_fin && !is_orig => TcpState::CloseWait,
        TcpState::FinWait1 if has_ack && !is_orig => TcpState::FinWait2,
        TcpState::FinWait1 if has_fin && !is_orig => TcpState::Closing,
        TcpState::FinWait2 if has_fin && !is_orig => TcpState::TimeWait,
        TcpState::CloseWait if has_fin && is_orig => TcpState::LastAck,
        TcpState::Closing if has_ack => TcpState::TimeWait,
        TcpState::LastAck if has_ack => TcpState::Closed,
        TcpState::TimeWait => TcpState::Closed, // Simplified: skip TIME_WAIT timer
        other => other,
    };
}

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------

/// Generate a unique connection identifier.
///
/// Uses a combination of timestamp and atomic counter for uniqueness.
/// Format uses a Napse-native UID style.
fn generate_uid() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    let count = COUNTER.fetch_add(1, Ordering::Relaxed);
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_micros() as u64;

    // Produce a compact alphanumeric UID
    format!("C{:x}{:04x}", ts & 0xFFFF_FFFF, count & 0xFFFF)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_flow_key_canonical() {
        let k1 = FlowKey::new("10.0.0.1".into(), "192.168.1.1".into(), 80, 12345, 6);
        let k2 = FlowKey::new("192.168.1.1".into(), "10.0.0.1".into(), 12345, 80, 6);
        assert_eq!(k1.canonical(), k2.canonical());
    }

    #[test]
    fn test_connection_table_insert_lookup() {
        let table = ConnectionTable::new();
        let key = FlowKey::new("10.0.0.1".into(), "10.0.0.2".into(), 1234, 80, 6);
        table.insert(key.clone(), 1000.0);
        assert!(table.lookup(&key).is_some());
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn test_connection_table_update_flow() {
        let table = ConnectionTable::new();
        let key = FlowKey::new("10.0.0.1".into(), "10.0.0.2".into(), 1234, 80, 6);
        table.insert(key.clone(), 1000.0);

        table.update_flow(&key, 100, 1001.0, TCP_SYN);
        let conn = table.lookup(&key).unwrap();
        assert_eq!(conn.orig_pkts, 1);
        assert_eq!(conn.orig_bytes, 100);
    }

    #[test]
    fn test_expire_flows() {
        let table = ConnectionTable::with_timeouts(10.0, 60.0, 5.0);
        let key = FlowKey::new("10.0.0.1".into(), "10.0.0.2".into(), 1234, 80, 17);
        table.insert(key.clone(), 1000.0);

        // Not expired yet
        let expired = table.expire_flows(1005.0);
        assert!(expired.is_empty());
        assert_eq!(table.len(), 1);

        // Now expired
        let expired = table.expire_flows(1015.0);
        assert_eq!(expired.len(), 1);
        assert!(table.is_empty());
    }

    #[test]
    fn test_tcp_state_transitions() {
        let table = ConnectionTable::new();
        let key = FlowKey::new("10.0.0.1".into(), "10.0.0.2".into(), 1234, 80, 6);
        table.insert(key.clone(), 1000.0);

        // SYN from originator
        table.update_flow(&key, 0, 1000.0, TCP_SYN);
        assert_eq!(table.lookup(&key).unwrap().state, TcpState::SynSent);

        // SYN-ACK from responder
        let resp_key = FlowKey::new("10.0.0.2".into(), "10.0.0.1".into(), 80, 1234, 6);
        table.update_flow(&resp_key, 0, 1000.1, TCP_SYN | TCP_ACK);
        assert_eq!(table.lookup(&key).unwrap().state, TcpState::SynReceived);

        // ACK from originator
        table.update_flow(&key, 0, 1000.2, TCP_ACK);
        assert_eq!(table.lookup(&key).unwrap().state, TcpState::Established);
    }

    #[test]
    fn test_app_protocol_from_port() {
        assert_eq!(AppProtocol::from_port(53), AppProtocol::DNS);
        assert_eq!(AppProtocol::from_port(443), AppProtocol::HTTPS);
        assert_eq!(AppProtocol::from_port(22), AppProtocol::SSH);
        assert_eq!(AppProtocol::from_port(5353), AppProtocol::MDNS);
        assert_eq!(AppProtocol::from_port(9999), AppProtocol::Unknown);
    }

    #[test]
    fn test_generate_uid() {
        let uid1 = generate_uid();
        let uid2 = generate_uid();
        assert!(uid1.starts_with('C'));
        assert_ne!(uid1, uid2);
    }
}
