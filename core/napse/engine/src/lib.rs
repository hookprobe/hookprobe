//! # NAPSE Engine - Neural Adaptive Packet Synthesis Engine
//!
//! This is the Rust core of the NAPSE protocol engine for HookProbe.
//! It provides high-performance packet parsing, protocol analysis, connection
//! tracking, signature matching, and ML-based threat detection.
//!
//! ## Architecture
//!
//! The engine is structured into several subsystems:
//!
//! - **conntrack**: Connection tracking with Community-ID flow hashing
//! - **protocols**: Protocol-specific parsers (DNS, TCP, TLS, HTTP, DHCP, SSH, mDNS)
//! - **matcher**: Multi-pattern signature matching using Aho-Corasick
//! - **ml**: Machine learning classifiers (DGA detection with optional ONNX inference)
//!
//! ## Python Integration
//!
//! Exposed to Python via PyO3 as the `napse_engine` module. The primary entry
//! point is `NapseEngine`, which orchestrates all subsystems and provides a
//! unified interface for packet processing and event retrieval.
//!
//! ## License
//!
//! Proprietary - HookProbe Team

pub mod community_id;
pub mod conntrack;
pub mod matcher;
pub mod ml;
pub mod protocols;

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use pyo3::prelude::*;
use serde::{Deserialize, Serialize};

use conntrack::ConnectionTable;
use matcher::SignatureEngine;
use protocols::dns::DnsParser;
use protocols::ProtocolParser;

// ---------------------------------------------------------------------------
// Engine statistics
// ---------------------------------------------------------------------------

/// Cumulative counters for the engine.
#[derive(Debug, Default)]
struct EngineStats {
    packets_processed: AtomicU64,
    bytes_processed: AtomicU64,
    connections_tracked: AtomicU64,
    alerts_generated: AtomicU64,
    dns_queries: AtomicU64,
    tls_handshakes: AtomicU64,
    http_transactions: AtomicU64,
    dhcp_events: AtomicU64,
}

// ---------------------------------------------------------------------------
// Python-visible record types
// ---------------------------------------------------------------------------

/// A connection record compatible with Zeek conn.log fields.
#[pyclass]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionRecord {
    #[pyo3(get)]
    pub uid: String,
    #[pyo3(get)]
    pub community_id: String,
    #[pyo3(get)]
    pub src_ip: String,
    #[pyo3(get)]
    pub dst_ip: String,
    #[pyo3(get)]
    pub src_port: u16,
    #[pyo3(get)]
    pub dst_port: u16,
    #[pyo3(get)]
    pub proto: String,
    #[pyo3(get)]
    pub service: String,
    #[pyo3(get)]
    pub duration: f64,
    #[pyo3(get)]
    pub orig_bytes: u64,
    #[pyo3(get)]
    pub resp_bytes: u64,
    #[pyo3(get)]
    pub orig_pkts: u64,
    #[pyo3(get)]
    pub resp_pkts: u64,
    #[pyo3(get)]
    pub conn_state: String,
    #[pyo3(get)]
    pub ts: f64,
}

#[pymethods]
impl ConnectionRecord {
    fn __repr__(&self) -> String {
        format!(
            "ConnectionRecord(uid={}, {}:{} -> {}:{}, proto={}, service={})",
            self.uid, self.src_ip, self.src_port, self.dst_ip, self.dst_port, self.proto, self.service
        )
    }

    /// Serialize this record to a JSON string.
    fn to_json(&self) -> PyResult<String> {
        serde_json::to_string(self).map_err(|e| {
            pyo3::exceptions::PyValueError::new_err(format!("JSON serialization failed: {e}"))
        })
    }
}

/// A DNS log record compatible with Zeek dns.log fields.
#[pyclass]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DNSRecord {
    #[pyo3(get)]
    pub ts: f64,
    #[pyo3(get)]
    pub uid: String,
    #[pyo3(get)]
    pub src_ip: String,
    #[pyo3(get)]
    pub dst_ip: String,
    #[pyo3(get)]
    pub src_port: u16,
    #[pyo3(get)]
    pub dst_port: u16,
    #[pyo3(get)]
    pub proto: String,
    #[pyo3(get)]
    pub trans_id: u16,
    #[pyo3(get)]
    pub query: String,
    #[pyo3(get)]
    pub qtype: u16,
    #[pyo3(get)]
    pub qtype_name: String,
    #[pyo3(get)]
    pub rcode: u16,
    #[pyo3(get)]
    pub rcode_name: String,
    #[pyo3(get)]
    pub answers: Vec<String>,
    #[pyo3(get)]
    pub ttls: Vec<u32>,
    #[pyo3(get)]
    pub is_mdns: bool,
    #[pyo3(get)]
    pub ecosystem: String,
}

#[pymethods]
impl DNSRecord {
    fn __repr__(&self) -> String {
        format!(
            "DNSRecord(query={}, qtype={}, rcode={}, answers={:?})",
            self.query, self.qtype_name, self.rcode_name, self.answers
        )
    }

    fn to_json(&self) -> PyResult<String> {
        serde_json::to_string(self).map_err(|e| {
            pyo3::exceptions::PyValueError::new_err(format!("JSON serialization failed: {e}"))
        })
    }
}

/// An HTTP log record compatible with Zeek http.log fields.
#[pyclass]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HTTPRecord {
    #[pyo3(get)]
    pub ts: f64,
    #[pyo3(get)]
    pub uid: String,
    #[pyo3(get)]
    pub src_ip: String,
    #[pyo3(get)]
    pub dst_ip: String,
    #[pyo3(get)]
    pub src_port: u16,
    #[pyo3(get)]
    pub dst_port: u16,
    #[pyo3(get)]
    pub method: String,
    #[pyo3(get)]
    pub host: String,
    #[pyo3(get)]
    pub uri: String,
    #[pyo3(get)]
    pub user_agent: String,
    #[pyo3(get)]
    pub referer: String,
    #[pyo3(get)]
    pub status_code: u16,
    #[pyo3(get)]
    pub content_type: String,
    #[pyo3(get)]
    pub content_length: u64,
    #[pyo3(get)]
    pub request_body_len: u64,
    #[pyo3(get)]
    pub response_body_len: u64,
}

#[pymethods]
impl HTTPRecord {
    fn __repr__(&self) -> String {
        format!(
            "HTTPRecord({} {} -> {} status={})",
            self.method, self.uri, self.host, self.status_code
        )
    }

    fn to_json(&self) -> PyResult<String> {
        serde_json::to_string(self).map_err(|e| {
            pyo3::exceptions::PyValueError::new_err(format!("JSON serialization failed: {e}"))
        })
    }
}

/// A TLS log record compatible with Zeek ssl.log fields.
#[pyclass]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TLSRecord {
    #[pyo3(get)]
    pub ts: f64,
    #[pyo3(get)]
    pub uid: String,
    #[pyo3(get)]
    pub src_ip: String,
    #[pyo3(get)]
    pub dst_ip: String,
    #[pyo3(get)]
    pub src_port: u16,
    #[pyo3(get)]
    pub dst_port: u16,
    #[pyo3(get)]
    pub version: String,
    #[pyo3(get)]
    pub cipher: String,
    #[pyo3(get)]
    pub server_name: String,
    #[pyo3(get)]
    pub ja3: String,
    #[pyo3(get)]
    pub ja3s: String,
    #[pyo3(get)]
    pub subject: String,
    #[pyo3(get)]
    pub issuer: String,
    #[pyo3(get)]
    pub not_valid_before: f64,
    #[pyo3(get)]
    pub not_valid_after: f64,
    #[pyo3(get)]
    pub is_malicious_ja3: bool,
    #[pyo3(get)]
    pub malicious_ja3_tag: String,
}

#[pymethods]
impl TLSRecord {
    fn __repr__(&self) -> String {
        format!(
            "TLSRecord(sni={}, ja3={}, version={}, malicious={})",
            self.server_name, self.ja3, self.version, self.is_malicious_ja3
        )
    }

    fn to_json(&self) -> PyResult<String> {
        serde_json::to_string(self).map_err(|e| {
            pyo3::exceptions::PyValueError::new_err(format!("JSON serialization failed: {e}"))
        })
    }
}

/// A DHCP log record for device fingerprinting.
#[pyclass]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DHCPRecord {
    #[pyo3(get)]
    pub ts: f64,
    #[pyo3(get)]
    pub uid: String,
    #[pyo3(get)]
    pub client_mac: String,
    #[pyo3(get)]
    pub assigned_ip: String,
    #[pyo3(get)]
    pub hostname: String,
    #[pyo3(get)]
    pub vendor_class: String,
    #[pyo3(get)]
    pub param_request_list: Vec<u8>,
    #[pyo3(get)]
    pub message_type: String,
    #[pyo3(get)]
    pub lease_time: u32,
    #[pyo3(get)]
    pub server_ip: String,
    #[pyo3(get)]
    pub fingerprint: String,
}

#[pymethods]
impl DHCPRecord {
    fn __repr__(&self) -> String {
        format!(
            "DHCPRecord(mac={}, ip={}, hostname={}, type={})",
            self.client_mac, self.assigned_ip, self.hostname, self.message_type
        )
    }

    fn to_json(&self) -> PyResult<String> {
        serde_json::to_string(self).map_err(|e| {
            pyo3::exceptions::PyValueError::new_err(format!("JSON serialization failed: {e}"))
        })
    }
}

// ---------------------------------------------------------------------------
// Alert / Notice types
// ---------------------------------------------------------------------------

/// A security alert generated by the engine.
///
/// Alerts represent actionable security events that typically require
/// attention or automated response (e.g., signature match, brute-force
/// detection, malicious JA3).
#[pyclass]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NapseAlert {
    #[pyo3(get)]
    pub ts: f64,
    #[pyo3(get)]
    pub alert_id: String,
    #[pyo3(get)]
    pub severity: String,
    #[pyo3(get)]
    pub category: String,
    #[pyo3(get)]
    pub message: String,
    #[pyo3(get)]
    pub src_ip: String,
    #[pyo3(get)]
    pub dst_ip: String,
    #[pyo3(get)]
    pub src_port: u16,
    #[pyo3(get)]
    pub dst_port: u16,
    #[pyo3(get)]
    pub proto: String,
    #[pyo3(get)]
    pub community_id: String,
    #[pyo3(get)]
    pub signature_id: u32,
    #[pyo3(get)]
    pub confidence: f32,
    #[pyo3(get)]
    pub mitre_tactic: String,
    #[pyo3(get)]
    pub mitre_technique: String,
}

#[pymethods]
impl NapseAlert {
    fn __repr__(&self) -> String {
        format!(
            "NapseAlert(severity={}, category={}, msg={})",
            self.severity, self.category, self.message
        )
    }

    fn to_json(&self) -> PyResult<String> {
        serde_json::to_string(self).map_err(|e| {
            pyo3::exceptions::PyValueError::new_err(format!("JSON serialization failed: {e}"))
        })
    }
}

/// An informational notice generated by the engine.
///
/// Notices represent noteworthy but non-critical observations such as
/// new device discovery, protocol anomalies, or certificate expiration.
#[pyclass]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NapseNotice {
    #[pyo3(get)]
    pub ts: f64,
    #[pyo3(get)]
    pub notice_type: String,
    #[pyo3(get)]
    pub message: String,
    #[pyo3(get)]
    pub src_ip: String,
    #[pyo3(get)]
    pub dst_ip: String,
    #[pyo3(get)]
    pub community_id: String,
    #[pyo3(get)]
    pub metadata: String,
}

#[pymethods]
impl NapseNotice {
    fn __repr__(&self) -> String {
        format!(
            "NapseNotice(type={}, msg={})",
            self.notice_type, self.message
        )
    }

    fn to_json(&self) -> PyResult<String> {
        serde_json::to_string(self).map_err(|e| {
            pyo3::exceptions::PyValueError::new_err(format!("JSON serialization failed: {e}"))
        })
    }
}

// ---------------------------------------------------------------------------
// NapseEngine - the main orchestrator exposed to Python
// ---------------------------------------------------------------------------

/// The main NAPSE protocol engine.
///
/// Orchestrates connection tracking, protocol parsing, signature matching,
/// and ML-based classification. Designed to be instantiated once and driven
/// by a packet capture loop from Python.
///
/// # Example (Python)
///
/// ```python
/// from napse_engine import NapseEngine
///
/// engine = NapseEngine()
/// engine.start()
/// stats = engine.get_stats()
/// print(stats)
/// engine.stop()
/// ```
#[pyclass]
pub struct NapseEngine {
    running: Arc<AtomicBool>,
    stats: Arc<EngineStats>,
    conn_table: Arc<ConnectionTable>,
    sig_engine: Arc<SignatureEngine>,
    // TODO: Add protocol parser instances
    // TODO: Add ML classifier instances
    // TODO: Add event output channels (crossbeam)
}

#[pymethods]
impl NapseEngine {
    /// Create a new NAPSE engine instance.
    ///
    /// Initialises the connection table, signature engine, protocol parsers,
    /// and ML classifiers. Does **not** start processing; call `start()`
    /// after construction.
    #[new]
    fn new() -> PyResult<Self> {
        let conn_table = Arc::new(ConnectionTable::new());
        let sig_engine = Arc::new(SignatureEngine::new());

        Ok(Self {
            running: Arc::new(AtomicBool::new(false)),
            stats: Arc::new(EngineStats::default()),
            conn_table,
            sig_engine,
        })
    }

    /// Start the engine's background processing loops.
    ///
    /// Spawns threads for:
    /// - Connection table expiry (every 30 seconds)
    /// - Alert aggregation and deduplication
    ///
    /// Returns immediately; processing is asynchronous.
    fn start(&self) -> PyResult<()> {
        if self.running.swap(true, Ordering::SeqCst) {
            return Err(pyo3::exceptions::PyRuntimeError::new_err(
                "Engine is already running",
            ));
        }

        // TODO: Spawn connection expiry thread
        // TODO: Spawn alert aggregation thread
        // TODO: Initialize protocol parsers
        tracing::info!("NAPSE engine started");
        Ok(())
    }

    /// Stop the engine and flush all pending events.
    ///
    /// Blocks until background threads have terminated and the connection
    /// table has been flushed to log records.
    fn stop(&self) -> PyResult<()> {
        if !self.running.swap(false, Ordering::SeqCst) {
            return Err(pyo3::exceptions::PyRuntimeError::new_err(
                "Engine is not running",
            ));
        }

        // TODO: Signal background threads to stop
        // TODO: Flush remaining connection records
        tracing::info!("NAPSE engine stopped");
        Ok(())
    }

    /// Return a dictionary of engine statistics.
    ///
    /// Keys: packets_processed, bytes_processed, connections_tracked,
    /// alerts_generated, dns_queries, tls_handshakes, http_transactions,
    /// dhcp_events.
    fn get_stats(&self) -> PyResult<std::collections::HashMap<String, u64>> {
        let mut map = std::collections::HashMap::new();
        map.insert(
            "packets_processed".into(),
            self.stats.packets_processed.load(Ordering::Relaxed),
        );
        map.insert(
            "bytes_processed".into(),
            self.stats.bytes_processed.load(Ordering::Relaxed),
        );
        map.insert(
            "connections_tracked".into(),
            self.stats.connections_tracked.load(Ordering::Relaxed),
        );
        map.insert(
            "alerts_generated".into(),
            self.stats.alerts_generated.load(Ordering::Relaxed),
        );
        map.insert(
            "dns_queries".into(),
            self.stats.dns_queries.load(Ordering::Relaxed),
        );
        map.insert(
            "tls_handshakes".into(),
            self.stats.tls_handshakes.load(Ordering::Relaxed),
        );
        map.insert(
            "http_transactions".into(),
            self.stats.http_transactions.load(Ordering::Relaxed),
        );
        map.insert(
            "dhcp_events".into(),
            self.stats.dhcp_events.load(Ordering::Relaxed),
        );
        Ok(map)
    }

    /// Process a single raw packet.
    ///
    /// # Arguments
    /// * `data` - Raw packet bytes (starting from IP header)
    /// * `ts` - Packet timestamp as Unix epoch float
    ///
    /// # Returns
    /// Number of events generated from this packet.
    fn process_packet(&self, _data: &[u8], _ts: f64) -> PyResult<u64> {
        // TODO: Decode IP header
        // TODO: Update connection table
        // TODO: Route to appropriate protocol parser
        // TODO: Run signature matching on payload
        // TODO: Emit events via crossbeam channel
        self.stats
            .packets_processed
            .fetch_add(1, Ordering::Relaxed);
        Ok(0)
    }

    /// Drain all pending connection records.
    fn drain_connection_records(&self) -> PyResult<Vec<ConnectionRecord>> {
        // TODO: Drain from the event channel
        Ok(Vec::new())
    }

    /// Drain all pending DNS records.
    fn drain_dns_records(&self) -> PyResult<Vec<DNSRecord>> {
        // TODO: Drain from the event channel
        Ok(Vec::new())
    }

    /// Drain all pending HTTP records.
    fn drain_http_records(&self) -> PyResult<Vec<HTTPRecord>> {
        // TODO: Drain from the event channel
        Ok(Vec::new())
    }

    /// Drain all pending TLS records.
    fn drain_tls_records(&self) -> PyResult<Vec<TLSRecord>> {
        // TODO: Drain from the event channel
        Ok(Vec::new())
    }

    /// Drain all pending DHCP records.
    fn drain_dhcp_records(&self) -> PyResult<Vec<DHCPRecord>> {
        // TODO: Drain from the event channel
        Ok(Vec::new())
    }

    /// Drain all pending alerts.
    fn drain_alerts(&self) -> PyResult<Vec<NapseAlert>> {
        // TODO: Drain from the alert channel
        Ok(Vec::new())
    }

    /// Drain all pending notices.
    fn drain_notices(&self) -> PyResult<Vec<NapseNotice>> {
        // TODO: Drain from the notice channel
        Ok(Vec::new())
    }

    /// Load signatures from a JSON file.
    ///
    /// # Arguments
    /// * `path` - Path to JSON signature file
    fn load_signatures(&self, path: &str) -> PyResult<usize> {
        self.sig_engine.load_signatures(path).map_err(|e| {
            pyo3::exceptions::PyIOError::new_err(format!("Failed to load signatures: {e}"))
        })
    }
}

// ---------------------------------------------------------------------------
// PyO3 module definition
// ---------------------------------------------------------------------------

/// NAPSE Engine - Neural Adaptive Packet Synthesis Engine
///
/// The Rust core of the NAPSE protocol engine for HookProbe. Provides
/// high-performance packet parsing, connection tracking, protocol analysis,
/// signature matching, and ML-based threat classification.
///
/// Classes:
///     NapseEngine: Main engine orchestrator
///     ConnectionRecord: Zeek-compatible conn.log record
///     DNSRecord: Zeek-compatible dns.log record
///     HTTPRecord: Zeek-compatible http.log record
///     TLSRecord: Zeek-compatible ssl.log record
///     DHCPRecord: DHCP event record for device fingerprinting
///     NapseAlert: Security alert
///     NapseNotice: Informational notice
#[pymodule]
fn napse_engine(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<NapseEngine>()?;
    m.add_class::<ConnectionRecord>()?;
    m.add_class::<DNSRecord>()?;
    m.add_class::<HTTPRecord>()?;
    m.add_class::<TLSRecord>()?;
    m.add_class::<DHCPRecord>()?;
    m.add_class::<NapseAlert>()?;
    m.add_class::<NapseNotice>()?;

    // Module-level metadata
    m.add("__version__", "1.0.0")?;
    m.add("__author__", "HookProbe Team")?;

    Ok(())
}
