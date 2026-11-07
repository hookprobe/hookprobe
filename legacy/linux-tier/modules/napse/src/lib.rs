//! # NAPSE — Detection-Synthesis Engine (Wasm component)
//!
//! Pure-Rust port of the **synthesis/intelligence** half of V1
//! `core/napse/` (Python). The XDP/eBPF capture layer is a separate sysext
//! (port #5 — not this crate).
//!
//! ## What V1 NAPSE synthesis does (and what this ports)
//!
//! | V1 component | File | V2 port |
//! |---|---|---|
//! | `EntityGraph` + `EntityNode` | `intelligence/entity_graph.py` | `EntityState` per-IP |
//! | `IntentDecoder` (HMM/Viterbi) | `intelligence/intent_decoder.py` | `viterbi_step()` |
//! | `BayesianScorer` (belief+decay) | `intelligence/bayesian_scorer.py` | `bayes_update()` |
//! | `napse_rules.yaml` signatures | `signatures/napse_rules.yaml` | `run_signatures()` |
//! | `GraphEmbedder` (2-layer GNN) | `intelligence/graph_embedder.py` | `TODO(wasi-nn)` stub |
//! | `SIAEngine` (orchestrator) | `intelligence/sia_engine.py` | `NapseSynthesizer` |
//! | `PacketInspector` heuristics | `inspector/packet_inspector.py` | folded into signatures |
//!
//! ## ML upgrade path
//!
//! The GNN deviation computation (`GraphEmbedder.compute_deviation`) is stubbed
//! with `EntityState::heuristic_deviation()`. To enable the full V1 pipeline:
//!
//! ```ignore
//! // TODO(wasi-nn): load V1's 2-layer GNN (16→32→64 dims) exported to ONNX.
//! // Feature vector layout (must match EntityNode.get_feature_vector()):
//! //   [n_dst_ports, n_dst_ips, n_protocols, n_services, byte_ratio,
//! //    dns_queries, failed_conns, alert_count, event_rate, port_entropy,
//! //    mb_sent, mb_recv, has_alerts, port_scan_indicator, conn_rate, hours_active]
//! //
//! // use wasi_nn::{GraphBuilder, GraphEncoding, ExecutionTarget};
//! // let graph = GraphBuilder::new(GraphEncoding::Onnx, ExecutionTarget::CPU)
//! //     .build_from_files(["/var/lib/hookprobe/models/napse-embedder.onnx"])
//! //     .expect("load GNN model");
//! // let ctx = graph.init_execution_context().expect("init ctx");
//! // ctx.set_input(0, wasi_nn::TensorType::F32, &[1, 16], &feat_f32)?;
//! // ctx.compute()?;
//! // let mut emb = vec![0f32; 64];
//! // ctx.get_output(0, &mut emb)?;
//! // // cosine_distance(emb, golden_harmonic) → deviation in [0,1]
//! ```
//!
//! Until then, `heuristic_deviation()` uses port_entropy + connection_rate
//! + alert_count signals, which is sufficient to drive the HMM into attack
//! states for real scans/brute-force but will miss subtle low-and-slow campaigns.

#![forbid(unsafe_code)]

use std::collections::{HashMap, HashSet, VecDeque};

pub mod tabular;
pub use tabular::{gated_deviation, p_attack_for_qsecbit, SeedLogisticScorer, TabularScorer};

// ─── Constants (faithfully ported from V1 source files) ───────────────────────

/// Severity levels — match V1 `napse_rules.yaml` `severity` field.
/// Lower = more critical (1=CRITICAL matches Suricata convention).
pub const SEV_CRITICAL: u8 = 1;
pub const SEV_HIGH: u8 = 2;
pub const SEV_MEDIUM: u8 = 3;
pub const SEV_LOW: u8 = 4;
pub const SEV_INFO: u8 = 5;

/// Sandbox trigger threshold.
/// Source: V1 `intelligence/bayesian_scorer.py` `SANDBOX_THRESHOLD = 0.92`.
pub const SANDBOX_THRESHOLD: f64 = 0.92;

/// Evidence decay half-life in seconds.
/// Source: V1 `EVIDENCE_DECAY_HALFLIFE = 300.0` (5 minutes).
pub const EVIDENCE_DECAY_HALFLIFE: f64 = 300.0;

/// 2026-07-07 fix for rule 1000025 (see `run_signatures`' doc comment for the full "dead rule"
/// analysis this replaces): sustained outbound byte volume, summed over the SAME 300s sliding
/// window every other rule in this engine uses, from an internal source toward EXTERNAL
/// destinations, above which a bulk-transfer exfiltration alert fires. 50 MB / 300s ≈ 1.33 Mbps
/// sustained upload — comfortably above ordinary browsing/chat/telemetry traffic, while still
/// catching a genuine bulk transfer (a single large upload, or many medium ones accumulating)
/// well before it completes. A tunable heuristic, not a hard boundary — see the rule's FP-guard
/// doc for what it deliberately does and does not catch.
pub const EXFIL_VOLUME_THRESHOLD_BYTES: u64 = 50_000_000;

/// Default Bayesian prior P(Attack).
/// Source: V1 `BayesianScorer.__init__(default_prior=0.1)`.
pub const DEFAULT_PRIOR: f64 = 0.1;

/// Number of HMM hidden states (BENIGN + 8 MITRE kill-chain phases).
/// Source: V1 `intelligence/intent_decoder.py` `NUM_STATES = len(IntentPhase)`.
pub const NUM_STATES: usize = 9;

/// Known malicious JA3 client fingerprint hashes.
/// Source: V1 `signatures/napse_rules.yaml` rule 1000004.
pub const MALICIOUS_JA3: &[&str] = &[
    "72a589da586844d7f0818ce684948eea", // CobaltStrike
    "a0e9f5d64349fb13191bc781f81f42e1", // CobaltStrike 4.x
    "3b5074b1b5d032e5620f69f9f700ff0e", // Metasploit
    "fc54e0d16d9764783542f0146a98b300", // Metasploit HTTPS
    "315b27e8b4d08f3ba6534dc84f0d9c2c", // Empire
];
// DELIBERATE division of JA4 detection (roadmap-B audit GAP-5): there is intentionally NO
// hardcoded `MALICIOUS_JA4` here. The modern JA4/JA4S surface is matched by HYDRA against its
// threat-intel feed (crates/hookprobe-hydra + the bundled seed's ja4/ja4s canaries; live C2 JA4s
// arrive via modules/hydra/hydra-feed-fetch.sh) — that is the correct home for feed-driven,
// operator-updatable fingerprint IOCs. This tiny hand-curated JA3 list stays as a legacy offensive-
// tool FAST-PATH only. A `MALICIOUS_JA4` fast-path could be added, but ONLY from VERIFIED public
// values (e.g. ja4db.com) — JA4 fingerprints must never be fabricated to look like a known tool.

/// Suspicious low-quality TLDs associated with free/abuse-prone registrars.
/// Source: V1 `signatures/napse_rules.yaml` rule 1000021.
pub const SUSPICIOUS_TLDS: &[&str] = &[
    ".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".xyz",
];

/// SQL injection indicator patterns (case-insensitive match against URI/body).
/// Source: V1 `signatures/napse_rules.yaml` rule 1000007.
pub const SQL_INJECTION_PATTERNS: &[&str] = &[
    "union select",
    "' or '1'='1",
    "; drop ",
    "benchmark(",
    "sleep(",
    "waitfor delay",
    "information_schema",
];

/// XSS indicator patterns (case-insensitive).
/// Source: V1 `signatures/napse_rules.yaml` rule 1000008.
pub const XSS_PATTERNS: &[&str] = &[
    "<script",
    "javascript:",
    "onerror=",
    "onload=",
    "document.cookie",
    "eval(",
];

/// Path traversal indicator patterns (case-insensitive).
/// Source: V1 `signatures/napse_rules.yaml` rule 1000010.
pub const PATH_TRAVERSAL_PATTERNS: &[&str] = &[
    "../..",
    "..\\.\\",
    "/etc/passwd",
    "/etc/shadow",
    "c:\\windows",
    "%2e%2e",
];

/// Cryptocurrency mining indicator patterns.
/// Source: V1 `signatures/napse_rules.yaml` rule 1000005.
pub const CRYPTO_MINING_PATTERNS: &[&str] = &[
    "stratum+tcp",
    "mining.subscribe",
    "mining.authorize",
    "eth_submitwork",
];

/// C2 beacon content indicator patterns.
/// Source: V1 `signatures/napse_rules.yaml` rule 1000004.
pub const C2_BEACON_PATTERNS: &[&str] = &["cobalt", "beacon", "meterpreter", "empire"];

// ─── HMM — MITRE ATT&CK kill-chain hidden states ─────────────────────────────

/// MITRE tactic IDs indexed by IntentPhase value.
/// Source: V1 `intelligence/intent_decoder.py` `IntentPhase.mitre_tactic`.
pub const MITRE_TACTICS: [&str; NUM_STATES] = [
    "none",   // BENIGN
    "TA0043", // Reconnaissance
    "TA0001", // Initial Access
    "TA0002", // Execution
    "TA0003", // Persistence
    "TA0008", // Lateral Movement
    "TA0009", // Collection
    "TA0010", // Exfiltration
    "TA0040", // Impact
];

/// HMM transition matrix A[i][j] = P(state_j | state_i). Rows sum to 1.0.
/// Source: V1 `intelligence/intent_decoder.py` `DEFAULT_TRANSITION_MATRIX`.
pub const HMM_TRANSITION: [[f64; NUM_STATES]; NUM_STATES] = [
    // BENIGN — mostly stays benign, small chance of recon
    [0.90, 0.08, 0.01, 0.005, 0.001, 0.001, 0.001, 0.001, 0.001],
    // RECONNAISSANCE — initial access or stays recon
    [0.10, 0.50, 0.25, 0.05, 0.03, 0.03, 0.02, 0.01, 0.01],
    // INITIAL_ACCESS — execution or persistence
    [0.05, 0.05, 0.30, 0.30, 0.15, 0.05, 0.05, 0.03, 0.02],
    // EXECUTION — persistence or lateral
    [0.03, 0.02, 0.05, 0.30, 0.25, 0.20, 0.08, 0.05, 0.02],
    // PERSISTENCE — lateral or collection
    [0.02, 0.01, 0.02, 0.05, 0.30, 0.30, 0.15, 0.10, 0.05],
    // LATERAL_MOVEMENT — collection or more lateral
    [0.02, 0.01, 0.02, 0.05, 0.05, 0.30, 0.30, 0.15, 0.10],
    // COLLECTION — exfiltration
    [0.02, 0.01, 0.01, 0.02, 0.02, 0.02, 0.30, 0.40, 0.20],
    // EXFILTRATION — impact or done
    [0.10, 0.01, 0.01, 0.01, 0.01, 0.01, 0.05, 0.40, 0.40],
    // IMPACT — stays or returns to benign
    [0.20, 0.01, 0.01, 0.01, 0.01, 0.01, 0.01, 0.04, 0.70],
];

/// HMM initial state probabilities.
/// Source: V1 `intelligence/intent_decoder.py` `DEFAULT_INITIAL_PROBS`.
pub const HMM_INITIAL: [f64; NUM_STATES] = [
    0.85,  // BENIGN
    0.08,  // RECONNAISSANCE
    0.02,  // INITIAL_ACCESS
    0.01,  // EXECUTION
    0.01,  // PERSISTENCE
    0.01,  // LATERAL_MOVEMENT
    0.01,  // COLLECTION
    0.005, // EXFILTRATION
    0.005, // IMPACT
];

/// Bayesian likelihood ratios P(E|Attack)/P(E|Benign) per phase.
/// Source: V1 `intelligence/bayesian_scorer.py` `PHASE_LIKELIHOOD_RATIOS`.
pub const PHASE_LIKELIHOOD_RATIOS: [f64; NUM_STATES] = [
    0.1,  // BENIGN     — evidence of benign behaviour lowers attack probability
    3.0,  // RECON
    8.0,  // INITIAL_ACCESS
    15.0, // EXECUTION
    12.0, // PERSISTENCE
    20.0, // LATERAL_MOVEMENT
    10.0, // COLLECTION
    25.0, // EXFILTRATION
    30.0, // IMPACT
];

/// Emission profiles per HMM state: [(port_entropy_mean, std), (conn_rate_mean, std), (alerts_mean, std)].
/// Source: V1 `intelligence/intent_decoder.py` `STATE_EMISSION_PROFILES`.
const EMISSION_PROFILES: [([f64; 2], [f64; 2], [f64; 2]); NUM_STATES] = [
    ([1.0, 0.5], [0.01, 0.01], [0.0, 0.1]),  // BENIGN
    ([4.0, 1.0], [0.5, 0.3], [0.0, 0.2]),    // RECONNAISSANCE
    ([2.0, 1.0], [0.1, 0.1], [1.0, 0.5]),    // INITIAL_ACCESS
    ([1.5, 0.8], [0.2, 0.2], [2.0, 1.0]),    // EXECUTION
    ([1.0, 0.5], [0.05, 0.05], [0.5, 0.5]),  // PERSISTENCE
    ([3.0, 1.0], [0.3, 0.2], [1.5, 1.0]),    // LATERAL_MOVEMENT
    ([1.5, 0.8], [0.1, 0.1], [0.5, 0.5]),    // COLLECTION
    ([1.0, 0.5], [0.2, 0.2], [1.0, 0.8]),    // EXFILTRATION
    ([2.0, 1.5], [1.0, 0.5], [3.0, 1.0]),    // IMPACT
];

// ─── Intent Phase ─────────────────────────────────────────────────────────────

/// MITRE ATT&CK kill-chain attack phase, mapped from HMM hidden state index.
/// Source: V1 `intelligence/intent_decoder.py` `IntentPhase`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntentPhase {
    Benign = 0,
    Reconnaissance = 1,
    InitialAccess = 2,
    Execution = 3,
    Persistence = 4,
    LateralMovement = 5,
    Collection = 6,
    Exfiltration = 7,
    Impact = 8,
}

impl IntentPhase {
    pub fn as_str(self) -> &'static str {
        match self {
            IntentPhase::Benign => "BENIGN",
            IntentPhase::Reconnaissance => "RECONNAISSANCE",
            IntentPhase::InitialAccess => "INITIAL_ACCESS",
            IntentPhase::Execution => "EXECUTION",
            IntentPhase::Persistence => "PERSISTENCE",
            IntentPhase::LateralMovement => "LATERAL_MOVEMENT",
            IntentPhase::Collection => "COLLECTION",
            IntentPhase::Exfiltration => "EXFILTRATION",
            IntentPhase::Impact => "IMPACT",
        }
    }

    pub fn mitre_tactic(self) -> &'static str {
        MITRE_TACTICS[self as usize]
    }

    pub fn from_index(i: usize) -> Self {
        match i {
            1 => IntentPhase::Reconnaissance,
            2 => IntentPhase::InitialAccess,
            3 => IntentPhase::Execution,
            4 => IntentPhase::Persistence,
            5 => IntentPhase::LateralMovement,
            6 => IntentPhase::Collection,
            7 => IntentPhase::Exfiltration,
            8 => IntentPhase::Impact,
            _ => IntentPhase::Benign,
        }
    }

    pub fn is_attack(self) -> bool {
        self != IntentPhase::Benign
    }
}

// ─── Normalized flow/event record ─────────────────────────────────────────────

/// Normalized flow or event record consumed from `/var/lib/hookprobe/flows`.
///
/// The capture sysext (napse-capture, V1 Zig/C XDP + C eBPF) writes these
/// records after normalizing raw packets to the common event schema. This
/// synthesis module consumes them via stdin (WASI redirect of the flows pipe).
///
/// Schema mirrors V1 `synthesis/event_bus.py`: `ConnectionRecord`, `DNSRecord`,
/// `TLSRecord`, `HTTPRecord`, `NapseAlert`.
#[derive(Debug, Clone, Default)]
pub struct FlowRecord {
    /// Record type: "conn" | "dns" | "tls" | "http" | "alert"
    pub record_type: String,
    /// Unix timestamp (seconds)
    pub ts: f64,
    /// Connection UID (Zeek-style or community-ID)
    pub uid: String,
    /// Source IP address
    pub src_ip: String,
    /// Source port
    pub src_port: u16,
    /// Destination IP address
    pub dst_ip: String,
    /// Destination port
    pub dst_port: u16,
    /// Protocol: "tcp" | "udp" | "icmp"
    pub proto: String,
    /// Detected service (e.g. "ssh", "dns", "http", "tls")
    pub service: String,
    /// Bytes originator→responder
    pub orig_bytes: u64,
    /// Bytes responder→originator
    pub resp_bytes: u64,
    /// Packets originator→responder
    pub orig_pkts: u32,
    /// Packets responder→originator
    pub resp_pkts: u32,
    /// Zeek-style connection state: "SF" | "S0" | "REJ" | "RSTO" | "RSTOS0"
    pub conn_state: String,

    // ── DNS enrichment (record_type == "dns") ─────────────────────────────────
    /// Fully qualified DNS query name
    pub query: Option<String>,
    /// Length of the query name (characters); precomputed by capture layer
    pub query_len: Option<u32>,
    /// Shannon entropy of DNS query name labels [0, 8]; precomputed
    pub query_entropy: Option<f64>,

    // ── TLS enrichment (record_type == "tls") ─────────────────────────────────
    /// JA3 client fingerprint hash (hex string)
    pub ja3: Option<String>,
    /// TLS version string e.g. "TLSv1.0", "SSLv3", "TLSv1.3"
    pub tls_version: Option<String>,
    /// TLS SNI (server_name) — the requested host of an encrypted connection.
    pub tls_sni: Option<String>,

    // ── HTTP enrichment (record_type == "http") ───────────────────────────────
    /// HTTP request URI
    pub uri: Option<String>,
    /// HTTP method
    pub method: Option<String>,

    // ── Payload features (any record type) ────────────────────────────────────
    /// Shannon entropy of the payload [0, 8]; precomputed by capture layer
    pub payload_entropy: Option<f64>,

    // ── Alert enrichment (record_type == "alert") ─────────────────────────────
    /// Alert severity from an upstream IDS (1=CRITICAL … 5=INFO)
    pub alert_severity: Option<u8>,
    /// Upstream alert signature name
    pub alert_signature: Option<String>,
}

impl FlowRecord {
    /// Convenience constructor for a minimal connection record (tests + main.rs).
    pub fn new_conn(
        ts: f64,
        src_ip: &str,
        src_port: u16,
        dst_ip: &str,
        dst_port: u16,
        proto: &str,
        conn_state: &str,
        orig_bytes: u64,
        resp_bytes: u64,
    ) -> Self {
        Self {
            record_type: "conn".to_string(),
            ts,
            src_ip: src_ip.to_string(),
            src_port,
            dst_ip: dst_ip.to_string(),
            dst_port,
            proto: proto.to_string(),
            conn_state: conn_state.to_string(),
            orig_bytes,
            resp_bytes,
            ..Default::default()
        }
    }
}

// ─── Alert output ─────────────────────────────────────────────────────────────

/// NAPSE alert verdict emitted when a threat is detected.
///
/// Mirrors V1 `synthesis/event_bus.py` `NapseAlert` with V2 additions
/// (intent_phase, risk_score).
#[derive(Debug, Clone)]
pub struct NapseAlert {
    /// Unix timestamp of the triggering event
    pub ts: f64,
    pub src_ip: String,
    pub src_port: u16,
    pub dst_ip: String,
    pub dst_port: u16,
    pub proto: String,
    /// 1=CRITICAL, 2=HIGH, 3=MEDIUM, 4=LOW, 5=INFO (Suricata convention)
    pub severity: u8,
    /// Rule ID from napse_rules.yaml
    pub rule_id: u32,
    /// Human-readable rule message
    pub rule_msg: String,
    /// MITRE ATT&CK technique ID (e.g. "T1046")
    pub mitre: String,
    /// Alert category (e.g. "port_scan", "brute_force")
    pub category: String,
    /// Detection confidence [0, 1]
    pub confidence: f64,
    /// HMM intent phase for this source entity
    pub intent_phase: String,
    /// Bayesian risk score for this source entity [0, 1]
    pub risk_score: f64,
    /// "alert" | "drop" (drop only in inline IPS mode)
    pub alert_action: String,
    /// Tabular-ML attack probability for the triggering entity (roadmap C /
    /// `tabular::p_attack_for_qsecbit`), in `[0.0, 1.0]`. Always `0.0` when `ml_cpu` isn't
    /// granted — the same "scoped, not global" contract `dga_lm::p_attack_for_qsecbit`
    /// uses. Downstream (`base/scripts/telemetry-export.sh`) reads this field out of the
    /// most recent alert line in `/var/lib/hookprobe/events` to populate QSECBIT's
    /// optional 5th CSV field — see that script's own doc comment for the exact,
    /// honestly-documented merge policy.
    pub p_attack: f64,
}

impl NapseAlert {
    /// Serialize to a single JSON line without external dependencies.
    pub fn to_json(&self) -> String {
        format!(
            concat!(
                r#"{{"ts":{ts:.3},"src_ip":"{src}","src_port":{sp},"#,
                r#""dst_ip":"{dst}","dst_port":{dp},"proto":"{proto}","#,
                r#""severity":{sev},"rule_id":{rid},"rule_msg":"{msg}","#,
                r#""mitre":"{mitre}","category":"{cat}","confidence":{conf:.4},"#,
                r#""intent_phase":"{phase}","risk_score":{risk:.4},"#,
                r#""alert_action":"{action}","p_attack":{patk:.4}}}"#,
            ),
            ts = self.ts,
            src = self.src_ip,
            sp = self.src_port,
            dst = self.dst_ip,
            dp = self.dst_port,
            proto = self.proto,
            sev = self.severity,
            rid = self.rule_id,
            msg = self.rule_msg.replace('"', "'"),
            mitre = self.mitre,
            cat = self.category,
            conf = self.confidence,
            phase = self.intent_phase,
            risk = self.risk_score,
            action = self.alert_action,
            patk = self.p_attack,
        )
    }
}

// ─── Per-entity behavioral state ─────────────────────────────────────────────

/// Per-entity behavioral state tracked across events.
///
/// Flattens V1's three separate objects — `EntityNode` (entity_graph.py),
/// Viterbi state (intent_decoder.py), and `EntityBelief` (bayesian_scorer.py)
/// — into one struct to avoid HashMap indirection inside the Wasm instance.
#[derive(Debug)]
pub struct EntityState {
    pub entity_id: String,

    // ── Graph feature accumulators (V1 EntityNode) ────────────────────────────
    pub unique_dest_ports: HashSet<u16>,
    pub unique_dest_ips: HashSet<String>,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub dns_query_count: u32,
    pub failed_conn_count: u32,
    pub alert_count: u32,
    pub event_count: u32,
    pub first_seen: f64,
    pub last_seen: f64,

    // ── Sliding-window signature counters ─────────────────────────────────────
    /// Timestamps of TCP connection attempts to port 22; window 300 s.
    /// Rule 1000001 fires when len ≥ 5.
    pub ssh_attempt_ts: VecDeque<f64>,
    /// Timestamps of DNS queries; window 300 s.
    /// Rule 1000002 fires when len > 100.
    pub dns_query_ts: VecDeque<f64>,
    /// (timestamp, dst_port) of each connection attempt; window 300 s.
    /// Rule 1000003 fires when unique ports ≥ 50.
    pub port_scan_entries: VecDeque<(f64, u16)>,
    /// (timestamp, orig_bytes) of each record whose ORIGINATOR is this (private/internal) entity
    /// and whose destination is EXTERNAL (`!is_private_ip`); window 300 s. 2026-07-07 fix for rule
    /// 1000025 — see `run_signatures`' doc comment for why the original entropy+bytes gate was
    /// dead and this windowed-byte-volume signal replaces it with something genuinely computable
    /// from conntrack-derived fields. Rule 1000025 fires when the windowed sum exceeds
    /// [`EXFIL_VOLUME_THRESHOLD_BYTES`].
    pub exfil_bytes_window: VecDeque<(f64, u64)>,

    // ── HMM Viterbi state (V1 IntentDecoder) ─────────────────────────────────
    /// Log-space Viterbi probabilities for each of the 9 hidden states.
    pub hmm_log_probs: [f64; NUM_STATES],
    /// Ring buffer of decoded phase indices (capped at 100).
    pub hmm_phase_history: VecDeque<u8>,
    /// False until the first Viterbi step initialises hmm_log_probs.
    pub hmm_initialized: bool,

    // ── Bayesian belief state (V1 BayesianScorer) ─────────────────────────────
    pub bayes_prior: f64,
    pub bayes_posterior: f64,
    /// Evidence ring: (timestamp_secs, likelihood_ratio); capped at 100.
    pub bayes_evidence: VecDeque<(f64, f64)>,
    /// Set when posterior first crosses SANDBOX_THRESHOLD.
    pub sandbox_triggered: bool,
}

impl EntityState {
    pub fn new(entity_id: &str, ts: f64) -> Self {
        Self {
            entity_id: entity_id.to_string(),
            unique_dest_ports: HashSet::new(),
            unique_dest_ips: HashSet::new(),
            bytes_sent: 0,
            bytes_received: 0,
            dns_query_count: 0,
            failed_conn_count: 0,
            alert_count: 0,
            event_count: 0,
            first_seen: ts,
            last_seen: ts,
            ssh_attempt_ts: VecDeque::new(),
            dns_query_ts: VecDeque::new(),
            port_scan_entries: VecDeque::new(),
            exfil_bytes_window: VecDeque::new(),
            hmm_log_probs: [0.0; NUM_STATES],
            hmm_phase_history: VecDeque::new(),
            hmm_initialized: false,
            bayes_prior: DEFAULT_PRIOR,
            bayes_posterior: DEFAULT_PRIOR,
            bayes_evidence: VecDeque::new(),
            sandbox_triggered: false,
        }
    }

    /// Port entropy = log₂(unique_dest_ports).
    /// Mirrors V1 `EntityNode.port_entropy`.
    pub fn port_entropy(&self) -> f64 {
        let n = self.unique_dest_ports.len();
        if n <= 1 {
            0.0
        } else {
            (n as f64).log2()
        }
    }

    /// Events per second of active time.
    /// Mirrors V1 `EntityNode.connection_rate`.
    pub fn connection_rate(&self) -> f64 {
        let duration = (self.last_seen - self.first_seen).max(1.0);
        self.event_count as f64 / duration
    }

    /// 16-element feature vector matching `EntityNode.get_feature_vector()`.
    ///
    /// Index layout (must match V1 for correct HMM emission computation):
    /// ```text
    ///  0  n_unique_dst_ports
    ///  1  n_unique_dst_ips
    ///  2  n_unique_protocols  (simplified: always 1.0)
    ///  3  n_unique_services   (simplified: always 1.0)
    ///  4  bytes_sent / bytes_received ratio
    ///  5  dns_query_count
    ///  6  failed_conn_count
    ///  7  alert_count            ← used by HMM emission profiles
    ///  8  event_rate (events/s)
    ///  9  port_entropy           ← used by HMM emission profiles
    /// 10  MB sent (capped at 1 GB)
    /// 11  MB received (capped at 1 GB)
    /// 12  has_alerts (0.0 or 1.0)
    /// 13  port_scan_indicator = n_unique_dst_ports / 100 (capped at 1.0)
    /// 14  connection_rate        ← used by HMM emission profiles
    /// 15  hours_active
    /// ```
    pub fn feature_vector(&self) -> [f64; 16] {
        let duration = (self.last_seen - self.first_seen).max(1.0);
        [
            self.unique_dest_ports.len() as f64,
            self.unique_dest_ips.len() as f64,
            1.0,
            1.0,
            self.bytes_sent as f64 / (self.bytes_received as f64 + 1.0),
            self.dns_query_count as f64,
            self.failed_conn_count as f64,
            self.alert_count as f64,
            self.event_count as f64 / duration,
            self.port_entropy(),
            self.bytes_sent.min(1_000_000_000) as f64 / 1_000_000.0,
            self.bytes_received.min(1_000_000_000) as f64 / 1_000_000.0,
            if self.alert_count > 0 { 1.0 } else { 0.0 },
            (self.unique_dest_ports.len().min(100) as f64) / 100.0,
            self.connection_rate(),
            duration / 3600.0,
        ]
    }

    /// Heuristic deviation from "normal" behaviour [0, 1].
    ///
    /// **TODO(wasi-nn):** replace with the GNN-based cosine distance from the
    /// Golden Harmonic (V1 `GraphEmbedder.compute_deviation()`). Once the
    /// `napse-embedder.onnx` model is available (16→32→64 dim GNN), load it
    /// via WASI-NN and compute:
    /// ```ignore
    /// // deviation = (1 - cosine_similarity(embed(entity), golden_harmonic)) / 2
    /// ```
    ///
    /// This stub combines three readily available signals:
    /// - **port entropy** — wide port spread indicates scanning
    /// - **connection rate** — high rate indicates automated tool
    /// - **alert count** — any upstream alert elevates risk
    pub fn heuristic_deviation(&self) -> f64 {
        let entropy_signal = (self.port_entropy() / 10.0).min(1.0);
        let rate_signal = (self.connection_rate() / 10.0).min(1.0);
        let alert_signal = (self.alert_count as f64 / 5.0).min(1.0);
        (0.4 * entropy_signal + 0.3 * rate_signal + 0.3 * alert_signal).min(1.0)
    }

    /// Tabular-ML attack probability over this entity's live 16-D `feature_vector()`
    /// (roadmap C — closes the audit's GAP-1/GAP-3: `tabular::TabularScorer` is the
    /// generic model seam, [`tabular::SeedLogisticScorer`] the real seed implementation).
    ///
    /// This is a PURE score — no capability gating here (mirrors `dga_lm::Scorer::score`,
    /// which is likewise ungated; gating happens one layer up, in
    /// [`tabular::gated_deviation`] / [`tabular::p_attack_for_qsecbit`]).
    pub fn tabular_p_attack(&self, scorer: &dyn TabularScorer) -> f64 {
        scorer.score(&self.feature_vector())
    }

    /// Expire sliding-window entries older than `window_s` seconds before `now`.
    pub fn expire_windows(&mut self, now: f64, window_s: f64) {
        let cutoff = now - window_s;
        while self.ssh_attempt_ts.front().copied().map_or(false, |t| t < cutoff) {
            self.ssh_attempt_ts.pop_front();
        }
        while self.dns_query_ts.front().copied().map_or(false, |t| t < cutoff) {
            self.dns_query_ts.pop_front();
        }
        while self
            .port_scan_entries
            .front()
            .map_or(false, |&(t, _)| t < cutoff)
        {
            self.port_scan_entries.pop_front();
        }
        while self
            .exfil_bytes_window
            .front()
            .is_some_and(|&(t, _)| t < cutoff)
        {
            self.exfil_bytes_window.pop_front();
        }
    }
}

// ─── HMM / Viterbi helpers ────────────────────────────────────────────────────

/// Log-Gaussian emission probability log P(x | N(mean, std)).
///
/// Mirrors V1 `intelligence/intent_decoder.py` `_log_gaussian(x, mean, std)`.
fn log_gaussian(x: f64, mean: f64, std: f64) -> f64 {
    let std = std.max(1e-12);
    -0.5 * (2.0 * std::f64::consts::PI * std * std).ln()
        - 0.5 * ((x - mean) / std).powi(2)
}

/// Log-space emission probabilities for each HMM state given entity features.
///
/// Mirrors V1 `IntentDecoder._compute_emissions(features, deviation)`.
/// Uses indices 7 (alert_count), 9 (port_entropy), 14 (connection_rate) from
/// the 16-dim feature vector — identical to V1.
pub fn compute_emissions(features: &[f64; 16], deviation: f64) -> [f64; NUM_STATES] {
    let port_entropy = features[9];
    let conn_rate = features[14];
    let alerts = features[7];
    let mut emissions = [0.0f64; NUM_STATES];
    for s in 0..NUM_STATES {
        let (pe, cr, al) = &EMISSION_PROFILES[s];
        let mut log_p = 0.0;
        log_p += log_gaussian(port_entropy, pe[0], pe[1]);
        log_p += log_gaussian(conn_rate, cr[0], cr[1]);
        log_p += log_gaussian(alerts, al[0], al[1]);
        // Deviation bonus mirrors V1:
        //   attack states (s > 0) benefit from high deviation
        //   benign state (s == 0) benefits from low deviation
        if s > 0 && deviation > 0.0 {
            log_p += deviation.max(1e-30).ln() * 2.0;
        } else if s == 0 && deviation < 0.3 {
            log_p += (1.0 - deviation).max(1e-30).ln();
        }
        emissions[s] = log_p;
    }
    emissions
}

/// Run one Viterbi forward step, updating `entity.hmm_log_probs` and appending
/// the decoded phase to `entity.hmm_phase_history`.
///
/// Mirrors V1 `IntentDecoder.observe()` Viterbi forward step.
pub fn viterbi_step(entity: &mut EntityState, features: &[f64; 16], deviation: f64) {
    let emissions = compute_emissions(features, deviation);
    if !entity.hmm_initialized {
        for s in 0..NUM_STATES {
            entity.hmm_log_probs[s] = HMM_INITIAL[s].max(1e-30).ln() + emissions[s];
        }
        entity.hmm_initialized = true;
    } else {
        let prev = entity.hmm_log_probs;
        for j in 0..NUM_STATES {
            let best = (0..NUM_STATES)
                .map(|i| prev[i] + HMM_TRANSITION[i][j].max(1e-30).ln())
                .fold(f64::NEG_INFINITY, f64::max);
            entity.hmm_log_probs[j] = best + emissions[j];
        }
    }
    let best = (0..NUM_STATES)
        .max_by(|&a, &b| {
            entity.hmm_log_probs[a]
                .partial_cmp(&entity.hmm_log_probs[b])
                .unwrap()
        })
        .unwrap_or(0);
    entity.hmm_phase_history.push_back(best as u8);
    if entity.hmm_phase_history.len() > 100 {
        entity.hmm_phase_history.pop_front();
    }
}

/// Softmax confidence of the best HMM state.
///
/// Mirrors V1 `IntentDecoder._compute_confidence(log_probs, best_state)`.
pub fn hmm_confidence(log_probs: &[f64; NUM_STATES], best: usize) -> f64 {
    let max_lp = log_probs
        .iter()
        .cloned()
        .fold(f64::NEG_INFINITY, f64::max);
    let exps: Vec<f64> = log_probs
        .iter()
        .map(|&lp| ((lp - max_lp).min(50.0)).exp())
        .collect();
    let total: f64 = exps.iter().sum();
    if total < 1e-30 {
        return 0.0;
    }
    exps[best] / total
}

/// Current decoded intent phase from the entity's phase history.
pub fn current_phase(entity: &EntityState) -> IntentPhase {
    entity
        .hmm_phase_history
        .back()
        .map(|&s| IntentPhase::from_index(s as usize))
        .unwrap_or(IntentPhase::Benign)
}

// ─── Bayesian scorer ──────────────────────────────────────────────────────────

/// Sequential Bayesian update with exponential evidence decay.
///
/// Mirrors V1 `BayesianScorer.update_belief()` + `_compute_posterior()`.
///
/// P(A|E) = P(E|A)·P(A) / [P(E|A)·P(A) + P(E|¬A)·P(¬A)]
/// where each evidence record's likelihood ratio is weighted by:
///   weight = exp(-0.693 · age_s / EVIDENCE_DECAY_HALFLIFE)
pub fn bayes_update(entity: &mut EntityState, phase: IntentPhase, confidence: f64, now: f64) {
    // likelihood ratio = 1 + (base_lr - 1) × confidence  (V1 formula)
    let base_lr = PHASE_LIKELIHOOD_RATIOS[phase as usize];
    let lr = 1.0 + (base_lr - 1.0) * confidence;

    entity.bayes_evidence.push_back((now, lr));
    if entity.bayes_evidence.len() > 100 {
        entity.bayes_evidence.pop_front();
    }

    // Recompute posterior from all decayed evidence (mirrors V1 _compute_posterior)
    let mut posterior = entity.bayes_prior;
    for &(ev_ts, ev_lr) in &entity.bayes_evidence {
        let age = now - ev_ts;
        let weight = (-0.693 * age / EVIDENCE_DECAY_HALFLIFE).exp();
        if weight < 0.01 {
            continue; // negligible — mirrors V1 "if weight < 0.01: continue"
        }
        let weighted_lr = 1.0 + (ev_lr - 1.0) * weight;
        let numerator = posterior * weighted_lr;
        let denominator = posterior * weighted_lr + (1.0 - posterior);
        if denominator > 1e-30 {
            posterior = numerator / denominator;
        }
        posterior = posterior.clamp(0.001, 0.999);
    }

    entity.bayes_posterior = posterior;
    if posterior >= SANDBOX_THRESHOLD && !entity.sandbox_triggered {
        entity.sandbox_triggered = true;
    }
}

// ─── Signature engine ─────────────────────────────────────────────────────────

/// Case-insensitive substring match against any pattern in `patterns`.
/// Mirrors V1 `napse_rules.yaml` `match_mode: "any"` / `case_insensitive: true`.
fn pattern_match_any(content: &str, patterns: &[&str]) -> bool {
    let lower = content.to_lowercase();
    patterns.iter().any(|p| lower.contains(*p))
}

/// Normalize a URI for pattern matching.
///
/// Replaces `+` (form-encoded space) and `%20` (percent-encoded space) with a
/// literal space so signature patterns like "union select" fire on
/// "union+select" and "union%20select" as they would in a real HTTP request.
/// Mirrors the URL-decoding step any reverse-proxy or WAF applies before matching.
fn normalize_uri(uri: &str) -> String {
    uri.replace('+', " ").replace("%20", " ").replace("%2B", "+")
}

/// Check if an IPv4 dotted-decimal string is in RFC-1918 private space.
/// Mirrors V1 `inspector/packet_inspector.py` `is_private_ip()`.
pub fn is_private_ip(ip: &str) -> bool {
    let parts: Vec<u8> = ip
        .split('.')
        .filter_map(|s| s.parse().ok())
        .collect();
    if parts.len() != 4 {
        return false;
    }
    match parts[0] {
        10 | 127 => true,
        172 => (16..=31).contains(&parts[1]),
        192 => parts[1] == 168,
        _ => false,
    }
}

/// Run all signature rules against a flow record and current entity state.
///
/// Returns the highest-priority alert (CRITICAL > HIGH > MEDIUM) that fires,
/// or `None` when the record is benign according to all rules.
///
/// **Rule catalogue** (faithfully ported from `signatures/napse_rules.yaml`):
/// | Rule ID | Name | Detection type | MITRE |
/// |---|---|---|---|
/// | 1000001 | SSH Brute Force | threshold 5/300s to port 22 | T1110 |
/// | 1000002 | DNS Tunneling | entropy>3.5 AND len>60; OR volume>100/300s | T1071.004 |
/// | 1000003 | Port Scan | ≥50 unique dst ports in 300s | T1046 |
/// | 1000004 | C2 Beacon | JA3 match OR content pattern | T1071.001 |
/// | 1000005 | Crypto Mining | content pattern | T1496 |
/// | 1000007 | SQL Injection | content pattern in URI | T1190 |
/// | 1000008 | XSS | content pattern in URI | T1059.007 |
/// | 1000009 | TLS Downgrade | blocked TLS versions | T1557.002 |
/// | 1000010 | Path Traversal | content pattern in URI | T1083 |
/// | 1000011 | DNS Non-Standard Port | dst_port ∉ {53,853,5353} | T1071.004 |
/// | 1000021 | Suspicious DNS TLD | suspicious TLD + (long OR high-entropy query) | T1071.004 |
/// | 1000025 | Bulk Outbound Exfil | orig_bytes to external dst, summed over 300s, > 50MB | T1048 |
pub fn run_signatures(record: &FlowRecord, entity: &EntityState, now: f64) -> Option<NapseAlert> {
    let phase_str = current_phase(entity).as_str().to_string();
    let risk_score = entity.bayes_posterior;

    let alert = |rule_id: u32, msg: &str, cat: &str, sev: u8, mitre: &str, conf: f64| NapseAlert {
        ts: now,
        src_ip: record.src_ip.clone(),
        src_port: record.src_port,
        dst_ip: record.dst_ip.clone(),
        dst_port: record.dst_port,
        proto: record.proto.clone(),
        severity: sev,
        rule_id,
        rule_msg: msg.to_string(),
        mitre: mitre.to_string(),
        category: cat.to_string(),
        confidence: conf,
        intent_phase: phase_str.clone(),
        risk_score,
        alert_action: "alert".to_string(),
        // `run_signatures` has no access to the tabular scorer / `ml_cpu` gate (both live
        // on `NapseSynthesizer`) — `NapseSynthesizer::ingest` fills this in with the real,
        // capability-gated value right after this function returns. Never left at this
        // default in the alert stream a caller actually observes.
        p_attack: 0.0,
    };

    // ── Rule 1000004: C2 Beacon — CRITICAL, checked first (highest priority) ──
    if let Some(ref ja3) = record.ja3 {
        if MALICIOUS_JA3.contains(&ja3.as_str()) {
            return Some(alert(
                1000004,
                "NAPSE Potential C2 Communication (JA3 match)",
                "malware_c2",
                SEV_CRITICAL,
                "T1071.001",
                0.90,
            ));
        }
    }

    // ── Rule 1000007: SQL Injection — CRITICAL ────────────────────────────────
    if let Some(ref uri) = record.uri {
        // Normalize URL encoding before pattern matching so "union+select"
        // and "union%20select" both fire — mirrors real WAF/reverse-proxy
        // pre-processing (normalize_uri replaces + and %20 with space).
        let norm_uri = normalize_uri(uri);
        if pattern_match_any(&norm_uri, SQL_INJECTION_PATTERNS) {
            return Some(alert(
                1000007,
                "NAPSE SQL Injection Attempt",
                "sql_injection",
                SEV_CRITICAL,
                "T1190",
                0.85,
            ));
        }
        // ── Rule 1000008: XSS — HIGH ──────────────────────────────────────────
        if pattern_match_any(&norm_uri, XSS_PATTERNS) {
            return Some(alert(
                1000008,
                "NAPSE Cross-Site Scripting Attempt",
                "xss",
                SEV_HIGH,
                "T1059.007",
                0.80,
            ));
        }
        // ── Rule 1000010: Path Traversal — HIGH ───────────────────────────────
        if pattern_match_any(&norm_uri, PATH_TRAVERSAL_PATTERNS) {
            return Some(alert(
                1000010,
                "NAPSE Path Traversal Attempt",
                "path_traversal",
                SEV_HIGH,
                "T1083",
                0.80,
            ));
        }
    }

    // C2 content pattern match (DNS query name, HTTP URI, payload indicators)
    let content = record
        .uri
        .as_deref()
        .or(record.query.as_deref())
        .unwrap_or("");
    if !content.is_empty() && pattern_match_any(content, C2_BEACON_PATTERNS) {
        return Some(alert(
            1000004,
            "NAPSE Potential C2 Communication (content pattern)",
            "malware_c2",
            SEV_CRITICAL,
            "T1071.001",
            0.75,
        ));
    }

    // ── Rule 1000009: TLS Downgrade — HIGH ───────────────────────────────────
    if let Some(ref ver) = record.tls_version {
        let v = ver.to_lowercase();
        if v.starts_with("sslv2")
            || v.starts_with("sslv3")
            || v.starts_with("tlsv1.0")
            || v.starts_with("tlsv1.1")
        {
            return Some(alert(
                1000009,
                "NAPSE TLS Downgrade Attack",
                "tls_downgrade",
                SEV_HIGH,
                "T1557.002",
                0.80,
            ));
        }
    }

    // ── Rule 1000001: SSH Brute Force — HIGH ─────────────────────────────────
    // threshold: 5 connection attempts to port 22 within 300 s
    if record.dst_port == 22 && record.proto == "tcp" {
        let attempts = entity.ssh_attempt_ts.len();
        if attempts >= 5 {
            let conf = (0.50 + attempts as f64 * 0.05).min(0.95);
            return Some(alert(
                1000001,
                "NAPSE SSH Brute Force Attempt",
                "brute_force",
                SEV_HIGH,
                "T1110",
                conf,
            ));
        }
    }

    // ── Rule 1000005: Crypto Mining — MEDIUM ─────────────────────────────────
    if !content.is_empty() && pattern_match_any(content, CRYPTO_MINING_PATTERNS) {
        return Some(alert(
            1000005,
            "NAPSE Cryptocurrency Mining Detected",
            "crypto_mining",
            SEV_MEDIUM,
            "T1496",
            0.80,
        ));
    }

    // ── Rule 1000002: DNS Tunneling — HIGH ───────────────────────────────────
    if record.record_type == "dns" {
        let high_entropy = record.query_entropy.map_or(false, |e| e > 3.5);
        let long_query = record.query_len.map_or(false, |l| l > 60);
        let high_volume = entity.dns_query_ts.len() > 100;

        if high_entropy && long_query {
            return Some(alert(
                1000002,
                "NAPSE DNS Tunneling Detected (entropy+length)",
                "dns_tunneling",
                SEV_HIGH,
                "T1071.004",
                0.85,
            ));
        }
        if high_volume {
            return Some(alert(
                1000002,
                "NAPSE DNS Tunneling Detected (high volume)",
                "dns_tunneling",
                SEV_HIGH,
                "T1071.004",
                0.70,
            ));
        }

        // ── Rule 1000021: Suspicious DNS TLD ─────────────────────────────────
        let suspicious_tld = record.query.as_ref().map_or(false, |q| {
            SUSPICIOUS_TLDS.iter().any(|tld| q.ends_with(tld))
        });
        if suspicious_tld && (long_query || high_entropy) {
            return Some(alert(
                1000021,
                "NAPSE Suspicious DNS Query (suspicious TLD + anomalous query)",
                "suspicious_dns",
                SEV_MEDIUM,
                "T1071.004",
                0.65,
            ));
        }

        // ── Rule 1000011: DNS to Non-Standard Port ────────────────────────────
        if record.dst_port != 53 && record.dst_port != 853 && record.dst_port != 5353 {
            return Some(alert(
                1000011,
                "NAPSE DNS Query to Non-Standard Port",
                "policy_violation",
                SEV_MEDIUM,
                "T1071.004",
                0.70,
            ));
        }
    }

    // ── Rule 1000003: Port Scan — MEDIUM ─────────────────────────────────────
    // threshold: 50 unique dst ports in 300 s (updated window already expired)
    {
        let unique_in_window: HashSet<u16> =
            entity.port_scan_entries.iter().map(|&(_, p)| p).collect();
        if unique_in_window.len() >= 50 {
            let conf = (0.50 + unique_in_window.len() as f64 * 0.005).min(0.95);
            return Some(alert(
                1000003,
                "NAPSE Port Scan Detected",
                "port_scan",
                SEV_MEDIUM,
                "T1046",
                conf,
            ));
        }
    }

    // ── Rule 1000025: Bulk Outbound Data Transfer / Possible Exfiltration ─────
    // 2026-07-07 fix (gap analysis): the ORIGINAL rule gated on `payload_entropy > 7.5 AND
    // orig_bytes > 1000` in the SAME record — dead on real traffic because the two fields never
    // coexist. `payload_entropy` is only ever populated by the capture layer for DNS query names
    // (`record.query_entropy`/`record.payload_entropy` on `record_type == "dns"` records), and a
    // DNS query is a handful of bytes — nowhere near `orig_bytes > 1000`. Meanwhile TCP "conn"
    // records, the ones that DO carry a real conntrack-derived `orig_bytes` for a bulk transfer,
    // never carry a payload entropy figure at all (the capture layer doesn't compute one for
    // plain connection summaries). The AND could never be satisfied — this rule could never fire
    // on any record this engine has ever actually been fed.
    //
    // Fixed to a real, measurable conntrack-BYTE-VOLUME heuristic instead: `entity.exfil_bytes_window`
    // (populated in `NapseSynthesizer::ingest`, same 300s sliding window every other rule here
    // uses) sums `orig_bytes` this entity has sent toward EXTERNAL (non-RFC1918) destinations.
    // Crossing [`EXFIL_VOLUME_THRESHOLD_BYTES`] fires — this is honestly computable from fields
    // that DO coexist on-device (conntrack always has `orig_bytes` + both IPs for every "conn"
    // record), unlike the dead entropy-based gate it replaces.
    //
    // Honest scope: this is a whole-ENTITY (per source-IP) windowed sum, not a per-destination one
    // — `EntityState` is keyed by `src_ip` alone (see its doc), so this cannot currently
    // distinguish "50MB to one destination" from "50MB spread across many different external
    // destinations in the same window". Both are treated as the same bulk-outbound signal; a
    // future per-(src,dst) breakdown (mirroring `portscan::SlowScanTracker`'s per-target scoping)
    // would sharpen this further but needs an entity-model change beyond this fix's scope.
    {
        let window_bytes: u64 = entity.exfil_bytes_window.iter().map(|&(_, b)| b).sum();
        if window_bytes > EXFIL_VOLUME_THRESHOLD_BYTES {
            let over_ratio =
                (window_bytes as f64 / EXFIL_VOLUME_THRESHOLD_BYTES as f64 - 1.0).clamp(0.0, 3.0);
            let conf = (0.60 + over_ratio * 0.05).min(0.95);
            return Some(alert(
                1000025,
                "NAPSE Bulk Outbound Data Transfer (Possible Exfiltration)",
                "exfiltration",
                SEV_HIGH,
                "T1048",
                conf,
            ));
        }
    }

    None
}

// ─── Top-level synthesizer ────────────────────────────────────────────────────

/// Top-level detection-synthesis engine.
///
/// Holds the entity state table, runs signatures + HMM intent decoding +
/// Bayesian risk scoring for each ingested flow record, and emits alerts.
///
/// One instance lives for the lifetime of the WASI process (started once by
/// the supervisor, fed a continuous stream via stdin redirect).
pub struct NapseSynthesizer {
    /// Per-entity state keyed by src_ip string.
    entities: HashMap<String, EntityState>,
    /// Entity table capacity (evicts oldest when full).
    /// Default 1 000 — fits in the wasm-M 256 MB budget on Pi-class hardware.
    max_entities: usize,
    /// Sliding window duration in seconds; matches V1 rule thresholds (300 s).
    window_s: f64,
    /// Running alert count (diagnostic).
    pub alerts_emitted: u64,
    /// Running ingested event count (diagnostic).
    pub events_processed: u64,
    /// Tabular-ML scorer (roadmap C seam). Always constructed — cost is a handful of
    /// `f64` multiplies per entity per event, negligible next to the existing HMM step —
    /// but only ever CONSULTED when `ml_cpu_granted` is true (see `ingest()`).
    tabular_scorer: SeedLogisticScorer,
    /// Whether the `ml_cpu` capability was granted per the signed Platform Manifest.
    /// Defaults to `false` (safe/ungated: HMM deviation keeps using
    /// `EntityState::heuristic_deviation()` unchanged, and alert `p_attack` stays `0.0`)
    /// so every existing caller/test is byte-for-byte unaffected until explicitly opted
    /// in via [`Self::set_ml_cpu_granted`].
    ///
    /// **Honest residual wire (owned outside this crate's scope):** nothing today calls
    /// `set_ml_cpu_granted(true)` in `src/main.rs` — reading the Platform Manifest at
    /// runtime requires either a new `read` grant in `module.yaml` (re-signing, staging
    /// churn — explicitly out of scope for this pass) or supervisor-side capability
    /// plumbing (env var / file descriptor) into the wasm sandbox, neither of which
    /// exists yet (`supervisor/src/wasm_loader.rs` is not owned by this task). This
    /// mirrors `dga_lm`'s own documented gap: its `p_attack_for_qsecbit` connector is
    /// fully implemented and unit-tested but nothing in `dga_lm::main` calls it either —
    /// see that module's "QSECBIT connector" doc block.
    ml_cpu_granted: bool,
}

impl NapseSynthesizer {
    pub fn new(max_entities: usize, window_s: f64) -> Self {
        Self {
            entities: HashMap::new(),
            max_entities,
            window_s,
            alerts_emitted: 0,
            events_processed: 0,
            tabular_scorer: SeedLogisticScorer::new(),
            ml_cpu_granted: false,
        }
    }

    /// Opt in to the tabular-ML scorer once the caller has confirmed `ml_cpu` is granted
    /// (read once from the signed Platform Manifest — this type never reads it itself).
    /// Builder-style so `NapseSynthesizer::new(..).with_ml_cpu_granted(granted)` composes
    /// at the call site without an API break for existing callers.
    pub fn with_ml_cpu_granted(mut self, granted: bool) -> Self {
        self.ml_cpu_granted = granted;
        self
    }

    /// Same as [`Self::with_ml_cpu_granted`] but in-place, for callers holding a `&mut`.
    pub fn set_ml_cpu_granted(&mut self, granted: bool) {
        self.ml_cpu_granted = granted;
    }

    /// Ingest one normalized flow record and return an alert verdict if a
    /// threat is detected, or `None` for benign records.
    ///
    /// Pipeline mirrors V1 `SIAEngine._process_entity()`:
    /// 1. Update entity feature accumulators + sliding windows
    /// 2. Compute heuristic deviation (TODO(wasi-nn): GNN deviation)
    /// 3. Viterbi HMM step → intent phase
    /// 4. Bayesian belief update → risk score
    /// 5. Signature rule sweep → alert (if triggered)
    pub fn ingest(&mut self, record: &FlowRecord) -> Option<NapseAlert> {
        self.events_processed += 1;
        let now = record.ts;
        let src = record.src_ip.clone();

        // ── 1. Get or create entity, then update it ───────────────────────────
        self.ensure_entity(&src, now);
        let entity = self.entities.get_mut(&src).unwrap();

        entity.last_seen = now;
        entity.event_count += 1;
        entity.unique_dest_ips.insert(record.dst_ip.clone());
        entity.unique_dest_ports.insert(record.dst_port);
        entity.bytes_sent += record.orig_bytes;
        entity.bytes_received += record.resp_bytes;

        if matches!(
            record.conn_state.as_str(),
            "S0" | "REJ" | "RSTO" | "RSTOS0"
        ) {
            entity.failed_conn_count += 1;
        }

        // Expire old sliding-window entries before adding new ones
        entity.expire_windows(now, self.window_s);

        // 2026-07-07 fix for rule 1000025: any record type can carry conntrack-derived
        // `orig_bytes` (not just "conn" summaries), so this check is independent of the
        // `record_type` match below — every byte this (internal) entity sends toward an EXTERNAL
        // destination accumulates into the windowed volume rule 1000025 sums.
        if record.orig_bytes > 0 && is_private_ip(&record.src_ip) && !is_private_ip(&record.dst_ip) {
            entity.exfil_bytes_window.push_back((now, record.orig_bytes));
        }

        match record.record_type.as_str() {
            "conn" | "" => {
                if record.dst_port == 22 && record.proto == "tcp" {
                    entity.ssh_attempt_ts.push_back(now);
                }
                entity.port_scan_entries.push_back((now, record.dst_port));
            }
            "dns" => {
                entity.dns_query_count += 1;
                entity.dns_query_ts.push_back(now);
            }
            "alert" => {
                entity.alert_count += 1;
                // High-signal: inject strong evidence immediately (mirrors V1
                // SIAEngine._on_alert forcing immediate processing)
                if record.alert_severity.map_or(false, |s| s <= 2) {
                    bayes_update(entity, IntentPhase::Reconnaissance, 0.80, now);
                }
            }
            _ => {}
        }

        // ── 2–4. HMM + Bayesian ───────────────────────────────────────────────
        let features = entity.feature_vector();
        // Roadmap C — tabular-ML seam: run the seed scorer over the live feature vector,
        // then gate its use on `ml_cpu` (falls back to the pre-existing heuristic when
        // ungranted — `heuristic_deviation()` is still unconditionally computed, never
        // removed). `viterbi_step`/the HMM flow is otherwise untouched.
        let model_p = entity.tabular_p_attack(&self.tabular_scorer);
        let heuristic = entity.heuristic_deviation();
        let deviation = tabular::gated_deviation(model_p, heuristic, self.ml_cpu_granted);
        viterbi_step(entity, &features, deviation);

        let best = entity
            .hmm_phase_history
            .back()
            .copied()
            .unwrap_or(0) as usize;
        let phase = IntentPhase::from_index(best);
        let confidence = hmm_confidence(&entity.hmm_log_probs, best);
        bayes_update(entity, phase, confidence, now);

        // ── 5. Signature sweep (immutable borrow after all mutations) ─────────
        let entity_ref = self.entities.get(&src).unwrap();
        let mut alert = run_signatures(record, entity_ref, now);

        if let Some(ref mut a) = alert {
            // `run_signatures` has no access to `tabular_scorer`/`ml_cpu_granted` (both
            // live on `Self`), so it always builds `p_attack: 0.0` — fill in the real,
            // capability-gated value here (QSECBIT-facing contract: stays 0.0 when
            // `ml_cpu` isn't granted, per `tabular::p_attack_for_qsecbit`).
            a.p_attack = tabular::p_attack_for_qsecbit(model_p, self.ml_cpu_granted);
            self.entities.get_mut(&src).unwrap().alert_count += 1;
            self.alerts_emitted += 1;
        }

        alert
    }

    /// Ensure entity exists, evicting the least-recently-seen entity when full.
    fn ensure_entity(&mut self, entity_id: &str, now: f64) {
        if self.entities.contains_key(entity_id) {
            return;
        }
        if self.entities.len() >= self.max_entities {
            // Evict oldest — mirrors V1 EntityGraph._evict_oldest_node()
            let oldest = self
                .entities
                .iter()
                .min_by(|a, b| a.1.last_seen.partial_cmp(&b.1.last_seen).unwrap())
                .map(|(k, _)| k.clone());
            if let Some(k) = oldest {
                self.entities.remove(&k);
            }
        }
        self.entities
            .insert(entity_id.to_string(), EntityState::new(entity_id, now));
    }

    pub fn entity_count(&self) -> usize {
        self.entities.len()
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Helper ───────────────────────────────────────────────────────────────

    fn conn(src: &str, dst_port: u16, ts: f64) -> FlowRecord {
        FlowRecord::new_conn(ts, src, 54321, "10.0.0.1", dst_port, "tcp", "S0", 0, 0)
    }

    // ── Benign flow — no alert ────────────────────────────────────────────────

    #[test]
    fn benign_single_connection_no_alert() {
        let mut synth = NapseSynthesizer::new(100, 300.0);
        let r = FlowRecord::new_conn(
            1.0,
            "192.168.1.10",
            54321,
            "8.8.8.8",
            443,
            "tcp",
            "SF",
            1000,
            2000,
        );
        let alert = synth.ingest(&r);
        assert!(
            alert.is_none(),
            "single benign HTTPS flow must not trigger an alert"
        );
    }

    // ── Port scan — rule 1000003 ──────────────────────────────────────────────

    #[test]
    fn port_scan_triggers_at_fifty_unique_ports() {
        let mut synth = NapseSynthesizer::new(100, 300.0);
        // 49 distinct ports → no alert yet
        for port in 1u16..=49 {
            let r = conn("10.1.1.1", port, 1.0);
            let a = synth.ingest(&r);
            assert!(
                a.is_none(),
                "port {port}: no alert before 50 unique ports"
            );
        }
        // 50th distinct port → alert fires
        let r = conn("10.1.1.1", 50, 1.0);
        let alert = synth
            .ingest(&r)
            .expect("port scan must fire at 50 unique ports");
        assert_eq!(alert.rule_id, 1000003, "wrong rule id");
        assert_eq!(alert.severity, SEV_MEDIUM, "port scan must be MEDIUM");
        assert_eq!(alert.mitre, "T1046");
    }

    #[test]
    fn port_scan_alert_carries_src_and_mitre() {
        let mut synth = NapseSynthesizer::new(100, 300.0);
        for port in 1u16..=50 {
            synth.ingest(&conn("192.168.2.5", port, 2.0));
        }
        // entity should have fired on the 50th
        // run one more to confirm the alert fields
        let r = conn("192.168.2.5", 51, 2.0);
        let alert = synth.ingest(&r).expect("port scan still firing");
        assert_eq!(alert.src_ip, "192.168.2.5");
        assert_eq!(alert.mitre, "T1046");
        assert!(alert.confidence > 0.5, "confidence must be > 0.5");
    }

    // ── SSH brute force — rule 1000001 ───────────────────────────────────────

    #[test]
    fn ssh_brute_force_fires_at_fifth_attempt() {
        let mut synth = NapseSynthesizer::new(100, 300.0);
        let ssh = |ts: f64| {
            FlowRecord::new_conn(ts, "203.0.113.1", 54000, "192.168.1.1", 22, "tcp", "S0", 0, 0)
        };
        for ts in [1.0f64, 2.0, 3.0, 4.0] {
            let a = synth.ingest(&ssh(ts));
            assert!(a.is_none(), "no alert before 5th SSH attempt (ts={ts})");
        }
        let alert = synth
            .ingest(&ssh(5.0))
            .expect("SSH brute force must fire on 5th attempt");
        assert_eq!(alert.rule_id, 1000001);
        assert_eq!(alert.severity, SEV_HIGH);
        assert_eq!(alert.mitre, "T1110");
        assert_eq!(alert.dst_port, 22);
    }

    // ── DNS tunneling — rule 1000002 ─────────────────────────────────────────

    #[test]
    fn dns_tunneling_fires_on_high_entropy_long_query() {
        let mut synth = NapseSynthesizer::new(100, 300.0);
        let mut r = FlowRecord {
            record_type: "dns".to_string(),
            ts: 1.0,
            src_ip: "192.168.5.1".to_string(),
            dst_ip: "8.8.8.8".to_string(),
            dst_port: 53,
            proto: "udp".to_string(),
            // both thresholds exceeded
            query_entropy: Some(4.2), // > 3.5
            query_len: Some(65),      // > 60
            ..Default::default()
        };
        r.query = Some("aGVsbG8gd29ybGQtZXZpbC1kb21haW4.evil.com".to_string());
        let alert = synth
            .ingest(&r)
            .expect("DNS tunneling must fire when entropy>3.5 AND len>60");
        assert_eq!(alert.rule_id, 1000002);
        assert_eq!(alert.severity, SEV_HIGH);
        assert_eq!(alert.mitre, "T1071.004");
    }

    #[test]
    fn dns_tunneling_no_alert_for_normal_query() {
        let mut synth = NapseSynthesizer::new(100, 300.0);
        let r = FlowRecord {
            record_type: "dns".to_string(),
            ts: 1.0,
            src_ip: "192.168.1.5".to_string(),
            dst_ip: "8.8.8.8".to_string(),
            dst_port: 53,
            proto: "udp".to_string(),
            query_entropy: Some(2.1), // low — normal
            query_len: Some(25),      // short — normal
            query: Some("www.google.com".to_string()),
            ..Default::default()
        };
        let alert = synth.ingest(&r);
        assert!(alert.is_none(), "normal DNS query must not alert");
    }

    // ── C2 beacon JA3 match — rule 1000004 ───────────────────────────────────

    #[test]
    fn c2_beacon_fires_on_known_ja3_hash() {
        let mut synth = NapseSynthesizer::new(100, 300.0);
        let r = FlowRecord {
            record_type: "tls".to_string(),
            ts: 1.0,
            src_ip: "10.0.0.5".to_string(),
            dst_ip: "1.2.3.4".to_string(),
            dst_port: 443,
            proto: "tcp".to_string(),
            ja3: Some("72a589da586844d7f0818ce684948eea".to_string()), // CobaltStrike
            ..Default::default()
        };
        let alert = synth
            .ingest(&r)
            .expect("known-bad JA3 must trigger C2 beacon alert");
        assert_eq!(alert.rule_id, 1000004);
        assert_eq!(alert.severity, SEV_CRITICAL);
        assert_eq!(alert.mitre, "T1071.001");
        assert!(alert.confidence >= 0.90);
    }

    #[test]
    fn c2_beacon_no_alert_for_unknown_ja3() {
        let mut synth = NapseSynthesizer::new(100, 300.0);
        let r = FlowRecord {
            record_type: "tls".to_string(),
            ts: 1.0,
            src_ip: "10.0.0.6".to_string(),
            dst_ip: "1.2.3.5".to_string(),
            dst_port: 443,
            proto: "tcp".to_string(),
            ja3: Some("ffffffffffffffffffffffffffffffff".to_string()), // unknown
            ..Default::default()
        };
        assert!(synth.ingest(&r).is_none(), "unknown JA3 must not alert");
    }

    // ── TLS downgrade — rule 1000009 ─────────────────────────────────────────

    #[test]
    fn tls_downgrade_fires_for_tlsv10() {
        let mut synth = NapseSynthesizer::new(100, 300.0);
        let r = FlowRecord {
            record_type: "tls".to_string(),
            ts: 1.0,
            src_ip: "10.0.0.7".to_string(),
            dst_ip: "1.2.3.6".to_string(),
            dst_port: 443,
            proto: "tcp".to_string(),
            tls_version: Some("TLSv1.0".to_string()),
            ..Default::default()
        };
        let alert = synth
            .ingest(&r)
            .expect("TLSv1.0 must trigger downgrade alert");
        assert_eq!(alert.rule_id, 1000009);
        assert_eq!(alert.severity, SEV_HIGH);
        assert_eq!(alert.mitre, "T1557.002");
    }

    #[test]
    fn tls_downgrade_no_alert_for_tlsv13() {
        let mut synth = NapseSynthesizer::new(100, 300.0);
        let r = FlowRecord {
            record_type: "tls".to_string(),
            ts: 1.0,
            src_ip: "10.0.0.8".to_string(),
            dst_ip: "1.2.3.7".to_string(),
            dst_port: 443,
            proto: "tcp".to_string(),
            tls_version: Some("TLSv1.3".to_string()),
            ..Default::default()
        };
        assert!(synth.ingest(&r).is_none(), "TLSv1.3 must not trigger downgrade");
    }

    // ── Bulk outbound exfiltration — rule 1000025 (2026-07-07 dead-rule fix) ──

    fn conn_bytes(src: &str, dst: &str, ts: f64, orig_bytes: u64) -> FlowRecord {
        FlowRecord::new_conn(ts, src, 54321, dst, 443, "tcp", "SF", orig_bytes, 0)
    }

    /// The core fix proof: the ORIGINAL gate (`payload_entropy>7.5 AND orig_bytes>1000` in the
    /// SAME record) could never fire on a "conn" record (no entropy field ever populated on it) —
    /// this must now fire from orig_bytes ALONE, summed over the window, with no entropy field
    /// present at all (confirming the dead AND-gate is truly gone).
    #[test]
    fn bulk_outbound_transfer_to_external_dst_fires() {
        let mut synth = NapseSynthesizer::new(100, 300.0);
        let src = "10.0.0.40";
        let dst = "203.0.113.40"; // external
        let mut alert = None;
        // 6 chunks of 10MB each = 60MB, comfortably over the 50MB/300s threshold, spread within
        // the window so the windowed SUM (not any single record) is what crosses it.
        for i in 0..6u64 {
            let r = conn_bytes(src, dst, i as f64 * 10.0, 10_000_000);
            alert = synth.ingest(&r);
        }
        let a = alert.expect("sustained 60MB outbound to an external dst must fire rule 1000025");
        assert_eq!(a.rule_id, 1000025);
        assert_eq!(a.severity, SEV_HIGH);
        assert_eq!(a.mitre, "T1048");
        assert_eq!(a.category, "exfiltration");
        assert!(a.confidence > 0.5);
    }

    /// A single connection large enough on its own must also fire (the windowed sum is >= any one
    /// record's contribution) — real exfil is often one big transfer, not always many small ones.
    #[test]
    fn single_large_outbound_transfer_fires() {
        let mut synth = NapseSynthesizer::new(100, 300.0);
        let r = conn_bytes("10.0.0.41", "203.0.113.41", 1.0, 80_000_000);
        let a = synth.ingest(&r).expect("one 80MB outbound transfer must fire rule 1000025");
        assert_eq!(a.rule_id, 1000025);
    }

    /// FP guard: small, ordinary volume — well under the threshold — never fires.
    #[test]
    fn small_outbound_volume_never_fires() {
        let mut synth = NapseSynthesizer::new(100, 300.0);
        let src = "10.0.0.42";
        let dst = "203.0.113.42";
        for i in 0..10u64 {
            let r = conn_bytes(src, dst, i as f64 * 10.0, 500_000); // 5MB total, well under 50MB
            assert!(synth.ingest(&r).is_none(), "5MB total outbound must never fire rule 1000025");
        }
    }

    /// FP guard (critical): the SAME large volume, but to an INTERNAL destination (e.g. a backup
    /// job copying to a NAS, a large internal file share transfer), must never fire — this rule is
    /// scoped to EXTERNAL exfiltration only, never internal-to-internal bulk transfers.
    #[test]
    fn large_volume_to_internal_destination_never_fires() {
        let mut synth = NapseSynthesizer::new(100, 300.0);
        let src = "10.0.0.43";
        let dst = "10.0.0.200"; // internal — e.g. a backup/NAS target
        for i in 0..8u64 {
            let r = conn_bytes(src, dst, i as f64 * 10.0, 10_000_000); // 80MB total, internal
            assert!(
                synth.ingest(&r).is_none(),
                "large volume to an INTERNAL destination must never fire the exfiltration rule"
            );
        }
    }

    /// FP guard: window eviction — volume spread across a gap wider than the 300s window must not
    /// accumulate into a false alert (mirrors the discipline every other windowed rule in this
    /// engine already applies).
    #[test]
    fn outbound_volume_spread_beyond_window_does_not_accumulate() {
        let mut synth = NapseSynthesizer::new(100, 300.0);
        let src = "10.0.0.44";
        let dst = "203.0.113.44";
        // 30MB at t=0, then 30MB again at t=1000 (well past the 300s window) — neither batch
        // alone crosses 50MB, and by t=1000 the first batch has aged out of the window.
        assert!(synth.ingest(&conn_bytes(src, dst, 0.0, 30_000_000)).is_none());
        assert!(
            synth.ingest(&conn_bytes(src, dst, 1000.0, 30_000_000)).is_none(),
            "the first 30MB must have aged out of the 300s window by t=1000"
        );
    }

    // ── SQL injection — rule 1000007 ─────────────────────────────────────────

    #[test]
    fn sql_injection_fires_on_union_select_uri() {
        let mut synth = NapseSynthesizer::new(100, 300.0);

        // URL-encoded space (`+`) variant — normalize_uri must convert
        // "UNION+SELECT" → "union select" before pattern matching.
        let r = FlowRecord {
            record_type: "http".to_string(),
            ts: 1.0,
            src_ip: "203.0.113.5".to_string(),
            dst_ip: "192.168.1.100".to_string(),
            dst_port: 80,
            proto: "tcp".to_string(),
            uri: Some("/api/users?id=1'+UNION+SELECT+1,2,3--".to_string()),
            ..Default::default()
        };
        let alert = synth.ingest(&r).expect("SQL injection with +-encoded spaces must alert");
        assert_eq!(alert.rule_id, 1000007, "wrong rule id for SQL injection");
        assert_eq!(alert.severity, SEV_CRITICAL, "SQL injection must be CRITICAL");
        assert_eq!(alert.mitre, "T1190");
    }

    #[test]
    fn sql_injection_fires_on_literal_space_uri() {
        let mut synth = NapseSynthesizer::new(100, 300.0);
        // Literal space variant (some proxies de-encode before forwarding)
        let r = FlowRecord {
            record_type: "http".to_string(),
            ts: 1.0,
            src_ip: "203.0.113.6".to_string(),
            dst_ip: "192.168.1.100".to_string(),
            dst_port: 443,
            proto: "tcp".to_string(),
            uri: Some("/search?q=1' union select password from users--".to_string()),
            ..Default::default()
        };
        let alert = synth.ingest(&r).expect("literal-space SQL injection must alert");
        assert_eq!(alert.rule_id, 1000007);
    }

    // ── is_private_ip helper ─────────────────────────────────────────────────

    #[test]
    fn private_ip_detection() {
        assert!(is_private_ip("10.0.0.1"));
        assert!(is_private_ip("172.16.0.1"));
        assert!(is_private_ip("172.31.255.255"));
        assert!(is_private_ip("192.168.1.1"));
        assert!(is_private_ip("127.0.0.1"));
        assert!(!is_private_ip("8.8.8.8"));
        assert!(!is_private_ip("1.1.1.1"));
        assert!(!is_private_ip("172.15.0.1"));  // not in 172.16.0.0/12
    }

    // ── Bayesian scorer ───────────────────────────────────────────────────────

    #[test]
    fn bayesian_posterior_increases_with_attack_evidence() {
        let mut entity = EntityState::new("10.0.0.1", 0.0);
        let prior = entity.bayes_posterior;

        // Feed IMPACT evidence (LR=30, high confidence) → posterior must increase
        bayes_update(&mut entity, IntentPhase::Impact, 0.9, 0.0);
        assert!(
            entity.bayes_posterior > prior,
            "IMPACT evidence must raise posterior (got {:.4})",
            entity.bayes_posterior
        );
    }

    #[test]
    fn bayesian_posterior_decreases_with_benign_evidence() {
        let mut entity = EntityState::new("10.0.0.1", 0.0);
        // Prime with some attack evidence first
        bayes_update(&mut entity, IntentPhase::Reconnaissance, 0.8, 0.0);
        let after_attack = entity.bayes_posterior;

        // Then feed BENIGN evidence (LR=0.1 < 1 → drives posterior down)
        bayes_update(&mut entity, IntentPhase::Benign, 0.9, 1.0);
        assert!(
            entity.bayes_posterior < after_attack,
            "BENIGN evidence must lower posterior from {:.4} → {:.4}",
            after_attack,
            entity.bayes_posterior
        );
    }

    #[test]
    fn sandbox_threshold_triggers_at_0_92() {
        let mut entity = EntityState::new("10.0.0.1", 0.0);
        // Feed many high-likelihood attack events to drive posterior past 0.92
        for i in 0..50u32 {
            bayes_update(&mut entity, IntentPhase::Impact, 0.99, i as f64);
        }
        assert!(
            entity.sandbox_triggered,
            "sandbox must trigger when posterior ≥ 0.92 (got {:.4})",
            entity.bayes_posterior
        );
    }

    // ── HMM Viterbi ──────────────────────────────────────────────────────────

    #[test]
    fn hmm_initialises_on_first_step() {
        let mut entity = EntityState::new("10.0.0.1", 0.0);
        assert!(!entity.hmm_initialized);
        let features = entity.feature_vector();
        let dev = entity.heuristic_deviation();
        viterbi_step(&mut entity, &features, dev);
        assert!(entity.hmm_initialized);
        assert_eq!(entity.hmm_phase_history.len(), 1);
    }

    #[test]
    fn hmm_stays_benign_for_quiet_entity() {
        // Entity with a single destination observed over a long period:
        // conn_rate = 1 event / 3600s ≈ 0.00028 — very close to BENIGN
        // emission profile mean (0.01) and far from RECON (0.5).
        let mut entity = EntityState::new("10.0.0.1", 0.0);
        entity.last_seen = 3600.0; // 1 hour of quiet activity
        entity.unique_dest_ports.insert(443);
        entity.bytes_sent = 1000;
        entity.bytes_received = 5000;
        entity.event_count = 1;
        let features = entity.feature_vector();
        let dev = entity.heuristic_deviation();
        viterbi_step(&mut entity, &features, dev);
        let phase = current_phase(&entity);
        // BENIGN emission dominates: low port_entropy(0.0→near-BENIGN),
        // very low conn_rate(≈0.00028), zero alerts.
        assert_eq!(
            phase,
            IntentPhase::Benign,
            "quiet entity with 1 event/hour should decode as BENIGN, got {}",
            phase.as_str()
        );
    }

    #[test]
    fn hmm_phases_attack_for_high_port_entropy_entity() {
        let mut entity = EntityState::new("10.0.0.1", 0.0);
        // 64 unique destination ports → port_entropy = log2(64) = 6.0
        for p in 1u16..=64 {
            entity.unique_dest_ports.insert(p);
        }
        entity.event_count = 64;
        entity.last_seen = entity.first_seen + 1.0; // fast scan
        entity.alert_count = 0;

        let features = entity.feature_vector();
        let dev = entity.heuristic_deviation();
        viterbi_step(&mut entity, &features, dev);
        let phase = current_phase(&entity);
        assert!(
            phase.is_attack(),
            "high port entropy entity should decode as attack phase, got {}",
            phase.as_str()
        );
    }

    // ── HMM confidence helper ─────────────────────────────────────────────────

    #[test]
    fn hmm_confidence_uniform_is_one_ninth() {
        let log_probs = [0.0f64; NUM_STATES];
        let conf = hmm_confidence(&log_probs, 0);
        let expected = 1.0 / NUM_STATES as f64;
        assert!(
            (conf - expected).abs() < 1e-10,
            "uniform log-probs → confidence = 1/9 ≈ {expected:.4}, got {conf:.4}"
        );
    }

    #[test]
    fn hmm_confidence_winner_dominates() {
        let mut log_probs = [f64::NEG_INFINITY; NUM_STATES];
        log_probs[2] = 0.0; // only state 2 has finite probability
        let conf = hmm_confidence(&log_probs, 2);
        assert!(
            (conf - 1.0).abs() < 1e-10,
            "sole finite state → confidence ≈ 1.0, got {conf:.4}"
        );
    }

    // ── compute_emissions ─────────────────────────────────────────────────────

    #[test]
    fn emissions_recon_higher_than_benign_for_port_scan() {
        // Features representing a port scanner:
        // port_entropy=6.0 (64 ports), conn_rate=10, alerts=0
        let mut features = [0.0f64; 16];
        features[7] = 0.0;  // alert_count
        features[9] = 6.0;  // port_entropy — RECON profile mean=4.0
        features[14] = 10.0; // conn_rate — high

        let deviation = 0.5; // moderate anomaly
        let emissions = compute_emissions(&features, deviation);

        // RECONNAISSANCE (state 1) should score better than BENIGN (state 0)
        // for a high port-entropy entity
        assert!(
            emissions[1] > emissions[0],
            "RECON emission ({:.4}) must exceed BENIGN ({:.4}) for port_entropy=6.0",
            emissions[1], emissions[0]
        );
    }

    // ── EntityState helpers ───────────────────────────────────────────────────

    #[test]
    fn port_entropy_zero_for_single_port() {
        let mut e = EntityState::new("1.2.3.4", 0.0);
        e.unique_dest_ports.insert(443);
        assert_eq!(e.port_entropy(), 0.0);
    }

    #[test]
    fn port_entropy_increases_with_unique_ports() {
        let mut e = EntityState::new("1.2.3.4", 0.0);
        e.unique_dest_ports.extend(1u16..=4); // log2(4) = 2.0
        assert!((e.port_entropy() - 2.0).abs() < 1e-10);
        e.unique_dest_ports.extend(5u16..=8); // log2(8) = 3.0
        assert!((e.port_entropy() - 3.0).abs() < 1e-10);
    }

    #[test]
    fn heuristic_deviation_zero_for_quiet_entity() {
        let e = EntityState::new("1.2.3.4", 0.0);
        // No ports, no rate, no alerts → deviation = 0
        assert_eq!(e.heuristic_deviation(), 0.0);
    }

    #[test]
    fn window_expiry_removes_old_entries() {
        let mut e = EntityState::new("1.2.3.4", 0.0);
        e.ssh_attempt_ts.push_back(1.0); // at t=1
        e.ssh_attempt_ts.push_back(2.0); // at t=2

        // At now=200, window_s=300: cutoff = 200 - 300 = -100.
        // Both entries (t=1, t=2) have t > -100 → neither expires.
        e.expire_windows(200.0, 300.0);
        assert_eq!(e.ssh_attempt_ts.len(), 2, "neither entry should expire at t=200 with window=300");

        // At now=302, window_s=300: cutoff = 302 - 300 = 2.
        // t=1 < 2 → expires.  t=2 is NOT < 2 → stays.
        e.expire_windows(302.0, 300.0);
        assert_eq!(e.ssh_attempt_ts.len(), 1, "only t=1 entry should expire at cutoff=2");

        // At now=400, window_s=300: cutoff = 100.
        // t=2 < 100 → the remaining entry expires too.
        e.expire_windows(400.0, 300.0);
        assert_eq!(e.ssh_attempt_ts.len(), 0, "t=2 entry must also expire at cutoff=100");
    }

    // ── NapseSynthesizer capacity management ──────────────────────────────────

    #[test]
    fn synthesizer_evicts_oldest_entity_at_capacity() {
        let mut synth = NapseSynthesizer::new(2, 300.0);
        synth.ingest(&FlowRecord::new_conn(1.0, "10.0.0.1", 1, "10.0.0.100", 80, "tcp", "SF", 0, 0));
        synth.ingest(&FlowRecord::new_conn(2.0, "10.0.0.2", 1, "10.0.0.100", 80, "tcp", "SF", 0, 0));
        assert_eq!(synth.entity_count(), 2);
        // Third entity at capacity → evicts oldest (10.0.0.1, last_seen=1.0)
        synth.ingest(&FlowRecord::new_conn(3.0, "10.0.0.3", 1, "10.0.0.100", 80, "tcp", "SF", 0, 0));
        assert_eq!(synth.entity_count(), 2, "capacity must stay at 2 after eviction");
    }
}
