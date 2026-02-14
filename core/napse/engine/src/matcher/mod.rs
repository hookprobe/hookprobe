//! # Signature Matching Engine
//!
//! High-performance multi-pattern matching using Aho-Corasick automaton
//! for SIMD-accelerated payload scanning. Supports loading signatures from
//! JSON files and matching against raw packet payloads.
//!
//! ## Architecture
//!
//! ```text
//! Payload bytes
//!     |
//!     v
//! [BloomFilter] --miss--> skip (fast negative)
//!     |
//!     hit (potential match)
//!     v
//! [Aho-Corasick Automaton] --> matched signatures
//!     |
//!     v
//! [Severity filter] --> NapseAlert events
//! ```
//!
//! The Bloom filter provides an O(1) fast path for payloads that contain
//! none of the loaded signature patterns. Only potential matches proceed
//! to the Aho-Corasick automaton for exact matching.
//!
//! ## Signature Format
//!
//! Signatures are loaded from JSON files with the following structure:
//!
//! ```json
//! {
//!   "signatures": [
//!     {
//!       "id": 1000001,
//!       "message": "ET MALWARE CobaltStrike Beacon",
//!       "content": ["POST /submit.php", "Cookie: "],
//!       "severity": "critical",
//!       "category": "malware",
//!       "mitre_tactic": "command-and-control",
//!       "mitre_technique": "T1071.001"
//!     }
//!   ]
//! }
//! ```

use std::collections::HashMap;
use std::sync::RwLock;

use aho_corasick::AhoCorasick;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Signature definition
// ---------------------------------------------------------------------------

/// A detection signature with one or more content patterns.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signature {
    /// Unique signature identifier.
    pub id: u32,
    /// Human-readable alert message.
    pub message: String,
    /// Content patterns that must ALL be present in the payload.
    pub content: Vec<String>,
    /// Severity level: "info", "low", "medium", "high", "critical".
    pub severity: String,
    /// Alert category (e.g., "malware", "exploit", "policy").
    #[serde(default)]
    pub category: String,
    /// MITRE ATT&CK tactic.
    #[serde(default)]
    pub mitre_tactic: String,
    /// MITRE ATT&CK technique ID.
    #[serde(default)]
    pub mitre_technique: String,
}

/// Result of a signature match.
#[derive(Debug, Clone)]
pub struct MatchResult {
    /// The matching signature.
    pub signature: Signature,
    /// Byte offsets where each content pattern was found.
    pub match_offsets: Vec<usize>,
}

/// Signature file format for JSON deserialization.
#[derive(Debug, Deserialize)]
struct SignatureFile {
    signatures: Vec<Signature>,
}

// ---------------------------------------------------------------------------
// Bloom Filter
// ---------------------------------------------------------------------------

/// A simple Bloom filter for fast negative lookups.
///
/// Uses multiple hash functions to set bits in a bit array. If any bit
/// for a query is not set, the item is definitely not in the set.
pub struct BloomFilter {
    bits: Vec<u64>,
    num_bits: usize,
    num_hashes: usize,
}

impl BloomFilter {
    /// Create a new Bloom filter with the given capacity.
    ///
    /// # Arguments
    /// * `num_items` - Expected number of items
    /// * `fp_rate` - Desired false positive rate (e.g., 0.01 for 1%)
    pub fn new(num_items: usize, fp_rate: f64) -> Self {
        let num_bits = optimal_num_bits(num_items, fp_rate);
        let num_hashes = optimal_num_hashes(num_bits, num_items);
        let words = (num_bits + 63) / 64;

        Self {
            bits: vec![0u64; words],
            num_bits,
            num_hashes,
        }
    }

    /// Insert an item (byte slice) into the filter.
    pub fn insert(&mut self, item: &[u8]) {
        for i in 0..self.num_hashes {
            let bit = self.hash(item, i) % self.num_bits;
            let word = bit / 64;
            let offset = bit % 64;
            self.bits[word] |= 1u64 << offset;
        }
    }

    /// Check if an item might be in the filter.
    ///
    /// Returns `false` if the item is definitely not present.
    /// Returns `true` if the item might be present (possible false positive).
    pub fn might_contain(&self, item: &[u8]) -> bool {
        for i in 0..self.num_hashes {
            let bit = self.hash(item, i) % self.num_bits;
            let word = bit / 64;
            let offset = bit % 64;
            if self.bits[word] & (1u64 << offset) == 0 {
                return false;
            }
        }
        true
    }

    /// Compute the i-th hash of an item using double hashing.
    fn hash(&self, item: &[u8], i: usize) -> usize {
        // Use FNV-1a as the base hash for speed
        let h1 = fnv1a_hash(item);
        let h2 = fnv1a_hash_seeded(item, 0x517cc1b727220a95);
        (h1.wrapping_add(i.wrapping_mul(h2))) as usize
    }
}

/// Calculate optimal number of bits for a Bloom filter.
fn optimal_num_bits(n: usize, fp: f64) -> usize {
    let ln2 = std::f64::consts::LN_2;
    let m = -(n as f64 * fp.ln()) / (ln2 * ln2);
    m.ceil() as usize
}

/// Calculate optimal number of hash functions.
fn optimal_num_hashes(m: usize, n: usize) -> usize {
    let k = (m as f64 / n as f64) * std::f64::consts::LN_2;
    k.ceil().max(1.0) as usize
}

/// FNV-1a hash function (64-bit).
fn fnv1a_hash(data: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    for &byte in data {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

/// FNV-1a hash function with seed (for double hashing).
fn fnv1a_hash_seeded(data: &[u8], seed: u64) -> u64 {
    let mut hash = seed;
    for &byte in data {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

// ---------------------------------------------------------------------------
// Signature Engine
// ---------------------------------------------------------------------------

/// Multi-pattern signature matching engine.
///
/// Uses Aho-Corasick for SIMD-accelerated multi-pattern matching and a
/// Bloom filter for fast negative lookups.
pub struct SignatureEngine {
    /// Loaded signatures indexed by ID.
    signatures: RwLock<HashMap<u32, Signature>>,
    /// Aho-Corasick automaton for all content patterns.
    automaton: RwLock<Option<AhoCorasick>>,
    /// Maps automaton pattern index back to signature ID.
    pattern_to_sig: RwLock<Vec<u32>>,
    /// Bloom filter for fast negative lookups.
    bloom: RwLock<BloomFilter>,
}

impl SignatureEngine {
    /// Create a new empty signature engine.
    pub fn new() -> Self {
        Self {
            signatures: RwLock::new(HashMap::new()),
            automaton: RwLock::new(None),
            pattern_to_sig: RwLock::new(Vec::new()),
            bloom: RwLock::new(BloomFilter::new(1000, 0.01)),
        }
    }

    /// Load signatures from a JSON file.
    ///
    /// Rebuilds the Aho-Corasick automaton and Bloom filter.
    ///
    /// # Returns
    /// The number of signatures loaded.
    pub fn load_signatures(&self, path: &str) -> Result<usize, SignatureError> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| SignatureError::IoError(format!("{}: {}", path, e)))?;

        let sig_file: SignatureFile = serde_json::from_str(&content)
            .map_err(|e| SignatureError::ParseError(format!("{}: {}", path, e)))?;

        let count = sig_file.signatures.len();

        // Build pattern list and mapping
        let mut patterns = Vec::new();
        let mut pattern_map = Vec::new();
        let mut bloom = BloomFilter::new(count * 2, 0.01);

        let mut sig_map = HashMap::new();

        for sig in &sig_file.signatures {
            sig_map.insert(sig.id, sig.clone());

            for content_pattern in &sig.content {
                patterns.push(content_pattern.clone());
                pattern_map.push(sig.id);
                bloom.insert(content_pattern.as_bytes());
            }
        }

        // Build Aho-Corasick automaton
        let ac = if !patterns.is_empty() {
            Some(
                AhoCorasick::builder()
                    .ascii_case_insensitive(true)
                    .build(&patterns)
                    .map_err(|e| SignatureError::BuildError(format!("{}", e)))?,
            )
        } else {
            None
        };

        // Update internal state
        *self.signatures.write().unwrap() = sig_map;
        *self.automaton.write().unwrap() = ac;
        *self.pattern_to_sig.write().unwrap() = pattern_map;
        *self.bloom.write().unwrap() = bloom;

        Ok(count)
    }

    /// Match a payload against loaded signatures.
    ///
    /// Uses the Bloom filter for a fast negative check, then falls back
    /// to Aho-Corasick for exact matching.
    ///
    /// # Returns
    /// A list of matching signatures with their match offsets.
    pub fn match_payload(&self, payload: &[u8]) -> Vec<MatchResult> {
        let mut results = Vec::new();

        // Fast path: check Bloom filter for any potential matches
        let bloom = self.bloom.read().unwrap();
        let has_potential = payload
            .windows(4)
            .any(|window| bloom.might_contain(window));

        if !has_potential && payload.len() >= 4 {
            return results;
        }

        // Full Aho-Corasick scan
        let automaton_guard = self.automaton.read().unwrap();
        let pattern_map = self.pattern_to_sig.read().unwrap();
        let signatures = self.signatures.read().unwrap();

        if let Some(ref ac) = *automaton_guard {
            // Track which signatures have matches and at what offsets
            let mut sig_matches: HashMap<u32, Vec<usize>> = HashMap::new();

            for mat in ac.find_iter(payload) {
                let pattern_idx = mat.pattern().as_usize();
                if pattern_idx < pattern_map.len() {
                    let sig_id = pattern_map[pattern_idx];
                    sig_matches
                        .entry(sig_id)
                        .or_insert_with(Vec::new)
                        .push(mat.start());
                }
            }

            // For each matched signature, verify ALL content patterns are present
            for (sig_id, offsets) in sig_matches {
                if let Some(sig) = signatures.get(&sig_id) {
                    // Check that we matched at least as many patterns as the
                    // signature requires (one match per content entry).
                    if offsets.len() >= sig.content.len() {
                        results.push(MatchResult {
                            signature: sig.clone(),
                            match_offsets: offsets,
                        });
                    }
                }
            }
        }

        results
    }

    /// Return the number of loaded signatures.
    pub fn signature_count(&self) -> usize {
        self.signatures.read().unwrap().len()
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors that can occur during signature loading or matching.
#[derive(Debug, thiserror::Error)]
pub enum SignatureError {
    #[error("I/O error: {0}")]
    IoError(String),

    #[error("Parse error: {0}")]
    ParseError(String),

    #[error("Build error: {0}")]
    BuildError(String),
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bloom_filter_basic() {
        let mut bf = BloomFilter::new(100, 0.01);
        bf.insert(b"hello");
        bf.insert(b"world");

        assert!(bf.might_contain(b"hello"));
        assert!(bf.might_contain(b"world"));
        // May or may not return true for "foobar" (false positive possible)
    }

    #[test]
    fn test_bloom_filter_negative() {
        let bf = BloomFilter::new(100, 0.01);
        // Empty filter should not contain anything
        assert!(!bf.might_contain(b"anything"));
    }

    #[test]
    fn test_signature_engine_new() {
        let engine = SignatureEngine::new();
        assert_eq!(engine.signature_count(), 0);
    }

    #[test]
    fn test_signature_engine_match_empty() {
        let engine = SignatureEngine::new();
        let results = engine.match_payload(b"some payload data");
        assert!(results.is_empty());
    }

    #[test]
    fn test_fnv1a_hash_deterministic() {
        let h1 = fnv1a_hash(b"test");
        let h2 = fnv1a_hash(b"test");
        assert_eq!(h1, h2);

        let h3 = fnv1a_hash(b"different");
        assert_ne!(h1, h3);
    }

    #[test]
    fn test_optimal_bits_and_hashes() {
        let bits = optimal_num_bits(1000, 0.01);
        assert!(bits > 0);
        assert!(bits > 1000); // Should be larger than item count

        let hashes = optimal_num_hashes(bits, 1000);
        assert!(hashes > 0);
        assert!(hashes < 20); // Reasonable number of hashes
    }

    #[test]
    fn test_signature_deserialization() {
        let json = r#"{
            "signatures": [
                {
                    "id": 1000001,
                    "message": "Test signature",
                    "content": ["malicious_payload"],
                    "severity": "high",
                    "category": "malware"
                }
            ]
        }"#;

        let sig_file: SignatureFile = serde_json::from_str(json).unwrap();
        assert_eq!(sig_file.signatures.len(), 1);
        assert_eq!(sig_file.signatures[0].id, 1000001);
        assert_eq!(sig_file.signatures[0].severity, "high");
    }

    #[test]
    fn test_load_signatures_missing_file() {
        let engine = SignatureEngine::new();
        let result = engine.load_signatures("/nonexistent/path.json");
        assert!(result.is_err());
    }
}
