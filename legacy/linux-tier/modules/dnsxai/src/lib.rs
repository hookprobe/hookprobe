//! # dnsXai — DNS / DGA Anomaly Classifier
//!
//! A pure-Rust heuristic classifier for detecting DGA (Domain Generation
//! Algorithm) domains and DNS tunneling, ported from V1 `shared/dnsXai/engine.py`.
//!
//! ## What V1 dnsXai did
//!
//! V1 dnsXai was a Python-based AI-powered DNS protection system with:
//!
//! - **Lexical feature extraction** (20+ features per domain): length, num_parts,
//!   char distribution, Shannon entropy, n-gram entropy, ad-pattern count, TLD
//!   analysis, subdomain depth, UUID patterns, DGA indicators.
//! - **Ensemble ML classifier**: Neural Network (Input(20) → Hidden(32, ReLU)
//!   → Output(8, Softmax)) combined 40/60 with a LightGBM model, classifying
//!   into 8 categories: LEGITIMATE, ADVERTISING, TRACKING, ANALYTICS,
//!   SOCIAL_TRACKER, MALWARE, CRYPTOMINER, UNKNOWN.
//! - **DGA detection** (`detect_dga`): entropy > 4.0 + vowel ratio < 0.15 +
//!   consonant-cluster regex → combined score ≥ 0.5 → DGA.
//! - **DNS tunneling detection**: long subdomains, base64/hex encoding, high
//!   subdomain entropy.
//! - **CNAME uncloaking**: follow CNAME chains (≤5 levels) and check each
//!   destination against blocklist + ML.
//! - **Multi-tier whitelist**: SYSTEM > ENTERPRISE > USER > ML_LEARNED.
//! - **Bloom filter** over 250 K+ domain blocklist.
//! - **Federated learning**: share model weight deltas, not raw query data.
//!
//! ## V2 approach — heuristic first cut, WASI-NN upgrade path
//!
//! This crate is a **pure-Rust feature-based classifier**: no model file, no
//! inference runtime dependency. It compiles to a ~120 KB stripped Wasm binary.
//! It implements the same feature extraction as V1's `DomainFeatureExtractor` and
//! applies V1's `detect_dga()` thresholds as deterministic scoring rules.
//!
//! **This is honestly heuristic, not ML.** It has the same feature *input* as V1's
//! neural network but uses threshold scoring instead of learned weights.
//! False-positive rate is higher than V1's trained ensemble.
//!
//! ## The ML-tier upgrade path: `dga-lm` (ADR 0014 D1b, supersedes the old ONNX/`edge_ai` plan)
//!
//! The ML upgrade is NOT this module secretly loading a model — it is a *separate,
//! signed, out-of-band* detector fed by the same L7 stream, per the continuous-improvement
//! detection lifecycle (ADR 0014) and the `dga-lm` feasibility scoping:
//!   - **Model:** a char-level classifier (catches dictionary-DGA + lookalikes the char
//!     heuristics below approximate), trained OFF-DEVICE on the accumulated evidence-graph
//!     corpus + CTI, int8-quantized (A72 has no SDOT → quantize for memory, not speed).
//!   - **Delivery:** shipped as a cosign-signed, digest-pinned, model-carded OCI pull —
//!     never self-trained on-device (C9, explainability, trust-nothing-unsigned).
//!   - **Gating:** a new `ml_cpu` capability token (memory-gated, NPU-independent), NOT the
//!     `edge_ai` token (which is NPU+8GB-gated and refused on a Pi 4).
//!   - **Placement:** assistive second tier in the `9_000_000+` `rule_id` band; the
//!     deterministic layer here still enforces.
//!
//! `DomainFeatures::as_tensor()` remains as the feature-extraction seam for that tier.
//! (Historical note: an earlier plan exported V1's LightGBM to ONNX via WASI-NN under
//! `edge_ai`; ADR 0014 D1b supersedes it with the `dga-lm`/`ml_cpu` scoping above.)
//!
//! ## Deterministic gap-closers: lookalike + dictionary DGA (C9, no ML)
//!
//! The entropy/vowel-ratio heuristic above is blind to two false-negative
//! classes confirmed live on-device: **lookalike/typosquat domains**
//! (`goog1e.com`, `paypa1-secure.com`) and **dictionary-DGA domains**
//! (`facilitycompany.net`, matsnu/suppobox-style concatenated real words).
//! Both classes have *normal* entropy/vowel ratios by construction — they use
//! real letters/words, not random ones — so no tuning of the entropy scorer
//! can catch them. Two dedicated, pure-Rust, deterministic detectors close the
//! gap (see [`detect_lookalike`] and [`DomainClassifier::detect_dictionary_dga`]):
//! bounded edit-distance + leetspeak-normalization against a small curated
//! brand list, and a bounded word-segmentation DP against a small curated
//! English word list. Zero new dependencies; the `.wasm` stays small.

#![forbid(unsafe_code)]

use std::collections::{HashMap, HashSet};
use std::fmt;

// ─── Brand-impersonation / dictionary-DGA reference data ──────────────────────
//
// Small, curated, embedded lists — no model file, no network fetch, bounded
// cost (a domain label is only ever compared against these, never against
// arbitrary external data).

/// High-value brands frequently impersonated by phishing/lookalike domains.
/// Deliberately small (~30 entries): [`detect_lookalike`] only runs bounded
/// edit-distance + leetspeak-normalization checks against THIS list, so cost
/// stays O(labels × brands) — cheap, and false-positive-bounded by design.
///
/// Note: a few real-word fragments of some of these brands ("face"/"book",
/// "micro"/"soft", "coin"/"base") are deliberately EXCLUDED from
/// [`COMMON_WORDS`] to avoid the dictionary-DGA segmenter false-flagging the
/// brands' own legitimate domains; [`BENIGN_ALLOWLIST`] is the second line of
/// defense for the collisions that remain (e.g. "sales"+"force").
const IMPERSONATION_BRANDS: &[&str] = &[
    "google", "paypal", "microsoft", "apple", "amazon", "facebook", "netflix",
    "icloud", "instagram", "whatsapp", "twitter", "linkedin", "dropbox", "adobe",
    "ebay", "gmail", "outlook", "chase", "wellsfargo", "bankofamerica", "citibank",
    "americanexpress", "coinbase", "binance", "steam", "playstation", "xbox",
    "spotify", "docusign", "fedex", "ups", "dhl", "usps",
];

/// Suffix/prefix keywords phishing kits compound onto a brand name
/// (`paypal` + `-secure`, `microsoft` + `-update`). A brand+keyword compound
/// with no other lexical similarity to the real brand domain is itself the
/// impersonation signal — this is exactly the pattern `paypa1-secure.com` and
/// `micros0ft-update.com` use.
const PHISHING_KEYWORDS: &[&str] = &[
    "secure", "update", "login", "verify", "verification", "account", "support",
    "confirm", "confirmation", "service", "alert", "billing", "signin",
    "security", "payment", "recovery", "reset", "unlock", "suspended",
    "validate", "validation", "help", "portal", "online", "access", "wallet",
    "invoice", "auth", "authentication", "central",
];

/// Full registrable domains (`sld.tld`) treated as known-good enough to skip
/// the dictionary-DGA segmenter outright. This is the brief's required second
/// gate ("AND the domain isn't on a benign allowlist") — belt-and-suspenders
/// against `COMMON_WORDS` collisions with real brandable/SaaS names (e.g.
/// `salesforce.com` = "sales" + "force", both real English words).
const BENIGN_ALLOWLIST: &[&str] = &[
    "google.com", "cloudflare.com", "github.com", "facebook.com", "amazon.com",
    "microsoft.com", "apple.com", "paypal.com", "wikipedia.org", "netflix.com",
    "instagram.com", "twitter.com", "x.com", "linkedin.com", "youtube.com",
    "reddit.com", "stackoverflow.com", "gmail.com", "outlook.com", "icloud.com",
    "dropbox.com", "spotify.com", "adobe.com", "ebay.com", "whatsapp.com",
    "binance.com", "coinbase.com", "steampowered.com", "docusign.com",
    "wellsfargo.com", "chase.com", "bankofamerica.com", "citibank.com",
    "americanexpress.com", "salesforce.com", "workday.com",
];

/// Common English words (≥4 letters) used to detect matsnu/suppobox-style
/// "dictionary DGA" — malware families that concatenate real words instead of
/// random characters specifically to evade entropy-based detectors
/// (`facilitycompany.net`, `southernproductgroup.com`). ~230 entries curated
/// for generic corporate/business/consumer vocabulary — the observed style of
/// this malware family's generated domains.
///
/// Deliberately EXCLUDES a handful of real words that are brand-name
/// fragments ("face", "book", "micro", "soft", "coin", "base") — see
/// [`IMPERSONATION_BRANDS`] doc note.
const COMMON_WORDS: &[&str] = &[
    // Corporate / entity
    "group", "company", "companies", "facility", "facilities", "corp", "corporation", "holding", "holdings",
    "global", "international", "national", "worldwide", "united", "southern",
    "northern", "eastern", "western", "central", "enterprise", "enterprises",
    "venture", "ventures", "startup", "partners", "partnership", "associates",
    "agency", "consulting", "consultant", "advisory", "firm", "team", "staff",
    "personnel",
    // Services / tech / security
    "service", "services", "solution", "solutions", "systems", "system",
    "network", "networks", "security", "secure", "technology", "technologies",
    "digital", "cyber", "data", "cloud", "computer", "computers", "mobile",
    "wireless", "communication", "communications", "software", "hardware",
    "platform", "portal", "online", "internet",
    // Finance / commerce
    "finance", "financial", "capital", "invest", "investment", "investments",
    "bank", "banking", "credit", "insurance", "market", "markets", "marketing",
    "trade", "trading", "commerce", "wholesale", "retail", "billing", "payment",
    "sales", "force", "loan", "loans", "mortgage", "broker", "brokerage",
    // Health / industry / manufacturing
    "health", "healthcare", "medical", "pharma", "energy", "power", "mining",
    "resources", "resource", "industrial", "industries", "industry",
    "manufacturing", "factory", "supply", "supplier", "suppliers",
    "distribution", "distributor", "warehouse", "storage", "inventory",
    // Logistics
    "logistics", "transport", "transportation", "shipping", "freight", "cargo",
    "delivery", "express", "package", "packaging", "container", "containers",
    "truck", "trucking", "fleet", "vehicle", "vehicles", "auto", "automotive",
    "motor", "motors", "engine", "repair", "maintenance", "garage", "dealer",
    "dealership", "rental", "lease", "leasing", "warranty", "financing",
    // Property / construction
    "property", "properties", "estate", "realty", "construction", "builder",
    "building", "development", "developer", "design", "studio", "creative",
    "house", "home", "plaza", "center", "tower",
    // People / society
    "human", "recruitment", "employment", "career", "careers", "professional",
    "business", "businesses", "management", "manager", "executive",
    "leadership", "director", "president", "chief", "officer",
    "administration", "operations", "quality", "control", "assurance",
    "compliance", "audit", "risk", "safety", "protection", "defense", "guard",
    "guardian", "shield", "emergency", "response", "rescue", "police",
    "military", "federal", "government", "public", "private", "personal",
    "individual", "family", "community", "social", "society", "culture",
    "cultural",
    // Research / education
    "research", "science", "scientific", "academy", "education", "educational",
    "school", "college", "university", "training", "learning", "knowledge",
    "information", "analytics", "insight", "insights", "intelligence",
    "strategy", "strategic", "innovation", "innovative",
    // Media / entertainment
    "entertainment", "news", "press", "publishing", "publisher", "magazine",
    "journal", "article", "content", "video", "audio", "photo", "image",
    "gallery", "museum", "theater", "cinema", "film", "movie", "production",
    "productions", "sound", "broadcast", "channel", "station", "stream",
    "streaming", "game", "games", "gaming", "sport", "sports", "fitness",
    "wellness", "beauty", "fashion", "style", "clothing", "apparel", "jewelry",
    "accessories",
    // Consumer / food / retail
    "flower", "flowers", "garden", "gardening", "plant", "plants", "farm",
    "farming", "agriculture", "food", "foods", "restaurant", "kitchen",
    "cooking", "recipe", "coffee", "wine", "beer", "brewery", "drink",
    "beverage", "grocery", "fresh", "organic", "natural", "product", "products",
    "store", "shop", "world", "work", "works", "workshop",
];

// ─── Public types ─────────────────────────────────────────────────────────────

/// Classification verdict: three-level output mirroring V1's confidence bands.
///
/// V1 thresholds (for the ensemble confidence score 0..1):
/// - > 0.85 → `BLOCK_INSTANT` (our Malicious)
/// - 0.5..0.85 → `ANALYZE_BACKGROUND` (our Suspicious)
/// - < 0.5 → `ALLOW` (our Benign)
///
/// Our heuristic uses tighter thresholds (0.60 / 0.30) because the heuristic
/// scorer is more conservative than the trained model.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Benign,
    Suspicious,
    Malicious,
}

impl fmt::Display for Verdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Verdict::Benign => f.write_str("benign"),
            Verdict::Suspicious => f.write_str("suspicious"),
            Verdict::Malicious => f.write_str("malicious"),
        }
    }
}

/// Domain features extracted from a single query.
///
/// The 12-float layout of [`as_tensor`] is the input vector for the WASI-NN
/// upgrade path. It is a subset of V1's 20-feature vector; the remaining 8
/// features (n-gram entropy, ad-pattern count, subdomain depth, UUID flag,
/// bigram-frequency deviation, dictionary coverage, Levenshtein distance,
/// punycode flag) can be added before the WASI-NN handoff.
///
/// [`as_tensor`]: DomainFeatures::as_tensor
#[derive(Debug, Clone, Default)]
pub struct DomainFeatures {
    // Lexical
    pub total_len: usize,
    pub label_len: usize,       // length of the SLD (second-level label)
    pub num_labels: usize,
    // Character distribution over the SLD
    pub digit_ratio: f32,
    pub vowel_ratio: f32,
    pub consonant_ratio: f32,
    // Entropy
    pub shannon_entropy: f32,
    pub bigram_deviation: f32,  // deviation from English bigram distribution
    // Structural
    pub has_consonant_cluster: bool,  // ≥5 consecutive consonants (V1 DGA pattern)
    pub suspicious_tld: bool,
    // DNS tunneling
    pub max_subdomain_len: usize,     // leftmost label length when ≥3 labels
    pub subdomain_entropy: f32,

    // Deterministic gap-closers (not part of the 12-float WASI-NN tensor above —
    // these are lexical/dictionary matches, not continuous features; they carry
    // their own XAI detail directly into `reasons`).
    /// Brand impersonated via leetspeak/character-substitution or a
    /// brand+phishing-keyword compound (e.g. `Some("paypal")` for
    /// `paypa1-secure.com`). `None` when no curated brand is impersonated.
    pub lookalike_brand: Option<String>,
    /// Dictionary words the label segments into when it looks like a
    /// matsnu/suppobox-style "dictionary DGA" (e.g. `["facility", "company"]`
    /// for `facilitycompany.net`). `None` when no such segmentation qualifies.
    pub dictionary_words: Option<Vec<String>>,
}

impl DomainFeatures {
    /// Produce a 12-float tensor for WASI-NN inference (see module doc for layout).
    pub fn as_tensor(&self) -> [f32; 12] {
        [
            self.total_len as f32,
            self.label_len as f32,
            self.num_labels as f32,
            self.digit_ratio,
            self.vowel_ratio,
            self.consonant_ratio,
            self.shannon_entropy,
            self.bigram_deviation,
            if self.has_consonant_cluster { 1.0 } else { 0.0 },
            if self.suspicious_tld { 1.0 } else { 0.0 },
            self.max_subdomain_len as f32,
            self.subdomain_entropy,
        ]
    }
}

/// Full result returned by [`DomainClassifier::classify`].
#[derive(Debug, Clone)]
pub struct ClassifyResult {
    pub domain: String,
    /// Score in \[0.0, 1.0\]. Higher = more likely malicious.
    pub score: f32,
    pub verdict: Verdict,
    pub features: DomainFeatures,
    /// Reasons driving the score (XAI / "why" panel in Mission Control).
    pub reasons: Vec<String>,
}

// ─── Classifier ───────────────────────────────────────────────────────────────

/// DGA / DNS anomaly classifier.
///
/// Construct once (`DomainClassifier::new()`), reuse across many queries.
/// The classifier is stateless between calls; hot-path allocations are limited
/// to the bigram count map (proportional to domain label length, ≤ ~300 bytes).
pub struct DomainClassifier {
    /// English bigram expected frequencies — used to compute `bigram_deviation`.
    /// Source: V1 `DomainFeatureExtractor.ENGLISH_BIGRAM_FREQ` (50 bigrams).
    english_bigrams: HashMap<[u8; 2], f32>,
    /// TLDs frequently seen in DGA and crimeware infrastructure.
    /// Source: V1 `SUSPICIOUS_TLDS` + OSINT threat-feed cross-reference.
    suspicious_tlds: Vec<Box<str>>,
    /// [`COMMON_WORDS`] as a `HashSet` for O(1) lookups in the dictionary-DGA
    /// word-segmentation DP (built once, reused across `classify()` calls).
    common_words: HashSet<&'static str>,
}

impl DomainClassifier {
    /// Create a classifier with the built-in English bigram table and TLD list.
    pub fn new() -> Self {
        Self {
            english_bigrams: Self::build_bigram_table(),
            suspicious_tlds: Self::build_suspicious_tlds(),
            common_words: COMMON_WORDS.iter().copied().collect(),
        }
    }

    fn build_bigram_table() -> HashMap<[u8; 2], f32> {
        // Top-50 English character bigram frequencies.
        // Source: V1 `DomainFeatureExtractor.ENGLISH_BIGRAM_FREQ` (corpus: standard
        // English text analysis). Used to compute deviation: DGA random strings
        // produce very different bigram distributions from natural English.
        const TABLE: &[([u8; 2], f32)] = &[
            (*b"th", 0.0356), (*b"he", 0.0307), (*b"in", 0.0243), (*b"er", 0.0205),
            (*b"an", 0.0199), (*b"on", 0.0176), (*b"en", 0.0145), (*b"at", 0.0149),
            (*b"es", 0.0145), (*b"ed", 0.0127), (*b"or", 0.0128), (*b"ti", 0.0134),
            (*b"is", 0.0113), (*b"re", 0.0132), (*b"it", 0.0112), (*b"al", 0.0109),
            (*b"ar", 0.0107), (*b"st", 0.0105), (*b"nd", 0.0107), (*b"to", 0.0104),
            (*b"nt", 0.0104), (*b"ng", 0.0095), (*b"se", 0.0093), (*b"ha", 0.0093),
            (*b"as", 0.0087), (*b"ou", 0.0087), (*b"io", 0.0083), (*b"le", 0.0083),
            (*b"ve", 0.0083), (*b"co", 0.0079), (*b"me", 0.0079), (*b"de", 0.0076),
            (*b"hi", 0.0076), (*b"ri", 0.0073), (*b"ro", 0.0073), (*b"ic", 0.0070),
            (*b"ne", 0.0069), (*b"ea", 0.0069), (*b"ra", 0.0069), (*b"ce", 0.0065),
            (*b"li", 0.0062), (*b"ch", 0.0060), (*b"ll", 0.0058), (*b"be", 0.0058),
            (*b"ma", 0.0057), (*b"si", 0.0055), (*b"om", 0.0055), (*b"ur", 0.0054),
            (*b"ca", 0.0053), (*b"el", 0.0053),
        ];
        TABLE.iter().copied().collect()
    }

    fn build_suspicious_tlds() -> Vec<Box<str>> {
        // TLDs over-represented in DGA / crimeware DNS traffic.
        // Source: V1 SUSPICIOUS_TLDS (click, link, trade, party, review, stream,
        // download, racing, cricket, science, gdn, bid) + OSINT additions.
        [
            // V1 originals
            "click", "link", "trade", "party", "review", "stream",
            "download", "racing", "cricket", "science", "gdn", "bid",
            // Free TLDs routinely abused by crimeware (Freenom ecosystem)
            "tk", "ml", "ga", "cf", "gq",
            // High-abuse new gTLDs from threat-feed analysis
            "xyz", "top", "club", "cc", "biz",
        ]
        .iter()
        .map(|&s| s.into())
        .collect()
    }

    /// Extract features from a fully-qualified domain name.
    ///
    /// Mirrors V1 `DomainFeatureExtractor.extract_features()`. The "main label"
    /// is the SLD (second-to-last label for 2+-label domains): for DGA analysis
    /// this is the registered-domain part that the DGA algorithm generates.
    /// DNS tunneling is detected separately via the leftmost label.
    pub fn extract_features(&self, domain: &str) -> DomainFeatures {
        let domain_lower = domain.to_ascii_lowercase();
        let domain_clean = domain_lower.trim_matches('.');

        let labels: Vec<&str> = domain_clean.split('.').collect();
        let num_labels = labels.len();
        let tld = labels.last().copied().unwrap_or("");

        // SLD = second-to-last label (the generated part in DGA domains).
        // For "kq3v9z7x1p2w.com" → "kq3v9z7x1p2w".
        // For "www.google.com"   → "google".
        let main_label = if num_labels >= 2 {
            labels[num_labels - 2]
        } else {
            labels[0]
        };
        let label_len = main_label.len();
        let total_len = domain_clean.len();

        // Character ratios over the SLD only (mirrors V1 extract_features scope).
        let (digit_n, vowel_n, consonant_n) = char_counts(main_label);
        let len_f = label_len.max(1) as f32;
        let digit_ratio = digit_n as f32 / len_f;
        let vowel_ratio = vowel_n as f32 / len_f;
        let consonant_ratio = consonant_n as f32 / len_f;

        let sld_entropy = shannon_entropy(main_label);
        let sld_bigram_dev = self.bigram_deviation(main_label);
        let sld_has_cluster = has_consonant_cluster(main_label, 5);
        let tld_suspicious = self.suspicious_tlds.iter().any(|t| t.as_ref() == tld);

        // DNS tunneling: the leftmost label carries encoded data (V1: len > 50
        // or base64/hex pattern). We record len + entropy; scoring is in score().
        let (max_subdomain_len, sub_entropy) = if num_labels >= 3 {
            let sub = labels[0];
            (sub.len(), shannon_entropy(sub))
        } else {
            (0, 0.0)
        };

        // Deterministic gap-closers: skip both entirely for the benign
        // allowlist (defense in depth against curated-list collisions), else
        // run the lookalike + dictionary-DGA detectors on the SLD.
        let is_allowlisted = BENIGN_ALLOWLIST.contains(&domain_clean);
        let lookalike_brand = if is_allowlisted {
            None
        } else {
            detect_lookalike(main_label)
        };
        let dictionary_words = if is_allowlisted {
            None
        } else {
            self.detect_dictionary_dga(main_label)
        };

        DomainFeatures {
            total_len,
            label_len,
            num_labels,
            digit_ratio,
            vowel_ratio,
            consonant_ratio,
            shannon_entropy: sld_entropy,
            bigram_deviation: sld_bigram_dev,
            has_consonant_cluster: sld_has_cluster,
            suspicious_tld: tld_suspicious,
            max_subdomain_len,
            subdomain_entropy: sub_entropy,
            lookalike_brand,
            dictionary_words,
        }
    }

    /// Classify a domain name.  Returns a score, verdict, and XAI reasons.
    pub fn classify(&self, domain: &str) -> ClassifyResult {
        let features = self.extract_features(domain);
        let (score, reasons) = self.score(&features);
        let verdict = match score {
            s if s >= 0.60 => Verdict::Malicious,
            s if s >= 0.30 => Verdict::Suspicious,
            _ => Verdict::Benign,
        };
        ClassifyResult {
            domain: domain.to_string(),
            score,
            verdict,
            features,
            reasons,
        }
    }

    /// Map extracted features to a score in \[0.0, 1.0\] and a reasons list.
    ///
    /// **Heuristic, not ML.** Weights are derived from V1's `detect_dga()`
    /// thresholds and `dga_combined_score` formula. The WASI-NN upgrade path
    /// replaces this function with a model inference call.
    fn score(&self, f: &DomainFeatures) -> (f32, Vec<String>) {
        let mut score = 0.0f32;
        let mut reasons: Vec<String> = Vec::new();

        // Very short SLDs are virtually never DGA (single-char CCTLDs, abbreviations).
        if f.label_len < 4 {
            return (0.0, vec![format!("short_label:{}", f.label_len)]);
        }

        // ── Shannon entropy ─────────────────────────────────────────────────
        // Random strings have high entropy. V1 threshold: > 4.0 → strong DGA signal.
        // Source: V1 detect_dga(): "entropy > 4.0 → dga_score += 0.3"
        if f.shannon_entropy > 4.0 {
            score += 0.30;
            reasons.push(format!("high_entropy:{:.2}", f.shannon_entropy));
        } else if f.shannon_entropy > 3.5 {
            score += 0.15;
            reasons.push(format!("elevated_entropy:{:.2}", f.shannon_entropy));
        }

        // ── Vowel ratio ─────────────────────────────────────────────────────
        // DGA domains have very few vowels; natural English hovers ~38-42%.
        // V1: "vowel_ratio < 0.15 → dga_score += 0.2". We split into two bands.
        if f.vowel_ratio < 0.10 {
            score += 0.25;
            reasons.push(format!("very_low_vowels:{:.2}", f.vowel_ratio));
        } else if f.vowel_ratio < 0.20 {
            score += 0.15;
            reasons.push(format!("low_vowels:{:.2}", f.vowel_ratio));
        }

        // ── Consonant cluster ───────────────────────────────────────────────
        // V1: r'[bcdfghjklmnpqrstvwxz]{5,}' → dga_score += 0.2
        if f.has_consonant_cluster {
            score += 0.20;
            reasons.push("consonant_cluster_5+".to_string());
        }

        // ── Label length ────────────────────────────────────────────────────
        // DGA domains are usually long. V1: r'^[a-z]{15,}$' and r'^[a-z0-9]{20,}$'.
        if f.label_len >= 20 {
            score += 0.15;
            reasons.push(format!("long_label:{}", f.label_len));
        } else if f.label_len >= 15 {
            score += 0.08;
            reasons.push(format!("elevated_label_len:{}", f.label_len));
        }

        // ── Digit ratio ─────────────────────────────────────────────────────
        // Many digits in the label = DGA fingerprint. V1: r'[0-9]{4,}' for
        // consecutive digits; we use overall ratio as a simpler proxy.
        if f.digit_ratio > 0.40 {
            score += 0.15;
            reasons.push(format!("high_digit_ratio:{:.2}", f.digit_ratio));
        } else if f.digit_ratio > 0.25 {
            score += 0.08;
            reasons.push(format!("elevated_digit_ratio:{:.2}", f.digit_ratio));
        }

        // ── Suspicious TLD ──────────────────────────────────────────────────
        // Adds a small signal; combined with other indicators it tips the verdict.
        if f.suspicious_tld {
            score += 0.10;
            reasons.push("suspicious_tld".to_string());
        }

        // ── DNS tunneling: long / high-entropy subdomains ───────────────────
        // V1 QueryPatternAnalyzer: subdomain len > 50 or base64-like → tunnel.
        // Concretely: > 30 chars is strong signal; 15+ chars with H > 4.0 bits
        // is moderate (base64/hex encoding raises entropy above 4 bits/char).
        if f.max_subdomain_len > 30 {
            score += 0.25;
            reasons.push(format!("long_subdomain:{}", f.max_subdomain_len));
        } else if f.max_subdomain_len > 15 && f.subdomain_entropy > 4.0 {
            score += 0.15;
            reasons.push(format!(
                "high_entropy_subdomain:len={},ent={:.2}",
                f.max_subdomain_len, f.subdomain_entropy
            ));
        }

        // ── Lookalike / typosquat (brand impersonation) ─────────────────────
        // Character-substitution ("goog1e"→google) or brand+phishing-keyword
        // compound ("paypal-secure") impersonation of a curated high-value
        // brand. Entropy/vowel-ratio heuristics are structurally blind to this
        // class (real letters, near-real word) — confirmed false negative on
        // `goog1e.com` / `paypa1-secure.com` / `micros0ft-update.com`
        // (previously 0.00 / 0.00 / 0.23). Bounded to a small brand list, so
        // this is a high-confidence, low-noise signal — score it to land
        // Malicious on its own.
        if let Some(brand) = &f.lookalike_brand {
            score += 0.65;
            reasons.push(format!("lookalike:{brand}"));
        }

        // ── Dictionary DGA (matsnu/suppobox pattern) ─────────────────────────
        // A long label built from ≥2 real English words with no separator
        // ("facilitycompany", "southernproductgroup") — invisible to
        // entropy/vowel-ratio scoring (real words have ordinary entropy and
        // vowel ratios) but is itself a distinct DGA fingerprint. Confirmed
        // false negative on `facilitycompany.net` / `southernproductgroup.com`
        // (previously 0.08 / 0.15).
        if let Some(words) = &f.dictionary_words {
            score += 0.45;
            reasons.push(format!("dictionary_dga:{}", words.join("+")));
        }

        (score.min(1.0), reasons)
    }

    /// Detect matsnu/suppobox-style "dictionary DGA": a long, purely-alphabetic
    /// label that segments into ≥2 real English words (from [`COMMON_WORDS`])
    /// covering most of the label's length, with no separators.
    ///
    /// Approach: a forward DP over label positions that, at each position,
    /// either (a) matches a dictionary word (≥4 chars) ending there — adding
    /// its length to the running "coverage" and one to the running word
    /// count — or (b) skips one character (tolerates a stray non-word
    /// character, e.g. a connector or plural 's', without matching a word).
    /// The DP maximizes coverage; we then require the final coverage ratio to
    /// be ≥80% of the label with 2..=5 words, matching the brief's
    /// "≥2-3 words covering most of its length" tuning. O(label_len × 16) —
    /// cheap for domain-length strings.
    fn detect_dictionary_dga(&self, main_label: &str) -> Option<Vec<String>> {
        const MIN_LABEL_LEN: usize = 12;
        const MIN_WORD_LEN: usize = 4;
        const MAX_WORD_LEN: usize = 16;
        const MIN_COVERAGE_RATIO: f32 = 0.8;
        const MIN_WORDS: usize = 2;
        const MAX_WORDS: usize = 5;

        let n = main_label.len();
        if n < MIN_LABEL_LEN {
            return None;
        }
        // Dictionary words are plain ASCII letters with no separators — a
        // label containing digits/hyphens is the lookalike/leetspeak case,
        // handled separately by `detect_lookalike`, not here.
        if !main_label.bytes().all(|b| b.is_ascii_lowercase()) {
            return None;
        }

        #[derive(Clone, Copy)]
        struct Cell {
            coverage: usize,
            count: usize,
            /// `Some((start, end))` if a dictionary word `label[start..end]`
            /// ends this cell; `None` if this cell was reached by skipping
            /// one character from `i - 1`.
            word: Option<(usize, usize)>,
        }

        let mut dp: Vec<Cell> = vec![
            Cell { coverage: 0, count: 0, word: None };
            n + 1
        ];
        for i in 1..=n {
            // Default transition: skip the character at i-1 (no coverage gained).
            let mut best = Cell {
                coverage: dp[i - 1].coverage,
                count: dp[i - 1].count,
                word: None,
            };
            let max_wlen = i.min(MAX_WORD_LEN);
            for wlen in MIN_WORD_LEN..=max_wlen {
                let start = i - wlen;
                let word = &main_label[start..i];
                if self.common_words.contains(word) {
                    let candidate = Cell {
                        coverage: dp[start].coverage + wlen,
                        count: dp[start].count + 1,
                        word: Some((start, i)),
                    };
                    if candidate.coverage > best.coverage
                        || (candidate.coverage == best.coverage && candidate.count < best.count)
                    {
                        best = candidate;
                    }
                }
            }
            dp[i] = best;
        }

        let last = dp[n];
        if last.count < MIN_WORDS || last.count > MAX_WORDS {
            return None;
        }
        if (last.coverage as f32 / n as f32) < MIN_COVERAGE_RATIO {
            return None;
        }

        // Backtrack the winning path to recover the actual words (for the XAI reason).
        let mut words: Vec<String> = Vec::new();
        let mut i = n;
        while i > 0 {
            match dp[i].word {
                Some((start, end)) => {
                    words.push(main_label[start..end].to_string());
                    i = start;
                }
                None => i -= 1,
            }
        }
        words.reverse();
        Some(words)
    }

    /// Compute the deviation of `s`'s bigram distribution from English.
    ///
    /// Used as an input feature for the WASI-NN tensor; not a direct scoring
    /// signal in the heuristic path (domain-name bigrams frequently deviate
    /// from English even for legitimate brands like "google", "github").
    ///
    /// Source: V1 `_bigram_frequency_deviation()`.
    fn bigram_deviation(&self, s: &str) -> f32 {
        let bytes = s.as_bytes();
        if bytes.len() < 2 {
            return 0.0;
        }
        let total = (bytes.len() - 1) as f32;

        let mut counts: HashMap<[u8; 2], u32> = HashMap::new();
        for pair in bytes.windows(2) {
            *counts.entry([pair[0], pair[1]]).or_insert(0) += 1;
        }

        let mut deviation = 0.0f32;
        let mut unknown = 0u32;
        for (&bigram, &count) in &counts {
            let obs = count as f32 / total;
            match self.english_bigrams.get(&bigram) {
                Some(&exp) => deviation += (obs - exp).abs(),
                None => {
                    deviation += obs;
                    unknown += 1;
                }
            }
        }
        // Penalise bigrams absent from the English corpus.
        deviation += (unknown as f32 / total) * 0.5;
        deviation.min(1.0)
    }
}

impl Default for DomainClassifier {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Free helper functions ────────────────────────────────────────────────────

/// Count (digits, vowels, consonants) in `s` (ASCII lowercase assumed).
///
/// Vowels = a e i o u (matches V1: `sum(c in 'aeiou' for c in domain)`).
/// 'y' and digits are neither vowels in this count.
pub fn char_counts(s: &str) -> (u32, u32, u32) {
    let (mut d, mut v, mut c) = (0u32, 0u32, 0u32);
    for &b in s.as_bytes() {
        if b.is_ascii_digit() {
            d += 1;
        } else if matches!(b, b'a' | b'e' | b'i' | b'o' | b'u') {
            v += 1;
        } else if b.is_ascii_alphabetic() {
            c += 1;
        }
    }
    (d, v, c)
}

/// Shannon entropy of `s`, in bits per symbol.
///
/// Matches V1 `_shannon_entropy()`.
pub fn shannon_entropy(s: &str) -> f32 {
    if s.is_empty() {
        return 0.0;
    }
    let len = s.len() as f32;
    let mut counts = [0u32; 128];
    for &b in s.as_bytes() {
        if (b as usize) < 128 {
            counts[b as usize] += 1;
        }
    }
    let mut h = 0.0f32;
    for &n in &counts {
        if n > 0 {
            let p = n as f32 / len;
            h -= p * p.log2();
        }
    }
    h
}

/// Returns `true` if `s` contains a run of `min_len` or more consecutive
/// ASCII consonants (vowels a e i o u and non-alpha chars break the run).
///
/// Matches V1: `r'[bcdfghjklmnpqrstvwxz]{5,}'` (substring, not anchored).
/// Note: V1's character class excludes 'y'; this implementation includes it
/// as a consonant (the difference does not affect DGA detection accuracy for
/// typical domain names since 'y' is rarely the only non-consonant in a DGA
/// domain).
pub fn has_consonant_cluster(s: &str, min_len: usize) -> bool {
    let mut run = 0usize;
    for &b in s.as_bytes() {
        if b.is_ascii_alphabetic() && !matches!(b, b'a' | b'e' | b'i' | b'o' | b'u') {
            run += 1;
            if run >= min_len {
                return true;
            }
        } else {
            run = 0;
        }
    }
    false
}

/// Replace leetspeak digit substitutions with the letter they impersonate:
/// `0→o, 1→l (or i), 3→e, 4→a, 5→s`. `one_as_i` selects the `1→i` variant
/// (callers try both, since `1` stands in for either letter in the wild —
/// "paypa1" is "paypal" but "f1le" is "file").
///
/// Non-digit characters pass through unchanged. Matches V1's registered-domain
/// scope: only the SLD is normalized, never the TLD.
pub fn leet_normalize(s: &str, one_as_i: bool) -> String {
    s.chars()
        .map(|c| match c {
            '0' => 'o',
            '1' => {
                if one_as_i {
                    'i'
                } else {
                    'l'
                }
            }
            '3' => 'e',
            '4' => 'a',
            '5' => 's',
            other => other,
        })
        .collect()
}

/// Classic Levenshtein (single-character insert/delete/substitute) edit
/// distance between two ASCII-ish strings. Rolling two-row DP — O(n·m) time,
/// O(m) space. Domain labels are short (≤63 bytes by DNS spec, and in
/// practice almost always far shorter), so this is cheap; callers additionally
/// only invoke it against a small (~30-entry) brand list.
pub fn levenshtein(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let (n, m) = (a.len(), b.len());
    if n == 0 {
        return m;
    }
    if m == 0 {
        return n;
    }
    let mut prev: Vec<usize> = (0..=m).collect();
    let mut cur = vec![0usize; m + 1];
    for i in 1..=n {
        cur[0] = i;
        for j in 1..=m {
            let cost = usize::from(a[i - 1] != b[j - 1]);
            cur[j] = (prev[j] + 1).min(cur[j - 1] + 1).min(prev[j - 1] + cost);
        }
        std::mem::swap(&mut prev, &mut cur);
    }
    prev[m]
}

/// Detect brand impersonation in a domain's SLD via three cheap, bounded
/// checks against [`IMPERSONATION_BRANDS`] (leetspeak/character-substitution,
/// near-miss edit distance, and brand+phishing-keyword compounds). Returns
/// the impersonated brand name, or `None` if the label isn't a real brand and
/// doesn't resemble one closely enough to qualify.
///
/// Deliberately conservative: an SLD that already *is* the literal brand name
/// (e.g. `main_label == "google"`) is treated as the legitimate registrant,
/// not a lookalike — this function only flags characters/keywords bolted
/// onto or substituted into a brand name, never the brand name itself.
pub fn detect_lookalike(main_label: &str) -> Option<String> {
    let lower = main_label.to_ascii_lowercase();
    if IMPERSONATION_BRANDS.iter().any(|&b| b == lower) {
        return None; // the real brand's own domain — not a lookalike.
    }

    // Hyphens are a common impersonation separator ("paypal-secure"); fold
    // them out before comparing so "paypa1-secure" normalizes the same way
    // "paypa1secure" would.
    let compact: String = lower.chars().filter(|&c| c != '-').collect();
    // Near-miss edit distance (below) is gated on the label actually
    // containing a leetspeak digit — without this gate it degenerates into a
    // generic alphabetic-typo detector, which false-positives on unrelated
    // real brands that merely sound/look similar (confirmed: "shopify.com"
    // is edit-distance 2 from "spotify" with zero digits involved — not a
    // lookalike, just two different companies). Requiring a digit keeps this
    // branch scoped to the brief's actual ask: digit-for-letter substitution.
    let has_leet_digit = compact.bytes().any(|b| matches!(b, b'0' | b'1' | b'3' | b'4' | b'5'));

    for one_as_i in [false, true] {
        let normalized = leet_normalize(&compact, one_as_i);
        for &brand in IMPERSONATION_BRANDS {
            // 1) Exact character-substitution match across the whole label:
            //    "goog1e" → "google", "micros0ft" → "microsoft".
            if normalized == brand {
                return Some(brand.to_string());
            }
            // 2) Bounded near-miss edit distance for partial/imperfect
            //    leetspeak substitution — only when a digit substitution is
            //    actually present and the lengths are close enough that a
            //    match is possible, keeping this O(labels × brands) cheap.
            if has_leet_digit && (normalized.len() as i32 - brand.len() as i32).abs() <= 1 {
                let d = levenshtein(&normalized, brand);
                if d > 0 && d <= 1 {
                    return Some(brand.to_string());
                }
            }
            // 3) Brand + phishing-keyword compound with no other similarity:
            //    "paypal" + "secure" → "paypalsecure", "microsoft" + "update".
            if normalized.len() > brand.len() {
                if let Some(pos) = normalized.find(brand) {
                    let before = &normalized[..pos];
                    let after = &normalized[pos + brand.len()..];
                    let residual = if before.is_empty() {
                        after
                    } else if after.is_empty() {
                        before
                    } else {
                        "" // brand sandwiched between two non-empty parts — too noisy, skip.
                    };
                    if !residual.is_empty() && PHISHING_KEYWORDS.contains(&residual) {
                        return Some(brand.to_string());
                    }
                }
            }
        }
    }
    None
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn c() -> DomainClassifier {
        DomainClassifier::new()
    }

    // ── DGA / malicious domains ──────────────────────────────────────────────

    /// Random consonant-digit interleaving: no vowels + high digit ratio +
    /// elevated entropy → score ≥ 0.30 (Suspicious or Malicious).
    #[test]
    fn dga_consonant_digit_interleaved() {
        let r = c().classify("kq3v9z7x1p2w.com");
        eprintln!(
            "{}: score={:.2} verdict={} reasons={:?}",
            r.domain, r.score, r.verdict, r.reasons
        );
        assert!(
            r.score >= 0.30,
            "kq3v9z7x1p2w.com: expected score≥0.30, got {:.2}",
            r.score
        );
        assert_ne!(r.verdict, Verdict::Benign);
    }

    /// Conficker-style: 16-character all-consonant lowercase string.
    /// Zero vowels + long consonant cluster + elevated entropy → Malicious.
    #[test]
    fn dga_conficker_style() {
        let r = c().classify("bnxkqvmzprtlsfwy.net");
        eprintln!(
            "{}: score={:.2} verdict={} reasons={:?}",
            r.domain, r.score, r.verdict, r.reasons
        );
        assert!(
            r.score >= 0.30,
            "bnxkqvmzprtlsfwy.net: expected score≥0.30, got {:.2}",
            r.score
        );
        assert_ne!(r.verdict, Verdict::Benign);
    }

    /// CryptoLocker-style: long alternating digit-letter + suspicious TLD.
    /// High entropy + high digit ratio + long label + suspicious TLD → Malicious.
    #[test]
    fn dga_cryptolocker_style() {
        let r = c().classify("a1b2c3d4e5f6g7h8i9j0.xyz");
        eprintln!(
            "{}: score={:.2} verdict={} reasons={:?}",
            r.domain, r.score, r.verdict, r.reasons
        );
        assert!(
            r.score >= 0.30,
            "a1b2c3d4e5f6g7h8i9j0.xyz: expected score≥0.30, got {:.2}",
            r.score
        );
        assert_ne!(r.verdict, Verdict::Benign);
    }

    /// All-consonant high-entropy string — canonical DGA fingerprint.
    /// Zero vowels + long consonant cluster + high entropy + elevated length.
    #[test]
    fn dga_all_consonants_high_entropy() {
        let r = c().classify("xkjqzrvwbmnfptlshg.com");
        eprintln!(
            "{}: score={:.2} verdict={} reasons={:?}",
            r.domain, r.score, r.verdict, r.reasons
        );
        assert!(
            r.score >= 0.30,
            "xkjqzrvwbmnfptlshg.com: expected score≥0.30, got {:.2}",
            r.score
        );
        assert_ne!(r.verdict, Verdict::Benign);
    }

    /// A suspicious TLD alone contributes a small positive signal even when
    /// the domain name itself looks legitimate.
    #[test]
    fn dga_suspicious_tld_adds_signal() {
        let r = c().classify("example.tk");
        eprintln!(
            "{}: score={:.2} reasons={:?}",
            r.domain, r.score, r.reasons
        );
        assert!(
            r.score >= 0.10,
            "suspicious TLD should contribute ≥0.10, got {:.2}",
            r.score
        );
        assert!(r.reasons.contains(&"suspicious_tld".to_string()));
    }

    // ── Benign / legitimate domains ──────────────────────────────────────────

    #[test]
    fn benign_google() {
        let r = c().classify("google.com");
        eprintln!(
            "{}: score={:.2} verdict={} reasons={:?}",
            r.domain, r.score, r.verdict, r.reasons
        );
        assert_eq!(r.verdict, Verdict::Benign, "google.com score={:.2}", r.score);
        assert!(r.score < 0.30);
    }

    #[test]
    fn benign_github() {
        let r = c().classify("github.com");
        eprintln!(
            "{}: score={:.2} verdict={} reasons={:?}",
            r.domain, r.score, r.verdict, r.reasons
        );
        assert_eq!(r.verdict, Verdict::Benign, "github.com score={:.2}", r.score);
    }

    #[test]
    fn benign_wikipedia() {
        let r = c().classify("wikipedia.org");
        eprintln!(
            "{}: score={:.2} verdict={} reasons={:?}",
            r.domain, r.score, r.verdict, r.reasons
        );
        assert_eq!(
            r.verdict,
            Verdict::Benign,
            "wikipedia.org score={:.2}",
            r.score
        );
    }

    #[test]
    fn benign_cloudflare() {
        let r = c().classify("cloudflare.com");
        eprintln!(
            "{}: score={:.2} verdict={} reasons={:?}",
            r.domain, r.score, r.verdict, r.reasons
        );
        assert_eq!(
            r.verdict,
            Verdict::Benign,
            "cloudflare.com score={:.2}",
            r.score
        );
    }

    #[test]
    fn benign_amazon() {
        let r = c().classify("amazon.com");
        eprintln!(
            "{}: score={:.2} verdict={} reasons={:?}",
            r.domain, r.score, r.verdict, r.reasons
        );
        assert_eq!(r.verdict, Verdict::Benign, "amazon.com score={:.2}", r.score);
    }

    // ── Lookalike / typosquat (confirmed live false negatives) ──────────────

    /// Pure leetspeak character substitution across the whole label: `1→l`
    /// makes "goog1e" normalize to the literal brand "google". Confirmed
    /// live-on-Pi false negative (was benign, score 0.00).
    #[test]
    fn lookalike_goog1e() {
        let r = c().classify("goog1e.com");
        eprintln!(
            "{}: score={:.2} verdict={} reasons={:?}",
            r.domain, r.score, r.verdict, r.reasons
        );
        assert_ne!(r.verdict, Verdict::Benign, "goog1e.com score={:.2}", r.score);
        assert!(r.reasons.iter().any(|x| x == "lookalike:google"));
    }

    /// Hyphen + digit-for-letter + phishing-keyword compound: "paypa1" (1→l)
    /// + "-secure". Confirmed live-on-Pi false negative (was benign, 0.00).
    #[test]
    fn lookalike_paypal_secure_hyphenated() {
        let r = c().classify("paypa1-secure.com");
        eprintln!(
            "{}: score={:.2} verdict={} reasons={:?}",
            r.domain, r.score, r.verdict, r.reasons
        );
        assert_ne!(
            r.verdict,
            Verdict::Benign,
            "paypa1-secure.com score={:.2}",
            r.score
        );
        assert!(r.reasons.iter().any(|x| x == "lookalike:paypal"));
    }

    /// Digit-for-letter ("micros0ft", 0→o) + hyphenated phishing keyword
    /// ("-update"). Confirmed live-on-Pi false negative (was benign, 0.23).
    #[test]
    fn lookalike_microsoft_update_hyphenated() {
        let r = c().classify("micros0ft-update.com");
        eprintln!(
            "{}: score={:.2} verdict={} reasons={:?}",
            r.domain, r.score, r.verdict, r.reasons
        );
        assert_ne!(
            r.verdict,
            Verdict::Benign,
            "micros0ft-update.com score={:.2}",
            r.score
        );
        assert!(r.reasons.iter().any(|x| x == "lookalike:microsoft"));
    }

    /// A domain that IS the literal brand must never be flagged as its own
    /// lookalike (the exact-match early-out in `detect_lookalike`).
    #[test]
    fn lookalike_does_not_flag_real_brand_domain() {
        for d in ["google.com", "paypal.com", "microsoft.com", "amazon.com"] {
            let r = c().classify(d);
            assert!(
                !r.reasons.iter().any(|x| x.starts_with("lookalike:")),
                "{d} must not be flagged as its own lookalike: {:?}",
                r.reasons
            );
        }
    }

    /// A near-brand alphabetic name with NO digit substitution (two different,
    /// unrelated real companies) must not be flagged — the near-miss
    /// edit-distance branch is gated on an actual leetspeak digit being
    /// present specifically to avoid this class of false positive.
    #[test]
    fn lookalike_no_digit_no_false_positive() {
        let r = c().classify("shopify.com");
        eprintln!(
            "{}: score={:.2} verdict={} reasons={:?}",
            r.domain, r.score, r.verdict, r.reasons
        );
        assert!(
            !r.reasons.iter().any(|x| x.starts_with("lookalike:")),
            "shopify.com is not a lookalike of spotify: {:?}",
            r.reasons
        );
    }

    // ── Dictionary DGA (matsnu/suppobox pattern; confirmed live false negatives) ──

    /// Two concatenated real words, no separator. Confirmed live-on-Pi false
    /// negative (was benign, score 0.08).
    #[test]
    fn dictionary_dga_facilitycompany() {
        let r = c().classify("facilitycompany.net");
        eprintln!(
            "{}: score={:.2} verdict={} reasons={:?}",
            r.domain, r.score, r.verdict, r.reasons
        );
        assert_ne!(
            r.verdict,
            Verdict::Benign,
            "facilitycompany.net score={:.2}",
            r.score
        );
        assert!(r
            .reasons
            .iter()
            .any(|x| x.starts_with("dictionary_dga:")));
    }

    /// Three concatenated real words, no separator. Confirmed live-on-Pi
    /// false negative (was benign, score 0.15).
    #[test]
    fn dictionary_dga_southernproductgroup() {
        let r = c().classify("southernproductgroup.com");
        eprintln!(
            "{}: score={:.2} verdict={} reasons={:?}",
            r.domain, r.score, r.verdict, r.reasons
        );
        assert_ne!(
            r.verdict,
            Verdict::Benign,
            "southernproductgroup.com score={:.2}",
            r.score
        );
        assert!(r
            .reasons
            .iter()
            .any(|x| x.starts_with("dictionary_dga:")));
    }

    /// The benign allowlist gate must suppress dictionary-DGA scoring even
    /// when a domain's SLD happens to segment into dictionary words that are
    /// deliberately kept in `COMMON_WORDS` for general coverage (`salesforce`
    /// = "sales" + "force", both real English words).
    #[test]
    fn dictionary_dga_allowlist_suppresses_known_collision() {
        let r = c().classify("salesforce.com");
        eprintln!(
            "{}: score={:.2} verdict={} reasons={:?}",
            r.domain, r.score, r.verdict, r.reasons
        );
        assert!(
            !r.reasons
                .iter()
                .any(|x| x.starts_with("dictionary_dga:")),
            "salesforce.com must be suppressed by BENIGN_ALLOWLIST: {:?}",
            r.reasons
        );
    }

    /// Brandable single-real-word-plus-suffix domains must not decompose into
    /// ≥2 dictionary words (github/cloudflare stay benign; word fragments
    /// "git"/"hub" and "flare" are excluded/absent from `COMMON_WORDS`).
    #[test]
    fn dictionary_dga_no_false_positive_on_brandable_names() {
        for d in ["github.com", "cloudflare.com", "google.com"] {
            let r = c().classify(d);
            assert_eq!(
                r.verdict,
                Verdict::Benign,
                "{d} must stay benign, got score={:.2} reasons={:?}",
                r.score,
                r.reasons
            );
        }
    }

    // ── Helper function unit tests ───────────────────────────────────────────

    #[test]
    fn entropy_uniform_string_is_zero() {
        // Every symbol is the same → P(x) = 1 → -1·log2(1) = 0
        assert!(
            shannon_entropy("aaaa").abs() < 1e-3,
            "uniform string entropy should be 0"
        );
    }

    #[test]
    fn entropy_diverse_higher_than_repeated() {
        let e_diverse = shannon_entropy("abcdefghijklmnop");
        let e_repeated = shannon_entropy("ababababababab");
        assert!(
            e_diverse > e_repeated,
            "diverse={e_diverse:.2} should exceed repeated={e_repeated:.2}"
        );
    }

    #[test]
    fn consonant_cluster_detects_long_run() {
        assert!(
            has_consonant_cluster("xkjqzrvwb", 5),
            "xkjqzrvwb has 9 consecutive consonants"
        );
    }

    #[test]
    fn consonant_cluster_not_triggered_by_short_run() {
        assert!(
            !has_consonant_cluster("google", 5),
            "google never has 5 consecutive consonants"
        );
    }

    #[test]
    fn consonant_cluster_vowel_breaks_run() {
        // "strength": s-t-r then vowel 'e', then n-g-t-h → max run = 3 or 4, not ≥5
        assert!(!has_consonant_cluster("strength", 5));
    }

    #[test]
    fn consonant_cluster_boundary_cases() {
        // "abcdfgh": a(v) breaks, then b-c-d-f-g-h = 6 consonants → ≥5 ✓
        assert!(has_consonant_cluster("abcdfgh", 5));
        // "bcdfg" = 5 consonants, min_len=6 → false
        assert!(!has_consonant_cluster("bcdfg", 6));
        // "bcdfgh" = 6 consonants, min_len=6 → true
        assert!(has_consonant_cluster("bcdfgh", 6));
    }

    #[test]
    fn char_counts_correct() {
        // "kq3v9z7x1p2w" → digits: 3,9,7,1,2 = 5; vowels: 0; consonants: k,q,v,z,x,p,w = 7
        let (d, v, c) = char_counts("kq3v9z7x1p2w");
        assert_eq!(d, 5, "digit count");
        assert_eq!(v, 0, "vowel count");
        assert_eq!(c, 7, "consonant count");
    }

    #[test]
    fn leet_normalize_digit_substitutions() {
        assert_eq!(leet_normalize("g00g13", false), "google");
        assert_eq!(leet_normalize("paypa1", false), "paypal");
        assert_eq!(leet_normalize("paypa1", true), "paypai");
        assert_eq!(leet_normalize("micros0ft", false), "microsoft");
        assert_eq!(leet_normalize("4pple", false), "apple");
        assert_eq!(leet_normalize("s3cure", false), "secure");
        assert_eq!(leet_normalize("5ecure", false), "secure");
        // Non-digit characters pass through unchanged.
        assert_eq!(leet_normalize("github", false), "github");
    }

    #[test]
    fn levenshtein_basic_cases() {
        assert_eq!(levenshtein("google", "google"), 0);
        assert_eq!(levenshtein("google", "gooogle"), 1); // one insertion
        assert_eq!(levenshtein("paypal", "paypai"), 1); // one substitution
        assert_eq!(levenshtein("", "abc"), 3);
        assert_eq!(levenshtein("abc", ""), 3);
    }

    #[test]
    fn detect_lookalike_finds_charsub_and_compound() {
        assert_eq!(detect_lookalike("goog1e"), Some("google".to_string()));
        assert_eq!(
            detect_lookalike("micros0ft-update"),
            Some("microsoft".to_string())
        );
        assert_eq!(detect_lookalike("google"), None, "the real brand itself");
        assert_eq!(
            detect_lookalike("shopify"),
            None,
            "unrelated real brand, no digit substitution"
        );
    }
}
