//! The identity-token seam (ADR 0008's "operators + role bindings + sessions" store, narrowed
//! honestly — see this crate's root doc for the "what's enforced vs still-model" line).
//!
//! **This is NOT a login system.** There is no session issuance, no password check, no MFA, no
//! dashboard user CRUD here — that full IAM surface is ADR 0008's own roadmap ("the dashboard user
//! store on the ENCRYPTED data volume... Argon2id password hashes"), not yet built, and this crate
//! does not fake it. What this module DOES provide is the one seam a real login system needs to
//! plug into: a flat, fail-closed mapping from an opaque bearer token to a role + subject + tenant,
//! loaded from the SAME store path ADR 0008 already names (`/var/lib/hookprobe/rbac/`), so that:
//! - a future dashboard backend can `POST` a freshly-issued session token in here (or write the
//!   file directly) the moment real login lands, with ZERO changes to the enforcement code path
//!   this crate + its axum middleware already exercise and test today;
//! - in the meantime, an operator (or an integration test, or a fleet controller) can hand-place a
//!   `tokens.json` to grant a specific bearer token a specific role, for exactly the "future
//!   dashboard/multi-operator/cloud-linked deployment" case named in the enforcement brief.
//!
//! Tokens are stored **hashed** (SHA-256, hex) — never in the clear on disk — mirroring the spirit
//! of ADR 0008's "Argon2id password hashes" requirement for the (still-roadmap) full user store.
//! SHA-256 rather than Argon2id here is a deliberate, honest choice: these are high-entropy
//! machine-generated bearer tokens (not human passwords), where a fast hash is the correct
//! primitive (Argon2id's slow-hash property defends against low-entropy secrets, which a random
//! 256-bit token never is) — this is the same reasoning GitHub/GitLab PAT storage uses.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;

/// One resolved identity — the caller behind a bearer token, once looked up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    pub subject: String,
    pub role: String,
    pub tenant: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TokenEntry {
    /// `sha256(token)`, hex-encoded lowercase.
    token_sha256: String,
    subject: String,
    role: String,
    #[serde(default)]
    tenant: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct TokenFile {
    #[serde(default)]
    tokens: Vec<TokenEntry>,
}

/// The loaded token → identity table. Deliberately linear-scan (this is an edge device's small,
/// hand-curated operator list, not a multi-tenant SaaS user base — see the module doc for the
/// honest scope) using constant-time comparison per candidate so a timing side-channel can't leak
/// which prefix of a guessed token is correct.
#[derive(Debug, Clone, Default)]
pub struct TokenStore {
    entries: Vec<TokenEntry>,
}

fn sha256_hex(s: &str) -> String {
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    hex::encode(h.finalize())
}

/// Constant-time byte-equality (avoids leaking a match's length-prefix via early-return `==`).
fn ct_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

impl TokenStore {
    /// Load `path` (the ADR 0008 store dir's `tokens.json`). Missing file → an empty store (the
    /// honest, expected default on a standalone device that has never had a second operator
    /// enrolled — every bearer-token lookup then fails closed, which is fine because the
    /// standalone-loopback path never needs a token at all; see [`crate::authorize`]). A present
    /// but unparseable file logs loudly and ALSO degrades to empty (fail-closed, never a panic —
    /// a corrupt token store must never crash the read-API or lock out the local operator, whose
    /// access never goes through this store in the first place).
    pub fn load(path: &Path) -> TokenStore {
        match std::fs::read_to_string(path) {
            Ok(text) => match serde_json::from_str::<TokenFile>(&text) {
                Ok(f) => TokenStore { entries: f.tokens },
                Err(e) => {
                    eprintln!("hookprobe-rbac: {} failed to parse ({e:#}); treating as an empty (fail-closed) token store", path.display());
                    TokenStore::default()
                }
            },
            Err(_) => TokenStore::default(),
        }
    }

    /// `Some(identity)` if `bearer_token`'s hash matches a stored entry; `None` otherwise (unknown
    /// token — the caller must treat this as a hard deny, never a fallback to any other identity).
    pub fn lookup(&self, bearer_token: &str) -> Option<Identity> {
        let hash = sha256_hex(bearer_token);
        self.entries
            .iter()
            .find(|e| ct_eq(&e.token_sha256, &hash))
            .map(|e| Identity { subject: e.subject.clone(), role: e.role.clone(), tenant: e.tenant.clone() })
    }

    /// Build a `TokenStore` directly from `(token, role, subject)` triples — no disk file involved.
    /// Intended for tests (both this crate's own and its consumers', `hookprobe-api`/
    /// `hookprobe-planner`) and for a small, hand-provisioned fleet that wants to seed tokens from
    /// code/config rather than writing `tokens.json` by hand; production's real path is still
    /// [`TokenStore::load`] against the ADR 0008 store file. Tokens are hashed immediately — the
    /// plaintext strings passed in are never retained.
    pub fn from_plaintext_tokens(entries: &[(&str, &str, &str)]) -> TokenStore {
        TokenStore {
            entries: entries
                .iter()
                .map(|(token, role, subject)| TokenEntry {
                    token_sha256: sha256_hex(token),
                    role: role.to_string(),
                    subject: subject.to_string(),
                    tenant: None,
                })
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_file_yields_an_empty_store_never_an_error() {
        let s = TokenStore::load(Path::new("/nonexistent/hookprobe-rbac-test/tokens.json"));
        assert!(s.lookup("anything").is_none());
    }

    #[test]
    fn unparseable_file_degrades_to_empty_never_panics() {
        let dir = std::env::temp_dir().join(format!("hp-rbac-tok-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let bad = dir.join("tokens.json");
        std::fs::write(&bad, "{ not json").unwrap();
        let s = TokenStore::load(&bad);
        assert!(s.lookup("anything").is_none());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn round_trips_a_real_file_and_matches_only_the_right_token() {
        let dir = std::env::temp_dir().join(format!("hp-rbac-tok-test2-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("tokens.json");
        let hash = sha256_hex("s3cr3t-token-value");
        let body = serde_json::json!({
            "tokens": [
                {"token_sha256": hash, "subject": "alice", "role": "analyst", "tenant": "root"}
            ]
        });
        std::fs::write(&path, body.to_string()).unwrap();

        let s = TokenStore::load(&path);
        let id = s.lookup("s3cr3t-token-value").expect("the seeded token must resolve");
        assert_eq!(id.subject, "alice");
        assert_eq!(id.role, "analyst");
        assert_eq!(id.tenant.as_deref(), Some("root"));
        assert!(s.lookup("wrong-token").is_none());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn tokens_are_never_stored_or_matched_in_plaintext() {
        let s = TokenStore::from_plaintext_tokens(&[("abc123", "viewer", "bob")]);
        // the raw token resolves...
        assert!(s.lookup("abc123").is_some());
        // ...but nothing in the struct's debug repr leaks the plaintext token itself.
        assert!(!format!("{s:?}").contains("abc123"));
    }
}
