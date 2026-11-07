//! `hookprobe-rbac` — the RBAC **enforcement seam** for HookProbe OS (ADR 0008, hardened by ADR
//! 0028).
//!
//! # What this crate is
//!
//! Before this crate, ADR 0008's RBAC was **model-only**: `security/rbac/roles.yaml` was a data
//! file nothing read at runtime, and the read-API (`crates/hookprobe-api`) had "no auth of its
//! own" by design (its own doc comment said so). This crate is the first real enforcement layer:
//! - [`policy::RolePolicy`] parses the REAL `roles.yaml` (embedded at compile time) and resolves
//!   `role × verb → granted?`, fail-closed on any unknown role (matches the file's own
//!   `enforcement.default: deny`).
//! - [`tokens::TokenStore`] maps an opaque bearer token (SHA-256-hashed on disk, never plaintext)
//!   to an [`tokens::Identity`] — the seam a future login/session system plugs into, without
//!   changing any of the enforcement code below it.
//! - [`authorize`] is the one decision function both consumer binaries (`hookprobe-api`,
//!   `hookprobe-planner`) call, via the shared axum middleware in [`axum_mw`].
//!
//! # What this crate is honestly NOT
//!
//! **Not a login system.** No session issuance, no password/MFA check, no dashboard user CRUD —
//! that's ADR 0008's own named roadmap ("the dashboard user store... Argon2id password hashes").
//! Standing up that full IAM surface is out of scope for this pass; faking it here would be
//! dishonest. What ships now is the seam + the decision engine + the two real consumers wired to
//! it, so the day a login system exists, it only needs to WRITE `tokens.json` — zero changes to
//! anything downstream of [`authorize`].
//!
//! # The core invariant — standalone-permissive, enforce-on-identity
//!
//! A HookProbe OS device runs a full local SOC **with no account, ever** (the OS invariant). This
//! crate must never contradict that. [`authorize`] therefore has exactly two triggers for
//! enforcement, and is permissive absent both:
//! - a **bearer token is presented** → always enforced (unknown token = deny; known token with an
//!   insufficient role = deny; sufficient role = allow, identity attached).
//! - the **caller is not local** (a real, non-loopback peer address was observed) → enforced even
//!   with NO token (an unauthenticated remote caller is always denied — defense-in-depth against a
//!   future misconfiguration that binds this API beyond loopback).
//!
//! Absent BOTH signals — no bearer token, and either no peer-address information at all (the
//! in-process test-harness case, and any caller topologically indistinguishable from local) or a
//! genuinely loopback peer — the request is **allowed** with no identity attached. This is the
//! anti-self-lockout property: a misconfigured or missing `roles.yaml`/`tokens.json` can only ever
//! turn INTO a stricter deny for token-bearing/remote callers, never into a lockout of the single,
//! local, no-account operator a standalone device is built around. See `axum_mw`'s tests for the
//! proof.
#![forbid(unsafe_code)]

pub mod axum_mw;
pub mod policy;
pub mod tokens;

pub use axum_mw::{enforce_middleware, RbacState, VerbOf};
pub use policy::{RolePolicy, Verb};
pub use tokens::{Identity, TokenStore};

/// The outcome of one authorization check.
#[derive(Debug, Clone, PartialEq)]
pub enum AuthDecision {
    /// Access is granted. `identity` is `Some` only when a bearer token resolved one; the
    /// standalone-permissive path allows with `None` (no operator identity exists to attach).
    Allow { identity: Option<Identity>, reason: &'static str },
    /// Access is refused. `status` is the HTTP status the caller should respond with (401 for "no
    /// or invalid identity", 403 for "identity known, insufficient role").
    Deny { status: u16, reason: String },
}

/// The one decision function every enforcement point in this OS calls — see the crate root doc for
/// the full standalone-permissive / enforce-on-identity rule this implements.
///
/// `bearer` is the raw token string from an `Authorization: Bearer <token>` header, if any.
/// `trusted_local` is true when the caller is topologically local (a genuine loopback peer, OR no
/// peer-address information was available at all — see `axum_mw::is_trusted_local`'s doc for why
/// the latter is intentional, not a loophole).
pub fn authorize(
    policy: &RolePolicy,
    tokens: &TokenStore,
    bearer: Option<&str>,
    trusted_local: bool,
    required: Verb,
) -> AuthDecision {
    if let Some(tok) = bearer {
        let Some(identity) = tokens.lookup(tok) else {
            return AuthDecision::Deny {
                status: 401,
                reason: "unknown or invalid identity token (ADR 0008 enforcement.default: deny)".to_string(),
            };
        };
        if policy.grants(&identity.role, required) {
            AuthDecision::Allow { identity: Some(identity), reason: "role grant" }
        } else {
            let role = identity.role.clone();
            AuthDecision::Deny {
                status: 403,
                reason: format!("role '{role}' does not grant verb '{required}'"),
            }
        }
    } else if trusted_local {
        AuthDecision::Allow {
            identity: None,
            reason: "standalone-permissive: local caller, no identity presented (no-account-required invariant)",
        }
    } else {
        AuthDecision::Deny {
            status: 401,
            reason: "identity required for non-local access".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn viewer_token_store() -> TokenStore {
        TokenStore::from_plaintext_tokens(&[
            ("viewer-tok", "viewer", "vic"),
            ("admin-tok", "admin", "alice"),
            ("responder-tok", "responder", "rana"),
        ])
    }

    #[test]
    fn standalone_loopback_with_no_token_is_always_allowed() {
        let policy = RolePolicy::built_in();
        let tokens = TokenStore::default();
        let d = authorize(&policy, &tokens, None, true, Verb::Configure);
        assert!(matches!(d, AuthDecision::Allow { identity: None, .. }));
    }

    #[test]
    fn a_corrupt_or_empty_token_store_never_denies_the_local_no_token_caller() {
        // anti-self-lockout: even a totally empty (e.g. never-provisioned, or fell back from a
        // parse error) token store must not affect the local/no-identity path at all.
        let policy = RolePolicy::built_in();
        let empty = TokenStore::default();
        for verb in [Verb::View, Verb::Query, Verb::Respond, Verb::Configure, Verb::ManageUsers] {
            let d = authorize(&policy, &empty, None, true, verb);
            assert!(matches!(d, AuthDecision::Allow { .. }), "verb {verb} must stay open for the local no-token caller");
        }
    }

    #[test]
    fn non_local_caller_with_no_token_is_denied() {
        let policy = RolePolicy::built_in();
        let tokens = TokenStore::default();
        let d = authorize(&policy, &tokens, None, false, Verb::View);
        assert!(matches!(d, AuthDecision::Deny { status: 401, .. }));
    }

    #[test]
    fn unknown_token_is_denied_even_from_a_local_caller() {
        let policy = RolePolicy::built_in();
        let tokens = viewer_token_store();
        let d = authorize(&policy, &tokens, Some("not-a-real-token"), true, Verb::View);
        assert!(matches!(d, AuthDecision::Deny { status: 401, .. }));
    }

    #[test]
    fn viewer_identity_cannot_reach_a_configure_gated_action() {
        let policy = RolePolicy::built_in();
        let tokens = viewer_token_store();
        let d = authorize(&policy, &tokens, Some("viewer-tok"), true, Verb::Configure);
        match d {
            AuthDecision::Deny { status, reason } => {
                assert_eq!(status, 403);
                assert!(reason.contains("viewer"), "reason should name the insufficient role: {reason}");
            }
            other => panic!("expected a 403 deny, got {other:?}"),
        }
    }

    #[test]
    fn admin_identity_grants_the_configure_gated_red_action() {
        let policy = RolePolicy::built_in();
        let tokens = viewer_token_store();
        let d = authorize(&policy, &tokens, Some("admin-tok"), true, Verb::Configure);
        match d {
            AuthDecision::Allow { identity: Some(id), .. } => assert_eq!(id.role, "admin"),
            other => panic!("expected an allow with identity, got {other:?}"),
        }
    }

    #[test]
    fn responder_still_cannot_configure_even_though_it_can_respond() {
        // Verifies the verb model is precise, not "any non-viewer role passes": responder has
        // `respond`/`run-playbook` but NOT `configure` (that's tenant-admin/admin only).
        let policy = RolePolicy::built_in();
        let tokens = viewer_token_store();
        assert!(matches!(
            authorize(&policy, &tokens, Some("responder-tok"), true, Verb::Respond),
            AuthDecision::Allow { .. }
        ));
        assert!(matches!(
            authorize(&policy, &tokens, Some("responder-tok"), true, Verb::Configure),
            AuthDecision::Deny { status: 403, .. }
        ));
    }
}
