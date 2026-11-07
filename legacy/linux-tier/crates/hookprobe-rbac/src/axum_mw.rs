//! The axum-facing wiring: one middleware function ([`enforce_middleware`]) both `hookprobe-api`
//! and `hookprobe-planner` install via `axum::middleware::from_fn_with_state`, so the two consumer
//! binaries can never drift on how a request's identity/verb is decided — they only differ in
//! their own per-route [`VerbOf`] table.

use crate::{authorize, AuthDecision, Identity, RolePolicy, TokenStore, Verb};
use axum::{
    body::Body,
    extract::{ConnectInfo, Request, State},
    http::{header, Method, StatusCode},
    middleware::Next,
    response::Response,
};
use serde_json::json;
use std::net::SocketAddr;
use std::sync::Arc;

/// A consumer's own "which verb does this route need?" table. Plain `fn` (not a closure) so
/// [`RbacState`] stays `Send + Sync + 'static` trivially and cheap to clone (it's just a pointer).
///
/// Convention for consumers: default UNMATCHED read (`GET`) routes to [`Verb::View`] (read-only
/// stays broad — ADR 0008's own wording); default unmatched MUTATING routes (anything else) to
/// [`Verb::Configure`] (the highest bar) — a newly added state-changing endpoint that forgets to
/// extend this table fails CLOSED, never open.
pub type VerbOf = fn(&Method, &str) -> Verb;

/// Bundles the parsed policy + token store + this binary's route→verb table behind one `Arc` so
/// `axum::middleware::from_fn_with_state` can clone it per-request for free.
pub struct RbacState {
    policy: RolePolicy,
    tokens: TokenStore,
    verb_of: VerbOf,
}

impl RbacState {
    pub fn new(policy: RolePolicy, tokens: TokenStore, verb_of: VerbOf) -> Arc<RbacState> {
        Arc::new(RbacState { policy, tokens, verb_of })
    }
}

/// Extract `Authorization: Bearer <token>` from a request, if present. Any other/malformed
/// `Authorization` header value is treated as "no bearer token" (falls through to the
/// standalone-permissive-or-deny-remote path in [`authorize`]) rather than a parse error — an
/// unrecognized header shape must never be silently upgraded to "trusted".
fn bearer_token(req: &Request<Body>) -> Option<String> {
    let raw = req.headers().get(header::AUTHORIZATION)?.to_str().ok()?;
    raw.strip_prefix("Bearer ").map(|t| t.trim().to_string()).filter(|t| !t.is_empty())
}

/// Is this request's peer topologically local?
///
/// - `ConnectInfo<SocketAddr>` present (a real TCP `axum::serve(...).into_make_service_with_connect_info::<SocketAddr>()`
///   deployment — see both `hookprobe-api`/`hookprobe-planner`'s `main.rs`): trusted iff the peer
///   IP `.is_loopback()`.
/// - `ConnectInfo` ABSENT: trusted. This covers (a) every existing in-process test in this
///   workspace that drives the router via `tower::ServiceExt::oneshot` without a real socket — so
///   this crate's arrival never turns a passing test into a spurious 401 — and (b) the anti-
///   self-lockout property itself: the one signal this crate trusts to withhold access is a
///   POSITIVELY OBSERVED non-local peer, never the mere absence of plumbing. A future deployment
///   that binds this API beyond loopback MUST wire `ConnectInfo` (both binaries already do) for
///   the "deny unauthenticated remote callers" defense-in-depth to engage — that is a deliberate,
///   documented tradeoff, not an oversight.
fn is_trusted_local(req: &Request<Body>) -> bool {
    match req.extensions().get::<ConnectInfo<SocketAddr>>() {
        Some(ConnectInfo(addr)) => addr.ip().is_loopback(),
        None => true,
    }
}

fn deny_response(status: u16, reason: String) -> Response {
    let code = StatusCode::from_u16(status).unwrap_or(StatusCode::UNAUTHORIZED);
    Response::builder()
        .status(code)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(json!({"error": "rbac_denied", "message": reason}).to_string()))
        .expect("building a JSON error response cannot fail")
}

/// The shared enforcement middleware. Install via:
/// ```ignore
/// router.layer(axum::middleware::from_fn_with_state(rbac_state, hookprobe_rbac::enforce_middleware))
/// ```
/// placed so it runs BEFORE any permissive CORS layer wraps it (i.e. add this layer first, then
/// `.layer(cors)` after, so CORS remains outermost and still decorates denied responses too — see
/// both consumer binaries' `build_router`).
pub async fn enforce_middleware(State(state): State<Arc<RbacState>>, mut req: Request, next: Next) -> Response {
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    let required = (state.verb_of)(&method, &path);
    let bearer = bearer_token(&req);
    let trusted_local = is_trusted_local(&req);

    match authorize(&state.policy, &state.tokens, bearer.as_deref(), trusted_local, required) {
        AuthDecision::Allow { identity, .. } => {
            if let Some(id) = identity {
                req.extensions_mut().insert(IdentityExt(id));
            }
            next.run(req).await
        }
        AuthDecision::Deny { status, reason } => deny_response(status, reason),
    }
}

/// Wrapper so `Identity` (this crate's, not axum's) can be inserted as a request extension without
/// an orphan-rule conflict; handlers that want the caller's identity extract `Extension<IdentityExt>`
/// and read `.0.0`. Neither current consumer's handlers need this yet (verb-level gating already
/// happened in the middleware) — it's here for a future per-tenant-scoped handler to use.
#[derive(Debug, Clone)]
pub struct IdentityExt(pub Identity);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::RolePolicy;
    use axum::{
        routing::{get, post},
        Router,
    };
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    fn test_verb_of(method: &Method, path: &str) -> Verb {
        match (method, path) {
            (&Method::GET, "/read") => Verb::View,
            (&Method::POST, "/configure-only") => Verb::Configure,
            _ => Verb::View,
        }
    }

    async fn ok_handler() -> &'static str {
        "ok"
    }

    fn test_router(tokens: TokenStore) -> Router {
        let state = RbacState::new(RolePolicy::built_in(), tokens, test_verb_of);
        Router::new()
            .route("/read", get(ok_handler))
            .route("/configure-only", post(ok_handler))
            .layer(axum::middleware::from_fn_with_state(state, enforce_middleware))
    }

    async fn call(app: &Router, method: &str, uri: &str, bearer: Option<&str>) -> StatusCode {
        let mut b = axum::http::Request::builder().method(method).uri(uri);
        if let Some(t) = bearer {
            b = b.header(header::AUTHORIZATION, format!("Bearer {t}"));
        }
        let req = b.body(Body::empty()).unwrap();
        app.clone().oneshot(req).await.unwrap().status()
    }

    #[tokio::test]
    async fn standalone_no_connectinfo_no_token_stays_permissive_for_every_route() {
        // Proves the dashboard/UI wiring from the standalone default keeps working: no
        // ConnectInfo (exactly what tower::oneshot in-process calls look like) + no bearer.
        let app = test_router(TokenStore::default());
        assert_eq!(call(&app, "GET", "/read", None).await, StatusCode::OK);
        assert_eq!(call(&app, "POST", "/configure-only", None).await, StatusCode::OK, "standalone-permissive covers Configure-gated routes too, absent any identity");
    }

    #[tokio::test]
    async fn viewer_bearer_cannot_reach_a_configure_gated_route() {
        let tokens = TokenStore::from_plaintext_tokens(&[("viewer-tok", "viewer", "vic")]);
        let app = test_router(tokens);
        assert_eq!(call(&app, "GET", "/read", Some("viewer-tok")).await, StatusCode::OK);
        assert_eq!(call(&app, "POST", "/configure-only", Some("viewer-tok")).await, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn admin_bearer_reaches_the_configure_gated_route() {
        let tokens = TokenStore::from_plaintext_tokens(&[("admin-tok", "admin", "alice")]);
        let app = test_router(tokens);
        assert_eq!(call(&app, "POST", "/configure-only", Some("admin-tok")).await, StatusCode::OK);
    }

    #[tokio::test]
    async fn unknown_bearer_token_is_rejected_with_401() {
        let app = test_router(TokenStore::default());
        assert_eq!(call(&app, "GET", "/read", Some("garbage")).await, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn a_corrupt_empty_token_store_never_locks_out_the_local_no_token_operator() {
        // Anti-self-lockout, exercised through the REAL axum middleware (not just the pure
        // `authorize()` unit test in lib.rs): an empty store (what `TokenStore::load` degrades to
        // on a missing/corrupt tokens.json) must still serve every route absent a bearer token.
        let app = test_router(TokenStore::default());
        for (method, uri) in [("GET", "/read"), ("POST", "/configure-only")] {
            assert_eq!(call(&app, method, uri, None).await, StatusCode::OK, "{method} {uri} must stay open with no identity presented");
        }
    }

    #[tokio::test]
    async fn a_non_loopback_connectinfo_peer_with_no_token_is_denied() {
        let state = RbacState::new(RolePolicy::built_in(), TokenStore::default(), test_verb_of);
        let app = Router::new()
            .route("/read", get(ok_handler))
            .layer(axum::middleware::from_fn_with_state(state, enforce_middleware));

        let remote: SocketAddr = "203.0.113.9:54321".parse().unwrap();
        let mut req = axum::http::Request::builder().method("GET").uri("/read").body(Body::empty()).unwrap();
        req.extensions_mut().insert(ConnectInfo(remote));
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["error"], "rbac_denied");
    }

    #[tokio::test]
    async fn a_loopback_connectinfo_peer_with_no_token_stays_permissive() {
        let state = RbacState::new(RolePolicy::built_in(), TokenStore::default(), test_verb_of);
        let app = Router::new()
            .route("/read", get(ok_handler))
            .layer(axum::middleware::from_fn_with_state(state, enforce_middleware));

        let local: SocketAddr = "127.0.0.1:54321".parse().unwrap();
        let mut req = axum::http::Request::builder().method("GET").uri("/read").body(Body::empty()).unwrap();
        req.extensions_mut().insert(ConnectInfo(local));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }
}
