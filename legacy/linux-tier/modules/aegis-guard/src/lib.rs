//! # AEGIS Guard — Deterministic Policy Guard & Reflex Engine
//!
//! V2 pure-Rust port of:
//! - V1 `core/aegis/principle_guard.py` — principle checks + CONFIRMATION_REQUIRED
//! - V1 `core/aegis/reflex/engine.py` + `types.py` — scored interference levels with
//!   velocity adjustment
//!
//! ## Guard contract
//!
//! Given a proposed action (name + risk level + optional trust score), the guard
//! returns one of three verdicts:
//!
//! | Verdict          | Meaning                                                            |
//! |------------------|--------------------------------------------------------------------|
//! | `AutoApply`      | Low-impact; the reconciler executes immediately.                  |
//! | `RequireApproval`| High-impact or confirmation-required; human must approve.         |
//! | `Deny`           | Principle violation; **final** — cannot be overridden by anyone.  |
//!
//! **Deny is terminal.** The `TODO(ai-planner)` comment on each `RequireApproval`
//! return marks where the assistive LLM plan attaches; no such hook exists for
//! `Deny` — the planner is never consulted when a principle is violated.
//!
//! ## Reflex contract
//!
//! Maps a per-source QSecBit score (+ velocity dQ/dt) to graduated interference:
//!
//! | Level        | Score range      | Prescribed response              |
//! |--------------|------------------|----------------------------------|
//! | `OBSERVE`    | \[0.00, 0.30)    | `monitor` (XDP pass-through)     |
//! | `JITTER`     | \[0.30, 0.60)    | `add_jitter` (TC 10–500 ms quad) |
//! | `SHADOW`     | \[0.60, 0.85)    | `redirect_to_honeypot` (sockmap) |
//! | `DISCONNECT` | \[0.85, 1.00\]   | `block_ip` (SIGKILL + TCP_RST)   |
//!
//! Velocity `dQ/dt > 0.10/s` escalates one level; `dQ/dt < −0.05/s` de-escalates.
//! Level is clamped to `[OBSERVE, DISCONNECT]`.
//!
//! ## Management-path safety valve (2026-07 audit fix)
//! A `DISCONNECT`/`block_ip` verdict for a source in the mgmt subnet, the LAN gateway, or this
//! device's own WAN address(es) is DOWNGRADED to `OBSERVE`/`monitor` before it is ever returned —
//! see [`evaluate_reflex_with_policy`]. This reuses the exact same allowlist predicate
//! (`hookprobe_mgmt_guard::protect_reason`) `hookprobe-manifest::scan_responder`'s quarantine
//! reflex already applies, so the two enforcement paths can't silently diverge on what "never
//! enforce against this address" means. **Enforcement wiring for `block_ip` itself remains
//! deferred** (no executor currently maps it to a live nft/eBPF action — this fix ensures the
//! safety valve is already in place for whenever that wiring lands).

#![forbid(unsafe_code)]

// ─── Risk Level ────────────────────────────────────────────────────────────────

/// Operator-declared impact of the proposed action.
///
/// Passed by the caller (AEGIS reconciler or operator intent translator) alongside
/// the action name. `High`/`Critical` risk → `RequireApproval` even when the
/// specific action is not in `CONFIRMATION_REQUIRED`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

impl RiskLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            RiskLevel::Low => "low",
            RiskLevel::Medium => "medium",
            RiskLevel::High => "high",
            RiskLevel::Critical => "critical",
        }
    }

    /// Parse a risk level from its lowercase name. Named `parse_str` (not `from_str`) to
    /// avoid shadowing the `std::str::FromStr` trait method.
    pub fn parse_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "low" => Some(RiskLevel::Low),
            "medium" => Some(RiskLevel::Medium),
            "high" => Some(RiskLevel::High),
            "critical" => Some(RiskLevel::Critical),
            _ => None,
        }
    }
}

// ─── Verdict ───────────────────────────────────────────────────────────────────

/// Guard verdict for a proposed action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Low-impact; the reconciler executes immediately without operator involvement.
    AutoApply,

    /// High-impact or confirmation-required.
    ///
    /// The assistive AI planner may suggest a course of action at the
    /// `TODO(ai-planner)` hooks in [`check_action`]. The operator reviews and
    /// explicitly approves before the reconciler applies the action.
    RequireApproval,

    /// Principle violation — **final**.
    ///
    /// The reconciler refuses and logs. The AI planner is **never consulted**
    /// for `Deny` verdicts; the LLM cannot override an immutable principle.
    Deny,
}

impl Verdict {
    pub fn as_str(&self) -> &'static str {
        match self {
            Verdict::AutoApply => "AutoApply",
            Verdict::RequireApproval => "RequireApproval",
            Verdict::Deny => "Deny",
        }
    }
}

// ─── Guard Decision ────────────────────────────────────────────────────────────

/// Outcome of [`check_action`]: verdict + reason + violated principle (when Deny).
#[derive(Debug, Clone)]
pub struct GuardDecision {
    /// The guard's verdict for the proposed action.
    pub verdict: Verdict,

    /// Human-readable reason (surfaces in Mission Control + audit log).
    pub reason: String,

    /// The principle that triggered this outcome (set for `Deny` and for the
    /// `never_block_trusted` `RequireApproval` case; `None` for all other
    /// `AutoApply` / `RequireApproval` outcomes).
    pub principle: Option<&'static str>,
}

// ─── Principles (private static data) ─────────────────────────────────────────

struct Principle {
    /// Machine-readable key (appears in `GuardDecision.principle`).
    key: &'static str,
    /// Human-readable description (appears in `GuardDecision.reason`).
    description: &'static str,
    /// Exact action names (lowercased) that always produce `Deny`.
    blocked_actions: &'static [&'static str],
    /// Keyword-pair patterns: each entry is `(verbs, nouns)`.
    ///
    /// An action matches a pattern if it contains ≥ 1 verb substring **and** ≥ 1
    /// noun substring (case-insensitive `str::contains`). This ports V1's
    /// `re.compile(r"verb\s+noun", re.I).search(action_str)` patterns to
    /// zero-dependency substring matching — conservative (few false negatives)
    /// and correct for underscore-delimited action names.
    blocked_keyword_patterns: &'static [(&'static [&'static str], &'static [&'static str])],
}

/// Immutable principles that produce an absolute `Deny` verdict.
///
/// Port of V1 `IMMUTABLE_PRINCIPLES` (principle_guard.py).
/// Advisory-only principles (`always_explain`, `always_audit`, `minimal_disruption`)
/// are enforced structurally: every `GuardDecision` carries a `reason`; every
/// decision is logged by the caller. They have no keyword blocks.
const DENY_PRINCIPLES: &[Principle] = &[
    Principle {
        key: "never_disable_protection",
        description: "Never disable firewall, IDS, DNS protection, or any security service",
        blocked_actions: &[
            "disable_firewall",
            "stop_qsecbit",
            "stop_dnsxai",
            "disable_ids",
            "stop_napse",
            "disable_protection",
            "disable_reflex",
        ],
        blocked_keyword_patterns: &[(
            &["disable", "stop", "kill", "remove", "shutdown"],
            &[
                "firewall",
                "protection",
                "security",
                "qsecbit",
                "dnsxai",
                "napse",
                "ids",
            ],
        )],
    },
    Principle {
        key: "never_expose_credentials",
        description: "Never expose API keys, passwords, certificates, or tokens",
        blocked_actions: &[
            "show_password",
            "dump_credentials",
            "export_keys",
            "log_token",
        ],
        blocked_keyword_patterns: &[(
            &["show", "display", "print", "log", "send", "expose", "dump"],
            &[
                "password",
                "key",
                "secret",
                "token",
                "credential",
                "certificate",
            ],
        )],
    },
    Principle {
        key: "human_override",
        description: "Humans always have final authority — operator veto cannot be bypassed",
        blocked_actions: &["override_human", "ignore_veto", "bypass_approval"],
        blocked_keyword_patterns: &[],
    },
    Principle {
        key: "never_disable_kernel_safety",
        description:
            "Never deploy eBPF that bypasses the kernel verifier or disables safety mechanisms",
        blocked_actions: &[
            "bypass_verifier",
            "disable_bpf_jit_hardening",
            "load_unverified_bpf",
            // V1 blocked function names (from ebpf_programs.py / principle_guard.py patterns)
            "bpf_probe_write_user",
            "bpf_override_return",
        ],
        blocked_keyword_patterns: &[
            // r"bypass.*verif" — catches bypass_verification, bypass_verif_check, etc.
            (&["bypass"], &["verif"]),
        ],
    },
];

/// Actions that always require human confirmation before execution.
///
/// Port of V1 `CONFIRMATION_REQUIRED` set (principle_guard.py).
const CONFIRMATION_REQUIRED: &[&str] = &[
    "full_quarantine",
    "quarantine_subnet",
    "terminate_session",
    "rotate_wifi",
    "block_ip_permanent",
    "factory_reset",
    "wipe_memory",
    "change_admin_password",
];

/// Blocking actions gated by target trust score (V1 `never_block_trusted` check).
///
/// If any of these actions targets a device with trust score > 80 %, the operator
/// must approve — the reconciler will not auto-block a trusted device.
const BLOCKING_ACTIONS: &[&str] = &[
    "block_ip",
    "quarantine",
    "block_mac",
    "terminate_session",
];

// ─── Guard check ───────────────────────────────────────────────────────────────

/// Check whether a proposed action is safe to execute.
///
/// Faithfully ports V1 `check_action()` (principle_guard.py) to a deterministic,
/// model-free, zero-dependency function.
///
/// # Decision order
///
/// 1. **Absolute principle check** — action matches blocked name or keyword pattern
///    → `Deny` (final; remaining checks are skipped).
/// 2. **Trust-score gate** — blocking action targeting a device with trust score
///    > 80 % → `RequireApproval` (`never_block_trusted`).
/// 3. **Confirmation-required set** — action requires explicit human sign-off
///    → `RequireApproval`.
/// 4. **Risk level gate** — caller declares `High` or `Critical` impact
///    → `RequireApproval`.
/// 5. **Default** — `AutoApply`.
pub fn check_action(action: &str, risk: RiskLevel, trust_score: f64) -> GuardDecision {
    let lower = action.to_lowercase();
    let action_l = lower.as_str();

    // ── 1. Absolute principle violations → Deny ───────────────────────────────
    for p in DENY_PRINCIPLES {
        // Exact action-name match.
        if p.blocked_actions.iter().any(|&ba| ba == action_l) {
            return GuardDecision {
                verdict: Verdict::Deny,
                reason: p.description.to_string(),
                principle: Some(p.key),
            };
        }
        // Keyword-pattern match (verb + noun substrings, V1 regex equivalent).
        for &(verbs, nouns) in p.blocked_keyword_patterns {
            if keyword_matches(action_l, verbs, nouns) {
                return GuardDecision {
                    verdict: Verdict::Deny,
                    reason: p.description.to_string(),
                    principle: Some(p.key),
                };
            }
        }
    }

    // ── 2. Trust-score gate for blocking actions ──────────────────────────────
    // V1: `never_block_trusted` — cannot auto-block a device with trust score
    // > 80 % without human approval. The principle says "without human approval"
    // → RequireApproval (human can authorize); it is NOT an absolute Deny.
    if BLOCKING_ACTIONS.iter().any(|&ba| ba == action_l) && trust_score > 0.8 {
        // TODO(ai-planner): AI planner may suggest an alternative mitigation
        // (e.g. rate-limit or shadow instead of hard-block) for operator review.
        // The planner cannot auto-approve; the operator must explicitly confirm.
        return GuardDecision {
            verdict: Verdict::RequireApproval,
            reason: format!(
                "Cannot auto-block a device with trust score {:.0}% (> 80%). \
                 Human approval required (principle: never_block_trusted).",
                trust_score * 100.0
            ),
            principle: Some("never_block_trusted"),
        };
    }

    // ── 3. Confirmation-required set ─────────────────────────────────────────
    if CONFIRMATION_REQUIRED.iter().any(|&a| a == action_l) {
        // TODO(ai-planner): AI planner may suggest a course of action for the
        // operator to review and approve. Applies only to RequireApproval; Deny
        // verdicts (above) are final and the planner is never invoked for them.
        return GuardDecision {
            verdict: Verdict::RequireApproval,
            reason: "Action is in the confirmation-required set; \
                     human approval needed before execution."
                .to_string(),
            principle: None,
        };
    }

    // ── 4. Risk level gate ────────────────────────────────────────────────────
    if matches!(risk, RiskLevel::High | RiskLevel::Critical) {
        // TODO(ai-planner): AI planner may suggest a course of action for the
        // operator to review. This hook is ONLY present on RequireApproval paths;
        // Deny is final and the planner is never invoked for it.
        return GuardDecision {
            verdict: Verdict::RequireApproval,
            reason: format!(
                "High-impact action (risk={}) requires human approval before execution.",
                risk.as_str()
            ),
            principle: None,
        };
    }

    // ── 5. Default: AutoApply ─────────────────────────────────────────────────
    GuardDecision {
        verdict: Verdict::AutoApply,
        reason: "Action permitted: no principle violations, within impact threshold.".to_string(),
        principle: None,
    }
}

/// Returns `true` if `action` contains ≥ 1 verb substring **and** ≥ 1 noun substring.
///
/// Ports V1 `re.compile(r"verb\s+noun", re.I).search(action_str)` to zero-dependency
/// substring matching. Conservative (security-first): prefers false positives over
/// false negatives.
fn keyword_matches(action: &str, verbs: &[&str], nouns: &[&str]) -> bool {
    verbs.iter().any(|v| action.contains(v)) && nouns.iter().any(|n| action.contains(n))
}

// ─── Reflex Level ──────────────────────────────────────────────────────────────

/// Graduated interference level mapped to QSecBit score ranges.
///
/// Port of V1 `ReflexLevel` enum (core/aegis/reflex/types.py).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ReflexLevel {
    /// Q ∈ \[0.00, 0.30) — XDP pass-through, baseline monitoring.
    Observe = 0,
    /// Q ∈ \[0.30, 0.60) — TC stochastic delay 10–500 ms (quadratic ramp).
    Jitter = 1,
    /// Q ∈ \[0.60, 0.85) — sockmap redirect to Mirage honeypot.
    Shadow = 2,
    /// Q ∈ \[0.85, 1.00\] — `bpf_send_signal(SIGKILL)` + TCP_RST.
    Disconnect = 3,
}

impl ReflexLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            ReflexLevel::Observe => "OBSERVE",
            ReflexLevel::Jitter => "JITTER",
            ReflexLevel::Shadow => "SHADOW",
            ReflexLevel::Disconnect => "DISCONNECT",
        }
    }

    /// Prescribed deterministic response token for this level.
    ///
    /// The executor (running as a container or host service, outside this Wasm binary)
    /// maps these tokens to actual eBPF / iptables / tc operations.
    pub fn response(self) -> &'static str {
        match self {
            ReflexLevel::Observe => "monitor",
            ReflexLevel::Jitter => "add_jitter",
            ReflexLevel::Shadow => "redirect_to_honeypot",
            ReflexLevel::Disconnect => "block_ip",
        }
    }
}

// ─── Reflex constants ──────────────────────────────────────────────────────────

/// Score velocity threshold for escalating one level (V1 `VELOCITY_ESCALATE`).
pub const VELOCITY_ESCALATE: f64 = 0.10;
/// Score velocity threshold for de-escalating one level (V1 `VELOCITY_DEESCALATE`).
pub const VELOCITY_DEESCALATE: f64 = -0.05;

/// Minimum jitter delay (V1 `JITTER_MIN_MS`).
pub const JITTER_MIN_MS: u32 = 10;
/// Maximum jitter delay (V1 `JITTER_MAX_MS`).
pub const JITTER_MAX_MS: u32 = 500;

// Score thresholds (V1 `LEVEL_THRESHOLDS`).
const JITTER_LOWER: f64 = 0.30;
const JITTER_UPPER: f64 = 0.60;
const SHADOW_UPPER: f64 = 0.85;

// ─── Reflex Decision ───────────────────────────────────────────────────────────

/// Outcome of [`evaluate_reflex`]: level + prescribed response + jitter duration.
#[derive(Debug, Clone)]
pub struct ReflexDecision {
    /// The interference level determined for this source.
    pub level: ReflexLevel,
    /// Prescribed deterministic response token (consumed by the executor service).
    pub response: &'static str,
    /// Jitter delay in milliseconds (non-zero only at `Jitter` level).
    pub jitter_ms: u32,
    /// Human-readable reason (surfaces in Mission Control + audit log).
    pub reason: String,
}

// ─── Reflex functions ──────────────────────────────────────────────────────────

/// Map a QSecBit score and velocity to a reflex level.
///
/// Port of V1 `ReflexEngine.score_to_level()` (engine.py):
/// 1. Base level from score thresholds (`LEVEL_THRESHOLDS`).
/// 2. Velocity adjustment ±1 level, clamped to `[Observe, Disconnect]`.
pub fn score_to_level(score: f64, velocity: f64) -> ReflexLevel {
    let base = if score < JITTER_LOWER {
        ReflexLevel::Observe
    } else if score < JITTER_UPPER {
        ReflexLevel::Jitter
    } else if score < SHADOW_UPPER {
        ReflexLevel::Shadow
    } else {
        ReflexLevel::Disconnect
    };

    let v = base as i32;
    let adjusted = if velocity > VELOCITY_ESCALATE {
        (v + 1).min(ReflexLevel::Disconnect as i32)
    } else if velocity < VELOCITY_DEESCALATE {
        (v - 1).max(ReflexLevel::Observe as i32)
    } else {
        v
    };

    match adjusted {
        0 => ReflexLevel::Observe,
        1 => ReflexLevel::Jitter,
        2 => ReflexLevel::Shadow,
        _ => ReflexLevel::Disconnect,
    }
}

/// Compute jitter delay in milliseconds for a QSecBit score.
///
/// Port of V1 `ReflexEngine.compute_jitter()` (engine.py):
/// Quadratic curve — 10 ms at Q = 0.30, 500 ms at Q = 0.60.
/// Score outside the JITTER band is clamped before the quadratic is applied.
pub fn compute_jitter(score: f64) -> u32 {
    let range = JITTER_UPPER - JITTER_LOWER; // 0.30
    let normalized = ((score - JITTER_LOWER) / range).clamp(0.0, 1.0);
    let jitter_f =
        JITTER_MIN_MS as f64 + (JITTER_MAX_MS - JITTER_MIN_MS) as f64 * (normalized * normalized);
    (jitter_f as u32).clamp(JITTER_MIN_MS, JITTER_MAX_MS)
}

/// Evaluate a QSecBit score for a source and produce a reflex decision.
///
/// Port of V1 `ReflexEngine.evaluate()` + `_build_reason()` (engine.py).
///
/// **Stateless**: this function does not track velocity across calls. The caller
/// (Senzorium or the executor service) computes `velocity = dQ/dt` from
/// consecutive score samples and passes it here.
///
/// # Management-path safety valve (2026-07 audit fix)
/// Applies the compiled-in default [`hookprobe_mgmt_guard::ProtectPolicy`] (the mgmt subnet
/// `10.200.0.0/28` + LAN gateway `10.66.0.1` — the same defaults `scan_responder::ProtectPolicy`
/// ships). Use [`evaluate_reflex_with_policy`] directly if the caller has resolved additional
/// live addresses (WAN IP/gateway/DNS resolvers) to protect, matching how the scan-responder
/// wrapper extends its own `ProtectPolicy` at runtime.
pub fn evaluate_reflex(ip: &str, score: f64, velocity: f64) -> ReflexDecision {
    evaluate_reflex_with_policy(ip, score, velocity, &hookprobe_mgmt_guard::ProtectPolicy::default())
}

/// [`evaluate_reflex`] parameterized by an explicit [`hookprobe_mgmt_guard::ProtectPolicy`] —
/// for callers that have resolved live mgmt/gateway/WAN-self addresses beyond the static
/// defaults (mirrors `scan_responder::decide`'s `policy` parameter).
///
/// # The gap this closes (2026-07 on-metal audit)
/// A live device logged reflex verdicts `{"level":"DISCONNECT","response":"block_ip",
/// "ip":"10.200.0.1"}` — targeting the OPERATOR'S OWN mgmt gateway, because a benign audit SSH
/// session looked like brute-force traffic to the scoring layer. This reflex path is advisory
/// only today (nothing wires `block_ip` to an actual nft/eBPF enforcement action yet — see the
/// module doc), so no harm occurred. But the safety invariant must hold regardless of whether an
/// executor is wired up later: a source in the mgmt subnet / at `wan_self_ips` must NEVER be
/// able to reach an enforceable `DISCONNECT`/`block_ip` verdict. This function shares the exact
/// same predicate (`hookprobe_mgmt_guard::protect_reason`) the scan-responder's quarantine path
/// already uses, so the two enforcement paths can't silently diverge on what "protected" means.
///
/// A `DISCONNECT` verdict for a protected address is DOWNGRADED to `OBSERVE` (`monitor`) — never
/// emitted as an enforceable block. Lower levels (`OBSERVE`/`JITTER`/`SHADOW`) are left as
/// scored: they're graduated interference, not a durable block, so they don't carry the same
/// self-lockout hazard the `DISCONNECT`/`block_ip` response does.
///
/// # Enforcement wiring is intentionally OUT of scope here
/// This function does not wire `block_ip` (or any other response token) to a live nft/eBPF
/// action — that remains a separate design decision for the executor service (see the module
/// doc's "Reflex contract" table: "the executor... maps these tokens to actual eBPF/iptables/tc
/// operations"). This fix ensures that WHENEVER that wiring lands, the mgmt-allowlist safety
/// valve is already in place and can't be bypassed by an unprotected `DISCONNECT` verdict.
pub fn evaluate_reflex_with_policy(
    ip: &str,
    score: f64,
    velocity: f64,
    policy: &hookprobe_mgmt_guard::ProtectPolicy,
) -> ReflexDecision {
    let level = score_to_level(score, velocity);

    // Safety valve FIRST: a DISCONNECT verdict for a protected address is downgraded before any
    // jitter/reason computation proceeds on the (now-superseded) level.
    if level == ReflexLevel::Disconnect {
        if let Some(protect_reason) = hookprobe_mgmt_guard::protect_reason(ip, None, policy) {
            let reason = format!(
                "ip={ip} Q={score:.3} \u{2192} DISCONNECT downgraded to OBSERVE: {protect_reason} \
                 (mgmt-path safety valve — a block_ip verdict here would risk self-lockout)"
            );
            return ReflexDecision {
                level: ReflexLevel::Observe,
                response: ReflexLevel::Observe.response(),
                jitter_ms: 0,
                reason,
            };
        }
    }

    let jitter_ms = if level == ReflexLevel::Jitter {
        compute_jitter(score)
    } else {
        0
    };

    // Mirrors V1 `_build_reason()` velocity annotation.
    let vel_note = if velocity > VELOCITY_ESCALATE {
        format!(" (fast rise dQ/dt={velocity:.4})")
    } else if velocity < VELOCITY_DEESCALATE {
        format!(" (rapid decay dQ/dt={velocity:.4})")
    } else {
        String::new()
    };

    let reason = format!("ip={ip} Q={score:.3} \u{2192} {}{vel_note}", level.as_str());

    ReflexDecision {
        level,
        response: level.response(),
        jitter_ms,
        reason,
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Guard: AutoApply ──────────────────────────────────────────────────────

    /// Low-impact action with no principle violations → AutoApply.
    #[test]
    fn low_impact_action_auto_apply() {
        let d = check_action("update_report", RiskLevel::Low, 0.0);
        assert_eq!(
            d.verdict,
            Verdict::AutoApply,
            "low-impact action should AutoApply, got {:?}: {}",
            d.verdict,
            d.reason
        );
    }

    /// Medium-impact action not in any special list → AutoApply.
    #[test]
    fn medium_impact_unknown_action_auto_apply() {
        let d = check_action("refresh_telemetry", RiskLevel::Medium, 0.0);
        assert_eq!(d.verdict, Verdict::AutoApply);
    }

    // ── Guard: RequireApproval — high-impact paths ────────────────────────────

    /// Host isolation at high risk → RequireApproval (risk gate).
    #[test]
    fn host_isolation_high_risk_requires_approval() {
        let d = check_action("isolate_host", RiskLevel::High, 0.0);
        assert_eq!(
            d.verdict,
            Verdict::RequireApproval,
            "host isolation (risk=high) must require approval, got {:?}: {}",
            d.verdict,
            d.reason
        );
    }

    /// Firewall rule application at high risk → RequireApproval (risk gate).
    #[test]
    fn firewall_change_high_risk_requires_approval() {
        let d = check_action("apply_firewall_rule", RiskLevel::High, 0.0);
        assert_eq!(
            d.verdict,
            Verdict::RequireApproval,
            "firewall change (risk=high) must require approval, got {:?}: {}",
            d.verdict,
            d.reason
        );
    }

    /// Block action at high risk (low trust) → RequireApproval (risk gate).
    #[test]
    fn block_high_risk_requires_approval() {
        let d = check_action("block_ip", RiskLevel::High, 0.0);
        assert_eq!(
            d.verdict,
            Verdict::RequireApproval,
            "block_ip (risk=high) must require approval, got {:?}: {}",
            d.verdict,
            d.reason
        );
    }

    /// Critical-risk action → RequireApproval (risk gate).
    #[test]
    fn critical_risk_requires_approval() {
        let d = check_action("reconfigure_routing", RiskLevel::Critical, 0.0);
        assert_eq!(d.verdict, Verdict::RequireApproval);
    }

    /// CONFIRMATION_REQUIRED action at any risk level → RequireApproval.
    #[test]
    fn confirmation_required_action_requires_approval() {
        let d = check_action("full_quarantine", RiskLevel::Medium, 0.0);
        assert_eq!(
            d.verdict,
            Verdict::RequireApproval,
            "full_quarantine must require approval, got {:?}: {}",
            d.verdict,
            d.reason
        );
    }

    /// factory_reset is confirmation-required even at low risk.
    #[test]
    fn factory_reset_requires_approval() {
        let d = check_action("factory_reset", RiskLevel::Low, 0.0);
        assert_eq!(d.verdict, Verdict::RequireApproval);
    }

    /// Block action on a high-trust device (> 80 %) → RequireApproval
    /// (never_block_trusted, not Deny — human can authorize it).
    #[test]
    fn block_high_trust_device_requires_approval() {
        let d = check_action("block_ip", RiskLevel::Medium, 0.9);
        assert_eq!(
            d.verdict,
            Verdict::RequireApproval,
            "blocking high-trust device must be RequireApproval, got {:?}: {}",
            d.verdict,
            d.reason
        );
        assert_eq!(
            d.principle,
            Some("never_block_trusted"),
            "principle should be never_block_trusted"
        );
    }

    /// Block action on a low-trust device at low risk → AutoApply
    /// (automated NAPSE response path).
    #[test]
    fn block_low_trust_device_low_risk_auto_apply() {
        let d = check_action("block_ip", RiskLevel::Low, 0.2);
        assert_eq!(
            d.verdict,
            Verdict::AutoApply,
            "blocking a low-trust device at low risk should AutoApply (NAPSE auto-response)"
        );
    }

    // ── Guard: Deny — principle violations ───────────────────────────────────

    /// disable_firewall is in blocked_actions → Deny (never_disable_protection).
    #[test]
    fn disable_firewall_is_denied() {
        let d = check_action("disable_firewall", RiskLevel::Low, 0.0);
        assert_eq!(
            d.verdict,
            Verdict::Deny,
            "disable_firewall must be Deny, got {:?}: {}",
            d.verdict,
            d.reason
        );
        assert_eq!(d.principle, Some("never_disable_protection"));
    }

    /// stop_napse matched by keyword pattern (stop + napse) → Deny.
    ///
    /// Also in blocked_actions; the blocked_actions check hits first.
    #[test]
    fn stop_napse_is_denied() {
        let d = check_action("stop_napse", RiskLevel::Medium, 0.0);
        assert_eq!(d.verdict, Verdict::Deny);
        assert_eq!(d.principle, Some("never_disable_protection"));
    }

    /// Generic "disable_security_service" matches keyword pattern (disable + security)
    /// → Deny (never_disable_protection), even if not in blocked_actions list.
    #[test]
    fn disable_security_service_pattern_denied() {
        let d = check_action("disable_security_service", RiskLevel::Low, 0.0);
        assert_eq!(
            d.verdict,
            Verdict::Deny,
            "keyword pattern disable+security must Deny, got {:?}: {}",
            d.verdict,
            d.reason
        );
    }

    /// dump_credentials is in blocked_actions → Deny (never_expose_credentials).
    #[test]
    fn dump_credentials_is_denied() {
        let d = check_action("dump_credentials", RiskLevel::Low, 0.0);
        assert_eq!(d.verdict, Verdict::Deny);
        assert_eq!(d.principle, Some("never_expose_credentials"));
    }

    /// expose_token matches keyword pattern (expose + token) → Deny.
    #[test]
    fn expose_token_pattern_denied() {
        let d = check_action("expose_token", RiskLevel::Low, 0.0);
        assert_eq!(d.verdict, Verdict::Deny);
        assert_eq!(d.principle, Some("never_expose_credentials"));
    }

    /// bypass_verifier → Deny (never_disable_kernel_safety).
    #[test]
    fn bypass_verifier_is_denied() {
        let d = check_action("bypass_verifier", RiskLevel::Low, 0.0);
        assert_eq!(d.verdict, Verdict::Deny);
        assert_eq!(d.principle, Some("never_disable_kernel_safety"));
    }

    /// Deny verdict is final: even with risk=Critical, a principle-violating
    /// action is Deny, not RequireApproval.
    #[test]
    fn deny_is_final_not_require_approval() {
        let d = check_action("disable_firewall", RiskLevel::Critical, 0.0);
        // Deny is returned immediately in step 1; the risk gate (step 4) is
        // never reached. The AI planner hook is absent for Deny paths.
        assert_eq!(
            d.verdict,
            Verdict::Deny,
            "Deny must be final even at Critical risk; got {:?}",
            d.verdict
        );
        assert_ne!(
            d.verdict,
            Verdict::RequireApproval,
            "Deny must not downgrade to RequireApproval"
        );
    }

    // ── Reflex: known triggers → expected responses ───────────────────────────

    /// Score Q=0.10 → OBSERVE, response "monitor", jitter_ms=0.
    #[test]
    fn reflex_low_score_observe() {
        let d = evaluate_reflex("192.168.1.1", 0.10, 0.0);
        assert_eq!(d.level, ReflexLevel::Observe);
        assert_eq!(d.response, "monitor");
        assert_eq!(d.jitter_ms, 0);
    }

    /// Score Q=0.45 → JITTER, response "add_jitter", jitter_ms in [10, 500].
    ///
    /// Known value: normalized=(0.45-0.30)/0.30=0.50, jitter=10+490×0.25=132 ms.
    #[test]
    fn reflex_mid_score_jitter() {
        let d = evaluate_reflex("192.168.1.2", 0.45, 0.0);
        assert_eq!(d.level, ReflexLevel::Jitter, "Q=0.45 should be JITTER");
        assert_eq!(d.response, "add_jitter");
        assert!(
            d.jitter_ms >= JITTER_MIN_MS && d.jitter_ms <= JITTER_MAX_MS,
            "jitter_ms out of [10, 500]: {}",
            d.jitter_ms
        );
        // Exact value from the quadratic: 10 + 490 * 0.50^2 = 132.5 → 132
        assert!(
            (d.jitter_ms as i32 - 132).abs() <= 2,
            "expected jitter ~132 ms at Q=0.45, got {}",
            d.jitter_ms
        );
    }

    /// Score Q=0.70 → SHADOW, response "redirect_to_honeypot", jitter_ms=0.
    #[test]
    fn reflex_shadow_score_redirect() {
        let d = evaluate_reflex("10.0.0.3", 0.70, 0.0);
        assert_eq!(d.level, ReflexLevel::Shadow);
        assert_eq!(d.response, "redirect_to_honeypot");
        assert_eq!(d.jitter_ms, 0);
    }

    /// Score Q=0.90 → DISCONNECT, response "block_ip".
    #[test]
    fn reflex_critical_score_disconnect() {
        let d = evaluate_reflex("10.0.0.4", 0.90, 0.0);
        assert_eq!(d.level, ReflexLevel::Disconnect);
        assert_eq!(d.response, "block_ip");
        assert_eq!(d.jitter_ms, 0);
    }

    // ---- Management-path safety valve (2026-07 audit fix) ----------------------------------

    /// The exact live-audit scenario: a DISCONNECT-scoring source in the mgmt subnet
    /// (`10.200.0.0/28`) must be downgraded to OBSERVE, never returned as an enforceable
    /// `block_ip` verdict — this is the self-lockout hazard the audit found.
    #[test]
    fn disconnect_verdict_for_mgmt_subnet_ip_is_downgraded_to_observe() {
        let d = evaluate_reflex("10.200.0.1", 0.95, 0.0);
        assert_eq!(d.level, ReflexLevel::Observe, "must be downgraded, not {:?}", d.level);
        assert_eq!(d.response, "monitor");
        assert_eq!(d.jitter_ms, 0);
        assert!(d.reason.contains("downgraded"), "reason must explain the downgrade: {}", d.reason);
    }

    /// The LAN gateway (`10.66.0.1`, `ProtectPolicy::default()`'s other protected address) gets
    /// the same downgrade.
    #[test]
    fn disconnect_verdict_for_lan_gateway_is_downgraded_to_observe() {
        let d = evaluate_reflex("10.66.0.1", 0.99, 0.0);
        assert_eq!(d.level, ReflexLevel::Observe);
        assert_eq!(d.response, "monitor");
    }

    /// A non-mgmt source scoring DISCONNECT is completely unaffected — the safety valve narrows
    /// to protected addresses only, it does not water down enforcement generally.
    #[test]
    fn disconnect_verdict_for_non_mgmt_ip_stands() {
        let d = evaluate_reflex("203.0.113.7", 0.95, 0.0);
        assert_eq!(d.level, ReflexLevel::Disconnect);
        assert_eq!(d.response, "block_ip");
    }

    /// The downgrade is scoped to DISCONNECT only — a mgmt-subnet source scoring into SHADOW
    /// (graduated interference, not a durable block) is left as scored.
    #[test]
    fn shadow_verdict_for_mgmt_subnet_ip_is_not_downgraded() {
        let d = evaluate_reflex("10.200.0.5", 0.70, 0.0);
        assert_eq!(d.level, ReflexLevel::Shadow, "only DISCONNECT carries the self-lockout hazard");
    }

    /// A caller-supplied policy (e.g. with the live WAN self-IP resolved at runtime, mirroring
    /// `scan_responder::decide`'s `policy` parameter) is honored via `evaluate_reflex_with_policy`.
    #[test]
    fn evaluate_reflex_with_policy_downgrades_an_operator_supplied_wan_self_ip() {
        let policy = hookprobe_mgmt_guard::ProtectPolicy {
            cidrs: vec!["10.200.0.0/28".into()],
            ips: vec!["10.66.0.1".into(), "198.51.100.44".into()],
            lan_macs: Vec::new(),
        };
        let d = evaluate_reflex_with_policy("198.51.100.44", 0.95, 0.0, &policy);
        assert_eq!(d.level, ReflexLevel::Observe, "the live WAN IP, once supplied, must be protected too");
    }

    /// Velocity escalation: score Q=0.28 → base OBSERVE, but dQ/dt=0.15 > 0.10
    /// → escalate one level → JITTER.
    #[test]
    fn reflex_velocity_escalation_bumps_level() {
        let level = score_to_level(0.28, 0.15);
        assert_eq!(
            level,
            ReflexLevel::Jitter,
            "Q=0.28 (OBSERVE base) + velocity=0.15 (> 0.10) must escalate to JITTER"
        );
        let d = evaluate_reflex("10.0.0.5", 0.28, 0.15);
        assert_eq!(d.level, ReflexLevel::Jitter);
        assert!(
            d.reason.contains("fast rise"),
            "reason must note fast rise velocity: {}",
            d.reason
        );
    }

    /// Velocity de-escalation: score Q=0.35 → base JITTER, but dQ/dt=−0.08 < −0.05
    /// → de-escalate one level → OBSERVE.
    #[test]
    fn reflex_velocity_deescalation_drops_level() {
        let level = score_to_level(0.35, -0.08);
        assert_eq!(
            level,
            ReflexLevel::Observe,
            "Q=0.35 (JITTER base) + velocity=-0.08 (< -0.05) must drop to OBSERVE"
        );
        let d = evaluate_reflex("10.0.0.6", 0.35, -0.08);
        assert_eq!(d.level, ReflexLevel::Observe);
        assert!(
            d.reason.contains("rapid decay"),
            "reason must note rapid decay: {}",
            d.reason
        );
    }

    // ── Reflex: jitter quadratic curve ────────────────────────────────────────

    /// At Q=0.30 (lower bound), jitter = JITTER_MIN_MS = 10 ms.
    #[test]
    fn jitter_at_lower_bound_is_min() {
        assert_eq!(compute_jitter(0.30), JITTER_MIN_MS);
    }

    /// At Q=0.60 (upper bound, normalized clamped to 1.0), jitter = JITTER_MAX_MS.
    #[test]
    fn jitter_at_upper_bound_is_max() {
        assert_eq!(compute_jitter(0.60), JITTER_MAX_MS);
    }

    /// Jitter is monotonically non-decreasing within the JITTER band.
    #[test]
    fn jitter_is_monotone_in_band() {
        let scores = [0.30, 0.35, 0.40, 0.45, 0.50, 0.55, 0.60];
        let jitters: Vec<u32> = scores.iter().map(|&s| compute_jitter(s)).collect();
        for w in jitters.windows(2) {
            assert!(
                w[1] >= w[0],
                "jitter must be non-decreasing: {} < {}",
                w[1],
                w[0]
            );
        }
    }

    // ── Reflex: level clamping ────────────────────────────────────────────────

    /// Disconnect + escalation velocity → still Disconnect (clamped at top).
    #[test]
    fn reflex_level_clamped_at_disconnect() {
        let level = score_to_level(0.90, 0.20); // would be DISCONNECT+1 without clamp
        assert_eq!(level, ReflexLevel::Disconnect);
    }

    /// Observe + de-escalation velocity → still Observe (clamped at bottom).
    #[test]
    fn reflex_level_clamped_at_observe() {
        let level = score_to_level(0.10, -0.10); // would be OBSERVE−1 without clamp
        assert_eq!(level, ReflexLevel::Observe);
    }
}
