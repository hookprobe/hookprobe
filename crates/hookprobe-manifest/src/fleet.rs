//! Fleet GitOps — pull-based desired-state reconcile (Readme "Fleet & scale").
//!
//! A node PULLS its desired state (`hookprobe.yaml` from Git, or a signed OCI
//! artifact at scale), diffs it against its live manifest + running modules, and
//! the supervisor converges toward it — **drift self-heal**, resilient to
//! intermittent links (pull, never push), works disconnected. Updates promote
//! through health-gated **rollout rings** (canary → ring → fleet).
//!
//! This module is the pure DIFF (desired vs actual); `fleet/agent.sh` is the pull
//! loop that fetches the desired state and feeds the diff into the supervisor.

use serde::Deserialize;

/// Desired state for a node or group (one `hookprobe.yaml`).
#[derive(Debug, Clone, Deserialize, Default)]
pub struct DesiredState {
    #[serde(default)]
    pub channel: Option<String>,
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(default)]
    pub modules: DesiredModules,
    #[serde(default)]
    pub rollout: Rollout,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct DesiredModules {
    #[serde(default)]
    pub enable: Vec<String>,
    #[serde(default)]
    pub disable: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct Rollout {
    /// `canary` | `ring` | `fleet` — which wave this node is in.
    #[serde(default)]
    pub ring: Option<String>,
}

impl DesiredState {
    pub fn parse(yaml: &str) -> anyhow::Result<DesiredState> {
        Ok(serde_yaml::from_str(yaml)?)
    }
}

/// Rollout state (ADR 0012 D2/build-step-3): which rings a promoted digest has
/// reached, for a given channel. Written by the `promote` CI job (or hand-edited
/// during rehearsal) into the desired-state repo alongside `hookprobe.yaml` —
/// `fleet/rollout.yaml` by convention. Nodes read it to know whether THEIR ring is
/// inside the promoted window before treating a channel mismatch as actionable.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct RolloutState {
    /// Calendar version this rollout state describes (ADR 0012 D1), informational.
    #[serde(default)]
    pub version: Option<String>,
    /// The blessed digest this rollout state describes, informational.
    #[serde(default)]
    pub digest: Option<String>,
    /// Rings that have been promoted into for `channel` below, e.g. `[canary]` or
    /// `[canary, ring]`. A ring not listed here is still WAITING (ADR 0012 D2).
    #[serde(default)]
    pub promoted_rings: Vec<String>,
    /// The channel this promotion state applies to (`stable` | `beta`). If a node's
    /// desired channel differs, this rollout state has no evidence for it either way
    /// (see `diff_ring_gated`'s doc comment for how that's handled).
    #[serde(default)]
    pub channel: Option<String>,
}

impl RolloutState {
    pub fn parse(yaml: &str) -> anyhow::Result<RolloutState> {
        Ok(serde_yaml::from_str(yaml)?)
    }
}

/// A single divergence between desired state and the live device.
#[derive(Debug, Clone, PartialEq)]
pub enum Drift {
    ModuleShouldStart(String),
    ModuleShouldStop(String),
    /// Channel drift the agent should act on now (`bootc upgrade`).
    ChannelMismatch { want: String, have: String },
    /// Channel drift EXISTS, but this node's ring is outside the promoted window
    /// for that channel (ADR 0012 D2) — non-actionable: the operator still SEES it
    /// (it doesn't silently vanish), but `fleet/agent.sh` must NOT run `bootc
    /// upgrade` for it. Only `diff_ring_gated` (below) ever produces this variant;
    /// `diff` itself stays pure and never emits it.
    ChannelMismatchPending { want: String, have: String, ring: String },
}
impl Drift {
    pub fn describe(&self) -> String {
        match self {
            Drift::ModuleShouldStart(m) => format!("module '{m}' desired but not running → start"),
            Drift::ModuleShouldStop(m) => format!("module '{m}' running but disabled → stop"),
            Drift::ChannelMismatch { want, have } => {
                format!("channel '{have}' != desired '{want}' → bootc upgrade")
            }
            Drift::ChannelMismatchPending { want, have, ring } => format!(
                "channel '{have}' != desired '{want}' but ring '{ring}' not yet promoted → waiting (no upgrade)"
            ),
        }
    }

    /// Whether the agent should ACT on this drift (start/stop a module, run `bootc
    /// upgrade`). `ChannelMismatchPending` is the one non-actionable variant — it
    /// exists purely so the operator sees "behind, but waiting on your ring", not
    /// nothing (ADR 0012 D2). `fleet/agent.sh` gates its `bootc upgrade` call on this.
    pub fn is_actionable(&self) -> bool {
        !matches!(self, Drift::ChannelMismatchPending { .. })
    }
}

/// Compute drift between the desired state and the device's live facts. The agent
/// applies the result (start/stop modules, schedule a `bootc upgrade`) — health-gated.
/// Pure: no ring-window awareness — see `diff_ring_gated` for that (ADR 0012 D2/D3
/// "keeps `diff()` pure" build step 3).
pub fn diff(desired: &DesiredState, running: &[String], current_channel: &str) -> Vec<Drift> {
    let mut out = Vec::new();
    if let Some(ch) = &desired.channel {
        if ch != current_channel {
            out.push(Drift::ChannelMismatch {
                want: ch.clone(),
                have: current_channel.to_string(),
            });
        }
    }
    for m in &desired.modules.enable {
        if !running.iter().any(|r| r == m) {
            out.push(Drift::ModuleShouldStart(m.clone()));
        }
    }
    for m in &desired.modules.disable {
        if running.iter().any(|r| r == m) {
            out.push(Drift::ModuleShouldStop(m.clone()));
        }
    }
    out
}

/// Ring-gated wrapper around `diff` (ADR 0012 D2/build-step-3). `diff` itself stays
/// pure (desired vs actual only, no rollout awareness); this reads the optional
/// rollout-state file and downgrades a `ChannelMismatch` to the non-actionable
/// `ChannelMismatchPending` when this node's `rollout.ring` has NOT been promoted
/// into yet for the desired channel — so `bootc upgrade` only fires inside the
/// promoted window (canary → ring → fleet), while the operator still sees the
/// pending drift instead of it disappearing.
///
/// Behavior:
/// - `rollout = None` → **legacy behavior**: identical to plain `diff` output, every
///   `ChannelMismatch` stays actionable. This is deliberate — a desired-state repo
///   without `rollout.yaml` (e.g. an older fleet, or a rehearsal setup) must not
///   silently stop upgrading nodes; ring-gating is opt-in via the file's presence.
/// - `rollout = Some(state)` whose `channel` doesn't match the node's desired
///   channel (or has no channel set at all) → this rollout state carries no
///   promoted-ring evidence for what the node actually wants, so it is IGNORED for
///   that computation and the legacy (actionable) behavior applies. A rollout file
///   only ever gates the channel it explicitly names.
/// - `rollout = Some(state)` matching the desired channel → a node with no declared
///   `rollout.ring` defaults to `"fleet"` (the widest, last-promoted ring) — the
///   conservative choice: an undeclared ring never jumps the queue ahead of canary.
pub fn diff_ring_gated(
    desired: &DesiredState,
    running: &[String],
    current_channel: &str,
    rollout: Option<&RolloutState>,
) -> Vec<Drift> {
    let out = diff(desired, running, current_channel);
    let Some(rollout) = rollout else {
        return out; // no rollout.yaml = legacy behavior
    };
    let applies = match (&rollout.channel, &desired.channel) {
        (Some(rc), Some(dc)) => rc == dc,
        _ => false, // either side silent about channel → no evidence, don't gate
    };
    if !applies {
        return out;
    }
    let ring = desired.rollout.ring.as_deref().unwrap_or("fleet");
    out.into_iter()
        .map(|d| match d {
            Drift::ChannelMismatch { want, have } if !rollout.promoted_rings.iter().any(|r| r == ring) => {
                Drift::ChannelMismatchPending { want, have, ring: ring.to_string() }
            }
            other => other,
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Tests — ring-window enforcement (ADR 0012 D2/build-step-3): in-window,
// out-of-window, and the no-rollout-file legacy path.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    fn desired_canary() -> DesiredState {
        DesiredState::parse("channel: stable\nrollout:\n  ring: canary\n").unwrap()
    }

    /// No `rollout.yaml` at all → legacy behavior: ChannelMismatch stays actionable.
    #[test]
    fn no_rollout_file_is_legacy_actionable() {
        let d = desired_canary();
        let drift = diff_ring_gated(&d, &[], "edge", None);
        assert_eq!(
            drift,
            vec![Drift::ChannelMismatch { want: "stable".into(), have: "edge".into() }]
        );
        assert!(drift[0].is_actionable());
    }

    /// Node's ring IS inside `promoted_rings` for the matching channel → actionable.
    #[test]
    fn ring_in_window_is_actionable() {
        let d = desired_canary();
        let rollout = RolloutState::parse(
            "version: '2026.7'\ndigest: sha256:aaa\npromoted_rings: [canary]\nchannel: stable\n",
        )
        .unwrap();
        let drift = diff_ring_gated(&d, &[], "edge", Some(&rollout));
        assert_eq!(
            drift,
            vec![Drift::ChannelMismatch { want: "stable".into(), have: "edge".into() }]
        );
        assert!(drift[0].is_actionable());
    }

    /// Node's ring is NOT inside `promoted_rings` → non-actionable, but still visible.
    #[test]
    fn ring_out_of_window_is_pending_not_actionable() {
        let d = desired_canary(); // ring: canary
        let rollout = RolloutState::parse(
            "version: '2026.7'\ndigest: sha256:aaa\npromoted_rings: [ring]\nchannel: stable\n", // canary NOT listed
        )
        .unwrap();
        let drift = diff_ring_gated(&d, &[], "edge", Some(&rollout));
        assert_eq!(
            drift,
            vec![Drift::ChannelMismatchPending {
                want: "stable".into(),
                have: "edge".into(),
                ring: "canary".into(),
            }]
        );
        assert!(!drift[0].is_actionable());
        assert!(drift[0].describe().contains("not yet promoted"));
    }

    /// A rollout.yaml that describes a DIFFERENT channel than the node wants carries
    /// no evidence either way → falls back to legacy actionable behavior.
    #[test]
    fn rollout_for_a_different_channel_is_ignored() {
        let d = desired_canary(); // wants "stable"
        let rollout = RolloutState::parse(
            "promoted_rings: []\nchannel: beta\n", // beta's rollout says nothing about stable
        )
        .unwrap();
        let drift = diff_ring_gated(&d, &[], "edge", Some(&rollout));
        assert_eq!(
            drift,
            vec![Drift::ChannelMismatch { want: "stable".into(), have: "edge".into() }]
        );
    }

    /// A node with no declared ring defaults to "fleet" (widest/last window) — the
    /// conservative choice: undeclared ring never jumps ahead of canary/ring.
    #[test]
    fn undeclared_ring_defaults_to_fleet_conservatively() {
        let d = DesiredState::parse("channel: stable\n").unwrap(); // no `rollout:` block at all
        let rollout = RolloutState::parse("promoted_rings: [canary, ring]\nchannel: stable\n").unwrap();
        let drift = diff_ring_gated(&d, &[], "edge", Some(&rollout));
        assert_eq!(
            drift,
            vec![Drift::ChannelMismatchPending {
                want: "stable".into(),
                have: "edge".into(),
                ring: "fleet".into(),
            }],
            "fleet ring not yet in promoted_rings → still pending"
        );
    }

    /// Non-channel drift (module start/stop) is untouched by ring-gating.
    #[test]
    fn module_drift_is_unaffected_by_ring_gating() {
        let d = DesiredState::parse("modules:\n  enable: [foo]\n").unwrap();
        let rollout = RolloutState::parse("promoted_rings: []\nchannel: stable\n").unwrap();
        let drift = diff_ring_gated(&d, &[], "stable", Some(&rollout));
        assert_eq!(drift, vec![Drift::ModuleShouldStart("foo".into())]);
    }
}
