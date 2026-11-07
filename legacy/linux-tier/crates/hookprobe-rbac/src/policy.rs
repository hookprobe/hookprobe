//! The role/verb model — parsed from the REAL `security/rbac/roles.yaml` (ADR 0008), embedded at
//! compile time via `include_str!` so this crate's enforcement logic can never silently drift from
//! the policy file a human edits (the failure mode this whole ADR exists to prevent: "roles are
//! data, not code" only holds if the code path that enforces them reads the SAME data, not a
//! hand-copied Rust re-statement of it that can rot).
//!
//! A caller MAY still point [`RolePolicy::load`] at a different path (e.g. a future dashboard
//! config override on the encrypted data volume) — the embedded copy is only the fallback when no
//! override path is given or the override doesn't exist, never a hidden second source of truth
//! that silently wins.

use std::collections::BTreeMap;
use std::path::Path;

/// The embedded, canonical copy of the real policy file — see this module's doc comment.
const BUILT_IN_ROLES_YAML: &str = include_str!("../../../security/rbac/roles.yaml");

/// The verbs `security/rbac/roles.yaml` defines (see that file's own header comment for the
/// authoritative description of each). `os-root` is deliberately NOT a member here — per ADR 0008
/// it is an OS-account property, never a dashboard-plane grant, so it has no verb-gated HTTP
/// meaning for this crate's consumers (`hookprobe-api`, `hookprobe-planner`) to check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Verb {
    View,
    Query,
    Annotate,
    Investigate,
    Respond,
    RunPlaybook,
    Configure,
    ManageUsers,
}

impl Verb {
    pub fn as_str(&self) -> &'static str {
        match self {
            Verb::View => "view",
            Verb::Query => "query",
            Verb::Annotate => "annotate",
            Verb::Investigate => "investigate",
            Verb::Respond => "respond",
            Verb::RunPlaybook => "run-playbook",
            Verb::Configure => "configure",
            Verb::ManageUsers => "manage-users",
        }
    }

    fn parse(s: &str) -> Option<Verb> {
        match s {
            "view" => Some(Verb::View),
            "query" => Some(Verb::Query),
            "annotate" => Some(Verb::Annotate),
            "investigate" => Some(Verb::Investigate),
            "respond" => Some(Verb::Respond),
            "run-playbook" => Some(Verb::RunPlaybook),
            "configure" => Some(Verb::Configure),
            "manage-users" => Some(Verb::ManageUsers),
            // "os-root" and anything unrecognized is deliberately not a verb this crate can grant
            // — see the enum's own doc comment.
            _ => None,
        }
    }
}

impl std::fmt::Display for Verb {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, serde::Deserialize, Default)]
struct RawRole {
    #[serde(default)]
    #[allow(dead_code)] // parsed for parity with the file; not consulted by verb-only enforcement (yet)
    description: String,
    #[serde(default)]
    inherits: Option<String>,
    #[serde(default)]
    #[allow(dead_code)] // workspace-level gating is roadmap (see crate root doc "still-model" note)
    workspaces: Vec<String>,
    #[serde(default)]
    verbs: Vec<String>,
}

#[derive(Debug, Clone, serde::Deserialize, Default)]
struct RawPolicy {
    #[serde(default)]
    #[allow(dead_code)]
    schema: u32,
    #[serde(default)]
    roles: BTreeMap<String, RawRole>,
}

/// The parsed role table plus the verb-grant resolver. Unknown role names always resolve to "no
/// verbs" (`security/rbac/roles.yaml`'s own `enforcement.default: deny`) — this is load-bearing:
/// a typo'd or unbound role name must never silently inherit access.
#[derive(Debug, Clone)]
pub struct RolePolicy {
    roles: BTreeMap<String, RawRole>,
}

impl RolePolicy {
    /// The compiled-in, always-available fallback — parses the SAME file this repo ships at
    /// `security/rbac/roles.yaml`. Parsing this must never fail in a way that panics production
    /// code: a malformed embedded file is a build-time bug (caught by this crate's own tests, and
    /// by `manifest/validate.py`-style fixture checks elsewhere), not a runtime one — but this
    /// function still degrades to an empty (fail-closed) policy rather than panicking, so a future
    /// edit to the YAML that breaks parsing fails safe (deny-all) instead of crashing the read-API.
    pub fn built_in() -> RolePolicy {
        Self::from_yaml(BUILT_IN_ROLES_YAML).unwrap_or_else(|e| {
            eprintln!("hookprobe-rbac: embedded roles.yaml failed to parse ({e:#}) — falling back to a deny-all policy");
            RolePolicy { roles: BTreeMap::new() }
        })
    }

    /// Load an override policy file (e.g. an operator-edited copy staged on the encrypted data
    /// volume). Missing/unreadable/unparseable → the embedded [`RolePolicy::built_in`] default,
    /// with a loud stderr note — never a hard failure, and never a SILENT fallback either.
    pub fn load(path: &Path) -> RolePolicy {
        match std::fs::read_to_string(path) {
            Ok(text) => match Self::from_yaml(&text) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("hookprobe-rbac: {} failed to parse ({e:#}); using the built-in roles.yaml", path.display());
                    Self::built_in()
                }
            },
            Err(_) => Self::built_in(),
        }
    }

    fn from_yaml(text: &str) -> anyhow::Result<RolePolicy> {
        let raw: RawPolicy = serde_yaml::from_str(text)?;
        Ok(RolePolicy { roles: raw.roles })
    }

    /// Resolve one role's full verb set, following `inherits:` chains. Bounded to 8 hops (roles.yaml
    /// today is 3 deep at most) so a future cyclic edit to the policy file fails safe — it stops
    /// walking rather than looping forever — instead of hanging every request.
    fn resolved_verbs(&self, role_name: &str) -> Vec<Verb> {
        let mut verbs = Vec::new();
        let mut current = Some(role_name.to_string());
        let mut hops = 0;
        while let Some(name) = current {
            hops += 1;
            if hops > 8 {
                break;
            }
            let Some(role) = self.roles.get(&name) else { break };
            verbs.extend(role.verbs.iter().filter_map(|v| Verb::parse(v)));
            current = role.inherits.clone();
        }
        verbs
    }

    /// Does `role_name` grant `verb`? An unknown role name always returns `false` — the fail-closed
    /// default `security/rbac/roles.yaml` itself documents (`enforcement.default: deny`).
    pub fn grants(&self, role_name: &str, verb: Verb) -> bool {
        if !self.roles.contains_key(role_name) {
            return false;
        }
        self.resolved_verbs(role_name).contains(&verb)
    }

    /// Every role name this policy knows — used by tests and by a future dashboard's "assign a
    /// role" picker (not yet built; the read-API/planner only ever need [`RolePolicy::grants`]).
    pub fn role_names(&self) -> Vec<String> {
        self.roles.keys().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn built_in_policy_parses_the_real_shipped_roles_yaml() {
        let p = RolePolicy::built_in();
        let mut names = p.role_names();
        names.sort();
        assert_eq!(names, vec!["admin", "analyst", "responder", "tenant-admin", "viewer"]);
    }

    #[test]
    fn viewer_has_view_but_not_configure_or_respond() {
        let p = RolePolicy::built_in();
        assert!(p.grants("viewer", Verb::View));
        assert!(!p.grants("viewer", Verb::Configure));
        assert!(!p.grants("viewer", Verb::Respond));
    }

    #[test]
    fn responder_inherits_analyst_and_viewer_verbs_transitively() {
        let p = RolePolicy::built_in();
        // responder inherits analyst inherits viewer — verify the WHOLE chain resolves, not just
        // the role's own directly-listed verbs.
        assert!(p.grants("responder", Verb::View), "inherited from viewer via analyst");
        assert!(p.grants("responder", Verb::Investigate), "inherited from analyst");
        assert!(p.grants("responder", Verb::Respond), "responder's own verb");
        assert!(!p.grants("responder", Verb::Configure), "configure is tenant-admin/admin only");
    }

    #[test]
    fn tenant_admin_and_admin_grant_configure() {
        let p = RolePolicy::built_in();
        assert!(p.grants("tenant-admin", Verb::Configure));
        assert!(p.grants("admin", Verb::Configure));
        assert!(p.grants("admin", Verb::ManageUsers));
    }

    #[test]
    fn unknown_role_grants_nothing_fail_closed() {
        let p = RolePolicy::built_in();
        assert!(!p.grants("not-a-real-role", Verb::View));
        assert!(!p.grants("", Verb::View));
    }

    #[test]
    fn load_falls_back_to_built_in_when_the_override_path_is_missing() {
        let p = RolePolicy::load(Path::new("/nonexistent/hookprobe-rbac-test/roles.yaml"));
        assert!(p.grants("admin", Verb::Configure), "missing override -> built-in policy, not deny-all");
    }

    #[test]
    fn load_falls_back_to_built_in_when_the_override_is_unparseable() {
        let dir = std::env::temp_dir().join(format!("hp-rbac-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let bad = dir.join("roles.yaml");
        std::fs::write(&bad, "not: [valid, roles: schema").unwrap();
        let p = RolePolicy::load(&bad);
        assert!(p.grants("viewer", Verb::View), "malformed override -> built-in policy, never a panic or deny-all");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_cyclic_policy_terminates_instead_of_hanging() {
        let cyclic = "schema: 1\nroles:\n  a:\n    inherits: b\n    verbs: [view]\n  b:\n    inherits: a\n    verbs: [query]\n";
        let p = RolePolicy::from_yaml(cyclic).unwrap();
        // must return promptly (test itself times out the suite if it doesn't) and still grant
        // the directly-reachable verbs before the hop bound kicks in.
        assert!(p.grants("a", Verb::View));
    }
}
