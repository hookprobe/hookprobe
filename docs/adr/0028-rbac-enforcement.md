# ADR 0028 — RBAC enforcement: the seam, the role/verb model, and the Red-action gate

**Status:** 🟢 Accepted (2026-07-08). Implemented as a working, tested, gate-green first version:
the `hookprobe-rbac` crate (`crates/hookprobe-rbac/`) — a role/verb policy engine parsed straight
from `security/rbac/roles.yaml` (ADR 0008), a bearer-token identity store, and one axum middleware
— wired into BOTH HTTP surfaces this OS exposes to Mission Control (`hookprobe-api`'s read-API and
`hookprobe-planner`'s AEGIS write surface), plus a hardened `rbac-os-check.sh` and a new greenboot
boot-health check. This is honestly scoped: it is the **enforcement seam**, not a full multi-
operator IAM (see Honest limits) — but it is real, tested enforcement, not a second audit script.

**Deciders:** code-developer (author — RBAC/identity/API-auth ownership for this pass),
os-architect (ADR 0008's own role/verb model and store-path contract, reused verbatim),
security-auditor (fail-closed-on-identity / fail-open-on-standalone-loopback boundary review),
ux-architect (Mission Control's dashboard continues to need zero login for the standalone case).

**Relates to:** [ADR 0008](0008-rbac-admin-operator.md) (the role/verb model + admin/operator
split this ADR enforces — status updated alongside this one), [ADR 0025](0025-aegis-byo-llm-planner.md)
(`hookprobe-planner`'s "no auth of its own" limit, closed by this ADR's Red-action gate — that
ADR's Honest-limits line is updated to point here), [ADR 0022](0022-behavioral-quarantine-vs-static-allowlists.md)
(the anti-self-lockout discipline this ADR's standalone-permissive design mirrors — "a
misconfigured enforcement layer must never lock out the operator's own path"), `CLAUDE.md`'s
"no account is ever required to run the device" invariant and contract C9 ("AI proposes, the
deterministic gates enforce... Red = commits, releases, flashing — never autonomous").

## Context

Before this ADR, ADR 0008's RBAC was **model-only**: `security/rbac/roles.yaml` was a policy file
nothing read at runtime. `hookprobe-api`'s own module doc said so explicitly — *"this read-only,
unauthenticated-by-design API"* — and `hookprobe-planner`'s ADR 0025 recorded the same gap
honestly: *"`GET/POST /api/planner/*` has no auth of its own... ADR 0008 RBAC enforcement is still
open."* `rbac-os-check.sh` only audited the OS/dashboard separation (no operator OS account, no
default creds) — a report, never a gate for anything at the HTTP layer, and only partially a gate
even at the OS layer (it hard-failed default credentials but only warned on other violations).

Two invariants bound the design space and cannot be relitigated:
1. **No account is ever required to run the device** (`CLAUDE.md`). A standalone device is a full
   local SOC with a single, local, no-login operator. RBAC enforcement must be **additive** —
   activating for multi-operator/cloud-linked/dashboard-login contexts — never a precondition.
2. **Fail-safe, anti-self-lockout** (the same discipline ADR 0022 already established for the
   enforcement-separation work: *"a misconfigured [enforcement layer] must never lock the operator
   out"*). A missing/corrupt role file or token store must degrade toward MORE access for the local
   operator, never less.

## Decision

Ship `hookprobe-rbac` as the one enforcement seam both HTTP surfaces call, with a single rule:

> **Standalone-loopback stays permissive. Enforcement activates the instant an identity is
> presented, or the caller is observed non-local.**

### D1 — The role/verb model is the REAL `roles.yaml`, embedded — never a second, drifting copy

`hookprobe_rbac::policy::RolePolicy::built_in()` parses `security/rbac/roles.yaml` via
`include_str!` at compile time (`crates/hookprobe-rbac/src/policy.rs`) — the exact file ADR 0008
shipped as a data-only artifact. There is no hand-written Rust re-statement of
`viewer < analyst < responder < tenant-admin < admin` to fall out of sync with the YAML; a future
edit to the policy file changes enforcement the next time this crate is rebuilt, and this crate's
own test (`built_in_policy_parses_the_real_shipped_roles_yaml`) asserts against the real role
names, not a fixture. `RolePolicy::load(path)` additionally supports an override file (e.g. a
future dashboard-managed copy on the encrypted data volume); missing/unparseable → falls back to
the embedded default, loudly, never silently.

Verb resolution follows `inherits:` chains (`responder` → `analyst` → `viewer`), bounded to 8 hops
so a cyclic edit to the policy fails safe (stops walking) instead of hanging every request. An
**unknown role name grants nothing** — `roles.yaml`'s own `enforcement.default: deny` line, made
real (`policy::tests::unknown_role_grants_nothing_fail_closed`).

### D2 — Identity is a bearer token → role/subject/tenant mapping, honestly scoped

`hookprobe_rbac::tokens::TokenStore` loads `/var/lib/hookprobe/rbac/tokens.json` (ADR 0008's own
store path) — a flat list of `{token_sha256, subject, role, tenant}` entries. Tokens are hashed
(SHA-256) on disk, matching the spirit of ADR 0008's "Argon2id password hashes" requirement for the
full user store (SHA-256 rather than Argon2id is the correct primitive for a high-entropy
machine-generated bearer token, not a human password — the module doc explains the reasoning).
Missing/corrupt file → an empty store (every token lookup then fails closed) — this NEVER affects
the standalone-loopback-no-token path, because that path never consults the token store at all
(see D3). This is deliberately **not** a login/session system: no issuance, no password check, no
MFA, no dashboard user CRUD. It is the seam a real login system writes into, so the day one exists,
zero changes are needed downstream of `authorize()`.

### D3 — The one decision function, and its anti-self-lockout proof

```rust
pub fn authorize(policy: &RolePolicy, tokens: &TokenStore, bearer: Option<&str>,
                  trusted_local: bool, required: Verb) -> AuthDecision {
    if let Some(tok) = bearer {
        match tokens.lookup(tok) {
            None => Deny(401, "unknown or invalid identity token"),
            Some(id) if policy.grants(&id.role, required) => Allow(Some(id)),
            Some(id) => Deny(403, "role '{id.role}' does not grant verb '{required}'"),
        }
    } else if trusted_local {
        Allow(None)   // standalone-permissive: no account required
    } else {
        Deny(401, "identity required for non-local access")
    }
}
```

`trusted_local` is true for a genuine loopback peer, **and** for the absence of any peer-address
information at all (`ConnectInfo` not present — the shape of every existing in-process
`tower::ServiceExt::oneshot` test in this workspace, and any deployment topology that doesn't wire
`ConnectInfo`). This is the deliberate anti-self-lockout choice: the only signal this crate ever
treats as grounds to deny is a **positively observed** non-loopback peer or a **presented and
invalid/insufficient** identity — never the mere absence of plumbing. A corrupt `roles.yaml`
override, an empty/missing `tokens.json`, or a deployment that never wires `ConnectInfo` can only
ever make enforcement MORE permissive for the local, no-account operator, never less — proven by
`a_corrupt_or_empty_token_store_never_denies_the_local_no_token_caller` (crate root) and its axum
middleware companion `a_corrupt_empty_token_store_never_locks_out_the_local_no_token_operator`.

### D4 — One shared axum middleware, two consumers, two verb tables

`hookprobe_rbac::axum_mw::enforce_middleware` is installed via
`axum::middleware::from_fn_with_state` in both `hookprobe-api::build_router` and
`hookprobe-planner`'s `build_router`, placed to run **before** the outer, permissive `CorsLayer` (so
CORS still decorates a 401/403 response, and OPTIONS preflight never reaches the auth check). Each
binary supplies its own `VerbOf` (`fn(&Method, &str) -> Verb`) — a plain function pointer, not a
closure, so `RbacState` stays trivially `Send + Sync + Clone`-via-`Arc`:

- **`hookprobe-api`** (`crates/hookprobe-api/src/lib.rs::required_verb`): every route is `Verb::View`
  — the whole API is read-only **by construction** (`EvidenceGraph::open_readonly`), and `viewer`
  (the least-privileged role) already covers the workspaces it backs (observe/detect/investigate/
  intelligence/business). "Read-only stays broad" (ADR 0008's own wording) — no per-endpoint table
  to keep in sync by hand.
- **`hookprobe-planner`** (`crates/hookprobe-planner/src/main.rs::required_verb`): `GET /status` →
  `Verb::View`; `POST /propose` and `POST /incidents/{id}/explain` → `Verb::Investigate` (analyst+ —
  SOC tier-1/2 already has this verb); **`POST /approve` → `Verb::Configure`** (tenant-admin/admin
  only) — **the Red-action gate** (D5). Any future, currently-unmapped mutating route defaults to
  `Verb::Configure` — fail-closed to the highest bar, not the lowest, for anything this table
  forgets to classify.

### D5 — The Red-action gate: a non-admin identity cannot approve a plan-as-diff

Per C9 ("Red = commits, releases, flashing — never autonomous") and the operator's own framing of
this task ("confirm/enforce that a non-admin identity cannot approve an AEGIS plan-as-diff"):
`POST /api/planner/approve` — staging a previously-proposed AEGIS plan-as-diff's artifacts for
operator review (ADR 0025 D5; still not a live apply, unchanged by this ADR) — now requires the
`configure` verb, which `security/rbac/roles.yaml` grants only to `tenant-admin` and `admin`.
`rbac_a_viewer_identity_cannot_approve_a_plan_as_diff` proves a `viewer` bearer gets `403` on
`/approve` while the SAME identity reaches `/status` (`view`-gated) fine;
`rbac_an_admin_identity_can_approve_a_plan_as_diff` proves the gate is precise, not a blanket
lockout, once RBAC is wired in. `rbac_standalone_loopback_can_still_approve_with_no_identity` proves
the standalone, no-account device keeps approving its own proposals exactly as before this ADR.

Actual OS-level Red actions — commits, releases, flashing — are already structurally unreachable
from any dashboard role, by ADR 0008's own "operators get no OS account, ever" design: no HTTP
endpoint in this OS *performs* a commit/release/flash, and no dashboard role has a code path to a
shell. This ADR does not need to (and does not) add a second gate for something the OS/dashboard
split already makes impossible by construction — it only needed to close the ONE dashboard-reachable
action that functions as an approval gate today, `/api/planner/approve`.

### D6 — `rbac-os-check.sh`: promoted from partial-audit to a real gate

`base/scripts/rbac-os-check.sh` already hard-failed (§4) on default/debug credential accounts on a
release image. This ADR promotes check §1 — **any non-admin OS login account** — to the SAME
hard-fail treatment on release images (`mode != debug`): a non-admin OS account existing is not a
lesser finding than a default password, it is a direct violation of ADR 0008's own load-bearing
claim ("operators get no OS account, ever") on a *release* artifact, and now blocks exactly like the
credential check does. The audit-only checks (disk-key mode hygiene, SSH exposure in debug mode)
are unchanged — still reported, not gated, because they are hygiene/debug-mode signals, not the
core RBAC separation claim itself.

A new `base/greenboot/check/required.d/20-hookprobe-rbac.sh` runs `rbac-os-check.sh` and exits
non-zero on `hard_fail`, which is greenboot's own generic mechanism for "this boot is unhealthy" —
on the bootc-managed UEFI tier (ADR 0019 D2), a hard RBAC violation is now a REAL trigger for
`bootc rollback`, not just a failed systemd unit an operator has to notice in the journal. The
existing `hookprobe-rbac-check.service` (boot-time, both tiers) is unchanged — it already exits
non-zero on `hard_fail`; this ADR gives that exit code an actual consequence on the tier where
rollback is real. **Honest scope**: on the rpi-native/single-slot tier (today's shipping Pi image),
`selftest-boot.sh` — not greenboot — is the actually-invoked verdict path (ADR 0019 D2/D3), and this
ADR deliberately does NOT fold the RBAC hard-fail into that file's own aggregate PASS/FAIL line;
that file is actively evolving under verification-engineer/os-architect's canon (the SOC-engine
liveness gate), and mixing in an unrelated concern risked a silent conflict. Wiring RBAC's hard-fail
into `selftest-boot.sh`'s verdict is a small, well-scoped follow-up, explicitly flagged here rather
than done unilaterally.

## Honest limits — what's enforced vs still-model

**Enforced (this ADR):**
- Role/verb resolution against the real `roles.yaml`, fail-closed on unknown roles/verbs.
- Bearer-token → identity lookup, fail-closed on unknown tokens.
- Both HTTP surfaces (`hookprobe-api`, `hookprobe-planner`) gate every route through the same
  middleware; `hookprobe-planner`'s `/approve` (the Red-action gate) requires `configure`.
- Standalone-loopback-no-identity stays fully open (proven both by pure-function tests in
  `hookprobe-rbac` and by router-level tests in both consumer crates).
- `rbac-os-check.sh`'s non-admin-OS-account check is now a release-image hard gate, and a new
  greenboot check makes a hard-fail verdict a real bootc-rollback trigger on the UEFI tier.

**Still model / roadmap (not built, not faked):**
- **No login/session system.** No password check, no MFA, no dashboard user CRUD, no token
  issuance UI. `tokens.json` is hand-provisioned (or written by a future dashboard backend) — this
  ADR ships the seam that system plugs into, not the system itself. This is the single biggest gap
  vs. ADR 0008's full vision and is the natural next PR.
- **No tenant-subtree clamping yet.** `Identity.tenant` is carried through but nothing currently
  scopes a query to it — `roles.yaml`'s `clamp_to_tenant_subtree` policy line is not yet enforced in
  code (single-tenant/standalone is today's only real deployment to test against).
- **No capability-manifest intersection.** `roles.yaml`'s `intersect_capability_manifest: true` line
  (a role can't be granted a verb tied to a capability the device lacks) is not implemented — verbs
  are granted/denied purely by role today.
- **No per-workspace verb granularity in `hookprobe-api`.** Every read route needs only `view`;
  finer gating (e.g. `business`-workspace reads needing a different verb than `detect`-workspace
  reads) is roadmap, noted in `required_verb`'s own doc comment.
- **`selftest-boot.sh` (rpi-native tier) does not yet include the RBAC hard-fail in its aggregate
  verdict** — see D6's honest-scope note.
- **UDS peer-credential identity** (an alternative to bearer tokens, named as an option in the
  original brief) is not implemented — bearer tokens were chosen as the simpler, more portable
  mechanism for a first pass; both HTTP surfaces are plain TCP loopback services today, not UDS.

## Consequences

- The two HTTP surfaces Mission Control depends on are no longer "unauthenticated by design" —
  they are permissive-by-default for the invariant that requires it (standalone, no account) and
  fail-closed the moment an identity or a non-local peer appears.
- A future login system's entire integration surface is "write a hashed token into
  `tokens.json`" — zero changes to either binary's routing/middleware.
- `rbac-os-check.sh` violations that used to be silent audit noise on a release image (a stray
  non-admin OS account) now block the same way a default-credential backdoor already did.

## Alternatives considered

- **UDS + `SO_PEERCRED` instead of bearer tokens.** More precisely "which process/user called this"
  on a single host, but requires reworking both binaries off plain TCP loopback listeners — a larger
  change than this pass's scope, and bearer tokens already support the actual near-term need
  (a browser-based dashboard calling a device over the network, once one is bound beyond loopback).
  Not rejected outright — a reasonable follow-up, noted as roadmap above.
- **Argon2id-hash the bearer tokens like passwords.** Rejected: tokens here are high-entropy
  machine-generated secrets, not human passwords — Argon2id's slow-hash defense against low-entropy
  guessing is the wrong tool; SHA-256 (with constant-time comparison) is the correct, standard
  primitive for this case (see `tokens.rs`'s own doc comment).
- **Gate the whole read-API behind mandatory auth, breaking the standalone default.** Rejected
  outright — directly violates "no account is ever required to run the device."
- **Fold the RBAC hard-fail directly into `10-hookprobe-soc.sh`/`selftest-boot.sh`.** Rejected for
  this pass: both files are actively-evolving canon owned by other agents; a new, additive
  `required.d/` script achieves the same greenboot consequence with zero risk of silently
  conflicting with concurrent work there.

---

## heqk migration — see [ADR 0043](0043-heqk-microkernel-substrate.md)

**Coupling: SOFT.** The `hookprobe-rbac` policy engine + axum middleware + bearer-token model are portable Rust; the `rbac-os-check.sh` `/etc/passwd` inspection and the greenboot→bootc-rollback trigger are re-expressed against heqk (no passwd; heqk self-heal + A/B rollback). → **Phase M5**.
