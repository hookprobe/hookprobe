# ADR 0008 — Admin/operator RBAC (the OS is the admin's; operators live in the dashboard)

**Status:** ✅ Accepted (2026-07-02) — E4a. **🟡 Policy accepted; ENFORCEMENT SEAM BUILT (2026-07-08, [ADR 0028](0028-rbac-enforcement.md)).** `security/rbac/roles.yaml` is now parsed at runtime (embedded, `hookprobe-rbac::RolePolicy`) and enforced by a shared axum middleware in BOTH `hookprobe-api` (read-API) and `hookprobe-planner` (the AEGIS write surface, including the `/approve` Red-action gate) — standalone-loopback stays permissive (no account required to run the device), enforcement activates the moment a bearer identity or a non-loopback peer is observed. `rbac-os-check.sh`'s non-admin-OS-account check is now a release-image hard gate (was audit-only), and a new greenboot check makes that a real bootc-rollback trigger. **Still ⬜ (ADR 0028's honest scope, not re-derived here):** no dashboard user store, no login/session/MFA/token-issuance UI, no tenant-subtree clamp, no capability-manifest-intersection code. Builds on [ADR 0007](0007-data-at-rest-encryption.md) (encryption)
and the Mission Control workspace model (`docs/MissionControl.md`).
**Deciders:** operator (the encryption requirement), os-architect.

## The load-bearing separation

> *"The designated administrator has full root access. Operational users are intentionally separated
> from the OS. They receive role-based access through the HookProbe dashboard."* — the encryption requirement.

Two populations, two planes — they never overlap:

| | **Admin** | **Operators** (all RBAC roles) |
|---|---|---|
| Identity lives in | the **OS** (a real account) | the **dashboard user store** — NEVER `/etc/passwd` |
| Access | **root/sudo + shell + SSH + the disk key** | **dashboard only** — no shell, no SSH, no OS account |
| Count | one (the appliance owner/installer) | many, tenant-scoped |
| Auth | SSH key (prod) / TPM-bound device identity | dashboard login (password + optional MFA/SSO) |
| Can | rebuild, rollback, rotate keys, hold the master key | see/act on evidence per role — nothing at the OS layer |

**Invariant:** an operator can *never* obtain OS-level access. There is no code path from a dashboard
role to a shell. This is what makes "encrypt the OS, give operators role-based dashboard access"
actually true — the operator population is architecturally incapable of touching the substrate.

## Roles (dashboard-plane, capability-gated, tenant-scoped)

Permissions map onto Mission Control **workspaces × verbs**, scoped by **tenant** (recursive
multi-tenancy — a role is always evaluated within a tenant subtree):

| Role | Workspaces | Verbs | Typical use |
|---|---|---|---|
| **viewer / auditor** | Observe, Detect, Investigate, Intelligence, Business (read) | `view` | read-only oversight, compliance |
| **analyst** | + Investigate, Intelligence | `view`, `investigate`, `query`, `annotate` | SOC tier-1/2 |
| **responder** | + Protect, Automate | `view`, `investigate`, `respond`, `run-playbook` | SOC tier-3, IR |
| **tenant-admin** | + Customers, Administration (tenant-scoped), user mgmt | `view`, `configure`, `manage-users` (within tenant) | MSSP customer admin |
| **admin** *(OS+dashboard)* | all, incl. Administration/Builder/Provisioning | all + **OS root** | appliance owner |

Verbs are additive; a role's grant = union of its verbs across its workspaces, **intersected with the
device's capability manifest** (you can't be granted `respond` on a capability the device lacks) and
**clamped to the tenant subtree**. Roles are data, not code — defined in `security/rbac/roles.yaml`,
loaded by the dashboard backend; adding a role is a policy edit, never a rebuild.

## Where identities live (and why it's safe)

- **Operators + role bindings + sessions** → the **dashboard user store on the ENCRYPTED data volume**
  (`/var/lib/hookprobe/rbac/`, dm-crypt per ADR 0007). Credentials are Argon2id-hashed; the store is
  unreadable if the disk is cloned. Operators do **not** appear in `/etc/passwd`, `/etc/shadow`, or any
  PAM/NSS source — so even a shell (which only the admin has) exposes no operator login path.
- **Admin** → a single OS account (sudo) provisioned at first boot / wizard, plus the TPM/OTP-bound
  **device identity** (exists before any account, ADR 0007 E3). The admin holds the master-key anchor.

## OS-level enforcement (the parts that live below the dashboard)

1. **Operators get no OS account, ever.** The dashboard writes to its own store, never to system auth.
   No sync from dashboard roles to `/etc/passwd`. (Enforced by construction + a boot self-check that
   fails loudly if any non-system, non-admin OS account exists.)
2. **SSH is admin-only in production.** Key-based, `PermitRootLogin prohibit-password`,
   `AllowUsers <admin>`, `PasswordAuthentication no`. The dev image's password/root SSH
   (`10-hookprobe-debug.conf`) is **debug-only** and must be absent from signed release images
   (gated by the signed-release build — E4b).
3. **The disk-key anchor is admin/root-only** (`/etc/hookprobe/keys/`, mode 0700). No operator path
   reaches it — the dashboard never reads it.
4. **Standalone-by-default holds:** with zero operators enrolled, the device still runs a full local
   SOC; the admin is the only identity. Operators are additive, exactly like cloud enrollment.

## Consequences

- Compromising an operator account yields dashboard access at that role's scope — **never** the OS,
  the keys, or other tenants. Blast radius = one role × one tenant subtree.
- The admin is the high-value target → protect with SSH keys + TPM device identity + (E4c) optional
  passphrase on the master-key anchor.
- The dashboard backend is now in the enforcement path for operators — it must fail closed (deny by
  default; a missing/unparseable role → no access).
- Fleet/MSSP: roles inherit down the tenant tree; a parent tenant-admin can scope child roles but
  never escalate to the device OS (that stays with the on-device admin / the fleet's signed GitOps).

---

## heqk migration — see [ADR 0043](0043-heqk-microkernel-substrate.md)

**Coupling: SOFT.** The two-plane admin/operator model is substrate-neutral. "Operators never get an OS account" becomes *trivially* true on a kernel with no `/etc/passwd`/PAM/NSS; the admin identity + SSH-equivalent access re-express against heqk (an authenticated API / restricted shell, never root bash — ADR 0035 D8). → **Phases M5/M6**.
