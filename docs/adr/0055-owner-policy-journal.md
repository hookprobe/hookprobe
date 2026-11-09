# ADR 0055 — Owner policy journal: durable owner settings from Mission Control

**Status:** 🟡 Proposed contract (2026-11-09) — direction approved by the operator 2026-11-09 ("durable owner
settings: approve — authenticated writable policy journal + audit"); this document is the contract to review
before implementation. **Amends [ADR 0053](0053-operator-write-actions-on-device.md) D1 and S7** (see D9).
Builds on ADR 0022 (behavioural quarantine vs static allowlists), ADR 0023 (enforcement separation),
ADR 0049 D1 (signed POLICY.TXT), ADR 0052 (Shield v2), ADR 0054 (per-device credential).

## Context

Today every durable setting is an operator-signed file on the boot partition (POLICY, DEVICES, BLOCK, ALLOW,
IOC, RULES, WIFI, OUI). Mission Control can only make **temporary** changes (ADR 0053: ≤ 24 h, RAM, cleared by
a reboot). For a home or small-office owner, "block this device for good" or "always allow this site" means
re-signing a file and re-flashing — nobody will do that (legacy parity audit 2026-11-09, item #1). The operator
approved durable owner settings **on the condition that they never become a route around the signed policy**.

## Three authorities (operator, 2026-11-09)

| State | Authority | Persistence |
|---|---|---|
| Signed platform / security baseline | Image + operator policy key | Signed artifacts; changes require signing |
| **Owner-managed rules (this ADR)** | **Authenticated device owner** | **Writable on-device journal** |
| Temporary automated / session responses | `decide()` (ADR 0023) and ADR 0053 actions | TTL state; expires automatically |

## Decision

**D1 — Scope (what an owner rule can be).** Phase 1 kinds, each a typed handler (no generic setter):
`device_policy` (MAC → full / internet_only / lan_only / quarantine / blocked), `shield_allow` (domain),
`shield_block` (domain), `shield_profile` (MAC → standard / off / strict, ADR 0052 + G22), `device_label`.
Phase 2 (after the categorised profiles exist): `shield_level` (relaxed / balanced / strict, per device or
network). **Never** an owner rule: WAN / VLAN / PPPoE / routes / ACLs, the management floor, trust keys,
rule packs, IOC entries, export targets, TLS material, Wi-Fi credentials (those stay signed).

**D2 — Precedence (fixed, evaluated in this order; first match wins).**
1. Management-safety floor (ADR 0023 `Allowlisted`; Shield's system FLOOR; DHCP/DNS/ARP to the AP) — immutable.
2. Confirmed-malicious indicators — the signed IOC pack, signed rule-pack drops, and (with profiles) the
   malware / C2 / phishing categories. An owner allow **never** overrides these.
3. **Signed pins** — any signed-artifact line marked `pin` (new optional token in DEVICES / BLOCK / ALLOW).
4. **Owner journal rules.**
5. Signed ordinary entries (an unpinned BLOCK.TXT line, an unpinned DEVICES.TXT policy) and profile defaults.
6. Built-in defaults.
For devices, an owner rule may **tighten** a signed DEVICES.TXT line freely; it may **loosen** one only if that
line is not pinned. Session actions (ADR 0053) are TTL overlays evaluated with the same precedence.

**D3 — Record format (append-only, tamper-evident).** Each record: `seq` (u64, strictly increasing), Unix ms
(0 if the clock is unsynced, with the monotonic tick), session tag, kind, target, previous value, resulting
value, mandatory reason (≤ 120 B), `ttl_s` (0 = permanent), `confirmed` flag, and
`mac = HMAC-SHA256(K_journal, prev_mac ‖ record)` where `K_journal = HKDF(SRK, "HQ-owner-journal-v1")`.
The chain is verified on load; replay stops at the first record whose MAC fails (power-loss tail or tampering),
and that event is itself reported. Refusals are recorded too (as in ADR 0053 S4).

**D4 — Storage.** A dedicated, registered eMMC region (the region registry is item #54: lifting the 16 KiB
write clamp to named regions) — never the boot FAT, never the snapshot window. Layout: an append area plus
two checkpoint slots (A/B, each a full sealed copy of the reconciled state + the last seq/mac). Compaction
writes the inactive checkpoint, then the commit record; power loss at any point leaves the previous
checkpoint + a verifiable journal prefix. Caps: 512 active rules, 64 KiB journal before compaction.

**D5 — Write path.** Owner session + `Origin` = `Host` + CSRF + strictly increasing per-session `seq`
(ADR 0053 S3). **Every permanent rule requires owner re-authentication** (S5) **and** an explicit
`permanent: true` confirmation; the API offers a TTL alternative for every kind. Removing a rule is a record
too (never an erase). Per-session rate limit; JSON body ≤ 1 KiB.

**D6 — Reconcile.** Boot: signed baseline loads → journal is verified and replayed into an in-RAM owner rule
table → the datapath consults the D2 order. Deterministic: the same baseline + journal always produce the same
state (QEMU selftest: replay twice, compare; power-cut at every byte offset of the last record, recover).
A rule that the D2 order makes ineffective (e.g. an allow for an IOC domain) is kept but reported as
`shadowed_by` so the owner sees why it does nothing.

**D7 — API (backend only; the UI is the designer's).** `GET /api/owner-rules` (active rules, each with
`effective` / `shadowed_by`, plus the audit history), `POST /api/owner-rules` (add / remove / preview:
`dry_run: true` returns the plan-as-diff of what would change), `POST /api/owner-rules/revoke-all`
(re-auth). Every response names the authority of each effective decision (signed / owner / session / default),
so Shield and device views can say *why*.

**D8 — Recovery.** The owner can revoke all owner rules from Mission Control. If locked out, physical
possession is the credential (ADR 0037 D3): a reflash clears the journal region; the signed baseline and the
management floor were never affected.

**D9 — Amendment to ADR 0053.** D1's "durable configuration stays in operator-signed files" becomes "durable
**baseline** configuration stays in operator-signed files; durable **owner rules** use the journal (ADR 0055)".
S7 is kept in substance: a temporary action never silently becomes permanent — permanence needs the explicit
`permanent: true` + re-authentication path above, and is recorded as a separate journal record.

## Consequences

- Durable owner control without re-signing; the signed baseline, the management floor and confirmed-malicious
  indicators stay out of the owner's (and a stolen session's) reach.
- New attack surface: the journal parser (fuzzed, ADR 0050 D3) and the write API (ADR 0053 safeguards).
- Depends on #54 (eMMC region registry) and on G12 (persistence in the AP image).

## Open items for the operator

- The `pin` token in signed files (D2.3) is new — confirm the name and that unpinned BLOCK.TXT lines are
  owner-overridable (the common "this site is wrongly blocked" case).
- Whether `blocked` (no network at all) is an owner device policy distinct from `quarantine` (DHCP/DNS only).
