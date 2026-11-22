# 29: Neuro policy compiler, from validated verdicts to HEQK policy proposals (specification draft, 2026-11-22)

**Status: PROPOSED.** This is a userspace design. It builds **only on enforcement primitives HEQK already has**
(audited 2026-11-22). The kernel (`os/kernel/**`) belongs to HomePods; anything here that needs a kernel change
is listed as a request in §7, never assumed.

## 1. Non-negotiable rules (existing decisions this spec obeys)

| Source | Rule |
|---|---|
| ADR 0023 / contract C9 | Observe by default. No model output is ever an enforcement decision. |
| ADR 0059 D1 | A session, CLI or **AI suggestion never grants config authority**. Only signed, device-bound, generation-floored config takes effect. |
| ADR 0053 | Session writes are reversible and TTL-bounded. |
| ADR 0055 | Owner rules are journaled. An owner rule may tighten anything, but loosen only unpinned lines. |
| Doc 09 §2 | A model update can never change policy. Weights, per-device state, threat intel and policy are separate stores. |
| Doc 20 | DNA is evidence only. It is not a `decide()` input. |
| Doc 13 | No model-to-enforcement path. No inference in the kernel. |

So the compiler **never applies anything**. It produces a **signed proposal**. Authority comes only from the owner
key (K_own), or later a delegated K_adm, through paths HEQK already verifies.

## 2. Pipeline

```
kernel L0 verdict / incident ─┐
supervised classifier score ──┼─> evidence bundle ─> COMPILER (deterministic, pure function) ─> HQPROP1 proposal
DNA deviation (evidence) ─────┘     (refs only)       rule table + guards, no ML                  (signed by K_cmp)
                                                                                                     │
                                       owner app shows proposal + explainer text (descriptive only) ─┘
                                                                                                     │ owner approves
                                                     existing signed path: HQMGMT1 action / journal SET / HQCFG1
```

**The compiler is a pure function:** `(evidence bundle, compiler rule table vN, device inventory) → proposal | none`.

**What it never sees:**
- free text from the explainer;
- any quoted attacker-controlled value;
- model weights.

**Its rule table is data, not code.** It is versioned and signed separately (K_cmp_rules). The explainer may
describe a proposal; it cannot create, modify or rank one.

## 3. HQPROP1: the proposal record

A canonical ASCII record, like HQCFG1's canonical text. Every field is mandatory unless marked.

| Field | Type | Meaning |
|---|---|---|
| `magic` | "HQPROP1" | |
| `prop_id` | 16 B random | unique per proposal |
| `compiler_ver`, `rules_ver` | u32, u32 | compiler build and rule-table version: provenance |
| `device_id` | 16 B | the gateway (binds the proposal to one device, as HQCFG1 does) |
| `target` | enum + id | `device:<dev_id>` (MAC-anchored), `ip:<addr>` (with an anti-spoof (IP, MAC) pair, ADR 0018/0022), or `domain:<hash>` |
| `action` | enum | maps onto existing primitives only (§4) |
| `scope` | enum | `session` (ADR 0053 TTL action) or `durable` (journal rule) |
| `ttl_s` | u32 | **required for every action**. Session: 60 s–24 h (ShieldPause ≤ 1 h). Durable: ≤ 7 days by default; renewal needs a new proposal. |
| `confidence` | u8 class | `low` / `medium` / `high`, from the evidence-combination table (§5). Not a raw model probability. |
| `evidence[]` | refs | incident id(s) from the kernel evidence log (HQKSEAL1 / HQX1), DNA record ids, classifier run id + model hash. **References only, never content.** |
| `reason_code` | enum | e.g. `scan.confirmed`, `exfil.volume+novel`, `beacon.periodic+novel`, `family.mirai.cls` |
| `expires_at` | u64 | the proposal itself expires if not approved (default 30 min) |
| `nonce`, `issued_at` | 16 B, u64 | anti-replay (§6) |
| `revokes` | prop_id (optional) | supersedes or withdraws an earlier proposal |
| `sig` | Ed25519 over sha256 with tag "HQPROP1-SIG" | key K_cmp (compiler key, held in the companion tier, never on the explainer path) |

## 4. Action mapping onto existing HEQK primitives (no new kernel semantics)

| Proposal action | Existing primitive (audited) | Scope |
|---|---|---|
| `observe` (default, no proposal) | — | — |
| `hold_ip` | ADR 0053 `HoldIp`, target Ip, TTL | session |
| `isolate_device` | ADR 0053 `Isolate` (`devpolicy.rs isolated`) → durable `quarantine` class | session, or durable via journal |
| `restrict_internet_only` / `restrict_lan_only` | per-device class `internet_only` / `lan_only` (owner journal `DevicePolicy` SET) | durable (tighten-only) |
| `block_domain` | owner journal `ShieldBlock` (domain hash) | durable |
| `shield_profile_strict` | owner journal `ShieldProfile` | durable |
| `revert` | journal REMOVE for that rule, or let the TTL lapse | — |

**Loosening actions** (allow-listing, `full` access) are **never proposed by the compiler**. They are owner-only.

## 5. Evidence-combination table v1 (deterministic; `rules_ver` = 1)

| Evidence | → confidence | → max action |
|---|---|---|
| Kernel L0 `scan confirmed` (Quarantine already reachable in `decide`) | high | `isolate_device` (session, 1 h) |
| L0 exfil + classifier ≥ high threshold + DNA novel destination | high | `hold_ip` (session, 4 h) + propose `restrict_lan_only` |
| L0 beacon + classifier family match | medium | `hold_ip` (session, 1 h) |
| Classifier only (no L0 detector) | low | **no action**: notify only |
| DNA deviation only | — | **no action, no notification** (doc 20) |

The thresholds are those fixed by the benchmark (doc 28) on dev data and confirmed on the sealed test splits.
**Changing them needs a new `rules_ver` and a new benchmark run.**

## 6. Anti-replay, revocation, expiry, versioning

**Anti-replay.**
- `nonce` and `issued_at`, plus `device_id` binding.
- The owner-app approval travels inside the existing HQMGMT1 envelope, which already enforces a per-boot TRNG
  epoch and a RAM sequence floor and fails closed without TRNG.
- A proposal past `expires_at` is refused.

**Revocation.**
- A signed `revokes` proposal, or owner journal REMOVE / CLEAR.
- K_cmp revocation is by rule-table epoch (pending K_adm work, ADR 0059 D4).

**Expiry.**
- Every applied action carries a TTL: session actions natively; durable rules need §7.
- No proposal produces a permanent rule. Permanence requires the owner's explicit `FLAG_CONFIRMED`, as today.

**Versioning.** `compiler_ver` and `rules_ver` are in every proposal and are journaled on approval, so any applied
rule traces back to its evidence and rule table.

## 7. Requests to HomePods (kernel changes this design would like; none is assumed)

- **R-P1: expiry on durable journal rules.** An `expires_at` field on DevicePolicy / ShieldBlock journal records.
  Today only RAM actions expire.
- **R-P2: evidence reference field.** Store `prop_id` plus the first evidence ref in the journal record, beside or
  replacing part of the 96-byte free-text `reason`.
- **R-P3: a per-change signed delta.** Accept an HQPROP1-derived owner-signed delta instead of a whole HQCFG1
  bundle, or confirm that whole-bundle regeneration is the intended path.
- **R-P4: K_adm delegation and revocation epoch** (ADR 0059 D4), so a household can pre-authorise session-scope
  actions of high confidence without a per-event tap. This would be the **only** automatic path, and it stays
  TTL-bound.

## 8. Reference implementation plan (userspace, outside the kernel)

- **`tools/neuro_policy/hqprop.py`:** the pure function and the canonical encoder/decoder for HQPROP1, plus
  golden vectors.
- **`tools/neuro_policy/rules_v1.toml`:** the §5 table.
- **Property tests:**
  - no loosening action is ever produced;
  - every output has a TTL;
  - identical input always produces identical output (determinism);
  - quoted attacker strings in the input cannot reach any output field;
  - an expired or replayed proposal is rejected.
- **Rust port** for the companion tier after the Python reference passes. Never inside heqk EL1.
