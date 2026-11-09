# ADR 0057 — Shield protection levels as transparent categorised profiles

**Status:** ✅ Implemented + metal-proven 2026-11-09 (`tools/diagnostics/cm5-shield-levels-check.sh` 12/12) — direction approved by the operator 2026-11-09 ("yes, but as
transparent policy profiles, not three opaque blocklist strengths; staged"). Extends ADR 0052 (Shield v2) and
G22 (per-client profiles); respects ADR 0023 (no profile turns uncertainty into a block) and ADR 0055 (owner
journal precedence).

## Decision

**D1 — Categories come from the signed list.** BLOCK.TXT sections are tagged with `#! category=<name>`; every
following entry carries that category until the next tag. Categories (most severe first): `malware` (incl.
known C2), `phishing`, `general` (untagged lines — today's lists), `ads`, `trackers`, `adult`. The category is a
classification *source* the operator controls and anyone can inspect: it is the signed list itself.

**D2 — Levels are fixed, published tables (no hidden strength).**

| Category | relaxed | balanced (default) | strict |
|---|---|---|---|
| malware / known C2 | block | block | block |
| phishing | block | block | block |
| general (untagged) | allow | block | block |
| ads | allow | block | block |
| trackers | allow | block | block |
| adult | allow | allow | block **only if** the signed list says `#! strict_adult=block` |
| encrypted DNS / Private Relay | network POLICY | network POLICY | blocked (G22 strict) |
| newly observed / uncertain (DGA score, unknown) | observe | observe | observe |

`off` (G22) blocks no ordinary category for that device; malware / phishing still block (D4), as they do
through a session pause. The network default is `balanced`, so today's behaviour is unchanged. A device whose
profile is `standard` (or that is unlisted) follows the network default; an explicit `relaxed | balanced |
strict` does not. The device-level `strict` also blocks encrypted DNS / Private Relay (G22); the network
`#! level=strict` changes categories only (encrypted DNS keeps its own `#! encrypted_dns=` directive).

**D3 — Where a level is set.** Per device: the signed DEVICES.TXT `shield=` token (`relaxed | balanced | strict
| off`; `standard` stays an alias of `balanced`) and the owner journal `shield_profile` kind (ADR 0055, unless
the signed line is pinned). Network default: `#! level=<name>` in BLOCK.TXT.

**D4 — Precedence (unchanged ADR 0055 D2).** Safety floor and confirmed-malicious (malware/phishing, IOC) are
never relaxed by a level or an owner allow; an owner allow/block overrides ordinary categories.

**D5 — Explainability.** A name a level lets through answers normally with its own verdict (`level-allowed`),
and the query log (`/api/dns`) carries the category and the level for every blocked or level-allowed query —
the UI (designer) can show "blocked: ads, balanced" or "allowed: ads, relaxed". A level change is previewed
with the owner-journal dry run (before/after).

## Implementation (2026-11-09)

`shield.rs`: `Level`, `CAT_*`, `category_of`, `classify` (level-independent) + `at_level`; `decide` = network
level, `decide_for_dev` = device level. `devpolicy::ShieldProfile` gains `Relaxed`, `Balanced` (owner journal
values 3, 4). `/api/dns`: `policy.level`, `policy.strict_adult`, counter `level-allowed`, and `recent[].category`
+ `recent[].level` on blocked / level-allowed / paused entries. The owner API previews an allow of a
malware / phishing name as shadowed ("confirmed malicious"). Self-test `[P-shield-levels]`.

UI fields (designer): `recent[].category`, `recent[].level`, `policy.level`, verdict `level-allowed`;
`/api/owner-rules` `shield_profile` values `standard | off | relaxed | balanced | strict`.

## Consequences

No extra memory (the 3-bit category rides in the low bits of each sorted 64-bit name hash). Existing signed lists
keep working (untagged = `general`). Curated category feeds are an operator/list-build concern; the device only
honours the tags.
