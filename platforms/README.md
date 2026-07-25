# `platforms/` — per-board profiles (the generator's input)

One file per board/SKU. The bootstrap generator combines a `platforms/<profile>.yaml`
with detected hardware facts to emit the signed **Platform Manifest**
(`manifest/`, schema 2; see [ADR 0003](../docs/adr/0003-platform-manifest-schema.md)).

**The design test:** *adding new hardware = one file here.* No scanner, mapper, UI,
or API change.

```
platforms/
├── rk3588.yaml    # Rockchip RK3588 (arm64) — matched via device-tree compatible
├── n100.yaml      # Intel N100 (x86)        — matched via DMI tuple
├── generic.yaml   # fallback (always matches last) — baseline-only, local-first
└── README.md
```

## What a profile carries

| Field | Feeds manifest | Notes |
|---|---|---|
| `profile`, `class`, `sku` | `platform.*` | `class` ∈ edge-lite/edge-pro/cloud/virtual/dev/generic |
| `match` | `platform.match` | `device-tree` (ARM, tokens), `dmi-tuple` (x86), or `fallback` |
| `spec.min/recommended` | builder warning | under-min targets warn at build |
| `resources.reserved/defaults` | `resources.*` | `allocatable` = total − reserved (generator computes) |
| `capabilities.<tok>` | `capabilities.*` | `requires` + `known_good` + `policy` → grant state |
| `crypto_suite` | `crypto` | resolved from ADR 0002 |
| `retention.tier_fractions` | `retention.tiers` | fractions of usable disk → absolute caps + honest window |

## Classifier priority

`device-tree` → `dmi-tuple` → `virt` overlay → `fallback` (generic). The first match
wins; `generic.yaml` is the safety net so an unrecognized box still runs a baseline SOC.

## The grant rule

`grant = presence ∧ known-good ∧ policy` → one of `granted | present_unsafe |
policy_denied | absent`. Example: `inline_ips` is `granted` on n100 (igc/ixgbe are in
`known_good_nic_drivers`) but `present_unsafe` on rk3588 (offload not yet validated) —
the visible form of the pfSense TSO/LRO lesson.

## Validation

`manifest/validate.py` cross-checks that every `manifest/examples/*.manifest.json`
`profile`/`class` matches a profile here, alongside schema + invariant checks. When you
add a profile, add a matching `examples/<profile>.manifest.json` so CI covers the path.
