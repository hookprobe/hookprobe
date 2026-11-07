# `manifest/` — the Platform Manifest contract

The signed source of truth for "detect once, query forever." Canonical schema:
**[ADR 0003](../../../docs/adr/0003-platform-manifest-schema.md)** · `schema_version 2`.

```
manifest/
├── schema/manifest.schema.json   # normative JSON Schema (Draft 2020-12)
├── examples/*.manifest.json       # validated reference manifests (rk3588, n100, generic)
├── fixtures/                       # probert-style hardware profiles (generator inputs) — TODO
├── validate.py                    # CI harness: schema + ADR-0003 semantic invariants
├── requirements.txt               # jsonschema
└── README.md
```

## Run the validator locally

```bash
pip install -r manifest/requirements.txt
python3 manifest/validate.py                 # all examples/
python3 manifest/validate.py path/to.json    # specific file(s)
```

Exit code is non-zero on any failure (CI gate). The harness runs:

1. **Schema validation** against `schema/manifest.schema.json` (includes the in-schema
   conditionals: capability `state != granted ⇒ non-empty reason`; interface
   `role == inline ⇒ fail_mode set`, else `null`).
2. **Semantic invariants** (ADR 0003 §"Validation invariants" that JSON Schema can't express):
   - `resources.allocatable == total − reserved` (per dimension, ≥ 0)
   - `schema_version == provenance.schema_version`
   - live module budgets sum within `resources.allocatable`
   - signature structure (`tpm_sealed ⇔ pcr_policy` present)
   - `generic` class grants only the baseline (`soc`, `ids`)

**Out of scope here** (runs in release CI): full cosign signature verification and the
`probert` round-trip (ADR 0003 #7/#8) — the latter needs the `bootstrap/` generator.

## CI

`.github/workflows/manifest-validate.yml` runs `validate.py` on any change under `manifest/`.

## Adding hardware

A new board = one file in `platforms/<profile>.yaml` (match keys, known-good lists,
budgets) → the generator emits a per-device manifest. Add a corresponding
`examples/<profile>.manifest.json` so the path is covered by CI.
