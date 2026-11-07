# `bootstrap/` — first-boot probe → signed Platform Manifest

The first-boot pipeline that runs **once** (Architecture.md C3–C7): scan hardware →
classify → map capabilities → allocate resources → assemble → sign → write
`/var/lib/hookprobe/manifest.json`. After this, nothing re-probes hardware
("detect once, query forever"); re-probe only when `hardware.fingerprint` changes.

```
bootstrap/
├── reference/
│   └── generate_manifest.py   # Python REFERENCE generator (the logic, testable offline)
└── README.md
```

## Reference vs shipping

- **`reference/generate_manifest.py`** — the executable spec for the classifier +
  the grant rule (`grant = presence ∧ known-good ∧ policy`) + resource/retention
  computation. Runs offline against `manifest/fixtures/*.profile.json`. **Emits an
  UNSIGNED manifest** (the signature is stubbed).
- **Shipping bootstrap (Rust, to build)** — aligns with ADR 0001 / the OS
  supply-chain posture. Adds the real **scanner** (`lshw`/DT/DMI/`ethtool`/`iw`/TPM
  probes, run as root after `systemd-udev-settle`) and **real cosign signing +
  TPM-sealing** of the manifest. It mirrors this reference's classification + mapping
  logic exactly.

## Pipeline stages

| Stage | Input | Output |
|---|---|---|
| **scan** | hardware | raw facts (see `manifest/fixtures/*.profile.json`) |
| **classify** | facts + `platforms/*.yaml` match keys | `platform.{class,profile,match}` (device-tree → dmi-tuple → fallback) |
| **map** | facts + `platforms/*.yaml` capability policy | `capabilities.{token}` ∈ granted / present_unsafe / policy_denied / absent |
| **allocate** | facts + `resources.reserved/defaults` | `resources` (allocatable = total − reserved) + `retention` (tier fractions × usable disk) |
| **sign** | manifest bytes | cosign signature + TPM seal (shipping); stub (reference) |

## Run the reference generator

```bash
pip install -r manifest/requirements.txt
python3 bootstrap/reference/generate_manifest.py manifest/fixtures/rk3588.profile.json
python3 bootstrap/reference/generate_manifest.py manifest/fixtures/n100.profile.json -o /tmp/n100.json
```

The output validates against the canonical schema and reproduces the capability
states in `manifest/examples/` — verified by `manifest/validate.py`. This is the
Phase-1 contract working end to end: **`platforms/*.yaml` (input) → generator →
manifest (schema-valid output)**.
