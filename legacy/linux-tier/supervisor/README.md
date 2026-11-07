# `supervisor/` — module reconciler

Resolves module `requires`/`grants`/`provides` against the signed Platform Manifest
and reconciles running modules to desired state (Architecture.md C9–C11). This is the
Marketplace backend and the enforcement half of "operated by intent" — the
deterministic reconciler that runs **locally, with no model** (the AEGIS AI planner
only *proposes*; the supervisor enforces).

```
supervisor/
├── reference/
│   └── supervisor.py   # Python REFERENCE reconciler (resolution logic, mock load)
└── README.md
```

## Resolution per module (in order)

1. **Capability gate** — every `requires.capabilities` token must be `state=granted`
   in the manifest. `present_unsafe` / `policy_denied` / `absent` ⇒ **clean refusal
   with the reason** (never a crash, never a silent no-op).
2. **Signature gate** — `signature: required` ⇒ artifact cosign signature must verify
   (stubbed in the reference; real in the Rust supervisor).
3. **Budget** — requested `resources` (or the manifest's per-runtime default); must
   meet `requires.min_memory_mb`.
4. **Resource fit** — budget must fit within `resources.allocatable` (tracked as
   modules load).
5. **provides** — granted capabilities are added so later modules can require them
   (chains resolve via a fixpoint loop).

## Properties

- **Level-triggered + idempotent** — reconciles to *current* state; re-running loads
  nothing new (proven: a second pass shows every running module as `no-op`).
- **Two-layer budget enforcement (shipping)** — cgroups v2 (host wall) + Wasmtime
  epoch/`StoreLimits` (between-module wall). The reference tracks budgets; it does not
  yet enforce them (mock load — no Wasmtime/Podman).
- Mutates only `modules[]` in the manifest, then re-signs (reference marks the
  signature `STALE-RESIGN-REQUIRED`).

## Run the reference (the Phase-1 "thesis" demo)

```bash
python3 bootstrap/reference/generate_manifest.py manifest/fixtures/rk3588.profile.json -o /tmp/m.json
python3 supervisor/reference/supervisor.py /tmp/m.json --write /tmp/reconciled.json
python3 manifest/validate.py /tmp/reconciled.json     # reconciled manifest stays schema-valid
```

Capability gating differs correctly by platform (same modules, same code):

| module | rk3588 | n100 | generic |
|---|---|---|---|
| napse (soc, ids) | running | running | running |
| hydra (soc) | running | running | running |
| edge-ai-detector (edge_ai) | **running** | refused (no NPU) | refused (no NPU) |
| inline-guard (inline_ips) | refused (present_unsafe) | **running** | refused (no inline iface) |

This is the Readme's "single demo is the whole thesis working": **one Wasm module
loading against a manifest grant** — generalized to capability-gated reconciliation.
