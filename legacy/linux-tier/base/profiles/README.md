# `base/profiles/` — build variants of the one HookProbe OS image

> One Containerfile, many outputs (Readme "The Builder"). A **profile** does **not**
> create a different OS — the image still self-detects hardware and writes the
> Platform Manifest at first boot. A profile only tunes (a) which *optional* packages
> and slices ship and (b) which **disk artifact** `bootc-image-builder` emits for that
> deployment target. The runtime hardware classification is still done by `bootstrap/`
> against `platforms/*.yaml`; profiles and platforms are orthogonal.

## How a profile is consumed

```
podman build -f base/Containerfile \
  --build-arg PROFILE=<profile> \
  --build-arg TARGETARCH=<arm64|amd64|riscv64> \
  -t ghcr.io/hookprobe/os:<tag> .          # build the bootc image
        │
        ▼  cosign sign + push to registry
        │
        ▼  bootc-image-builder, per profile `bib:` block below
   .img.xz (SBC) · .iso (x86) · .qcow2 (VM) · .raw/.ami (cloud)
```

The `bib:` block in each profile maps 1:1 to a `bootc-image-builder` invocation
(`--type` is repeatable; `--target-arch` cross-builds; a `config.toml` carries the
filesystem/partition + user customizations). CI reads these YAMLs to drive both the
`podman build --build-arg` matrix and the image-builder stage.

## The five profiles → `platform.class` (ADR 0003 enum)

| Profile | `platform.class` | Target hardware | Primary bib output | Notes |
|---|---|---|---|---|
| `edge-lite` | `edge-lite` | Pi 5 / CM5, small SBC, ≤4 GB | `.img.xz` (arm64) | leanest; out-of-band SOC; no heavy container stack baked in |
| `edge-pro`  | `edge-pro`  | RK3588 SBC, N100 appliance | `.img.xz` (arm64) / `.iso` (amd64) | full local SOC; OVS + AP + inline IPS capable |
| `cloud`     | `cloud`     | AWS/GCP/Azure, aggregation | `.raw` + `.ami` (amd64/arm64) | cloud-init seed; elastic resources; no Wi-Fi/AP bits |
| `virtual`   | `virtual`   | KVM/VMware/Proxmox lab | `.qcow2` (+ `.vmdk`) | VM guest tools; quick demo / dev SOC |
| `dev`       | `dev`       | maintainer workstation | `.qcow2` | adds debug tooling; relaxed (still signed) for iteration |

> `generic` is **not** a build profile — it is the runtime *fallback class*
> (`platforms/generic.yaml`) chosen when no `platforms/*.yaml` matches the detected
> hardware. Any profile's image can classify as `generic` at first boot on unknown
> hardware and still run the conservative baseline SOC (local-first invariant).

## Honest scope

These descriptors are reviewed scaffold. The exact `bootc-image-builder`
filesystem-customization syntax (notably the separate labelled `hookprobe-data`
partition) and some package deltas are marked `# TODO:` — they must be validated in
CI against the pinned image-builder version. See `base/README.md`.
