# Path map: the repo merge (2026-11-07)

`hookprobe-os` became the top level of `hookprobe`, and the old `hookprobe` repo moved under
`legacy/v1/`. Live files (scripts, CI, CLAUDE.md, READMEs, docs) were rewritten to the new paths.
Dated records (ADRs, design notes, commit messages, memory) may still cite old paths, so use this
table. Commit hashes did **not** change. Both histories were merged without rewriting.

| Old path | New path |
|---|---|
| `kernel/heqk/` | `os/kernel/` |
| `kernel/responder-sim/` | `onboarding/enrollment/responder-sim/` |
| `ui/` | `os/mission-control/` |
| `builder/make-cm5-heqk-image.sh`, `make-cm5-heqk-disk.sh`, `heqk-sign/`, `gen-heqk-dev-keys.sh`, `heqk-dev-key-fingerprints.txt` | `os/build/…` |
| `builder/generated/cm5-heqk/` · `builder/.heqk-dev-keys/` | `os/build/generated/cm5-heqk/` · `os/build/.heqk-dev-keys/` |
| `base/scripts/heqk-boot-key-check.sh` | `os/build/heqk-boot-key-check.sh` |
| `base/drivers/brcm-firmware-rpt/` | `os/drivers/firmware/brcm-firmware-rpt/` |
| `base/ bootstrap/ supervisor/ modules/ crates/ security/ manifest/ fleet/ platforms/ builder/` (the rest), `Cargo.toml`, `Cargo.lock` | `legacy/linux-tier/…` |
| `.github/workflows/{build-os,build-modules,build-napse-capture,gate-ladder,manifest-validate}.yml` | `legacy/linux-tier/ci-workflows/` (parked, not run) |
| `tools/cm5-relay.py` | `tools/diagnostics/cm5-relay.py` |
| `scripts/hooks/pre-push` | `tools/build/git-hooks/pre-push` |
| `docs/{Readme,MissionControl,Architecture,MIGRATION-heqk,network-*,runtime-engine-map,driver-strategy,OS-platform-report,htp-v2-*}.md` | `docs/architecture/` |
| `docs/{BuildPlan,base-tier-build-ticket}.md` | `docs/roadmap/` |
| `docs/{V1-alignment,v1-map-*,V2-investigation,v2-*,feedback-ux,product-cortex-competitive,htp-dsm-neuro-investigation}.md` | `docs/research/` |
| everything in the old `hookprobe` repo (V1) | `legacy/v1/` |
