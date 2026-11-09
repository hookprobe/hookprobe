# docs/

| Folder | Read it for |
|---|---|
| [`architecture/`](architecture/) | What HookProbe OS is. **Canon for the current product:** [`MissionControl.md`](architecture/MissionControl.md) (target UI), [`MIGRATION-heqk.md`](architecture/MIGRATION-heqk.md) (the move from Linux to heqk) and ADR [0047](adr/0047-heqk-everywhere-on-device-mission-control.md). [`Readme.md`](architecture/Readme.md) describes the retired Linux-tier (bootc) architecture and is **historical, not canon** for heqk. |
| [`getting-started/`](getting-started/) | Build, test in QEMU, flash a CM5 |
| [`security/`](security/) | Security model, supply chain, disclosure |
| [`roadmap/`](roadmap/) | [`BuildPlan.md`](roadmap/BuildPlan.md) (phase history; Linux-tier tracks are historical) |
| [`adr/`](adr/) | Architecture Decision Records, numbered, never renumbered. Start with 0047 (heqk everywhere). Index: [`adr/README.md`](adr/README.md). |
| [`design/`](design/) | Dated design notes, audits, bench runbooks. **Status source of truth:** [`heqk-parity-gaps.md`](design/heqk-parity-gaps.md) (gap register) + [`heqk-decisions-2026-11-08.md`](design/heqk-decisions-2026-11-08.md) (decision register) |
| [`research/`](research/) | Investigations, V1→V2 maps, competitive analysis |

The kernel's own deep-dive docs live next to the code in [`os/kernel/`](../os/kernel/)
(start with `ARCHITECTURE.md`). Paths changed in the repo merge: see [`PATHS.md`](PATHS.md).
