# Architecture

Read in this order:

1. [`Readme.md`](Readme.md): the OS architecture (canon)
2. [`MissionControl.md`](MissionControl.md): the target dashboard / UX spec (canon)
3. [`MIGRATION-heqk.md`](MIGRATION-heqk.md): how and why Linux is replaced by heqk (ADR 0043/0044/0047)
4. [`os/kernel/ARCHITECTURE.md`](../../os/kernel/ARCHITECTURE.md): the kernel itself

Topic docs: [`Architecture.md`](Architecture.md) (connections spine) ·
[`network-fabric.md`](network-fabric.md) · [`network-segmentation.md`](network-segmentation.md) ·
[`runtime-engine-map.md`](runtime-engine-map.md) · [`driver-strategy.md`](driver-strategy.md) ·
[`OS-platform-report.md`](OS-platform-report.md) · HTP: [`htp-v2-handshake.md`](htp-v2-handshake.md),
[`htp-v2-formal-analysis.md`](htp-v2-formal-analysis.md)

> Parts of `Readme.md` still describe the Linux/bootc tier as canonical. ADR 0047 supersedes
> that: heqk replaces Linux everywhere.
