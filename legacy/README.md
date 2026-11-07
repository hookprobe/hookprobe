# legacy/ — previous HookProbe implementations

Kept with **full git history** (`git log --follow <file>` works across the move). New features
are not added here.

| Folder | What | Status |
|---|---|---|
| [`v1/`](v1/) | The original HookProbe: Python + Zig XDP. Products Fortress / Guardian / Nexus / Sentinel, `core/`, `shared/`, `install.sh` | Frozen. Old install URLs: use the `v1-final` tag. |
| [`linux-tier/`](linux-tier/) | HookProbe OS V2 on Linux: bootc/Debian image (`base/`), supervisor, Wasm/eBPF modules, Rust crates (`crates/`, including the `hookprobe-api` contract that heqk's `http.rs` implements), mkosi builder, platform manifests | Bug and security fixes only (ADR 0047). Its own Cargo workspace: `cd legacy/linux-tier && cargo test`. CI workflows are parked in `ci-workflows/`. |
