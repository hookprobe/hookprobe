# base/sysext — the host-integral (sysext / image-layer) model

> The third runtime, for the engines that **cannot** be Wasm and **should not** be a
> rootless container: kernel-coupled dataplane (NAPSE XDP capture, OVS). This is the
> honest exception to "logic = Wasm, services = Podman". It documents how a
> `runtime: sysext` (or `image-layer`) module differs from `wasm`/`container`, how the
> supervisor gates it, and the build → sign → ship → merge flow.

Canon: `docs/Readme.md` Pillar 1 ("host-integral pieces layer into the image via
`sysext`/image layer"), `docs/Architecture.md` (C11 budgets, C12 fast path, §4.4 OS-Agent
bridge), `docs/runtime-engine-map.md` (§0 + the sysext/image-layer rows),
`docs/adr/0003-platform-manifest-schema.md` (`runtime` ∈ wasm/container/sysext).

Modules implemented against this model:
- `../../modules/napse-capture/` — `runtime: sysext` (kernel XDP/eBPF; the crown jewel).
- `../../modules/ovs/` — `runtime: image-layer` (binaries already baked in `base/Containerfile`).

## The three runtimes, side by side

| | `wasm` (default) | `container` | `sysext` / `image-layer` |
|---|---|---|---|
| What it is | WASI component, one `.wasm` all arches | rootless Podman/Quadlet | a signed `/usr` overlay (sysext) or files baked into the bootc image (image-layer) |
| Where it runs | Wasmtime, in-process sandbox | OCI runtime (crun), user namespace | the **host** — kernel programs + privileged daemons in `/usr` |
| Isolation | capability-sandbox (WIT imports only) | namespaces + cgroups | **none of its own** — it IS the host; trust comes from signing + narrow caps |
| Host access | WASI grants (fs handle, wasi-nn) | cgroups + selected mounts/net | real **Linux capabilities** (CAP_BPF/NET_ADMIN/NET_RAW/SYS_MODULE) |
| Budget enforced by | Wasmtime epoch + fuel + `StoreLimits` | cgroups v2 on the container | cgroups v2 on the **userspace** companion (`hookprobe-dataplane.slice`); the in-kernel part is not cgroup-accountable |
| Supervisor action | **loads** it (sandbox-executes) | **runs** it (Podman) | **enables/attaches** it (systemctl) — does NOT execute it in a sandbox |
| Hot-reload | yes (swap the `.wasm`) | restart container | requires sysext re-merge / `bootc upgrade` (image-layer) |
| Why here | n/a | heavy stateful service | **kernel-coupled**: XDP runs in-kernel; OVS owns a kernel datapath |

## How a sysext extends the OS

`systemd-sysext` merges extension images into `/usr` (and `/opt`) at boot via an
overlayfs, so an immutable bootc rootfs gains host-integral binaries/units **without**
rebuilding the base. A sysext image is a plain directory tree / erofs / squashfs that:

1. mirrors the real hierarchy under `usr/` (e.g. `usr/lib/hookprobe/xdp/aegis_xdp.o`,
   `usr/lib/systemd/system/napse-capture@.service`);
2. carries a marker at `usr/lib/extension-release.d/extension-release.<NAME>` whose
   `ID`/`VERSION_ID`/`SYSEXT_LEVEL`/`ARCHITECTURE` **must match the base os-release** —
   else `systemd-sysext` refuses to merge it (a wrong-OS or wrong-arch sysext cannot load).

At boot `systemd-sysext.service` merges all extensions from `/usr/lib/extensions/`,
`/etc/extensions/`, `/var/lib/extensions/`; then a daemon-reload makes the merged units
visible. HookProbe ships sysext images under **`/usr/lib/extensions/`** so they are
covered by the bootc image signature and travel atomically with `bootc upgrade`/`rollback`.

`image-layer` is the simpler cousin: the files are baked directly into the bootc image
(no overlay, no separate signature). We use it when the base already provides the binaries
(OVS) and the module only adds config + a bring-up unit.

## How the supervisor gates a sysext module (without sandbox-loading it)

A sysext module flows through the **same** `requires`/`grants`/`provides` resolution as a
Wasm module (Architecture C10), but the **action differs**:

1. **Gate by capability.** The supervisor reads the signed manifest. It enables the
   sysext's units **only** when every `requires.capabilities` token is `state == "granted"`
   (`grant = presence ∧ known-good ∧ policy`). Unmet → clean refusal with the reason
   (same as Wasm/container). Example: `napse-capture` stays disabled unless `capture` is
   granted; its inline drop path additionally needs `ddos_mitigation`.
2. **Enable, don't execute.** For Wasm the supervisor *is* the runtime (Wasmtime in-process).
   For a sysext it is NOT: it `systemctl enable/start`s the unit (or installs an OnFailure
   drop-in) and lets systemd run the privileged process. The supervisor itself never holds
   CAP_BPF/CAP_NET_ADMIN — those live on the per-unit process (`AmbientCapabilities`), and
   any *runtime* privileged action (e.g. programming an OVS flow on operator intent) goes
   through the **one OS-Agent bridge** (Architecture §4.4), not the supervisor's own creds.
3. **Budget via cgroups, not Wasmtime.** There is no fuel/epoch/`StoreLimits` for kernel
   code. The supervisor places the userspace companion (XDP loader, OVS daemons' bring-up)
   in `hookprobe-dataplane.slice` and bounds it with cgroups v2 (`CPUWeight`/`MemoryHigh`).
   The in-kernel XDP program / OVS datapath are not cgroup-accountable — accepted and
   stated. Over-budget userspace → throttle the loader, never the host (C11 outer wall).
4. **Track state in the manifest.** `modules[]` gets `runtime: sysext`, a `state`
   (pending/running/failed/…), and the `signature` verification result, exactly like other
   runtimes (ADR 0003 §`modules`).

The honest asymmetry: a sysext gets **real host capabilities a Wasm module can never have**
(no kernel address space, no `bpf(2)`, no netdev admin from WASI). That is *why* these two
engines are sysext/image-layer and not Wasm — and it is precisely the boundary the OS-Agent
privileged bridge exists to keep narrow, single, and auditable instead of scattered.

## Build → sign → ship → merge (CI, not this dev box)

1. **Build** the payload on a CI host that HAS the toolchain (clang/llvm + Zig + kernel
   BTF for eBPF; OVS is already in the base). See `modules/napse-capture/Makefile`.
   Decision (locked): **pre-compiled CO-RE eBPF objects baked into the sysext**, never
   on-device compilation (immutable image; no clang in the base).
2. **Package** the `sysext/` tree (with its `extension-release` marker) into an
   erofs/squashfs sysext image, per arch.
3. **Sign** the sysext OCI artifact with cosign (ADR 0002 `module_signing`); the device
   only VERIFIES. Image-layer modules need no separate signature — the bootc image
   signature covers them.
4. **Ship** under `/usr/lib/extensions/` (sysext) or baked into `/usr` (image-layer);
   `systemd-sysext.service` merges at boot; the supervisor enables units per capability.

## Honest "can't build/run eBPF or OVS here" note

This dev box has **no kernel BPF access, no root, no XDP-capable NIC, and no OVS
datapath**. Nothing under `modules/napse-capture/` or `modules/ovs/` can be compiled,
loaded, or functionally verified here. Everything in those trees is **reviewed scaffold +
build/load design**; genuine unknowns are marked `# TODO` and can only be closed in a
privileged CI VM or on real target hardware. The largest residual risks:

- the **BTF/kernel-version matrix** for CO-RE across Pi5 / RK3588 (BSP + mainline) / N100 /
  cloud (`Makefile` `vmlinux-h`);
- the **native-XDP / OVS-datapath known-good lists** per NIC/driver in `platforms/*.yaml`
  (the pfSense TSO/LRO lesson: "supported" ≠ "safe");
- the **OS-Agent bridge IPC** that runtime privileged dataplane actions must funnel through
  (Architecture §4.4 / runtime-engine-map open-Q 4), still to be specified.
