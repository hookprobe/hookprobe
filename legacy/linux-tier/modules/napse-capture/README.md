# napse-capture — kernel XDP/eBPF packet intake (systemd-sysext)

> **A2 LEGACY NOTE:** the "Build → ship → run" / "Out-of-band default" sections below
> describe the original Zig/C `napse-xdp-attach` → `napse-capture@<iface>` orchestrator
> design. That Zig loader (`napse-xdp-loader`) is no longer in the tree; the units that
> `ExecStart` it (`napse-capture@.service`, `napse-capture-failclosed@.service`) have been
> moved to `legacy/` (marked, not deleted — not staged by `builder/gen-staging.sh`, which
> only stages units this module's `module.yaml` `staging.units` lists explicitly). The
> module's WORKING, actually-staged artifact today is the Rust `napse-loader`/`napse-dpi`
> path (see `module.yaml`'s `staging:` block + `loader/`).

> The honest exception to "logic = Wasm". An XDP program runs **inside the kernel** at
> the NIC RX path; a WASI sandbox cannot. So NAPSE capture ships as a **sysext** that
> extends `/usr`, the supervisor **gates it by capability and enables it** (it does NOT
> Wasmtime-load it), and the kernel program is budgeted by a **host cgroup slice**, never
> by fuel/epoch. Crown-jewel V1 Zig/C dataplane, repackaged — not rewritten.

Canon: `docs/architecture/runtime-engine-map.md` (§0, §4 sketch), `docs/architecture/Readme.md` (Pillar 1 sysext;
"Data plane"), `docs/architecture/Architecture.md` (C12 NIC→fast path; §4.4 OS-Agent bridge),
`docs/adr/0003-platform-manifest-schema.md` (module model; `runtime: sysext`).
Sysext mechanics + supervisor gating: `../../base/sysext/README.md`.

## Why sysext (not Wasm, not container)

`runtime: sysext`. An eBPF/XDP program executes in kernel space, needs `bpf(2)` +
`CAP_BPF`/`CAP_NET_ADMIN`/`CAP_NET_RAW`, and owns AF_XDP rings — none of which a Wasm
module can have (no kernel address space, no privileged syscalls). The userspace loader
is host-integral and pairs with kernel objects, so it belongs in `/usr`, delivered as a
signed `/usr` overlay merged at boot by `systemd-sysext`.

## Host capabilities = the honest WASI boundary

| Cap | Why XDP needs it | Why a Wasm module can never have it |
|---|---|---|
| `CAP_BPF` | `bpf(2)`: load XDP prog, create/update maps + ring buffer | Wasm has no syscall surface; bpf() is unreachable from WASI |
| `CAP_NET_ADMIN` | attach/detach XDP on a netdev; configure AF_XDP / TC | WASI grants are filesystem/socket handles, not netdev admin |
| `CAP_NET_RAW` | AF_XDP raw-frame RX rings | WASI has no raw-frame access by design |

These are scoped to the per-interface worker process (`AmbientCapabilities` in
`napse-capture@.service`), not granted host-wide. This is exactly **why** the engine is a
sysext and not Wasm — and it is the boundary the OS-Agent privileged bridge exists to keep
narrow and auditable (Architecture §4.4): the supervisor never holds these caps; it only
enables the unit that does.

## eBPF on an immutable image — decision

**Pre-compiled CO-RE objects baked into the sysext** (NOT on-device compilation). The
bootc rootfs is immutable + read-only `/usr`; shipping clang/llvm/headers would bloat the
image and widen attack surface. CO-RE + BTF relocations let one object run across kernel
versions. CI builds the objects (`Makefile`), they are baked into the sysext, and the
sysext is cosign-signed. Residual risk = the **BTF/kernel-version matrix** (`Makefile`
`vmlinux-h` TODO): kernels without `CONFIG_DEBUG_INFO_BTF` (some vendor RK3588 BSPs) need a
shipped BTF blob + libbpf fallback.

## Build → ship → run

1. **Build (CI host, has toolchain):** `make all` compiles `xdp_program.zig` → `aegis_xdp.o`,
   the C drop objects (`xdp_synwall/gate/flow_ctrl.o`) via `clang -target bpf -g`, and the
   Zig loader → `napse-xdp-loader`, staged under `sysext/usr/lib/hookprobe/`.
2. **Package:** the `sysext/` tree (incl. `extension-release.d/extension-release.napse-capture`)
   becomes an erofs/squashfs sysext image, pushed as a per-arch OCI artifact, cosign-signed.
3. **Ship:** baked into / shipped alongside the bootc image under `/usr/lib/extensions/`
   (covered by the image signature). Merged at boot by `systemd-sysext.service`.
4. **Run:** supervisor sees `capabilities.capture == granted` → enables
   `napse-capture.service`, which reads the manifest and starts one
   `napse-capture@<iface>` worker per selected interface.

## Out-of-band default / inline opt-in / fail-open|closed

The orchestrator (`napse-xdp-attach`) converts manifest `network.interfaces[]` into
posture:

- **out-of-band (default):** attach the **passive** object (`aegis_xdp.o`), always
  `XDP_PASS` + feed a copy to `/var/lib/hookprobe/flows`. Inherently fail-open: detaching
  the program leaves traffic untouched. Allowed whenever `capture` is granted.
- **inline (opt-in):** attach a **drop** object — only when `ddos_mitigation` is granted.
  `fail_mode` (from the manifest) decides crash behavior:
  - **fail-open (default):** worker `ExecStopPost` detaches XDP → traffic flows.
  - **fail-closed:** `napse-xdp-attach` installs an `OnFailure=` drop-in pointing at
    `napse-capture-failclosed@<iface>.service`, which pins a drop-all object so the
    segment blocks until an operator clears it.

This realizes Architecture C12 ("per-interface fail-open default / fail-closed policy;
out-of-band sees a copy only") and the Readme "an edge box must never take the network
down with it" invariant.

## TODOs only CI / real hardware can close

- Build + verifier-load the objects per target arch in a privileged CI VM (`Makefile` `verify`).
- The **BTF/kernel matrix** (Pi5 / RK3588 BSP+mainline / N100 / cloud) — the real open risk.
- Finalize the V2 loader CLI (`--object/--mode/--flows/--detach`, `sd_notify` READY+WATCHDOG);
  V1 `main.zig` is a scaffold today.
- Author `xdp_drop_all.o` for the fail-closed handler.
- Native-XDP **known-good NIC list** in `platforms/*.yaml` (TSO/LRO/native-XDP safety) so
  `xdp_mode_for` chooses `native` instead of always `skb`.
- ADR 0003: add a `sysext` resources tier + a `min_kernel`/BTF gate; reconcile the
  `provides: [capture]` vs `[flows, packets]` token choice (flagged in `module.yaml`).
