# napse-capture — eBPF/XDP source map (V1 → V2)

> Where the kernel programs come from and how they map into this sysext. The V1
> sources are the crown jewel (runtime-engine-map: "Repackage as-is"); V2 does NOT
> rewrite the dataplane, it **repackages** it into a signed, pre-compiled sysext.

## V1 sources (in `~/hookprobe`, first-hand inspected 2026-06-28)

| V1 file | Lang | Role | V2 disposition |
|---|---|---|---|
| `core/napse/aegis/src/xdp_program.zig` | Zig (→ bpfel) | passive inspect: parse eth/ip/tcp/udp, Shannon entropy, 32-dim feature vector, `XDP_PASS` | compile to `aegis_xdp.o` (CO-RE), bake into sysext |
| `core/napse/aegis/src/{ring_buffer,entropy,feature_extract}.zig` | Zig | BPF ring buffer + feature math | compiled into the same object / loader |
| `core/napse/aegis/src/main.zig` | Zig | userspace loader (libbpf FFI: `bpf`,`elf`,`z`) | becomes `napse-xdp-loader` |
| `core/napse/aegis/build.zig` | Zig | builds BPF obj (`bpfel-freestanding`) + loader | drives the image-build compile (see ../Makefile) |
| `core/napse/kernel/xdp_gate.c` | C eBPF | inline gate / drop logic | drop fast path → gated by `ddos_mitigation` |
| `core/napse/kernel/xdp_synwall.c` (+`.o`) | C eBPF | SYN flood wall (DDoS) | drop fast path → `ddos_mitigation` |
| `core/napse/kernel/xdp_flow_ctrl.c` | C eBPF | flow control / rate | drop fast path → `ddos_mitigation` |
| `core/napse/kernel/af_xdp_rx.c` | C | AF_XDP RX ring consumer | loader RX path |
| `core/napse/kernel/ringbuf_events.c` | C eBPF | ring buffer event export | loader → `/var/lib/hookprobe/flows` |
| `core/napse/kernel/{syscall_monitor,process_tracer,conntrack_lite}.c` | C eBPF | host telemetry (syscall/proc/conntrack) | SEPARATE capability `host_telemetry`, NOT `capture` — out of scope for this module (runtime-engine-map §2) |
| `core/napse/aegis/aegis.toml` | TOML | capture config (interface, ring size, xdp_mode, protocol parsers) | template → manifest-driven (see ../sysext/.../napse-xdp-attach) |

## What this module ships (scope = `capture`)

- The **passive out-of-band** inspect program (`aegis_xdp.o`) — always `XDP_PASS`,
  feeds a feature/flow copy to userspace. Zero risk to connectivity by construction.
- The **drop fast-path** objects (`xdp_gate.o`, `xdp_synwall.o`, `xdp_flow_ctrl.o`) are
  ALSO baked in, but only attached when `ddos_mitigation` is granted AND a per-interface
  policy opts into inline drop (see fail-open/closed wiring in ../README.md).

`host_telemetry` (syscall/process/conntrack eBPF) is a DIFFERENT capability and would be
a sibling sysext (`napse-host-telemetry`); deliberately not bundled here.

## Honest limits (cannot be closed on this dev box)

- These are kernel programs: no BPF, no root, no XDP-capable NIC here → **cannot compile,
  load, or verify** in this environment. Everything below is reviewed scaffold.
- The `.o` placeholder under `../sysext/usr/lib/hookprobe/xdp/` is empty; CI fills it.
