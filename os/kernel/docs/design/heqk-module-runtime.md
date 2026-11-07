# heqk M5 — the module runtime (the Wasm host road, ADR 0044 D4 #2 / D5)

> **Status: reconstructed 2026-09-11 from the authoritative in-tree sources.** Code
> is the source of truth. Canonical sources: `validate.sh` (`[P-elf]`, `[P-wasm]`,
> `[P-wasm-el0]`, `[P-wasmi-el0]`, `[P-wasm-parity]`, `[P-wasip1]`, `[P12]`),
> `kernel/src/wasmhost.rs`, `el0-wasmhost/`, `wasip1-fixture/`, `kernel/src/elf.rs`.
> Cited by `wasmhost.rs` (§M5.2) before it existed; reconstructed so the canon ref
> resolves.

## 0. Why a module runtime, and why it must NOT live in the kernel

The Linux/UEFI tier runs detection logic as Wasm components (CLAUDE.md decision #2).
On the CM5/heqk tier the same portable modules must run **on heqk** — but the
kernel is a capability microkernel whose TCB must stay minimal. So the **Wasm host
is an EL0 server**, never kernel code: the interpreter's text lives in an isolated
EL0 task (own ASID/TTBR0, own per-TCB CSpace, own heap window), the kernel is only
the **trust root** (it Ed25519-verifies a module BEFORE any hand-off) and the IPC
endpoint the verdict returns over. Each step below is an ADR 0044 D4 #2/#4 sliver,
built at minimal scale and QEMU-gated; the "multi-year road" (signed catalogue at
detection parity, WASI 0.2) is scoped, not faked (D5).

## M5.0 / P12 — the substrate the host inherits

`[P12]` notification objects + capability pub-sub (seL4 Signal/Poll OR-coalescing,
topics-as-caps — an ungranted subscribe is REFUSED via `has_rights`), a blocking
WAIT syscall woken by Signal under the scheduler, badge-from-cap. The EL0 host
talks to the kernel over an **enforced Endpoint capability** (M5.0), inherited by
every later step.

## M5.1 — ELF loader beachhead (`[P-elf]`, `elf.rs`)

A MINIMAL bounds-safe ELF64/aarch64 **static** loader replaces the hand-asm EL0 stub
path with parse→map→run. PT_LOAD segments are mapped into a fresh per-TCB VSpace
through the ENFORCED CORE-1 `map_frame_cap` path (R+X code / RW data, **W^X**: a
segment requesting W+X is rejected at parse AND at map). Fail-closed parser:
truncated / bad-magic / non-ELF64 / wrong-machine / out-of-bounds phdrs or file
ranges / memsz<filesz / oversize / unaligned / overlapping images all refuse for the
right reason, never OOB, never partial-map. Not a dynamic loader (no relocations,
no shared libs).

## §M5.2 — the Wasm-host BEACHHEAD (`[P-wasm]`, `wasmhost.rs`)

Verify-then-run ONE signed `.wasm`: a memoryless detection-shaped module
`classify(port) -> {0,1}` (1 iff port==4444 — rule 1 "block-port-4444"),
hand-assembled and **Ed25519-signed** in `build.rs`, is Ed25519-VERIFIED by the
kernel using heqk's real per-artifact hybrid (Ed25519 + SLH-DSA; **not** ML-DSA-65,
which is not on heqk) before it runs. A tampered module is refused before any
execution. This is the first sliver of the road, executed by a bespoke 5-opcode
interpreter (replaced by real wasmi in M5.3).

## M5.2b — the host AS an EL0 server (`[P-wasm-el0]`)

The M5.2 execution engine (`exec_expr`) is relocated OUT of the kernel into an
isolated EL0 task. The kernel (trust root) verifies the signed fixture and
bounds-safely locates `classify()`'s code before hand-off; the EL0 host then
interprets `classify(4444)` at EL0 and returns the verdict over the cap-gated
`SYS_CALL` / Endpoint. Shape of ADR 0044 D4 #2 at minimal scale.

## M5.3 — REAL wasmi in an EL0 server (`[P-wasmi-el0]`, `el0-wasmhost/`)

ONE signed module through a genuine **wasmi 0.32** interpreter living in an
isolated EL0 binary — NOT the kernel. wasmi's ~326 KiB `.text` is loaded via the
M5.1 ELF loader into an EL0 task (own ASID/TTBR0, own bump-heap over a
kernel-mapped 256 KiB window, own `#[global_allocator]`); the kernel TCB gains only
the `include_bytes!` of that image (kernel `.text` size printed to prove no bloat).
The EL0 host is a detached-workspace crate built to an aarch64 ELF by a nested cargo
build in `build.rs`; loader caps raised 64 KiB→2 MiB / 4→8 segments (all bounds,
W^X, overflow, overlap checks kept). (a) LIVE: `classify(4444)` AND `classify(443)`
computed THROUGH wasmi and packed (`0x0001_0000`) — proving the predicate genuinely
computes; (b) FAIL-CLOSED: a tampered module → no EL0 host spawned; (c) ISOLATION: a
second host running a signed module whose `classify` is `unreachable` traps INSIDE
wasmi at EL0 and returns the FAIL sentinel — host A's verdict intact, kernel
survives. **Metal-proven on CM5 2026-09-09** (`[P-wasmi-el0-metal]`, synchronous
excursion — Option B, because cm5 prod is IRQs-off; see memory
`hookprobe-heqk-m5-wasmi-el0`).

## M5.4 — detection AT PARITY (`[P-wasm-parity]`, ADR 0044 D4 #4 small scale)

A signed detection-shaped module with **linear memory** + a bespoke minimal
host-import shim (`hp_input(ptr,cap)->len` reads the L4 header into linear memory;
`hp_emit(verdict)`) runs through real wasmi in the isolated EL0 host, and its
per-input verdict **matches the in-kernel `rules::run_l4` case-for-case** over the
L4 header set. The real IDS-rule-as-Wasm use. **Metal-proven 2026-09-09**
(`[P-wasm-parity-metal]`, `0x11111222 == kernel`, tamper-refused).

## M5.5 — REAL WASI preview1 host (`[P-wasip1]`, `wasip1-fixture/`)

TWO signed `wasm32-wasip1` STD modules (stdin/stdout — the PRODUCTION module shape:
`napse-dpi` / `dnsxai` / `qsecbit` ARE wasm32-wasip1 binaries) run through real wasmi
in isolated EL0 hosts over the genuine WASI preview1 ABI (`fd_read`, `fd_write`,
`environ_sizes_get`, `environ_get`, `proc_exit`) — NOT the bespoke shim. Each host
reads a 16-B L4 header from STDIN, classifies the big-endian dst-port, writes a 1-B
verdict to STDOUT; dst-port 4444→DROP and 443→PASS (a pair proves the predicate
runs over real WASI stdin). Fail-closed: a bad-signature module is refused before
hand-off. The std module needs a MiB-scale heap window + its own 64 KiB module
window. QEMU-proven; on metal the GB5 2-MiB window is too small for a MiB heap — a
future cm5 concern.

## What is NOT built (honest scope, ADR 0044 D5)

- The full **signed module catalogue** (`napse-dpi` / `aegis-guard` / `qsecbit` /
  `dnsxai`) running at detection parity as a fleet artifact.
- **WASI 0.2 / component model** (only preview1 today).
- A scheduler/IPC-driven host on cm5 (prod is IRQs-off; hosts run as synchronous
  excursions).
- Field-updatable signed rules (DET-2 dynamic load: RState table + storage/HYDRA
  transport) — the `[P8-det2]` gate exists; the wiring is the follow-on.
