# heqk Module-Runtime & On-Device-Brain Gap-Map — Track C / Milestone M5

> **Scope.** The M5 milestone turns heqk from a **microkernel-*shaped* monolith** (detection,
> TCP, drivers, rule engine link *into the one EL1 kernel image*) into a real **userspace-server
> substrate** — an EL0 ELF loader + a real syscall surface + **capabilities enforced, not asserted**
> (heqk remediation **R1**) — and then a **Wasm/WASI host** (an EL0 server) that runs the signed
> `.wasm`/`.cwasm` module catalogue (ADR 0016/0017) on heqk at detection parity.
> This document is the **scoping deliverable** — a grounded gap-map. **It changes no code and
> commits nothing.**
>
> Canon: `docs/adr/0044-zero-linux-rpi-native-cm5.md` **D4** (the ranked component contract; #1
> userspace-server substrate = the keystone every isolation claim depends on; #2 Wasm host) + **D5**
> (the honesty floor), `docs/adr/0043` (the substrate keystone), `docs/adr/0016` (artifact-hash
> module signing) + `0017` (authenticated AOT `.cwasm` cache), `kernel/heqk/HEQK_REMEDIATION_PLAN.md`
> (**R1** = "the security mechanism, before any claim holds"), `kernel/heqk/PER_TCB_CSPACE.md` +
> `CAPABILITY_MODEL.md` (the cap model claims), `kernel/heqk/PRODUCTION_READINESS.md` (heqk's
> QEMU-proven surface). Sibling scopings: `heqk-detection-parity.md` (M2), `heqk-persistence.md`
> (M3), `heqk-control-plane.md` (M4).

---

## Honesty header (ADR 0044 D5 — the honesty floor, non-negotiable)

1. **heqk is a microkernel-shaped MONOLITH today.** The capability-microkernel *core* (EL0/EL1
   split, per-ASID VSpaces, preemptive scheduling, the seL4-style CapSpace) is real and QEMU-green.
   But the *product* — detection (`rules.rs`/`verdict.rs`/`classify`), the TCP stack (`smoltcp`),
   the drivers, blocklist, ratelimit, securechannel — **all link into the one EL1 kernel image and
   run at EL1.** The EL0 tasks that exist are hand-written asm *stubs*, not the SOC workload.
2. **M5 is the multi-year weight, not a few-agent milestone.** ADR 0044 D4 calls the userspace-server
   substrate "the keystone" and D5.2/§Consequences calls M5 the "**win the kernel, risk losing the
   SOC**" danger. Unlike M2–M4 (~70% QEMU-closable-soon), **the large majority of M5 is a genuine
   multi-year build + metal**, not a QEMU scaffold you close in a sprint. §4 quantifies this honestly.
3. **QEMU-green ≠ metal.** `validate.sh` gates QEMU only. Every M5 gate below has a QEMU tier AND a
   distinct metal tier; the metal tier is where the isolation claim is actually *earned*.
4. **The heavy stateful tier is NOT in M5.** Per ADR 0044 **D3 (B2, the recommended default)**,
   HYDRA / Mission Control / the tokio services move **off-device** to a hosted control plane. M5's
   Wasm host is the **detection engine** (the product's core), not "the app tier." Do not read M5 as
   "port the whole Linux stack to heqk" — that is explicitly de-scoped.

---

## 1. What heqk has today (M5-relevant surface)

### 1a. EL0/EL1 separation — REAL, not simulated ✅

There *is* a genuine user/kernel split, and it is more than a demo:

- `enter_user(entry, user_sp)` (`arch-aarch64/src/syscall.s`) ERETs to **EL0t** (`SPSR=0x80`,
  IRQ-masked-then-enabled per stub), and **scrubs x0..x30** before the drop so EL0 never starts with
  a live kernel pointer (a deliberate info-leak fix).
- EL0 tasks run in **isolated address spaces** — each gets its own ASID/TTBR0 (`mmu.new_addr_space()`,
  `switch_to` enters the ASID). This is not a shared flat map.
- EL0 is **preemptively scheduled**: `el0_preempt_spawn()` runs an *uncooperative* EL0 loop (IRQs on,
  no syscalls) and proves the timer preempts it — "the box is NOT wedged" (B-6 closed). EL0 is a real
  schedulable TCB, not a cooperative side-path.
- EL0 **faults are contained**: an EL0 data abort traps to `handle_lower_sync`, which **restarts** the
  faulting TCB from its *own* per-TCB record up to `EL0_MAX_RESTARTS = 3`, then **kills** it and
  reschedules — the kernel survives a driver crash (`el0_fault_stub`, the P7c "crash-restart" server).

**Highwater mark:** `cm5_gem_el0_server()` — a continuous **RX → IDS → verdict** loop where an
**isolated EL0 GEM driver** reads frames from a granted NIC ring and survives a crash-restart. This is
the closest thing to a userspace server that exists. **But note the tell:** the *IDS verdict is
computed in the kernel at EL1* — only the driver polling is at EL0. The server pattern is proven; the
*workload* is still in the monolith.

### 1b. The syscall surface — 7 demo syscalls + P12 async pub/sub

Register ABI: `x8` = syscall number, `x0`/`x1` = args `a0`/`a1`, return in `x0`
(`syscall_dispatch(num, a0, a1)`, `main.rs:6118`). The **7 demo syscalls**:

| # | Name | What it does |
|---|------|-------------|
| 2 | `SYS_GETVAL` | returns a constant `0x1234` (liveness demo) |
| 3 | `SYS_HELLO` | prints "hello from EL0" (liveness demo) |
| 4 | `SYS_PRINTVAL` | prints an arg the kernel handed it (liveness demo) |
| 5 | `SYS_CAP_IDENTIFY` | **the one real cap invocation** — resolves a CPtr in the caller's *own* CSpace, returns the object type or `u64::MAX` |
| 6 | `SYS_EXIT_USER` | cooperative EL0 returns control to the kernel (longjmp) |
| 7 | `SYS_DRIVER_REPORT` | an isolated EL0 driver reports one value it read from its device |

Plus the **P12 async signalling** block (16..23): `SYS_SIGNAL/WAIT/POLL/PUBLISH/RECV/SUBSCRIBE/
TASK_EXIT` — a real, cap-gated **notification/pub-sub** IPC (badge read from the cap, never from an
arg; ungranted subscribe → `RC_DENIED`; `SYS_WAIT` is the one blocking syscall and blocks only the
caller). This is the **only IPC heqk has**.

**What is conspicuously absent from the syscall surface:**
- **No `SYS_SEND`/`SYS_CALL`/`SYS_REPLY` on an `Endpoint`.** The `Endpoint` object type *exists as a
  cap* (`ObjType::Endpoint`) but is **inert** — there is no synchronous message-passing IPC. A real
  server substrate needs this.
- **No memory syscall.** EL0 cannot `retype`/`mint`/`map` — every cap operation is performed
  **kernel-side by the spawner**. EL0 can only *read* a cap's type (`SYS_CAP_IDENTIFY`). There is no
  way for a userspace server to *request* memory or a mapping against an Untyped cap it holds.
- **No `SYS_YIELD`, no time syscall, no fault/exception delivery to userspace.** No stable ABI.

### 1c. The capability model — build vs. wire

The seL4-modelled `CapSpace` (`kernel/src/caps.rs`, 610 lines) is genuinely built and self-tested:

- **Untyped → retype → typed objects** (`Untyped/CNode/Endpoint/Frame/Tcb/Notification/Topic`),
  with **zero-on-retype** (CORE-3, closes cross-tenant leak), and the sole allocation path (the
  kernel never mallocs).
- **Derivation tree + synchronous `revoke`** (iterative, no GC), with a **generation-tagged MDB**
  (CORE-9) so a freed-then-reused slot can't be re-attached by a stale child.
- **Rights monotonicity**: `mint`/`mint_into` can only **narrow** rights (`requested & src.rights`),
  never amplify, and require the **Grant** right to delegate.
- **Per-TCB CSpaces** (CORE-2, `PER_TCB_CSPACE.md`): `static CSPACE[MAX_THREADS]`; `SYS_CAP_IDENTIFY`
  resolves against `current_cspace()`, never a global — the confused-deputy fix.
- **CORE-1 — mapping through cap invocation**: `map_frame_cap(slot, va, need)` checks Frame-type +
  rights *before* writing a PTE, derives RO/RW from the cap's rights, and **records `mapped_va` so
  `revoke` invalidates that exact L3 entry + `tlbi`** — revoking a driver's Frame cap actually severs
  its MMIO/DMA/RAM access, not just its CSpace slot.
- Self-tests: `cap_invariants_selftest`, `core9_gen_selftest`, `[P2-iso]` `cspace_isolation_demo`,
  `[P2-unmap]`.

**No ELF loader anywhere.** EL0 code is position-independent **asm stubs** (`user_stub`,
`driver_stub`, `el0_loop_stub`, `el0_fault_stub`, the GEM server) `memcpy`'d into a **single** EL0
code page. No ELF64 parsing, no `PT_LOAD`, no multi-page loader (**DSN-10** open in `GAP_REGISTER.md`).

**No Wasm/WASI runtime anywhere in heqk.** `grep` finds zero `wasm`/`wasi`/`wasmi`/`wasmtime` in the
kernel tree — only design-doc *aspirations*. The heqk `Cargo.toml` deps are `ed25519-compact`,
`smoltcp`, `ml-kem`, `x25519-dalek`, `chacha20poly1305` — no interpreter.

### 1d. R1 — the load-bearing honesty answer: **enforced or asserted?**

The canonical R1 statement (`HEQK_REMEDIATION_PLAN.md:21`): *"The capability system is asserted but
not yet enforced — mapping/IPC/IRQ aren't cap-gated… a data-structure, not a mechanism, today."*

That statement **predates** CORE-1/CORE-2, which have since landed a *partial* enforcement seam. So
the precise, current truth is:

> **The cap model is ENFORCED in one narrow, wired corner — and ASSERTED-only everywhere that a real
> app-host depends on.**
>
> - **Enforced (real mechanism):** Frame-cap → PTE-rights → `revoke`-unmaps (CORE-1); per-TCB CSpace
>   resolution for `SYS_CAP_IDENTIFY` (CORE-2); rights-narrowing, zero-on-retype, generation-safe
>   revoke (self-tested). For the handful of EL0 *stubs*, authority *is* a held, revocable cap.
> - **Asserted-only (data structure, not yet the mechanism):**
>   1. **The actual SOC workload is not cap-mediated at all** — detection/TCP/drivers/rule-engine run
>      at **EL1 in the monolith**, outside the cap system. Caps govern proof-of-concept stubs, not the
>      product.
>   2. **IPC is not cap-invocable as a message channel** — `Endpoint` is an inert type; only the P12
>      pub/sub is enforced.
>   3. **Device-MMIO grants on the CM5 bring-up path are still ad-hoc `map_user_device`/`map_user_data`**
>      (remediation A1), not always a Frame/device-cap invocation.
>   4. **IRQ delivery is not cap-gated.**
>   5. **EL0 cannot invoke cap operations** (no memory/retype/map syscall) — so no userspace server
>      can manage its own authority; the kernel does it *for* the stub at spawn.

**Bottom line for R1:** heqk is past "pure data structure" but far short of "the authority mechanism
the app tier runs under." Call it **enforced-in-a-corner, asserted-at-large.** M5.0 (R1-complete) is
exactly the work of moving mapping / IPC / IRQ / device-grants *all* onto cap invocation, and making
the real workload an EL0 cap-governed server.

---

## 2. The gap to a real app-host

### 2a. What "caps enforced not asserted" (R1) concretely requires

| Gap | Today | R1-complete requires |
|-----|-------|----------------------|
| **IPC** | `Endpoint` cap inert; only pub/sub | Synchronous `SYS_SEND`/`SYS_RECV`/`SYS_CALL`/`SYS_REPLY` gated on an `Endpoint` cap in the caller's CSpace; message registers (a real transfer, not just a badge) |
| **Memory** | kernel-side only; EL0 can't map | A cap-invocation syscall: EL0 requests a mapping *against a Frame/Untyped cap it holds*; `has_rights` gate → RO/RW PTE; fail-closed if the cap is absent |
| **Device MMIO** | ad-hoc `map_user_device` (A1) | Every device window is a **Frame/device cap**; drivers get authority via `mint_into` at spawn; `revoke` severs it |
| **IRQ** | not cap-gated | IRQ delivery bound to an IRQHandler cap → a Notification the driver holds |
| **Workload** | detection/TCP/drivers at EL1 in the monolith | at least the driver + net + (eventually) detection run as **EL0 servers**, each holding *only* its granted caps |
| **Fail-closed proof** | `[P2-iso]` on local CSpaces | a *scheduled* second EL0 TCB that lacks a cap is **denied at the syscall boundary** (`RC_DENIED`), while the holder succeeds — the confused-deputy fix demonstrated end-to-end |

### 2b. What an EL0 ELF loader + real syscall surface needs

- **ELF64 parse** (no_std, no alloc): validate header, iterate `PT_LOAD`, reject bad/overlapping
  segments. Source: a signed blob from the sealed store (M3) or the module catalogue.
- **Multi-page mapping (DSN-10)**: retype N Frames from an Untyped, `map_frame_cap` each into a fresh
  per-TCB VSpace at the ELF vaddrs, with **W^X** (code RX, data RW — reuse the `jit_seal`/W^X seam,
  needs mmu.rs parity per remediation X1), set up a stack Frame + `PT_GNU_STACK` policy, set the entry.
- **Spawn as a scheduled TCB**: fresh CSpace (`CapSpace::empty()`) minted with *exactly* its grant set;
  `make_el0_thread`; a per-TCB restart record (CORE-6). This substrate already exists for stubs — the
  loader replaces `memcpy(stub)` with `load_elf(signed_blob)`.
- **A stable syscall ABI**: the current 7-demo + P12 set is not a substrate ABI. Need at minimum
  `map`/`unmap` (cap-gated), `send`/`recv`/`call`/`reply` (Endpoint IPC), `yield`, `exit`, a time
  read, and a fault/notification delivery path — versioned, documented in `abi/`.

### 2c. What a Wasm/WASI host as an EL0 server needs — and which runtime is even feasible

The host is itself an **EL0 ELF server** (loaded by 2b) that embeds a Wasm engine and shims WASI over
heqk syscalls. The runtime choice is the crux:

| Candidate | no_std / EL0 aarch64? | Verdict |
|-----------|----------------------|---------|
| **wasmtime** (the Linux-tier engine, `.cwasm` AOT) | **No** — needs `std`, Cranelift JIT, an OS mmap/signal model | Out for on-device. (Its AOT `.cwasm` artifacts are also x86/aarch64 *native* code baked for Linux — not runnable under a heqk W^X server without a JIT the host doesn't have.) |
| **wasmi** (pure-Rust **interpreter**) | **Plausible** — `no_std`-capable, no JIT, bounded memory | **The feasible near-term path.** Slower than JIT, but interpretation is the only realistic option under a no_std/EL0/W^X server without shipping a code-gen backend. |
| **bespoke minimal interpreter** | yes (full control) | Viable for a *one-module* beachhead; not for catalogue parity. |
| **WASI 0.2/0.3 component model host** | effectively **research-grade** on no_std/EL0 | **Not near-term.** The component model + `wit-bindgen` host runtime is heavy; heqk's modules are **`wasm32-wasip1`** (WASI Preview 1) *today*, which is the tractable target. |

**Honest note on the ABI mismatch:** `CLAUDE.md` aspires to "WASI 0.2/0.3 components." The actual
module binaries build to **`wasm32-wasip1`** (`modules/*/Cargo.toml`). A **wasmi interpreter + a
hand-rolled WASI-p1 shim** (clock, random, a stdout/log sink, and a heqk-native import surface for
packet-in / verdict-out) is the feasible M5.2 target. A WASI-0.2-component host on heqk is a *later*,
separate, large effort — do not scope it into M5.

WASI-NN (inference, `CLAUDE.md`) has **no no_std/EL0 host** and is out of M5 entirely.

---

## 3. The phased M5 plan (each phase a testable gate)

Ordered per ADR 0044 D4 (server substrate → Wasm host → detection parity — "prove the *product* runs
on heqk early, not last").

### M5.0 — R1: cap-enforcement + real IPC (**the prerequisite; no claim holds without it**)
Move mapping / IPC / IRQ / device-grants onto cap invocation. Add synchronous `Endpoint` IPC. Make a
*scheduled* second EL0 TCB fail-closed when it lacks a cap.
- **Gate `[P-r1-ipc]`** (QEMU): two scheduled EL0 TCBs; a server holds an `Endpoint` cap and `RECV`s,
  a client holds a delegated `Endpoint{send}` and `CALL`s → message delivered; a third TCB **without**
  the cap `CALL`s → **`RC_DENIED`** (fail-closed). Revoke the client's cap mid-run → subsequent
  `CALL` denied.
- **Gate `[P-r1-map]`** (QEMU + metal): an EL0 task maps a Frame *only* via a held cap; `revoke`
  severs the mapping (next access faults). Device-MMIO on the CM5 path routed through a Frame cap (A1).

### M5.1 — Userspace-server substrate: EL0 ELF loader + real syscall surface (**ADR 0044 D4 #1 KEYSTONE**)
Replace `memcpy(stub)` with `load_elf(signed_blob)`; multi-page W^X mapping (DSN-10); the stable ABI
of §2b.
- **Gate `[P-elf]`** (QEMU then metal): load a real **signed** ELF from the store, run it at EL0 in its
  own CSpace/VSpace, it makes real syscalls (map + Endpoint IPC) through **enforced** caps, W^X
  enforced (writing code faults), fault-isolated (a wild write is contained + restarted), killable.

### M5.2 — Wasm/WASI host as an EL0 server
A wasmi-based (or bespoke) interpreter, loaded as an EL0 ELF server by M5.1, with a WASI-p1 shim over
heqk syscalls, running **one** signed `wasm32-wasip1` module.
- **Gate `[P-wasm-1]`** (QEMU then metal): one signed module (ADR 0016 hash-verify → ADR 0017
  authenticated-cache admission) executes on the heqk host, its output is verified against a known
  vector, and the host is confined to EL0 (a module trap does not escape the server; the server trap
  does not escape heqk).

### M5.3 — The signed catalogue at detection parity
Run the real detection modules (`napse-dpi`, `aegis-guard`, `qsecbit`, `dnsxai`) on the heqk Wasm host,
wired to the packet plane, producing verdicts that match the Linux M1 catalogue and pass the M2
`0.7-separation-matrix` (ties into `heqk-detection-parity.md`).
- **Gate `[P-cat]`** (metal, under load): catalogue **verified → running → producing** verdicts; the
  separation matrix (legit-always-passes + attacks-caught, both directions) holds on heqk **metal**.

---

## 4. The honest QEMU-scaffold vs. multi-year vs. metal split

**This is NOT M2–M4.** Those were ~70% QEMU-closable-soon. M5 inverts that ratio.

| Piece | QEMU-scaffoldable soon? | Reality |
|-------|------------------------|---------|
| M5.0 `Endpoint` IPC syscalls + fail-closed `[P-r1-ipc]` | **Yes** — days-to-weeks | Rides the working per-TCB CSpace + EL0 scheduler. A real beachhead. |
| M5.0 route mapping/device-grants through caps (A1) | **Partly** — QEMU seam exists (CORE-1); metal CM5 path is the work | The QEMU half is close; the metal DMA/IOMMU-containment half is not. |
| M5.1 a **minimal** single-file ELF loader running a hand-built ELF | **Yes** — a demonstrable QEMU beachhead | A one-segment loader is tractable; multi-page W^X + signed-blob + the full ABI is more. |
| M5.2 a **tiny interpreter running ONE trivial signed module** | **Yes-ish** — a QEMU proof is buildable | wasmi-in-no_std brings porting friction; a one-module proof is a milestone, not the host. |
| **Full cap-enforcement TCB** (every mapping/IPC/IRQ/DMA cap-gated + W^X both backends + verified) | **No** | **seL4-grade, multi-year.** The whole isolation claim rests here. |
| **Production Wasm/WASI host** (WASI-p1 parity, resource metering / fuel-epoch equivalents, the full module ABI, WASI-0.2 later) | **No** | **Multi-year.** Interpreter perf on a softfloat A76 is an open risk vs. the Linux wasmtime-AOT baseline. |
| **Whole signed catalogue at detection parity UNDER LOAD on metal** | **No** | **Multi-year + metal.** Depends on M5.0–M5.2 *and* M2's metal Gate R. |
| Heavy stateful tier (HYDRA / MC) | **N/A** | **Off-device (ADR 0044 D3 B2).** Not in M5 at all. |

**Estimate (stated plainly):** roughly **~15–20% of M5 is QEMU-scaffoldable-soon** — the beachheads:
cap-enforced IPC, a minimal ELF loader, a one-module interpreter proof. The remaining **~80%+ is a
genuine multi-year build plus metal validation** — the full cap-enforcement TCB, the production Wasm
host, and catalogue parity under load. Anyone reading "M5 in progress" should read it as *"the
multi-year keystone has begun with a tractable beachhead,"* **not** *"nearly done."* The M1 **Linux**
image remains the canonical rpi-native shipping SOC until each M5 gate is green on heqk **metal**
(ADR 0044 §Consequences).

---

## 5. Recommended first target — the R1 beachhead (the "caps enforced not asserted" proof)

**Smallest real step toward the D4 #1 keystone: convert the inert `Endpoint` cap into an ENFORCED
IPC mechanism on the substrate that already works, and prove it fails closed — in QEMU.**

Concretely:
1. Add synchronous **`SYS_CALL`/`SYS_RECV`/`SYS_REPLY`** gated on an `Endpoint` cap resolved in the
   caller's **own** per-TCB CSpace (missing/wrong-type/wrong-rights cap → **`RC_DENIED`**, fail-closed).
   A minimal fixed-size message-register transfer (no ELF loader needed yet — reuse the existing EL0
   stub-spawn path).
2. New gate **`[P-r1-ipc]`**: spawn two scheduled EL0 TCBs from stubs; delegate an `Endpoint{send}`
   cap to the client via `mint_into` at spawn; the server `RECV`s and the client `CALL`s → message
   delivered. Spawn a **third** TCB with **no** Endpoint cap; its `CALL` returns `RC_DENIED`. Revoke
   the client's cap and prove the next `CALL` is denied.

**Why this first, ahead of the ELF loader:** it directly closes the R1 honesty gap (`Endpoint` inert →
`Endpoint` enforced), it makes IPC — the thing a userspace server *is* — a real cap-invocation, and it
rides the already-proven per-TCB CSpace + preemptive-EL0 + fault-restart substrate **without** first
building the multi-page ELF loader. The loader (M5.1) then rides on top of a substrate whose authority
model is already enforced, so the ELF-loaded server inherits a real mechanism instead of an asserted
one. It is the literal "prove ONE EL0 task making a real syscall through an ENFORCED capability that
fails closed" that ADR 0044 D4 #1 gates on — the beachhead, then the loader.

---

## 6. Open questions to route (not resolved here)

- **PRODUCTION_READINESS.md drift** — its roadmap still reads "M5 loader+Wasm host → **M6 app-tier
  Linux guest** → M7 unbuild." **M6-as-Linux-guest is superseded by ADR 0044 D1/D3** (zero Linux on
  CM5; app tier native-on-heqk *or* off-device). `product-steward` should reconcile PR §"Migration
  continuation" and `MIGRATION-heqk.md` M6 to the D3 framing. (Same class of P7-vs-§5a drift the task
  brief flags.)
- **WASI version honesty** — `CLAUDE.md` says "WASI 0.2/0.3 components"; the modules build
  `wasm32-wasip1`. M5.2 targets WASI-p1 (feasible); a component-model host is a later, separate effort.
  Flag, don't silently resolve.
- **AOT question** — the Linux `.cwasm` (ADR 0017) is wasmtime-AOT *native code*, not runnable under a
  no_std interpreter. On heqk the "authenticated AOT cache" either (a) degrades to
  authenticated-`.wasm` + interpret, or (b) waits for a heqk-native code-gen backend (out of M5).
  Decide + record when M5.2 lands.
</content>
</invoke>
