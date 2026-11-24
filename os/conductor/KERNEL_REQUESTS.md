# Kernel requests for the unified runtime (KR-1 to KR-3)

> **Status: requests to HomePods, 2026-11-24. They change nothing.** `os/kernel/**` is HomePods-owned and
> was not modified. Evidence is cited against `main` @ `1ce96d52`. Published by operator decision under
> ADR 0067 D12 (2026-11-24). Format follows `docs/research/neuro/12` (requests R0–R9); KR-1
> is that document's R2, restated with current evidence and gates. KR-2 is new.

The target: *a unified, AI-native operating runtime where neural computation, networking, security,
applications and autonomous execution are first-class native workloads.* Networking, security and
autonomous execution already are (or are built and waiting to be wired). Two things stop the other two:

| Workload | What stops it today | Request |
|---|---|---|
| Neural computation | every EL0 server is scalar integer: FP/SIMD traps, so no vector kernel can run | **KR-1** |
| Applications | the EL0 servers are compiled into the image; nothing can be added, replaced or removed at run time | **KR-2** |
| Delegated AI (Conductor C1, ADR 0071) | the delegation signer, its sealed counter and epoch, leases and the ledger exist only as a tested library; the kernel has none of them | **KR-3** |

### HomePods' response (2026-11-24, hookprobe/hookprobe#1580, `docs/design/heqk-conductor-kernel-requests-response.md`)

| Request | HomePods | What it means here |
|---|---|---|
| **R0** | Answered from the CM5's metal `[T0-inv]` inventory: Cortex-A76 r4p1, FP and AdvSIMD (with FP16), **DotProd = 1**, SVE = 0. `CPTR_EL2.TFP`, `CPACR_EL1.FPEN`, `SCTLR_EL1.A` and `HCR_EL2.E2H` are now read by the `t0inv` build. One USB-flashed boot after the 72 h soak reads them | The engine's SDOT kernels (`neuro-kernels`, `neon-proof`) match the silicon. No SVE path is needed |
| **KR-1** | Accepted in principle as a proposed ADR. It takes this request's design, plus two hard rules: a second FP/SIMD grant fails the build until registers are scrubbed when the owner changes, and `SCTLR_EL1.A` is cleared explicitly. It needs the operator's decision and the G46 review. Implementation starts after acceptance, and after the soak | It matches the request, including the alignment rule (Q8_0's 34-byte blocks) |
| **KR-2** | Agreed in this request's order, (a) to (d). The signing policy (vendor root only, or owner-signed third party) is the operator's decision, together with Neuro R5 | It needs an operator decision |
| `el0-harness` behind a feature | Fine, as a bench feature with the size gate and no shipping change, **on request** | **Requested** (below) |
| **KR-3** | Not yet seen: it was written after their response (hookprobe/hookprobe#1579) | Waiting for their answer |

**KR-1's ADR is 0072** (`docs/adr/0072-el0-fpsimd-grant.md`). HomePods filed it as 0071, which the Conductor ADR
already held (hookprobe/hookprobe#1578), so it was renumbered by operator decision (2026-11-24).

**Request: the `el0-harness` bench feature.** Add `os/conductor/el0-harness` to `kernel/build.rs` behind a bench
feature, as `neuro` was added:
- no shipping change;
- the size gate (`.text` 90,736 B, `.bss` 52,408 B, `.data` 0);
- its address range assigned.

It needs nothing from KR-1, KR-2 or KR-3: zero FP/SIMD instructions and one syscall. It is the first Conductor
code to run on heqk, and the first place to time Ed25519 verification at opt-level "z" on the A76.

None of the requests brings in Linux, POSIX, a filesystem, a dynamic linker or an interpreter. All keep
tensor maths and application logic out of EL1.

---

## KR-1 — FP/SIMD for one EL0 server (= Neuro R2)

### Evidence

- No code writes `CPACR_EL1` or `CPTR_EL2`: a search for `cpacr|cptr_el2|fpen` over `os/kernel` finds
  nothing. What the firmware leaves there is not published (Neuro `12` R0).
- The thread frame is 34 words: `x0..x30, ELR_EL1, SPSR_EL1, SP_EL0` (`arch-aarch64/src/thread.rs:3-11`).
  No V registers, no FPCR/FPSR.
- Every crate builds for `aarch64-unknown-none-softfloat` (`.cargo/config.toml:3`,
  `rust-toolchain.toml:11`).
- The gap is known and undecided: `GAP_REGISTER.md:21` CORE-7 ("FP/SIMD traps; frame saves no q-regs;
  leak if FPEN later set") and `:86` XC-8.
- Cost of not having it: integer-scalar GEMV is an estimated 10–30× slower than SDOT (Neuro `08` C1).
  That is fine for the temporal and specialist tiers, and rules out a language model.

### Request (the smallest interface)

1. **A per-server grant.** One EL0 server may be marked `FpSimd` (a static flag at build time is enough
   for the first step; a capability later).
2. **Enable only inside that server's excursion.** On entry to its excursion the kernel sets
   `CPACR_EL1.FPEN = 0b01` (EL0 only); on exit it restores trapping. EL1 never uses FP/SIMD and stays
   softfloat, so a stray vector instruction in the kernel still traps.
3. **State belongs to that server only.** The kernel keeps one save area (V0–V31, FPCR, FPSR: 528 bytes)
   for it. With a single `FpSimd` server and excursions that run to completion, the registers can be saved
   on exit and restored on entry; nothing else can observe them because nothing else has FPEN.
4. **Scrub before anyone else could see them.** If a second `FpSimd` server ever exists, or once ADR 0060
   SMP lands, the kernel zeroes or switches the registers on every change of owner. Until then the rule is
   "one owner, FPEN off everywhere else", which needs no scrub.
5. **Fault containment unchanged.** An FP/SIMD trap in a server without the grant ends that excursion,
   exactly like any other fault today.
6. **Build.** That one server's crate builds for `aarch64-unknown-none` (hard-float). Its ELF is still
   loaded by `elf.rs`, W^X, in its own address space (`el0as.rs`).

Not asked: FP in EL1; lazy trapping schemes; SVE/SME (absent on Cortex-A76); any change to the 33 other
frame words.

### Readouts needed first (Neuro `12` R0: ID registers answered by HomePods on metal, control registers read by `t0inv` after the soak)

`CPACR_EL1` and `CPTR_EL2` as firmware leaves them; `ID_AA64ISAR0_EL1` (DotProd) and
`ID_AA64PFR0_EL1` (FP, AdvSIMD). `hboot/src/t0inv.rs` already has the `mrs` reader; these are a few more
lines there. If `CPTR_EL2.TFP` is set, hboot must clear it for EL0/EL1 or every vector instruction traps
to EL2.

**Alignment (added 2026-11-24).** GGUF `Q8_0` blocks are 34 bytes, so the kernels' 16-byte loads are
unaligned. The granted server's model region and arena must be Normal cacheable memory, and
`SCTLR_EL1.A` must be clear. heqk today ORs M, C, I and WXN into `SCTLR_EL1` (`arch-aarch64/src/mmu.rs`,
`mmu_cm5.rs`) but never writes A, so it keeps whatever firmware left. The request: clear A explicitly in
the same write. The kernels are then built without `strict-align`. With strict alignment the compiler
splits every 16-byte load into 16 byte loads: measured 6.2 instead of 1.4 instructions per multiply-add
(`neon-proof` benchmark).

### Gates

| Gate | Where | Pass |
|---|---|---|
| `[P-fpsimd-align]` | QEMU | the granted server performs an unaligned 16-byte load from its model region without a fault |
| `[P-fpsimd-grant]` | QEMU | the granted server runs a NEON self-test (SDOT dot product, known answer) |
| `[P-fpsimd-deny]` | QEMU | a server without the grant executing one vector instruction faults; the kernel and other servers continue |
| `[P-fpsimd-leak]` | QEMU | the granted server fills V0–V31 with a pattern; afterwards no other EL0 server and no EL1 path can read it (other servers trap; a second granted test server sees zeros) |
| `[P-fpsimd-persist]` | QEMU | the server's registers survive across two of its own excursions with other servers run in between |
| metal | CM5 | the same four; data-plane loop worst gap and the 33-row separation matrix unchanged; excursion round trip within 8% of the current 388 ns (ADR 0067 timing rule) |

### Risk and cost

Medium size, security-sensitive: it touches excursion entry/exit (`excursion_bounded`,
`kernel/src/main.rs:14149`) and the EL0 vectors. The design above avoids the usual risk (lazy-FP leaks)
by never having two owners. Review: `security-auditor` before the shipping flavour takes it.

### What it unlocks

Vector kernels for the specialist tier at once (Neuro N1). A language model additionally needs memory
(ADR 0061), a model region and a loader (Neuro R3–R6), so KR-1 is necessary, not sufficient.

---

## KR-2 — A runtime workload loader

### Evidence

- EL0 servers are built by `kernel/build.rs` (8 `build_el0_crate` calls) and embedded with
  `include_bytes!`. Adding or updating one means a new kernel image and an OTA.
- The artifact store has 10 fixed types, the largest 16 MiB, none for code
  (`kernel/src/artstore.rs:66-77`).
- On CM5 the user window is `2 × 2 MiB` (`arch-aarch64/src/mmu_cm5.rs:74`); ELF segments are capped at
  2 MiB and 8 segments (`kernel/src/elf.rs:61-62`).
- EL0 has no capability syscalls: no retype, mint, map or revoke (`abi/src/lib.rs`). Excursion servers
  hold no capabilities and talk over fixed IO pages.
- Pieces that already exist and are reused, not rebuilt: the bounds-safe static ELF loader with W^X
  (`elf.rs`, `[P-elf]`); one address space and ASID per server (`el0as.rs`, `[P-el0-as]`); hybrid
  Ed25519 + SLH-DSA verification (`boot-abi/src/verify.rs`); signed A/B artifact slots with rollback
  (`artstore.rs`, `[P-artstore]`); fault restart budget and the recovery journal (`superv.rs`); bounded
  excursions (`[P-exc-bound]`).

### Request: load, run and remove a signed workload without a new image

A **workload** is one static, position-fixed ELF for an EL0 address space plus a manifest. No dynamic
linking, no relocation, no interpreter, no filesystem, no `fork`/`exec`, no ambient authority.

1. **Package** (`HQW1`): `manifest ‖ ELF`, signed with the existing hybrid scheme under a domain tag for
   workloads. The vendor root signs HookProbe workloads; whether an owner key may sign third-party ones is
   the same open policy question as for model packages (Neuro `12` R5) and should get the same answer.
2. **Manifest** (fixed layout, bounded):
   - identity: name, version, SVN (rollback floor), target (`cm5-a76`, `qemu-virt`, later `x86_64`), ABI version;
   - memory: code, rodata, data+bss, stack, IO-page sizes — all reserved at admission (ADR 0061 D4), never grown;
   - CPU: excursion budget in µs, and (after ADR 0060) a core role, never DP;
   - grants, each explicit and narrow: which kernel↔EL0 ring or IO page, which topics it may subscribe
     or publish, an optional device-MMIO grant (`el0as::Map::Dev`), `FpSimd` (KR-1). **No network, storage
     or policy capability unless listed**; the default is none, as for `el0-neuro` today.
3. **Store**: a new artifact type `workload` in the A/B artifact store, sized by the manifest, with the
   existing activate / roll back behaviour.
4. **Admission**: verify signature and SVN → check target and ABI → reserve memory or refuse with a reason
   (shown in `/api/capabilities`) → load through `elf.rs` into a fresh address space → register with the
   supervisor.
5. **Lifecycle**: start, stop, restart on fault (existing budget), remove. Stop and remove revoke every
   grant and return the memory; `caps.rs` already implements transitive revoke with unmap and TLB
   invalidation (`[P2-unmap]`).
6. **Address space**: each loaded workload gets its own window. The current `2 × 2 MiB` window is shared
   by all built-in servers by link address; loaded workloads need per-address-space placement so link
   addresses stop being a global allocation (they are already private per ASID since ADR 0065 S0).
7. **Frame allocator**: CM5's pool is a 128 MiB bump allocator with no free (ADR 0061 M3). Loading works
   with it; *removing* and reloading needs frames to be freed, so KR-2's remove path depends on ADR 0061
   D3 (free lists). A first step without remove (load-once per boot) does not.

Not asked: generic Untyped retype for EL0; a general syscall surface; POSIX; containers; running
unsigned code; any loader inside an EL0 server.

### How applications and Wasm fit

- First-party servers (TLS host, LAN services, Neuro, the Conductor harness) become workloads: same
  binaries, delivered as signed packages instead of image contents. The kernel image shrinks and its
  33 KB headroom stops being the limit for every new server.
- Third-party logic keeps the Wasm path (decision #2; ADR 0067 D6): a `.wasm` plus the native artifact
  compiled from it at signing time. The native artifact *is* a workload ELF; wasmi stays the fallback
  and the differential oracle. KR-2 is the loader D6 needs.
- A neural model is not a workload: it is data (an HNX package) admitted to the engine workload. Code and
  models keep one trust root and one admission path.

### Gates

| Gate | Where | Pass |
|---|---|---|
| `[P-wl-load]` | QEMU | a signed workload installs at run time, starts, answers over its IO page |
| `[P-wl-refuse]` | QEMU | bad signature, wrong target, old SVN, W+X segment, oversize, memory not available: each refused for the right reason, nothing mapped |
| `[P-wl-isolate]` | QEMU | the workload cannot read any other server's pages (`AT S1E0R`, as `[P-el0-as]`), and holds no grant its manifest does not list |
| `[P-wl-fault]` | QEMU | a faulting workload is restarted within its budget, then stopped; kernel and other servers continue; journal records it |
| `[P-wl-update]` | QEMU | a newer version activates; a failing one rolls back to the previous slot |
| `[P-wl-remove]` | QEMU | after remove, its grants are gone and its frames are reusable (needs ADR 0061 D3) |
| `[P-wl-fuzz]` | QEMU | mutated packages and manifests: no panic (`[P-fuzz]` discipline) |
| metal | CM5 | load and fault gates; separation matrix and data-plane timings unchanged |

### Risk and cost

Large, and it widens what can run on the device, so the signing policy is the real security decision.
Suggested order: (a) package format, verification and the `workload` artifact type; (b) load-once at
boot from the store (no remove) — this already moves servers out of the image; (c) run-time install and
update; (d) remove, after ADR 0061 D3.

---

## KR-3 — Conductor C1 in the kernel: the delegation signer, its sealed state, leases and the ledger

### Evidence

**What C1 needs is built and tested as a library** (`os/conductor/conductor-core`, ADR 0071 D2, D9):
- the signer (`signer.rs`). It re-checks every rule and never trusts the harness;
- owner-signed pairing records;
- the signed epoch announcement;
- the hash-chained ledger with anchor and power-loss recovery (`chain.rs`);
- the sealed state, the delegation counter and the revocation epoch (`durable.rs`). It uses **the record scheme
  of ADR 0069's `g19ctr.rs`**: two alternating sectors, `magic | value LE64 | sha256`, newest valid wins,
  write and read back before use.

**`conductor-mock/tests/c1.rs` checks:**
- **drift:** the record equals `g19ctr.rs`, byte for byte (the test reads the kernel source);
- **power loss:** at every write, torn at 9 lengths, 324 crash points: no counter is ever handed out twice,
  and no confirmed epoch is lost;
- **the signer on a crashing disk:** counters strictly increase across 10 crashing boots;
- **the kill switch:** it survives a reboot, and the worker then refuses an old capability as `Revoked`;
- **an unreadable store** signs nothing, announces nothing and revokes nothing.

**Today the kernel has none of this.** In C0 the signer runs in the host mock.

### Request (the smallest interface, reusing what exists)

1. **Two DataVolume regions** in the `datavol.rs` registry, in the unused space after `G19Ctr`:

   | Region | Offset | Size | Writer |
   |---|---|---|---|
   | `CondCtr` | 2058 | 2 | delegation counter (record magic `HQCDLG1\0`) |
   | `CondEpoch` | 2060 | 2 | revocation epoch (record magic `HQCEPO1\0`) |

   The same Gate-2 discipline as `G19Ctr` applies: each writer arms only its own two sectors.
2. **One counter mechanism.** Give `g19ctr::{load, advance}` a magic parameter, or link
   `conductor_core::durable` (`no_std`, no allocation, same layout). Either way the kernel keeps one way to
   persist a monotonic value, and the drift test keeps the two copies equal until HomePods picks one.
3. **The delegation key.** Derive it as `HKDF(SRK, "HQ-conductor-delegation-v1")`, the same pattern as the
   owner journal's `"HQ-owner-journal-v1"`. Derive the cache-salt key the same way
   (`"HQ-conductor-salt-v1"`).
   - The keys stay in EL1, and no EL0 server ever maps them.
   - They are separate from the Noise static key, the image trust root and the owner keys (ADR 0071 D2).
4. **One EL1 service, `conductor_sign`.** Its input is the harness's `SignRequest` (the existing
   `conductor_core::abi` encoding). Its output is the 397-byte signed capability, or a refusal code. The
   kernel runs `Signer::sign` with:
   - the pairings and owner policy from the **owner policy journal** (ADR 0055). A pairing is an owner-signed
     record; a new record kind, not a new store;
   - the sealed state from (1).

   The harness's only new syscall is this one.
5. **Leases in the data plane** (the decision is built and red-team tested: `conductor_core::lease`, `tests/c2_lease.rs`; lift it like the signer). On `StartLease { tier, until, egress_policy_id }`, the worker's compute segment
   may reach only that policy's destinations until `until`. At expiry, on `EndLease`, or when the kill switch
   bumps the epoch, the kernel closes every path. A frame from the worker outside its lease is dropped,
   recorded as evidence, and suspends the worker.
6. **The ledger in the evidence log.** Conductor records (`ledger::Record`) become a record type in the existing
   sealed evidence log (`fslog`, ADR 0066 export), not a separate store. The chain and anchor of `chain.rs`
   become a check on top of the log's own sealing.

### Gates

| Gate | Where | Pass |
|---|---|---|
| `[P-cond-ctr]` | QEMU | the record layer on an in-memory disk, like `[P-g19ctr]`: fresh = 0, strictly increasing, alternating sectors, a torn newest falls back, a refused write hands out nothing; the same for the epoch |
| `[P-cond-sign]` | QEMU | the EL0 harness gets a signature only through `conductor_sign`; the delegation key is not mapped to any EL0 server (`AT S1E0R`); a request for an unpaired worker, a disallowed class or a wrong egress policy is refused |
| `[P-cond-lease]` | QEMU | a worker frame to a destination outside its lease is dropped and recorded; the lease ends at expiry and at the kill switch |
| `[P-cond-ledger]` | QEMU | delegation records land in the evidence log; edited, removed or reordered records are detected |
| metal | CM5 | power-cycle on the relay rig, as the ADR 0069 evidence did: counter and epoch durable across reboot and power cut; no counter reused; a recorded capability replayed after reboot refused by the worker; data-plane timings and the 33-row separation matrix unchanged |

### Risk and cost

- **Small and local:** two regions, one EL1 service, one record kind each in the journal and the evidence log.
  The data-plane lease is the part with real risk: it touches enforcement, so it needs the separation-matrix
  gate.
- **Review:** `security-auditor` reviews the key derivation and the service before the shipping flavour takes
  it.

### What it unlocks

C1's gate (ADR 0071): no unauthorized execution or replay, and ledger integrity across power cycles. Then C2,
a P1 heqk worker on the owner's LAN.

## Order and what needs no kernel change meanwhile

1. R0 readouts: ID registers done (DotProd = 1, SVE = 0); control registers after the 72 h soak (one `t0inv` boot).
   Meanwhile: the `el0-harness` bench feature.
2. KR-1: the operator accepts ADR 0072, then the QEMU gates, the metal gates and the G46 review.
3. KR-2 (a) and (b).
4. ADR 0061 D1–D4, then KR-2 (c)–(d) and Neuro R3–R6 (model region, loader, admission).
5. KR-3 is independent of KR-1 and KR-2, and can go in parallel: it unblocks Conductor C1.

Until then, already possible on today's kernel with no change beyond adding an EL0 crate to
`kernel/build.rs` behind a feature: the Conductor harness (`el0-harness`: `.text` 90,736 B, `.data` 0,
`.bss` 52,408 B, stack bound 10,912 B, zero FP/SIMD instructions, no imports, one syscall) and Runtime
Proof 001's pipeline with the integer specialist.
