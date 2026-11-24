# os/conductor — HookProbe Conductor, C0 spike

> **Status: C0, restricted research spike (approved 2026-11-24).** Not wired into `os/kernel`. Not for
> publication before the ADR 0067 D12 decision (file first / publish defensively / keep unpublished).
> Wire formats are **prototypes** built from primitives heqk already ships; they are not a production
> protocol. Design: *heqk Conductor* design review v2/v3 (private artifact).

heqk keeps the authority (identity, keys, policy, evidence, capability issuance, verification, ledger);
remote workers only compute. C0 is the device-side core: the protocol, the HP-EXEC capability, data classes,
typed tools, the verifier, placement and a sans-IO harness state machine, tested against a mock kernel and a
scripted, misbehaving mock worker.

## C0 boundaries (as approved)

No change to `os/kernel` · no x86 dependency · no cloud deployment · no change to packet enforcement · no new
production crypto protocol · no public disclosure · no remote application execution · mock worker only.

## No Linux, no Python (enforced)

Everything here is Rust. `conductor-mock/tests/no_linux_no_python.rs` fails if a non-Rust source appears
under `os/conductor`, if a device crate stops being `no_std` or names std, alloc, libc or a POSIX API, or
if the device binary gains a dependency. Checked on the built device binary (`el0-harness`): 10 Rust
crates compiled for the target, 0 imported symbols, no dynamic section, one syscall (heqk's
`SYS_EXIT_USER`), 0 FP/SIMD instructions.

| Crate | Runs on | Linux at run time? |
|---|---|---|
| `conductor-core`, `el0-harness`, `runtime-proof` (lib) | heqk (EL0) | **no** |
| `conductor-mock` (tests, fuzz, `measure`, `stack_bound`) | the build host only (ADR 0047 D3) | not shipped |

There is no Linux-hosted component. A reference worker for a Linux GPU machine was built and then removed
on 2026-11-24 (operator decision: everything stays heqk-native). The worker-side acceptance rules remain
as `no_std` protocol code (`conductor-core/src/worker.rs`) for a future heqk-native worker, and are
exercised by the mock in the tests. The two kernel requests that make neural computation and applications
native are in [`KERNEL_REQUESTS.md`](KERNEL_REQUESTS.md).

## neuro-engine, step 1 (N0): an integer specialist engine

A model is a data package (prototype layout `HNX0`, after Neuro doc 06): memory plan, execution plan over a
closed kernel table, weights, SHA-256 root. Admission checks everything once, including a worst-case bound
that no accumulator can overflow for any input; after that a run cannot fail, allocates nothing and does a
known amount of work. The plan is interruptible step by step.

| Gate | Result |
|---|---|
| The frozen S1 specialist shipped as a 212-byte package gives bit-identical scores and alerts to `neuro_l1`'s compiled-in code (200,003 inputs) | pass |
| 300 random 1–3 layer int8 models × 20 inputs match an independently written reference; stepping equals running | pass |
| Malformed packages refused for the right reason (17 cases, incl. overflow bound, in-place misuse, trailing byte) | pass |
| 3,000,000 mutated packages (most re-hashed so they pass integrity): no panic; 384,725 admitted and run | pass |
| Runtime Proof 001 runs S1 through the engine: identical findings to the compiled-in run | pass |

`el0-engine` (aarch64 softfloat, runs on today's heqk, no FP/SIMD grant): `.text` 8,796 B, `.data` 0,
`.bss` 131,080 B (64 KiB package buffer + 64 KiB arena, sized for the limits, not for S1), stack bound
10,880 B, 0 imports, 0 FP/SIMD instructions. Not wired into `os/kernel`.

Not in step 1: package signature verification (the kernel's job, R5), a recurrent cell, SIMD kernels
(step 2, needs KR-1 to run on the device), a language model.

## Crates

| Crate | What | Target |
|---|---|---|
| [`conductor-core/`](conductor-core/) | protocol, HP-EXEC v1, classes, tools, strict JSON, verifier, placement, ledger, harness, worker gate; signer behind `--features signer` | `no_std`, no alloc, `forbid(unsafe_code)`; clippy denies indexing, unwrap/expect/panic, unchecked arithmetic, truncating casts |
| [`conductor-mock/`](conductor-mock/) | mock kernel + mock worker, the C0 gate tests, fuzzing, host timing | host only |
| [`el0-harness/`](el0-harness/) | the harness as an EL0 excursion server (no signer, no key) | `aarch64-unknown-none-softfloat`, pinned heqk nightly |

The crypto crates are the kernel's own, pinned to the kernel's versions: `sha2 =0.10.9`,
`ed25519-compact =2.3.1`.

## C0 gate — results (main @ 1ce96d52 + this branch)

| Gate item | Evidence | Result |
|---|---|---|
| Capability refusal | `gate.rs`: remote off by default; required Fingerprint without owner opt-in; Raw/Secret on any tier; P3 public-only; P4 public-only until C3b; P2 refused (fleet_mesh unbuilt); unpaired worker; signer refuses Raw, unapproved classes, wrong egress profile, P2, unknown ops, KV persistence; harness refuses a blob the signer did not sign | pass |
| Replay rejection | worker gate: same capability twice → Replay (ADR 0069 counter pattern); wrong session, wrong worker, wrong tier, altered request, not-yet-valid, expired, tampered body, revoked epoch; device: frames replayed from a previous call → CapabilityMismatch | pass |
| Budget exhaustion | step budget ends a tool loop; output-unit budget caps the capability and rejects an overrun; deadline aborts even while frames arrive; silent worker times out | pass |
| Malformed responses | bad result signature, bad output hash, wrong capability id, skipped sequence, usage lie, garbage, oversize, error frame, double FINAL; 15 strict-schema cases (unknown/duplicate/reordered keys, trailing bytes, leading zeros, tab, `\u` escape, bidi override, raw control char, negative/float numbers, unknown tool, non-object) | pass |
| Fault containment | `fuzz.rs`: 2,000,000 random/mutated inputs through every decoder, no panic (panic=abort, overflow checks on); 30,000 end-to-end runs where worker frames are altered in flight: **an altered frame never produced a Verified outcome**, and every lease was ended exactly once | pass |
| Injection / data flow | ungranted tool, out-of-scope evidence → refused, counted, model told; 3 refusals → REJECTED; tool result of a class the tier may not see never reaches the worker; optional Address card withheld from P1 | pass |
| Verifier statuses | VALID (L0 decides / descriptive), CONFLICT (shows L0 verdict, never the model's), INCOMPLETE, UNVERIFIED (model verdict not shown), REJECTED (fabricated citation) | pass |
| Kill switch | cancel mid-call ends the lease; epoch bump revokes older capabilities at the worker | pass |

Lease invariant: every `StartLease` is matched by exactly one `EndLease` in every gate and fuzz run.

## Built ahead of C1/C2 (still no kernel change, mock only)

| Piece | What it stops | Evidence | Result |
|---|---|---|---|
| **Hash-chained ledger** (`chain.rs`): HMAC chain + sealed anchor + power-loss recovery | edited, removed, reordered, truncated or rewritten history; torn writes | `c1_prep.rs`: every byte edit caught; removed / swapped entries; tail cut caught only via the anchor; history rewritten with the real key caught by the anchor; roll-forward of one unanchored entry; torn tail discarded; tampering before the anchor reported, never repaired; a real job's ledger verifies | pass |
| **Owner pairing** (`pairing.rs`): commit-then-reveal, six-digit comparison, owner-signed record with revision and expiry | a LAN attacker substituting its worker key; a compromised harness pairing a worker; replaying an old pairing to undo a revocation | MITM key/late-nonce fail the commitment; codes spread uniformly; forged and wrong-purpose owner signatures refused; stale revision refused; P2 refused; lapsed pairing stops signing | pass |
| **Signed epoch announcement** (kill switch, part 2) | a captured but unused capability surviving the kill switch | announcement revokes an outstanding epoch-1 capability at the worker; forged / other-device announcements refused; epoch never lowered | pass |
| **SLO admission quotes** (Select-N style; heqk is the upper-level scheduler) | sending data to a worker that cannot meet the time targets; forged or replayed quotes | data-free fixed-size quote request (no evidence or intent bytes); slow worker (NVMe-streaming profile) skipped for the next tier without ever receiving a capability or prompt; nobody meets the SLO → refused with only quote requests sent; wrong nonce or wrong key → REJECTED; a broken promise is recorded (SloMiss code 2) | pass |

Fuzzing now also covers events, quote requests and quotes (1,000,000 decoder inputs) and runs half of the
20,000 end-to-end mutation runs with SLO admission: an altered frame or quote never produced a Verified
outcome.

## Measurements

EL0 binary (`el0-harness`, release, opt-level "s", ed25519-compact at "z"):

| | Bytes |
|---|---|
| `.text` | 74,772 |
| `.rodata` | 2,936 |
| `.data` | 0 |
| `.bss` (whole job state, in place) | 47,792 |
| Worst-case stack from `_start` (static bound: no indirect calls, no register-based sp adjustment) | 13,280 |
| FP/SIMD instructions | 0 (runs on today's softfloat heqk; no R2 needed) |

Findings fixed during measurement:
- **47 KB of `.data`**: niche-encoded `Option`s made the empty harness non-zero, so the compiler stored the
  state in the image (which the kernel embeds; its headroom is about 33 KB). The state is now all-zero by
  construction and lives in `.bss`.
- **Ed25519 verify was 137 KB of 171 KB `.text`** (`double_scalarmult_vartime` unrolls to ~95 KB at "s").
  Building that one crate at "z" cut `.text` to 72 KB; verification gets slower (measure on CM5 in C1).
- **Clock bug**: the harness clock only advanced on ticks, so a deadline could be overrun while frames
  arrived. Every event now carries the time.

Host timing (x86-64, NOT CM5): a two-call job end to end ≈ 0.93 ms including the mock signer and worker;
device-side crypto per call ≈ 0.10 ms (two Ed25519 verifies) + 8 µs (SHA-256 of an 8 KiB request).

## Run

```bash
cd os/conductor && cargo test --release -p conductor-mock
```

```bash
cd os/conductor && FUZZ_ITERS=2000000 cargo test --release -p conductor-mock --test fuzz
```

```bash
cd os/conductor && cargo clippy -p conductor-core --features signer
```

```bash
cd os/conductor && cargo run --release -p conductor-mock --bin measure
```

```bash
cd os/conductor/el0-harness && cargo build --release
```

## Not in C0 (next)

- **C1** (HomePods): lift `signer.rs` and `chain.rs` into EL1 with purpose-separated keys (delegation,
  cache salt, ledger) derived from the sealed root; persist the counter and the ledger anchor in the sealed
  store (ADR 0069 pattern); broadcast epoch announcements; wire `el0-harness` behind a feature; assign its
  address range; time Ed25519 verify at opt-level "z" on CM5.
- **Remote workers**: only as heqk-native nodes (heqk on the worker machine), after ADR 0068 and the
  kernel requests. No Linux-hosted worker.
- Third-party applications (containers / microVMs on a companion host) are outside C0 and need their own
  ADR.
