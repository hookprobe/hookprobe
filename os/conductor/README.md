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

## Measurements

EL0 binary (`el0-harness`, release, opt-level "s", ed25519-compact at "z"):

| | Bytes |
|---|---|
| `.text` | 72,040 |
| `.rodata` | 2,872 |
| `.data` | 0 |
| `.bss` (whole job state, in place) | 47,768 |
| Worst-case stack from `_start` (static bound: no indirect calls, no register-based sp adjustment) | 13,296 |
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

- **C1** (HomePods): the signer in EL1 with a purpose-separated key; the sealed monotonic counter; the
  revocation epoch announced to workers; the sealed append-only ledger; wiring `el0-harness` behind a
  feature; its address range; CM5 timing of Ed25519 verify at opt-level "z".
- **C2**: owner pairing, the compute segment, the reference worker (request-level; engines bind to
  localhost behind the worker agent), worker quotes (SLO admission), the red-team egress gate.
- Third-party applications (containers / microVMs on a companion host) are outside C0 and need their own
  ADR.
