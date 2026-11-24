<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# ADR 0071 — heqk Conductor: directed execution, where the device keeps authority and compute is never trusted

**Status:** proposed. Operator decisions recorded:
- C0 approved as a restricted spike (2026-11-24);
- the Linux reference worker removed: workers are heqk-native only (2026-11-24);
- this design supersedes row (a) of the x86 de-Linux plan §4a, "Claude as heqk's on-device AI"
  (2026-11-24);
- ADR 0067 D12 decided as publish (2026-11-24).

Everything from C1 on is awaiting review.

**Built so far (2026-11-24):**
- **C0** (`os/conductor/conductor-core`, `el0-harness`): the capability, harness, verifier, ledger and
  pairing, tested against a mock kernel and a mock worker. Not wired into `os/kernel`.
- **The heqk-native engine** (`neuro-kernels`, `neuro-lm`, `neuro-gguf`, `neuro-contract`, `neuro-hnx`):
  runs a real Qwen3-1.7B Q8_0 GGUF end to end with integers only. Verified on the build host and on an
  emulated Cortex-A76.

**Nothing here has run on a CM5.** Gate tables and measurements: `os/conductor/README.md`.

**Relates to:**
- [0004](0004-secure-edge-transport.md): fleet transport, and the `fleet_mesh` capability that gates P2.
- [0011](0011-product-cortex.md): contract C9, AI proposes and gates enforce.
- [0023](0023-enforcement-separation.md): model output never enforces.
- [0025](0025-aegis-byo-llm-planner.md): the AEGIS BYO-LLM planner. The Conductor is its governed execution path (P5 here).
- [0047](0047-heqk-everywhere-on-device-mission-control.md): no Linux on the device.
- [0053](0053-operator-write-actions-on-device.md): operator write actions on the device: TTL-bound and audited, with owner re-authentication for high-impact kinds.
- [0060](0060-heqk-smp-execution-model-core-roles-bkl.md) and [0061](0061-heqk-memory-budgets-and-admission.md):
  cores and memory for a local engine.
- [0067](0067-heqk-efficiency-programme-and-ip-hygiene.md): D12 record and D13 counsel.
- [0069](0069-g19-msg1-replay-protection.md): the counter pattern reused for anti-replay.
- Neuro docs 30, 39–42, `tools/neuro-research/eval/run_eval.py`.
- Kernel requests KR-1 and KR-2 (`os/conductor/KERNEL_REQUESTS.md`).

## Context

Two things need compute that heqk does not have on the device, and will not have for a long time:
- **AI on the device's evidence:** Neuro's explainer, the Copilot and the AEGIS planner.
- **Neuro's learning:** training on owner-confirmed data.

**The options people reach for break invariants:**
- Running the model on a general-purpose host gives the agent that host's shell, credentials and network,
  so one prompt injection becomes exfiltration.
- Running Linux on the device contradicts ADR 0047.
- Sending raw evidence to an API leaks the data classes the product promises to keep.

**What exists to build on:**
- heqk is a small capability kernel that already sits on the wire as the IPS.
- It holds the device identity and keys, a sealed evidence store, and the PQ control channel.
- It can run bounded EL0 excursions.

**Measured facts that set the scale:**
- Neuro's explainer (ftFg: Qwen3-1.7B, Q8_0, 1.7 GB) runs only on alerts. That is about 3 explanations a
  day for a 30-device home (Neuro e2e run 1).
- Each generated token reads the whole model.
- The input is small: evidence cards average 76 tokens.

So the cost of local AI is mainly the RAM SKU, and the risk of remote AI is mainly authority and data egress.

## Decision

### D1 — The principle: authority on the device, compute interchangeable and never trusted

**The device holds:**
- identity, keys and policy;
- evidence and the sealed ledger;
- capability issuance and verification.

**A worker runs:** inference, embeddings or training.

**A worker never:**
- receives a key that outlives its job;
- reaches a network its job did not allow;
- sees a data class its tier does not permit;
- produces an output that enforces anything.

The model may propose. Only the deterministic reconciler applies, and only TTL-bound, owner-authorised
operations (ADR 0053, contract C9).

### D2 — HP-EXEC v1: one worker, one session, one job, one use

A canonical fixed-layout capability: a 333-byte body plus an Ed25519 signature over a domain tag and the
body, with no optional encodings. It binds:
- the worker's pinned key;
- a hash of the channel handshake transcript;
- `job_id`;
- a monotonic counter: ADR 0069's pattern, sealed on the device, with a persisted high-water mark on the
  worker;
- the SHA-256 of the exact request;
- the model digest, operations, data classes, tier and egress-policy id;
- input and output token limits, compute time, response bytes;
- validity times, and the revocation epoch.

**Rules:**
- No widening and no sub-delegation.
- Expiry is checked by the worker and enforced independently by the device as a lease: when the lease
  ends, the data plane closes the worker's paths.
- One owner action (the kill switch) raises the epoch and ends every lease.
- Workers sign `(capability_id, request_hash, output_hash, final_seq)`, so every result is attributable.
- **The delegation key lives in the kernel (C1).** The EL0 harness builds unsigned bodies and an EL1
  service signs them within the policy it checks. A compromised harness can ask for signatures, but it
  cannot extract the key.

### D3 — Providers

| Tier | Provider | Data it may receive | State |
|---|---|---|---|
| P0 | **The native engine on the device** (D8) | as the device | built (host and emulated A76); device needs KR-1, R3–R6 |
| P1 | The owner's LAN machine, paired by the owner (commit-then-reveal, six-digit comparison, owner-signed record) | owner policy | pairing built (C1 prep). **Workers are heqk nodes only** (operator, 2026-11-24): no Linux worker |
| P2 | HookProbe peers | under `fleet_mesh` (ADR 0004), off by default | not built |
| P3 | Untrusted cloud worker | public-class data only; tunnel-only egress enforced by the cloud network | not built |
| P4 | Confidential VM (+ GPU) | `org` data only after the full attestation chain, including separate GPU attestation | not built |
| P5 | **External API** (Anthropic or any OpenAI-compatible endpoint, BYO) | the owner's data-sharing policy | **supersedes x86 plan §4a(a)**; transport is HomePods' outbound TLS 1.3 client; not built |

**Placement:**
- Select-N-style SLO quotes: data-free, fixed-size quote requests. A worker that cannot meet the time
  targets is skipped without ever seeing a prompt.
- Standalone stays the default: with no provider configured, the device is a full SOC.

### D4 — Confinement must be provable, not configured

**P1:**
- a dedicated compute segment, with heqk the only gateway;
- no direct internet egress, and DNS only through heqk;
- per-lease destination allowlists;
- traffic cut when the lease ends;
- any frame outside the lease is dropped, recorded and suspends the worker.

**P3 and P4:** the cloud network enforces tunnel-only egress.

**Gate (C2, C3):** a red-team test with a deliberately compromised, root-owned worker. Every unauthorised
path fails, and each attempt appears as evidence.

### D5 — Data classes per tier, and injection as application security

| Data class | P3 cloud | P1 owner LAN | P4 attested | P5 external API |
|---|---|---|---|---|
| Public CVE / threat intel | yes | yes | yes | yes |
| Aggregate anonymous statistics | reviewed only | yes | yes | owner policy |
| Internal device fingerprints | no | owner-approved | owner-approved | no |
| Internal IP addresses, names | no | owner policy | owner policy | no |
| Raw packet captures | no | no | no | no |
| Credentials, keys, tokens | never | never | never | never |

Credentials are blocked structurally: the harness has no read path to them.

**Every tool has:**
- typed, bounded arguments;
- a data-flow check: a result goes back only if its class is allowed on the tier;
- authorization per call;
- write access only as staged proposals.

**Model output** is rendered as inert text, after JSON unescaping.

### D6 — The explainer contract has one source of truth: Neuro's

`os/conductor/neuro-contract` is the only device-side definition of the explainer's answer. It mirrors
`run_eval.py`:
- enums, bounds and key order;
- the system prompts and user framing;
- the id rule;
- the closed-mode schema text, byte for byte;
- the Qwen3 ChatML wrapping with reasoning off;
- one byte automaton for the answer language. It accepts what llama.cpp's grammar for that schema
  accepts.

**One automaton, two uses:** it drives evidence-closed decoding in the engine, and the parser in the
verifier. An answer cannot cite an id that is not in its context.

**Drift gate:** a test reads `run_eval.py` and fails on any difference.

Conductor's earlier invented answer schema is retired. Neuro owns the contract. A proposal to move it into
a shared data file is with Neuro (`os/conductor/NEURO_ALIGNMENT.md`).

### D7 — Verification without overclaiming

**Levels:**
- **Structural:** the contract automaton.
- **Evidential:** every citation exists and was shown to this provider; required evidence is cited.
- **Computational:** a deterministic L0 verdict decides wherever one exists; the model only words it
  (Neuro doc 40).

**Statuses:**

| Status | Meaning | What the UI shows |
|---|---|---|
| REJECTED | Authorization, schema or integrity failure, including a citation that does not exist | Nothing from the model; the reason |
| CONFLICT | The conclusion contradicts deterministic evidence | The L0 verdict, the model text flagged |
| INCOMPLETE | Required evidence was not cited | Partial, marked incomplete |
| UNVERIFIED | Structure and evidence pass, but the conclusion cannot be reproduced | The explanation, labelled unverified |
| VALID | Structure and evidence pass, and the conclusion matches L0 or claims nothing | The explanation, labelled "checked against evidence", never "proven" |

Precedence is REJECTED, then CONFLICT, then INCOMPLETE, then UNVERIFIED, then VALID.
`insufficient_evidence` counts as no claim.

### D8 — The native engine (P0): integers only, Neuro's bytes, exact speed-ups

**What it is:**
- `no_std`, no allocation, no floating point on the device, no Linux and no Python. A test scans every
  device crate.
- It runs Neuro's GGUF directly: Q8_0 weights, a Qwen3 decoder, the Qwen tokenizer with NFC, and
  binary16/binary32 decoded with integers.
- Activations are 64-bit fixed point, and their block quantization matches llama.cpp's CPU path.

**Speed-ups that do not change the output:**
- A lossless packed layout: 144-byte aligned records; every row unpacks to the exact GGUF bytes, so a
  device can verify against the GGUF hash.
- One batched forward pass for steps, prefill and verification: every column bit-identical to a one-token
  pass.
- A grammar-pruned output head.
- Verified speculation.

**Measured on Qwen3-1.7B:**
- identical output with and without the speed-ups;
- 0.99 → 0.75 forward passes per token;
- 0.37 executed instructions per multiply-add on the emulated A76.

**No device speed has been measured.** The kernel keeps no tensor maths (Neuro doc 08). The engine needs:
- KR-1: FP/SIMD for one EL0 server, and `SCTLR_EL1.A` cleared;
- R3–R6: model region, loader, admission (ADR 0061).

### D9 — The ledger is the egress audit

**What it records:** one record per delegation:
- job and capability ids;
- tier and worker key;
- the data-class mask sent;
- request and output hashes;
- outcome and verifier status.

**How it is protected:**
- an HMAC chain with a sealed anchor;
- torn writes are discarded;
- tampering before the anchor is reported, never repaired.

This is the "audit record of exactly what evidence left the device" that x86 plan §4a(a) asked for.

### D10 — Ownership

| Area | Owner |
|---|---|
| Models, training, evaluation sets, quality gates, the answer contract | **Neuro** (Conductor trains and evaluates nothing) |
| Kernel: delegation signer (C1), FP/SIMD grant, model region and loader, outbound TLS client, `mgmtabi` tools | **HomePods** (`os/kernel/**`) |
| Harness, capability, placement, verifier, ledger, native engine, contract mirror | **Conductor** (`os/conductor`) |

## Alternatives

- **Split a model's layers across the network.** Rejected: over anything slower than NVLink, move requests,
  not tensors. Research reviewed: Select-N, Cheops '25, the NVIDIA JAX host-offload results.
- **A Linux reference worker.** Built, then removed by operator decision: workers are heqk-native.
- **Claude Code natively on heqk.** Rejected: x86 plan §4a(b). It needs a POSIX world, which would mean
  re-implementing Linux.
- **Tensor operations in the kernel.** Rejected: Neuro doc 08 (image headroom, isolation).
- **An answer schema of Conductor's own.** Retired for Neuro's contract (D6).
- **Speed by matrix maths alone.** Decode is bound by memory bandwidth. The gains that matter are:
  - fewer calls (L0 decides);
  - footprint (the RAM SKU);
  - exact decode savings (D8).

## Consequences

**Positive:**
- One governance path for every model, local or remote.
- The device can use a DGX, a gaming PC, a cloud GPU or an API without handing any of them authority.
- Neuro's quality results carry over to the device only through a fidelity check on Neuro's dev set,
  measured as token agreement, not bit-exactness.

**Costs:**
- C1 needs kernel work: a delegation signer, a sealed counter and an epoch store.
- P5 needs an outbound TLS client.
- P0 needs KR-1 and R3–R6.

**Risks:**
- Decode on the CM5 competes with the packet path for memory bandwidth. This must be measured on metal
  before P0 ships.

## Roadmap and gates

| Stage | Content | Gate |
|---|---|---|
| C0 | Protocol and harness prototype, mock kernel and worker | **passed** (28 gate tests; fuzzing; contract; Runtime Proof 001) |
| C1 | Kernel-held delegation signer, sealed counter, epoch, ledger anchor, power-loss recovery | no unauthorized execution or replay; ledger integrity across power cycles |
| C2 | P1 owner LAN worker (heqk node): pairing, compute segment, `infer` / `embed` / `classify` | metal red-team egress test; the 33-row separation matrix unchanged; main-loop impact measured |
| C3a / C3b | P3 public-only cloud worker / P4 confidential VM with GPU attestation | cloud red-team egress test / any attestation failure sends no sensitive data |
| C4 | Verifier and Copilot in Mission Control; P5 external API; `/api/planner/*` served from Conductor job state | blind evaluation of fabricated entities, unsupported claims and malicious tool requests |
| C5 | P0 native engine on CM5 (after KR-1, R3–R6); heqk x86 workers (after ADR 0068); P2 under `fleet_mesh` | fidelity with ftFg on Neuro's dev set; device speed and power measured; packet path unaffected |

## Open questions

1. **Neuro:**
   - the ftFg GGUF (SHA-256 `0b0d276e…61ed`) and its licence record;
   - the dev set for the fidelity check;
   - which of guard A, filter E and rule T run on the device;
   - how severe a grounding finding is (an invented ATT&CK id);
   - whether the contract becomes a shared data file.
2. **HomePods:** KR-1 and KR-2; the C1 signer; the outbound TLS client.
3. **Operator:**
   - the Technical Disclosure Commons copy (ADR 0067 D12);
   - counsel review before shipping (D13);
   - approval of C1 onward.
