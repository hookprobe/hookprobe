# ADR 0067: heqk efficiency programme, measured gates and IP hygiene

**Status:** 🟡 Proposed (2026-11-19). Amended 2026-11-19 (operator decisions, see "Amendment" below).
Not ratified: the licensing-sensitive and patent-sensitive decisions (D5–D9 as protectable subject matter,
D10 learning, D11, D12, D13) stay subject to counsel. The engineering decisions (D1–D4) are being built.

**Scope:** os/kernel (data plane, EL0 call boundary, NAT, frame pool, JIT, Wasm host, evidence log,
build targets), hboot (signature verify cost), tools/ci (performance ratchet), licensing and
provenance of everything compiled into a heqk image.

**Related:**
- ADR 0023 (enforcement separation: every data-plane change re-proves the 33-row matrix);
- ADR 0050 (line-rate parsing and BPF tiers stay in EL1; throughput must not fall);
- ADR 0059 (cfgd is the single writer of configuration);
- ADR 0060 (SMP execution model) and ADR 0061 (budgets and admission), which this ADR sequences
  but does not change;
- ADR 0063 (gate spine and heal loop), which this ADR extends with a performance ratchet;
- ADR 0065 (Wi-Fi driver out of the kernel);
- `docs/roadmap/heqk-efficiency-build-plan.md` (the work items, gates and autonomy rules).

**Publication note (corrected 2026-11-19).** This file describes ideas judged distinctive (D5–D9). It
was pushed to the public repository on 2026-11-19 (PR #1340, merged the same day). The decision point
that D12 originally required "before a push" has therefore passed for D5–D9 as described here. See the
disclosure record under D12. Nothing in this ADR labels those mechanisms unpublished.

## Context

Findings of the 2026-11-19 efficiency study (code map of `main` at `4ae769886`, a survey of
published work, and a patent and licence review). Line references are to `os/kernel`.

| # | Finding | Status | Evidence |
|---|---|---|---|
| F1 | One core runs one polled loop; cores 1–3 are parked | BY DESIGN (until 0060) | `hboot/src/boot.s:28-30`; `ARCHITECTURE.md:143-175` |
| F2 | el0-wifi carries one frame per EL0 round trip (388 ns, 1.2 µs with a frame); AP+NAT fell from 120–160 to 98–106 Mbps after the bus moved to EL0 | MEASURED | `hal/src/wifisrvabi.rs:482-486`; ADR 0065 status table |
| F3 | GEM transmit is synchronous, `NTX=2`: each frame waits for completion | ACKNOWLEDGED | `arch-aarch64/src/gem.rs:56-73, 961-1010` |
| F4 | A new NAT flow scans up to 4,096 entries; checksums are fully recomputed on each rewrite | IMPLEMENTED (slow path) | `arch-aarch64/src/nat.rs:189-230, 318-355` |
| F5 | The CM5 frame pool zeroes each frame word by word and never frees | PARTIAL (0061 M3) | `arch-aarch64/src/mmu_cm5.rs:405-431` |
| F6 | The build target disables NEON; TLS, sealing and boot signature checks are scalar; verifiers are built for size | IMPLEMENTED (softfloat) | rustc target `aarch64-unknown-none-softfloat`; `seal.rs:1-22` |
| F7 | Rule tiers run in sequence (4 tiers × `MAX_RULES=16`); IDS cost is 398–441 ns per packet on one A76 | MEASURED | `rules.rs:86-103`; `docs/design/metal-evidence/20261109-detection-network-series.md` |
| F8 | The Wasm host is a one-shot boot proof; it is on no packet, flow or event path | PARTIAL | `kernel/src/main.rs:1391-1397` |
| F9 | No DVFS and no thermal governor; enclosure thermal is an open item | NOT IMPLEMENTED | `PRODUCTION_READINESS.md:50` |
| F10 | No ARM PMU use; `validate.sh` has functional gates only, no performance gate | NOT IMPLEMENTED | — |
| F11 | GEM RX overruns at saturation; a deeper ring needs a multi-page EL0 grant | ACKNOWLEDGED | `gem.rs:344-349` |
| F12 | Boot takes 60–70 s to the product loop; the evidence-log mount scans every slot (~1.5 s) | MEASURED | `[BOOT-TIMING]`; `kernel/src/evlog.rs` |
| F13 | The CYW43455 firmware, regulatory blob and a **GPL-2** NVRAM file are compiled into the kernel image | LICENCE CONFLICT | `arch-aarch64/src/cyw43.rs:594-596`; `os/drivers/firmware/brcm-firmware-rpt/LICENSE.md` |
| F14 | Several drivers say they were transcribed from, or mirror, Linux GPL-2.0 sources | PROVENANCE UNRECORDED | `arch-aarch64/src/rng200.rs:15`; `gem.rs:1363`; `rtl8111.rs:377`; `hboot/src/watchdog.rs:63`; `cyw43.rs:293, 2096` |
| F15 | No source file carries an SPDX header | NOT IMPLEMENTED | — |
| F16 | The Neuro engine is not on `main` (commit `4ad1931ff`, unmerged); no ADR names it | OPEN | `docs/adr/0048-RESERVED.md` |
| F17 | Flow offload, ML traffic classification and feedback-gated anomaly learning are densely patented; replay-based durable execution is patented by Microsoft | EXTERNAL RISK | study notes; claims not read by counsel |

## Decision

### Measurement first

**D1. No efficiency claim without a gate.** Every item in the build plan lands with two proofs:
- a **work counter** that is deterministic under QEMU (frames per EL0 round trip, copies per
  frame, entries scanned per new flow, rule evaluations per packet, excursions per event), gated
  in `validate.sh` and therefore in g2;
- a **timing** measured on CM5 (ns per packet, Mbps, ms), read from the ARM PMU cycle counter in
  EL1 and gated in g6.

QEMU timing is never evidence. ADR 0062 D5 stands: the PMU stays EL1-only.

**D2. Performance ratchet (extends ADR 0063 D3).** `tools/ci/baselines/perf.json` records each
counter and each metal timing. A change that worsens a counter fails g2. A metal timing that
worsens by more than 8 % of baseline (boot-to-boot spread is about ±5 %) fails g6. Baselines move
only by a reviewed commit that names the evidence file.

### Engineering fixes (old public art, no novelty claimed)

**D3. Fix the single-core path before adding cores.**
- el0-wifi RX and TX carry a vector of frames per round trip, bounded by the ring size.
- GEM transmit reaps completions asynchronously on a deeper TX ring.
- NAT gets a free list and an LRU list, and RFC 1624 incremental checksum updates.
- The frame pool zeroes with `dc zva`. Reclaim stays with ADR 0061 D3.
- A multi-page EL0 grant lets the GEM RX ring grow past the overrun point.

SMP remains ADR 0060's decision; this ADR only orders it after the items above, so that each core
added multiplies an efficient loop.

**D4. Hardware crypto in EL0 and hboot only.** The kernel stays softfloat. EL0 servers that do
bulk crypto (el0-tlshost first) and the hboot verifier may be built with NEON, AES and SHA-2
instructions, on these conditions:
- the capability is read once from `ID_AA64ISAR0_EL1` into the Platform Manifest; a scalar build
  remains the fallback;
- the kernel enables FP/SIMD access only for the server's excursion and zeroes `v0–v31` on exit,
  so no FP state crosses servers. EL0 calls are synchronous, so no FP save is needed;
- constant-time review by security-auditor before the shipping flavour takes it.

### Distinctive mechanisms

**D5. Policy-specialised packet path.** At each cfgd commit, the active rules, ACLs, reach policy
and NAT configuration are fused into one verified program, compiled by the existing BPF JIT, and
swapped in atomically. cfgd is the only writer (ADR 0059), so the specialised path needs no
run-time guards: it is valid exactly until the next commit. The generic tier walk stays as the
fallback and as the oracle the specialised path is tested against.

**D6. Sign-time native compilation of detection modules.** A signed detection module may carry a
native aarch64 artifact compiled from its Wasm at signing time. The hybrid signature covers both.
The CI rebuilds the artifact reproducibly and compares hashes; a differential corpus checks
native against wasmi. The device loads the native artifact W^X in the module's own EL0 address
space; wasmi stays the fallback. Order: first put Wasm on a batched flow-event path and measure
it (F8), then add the native artifact.

**D7. Verdict as a revocable capability.** A flow the per-packet tiers have found unremarkable for
a bounded number of packets receives a flow token. Later packets of that flow skip the per-packet
tiers until the token is revoked. Limits:
- tokens are revoked by any cfgd commit, any rule or blocklist update, and a byte, packet or time
  budget;
- flow-level rules, resource-shed counters and confirmed-attack drops still see every packet;
- a token only ever skips inspection. It never changes a verdict toward dropping (ADR 0023).

**D8. Inspection shedding with evidence.** Under CPU or pool pressure heqk sheds inspection, never
legitimate traffic, in the order module events → per-packet tiers for tokened flows → sampling.
Each shed interval writes a sealed evidence record (what was shed, how much, why), and the
operator sees the real inspected fraction. This extends ADR 0061 D5 "inspection overload".

**D9. Thermal as a budgeted resource.** A thermal budget joins the CPU and memory budgets. The
governor is designed from the SoC's own sensor and clock controls, not from Linux's energy-aware
scheduler. It picks idle strategy, polling interval and clock rate from load and temperature, and
its only data-plane action is D8 shedding.

### System state and learning (from the DBOS review)

**D10. Checkpoint-and-resume, same-record provenance, no replay.**
- Recovery and configuration workflows record each completed step with an idempotency key, then
  resume after a restart. heqk does not rebuild workflow state by re-executing code against a
  recorded history.
- Every enforcement evidence record carries the configuration generation and the ruleset hash in
  force, and the module or model version when one contributed, in the same sealed record.
- Behavioural learning changes (Neuro) journalled with the owner's signed confirmation in one atomic
  record are a **proposed architectural direction, not an approved Neuro implementation**. Nothing
  here approves a Neuro design: that needs its own ADR (0048). Subject to counsel (D13, review C).
- Fleet sharing of behavioural observations is deferred until counsel has reviewed it.

No SQL engine and no general database enters the kernel or the packet path.

### IP hygiene

**D11. Nothing unlicensable is linked into a heqk image.**
- Vendor firmware, regulatory blobs and NVRAM files are separate files on the boot partition,
  loaded at run time under their owners' terms. They are not `include_bytes!` inputs.
- Every driver has a provenance entry: its sources (datasheet, register map, specification,
  permissively licensed code, or a functional note) and who read what. The register is
  `docs/security/driver-provenance.md`; g0 (`tools/ci/provenance_check.py`) fails when a driver file
  under `os/kernel/arch-aarch64/src` or `os/kernel/hboot/src` has no row. No class in the register is a
  finding of independent implementation. Code whose only recorded
  source is a GPL-2.0 file is rewritten from a functional note by someone who did not read that
  file.
- Every source file carries an SPDX header; g0 checks it. Dependencies stay permissive-only
  (`tools/ci/deny.toml`).
- New work is implemented from papers, standards and datasheets. Linux and seL4 kernel sources
  are not read for it.

**D12. Publish-or-patent is decided before a push — for anything not yet public.** For a new mechanism
the operator records one of: file first, publish defensively, or keep unpublished, before it is pushed.
Defensive publication means an enabling description in this repo **and** a dated copy at Technical
Disclosure Commons. Standards are implemented exactly (FIPS 203, RFC 9669, the W3C Wasm specification).

*Disclosure record for D5–D9 (facts, 2026-11-19).* These were public before any D12 decision was
recorded:

| Mechanism | Described publicly | Implemented publicly |
|---|---|---|
| D5 policy-specialised packet path | this ADR, 2026-11-19 (PR #1340) | first steps only: guards read from a rule program at install (PR #1355, 2026-11-19; TCP-flag guards to follow). The fused program is not written |
| D6 sign-time native compilation of detection modules | this ADR, 2026-11-19 | no |
| D7 revocable verdict token | this ADR, 2026-11-19 | no |
| D8 inspection shedding recorded as evidence | this ADR, 2026-11-19 | no |
| D9 thermal budget | this ADR, 2026-11-19 | no |

This record does not say that every implementation detail is public, and it does not settle the legal
status of any patent claim. Counsel establishes the disclosure dates, the technical scope disclosed and
what protection remains (D13, review B).

*D12 decision for the heqk Conductor and the heqk-native engine (operator, 2026-11-24): publish.* The work
held local on branch `conductor/c0-local` is published by its push to this repo. It covers:
- HP-EXEC delegation capabilities, the harness, verifier, ledger and pairing (`os/conductor/conductor-core`);
- the integer Q8_0 / fixed-point Qwen3 engine and the lossless packed weight layout;
- the GGUF reader and the Qwen tokenizer with NFC;
- evidence-closed decoding from `neuro-contract`;
- the exact speed-ups: batched verification, grammar-pruned head, verified speculation.

The dated Technical Disclosure Commons copy that defensive publication also asks for is an operator step
and is not done. Counsel review (D13) still applies before shipping.

**D13. Counsel reviews before shipping**, as three separate reviews, each answering copyright,
open-source licence obligations, patent infringement and patentability as different questions:

- **Review A — embedded firmware and Linux-derived drivers:** F13 and F14, licence compatibility and
  distribution obligations, the clean-room method.
- **Review B — flow-related mechanisms:** D5, D7, D8 against flow-offload, megaflow and security
  patents; the D5–D9 disclosure record.
- **Review C — Neuro and learning:** D10 (recovery by recorded steps, transactional learning,
  owner-confirmed learning records), the feedback-gated anomaly-learning patents, later fleet sharing.

These are operator (Red) steps. Development is not blocked on them: the work may be built and measured
behind a feature flag first. Code that a review has questioned does not ship until it is resolved.

## Amendment (2026-11-19, operator decisions)

1. D12 corrected: D5–D9 were public before a patent-or-publish decision was recorded; the disclosure
   record states that.
2. D11 names the committed location of the provenance register and its gate.
3. The licensing-sensitive and patent-sensitive decisions stay subject to counsel; D13 is three reviews.
4. D10: transactional learning is a proposed direction, not an approved Neuro implementation.
5. The GPL-derived driver code is rewritten by a clean-room process (functional note from the
   datasheet, separate implementer, metal comparison, counsel review before shipping). The present
   implementation is not deleted and git history is not rewritten as a substitute for remediation.
6. E9 (evidence-log mount scan) is dropped; see the build plan.
7. The first CM5 bench slot is batch B1: timing baselines, AP+NAT throughput, firmware separation.
   Acceptance: functional regression, the 33-row separation matrix, timings within 8 %, evidence
   under `docs/design/metal-evidence/`.
8. This ADR stays Proposed until the operator has reviewed the amended text and the legal risks
   have been assessed.

## Consequences

- g2 gains work-counter phases; g6 gains timing gates; a slower change now fails like a broken one.
- Each item is behind a cargo feature until its metal gate passes; adding it to
  `tools/ci/shipping-features.txt` is the operator's step.
- The image build must stage firmware as files (`tools/ci/stage-firmware.sh` and
  `os/build/make-cm5-heqk-disk.sh` change); a device with no firmware files boots with Wi-Fi
  reported unavailable, not with a panic.
- D5 and D6 enlarge the trusted compile path. The verifier, the oracle comparison and the
  differential corpus are release-blocking for them.
- D7 lowers inspection coverage by design. The inspected fraction is reported honestly (D8).
- ADR 0048 (BOI / behavioural genome) is the home for Neuro decisions; this ADR adds none.

## Not decided here

- RK3588 or big.LITTLE placement (barred by ADR 0064 until CM5 validation).
- Intra-level isolation with Arm permission overlays (not present on Cortex-A76, to be confirmed
  against the core manual; revisit with newer hardware).
- RCU. If lock-free reclamation is needed for SMP, epoch-based reclamation is the default.
