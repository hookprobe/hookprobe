# ADR 0067: heqk efficiency programme, measured gates and IP hygiene

**Status:** 🟡 Proposed (2026-11-19). Needs operator review.

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

**Publication note.** This file describes ideas judged distinctive (D5–D9). Under EPC Art. 54 a
public push is prior art against our own later filing; there is no grace period in the EU. The
operator decides patent-or-publish for D5–D9 **before** this branch is pushed (D12).

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
- Behavioural learning changes (Neuro) are journalled with the owner's signed confirmation in one
  atomic record. This is decided in principle only: the Neuro engine needs its own ADR (0048)
  and must be on `main` first.
- Fleet sharing of behavioural observations is deferred until counsel has reviewed it.

No SQL engine and no general database enters the kernel or the packet path.

### IP hygiene

**D11. Nothing unlicensable is linked into a heqk image.**
- Vendor firmware, regulatory blobs and NVRAM files are separate files on the boot partition,
  loaded at run time under their owners' terms. They are not `include_bytes!` inputs.
- Every driver has a provenance entry: its sources (datasheet, register map, specification,
  permissively licensed code, or a functional note) and who read what. Code whose only recorded
  source is a GPL-2.0 file is rewritten from a functional note by someone who did not read that
  file.
- Every source file carries an SPDX header; g0 checks it. Dependencies stay permissive-only
  (`tools/ci/deny.toml`).
- New work is implemented from papers, standards and datasheets. Linux and seL4 kernel sources
  are not read for it.

**D12. Publish-or-patent is decided before a push.** For each of D5–D9 the operator records one of:
file first, publish defensively, or keep unpublished. Defensive publication means an enabling
description in this repo **and** a dated copy at Technical Disclosure Commons. Standards are
implemented exactly (FIPS 203, RFC 9669, the W3C Wasm specification).

**D13. Counsel reviews before shipping:** D5 and D7 against flow-offload and megaflow patents; D10
learning against feedback-gated anomaly-learning patents; any replay-style recovery; F13 and F14.
These are operator (Red) steps. The work may be built and measured behind a feature flag first.

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
