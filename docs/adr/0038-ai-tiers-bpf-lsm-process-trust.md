# ADR 0038 — AI-tier architecture & the BPF-LSM process-trust framework

**Status:** 🟡 Proposed (2026-07-17) — design-session posture, pending ratification. Records the
"right altitude for each AI question" model and the kernel-side process-trust framework that a
2026-07-17 architecture session converged on. **Partly implemented, partly vision — flagged per item:**
the microsecond reflex tier (QSECBIT — Mahalanobis/entropy) and the first millisecond-semantic model
(`dga-lm`, int8 char-CNN) **exist**; the BYO-LLM copilot (AEGIS) **exists** ([ADR 0025](0025-aegis-byo-llm-planner.md));
the unified XDP/TC eBPF plane **exists** ([ADR 0005](0005-unified-ebpf-detection.md)). The **BPF-LSM
process-trust framework** and the **TinyBERT-class semantic tier beyond `dga-lm`** are vision (no code
yet; marked roadmap, never fabricated).
**Deciders:** os-architect (author), security-auditor, telemetry-analyst, code-developer.
**Relates to:** [ADR 0005](0005-unified-ebpf-detection.md) (the XDP/TC eBPF plane this extends toward
LSM hooks), [ADR 0009](0009-soc-brain-edge-cloud.md) (C9 — AI is *never* in the enforcement path;
deterministic core, LLM assistive), [ADR 0014](0014-continuous-improvement-detection-lifecycle.md)
(off-device training, signed/model-carded models, observe-only), [ADR 0023](0023-enforcement-separation.md)
(the single deterministic `decide()` + tri-state verdict that is the ONLY enforcer),
[ADR 0025](0025-aegis-byo-llm-planner.md) (the BYO-LLM copilot), [ADR 0035](0035-substrate-ownership-underlay-overlay.md)
(the minimal/immutable underlay this posture starves attackers on), [ADR 0036](0036-verifiable-supply-chain-reproducible-bootstrappable.md)
(the measurement/attestation chain the models fold into).

---

## Context

The failure mode of every "AI security" product is putting the model at the wrong altitude — most
notoriously **an LLM in the packet path**, which is three-to-six orders of magnitude too slow and turns
the detector into the bottleneck an attacker exploits. HookProbe already runs deterministic reflex
scoring (QSECBIT) and its first small quantized classifier (`dga-lm`), and an assistive BYO LLM (AEGIS),
but the *relationship* between these — which model answers which question, at what latency, and how none
of them is ever allowed to be the enforcer — has not been written down as one model. This ADR does that,
and adds the natural kernel-side extension: a **per-process trust score** the OS itself can consult, built
on the BPF-LSM extension point rather than a kernel fork.

The spine of the decision is the invariant the whole system already depends on: **C9 — AI plans, scores,
and advises; only the single deterministic `decide()` ([ADR 0023](0023-enforcement-separation.md))
enforces.** Nothing here weakens it; everything here is arranged *around* it.

## Decision

### D1 — Three AI tiers, one rule: the right altitude for each question

Detection/response AI is organized into three tiers by the latency the question can tolerate. The rule:
**tiny-classifier at the wire, transformer near it, LLM beside the human.**

| Tier | What | Where / latency | Status |
|---|---|---|---|
| **1 · Microsecond reflex** | A tiny classifier — MLP / decision-tree / logistic over a handful of features → a score. QSECBIT's shape (Mahalanobis distance + Shannon entropy + logistic). Deterministic, allocation-free. | In / adjacent to the hot path; **sub-millisecond**. | ✅ QSECBIT |
| **2 · Millisecond semantic** | A TinyBERT-class / small-transformer / char-CNN model for questions that need *meaning* — DGA domains, log/text, triage. Quantized int8 (A76 SDOT via the relaxed-dot path, NEON fallback; NPU where granted). | *Near* the hot path, fed escalated events; **tens of ms**. | ✅ `dga-lm` (first); ⬜ broader TinyBERT tier |
| **3 · Human-speed copilot** | A BYO LLM (AEGIS, [ADR 0025](0025-aegis-byo-llm-planner.md)) at the analyst's shoulder — investigation, correlation narrative, intent-to-diff. | Interactive; **never at packet speed**. | ✅ AEGIS |

Two design consequences follow: (a) a question must be answered at the **lowest** tier that can answer
it — you never promote a wire-speed decision to a slower tier, and you never demote an
investigation-grade question to a classifier; (b) the tiers **feed forward, not sideways** — tier-1 scores
escalate to tier-2 semantic analysis, whose findings surface to the tier-3 copilot; enforcement is drawn
from *none* of them directly (D2).

### D2 — C9 is absolute across all three tiers: the enforcement path is model-free

**No tier — not even the deterministic tier-1 reflex classifier — is *the* drop decision.** All three
emit **alerts / scores / advice**; the single deterministic `decide()` and its tri-state verdict
([ADR 0023](0023-enforcement-separation.md) D1) are the ONLY thing that enforces. Model outputs are
**advisory / observe-only inputs** to that deterministic policy, exactly as `dga-lm`'s probability feeds
QSECBIT's `p_attack` component without ever itself dropping a packet
([ADR 0014](0014-continuous-improvement-detection-lifecycle.md) D6). This is what keeps verdicts
explainable, reproducible, and signable, and it is why an adversarial or poisoned model can, at worst,
skew a *score* an operator sees — never silently drop a legitimate customer or wave through an attacker.
The enforcement path carries no model weights.

### D3 — The BPF-LSM process-trust framework (vision): a security framework everything passes through, without a fork

The session's most ambitious idea — *"a custom security framework everything passes through, and every
process carries a trust score"* — is achievable as an **extension point, not a kernel fork**:

- **BPF LSM** (mainline since Linux 5.7) lets eBPF programs attach to LSM hooks — `bprm_check`/exec,
  file open, `socket_*`, `mmap`, `bpf`, module-load, and the rest. That set of hooks *is*
  `hookprobe_security()` — expressed in eBPF, **verifier-sandboxed, updatable without a reboot**, and
  composing with the XDP/TC investment ([ADR 0005](0005-unified-ebpf-detection.md)) rather than replacing
  it. No `security/hookprobe/` in-tree LSM, no patched kernel — it rides the same CO-RE/BTF edge kernel
  ([ADR 0032](0032-custom-edge-kernel-btf-mainline-rp1.md)).
- The per-process **`{ trust, entropy, ai }`** score lives in the **LSM per-task blob**, *not* a
  `task_struct` patch — the LSM framework hangs storage off every task without modifying the struct. So
  "every syscall can ask *should I allow this?*" becomes **QSECBIT-at-the-process-level**: behavioural
  trust gating at syscall time, the host-EDR analogue of the wire-speed reflex tier.
- **Honest bounds.** (1) BPF-LSM's allow/deny-at-hook model is strong for *observe + gate* but is not a
  full in-tree LSM; some enforcement semantics need care or aren't reachable. (2) **C9 still binds it**:
  the trust score is an **INPUT to deterministic policy**, never an autonomous AI kill-switch — any drop
  it motivates routes through the same `decide()` discipline (D2), so a mis-scored process degrades to a
  logged observation, not a silent syscall denial that breaks a legitimate workload. (3) Kill-at-hook
  must honour the overlay-isolation contract ([ADR 0035](0035-substrate-ownership-underlay-overlay.md)):
  it protects the security plane from the workload plane, never the reverse.

### D4 — Attack-surface starvation as an explicit, measured anti-automation posture

Against **AI-scaled / automated attackers**, the OS's own shape is a defence, and it should be named and
*measured*, not left implicit. The minimal, immutable, attested underlay
([ADR 0035](0035-substrate-ownership-underlay-overlay.md) / [ADR 0036](0036-verifiable-supply-chain-reproducible-bootstrappable.md))
— **no shell, no package manager, no persistence, every binary attested, deterministic enforcement** —
**breaks the economics of automated attack**: an exploit chain has nothing to pivot into, nothing to
persist through a reboot, and no un-attested code path to land on. Where an incumbent presents a fat
mutable host that rewards automated lateral movement, HookProbe presents a surface that *starves* it.
This is a positioning and engineering claim to back with a metric (e.g. "N classes of automated
post-exploitation have no landing zone on this image"), owned jointly by security-auditor and
telemetry-analyst — the reflex/semantic tiers catch the *attempt*; the base denies the *foothold*.

### D5 — Model integrity: the detector is an attack surface too

On-device models are themselves attackable (evasion, poisoning, extraction). The
[ADR 0014](0014-continuous-improvement-detection-lifecycle.md) discipline is retained and **extended**:
models are trained **off-device**, **signed**, **digest-pinned**, and **model-carded (SBOM)**; on-device
they are **observe-only** and can never self-train in the enforcement path. The extension is to **attest
the model into the measurement chain** ([ADR 0036](0036-verifiable-supply-chain-reproducible-bootstrappable.md)) — the running
detector's identity is measured/verifiable, so a customer can *prove which model produced a verdict*.
Combined with C9 (D2), this means the worst a compromised model can do is skew an advisory score that is
provably attributed — a posture ahead of a field that mostly ships unsigned, unattested edge models.

## Consequences

- **+ One coherent AI story.** "LLM-per-packet" is ruled out by construction; each question is answered at
  the cheapest tier that can answer it, and the enforcement path stays model-free and deterministic (C9).
- **+ The process-trust framework needs no fork.** BPF-LSM + the per-task blob deliver "trust score per
  process, consulted at syscall time" on the existing edge kernel, updatable without reboot — reusing,
  not duplicating, the eBPF muscle ([ADR 0005](0005-unified-ebpf-detection.md)).
- **+ A named anti-automation posture (D4)** turns the minimal/attested base into a *measurable* security
  claim against AI-scaled attackers, not just a footprint number.
- **− BPF-LSM is roadmap, not built.** Its hooks, performance under load, and the trust-score→policy
  plumbing are unimplemented; the honest bounds in D3 must survive contact with the verifier and a
  benchmark before any gate depends on it.
- **− The semantic tier is one model deep.** `dga-lm` proves the shape; a real TinyBERT-class tier
  (latency/RAM budget on Pi5/CM5/RK3588 silicon, headroom guaranteed by
  [ADR 0035](0035-substrate-ownership-underlay-overlay.md)'s reserved slice) is unbuilt.
- **− Model attestation (D5)** depends on the measurement chain in [ADR 0036](0036-verifiable-supply-chain-reproducible-bootstrappable.md)
  landing first; until then models are signed + digest-pinned (today) but not yet *measured* into an
  attestable boot state.

---

## heqk migration — see [ADR 0043](0043-heqk-microkernel-substrate.md)

**Coupling: SOFT (with a HARD BPF-LSM leg).** The three AI-tier altitude model (µs reflex / ms semantic / human LLM) and the C9 model-free enforcement boundary survive; the headline BPF-LSM per-process-trust framework is re-decided — a capability microkernel implements per-process/syscall trust *more natively* than BPF-LSM hooks. The "attack-surface starvation / no pivot surface" thesis (D4) actively **favours** heqk. → **Phase M5**.
