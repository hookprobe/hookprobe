# ADR 0036 — Verifiable supply chain: reproducible → provenance → transparency → bootstrappable

**Status:** 🟡 Proposed (2026-07-17) — a design-session posture that records the "verify, don't trust"
trust ladder as a ranked, honest roadmap; pending ratification. **Separates implemented-today from
roadmap explicitly**: cosign-keyless image signing, hybrid ML-DSA-65+Ed25519 module signing, and
SBOM/CBOM-per-image already ship (ADR 0016, ADR 0002); **everything this ADR adds — reproducible
builds, SLSA/in-toto provenance, a binary-transparency log, diverse-double-compiling, and a
reduced-seed bootstrap — is roadmap, marked per-rung, never fabricated as present.**
**Deciders:** security-auditor (author), release-engineer, os-architect, product-steward.
**Relates to:** [ADR 0002](0002-crypto-agility-pqc.md) (crypto-agility; the signing suites this rides on;
hash alg is policy), [ADR 0016](0016-artifact-hash-signing.md) (artifact-hash signing — "the signature
covers the payload"; the digest this ADR makes a *rebuilder* recompute), [ADR 0017](0017-authenticated-aot-cache.md)
(authenticated AOT — the same digest-before-execute discipline), [ADR 0035](0035-substrate-ownership-underlay-overlay.md)
(the minimal owned base — a *smaller* trust surface to bootstrap), [ADR 0037](0037-zero-touch-onboarding-flasher-provisioning.md)
(the client-side flasher + device self-verify that close the chain with zero trusted third parties).

---

## Context — reproducibility is necessary but not sufficient

For a security OS whose threat model names nation-states and AI-scaled attackers, **"it's open source"
is a weak claim unless the binary you flash provably ties to the source you can read.** Today the trust
story stops at *signing*: the image and every module are cosign/ML-DSA-signed and carry an SBOM/CBOM
(ADR 0016/0002), and the device refuses to run anything unsigned. That defeats a tampered *artifact* —
but it does **not** answer "does this signed binary correspond to the public source, or did something
get inserted at build time?"

Ken Thompson's *Reflections on Trusting Trust* (1984) is the ghost: a compiler can be backdoored to
poison a target **and** to re-insert both backdoors when compiling its own source, so the attack
survives a clean-source recompile and is invisible in the source forever. **Reproducible builds alone do
not kill it** — if everyone bootstraps from the same poisoned toolchain binary, everyone reproduces the
same poisoned output *bit-for-bit*. Reproducibility proves "binary matches source **+ toolchain**"; the
**toolchain itself is the un-audited root** (historically hundreds of MB of opaque GCC/glibc/bash
binaries you simply trust). Verifiable trust is therefore a **ladder**, and this ADR records the rungs,
each with its honest cost and altitude, and which ones HookProbe commits to when.

---

## Decision

**Adopt "verify, don't trust" as the supply-chain posture, climbed as a ranked ladder. Ship Rung 1+1b
as the v1 must-have; treat Rung 2 as the high-ROI next step; treat Rung 3 as a long-horizon
differentiator that does NOT gate v1.** Being *on this ladder at all* is already further than the entire
commercial security-appliance market.

### D1 · Rung 1 — Reproducible builds (must-have, roadmap)

Anyone can rebuild the published version from pinned source and get a **bit-identical** image whose hash
matches the signed one — so a build-server compromise or a slipped-in backdoor is *caught* by any
rebuilder, not merely prevented. The signature (ADR 0016) already covers a content hash; reproducibility
makes that hash **independently recomputable**.

Honest hard parts (each a tracked work item, not a hand-wave):
- **Timestamps are the #1 enemy** — `SOURCE_DATE_EPOCH`, `KBUILD_BUILD_TIMESTAMP` / `KBUILD_BUILD_USER`
  / `KBUILD_BUILD_HOST`, clamped mtimes, deterministic `tar`/`mkfs`.
- **The kernel + BTF is the sharp edge** — `pahole` can emit *different BTF* across versions, and the
  edge kernel *needs* BTF (ADR 0032, ADR 0005 CO-RE). Pinning the exact `pahole` + toolchain is a real
  landmine, called out here so it is designed for, not discovered.
- **Deterministic image assembly** — ext4/squashfs bake in UUIDs/timestamps; the **composefs /
  content-addressed** direction (ADR 0019) helps and should be preferred.
- **Full toolchain-closure pinning** — "reproducible" is fragile unless the *entire* dependency graph is
  version/hash-pinned; this is where a deterministic builder (ADR 0035's Buildroot/Yocto/Nix path) wins
  natively over a curated general distro.
- **The UX gotcha** — reproducible-*in-theory* is theatre if rebuilding is a 40-step ordeal nobody
  attempts. The deliverable is a **one-command rebuild** (`hookprobe-rebuild <version>` → image →
  `sha256 == published`) so *verification* is a two-minute act, not a research project.

Precedents to follow: **Tails** (an amnesic security OS that ships reproducible, user-verifiable
images — almost exactly HookProbe's shape), **Debian Reproducible Builds**, **Bitcoin Core** and **Tor
Browser** (security-critical binaries verified by independent rebuilds for years).

### D2 · Rung 1b — Provenance + binary transparency (ships alongside Rung 1)

- **SLSA / in-toto provenance attestation** beside the cosign signature — not just "this hash is signed"
  but "this hash was built from *this* source by *this* pipeline."
- **A binary-transparency append-only log** (sigstore Rekor / Go-sumdb style): every released image hash
  is published so **everyone is offered the *same* signed artifact.** Reproducibility lets you verify
  *if you rebuild*; the transparency log stops a **targeted** attack (serving one specific user a
  backdoored image) because the attacker cannot fork an append-only log without everyone noticing.
- **Emergent property worth stating**: reproducibility makes **signing-key compromise *detectable*, not
  just preventable** — a stolen CI key signing a *different* image will not match anyone's rebuild, so
  the mismatch screams. This is the backstop for "the signing keys are the crown jewels."

### D3 · Rung 2 — Diverse Double-Compiling (high-ROI next rung, roadmap)

Wheeler's DDC: rebuild the toolchain's source with a **second, independent** compiler, use the result to
rebuild the real compiler, and confirm the binary matches the official one. A trusting-trust backdoor in
compiler A would not exist in compiler B, so the outputs diverge and the attack is exposed. **It detects
the poisoned toolchain via *diversity* without re-architecting the build** — a periodic verification
project, not a rebuild-the-world commitment. This is the recommended rung *after* v1, because it closes
the trusting-trust residual that Rung 1 leaves open at modest cost.

### D4 · Rung 3 — Bootstrappable / reduced-seed (the summit, long-horizon; does NOT gate v1)

Eliminate the trust root rather than detect its poison: shrink the trusted binary seed until it is
**human-auditable**. The GNU Guix "Full-Source Bootstrap" reduces the entire opaque binary root to a
**~357-byte `hex0` seed** → hex/M-assemblers → M2-Planet → **GNU Mes/MesCC** → **TinyCC** → an old GCC →
a modern GCC → glibc → kernel → distro; **live-bootstrap** does this end-to-end on Linux. At the summit,
the only software you trust as an opaque binary is a few hundred bytes you can read in an afternoon.

**The floor is hardware.** Even at 357 bytes you still trust the CPU/microcode/firmware running the seed,
and the human who audits it. Going deeper is a *hardware* frontier (open silicon — RISC-V, OpenTitan),
not a software one. This ADR names the floor honestly so "trust nothing you didn't build" is not
oversold: software bootstrapping bottoms out at "trust the chip."

### D5 · The convergence — this is the same bet as the minimal owned base

A **minimal** base (ADR 0035) is a **smaller thing to bootstrap and reproduce** — every package not
shipped is one fewer artifact to trace to source. So **minimal → owned → reproducible → bootstrappable
is one coherent arc**, each rung enabling the next, and minimalism is what makes the summit reachable.
The choice of a deterministic builder (ADR 0035) delivers *minimal + owned + reproducible* in one move;
that is a second, larger reason to leave a general-purpose base beyond footprint.

### D6 · The chain closes with zero trusted third parties

Combined with ADR 0037's provisioning model, the end-to-end chain has **no unverifiable trusted party**:

> reproducible (source → bit-identical binary) → SLSA-attested + cosign/ML-DSA-signed (provenance) →
> transparency-logged (everyone gets the same artifact) → **client-side static flasher** (no backend
> ever touches a key) → **device self-verifies the signature on boot** (the trust store, ADR 0016).

Every link is auditable by math or by the operator's own rebuild. Not even HookProbe sits in a position
of unverifiable trust — the point of *"verify, don't trust,"* and the deepest available answer to "why
should I trust your black box?" for the customers who scrutinize hardest.

---

## Consequences

**Positive.** A trust story no closed competitor can structurally match, and one most open projects do
not bother to climb: source↔binary provenance (Rung 1), same-artifact-for-everyone (Rung 1b),
trusting-trust detection (Rung 2), and a path to a ~357-byte auditable root (Rung 3). Reproducibility
also turns signing-key compromise from a silent catastrophe into a *detectable* event. The posture
reinforces — and is reinforced by — the minimal owned base (ADR 0035).

**Costs / honest limits.**
- **Reproducibility is real engineering, not a flag** — timestamps, kernel+BTF/pahole determinism,
  deterministic image assembly, and full toolchain pinning are each nontrivial; the BTF landmine in
  particular is load-bearing for HookProbe specifically.
- **Verification UX is as important as the property** — without a one-command rebuild, reproducibility
  is theatre; the rebuild tool is a first-class deliverable, not documentation.
- **DDC needs a genuinely independent second compiler** — diversity is the whole point; a same-lineage
  "second" compiler proves little.
- **Rung 3 is a heavy ecosystem commitment** (Guix's bootstrap is a specific world); it is a
  differentiator to *aim at*, explicitly **not** a v1 gate.
- **The hardware floor is irreducible in software** — CPU/microcode/firmware and the auditing human
  remain; only open silicon goes deeper, and that is out of scope here.

**Residual / follow-ups.** Pin the reproducibility toolchain (esp. `pahole`/BTF); decide the transparency
log (self-hosted Rekor vs a public log); scope the one-command rebuild tool; sequence DDC after v1; keep
Rung 3 as a tracked north-star, not a commitment. The traceability trail (this posture → per-rung work
items → gate evidence) is owned by product-steward per the Cortex.

---

## heqk migration — see [ADR 0043](0043-heqk-microkernel-substrate.md)

**Coupling: ENABLES.** heqk (a ~33k-LOC owned Rust kernel) is the *endpoint* of this ADR's minimal→owned→reproducible→bootstrappable arc — far more reproducible than a 1.3 GB Debian image — and it **deletes** the kernel-BTF/`pahole` reproducibility landmine this ADR flags. The goal is advanced, not blocked. → **Phase M7**.
