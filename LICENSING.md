# HookProbe OS — Licensing

> **Transparent licensing for transparent technology.**
> Personal and business self-protection: free, forever. Offering HookProbe OS
> as a service to others: commercial license required. Audit the code: always.

**Applies to:** the whole HookProbe OS monorepo (this repository).
**Model:** dual-license — **GNU AGPL-3.0** (open / source-available) **+ Commercial**.

---

## The short version

- **Run it yourself — personal or business — free.** Deploy HookProbe OS on your
  own hardware/infrastructure to protect yourself or your own organization at no
  cost, under the AGPL-3.0.
- **Offer it as a service to third parties — commercial license.** The AGPL
  network-copyleft clause treats "running modified software as a network
  service" as distribution; offering HookProbe OS (or a derivative) as a managed
  service, SaaS, or OEM/embedded product requires either full AGPL source
  disclosure of your service **or** a commercial license.
- **Some core innovations are proprietary** and require a commercial license
  regardless — they are fully documented so you always understand what they do.

This is the deliberate open-core moat behind HookProbe OS's business model:
**the standalone SOC is free; the cloud/account/service layer is commercial.**

---

## Why dual licensing

1. **Community trust** — AGPL-3.0 is OSI-approved; the base OS is genuinely
   open and auditable.
2. **Protection against cloud exploitation** — network copyleft prevents a
   competitor from reselling HookProbe-as-a-service without contributing back.
3. **Sustainable development** — commercial licenses fund continued work.
4. **Innovation protection** — the core AI/ML detection algorithms stay a
   competitive advantage.
5. **Transparency maintained** — even proprietary components are documented.

---

## What is AGPL-3.0 (open) vs Commercial (proprietary)

The **open, AGPL-3.0** surface is the base operating system and standalone SOC:
the substrate/image build, the module framework and detection modules, the
supervisor/reconciler, Mission Control, deployment scripts, and public docs.
The full AGPL-3.0 text is in [`LICENSE`](LICENSE).

The **proprietary / commercial** surface is the set of core innovations —
the QSECBIT AI scoring models and trained weights, the dnsXai ML classifier and
federated learning, the Neural Resonance / keyless-HTP schemes, the DSM
consensus/ledger, premium threat intelligence, the cloud management plane, and
white-label capabilities — plus **any offering-as-a-service** of the whole.

For the detailed, component-by-component breakdown of exactly which files fall
under each category, the usage scenarios (home / self-hosted business / SaaS /
OEM / academic), the commercial license tiers, and the FAQ, see the canonical
source, which the whole project follows:

- **[`kernel/heqk/LICENSING.md`](kernel/heqk/LICENSING.md)** — the detailed
  HookProbe licensing policy (v5.0 "Cortex"). It is component-scoped in its file
  paths but is the project-wide policy of record; this root document promotes it
  to the repo front door. Where the two ever diverge, this root document governs
  repo scope and `kernel/heqk/LICENSING.md` governs the HEQK component.

---

## Usage scenarios (summary)

| You want to… | License | Cost |
|---|---|---|
| Protect your own home network | AGPL-3.0 | Free |
| Protect your own business (internal use only) | AGPL-3.0 | Free |
| Offer HookProbe-based security as a managed service | Commercial | Contact |
| Embed / OEM / white-label HookProbe into a product | Commercial | Contact |
| Academic / non-commercial research | Research license | Free (qualifying) |

Modifications to AGPL components must be shared if you distribute them or offer
them as a network service. Proprietary components cannot be used or modified
without a commercial license.

---

## Contact

Licensing, compliance, contributor agreements (CLA), and commercial terms:
**qsecbit@hookprobe.com**

For third-party component licenses, see the project's third-party license
documentation referenced from `kernel/heqk/LICENSING.md`.
