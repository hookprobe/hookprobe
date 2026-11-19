# HEQK Security Intelligence — data foundation (2026-11-18)

This is the data layer that HookProbe's intelligence tiers (`docs/research/neuro/09`) will learn from
and be evaluated on. It covers which sources are legally usable, a canonical data model, a traceable
pipeline, and the first licence-clean builds. It is research plus tooling only: it changes no product
behaviour, no kernel code and no ADR.

| Document | Contents |
|---|---|
| [HEQK-SECURITY-INTELLIGENCE.md](HEQK-SECURITY-INTELLIGENCE.md) | architecture assessment of what exists; the canonical data model (30 entities); taxonomy alignment; pipeline |
| [HEQK-DATASET-RESEARCH.md](HEQK-DATASET-RESEARCH.md) | findings from three research passes; licensing traps; regional (CH/LU/EU/UK/RO) routes; recommended actions |
| [CATALOGUE.md](CATALOGUE.md) | generated table of all 149 sources and 118 licence decisions, with the gate result per purpose |
| [HEQK-DATA-GOVERNANCE.md](HEQK-DATA-GOVERNANCE.md) | licence gate, provenance, GDPR and telemetry consent, safe parsing, synthetic data, evaluation hygiene |
| [HEQK-TRAINING-STRATEGY.md](HEQK-TRAINING-STRATEGY.md) | what each tier learns from; TrainingExample format; export spec; evaluation; roadmap R1–R8 |
| [QUALITY-2026-11-19.md](QUALITY-2026-11-19.md) | quality report and manifest of the latest build: 660,123 examples (DNS 266,548 · network flows 391,047 from all 23 IoT-23 captures · KEV 1,786 · ATT&CK 706 · synthetic SOC 36), with the measured label counts of the 12 sampled captures |
| [DGA-BASELINE-2026-11-18.md](DGA-BASELINE-2026-11-18.md) | **measured:** the shipped `dga.rs` on 49,898 DGA names (50 families) and 135,796 benign names |

Tooling: [`tools/intel-data/`](../../../tools/intel-data/).

**Three findings to read first:**
1. **Most of the obvious data is not usable for a commercial model.**
   - abuse.ch now forbids AI training without Spamhaus consent, and needs a paid licence for
     commercial use.
   - Tranco has no licence and blends non-commercial (NC) sources.
   - Every phishing feed checked is closed.
   - What is clean: MITRE ATT&CK/CWE/CAPEC, CVE, CISA KEV, UMUDGA, IoT-23, CTU-13, LANL (CC0), Kitsune,
     PhiUSIIL, Atomic Red Team, CALDERA, and HookProbe's own lab data.
2. **The language model should be trained to explain, not to judge.** This follows Phase 0: small LMs
   judged worse than the deterministic core. Feeds stay live intelligence and are not memorised.
3. **`dga.rs` never cries wolf, but it rarely catches DGAs.** At the device threshold it raised zero false positives on 135,796 benign names, and it caught 6.8% of DGA names; 31 of 50 families are never flagged ([baseline](DGA-BASELINE-2026-11-18.md)). This is the measured case for a tier-B DNS specialist.
4. **HookProbe's own DNS protection blocks security-research sites.** The lab resolver (dnsXai on the lab router) answers NXDOMAIN for feodotracker.abuse.ch, archive.ics.uci.edu, stratosphereips.org
   and data.mendeley.com. The operator allowlisted them on 2026-11-18 so the acquisitions could run.
