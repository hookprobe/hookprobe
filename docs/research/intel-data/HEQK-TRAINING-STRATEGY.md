# HEQK intelligence — training strategy, export specification and roadmap

> Status: 2026-11-18. This specifies what the data foundation hands to training, and what it does not.
> No model is trained by this work. The language-tier decision is in `docs/research/neuro/13`; this
> document follows it.

## 1. What each tier learns from

| Tier (`neuro/09`) | Learns | From | Never learns |
|---|---|---|---|
| A deterministic | nothing (rules) | evaluated by collection 01/02 test splits (`dga_ref`, rule recall/FP) | — |
| B fast specialists (int8 trees, char-CNN, logistic heads ≤ 100 KB) | DGA/tunnel names, flow classes | `classify` examples, collections 01, 02 | IOC lists (memorised indicators go stale) |
| C temporal (Neural DNA, learned cell E-N2) | per-device normality | scenario-grouped flows in time order (collection 02) | cross-device identity |
| D language (explainer, evidence-closed decoding) | **explaining a supplied verdict**, citing evidence ids; ATT&CK / CVE knowledge for retrieval | `explain`/`triage` (06), `knowledge` (03, 05) | to be the judge. Phase 0: small LMs judge worse than L0 and anchor on example verdicts |
| E distributed | — | signed indicator deltas (future) | raw customer data |

**Threat feeds stay live intelligence.** Indicators reach devices as signed `IOC.TXT` packs and lookups.
They enter training only as *patterns*, e.g. "a name of this shape was listed". They never enter as a
list for the model to memorise. IPs, domains and CVEs change faster than any retraining cycle.

## 2. Training-example format (`heqk.training-example/1`)

Schema: [`tools/intel-data/schemas/training-example.schema.json`](../../../tools/intel-data/schemas/training-example.schema.json).
A real (fixture-derived) record looks like this, trimmed:

```json
{
  "schema": "heqk.training-example/1",
  "id": "heqk-net-3f1c0a9d2b7e4c51",
  "collection": "network_intelligence",
  "task": "classify",
  "lang": "en",
  "input": {
    "records": [{
      "schema": "heqk.security-event/1", "record_id": "flow:…", "kind": "flow",
      "observed_at": "2018-05-09T15:30:31.015Z", "sensor": {"type": "dataset", "name": "iot-23"},
      "body": {"schema": "heqk.network-flow/1", "proto": "tcp", "orig_ip": "192.168.100.103", "resp_port": 23,
               "conn_state": "S0", "orig_bytes": 0, "…": "…"},
      "labels": {"label": "malicious", "family": "PartOfAHorizontalPortScan", "label_source": "dataset",
                 "original_label": "Malicious/PartOfAHorizontalPortScan",
                 "attack_mapping": {"framework": "MITRE ATT&CK", "techniques": ["T1046"], "tactics": ["TA0007"],
                                    "mapping_source": "heuristic", "version": null}},
      "provenance": {"source_id": "iot-23", "source_record_id": "CTU-IoT-Malware-Capture-1-1:CUmrqr4svHuSXJy5z7",
                     "acquisition_id": "<sha256 of the raw file>", "raw_sha256": "<sha256 of the row>",
                     "license_id": "cc-by-4.0", "transform": {"name": "zeek-conn-labeled", "version": "1.0.0"},
                     "created_at": "…"}
    }],
    "context": {},
    "question": "Classify this connection."
  },
  "target": {"label": "malicious", "confidence": null, "severity": null,
             "attack_mapping": {"…": "…"}, "evidence": ["flow:…"], "reasoning": null,
             "false_positive_considerations": [], "recommended_action": null, "answer": null},
  "ground_truth": {"type": "dataset_label", "verified": false, "label_source": "iot-23 label 'Malicious/…'",
                   "label_quality": "medium", "notes": "ATT&CK mapping is a heuristic of the adapter, not the dataset authors'."},
  "provenance": {"builder": {"name": "heqk-intel-builders", "version": "0.1.0"}, "source_ids": ["iot-23"],
                 "license_ids": ["cc-by-4.0"], "created_at": "…"},
  "split": {"name": "train", "group_key": "iot-23:CTU-IoT-Malware-Capture-1-1", "strategy": "group_hash"},
  "content_sha256": "3f1c0a9d2b7e4c51…"
}
```

Requirements from the brief, and where each one is met:

| Requirement | Where |
|---|---|
| JSON Schema, versioned | `schema` const `heqk.training-example/1`; a breaking change creates `/2` |
| strict types | `additionalProperties: false` throughout; bool is not an integer; unsupported keywords fail closed |
| timestamps, IP and domain forms | `canon.py` + `ip-canonical` / `domain-canonical` formats (validation fails on non-canonical values) |
| explicit nulls | every field is required; absent knowledge is `null` |
| provenance, licences | record-level and example-level provenance; licence ids on every example |
| ground-truth verification | `ground_truth.{type, verified, label_source, label_quality}` |
| confidence calibration | `confidence` is null unless the label source supplies one; calibration is measured on model outputs (§5), never written into labels |
| duplicate detection | `content_sha256` (provenance-free content) → exact dedup; `group_key` → near-duplicate isolation |
| quality validation | every example schema-validated at build; `QUALITY.md` |

## 3. Exports (per `dataset_version`)

| File | Use |
|---|---|
| `examples/<collection>.<split>.jsonl` | canonical, one example per line, sorted by id |
| `sft/<collection>.<split>.jsonl` | `{"id", "messages": [system, user, assistant]}`. The user turn holds evidence cards marked **untrusted** and the question; the assistant turn is a canonical-JSON answer (label, severity, ATT&CK, evidence ids, answer/reasoning). Works with any chat fine-tuning stack (TRL, Axolotl, llama.cpp finetune) |
| `ioc/IOC.TXT` | `live_intel` purpose only; `ioc.rs` syntax; **unsigned**: sign with the operator key |
| `parquet/examples.parquet` | only if `pyarrow` is installed; same content as the canonical JSONL |
| `manifest.json` | `heqk.manifest/1`: inputs, licences, output sha256s, exclusions |
| `quality.json`, `QUALITY.md` | the quality report (§5) |

The `sft` view follows the system rule from Phase 0 / `09` §5: telemetry is untrusted data, never
instructions. Distillation runs the same way: the teacher's outputs are stored as new examples with
`ground_truth.type = "synthetic"` and the teacher named in `label_source`. They are never stored as
`dataset_label`.

## 4. Collection plan

| # | Collection | Implemented now | Next real source (licence-cleared) | Blocked on |
|---|---|---|---|---|
| 01 | DNS | builder; dga.rs benchmark; **266,548 examples** from UMUDGA (MIT) + PhiUSIIL (CC BY 4.0) | an open DGA/tunnel corpus (see research §3); HookProbe lab captures of DNS tunnelling tools (iodine, dnscat2) in the isolated lab | a benign baseline with a clear licence (Tranco UNKNOWN; Cloudflare Radar NC); abuse.ch AI-training consent |
| 02 | Network | Zeek (IoT-23, CTU) + CICFlowMeter adapters | IoT-23 (CC BY 4.0) via `register` | — |
| 03 | Attack | ATT&CK knowledge | Atomic Red Team (MIT) test metadata; OTRF Security-Datasets (MIT) / Splunk attack_data (Apache-2.0) host logs; **lab traces** | the isolated lab (below) |
| 04 | Malware | — (specified) | sandbox-report metadata with a training licence | abuse.ch consent, or a vendor agreement |
| 05 | Vulnerability | KEV knowledge | CVE List v5 (CVE ToU), CWE/CAPEC (MITRE ToU), Vulnrichment (CC0), GHSA (CC BY 4.0) | — |
| 06 | SOC reasoning | 36 synthetic triage examples (9 scenarios incl. 3 benign twins) | **analyst-reviewed** incidents from HookProbe's own lab and home deployments with consent; the neuro E-SC2 IoT-23 evidence cards | consent flow ([governance](HEQK-DATA-GOVERNANCE.md) §3) |

**Lab traces (collection 03):** attack simulation runs only in an isolated, HookProbe-owned lab network
behind a heqk device:
- no attack tooling runs on the development Mac, and nothing targets third parties;
- each run records the Atomic/CALDERA test id, which gives `AttackScenario` ground truth with
  `mapping_source = source`;
- each run is also captured as pcap → Zeek/heqk detections;
- the result is the highest-value training data in the plan: labelled by construction, licensed by
  ownership (HookProbe's own), and matching the device's real telemetry shape.

## 5. Evaluation

| Measure | How |
|---|---|
| Precision, recall, F1, FPR | per collection, per source, on group-held-out test splits |
| **DNS false positives** | benign-baseline FP rate at the device threshold (600) for `dga_ref`, and at the operating point for any tier B model. Report FP per 10 k distinct names *and* per device-day at measured home query volumes (`docs/design/det01-home-24h-2026-11-13.md`) |
| Calibration | reliability diagram + ECE on model scores (tier B), on dev split, before any confidence is shown in Mission Control |
| Distribution shift | `time` split (train past → test future) and `source_holdout` (train CTU, test IoT-23 / CIC) |
| Language tier | the existing blind set (215 cases, never trained on) + constant-answer and L0 baselines published next to every model score (`09` §5) |
| Data quality | `QUALITY.md`: label-quality grades, verified share, synthetic share, class imbalance, missing fields, temporal coverage, source diversity, provenance and licence completeness, contamination |

Accuracy on one benchmark is never reported alone. CIC-IDS-style datasets reach 99%+ for artefactual
reasons (Engelen et al. 2021); every headline number needs a cross-source result next to it.

## 6. Deployment targets

The data contract is the same on every target; only model size changes.

| Target | Tier B | Tier D | Notes |
|---|---|---|---|
| CM5 (heqk, aarch64, 4×A76) | int8 specialists in the EL0 server, scalar now, NEON after R2 | leased, 0.3–1 GiB, 4 GB SKU+, explain-only (`neuro/07`, `13`) | inference budget measured, not assumed (`neuro/11`) |
| RK3588 (HookProbe SBC) | same + NPU later | same | chip-down board, not a module |
| N100 / x86-64 | same | larger model or off-device fallback | — |

## 7. Roadmap

| Step | Deliverable | Gate to pass |
|---|---|---|
| R1 (this PR) | registry (149 sources, 118 licences), schemas, pipeline, tests, acquisitions: KEV, ATT&CK, Feodo, PhiUSIIL, UMUDGA; dga.rs baseline | `heqk_data.py check` + unit tests green |
| R2 | licence actions: abuse.ch/Spamhaus AI-training consent request; Tranco terms confirmation; CIRCL MISP community application; DNSC cooperation proposal; UPB research partnership | registry entries updated by reviewed commits |
| R3 | IoT-23 registered and normalised; collection 02 first real build; neuro E-N2 consumes it | contamination 0; cross-scenario results |
| R4 | isolated attack lab + capture → collection 03 traces | security-auditor review of the lab isolation |
| R5 | consent flow + telemetry adapter (heqk export frame v2 → `detection` records) | governance §3 checklist; legal review |
| R6 | first tier B DNS specialist trained on a licence-clean build; compared with `dga.rs` on the same test split | FP per device-day ≤ dga.rs at equal recall |
| R7 | language-tier explainer fine-tune on 03/05/06, evaluated on the blind set | beats template-only explanation coverage without verdict regressions |
| R8 | CI wiring: add `python3 -I -m unittest discover -s tools/intel-data/tests` to gate g0 | needs a human-authored change to `tools/ci/` (autofix-protected path) |
