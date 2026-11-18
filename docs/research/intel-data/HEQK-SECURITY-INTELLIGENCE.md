# HEQK Security Intelligence — data foundation: architecture assessment and canonical data model

> Status: **research + first implementation, 2026-11-18.** A proposal for operator review; it changes no
> product behaviour, no kernel code and no ADR. Tooling: [`tools/intel-data/`](../../../tools/intel-data/).
> Companion documents: [dataset research](HEQK-DATASET-RESEARCH.md) ·
> [governance](HEQK-DATA-GOVERNANCE.md) · [training strategy and export spec](HEQK-TRAINING-STRATEGY.md) ·
> [generated catalogue](CATALOGUE.md).

## 1. Architecture assessment (Phase 1)

The repository already decides most of what a data foundation must respect. This section records what
exists, so the foundation feeds it instead of duplicating it.

### 1.1 What produces security events on heqk today

| Component (name in the brief) | What actually exists on heqk | Event shape | Source |
|---|---|---|---|
| NAPSE (IDS) | In-kernel rules: built-in catalogue (ids 1–302) + signed field-updatable rule packs (`RULES.BIN`, ids 1000–1999), RFC 9669 BPF programs, JIT-compiled | detection row: `rule_id, rule_msg, category, severity 1–5, mitre, src_ip, dst_ip, dst_port, confidence, build` | `os/kernel/kernel/src/{rules,rulecat,rulepack,bpf}.rs`, `mcstate.rs::det_row` |
| dnsXai | **Shield v2**: signed BLOCK/ALLOW lists, NXDOMAIN + EDE 15; plus `dga.rs` (integer port of the dnsXai lexical scorer) raising observe-only `dns_dga` (rule 119). *"No ML/keyword rule ever blocks."* | detection rows; Shield decisions | `shield.rs`, `dga.rs`, `dnssink.rs`, ADR 0052 |
| HYDRA (threat intel) | `ioc.rs`: operator-signed `IOC.TXT` (≤ 64 K IPv4 prefixes + 64 K domains, optional `exp=`), matching is **observe-only** (rule 302 / Shield `ioc_match`). Feeds are compiled into this format **off-device**. Legacy tier: `hookprobe-ioc-v1` JSON (ADR 0027). | `ioc_match` detections | `ioc.rs`, ADR 0027, `legacy/linux-tier/security/threat-intel/` |
| AEGIS | Deterministic reconciler; the AI planner endpoint answers `503 not_configured` | — | `http.rs:429` |
| XDP/eBPF | **Not on heqk.** heqk runs its own RFC 9669 BPF ISA verifier + interpreter + arm64 JIT. XDP/eBPF lives in `legacy/v1` | — | ADR 0043 D2 |
| Suricata / Zeek | **Not on heqk.** They were V1 NAPSE components (`legacy/v1/core/napse`). Their formats matter here only because most public datasets are Zeek logs, CICFlowMeter CSVs or Suricata EVE | — | `legacy/v1` |
| Corroboration | Multi-axis per-source severity raise. **Never changes the wire verdict** (security-auditor ruling 2026-09-08) | severity only | `corroboration.rs` |
| Export | M6 frame v2 (`exportwire.rs`, 20-byte records) over the enrolled Noise channel; local SIEM export as RFC 5424 or OCSF-style JSON (class 2004) | binary frames / syslog / OCSF | `export.rs`, `exportwire.rs`, `siem.rs` |
| Device identity | JA4 per MAC (`ja4id.rs`), DHCP fingerprints (`fpdb.rs`, generated from V1 Fingerbank tables) | hints, never identity merges | — |

### 1.2 What inference exists

- **Neuro stage 1** (merged 2026-11-18, `os/neuro/`): the per-device "Neural DNA" temporal engine. It is
  integer-only `no_std` Rust in one EL0 server, 1,296 B per device, and bit-exact to its Python reference.
  It was measured on IoT-23 (CC BY 4.0, not committed). **It observes and scores; it never decides
  enforcement.**
- **Native inference programme** (`docs/research/neuro/00–14`): fixes the five intelligence tiers this
  foundation serves:
  - A: deterministic;
  - B: fast specialists;
  - C: temporal;
  - D: language, used to explain only;
  - E: distributed.
- **Phase 0 evidence** (`docs/research/neuro-engine/`):
  - On a 215-case blind set, small LMs judged *worse* than the deterministic L0 core (0.37–0.50 vs 0.59).
  - They anchor on example verdicts.
  - They are good explainers: explanation coverage rose from 0.27 to 0.56–0.73.
  - This is the strongest constraint on the training strategy: **do not train the LM to be the judge.**
- **Tooling conventions this foundation keeps:**
  - stdlib-only Python run with `python3 -I`;
  - real data never committed;
  - dev/test split by scenario hash;
  - evidence classes `measured` / `simulated` / `proposed`.

### 1.3 Decisions the foundation must preserve

1. **No model authorises enforcement** (ADR 0023, contract C9; `09` §1). Training targets carry a
   `recommended_action`. The vocabulary is advisory, `decide()` and the separation matrix enforce, and
   identity-based intel (IOCs, feeds) stays observe-only.
2. **Four separate stores** (`09` §2): learned weights, per-device state, threat intelligence and
   deterministic policy. A feed update can never change a model, and the reverse holds too. Here this
   means **feeds are live inputs (IOC.TXT, lookups), not training labels to memorise.**
3. **Trust nothing unsigned.** This tooling emits an *unsigned* `IOC.TXT`. Signing stays with the
   operator key, the same as every IOC pack.
4. **Standalone and private by default.** No customer telemetry enters a dataset without consent and a
   legal basis ([governance](HEQK-DATA-GOVERNANCE.md) §3).
5. **Kernel is HomePods'.** Nothing here touches `os/kernel`. The DGA reference is a read-only port,
   checked against the Rust source.

### 1.4 Gaps this foundation fills

| Gap | Before | Now |
|---|---|---|
| Source and licence knowledge | Feeds hard-coded in scripts, licences unchecked (`hydra-feed-fetch.sh`, V1 `feed_sync.py`) | 149 catalogued sources and 122 licence decisions, all machine-checked ([catalogue](CATALOGUE.md)) |
| A data model shared by datasets and heqk telemetry | Each experiment parsed its own format | `heqk.security-event/1` envelope + kind schemas, aligned to `det_row` / `siem.rs` |
| Licence enforcement | none | `licensing.decide()` gates acquisition **and** build, per purpose |
| Leak-free splits | per script | group-keyed splits + contamination check that fails the build |
| A benchmark of the shipped DNS scorer | `[P-dga]` self-test (8 bad / 38 good names) | bit-exact `dga_ref.py`; per-source FP/TP on every DNS build |
| IOC pack generation | "compiled off-device" (by nothing in this repo) | `build --purpose live_intel` → `IOC.TXT` |

**Findings worth flagging:**
1. Two legacy feed scripts fetch sources whose terms are now restrictive or unknown:
   - `legacy/linux-tier/modules/hydra/hydra-feed-fetch.sh` and V1 `feed_sync.py`;
   - affected feeds: FireHOL level 1, ET compromised-ips, blocklist.de, CINS, GreenSnow, IPsum;
   - see the research doc §3.
   They are frozen legacy code, but a heqk IOC pack must not be compiled from them without a licence
   decision.
2. The brief places **CIRCL in Switzerland. It is Luxembourg's CERT.**

## 2. Canonical data model

### 2.1 Layers

```
raw (immutable, as acquired)  ──adapter vX──▶  normalised records          ──builder vY──▶  examples
raw/<source>/<sha256>/file                     heqk.security-event/1                       heqk.training-example/1
acquisition.json (licence snapshot)            one envelope, kind-specific body            input = records, target = what the label source asserted
```

Each layer is versioned (adapter / builder versions are in every record's provenance), and each record
traces back to the raw bytes: `provenance.acquisition_id` is the file's sha256 and `raw_sha256` is the
row's sha256.

### 2.2 Entities

The brief lists 30 entities. The table shows how each is represented. Entities marked **schema** have
a versioned JSON Schema in `tools/intel-data/schemas/` and are enforced. Entities marked
**specified** have their mapping decided here and get a schema with their first real source.

| Entity | Representation | Status |
|---|---|---|
| Dataset | `collection.schema.json` (the six training collections) | schema |
| DatasetVersion | `manifest.schema.json` (`dataset_version`, inputs, output checksums, exclusions) | schema |
| DataSource | `source.schema.json` (catalogue entry) | schema |
| DataLicense | `license.schema.json` (+ the gate in `licensing.py`) | schema |
| SecurityEvent | `security-event.schema.json` envelope: `record_id, kind, observed_at, sensor, body, labels, provenance` | schema |
| NetworkFlow | `network-flow.schema.json` (Zeek conn vocabulary; CICFlowMeter mapped in) | schema |
| DNSQuery + DNSResponse | `dns-event.schema.json` (one transaction; `answers` empty when no response) | schema |
| IPAddress, Domain, URL | canonical **value types** (`common.schema.json` `ip`, `domain`; URL inside `indicator`), not tables. A graph store can promote them to nodes keyed on the canonical value | schema (types) |
| Certificate | `indicator` with `ioc_type: x509_sha1`; full X.509 metadata specified for when a certificate source (SSLBL, CT logs) is admitted | specified |
| FileHash | `indicator` with `ioc_type: sha256/sha1/md5` | schema |
| MalwareSample | **never stored**: metadata only, via `indicator.family` + sandbox-report fields (specified). `safeio` refuses executable members | specified (by design) |
| MalwareFamily | `labels.family` / `indicator.family` string. A family table keyed on Malpedia-style names is specified | specified |
| ThreatActor, Campaign | STIX 2.1 `threat-actor` / `campaign` mapping specified (§2.4); no source admitted yet with usable licence | specified |
| IndicatorOfCompromise | `indicator.schema.json` (a superset of `hookprobe-ioc-v1`) | schema |
| Vulnerability | `vulnerability.schema.json` (CVE, CWE, CVSS, KEV, ransomware use) | schema |
| Exploit | `vulnerability` + exploit-availability fields specified (Exploit-DB is GPL: metadata/eval only) | specified |
| AttackTechnique | `attack-technique.schema.json` (from ATT&CK STIX, STIX id kept) | schema |
| AttackScenario | `collection` 03 lab traces: an ordered list of records with a scenario id as `group_key` | specified |
| SecurityAlert | `security-event` kind `detection` (= heqk `det_row` / `siem.rs::Det`) | schema |
| DetectionRule | heqk `rulecat` id + category + ATT&CK; Sigma/YARA/Suricata rule *metadata* (id, author, licence) specified. DRL 1.1 requires keeping the author on alerts | specified |
| Incident | an analyst-reviewed `soc_reasoning` example: records + verdict + response | schema (as example) |
| Remediation | `target.recommended_action` (advisory vocabulary) + `answer` text | schema |
| ThreatIntelligence | `indicator` records with `sensor.type = feed` | schema |
| TrainingExample, EvaluationExample | `training-example.schema.json` (`split.name` distinguishes) | schema |
| ModelVersion | specified: `{model_id, base_model, dataset_versions[], hnx_package_sha256, eval_report}`. Belongs with HNX (`docs/research/neuro/06`) | specified |
| DataLineage | `provenance` on every record + example; `audit.jsonl`; `catalog.sqlite` | schema |

### 2.3 Canonical forms and null handling

| Value | Canonical form | Why |
|---|---|---|
| timestamp | RFC 3339 UTC, ms, `Z` (`2026-11-18T09:30:00.000Z`) | sortable as strings; time splits |
| IP | `ipaddress` compressed; IPv4-mapped IPv6 → IPv4 | dedup across sources |
| domain | lowercase IDNA A-label, no trailing dot, RFC 1035 limits | dedup; registrable grouping |
| registrable domain | label + suffix by **the same rule as `dga.rs::split`** | split groups match what the device scores |
| severity | heqk catalogue words `critical/high/medium/low/info` (= 1–5) | one scale with Mission Control |
| JSON | sorted keys, no whitespace, UTF-8 | content hashes |

Absent knowledge is always an explicit `null`, never `0`, `""` or a guess. In particular:
- `labels.label` is `null` for unlabelled flows. An unlabelled flow is unknown, not benign.
- `target.confidence` is `null` unless the label source gives one. This tooling never invents
  calibration.
- `reasoning` is `null` unless a human or an explicitly synthetic generator wrote it.

### 2.4 Taxonomy and format alignment (what is mapped, what is kept separate)

The rule is: **do not blindly combine incompatible schemas.** Each upstream identifier is preserved in
place, and nothing is merged into a lossy "universal" field.

| Standard | How it is used | Kept from upstream |
|---|---|---|
| MITRE ATT&CK | `attack_mapping{framework, version, techniques[], tactics[], mapping_source}`. `mapping_source` says WHO asserted it (`source`, `heqk_rulecat`, `analyst`, `heuristic`) | STIX `attack-pattern--` id, ATT&CK version |
| CWE / CAPEC / CVE | ids by pattern in `vulnerability`; CAPEC ↔ ATT&CK links come only from CAPEC's own references | upstream ids |
| CVSS | `{version, vector, base_score}`; vector string kept verbatim | vector |
| CPE | specified for `vulnerability` (`affected[]`), when NVD/CVE-list is admitted | CPE 2.3 string |
| STIX 2.1 | `indicator` ↔ STIX `indicator`: `value/ioc_type` ↔ pattern, `first_seen` ↔ `valid_from`, `expires` ↔ `valid_until`, `confidence` (0–100 → 0–1), TLP marking | STIX id in `source_record_id` |
| MISP | attribute `type/value/category/to_ids/first_seen/last_seen/tags` → `indicator`. Galaxy clusters → `family` / ATT&CK | MISP event + attribute uuid |
| Sigma | rule metadata (id, title, status, level → severity, tags `attack.t####` → ATT&CK, **author**) | rule id + author (DRL 1.1) |
| YARA | rule metadata only (name, author, licence, family tags). Never executed against samples here | rule name + licence |
| Suricata EVE | `alert` → `detection` (signature_id, category, severity 1–3 → high/medium/low); `flow`/`dns` → `flow`/`dns` | `flow_id`, sid |
| Zeek | `conn.log` → `network-flow` (native vocabulary); `dns.log` → `dns-event` (`query, qtype_name, rcode_name, answers, TTLs`) | `uid` |
| DNS RFCs | RFC 1035 names/limits; RFC 3597 `TYPEnnn`; RFC 6895 RCODE mnemonics; RFC 8914 EDE (Shield emits 15) | — |
| OCSF | `siem.rs` emits Detection Finding (2004); `detection` maps 1:1 | — |

## 3. Pipeline (implemented)

```
SOURCE DISCOVERY        research passes → registry/sources.json (149) + licenses.json (122)       heqk_data.py check
SOURCE REGISTRY         schema-validated, sorted, cross-checked (source ↔ licence ↔ collection)
DATA ACQUISITION        fetch (https only, size-capped, redirect-checked) | register (manual)    heqk_data.py fetch/register
LICENCE VALIDATION      licensing.decide(licence, purpose) at acquisition AND at build           heqk_data.py gate
RAW STORAGE             content-addressed, chmod 0444, acquisition.json with licence snapshot
NORMALISATION           adapter vX → heqk.security-event/1, schema-validated, rejects kept      heqk_data.py normalize
DEDUPLICATION           record_id (source, record, adapter version); example content_sha256
LABEL VALIDATION        label only from the source; label_source + original_label kept; canaries never positive
TAXONOMY MAPPING        ATT&CK with mapping_source; heuristic maps are marked heuristic
TRAINING GENERATION     builders per collection; deterministic caps; synthetic explicitly marked
QUALITY ASSURANCE       schema on every example; contamination check fails the build; QUALITY.md
EXPORT                  JSONL (canonical) · chat SFT JSONL · IOC.TXT · optional Parquet · manifest  heqk_data.py build
```

**Technology choices:**

| Choice | Decision and reason |
|---|---|
| JSONL | The canonical format: diffable, streamable, and readable by any fine-tuning stack. |
| SQLite (stdlib) | The local metadata index. It can be rebuilt from the files. |
| DuckDB / Arrow / Parquet | Not required. Parquet is emitted only if `pyarrow` is importable. Analytics over JSONL can use DuckDB on the analyst's machine without adding a dependency here. |
| JSON Schema | Enforced by a 230-line validator in `heqkdata/schema.py`. It **fails closed on any unsupported keyword**, so a schema can never claim more than is checked. Pydantic would add a dependency and duplicate the schemas. |
| Rust compatibility | Schemas are plain JSON Schema; `IOC.TXT` is the exact format `ioc.rs` parses. Severity and categories use the heqk catalogue's own vocabulary. |

## 4. Deployment shape this data must support

| Consumer | Tier | Fed by | Format |
|---|---|---|---|
| `dga.rs` (shipped scorer) | A | DNS collection test split | benchmark (`QUALITY.md` §DGA) |
| IOC pack (`ioc.rs`) | A | `live_intel` build | `IOC.TXT`, operator-signed |
| DNS / flow specialists (int8 trees, char-CNN ≤ 100 KB) | B | collections 01, 02 | `classify` examples → features computed by the trainer |
| Neural DNA evaluation, learned cell (E-N2) | C | collection 02 (scenario-grouped flows) | flows in time order |
| Language tier (explainer, evidence-closed) | D | collections 03, 05 (knowledge/RAG), 06 (explain/triage) | chat SFT JSONL with evidence cards |
| Mesh sharing | E | signed indicator deltas (future) | `indicator` records |

The language model is trained to **explain a verdict it is given** and to cite evidence ids, matching
Phase 0's finding and the explanation-panel order in `09` §4. `classify` examples train the tier B
specialists. They are not for teaching the LM to judge. CM5 first and N100 later only change model
size, never the data contract.
