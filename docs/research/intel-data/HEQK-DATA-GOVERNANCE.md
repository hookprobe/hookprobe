# HEQK intelligence data — governance, privacy and security

> Status: 2026-11-18, first version. These rules are implemented in `tools/intel-data` where marked
> **[enforced]**. The others are procedure for the operator. Not legal advice: the licence and GDPR
> positions below need review by counsel before any model is shipped.

## 1. Licences: public is not permission

1. **Every source has a licence decision in `registry/licenses.json`.** Each decision has
   `commercial_use`, `training_use`, `redistribution` and `derivatives` (`yes | no | unclear |
   requires_agreement`), plus share-alike and attribution flags. **[enforced]** The registry check
   rejects a source whose permissions disagree with its licence entry.
2. **The gate is the only path in.** `licensing.decide(licence, purpose)` runs at acquisition (`fetch`,
   `register`) and again for every record at build time. **[enforced]**

   | Purpose | Allowed when |
   |---|---|
   | `commercial_training` | class not UNKNOWN/RESTRICTED, `commercial_use = yes`, `training_use = yes`, not share-alike |
   | `evaluation` | class not UNKNOWN/RESTRICTED; commercial use yes **or unclear** (see rule 3); training and derivatives not both forbidden (internal benchmarking of a commercial model is commercial use) |
   | `research` | class not UNKNOWN/RESTRICTED, training not forbidden. Output never enters a shipped model |
   | `live_intel` | commercial use and redistribution yes (shipping indicators on devices) |

3. **`unclear` means no.** A source becomes usable by changing its registry entry in a reviewed commit
   that cites the licence text or the signed agreement. The registry is the record of the decision.
   **One exception (operator decision, 2026-11-22):** `evaluation` accepts a verified licence (class
   OPEN, RESEARCH or COMMERCIAL) whose `commercial_use` is `unclear`. The operator accepts that
   licence risk for internal benchmarks only. Such a build lists the sources in its manifest
   (`licence_caveats`; `licence_caveat` on a windows export) and must never train or ship a model.
   UNKNOWN, RESTRICTED, `no` and `requires_agreement` stay denied. **[enforced]**
4. **Share-alike** (CC BY-SA, e.g. Tranco's CrUX component): whether model weights are "Adapted
   Material" is unresolved. Such sources are blocked from `commercial_training` until counsel decides.
   **[enforced]**
5. **Contractual AI clauses override open-looking licences.** abuse.ch states Feodo Tracker, SSLBL and
   YARAify are CC0. Its Platforms Terms §7.3 still forbids AI training on any abuse.ch data without
   Spamhaus' written consent. The registry records this as `abusech-cc0-ai-clause`: live intel yes,
   training requires agreement.
6. **Attribution duties travel with the data.** Each `dataset_version` manifest lists its licences.
   Model cards must reproduce the required notices (MITRE, CC BY). Alerts produced by DRL-1.1 rules
   (Sigma, signature-base) must keep the rule author in Mission Control.
7. **Licence terms change.** Every source records `verified_on`, and the raw store snapshots the
   licence entry into each `acquisition.json`. Re-verify sources before each training run older than
   90 days. abuse.ch changed its terms in 2025–2026.

## 2. Provenance, integrity and reproducibility

| Control | Implementation |
|---|---|
| Immutable raw records **[enforced]** | content-addressed path `raw/<source>/<sha256>/`, files `chmod 0444`, re-registering identical bytes is a no-op |
| Licence at acquisition time **[enforced]** | `acquisition.json` holds a copy of the licence entry, the URL, the time and the tool version |
| Traceability **[enforced]** | every record: `source_id, source_record_id, acquisition_id (file sha256), raw_sha256 (row sha256), license_id, transform{name,version}`; every example: builder version, source and licence ids |
| Versioning **[enforced]** | adapter and builder versions are in `record_id` / provenance. `dataset_version` = date + hash(inputs, tool version, purpose, options) |
| Checksums **[enforced]** | `manifest.json` lists the sha256 of every output file |
| Reproducibility **[enforced, tested]** | same acquisitions + same tool version ⇒ byte-identical outputs (`test_reproducible`); timestamps come from acquisitions, never the wall clock |
| Audit log **[enforced]** | `audit.jsonl`: every acquisition, normalisation and build, append-only, local only (contains the OS user name; never exported) |
| Signing | the tooling emits **unsigned** artefacts. `IOC.TXT` is signed with the operator key like any IOC pack; datasets that feed a shipped model are recorded in the model's HNX package metadata (`docs/research/neuro/06`) |

## 3. Personal data and customer telemetry

1. **No customer traffic and no private HookProbe telemetry** enters a training dataset without both:
   - the data owner's explicit permission;
   - a documented legal basis.

   Under GDPR art. 6, consent or legitimate interest needs a recorded balancing test. Device telemetry
   includes IP addresses, DNS names a person looked up, and device identifiers, all of which are
   personal data (CJEU *Breyer*, C-582/14). There is **no adapter for heqk device telemetry** in this
   version on purpose. When one is added it must:
   - check a per-device consent flag in the export frame;
   - pseudonymise client identity at ingestion (below);
   - drop DNS names a single client looked up, unless they also appear in a public source (k-anonymity on names);
   - keep data in the EU.
2. **Pseudonymisation [enforced where clients appear].** Client identities become
   `HMAC-SHA256(key, value)` truncated to 64 bits (`c:<16 hex>`).
   - The key lives in `<data root>/pseudonym.key` (0600). It is never exported or committed.
   - Deleting it makes future pseudonyms unlinkable to past ones (a crypto-shredding lever).
   - This is pseudonymisation (art. 4(5)), not anonymisation. The output is still personal data and
     stays under these rules.
3. **Public datasets with real IPs** (CTU-13, IoT-23, CIC-IDS): the IPs belong to lab hosts or are
   documented as captures. They are kept for flow semantics but are never exported in `live_intel`
   packs. Dataset IPs are not threat intelligence.
4. **Feed fields naming people are dropped.** The URLhaus adapter drops `reporter` **[enforced]**, and a
   future MISP adapter must drop the creator org and user.
   URLs can carry victim e-mails or tokens in query strings, so the DNS builder uses only the host.
5. **Retention.**
   - Raw acquisitions are kept while any `dataset_version` that cites them is retained, then deleted.
   - Live-intel feeds older than 180 days are deleted unless a build cites them.
   - Personal data from consented telemetry is held for at most 12 months unless consent says
     otherwise.
   - Data root: `$HEQK_INTEL_DATA`. It is never inside the repository **[enforced]**.

## 4. Data sensitivity classes

| Class | Examples | Handling |
|---|---|---|
| low | taxonomies (ATT&CK, CWE), KEV, synthetic | normal |
| medium | flow datasets with lab IPs, feed indicators, popularity lists | data root on an encrypted volume (FileVault) |
| high | malware samples, passive DNS, anything with payloads or customer data | **never fetched automatically [enforced: registry rejects `acquisition` on high-sensitivity sources]**; needs an approved isolated environment |

## 5. Safe handling of untrusted files [enforced]

- Downloads: HTTPS only, final URL re-checked after redirects, streamed with the source's `max_bytes`
  cap, written to a temp file and moved into place only when complete.
- Archives (`safeio.extract_zip`):
  - extracted member by member into an empty directory;
  - refused: absolute paths, `..`, links and devices, encrypted members (the sample-set convention),
    executable or script extensions;
  - caps: member size, total size, member count, compression ratio > 200 (zip bombs);
  - a member that inflates beyond its declared size.
- Parsers are `json` (with `NaN`/`Infinity` refused), `csv` (field cap) and line readers (1 MiB line
  cap). Nothing is `eval`ed, unpickled, imported or executed. Run every tool with `python3 -I` so the
  data directory can never shadow a module.
- **Malware quarantine:** this pipeline handles **no samples**, only metadata and reports. Sample
  analysis needs a separately approved, network-isolated environment. It is outside this repository and
  outside the development Mac.
- **Credentials:**
  - API keys (abuse.ch Auth-Key, NVD key) come from environment variables when an adapter needs them;
  - they are never written to the registry, manifests or audit log;
  - the repo's `.gitleaks.toml` and secrets-scan workflow still apply.

## 6. Synthetic data

Synthetic examples are allowed only if all of the following hold:
1. `ground_truth.type = "synthetic"`, `verified = false`, `sensor.type = "synthetic"`;
2. any generated reasoning text starts with `SYNTHETIC:`;
3. values come only from documentation ranges (RFC 5737, RFC 3849, RFC 2606) or RFC 1918.

They are never presented as telemetry and are never used as evaluation evidence for a real-world
claim. **[enforced by schema + tests]**

## 7. Evaluation hygiene

- The 215 blind cases in `tools/neuro-research/eval/blind/` are **never ingested** by this tooling. They
  stay an independent judge.
- Splits are group-keyed. A build with any content, group or record in two splits reports contamination
  and the CLI exits non-zero **[enforced]**.
- Time-based and source-holdout splits are available for distribution-shift evaluation.
