# tools/intel-data — HEQK Security Intelligence data foundation

This tool builds the training and evaluation data that HookProbe's intelligence tiers learn from. Every
record can be traced to its source and has a recorded licence decision. Design and rationale are in
[`docs/research/intel-data/`](../../docs/research/intel-data/).

Conventions:
- Python standard library only; run with `python3 -I`.
- Nothing here trains a model, touches a device, or executes downloaded content.
- **Real data never enters the repository.** It lives in `$HEQK_INTEL_DATA`
  (default `~/.cache/hookprobe-intel-data`), and the store refuses a data root inside the repo.

```bash
cd tools/intel-data
python3 -I heqk_data.py check                                        # registry + schemas consistent?
python3 -I heqk_data.py sources --class OPEN                         # what is usable
python3 -I heqk_data.py gate abusech-urlhaus commercial_training      # DENY + the reason
python3 -I heqk_data.py fetch cisa-kev --purpose commercial_training  # licence-gated download
python3 -I heqk_data.py register iot-23 ~/data/IoT-23/CTU-IoT-Malware-Capture-1-1/bro/conn.log.labeled --purpose commercial_training
python3 -I heqk_data.py register iot-23 ~/data/IoT-23/CTU-IoT-Malware-Capture-39-1/bro/conn.log.labeled \
    --purpose commercial_training --sample-per-label 20000          # multi-GB capture: per-label reservoir, original hash kept
python3 -I heqk_data.py normalize                                    # raw -> heqk.security-event/1
python3 -I heqk_data.py build --purpose commercial_training --cap 50000
python3 -I heqk_data.py dga xjw3kq9vzt2lmpr8.com                     # heqk dga.rs, bit-exact
python3 -I heqk_data.py dga-eval                                     # dga.rs FP/recall sweep on the store
python3 -I heqk_data.py catalog --out ../../docs/research/intel-data/CATALOGUE.md
python3 -I -m unittest discover -s tests -t tests                     # 61 tests, fixtures only
```

Purposes are `commercial_training`, `evaluation`, `research` and `live_intel`. Each source is checked
against the right one at acquisition and again at build. A build reads only the latest acquisition of each
file of a source (a re-fetched feed snapshot supersedes the older one), and each collection only the
sources that declare it (in `collections.json` or the source's own `collections` field).

| Path | What |
|---|---|
| `registry/sources.json` | 149 catalogued sources: datasets, feeds, knowledge bases, CERTs, programmes |
| `registry/licenses.json` | 118 licence decisions (`commercial_use`, `training_use`, `redistribution`, `derivatives`, share-alike) |
| `registry/collections.json` | the six training collections (DNS, network, attack, malware, vulnerability, SOC reasoning) |
| `schemas/` | versioned JSON Schemas: `security-event`, `dns-event`, `network-flow`, `indicator`, `vulnerability`, `attack-technique`, `training-example`, `source`, `license`, `collection`, `manifest`, `common` |
| `heqkdata/schema.py` | strict JSON Schema subset validator (fails closed on unknown keywords) |
| `heqkdata/canon.py` | canonical timestamps, IPs, domains, JSON; keyed pseudonyms |
| `heqkdata/licensing.py` | the licence gate |
| `heqkdata/safeio.py` | safe parsing of untrusted files (zip-slip, bombs, executables refused) |
| `heqkdata/store.py` | immutable raw store, normalised records, audit log, SQLite index |
| `heqkdata/adapters/` | MITRE ATT&CK STIX, CISA KEV, URLhaus CSV, Feodo JSON, Tranco, Zeek conn (IoT-23/CTU), CICFlowMeter CSV, hookprobe-ioc-v1, labelled domain lists (UMUDGA), PhiUSIIL |
| `heqkdata/builders.py` | records → training examples per collection; synthetic SOC templates |
| `heqkdata/splits.py` | group / time / source-holdout splits, contamination check, dedup |
| `heqkdata/quality.py` | quality report + tier-A baseline of `dga.rs` on the DNS test split |
| `heqkdata/export.py` | versioned build: JSONL, chat SFT JSONL, `IOC.TXT` (unsigned), optional Parquet, manifest |
| `heqkdata/dga_ref.py` | bit-exact port of `os/kernel/kernel/src/dga.rs` (checked against compiled Rust on 20,009 names) |
| `samples/` | example records and exports produced from the test fixtures (reserved IP and domain values only) |

**Adding a source:**
1. Add its licence decision to `licenses.json`, citing the text you read.
2. Add the source to `sources.json`.
3. Add an adapter if no existing one fits, plus a fixture made from reserved values.
4. Run `check` and the tests.

Changing a licence decision is a reviewed commit.
