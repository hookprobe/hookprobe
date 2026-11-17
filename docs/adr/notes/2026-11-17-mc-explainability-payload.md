# Note — Mission Control explainability: payload extensions requested from heqk

**Date:** 2026-11-17 · **Status:** request (no kernel change made) · **Relates to:** ADR 0047 D2 (Mission
Control served by heqk), ADR 0052 (Shield v2), `docs/architecture/MissionControl.md` (AI explanation panel).
**UI side:** `os/mission-control/src/store/explain.ts` (types + fallbacks), `IncidentExplain.tsx`,
`QsecbitBand.tsx`, `ShieldApp.tsx` (Audit panel). Branch `feat/mc-explainability`.

The explainability views bind only to fields heqk serves today. Where a view needs more, the field is typed
**optional** in `explain.ts`, and the view says "not reported" until the device sends it. Nothing below is
required for the UI to work; each one turns a "not reported" line into a real value. The renderers named are in
`os/kernel/kernel/src/`.

## What the views use today (no change needed)

| View | Source | Fields |
|---|---|---|
| Incident: Case card, "Why it was flagged" | `GET /api/incidents/:id` (`mcstate.rs::render_incident`) + `GET /api/detections` (`det_row`) | `explanation.{why, confidence, evidence, model, related_events}`; per detection `rule_id`, `rule_msg` "(DROP\|PASS, class)", `confidence`, `mitre`, `dst_ip`, `dst_port`, `build` |
| Incident: attack path | same | source IP → rule(s) → destinations → strongest class |
| QSECBIT band + window | `GET /api/qsecbit` (`render_qsecbit`) | `{ts, score (risk 0–1), band}`; thresholds from `band()`: risk < 0.300 GREEN, < 0.700 AMBER, else RED |
| QSECBIT shifts | `/api/qsecbit` + `/api/detections` | detections in the 5 min before a shift |
| Shield audit | `GET /api/dns` (`shield.rs::render`) | `counters` per verdict, `lists`, `clients`, `recent[].category/level` |

## Requested additions

### 1. `GET /api/incidents/:id`: three optional objects

```json
"ingress": { "interface": "wlan0", "zone": "IoT" },
"trigger": { "kind": "bpf" | "wasm", "rule_id": 100004, "module_name": "dga-detector",
             "module_hash": "<sha256 hex>", "verdict": "DROP", "reason": "…" },
"evidence_ref": { "record_id": "<log seq>:<index>", "sealed_ts": 1763390702.000, "verified": true }
```

- `ingress`: the interface the incident's first detection arrived on. Today the attack path's first step says
  "The device does not report the interface it came in on yet".
- `trigger`: only needed for Wasm detections; BPF rules are already identified through the related detections.
  A Wasm module should be named by its signed name and its SHA-256, the same digest the signature covers.
- `evidence_ref`: the sealed evidence-log position (`evlog.rs` record seq and index, the same cursor ADR 0066 uses)
  and whether the record unsealed (HQKSEAL1 tag) on this read. The "Sealed evidence" panel shows "not reported by
  this build" until then. The UI never claims a verification the device did not report.

### 2. `GET /api/detections` rows: two optional fields

`"wasm_module": "<name>"`, `"wasm_hash": "<sha256 hex>"`, only on detections raised by a Wasm module. With
these, the trigger list names the module instead of a rule id.

### 3. `GET /api/dns`: per-interface counters

```json
"interfaces": [ { "name": "wlan0", "queries": 1234, "blocked": 56 } ]
```

The Audit panel shows "This device build does not report per-interface counts yet" until then. Per-client
counters (`clients`) are already served and shown.

### 4. Not requested: QSECBIT sub-scores

The band view explains a drop with the detections that preceded it. If heqk later scores components (detection,
posture, exposure), add them as `"components": {…}` on each `/api/qsecbit` row; the UI would show them under the
window. Until then, no component is shown.

## Privacy

None of the additions carries payload bytes or anything beyond what the device already shows on its own Mission
Control. The JSON export ("Export JSON (on device)") is built in the browser from these same responses and saved
as a file; it makes no network request.
