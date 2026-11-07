/**
 * detectLive — Detect (§4, NAPSE) real-data layer: `GET /api/detections` + `/api/stream` deltas.
 *
 * Mirrors `store/live.ts`'s fetch-and-subscribe pattern, but — unlike the Layer-0 orb, which keeps
 * `store/mock.ts`'s defaults as a silent fallback — this module is honest about its OWN loading/
 * live/error/empty status via `detectStatus()`, because `DetectApp` must render a real "loading" or
 * "API unreachable" state rather than quietly showing the old static demo feed as if it were live
 * (see the build brief: "do NOT fall back to mock data silently").
 *
 * `ENGINES` (docs/architecture/MissionControl.md §4's per-engine hit counts) is now PARTLY real (ADR 0026):
 * `GET /api/engines` reports REAL loaded-rule counts / last-run data for Sigma + YARA (their own
 * status files), honestly labelled `source: "mock"` for Suricata/AI Detection/Behavioral (no
 * backing engine exists yet) — see `engines()`/`enginesStatus()` below. `COVERAGE` (the ATT&CK
 * rule-coverage bars) still has no backing total-rule-catalog denominator, so `DetectApp` keeps
 * rendering `detectMock.ts`'s static values for THAT one panel only, clearly labelled "mock".
 * `TOP_TECHNIQUES` below IS derived from real detections (technique ids the API actually
 * returned, named via `api.ts`'s public MITRE taxonomy table) once live data has loaded.
 */

import { createSignal } from 'solid-js';
import {
  fetchJson, openStream, parseStreamPayload, severityLabel, formatTime, mitreName, mitreTactic,
  type DetectionRow, type DetectionsResponse,
} from './api';

export type LiveStatus = 'loading' | 'live' | 'error';

export const [detections, setDetections] = createSignal<DetectionRow[]>([]);
export const [detectStatus, setDetectStatus] = createSignal<LiveStatus>('loading');
export const [detectError, setDetectError] = createSignal<string | null>(null);

/** One `GET /api/engines` row — see `crates/hookprobe-api/src/engine_status.rs`'s doc for the
 * exact shape. `source` is the honesty flag: `"real"` (Sigma/YARA, from their own status files)
 * vs `"mock"` (Suricata/AI Detection/Behavioral — no backing engine exists in this workspace). */
export interface EngineRow {
  name: string;
  kind: string | null;
  source: 'real' | 'mock';
  status: 'active' | 'not_yet_run' | 'unknown';
  loaded_rules: number | null;
  skipped_rules: number | null;
  hits: number | null;
  last_run_ts: number | null;
}

interface EnginesResponse {
  engines: EngineRow[];
}

export const [engines, setEngines] = createSignal<EngineRow[]>([]);
export const [enginesStatus, setEnginesStatus] = createSignal<LiveStatus>('loading');

const LIMIT = 200;

async function refetch(): Promise<void> {
  try {
    const res = await fetchJson<DetectionsResponse>(`/api/detections?limit=${LIMIT}`);
    setDetections(res.detections ?? []);
    setDetectStatus('live');
    setDetectError(null);
  } catch (e) {
    setDetectStatus('error');
    setDetectError(e instanceof Error ? e.message : String(e));
  }
}

async function refetchEngines(): Promise<void> {
  try {
    const res = await fetchJson<EnginesResponse>('/api/engines');
    setEngines(res.engines ?? []);
    setEnginesStatus('live');
  } catch (e) {
    setEnginesStatus('error');
    console.debug('[hookprobe] /api/engines fetch failed:', e);
  }
}

let started = false;

/** Call once from `DetectApp`'s `onMount`. Idempotent — a second call is a no-op. */
export function startDetectLive(): void {
  if (started) return;
  started = true;

  void refetch();
  void refetchEngines();

  try {
    const es = openStream();
    es.addEventListener('update', (ev) => {
      const message = ev as MessageEvent<string>;
      const payload = parseStreamPayload(message.data);
      // The streamed detection row is narrower than `DetectionRow` (no rule_id/mitre/dst_port) —
      // re-fetch the authoritative list rather than trust the partial row (same pattern
      // `store/live.ts`'s `applyIncidents` uses).
      if (payload?.detections && payload.detections.length > 0) {
        void refetch();
        void refetchEngines(); // a new detection likely bumped an engine's own hit count too
      }
    });
    es.onerror = () => {
      /* EventSource auto-reconnects; nothing to do here except not throw on every retry */
    };
  } catch (e) {
    console.debug('[hookprobe] Detect SSE stream failed to open:', e);
  }
}

// ── real-data derivations (KPIs + top techniques) ───────────────────────────
//
// Computed purely from whatever `detections()` currently holds — never a fabricated number. A
// severity/technique count over the currently-loaded page (bounded by `LIMIT`) is honestly labelled
// "loaded", not "24h", because the read-API has no time-windowed aggregate endpoint yet.

export interface DetectKpi {
  label: string;
  value: string;
  tone: 'red' | 'amber' | 'blue' | 'purple' | 'grey';
}

export function computeKpis(rows: DetectionRow[]): DetectKpi[] {
  const bySeverity = { critical: 0, high: 0, medium: 0, low: 0 };
  const techniques = new Set<string>();
  for (const r of rows) {
    bySeverity[severityLabel(r.severity)] += 1;
    if (r.mitre) techniques.add(r.mitre);
  }
  return [
    { label: 'Detections (loaded)', value: String(rows.length), tone: 'blue' },
    { label: 'Critical',            value: String(bySeverity.critical), tone: 'red' },
    { label: 'High',                value: String(bySeverity.high),     tone: 'amber' },
    { label: 'Medium + Low',        value: String(bySeverity.medium + bySeverity.low), tone: 'grey' },
    { label: 'Techniques observed', value: String(techniques.size), tone: 'purple' },
  ];
}

export interface DetectTechnique {
  id: string;
  name: string;
  tactic: string;
  count: number;
}

export function computeTopTechniques(rows: DetectionRow[], top = 5): DetectTechnique[] {
  const counts = new Map<string, number>();
  for (const r of rows) {
    if (!r.mitre) continue;
    counts.set(r.mitre, (counts.get(r.mitre) ?? 0) + 1);
  }
  return [...counts.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, top)
    .map(([id, count]) => ({ id, name: mitreName(id), tactic: mitreTactic(id), count }));
}

export { severityLabel, formatTime };
