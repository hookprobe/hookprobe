/**
 * investigateLive — Investigate (§5, AEGIS) real-data layer: the incident queue
 * (`GET /api/incidents`), the incident-story drill-down (`GET /api/incidents/:id`, the
 * why/confidence/evidence/model/related_events envelope), the incident timeline
 * (`GET /api/incidents/:id/timeline`), the host process tree
 * (`GET /api/incidents/:id/processes`), the executive-report terminus
 * (`GET /api/reports`, `GET /api/reports/:id`), the "everything clickable" evidence-graph
 * explorer (`GET /api/evidence/graph?node=`, `GET /api/evidence/stats`), and `/api/stream` deltas.
 *
 * HONESTY NOTE (read before extending): the real envelopes are still materially narrower than
 * `investigateMock.ts`'s `Incident` shape. The read-API does NOT (yet) carry:
 *   - alternative hypotheses with confidence splits — AEGIS's deterministic reconciler doesn't
 *     track rejected hypotheses today; `InvestigateApp` renders nothing here rather than invent one.
 *   - a per-incident MITRE ATT&CK tactic list from a dedicated endpoint — derived below by
 *     cross-referencing `explanation.related_events` (real `det:`-prefixed node ids) against a
 *     `/api/detections` fetch, so it's real, best-effort (only covers the currently-loaded
 *     detections window).
 *   - a threat-intel panel (CVE/IOC/YARA/Sigma counts) — no such endpoint exists yet.
 *   - a proposed remediation plan (the "plan as a diff") — the BYO-LLM planner leg is not wired;
 *     `model: null` already says this honestly, `InvestigateApp` extends the same honesty to the
 *     plan panel instead of keeping the mock's fabricated plan text.
 * `attack_path` (the incident-detail subgraph) IS now duplicated by the generic
 * `/api/evidence/graph?node=` explorer below — both are kept: `attack_path` is the incident's own
 * subgraph fetched alongside `incident_detail` (no extra round trip), the explorer is the
 * "click any node id, from anywhere" drill-down the evidence graph is supposed to support.
 * These gaps are flagged to the backend agents in the wiring report, not silently guessed at here.
 */

import { createSignal } from 'solid-js';
import {
  fetchJson, openStream, parseStreamPayload,
  type IncidentRow, type IncidentsResponse, type IncidentDetail, type DetectionRow, type DetectionsResponse,
  type IncidentTimelineResponse, type IncidentTimelineEvent,
  type ProcessTreeResponse, type ProcessTreeNode,
  type ReportRow, type ReportsResponse, type ReportDetail,
  type EvidenceGraphResponse, type EvidenceStatsResponse,
} from './api';

export type LiveStatus = 'loading' | 'live' | 'error';

// ── incident queue ───────────────────────────────────────────────────────────

export const [incidents, setIncidents] = createSignal<IncidentRow[]>([]);
export const [queueStatus, setQueueStatus] = createSignal<LiveStatus>('loading');
export const [queueError, setQueueError] = createSignal<string | null>(null);

async function refetchQueue(): Promise<void> {
  try {
    const res = await fetchJson<IncidentsResponse>('/api/incidents?limit=100');
    setIncidents(res.incidents ?? []);
    setQueueStatus('live');
    setQueueError(null);
  } catch (e) {
    setQueueStatus('error');
    setQueueError(e instanceof Error ? e.message : String(e));
  }
}

let started = false;

/** Call once from `InvestigateApp`'s `onMount`. Idempotent. */
export function startInvestigateLive(): void {
  if (started) return;
  started = true;

  void refetchQueue();
  void refetchReports();
  void fetchEvidenceStats();

  try {
    const es = openStream();
    es.addEventListener('update', (ev) => {
      const message = ev as MessageEvent<string>;
      const payload = parseStreamPayload(message.data);
      if (payload?.incidents && payload.incidents.length > 0) {
        void refetchQueue();
      }
    });
    es.onerror = () => {
      /* EventSource auto-reconnects */
    };
  } catch (e) {
    console.debug('[hookprobe] Investigate SSE stream failed to open:', e);
  }
}

// ── incident detail (selected incident's story/evidence/why-AEGIS) ─────────

export const [detail, setDetail] = createSignal<IncidentDetail | null>(null);
export const [detailStatus, setDetailStatus] = createSignal<LiveStatus>('loading');
export const [detailError, setDetailError] = createSignal<string | null>(null);

export async function fetchIncidentDetail(id: string): Promise<void> {
  setDetailStatus('loading');
  try {
    const d = await fetchJson<IncidentDetail>(`/api/incidents/${encodeURIComponent(id)}`);
    setDetail(d);
    setDetailStatus('live');
    setDetailError(null);
  } catch (e) {
    setDetail(null);
    setDetailStatus('error');
    setDetailError(e instanceof Error ? e.message : String(e));
  }
}

// ── best-effort MITRE cross-reference for the selected incident ─────────────
//
// `related_events` gives real `det:`-prefixed node ids but not their `mitre` field; cross-reference
// against one `/api/detections` fetch. Best-effort: an incident whose detections have aged out of
// this window simply shows no MITRE row rather than a guessed one.

const [detectionsById, setDetectionsById] = createSignal<Map<string, DetectionRow>>(new Map());
let detectionsFetched = false;

async function ensureDetectionsLoaded(): Promise<void> {
  if (detectionsFetched) return;
  detectionsFetched = true;
  try {
    const res = await fetchJson<DetectionsResponse>('/api/detections?limit=500');
    setDetectionsById(new Map((res.detections ?? []).map((d) => [d.id, d])));
  } catch (e) {
    // Non-fatal — the MITRE row just stays empty for this session; the next full reload retries.
    console.debug('[hookprobe] MITRE cross-reference fetch failed:', e);
  }
}

export interface RelatedMitre {
  id: string;
  detectionId: string;
}

/** Loads (once, lazily) the detections cache and returns the MITRE ids for `relatedEventIds`. */
export async function mitreForRelatedEvents(relatedEventIds: string[]): Promise<RelatedMitre[]> {
  await ensureDetectionsLoaded();
  const byId = detectionsById();
  const out: RelatedMitre[] = [];
  const seen = new Set<string>();
  for (const evId of relatedEventIds) {
    const d = byId.get(evId);
    if (d?.mitre && !seen.has(d.mitre)) {
      seen.add(d.mitre);
      out.push({ id: d.mitre, detectionId: evId });
    }
  }
  return out;
}

// ── incident timeline (the real ts-ordered narrative) ────────────────────────

export const [timelineEvents, setTimelineEvents] = createSignal<IncidentTimelineEvent[]>([]);
export const [timelineStatus, setTimelineStatus] = createSignal<LiveStatus>('loading');
export const [timelineError, setTimelineError] = createSignal<string | null>(null);

/** `GET /api/incidents/:id/timeline` — call whenever the selected incident changes. */
export async function fetchIncidentTimeline(id: string): Promise<void> {
  setTimelineStatus('loading');
  try {
    const r = await fetchJson<IncidentTimelineResponse>(`/api/incidents/${encodeURIComponent(id)}/timeline`);
    setTimelineEvents(r.events ?? []);
    setTimelineStatus('live');
    setTimelineError(null);
  } catch (e) {
    setTimelineEvents([]);
    setTimelineStatus('error');
    setTimelineError(e instanceof Error ? e.message : String(e));
  }
}

// ── incident process tree (host-layer, walks spawned_by edges) ──────────────

export const [processRoots, setProcessRoots] = createSignal<ProcessTreeNode[]>([]);
export const [processCount, setProcessCount] = createSignal<number>(0);
export const [processStatus, setProcessStatus] = createSignal<LiveStatus>('loading');
export const [processError, setProcessError] = createSignal<string | null>(null);

/** `GET /api/incidents/:id/processes` — call whenever the selected incident changes. */
export async function fetchIncidentProcessTree(id: string): Promise<void> {
  setProcessStatus('loading');
  try {
    const r = await fetchJson<ProcessTreeResponse>(`/api/incidents/${encodeURIComponent(id)}/processes`);
    setProcessRoots(r.roots ?? []);
    setProcessCount(r.process_count ?? 0);
    setProcessStatus('live');
    setProcessError(null);
  } catch (e) {
    setProcessRoots([]);
    setProcessCount(0);
    setProcessStatus('error');
    setProcessError(e instanceof Error ? e.message : String(e));
  }
}

// ── reports (the evidence-chain terminus: incident -> report -> back to raw evidence) ───────

export const [reports, setReports] = createSignal<ReportRow[]>([]);
export const [reportsStatus, setReportsStatus] = createSignal<LiveStatus>('loading');
export const [reportsError, setReportsError] = createSignal<string | null>(null);

/** `GET /api/reports` — the full report list (all incidents), newest-generated first. */
export async function refetchReports(): Promise<void> {
  try {
    const r = await fetchJson<ReportsResponse>('/api/reports?limit=200');
    setReports(r.reports ?? []);
    setReportsStatus('live');
    setReportsError(null);
  } catch (e) {
    setReportsStatus('error');
    setReportsError(e instanceof Error ? e.message : String(e));
  }
}

export const [reportDetail, setReportDetail] = createSignal<ReportDetail | null>(null);
export const [reportDetailStatus, setReportDetailStatus] = createSignal<LiveStatus>('loading');
export const [reportDetailError, setReportDetailError] = createSignal<string | null>(null);

/** `GET /api/reports/:id` — the full drill-back-to-raw-evidence document. */
export async function fetchReportDetail(id: string): Promise<void> {
  setReportDetailStatus('loading');
  try {
    const d = await fetchJson<ReportDetail>(`/api/reports/${encodeURIComponent(id)}`);
    setReportDetail(d);
    setReportDetailStatus('live');
    setReportDetailError(null);
  } catch (e) {
    setReportDetail(null);
    setReportDetailStatus('error');
    setReportDetailError(e instanceof Error ? e.message : String(e));
  }
}

/**
 * Refreshes the report list, then loads the report generated FOR `incidentId` if one exists —
 * call whenever the selected incident changes. No report yet for this incident is an honest
 * `reportDetailStatus === 'live'` + `reportDetail() === null` (an empty state, not an error and
 * not a stuck spinner): report generation is a separate, not-yet-automatic-on-every-incident
 * backend step (see `EvidenceGraph::generate_report`'s doc comment), so "none generated yet" is
 * the common, non-error case.
 */
export async function syncReportForIncident(incidentId: string): Promise<void> {
  await refetchReports();
  const match = reports().find((r) => r.incident_id === incidentId);
  if (match) {
    await fetchReportDetail(match.id);
  } else {
    setReportDetail(null);
    setReportDetailError(null);
    setReportDetailStatus('live');
  }
}

// ── evidence graph explorer ("everything clickable": drill into ANY node id) ────────────────

export const [graphNodeQuery, setGraphNodeQuery] = createSignal<string>('');
export const [graphResult, setGraphResult] = createSignal<EvidenceGraphResponse | null>(null);
export const [graphStatus, setGraphStatus] = createSignal<LiveStatus>('loading');
export const [graphError, setGraphError] = createSignal<string | null>(null);

/**
 * `GET /api/evidence/graph?node=<id>` — drills into the subgraph reachable from ANY node id
 * (an incident, a device, a flow, a process, …), not only incidents. Call this from any "clickable"
 * node id in the UI (a `nodes` entry from a previous graph fetch, an `attack_path` node, a
 * process-tree pid's node id, a report's `evidence_node_ids`) to keep drilling.
 */
export async function exploreEvidenceNode(nodeId: string): Promise<void> {
  const id = nodeId.trim();
  if (!id) return;
  setGraphNodeQuery(id);
  setGraphStatus('loading');
  try {
    const g = await fetchJson<EvidenceGraphResponse>(`/api/evidence/graph?node=${encodeURIComponent(id)}`);
    setGraphResult(g);
    setGraphStatus('live');
    setGraphError(null);
  } catch (e) {
    setGraphResult(null);
    setGraphStatus('error');
    setGraphError(e instanceof Error ? e.message : String(e));
  }
}

// ── evidence stats (retention/size visibility — the graph_stats surface) ────────────────────

export const [evidenceStats, setEvidenceStats] = createSignal<EvidenceStatsResponse | null>(null);
export const [evidenceStatsStatus, setEvidenceStatsStatus] = createSignal<LiveStatus>('loading');
export const [evidenceStatsError, setEvidenceStatsError] = createSignal<string | null>(null);

/** `GET /api/evidence/stats` — per-table node/edge counts + retention/prune state. */
export async function fetchEvidenceStats(): Promise<void> {
  try {
    const s = await fetchJson<EvidenceStatsResponse>('/api/evidence/stats');
    setEvidenceStats(s);
    setEvidenceStatsStatus('live');
    setEvidenceStatsError(null);
  } catch (e) {
    setEvidenceStatsStatus('error');
    setEvidenceStatsError(e instanceof Error ? e.message : String(e));
  }
}
