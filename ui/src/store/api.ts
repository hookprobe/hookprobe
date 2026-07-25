/**
 * api — the shared, low-level `hookprobe-api` read-API client (ADR 0001: Rust/Axum).
 *
 * One `fetchJson`/`API_BASE`/response-type home for every store module that talks to the real
 * evidence-graph read-API (`crates/hookprobe-api`), instead of each workspace's live-data module
 * re-declaring its own copy (the shapes below are transcribed 1:1 from `crates/hookprobe-api/src/
 * lib.rs` + `crates/hookprobe-evidence/src/lib.rs`'s query methods — keep them in sync if those
 * change). `store/live.ts` (Layer-0) predates this file and still carries its own copies of the
 * `qsecbit`/`incidents` shapes it uses; new workspace live-data modules (`detectLive.ts`,
 * `investigateLive.ts`, `obsLive.ts`) should import from here instead of re-declaring.
 *
 * Read-only by construction on the client side too: nothing in this module ever issues a
 * non-GET request — `hookprobe-api` itself has no write routes (see its module doc comment).
 */

// ── transport ────────────────────────────────────────────────────────────────

/**
 * Base URL for the read-API. Same-origin (`''`) in production once the UI's static assets are
 * served from the same origin as `hookprobe-api` (or a reverse proxy fronts both) — override at
 * build time with `PUBLIC_API_BASE` (see `ui/.env.example`). Defaults to the API's own documented
 * default listen address for local dev, where the Astro dev server (`:4321`) and the API (`:8420`)
 * are different origins; the API's permissive CORS layer exists precisely for this case.
 */
export const API_BASE = (import.meta.env.PUBLIC_API_BASE as string | undefined) ?? 'http://127.0.0.1:8420';

export async function fetchJson<T>(path: string): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, { headers: { accept: 'application/json' } });
  if (!res.ok) {
    throw new Error(`${path} -> HTTP ${res.status}`);
  }
  return res.json() as Promise<T>;
}

/** Opens the one shared `/api/stream` SSE connection (detections/incidents/qsecbit deltas). */
export function openStream(): EventSource {
  return new EventSource(`${API_BASE}/api/stream`);
}

// ── response shapes (mirror crates/hookprobe-api + hookprobe-evidence exactly) ──────────────────

/** `EvidenceGraph::recent_detections` / `detections_by_categories` row shape. */
export interface DetectionRow {
  id: string;
  ts: number;
  rule_id: number;
  rule_msg: string;
  category: string;
  /** 1=CRITICAL, 2=HIGH, 3=MEDIUM, 4=LOW, 5=INFO — see `modules/napse/src/lib.rs`'s `SEV_*` consts. */
  severity: number;
  mitre: string;
  src_ip: string;
  dst_ip: string;
  dst_port: number;
  confidence: number;
}
export interface DetectionsResponse {
  count: number;
  detections: DetectionRow[];
}

/** `EvidenceGraph::list_incidents` row shape (the Investigate queue). */
export interface IncidentRow {
  id: string;
  ts: number;
  title: string;
  device_ip: string;
  priority: string;
  status: string;
  threat_score: number;
}
export interface IncidentsResponse {
  count: number;
  incidents: IncidentRow[];
}

/** `EvidenceGraph::attack_path` node/edge shapes — the Threat Graph subgraph. */
export interface AttackPathNode {
  id: string;
  type: string;
  label: string;
}
export interface AttackPathEdge {
  src: string;
  type: string;
  dst: string;
}
export interface AttackPath {
  incident: string;
  node_count: number;
  edge_count: number;
  nodes: AttackPathNode[];
  edges: AttackPathEdge[];
}

/**
 * `GET /api/incidents/:id`'s AI-explanation envelope — MissionControl.md's differentiator
 * ("why · confidence · evidence · model · related events"). `model` is `null` when no BYO-LLM
 * planner has run over this incident (AEGIS's deterministic reconciler produced the correlation
 * alone) — render that honestly ("no AI planner run"), never fabricate a model name.
 */
export interface IncidentExplanation {
  why: string;
  confidence: number;
  evidence: number;
  model: string | null;
  related_events: string[];
}
export interface IncidentDetail {
  id: string;
  ts: number;
  title: string;
  device_ip: string;
  priority: string;
  status: string;
  threat_score: number;
  explanation: IncidentExplanation;
  attack_path: AttackPath;
}

/** `EvidenceGraph::list_flows` row shape (Observe workspace). */
export interface FlowRow {
  id: string;
  ts: number;
  src_ip: string;
  src_port: number;
  dst_ip: string;
  dst_port: number;
  proto: string;
  conn_state: string;
  orig_bytes: number;
  resp_bytes: number;
}
export interface FlowsResponse {
  count: number;
  flows: FlowRow[];
}

/** `EvidenceGraph::list_devices` row shape (Observe/Network asset inventory). */
export interface DeviceRow {
  id: string;
  ip: string;
  mac: string | null;
  first_seen: number;
  last_seen: number;
}
export interface DevicesResponse {
  count: number;
  devices: DeviceRow[];
}

/** `GET /api/qsecbit` shape (used by `store/live.ts`; re-exported here for reuse). */
export interface QsecbitScoreRow {
  ts: number;
  score: number;
  band: string;
}
export interface QsecbitResponse {
  latest: QsecbitScoreRow | null;
  history: QsecbitScoreRow[];
  count: number;
}

/** `EvidenceGraph::incident_timeline` event shape (`GET /api/incidents/:id/timeline`). */
export interface IncidentTimelineEvent {
  id: string;
  ts: number;
  /** `'detection' | 'flow' | 'response' | 'process' | 'file' | 'registry' | 'incident'`. */
  kind: string;
  label: string;
}
export interface IncidentTimelineResponse {
  incident: string;
  found: boolean;
  count: number;
  events: IncidentTimelineEvent[];
}

/**
 * `EvidenceGraph::incident_process_tree` node shape (`GET /api/incidents/:id/processes`) — a real
 * tree (walks `spawned_by` edges), not a flat list; `children` recurses.
 */
export interface ProcessTreeNode {
  id: string;
  ts: number;
  device_ip: string;
  pid: number;
  name: string;
  cmdline: string;
  children: ProcessTreeNode[];
}
export interface ProcessTreeResponse {
  incident: string;
  found: boolean;
  process_count: number;
  roots: ProcessTreeNode[];
}

/** `EvidenceGraph::list_reports` row shape (`GET /api/reports`). */
export interface ReportRow {
  id: string;
  ts: number;
  incident_id: string;
  title: string;
  summary: string;
}
export interface ReportsResponse {
  count: number;
  reports: ReportRow[];
}

/** A response action cited inside a generated report's `response_taken` array. */
export interface ReportResponseTaken {
  id: string;
  ts: number;
  action: string;
  target: string;
  mechanism: string;
  detail: string;
  status: string;
}

/**
 * `EvidenceGraph::generate_report`'s structured body — the `report` field of
 * `GET /api/reports/:id`. `timeline`/`process_tree` here are the SAME shapes as
 * `IncidentTimelineEvent[]`/`ProcessTreeNode[]` above, frozen at generation time (a report is a
 * point-in-time snapshot, not a live view — it will not reflect evidence added after generation).
 */
export interface ReportBody {
  incident_id: string;
  title: string;
  device_ip: string;
  priority: string;
  status: string;
  confidence: number;
  mitre_techniques: string[];
  timeline: IncidentTimelineEvent[];
  process_tree: ProcessTreeNode[];
  response_taken: ReportResponseTaken[];
  /** Evidence-graph node ids this report cites (drill-back target for `/api/evidence/graph?node=`). */
  evidence_node_ids: string[];
  generated_ts: number;
}
/** `GET /api/reports/:id` — the full drill-back-to-raw-evidence document. */
export interface ReportDetail {
  id: string;
  ts: number;
  incident_id: string;
  title: string;
  summary: string;
  report: ReportBody;
}

/**
 * `GET /api/evidence/graph?node=<id>` response shape. The backend still reuses
 * `EvidenceGraph::attack_path` verbatim under the hood for this generic, any-node endpoint, but as
 * of the 2026-07-08 key-rename fix the HTTP handler (`crates/hookprobe-api`) now also carries the
 * queried node id under the canonical `node` field for EVERY node type (device, flow, process, …,
 * not just incidents). `incident` is still present too — same value as `node`, unchanged — kept
 * ONLY as a deprecated back-compat alias; new code should read `node`, not `incident`.
 */
export interface EvidenceGraphResponse {
  node: string;
  /** @deprecated back-compat alias for `node` — always equal to it; read `node` instead. */
  incident: string;
  node_count: number;
  edge_count: number;
  nodes: AttackPathNode[];
  edges: AttackPathEdge[];
}

/** `EvidenceGraph::graph_stats` — `GET /api/evidence/stats`'s retention/size visibility surface. */
export interface EvidenceStatsLastPrune {
  ts: number;
  retention_days: number | null;
  max_db_bytes: number | null;
  deleted_nodes: number;
  deleted_edges: number;
  deleted_incidents: number;
  deleted_reports: number;
  size_before_bytes: number;
  size_after_bytes: number;
  vacuumed: boolean;
}
export interface EvidenceStatsResponse {
  /** Per-table node counts (`devices`, `detections`, `incidents`, `reports`, `processes`, …). */
  nodes: Record<string, number>;
  total_edges: number;
  /** Per-`edge_type` counts (e.g. `spawned_by`, `incident_includes_detection`). */
  edges_by_type: Record<string, number>;
  db_size_bytes: number;
  /** `null` until `hookprobe-evidence --prune` has run at least once against this DB — never fabricated. */
  last_prune: EvidenceStatsLastPrune | null;
}

/**
 * `GET /api/stream` (SSE) payload — `EvidenceGraph::poll_since`'s per-tick delta. NOTE: the
 * detection/incident row shapes here are narrower than `DetectionRow`/`IncidentRow` above (e.g. no
 * `rule_id`/`mitre`/`dst_port` on the streamed detection row) — `poll_since` selects fewer columns
 * than `recent_detections`. Consumers that need the full row shape should treat an `update` event
 * as "something changed, re-fetch the authoritative list" (the same pattern `store/live.ts`'s
 * `applyIncidents` already uses for incidents) rather than trust the partial row.
 */
export interface StreamDetectionRow {
  id: string;
  ts: number;
  rule_msg: string;
  category: string;
  severity: number;
  src_ip: string;
  dst_ip: string;
  confidence: number;
}
export interface StreamIncidentRow {
  id: string;
  ts: number;
  title: string;
  device_ip: string;
  priority: string;
  status: string;
  threat_score: number;
}
export interface StreamQsecbitRow {
  id: string;
  ts: number;
  score: number;
  band: string;
}
export interface StreamPayload {
  detections?: StreamDetectionRow[];
  incidents?: StreamIncidentRow[];
  qsecbit?: StreamQsecbitRow[];
}

/** Parses one SSE `update` event's `data` field; returns `null` on malformed JSON (skip the tick). */
export function parseStreamPayload(data: string): StreamPayload | null {
  try {
    return JSON.parse(data) as StreamPayload;
  } catch {
    return null;
  }
}

// ── shared, honest data-shaping helpers ─────────────────────────────────────
//
// These derive UI-ready values from ONLY the fields the read-API actually returns — no invented
// per-row fields (no fabricated "engine" identity, no fabricated "blocked/alert" verdict; those
// fields don't exist in the `detections` table yet, see the Detect-workspace wiring report).

export type Severity = 'critical' | 'high' | 'medium' | 'low';

/** `severity` is 1=CRITICAL … 5=INFO (see `DetectionRow` doc comment); LOW absorbs 4 (LOW) + 5 (INFO). */
export function severityLabel(severity: number): Severity {
  if (severity <= 1) return 'critical';
  if (severity === 2) return 'high';
  if (severity === 3) return 'medium';
  return 'low';
}

/** `ts` fields are epoch seconds (float) throughout the evidence graph — render as local HH:MM:SS. */
export function formatTime(ts: number): string {
  if (!Number.isFinite(ts) || ts <= 0) return '--:--:--';
  return new Date(ts * 1000).toLocaleTimeString([], { hour12: false });
}

/** Human-readable byte size (`evidence_stats.db_size_bytes` and friends) — binary (1024) units. */
export function formatBytes(n: number): string {
  if (!Number.isFinite(n) || n < 0) return '—';
  if (n < 1024) return `${n} B`;
  const units = ['KiB', 'MiB', 'GiB', 'TiB'];
  let v = n / 1024;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i += 1;
  }
  return `${v.toFixed(v >= 10 ? 0 : 1)} ${units[i]}`;
}

/**
 * MITRE ATT&CK technique-id -> {name, tactic} — a small, static reference table (public taxonomy,
 * not per-detection evidence) covering the technique ids this codebase's rule sets actually emit
 * (`modules/napse*`, `modules/host-telemetry`). Filling in the public name/tactic for a REAL
 * technique id the API returned is not fabricating data (same category as looking up a country
 * name from an ISO code) — it is NOT used to invent a technique id that wasn't in the response.
 * Unknown ids fall back to the raw id with tactic `'Unmapped'` rather than a guessed name.
 */
const MITRE_TAXONOMY: Record<string, { name: string; tactic: string }> = {
  T1003: { name: 'OS Credential Dumping', tactic: 'Credential Access' },
  'T1003.008': { name: 'OS Credential Dumping: /etc/passwd and /etc/shadow', tactic: 'Credential Access' },
  T1018: { name: 'Remote System Discovery', tactic: 'Discovery' },
  T1020: { name: 'Automated Exfiltration', tactic: 'Exfiltration' },
  T1021: { name: 'Remote Services', tactic: 'Lateral Movement' },
  T1041: { name: 'Exfiltration Over C2 Channel', tactic: 'Exfiltration' },
  T1046: { name: 'Network Service Discovery', tactic: 'Discovery' },
  T1053: { name: 'Scheduled Task/Job', tactic: 'Persistence' },
  'T1053.003': { name: 'Scheduled Task/Job: Cron', tactic: 'Persistence' },
  T1059: { name: 'Command and Scripting Interpreter', tactic: 'Execution' },
  'T1059.004': { name: 'Command and Scripting Interpreter: Unix Shell', tactic: 'Execution' },
  'T1059.007': { name: 'Command and Scripting Interpreter: JavaScript', tactic: 'Execution' },
  T1068: { name: 'Exploitation for Privilege Escalation', tactic: 'Privilege Escalation' },
  T1070: { name: 'Indicator Removal', tactic: 'Defense Evasion' },
  T1071: { name: 'Application Layer Protocol', tactic: 'Command and Control' },
  'T1071.001': { name: 'Application Layer Protocol: Web Protocols', tactic: 'Command and Control' },
  'T1071.004': { name: 'Application Layer Protocol: DNS', tactic: 'Command and Control' },
  T1083: { name: 'File and Directory Discovery', tactic: 'Discovery' },
  T1098: { name: 'Account Manipulation', tactic: 'Persistence' },
  'T1098.004': { name: 'Account Manipulation: SSH Authorized Keys', tactic: 'Persistence' },
  T1105: { name: 'Ingress Tool Transfer', tactic: 'Command and Control' },
  T1110: { name: 'Brute Force', tactic: 'Credential Access' },
  T1190: { name: 'Exploit Public-Facing Application', tactic: 'Initial Access' },
  T1195: { name: 'Supply Chain Compromise', tactic: 'Initial Access' },
  T1486: { name: 'Data Encrypted for Impact', tactic: 'Impact' },
  T1496: { name: 'Resource Hijacking', tactic: 'Impact' },
  T1498: { name: 'Network Denial of Service', tactic: 'Impact' },
  'T1498.001': { name: 'Network Denial of Service: Direct Flood', tactic: 'Impact' },
  T1499: { name: 'Endpoint Denial of Service', tactic: 'Impact' },
  'T1499.004': { name: 'Endpoint Denial of Service: Application/System Exploitation', tactic: 'Impact' },
  T1530: { name: 'Data from Cloud Storage', tactic: 'Collection' },
  T1543: { name: 'Create or Modify System Process', tactic: 'Persistence' },
  'T1543.002': { name: 'Create or Modify System Process: Systemd Service', tactic: 'Persistence' },
  T1546: { name: 'Event Triggered Execution', tactic: 'Persistence' },
  'T1546.004': { name: 'Event Triggered Execution: Unix Shell Config Modification', tactic: 'Persistence' },
  T1548: { name: 'Abuse Elevation Control Mechanism', tactic: 'Privilege Escalation' },
  'T1548.003': { name: 'Abuse Elevation Control Mechanism: Sudo and Sudo Caching', tactic: 'Privilege Escalation' },
  T1557: { name: 'Adversary-in-the-Middle', tactic: 'Credential Access' },
  'T1557.002': { name: 'Adversary-in-the-Middle: ARP Cache Poisoning', tactic: 'Credential Access' },
  T1568: { name: 'Dynamic Resolution', tactic: 'Command and Control' },
  'T1568.002': { name: 'Dynamic Resolution: Domain Generation Algorithms', tactic: 'Command and Control' },
  T1571: { name: 'Non-Standard Port', tactic: 'Command and Control' },
  T1572: { name: 'Protocol Tunneling', tactic: 'Command and Control' },
  T1574: { name: 'Hijack Execution Flow', tactic: 'Persistence' },
  'T1574.006': { name: 'Hijack Execution Flow: Dynamic Linker Hijacking', tactic: 'Persistence' },
};

export function mitreName(id: string): string {
  return MITRE_TAXONOMY[id]?.name ?? id;
}

export function mitreTactic(id: string): string {
  return MITRE_TAXONOMY[id]?.tactic ?? 'Unmapped';
}
