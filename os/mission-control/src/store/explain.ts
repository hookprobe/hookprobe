/**
 * explain — the pure logic behind the explainability views: incident trigger and attack path,
 * the sealed-evidence reference and its on-device JSON export, the QSECBIT band and its sliding
 * window, and the Shield DNS audit.
 *
 * No Solid, no fetch, no DOM: every function maps device JSON to view data, so `node --test`
 * covers it (tests/unit). Type-only imports keep it runnable by Node's type stripping.
 *
 * Fields the device does not send yet (see docs/adr/notes/2026-11-17-mc-explainability-payload.md)
 * are typed optional here and every view has a fallback that says what is missing, never a
 * made-up value.
 */
import type { DetectionRow, IncidentDetail, IncidentTimelineEvent, QsecbitScoreRow } from './api';
import type { DnsLive } from './dnsLive';

// ── Incident: the record, tolerant of missing fields ─────────────────────────────────────────────

/** Optional fields a later device build may add to `GET /api/incidents/:id` (payload note). */
export interface IncidentExt {
  /** What fired, when the device can name it directly (otherwise derived from related detections). */
  trigger?: { kind?: 'bpf' | 'wasm'; rule_id?: number; module_name?: string; module_hash?: string; verdict?: string; reason?: string };
  /** Where the traffic entered the device. */
  ingress?: { interface?: string; zone?: string };
  /** The sealed evidence-log record that holds this incident's detections. */
  evidence_ref?: { record_id?: string; sealed_ts?: number; verified?: boolean };
}
export type IncidentDetailX = IncidentDetail & IncidentExt;

/** Optional fields a later build may add to a detection row. `build` is sent today. */
export interface DetectionExt { wasm_module?: string; wasm_hash?: string; build?: string | null; src_device?: string }
export type DetectionRowX = DetectionRow & DetectionExt;

const obj = (v: unknown): Record<string, unknown> => (v && typeof v === 'object' && !Array.isArray(v) ? (v as Record<string, unknown>) : {});
const str = (v: unknown, d = ''): string => (typeof v === 'string' ? v : d);
const num = (v: unknown, d = 0): number => (typeof v === 'number' && Number.isFinite(v) ? v : d);

/**
 * Read an incident record defensively: required fields get safe defaults, optional extensions
 * are kept only when well-formed. Returns null when there is no id (not an incident at all).
 */
export function parseIncident(raw: unknown): IncidentDetailX | null {
  const r = obj(raw);
  const id = str(r.id);
  if (!id) return null;
  const ex = obj(r.explanation);
  const ap = obj(r.attack_path);
  const nodes = Array.isArray(ap.nodes) ? ap.nodes.map(obj).map((n) => ({ id: str(n.id), type: str(n.type), label: str(n.label) })).filter((n) => n.id) : [];
  const edges = Array.isArray(ap.edges) ? ap.edges.map(obj).map((e) => ({ src: str(e.src), type: str(e.type), dst: str(e.dst) })) : [];
  const out: IncidentDetailX = {
    id,
    ts: num(r.ts),
    title: str(r.title, id),
    device_ip: str(r.device_ip),
    priority: str(r.priority),
    status: str(r.status),
    threat_score: num(r.threat_score),
    explanation: {
      why: str(ex.why),
      confidence: num(ex.confidence),
      evidence: num(ex.evidence),
      model: typeof ex.model === 'string' ? ex.model : null,
      related_events: Array.isArray(ex.related_events) ? ex.related_events.filter((x): x is string => typeof x === 'string') : [],
    },
    attack_path: { incident: str(ap.incident, id), node_count: num(ap.node_count, nodes.length), edge_count: num(ap.edge_count, edges.length), nodes, edges },
  };
  const t = obj(r.trigger);
  if (Object.keys(t).length) {
    out.trigger = {
      kind: t.kind === 'bpf' || t.kind === 'wasm' ? t.kind : undefined,
      rule_id: typeof t.rule_id === 'number' ? t.rule_id : undefined,
      module_name: typeof t.module_name === 'string' ? t.module_name : undefined,
      module_hash: typeof t.module_hash === 'string' ? t.module_hash : undefined,
      verdict: typeof t.verdict === 'string' ? t.verdict : undefined,
      reason: typeof t.reason === 'string' ? t.reason : undefined,
    };
  }
  const ing = obj(r.ingress);
  if (typeof ing.interface === 'string' || typeof ing.zone === 'string') {
    out.ingress = { interface: typeof ing.interface === 'string' ? ing.interface : undefined, zone: typeof ing.zone === 'string' ? ing.zone : undefined };
  }
  const ev = obj(r.evidence_ref);
  if (typeof ev.record_id === 'string' && ev.record_id) {
    out.evidence_ref = { record_id: ev.record_id, sealed_ts: typeof ev.sealed_ts === 'number' ? ev.sealed_ts : undefined, verified: typeof ev.verified === 'boolean' ? ev.verified : undefined };
  }
  return out;
}

/** Confidence as a percentage: heqk sends a 0–1 fraction, planners may send 0–100. */
export function confidencePct(c: number): number {
  if (!Number.isFinite(c) || c <= 0) return 0;
  return Math.min(100, Math.round(c <= 1 ? c * 100 : c));
}

// ── Incident: why it was flagged ─────────────────────────────────────────────────────────────────

/** The device's tri-state class names (`mcstate.rs::class_name`) in plain words. */
export const CLASS_TEXT: Record<string, string> = {
  observe: 'Watched only, not blocked',
  ratelimit: 'Slowed down (still under the limit)',
  ratelimit_enforced: 'Slowed down (over the limit)',
  framedrop: 'Blocked: the traffic was dropped',
  quarantine: 'Quarantined: the device was cut off',
  allowlisted: 'Allowed: management traffic is never blocked',
  unknown: 'Recorded',
};
/** Strength of each class, for "the strongest action taken". */
const CLASS_RANK: Record<string, number> = { unknown: 0, allowlisted: 0, observe: 1, ratelimit: 2, ratelimit_enforced: 3, framedrop: 4, quarantine: 5 };

/** Split the device's `rule_msg` "<message> (<DROP|PASS>, <class>)" into its parts. */
export function parseRuleMsg(msg: string): { text: string; verdict?: 'DROP' | 'PASS'; cls?: string } {
  const m = /^(.*) \((DROP|PASS), ([a-z_]+)\)$/.exec(msg);
  return m ? { text: m[1], verdict: m[2] as 'DROP' | 'PASS', cls: m[3] } : { text: msg };
}

export interface Trigger {
  kind: 'bpf' | 'wasm';
  /** e.g. "Signed BPF rule 1200113" or "Wasm module dga-detector". */
  name: string;
  ruleId?: number;
  moduleHash?: string;
  verdict?: 'DROP' | 'PASS';
  /** Plain-language action from the class. */
  action: string;
  /** What the rule looks for. */
  reason: string;
  confidence: number;
  mitre?: string;
  severity?: number;
  /** How many of the incident's detections this rule raised. */
  hits: number;
  build?: string | null;
}

/**
 * The rules or modules that raised this incident, strongest first. From the device's own
 * `trigger` when it sends one; otherwise from the related detections (rule id, message, class,
 * confidence: all real fields of `/api/detections`).
 */
export function triggers(d: IncidentDetailX, dets: DetectionRowX[]): Trigger[] {
  const related = new Set(d.explanation.related_events);
  const mine = dets.filter((x) => related.has(x.id));
  const by = new Map<string, Trigger & { rank: number }>();
  for (const x of mine) {
    const p = parseRuleMsg(x.rule_msg);
    const wasm = !!x.wasm_module;
    const key = wasm ? `w:${x.wasm_module}` : `r:${x.rule_id}`;
    const rank = CLASS_RANK[p.cls ?? 'unknown'] ?? 0;
    const prev = by.get(key);
    if (prev) {
      prev.hits += 1;
      if (rank > prev.rank) Object.assign(prev, { rank, verdict: p.verdict, action: CLASS_TEXT[p.cls ?? 'unknown'] ?? CLASS_TEXT.unknown });
      prev.confidence = Math.max(prev.confidence, confidencePct(x.confidence));
      continue;
    }
    by.set(key, {
      kind: wasm ? 'wasm' : 'bpf',
      name: wasm ? `Signed Wasm module ${x.wasm_module}` : `Signed BPF rule ${x.rule_id} (RFC 9669)`,
      ruleId: wasm ? undefined : x.rule_id,
      moduleHash: x.wasm_hash,
      verdict: p.verdict,
      action: CLASS_TEXT[p.cls ?? 'unknown'] ?? CLASS_TEXT.unknown,
      reason: p.text,
      confidence: confidencePct(x.confidence),
      mitre: x.mitre || undefined,
      severity: x.severity,
      hits: 1,
      build: x.build,
      rank,
    });
  }
  const list = [...by.values()].sort((a, b) => b.rank - a.rank || b.hits - a.hits).map(({ rank: _r, ...t }) => t);
  const t = d.trigger;
  if (t && (t.rule_id !== undefined || t.module_name)) {
    const wasm = t.kind === 'wasm' || (!!t.module_name && t.rule_id === undefined);
    const own: Trigger = {
      kind: wasm ? 'wasm' : 'bpf',
      name: wasm ? `Signed Wasm module ${t.module_name ?? 'unnamed'}` : `Signed BPF rule ${t.rule_id} (RFC 9669)`,
      ruleId: wasm ? undefined : t.rule_id,
      moduleHash: t.module_hash,
      verdict: t.verdict === 'DROP' || t.verdict === 'PASS' ? t.verdict : undefined,
      action: list[0]?.action ?? CLASS_TEXT.unknown,
      reason: t.reason ?? list[0]?.reason ?? '',
      confidence: confidencePct(d.explanation.confidence),
      hits: list.find((x) => (wasm ? x.name.endsWith(` ${t.module_name}`) : x.ruleId === t.rule_id))?.hits ?? 0,
    };
    return [own, ...list.filter((x) => (wasm ? !x.name.endsWith(` ${t.module_name}`) : x.ruleId !== t.rule_id))];
  }
  return list;
}

// ── Incident: the attack path in plain steps ─────────────────────────────────────────────────────

export interface PathStep {
  kind: 'ingress' | 'inspect' | 'target' | 'action';
  title: string;
  detail: string;
  /** False when the step is a placeholder for data the device does not send yet. */
  known: boolean;
}

/** Ingress → inspection rule(s) → where it was going → what the device did. */
export function attackPath(d: IncidentDetailX, dets: DetectionRowX[]): PathStep[] {
  const steps: PathStep[] = [];
  const iface = d.ingress?.interface;
  steps.push({
    kind: 'ingress',
    title: `Traffic from ${d.device_ip || 'an unknown source'} reached the device`,
    detail: iface ? `It came in on ${iface}${d.ingress?.zone ? ` (${d.ingress.zone})` : ''}.` : 'The device does not report the interface it came in on yet.',
    known: !!iface,
  });
  const ts = triggers(d, dets);
  for (const t of ts.slice(0, 3)) {
    steps.push({ kind: 'inspect', title: `Checked by ${t.name}`, detail: t.reason ? `It matched: ${t.reason}.` : 'It matched this rule.', known: true });
  }
  if (ts.length === 0) steps.push({ kind: 'inspect', title: 'Checked by the device rules', detail: d.explanation.why || 'The matching detections are no longer in the recent list.', known: !!d.explanation.why });
  const related = new Set(d.explanation.related_events);
  const seen = new Set<string>();
  for (const x of dets) {
    if (!related.has(x.id) || !x.dst_ip) continue;
    const k = `${x.dst_ip}:${x.dst_port}`;
    if (seen.has(k) || seen.size >= 3) continue;
    seen.add(k);
    steps.push({ kind: 'target', title: `It was heading for ${x.dst_ip}${x.dst_port ? ` port ${x.dst_port}` : ''}`, detail: 'Destination of the traffic that matched.', known: true });
  }
  const strongest = ts[0];
  steps.push({
    kind: 'action',
    title: strongest ? strongest.action : 'Recorded',
    detail: strongest?.verdict === 'DROP' ? 'The device acted on the wire. Every automatic action ends on its own.' : 'The traffic passed; the device kept the evidence.',
    known: !!strongest,
  });
  return steps;
}

// ── Incident: sealed evidence ────────────────────────────────────────────────────────────────────

export interface EvidenceRef {
  recordId: string | null;
  sealedAt: number | null;
  /** true = the device verified the seal, false = it failed, null = not reported. */
  verified: boolean | null;
  /** Plain-language status line. */
  status: string;
}

export function evidenceRef(d: IncidentDetailX): EvidenceRef {
  const e = d.evidence_ref;
  if (!e?.record_id) {
    return {
      recordId: null, sealedAt: null, verified: null,
      status: 'Kept in the sealed evidence log on this device. This build does not report the record id or its seal check yet.',
    };
  }
  const v = e.verified ?? null;
  return {
    recordId: e.record_id, sealedAt: e.sealed_ts ?? null, verified: v,
    status: v === true ? 'Seal verified on this device.' : v === false ? 'Seal check FAILED: the record may have been altered.' : 'Sealed on this device; seal check not reported.',
  };
}

export const EXPORT_FORMAT = 'hookprobe.incident-evidence/1';

/**
 * The JSON the operator saves. Built in the browser from what the device served; nothing is
 * sent anywhere. `sha256` is filled in by the caller (Web Crypto) over this object without it.
 */
export function evidenceExport(d: IncidentDetailX, dets: DetectionRowX[], timeline: IncidentTimelineEvent[], nowMs: number) {
  const related = new Set(d.explanation.related_events);
  return {
    format: EXPORT_FORMAT,
    exported_at: new Date(nowMs).toISOString(),
    note: 'Exported in the browser from this device. Nothing was sent to any other system.',
    incident: d,
    evidence_ref: evidenceRef(d),
    triggers: triggers(d, dets),
    attack_path: attackPath(d, dets),
    related_detections: dets.filter((x) => related.has(x.id)),
    timeline,
  };
}

export function exportFileName(id: string): string {
  return `${id.replace(/[^A-Za-z0-9._-]+/g, '_')}-evidence.json`;
}

// ── QSECBIT ──────────────────────────────────────────────────────────────────────────────────────

export type Band = 'GREEN' | 'AMBER' | 'RED';
/**
 * The device scores RISK in [0, 1] (lower is healthier) and bands it in `mcstate.rs::band`:
 * below 0.300 GREEN, below 0.700 AMBER, else RED. Mission Control shows resilience = 1 − risk,
 * so GREEN is resilience above 70, AMBER 31–70, RED 30 and below.
 */
export const RISK_AMBER = 0.3;
export const RISK_RED = 0.7;

export function bandOf(risk: number): Band {
  if (!Number.isFinite(risk)) return 'AMBER';
  return risk < RISK_AMBER ? 'GREEN' : risk < RISK_RED ? 'AMBER' : 'RED';
}

/** Trust the device's band string when it is one of the three; else compute it. */
export function rowBand(r: QsecbitScoreRow): Band {
  return r.band === 'GREEN' || r.band === 'AMBER' || r.band === 'RED' ? r.band : bandOf(r.score);
}

export const BAND_TEXT: Record<Band, { mark: string; word: string; line: string }> = {
  GREEN: { mark: '🟢', word: 'GREEN', line: 'All clear · Protected' },
  AMBER: { mark: '🟡', word: 'AMBER', line: 'Monitoring · Stay alert' },
  RED: { mark: '🔴', word: 'RED', line: 'Under attack · Defending' },
};

export function resilience(risk: number): number {
  return Math.max(0, Math.min(100, Math.round((1 - risk) * 100)));
}

export interface WindowStats {
  n: number;
  fromTs: number;
  toTs: number;
  /** Resilience (0–100), not risk. */
  min: number;
  max: number;
  mean: number;
  latest: number | null;
  /** Samples per band. */
  inBand: Record<Band, number>;
}

/** Summarise a history (any order) over the samples with `ts >= toTs - windowS`. */
export function windowStats(history: QsecbitScoreRow[], windowS = Infinity): WindowStats {
  const rows = [...history].filter((r) => Number.isFinite(r.score)).sort((a, b) => a.ts - b.ts);
  const toTs = rows.length ? rows[rows.length - 1].ts : 0;
  const inWin = rows.filter((r) => r.ts >= toTs - windowS);
  const inBand: Record<Band, number> = { GREEN: 0, AMBER: 0, RED: 0 };
  if (inWin.length === 0) return { n: 0, fromTs: 0, toTs: 0, min: 0, max: 0, mean: 0, latest: null, inBand };
  const res = inWin.map((r) => resilience(r.score));
  for (const r of inWin) inBand[rowBand(r)] += 1;
  return {
    n: inWin.length,
    fromTs: inWin[0].ts,
    toTs,
    min: Math.min(...res),
    max: Math.max(...res),
    mean: Math.round(res.reduce((s, v) => s + v, 0) / res.length),
    latest: res[res.length - 1],
    inBand,
  };
}

export interface BandShift { ts: number; from: Band; to: Band; fromRes: number; toRes: number }

/** Every change of band, newest first. */
export function bandShifts(history: QsecbitScoreRow[]): BandShift[] {
  const rows = [...history].filter((r) => Number.isFinite(r.score)).sort((a, b) => a.ts - b.ts);
  const out: BandShift[] = [];
  for (let i = 1; i < rows.length; i++) {
    const a = rowBand(rows[i - 1]);
    const b = rowBand(rows[i]);
    if (a !== b) out.push({ ts: rows[i].ts, from: a, to: b, fromRes: resilience(rows[i - 1].score), toRes: resilience(rows[i].score) });
  }
  return out.reverse();
}

export interface ShiftSignal { label: string; count: number; worst: number; mitre?: string }

const BAND_ORDER: Record<Band, number> = { GREEN: 0, AMBER: 1, RED: 2 };

/**
 * The detections that pushed a shift: those in the `lookbackS` before it, grouped by rule
 * message, worst severity first (1 = critical). A recovery has no "cause" in detections: the
 * risk window simply aged out, and the caller says so.
 */
export function shiftSignals(s: BandShift, dets: DetectionRowX[], lookbackS = 300): ShiftSignal[] {
  if (BAND_ORDER[s.to] < BAND_ORDER[s.from]) return [];
  const m = new Map<string, ShiftSignal>();
  for (const d of dets) {
    if (d.ts > s.ts || d.ts <= s.ts - lookbackS) continue;
    const label = parseRuleMsg(d.rule_msg).text || `Rule ${d.rule_id}`;
    const g = m.get(label);
    if (g) { g.count += 1; g.worst = Math.min(g.worst, d.severity); }
    else m.set(label, { label, count: 1, worst: d.severity, mitre: d.mitre || undefined });
  }
  return [...m.values()].sort((a, b) => a.worst - b.worst || b.count - a.count).slice(0, 5);
}

/** One plain sentence for a shift. */
export function explainShift(s: BandShift, signals: ShiftSignal[]): string {
  const dir = BAND_ORDER[s.to] > BAND_ORDER[s.from] ? 'dropped' : 'recovered';
  const head = `Resilience ${dir} from ${s.fromRes} to ${s.toRes} (${s.from} → ${s.to}).`;
  if (dir === 'recovered') return `${head} No new detections kept the risk up, so the window aged out.`;
  if (signals.length === 0) return `${head} The detections behind it are no longer in the recent list.`;
  const top = signals.slice(0, 3).map((g) => `${g.label} ×${g.count}`).join('; ');
  return `${head} In the 5 minutes before: ${top}.`;
}

// ── Shield DNS audit ─────────────────────────────────────────────────────────────────────────────

/** Optional fields: the kernel sends `category`/`level` on recent rows today, interfaces not yet. */
export interface DnsRecentExt { category?: string; level?: string }
export interface DnsInterfaceRow { name: string; queries: number; blocked: number }
export type DnsLiveX = DnsLive & {
  recent: (DnsLive['recent'][number] & DnsRecentExt)[];
  interfaces?: DnsInterfaceRow[];
  dga_suspects?: number;
  ioc_domain_hits?: number;
};

/** Verdicts the device answers itself instead of forwarding (`shield.rs::Verdict::answered`). */
export const ANSWERED_LOCALLY = ['blocked', 'ddr', 'canary', 'relay-blocked', 'doh-blocked'] as const;
const BLOCK_VERDICTS = ['blocked', 'blocked-cname', 'tcp53-refused'];

export interface DnsAudit {
  /** Every parsed lookup. */
  total: number;
  answeredLocally: number;
  blocked: number;
  /** Lookups whose answer was blocked or refused, per verdict, largest first. */
  reasons: { verdict: string; count: number }[];
  /** Per-interface counters, or null when the device does not send them. */
  interfaces: DnsInterfaceRow[] | null;
}

export function dnsAudit(d: DnsLiveX): DnsAudit {
  const c = d.counters ?? {};
  const total = Object.entries(c).filter(([k]) => k !== 'unparsable').reduce((s, [, v]) => s + (Number.isFinite(v) ? v : 0), 0);
  const answeredLocally = ANSWERED_LOCALLY.reduce((s, k) => s + (c[k] ?? 0), 0);
  const blocked = BLOCK_VERDICTS.reduce((s, k) => s + (c[k] ?? 0), 0);
  const reasons = Object.entries(c)
    .filter(([k, v]) => v > 0 && k !== 'allowed' && k !== 'unparsable' && k !== 'floor' && k !== 'allow-rule' && k !== 'level-allowed')
    .map(([verdict, count]) => ({ verdict, count }))
    .sort((a, b) => b.count - a.count);
  const interfaces = Array.isArray(d.interfaces) ? d.interfaces.filter((x) => x && typeof x.name === 'string') : null;
  return { total, answeredLocally, blocked, reasons, interfaces };
}

/** Which rule a recent lookup's verdict came from, in plain words. */
export function blockSource(r: DnsLiveX['recent'][number], lists: DnsLive['lists']): string {
  if (r.category && r.category !== 'none') return `${r.category} category, blocked at the ${r.level ?? 'current'} protection level`;
  switch (r.verdict) {
    case 'blocked':
    case 'blocked-cname': {
      const via = r.verdict === 'blocked-cname' ? ' (through a CNAME)' : '';
      if (lists.block_file !== 'loaded') return `block list${via}`;
      return `your block list BLOCK.TXT${lists.signed ? `, signed, generation ${lists.generation}` : ', unsigned'}${via}`;
    }
    case 'tcp53-refused': return 'policy: DNS over TCP to another resolver';
    case 'doh-blocked': return 'policy: encrypted DNS (DoH) blocked';
    case 'dot-refused': return 'policy: DNS over TLS refused';
    case 'relay-blocked': return 'policy: Private Relay blocked';
    case 'ddr':
    case 'canary': return 'policy: keep devices on filtered DNS';
    case 'paused': return 'Shield paused for this device';
    case 'floor': return 'always-allowed list (management)';
    case 'allow-rule': return 'your allow list ALLOW.TXT';
    default: return '';
  }
}
