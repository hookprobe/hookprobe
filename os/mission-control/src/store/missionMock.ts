/**
 * missionMock — Mission Control (§1) Layer-0 mock data.
 *
 * Numbers/labels match the reference ~/mission-control-page.png exactly (the MSSP
 * command center). Real values arrive over SSE/WS from Rust/Axum (ADR 0001);
 * shapes here are what those feeds will carry. Spec: docs/architecture/MissionControl.md §1.
 */

export type Tone = 'green' | 'amber' | 'red' | 'blue' | 'purple' | 'cyan' | 'orange' | 'grey';

// ── header vitals ─────────────────────────────────────────────────────────────
export const VITALS = {
  aiStatus: 'AUTONOMOUS', systemHealth: 'HEALTHY', activeAgents: '12,847', ingestion: '8.3 GB/s',
  stamp: 'May 21, 2025  14:32:45 UTC',
};

// ── 6 KPI cards ───────────────────────────────────────────────────────────────
// spark: 'area' (filled line) | 'spike' (jagged line) | 'bars'
export interface Kpi { label: string; value: string; sub: string; subTone?: Tone; tone: Tone; delta?: string; icon: string; spark: 'area' | 'spike' | 'bars'; data: number[] }
export const KPIS: Kpi[] = [
  { label: 'Threat Level',   value: 'HIGH',   sub: 'vs last hour',   tone: 'red',    delta: '↑ 18%', icon: 'shield', spark: 'area',
    data: [8,10,9,12,11,14,10,13,16,12,15,18,14,17,20,16] },
  { label: 'Fleet Health',   value: '94%',    sub: 'Healthy',        tone: 'blue',   icon: 'pulse',  spark: 'area',
    data: [6,8,7,9,8,10,12,9,11,13,10,12,14,13,15,16] },
  { label: 'AI Activity',    value: '223',    sub: 'Decisions Today', tone: 'purple', icon: 'ai',    spark: 'spike',
    data: [4,12,6,16,8,20,7,14,22,9,18,6,24,10,19,12] },
  { label: 'Open Incidents', value: '37',     sub: '12 Critical',    subTone: 'orange', tone: 'orange', icon: 'target', spark: 'bars',
    data: [3,5,4,7,6,9,5,8,11,7,10,6,12,8,11,9] },
  { label: 'Customer Risk',  value: '5',      sub: 'At Risk',        tone: 'cyan',   icon: 'people', spark: 'bars',
    data: [4,6,5,8,4,9,5,7,10,6,8,5,9,6,8,7] },
  { label: 'Mesh Status',    value: '98.7%',  sub: 'Connected',      tone: 'green',  icon: 'mesh',   spark: 'area',
    data: [12,14,13,15,14,16,15,17,16,15,17,16,18,17,18,19] },
];

// ── global threat map ─────────────────────────────────────────────────────────
export const THREATMAP = {
  stats: [
    { label: 'Attacks Detected (24H)', value: '12,842', delta: '↑ 23%', tone: 'red' as Tone },
    { label: 'Blocked Attacks',        value: '11,203', delta: '↑ 19%', tone: 'green' as Tone },
    { label: 'Targeted Endpoints',     value: '1,639',  delta: '↑ 8%',  tone: 'orange' as Tone },
    { label: 'Active Countries',       value: '128',    delta: '',      tone: 'cyan' as Tone },
  ],
  origins: [
    { country: 'Russia',        attacks: 2842, flag: '#e63946' },
    { country: 'United States', attacks: 1986, flag: '#4895ef' },
    { country: 'China',         attacks: 1423, flag: '#adb5bd' },
    { country: 'Netherlands',   attacks: 987,  flag: '#f77f00' },
    { country: 'Germany',       attacks: 623,  flag: '#ffba08' },
    { country: 'Others',        attacks: 4981, flag: '#8338ec' },
  ],
  // attack arcs on the stylized map: [x1%,y1%] → [x2%,y2%], severity
  arcs: [
    { from: [58, 30], to: [28, 42], sev: 'high' as const },
    { from: [72, 34], to: [30, 40], sev: 'high' as const },
    { from: [55, 28], to: [82, 62], sev: 'medium' as const },
    { from: [50, 33], to: [25, 45], sev: 'medium' as const },
    { from: [60, 31], to: [48, 68], sev: 'low' as const },
    { from: [30, 40], to: [78, 38], sev: 'info' as const },
  ],
  // glowing origin points [x%, y%, severity]
  points: [
    [58, 30, 'high'], [72, 34, 'high'], [55, 28, 'high'], [30, 40, 'medium'],
    [25, 45, 'medium'], [82, 62, 'low'], [48, 68, 'low'], [50, 33, 'medium'], [78, 38, 'info'],
  ] as [number, number, string][],
};

// ── QSecBit score history ─────────────────────────────────────────────────────
export const QSCORE = {
  score: 91, delta: '↑ 7 pts', deltaSub: 'vs last 30 days',
  axis: ['Apr 22', 'Apr 29', 'May 06', 'May 13', 'May 21'],
  // 0..100 trend, generally rising
  trend: [42, 40, 55, 52, 58, 60, 57, 68, 70, 74, 78, 82, 80, 86, 88, 91],
  factors: [
    { name: 'Network Security',   score: 92 },
    { name: 'Endpoint Security',  score: 89 },
    { name: 'Threat Intelligence', score: 94 },
    { name: 'Compliance',         score: 90 },
    { name: 'Data Protection',    score: 91 },
  ],
};

// ── AI decisions (today) donut ────────────────────────────────────────────────
export const AI_DECISIONS = {
  total: 319,
  segments: [
    { name: 'Autonomous',          n: 276, pct: 86, tone: 'purple' as Tone },
    { name: 'Human Assisted',      n: 31,  pct: 10, tone: 'blue' as Tone },
    { name: 'Escalated to Analyst', n: 12,  pct: 4,  tone: 'orange' as Tone },
  ],
};

// ── threat categories (24H) donut ─────────────────────────────────────────────
export const THREAT_CATS = {
  total: '12,842',
  segments: [
    { name: 'Malware',          pct: 32, tone: 'red' as Tone },
    { name: 'Reconnaissance',   pct: 24, tone: 'orange' as Tone },
    { name: 'Credential Access', pct: 18, tone: 'amber' as Tone },
    { name: 'Lateral Movement', pct: 12, tone: 'green' as Tone },
    { name: 'Exploitation',     pct: 8,  tone: 'blue' as Tone },
    { name: 'Other',            pct: 6,  tone: 'purple' as Tone },
  ],
};

// ── recent critical incidents ─────────────────────────────────────────────────
export interface Incident { title: string; customer: string; sev: 'Critical' | 'High' | 'Medium'; time: string }
export const INCIDENTS: Incident[] = [
  { title: 'Ransomware Activity Detected',   customer: 'ACME Corp',    sev: 'Critical', time: '2m ago' },
  { title: 'Unauthorized Lateral Movement',  customer: 'Globex Inc',   sev: 'Critical', time: '8m ago' },
  { title: 'Data Exfiltration Attempt',      customer: 'Initech',      sev: 'High',     time: '15m ago' },
  { title: 'Exploit Attempt Blocked',        customer: 'Soylent Corp', sev: 'Medium',   time: '22m ago' },
];

// ── system resources ──────────────────────────────────────────────────────────
export const RESOURCES = {
  rings: [
    { label: 'CPU',     pct: 23, tone: 'blue' as Tone },
    { label: 'Memory',  pct: 45, tone: 'purple' as Tone },
    { label: 'Storage', pct: 62, tone: 'orange' as Tone },
    { label: 'Network', pct: 31, tone: 'green' as Tone },
  ],
  throughput: [
    { label: 'Data Ingestion',   value: '8.3 GB/s', data: [5,7,6,8,7,9,8,7,9,8,10,9] },
    { label: 'Event Processing', value: '128K EPS', data: [6,8,7,9,8,7,9,10,8,9,11,10] },
  ],
};

// ── live feed ─────────────────────────────────────────────────────────────────
export interface FeedItem { time: string; tag: string; tagTone: Tone; text: string }
export const LIVE_FEED: FeedItem[] = [
  { time: '14:32:12', tag: 'AI',    tagTone: 'purple', text: 'NAPSE detected anomalous behavior on endpoint HP-7842' },
  { time: '14:31:58', tag: 'XDP',   tagTone: 'blue',   text: 'Blocked connection from 185.220.101.45 to 10.0.12.25' },
  { time: '14:31:45', tag: 'HYDRA', tagTone: 'green',  text: 'New IOC matched: C2 server 45.77.32.11' },
];

// QSecBit sidebar card
export const QSIDEBAR = { score: 91, posture: 'Excellent Security Posture', spark: [70,72,68,74,73,78,80,79,84,86,88,91] };
