/**
 * detectMock — Detect (§4, NAPSE) Layer-0 mock data.
 *
 * Spec: docs/MissionControl.md §4 — detections + the rules behind them; wraps
 * Suricata / YARA / Sigma mapped to MITRE ATT&CK; custom logic ships as signed
 * Wasm. A detection links to Investigate (the story) or the Threat Graph.
 */

import type { Tone } from './missionMock';

export type Severity = 'critical' | 'high' | 'medium' | 'low';
export type Verdict = 'blocked' | 'alert';

export interface Detection {
  time: string; severity: Severity; engine: string;
  technique: string; tName: string;
  title: string; src: string; dst: string; verdict: Verdict;
}

export interface Engine { name: string; kind: string; rules: string; hits: number; status: 'active' | 'degraded' }
export interface Coverage { tactic: string; covered: number; total: number }
export interface Technique { id: string; name: string; count: number; tactic: string }

export interface Kpi { label: string; value: string; tone: Tone }
export const KPIS: Kpi[] = [
  { label: 'Detections · 24h', value: '1,284', tone: 'blue' },
  { label: 'Blocked',         value: '412',   tone: 'green' },
  { label: 'Alert-only',      value: '872',   tone: 'amber' },
  { label: 'Active rules',    value: '48,210', tone: 'purple' },
  { label: 'ATT&CK coverage', value: '78%',   tone: 'green' },
];

export const DETECTIONS: Detection[] = [
  { time: '12:46', severity: 'high',     engine: 'Suricata',   technique: 'T1110', tName: 'Brute Force',           title: 'Credential stuffing burst', src: '209.x.x.14', dst: 'vpn-gw-01',  verdict: 'blocked' },
  { time: '12:38', severity: 'high',     engine: 'AI Detection', technique: 'T1071', tName: 'App Layer Protocol',  title: 'C2 beacon (60s interval)',  src: 'Marketing-12', dst: '185.x.x.7', verdict: 'alert' },
  { time: '12:18', severity: 'critical', engine: 'Sigma',      technique: 'T1068', tName: 'Privilege Escalation', title: 'Suspicious token manipulation', src: 'DC-01', dst: 'localhost', verdict: 'blocked' },
  { time: '12:02', severity: 'medium',   engine: 'YARA',       technique: 'T1486', tName: 'Data Encrypted for Impact', title: 'Ransomware string match', src: 'LAPTOP-7', dst: 'file', verdict: 'blocked' },
  { time: '11:47', severity: 'low',      engine: 'Behavioral', technique: 'T1046', tName: 'Network Service Discovery', title: 'Internal port sweep', src: 'IoT-Cam-3', dst: '10.200.0.0/24', verdict: 'alert' },
  { time: '11:31', severity: 'medium',   engine: 'Suricata',   technique: 'T1572', tName: 'Protocol Tunneling',   title: 'DNS tunneling pattern', src: 'Guest-Phone', dst: '8.8.8.8', verdict: 'alert' },
  { time: '10:58', severity: 'high',     engine: 'Sigma',      technique: 'T1021', tName: 'Remote Services',      title: 'Lateral RDP from non-admin', src: 'WS-22', dst: 'srv-08', verdict: 'blocked' },
];

export const ENGINES: Engine[] = [
  { name: 'Suricata',     kind: 'Network signatures', rules: '41,203', hits: 618, status: 'active' },
  { name: 'Sigma',        kind: 'Log rules',          rules: '3,910',  hits: 512, status: 'active' },
  { name: 'YARA',         kind: 'File patterns',      rules: '2,847',  hits: 34,  status: 'active' },
  { name: 'AI Detection', kind: 'ML anomaly (WASI-NN)', rules: '—',    hits: 96,  status: 'active' },
  { name: 'Behavioral',   kind: 'Baseline deviation', rules: '250',    hits: 24,  status: 'active' },
];

export const COVERAGE: Coverage[] = [
  { tactic: 'Initial Access',      covered: 12, total: 15 },
  { tactic: 'Execution',           covered: 9,  total: 14 },
  { tactic: 'Persistence',         covered: 14, total: 20 },
  { tactic: 'Privilege Escalation', covered: 11, total: 13 },
  { tactic: 'Defense Evasion',     covered: 28, total: 43 },
  { tactic: 'Credential Access',   covered: 13, total: 17 },
  { tactic: 'Discovery',           covered: 21, total: 31 },
  { tactic: 'Lateral Movement',    covered: 8,  total: 9 },
  { tactic: 'Command & Control',   covered: 12, total: 16 },
  { tactic: 'Exfiltration',        covered: 7,  total: 9 },
];

export const TOP_TECHNIQUES: Technique[] = [
  { id: 'T1110', name: 'Brute Force',         count: 412, tactic: 'Credential Access' },
  { id: 'T1071', name: 'App Layer Protocol',  count: 243, tactic: 'Command & Control' },
  { id: 'T1046', name: 'Network Svc Discovery', count: 198, tactic: 'Discovery' },
  { id: 'T1021', name: 'Remote Services',     count: 156, tactic: 'Lateral Movement' },
  { id: 'T1486', name: 'Data Encrypted',      count: 88,  tactic: 'Impact' },
];
