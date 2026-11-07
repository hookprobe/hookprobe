/**
 * atmMock — Automate (§7, SOAR) Layer-0 mock data.
 *
 * Spec: docs/architecture/MissionControl.md §7 — orchestration; playbooks/agents/workflows
 * as CI/CD-style pipelines (detect → validate → contain → notify → recover →
 * verify → close). Autonomy is policy-gated per stage (auto-apply vs approval).
 * Intent: "Auto-contain credential-stuffing but require approval before
 * isolating a server." Backed by AEGIS reconciler; deterministic path works
 * with no model. Real values arrive over SSE/WS from Rust/Axum (ADR 0001).
 */

import type { Tone } from './missionMock';

export type StageState  = 'done' | 'running' | 'waiting' | 'failed';
export type Autonomy    = 'auto' | 'approval';
export type PbStatus    = 'active' | 'paused' | 'draft';
export type Urgency     = 'critical' | 'high' | 'medium';
export type AgentStatus = 'active' | 'idle' | 'paused';

export interface Stage {
  name:      string;
  state:     StageState;
  autonomy:  Autonomy;
  duration?: string;   // e.g. '0.3s', '4m2s' — present only when done/running
}

export interface Playbook {
  id:          string;
  name:        string;
  trigger:     string;
  lastRun:     string;
  runCount:    number;
  status:      PbStatus;
  stages:      Stage[];
}

export interface ApprovalItem {
  id:         string;
  time:       string;
  playbook:   string;
  action:     string;
  target:     string;
  rationale:  string;
  confidence: number;
  urgency:    Urgency;
}

export interface Agent {
  name:       string;
  role:       string;
  status:     AgentStatus;
  actions:    number;
  lastAction: string;
}

export interface AnalyticRow { label: string; value: string; delta?: string; tone: Tone }

// ── KPI row ─────────────────────────────────────────────────────────────────

export interface Kpi { label: string; value: string; tone: Tone }

export const KPIS: Kpi[] = [
  { label: 'Playbooks',      value: '12',  tone: 'blue'   },
  { label: 'Runs today',     value: '47',  tone: 'green'  },
  { label: 'Auto-applied',   value: '84%', tone: 'green'  },
  { label: 'Await approval', value: '3',   tone: 'amber'  },
];

// ── Playbooks ────────────────────────────────────────────────────────────────

export const PLAYBOOKS: Playbook[] = [
  {
    id: 'pb-001',
    name: 'Credential Stuffing Response',
    trigger: 'NAPSE: T1110 burst ≥5 in 10 min',
    lastRun: '12:46', runCount: 14, status: 'active',
    stages: [
      { name: 'detect',   state: 'done',    autonomy: 'auto',     duration: '0.1s' },
      { name: 'validate', state: 'done',    autonomy: 'auto',     duration: '0.8s' },
      { name: 'contain',  state: 'running', autonomy: 'approval'                   },
      { name: 'notify',   state: 'waiting', autonomy: 'auto'                       },
      { name: 'recover',  state: 'waiting', autonomy: 'approval'                   },
      { name: 'verify',   state: 'waiting', autonomy: 'auto'                       },
      { name: 'close',    state: 'waiting', autonomy: 'auto'                       },
    ],
  },
  {
    id: 'pb-002',
    name: 'Ransomware Containment',
    trigger: 'YARA: ransomware-string OR Sigma: T1486',
    lastRun: '12:02', runCount: 3, status: 'active',
    stages: [
      { name: 'detect',   state: 'done',    autonomy: 'auto',     duration: '0.1s' },
      { name: 'validate', state: 'done',    autonomy: 'auto',     duration: '1.2s' },
      { name: 'contain',  state: 'done',    autonomy: 'approval', duration: '4m2s' },
      { name: 'notify',   state: 'done',    autonomy: 'auto',     duration: '0.2s' },
      { name: 'recover',  state: 'running', autonomy: 'approval'                   },
      { name: 'verify',   state: 'waiting', autonomy: 'auto'                       },
      { name: 'close',    state: 'waiting', autonomy: 'auto'                       },
    ],
  },
  {
    id: 'pb-003',
    name: 'C2 Beacon Auto-Quarantine',
    trigger: 'AI Detection: C2 beacon (60s interval, JA3 match)',
    lastRun: '11:31', runCount: 8, status: 'active',
    stages: [
      { name: 'detect',   state: 'done',    autonomy: 'auto', duration: '0.1s' },
      { name: 'validate', state: 'done',    autonomy: 'auto', duration: '0.4s' },
      { name: 'contain',  state: 'done',    autonomy: 'auto', duration: '0.9s' },
      { name: 'notify',   state: 'done',    autonomy: 'auto', duration: '0.2s' },
      { name: 'recover',  state: 'waiting', autonomy: 'auto'                   },
      { name: 'verify',   state: 'running', autonomy: 'auto'                   },
      { name: 'close',    state: 'waiting', autonomy: 'auto'                   },
    ],
  },
  {
    id: 'pb-004',
    name: 'Lateral Movement Block',
    trigger: 'Sigma: T1021 — non-admin RDP',
    lastRun: '10:58', runCount: 6, status: 'active',
    stages: [
      { name: 'detect',   state: 'done',    autonomy: 'auto',     duration: '0.1s' },
      { name: 'validate', state: 'running', autonomy: 'auto'                       },
      { name: 'contain',  state: 'waiting', autonomy: 'approval'                   },
      { name: 'notify',   state: 'waiting', autonomy: 'auto'                       },
      { name: 'recover',  state: 'waiting', autonomy: 'auto'                       },
      { name: 'verify',   state: 'waiting', autonomy: 'auto'                       },
      { name: 'close',    state: 'waiting', autonomy: 'auto'                       },
    ],
  },
  {
    id: 'pb-005',
    name: 'Patch Compliance Enforcer',
    trigger: 'HYDRA CVE: CVSS ≥ 8.0, unpatched > 72 h',
    lastRun: '—', runCount: 0, status: 'paused',
    stages: [
      { name: 'detect',   state: 'waiting', autonomy: 'auto'     },
      { name: 'validate', state: 'waiting', autonomy: 'auto'     },
      { name: 'contain',  state: 'waiting', autonomy: 'approval' },
      { name: 'notify',   state: 'waiting', autonomy: 'auto'     },
      { name: 'recover',  state: 'waiting', autonomy: 'approval' },
      { name: 'verify',   state: 'waiting', autonomy: 'auto'     },
      { name: 'close',    state: 'waiting', autonomy: 'auto'     },
    ],
  },
];

// ── Approval queue ───────────────────────────────────────────────────────────

export const APPROVAL_QUEUE: ApprovalItem[] = [
  {
    id: 'appr-001', time: '12:47',
    playbook: 'Credential Stuffing Response',
    action: 'Isolate host', target: 'vpn-gw-01',
    rationale: '5 brute-force bursts from 3 distinct IPs in 10 min. T1110 confirmed. Isolating vpn-gw-01 prevents further credential exposure. All other servers remain unaffected.',
    confidence: 94, urgency: 'critical',
  },
  {
    id: 'appr-002', time: '12:03',
    playbook: 'Ransomware Containment',
    action: 'Snapshot & preserve evidence', target: 'LAPTOP-7',
    rationale: 'YARA match + Sigma T1486. LAPTOP-7 shows crypto-locker write patterns on /users share. Snapshot preserves forensic chain before remediation wipes evidence.',
    confidence: 88, urgency: 'high',
  },
  {
    id: 'appr-003', time: '11:02',
    playbook: 'Lateral Movement Block',
    action: 'Micro-segment workstation', target: 'WS-22',
    rationale: 'Non-admin RDP from WS-22 → srv-08 detected. Micro-segmenting WS-22 blocks the lateral path without interrupting other workstations on the same subnet.',
    confidence: 81, urgency: 'medium',
  },
];

// ── AI Agents ────────────────────────────────────────────────────────────────

export const AGENTS: Agent[] = [
  { name: 'Threat Hunter',      role: 'Proactive IOC hunt across Telemetry Fabric',     status: 'active', actions: 42, lastAction: 'Correlated 3 IPs to APT28 campaign'   },
  { name: 'Patch Enforcer',     role: 'Tracks CVE exposure and enforces patch schedule', status: 'active', actions: 12, lastAction: 'Flagged 4 endpoints: CVE-2024-3094'   },
  { name: 'C2 Tracker',         role: 'Identifies and blocks C2 beaconing patterns',    status: 'active', actions: 8,  lastAction: 'Blocked 185.x.x.7 (JA3: f44…)'       },
  { name: 'IOC Correlator',     role: 'Enriches events with MISP/STIX IOC context',     status: 'idle',   actions: 0,  lastAction: 'No events in last 30 min'             },
  { name: 'Compliance Monitor', role: 'Audits controls against CIS/NIST benchmarks',    status: 'paused', actions: 0,  lastAction: 'Paused — pending policy approval'     },
];

// ── Automation analytics ─────────────────────────────────────────────────────

export const ANALYTICS: AnalyticRow[] = [
  { label: 'Playbook success rate', value: '94.2%',   delta: '+2.1% vs last week', tone: 'green'  },
  { label: 'MTTR impact',           value: '−67%',    delta: 'vs manual response', tone: 'green'  },
  { label: 'Auto-applied actions',  value: '84%',     delta: 'of all playbook runs', tone: 'blue' },
  { label: 'False-positive rate',   value: '1.8%',    delta: '−0.4% trend',        tone: 'green'  },
  { label: 'Avg resolution time',   value: '4.2 min', delta: 'p50 · all playbooks', tone: 'blue'  },
  { label: 'Runs today',            value: '47',      delta: '+11 vs yesterday',   tone: 'blue'   },
];
