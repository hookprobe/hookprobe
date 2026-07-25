/**
 * obsMock — Observe (§3, Senzorium) Layer-0 mock data.
 *
 * Spec: docs/MissionControl.md §3 — everything entering the platform; the
 * Telemetry Fabric operationally. Sources → normalized events → retention tiers.
 * Drill: flow → session → packets → raw pcap ("detect once, query forever;
 * bounded by storage"). Real values arrive over SSE/WS from Rust/Axum; shapes
 * here are what those feeds will carry.
 */

import type { Tone } from './missionMock';

export type SevLevel = 'critical' | 'high' | 'medium' | 'info';

export interface SourceEntry {
  name: string;
  countLabel: string;
  pct: number;
  tone: Tone;
}

export interface LiveEvent {
  time: string;
  source: string;
  type: string;
  host: string;
  sev: SevLevel;
}

export interface RetentionTier {
  name: string;
  window: string;
  fill: number;   /* percentage 0–100 */
  tone: Tone;
  note: string;
}

export interface AssetGroup {
  os: string;
  countLabel: string;
  barPct: number;
  tone: Tone;
  delta?: string;
}

export interface Kpi { label: string; value: string; tone: Tone }

export const KPIS: Kpi[] = [
  { label: 'Events · sec',     value: '48,230',  tone: 'blue'   },
  { label: 'Active sources',   value: '127',     tone: 'green'  },
  { label: 'Retention window', value: '21 days', tone: 'purple' },
  { label: 'Dropped',          value: '0.02%',   tone: 'grey'   },
];

export const SOURCES: SourceEntry[] = [
  { name: 'Endpoints', countLabel: '1,284,521', pct: 100, tone: 'blue'   },
  { name: 'Network',   countLabel: '892,403',   pct: 69,  tone: 'blue'   },
  { name: 'DNS',       countLabel: '312,885',   pct: 24,  tone: 'green'  },
  { name: 'HTTP',      countLabel: '204,119',   pct: 16,  tone: 'purple' },
  { name: 'Syslog',    countLabel: '98,744',    pct: 8,   tone: 'amber'  },
  { name: 'NetFlow',   countLabel: '76,312',    pct: 6,   tone: 'blue'   },
  { name: 'Packets',   countLabel: '24,581',    pct: 2,   tone: 'grey'   },
];

export const LIVE_EVENTS: LiveEvent[] = [
  { time: '12:47:03', source: 'Endpoint', type: 'Process/exec',    host: 'LAPTOP-7',     sev: 'medium'   },
  { time: '12:47:01', source: 'Network',  type: 'Conn/outbound',   host: 'Marketing-12', sev: 'info'     },
  { time: '12:46:58', source: 'DNS',      type: 'Query/NXDOMAIN',  host: 'IoT-Cam-3',    sev: 'high'     },
  { time: '12:46:55', source: 'HTTP',     type: 'Request/POST',    host: 'Guest-Phone',  sev: 'info'     },
  { time: '12:46:52', source: 'Syslog',   type: 'Auth/sudo',       host: 'srv-08',       sev: 'medium'   },
  { time: '12:46:49', source: 'NetFlow',  type: 'Flow/lateral',    host: 'WS-22',        sev: 'high'     },
  { time: '12:46:47', source: 'Endpoint', type: 'File/write',      host: 'DC-01',        sev: 'critical' },
  { time: '12:46:44', source: 'Network',  type: 'Conn/inbound',    host: 'vpn-gw-01',   sev: 'info'     },
  { time: '12:46:41', source: 'DNS',      type: 'Query/A',         host: 'LAPTOP-7',     sev: 'info'     },
  { time: '12:46:38', source: 'Syslog',   type: 'Auth/fail',       host: 'WS-14',        sev: 'medium'   },
];

export const RETENTION_TIERS: RetentionTier[] = [
  { name: 'pcap',   window: '4 hours', fill: 87, tone: 'amber', note: 'Raw packets · 1.2 TB / 1.4 TB' },
  { name: 'events', window: '21 days', fill: 62, tone: 'blue',  note: 'Normalized events · 284 GB / 458 GB' },
  { name: 'alerts', window: '90 days', fill: 34, tone: 'green', note: 'Alerts + evidence · 68 GB / 200 GB' },
];

export const ASSET_GROUPS: AssetGroup[] = [
  { os: 'Windows',    countLabel: '312',   barPct: 100, tone: 'blue',   delta: '+2' },
  { os: 'Linux',      countLabel: '89',    barPct: 29,  tone: 'green',  delta: '+1' },
  { os: 'macOS',      countLabel: '47',    barPct: 15,  tone: 'purple' },
  { os: 'IoT',        countLabel: '203',   barPct: 65,  tone: 'amber',  delta: '+5' },
  { os: 'Containers', countLabel: '1,284', barPct: 88,  tone: 'blue'   },
];
