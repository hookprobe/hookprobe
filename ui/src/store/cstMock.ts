/**
 * cstMock — Customers (§9) Layer-0 mock data.
 *
 * Spec: docs/MissionControl.md §9 — recursive multi-tenant portal.
 * AWS-Organizations-style: HookProbe → MSSP → Customer → Customer …
 * Unlimited depth, hard per-tenant isolation, cloud-linked only.
 *
 * Real values arrive over SSE/WS from Rust/Axum (ADR 0001); shapes here are
 * what those feeds will carry. Customer type imported from missionMock so both
 * surfaces share a single definition.
 */

import type { Tone } from './missionMock';

// ── KPI row ─────────────────────────────────────────────────────────────────

export interface Kpi { label: string; value: string; tone: Tone }

export const KPIS: Kpi[] = [
  { label: 'Total Managed', value: '52',  tone: 'blue'   },
  { label: 'Healthy',       value: '44',  tone: 'green'  },
  { label: 'Warning',       value: '6',   tone: 'amber'  },
  { label: 'Critical',      value: '2',   tone: 'red'    },
  { label: 'Avg QSecBit',   value: '82',  tone: 'green'  },
];

// ── Managed customers (extended) ─────────────────────────────────────────────

export type TierLabel       = 'Enterprise' | 'Business' | 'Starter';
export type CustomerStatus  = 'Healthy' | 'Warning' | 'Critical';

export interface ManagedCustomer {
  name: string; score: number; tone: Tone;
  endpoints: string; drift: number;
  compliance: string; sla: string;
  tier: TierLabel; region: string;
  status: CustomerStatus; subTenants: number;
}

export const MANAGED: ManagedCustomer[] = [
  { name: 'Vodafone',         score: 91, tone: 'green', endpoints: '21,887', drift: 0,  compliance: '100%', sla: '99.9%', tier: 'Enterprise', region: 'EU-West',  status: 'Healthy',  subTenants: 3 },
  { name: 'Globex Corp',      score: 88, tone: 'green', endpoints: '8,420',  drift: 2,  compliance: '98%',  sla: '99.7%', tier: 'Enterprise', region: 'US-East',  status: 'Healthy',  subTenants: 0 },
  { name: 'Initech',          score: 76, tone: 'amber', endpoints: '3,456',  drift: 5,  compliance: '92%',  sla: '98.7%', tier: 'Business',   region: 'EU-North', status: 'Warning',  subTenants: 1 },
  { name: 'Stark Industries', score: 64, tone: 'amber', endpoints: '12,004', drift: 7,  compliance: '87%',  sla: '97.1%', tier: 'Enterprise', region: 'US-West',  status: 'Warning',  subTenants: 2 },
  { name: 'Soylent Corp',     score: 28, tone: 'red',   endpoints: '1,023',  drift: 12, compliance: '62%',  sla: '91.3%', tier: 'Starter',    region: 'APAC',     status: 'Critical', subTenants: 0 },
];

// ── Tenant inheritance tree ──────────────────────────────────────────────────
// Recursive: each MSSP node can itself have children (unlimited depth).

export interface TenantNode {
  id: string; name: string; score: number; tone: Tone;
  role: 'mssp' | 'customer';
  children?: TenantNode[];
}

export const TENANT_TREE: TenantNode = {
  id: 'root', name: 'HookProbe OS (You)', score: 91, tone: 'green', role: 'mssp',
  children: [
    {
      id: 'vodafone', name: 'Vodafone', score: 91, tone: 'green', role: 'mssp',
      children: [
        { id: 'vodafone-uk', name: 'Vodafone UK',     score: 93, tone: 'green', role: 'customer' },
        { id: 'vodafone-de', name: 'Vodafone DE',     score: 89, tone: 'green', role: 'customer' },
        { id: 'vodafone-es', name: 'Vodafone ES',     score: 88, tone: 'green', role: 'customer' },
      ],
    },
    { id: 'globex', name: 'Globex Corp', score: 88, tone: 'green', role: 'customer' },
    {
      id: 'initech', name: 'Initech', score: 76, tone: 'amber', role: 'mssp',
      children: [
        { id: 'initech-emea', name: 'Initech EMEA',   score: 74, tone: 'amber', role: 'customer' },
      ],
    },
    {
      id: 'stark', name: 'Stark Industries', score: 64, tone: 'amber', role: 'mssp',
      children: [
        { id: 'stark-eu',   name: 'SI Europe',        score: 71, tone: 'amber', role: 'customer' },
        { id: 'stark-asia', name: 'SI Asia Pacific',  score: 58, tone: 'amber', role: 'customer' },
      ],
    },
    { id: 'soylent', name: 'Soylent Corp', score: 28, tone: 'red', role: 'customer' },
  ],
};

// ── SLA / Compliance ─────────────────────────────────────────────────────────

export interface SlaEntry {
  name: string; target: string; actual: string; met: boolean; pct: number;
}

export const SLA_ENTRIES: SlaEntry[] = [
  { name: 'Vodafone',         target: '99.9%', actual: '99.9%', met: true,  pct: 100 },
  { name: 'Globex Corp',      target: '99.5%', actual: '99.7%', met: true,  pct: 100 },
  { name: 'Initech',          target: '99.0%', actual: '98.7%', met: false, pct:  87 },
  { name: 'Stark Industries', target: '99.0%', actual: '97.1%', met: false, pct:  60 },
  { name: 'Soylent Corp',     target: '98.0%', actual: '91.3%', met: false, pct:  22 },
];

export const SLA_SUMMARY = {
  overall: '99.4%', met: 48, total: 52, breached: 2, atRisk: 2,
};
