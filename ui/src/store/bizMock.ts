/**
 * bizMock — Business (§10) Layer-0 mock data.
 *
 * Spec: docs/MissionControl.md §10 — run the commercial side inside the platform.
 * Panels: KPI row (MRR, active licenses, AI cost/mo, SLA, margin); Revenue & Costs
 * (stacked monthly bars + margin sparkline); Licenses (by tier/customer, seats used);
 * Marketplace (signed module catalog); AI Cost per tenant/workspace.
 * Cloud-linked / self-hosted only for full view; standalone shows licensing only.
 *
 * Real values will arrive over SSE/WS from Rust/Axum (ADR 0001).
 */

import type { Tone } from './missionMock';

export type Tier = 'community' | 'professional' | 'enterprise';

// ── KPIs ─────────────────────────────────────────────────────────────────────

export interface BizKpi { label: string; value: string; tone: Tone; delta?: string }
export const KPIS: BizKpi[] = [
  { label: 'MRR',             value: '$124,800', tone: 'green',  delta: '+8.3%' },
  { label: 'Active Licenses', value: '412',      tone: 'blue' },
  { label: 'AI Cost / mo',    value: '$3,280',   tone: 'amber',  delta: '+12%' },
  { label: 'Avg SLA',         value: '99.94%',   tone: 'green' },
  { label: 'Gross Margin',    value: '71.4%',    tone: 'green',  delta: '+2pp' },
];

// ── Revenue & Costs — trailing 12 months ─────────────────────────────────────

export interface MonthBucket { month: string; revenue: number; cost: number }
export const REVENUE_COSTS: MonthBucket[] = [
  { month: 'Jul', revenue:  98000, cost: 31000 },
  { month: 'Aug', revenue: 102400, cost: 32100 },
  { month: 'Sep', revenue: 107200, cost: 33800 },
  { month: 'Oct', revenue: 109600, cost: 34200 },
  { month: 'Nov', revenue: 111000, cost: 33600 },
  { month: 'Dec', revenue: 108800, cost: 32900 },
  { month: 'Jan', revenue: 112400, cost: 34500 },
  { month: 'Feb', revenue: 115200, cost: 34900 },
  { month: 'Mar', revenue: 118600, cost: 35200 },
  { month: 'Apr', revenue: 120800, cost: 35600 },
  { month: 'May', revenue: 122400, cost: 35800 },
  { month: 'Jun', revenue: 124800, cost: 35900 },
];

// ── Licenses — by tier / customer ────────────────────────────────────────────

export interface License {
  customer: string; tier: Tier;
  seatsUsed: number; seatsTotal: number; renewal: string;
}
export const LICENSES: License[] = [
  { customer: 'Vodafone',         tier: 'enterprise',   seatsUsed: 21800, seatsTotal: 25000, renewal: '2025-12-01' },
  { customer: 'Globex Corp',      tier: 'enterprise',   seatsUsed:  8200, seatsTotal: 10000, renewal: '2025-11-15' },
  { customer: 'Initech',          tier: 'professional', seatsUsed:  3200, seatsTotal:  5000, renewal: '2026-02-01' },
  { customer: 'Stark Industries', tier: 'professional', seatsUsed: 11800, seatsTotal: 12000, renewal: '2025-10-30' },
  { customer: 'Soylent Corp',     tier: 'community',    seatsUsed:   990, seatsTotal:  1000, renewal: '2026-01-01' },
];

// ── Marketplace — signed module catalog ──────────────────────────────────────

export interface MarketModule {
  name: string; description: string; version: string;
  installs: number; price: string;
  signed: boolean; runtime: 'wasm' | 'container'; category: string;
}
export const MODULES: MarketModule[] = [
  { name: 'NAPSE Core',         description: 'Suricata + YARA + Sigma engine bundle',      version: '2.4.1', installs: 892, price: 'free',   signed: true, runtime: 'wasm',      category: 'Detection' },
  { name: 'HYDRA Threat Feeds', description: 'STIX/TAXII + MISP + CVE pipeline',           version: '1.9.0', installs: 647, price: '$29/mo', signed: true, runtime: 'container', category: 'Intelligence' },
  { name: 'AI Anomaly Detect',  description: 'WASI-NN behavioral baseline + predictor',    version: '1.2.3', installs: 543, price: '$49/mo', signed: true, runtime: 'wasm',      category: 'AI' },
  { name: 'PQC Key Manager',    description: 'ML-DSA + ML-KEM hybrid key lifecycle',       version: '0.8.1', installs: 421, price: 'free',   signed: true, runtime: 'wasm',      category: 'Security' },
  { name: 'SIEM Egress',        description: 'Splunk / Elastic / Sentinel push connector', version: '3.1.2', installs: 318, price: '$19/mo', signed: true, runtime: 'container', category: 'Integration' },
];

// ── AI Cost — per tenant / workspace ─────────────────────────────────────────

export interface AiCostRow {
  tenant: string; workspace: string; model: string;
  tokens: string; cost: number;
}
export const AI_COSTS: AiCostRow[] = [
  { tenant: 'Vodafone',         workspace: 'Investigate', model: 'llama-3.1-70b', tokens: '18.4M', cost: 1240 },
  { tenant: 'Globex Corp',      workspace: 'Intelligence', model: 'gpt-4o',        tokens:  '6.2M', cost:  680 },
  { tenant: 'Stark Industries', workspace: 'Automate',    model: 'claude-haiku',  tokens:  '9.8M', cost:  540 },
  { tenant: 'Initech',          workspace: 'Investigate', model: 'llama-3.1-8b',  tokens:  '4.1M', cost:  210 },
  { tenant: 'Internal',         workspace: 'AI Copilot',  model: 'llama-3.1-70b', tokens:  '2.1M', cost:  142 },
  { tenant: 'Soylent Corp',     workspace: 'Detect',      model: 'llama-3.1-8b',  tokens:  '1.2M', cost:   68 },
];
