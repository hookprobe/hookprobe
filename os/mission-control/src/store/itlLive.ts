/**
 * itlLive — Intelligence (§8, HYDRA) real-data layer for the EXPLOITABILITY surface (ADR 0024):
 * `GET /api/exploitability`. This is the first real backing for the Intelligence workspace's CVE
 * board — the honest replacement for `itlMock.ts`'s hard-coded `CVES`/`KPIS`.
 *
 * Mirrors `detectLive.ts`'s fetch-and-be-honest-about-status pattern: a real `loading` / `live` /
 * `error` state, never a silent fallback to the static demo list. The rest of the Intelligence
 * workspace (IOC feeds, threat actors, campaigns) has NO backing read-API endpoint yet, so those
 * panels legitimately keep rendering `itlMock.ts` values, labelled "mock" — only the CVE/
 * exploitability board goes live here.
 *
 * Each row carries the full VEX+SSVC assessment: `status` (affected / not_affected /
 * under_investigation), `justification` (e.g. `vulnerable_code_not_in_execute_path` — the
 * capability-grounded differentiator), `ssvc` (act / attend / track / defer), `epss`, `exposed`.
 */

import { createSignal } from 'solid-js';
import { fetchJson } from './api';

export type LiveStatus = 'loading' | 'live' | 'error';

export interface ExploitFinding {
  cve: string;
  component: string;
  component_version: string;
  summary: string;
  published: string;
  cvss: number;
  epss: number;
  kev: boolean;
  status: 'affected' | 'not_affected' | 'under_investigation' | 'fixed';
  justification: string;
  impact_statement: string;
  ssvc: 'act' | 'attend' | 'track' | 'defer';
  exploitation: 'active' | 'poc' | 'none';
  exposed: boolean;
  reason: string;
  fixed_version: string;
}

export interface ExploitSummary {
  act: number;
  attend: number;
  affected: number;
  not_affected: number;
  under_investigation: number;
  total: number;
}

interface ExploitResponse {
  summary: ExploitSummary;
  findings: ExploitFinding[];
}

export const [exploitFindings, setExploitFindings] = createSignal<ExploitFinding[]>([]);
export const [exploitSummary, setExploitSummary] = createSignal<ExploitSummary | null>(null);
export const [exploitStatus, setExploitStatus] = createSignal<LiveStatus>('loading');
export const [exploitError, setExploitError] = createSignal<string | null>(null);

async function refetch(): Promise<void> {
  try {
    const res = await fetchJson<ExploitResponse>('/api/exploitability?limit=200');
    setExploitFindings(res.findings ?? []);
    setExploitSummary(res.summary ?? null);
    setExploitStatus('live');
    setExploitError(null);
  } catch (e) {
    setExploitStatus('error');
    setExploitError(e instanceof Error ? e.message : String(e));
  }
}

let started = false;

/** Call once from `IntelligenceApp`'s `onMount`. Idempotent. */
export function startItlLive(): void {
  if (started) return;
  started = true;
  void refetch();
  // Exploitability is regenerated on the pipeline's daily timer, not a live stream — a periodic
  // re-poll keeps the board fresh without a firehose.
  setInterval(() => void refetch(), 5 * 60 * 1000);
}
