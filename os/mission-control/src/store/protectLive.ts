/**
 * protectLive — Protect's read side on heqk:
 *   GET /api/enforcement  who the device is acting against right now (scan sources; all self-revert)
 *   GET /api/intel        the signed IOC pack and the signed DEVICES.TXT policy file
 */
import { createSignal } from 'solid-js';
import { fetchJson } from './api';

export interface EnforcementSource { ip: string; state: 'watching' | 'rate_limited' | 'quarantined'; reason: string; distinct_ports: number; established: number; expires_in_s: number }
export interface EnforcementView { policy: string; sources: EnforcementSource[]; count: number }
export interface IntelView {
  ioc: { file: string; signed: boolean; generation: number; ipv4_prefixes: number; domains: number; skipped_lines: number; mode: string };
  devices: { file: string; signed: boolean; generation: number; entries: number; skipped_lines: number; denied: { internet_only: number; lan_only: number; quarantine: number } };
}

export const [enforcement, setEnforcement] = createSignal<EnforcementView | null>(null);
export const [intel, setIntel] = createSignal<IntelView | null>(null);

export async function refreshProtect(): Promise<void> {
  const [e, i] = await Promise.allSettled([fetchJson<EnforcementView>('/api/enforcement'), fetchJson<IntelView>('/api/intel')]);
  if (e.status === 'fulfilled') setEnforcement(e.value);
  if (i.status === 'fulfilled') setIntel(i.value);
}
