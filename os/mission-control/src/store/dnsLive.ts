/**
 * dnsLive — Shield v2 live data from the device (`GET /api/dns`, ADR 0052 D7).
 * Polled every 10 s; stays null when the API is absent (dev box / Linux tier) so the page keeps
 * its sample layout there. Nothing here is invented: every number is the device's.
 */
import { createSignal } from 'solid-js';
import { fetchJson } from './api';

export interface DnsLists {
  blocked_domains: number; allowed_domains: number;
  block_file: 'none' | 'loaded' | 'refused'; allow_file: 'none' | 'loaded' | 'refused';
  signed: boolean; generation: number; skipped_lines: number; truncated: number; refused: string | null;
}
export interface DnsTop { name: string; count: number; max_overcount: number }
export interface DnsClient { ip: string; queries: number; blocked: number; bypass: number; last_bypass?: string }
export interface DnsRecent { ts: number; client: string; qtype: number; name: string; verdict: string }
export interface DnsLive {
  lists: DnsLists;
  policy: { encrypted_dns: 'block' | 'allow'; private_relay: 'block' | 'report' };
  counters: Record<string, number>;
  top_blocked: DnsTop[];
  clients: DnsClient[];
  recent: DnsRecent[];
  recent_count: number;
}

export const [dnsLive, setDnsLive] = createSignal<DnsLive | null>(null);

async function read(): Promise<void> {
  try {
    setDnsLive(await fetchJson<DnsLive>('/api/dns?limit=100'));
  } catch {
    /* no device API: keep null */
  }
}

let timer: ReturnType<typeof setInterval> | null = null;
export function startDnsLive(): void {
  if (timer) return;
  void read();
  timer = setInterval(() => void read(), 10_000);
}

/** Human labels for verdicts. */
export const VERDICT_LABEL: Record<string, string> = {
  allowed: 'allowed', floor: 'always allowed', 'allow-rule': 'allowed by rule', blocked: 'blocked',
  'blocked-cname': 'blocked (hidden tracker)', ddr: 'encrypted-DNS discovery answered', canary: 'browser DoH switched off',
  'relay-seen': 'Private Relay in use', 'relay-blocked': 'Private Relay blocked', 'doh-seen': 'DoH resolver in use',
  'doh-blocked': 'DoH resolver blocked', 'dot-refused': 'DNS-over-TLS refused', 'tcp53-refused': 'blocked (DNS over TCP)',
};

export const QTYPE: Record<number, string> = { 1: 'A', 28: 'AAAA', 5: 'CNAME', 12: 'PTR', 15: 'MX', 16: 'TXT', 33: 'SRV', 64: 'SVCB', 65: 'HTTPS', 0: '—' };
