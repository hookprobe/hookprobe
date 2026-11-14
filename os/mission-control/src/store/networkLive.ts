/**
 * networkLive — `GET /api/network` (heqk, audit A8): the Get Online pillar's read side — the Wi-Fi
 * and WAN the device actually applied, and which signed file they came from. Read-only by design:
 * changes are made by re-signing WIFI.TXT / WAN.TXT / POLICY.TXT.
 */
import { createSignal } from 'solid-js';
import { fetchJson } from './api';

export interface NetworkView {
  available: boolean;
  wifi?: { ssid: string; source: string; channel: number; width_mhz: number; security: string };
  wan?: { up: boolean; mode: string; ip: string; gateway: string; vlan: number; clients: number };
  ipv6?: { up: boolean; lan_prefix: string };
  management?: { vlan: number; ip: string };
  /** The LAN the device serves (heqk #1140), e.g. { ip: '10.99.0.1', prefix: 24, cidr: '10.99.0.0/24' }. */
  lan?: { ip: string; prefix: number; cidr: string };
  policy?: { state: string; generation: number };
  trust_anchor?: { state: string; key: string; public_key?: string | null };
  changes?: string;
}

export const [networkView, setNetworkView] = createSignal<NetworkView | null>(null);
/** 'absent' = no device answered (preview build); 'live' = the device answered. */
export const [networkState, setNetworkState] = createSignal<'loading' | 'live' | 'absent'>('loading');

async function read(): Promise<void> {
  try {
    setNetworkView(await fetchJson<NetworkView>('/api/network'));
    setNetworkState('live');
  } catch {
    if (networkState() === 'loading') setNetworkState('absent');
  }
}

let timer: ReturnType<typeof setInterval> | null = null;
export function startNetworkLive(): void {
  if (timer) return;
  void read();
  timer = setInterval(() => void read(), 30_000);
}
