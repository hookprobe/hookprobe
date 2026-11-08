/**
 * tlsLive — the device's passive TLS view (`GET /api/tls`): per client, the JA4 fingerprint of each TLS
 * client program it runs and the server names (SNI) it asked for, with the two flags the IDS raises on them:
 * `ioc` (rule 125, the fingerprint is on the signed IOC pack) and `shield_bypass` (rule 126, TLS to a name
 * Shield blocks — the DNS answer came from somewhere else). IPv6 clients carry their device's IPv4 `lease`.
 * Nothing is invented here; on a dev box without the API the list just stays empty.
 */
import { createSignal } from 'solid-js';
import { fetchJson } from './api';

export interface TlsClient {
  client: string; lease?: string; ja4: string; sni: string;
  count: number; last_ms: number; ioc: boolean; shield_bypass: boolean;
}
export const [tlsClients, setTlsClients] = createSignal<TlsClient[]>([]);

export async function refetchTls(): Promise<void> {
  try {
    const r = await fetchJson<{ hellos: number; clients: TlsClient[] }>('/api/tls');
    setTlsClients(r.clients ?? []);
  } catch {
    /* keep the last view — the device inventory carries its own status */
  }
}

/** One device's TLS summary: rows whose client (or, for IPv6, lease) is this device's IPv4 address. */
export function tlsFor(ip: string): { fingerprints: number; names: string[]; ioc: TlsClient[]; bypass: TlsClient[] } {
  const rows = tlsClients().filter((t) => t.client === ip || t.lease === ip);
  const names = [...new Set(rows.map((t) => t.sni).filter(Boolean))];
  return {
    fingerprints: new Set(rows.map((t) => t.ja4)).size,
    names,
    ioc: rows.filter((t) => t.ioc),
    bypass: rows.filter((t) => t.shield_bypass),
  };
}
