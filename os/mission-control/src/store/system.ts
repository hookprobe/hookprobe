/**
 * system — GET /api/system (heqk, owner session): the OS version and build, the boot slot and whether it is on trial,
 * the image security version, and storage. Older images do not serve it (404): the view stays null and the screens say
 * "not reported". Nulls from the device (e.g. QEMU has no storage) are shown as not reported, never filled in.
 */
import { createSignal } from 'solid-js';
import { fetchJson } from './api';

export interface SystemView {
  version: string | null; build: string; slot: 'A' | 'B'; trial: boolean; svn: number;
  storage: { used: number; total: number; retention_days: number | null } | null;
}

export const [systemView, setSystemView] = createSignal<SystemView | null>(null);

export async function refreshSystem(): Promise<void> {
  try { setSystemView(await fetchJson<SystemView>('/api/system')); } catch { setSystemView(null); }
}

/** "1.2 GB of 7.3 GB" (decimal units, as storage is sold). */
export function bytesOf(used: number, total: number): string {
  const g = (b: number) => (b >= 1e9 ? `${(b / 1e9).toFixed(1)} GB` : `${Math.round(b / 1e6)} MB`);
  return `${g(used)} of ${g(total)}`;
}
