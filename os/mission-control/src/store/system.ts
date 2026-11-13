/**
 * system — GET /api/system (heqk, owner session): the OS version and build, the boot slot and whether it is on trial,
 * the image security version, and storage. Older images do not serve it (404): the view stays null and the screens say
 * "not reported". Nulls from the device (e.g. QEMU has no storage) are shown as not reported, never filled in.
 */
import { createSignal } from 'solid-js';
import { fetchJson } from './api';

/** Shape per docs/design/mgmt-envelope-api.md (kernel #1108): version is always null today (the build id is the
 *  identifier); slot / trial without the factory A/B layout, svn without HBoot, used / total without a DataVolume are
 *  null; retention_days is null (the evidence log is a ring, not a time window). */
export interface SystemView {
  version: string | null; build: string | null; slot: 'A' | 'B' | null; trial: boolean | null; svn: number | null;
  storage: { used: number | null; total: number | null; retention_days: number | null } | null;
}

export const [systemView, setSystemView] = createSignal<SystemView | null>(null);

export async function refreshSystem(): Promise<void> {
  try { setSystemView(await fetchJson<SystemView>('/api/system')); } catch { setSystemView(null); }
}

/** "1.2 GB of 7.3 GB" (decimal units, as storage is sold). */
export function bytesOf(used: number, total: number): string {
  // small amounts in B / KB: a fresh flash uses 512 B (the evidence-log superblock), which "0 MB" made look empty or broken
  const g = (b: number) => (b >= 1e9 ? `${(b / 1e9).toFixed(1)} GB` : b >= 1e6 ? `${Math.round(b / 1e6)} MB` : b >= 1e3 ? `${Math.round(b / 1e3)} KB` : `${b} B`);
  return `${g(used)} of ${g(total)}`;
}
