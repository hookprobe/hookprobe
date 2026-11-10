/**
 * anchor — who the device trusts for signed configuration (GET /api/anchor; ADR 0058 D3).
 *   vendor_key   the image's compiled operator key (verifies the factory boot files)
 *   owner_key    the owner's enrolled key: once set, WAN / WIFI / POLICY uploads must be signed by it
 *   can          "enroll" (no owner key yet) | "rotate"
 * Enroll and rotate are permanent: owner key re-authentication, plus a proof by the new key.
 */
import { createSignal } from 'solid-js';
import { fetchJson } from './api';
import { post } from './actions';

export interface AnchorView {
  vendor_key: string | null; owner_key: string | null; owner_enrolled: boolean; owner_generation: number;
  config_files_verified_by: string; can: 'enroll' | 'rotate' | string;
  /** Newer images: whether the device refuses unsigned configuration, and the per-file generation floors. */
  config_protected?: boolean; state?: 'protected' | 'CONFIG UNPROTECTED' | string;
  floors?: Partial<Record<'wan' | 'wifi' | 'policy', { current: number; floor: number }>>;
}
export const [anchorView, setAnchorView] = createSignal<AnchorView | null>(null);
/** 'absent' = this device does not serve /api/anchor (older image). */
export const [anchorState, setAnchorState] = createSignal<'unknown' | 'ok' | 'absent'>('unknown');

export async function refreshAnchor(): Promise<void> {
  try { setAnchorView(await fetchJson<AnchorView>('/api/anchor')); setAnchorState('ok'); }
  catch (e) { if (e instanceof Error && / HTTP 404$/.test(e.message)) setAnchorState('absent'); }
}

type Res = { ok: boolean; refused?: string; note?: string; owner_generation?: number };
export async function enroll(f: { public_key: string; proof: string; owner_key: string }): Promise<Res> {
  const r = await post<Res>('/api/anchor/enroll', f); await refreshAnchor(); return r;
}
export async function rotate(f: { public_key: string; proof: string; generation: string; signature: string; owner_key: string }): Promise<Res> {
  const r = await post<Res>('/api/anchor/rotate', f); await refreshAnchor(); return r;
}
