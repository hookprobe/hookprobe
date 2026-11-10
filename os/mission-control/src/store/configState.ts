/**
 * configState — the device's configuration trial (cfgd, ADR 0059 Step 3; GET /api/config).
 *   none | trial | committed | reverted | refused
 * A signed configuration BUNDLE (upload type "config") starts a trial at the next boot: the device commits it
 * once the internet works, or reverts it and restarts after `window_s` (or on a second boot while pending).
 * `auto_rollback` comes from the device; the UI only promises a rollback when the device says it does one.
 * Per-file WAN / WIFI / POLICY uploads never get this — they stay until rolled back by hand.
 */
import { createSignal } from 'solid-js';
import { fetchJson } from './api';
import { post } from './actions';

export interface ConfigView {
  state: 'none' | 'trial' | 'committed' | 'reverted' | 'refused' | string;
  generation: number; floor: number; on_trial: number | null; window_s: number; elapsed_s: number;
  auto_rollback: boolean; health: string;
  /** Management-plane change: not auto-committed — the owner must Keep it within the window or it reverts. */
  needs_confirm?: boolean;
}
export const [configView, setConfigView] = createSignal<ConfigView | null>(null);
/** When the last answer arrived (ms), to count the trial window down between polls. */
export const [configAt, setConfigAt] = createSignal(0);

export async function refreshConfig(): Promise<void> {
  try { setConfigView(await fetchJson<ConfigView>('/api/config')); setConfigAt(Date.now()); } catch { /* not served: no cfgd */ }
}

/** Seconds left in the trial window, counted locally from the last answer. */
export function secondsLeft(now: number): number {
  const v = configView();
  if (!v || v.state !== 'trial') return 0;
  return Math.max(0, Math.round(v.window_s - v.elapsed_s - (now - configAt()) / 1000));
}

type Res = { ok: boolean; refused?: string; committed?: boolean; rolled_back?: boolean; generation?: number };
async function act(path: string, ask: string): Promise<string> {
  const reason = window.prompt(`${ask} Reason (kept in the journal):`, path.endsWith('confirm') ? 'works for me' : 'does not work');
  if (!reason || reason.trim().length < 3) throw new Error('Cancelled: a reason of at least 3 characters is required.');
  const key = window.prompt('Enter your owner key:', '');
  if (!key) throw new Error('Cancelled: the owner key is required.');
  const r = await post<Res>(path, { reason: reason.trim(), permanent: 'true', owner_key: key });
  await refreshConfig();
  if (!r.ok) throw new Error(`The device refused: ${r.refused}`);
  return path.endsWith('confirm') ? `Kept: configuration generation ${r.generation} is now committed.` : `Rolled back from generation ${r.generation}. The device restarts with the previous configuration.`;
}
export const confirmConfig = () => act('/api/config/confirm', 'Keep this configuration?');
export const rollbackConfig = () => act('/api/config/rollback', 'Go back to the previous configuration? The device restarts.');
