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
import { postSigned, MSG } from './envelope';

export interface ConfigView {
  state: 'none' | 'trial' | 'committed' | 'reverted' | 'refused' | string;
  generation: number; floor: number; on_trial: boolean; window_s: number; elapsed_s: number;
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
  // R6 = D: authorised by an HQMGMT1 envelope signed with this browser's (enrolled) key, bound to the bundle in
  // force — the generation and digest come from the same GET /api/config read. The owner token is not used.
  const confirm = path.endsWith('confirm');
  const r = await postSigned<Res & { ok: boolean }>(path, { reason: reason.trim(), permanent: 'true' },
    (e) => ({ msg: confirm ? MSG.CFG_CONFIRM : MSG.CFG_ROLLBACK, generation: e.generation, digest: e.digest }));
  await refreshConfig();
  if (!r.ok) throw new Error(`The device refused: ${r.refused}`);
  return confirm ? `Kept: configuration generation ${r.generation} is now committed.` : `Rolled back: the device is going back to the previous configuration (from generation ${r.generation}).`;
}
export const confirmConfig = () => act('/api/config/confirm', 'Keep this configuration?');
export const rollbackConfig = () => act('/api/config/rollback', 'Go back to the previous configuration? The device restarts.');
