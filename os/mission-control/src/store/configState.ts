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
import { approve } from './approve';

export interface ConfigView {
  state: 'none' | 'trial' | 'committed' | 'reverted' | 'refused' | string;
  generation: number; floor: number; on_trial: boolean; window_s: number; elapsed_s: number;
  auto_rollback: boolean; health: string;
  /** Management-plane change: not auto-committed — the owner must Keep it within the window or it reverts. */
  needs_confirm?: boolean;
  /** Live apply (ADR 0059 step 3): what the engine is doing now and how the last trial ended. */
  live?: { phase: 'idle' | 'applying' | 'trial' | 'reverting' | string; changes: string[]; needs_confirm: boolean; window_s: number; remaining_s: number;
    last: { result: 'none' | 'committed' | 'reverted' | 'revert_failed' | string; generation: number }; policy_generation: number; mgmt_ok: boolean | null; mgmt_probe: string | null };
  /** How stored settings are protected (sealed with the device key, or not). */
  at_rest?: { sealed: boolean; secrets_protected: boolean; migrated: number; device_key: boolean; volatile_ram_only: boolean; persisted: boolean };
  envelope?: { owner_enrolled: boolean };
  /** What the bundle in force holds (kernel #1055): a bundle replaces the WHOLE configuration, so an edit re-sends
   *  the sections in force. Secrets are never served, only `<key>_set`. */
  sections?: Record<'wan' | 'wifi' | 'policy', { present: boolean; digest: string | null }>;
  policy_text?: string | null;
  wan_keys?: Record<string, string | boolean> | null;
  wifi_keys?: Record<string, string | boolean> | null;
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
  // The device's own remaining time when it reports one (live trials: 120 s auto-commit, 300 s owner confirm).
  if (v.live && v.live.phase === 'trial') return Math.max(0, Math.round(v.live.remaining_s - (now - configAt()) / 1000));
  return Math.max(0, Math.round(v.window_s - v.elapsed_s - (now - configAt()) / 1000));
}

type Res = { ok: boolean; refused?: string; committed?: boolean; rolled_back?: boolean; generation?: number };
async function act(path: string, ask: string): Promise<string> {
  const keep = path.endsWith('confirm');
  const a = await approve({ title: ask, body: keep ? 'The device keeps these settings as the new last-known-good.' : 'The device goes back to the previous settings.', confirm: keep ? 'Keep' : 'Roll back', destructive: !keep, reason: { default: keep ? 'works for me' : 'does not work' } });
  if (!a) throw new Error('Cancelled.');
  const reason = a.reason;
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

/** How the Wi-Fi / PPPoE passwords inside signed configuration are stored, from the device's own report. */
export function restNote(): string {
  const r = configView()?.at_rest;
  if (!r) return 'The passwords travel inside the signed configuration. This device does not report how it stores them, so they are not confirmed protected at rest.';
  if (r.volatile_ram_only) return 'This device has no device key: the passwords apply, but they are kept only in memory, not after a restart.';
  if (r.secrets_protected && r.device_key) return 'Stored encrypted with a key only this device has, so a copy of its storage cannot be read elsewhere.';
  return 'Stored in clear on this device: anyone holding its storage can read them. Not protected at rest.';
}
