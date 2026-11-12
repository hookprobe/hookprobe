/**
 * actions — ADR 0053 operator actions from Mission Control (heqk device).
 * Reversible, time-bounded only; the kernel enforces the limits, writes the audit log and checks the
 * Origin, the per-session CSRF token and a strictly increasing sequence number.
 */
import { createSignal } from 'solid-js';
import { fetchJson } from './api';
import { approve } from './approve';

export interface ActiveAction { id: number; kind: string; target: string; expires_in_s: number }
export interface AuditRow { session: string; kind: string; target: string; ttl_s: number; ok: boolean; result: string; reason: string }
export interface ActionsView { active: ActiveAction[]; audit: AuditRow[] }

export const [actionsView, setActionsView] = createSignal<ActionsView | null>(null);

export async function refreshActions(): Promise<void> {
  try { setActionsView(await fetchJson<ActionsView>('/api/actions')); } catch { /* not a heqk device */ }
}

interface Session { csrf: string; next_seq: number; max_ttl_s: number }

/** One guarded owner write (same Origin, per-session CSRF, strictly increasing seq — ADR 0053). */
export async function post<T = { ok: boolean; refused?: string }>(path: string, fields: Record<string, string>): Promise<T> {
  const s = await fetchJson<Session>('/api/session');
  const body = new URLSearchParams({ ...fields, seq: String(s.next_seq) });
  const r = await fetch(path, { method: 'POST', credentials: 'same-origin', headers: { 'X-HQ-CSRF': s.csrf }, body });
  const j = await r.json().catch(() => ({ ok: false, refused: `HTTP ${r.status}` }));
  await refreshActions();
  return j;
}

/** Run one action. `ownerKey` is required for isolate / shield_allow (re-authentication). */
export function runAction(kind: 'ack' | 'hold_ip' | 'isolate' | 'shield_allow' | 'shield_pause', target: string, ttlS: number, reason: string, ownerKey?: string) {
  const f: Record<string, string> = { kind, target, ttl: String(ttlS), reason };
  if (ownerKey) f.owner_key = ownerKey;
  return post('/api/actions', f);
}

export function revokeAction(id: number) {
  return post('/api/actions/revoke', { id: String(id) });
}

/** Ask for a reason (and the owner key when needed), then run. Returns a message for the UI. */
export async function promptAndRun(kind: 'ack' | 'hold_ip' | 'isolate' | 'shield_allow' | 'shield_pause', target: string, ttlS: number): Promise<string> {
  const needsKey = kind === 'isolate' || kind === 'shield_allow' || kind === 'shield_pause';
  const what = { ack: 'Acknowledge', hold_ip: 'Hold the address', isolate: 'Isolate the device', shield_allow: 'Allow through Shield', shield_pause: 'Pause Shield' }[kind];
  const a = await approve({ title: `${what}?`, body: `${target}${ttlS ? ` · for ${Math.round(ttlS / 60)} min, then it ends by itself` : ''}. Recorded in the audit log.`, confirm: what, reason: {}, ...(needsKey ? { key: {} } : {}) });
  if (!a) return 'Cancelled.';
  const r = await runAction(kind, target, ttlS, a.reason, needsKey ? a.key : undefined);
  return r.ok ? (ttlS ? `Done: it ends by itself in ${Math.round(ttlS / 60)} min.` : 'Done.') : `Refused by the device: ${r.refused}`;
}
