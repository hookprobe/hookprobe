/**
 * actions — ADR 0053 operator actions from Mission Control (heqk device).
 * Reversible, time-bounded only; the kernel enforces the limits, writes the audit log and checks the
 * Origin, the per-session CSRF token and a strictly increasing sequence number.
 */
import { createSignal } from 'solid-js';
import { fetchJson } from './api';

export interface ActiveAction { id: number; kind: string; target: string; expires_in_s: number }
export interface AuditRow { session: string; kind: string; target: string; ttl_s: number; ok: boolean; result: string; reason: string }
export interface ActionsView { active: ActiveAction[]; audit: AuditRow[] }

export const [actionsView, setActionsView] = createSignal<ActionsView | null>(null);

export async function refreshActions(): Promise<void> {
  try { setActionsView(await fetchJson<ActionsView>('/api/actions')); } catch { /* not a heqk device */ }
}

interface Session { csrf: string; next_seq: number; max_ttl_s: number }

async function post(path: string, fields: Record<string, string>): Promise<{ ok: boolean; refused?: string }> {
  const s = await fetchJson<Session>('/api/session');
  const body = new URLSearchParams({ ...fields, seq: String(s.next_seq) });
  const r = await fetch(path, { method: 'POST', credentials: 'same-origin', headers: { 'X-HQ-CSRF': s.csrf }, body });
  const j = await r.json().catch(() => ({ ok: false, refused: `HTTP ${r.status}` }));
  await refreshActions();
  return j;
}

/** Run one action. `ownerKey` is required for isolate / shield_allow (re-authentication). */
export function runAction(kind: 'ack' | 'hold_ip' | 'isolate' | 'shield_allow', target: string, ttlS: number, reason: string, ownerKey?: string) {
  const f: Record<string, string> = { kind, target, ttl: String(ttlS), reason };
  if (ownerKey) f.owner_key = ownerKey;
  return post('/api/actions', f);
}

export function revokeAction(id: number) {
  return post('/api/actions/revoke', { id: String(id) });
}

/** Ask for a reason (and the owner key when needed), then run. Returns a message for the UI. */
export async function promptAndRun(kind: 'ack' | 'hold_ip' | 'isolate' | 'shield_allow', target: string, ttlS: number): Promise<string> {
  const reason = window.prompt(`Reason for ${kind.replace('_', ' ')} on ${target} (recorded in the audit log):`, '');
  if (!reason || reason.trim().length < 3) return 'Cancelled — a reason is required.';
  let key: string | undefined;
  if (kind === 'isolate' || kind === 'shield_allow') {
    key = window.prompt('This action needs your owner key again:', '') ?? undefined;
    if (!key) return 'Cancelled — owner key required.';
  }
  const r = await runAction(kind, target, ttlS, reason.trim(), key);
  return r.ok ? `Done — expires on its own${ttlS ? ` in ${Math.round(ttlS / 60)} min` : ''}.` : `Refused by the device: ${r.refused}`;
}
