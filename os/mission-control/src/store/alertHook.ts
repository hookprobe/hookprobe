/**
 * alertHook — heqk `/api/alert-hook`: where the device sends alerts (ntfy, Gotify or JSON webhook).
 * GET is the status; POST op=set|remove is a durable owner write (reason + permanent + owner key).
 */
import { createSignal } from 'solid-js';
import { fetchJson } from './api';
import { post } from './actions';

export interface AlertHookView {
  configured: boolean;
  target?: string; format?: string; path?: string; min_severity?: number;
  sent: number; failed: number; held_back: number; queued: number; last_status: number; max_per_hour: number;
}
export interface AlertHookSettings { ip: string; port: number; format: 'ntfy' | 'gotify' | 'json'; path: string; secret: string; min_severity: 'critical' | 'high' | 'medium' | 'low' }

export const [alertHook, setAlertHook] = createSignal<AlertHookView | null>(null);
export const SEVERITY = ['', 'critical', 'high', 'medium', 'low'];

export async function refreshAlertHook(): Promise<void> {
  try { setAlertHook(await fetchJson<AlertHookView>('/api/alert-hook')); } catch { /* not a heqk device */ }
}

/** Durable write: asks for a reason and the owner key. Returns a message for the UI. */
export async function saveAlertHook(s: AlertHookSettings | null): Promise<string> {
  const reason = window.prompt(s ? 'Reason for this alert destination (kept in the journal):' : 'Reason for removing the alert destination:', '');
  if (!reason || reason.trim().length < 3) return 'Cancelled: a reason of at least 3 characters is required.';
  const key = window.prompt('This is a permanent change. Enter your owner key:', '');
  if (!key) return 'Cancelled: the owner key is required.';
  const f: Record<string, string> = s
    ? { op: 'set', ip: s.ip, port: String(s.port), format: s.format, path: s.path, secret: s.secret, min_severity: s.min_severity, reason: reason.trim(), permanent: 'true', owner_key: key }
    : { op: 'remove', reason: reason.trim(), permanent: 'true', owner_key: key };
  const r = await post<{ ok: boolean; seq?: number; refused?: string }>('/api/alert-hook', f);
  await refreshAlertHook();
  if (!r.ok) return `Refused by the device: ${r.refused}`;
  const v = alertHook();
  if (s && v?.configured) return `Saved and read back: alerts go to ${v.target} (${v.format}).`;
  if (!s && v && !v.configured) return 'Removed. The device no longer sends alerts.';
  return 'The device accepted the change but did not report it back yet.';
}
