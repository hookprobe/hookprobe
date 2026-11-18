/**
 * ownerRules — ADR 0055 durable owner rules (heqk `/api/owner-rules`): the operator's own changes on
 * top of the signed baseline, kept in the sealed journal.
 *
 *   kinds: device_policy (a device's zone, by MAC) · shield_profile (by MAC) · shield_allow /
 *          shield_block (by domain)
 *
 * The plan-as-diff flow (FR-08) maps onto it exactly:
 *   preview  → POST dry_run=1 (nothing written) → PlanDiff lines (before → after, shadowed_by)
 *   approve  → POST permanent=true + owner_key re-authentication → journal seq        = Staged
 *   verify   → GET: the rule exists and is `effective`, not `shadowed_by` a pinned signed line
 *              → Applied and verified, or Failed with the device's own reason
 */
import { createSignal } from 'solid-js';
import { fetchJson } from './api';
import { post } from './actions';
import { approve } from './approve';
import type { ApplyUpdate, DiffLine } from '../components/PlanDiff';

export type OwnerKind = 'device_policy' | 'shield_profile' | 'shield_allow' | 'shield_block' | 'device_label';
export interface OwnerRule { seq: number; kind: OwnerKind | string; target: string; value: string; effective: boolean; shadowed_by: string | null }
export interface OwnerRulesView {
  persistent: boolean;
  journal: { records: number; damaged: boolean; full: boolean };
  rules: OwnerRule[];
  refused: { ms: number; session: string; why: string }[];
}
export interface OwnerChange { op: 'set' | 'remove'; kind: OwnerKind; target: string; value?: string }
interface Outcome { ok: boolean; seq?: number; dry_run?: boolean; before?: string; after?: string; shadowed_by?: string | null; refused?: string }

export const [ownerRules, setOwnerRules] = createSignal<OwnerRulesView | null>(null);

export async function refreshOwnerRules(): Promise<OwnerRulesView | null> {
  try {
    const v = await fetchJson<OwnerRulesView>('/api/owner-rules');
    setOwnerRules(v);
    return v;
  } catch {
    return null;
  }
}

function fields(c: OwnerChange, reason: string): Record<string, string> {
  const f: Record<string, string> = { op: c.op, kind: c.kind, target: c.target, reason };
  if (c.value) f.value = c.value;
  return f;
}

export const KIND_LABEL: Record<string, string> = {
  device_policy: 'Device zone', shield_profile: 'Shield profile', shield_allow: 'Always allow', shield_block: 'Always block', device_label: 'Name',
};

/** Dry run: what the device WOULD do. Throws with the device's refusal. */
export async function previewOwnerChange(c: OwnerChange): Promise<{ lines: DiffLine[]; warnings: string[] }> {
  const o = await post<Outcome>('/api/owner-rules', { ...fields(c, 'preview from Mission Control'), dry_run: '1' });
  if (!o.ok) throw new Error(`The device refused the preview: ${o.refused}`);
  const label = KIND_LABEL[c.kind] ?? c.kind;
  const lines: DiffLine[] = [
    { kind: c.op === 'remove' ? 'removed' : 'changed', text: c.kind === 'device_label'
      ? `${label} · ${c.target}: ${c.op === 'set' ? `"${c.value}"` : 'back to the signed name (DEVICES.TXT), if any'}`
      : `${label} · ${c.target}: ${o.before} → ${o.after}` },
  ];
  const warnings: string[] = [];
  if (o.shadowed_by) warnings.push(`This would be recorded but not take effect: ${o.shadowed_by} wins.`);
  if (ownerRules() && !ownerRules()!.persistent) warnings.push('This device has no persistent journal: the rule lasts until the next restart.');
  return { lines, warnings };
}

/** Approve: ask for a reason and the owner key, then write permanently. Returns the journal seq as id. */
export async function applyOwnerChange(c: OwnerChange): Promise<{ id: string; note: string }> {
  const a = await approve({ title: 'Make this a permanent rule?', body: `${KIND_LABEL[c.kind] ?? c.kind} for ${c.target}. The device writes it to its journal and keeps it across restarts.`, confirm: 'Approve', reason: {}, key: {} });
  if (!a) throw new Error('Cancelled.');
  const o = await post<Outcome>('/api/owner-rules', { ...fields(c, a.reason), permanent: 'true', owner_key: a.key });
  if (!o.ok) throw new Error(`The device refused it: ${o.refused}`);
  return { id: `${c.kind}|${c.target}|${o.seq ?? 0}`, note: `Journal record ${o.seq}.` };
}

/** PlanDiff `watch`: read the rules back and report what the device actually enforces. */
export function verifyOwnerChange(c: OwnerChange, onVerified?: () => void) {
  return (id: string, update: (u: ApplyUpdate) => void): (() => void) => {
    let stop = false;
    const wroteSeq = Number(id.split('|').pop()) || 0;
    const volatileNote = 'This device has no persistent journal, so the change is lost at the next restart.';
    update({ state: 'applying' });
    void (async () => {
      for (let i = 0; i < 5 && !stop; i++) {
        const v = await refreshOwnerRules();
        // Match by (kind, target) and seq ≥ the record just written — never by position (a re-set rule
        // keeps one row; compaction renumbers).
        const r = v?.rules.find((x) => x.kind === c.kind && x.target.toLowerCase() === c.target.toLowerCase() && x.seq >= wroteSeq);
        const gone = !v?.rules.some((x) => x.kind === c.kind && x.target.toLowerCase() === c.target.toLowerCase());
        if (c.op === 'remove' && v && gone) {
          onVerified?.();
          if (v.persistent) update({ state: 'verified', detail: 'The rule is gone; the signed baseline applies again.' });
          else update({ state: 'volatile', detail: `The rule is gone for now. ${volatileNote}` });
          return;
        }
        if (c.op === 'set' && r) {
          if (!r.effective) { update({ state: 'failed', detail: `Recorded, but ${r.shadowed_by ?? 'the signed baseline'} still wins.` }); return; }
          onVerified?.();
          if (!v!.persistent) update({ state: 'volatile', detail: `In effect now. ${volatileNote}` });
          else update({ state: 'verified', detail: c.kind === 'device_policy' || c.kind === 'shield_profile' ? `${KIND_LABEL[c.kind]} is now ${r.value.replace('_', ' ')}.` : c.kind === 'device_label' ? `The device is now called "${r.value}".` : 'The rule is in effect.' });
          return;
        }
        await new Promise((res) => setTimeout(res, 1000));
      }
      if (!stop) update({ state: 'failed', detail: 'The device did not report the change back. Check Protect → Owner rules.' });
    })();
    return () => { stop = true; };
  };
}

/* ── Remove all owner rules (ADR 0055 D7/D8: heqk `POST /api/owner-rules/revoke-all`, `op=revoke_all`) ──
 * One journal record clears every owner rule (zones, Shield profiles, always-allow / always-block, names) and ends
 * every LAN-access exception. The signed baseline and the management floor are untouched. Same guards as a single
 * rule: a dry run first, then a reason + owner-key re-authentication + permanent=true, then read back. */

interface LanAccessView { exceptions: { device?: string; dst?: string }[] }
export const [lanExceptions, setLanExceptions] = createSignal<number | null>(null);

/** Count of LAN-access exceptions in force (`/api/lan-access`), or null when the device does not report it. */
export async function refreshLanExceptions(): Promise<number | null> {
  try {
    const v = await fetchJson<LanAccessView>('/api/lan-access');
    const n = Array.isArray(v.exceptions) ? v.exceptions.length : null;
    setLanExceptions(n);
    return n;
  } catch {
    setLanExceptions(null);
    return null;
  }
}

/** Dry run: the device confirms it would accept the revoke; the lines list what goes, read from the device. */
export async function previewRevokeAll(): Promise<{ lines: DiffLine[]; warnings: string[] }> {
  const o = await post<Outcome>('/api/owner-rules/revoke-all', { op: 'revoke_all', reason: 'preview from Mission Control', dry_run: '1' });
  if (!o.ok) throw new Error(`The device refused the preview: ${o.refused}`);
  const v = await refreshOwnerRules();
  const lan = await refreshLanExceptions();
  const lines: DiffLine[] = (v?.rules ?? []).map((r) => ({
    kind: 'removed' as const,
    text: `${KIND_LABEL[r.kind] ?? r.kind} · ${r.target}${r.kind === 'device_policy' || r.kind === 'shield_profile' ? ` (${r.value})` : ''}`,
  }));
  if (lan === null) lines.push({ kind: 'removed', text: 'Any LAN-access exceptions in force (this device did not list them)' });
  else if (lan > 0) lines.push({ kind: 'removed', text: `LAN-access exceptions · ${lan} in force` });
  lines.push({ kind: 'unchanged', text: 'Signed baseline (DEVICES.TXT, policy, Shield) and management access' });
  const warnings: string[] = [];
  if (!v) warnings.push('The device did not list its owner rules, so the list above may be incomplete.');
  else if (v.rules.length === 0 && !lan) warnings.push('There are no owner rules to remove. Approving still writes a "start over" record to the journal.');
  return { lines, warnings };
}

/** Approve: reason + owner key, then one permanent "start over" record. */
export async function applyRevokeAll(): Promise<{ id: string; note: string }> {
  const a = await approve({
    title: 'Remove every owner rule?',
    body: 'Every rule you added on this device ends, and LAN-access exceptions end too. The signed baseline applies as shipped. This cannot be undone; you would add the rules again one by one.',
    confirm: 'Remove all', destructive: true, reason: {}, key: {},
  });
  if (!a) throw new Error('Cancelled.');
  const o = await post<Outcome>('/api/owner-rules/revoke-all', { op: 'revoke_all', reason: a.reason, permanent: 'true', owner_key: a.key });
  if (!o.ok) throw new Error(`The device refused it: ${o.refused}`);
  return { id: `revoke_all|${o.seq ?? 0}`, note: `Journal record ${o.seq}.` };
}

/** PlanDiff `watch`: verified only when the device reports no owner rules and no LAN-access exceptions. */
export function verifyRevokeAll(onVerified?: () => void) {
  return (_id: string, update: (u: ApplyUpdate) => void): (() => void) => {
    let stop = false;
    update({ state: 'applying' });
    void (async () => {
      for (let i = 0; i < 5 && !stop; i++) {
        const v = await refreshOwnerRules();
        const lan = await refreshLanExceptions();
        if (v && v.rules.length === 0 && !lan) {
          onVerified?.();
          update({ state: 'verified', detail: `No owner rules are left${lan === null ? '' : ' and no LAN-access exceptions'}; the signed baseline applies.` });
          return;
        }
        await new Promise((res) => setTimeout(res, 1000));
      }
      if (!stop) update({ state: 'failed', detail: 'The device still reports owner rules. Check the list on Protect → Rules.' });
    })();
    return () => { stop = true; };
  };
}

/** device_label grammar, as heqk checks it: 1–31 printable ASCII — letters, digits, space and . _ - ' ( ) , —
 *  no leading or trailing space. Returns the problem, or '' when valid. */
export function checkLabel(v: string): string {
  if (!v.length) return '';
  if (v.length > 31) return 'At most 31 characters.';
  if (!/^[A-Za-z0-9 ._\-'(),]+$/.test(v)) return "Letters, digits, spaces and . _ - ' ( ) , only (no accents or quotes).";
  if (v !== v.trim()) return 'No space at the start or end.';
  return '';
}
