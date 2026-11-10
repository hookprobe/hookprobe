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
  const reason = window.prompt(`Reason for this change (kept in the journal):`, '');
  if (!reason || reason.trim().length < 3) throw new Error('Cancelled: a reason of at least 3 characters is required.');
  const key = window.prompt('This is a permanent change. Enter your owner key:', '');
  if (!key) throw new Error('Cancelled: the owner key is required.');
  const o = await post<Outcome>('/api/owner-rules', { ...fields(c, reason.trim()), permanent: 'true', owner_key: key });
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

/** device_label grammar, as heqk checks it: 1–31 printable ASCII — letters, digits, space and . _ - ' ( ) , —
 *  no leading or trailing space. Returns the problem, or '' when valid. */
export function checkLabel(v: string): string {
  if (!v.length) return '';
  if (v.length > 31) return 'At most 31 characters.';
  if (!/^[A-Za-z0-9 ._\-'(),]+$/.test(v)) return "Letters, digits, spaces and . _ - ' ( ) , only (no accents or quotes).";
  if (v !== v.trim()) return 'No space at the start or end.';
  return '';
}
