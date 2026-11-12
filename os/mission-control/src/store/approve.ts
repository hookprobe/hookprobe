/**
 * approve — the one way Mission Control asks for consent and credentials (UX review step 2). Replaces the browser's
 * `prompt()` / `confirm()`, which showed secrets in clear, could not be styled, and could be silenced by the browser
 * after a few dialogs. `approve()` opens the ApproveSheet (mounted once per page) and resolves with what the owner
 * entered, or null when they cancel.
 *
 *   title / body     what is about to happen, in plain words
 *   reason           a journal reason (≥ 3 characters), with a default the owner can keep
 *   key              a masked device-password field (the label on the device; still needed for sign-in-level actions)
 *   passphrase       a masked passphrase with a repeat field (backup encryption)
 *   destructive      red confirm button (reset, rollback, removal)
 */
import { createSignal } from 'solid-js';

export interface ApproveRequest {
  title: string;
  body?: string;
  confirm: string;
  destructive?: boolean;
  reason?: { default?: string };
  key?: { label?: string };
  passphrase?: { label?: string; min: number };
}
export interface ApproveResult { reason: string; key: string; passphrase: string }

interface Pending extends ApproveRequest { resolve: (r: ApproveResult | null) => void }
export const [approveRequest, setApproveRequest] = createSignal<Pending | null>(null);

export function approve(r: ApproveRequest): Promise<ApproveResult | null> {
  // One request at a time: a second one cancels the first rather than stacking dialogs.
  approveRequest()?.resolve(null);
  return new Promise((resolve) => setApproveRequest({ ...r, resolve }));
}

/** Resolve the open request (called by the sheet). */
export function settleApprove(r: ApproveResult | null): void {
  const p = approveRequest();
  setApproveRequest(null);
  p?.resolve(r);
}

/** The owner key alone, for flows that only need it (upload begin, enroll). Null when cancelled. */
export async function askOwnerKey(title: string, body?: string, confirm = 'Continue'): Promise<string | null> {
  return (await approve({ title, body, confirm, key: {} }))?.key ?? null;
}
