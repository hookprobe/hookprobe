/**
 * LiveState — the honest loading/error/empty placeholder for a live-data panel.
 *
 * Shared by Detect/Investigate/Observe (any panel driven by a `store/*Live.ts` fetch): a clear
 * "no data yet" beats fake data (build brief). Visually mirrors `ProtectApp`'s capability-gated
 * "greyed-with-reason" panel (`.prot-gated*` in `styles/prot.css`) so a data-unavailable panel and a
 * capability-ungranted panel read as the same family of "nothing broken, here's why" states.
 */

import type { Component } from 'solid-js';

export type LiveStateKind = 'loading' | 'error' | 'empty';

const ICON: Record<LiveStateKind, string> = { loading: '◌', error: '⚠', empty: '○' };

const LiveState: Component<{ kind: LiveStateKind; label: string; reason?: string }> = (p) => (
  <div class="hp-live-state" role="status">
    <span class="hp-live-state-icon" classList={{ 'hp-live-state-icon--spin': p.kind === 'loading' }} aria-hidden="true">
      {ICON[p.kind]}
    </span>
    <div class="hp-live-state-body">
      <div class="hp-live-state-label">{p.label}</div>
      {p.reason && <div class="hp-live-state-reason">{p.reason}</div>}
    </div>
  </div>
);

export default LiveState;
