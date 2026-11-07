/**
 * SampleDataNotice — honesty label for the device-served Mission Control.
 *
 * On heqk (`/api/health` → `substrate: "heqk"`) only some workspaces have a real API behind them;
 * the rest render their built-in sample data. An operator must never mistake sample data for
 * their network, so every page that is not (fully) live says so. Off-device (dev / Linux tier)
 * nothing is shown: those builds have their own live/mock badges.
 */
import { type Component, Show, createMemo, onMount } from 'solid-js';
import { substrate } from '../store/mock';
import { loadHealth } from '../store/health';

/** What the heqk API backs today (kernel/heqk/kernel/src/http.rs routes). */
const LIVE: Record<string, 'live' | string> = {
  '/': 'live',
  '/detect/feed': 'live',
  '/investigate/queue': 'live',
  '/observe/events': 'live',
};

function norm(p: string): string {
  const t = p.replace(/\/index\.html$/, '/').replace(/\.html$/, '').replace(/\/+$/, '');
  return t === '' ? '/' : t;
}

const SampleDataNotice: Component = () => {
  onMount(() => void loadHealth());
  const status = createMemo(() => {
    if (substrate() !== 'heqk' || typeof location === 'undefined') return null;
    const s = LIVE[norm(location.pathname)];
    if (s === 'live') return null;
    return s ?? "This view isn't served by this device yet — everything here is sample data.";
  });
  return (
    <Show when={status()}>
      <div
        role="status"
        style={{
          position: 'fixed', left: '50%', bottom: '14px', transform: 'translateX(-50%)', 'z-index': '1000',
          'max-width': 'min(92vw, 640px)', padding: '8px 14px', 'border-radius': '999px',
          background: 'rgba(250, 204, 21, 0.12)', border: '1px solid rgba(250, 204, 21, 0.55)',
          color: '#fde68a', font: '13px/1.35 system-ui, sans-serif', 'text-align': 'center',
          'backdrop-filter': 'blur(6px)',
        }}
      >
        <strong>Sample data</strong> — {status()} Live on this device: Home, Detect, Investigate, Observe.
      </div>
    </Show>
  );
};

export default SampleDataNotice;
