/**
 * SampleDataNotice — the "Sample data" banner (DR-03, requirements doc §Global banners). An operator
 * must never mistake sample data for their own network:
 *
 *   - on the device (`/api/health` → `substrate: "heqk"`): every route without a real API behind
 *     it says so; live routes show nothing;
 *   - with no device answering at all (a preview / dev build): every route says so, once the
 *     health check has failed (never flashed before it answers).
 *
 * Rendered inline at the top of AppShell's content, so it never covers the phone bottom tabs.
 */
import { type Component, Show, createMemo, onMount } from 'solid-js';
import { substrate } from '../store/mock';
import { loadHealth, healthChecked } from '../store/health';

/** What the heqk API backs today (os/kernel/kernel/src/http.rs routes). */
const LIVE: Record<string, 'live' | string> = {
  '/': 'live',
  '/detect/feed': 'live',
  '/investigate/queue': 'live',
  '/observe/events': 'live',
  '/network/dns': 'live',
  '/network/map': 'live',
  '/network/zones': 'live',
};

const LIVE_NAMES = 'Home, Detect, Investigate, Observe, Shield, My Network';

function norm(p: string): string {
  const t = p.replace(/\/index\.html$/, '/').replace(/\.html$/, '').replace(/\/+$/, '');
  return t === '' ? '/' : t;
}

const SampleDataNotice: Component = () => {
  onMount(() => void loadHealth());
  const status = createMemo(() => {
    if (typeof location === 'undefined') return null;
    if (substrate() === 'heqk') {
      const s = LIVE[norm(location.pathname)];
      if (s === 'live') return null;
      return `${s ?? "This view isn't served by this device yet, so everything here is sample data."} Live on this device: ${LIVE_NAMES}.`;
    }
    if (healthChecked() && !substrate()) return 'No device is answering, so everything here is sample data.';
    return null;
  });
  return (
    <Show when={status()}>
      <div class="hp-banner hp-banner--sample" role="status">
        <strong>Sample data</strong> {status()}
      </div>
    </Show>
  );
};

export default SampleDataNotice;
