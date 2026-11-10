/**
 * WorkspaceApp — Workspace (`/workspace`): your recent and saved work, each row linking to the live
 * object (wireframe "Workspace"; requirements doc §2). Kept in this browser (store/recents.ts): the
 * device has no per-user work store, and the screen says so. Filter by type, pin what matters.
 */
import { type Component, For, Show, createMemo, createSignal, onMount } from 'solid-js';
import { workItems, loadWork, togglePin, clearUnpinned, type WorkType } from '../store/recents';
import AppShell from './AppShell';

type Filter = 'All' | 'Pinned' | WorkType;
const FILTERS: Filter[] = ['All', 'Pinned', 'Incident', 'Screen'];

function ago(ms: number): string {
  const s = Math.max(0, Math.round((Date.now() - ms) / 1000));
  if (s < 60) return 'just now';
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
  return new Date(ms).toLocaleDateString([], { day: 'numeric', month: 'short' });
}

const WorkspaceApp: Component = () => {
  const [filter, setFilter] = createSignal<Filter>('All');
  onMount(() => loadWork());

  const rows = createMemo(() => workItems().filter((w) =>
    filter() === 'All' || (filter() === 'Pinned' ? w.pinned : w.type === filter())));

  return (
    <AppShell path="/workspace">
      <main class="pro-main" aria-label="Workspace" style={{ 'max-width': '1100px' }}>
        <div class="pro-head">
          <div>
            <h1 class="pro-title">Workspace</h1>
            <p class="pro-sub">Your recent and saved work. Everything links to the live object · kept in this browser</p>
          </div>
          <Show when={workItems().some((w) => !w.pinned)}>
            <button class="hp-btn" onClick={clearUnpinned}>Clear recent</button>
          </Show>
        </div>

        <div class="l0-chips" role="group" aria-label="Show">
          <For each={FILTERS}>{(f) => (
            <button class={`l0-chip${filter() === f ? ' is-on' : ''}`} aria-pressed={filter() === f} onClick={() => setFilter(f)}>
              {f} · {f === 'All' ? workItems().length : f === 'Pinned' ? workItems().filter((w) => w.pinned).length : workItems().filter((w) => w.type === f).length}
            </button>
          )}</For>
        </div>

        <Show when={rows().length > 0} fallback={
          <div class="pcard">
            <p style={{ margin: 0 }}>Nothing here yet.</p>
            <p class="pcard-note">Screens and incidents you open appear here; pin the ones you come back to.</p>
            <div class="l0-card-foot">
              <a class="hp-btn" href="/investigate/queue">Open the incident queue</a>
              <a class="hp-btn" href="/observe/live">Watch live telemetry</a>
              <a class="hp-btn" href="/detect/feed">Review detections</a>
            </div>
          </div>
        }>
          <div class="l0-table-wrap">
            <table class="l0-table obs-table">
              <thead><tr><th scope="col">Pin</th><th scope="col">Type</th><th scope="col">Title</th><th scope="col">Scope</th><th scope="col">Last opened</th></tr></thead>
              <tbody>
                <For each={rows()}>{(w) => (
                  <tr>
                    <td>
                      <button class="tb-icon" style={{ 'min-height': '36px', 'min-width': '36px' }} aria-pressed={!!w.pinned}
                        aria-label={w.pinned ? `Unpin ${w.title}` : `Pin ${w.title}`} onClick={() => togglePin(w.key)}>{w.pinned ? '★' : '☆'}</button>
                    </td>
                    <td><span class="inc-status">{w.type}</span></td>
                    <td><a href={w.href} style={{ color: 'var(--hp-text-primary)', 'font-weight': 500 }}>{w.title}</a></td>
                    <td class="l0-muted">{w.scope}</td>
                    <td class="l0-num" style={{ 'font-weight': 400, 'font-size': '12px' }}>{ago(w.at)}</td>
                  </tr>
                )}</For>
              </tbody>
            </table>
          </div>
        </Show>
        <p class="pcard-note">Saved searches, AI conversations and draft playbooks appear here once the device keeps them; today it keeps none, so nothing is invented.</p>
      </main>
    </AppShell>
  );
};

export default WorkspaceApp;
