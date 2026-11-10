/**
 * TimelineApp — Timeline & Export (`/observe/events`), the Layer 0 pillar "It's my data"
 * (wireframe "Timeline & Export"; ObserveApp's story mode). Everything that happened, in plain
 * words, grouped by day; every row opens its evidence. Export is real: CSV / JSON files built from
 * exactly the rows shown, or a printable report. The raw telemetry table is Pro Observe
 * (`/observe/live`).
 */
import { type Component, For, Show, createMemo, createSignal, onMount } from 'solid-js';
import { deviceStats, substrate } from '../store/mock';
import { startStory, storyEvents, storySource, dayKey, dayLabel, hhmm, isUnsynced, type StoryCat, type StoryEvent } from '../store/story';
import AppShell from './AppShell';
import PageHeader from './PageHeader';

type Format = 'CSV' | 'JSON' | 'Print / PDF';
type Period = 'today' | '7d' | 'all';

function download(name: string, mime: string, body: string): void {
  const url = URL.createObjectURL(new Blob([body], { type: mime }));
  const a = document.createElement('a');
  a.href = url; a.download = name;
  document.body.append(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

const csvCell = (v: string) => (/[",\n]/.test(v) ? `"${v.replace(/"/g, '""')}"` : v);

const TimelineApp: Component = () => {
  const [filter, setFilter] = createSignal<StoryCat | 'All'>('All');
  const [format, setFormat] = createSignal<Format>('CSV');
  const [period, setPeriod] = createSignal<Period>('all');
  const [done, setDone] = createSignal('');
  onMount(() => startStory());

  const cats = createMemo(() => {
    const present = new Set(storyEvents().map((e) => e.cat));
    return (['Security', 'Devices', 'Shield', 'Network'] as StoryCat[]).filter((c) => present.has(c));
  });

  const inPeriod = (e: StoryEvent) => {
    if (period() === 'all' || isUnsynced(e.ts)) return true;
    const since = dayKey(Date.now() / 1000) - (period() === '7d' ? 6 * 86400 : 0);
    return e.ts >= since;
  };
  const shown = createMemo(() => storyEvents().filter((e) => (filter() === 'All' || e.cat === filter()) && inPeriod(e)));
  const days = createMemo(() => {
    const m = new Map<number, StoryEvent[]>();
    for (const e of shown()) m.set(dayKey(e.ts), [...(m.get(dayKey(e.ts)) ?? []), e]);
    return [...m.entries()];
  });

  const retention = () => {
    const d = deviceStats();
    if (!d) return substrate() ? 'Checking what this device keeps…' : 'Raw packets are kept 7 days. Older items export as summaries.';
    return `This device keeps its newest ${d.detectionsCap} detections${d.sealedCap > 0 ? `, the newest ${d.sealedCap} sealed across restarts` : ', in memory until restart'}. Send them to your own system to keep more.`;
  };

  const doExport = () => {
    const rows = shown();
    const stamp = new Date().toISOString().slice(0, 10);
    const when = (e: StoryEvent) => (isUnsynced(e.ts) ? `since-boot ${hhmm(e.ts)}` : new Date(e.ts * 1000).toISOString());
    if (format() === 'CSV') {
      const lines = ['time,category,title,detail,evidence', ...rows.map((e) => [when(e), e.cat, e.title, e.sub, location.origin + e.href].map(csvCell).join(','))];
      download(`hookprobe-timeline-${stamp}.csv`, 'text/csv', lines.join('\n') + '\n');
    } else if (format() === 'JSON') {
      download(`hookprobe-timeline-${stamp}.json`, 'application/json', JSON.stringify({
        exported_at: new Date().toISOString(), source: storySource() === 'sample' ? 'sample' : 'device',
        events: rows.map((e) => ({ time: when(e), ts: e.ts, category: e.cat, title: e.title, detail: e.sub, evidence: e.href })),
      }, null, 2));
    } else {
      window.print();
    }
    setDone(format() === 'Print / PDF' ? 'Opened the print dialog. Choose "Save as PDF" to keep a file.' : `Downloaded ${rows.length} event${rows.length === 1 ? '' : 's'} as ${format()}.`);
  };

  return (
    <AppShell path="/observe/events">
      <main class="l0-main l0-main--wide" aria-label="Timeline and export">
        <PageHeader title="Timeline" status="Everything that happened on your network, in plain words. It's your data." />
        <div class="tl">
          <section style={{ display: 'flex', 'flex-direction': 'column', gap: '20px', 'min-width': 0 }}>
            <div class="l0-chips" role="group" aria-label="Show">
              <For each={['All', ...cats()] as (StoryCat | 'All')[]}>{(c) => (
                <button class={`l0-chip${filter() === c ? ' is-on' : ''}`} aria-pressed={filter() === c} onClick={() => setFilter(c)}>{c}</button>
              )}</For>
            </div>
            <Show when={days().length > 0} fallback={
              <p class="l0-muted">{storySource() === 'loading' ? 'Loading…' : 'Nothing to show yet. Events appear here as they happen.'}</p>
            }>
              <For each={days()}>{([key, items]) => (
                <div class="tl-day">
                  <p class="l0-label">{dayLabel(key)}</p>
                  <For each={items}>{(e) => (
                    <a class="tl-item" href={e.href}>
                      <span class="tl-item-t">{hhmm(e.ts)}</span>
                      <span class="tl-item-cat">{e.cat}</span>
                      <span style={{ display: 'flex', 'flex-direction': 'column', gap: '2px', 'min-width': 0 }}>
                        <span class="l0-ev-title">{e.title}</span>
                        <span class="l0-ev-sub">{e.sub}</span>
                      </span>
                    </a>
                  )}</For>
                </div>
              )}</For>
            </Show>
          </section>

          <aside class="tl-side" aria-label="Export">
            <div class="l0-card">
              <h2 style={{ margin: 0, 'font-size': '18px' }}>Export</h2>
              <p class="l0-label">Format</p>
              <div class="l0-chips" role="group" aria-label="Format">
                <For each={['CSV', 'JSON', 'Print / PDF'] as Format[]}>{(f) => (
                  <button class={`l0-chip${format() === f ? ' is-on' : ''}`} aria-pressed={format() === f} onClick={() => { setFormat(f); setDone(''); }}>{f}</button>
                )}</For>
              </div>
              <p class="l0-label">Period</p>
              <div class="l0-chips" role="group" aria-label="Period">
                <For each={[['today', 'Today'], ['7d', 'Last 7 days'], ['all', 'Everything kept']] as [Period, string][]}>{([p, label]) => (
                  <button class={`l0-chip${period() === p ? ' is-on' : ''}`} aria-pressed={period() === p} onClick={() => { setPeriod(p); setDone(''); }}>{label}</button>
                )}</For>
              </div>
              <button class="hp-btn hp-btn--primary" onClick={doExport} disabled={shown().length === 0}>
                Export {shown().length} event{shown().length === 1 ? '' : 's'} · {format()}
              </button>
              <p class="l0-card-sub" role="status" aria-live="polite">{done()}</p>
              <p class="l0-card-sub">{retention()}</p>
            </div>
            <div class="l0-card">
              <h2 style={{ margin: 0, 'font-size': '18px' }}>Send it somewhere</h2>
              <p class="l0-card-sub">Get alerts on your phone or in your own system through a webhook (ntfy, Gotify or JSON).</p>
              <div class="l0-card-foot"><a class="hp-btn" href="/admin/identity">Set up alerts</a></div>
            </div>
          </aside>
        </div>
      </main>
    </AppShell>
  );
};

export default TimelineApp;
