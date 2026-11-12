/**
 * App — Home (`/`), the calm Layer 0 landing for Sam and Dana (wireframe "Home"; requirements doc
 * §Calm home). Answers "Am I safe, what happened, is it handled?" with no clicks:
 *
 *   hero (orb + verdict + "What happened today")  ·  Shield + My Network cards  ·  Needs you
 *
 * On a device every number is the device's own (QSecBit, /api/incidents, /api/dns, /api/devices,
 * /api/actions); with no device answering, the sample values below render under the Sample-data
 * banner. Both drawers drill into the evidence (FR-06/FR-07).
 */
import { type Component, For, Show, createMemo, createSignal, onCleanup, onMount } from 'solid-js';
import {
  qsecbit, heartbeat, setHeartbeat, protectionStatus, lastCheckedAt, security, shield, network, substrate,
} from '../store/mock';
import { startLiveUpdates } from '../store/live';
import { setProView } from '../store/layer';
import { dnsLive, startDnsLive } from '../store/dnsLive';
import { devices } from '../store/obsLive';
import { incidents } from '../store/investigateLive';
import { actionsView, refreshActions } from '../store/actions';
import { startStory, todayEvents, hhmm, storySource } from '../store/story';
import { healthChecked } from '../store/health';
import AppShell from './AppShell';
import Drawer from './Drawer';

const VERDICT = {
  protected:         'You’re protected.',
  'needs-attention': 'Something needs a look.',
  critical:          'We’re dealing with an attack.',
} as const;

const R = 92;
const C = 2 * Math.PI * R;

const App: Component = () => {
  const [panel, setPanel] = createSignal<'today' | 'why' | null>(null);
  const device = () => substrate() === 'heqk';
  /** Sample values only once we know no device is answering; until then a neutral placeholder. */
  const sampleMode = () => healthChecked() && !substrate();
  const waiting = () => !device() && !sampleMode();
  // "Last checked" ages for real: it is the time the device last sent fresh data, not a fixed "just now".
  const [nowMs, setNowMs] = createSignal(Date.now());
  onMount(() => { const t = setInterval(() => setNowMs(Date.now()), 15_000); onCleanup(() => clearInterval(t)); });
  const checked = () => {
    if (sampleMode()) return 'sample data';
    const at = lastCheckedAt();
    if (!at) return 'not yet';
    const s = Math.max(0, Math.round((nowMs() - at) / 1000));
    return s < 60 ? 'just now' : s < 3600 ? `${Math.round(s / 60)} min ago` : `${Math.round(s / 3600)} h ago`;
  };

  onMount(() => {
    const noMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    let iv: ReturnType<typeof setInterval> | undefined;
    // Real data when the API answers; the sample heartbeat only when nothing does (never noise over real values).
    void startLiveUpdates().then((live) => {
      if (live || noMotion) return;
      iv = setInterval(() => {
        setHeartbeat((prev) => {
          const next = prev.slice(1);
          const last = next[next.length - 1] ?? 90;
          return [...next, Math.round(Math.max(60, Math.min(100, last + (Math.random() - 0.45) * 8)))];
        });
      }, 2000);
    });
    startDnsLive();
    startStory();
    void refreshActions();
    onCleanup(() => { if (iv !== undefined) clearInterval(iv); });
  });

  // ── Shield card ────────────────────────────────────────────────────────
  const dnsBlocked = () => {
    const c = dnsLive()?.counters ?? {};
    return (c['blocked'] ?? 0) + (c['blocked-cname'] ?? 0) + (c['tcp53-refused'] ?? 0);
  };
  const shieldKpi = () => (waiting() ? '—' : device() ? (dnsLive() ? dnsBlocked().toLocaleString() : '—') : shield().adsBlocked.toLocaleString());
  const shieldLine = () => (sampleMode() ? 'ads and trackers blocked today' : 'ads, trackers and dangerous sites blocked since start-up');
  const shieldSub = () => {
    if (waiting()) return 'Checking…';
    if (sampleMode()) return `${shield().malwareStopped} malware sites stopped`;
    const hidden = dnsLive()?.counters['blocked-cname'] ?? 0;
    return dnsLive() ? (hidden > 0 ? `${hidden} hidden trackers caught` : 'Answering every lookup on this network') : 'Waiting for the device…';
  };

  // ── My Network card ────────────────────────────────────────────────────
  const POLICY_NAME: Record<string, string> = { full: 'Full access', internet_only: 'Internet only', lan_only: 'Local only', quarantine: 'Quarantine' };
  const netKpi = () => (waiting() ? '—' : device() ? String(devices().length) : String(network().devices));
  const netLine = () => (sampleMode()
    ? `devices · ${network().online} online`
    : `devices · ${devices().filter((d) => d.active !== false).length} online`);
  const netSub = createMemo(() => {
    if (waiting()) return 'Checking…';
    if (sampleMode()) return 'Family 9 · Kids 4 · IoT 7 · Guests 3 · 1 needs a zone';
    const counts = new Map<string, number>();
    for (const d of devices()) counts.set(d.policy ?? 'full', (counts.get(d.policy ?? 'full') ?? 0) + 1);
    return [...counts].map(([k, n]) => `${POLICY_NAME[k] ?? k} ${n}`).join(' · ') || 'No devices have joined yet';
  });

  // ── Needs you ──────────────────────────────────────────────────────────
  const open = () => security().openIncidents;
  const openIncidents = () => incidents().filter((i) => i.status !== 'resolved' && i.status !== 'closed').slice(0, 5);
  const handled = () => actionsView()?.active ?? [];

  const lead = () => (open() === 0 ? 'Nothing needs you right now.' : `${open()} thing${open() === 1 ? '' : 's'} to look at.`);

  return (
    <AppShell path="/">
      <main class="l0-main" aria-label="Home">
        <section class="home-hero">
          <Show when={!waiting()} fallback={<div class="home-orb" role="img" aria-label="Checking the device"><div class="home-orb-num"><b>…</b><span>Checking</span></div></div>}>
          <div class="home-orb" role="img" aria-label={`QSecBit score ${qsecbit()} out of 100: ${VERDICT[protectionStatus()]}`}>
            <svg viewBox="0 0 200 200" aria-hidden="true">
              <circle cx="100" cy="100" r={R} fill="none" stroke="rgba(255,255,255,.08)" stroke-width="8" />
              <circle cx="100" cy="100" r={R} fill="none" stroke-width="8" stroke-linecap="round"
                stroke={protectionStatus() === 'protected' ? 'var(--hp-green)' : protectionStatus() === 'needs-attention' ? 'var(--hp-amber)' : 'var(--hp-red)'}
                stroke-dasharray={`${(qsecbit() / 100) * C} ${C}`} />
            </svg>
            <div class="home-orb-num" aria-hidden="true"><b>{qsecbit()}</b><span>QSecBit</span></div>
          </div>
          </Show>
          <div class={`home-verdict home-verdict--${protectionStatus()}`}>
            <h1>{waiting() ? 'Checking your network\u2026' : VERDICT[protectionStatus()]}</h1>
            <p class="home-lead">{lead()}</p>
            <p class="home-meta">
              <span>Last checked {checked()}</span>
              <svg width="120" height="20" viewBox="0 0 120 20" aria-hidden="true">
                <polyline fill="none" stroke="var(--hp-green)" stroke-width="1.5"
                  points={heartbeat().map((v, i, a) => `${((i / Math.max(1, a.length - 1)) * 120).toFixed(1)},${(20 - ((Math.max(60, v) - 60) / 40) * 20).toFixed(1)}`).join(' ')} />
              </svg>
            </p>
            <div><button class="hp-btn" onClick={() => setPanel('today')}>What happened today →</button></div>
          </div>
        </section>

        <section class="l0-grid-2" aria-label="Pillars">
          <article class="l0-card">
            <p class="l0-label">Shield</p>
            <p class="l0-card-kpi">{shieldKpi()}</p>
            <p class="l0-card-line">{shieldLine()}</p>
            <p class="l0-card-sub">{shieldSub()}</p>
            <div class="l0-card-foot"><a class="hp-btn" href="/network/dns">Manage</a></div>
          </article>
          <article class="l0-card">
            <p class="l0-label">My Network</p>
            <p class="l0-card-kpi">{netKpi()}</p>
            <p class="l0-card-line">{netLine()}</p>
            <p class="l0-card-sub">{netSub()}</p>
            <div class="l0-card-foot"><a class="hp-btn" href="/network/zones">Open map</a></div>
          </article>
        </section>

        <section class="l0-card l0-card--dashed home-needs" role="region" aria-label="Needs you">
          <div class="home-needs-body">
            <p class="l0-label">Needs you</p>
            {/* Same wording as before: the browser gate reads it. */}
            <p class="needs-msg">
              {open() === 0
                ? 'Nothing to approve. Everything detected today was handled automatically.'
                : `${open()} incident${open() !== 1 ? 's' : ''} need your review.`}
            </p>
            <p class="l0-card-sub">
              {handled().length > 0
                ? `${handled().length} temporary protective action${handled().length === 1 ? '' : 's'} in force right now.`
                : 'Everything the system did on its own is listed with the reason.'}
            </p>
          </div>
          <button class="hp-btn" onClick={() => setPanel('why')}>See what we did and why</button>
        </section>

        <nav class="home-foot" aria-label="More">
          <a href="/network/wan">Get Online</a>
          <a href="/observe/events">Timeline &amp; Export</a>
          <button onClick={() => { setProView(true); location.href = '/mission'; }} aria-label="Switch to Pro view (every workspace)">Pro view ⤢</button>
        </nav>
      </main>

      <Drawer open={panel() === 'today'} title="Today" onClose={() => setPanel(null)}
        footer={<a class="hp-btn" href="/observe/events">Open the full timeline and export</a>}>
        <Show when={todayEvents().length > 0} fallback={<p class="l0-muted">{storySource() === 'loading' ? 'Loading…' : 'Nothing has happened yet today.'}</p>}>
          <ol class="l0-evlist">
            <For each={todayEvents().slice(0, 12)}>{(e) => (
              <li class="l0-ev">
                <span class="l0-ev-t">{hhmm(e.ts)}</span>
                <a class="l0-ev-body" href={e.href} style={{ 'text-decoration': 'none' }}>
                  <span class="l0-ev-title">{e.title}</span>
                  <span class="l0-ev-sub">{e.cat} · {e.sub}</span>
                </a>
              </li>
            )}</For>
          </ol>
        </Show>
      </Drawer>

      <Drawer open={panel() === 'why'} title="What we did and why" onClose={() => setPanel(null)}
        footer={<a class="hp-btn hp-btn--primary" href="/investigate/queue">Open the full story</a>}>
        <Show when={!sampleMode()} fallback={
          <>
            <p class="l0-label">Kitchen camera isolated</p>
            <p>It started contacting a known malware host and scanning other devices on your network.</p>
            <div>
              <p class="l0-label">Confidence</p>
              <div class="l0-meter"><span class="l0-meter-track"><span class="l0-meter-fill" style={{ width: '94%' }} /></span><span class="l0-num">94%</span></div>
            </div>
            <a class="l0-link-row" href="/investigate/queue">DNS lookups to a blocklisted domain →</a>
            <a class="l0-link-row" href="/investigate/queue">Connection attempts to 6 local devices →</a>
            <p class="l0-muted" style={{ 'font-size': '12px' }}>Decided by AEGIS · local rules · sample data</p>
          </>
        }>
          <div>
            <p class="l0-label">Protective actions in force</p>
            <Show when={handled().length > 0} fallback={<p class="l0-muted">None right now. Every action expires on its own.</p>}>
              <For each={handled()}>{(a) => (
                <p>{a.kind.replace('_', ' ')} · <span class="l0-num" style={{ 'font-weight': 500 }}>{a.target}</span>
                  {a.expires_in_s ? ` · ${Math.ceil(a.expires_in_s / 60)} min left` : ''}</p>
              )}</For>
            </Show>
          </div>
          <div>
            <p class="l0-label">Open incidents</p>
            <Show when={openIncidents().length > 0} fallback={<p class="l0-muted">No open incidents.</p>}>
              <For each={openIncidents()}>{(i) => (
                <a class="l0-link-row" href="/investigate/queue">{i.title} · {i.device_ip} · {i.priority} →</a>
              )}</For>
            </Show>
          </div>
          <p class="l0-muted" style={{ 'font-size': '12px' }}>
            Decided by the device's own rules (deterministic; no AI model was used). Every number links to its evidence.
          </p>
        </Show>
      </Drawer>
    </AppShell>
  );
};

export default App;
