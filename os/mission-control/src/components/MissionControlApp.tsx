/**
 * MissionControlApp — Mission Control (`/mission`), the Pro landing: what the system is doing right
 * now (wireframe "Mission Control"; requirements doc §1; MissionControl.md §1).
 *
 *   row 1  Global health (4) · Threat pulse (4) · Engines (4)
 *   linked Fleet health (6) · Customer health (6)        — only when cloud-linked / self-hosted
 *   row 2  Active incidents (6) · Autonomous actions (6)
 *   row 3  Infrastructure (8) · Performance (4)
 *   row 4  Activity timeline (12)
 *
 * Every card opens the shared Drawer with its drill path and "Open full view" (FR-06). On a device
 * every number is the device's own (/api/health, /api/qsecbit, /api/incidents, /api/detections,
 * /api/engines, /api/actions, /api/network); with no device answering, the labelled sample values
 * render; until we know, a neutral placeholder. Nothing the device cannot measure is shown
 * (no CPU/memory: heqk does not report them).
 */
import { type Component, For, Show, createMemo, createSignal, onMount } from 'solid-js';
import { qsecbit, heartbeat, protectionStatus, deployMode, deviceStats, substrate } from '../store/mock';
import { healthChecked } from '../store/health';
import { startLiveUpdates } from '../store/live';
import { incidents, startInvestigateLive } from '../store/investigateLive';
import { detections, engines, startDetectLive } from '../store/detectLive';
import { actionsView, refreshActions } from '../store/actions';
import { devices } from '../store/obsLive';
import { networkView, startNetworkLive } from '../store/networkLive';
import { startStory, storyEvents, hhmm } from '../store/story';
import { incidentHref } from '../store/routes';
import AppShell from './AppShell';
import Drawer from './Drawer';

const WORD = { protected: 'Protected', 'needs-attention': 'Needs attention', critical: 'At risk' } as const;
const R = 42, C = 2 * Math.PI * R;

interface CardInfo { title: string; crumb: string; body: string; href: string; hrefLabel: string }

const MissionControlApp: Component = () => {
  const [open, setOpen] = createSignal<string | null>(null);
  onMount(() => {
    void startLiveUpdates();
    startInvestigateLive();
    startDetectLive();
    startNetworkLive();
    startStory();
    void refreshActions();
  });

  const device = () => !!substrate();
  const sample = () => healthChecked() && !substrate();
  const linked = () => deployMode() !== 'standalone';
  const n = (v: number | undefined) => (v === undefined ? '—' : v.toLocaleString());
  const ds = () => deviceStats();

  // ── Threat pulse ──────────────────────────────────────────────────────
  const families = createMemo(() => {
    const m = new Map<string, number>();
    for (const d of detections()) m.set(d.category || 'other', (m.get(d.category || 'other') ?? 0) + 1);
    return [...m.entries()].sort((a, b) => b[1] - a[1]).slice(0, 3);
  });

  // ── Engines ──────────────────────────────────────────────────────────
  const engineRows = () => (sample()
    ? [{ name: 'NAPSE', hits: 88 }, { name: 'HYDRA', hits: 54 }, { name: 'AEGIS', hits: 23 }]
    : engines().map((e) => ({ name: e.name, hits: e.hits ?? 0 })));
  const maxHits = () => Math.max(1, ...engineRows().map((e) => e.hits));

  // ── Incidents / actions ──────────────────────────────────────────────
  const openInc = () => incidents().filter((i) => i.status !== 'resolved' && i.status !== 'closed');
  const SAMPLE_INC = [
    { id: 's1', priority: 'HIGH', title: 'Kitchen camera contacted malware host', when: '13:05' },
    { id: 's2', priority: 'MEDIUM', title: 'Brute force on admin page', when: 'yesterday' },
    { id: 's3', priority: 'LOW', title: 'New unknown device', when: '10:40' },
  ];
  const actions = () => actionsView()?.active ?? [];
  const audit = () => (actionsView()?.audit ?? []).filter((a) => a.ok).slice(0, 3);

  // ── Infrastructure / performance ─────────────────────────────────────
  const wan = () => networkView()?.wan ?? ds()?.wan ?? null;
  const wifi = () => networkView()?.wifi ?? null;

  const cards: Record<string, () => CardInfo> = {
    health: () => ({ title: 'Global health', crumb: 'QSecBit → risk window → contributing detections', body: 'QSecBit is the device’s own resilience score over its recent risk window. Open Protect to see what is enforced, or Detect for the detections behind it.', href: '/protect/firewall', hrefLabel: 'Open Protect' }),
    pulse: () => ({ title: 'Threat pulse', crumb: 'Dropped frames → detections → rule → source', body: 'Frames the device dropped on the wire and the detections they raised, grouped by family. Every detection links to its rule, source and evidence.', href: '/detect/feed', hrefLabel: 'Open Detect' }),
    engines: () => ({ title: 'Engines', crumb: 'Engine → hits → detections', body: 'The detection tiers this device actually runs and how many hits each recorded. Nothing here is a model claim: AEGIS correlates deterministically unless you connect an AI planner.', href: '/detect/feed', hrefLabel: 'Open Detect' }),
    fleet: () => ({ title: 'Fleet health', crumb: 'Fleet → site → device → manifest', body: 'Fleet status comes from your control plane. This device has not received fleet data yet.', href: '/admin/identity', hrefLabel: 'Open Administration' }),
    customers: () => ({ title: 'Customer health', crumb: 'Tenants → customer → score', body: 'Per-tenant scores come from your control plane. No tenant data has arrived yet.', href: '/customers/managed', hrefLabel: 'Open Customers' }),
    incidents: () => ({ title: 'Active incidents', crumb: 'Queue → incident story → evidence', body: 'Open incidents, highest priority first. Each one opens as a story with the evidence and the reason for every step.', href: '/investigate/queue', hrefLabel: 'Open Investigate' }),
    actions: () => ({ title: 'Autonomous actions', crumb: 'Action → why → audit log → undo', body: 'Every protective action is time-bounded and expires on its own; the audit log records who or what started it and why. End any of them early from Shield or Protect.', href: '/network/dns', hrefLabel: 'Open Shield actions' }),
    infra: () => ({ title: 'Infrastructure', crumb: 'Links → interfaces → flows', body: 'How this device sits between your internet line and your network. Open Network / Gateway for links, Wi-Fi and zones, or Observe for live flows.', href: '/network/map', hrefLabel: 'Open Network / Gateway' }),
    perf: () => ({ title: 'Performance', crumb: 'Packets → verdicts → retention', body: 'What the inline sensor has handled since start-up and how much evidence the device keeps. Data older than the window is offloaded or summarised, never silently lost.', href: '/observe/live', hrefLabel: 'Open Observe' }),
  };
  const info = () => (open() ? cards[open()!]() : null);

  return (
    <AppShell path="/mission">
      <main class="pro-main" aria-label="Mission Control">
        <div class="pro-head">
          <div>
            <h1 class="pro-title">Mission Control</h1>
            <p class="pro-sub">What the system is doing right now{device() ? ' · live from this device' : ''}</p>
          </div>
        </div>

        <div class="bento">
          <button class="pcard span-4" onClick={() => setOpen('health')} style={{ 'border-width': '2px' }}>
            <span class="l0-label">Global health</span>
            <span class="mc-orb">
              <span class="mc-orb-ring" role="img" aria-label={`QSecBit ${qsecbit()}`}>
                <svg viewBox="0 0 100 100" aria-hidden="true">
                  <circle cx="50" cy="50" r={R} fill="none" stroke="rgba(255,255,255,.08)" stroke-width="6" />
                  <circle cx="50" cy="50" r={R} fill="none" stroke-width="6" stroke-linecap="round"
                    stroke={protectionStatus() === 'protected' ? 'var(--hp-green)' : protectionStatus() === 'needs-attention' ? 'var(--hp-amber)' : 'var(--hp-red)'}
                    stroke-dasharray={`${(qsecbit() / 100) * C} ${C}`} />
                </svg>
                <b aria-hidden="true">{qsecbit()}</b>
              </span>
              <span style={{ display: 'flex', 'flex-direction': 'column', gap: '4px' }}>
                <span style={{ 'font-size': '18px', 'font-weight': 700 }}>{WORD[protectionStatus()]}</span>
                <span class="pcard-note">
                  {sample() ? 'Detection 96 · Posture 88 · Exposure 91' : `${n(ds()?.rulesActive)} rules armed · ${n(ds()?.hostsActive)} devices watched`}
                </span>
              </span>
            </span>
          </button>

          <button class="pcard span-4" onClick={() => setOpen('pulse')}>
            <span class="l0-label">Threat pulse</span>
            <p class="pcard-kpi">{sample() ? '142' : n(ds()?.dropped)} <small>{sample() ? 'blocked today' : 'frames dropped since start-up'}</small></p>
            <svg width="100%" height="36" viewBox="0 0 300 36" preserveAspectRatio="none" aria-hidden="true">
              <polyline fill="none" stroke="var(--hp-cyan)" stroke-width="1.5"
                points={heartbeat().map((v, i, a) => `${((i / Math.max(1, a.length - 1)) * 300).toFixed(1)},${(36 - ((Math.max(0, Math.min(100, v)) / 100) * 34)).toFixed(1)}`).join(' ')} />
            </svg>
            <span class="pcard-note">
              {sample() ? 'Top: scanning 61 · phishing 34 · botnet 12'
                : families().length ? `Top: ${families().map(([k, v]) => `${k} ${v}`).join(' · ')}` : 'No detections yet'}
            </span>
          </button>

          <button class="pcard span-4" onClick={() => setOpen('engines')}>
            <span class="l0-label">Engines</span>
            <Show when={engineRows().length > 0} fallback={<span class="pcard-note">{device() ? 'Waiting for engine status…' : '—'}</span>}>
              <For each={engineRows().slice(0, 4)}>{(e) => (
                <span class="pbar">
                  <span class="pbar-name">{e.name}</span>
                  <span class="pbar-track"><span class="pbar-fill" style={{ width: `${(e.hits / maxHits()) * 100}%` }} /></span>
                  <span class="pbar-val">{e.hits.toLocaleString()}</span>
                </span>
              )}</For>
            </Show>
            <span class="pcard-note">
              {sample() ? '3 escalated · 20 fixed on its own · avg confidence 91%'
                : `${openInc().length} open incident${openInc().length === 1 ? '' : 's'} · ${actions().length} protective action${actions().length === 1 ? '' : 's'} in force`}
            </span>
          </button>

          <Show when={linked()}>
            <button class="pcard span-6" onClick={() => setOpen('fleet')}>
              <span class="l0-label">Fleet health</span>
              <span class="pcard-note">No fleet data from the control plane yet.</span>
            </button>
            <button class="pcard span-6" onClick={() => setOpen('customers')}>
              <span class="l0-label">Customer health</span>
              <span class="pcard-note">No tenant data from the control plane yet.</span>
            </button>
          </Show>

          <div class="pcard span-6">
            <button class="tab" style={{ padding: 0, 'min-height': '24px', 'text-align': 'left' }} onClick={() => setOpen('incidents')}>
              <span class="l0-label">Active incidents · {sample() ? 3 : openInc().length}</span>
            </button>
            <Show when={sample()} fallback={
              <Show when={openInc().length > 0} fallback={<span class="pcard-note">No open incidents.</span>}>
                <For each={openInc().slice(0, 4)}>{(i) => (
                  <a class="prow" href={incidentHref(i.id)} style={{ 'text-decoration': 'none', color: 'inherit' }}>
                    <span><span class={`sev sev--${i.priority.toLowerCase()}`}>{i.priority}</span>{i.title}</span>
                    <span>{hhmm(i.ts)}</span>
                  </a>
                )}</For>
              </Show>
            }>
              <For each={SAMPLE_INC}>{(i) => (
                <a class="prow" href="/investigate/queue" style={{ 'text-decoration': 'none', color: 'inherit' }}>
                  <span><span class={`sev sev--${i.priority.toLowerCase()}`}>{i.priority}</span>{i.title}</span><span>{i.when}</span>
                </a>
              )}</For>
            </Show>
          </div>

          <button class="pcard span-6" onClick={() => setOpen('actions')}>
            <span class="l0-label">Autonomous actions</span>
            <Show when={sample()} fallback={
              <Show when={actions().length + audit().length > 0} fallback={<span class="pcard-note">No protective actions recorded since start-up.</span>}>
                <For each={actions()}>{(a) => <span class="prow"><span>{a.kind.replace('_', ' ')} · {a.target}</span><span>{a.expires_in_s ? `${Math.ceil(a.expires_in_s / 60)} min left` : 'in force'}</span></span>}</For>
                <For each={audit()}>{(a) => <span class="prow"><span>{a.kind.replace('_', ' ')} · {a.target}</span><span>why: {a.reason}</span></span>}</For>
              </Show>
            }>
              <span class="prow"><span>Isolated Kitchen camera</span><span>why →</span></span>
              <span class="prow"><span>Blocked 38 login attempts</span><span>why →</span></span>
              <span class="prow"><span>Moved guest phone to Guests</span><span>why →</span></span>
            </Show>
          </button>

          <button class="pcard span-8" onClick={() => setOpen('infra')} style={{ 'min-height': '200px' }}>
            <span class="l0-label">Infrastructure</span>
            <span class="infra">
              <span class={`infra-node${wan() && !wan()!.up ? ' infra-node--down' : ''}`}>WAN<em>{sample() ? 'online' : wan() ? (wan()!.up ? `online · ${wan()!.mode}` : 'down') : 'not the gateway'}</em></span>
              <span aria-hidden="true">—</span>
              <span class="infra-node infra-node--self">This device<em>{sample() ? 'inline' : device() ? 'inline IPS' : '—'}</em></span>
              <span aria-hidden="true">—</span>
              <span class="infra-node">LAN<em>{sample() ? '24 devices' : `${devices().length} device${devices().length === 1 ? '' : 's'}`}</em></span>
              <span aria-hidden="true">—</span>
              <span class="infra-node">Wi-Fi<em>{sample() ? '21 devices' : wifi() ? `${wifi()!.ssid} · ch ${wifi()!.channel}` : 'not running'}</em></span>
            </span>
          </button>

          <button class="pcard span-4" onClick={() => setOpen('perf')}>
            <span class="l0-label">Performance</span>
            <Show when={!sample()} fallback={
              <>
                <span class="prow"><span>Ingest</span><span>1,240 ev/s</span></span>
                <span class="prow"><span>Verdict latency</span><span>0.8 ms</span></span>
                <span class="prow"><span>Storage · retention</span><span>62% · 7 days raw</span></span>
              </>
            }>
              <span class="prow"><span>Packets seen</span><span>{n(ds()?.seen)}</span></span>
              <span class="prow"><span>Forwarded / dropped</span><span>{n(ds()?.forwarded)} / {n(ds()?.dropped)}</span></span>
              <span class="prow"><span>Detections kept</span><span>{ds() ? `${ds()!.detections} of ${ds()!.detectionsCap}` : '—'}</span></span>
              <span class="prow"><span>Kept across restart</span><span>{ds() ? (ds()!.sealedCap > 0 ? `newest ${ds()!.sealedCap}` : 'none (memory only)') : '—'}</span></span>
              <span class="prow"><span>Last restart</span><span>{ds()?.lastReset ?? '—'}</span></span>
            </Show>
          </button>

          <div class="pcard span-12">
            <span class="l0-label">Activity timeline</span>
            <Show when={storyEvents().length > 0} fallback={<span class="pcard-note">Nothing has happened yet.</span>}>
              <div class="aitl">
                <For each={storyEvents().slice(0, 10)}>{(e) => (
                  <a class="aitl-item" href={e.href}>
                    <span class="aitl-when">{hhmm(e.ts)} · {e.cat}</span>
                    <span class="aitl-what">{e.title}</span>
                  </a>
                )}</For>
              </div>
            </Show>
          </div>
        </div>
      </main>

      <Drawer open={!!info()} title={info()?.title ?? ''} crumb={info()?.crumb} onClose={() => setOpen(null)}
        footer={<Show when={info()}><a class="hp-btn hp-btn--primary" href={info()!.href}>{info()!.hrefLabel} →</a></Show>}>
        <p>{info()?.body}</p>
      </Drawer>
    </AppShell>
  );
};

export default MissionControlApp;
