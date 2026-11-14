/**
 * ObserveApp — Observe (`/observe/live`, Senzorium): all telemetry entering the platform as one
 * live table (wireframe "Observe"; requirements doc §3). The plain-words story of the same data is
 * Timeline & Export (`/observe/events`).
 *
 * Sources (each a real device feed): Connections (/api/flows), DNS (/api/dns query log),
 * Detections (/api/detections), Devices (/api/devices), TLS clients (/api/tls JA4 + SNI).
 * Live / Paused freezes a snapshot. A row opens the Drawer with its details and the related
 * incident. Raw packet capture is not offered: the device does not keep pcap.
 */
import { type Component, For, Show, createMemo, createSignal, onCleanup, onMount } from 'solid-js';
import { substrate, deviceStats } from '../store/mock';
import { CAMERA, SAMPLE_NOW } from '../store/sampleClock';
import { healthChecked } from '../store/health';
import { formatTime, formatBytes, severityLabel } from '../store/api';
import { flows, devices, refetch as refetchObs } from '../store/obsLive';
import { dnsLive, startDnsLive, QTYPE, VERDICT_LABEL } from '../store/dnsLive';
import { detections, startDetectLive } from '../store/detectLive';
import { tlsClients, refetchTls } from '../store/tlsLive';
import { incidents, startInvestigateLive } from '../store/investigateLive';
import { incidentHref } from '../store/routes';
import AppShell from './AppShell';
import Drawer from './Drawer';

type Src = 'Connections' | 'DNS' | 'Detections' | 'Devices' | 'TLS';
const SOURCES: Src[] = ['Connections', 'DNS', 'Detections', 'Devices', 'TLS'];
type Sev = 'critical' | 'high' | 'medium' | 'low' | 'info';
interface Ev { id: string; ts: number; src: Src; entity: string; sev: Sev; sum: string; facts: [string, string][]; href?: string }

const BLOCKED = new Set(['blocked', 'blocked-cname', 'tcp53-refused']);
const now = SAMPLE_NOW;
const SAMPLE: Ev[] = [
  { id: 's1', ts: CAMERA.isolated, src: 'Detections', entity: 'Kitchen camera', sev: 'high', sum: 'Device isolated by policy', facts: [['Action', 'Isolate 1 h'], ['Reason', 'Contacted a known C2 domain']] },
  { id: 's2', ts: CAMERA.scan, src: 'Connections', entity: 'Kitchen camera', sev: 'high', sum: '6 connection attempts to LAN hosts', facts: [['Protocol', 'tcp'], ['Targets', '6 local devices']] },
  { id: 's3', ts: CAMERA.dns, src: 'DNS', entity: 'Kitchen camera', sev: 'medium', sum: 'First-seen domain resolved', facts: [['Verdict', 'blocked']] },
  { id: 's4', ts: now - 230, src: 'TLS', entity: 'Alina MacBook', sev: 'info', sum: 'TLS 1.3 to cloud storage', facts: [['JA4', 't13d1516h2_8daaf6152771_02713d6af862']] },
  { id: 's5', ts: now - 376, src: 'DNS', entity: 'Smart TV', sev: 'low', sum: '38 tracker lookups blocked', facts: [] },
  { id: 's6', ts: now - 778, src: 'Devices', entity: 'Ana iPad', sev: 'info', sum: 'Joined the network', facts: [] },
];

const ObserveApp: Component = () => {
  const [src, setSrc] = createSignal<Src | 'All'>('All');
  const [q, setQ] = createSignal('');
  const [live, setLive] = createSignal(true);
  const [frozen, setFrozen] = createSignal<Ev[] | null>(null);
  const [sel, setSel] = createSignal<Ev | null>(null);

  onMount(() => {
    startDnsLive(); startDetectLive(); startInvestigateLive();
    const tick = () => { if (live()) { void refetchObs(); void refetchTls(); } };
    tick();
    const t = setInterval(tick, 10_000);
    onCleanup(() => clearInterval(t));
  });

  const sample = () => healthChecked() && !substrate();
  const storyFor = (ip: string) => {
    const inc = incidents().find((i) => i.device_ip === ip);
    return inc ? incidentHref(inc.id) : undefined;
  };

  const liveEvents = createMemo<Ev[]>(() => {
    const out: Ev[] = [];
    for (const f of flows()) out.push({
      id: `f-${f.id}`, ts: f.ts, src: 'Connections', entity: f.src_ip, sev: 'info',
      sum: `${f.proto} ${f.src_ip}:${f.src_port} → ${f.dst_ip}:${f.dst_port} · ${f.conn_state}`,
      facts: [['From', `${f.src_ip}:${f.src_port}`], ['To', `${f.dst_ip}:${f.dst_port}`], ['Protocol', f.proto], ['State', f.conn_state], ['Sent / received', `${formatBytes(f.orig_bytes)} / ${formatBytes(f.resp_bytes)}`]],
      href: storyFor(f.src_ip),
    });
    for (const r of dnsLive()?.recent ?? []) out.push({
      id: `d-${r.ts}-${r.client}-${r.name}`, ts: r.ts, src: 'DNS', entity: r.client, sev: BLOCKED.has(r.verdict) ? 'low' : 'info',
      sum: `${QTYPE[r.qtype] ?? r.qtype} ${r.name} · ${VERDICT_LABEL[r.verdict] ?? r.verdict}`,
      facts: [['Name', r.name], ['Type', String(QTYPE[r.qtype] ?? r.qtype)], ['Verdict', VERDICT_LABEL[r.verdict] ?? r.verdict], ['Client', r.client]],
    });
    for (const d of detections()) out.push({
      id: `x-${d.id}`, ts: d.ts, src: 'Detections', entity: d.src_ip, sev: severityLabel(d.severity),
      sum: d.rule_msg,
      facts: [['Rule', `${d.rule_id} · ${d.rule_msg}`], ['Category', d.category], ['ATT&CK', d.mitre || '—'], ['Target', d.dst_ip ? `${d.dst_ip}${d.dst_port ? `:${d.dst_port}` : ''}` : '—']],
      href: storyFor(d.src_ip),
    });
    for (const v of devices()) out.push({
      id: `v-${v.id}`, ts: v.first_seen, src: 'Devices', entity: v.label || v.hostname || v.ip, sev: 'info',
      sum: `Joined the network${v.active === false ? ' · lease expired' : ''}`,
      facts: [['Address', v.ip], ['Hardware address', v.mac ?? '—'], ['Last seen', formatTime(v.last_seen)]],
    });
    for (const t of tlsClients()) out.push({
      id: `t-${t.client}-${t.ja4}-${t.sni}`, ts: Math.floor(t.last_ms / 1000), src: 'TLS', entity: t.lease || t.client,
      sev: t.ioc ? 'high' : t.shield_bypass ? 'medium' : 'info',
      sum: `TLS to ${t.sni || 'unnamed server'} · ${t.count} hello${t.count === 1 ? '' : 's'}${t.ioc ? ' · known-bad client' : ''}${t.shield_bypass ? ' · bypassed Shield' : ''}`,
      facts: [['JA4', t.ja4], ['Server name', t.sni || '—'], ['Hellos', String(t.count)]],
      href: storyFor(t.client),
    });
    return out.sort((a, b) => b.ts - a.ts);
  });

  const all = () => frozen() ?? (sample() ? SAMPLE : liveEvents());
  const counts = createMemo(() => {
    const c: Record<string, number> = { All: all().length };
    for (const e of all()) c[e.src] = (c[e.src] ?? 0) + 1;
    return c;
  });
  const shown = createMemo(() => {
    const needle = q().trim().toLowerCase();
    return all().filter((e) => (src() === 'All' || e.src === src()) && (!needle || `${e.entity} ${e.sum} ${e.src}`.toLowerCase().includes(needle)));
  });

  const toggleLive = () => {
    if (live()) { setFrozen(all()); setLive(false); } else { setFrozen(null); setLive(true); }
  };
  const retention = () => {
    const d = deviceStats();
    if (sample()) return 'Raw packets kept 7 days';
    if (!d) return '';
    return `Keeps newest ${d.detectionsCap} detections${d.sealedCap > 0 ? ` · ${d.sealedCap} across restart` : ' · memory only'}`;
  };

  return (
    <AppShell path="/observe/live">
      <main class="pro-main" aria-label="Observe">
        <div class="pro-head">
          <div>
            <h1 class="pro-title">Observe</h1>
            <p class="pro-sub">All telemetry entering the platform{substrate() ? ' · live from this device' : ''}</p>
          </div>
          <div class="l0-head-actions">
            <Show when={substrate() || sample()}><span class="inc-status">{sample() ? 'eth0 inline · eth1 out-of-band' : 'Inline · every frame checked both ways'}</span></Show>
            <Show when={retention()}><span class="inc-status">{retention()}</span></Show>
            <button class={`hp-btn${live() ? ' hp-btn--primary' : ''}`} aria-pressed={live()} onClick={toggleLive}>{live() ? '● Live' : 'Paused · resume'}</button>
          </div>
        </div>

        <div class="obs-grid">
          <nav class="pcard obs-sources" aria-label="Sources">
            <p class="l0-label" style={{ padding: '0 8px 6px' }}>Sources</p>
            <For each={['All', ...SOURCES] as (Src | 'All')[]}>{(s) => (
              <button class={`shell-rail-item${src() === s ? ' is-active' : ''}`} aria-pressed={src() === s} onClick={() => setSrc(s)} style={{ 'justify-content': 'space-between' }}>
                <span>{s}</span><span class="l0-num" style={{ 'font-weight': 400, 'font-size': '12px' }}>{counts()[s] ?? 0}</span>
              </button>
            )}</For>
          </nav>

          <section style={{ display: 'flex', 'flex-direction': 'column', gap: '12px', 'min-width': 0 }}>
            <label class="l0-card-sub" style={{ display: 'flex', 'flex-direction': 'column', gap: '4px' }}>
              Filter
              <input value={q()} onInput={(e) => setQ(e.currentTarget.value)} placeholder="address, name, domain or rule"
                style={{ font: 'inherit', 'min-height': '40px', padding: '0 12px', background: 'var(--hp-surface)', color: 'var(--hp-text-primary)', border: '1px solid var(--hp-border)', 'border-radius': 'var(--hp-radius)' }} />
            </label>
            <div class="l0-table-wrap">
              <table class="l0-table obs-table">
                <thead><tr><th scope="col">Time</th><th scope="col">Source</th><th scope="col">Entity</th><th scope="col">Severity</th><th scope="col">Summary</th></tr></thead>
                <tbody>
                  <Show when={shown().length > 0} fallback={<tr><td colSpan={5} class="l0-muted">{substrate() || sample() ? 'Nothing matches.' : 'Loading…'}</td></tr>}>
                    <For each={shown().slice(0, 200)}>{(e) => (
                      <tr>
                        <td class="l0-num" style={{ 'font-weight': 400, 'white-space': 'nowrap', 'font-size': '12px' }}>{formatTime(e.ts)}</td>
                        <td>{e.src}</td>
                        <td style={{ 'overflow-wrap': 'anywhere' }}>{e.entity}</td>
                        <td><span class={`sev sev--${e.sev}`}>{e.sev.toUpperCase()}</span></td>
                        <td><button class="dev-btn" style={{ border: 0, padding: 0, background: 'none', 'min-height': '28px', 'white-space': 'normal' }} onClick={() => setSel(e)}>{e.sum}</button></td>
                      </tr>
                    )}</For>
                  </Show>
                </tbody>
              </table>
            </div>
            <Show when={shown().length > 200}><p class="pcard-note">Showing the newest 200 of {shown().length}.</p></Show>
          </section>
        </div>
      </main>

      <Drawer open={!!sel()} title={sel()?.sum ?? ''} crumb={sel() ? `${sel()!.src} · ${sel()!.entity} · ${formatTime(sel()!.ts)}` : ''} onClose={() => setSel(null)}
        footer={<Show when={sel()?.href}><a class="hp-btn hp-btn--primary" href={sel()!.href}>Open related incident</a></Show>}>
        <p class="l0-label">Details</p>
        <div class="dev-facts">
          <For each={sel()?.facts ?? []}>{([k, v]) => <p class="l0-card-sub">{k}<b>{v}</b></p>}</For>
        </div>
        <p class="l0-label">Packets</p>
        <span class="gate gate--off">
          <span class="gate-body" ref={(el) => el.setAttribute('inert', '')} aria-hidden="true"><button class="hp-btn">Download pcap</button></span>
          <span class="gate-reason" role="note">{sample() ? 'Preview: no device is answering, so there is no capture to download.' : 'This device does not keep packet captures.'} Send events to your own system from Timeline &amp; Export to keep them longer.</span>
        </span>
      </Drawer>
    </AppShell>
  );
};

export default ObserveApp;
