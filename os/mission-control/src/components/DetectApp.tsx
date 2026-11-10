/**
 * DetectApp — Detect (`/detect/feed`, NAPSE): detections and the rules behind them (wireframe
 * "Detect"; requirements doc §4).
 *
 *   Threat feed  severity + ATT&CK tactic filters; one card per detection with Open story / Graph
 *   Rules        the device's real engines (rules loaded, hits, last run); authoring is greyed:
 *                rules ship as signed packs (Administration → upload), not edited in the browser
 *   ATT&CK       tactic heatmap from the loaded detections; a cell filters the feed
 *
 * Live: /api/detections (+ /api/stream), /api/engines, /api/incidents. With no device answering,
 * the labelled sample feed renders. `.det-title` carries the rule message (the browser gate reads it).
 */
import { type Component, For, Show, createMemo, createSignal, onMount } from 'solid-js';
import { substrate } from '../store/mock';
import { healthChecked } from '../store/health';
import { severityLabel, formatTime, mitreName, mitreTactic, type DetectionRow } from '../store/api';
import { startDetectLive, detections, detectStatus, detectError, engines } from '../store/detectLive';
import { incidents, startInvestigateLive } from '../store/investigateLive';
import { incidentHref } from '../store/routes';
import AppShell from './AppShell';

type Tab = 'feed' | 'rules' | 'mitre';
type Sev = 'all' | 'critical' | 'high' | 'medium' | 'low';
const TACTICS = ['Reconnaissance', 'Resource Development', 'Initial Access', 'Execution', 'Persistence', 'Privilege Escalation', 'Defense Evasion',
  'Credential Access', 'Discovery', 'Lateral Movement', 'Collection', 'Command and Control', 'Exfiltration', 'Impact'];

const now = Math.floor(Date.now() / 1000);
const S = (id: string, sev: number, mitre: string, category: string, ago: number, rule_msg: string, src_ip: string, confidence: number): DetectionRow =>
  ({ id, ts: now - ago, rule_id: 0, rule_msg, category, severity: sev, mitre, src_ip, dst_ip: '', dst_port: 0, confidence });
const SAMPLE: DetectionRow[] = [
  S('s1', 2, 'T1071', 'ioc', 300, 'Device resolved known C2 domain', 'Kitchen camera', 0.97),
  S('s2', 2, 'T1046', 'scan', 320, 'IoT device scanning LAN', 'Kitchen camera', 0.92),
  S('s3', 3, 'T1110', 'bruteforce', 86400, 'Brute force on router admin', 'This device', 0.88),
  S('s4', 4, 'T1200', 'behavioral', 9000, 'New device without a known fingerprint', 'Unknown phone', 0.61),
];
const SAMPLE_ENGINES = [
  { name: 'Suricata-compatible signatures', kind: 'signature', status: 'active', loaded_rules: 41203, hits: 38, last_run_ts: now - 60 },
  { name: 'IOC lists', kind: 'ioc', status: 'active', loaded_rules: 1210, hits: 14, last_run_ts: now - 60 },
  { name: 'Sigma', kind: 'log', status: 'active', loaded_rules: 3910, hits: 6, last_run_ts: now - 120 },
  { name: 'YARA', kind: 'file', status: 'not_yet_run', loaded_rules: 2847, hits: 0, last_run_ts: null },
];

const pct = (c: number) => Math.round(c <= 1 ? c * 100 : c);

const DetectApp: Component = () => {
  const [tab, setTab] = createSignal<Tab>('feed');
  const [sev, setSev] = createSignal<Sev>('all');
  const [tactic, setTactic] = createSignal<string | null>(null);
  onMount(() => { startDetectLive(); startInvestigateLive(); });

  const sample = () => healthChecked() && !substrate();
  const rows = (): DetectionRow[] => (sample() ? SAMPLE : detections());
  const shown = createMemo(() => rows()
    .filter((d) => sev() === 'all' || severityLabel(d.severity) === sev())
    .filter((d) => !tactic() || mitreTactic(d.mitre) === tactic())
    .sort((a, b) => b.ts - a.ts));
  const counts = createMemo(() => {
    const c: Record<string, number> = { all: rows().length };
    for (const d of rows()) c[severityLabel(d.severity)] = (c[severityLabel(d.severity)] ?? 0) + 1;
    return c;
  });
  const heat = createMemo(() => {
    const m = new Map<string, number>();
    for (const d of rows()) m.set(mitreTactic(d.mitre), (m.get(mitreTactic(d.mitre)) ?? 0) + 1);
    return m;
  });
  const maxHeat = () => Math.max(1, ...heat().values());
  const storyFor = (d: DetectionRow) => {
    const inc = incidents().find((i) => i.device_ip === d.src_ip);
    return inc ? incidentHref(inc.id) : '/investigate/queue';
  };
  const engineRows = () => (sample() ? SAMPLE_ENGINES : engines());

  return (
    <AppShell path="/detect/feed">
      <main class="pro-main" aria-label="Detect">
        <div class="pro-head">
          <div>
            <h1 class="pro-title">Detect</h1>
            <p class="pro-sub">Detections and the rules behind them · NAPSE{substrate() ? ' · live from this device' : ''}</p>
          </div>
        </div>

        <div class="tabs" role="tablist" aria-label="Detect views">
          <For each={[['feed', 'Threat feed'], ['rules', 'Rules'], ['mitre', 'MITRE ATT&CK']] as [Tab, string][]}>{([t, label]) => (
            <button class="tab" role="tab" aria-selected={tab() === t} onClick={() => setTab(t)}>{label}</button>
          )}</For>
        </div>

        <Show when={tab() === 'feed'}>
          <div class="l0-chips" role="group" aria-label="Severity">
            <For each={['all', 'critical', 'high', 'medium', 'low'] as Sev[]}>{(s) => (
              <button class={`l0-chip${sev() === s ? ' is-on' : ''}`} aria-pressed={sev() === s} onClick={() => setSev(s)}>
                {s === 'all' ? 'All' : s[0].toUpperCase() + s.slice(1)} · {counts()[s] ?? 0}
              </button>
            )}</For>
            <Show when={tactic()}>
              <button class="l0-chip is-on" onClick={() => setTactic(null)} aria-label={`Clear tactic filter ${tactic()}`}>Tactic: {tactic()} ✕</button>
            </Show>
          </div>

          <Show when={sample() || detectStatus() !== 'error'} fallback={
            <div class="pcard"><p>Detections are not available right now.</p><p class="pcard-note">{detectError()}</p></div>
          }>
            <Show when={shown().length > 0} fallback={
              <p class="l0-muted">{!sample() && detectStatus() === 'loading' ? 'Loading detections…' : 'No detections match. That is good news.'}</p>
            }>
              <div class="bento" role="list" aria-label="Detections">
                <For each={shown().slice(0, 60)}>{(d) => (
                  <article class="pcard span-6" role="listitem" style={{ 'text-align': 'left' }}>
                    <span class="prow" style={{ border: 0, padding: 0 }}>
                      <span><span class={`sev sev--${severityLabel(d.severity)}`}>{severityLabel(d.severity).toUpperCase()}</span>{d.mitre ? `${d.mitre} · ${mitreName(d.mitre)}` : 'No ATT&CK mapping'}</span>
                      <span>{d.category} · {formatTime(d.ts)}</span>
                    </span>
                    <span class="det-title story-title" style={{ 'white-space': 'normal', 'font-size': '15px' }}>{d.rule_msg}</span>
                    <span class="pcard-note">
                      {sample() ? `Asset: ${d.src_ip}` : `${d.src_ip || '—'} → ${d.dst_ip ? `${d.dst_ip}${d.dst_port ? `:${d.dst_port}` : ''}` : '—'}`}
                      {` · confidence ${pct(d.confidence)}%`}
                    </span>
                    <span class="l0-card-foot">
                      <a class="hp-btn" href={sample() ? '/investigate/incident/?id=INC-0142' : storyFor(d)}>Open story</a>
                      <a class="hp-btn" href={sample() ? '/investigate/incident/?id=INC-0142' : storyFor(d)}>Graph</a>
                    </span>
                  </article>
                )}</For>
              </div>
              <Show when={shown().length > 60}><p class="pcard-note">Showing the newest 60 of {shown().length}.</p></Show>
            </Show>
          </Show>
        </Show>

        <Show when={tab() === 'rules'}>
          <div class="inc-layout">
            <section class="pcard" aria-label="Engines">
              <p class="l0-label">Engines on this device</p>
              <Show when={engineRows().length > 0} fallback={<p class="pcard-note">Waiting for engine status…</p>}>
                <div class="l0-table-wrap"><table class="l0-table">
                  <thead><tr><th scope="col">Engine</th><th scope="col">Status</th><th scope="col">Rules</th><th scope="col">Hits</th><th scope="col">Last run</th></tr></thead>
                  <tbody><For each={engineRows()}>{(e) => (
                    <tr>
                      <td>{e.name}{e.kind ? <span class="l0-muted"> · {e.kind}</span> : ''}</td>
                      <td>{e.status === 'active' ? 'Active' : e.status === 'not_yet_run' ? 'Not run yet' : 'Unknown'}</td>
                      <td class="l0-num" style={{ 'font-weight': 400 }}>{e.loaded_rules?.toLocaleString() ?? '—'}</td>
                      <td class="l0-num" style={{ 'font-weight': 400 }}>{e.hits?.toLocaleString() ?? '—'}</td>
                      <td>{e.last_run_ts ? formatTime(e.last_run_ts) : '—'}</td>
                    </tr>
                  )}</For></tbody>
                </table></div>
              </Show>
            </section>
            <aside class="pcard" aria-label="Rule builder">
              <p class="l0-label">Rule builder</p>
              <p class="l0-card-sub">Rules run on this device only as signed packs, so a rule edited in the browser could never be trusted. Write a rule, test it, and sign it with your operator key; then upload the pack.</p>
              <span class="gate gate--off" title="Rule packs are signed offline and uploaded">
                <span class="gate-body" ref={(el) => el.setAttribute('inert', '')} aria-hidden="true"><button class="hp-btn">Edit rule</button> <button class="hp-btn">Run test</button></span>
                <span class="gate-reason" role="note">Authoring happens offline; this device accepts signed rule packs only.</span>
              </span>
              <a class="hp-btn" href="/admin/identity">Upload a signed rule pack</a>
            </aside>
          </div>
        </Show>

        <Show when={tab() === 'mitre'}>
          <p class="l0-card-sub" style={{ margin: 0 }}>Brighter means more detections among those loaded. Select a tactic to filter the feed.</p>
          <div class="bento" role="list" aria-label="ATT&CK tactics">
            <For each={[...TACTICS, ...(heat().has('Unmapped') ? ['Unmapped'] : [])]}>{(t) => {
              const n = () => heat().get(t) ?? 0;
              return (
                <button class="pcard span-4" role="listitem" onClick={() => { setTactic(t); setTab('feed'); }}
                  style={{ background: n() ? `rgba(168, 85, 247, ${0.12 + 0.5 * (n() / maxHeat())})` : undefined }}
                  aria-label={`${t}: ${n()} detection${n() === 1 ? '' : 's'}`}>
                  <span style={{ 'font-size': '13px' }}>{t}</span>
                  <span class="pcard-kpi" style={{ 'font-size': '20px' }}>{n()}</span>
                </button>
              );
            }}</For>
          </div>
        </Show>
      </main>
    </AppShell>
  );
};

export default DetectApp;
