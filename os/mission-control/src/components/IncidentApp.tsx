/**
 * IncidentApp — one incident as a story (`/investigate/:id`; served from
 * `/investigate/incident/?id=…` until the device maps the canonical path). Wireframe "Investigate";
 * requirements doc §5 "Incident story (the key screen)".
 *
 *   left (8)  tabs: Story · Evidence · Graph · Executive summary
 *   right (4) Why this was decided (confidence, evidence, model, ATT&CK) · Proposed plan
 *
 * Live data: /api/incidents/:id, …/timeline, …/processes, /api/evidence/graph, /api/reports/:id.
 * The device correlates deterministically: when no AI planner ran, the model line says so and no
 * plan is invented; the Copilot can propose one (PlanDiff, staged → applying → verified).
 * Below 1024 px the plan column moves under the story with a sticky "Review plan" bar.
 */
import { type Component, For, Show, createEffect, createSignal, onMount } from 'solid-js';
import { substrate, setCopilotOpen, setCopilotQuery } from '../store/mock';
import { healthChecked } from '../store/health';
import { promptAndRun } from '../store/actions';
import { formatTime, mitreName, mitreTactic, type IncidentTimelineEvent, type ProcessTreeNode } from '../store/api';
import {
  detail, detailStatus, detailError, fetchIncidentDetail, mitreForRelatedEvents,
  timelineEvents, timelineStatus, fetchIncidentTimeline,
  processRoots, fetchIncidentProcessTree,
  reportDetail, reportDetailStatus, syncReportForIncident,
  type RelatedMitre,
} from '../store/investigateLive';
import { incidentIdFromLocation } from '../store/routes';
import AppShell from './AppShell';
import PlanDiff from './PlanDiff';

type Tab = 'story' | 'evidence' | 'graph' | 'summary';
const TABS: [Tab, string][] = [['story', 'Story'], ['evidence', 'Evidence'], ['graph', 'Graph'], ['summary', 'Executive summary']];

const KIND: Record<string, string> = { detection: 'Detection', flow: 'Connection', response: 'Response', process: 'Process', file: 'File', registry: 'Registry', incident: 'Incident' };
const NODE: Record<string, string> = { inc: 'Incident', det: 'Detection', dev: 'Device', ioc: 'Indicator', flow: 'Connection', proc: 'Process', act: 'Action' };

/** Shown only when no device answers (preview build), under the Sample-data banner. */
const SAMPLE = {
  id: 'INC-0142', title: 'Kitchen camera contacted a malware host', device_ip: '10.66.0.42', priority: 'HIGH', status: 'open', ts: 0,
  why: 'The camera resolved a domain on 3 threat feeds, then tried to connect to 6 other devices. Policy allows auto-isolation of IoT devices.',
  confidence: 94, evidence: 4,
  steps: [
    { t: '13:04:51', engine: 'Senzorium', title: 'Unusual DNS lookup', body: 'Kitchen camera resolved a domain it has never used before.', kind: 'flow' },
    { t: '13:04:52', engine: 'HYDRA', title: 'Domain flagged', body: 'The domain appears on 3 threat-intel feeds as botnet command and control.', kind: 'detection' },
    { t: '13:04:58', engine: 'NAPSE', title: 'Local scanning detected', body: 'The camera tried to connect to 6 other devices on the network.', kind: 'detection' },
    { t: '13:05:00', engine: 'AEGIS', title: 'Isolated automatically', body: 'Internet and LAN access cut. DHCP and DNS keep working.', kind: 'response' },
  ],
  plan: [
    { kind: 'added' as const, text: 'block domain for all zones' },
    { kind: 'changed' as const, text: 'camera: isolated → internet only' },
    { kind: 'added' as const, text: 'notify me if it repeats' },
  ],
};

const ProcItem: Component<{ n: ProcessTreeNode; depth: number }> = (p) => (
  <li style={{ 'padding-left': `${p.depth * 16}px` }}>
    <span class="prow"><span>pid {p.n.pid} · {p.n.name} <span class="l0-muted">{p.n.cmdline}</span></span><span>{formatTime(p.n.ts)}</span></span>
    <Show when={p.n.children.length}><ul style={{ 'list-style': 'none', margin: 0, padding: 0 }}><For each={p.n.children}>{(c) => <ProcItem n={c} depth={p.depth + 1} />}</For></ul></Show>
  </li>
);

const IncidentApp: Component = () => {
  const [id, setId] = createSignal<string | null>(null);
  const [tab, setTab] = createSignal<Tab>('story');
  const [msg, setMsg] = createSignal('');
  const [mitre, setMitre] = createSignal<RelatedMitre[]>([]);
  const [resolved, setResolved] = createSignal(false);

  onMount(() => {
    setId(incidentIdFromLocation(location));
    setResolved(true);
  });
  createEffect(() => {
    const i = id();
    if (!i || !substrate()) return;
    void fetchIncidentDetail(i);
    void fetchIncidentTimeline(i);
    void fetchIncidentProcessTree(i);
    void syncReportForIncident(i);
  });
  createEffect(() => {
    const d = detail();
    if (d && d.id === id()) void mitreForRelatedEvents(d.explanation.related_events).then(setMitre);
  });

  const sample = () => healthChecked() && !substrate();
  const d = () => (detail() && detail()!.id === id() ? detail() : null);

  const title = () => (sample() ? SAMPLE.title : d()?.title ?? (id() ?? 'Incident'));
  const priority = () => (sample() ? SAMPLE.priority : d()?.priority ?? '');
  const status = () => (sample() ? SAMPLE.status : d()?.status ?? '');
  /** heqk reports a 0–1 fraction (0.5 / 0.9); planners may report 0–100. Show a percentage either way. */
  const confidence = () => {
    if (sample()) return SAMPLE.confidence;
    const c = d()?.explanation.confidence ?? 0;
    return Math.round(c <= 1 ? c * 100 : c);
  };
  const askCopilot = () => { setCopilotQuery(`Explain incident ${id() ?? ''} and propose a plan`); setCopilotOpen(true); };

  const storyRows = (): { meta: string; title: string; body: string; kind: string }[] => {
    if (sample()) return SAMPLE.steps.map((s) => ({ meta: `${s.t} · ${s.engine}`, title: s.title, body: s.body, kind: s.kind }));
    return timelineEvents().map((e: IncidentTimelineEvent) => ({ meta: `${formatTime(e.ts)} · ${KIND[e.kind] ?? e.kind}`, title: e.label, body: '', kind: e.kind }));
  };

  return (
    <AppShell path="/investigate/incident">
      <main class="pro-main" aria-label="Incident story">
        <Show when={!resolved() || id() || sample()} fallback={
          <div class="l0-card"><p>No incident selected.</p><a class="hp-btn" href="/investigate/queue">Open the incident queue</a></div>
        }>
          <div class="pro-head">
            <div style={{ 'min-width': 0 }}>
              <p class="pro-crumb"><a href="/investigate/queue">Investigate</a> / <a href="/investigate/queue">Queue</a> / {sample() ? SAMPLE.id : id()}</p>
              <div class="inc-head-row">
                <h1 class="pro-title">{title()}</h1>
                <Show when={priority()}><span class={`sev sev--${priority().toLowerCase()}`}>{priority()}</span></Show>
                <Show when={status()}><span class="inc-status">{status()}</span></Show>
              </div>
              <p class="pro-sub">
                {sample() ? `Sample data · ${SAMPLE.device_ip} · ATT&CK T1071 Application Layer Protocol · opened 13:05`
                  : d() ? `${d()!.device_ip} · ${d()!.explanation.related_events.length} related detection${d()!.explanation.related_events.length === 1 ? '' : 's'} · opened ${formatTime(d()!.ts)}` : ''}
              </p>
            </div>
            <div class="l0-head-actions">
              <Show when={!sample() && d()?.id.startsWith('inc:heqk:')}>
                <button class="hp-btn" disabled={status() === 'acknowledged'} onClick={async () => setMsg(await promptAndRun('ack', d()!.device_ip, 0))}>Acknowledge</button>
                <button class="hp-btn" title="Hold all traffic from/to this address for 1 hour (expires on its own)" onClick={async () => setMsg(await promptAndRun('hold_ip', d()!.device_ip, 3600))}>Hold source 1 h</button>
              </Show>
              <button class="hp-btn" onClick={askCopilot}>Ask Copilot</button>
            </div>
          </div>
          <Show when={msg()}><p class="pro-sub" role="status">{msg()}</p></Show>

          <Show when={sample() || detailStatus() !== 'error'} fallback={
            <div class="l0-card"><p>This incident could not be loaded.</p><p class="pcard-note">{detailError()}</p><a class="hp-btn" href="/investigate/queue">Back to the queue</a></div>
          }>
            <div class="inc-layout">
              <section style={{ display: 'flex', 'flex-direction': 'column', gap: '16px', 'min-width': 0 }}>
                <div class="tabs" role="tablist" aria-label="Incident views">
                  <For each={TABS}>{([t, label]) => (
                    <button class="tab" role="tab" id={`tab-${t}`} aria-selected={tab() === t} aria-controls={`panel-${t}`} onClick={() => setTab(t)}>{label}</button>
                  )}</For>
                </div>

                <div role="tabpanel" id={`panel-${tab()}`} aria-labelledby={`tab-${tab()}`} class="pcard">
                  <Show when={tab() === 'story'}>
                    <Show when={storyRows().length > 0} fallback={<p class="pcard-note">{!sample() && timelineStatus() === 'loading' ? 'Loading the story…' : 'No timeline events recorded for this incident.'}</p>}>
                      <ol class="story">
                        <For each={storyRows()}>{(s, i) => (
                          <li class="story-step">
                            <span class="story-rail" aria-hidden="true">
                              <span class={`story-dot story-dot--${s.kind}`} />
                              <Show when={i() < storyRows().length - 1}><span class="story-line" /></Show>
                            </span>
                            <span class="story-body">
                              <span class="story-meta">{s.meta}</span>
                              <span class="story-title">{s.title}</span>
                              <Show when={s.body}><span class="l0-card-sub">{s.body}</span></Show>
                            </span>
                          </li>
                        )}</For>
                      </ol>
                    </Show>
                  </Show>

                  <Show when={tab() === 'evidence'}>
                    <Show when={!sample()} fallback={
                      <div class="l0-table-wrap"><table class="l0-table"><thead><tr><th>Time</th><th>Type</th><th>Entity</th><th>Kept</th></tr></thead><tbody>
                        <tr><td>13:04:51</td><td>DNS query</td><td>Kitchen camera</td><td>Raw · 7 days</td></tr>
                        <tr><td>13:04:52</td><td>Intel match</td><td>Domain</td><td>Kept</td></tr>
                        <tr><td>13:04:58</td><td>Flows ×6</td><td>LAN devices</td><td>Raw · 7 days</td></tr>
                        <tr><td>13:05:00</td><td>Action</td><td>Isolation</td><td>Audit log</td></tr>
                      </tbody></table></div>
                    }>
                      <p class="l0-label">Linked evidence · {d()?.attack_path.node_count ?? 0} items</p>
                      <div class="l0-table-wrap"><table class="l0-table"><thead><tr><th>Type</th><th>Item</th></tr></thead><tbody>
                        <For each={d()?.attack_path.nodes ?? []}>{(nd) => <tr><td>{NODE[nd.type] ?? nd.type}</td><td style={{ 'overflow-wrap': 'anywhere' }}>{nd.label || nd.id}</td></tr>}</For>
                      </tbody></table></div>
                      <Show when={processRoots().length > 0}>
                        <p class="l0-label">Process tree</p>
                        <ul style={{ 'list-style': 'none', margin: 0, padding: 0 }}><For each={processRoots()}>{(r) => <ProcItem n={r} depth={0} />}</For></ul>
                      </Show>
                      <a class="l0-link-row" href="/detect/feed">See the detections in Detect →</a>
                    </Show>
                  </Show>

                  <Show when={tab() === 'graph'}>
                    <div class="chain" role="list" aria-label="Attack path">
                      <Show when={!sample()} fallback={
                        <For each={['Kitchen camera', 'DNS lookup', 'Malware host', 'Isolated']}>{(x, i) => (
                          <><span class="chain-node" role="listitem">{x}</span><Show when={i() < 3}><span aria-hidden="true">→</span></Show></>
                        )}</For>
                      }>
                        <For each={d()?.attack_path.nodes ?? []}>{(nd, i) => (
                          <><span class="chain-node" role="listitem"><em>{NODE[nd.type] ?? nd.type}</em>{nd.label || nd.id}</span>
                            <Show when={i() < (d()?.attack_path.nodes.length ?? 0) - 1}><span aria-hidden="true">→</span></Show></>
                        )}</For>
                      </Show>
                    </div>
                    <p class="pcard-note">{sample() ? '' : `${d()?.attack_path.node_count ?? 0} items linked by ${d()?.attack_path.edge_count ?? 0} relations in the evidence graph.`}</p>
                  </Show>

                  <Show when={tab() === 'summary'}>
                    <h2 style={{ margin: 0, 'font-size': '18px' }}>Executive summary</h2>
                    <Show when={!sample()} fallback={
                      <p>A camera in the kitchen tried to reach a known malware server and probe other devices. HookProbe isolated it within seconds. No data left the network. Recommended next step: update or replace the camera.</p>
                    }>
                      <Show when={reportDetail() && reportDetail()!.incident_id === id()} fallback={
                        <p class="l0-muted">{reportDetailStatus() === 'loading' ? 'Loading the report…' : `No report generated yet. What the device knows: ${d()?.explanation.why ?? ''}`}</p>
                      }>
                        <p>{reportDetail()!.summary}</p>
                        <Show when={reportDetail()!.report.response_taken.length > 0}>
                          <p class="l0-label">Response taken</p>
                          <For each={reportDetail()!.report.response_taken}>{(r) => <span class="prow"><span>{r.action} · {r.target}</span><span>{r.status}</span></span>}</For>
                        </Show>
                        <p class="pcard-note">Report generated {formatTime(reportDetail()!.report.generated_ts)} · a point-in-time snapshot of the evidence.</p>
                      </Show>
                    </Show>
                    <div><button class="hp-btn" onClick={() => window.print()}>Print or save as PDF</button></div>
                  </Show>
                </div>
              </section>

              <aside class="inc-side" aria-label="Decision">
                <div class="pcard">
                  <p class="l0-label">Why this was decided</p>
                  <p style={{ margin: 0 }}>{sample() ? SAMPLE.why : d()?.explanation.why ?? '…'}</p>
                  <div class="l0-meter" role="img" aria-label={`Confidence ${confidence()}%`}>
                    <span class="l0-meter-track"><span class="l0-meter-fill" style={{ width: `${confidence()}%` }} /></span>
                    <span class="l0-num">{confidence()}%</span>
                  </div>
                  <span class="prow"><span>Evidence items</span><span>{sample() ? SAMPLE.evidence : d()?.explanation.evidence ?? '—'}</span></span>
                  <span class="prow"><span>Decided by</span><span>{sample() ? 'local · deterministic' : d()?.explanation.model ?? 'device rules · no AI model'}</span></span>
                  <Show when={mitre().length > 0}>
                    <p class="l0-label">ATT&amp;CK</p>
                    <For each={mitre()}>{(m) => <span class="prow"><span>{m.id} · {mitreName(m.id)}</span><span>{mitreTactic(m.id)}</span></span>}</For>
                  </Show>
                  <details>
                    <summary class="pcard-note" style={{ cursor: 'pointer' }}>Alternative hypotheses</summary>
                    <p class="pcard-note">{sample() ? 'Firmware update server misconfigured (4%).' : 'None recorded: the device correlates by rule, not by competing hypotheses. Ask Copilot to weigh alternatives.'}</p>
                  </details>
                </div>

                <div class="pcard inc-plan-sticky">
                  <Show when={sample()} fallback={
                    <>
                      <p class="l0-label">Proposed plan</p>
                      <p class="l0-card-sub">No plan has been proposed for this incident. The device's own response is in the story. Ask Copilot to propose a plan you can approve.</p>
                      <div><button class="hp-btn hp-btn--primary" onClick={askCopilot}>Ask Copilot for a plan</button></div>
                    </>
                  }>
                    <PlanDiff lines={SAMPLE.plan} onApprove={() => Promise.reject(new Error('Preview: no device is connected to apply this.'))} />
                  </Show>
                </div>
              </aside>
            </div>
          </Show>
        </Show>
      </main>
    </AppShell>
  );
};

export default IncidentApp;
