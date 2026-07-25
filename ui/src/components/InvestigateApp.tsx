/**
 * InvestigateApp — Investigate (§5, AEGIS): "everything becomes a story".
 *
 * Spec: docs/MissionControl.md §5 — the differentiator. Incident Queue + Incident Story +
 * Why AEGIS decided this (confidence · evidence · model) + ATT&CK context + Attack Timeline +
 * Process Tree + Executive Report + the Evidence Graph explorer, all drilled from the real
 * evidence graph.
 *
 * WIRED to the real `hookprobe-api` read-API (ADR 0001) via `store/investigateLive.ts`:
 *   - Queue:          `GET /api/incidents` (+ `/api/stream` deltas).
 *   - Detail:         `GET /api/incidents/:id` — the why/confidence/evidence/model/related_events envelope.
 *   - Timeline:       `GET /api/incidents/:id/timeline` — the ts-ordered incident-story narrative.
 *   - Process tree:   `GET /api/incidents/:id/processes` — the host-layer `spawned_by` walk.
 *   - Reports:        `GET /api/reports` (list) + `GET /api/reports/:id` (the executive report that
 *                      cites raw evidence) — the evidence-chain terminus.
 *   - Evidence graph:  `GET /api/evidence/graph?node=` (the "everything clickable" drill-down, any
 *                      node id) + `GET /api/evidence/stats` (retention/size visibility).
 * `model: null` renders honestly as "No AI planner run" (never a fabricated model name) — see
 * `store/investigateLive.ts`'s doc comment for the full list of what the real envelopes do NOT
 * (yet) carry: alternative hypotheses, a per-incident threat-intel panel, and a proposed
 * remediation plan. Those sections render an honest "not available yet" state instead of the old
 * mock's fabricated content.
 */

import { type Component, For, Show, createSignal, createEffect, onMount } from 'solid-js';
import LeftRail from './LeftRail';
import CommandPalette from './CommandPalette';
import LiveState from './LiveState';
import { setCopilotOpen, setCopilotQuery, copilotOpen, copilotQuery } from '../store/mock';
import type { Tone } from '../store/missionMock';
import { formatTime, formatBytes, mitreName, mitreTactic, type ProcessTreeNode } from '../store/api';
import {
  startInvestigateLive, incidents, queueStatus, queueError,
  detail, detailStatus, detailError, fetchIncidentDetail, mitreForRelatedEvents,
  timelineEvents, timelineStatus, timelineError, fetchIncidentTimeline,
  processRoots, processCount, processStatus, processError, fetchIncidentProcessTree,
  reports, reportsStatus, reportsError, fetchReportDetail, syncReportForIncident,
  reportDetail, reportDetailStatus, reportDetailError,
  graphNodeQuery, graphResult, graphStatus, graphError, exploreEvidenceNode,
  evidenceStats, evidenceStatsStatus, evidenceStatsError,
  type RelatedMitre,
} from '../store/investigateLive';

function toneVar(t: Tone): string {
  return {
    green: 'var(--hp-green)', amber: 'var(--hp-amber)', red: 'var(--hp-red)',
    blue: 'var(--hp-cyan)', cyan: 'var(--hp-cyan)', purple: 'var(--hp-purple)',
    orange: 'var(--hp-orange)', grey: 'var(--hp-grey)',
  }[t];
}

/** `attack_path` nodes carry no severity — a coarse, honest tone by node TYPE (id prefix). */
function nodeTone(type: string): Tone {
  switch (type) {
    case 'inc': return 'purple';
    case 'det': return 'amber';
    case 'dev': return 'blue';
    case 'ioc': return 'red';
    default: return 'grey';
  }
}

const Panel: Component<{ ctx: string; title: string; children: any }> = (p) => (
  <section class="hp-terminal inv-panel">
    <div class="hp-terminal-bar">
      <span class="hp-dot red" aria-hidden="true" /><span class="hp-dot yellow" aria-hidden="true" /><span class="hp-dot green" aria-hidden="true" />
      <span class="mc-panel-title">{p.title}</span>
      <span class="hp-terminal-title">hookprobe@edge ~ {p.ctx}</span>
    </div>
    <div class="hp-terminal-body inv-panel-body">{p.children}</div>
  </section>
);

/** `ProcessTreeNode` recursive renderer — `incident_process_tree`'s `spawned_by` walk. */
const ProcessTreeItem: Component<{ node: ProcessTreeNode; depth: number }> = (p) => (
  <li class="inv-proc-node" style={{ 'padding-left': `${p.depth * 16}px` }}>
    <button class="inv-proc-row" onClick={() => void exploreEvidenceNode(p.node.id)} title="Drill into evidence graph">
      <span class="inv-proc-pid">pid {p.node.pid}</span>
      <span class="inv-proc-name">{p.node.name}</span>
      <span class="inv-proc-cmd">{p.node.cmdline}</span>
      <span class="inv-proc-time">{formatTime(p.node.ts)}</span>
    </button>
    <Show when={p.node.children.length > 0}>
      <ul class="inv-proc-children">
        <For each={p.node.children}>{(c) => <ProcessTreeItem node={c} depth={p.depth + 1} />}</For>
      </ul>
    </Show>
  </li>
);

const InvestigateApp: Component = () => {
  const [selectedId, setSelectedId] = createSignal<string | null>(null);
  const [relatedMitre, setRelatedMitre] = createSignal<RelatedMitre[]>([]);
  const [graphInput, setGraphInput] = createSignal('');

  onMount(() => {
    startInvestigateLive();
  });

  // Auto-select the first (newest) incident once the queue loads, if nothing is selected yet.
  createEffect(() => {
    const rows = incidents();
    if (rows.length > 0 && selectedId() === null) {
      setSelectedId(rows[0].id);
    }
  });

  // Fetch every per-incident envelope whenever the selection changes: the why/confidence detail,
  // the ts-ordered timeline, the host process tree, the incident's own evidence subgraph (seeds the
  // graph explorer), and this incident's executive report if one has been generated.
  createEffect(() => {
    const id = selectedId();
    if (!id) return;
    void fetchIncidentDetail(id);
    void fetchIncidentTimeline(id);
    void fetchIncidentProcessTree(id);
    void exploreEvidenceNode(id);
    void syncReportForIncident(id);
  });

  // Best-effort MITRE cross-reference once the detail envelope lands.
  createEffect(() => {
    const d = detail();
    if (d) {
      void mitreForRelatedEvents(d.explanation.related_events).then(setRelatedMitre);
    } else {
      setRelatedMitre([]);
    }
  });

  function select(id: string) {
    setSelectedId(id);
  }

  function submitGraphQuery(e: Event) {
    e.preventDefault();
    void exploreEvidenceNode(graphInput() || selectedId() || '');
  }

  return (
    <div class="dash-layout">
      <LeftRail active="/investigate" mode="cloud-linked" onOpenCopilot={() => setCopilotOpen(true)} />

      <main class="dash-main">
        <header class="mc-header">
          <div>
            <h1 class="mc-h1">INVESTIGATE</h1>
            <div class="mc-sub">Every alert becomes an explained story · AEGIS</div>
          </div>
          <div class="mc-header-actions">
            <button class="mc-chip" onClick={() => setCopilotOpen(true)}>⌘ Ask AEGIS</button>
            <span class="mc-mode-badge">● cloud-linked</span>
          </div>
        </header>

        <div class="inv-layout">

          {/* Incident queue — real GET /api/incidents + /api/stream deltas */}
          <aside class="inv-queue hp-terminal">
            <div class="hp-terminal-bar">
              <span class="hp-dot red" aria-hidden="true" /><span class="hp-dot yellow" aria-hidden="true" /><span class="hp-dot green" aria-hidden="true" />
              <span class="mc-panel-title">INCIDENT QUEUE</span>
              <span class="hp-terminal-title">~ queue</span>
            </div>
            <div class="inv-queue-list">
              <Show when={queueStatus() !== 'loading'} fallback={<LiveState kind="loading" label="Loading incidents…" />}>
                <Show when={queueStatus() !== 'error'} fallback={<LiveState kind="error" label="Incident queue unavailable" reason={queueError() ?? undefined} />}>
                  <Show when={incidents().length > 0} fallback={<LiveState kind="empty" label="No incidents yet" reason="Nothing has correlated into an incident on this device yet." />}>
                    <For each={incidents()}>
                      {(i) => (
                        <button
                          class={`inv-q-item${selectedId() === i.id ? ' inv-q-item--active' : ''}`}
                          onClick={() => select(i.id)}
                        >
                          <div class="inv-q-top">
                            <span class={`inv-pri pri--${i.priority.toLowerCase()}`}>{i.priority}</span>
                            <span class="inv-q-time">{formatTime(i.ts)}</span>
                          </div>
                          <div class="inv-q-title">{i.title}</div>
                          <div class="inv-q-meta">{i.device_ip} · {i.status}</div>
                        </button>
                      )}
                    </For>
                  </Show>
                </Show>
              </Show>
            </div>
          </aside>

          {/* Incident detail — real GET /api/incidents/:id */}
          <Show
            when={detailStatus() !== 'loading'}
            fallback={<div class="inv-detail"><LiveState kind="loading" label="Loading incident story…" /></div>}
          >
            <Show
              when={detailStatus() !== 'error' && detail() !== null}
              fallback={<div class="inv-detail"><LiveState kind="error" label="Incident detail unavailable" reason={detailError() ?? undefined} /></div>}
            >
              {(() => {
                const d = detail()!;
                const nodes = d.attack_path.nodes;
                return (
                  <div class="inv-detail">

                    {/* Headline */}
                    <div class="inv-headline">
                      <div class="inv-headline-top">
                        <span class={`inv-pri pri--${d.priority.toLowerCase()}`}>{d.priority}</span>
                        <h2 class="inv-title">{d.title}</h2>
                        <span class="inv-status">{d.status}</span>
                      </div>
                      <div class="inv-id">{d.device_ip} · {d.id}</div>
                      <p class="inv-summary">{d.explanation.why}</p>
                    </div>

                    <div class="inv-grid">

                      {/* Incident story — the REAL evidence-graph subgraph (attack_path), nearest
                          nodes first; no timestamped narrative exists server-side yet, so this is
                          the evidence itself rather than invented prose. */}
                      <Panel ctx="story · evidence graph" title="INCIDENT STORY">
                        <Show when={nodes.length > 0} fallback={<LiveState kind="empty" label="No linked evidence yet" />}>
                          <ul class="inv-story">
                            <For each={nodes}>
                              {(n) => (
                                <li class="inv-step">
                                  <span class="inv-step-time">{n.type}</span>
                                  <span class="inv-step-dot" style={{ background: toneVar(nodeTone(n.type)) }} aria-hidden="true" />
                                  <span class="inv-step-text">{n.label || n.id}</span>
                                </li>
                              )}
                            </For>
                          </ul>
                        </Show>
                      </Panel>

                      {/* Why AEGIS decided this — the real why/confidence/evidence/model envelope */}
                      <Panel ctx="aegis" title="WHY AEGIS DECIDED THIS">
                        <div class="inv-why-top">
                          <div class="inv-why-stat">
                            <div class="inv-why-big hp-text-gradient">{Math.round(d.explanation.confidence)}%</div>
                            <div class="inv-why-k">Confidence</div>
                          </div>
                          <div class="inv-why-stat">
                            <div class="inv-why-big">{d.explanation.evidence}</div>
                            <div class="inv-why-k">Evidence artifacts</div>
                          </div>
                          <div class="inv-why-model">
                            <div class="inv-why-k">Model</div>
                            <div class="inv-why-modelv">
                              {d.explanation.model ?? 'No AI planner run'}
                            </div>
                          </div>
                        </div>
                        <div class="inv-hyp-label">Alternative hypotheses</div>
                        <p class="inv-summary">
                          AEGIS's deterministic reconciler doesn't track rejected hypotheses yet —
                          only the correlation above. The BYO-LLM planner (a separate, opt-in leg)
                          hasn't run over this incident.
                        </p>
                      </Panel>

                      {/* MITRE ATT&CK — cross-referenced from real related detections' `mitre` field */}
                      <Panel ctx="mitre" title="MITRE ATT&CK">
                        <Show when={relatedMitre().length > 0} fallback={<LiveState kind="empty" label="No MITRE techniques resolved" reason="The related detections either carry no MITRE tag or have aged out of the loaded detections window." />}>
                          <ul class="inv-mitre">
                            <For each={relatedMitre()}>
                              {(m) => (
                                <li class="inv-tactic">
                                  <span class="inv-tactic-id">{m.id}</span>
                                  <span class="inv-tactic-name">{mitreName(m.id)} · {mitreTactic(m.id)}</span>
                                </li>
                              )}
                            </For>
                          </ul>
                        </Show>
                      </Panel>

                      {/* Evidence summary — real graph facts (no threat-intel/CVE/IOC endpoint yet) */}
                      <Panel ctx="evidence" title="EVIDENCE SUMMARY">
                        <ul class="inv-intel">
                          <li class="inv-intel-row"><span class="inv-intel-label">Threat score</span><span class="inv-intel-val">{Math.round(d.threat_score * 100)}%</span></li>
                          <li class="inv-intel-row"><span class="inv-intel-label">Linked nodes</span><span class="inv-intel-val">{d.attack_path.node_count}</span></li>
                          <li class="inv-intel-row"><span class="inv-intel-label">Linked edges</span><span class="inv-intel-val">{d.attack_path.edge_count}</span></li>
                          <li class="inv-intel-row"><span class="inv-intel-label">Related detections</span><span class="inv-intel-val">{d.explanation.related_events.length}</span></li>
                        </ul>
                      </Panel>

                      {/* Attack Timeline — real GET /api/incidents/:id/timeline (ts-ordered narrative) */}
                      <Panel ctx="timeline" title="ATTACK TIMELINE">
                        <Show when={timelineStatus() !== 'loading'} fallback={<LiveState kind="loading" label="Loading timeline…" />}>
                          <Show when={timelineStatus() !== 'error'} fallback={<LiveState kind="error" label="Timeline unavailable" reason={timelineError() ?? undefined} />}>
                            <Show when={timelineEvents().length > 0} fallback={<LiveState kind="empty" label="No timeline events yet" reason="No detection/flow/process/response nodes have linked into this incident's subgraph yet." />}>
                              <ul class="inv-story">
                                <For each={timelineEvents()}>
                                  {(ev) => (
                                    <li class="inv-step">
                                      <span class="inv-step-time">{formatTime(ev.ts)}</span>
                                      <span class="inv-step-dot" style={{ background: toneVar(nodeTone(ev.kind === 'detection' ? 'det' : ev.kind === 'incident' ? 'inc' : ev.kind)) }} aria-hidden="true" />
                                      <span class="inv-step-text"><span class="inv-tl-kind">[{ev.kind}]</span> {ev.label}</span>
                                    </li>
                                  )}
                                </For>
                              </ul>
                            </Show>
                          </Show>
                        </Show>
                      </Panel>

                      {/* Process Tree — real GET /api/incidents/:id/processes (spawned_by walk) */}
                      <Panel ctx="processes" title={`PROCESS TREE${processStatus() === 'live' ? ` (${processCount()})` : ''}`}>
                        <Show when={processStatus() !== 'loading'} fallback={<LiveState kind="loading" label="Loading process tree…" />}>
                          <Show when={processStatus() !== 'error'} fallback={<LiveState kind="error" label="Process tree unavailable" reason={processError() ?? undefined} />}>
                            <Show when={processRoots().length > 0} fallback={<LiveState kind="empty" label="No host process telemetry linked yet" reason="No host-telemetry process nodes have entered this incident's subgraph — this device's EDR layer may not have observed process activity for it yet." />}>
                              <ul class="inv-proc-tree">
                                <For each={processRoots()}>{(r) => <ProcessTreeItem node={r} depth={0} />}</For>
                              </ul>
                            </Show>
                          </Show>
                        </Show>
                      </Panel>
                    </div>

                    {/* Proposed plan — no BYO-LLM planner has run (see Model above); honest, not fabricated */}
                    <section class="hp-terminal inv-plan">
                      <div class="hp-terminal-bar">
                        <span class="hp-dot red" aria-hidden="true" /><span class="hp-dot yellow" aria-hidden="true" /><span class="hp-dot green" aria-hidden="true" />
                        <span class="mc-panel-title">PROPOSED PLAN</span>
                        <span class="hp-terminal-title">~ plan</span>
                      </div>
                      <div class="hp-terminal-body inv-plan-body">
                        <LiveState
                          kind="empty"
                          label="No automated plan proposed yet"
                          reason="AEGIS's deterministic reconciler correlated this incident from evidence alone. The BYO-LLM planner — which would propose a remediation plan as a diff to approve — is a separate, opt-in leg and hasn't run (Model: none, above)."
                        />
                      </div>
                    </section>

                    {/* Executive Report — the evidence-chain terminus: real GET /api/reports/:id
                        for whichever report was generated FOR this incident (if any). */}
                    <section class="hp-terminal inv-plan">
                      <div class="hp-terminal-bar">
                        <span class="hp-dot red" aria-hidden="true" /><span class="hp-dot yellow" aria-hidden="true" /><span class="hp-dot green" aria-hidden="true" />
                        <span class="mc-panel-title">EXECUTIVE REPORT</span>
                        <span class="hp-terminal-title">~ reports/{selectedId()}</span>
                      </div>
                      <div class="hp-terminal-body inv-plan-body">
                        <Show when={reportDetailStatus() !== 'loading'} fallback={<LiveState kind="loading" label="Loading report…" />}>
                          <Show when={reportDetailStatus() !== 'error'} fallback={<LiveState kind="error" label="Report unavailable" reason={reportDetailError() ?? undefined} />}>
                            <Show
                              when={reportDetail() !== null}
                              fallback={<LiveState kind="empty" label="No executive report generated yet for this incident" reason="Report generation (EvidenceGraph::generate_report) is a separate step from incident correlation and hasn't run for this incident yet." />}
                            >
                              {(() => {
                                const rep = reportDetail()!;
                                return (
                                  <>
                                    <p class="inv-plan-summary">{rep.summary}</p>
                                    <div class="inv-why-top">
                                      <div class="inv-why-stat">
                                        <div class="inv-why-big hp-text-gradient">{Math.round(rep.report.confidence)}%</div>
                                        <div class="inv-why-k">Confidence</div>
                                      </div>
                                      <div class="inv-why-stat">
                                        <div class="inv-why-big">{rep.report.evidence_node_ids.length}</div>
                                        <div class="inv-why-k">Evidence nodes cited</div>
                                      </div>
                                      <div class="inv-why-stat">
                                        <div class="inv-why-big">{rep.report.response_taken.length}</div>
                                        <div class="inv-why-k">Response actions</div>
                                      </div>
                                      <div class="inv-why-model">
                                        <div class="inv-why-k">Generated</div>
                                        <div class="inv-why-modelv">{formatTime(rep.report.generated_ts)}</div>
                                      </div>
                                    </div>
                                    <Show when={rep.report.mitre_techniques.length > 0}>
                                      <div class="inv-hyp-label">MITRE techniques</div>
                                      <ul class="inv-plan-steps">
                                        <For each={rep.report.mitre_techniques}>
                                          {(t) => <li class="inv-plan-step">{t} · {mitreName(t)}</li>}
                                        </For>
                                      </ul>
                                    </Show>
                                    <div class="inv-hyp-label">Evidence cited — drill into any node</div>
                                    <ul class="inv-plan-steps">
                                      <For each={rep.report.evidence_node_ids}>
                                        {(nid) => (
                                          <li class="inv-plan-step">
                                            <button class="inv-node-chip" onClick={() => void exploreEvidenceNode(nid)}>{nid}</button>
                                          </li>
                                        )}
                                      </For>
                                    </ul>
                                  </>
                                );
                              })()}
                            </Show>
                          </Show>
                        </Show>
                      </div>
                    </section>

                    {/* Reports — GET /api/reports, the full list across every incident (browse any report). */}
                    <section class="hp-terminal inv-plan">
                      <div class="hp-terminal-bar">
                        <span class="hp-dot red" aria-hidden="true" /><span class="hp-dot yellow" aria-hidden="true" /><span class="hp-dot green" aria-hidden="true" />
                        <span class="mc-panel-title">ALL REPORTS</span>
                        <span class="hp-terminal-title">~ reports</span>
                      </div>
                      <div class="hp-terminal-body inv-plan-body">
                        <Show when={reportsStatus() !== 'loading'} fallback={<LiveState kind="loading" label="Loading reports…" />}>
                          <Show when={reportsStatus() !== 'error'} fallback={<LiveState kind="error" label="Report list unavailable" reason={reportsError() ?? undefined} />}>
                            <Show when={reports().length > 0} fallback={<LiveState kind="empty" label="No executive reports generated yet on this device" />}>
                              <ul class="inv-reports-list">
                                <For each={reports()}>
                                  {(r) => (
                                    <li>
                                      <button
                                        class={`inv-report-row${r.incident_id === selectedId() ? ' inv-report-row--active' : ''}`}
                                        onClick={() => { setSelectedId(r.incident_id); void fetchReportDetail(r.id); }}
                                      >
                                        <span class="inv-q-time">{formatTime(r.ts)}</span>
                                        <span class="inv-q-title">{r.title}</span>
                                        <span class="inv-q-meta">{r.incident_id}</span>
                                      </button>
                                    </li>
                                  )}
                                </For>
                              </ul>
                            </Show>
                          </Show>
                        </Show>
                      </div>
                    </section>

                    {/* Evidence Graph explorer — GET /api/evidence/graph?node= + GET /api/evidence/stats:
                        "everything clickable" — drill into ANY node id from anywhere in the UI. */}
                    <section class="hp-terminal inv-plan">
                      <div class="hp-terminal-bar">
                        <span class="hp-dot red" aria-hidden="true" /><span class="hp-dot yellow" aria-hidden="true" /><span class="hp-dot green" aria-hidden="true" />
                        <span class="mc-panel-title">EVIDENCE GRAPH</span>
                        <span class="hp-terminal-title">~ evidence/graph?node={graphNodeQuery()}</span>
                      </div>
                      <div class="hp-terminal-body inv-plan-body">
                        <form class="inv-graph-form" onSubmit={submitGraphQuery}>
                          <input
                            class="inv-graph-input"
                            type="text"
                            placeholder="node id (e.g. inc:…, det:…, dev:…, proc:…)"
                            value={graphInput()}
                            onInput={(e) => setGraphInput(e.currentTarget.value)}
                          />
                          <button type="submit" class="inv-modify">Explore</button>
                        </form>

                        <Show when={graphStatus() !== 'loading'} fallback={<LiveState kind="loading" label="Loading subgraph…" />}>
                          <Show when={graphStatus() !== 'error'} fallback={<LiveState kind="error" label="Node not found or unavailable" reason={graphError() ?? undefined} />}>
                            {(() => {
                              const g = graphResult();
                              if (!g) return <LiveState kind="empty" label="No node explored yet" />;
                              return (
                                <>
                                  <div class="inv-intel-row"><span class="inv-intel-label">Nodes / edges</span><span class="inv-intel-val">{g.node_count} / {g.edge_count}</span></div>
                                  <ul class="inv-graph-nodes">
                                    <For each={g.nodes}>
                                      {(n) => (
                                        <li>
                                          <button class="inv-node-chip" onClick={() => void exploreEvidenceNode(n.id)}>
                                            <span class="inv-tactic-id">{n.type}</span> {n.label || n.id}
                                          </button>
                                        </li>
                                      )}
                                    </For>
                                  </ul>
                                </>
                              );
                            })()}
                          </Show>
                        </Show>

                        <div class="inv-hyp-label" style={{ 'margin-top': '14px' }}>Retention &amp; storage</div>
                        <Show when={evidenceStatsStatus() !== 'loading'} fallback={<LiveState kind="loading" label="Loading evidence stats…" />}>
                          <Show when={evidenceStatsStatus() !== 'error'} fallback={<LiveState kind="error" label="Evidence stats unavailable" reason={evidenceStatsError() ?? undefined} />}>
                            {(() => {
                              const s = evidenceStats();
                              if (!s) return <LiveState kind="empty" label="No evidence stats yet" />;
                              return (
                                <ul class="inv-intel">
                                  <li class="inv-intel-row"><span class="inv-intel-label">DB size</span><span class="inv-intel-val">{formatBytes(s.db_size_bytes)}</span></li>
                                  <li class="inv-intel-row"><span class="inv-intel-label">Total edges</span><span class="inv-intel-val">{s.total_edges}</span></li>
                                  <li class="inv-intel-row"><span class="inv-intel-label">Incidents / reports</span><span class="inv-intel-val">{s.nodes.incidents ?? 0} / {s.nodes.reports ?? 0}</span></li>
                                  <li class="inv-intel-row">
                                    <span class="inv-intel-label">Last prune</span>
                                    <span class="inv-intel-val">{s.last_prune ? formatTime(s.last_prune.ts) : 'never'}</span>
                                  </li>
                                </ul>
                              );
                            })()}
                          </Show>
                        </Show>
                      </div>
                    </section>

                  </div>
                );
              })()}
            </Show>
          </Show>
        </div>
      </main>

      <CommandPalette
        open={copilotOpen()}
        query={copilotQuery()}
        onQuery={setCopilotQuery}
        onClose={() => { setCopilotOpen(false); setCopilotQuery(''); }}
      />
    </div>
  );
};

export default InvestigateApp;
