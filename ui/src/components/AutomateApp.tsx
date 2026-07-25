/**
 * AutomateApp — Automate (§7, SOAR): playbooks, agents, and workflows as pipelines.
 *
 * Spec: docs/MissionControl.md §7. Playbooks rendered as CI/CD-style pipelines
 * (detect → validate → contain → notify → recover → verify → close); each stage
 * carries a state (done/running/waiting/failed) and an autonomy marker
 * (auto-apply vs approval). Approval Queue surfaces pending AEGIS-reasoned
 * actions; AI Agents list exposes the active orchestration agents.
 * Intent: "Auto-contain credential-stuffing but require approval before
 * isolating a server."
 */

import { type Component, For, Show } from 'solid-js';
import LeftRail from './LeftRail';
import CommandPalette from './CommandPalette';
import { setCopilotOpen, setCopilotQuery, copilotOpen, copilotQuery } from '../store/mock';
import type { Tone } from '../store/missionMock';
import type { StageState } from '../store/atmMock';
import {
  KPIS, PLAYBOOKS, APPROVAL_QUEUE, AGENTS, ANALYTICS,
} from '../store/atmMock';

function toneVar(t: Tone): string {
  return { green: 'var(--hp-green)', amber: 'var(--hp-amber)', red: 'var(--hp-red)',
    blue: 'var(--hp-cyan)', cyan: 'var(--hp-cyan)', purple: 'var(--hp-purple)', orange: 'var(--hp-orange)', grey: 'var(--hp-grey)' }[t];
}

function urgTone(u: 'critical' | 'high' | 'medium'): string {
  return u === 'critical' ? 'var(--hp-red)' : u === 'high' ? 'var(--hp-amber)' : 'var(--hp-cyan)';
}

function stateGlyph(s: StageState): string {
  return { done: '◉', running: '◈', waiting: '○', failed: '✕' }[s];
}

const Panel: Component<{ ctx: string; title: string; span?: string; children: any }> = (p) => (
  <section class="hp-terminal mc-panel" style={p.span ? { 'grid-column': p.span } : undefined}>
    <div class="hp-terminal-bar">
      <span class="hp-dot red" aria-hidden="true" /><span class="hp-dot yellow" aria-hidden="true" /><span class="hp-dot green" aria-hidden="true" />
      <span class="mc-panel-title">{p.title}</span>
      <span class="hp-terminal-title">hookprobe@edge ~ {p.ctx}</span>
    </div>
    <div class="hp-terminal-body mc-panel-body">{p.children}</div>
  </section>
);

const AutomateApp: Component = () => (
  <div class="dash-layout">
    <LeftRail active="/automate" mode="cloud-linked" onOpenCopilot={() => setCopilotOpen(true)} />

    <main class="dash-main">
      <header class="mc-header">
        <div>
          <h1 class="mc-h1">AUTOMATE</h1>
          <div class="mc-sub">Playbooks, agents &amp; workflows · SOAR · AEGIS reconciler</div>
        </div>
        <div class="mc-header-actions">
          <button class="mc-chip" onClick={() => setCopilotOpen(true)}>⌘ "auto-contain credential stuffing"</button>
          <span class="mc-mode-badge">● automate granted</span>
        </div>
      </header>

      <div class="mc-grid">

        {/* KPI row */}
        <div class="mc-cell--kpis atm-kpis">
          <For each={KPIS}>
            {(k) => (
              <div class="mc-kpi" style={{ '--tone': toneVar(k.tone) }}>
                <div class="mc-kpi-label">{k.label}</div>
                <div class="mc-kpi-value">{k.value}</div>
              </div>
            )}
          </For>
        </div>

        {/* Playbooks — CI/CD pipeline view */}
        <Panel ctx="playbooks" title="PLAYBOOKS — PIPELINE VIEW" span="span 12">
          <ul class="atm-playbooks">
            <For each={PLAYBOOKS}>
              {(pb) => (
                <li class="atm-pb-row">
                  <div class="atm-pb-name-row">
                    <span class="atm-pb-name">{pb.name}</span>
                    <span class={`atm-pb-status atm-pb-status--${pb.status}`}>{pb.status.toUpperCase()}</span>
                    <span class="atm-pb-runs">{pb.runCount} runs</span>
                    <span class="atm-pb-trigger">{pb.trigger}</span>
                    <span class="atm-pb-lastrun">last: {pb.lastRun}</span>
                  </div>
                  <div class="atm-pipeline" role="list" aria-label={`${pb.name} pipeline stages`}>
                    <For each={pb.stages}>
                      {(stage, i) => (
                        <>
                          <Show when={i() > 0}>
                            <span class="atm-stage-arrow" aria-hidden="true">→</span>
                          </Show>
                          <div
                            class={`atm-stage atm-stage--${stage.state}`}
                            role="listitem"
                            title={`${stage.name}: ${stage.state} · ${stage.autonomy}`}
                          >
                            <div class="atm-stage-top">
                              <span class="atm-stage-icon" aria-hidden="true">{stateGlyph(stage.state)}</span>
                              <span class="atm-stage-name">{stage.name}</span>
                            </div>
                            <div class="atm-stage-foot">
                              <span class={`atm-autonomy atm-autonomy--${stage.autonomy}`}>
                                {stage.autonomy === 'auto' ? 'AUTO' : '⚠ APPR'}
                              </span>
                              <Show when={stage.duration}>
                                <span class="atm-stage-dur">{stage.duration}</span>
                              </Show>
                            </div>
                          </div>
                        </>
                      )}
                    </For>
                  </div>
                </li>
              )}
            </For>
          </ul>
        </Panel>

        {/* Approval queue */}
        <Panel ctx="approval" title="APPROVAL QUEUE" span="span 5">
          <ul class="atm-queue">
            <For each={APPROVAL_QUEUE}>
              {(item) => (
                <li class="atm-queue-item" style={{ '--urg': urgTone(item.urgency) }}>
                  <div class="atm-queue-top">
                    <span class="atm-queue-time">{item.time}</span>
                    <span class={`atm-queue-urgency atm-urg--${item.urgency}`}>{item.urgency.toUpperCase()}</span>
                    <span class="atm-queue-pb">{item.playbook}</span>
                  </div>
                  <div class="atm-queue-action">
                    <span class="atm-queue-verb">{item.action}</span>
                    <span class="atm-queue-target">{item.target}</span>
                    <span class="atm-queue-conf">AEGIS {item.confidence}%</span>
                  </div>
                  <div class="atm-queue-rationale">{item.rationale}</div>
                  <div class="atm-queue-actions">
                    <button class="atm-approve-btn">Approve</button>
                    <button class="atm-reject-btn">Reject</button>
                  </div>
                </li>
              )}
            </For>
          </ul>
        </Panel>

        {/* AI Agents */}
        <Panel ctx="agents" title="AI AGENTS" span="span 7">
          <ul class="atm-agents">
            <For each={AGENTS}>
              {(agent) => (
                <li class="atm-agent-row">
                  <span class={`atm-agent-dot atm-agent-dot--${agent.status}`} aria-hidden="true" />
                  <div class="atm-agent-body">
                    <div class="atm-agent-name-row">
                      <span class="atm-agent-name">{agent.name}</span>
                      <span class={`atm-agent-status atm-agent-status--${agent.status}`}>{agent.status}</span>
                    </div>
                    <div class="atm-agent-role">{agent.role}</div>
                    <div class="atm-agent-last">{agent.lastAction}</div>
                  </div>
                  <span class="atm-agent-count">{agent.actions}<span class="atm-agent-ck"> acts</span></span>
                </li>
              )}
            </For>
          </ul>
        </Panel>

        {/* Automation analytics */}
        <Panel ctx="analytics" title="AUTOMATION ANALYTICS" span="span 12">
          <ul class="atm-analytics">
            <For each={ANALYTICS}>
              {(row) => (
                <li class="atm-analytic-row" style={{ '--tone': toneVar(row.tone) }}>
                  <div class="atm-analytic-label">{row.label}</div>
                  <div class="atm-analytic-value">{row.value}</div>
                  <Show when={row.delta}>
                    <div class="atm-analytic-delta">{row.delta}</div>
                  </Show>
                </li>
              )}
            </For>
          </ul>
        </Panel>

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

export default AutomateApp;
