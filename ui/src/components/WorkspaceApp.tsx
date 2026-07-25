/**
 * WorkspaceApp — Workspace (§2): the operator's personal work-tracker.
 *
 * Continuity hub — resume in-progress work, running activity log, items pinned to
 * investigate later, tasks, recent dashboards, saved searches. Built to match
 * ~/workspace.png. Clean cards; charts inline SVG. Spec: docs/MissionControl.md §2.
 */

import { type Component, For, Show, createSignal } from 'solid-js';
import AppRail from './AppRail';
import {
  RESUME, ACTIVITY, PINNED, TASKS, TASK_TABS, DASHBOARDS, SEARCHES, STATUS, type Tone,
} from '../store/workspaceMock';

const TONE: Record<Tone, string> = {
  green: 'var(--hp-green)', amber: 'var(--hp-amber)', red: 'var(--hp-red)', blue: '#4895ef',
  purple: 'var(--hp-purple)', cyan: 'var(--hp-cyan)', orange: 'var(--hp-orange)', grey: 'var(--hp-grey)',
};
const ACT_TABS = ['All', 'Alerts', 'Investigations', 'Playbooks', 'System'];

function sparkLine(data: number[], w: number, h: number) {
  const max = Math.max(...data), min = Math.min(...data), rng = max - min || 1;
  const p = data.map((v, i) => [1 + (i * (w - 2)) / (data.length - 1), h - 1 - ((v - min) / rng) * (h - 2)] as const);
  return p.map((q, i) => `${i ? 'L' : 'M'}${q[0].toFixed(1)},${q[1].toFixed(1)}`).join(' ');
}
function prioTone(p: string): Tone {
  return ({ Critical: 'red', High: 'orange', Medium: 'amber', Low: 'green' }[p] as Tone) || 'grey';
}

const WorkspaceApp: Component = () => {
  const [actTab, setActTab] = createSignal('All');
  const [taskTab, setTaskTab] = createSignal(0);
  const acts = () => (actTab() === 'All' ? ACTIVITY : ACTIVITY.filter(a => a.tab === actTab()));

  return (
    <div class="dash-layout">
      <AppRail active="Workspace" />

      <main class="dash-main wsp">
        {/* header */}
        <header class="wsp-top">
          <div class="wsp-title"><h1>Workspace</h1><span>Your recent work, pinned items and context across the platform.</span></div>
          <div class="wsp-top-right">
            <div class="wsp-search"><span>⌕</span><input placeholder="Search workspace..." /><kbd>⌘ K</kbd></div>
            <button class="wsp-copilot">⌘ AI Copilot</button>
            <button class="wsp-ic">🔔<span class="wsp-badge">7</span></button>
            <button class="wsp-ic">?</button>
            <span class="wsp-avatar">HP</span>
          </div>
        </header>

        {/* Continue Where You Left Off */}
        <section class="wsp-sec">
          <div class="wsp-sec-head"><h2>Continue Where You Left Off</h2><div class="wsp-arrows"><button>‹</button><button>›</button></div></div>
          <div class="wsp-resume">
            <For each={RESUME}>{r => (
              <article class="wsp-rcard">
                <div class="wsp-rcard-top">
                  <span class="wsp-rcard-ic" style={{ background: `color-mix(in srgb, ${TONE[r.tone]} 16%, transparent)`, color: TONE[r.tone] }}>{r.icon}</span>
                  <span class="wsp-rcard-kind" style={{ color: TONE[r.tone] }}>{r.kind.toUpperCase()}</span>
                </div>
                <h3 class="wsp-rcard-title">{r.title}</h3>
                <Show when={r.sub}><span class="wsp-rcard-sub">{r.sub}</span></Show>
                <span class="wsp-rcard-upd">{r.updated}</span>
                <div class="wsp-rcard-bar">
                  <span class="wsp-rcard-fill" style={{ width: `${r.pct}%`, background: TONE[r.tone] }} />
                  <b>{r.pct}%</b>
                </div>
              </article>
            )}</For>
          </div>
        </section>

        {/* middle: activity · pinned · tasks */}
        <section class="wsp-mid">
          {/* Recent Activity */}
          <article class="wsp-card">
            <header class="wsp-card-head">
              <h2>Recent Activity</h2>
              <div class="wsp-tabs"><For each={ACT_TABS}>{t => <button class={`wsp-tab${actTab() === t ? ' wsp-tab--on' : ''}`} onClick={() => setActTab(t)}>{t}</button>}</For></div>
            </header>
            <ul class="wsp-act">
              <For each={acts()}>{a => (
                <li>
                  <span class="wsp-act-ic" style={{ background: `color-mix(in srgb, ${TONE[a.tone]} 16%, transparent)`, color: TONE[a.tone] }}>{a.icon}</span>
                  <span class="wsp-act-text"><b>{a.title}</b><em>{a.meta}</em></span>
                  <span class="wsp-act-time">{a.time}</span>
                </li>
              )}</For>
            </ul>
            <button class="wsp-more">View All Activity →</button>
          </article>

          {/* Pinned Items */}
          <article class="wsp-card">
            <header class="wsp-card-head"><h2>Pinned Items</h2><button class="wsp-link">Manage</button></header>
            <ul class="wsp-pin">
              <For each={PINNED}>{p => (
                <li>
                  <span class="wsp-pin-ic">{p.icon}</span>
                  <span class="wsp-pin-text"><b>{p.title}</b><em>{p.type}</em></span>
                  <Show when={p.badge}><span class="wsp-pin-badge" style={{ color: TONE[p.badgeTone] }}>{p.badge}</span></Show>
                  <span class="wsp-pin-star">★</span>
                </li>
              )}</For>
            </ul>
            <button class="wsp-more">View All Pinned →</button>
          </article>

          {/* My Tasks */}
          <article class="wsp-card">
            <header class="wsp-card-head"><h2>My Tasks</h2><button class="wsp-link">View All</button></header>
            <div class="wsp-tabs wsp-tabs--pill"><For each={TASK_TABS}>{(t, i) => <button class={`wsp-tab${taskTab() === i() ? ' wsp-tab--on' : ''}`} onClick={() => setTaskTab(i())}>{t}</button>}</For></div>
            <ul class="wsp-task">
              <For each={TASKS}>{t => (
                <li>
                  <span class="wsp-check" />
                  <span class="wsp-task-text"><b>{t.title}</b><em>{t.sub}</em></span>
                  <span class="wsp-task-prio"><span style={{ color: TONE[prioTone(t.prio)] }}>{t.prio}</span><i style={{ background: TONE[prioTone(t.prio)] }} /></span>
                </li>
              )}</For>
            </ul>
            <button class="wsp-more">View All Tasks →</button>
          </article>
        </section>

        {/* bottom: dashboards · saved searches */}
        <section class="wsp-bot">
          <article class="wsp-card">
            <header class="wsp-card-head"><h2>Recent Dashboards</h2></header>
            <div class="wsp-dash">
              <For each={DASHBOARDS}>{d => (
                <div class="wsp-dcard">
                  <b>{d.title}</b><em>{d.sub}</em>
                  <svg viewBox="0 0 120 34" class="wsp-dspark" preserveAspectRatio="none" aria-hidden="true">
                    <path d={sparkLine(d.data, 120, 34)} fill="none" stroke={TONE[d.tone]} stroke-width="1.5" />
                  </svg>
                  <span class="wsp-dtime">{d.time}</span>
                </div>
              )}</For>
            </div>
            <button class="wsp-more">View All Dashboards →</button>
          </article>

          <article class="wsp-card">
            <header class="wsp-card-head"><h2>Saved Searches</h2><button class="wsp-link">Manage</button></header>
            <ul class="wsp-search-list">
              <For each={SEARCHES}>{s => (
                <li><span class="wsp-search-ic">⌕</span><span class="wsp-search-text"><b>{s.title}</b><em>{s.updated}</em></span><button class="wsp-run">▶</button></li>
              )}</For>
            </ul>
            <button class="wsp-more">View All Saved Searches →</button>
          </article>
        </section>

        {/* status strip */}
        <footer class="wsp-strip">
          <span class="wsp-strip-ver"><span class="wsp-strip-dot" /> v1.0.0-beta.1 ›</span>
          <For each={STATUS}>{s => (
            <span class="wsp-strip-item"><span class="wsp-strip-ic" style={{ color: TONE[s.tone] }}>{s.icon}</span><span><em>{s.label}</em><b style={s.label === 'System Health' ? { color: 'var(--hp-green)' } : undefined}>{s.value}</b></span></span>
          )}</For>
        </footer>
      </main>
    </div>
  );
};

export default WorkspaceApp;
