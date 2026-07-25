/**
 * DetectApp — Detect (§4, NAPSE): detections, anomalies, and the rules behind them.
 *
 * Spec: docs/MissionControl.md §4. Live detections feed (Suricata/YARA/Sigma/AI/
 * Behavioral) mapped to MITRE ATT&CK; each detection → Investigate (the story).
 * Capability-gated on `ids` in a real build. Cyber-industrial terminal soul.
 *
 * WIRED to the real `hookprobe-api` read-API (ADR 0001): `GET /api/detections` + `/api/stream`
 * deltas via `store/detectLive.ts` — live detections feed, KPI row, and "top techniques" panel are
 * all real, computed from whatever the device has actually observed (never the old static demo
 * numbers). ENGINES (ADR 0026, `GET /api/engines`) is now PARTLY real: Sigma/YARA rows show REAL
 * loaded-rule counts / hit counts from their own status files; Suricata/AI Detection/Behavioral
 * stay on `store/detectMock.ts`'s static numbers, each row honestly badged "live" vs "mock" (see
 * `mergedEngines()` below) — never a blanket panel-title "mock" once part of it is real. ATT&CK
 * COVERAGE stays fully mock (no total-rule-catalog denominator endpoint yet); see
 * `detectLive.ts`'s doc comment for the exact split.
 */

import { type Component, For, Show, onMount } from 'solid-js';
import LeftRail from './LeftRail';
import CommandPalette from './CommandPalette';
import LiveState from './LiveState';
import { setCopilotOpen, setCopilotQuery, copilotOpen, copilotQuery } from '../store/mock';
import type { Tone } from '../store/missionMock';
import { ENGINES, COVERAGE } from '../store/detectMock';
import { severityLabel, formatTime, type DetectionRow } from '../store/api';
import {
  startDetectLive, detections, detectStatus, detectError, computeKpis, computeTopTechniques,
  engines as liveEngines,
} from '../store/detectLive';

/** Merge `detectMock.ts`'s static ENGINES with whatever `/api/engines` actually reported. A row
 * whose live entry carries `source: "real"` (Sigma/YARA) is REPLACED with the live numbers; a
 * row with no live entry, or `source: "mock"` (Suricata/AI Detection/Behavioral), keeps the
 * static demo numbers — but every row is tagged `live` so the template can badge it honestly
 * instead of one blanket panel-level "mock" label. */
function mergedEngines() {
  const live = liveEngines();
  return ENGINES.map((m) => {
    const l = live.find((e) => e.name === m.name);
    if (l && l.source === 'real') {
      return {
        name: m.name,
        kind: m.kind,
        rules: l.loaded_rules != null ? `${l.loaded_rules}` : (l.status === 'not_yet_run' ? 'not run yet' : m.rules),
        hits: l.hits ?? 0,
        status: (l.status === 'active' ? 'active' : 'degraded') as 'active' | 'degraded',
        live: true,
      };
    }
    return { ...m, live: false };
  });
}

function toneVar(t: Tone): string {
  return {
    green: 'var(--hp-green)', amber: 'var(--hp-amber)', red: 'var(--hp-red)',
    blue: 'var(--hp-cyan)', cyan: 'var(--hp-cyan)', purple: 'var(--hp-purple)',
    orange: 'var(--hp-orange)', grey: 'var(--hp-grey)',
  }[t];
}
function sevTone(s: ReturnType<typeof severityLabel>): Tone {
  return s === 'critical' ? 'red' : s === 'high' ? 'amber' : s === 'medium' ? 'blue' : 'grey';
}
/** Confidence tier for the verdict pill — `detections` carries no blocked/alert outcome field yet
 * (see `store/api.ts`'s `DetectionRow` doc comment), so the pill honestly shows model confidence
 * instead of a fabricated enforcement verdict. */
function confTier(c: number): 'high' | 'med' | 'low' {
  return c >= 0.8 ? 'high' : c >= 0.5 ? 'med' : 'low';
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

const DetectApp: Component = () => {
  onMount(() => {
    startDetectLive();
  });

  const kpis = () => computeKpis(detections());
  const topTechniques = () => computeTopTechniques(detections());

  return (
    <div class="dash-layout">
      <LeftRail active="/detect" mode="cloud-linked" onOpenCopilot={() => setCopilotOpen(true)} />

      <main class="dash-main">
        <header class="mc-header">
          <div>
            <h1 class="mc-h1">DETECT</h1>
            <div class="mc-sub">Detections, anomalies &amp; the rules behind them · NAPSE</div>
          </div>
          <div class="mc-header-actions">
            <button class="mc-chip" onClick={() => setCopilotOpen(true)}>⌘ "today's ransomware?"</button>
            <span class="mc-mode-badge">● ids granted</span>
          </div>
        </header>

        <div class="mc-grid">

          {/* KPI row — computed live from store/detectLive.ts's computeKpis(); "—" while loading/error */}
          <div class="mc-cell--kpis det-kpis">
            <For each={kpis()}>
              {(k) => (
                <div class="mc-kpi" style={{ '--tone': toneVar(k.tone) }}>
                  <div class="mc-kpi-label">{k.label}</div>
                  <div class="mc-kpi-value">{detectStatus() === 'error' ? '—' : k.value}</div>
                </div>
              )}
            </For>
          </div>

          {/* Live detections — real GET /api/detections + /api/stream deltas */}
          <Panel ctx="detections" title="LIVE DETECTIONS" span="span 7">
            <Show
              when={detectStatus() !== 'loading'}
              fallback={<LiveState kind="loading" label="Loading live detections…" />}
            >
              <Show
                when={detectStatus() !== 'error'}
                fallback={<LiveState kind="error" label="Live detections unavailable" reason={detectError() ?? undefined} />}
              >
                <Show
                  when={detections().length > 0}
                  fallback={<LiveState kind="empty" label="No detections yet" reason="Nothing has fired on this device since it started watching — that's a good sign, not a broken feed." />}
                >
                  <ul class="det-feed">
                    <For each={detections()}>
                      {(d: DetectionRow) => (
                        <li class="det-row">
                          <span class="det-sev" style={{ background: toneVar(sevTone(severityLabel(d.severity))) }} title={severityLabel(d.severity)} aria-hidden="true" />
                          <span class="det-time">{formatTime(d.ts)}</span>
                          {/* real `category` (e.g. "port_scan", "brute_force") — the schema has no
                              per-engine identity (Suricata/YARA/…) to show truthfully yet */}
                          <span class="det-engine" title="detection category">{d.category}</span>
                          <div class="det-body">
                            <div class="det-title">{d.rule_msg}</div>
                            <div class="det-flow">{d.src_ip} <span class="det-arrow">→</span> {d.dst_ip}:{d.dst_port}</div>
                          </div>
                          <span class="det-tech" title={d.mitre}>{d.mitre}</span>
                          <span class={`det-verdict v--conf-${confTier(d.confidence)}`} title="model confidence — no enforcement-outcome field yet">
                            {Math.round(d.confidence * 100)}%
                          </span>
                          <a class="det-link" href="/investigate/queue" aria-label="Investigate">↗</a>
                        </li>
                      )}
                    </For>
                  </ul>
                </Show>
              </Show>
            </Show>
          </Panel>

          {/* Detection engines — Sigma/YARA rows are REAL (ADR 0026, /api/engines); the rest stay
              mock, each row badged honestly rather than one blanket panel-level label. */}
          <Panel ctx="engines · sigma/yara live · rest mock" title="DETECTION ENGINES" span="span 5">
            <ul class="det-engines">
              <For each={mergedEngines()}>
                {(e) => (
                  <li class="det-eng">
                    <span class="det-eng-dot" classList={{ 'deg': e.status === 'degraded' }} aria-hidden="true" />
                    <div class="det-eng-body">
                      <div class="det-eng-name">
                        {e.name} <span class="det-eng-kind">{e.kind}</span>{' '}
                        <span class="det-eng-badge" classList={{ live: e.live }}>{e.live ? 'live' : 'mock'}</span>
                      </div>
                      <div class="det-eng-rules">{e.rules} rules</div>
                    </div>
                    <span class="det-eng-hits">{e.hits}<span class="det-eng-hk"> hits</span></span>
                  </li>
                )}
              </For>
            </ul>
          </Panel>

          {/* MITRE coverage — mock: no total-rule-catalog denominator endpoint yet */}
          <Panel ctx="mitre · mock" title="ATT&CK COVERAGE" span="span 7">
            <ul class="det-cov">
              <For each={COVERAGE}>
                {(c) => {
                  const pct = Math.round((c.covered / c.total) * 100);
                  const tone = pct >= 80 ? 'var(--hp-green)' : pct >= 55 ? 'var(--hp-amber)' : 'var(--hp-red)';
                  return (
                    <li class="det-cov-row">
                      <span class="det-cov-tactic">{c.tactic}</span>
                      <span class="det-cov-bar"><span class="det-cov-fill" style={{ width: `${pct}%`, background: tone }} /></span>
                      <span class="det-cov-n">{c.covered}/{c.total}</span>
                    </li>
                  );
                }}
              </For>
            </ul>
          </Panel>

          {/* Top techniques — real, computed from the loaded detections window */}
          <Panel ctx="techniques" title="TOP TECHNIQUES · loaded window" span="span 5">
            <Show
              when={detectStatus() === 'live' && topTechniques().length > 0}
              fallback={<LiveState kind={detectStatus() === 'loading' ? 'loading' : detectStatus() === 'error' ? 'error' : 'empty'}
                label={detectStatus() === 'loading' ? 'Loading…' : detectStatus() === 'error' ? 'Unavailable' : 'No techniques observed yet'}
                reason={detectStatus() === 'error' ? (detectError() ?? undefined) : undefined} />}
            >
              <ul class="det-top">
                <For each={topTechniques()}>
                  {(t) => (
                    <li class="det-top-row">
                      <span class="inv-tactic-id">{t.id}</span>
                      <div class="det-top-body">
                        <div class="det-top-name">{t.name}</div>
                        <div class="det-top-tactic">{t.tactic}</div>
                      </div>
                      <span class="det-top-count">{t.count}</span>
                    </li>
                  )}
                </For>
              </ul>
            </Show>
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
};

export default DetectApp;
