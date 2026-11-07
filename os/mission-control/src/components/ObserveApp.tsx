/**
 * ObserveApp — Observe (§3, Senzorium): everything entering the platform.
 *
 * Spec: docs/architecture/MissionControl.md §3. The Telemetry Fabric operationally — sources, normalized
 * events, retention tiers, asset inventory. Capability-gated on `senzorium` in a real build.
 * Cyber-industrial terminal soul.
 *
 * WIRED to the real `hookprobe-api` read-API (ADR 0001) via `store/obsLive.ts`:
 *   - LIVE EVENT STREAM ← `GET /api/flows` (polled — flows aren't in `/api/stream`'s payload).
 *   - ASSET INVENTORY   ← `GET /api/devices` (same poll).
 * KPI row, SOURCE BREAKDOWN and RETENTION TIERS stay on `store/obsMock.ts` — no per-source ingest
 * counter or retention-tier accounting endpoint exists yet — clearly labelled "mock" in their panel
 * titles; see `obsLive.ts`'s doc comment for the exact split. `devices` carries no OS field, so the
 * asset panel is a real ip/mac/last-seen list rather than the mock's fabricated OS breakdown.
 */

import { type Component, For, Show, onMount, onCleanup } from 'solid-js';
import LeftRail from './LeftRail';
import CommandPalette from './CommandPalette';
import LiveState from './LiveState';
import { setCopilotOpen, setCopilotQuery, copilotOpen, copilotQuery } from '../store/mock';
import type { Tone } from '../store/missionMock';
import { KPIS, SOURCES, RETENTION_TIERS } from '../store/obsMock';
import { formatTime } from '../store/api';
import { refetch, flows, flowsStatus, flowsError, devices, devicesStatus, devicesError } from '../store/obsLive';

function toneVar(t: Tone): string {
  return {
    green: 'var(--hp-green)', amber: 'var(--hp-amber)', red: 'var(--hp-red)',
    blue: 'var(--hp-cyan)', cyan: 'var(--hp-cyan)', purple: 'var(--hp-purple)',
    orange: 'var(--hp-orange)', grey: 'var(--hp-grey)',
  }[t];
}

/** Live-data poll interval — flows/devices aren't pushed over `/api/stream`, so a light poll is
 * the edge-cheap substitute (see `obsLive.ts`'s doc comment). */
const POLL_MS = 5000;

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

const ObserveApp: Component = () => {
  onMount(() => {
    void refetch();
    const iv = setInterval(() => void refetch(), POLL_MS);
    onCleanup(() => clearInterval(iv));
  });

  return (
    <div class="dash-layout">
      <LeftRail active="/observe" mode="cloud-linked" onOpenCopilot={() => setCopilotOpen(true)} />

      <main class="dash-main">
        <header class="mc-header">
          <div>
            <h1 class="mc-h1">OBSERVE</h1>
            <div class="mc-sub">Everything entering the platform · Senzorium · Telemetry Fabric</div>
          </div>
          <div class="mc-header-actions">
            <button class="mc-chip" onClick={() => setCopilotOpen(true)}>⌘ "show dns anomalies"</button>
            <span class="mc-mode-badge">● senzorium active</span>
          </div>
        </header>

        <div class="mc-grid">

          {/* KPI row — mock: no time-windowed ingest-rate/retention aggregate endpoint yet */}
          <div class="mc-cell--kpis obs-kpis">
            <For each={KPIS}>
              {(k) => (
                <div class="mc-kpi" style={{ '--tone': toneVar(k.tone) }}>
                  <div class="mc-kpi-label">{k.label} <span style={{ opacity: 0.6, 'text-transform': 'none' }}>· mock</span></div>
                  <div class="mc-kpi-value">{k.value}</div>
                </div>
              )}
            </For>
          </div>

          {/* Source breakdown — mock: no per-source ingest-count endpoint yet */}
          <Panel ctx="sources · mock" title="SOURCE BREAKDOWN" span="span 5">
            <ul class="obs-sources">
              <For each={SOURCES}>
                {(s) => (
                  <li class="obs-src-row">
                    <span class="obs-src-name">{s.name}</span>
                    <span class="obs-src-bar">
                      <span class="obs-src-fill" style={{ width: `${s.pct}%`, background: toneVar(s.tone) }} />
                    </span>
                    <span class="obs-src-count">{s.countLabel}</span>
                  </li>
                )}
              </For>
            </ul>
          </Panel>

          {/* Live event stream — real GET /api/flows, polled every 5s */}
          <Panel ctx="flows" title="LIVE EVENT STREAM" span="span 7">
            <Show when={flowsStatus() !== 'loading'} fallback={<LiveState kind="loading" label="Loading live flows…" />}>
              <Show when={flowsStatus() !== 'error'} fallback={<LiveState kind="error" label="Live flow stream unavailable" reason={flowsError() ?? undefined} />}>
                <Show when={flows().length > 0} fallback={<LiveState kind="empty" label="No flows yet" reason="No connections observed on this device yet." />}>
                  <ul class="obs-events">
                    <For each={flows()}>
                      {(f) => (
                        <li class="obs-evt-row">
                          <span class="obs-evt-dot" style={{ background: toneVar('grey') }} title="flow (no per-row severity)" aria-hidden="true" />
                          <span class="obs-evt-time">{formatTime(f.ts)}</span>
                          <span class="obs-evt-source">flow</span>
                          <span class="obs-evt-type">{f.proto}/{f.conn_state}</span>
                          <span class="obs-evt-host">{f.src_ip} → {f.dst_ip}:{f.dst_port}</span>
                        </li>
                      )}
                    </For>
                  </ul>
                </Show>
              </Show>
            </Show>
            <div class="obs-evt-footer">
              <span class="obs-evt-drill">drill: flow</span>
              <span class="obs-evt-arrow"> → </span>
              <span class="obs-evt-drill">session</span>
              <span class="obs-evt-arrow"> → </span>
              <span class="obs-evt-drill">packets</span>
              <span class="obs-evt-arrow"> → </span>
              <a class="obs-evt-link" href="/observe/pcap" aria-label="Open raw pcap viewer">raw pcap</a>
            </div>
          </Panel>

          {/* Retention tiers — mock: no retention-tier accounting endpoint yet */}
          <Panel ctx="retention · mock" title="RETENTION TIERS" span="span 5">
            <ul class="obs-tiers">
              <For each={RETENTION_TIERS}>
                {(t) => (
                  <li class="obs-tier">
                    <div class="obs-tier-head">
                      <span class="obs-tier-name">{t.name}</span>
                      <span class="obs-tier-window" style={{ color: toneVar(t.tone) }}>{t.window}</span>
                      <span class="obs-tier-pct">{t.fill}%</span>
                    </div>
                    <span class="obs-tier-bar">
                      <span class="obs-tier-fill" style={{ width: `${t.fill}%`, background: toneVar(t.tone) }} />
                    </span>
                    <span class="obs-tier-note">{t.note}</span>
                  </li>
                )}
              </For>
            </ul>
            <div class="obs-tier-footer">detect once, query forever · offload to SIEM to exceed local cap</div>
          </Panel>

          {/* Asset inventory — real GET /api/devices, polled every 5s. `devices` carries no OS
              field yet, so this is a real ip/mac/last-seen list rather than an OS breakdown. */}
          <Panel ctx="devices" title="ASSET INVENTORY" span="span 7">
            <Show when={devicesStatus() !== 'loading'} fallback={<LiveState kind="loading" label="Loading device inventory…" />}>
              <Show when={devicesStatus() !== 'error'} fallback={<LiveState kind="error" label="Device inventory unavailable" reason={devicesError() ?? undefined} />}>
                <Show when={devices().length > 0} fallback={<LiveState kind="empty" label="No devices observed yet" />}>
                  <ul class="obs-assets">
                    <For each={devices()}>
                      {(dv) => (
                        <li class="obs-asset-row">
                          <span class="obs-asset-name">{dv.ip}</span>
                          <span class="obs-asset-mac">{dv.mac ?? 'mac unknown'}</span>
                          <span class="obs-asset-count">{formatTime(dv.last_seen)}</span>
                        </li>
                      )}
                    </For>
                  </ul>
                  <div class="obs-asset-total">
                    <span class="obs-asset-total-v">{devices().length} device{devices().length === 1 ? '' : 's'} observed</span>
                  </div>
                </Show>
              </Show>
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

export default ObserveApp;
