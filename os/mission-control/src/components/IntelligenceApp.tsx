/**
 * IntelligenceApp — Intelligence (§8, HYDRA): threat intelligence workspace.
 *
 * Spec: docs/architecture/MissionControl.md §8. HYDRA = the 11-service ids-hydra-* pipeline
 * (feeds/CVE/IOC/anomaly/predictor/temporal). Ingests STIX/TAXII + MISP; every
 * IOC links to every event/endpoint it touched; every CVE links to affected assets.
 * Capability-gated on `threat_intel` in a real build. Cyber-industrial terminal soul.
 */

import { type Component, For } from 'solid-js';
import LeftRail from './LeftRail';
import CommandPalette from './CommandPalette';
import { setCopilotOpen, setCopilotQuery, copilotOpen, copilotQuery } from '../store/mock';
import type { Tone } from '../store/missionMock';
import { KPIS, CVES, IOCS, THREAT_ACTORS, FEEDS } from '../store/itlMock';

function toneVar(t: Tone): string {
  return { green: 'var(--hp-green)', amber: 'var(--hp-amber)', red: 'var(--hp-red)',
    blue: 'var(--hp-cyan)', cyan: 'var(--hp-cyan)', purple: 'var(--hp-purple)', orange: 'var(--hp-orange)', grey: 'var(--hp-grey)' }[t];
}

const Panel: Component<{ ctx: string; title: string; span?: string; children: any }> = (p) => (
  <section class="hp-terminal mc-panel" style={p.span ? { 'grid-column': p.span } : undefined}>
    <div class="hp-terminal-bar">
      <span class="hp-dot red"    aria-hidden="true" />
      <span class="hp-dot yellow" aria-hidden="true" />
      <span class="hp-dot green"  aria-hidden="true" />
      <span class="mc-panel-title">{p.title}</span>
      <span class="hp-terminal-title">hookprobe@edge ~ {p.ctx}</span>
    </div>
    <div class="hp-terminal-body mc-panel-body">{p.children}</div>
  </section>
);

const IntelligenceApp: Component = () => (
  <div class="dash-layout">
    <LeftRail active="/intelligence" mode="cloud-linked" onOpenCopilot={() => setCopilotOpen(true)} />

    <main class="dash-main">
      <header class="mc-header">
        <div>
          <h1 class="mc-h1">INTELLIGENCE</h1>
          <div class="mc-sub">Threat intelligence &amp; enrichment · HYDRA</div>
        </div>
        <div class="mc-header-actions">
          <button class="mc-chip" onClick={() => setCopilotOpen(true)}>⌘ "CVE-2024-3094 exposure?"</button>
          <span class="mc-mode-badge">● hydra active</span>
        </div>
      </header>

      <div class="mc-grid">

        {/* KPI row */}
        <div class="mc-cell--kpis itl-kpis">
          <For each={KPIS}>
            {(k) => (
              <div class="mc-kpi" style={{ '--tone': toneVar(k.tone) }}>
                <div class="mc-kpi-label">{k.label}</div>
                <div class="mc-kpi-value">{k.value}</div>
              </div>
            )}
          </For>
        </div>

        {/* CVE List */}
        <Panel ctx="cves" title="CVE LIST" span="span 7">
          <ul class="itl-cve-list">
            <For each={CVES}>
              {(c) => (
                <li class="itl-cve-row">
                  <span class={`itl-cve-sev itl-sev--${c.severity}`} aria-label={c.severity}>
                    {c.severity}
                  </span>
                  <span class="itl-cve-id">{c.id}</span>
                  <div class="itl-cve-body">
                    <div class="itl-cve-title">{c.title}</div>
                    <div class="itl-cve-meta">Published {c.published} · CVSS {c.cvss}</div>
                  </div>
                  <a class="itl-cve-assets" href="/intelligence/cves" aria-label={`${c.affectedAssets} affected assets`}>
                    {c.affectedAssets}<span class="itl-unit"> assets</span>
                  </a>
                  <a class="det-link" href="/investigate/queue" aria-label="Investigate">↗</a>
                </li>
              )}
            </For>
          </ul>
        </Panel>

        {/* IOC Matches */}
        <Panel ctx="ioc" title="IOC MATCHES" span="span 5">
          <ul class="itl-ioc-list">
            <For each={IOCS}>
              {(i) => (
                <li class="itl-ioc-row">
                  <span class={`itl-ioc-type itype--${i.type.toLowerCase()}`}>{i.type}</span>
                  <div class="itl-ioc-body">
                    <div class="itl-ioc-indicator">{i.indicator}</div>
                    <div class="itl-ioc-family">{i.family}</div>
                  </div>
                  <span class="itl-ioc-seen">{i.lastSeen}</span>
                  <span class="itl-ioc-hits">{i.hits}<span class="itl-unit"> hits</span></span>
                  <a class="det-link" href="/intelligence/ioc" aria-label="Drill into IOC">↗</a>
                </li>
              )}
            </For>
          </ul>
        </Panel>

        {/* Threat Actors / Campaigns */}
        <Panel ctx="actors" title="THREAT ACTORS / CAMPAIGNS" span="span 6">
          <ul class="itl-actor-list">
            <For each={THREAT_ACTORS}>
              {(a) => (
                <li class="itl-actor-row">
                  <div class="itl-actor-head">
                    <span class="itl-actor-name">{a.name}</span>
                    <span class="itl-actor-alias">{a.alias}</span>
                    <span class="itl-actor-origin">{a.origin}</span>
                  </div>
                  <div class="itl-actor-conf-row">
                    <span class="itl-conf-bar">
                      <span class="itl-conf-fill" style={{ width: `${a.confidence}%` }} />
                    </span>
                    <span class="itl-actor-conf-pct">{a.confidence}%</span>
                    <span class="itl-actor-techs">{a.techniques} techniques</span>
                  </div>
                  <div class="itl-actor-camps">
                    <For each={a.campaigns}>
                      {(c) => <span class="itl-camp-tag">{c}</span>}
                    </For>
                  </div>
                </li>
              )}
            </For>
          </ul>
        </Panel>

        {/* Feed Status */}
        <Panel ctx="feeds" title="FEED STATUS · STIX/TAXII · MISP" span="span 6">
          <ul class="itl-feed-list">
            <For each={FEEDS}>
              {(f) => (
                <li class="itl-feed-row">
                  <span class={`itl-feed-dot fst--${f.status}`} aria-label={f.status} />
                  <div class="itl-feed-body">
                    <div class="itl-feed-name">
                      {f.name}
                      <span class="itl-feed-proto">{f.protocol}</span>
                    </div>
                    <div class="itl-feed-prov">{f.provider}</div>
                  </div>
                  <div class="itl-feed-right">
                    <div class="itl-feed-sync">{f.lastSync}</div>
                    <div class="itl-feed-recs">{f.records}</div>
                  </div>
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

export default IntelligenceApp;
