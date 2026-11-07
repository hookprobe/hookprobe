/**
 * BusinessApp — Business (§10): run the commercial side inside the platform.
 *
 * Spec: docs/architecture/MissionControl.md §10. Panels (terminal-framed):
 *   KPI row (MRR, licenses, AI cost/mo, SLA, margin)
 *   REVENUE & COSTS — stacked bars (profit / cost) + margin sparkline, 12 months
 *   LICENSES — by tier / customer, seats used with progress bar
 *   MARKETPLACE — signed module catalog (wasm / container, price, installs)
 *   AI COST — per tenant / workspace, model spend breakdown
 *
 * Mode: cloud-linked / self-hosted only for full view (capability-gated in a
 * real build via the Platform Manifest). Standalone would show licensing only.
 * Cyber-industrial terminal soul; stacked bars + sparklines, no pie charts.
 */

import { type Component, For } from 'solid-js';
import LeftRail from './LeftRail';
import CommandPalette from './CommandPalette';
import { setCopilotOpen, setCopilotQuery, copilotOpen, copilotQuery } from '../store/mock';
import type { Tone } from '../store/missionMock';
import {
  type Tier,
  KPIS, REVENUE_COSTS, LICENSES, MODULES, AI_COSTS,
} from '../store/bizMock';

// ── Tone helpers ──────────────────────────────────────────────────────────────

function toneVar(t: Tone): string {
  return {
    green: 'var(--hp-green)', amber: 'var(--hp-amber)', red: 'var(--hp-red)',
    blue: 'var(--hp-cyan)', cyan: 'var(--hp-cyan)', purple: 'var(--hp-purple)', orange: 'var(--hp-orange)', grey: 'var(--hp-grey)',
  }[t];
}
function tierColor(t: Tier): string {
  return t === 'enterprise' ? 'var(--hp-cyan)'
       : t === 'professional' ? 'var(--hp-green)'
       : 'var(--hp-grey)';
}

// ── Shared terminal-window Panel (identical pattern to DetectApp) ─────────────

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

// ── Revenue & Costs — stacked bar chart (SVG, no external deps) ───────────────
//
// Each month bar is split into:
//   top  = profit (green→cyan gradient)
//   base = cost   (amber, semi-opaque)
// The combined height is proportional to revenue against the 12-month max.

const MAX_REV   = Math.max(...REVENUE_COSTS.map(b => b.revenue));
const MAX_AI    = Math.max(...AI_COSTS.map(r => r.cost));
const MARGINS   = REVENUE_COSTS.map(b => Math.round(((b.revenue - b.cost) / b.revenue) * 100));

// SVG chart geometry
const CH    = 96;   // chart height (SVG units)
const CW    = 560;  // chart width  (SVG units)
const BW    = 30;   // bar width
const BGAP  = 16;   // gap between bars
const N     = REVENUE_COSTS.length;
const TOTAL = N * (BW + BGAP) - BGAP;
const XOFF  = (CW - TOTAL) / 2;

// Margin sparkline geometry
const SX = 180; const SY = 28;
const MIN_M = Math.min(...MARGINS);
const MAX_M = Math.max(...MARGINS);
const M_RNG = MAX_M - MIN_M || 1;
const SPARK_PTS = MARGINS
  .map((v, i) => {
    const x = (i / (N - 1)) * (SX - 10) + 5;
    const y = (SY - 4) - ((v - MIN_M) / M_RNG) * (SY - 8);
    return `${x.toFixed(1)},${y.toFixed(1)}`;
  })
  .join(' ');
const LAST_SX = (SX - 10) + 5;
const LAST_SY = (SY - 4) - ((MARGINS[N - 1] - MIN_M) / M_RNG) * (SY - 8);

const RevenueChart: Component = () => (
  <svg viewBox={`0 0 ${CW} ${CH + 20}`} class="biz-chart-svg" role="img"
    aria-label="Revenue and costs stacked by month (trailing 12 months)">
    <defs>
      <linearGradient id="biz-bar-grad" x1="0" y1="1" x2="0" y2="0">
        <stop offset="0%"   stop-color="rgba(0,180,255,0.72)" />
        <stop offset="100%" stop-color="rgba(0,255,157,0.90)" />
      </linearGradient>
    </defs>
    <For each={REVENUE_COSTS}>
      {(b, getI) => {
        const i  = getI();
        const x  = XOFF + i * (BW + BGAP);
        const rh = (b.revenue / MAX_REV) * CH;          // total bar height
        const ch = (b.cost    / MAX_REV) * CH;          // cost portion height
        const ph = rh - ch;                              // profit portion height
        return (
          <g>
            {/* cost segment — sits at the base of the bar */}
            <rect x={x} y={CH - ch} width={BW} height={ch} rx="2"
              fill="rgba(255,170,0,0.50)" />
            {/* profit segment — stacked on top */}
            <rect x={x} y={CH - rh} width={BW} height={ph} rx="2"
              fill="url(#biz-bar-grad)" />
            {/* month label */}
            <text x={x + BW / 2} y={CH + 14}
              text-anchor="middle" font-size="8"
              fill="#7a7a8a" font-family="'JetBrains Mono', monospace">
              {b.month}
            </text>
          </g>
        );
      }}
    </For>
  </svg>
);

const MarginSparkline: Component = () => (
  <svg viewBox={`0 0 ${SX} ${SY}`} class="biz-margin-spark" role="img"
    aria-label={`Margin trend: ${MARGINS[0]}% → ${MARGINS[N - 1]}%`}>
    <polyline points={SPARK_PTS} fill="none"
      stroke="#00FF9D" stroke-width="1.5" stroke-linejoin="round" stroke-linecap="round" />
    <circle cx={LAST_SX} cy={LAST_SY} r="2.5" fill="#00FF9D" />
  </svg>
);

// ── Main component ────────────────────────────────────────────────────────────

const BusinessApp: Component = () => (
  <div class="dash-layout">
    <LeftRail active="/business" mode="cloud-linked" onOpenCopilot={() => setCopilotOpen(true)} />

    <main class="dash-main">
      <header class="mc-header">
        <div>
          <h1 class="mc-h1">BUSINESS</h1>
          <div class="mc-sub">Revenue, licenses, marketplace &amp; AI cost · open-core commercial layer</div>
        </div>
        <div class="mc-header-actions">
          <button class="mc-chip" onClick={() => setCopilotOpen(true)}>⌘ "show top AI spenders"</button>
          <span class="mc-mode-badge">● cloud-linked</span>
        </div>
      </header>

      <div class="mc-grid">

        {/* ── KPI row ── */}
        <div class="mc-cell--kpis biz-kpis">
          <For each={KPIS}>
            {(k) => (
              <div class="mc-kpi" style={{ '--tone': toneVar(k.tone) }}>
                <div class="mc-kpi-label">{k.label}</div>
                <div class="mc-kpi-value">{k.value}</div>
                {k.delta && <div class="mc-kpi-sub mc-kpi-delta">{k.delta}</div>}
              </div>
            )}
          </For>
        </div>

        {/* ── Revenue & Costs ── */}
        <Panel ctx="revenue" title="REVENUE & COSTS · 12 MONTHS" span="span 7">
          <div class="biz-rev-header">
            <div class="biz-legend">
              <span class="biz-leg-swatch biz-leg-swatch--profit" aria-hidden="true" />
              <span class="biz-leg-label">Revenue (profit)</span>
              <span class="biz-leg-swatch biz-leg-swatch--cost" aria-hidden="true" />
              <span class="biz-leg-label">Cost</span>
            </div>
            <div class="biz-margin-row">
              <span class="biz-margin-label">Margin</span>
              <MarginSparkline />
              <span class="biz-margin-val">{MARGINS[N - 1]}%</span>
            </div>
          </div>
          <RevenueChart />
        </Panel>

        {/* ── Licenses by tier ── */}
        <Panel ctx="licenses" title="LICENSES BY TIER" span="span 5">
          <ul class="biz-lic-list">
            <For each={LICENSES}>
              {(l) => {
                const pct  = Math.round((l.seatsUsed / l.seatsTotal) * 100);
                const warn = pct >= 95;
                return (
                  <li class="biz-lic-row">
                    <div class="biz-lic-top">
                      <span class="biz-lic-name">{l.customer}</span>
                      <span class="biz-lic-tier" style={{ color: tierColor(l.tier) }}>{l.tier}</span>
                    </div>
                    <div class="biz-lic-bar-track">
                      <span class="biz-lic-bar-fill"
                        style={{ width: `${pct}%`, background: warn ? 'var(--hp-amber)' : 'var(--hp-gradient)' }} />
                    </div>
                    <div class="biz-lic-foot">
                      <span class="biz-lic-seats">{l.seatsUsed.toLocaleString()} / {l.seatsTotal.toLocaleString()} seats</span>
                      <span class="biz-lic-renew">↻ {l.renewal}</span>
                    </div>
                  </li>
                );
              }}
            </For>
          </ul>
        </Panel>

        {/* ── Marketplace — signed module catalog ── */}
        <Panel ctx="marketplace" title="MARKETPLACE · SIGNED MODULES" span="span 7">
          <ul class="biz-mod-list">
            <For each={MODULES}>
              {(m) => (
                <li class="biz-mod-row">
                  <div class="biz-mod-body">
                    <div class="biz-mod-name">
                      {m.name}
                      <span class="biz-mod-ver">{m.version}</span>
                      {m.signed && <span class="biz-mod-signed" title="cosign verified">✓ signed</span>}
                    </div>
                    <div class="biz-mod-desc">{m.description}</div>
                    <div class="biz-mod-meta">
                      <span class={`biz-rt biz-rt--${m.runtime}`}>{m.runtime}</span>
                      <span class="biz-mod-cat">{m.category}</span>
                    </div>
                  </div>
                  <div class="biz-mod-right">
                    <span class="biz-mod-installs">
                      {m.installs.toLocaleString()}<span class="biz-mod-ik"> installs</span>
                    </span>
                    <span class={`biz-mod-price${m.price === 'free' ? ' biz-mod-price--free' : ''}`}>
                      {m.price}
                    </span>
                  </div>
                </li>
              )}
            </For>
          </ul>
        </Panel>

        {/* ── AI Cost per tenant / workspace ── */}
        <Panel ctx="ai-cost" title="AI COST · PER TENANT / WORKSPACE" span="span 5">
          <ul class="biz-ai-list">
            <For each={AI_COSTS}>
              {(r) => {
                const pct = Math.round((r.cost / MAX_AI) * 100);
                return (
                  <li class="biz-ai-row">
                    <div class="biz-ai-body">
                      <div class="biz-ai-tenant">{r.tenant}</div>
                      <div class="biz-ai-meta">{r.workspace} · {r.model} · {r.tokens} tokens</div>
                    </div>
                    <div class="biz-ai-right">
                      <div class="biz-ai-bar-track">
                        <span class="biz-ai-bar-fill" style={{ width: `${pct}%` }} />
                      </div>
                      <span class="biz-ai-cost">${r.cost.toLocaleString()}</span>
                    </div>
                  </li>
                );
              }}
            </For>
          </ul>
          <div class="biz-ai-total">
            <span class="biz-ai-total-label">Total this month</span>
            <span class="biz-ai-total-val">
              ${AI_COSTS.reduce((s, r) => s + r.cost, 0).toLocaleString()}
            </span>
          </div>
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

export default BusinessApp;
