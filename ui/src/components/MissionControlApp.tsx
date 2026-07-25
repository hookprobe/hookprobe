/**
 * MissionControlApp — Mission Control (§1): the MSSP command center / landing page.
 *
 * Built to match ~/mission-control-page.png exactly: header vitals · 6 KPI cards ·
 * global threat map + top origins · QSecBit score history + factors · AI-decisions
 * and threat-category donuts · recent critical incidents · system-resource rings ·
 * live feed. Clean-card design (no terminal chrome). Charts are inline SVG.
 * Spec: docs/MissionControl.md §1.
 */

import { type Component, For, Show } from 'solid-js';
import AppRail from './AppRail';
import {
  VITALS, KPIS, THREATMAP, QSCORE, AI_DECISIONS, THREAT_CATS, INCIDENTS, RESOURCES, LIVE_FEED,
  type Tone, type Kpi,
} from '../store/missionMock';

const TONE: Record<Tone, string> = {
  green: 'var(--hp-green)', amber: 'var(--hp-amber)', red: 'var(--hp-red)', blue: '#4895ef',
  purple: 'var(--hp-purple)', cyan: 'var(--hp-cyan)', orange: 'var(--hp-orange)', grey: 'var(--hp-grey)',
};

// ── tiny SVG chart helpers ────────────────────────────────────────────────────
function pts(data: number[], w: number, h: number, pad = 2): [number, number][] {
  const max = Math.max(...data), min = Math.min(...data), rng = max - min || 1;
  return data.map((v, i) => [pad + (i * (w - 2 * pad)) / (data.length - 1), h - pad - ((v - min) / rng) * (h - 2 * pad)]);
}
const line = (p: [number, number][]) => p.map((q, i) => `${i ? 'L' : 'M'}${q[0].toFixed(1)},${q[1].toFixed(1)}`).join(' ');
const area = (p: [number, number][], h: number) => `${line(p)} L${p[p.length - 1][0].toFixed(1)},${h} L${p[0][0].toFixed(1)},${h} Z`;

const ICONS: Record<string, string> = { shield: '🛡', pulse: '📈', ai: '🤖', target: '🎯', people: '👥', mesh: '🕸' };

// KPI mini-chart (area / spike line / bars)
const Spark: Component<{ k: Kpi; i: number }> = (p) => {
  const w = 200, h = 46, c = TONE[p.k.tone], gid = `sp${p.i}`;
  const pp = () => pts(p.k.data, w, h);
  return (
    <svg class="mc-spark" viewBox={`0 0 ${w} ${h}`} preserveAspectRatio="none" aria-hidden="true">
      <Show when={p.k.spark === 'bars'} fallback={
        <>
          <defs><linearGradient id={gid} x1="0" x2="0" y1="0" y2="1">
            <stop offset="0" stop-color={c} stop-opacity="0.35" /><stop offset="1" stop-color={c} stop-opacity="0" />
          </linearGradient></defs>
          <path d={area(pp(), h)} fill={`url(#${gid})`} />
          <path d={line(pp())} fill="none" stroke={c} stroke-width="1.5" />
        </>
      }>
        <For each={p.k.data}>{(v, i) => {
          const max = Math.max(...p.k.data), bh = (v / max) * (h - 4), bw = w / p.k.data.length;
          return <rect x={i() * bw + 1} y={h - bh} width={bw - 2} height={bh} fill={c} opacity="0.85" rx="1" />;
        }}</For>
      </Show>
    </svg>
  );
};

// Donut (segments by pct)
const Donut: Component<{ segs: { tone: Tone; pct: number }[]; center: string; sub: string }> = (p) => {
  const r = 54, C = 2 * Math.PI * r; let acc = 0;
  return (
    <svg viewBox="0 0 140 140" class="mc-donut">
      <circle cx="70" cy="70" r={r} fill="none" stroke="var(--hp-surface-elevated)" stroke-width="15" />
      <For each={p.segs}>{s => {
        const len = (s.pct / 100) * C, off = acc; acc += len;
        return <circle cx="70" cy="70" r={r} fill="none" stroke={TONE[s.tone]} stroke-width="15"
          stroke-dasharray={`${len.toFixed(2)} ${(C - len).toFixed(2)}`} stroke-dashoffset={(-off).toFixed(2)}
          transform="rotate(-90 70 70)" />;
      }}</For>
      <text x="70" y="68" class="mc-donut-num">{p.center}</text>
      <text x="70" y="88" class="mc-donut-sub">{p.sub}</text>
    </svg>
  );
};

// Ring gauge
const Ring: Component<{ pct: number; tone: Tone; label: string }> = (p) => {
  const r = 26, C = 2 * Math.PI * r, len = (p.pct / 100) * C;
  return (
    <div class="mc-ring">
      <svg viewBox="0 0 64 64">
        <circle cx="32" cy="32" r={r} fill="none" stroke="var(--hp-surface-elevated)" stroke-width="6" />
        <circle cx="32" cy="32" r={r} fill="none" stroke={TONE[p.tone]} stroke-width="6"
          stroke-dasharray={`${len.toFixed(1)} ${C.toFixed(1)}`} stroke-linecap="round" transform="rotate(-90 32 32)" />
        <text x="32" y="37" class="mc-ring-num">{p.pct}%</text>
      </svg>
      <span class="mc-ring-label">{p.label}</span>
    </div>
  );
};

const SEV: Record<string, string> = { high: 'var(--hp-red)', medium: 'var(--hp-orange)', low: 'var(--hp-amber)', info: '#4895ef' };

const MissionControlApp: Component = () => {
  const qpts = () => pts(QSCORE.trend, 300, 120, 6);
  return (
    <div class="dash-layout">
      <AppRail active="Mission Control" />

      <main class="dash-main mc2">
        {/* ── header ── */}
        <header class="mc2-top">
          <div class="mc2-title">
            <h1>Mission Control</h1><span>Global Situational Awareness</span>
          </div>
          <div class="mc2-vitals">
            <div class="mc2-vital"><em>AI Status</em><b class="t-green">{VITALS.aiStatus}</b></div>
            <div class="mc2-vital"><em>System Health</em><b class="t-green">{VITALS.systemHealth}</b></div>
            <div class="mc2-vital"><em>Active Agents</em><b>{VITALS.activeAgents}</b></div>
            <div class="mc2-vital"><em>Data Ingestion</em><b>{VITALS.ingestion}</b></div>
          </div>
          <div class="mc2-topright">
            <span class="mc2-stamp">{VITALS.stamp}</span>
            <button class="mc2-ic" aria-label="Fullscreen">⛶</button>
            <button class="mc2-ic" aria-label="Notifications">🔔<span class="mc2-badge" /></button>
            <button class="mc2-ic" aria-label="Account">◔</button>
          </div>
        </header>

        {/* ── KPI row ── */}
        <section class="mc2-kpis">
          <For each={KPIS}>{(k, i) => (
            <article class={`mc2-kpi mc2-kpi--${k.tone}`}>
              <div class="mc2-kpi-head">
                <span class="mc2-kpi-label" style={{ color: TONE[k.tone] }}>{k.label.toUpperCase()}</span>
                <span class="mc2-kpi-icon">{ICONS[k.icon]}</span>
              </div>
              <div class="mc2-kpi-value" style={k.value.length > 4 ? { 'font-size': '1.7rem' } : undefined}>{k.value}</div>
              <div class="mc2-kpi-sub">
                <Show when={k.delta}><span style={{ color: TONE[k.tone] }}>{k.delta}</span> </Show>
                <span style={k.subTone ? { color: TONE[k.subTone] } : undefined}>{k.sub}</span>
              </div>
              <Spark k={k} i={i()} />
            </article>
          )}</For>
        </section>

        {/* ── threat map + QSecBit history ── */}
        <section class="mc2-two">
          {/* threat map */}
          <article class="mc2-card mc2-map">
            <header class="mc2-card-head">
              <h2>Global Threat Map</h2>
              <div class="mc2-card-tools"><span class="mc2-pill">Last 24 Hours ▾</span><button class="mc2-ic">↻</button><button class="mc2-ic">⛶</button></div>
            </header>
            <div class="mc2-map-stats">
              <For each={THREATMAP.stats}>{s => (
                <div class="mc2-mstat"><em>{s.label}</em><b>{s.value} <Show when={s.delta}><span style={{ color: TONE[s.tone] }}>{s.delta}</span></Show></b></div>
              )}</For>
            </div>
            <div class="mc2-map-body">
              <div class="mc2-globe">
                <svg viewBox="0 0 100 60" class="mc2-worldsvg" preserveAspectRatio="none" aria-hidden="true">
                  {/* stylized continents (approximate) */}
                  <g class="mc2-land">
                    <path d="M8,16 L26,13 L31,22 L26,30 L16,32 L10,26 Z" />
                    <path d="M24,34 L31,33 L33,44 L28,56 L25,46 Z" />
                    <path d="M44,14 L54,13 L53,22 L46,24 L43,19 Z" />
                    <path d="M45,26 L55,25 L57,40 L50,52 L46,38 Z" />
                    <path d="M55,12 L84,14 L82,30 L66,34 L56,26 Z" />
                    <path d="M76,48 L86,47 L85,56 L77,57 Z" />
                  </g>
                  {/* arcs */}
                  <For each={THREATMAP.arcs}>{a => {
                    const mx = (a.from[0] + a.to[0]) / 2, my = Math.min(a.from[1], a.to[1]) - 12;
                    return <path d={`M${a.from[0]/100*100},${a.from[1]/100*60} Q${mx},${my} ${a.to[0]/100*100},${a.to[1]/100*60}`}
                      fill="none" stroke={SEV[a.sev]} stroke-width="0.5" opacity="0.7" class="mc2-arc" />;
                  }}</For>
                  {/* points */}
                  <For each={THREATMAP.points}>{p => (
                    <circle cx={p[0]} cy={p[1]/100*60} r="0.9" fill={SEV[p[2]]} class="mc2-pt" />
                  )}</For>
                </svg>
                <div class="mc2-map-legend">
                  <span><i style={{ background: SEV.high }} />High Threat</span>
                  <span><i style={{ background: SEV.medium }} />Medium</span>
                  <span><i style={{ background: SEV.low }} />Low</span>
                  <span><i style={{ background: SEV.info }} />Info</span>
                </div>
                <div class="mc2-zoom"><button>+</button><button>⊖</button></div>
              </div>
              <aside class="mc2-origins">
                <div class="mc2-origins-head"><b>Top Attack Origins</b></div>
                <div class="mc2-origins-cols"><span>Country</span><span>Attacks</span></div>
                <For each={THREATMAP.origins}>{o => {
                  const max = Math.max(...THREATMAP.origins.map(x => x.attacks));
                  return (
                    <div class="mc2-origin">
                      <span class="mc2-origin-c"><i style={{ background: o.flag }} />{o.country}</span>
                      <span class="mc2-origin-bar"><i style={{ width: `${(o.attacks / max) * 100}%`, background: o.flag }} /></span>
                      <span class="mc2-origin-n">{o.attacks.toLocaleString()}</span>
                    </div>
                  );
                }}</For>
                <button class="mc2-linkbtn">View Full Threat Intelligence →</button>
              </aside>
            </div>
          </article>

          {/* QSecBit history */}
          <article class="mc2-card mc2-qhist">
            <header class="mc2-card-head"><h2>QSecBit Score History</h2><span class="mc2-pill">30 Days ▾</span></header>
            <div class="mc2-qtop">
              <span class="mc2-qbig">{QSCORE.score}<em>/100</em></span>
              <span class="mc2-qdelta t-green">{QSCORE.delta}<em>{QSCORE.deltaSub}</em></span>
            </div>
            <svg viewBox="0 0 300 130" class="mc2-qchart" preserveAspectRatio="none" aria-hidden="true">
              <defs><linearGradient id="qg" x1="0" x2="0" y1="0" y2="1"><stop offset="0" stop-color="var(--hp-green)" stop-opacity="0.3" /><stop offset="1" stop-color="var(--hp-green)" stop-opacity="0" /></linearGradient></defs>
              <For each={[0, 25, 50, 75, 100]}>{g => <line x1="0" x2="300" y1={120 - g / 100 * 114} y2={120 - g / 100 * 114} stroke="var(--hp-border)" stroke-width="0.5" />}</For>
              <path d={area(qpts(), 130)} fill="url(#qg)" />
              <path d={line(qpts())} fill="none" stroke="var(--hp-green)" stroke-width="2" />
              <For each={qpts()}>{q => <circle cx={q[0]} cy={q[1]} r="2" fill="var(--hp-green)" />}</For>
            </svg>
            <div class="mc2-qaxis"><For each={QSCORE.axis}>{a => <span>{a}</span>}</For></div>
            <div class="mc2-factors">
              <div class="mc2-factors-head"><span>Score Factors</span><span>Score</span></div>
              <For each={QSCORE.factors}>{f => (
                <div class="mc2-factor">
                  <span class="mc2-factor-name">✓ {f.name}</span>
                  <span class="mc2-factor-bar"><i style={{ width: `${f.score}%` }} /></span>
                  <span class="mc2-factor-score">{f.score}</span>
                </div>
              )}</For>
            </div>
          </article>
        </section>

        {/* ── bottom row: 4 panels ── */}
        <section class="mc2-four">
          {/* AI decisions */}
          <article class="mc2-card">
            <header class="mc2-card-head"><h2>AI Decisions (Today)</h2></header>
            <div class="mc2-donut-row">
              <Donut segs={AI_DECISIONS.segments} center={String(AI_DECISIONS.total)} sub="Total" />
              <ul class="mc2-legend">
                <For each={AI_DECISIONS.segments}>{s => (
                  <li><i style={{ background: TONE[s.tone] }} /><span>{s.name}</span><b>{s.n} ({s.pct}%)</b></li>
                )}</For>
              </ul>
            </div>
            <button class="mc2-linkbtn">View AI Activity →</button>
          </article>

          {/* threat categories */}
          <article class="mc2-card">
            <header class="mc2-card-head"><h2>Threat Categories (24H)</h2></header>
            <div class="mc2-donut-row">
              <Donut segs={THREAT_CATS.segments} center={THREAT_CATS.total} sub="Total" />
              <ul class="mc2-legend">
                <For each={THREAT_CATS.segments}>{s => (
                  <li><i style={{ background: TONE[s.tone] }} /><span>{s.name}</span><b>{s.pct}%</b></li>
                )}</For>
              </ul>
            </div>
            <button class="mc2-linkbtn">View All Threats →</button>
          </article>

          {/* recent critical incidents */}
          <article class="mc2-card">
            <header class="mc2-card-head"><h2>Recent Critical Incidents</h2><button class="mc2-link">View All →</button></header>
            <ul class="mc2-inc">
              <For each={INCIDENTS}>{inc => (
                <li>
                  <span class={`mc2-inc-dot mc2-sev--${inc.sev.toLowerCase()}`} />
                  <span class="mc2-inc-text"><b>{inc.title}</b><em>Customer: {inc.customer}</em></span>
                  <span class="mc2-inc-right"><span class={`mc2-sevtag mc2-sev--${inc.sev.toLowerCase()}`}>{inc.sev}</span><em>{inc.time}</em></span>
                </li>
              )}</For>
            </ul>
          </article>

          {/* system resources */}
          <article class="mc2-card">
            <header class="mc2-card-head"><h2>System Resources</h2></header>
            <div class="mc2-rings"><For each={RESOURCES.rings}>{r => <Ring pct={r.pct} tone={r.tone} label={r.label} />}</For></div>
            <div class="mc2-through">
              <For each={RESOURCES.throughput}>{t => (
                <div class="mc2-thru">
                  <em>{t.label}</em><b>{t.value}</b>
                  <svg viewBox="0 0 120 30" class="mc2-thru-spark" preserveAspectRatio="none" aria-hidden="true">
                    <path d={line(pts(t.data, 120, 30, 2))} fill="none" stroke="#4895ef" stroke-width="1.5" />
                  </svg>
                </div>
              )}</For>
            </div>
          </article>
        </section>

        {/* ── live feed ── */}
        <footer class="mc2-feed">
          <span class="mc2-feed-live"><i />LIVE FEED</span>
          <For each={LIVE_FEED}>{f => (
            <span class="mc2-feed-item"><em>{f.time}</em> <b style={{ color: TONE[f.tagTone] }}>[{f.tag}]</b> {f.text}</span>
          )}</For>
          <button class="mc2-link mc2-feed-all">View All Feed →</button>
        </footer>
      </main>
    </div>
  );
};

export default MissionControlApp;
