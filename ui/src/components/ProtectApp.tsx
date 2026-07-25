/**
 * ProtectApp — Protect (§6): response & posture, the data-plane surface.
 *
 * Spec: docs/MissionControl.md §6. Panels (terminal-framed):
 *   KPI row (blocked today, isolated hosts, active policies, fail-closed segments)
 *   PER-INTERFACE POSTURE — the key panel: each NIC, role, fail-open/closed, traffic
 *   ACTIVE CONTROLS — firewall rules + isolation/quarantine (capability-gated)
 *   SEGMENT POLICIES — segment → posture → fail-mode
 *   ZERO TRUST / COMPLIANCE / RISK summary
 *   PROPOSED PLAN — plan-as-diff strip (mirrors InvestigateApp pattern), triggered by
 *     header intent chips: "Make the OT VLAN fail-closed" / "Isolate 10.4.2.17 now"
 *
 * Capability gating: active controls shown when the manifest grants `firewall` /
 * `inline_control`; otherwise rendered greyed-with-reason (alert-only mode).
 * `vpn` not granted → greyed-with-reason example panel.
 */

import { type Component, For, Show, createSignal, createMemo } from 'solid-js';
import LeftRail from './LeftRail';
import CommandPalette from './CommandPalette';
import { setCopilotOpen, setCopilotQuery, copilotOpen, copilotQuery } from '../store/mock';
import type { Tone } from '../store/missionMock';
import {
  type ProtPlan,
  GRANTS, KPIS, INTERFACES, FIREWALL_RULES, ISOLATIONS,
  POLICIES, ZERO_TRUST, COMPLIANCE, RISK, PLANS,
} from '../store/protMock';

function toneVar(t: Tone): string {
  return { green: 'var(--hp-green)', amber: 'var(--hp-amber)', red: 'var(--hp-red)',
    blue: 'var(--hp-cyan)', cyan: 'var(--hp-cyan)', purple: 'var(--hp-purple)', orange: 'var(--hp-orange)', grey: 'var(--hp-grey)' }[t];
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

/** Greyed-with-reason when a manifest grant is absent. */
const GatedPanel: Component<{ ctx: string; title: string; span?: string; grantKey: string; reason: string }> = (p) => (
  <Panel ctx={p.ctx} title={p.title} span={p.span}>
    <div class="prot-gated">
      <span class="prot-gated-icon" aria-hidden="true">⊘</span>
      <div class="prot-gated-body">
        <div class="prot-gated-label">Alert-only mode</div>
        <div class="prot-gated-reason">
          Manifest: <code class="prot-gated-code">{p.grantKey}</code> not granted on this device · {p.reason}
        </div>
      </div>
    </div>
  </Panel>
);

const ProtectApp: Component = () => {
  const [planIdx,  setPlanIdx]  = createSignal<number | null>(null);
  const [showTech, setShowTech] = createSignal(false);
  const [applied,  setApplied]  = createSignal<Set<number>>(new Set());

  const plan      = createMemo<ProtPlan | null>(() => planIdx() !== null ? PLANS[planIdx()!] : null);
  const isApplied = createMemo(() => planIdx() !== null && applied().has(planIdx()!));

  function openPlan(idx: number) {
    setPlanIdx(idx);
    setShowTech(false);
  }

  function approve() {
    const idx = planIdx();
    if (idx !== null) setApplied(prev => new Set([...prev, idx]));
  }

  return (
    <div class="dash-layout">
      <LeftRail active="/protect" mode="cloud-linked" onOpenCopilot={() => setCopilotOpen(true)} />

      <main class="dash-main">
        <header class="mc-header">
          <div>
            <h1 class="mc-h1">PROTECT</h1>
            <div class="mc-sub">Response &amp; posture · data-plane surface · out-of-band default · inline opt-in</div>
          </div>
          <div class="mc-header-actions">
            <For each={PLANS}>
              {(p, i) => (
                <button class="mc-chip" onClick={() => openPlan(i())}>
                  ⌘ "{p.intent}"
                </button>
              )}
            </For>
            <span class="mc-mode-badge">● firewall + inline granted</span>
          </div>
        </header>

        <div class="mc-grid">

          {/* ── KPI row ─────────────────────────────────────────────────── */}
          <div class="mc-cell--kpis prot-kpis">
            <For each={KPIS}>
              {(k) => (
                <div class="mc-kpi" style={{ '--tone': toneVar(k.tone) }}>
                  <div class="mc-kpi-label">{k.label}</div>
                  <div class="mc-kpi-value">{k.value}</div>
                </div>
              )}
            </For>
          </div>

          {/* ── Per-interface posture (KEY PANEL) ───────────────────────── */}
          <Panel ctx="posture" title="PER-INTERFACE POSTURE" span="span 12">
            <div class="prot-ifaces">
              <For each={INTERFACES}>
                {(iface) => (
                  <div class={`prot-iface prot-iface--${iface.role === 'inline' ? 'inline' : 'oob'} prot-iface-st--${iface.status}`}>
                    <div class="prot-iface-top">
                      <div class="prot-iface-name-row">
                        <span class="prot-iface-name">{iface.name}</span>
                        <span class={`prot-iface-st-dot prot-iface-st-dot--${iface.status}`} aria-hidden="true" />
                      </div>
                      <div class="prot-iface-label">{iface.label}</div>
                    </div>
                    <div class="prot-iface-badges">
                      <span class={`prot-role prot-role--${iface.role === 'inline' ? 'inline' : 'oob'}`}>
                        {iface.role}
                      </span>
                      <span class={`prot-fail prot-fail--${iface.failMode === 'fail-closed' ? 'closed' : 'open'}`}>
                        {iface.failMode}
                      </span>
                    </div>
                    <div class="prot-iface-traffic">
                      <div class="prot-traffic-row">
                        <span class="prot-traffic-dir">↓</span>
                        <span class="prot-traffic-val">{iface.trafficIn}</span>
                      </div>
                      <div class="prot-traffic-row">
                        <span class="prot-traffic-dir">↑</span>
                        <span class="prot-traffic-val">{iface.trafficOut}</span>
                      </div>
                      <div class="prot-traffic-pps">{iface.pps}</div>
                    </div>
                    <div class="prot-iface-seg">{iface.segment}</div>
                  </div>
                )}
              </For>
            </div>
          </Panel>

          {/* ── Firewall rules (gated on `firewall` grant) ──────────────── */}
          <Show
            when={GRANTS.firewall}
            fallback={<GatedPanel ctx="firewall" title="ACTIVE FIREWALL RULES" span="span 7" grantKey="firewall" reason="controls read-only" />}
          >
            <Panel ctx="firewall" title="ACTIVE FIREWALL RULES" span="span 7">
              <ul class="prot-rules">
                <For each={FIREWALL_RULES}>
                  {(r) => (
                    <li class={`prot-rule${r.enabled ? '' : ' prot-rule--disabled'}`}>
                      <span class="prot-rule-id">{r.id}</span>
                      <span class={`prot-rule-action prot-ra--${r.action}`}>{r.action}</span>
                      <div class="prot-rule-body">
                        <span class="prot-rule-chain">{r.chain}</span>
                        <span class="prot-rule-flow">
                          <span class="prot-rule-ep">{r.src}</span>
                          <span class="prot-arrow">→</span>
                          <span class="prot-rule-ep">{r.dst}</span>
                        </span>
                        <span class="prot-rule-proto">{r.proto}</span>
                      </div>
                      <span class="prot-rule-hits">
                        {r.hits.toLocaleString()}<span class="prot-rule-hk"> hits</span>
                      </span>
                    </li>
                  )}
                </For>
              </ul>
            </Panel>
          </Show>

          {/* ── Isolations / quarantine (gated on `inline_control` grant) ─ */}
          <Show
            when={GRANTS.inline_control}
            fallback={<GatedPanel ctx="isolation" title="ISOLATION & QUARANTINE" span="span 5" grantKey="inline_control" reason="quarantine unavailable" />}
          >
            <Panel ctx="isolation" title="ISOLATION & QUARANTINE" span="span 5">
              <ul class="prot-isolations">
                <For each={ISOLATIONS}>
                  {(iso) => (
                    <li class="prot-iso">
                      <div class={`prot-iso-dot prot-iso-dot--${iso.status}`} aria-hidden="true" />
                      <div class="prot-iso-body">
                        <div class="prot-iso-host">{iso.host}</div>
                        <div class="prot-iso-ip">{iso.ip}</div>
                        <div class="prot-iso-reason">{iso.reason}</div>
                      </div>
                      <div class="prot-iso-meta">
                        <span class="prot-iso-time">{iso.started}</span>
                        <span class={`prot-iso-status prot-iso-status--${iso.status}`}>{iso.status}</span>
                        <Show when={iso.ttl !== '—'}>
                          <span class="prot-iso-ttl">ttl {iso.ttl}</span>
                        </Show>
                      </div>
                    </li>
                  )}
                </For>
              </ul>
            </Panel>
          </Show>

          {/* ── Segment policies ────────────────────────────────────────── */}
          <Panel ctx="policies" title="SEGMENT POLICIES" span="span 4">
            <ul class="prot-policies">
              <For each={POLICIES}>
                {(pol) => (
                  <li class="prot-policy">
                    <span class="prot-policy-seg" style={{ '--seg-tone': toneVar(pol.tone) }}>
                      {pol.segment}
                    </span>
                    <div class="prot-policy-right">
                      <span class="prot-policy-posture">{pol.posture}</span>
                      <span class={`prot-failmode prot-failmode--${pol.failMode === 'fail-closed' ? 'closed' : 'open'}`}>
                        {pol.failMode}
                      </span>
                      <span class="prot-policy-devs">{pol.devices}d</span>
                    </div>
                  </li>
                )}
              </For>
            </ul>
          </Panel>

          {/* ── Zero-trust ───────────────────────────────────────────────── */}
          <Panel ctx="zt" title="ZERO TRUST" span="span 4">
            <ul class="prot-zt">
              <For each={ZERO_TRUST}>
                {(z) => (
                  <li class="prot-zt-row">
                    <span class="prot-zt-label">{z.label}</span>
                    <span class="prot-zt-val" style={{ color: toneVar(z.tone) }}>{z.value}</span>
                  </li>
                )}
              </For>
            </ul>
          </Panel>

          {/* ── Compliance + Risk ────────────────────────────────────────── */}
          <Panel ctx="risk" title="COMPLIANCE & RISK" span="span 4">
            <div class="prot-compliance">
              <For each={COMPLIANCE}>
                {(c) => {
                  const bar = c.tone === 'green' ? 'var(--hp-green)' : 'var(--hp-amber)';
                  return (
                    <div class="prot-comp-row">
                      <span class="prot-comp-fw">{c.framework}</span>
                      <span class="prot-comp-bar">
                        <span class="prot-comp-fill" style={{ width: `${c.score}%`, background: bar }} />
                      </span>
                      <span class="prot-comp-score" style={{ color: bar }}>{c.score}%</span>
                    </div>
                  );
                }}
              </For>
            </div>
            <div class="prot-risk-div" />
            <ul class="prot-risk">
              <For each={RISK}>
                {(r) => (
                  <li class="prot-risk-row">
                    <span class="prot-risk-label">{r.label}</span>
                    <span class="prot-risk-val" style={{ color: toneVar(r.tone) }}>{r.value}</span>
                  </li>
                )}
              </For>
            </ul>
          </Panel>

          {/* ── VPN — greyed-with-reason (`vpn` not granted) ─────────────── */}
          <Show when={!GRANTS.vpn}>
            <GatedPanel
              ctx="vpn" title="VPN ENDPOINT" span="span 4"
              grantKey="vpn"
              reason="no VPN endpoint provisioned on this device"
            />
          </Show>

          {/* ── Plan-as-diff (mirrors InvestigateApp's plan section) ──────── */}
          <Show when={plan() !== null}>
            <section class="hp-terminal mc-panel prot-plan" style={{ 'grid-column': 'span 12' }}>
              <div class="hp-terminal-bar">
                <span class="hp-dot red" aria-hidden="true" />
                <span class="hp-dot yellow" aria-hidden="true" />
                <span class="hp-dot green" aria-hidden="true" />
                <span class="mc-panel-title">PROPOSED PLAN</span>
                <span class="hp-terminal-title">hookprobe@edge ~ plan</span>
              </div>
              <div class="hp-terminal-body prot-plan-body">
                <div class="prot-plan-intent">{plan()!.intent}</div>
                <p class="prot-plan-summary">{plan()!.summary}</p>
                <ul class="inv-plan-steps">
                  <For each={plan()!.steps}>
                    {(st, idx) => (
                      <li class="inv-plan-step">
                        <span class="inv-plan-num">{idx() + 1}</span>{st}
                      </li>
                    )}
                  </For>
                </ul>
                <button
                  class="inv-tech-toggle"
                  onClick={() => setShowTech(v => !v)}
                  aria-expanded={showTech()}
                >
                  {showTech() ? 'Hide' : 'Show'} technical diff (nftables / OVS)
                </button>
                <Show when={showTech()}>
                  <pre class="inv-tech"><span class="hp-prompt">$</span> {plan()!.technical}</pre>
                </Show>
                <div class="inv-plan-actions">
                  <Show
                    when={!isApplied()}
                    fallback={<span class="inv-applied">✓ Plan applied · enforcing</span>}
                  >
                    <button class="prot-dismiss" onClick={() => { setPlanIdx(null); setShowTech(false); }}>
                      Dismiss
                    </button>
                    <button class="inv-modify" onClick={() => setCopilotOpen(true)}>
                      Modify in Copilot
                    </button>
                    <button class="hp-btn-primary inv-approve" onClick={approve}>
                      Approve &amp; apply
                    </button>
                  </Show>
                </div>
              </div>
            </section>
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

export default ProtectApp;
