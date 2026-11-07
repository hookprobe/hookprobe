/**
 * CustomersApp — Customers (§9): recursive multi-tenant portal.
 *
 * Spec: docs/architecture/MissionControl.md §9. AWS-Organizations-style tenancy:
 * HookProbe → MSSP → Customer → Customer … unlimited depth, hard per-tenant
 * isolation, scoped RBAC, separate keys. Cloud-linked / self-hosted only.
 *
 * Panels (terminal-framed, cyber-industrial):
 *   KPI row · Managed Customers table · Tenant Inheritance Tree · SLA/Compliance
 *
 * Capability-gated on `cloud-linked` mode in a real build (Platform Manifest).
 */

import { type Component, For } from 'solid-js';
import LeftRail from './LeftRail';
import CommandPalette from './CommandPalette';
import { setCopilotOpen, setCopilotQuery, copilotOpen, copilotQuery } from '../store/mock';
import type { Tone } from '../store/missionMock';
import {
  type ManagedCustomer, type TenantNode, type SlaEntry,
  KPIS, MANAGED, TENANT_TREE, SLA_ENTRIES, SLA_SUMMARY,
} from '../store/cstMock';

function toneVar(t: Tone): string {
  return { green: 'var(--hp-green)', amber: 'var(--hp-amber)', red: 'var(--hp-red)',
    blue: 'var(--hp-cyan)', cyan: 'var(--hp-cyan)', purple: 'var(--hp-purple)', orange: 'var(--hp-orange)', grey: 'var(--hp-grey)' }[t];
}

// Terminal-framed panel — identical signature to DetectApp.Panel.
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

// Recursive tenant tree node — unlimited depth via SolidJS For.
const TreeNode: Component<{ node: TenantNode; depth: number }> = (p) => (
  <li class="cst-tree-node">
    <div class="cst-tree-row">
      <span class="cst-tree-icon" aria-hidden="true">
        {p.node.role === 'mssp' ? '◫' : '·'}
      </span>
      <span class="cst-tree-name">{p.node.name}</span>
      {p.depth === 0 && <span class="cst-tree-root-badge">ROOT</span>}
      {p.node.role === 'mssp' && p.depth > 0 && <span class="cst-tree-mssp-badge">MSSP</span>}
      <span class="cst-tree-score" style={{ color: toneVar(p.node.tone) }}>{p.node.score}</span>
    </div>
    {p.node.children && p.node.children.length > 0 && (
      <ul class="cst-tree-children">
        <For each={p.node.children}>
          {(child) => <TreeNode node={child} depth={p.depth + 1} />}
        </For>
      </ul>
    )}
  </li>
);

const CustomersApp: Component = () => (
  <div class="dash-layout">
    <LeftRail active="/customers" mode="cloud-linked" onOpenCopilot={() => setCopilotOpen(true)} />

    <main class="dash-main">
      <header class="mc-header">
        <div>
          <h1 class="mc-h1">CUSTOMERS</h1>
          <div class="mc-sub">Recursive multi-tenant portal · AWS-Organizations-style tenancy · cloud-linked only</div>
        </div>
        <div class="mc-header-actions">
          <button class="mc-chip" onClick={() => setCopilotOpen(true)}>⌘ "Why is Vodafone risk increasing?"</button>
          <span class="mc-mode-badge">● cloud-linked</span>
        </div>
      </header>

      <div class="mc-grid">

        {/* KPI row */}
        <div class="mc-cell--kpis cst-kpis">
          <For each={KPIS}>
            {(k) => (
              <div class="mc-kpi" style={{ '--tone': toneVar(k.tone) }}>
                <div class="mc-kpi-label">{k.label}</div>
                <div class="mc-kpi-value">{k.value}</div>
              </div>
            )}
          </For>
        </div>

        {/* Managed customers table */}
        <Panel ctx="managed" title="MANAGED CUSTOMERS" span="span 8">
          <div class="cst-managed-head" aria-hidden="true">
            <span>Customer</span>
            <span>QSecBit</span>
            <span>Endpoints</span>
            <span>Drift</span>
            <span>Compliance</span>
            <span>SLA</span>
            <span>Status</span>
            <span />
          </div>
          <ul class="cst-managed-list" role="list">
            <For each={MANAGED}>
              {(c: ManagedCustomer) => (
                <li class="cst-managed-row">
                  <div class="cst-cust-name-cell">
                    <span class="cst-cust-name">{c.name}</span>
                    <span class="cst-cust-meta">
                      {c.tier} · {c.region}
                      {c.subTenants > 0 ? ` · ${c.subTenants} sub-tenants` : ''}
                    </span>
                  </div>
                  <span class="cst-score" style={{ color: toneVar(c.tone) }}>{c.score}</span>
                  <span class="cst-col-mono">{c.endpoints}</span>
                  <span class={`cst-drift${c.drift === 0 ? ' cst-drift--ok' : c.drift <= 5 ? ' cst-drift--warn' : ' cst-drift--crit'}`}>
                    {c.drift === 0 ? '—' : `+${c.drift}`}
                  </span>
                  <span class="cst-col-mono">{c.compliance}</span>
                  <span class="cst-col-mono">{c.sla}</span>
                  <span class={`cst-status-badge cst-st--${c.status.toLowerCase()}`}>{c.status}</span>
                  <a class="det-link" href="/customers/dashboard" aria-label={`Open ${c.name} dashboard`}>↗</a>
                </li>
              )}
            </For>
          </ul>
        </Panel>

        {/* Tenant inheritance tree */}
        <Panel ctx="tenant-tree" title="TENANT INHERITANCE TREE" span="span 4">
          <ul class="cst-tree" role="tree" aria-label="Tenant hierarchy">
            <TreeNode node={TENANT_TREE} depth={0} />
          </ul>
        </Panel>

        {/* SLA / Compliance summary */}
        <Panel ctx="sla" title="SLA · COMPLIANCE SUMMARY" span="span 12">
          <div class="cst-sla-wrap">
            <div class="cst-sla-summary" aria-label="SLA summary statistics">
              <div class="cst-sla-summary-stat">
                <span class="cst-sla-summary-val" style={{ color: 'var(--hp-green)' }}>{SLA_SUMMARY.overall}</span>
                <span class="cst-sla-summary-label">Overall SLA</span>
              </div>
              <div class="cst-sla-summary-stat">
                <span class="cst-sla-summary-val" style={{ color: 'var(--hp-text-primary)' }}>{SLA_SUMMARY.met}/{SLA_SUMMARY.total}</span>
                <span class="cst-sla-summary-label">Met</span>
              </div>
              <div class="cst-sla-summary-stat">
                <span class="cst-sla-summary-val" style={{ color: 'var(--hp-red)' }}>{SLA_SUMMARY.breached}</span>
                <span class="cst-sla-summary-label">Breached</span>
              </div>
              <div class="cst-sla-summary-stat">
                <span class="cst-sla-summary-val" style={{ color: 'var(--hp-amber)' }}>{SLA_SUMMARY.atRisk}</span>
                <span class="cst-sla-summary-label">At Risk</span>
              </div>
            </div>

            <ul class="cst-sla-list" role="list">
              <For each={SLA_ENTRIES}>
                {(e: SlaEntry) => {
                  const tone = e.met ? 'var(--hp-green)' : e.pct >= 60 ? 'var(--hp-amber)' : 'var(--hp-red)';
                  return (
                    <li class="cst-sla-row">
                      <span class="cst-sla-name">{e.name}</span>
                      <span class="cst-sla-target">target {e.target}</span>
                      <span class="cst-sla-bar" role="progressbar" aria-valuenow={e.pct} aria-valuemin={0} aria-valuemax={100}>
                        <span class="cst-sla-fill" style={{ width: `${e.pct}%`, background: tone }} />
                      </span>
                      <span class="cst-sla-actual" style={{ color: tone }}>{e.actual}</span>
                      <span class={`cst-sla-badge ${e.met ? 'cst-sla-badge--met' : 'cst-sla-badge--miss'}`} aria-label={e.met ? 'SLA met' : 'SLA missed'}>
                        {e.met ? '✓' : '✗'}
                      </span>
                    </li>
                  );
                }}
              </For>
            </ul>
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

export default CustomersApp;
