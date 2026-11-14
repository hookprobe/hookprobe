/**
 * CustomersApp — Customers (`/customers/managed`): the recursive multi-tenant portal (wireframe
 * "Customers"; requirements doc §9). Cloud-linked only: tenants come from the control plane.
 *
 * Standalone device: says so and shows how linking works (the rail hides Customers there).
 * Linked device with no tenant data yet: says so. Preview (no device): the wireframe's tenant tree.
 */
import { type Component, For, Show, createSignal } from 'solid-js';
import { substrate, deployMode } from '../store/mock';
import { healthChecked } from '../store/health';
import AppShell from './AppShell';

interface Tenant { label: string; depth: number; score: number; sla: string; sites: string; inc: number; nis2: number; gdpr: number; users: string }
const TREE: Tenant[] = [
  { label: 'HookProbe MSSP', depth: 0, score: 91, sla: '99.9%', sites: '12 · 1,120', inc: 3, nis2: 88, gdpr: 93, users: '9 users · 3 admins · SSO on' },
  { label: 'Clinic Nord', depth: 1, score: 94, sla: '100%', sites: '3 · 64', inc: 0, nis2: 82, gdpr: 90, users: '4 users · 1 admin · SSO on' },
  { label: 'Bakery Sud', depth: 1, score: 71, sla: '99.5%', sites: '1 · 18', inc: 2, nis2: 64, gdpr: 78, users: '2 users · 1 admin' },
  { label: 'IT Partner Vest', depth: 1, score: 89, sla: '99.9%', sites: '6 · 210', inc: 1, nis2: 85, gdpr: 91, users: '6 users · 2 admins · SSO on' },
  { label: 'Dental Est', depth: 2, score: 86, sla: '100%', sites: '1 · 22', inc: 0, nis2: 79, gdpr: 88, users: '2 users · 1 admin' },
];

const CustomersApp: Component = () => {
  const [sel, setSel] = createSignal(1);
  const sample = () => healthChecked() && !substrate();
  const linked = () => deployMode() !== 'standalone';
  const t = () => TREE[sel()];

  return (
    <AppShell path="/customers/managed">
      <main class="pro-main" aria-label="Customers">
        <div class="pro-head">
          <div>
            <h1 class="pro-title">Customers</h1>
            <p class="pro-sub">Cloud-linked only. Tenants nest: any customer can manage its own customers</p>
          </div>
        </div>

        <Show when={sample()} fallback={
          <div class="pcard" style={{ 'max-width': '760px' }}>
            <Show when={linked()} fallback={
              <>
                <p style={{ margin: 0 }}>This device is standalone, so it has no customers.</p>
                <p class="l0-card-sub">Customers appear when the device is linked to a control plane — your MSSP's or your own self-hosted one. Linking is additive: everything on this device keeps working without it, and each tenant's data stays isolated.</p>
                <div class="l0-card-foot"><a class="hp-btn" href="/admin/identity">Open Administration</a><a class="hp-btn" href="/mission">Back to Mission Control</a></div>
              </>
            }>
              <p style={{ margin: 0 }}>Linked, but the control plane has not sent tenant data yet.</p>
              <p class="l0-card-sub">Tenants and their scores appear here as the control plane reports them. Above your own level you only ever see aggregates.</p>
            </Show>
          </div>
        }>
          <div class="obs-grid obs-grid--wide">
            <nav class="pcard obs-sources" aria-label="Tenant tree">
              <p class="l0-label" style={{ padding: '0 8px 6px' }}>Tenant tree</p>
              <For each={TREE}>{(x, i) => (
                <button class={`shell-rail-item${sel() === i() ? ' is-active' : ''}`} aria-pressed={sel() === i()} onClick={() => setSel(i())}
                  style={{ 'padding-left': `${12 + x.depth * 16}px`, 'justify-content': 'space-between' }}>
                  <span>{x.depth ? '↳ ' : ''}{x.label}</span><span class="l0-num" style={{ 'font-weight': 400, 'font-size': '12px' }}>{x.score}</span>
                </button>
              )}</For>
            </nav>
            <section style={{ display: 'flex', 'flex-direction': 'column', gap: '16px', 'min-width': 0 }}>
              <div class="pro-head">
                <h2 style={{ margin: 0, 'font-size': '20px' }}>{t().label}</h2>
                <div class="l0-head-actions"><a class="hp-btn" href="/mission">Open as this customer</a><span class="gate gate--off" title="Customer reports are made by the control plane (cloud-linked or self-hosted), not by this device"><span class="gate-body" ref={(el) => el.setAttribute('inert', '')} aria-hidden="true"><button class="hp-btn hp-btn--primary">Generate report</button></span><span class="gate-reason" role="note">Reports come from the control plane, not this device.</span></span></div>
              </div>
              <div class="bento">
                <div class="pcard span-4"><p class="l0-label">Security score</p><p class="pcard-kpi">{t().score}</p></div>
                <div class="pcard span-4"><p class="l0-label">SLA this month</p><p class="pcard-kpi">{t().sla}</p></div>
                <div class="pcard span-4"><p class="l0-label">Sites · devices</p><p class="pcard-kpi">{t().sites}</p></div>
                <div class="pcard span-6">
                  <p class="l0-label">Compliance</p>
                  <For each={[['NIS2', t().nis2], ['GDPR', t().gdpr]] as [string, number][]}>{([k, v]) => (
                    <span class="pbar"><span class="pbar-name">{k}</span><span class="pbar-track"><span class="pbar-fill" style={{ width: `${v}%`, background: 'var(--hp-cyan)' }} /></span><span class="pbar-val">{v}%</span></span>
                  )}</For>
                </div>
                <div class="pcard span-6">
                  <p class="l0-label">Users and access · {t().inc} open incident{t().inc === 1 ? '' : 's'}</p>
                  <span class="l0-card-sub">{t().users}</span>
                  <span class="pcard-note">Data is isolated per tenant; you see aggregates only above this level.</span>
                </div>
              </div>
            </section>
          </div>
        </Show>
      </main>
    </AppShell>
  );
};

export default CustomersApp;
