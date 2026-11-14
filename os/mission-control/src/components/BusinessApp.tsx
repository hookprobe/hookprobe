/**
 * BusinessApp — Business (`/business/dashboard`): licenses, billing, marketplace (wireframe
 * "Business"; requirements doc §10). Standalone devices see licensing only (FR-05).
 *
 * Device: the licence it actually runs under (open core: HookProbe OS + the standalone SOC are
 * AGPL-3.0, no account) and the signed packs it has; billing and the marketplace belong to a control
 * plane and are greyed with that reason. Preview (no device): the wireframe's sample business view.
 */
import { type Component, For, Show, createSignal, onMount } from 'solid-js';
import { substrate, deployMode } from '../store/mock';
import { healthChecked } from '../store/health';
import { uploadView, refreshUploads, PACK_LABEL } from '../store/packUpload';
import AppShell from './AppShell';

type Tab = 'licensing' | 'overview' | 'market';
const MODULES = [
  { name: 'Ransomware early warning', kind: 'Detection', desc: 'Behavioural signs of mass encryption on file shares.', meta: 'wasm · signed · 2.1 MB' },
  { name: 'Microsoft 365 sign-ins', kind: 'Integration', desc: 'Impossible-travel and token-theft signals from Entra ID.', meta: 'wasm · signed · 1.4 MB' },
  { name: 'Printer hardening', kind: 'Policy', desc: 'Keeps printers in their own zone with only print ports open.', meta: 'wasm · signed · 0.3 MB' },
];

const BusinessApp: Component = () => {
  const [tab, setTab] = createSignal<Tab>('licensing');
  onMount(() => void refreshUploads());
  const sample = () => healthChecked() && !substrate();
  const linked = () => deployMode() !== 'standalone';
  const tabs = (): [Tab, string][] => (sample() || linked() ? [['licensing', 'Licensing'], ['overview', 'Overview'], ['market', 'Marketplace']] : [['licensing', 'Licensing']]);

  return (
    <AppShell path="/business/dashboard">
      <main class="pro-main" aria-label="Business">
        <div class="pro-head">
          <div>
            <h1 class="pro-title">Business</h1>
            <p class="pro-sub">Licenses, billing, marketplace. Standalone devices see licensing only</p>
          </div>
        </div>
        <div class="tabs" role="tablist" aria-label="Business views">
          <For each={tabs()}>{([t, label]) => <button class="tab" role="tab" aria-selected={tab() === t} onClick={() => setTab(t)}>{label}</button>}</For>
        </div>

        <Show when={tab() === 'licensing'}>
          <div class="bento">
            <div class="pcard span-6">
              <p class="l0-label">This device</p>
              <p class="pcard-kpi" style={{ 'font-size': '22px' }}>HookProbe OS · Community</p>
              <p class="l0-card-sub">The operating system and the full standalone SOC are free under the GNU AGPL-3.0. No account, no cloud, works air-gapped.</p>
              <p class="pcard-note">Running it as a service for others, or the cloud / account layer, needs a commercial licence (dual licence: AGPL-3.0 + commercial).</p>
            </div>
            <div class="pcard span-6">
              <p class="l0-label">Signed content on this device</p>
              <Show when={!sample()} fallback={<p class="l0-card-sub">Threat-intel pack · generation 7 · Shield lists · generation 12</p>}>
                <For each={(uploadView()?.types ?? []).filter((x) => x.generation > 0)} fallback={<p class="pcard-note">Only the packs from the boot image.</p>}>{(x) => (
                  <span class="prow"><span>{PACK_LABEL[x.type] ?? x.type}</span><span>generation {x.generation}</span></span>
                )}</For>
              </Show>
            </div>
          </div>
        </Show>

        <Show when={tab() === 'overview'}>
          <Show when={sample()} fallback={<div class="pcard"><p style={{ margin: 0 }}>No billing data from the control plane yet.</p></div>}>
            <p class="plan-diff-warn" role="note" style={{ margin: 0 }}>Preview of what a cloud-linked control plane shows (MSSP billing). A standalone device has no billing and shows licensing only.</p>
            <div class="bento">
              <div class="pcard span-4"><p class="l0-label">Active licenses</p><p class="pcard-kpi">45</p></div>
              <div class="pcard span-4"><p class="l0-label">Devices in use</p><p class="pcard-kpi">1,120</p></div>
              <div class="pcard span-4"><p class="l0-label">Monthly revenue</p><p class="pcard-kpi">—</p><p class="pcard-note">Reported by your billing system, not this device.</p></div>
              <div class="span-12 l0-table-wrap"><table class="l0-table obs-table">
                <thead><tr><th scope="col">Customer</th><th scope="col">Plan</th><th scope="col">Devices</th><th scope="col">Renews</th></tr></thead>
                <tbody>
                  <tr><td>Clinic Nord</td><td>Fortress</td><td>64 / 75</td><td>2027-02-01</td></tr>
                  <tr><td>Bakery Sud</td><td>Guardian</td><td>18 / 20</td><td>2026-12-15</td></tr>
                  <tr><td>IT Partner Vest</td><td>Nexus · MSSP</td><td>210 / 300</td><td>2027-06-30</td></tr>
                </tbody>
              </table></div>
            </div>
          </Show>
        </Show>

        <Show when={tab() === 'market'}>
          <p class="l0-card-sub" style={{ margin: 0 }}>Signed modules: detections, integrations, policies. Installing shows exactly which capabilities a module gets.</p>
          <div class="bento">
            <For each={MODULES}>{(m) => (
              <div class="pcard span-4">
                <span class="prow" style={{ border: 0, padding: 0 }}><span style={{ 'font-weight': 600 }}>{m.name}</span><span>{m.kind}</span></span>
                <span class="l0-card-sub">{m.desc}</span>
                <span class="pcard-note">{m.meta}</span>
                <span class="gate gate--off">
                  <span class="gate-body" ref={(el) => el.setAttribute('inert', '')} aria-hidden="true"><button class="hp-btn">Install</button></span>
                  <span class="gate-reason" role="note">{sample() ? 'Preview: modules install through a control plane.' : 'Modules are installed through your control plane, which signs them for this device.'}</span>
                </span>
              </div>
            )}</For>
          </div>
        </Show>
      </main>
    </AppShell>
  );
};

export default BusinessApp;
