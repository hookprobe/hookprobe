/**
 * ConfigurationApp — Administration → Configuration and keys (`/admin/config`; canvas board "AdminConfig").
 * One place to see what configuration is in force, who can change it, how it is stored, how changes apply, and the
 * journal of recent changes — all from the device (GET /api/config, /api/anchor, /api/upload).
 *
 *   in force     state + generation, bundle floor, per-file floors, automatic rollback, live phase
 *   who          the signing key the device trusts, the image (vendor) key, this device's id
 *   stored       sealed with the device key or not (at_rest), in plain words
 *   journal      activations (owner journal): applied / rolled back / refused, with the device's own detail
 *   actions      Change settings (Advanced), Roll back to N (signed pack rollback of type config), Restart
 */
import { type Component, For, Show, onMount } from 'solid-js';
import AppShell from './AppShell';
import AdminTabs from './AdminTabs';
import RestartButton from './RestartButton';
import { substrate } from '../store/mock';
import { healthChecked } from '../store/health';
import { configView, refreshConfig, restNote, type ConfigView } from '../store/configState';
import { anchorView, refreshAnchor, type AnchorView } from '../store/anchor';
import { uploadView, refreshUploads, rollbackPack } from '../store/packUpload';
import { approve } from '../store/approve';
import { createSignal } from 'solid-js';

const STATE: Record<string, string> = { none: 'No bundle (per-file settings)', committed: 'Committed', trial: 'On trial', reverted: 'Switched back', refused: 'Refused at boot' };
const TYPE: Record<string, string> = { config: 'Configuration bundle', wan: 'Internet file', wifi: 'Wi-Fi file', policy: 'Firewall file', shield_block: 'Shield block list', shield_allow: 'Shield allow list', ioc: 'Threat-intel pack', rules: 'Rule pack', oui: 'Vendor list', devices: 'Device policy', os_image: 'OS image' };

// No device answering: the board's three cards with labelled sample values (the page banner says it is sample data).
const SAMPLE_CFG = { state: 'committed', generation: 9, floor: 9, auto_rollback: true, at_rest: { sealed: true, secrets_protected: true, device_key: true, volatile_ram_only: false, persisted: true } } as unknown as ConfigView;
const SAMPLE_ANCHOR = { state: 'protected', owner_enrolled: true, owner_key: '3f9a1c0e7b2d', owner_generation: 1, vendor_key: 'a81d44e2c905', device_id: '7c1e9b04d2a65f38', floors: { wan: 8, wifi: 8, policy: 8 } } as unknown as AnchorView;
const SAMPLE_JOURNAL = [
  { seq: 1, ms: 0, type: 'config', result: 'ok', detail: 'gen 7->8' },
  { seq: 2, ms: 0, type: 'shield_block', result: 'ok', detail: 'gen 3->4' },
  { seq: 3, ms: 0, type: 'config', result: 'ok', detail: 'gen 8->9' },
];

/** The journal's detail, in words: "gen 8->9 sha256:…" / "rollback gen 9->8" / "<op> gen N <reason>". */
function describe(detail: string): string {
  let m = detail.match(/^rollback gen (\d+)->(\d+)/);
  if (m) return `rolled back from generation ${m[1]} to ${m[2]}`;
  m = detail.match(/^gen (\d+)->(\d+)/);
  if (m) return `generation ${m[1]} → ${m[2]}`;
  m = detail.match(/^(\S+) gen (\d+)\s*(.*)$/);
  if (m) return `${m[1]} · generation ${m[2]}${m[3] ? ` · ${m[3]}` : ''}`;
  return detail;
}

const ConfigurationApp: Component = () => {
  const [msg, setMsg] = createSignal('');
  onMount(() => { void refreshConfig(); void refreshAnchor(); void refreshUploads(); });
  const sample = () => healthChecked() && !substrate();
  const c = () => (sample() ? SAMPLE_CFG : configView());
  const a = () => (sample() ? SAMPLE_ANCHOR : anchorView());
  const journal = () => (sample() ? SAMPLE_JOURNAL : uploadView()?.activations ?? []);
  const cfgSlot = () => uploadView()?.types.find((t) => t.type === 'config');
  const fp = (h?: string | null) => (h ? `${h.slice(0, 8)}…` : '—');
  const devId = () => { const d = a()?.device_id; return d && /[1-9a-f]/i.test(d) ? fp(d) : 'none (bundles not bound to this device)'; };
  const floorRow = (k: 'wan' | 'wifi' | 'policy') => { const f = a()?.floors?.[k]; return f === undefined ? '—' : typeof f === 'number' ? `older than ${f + 1} refused` : `${f.current} (older than ${f.floor + 1} refused)`; };

  const rollBack = async (to: number) => {
    setMsg('');
    if (!(await approve({ title: `Roll back to configuration generation ${to}?`, body: 'The previous verified bundle kept on the device comes back. If its internet or Wi-Fi settings no longer match your line, the device may go offline until you fix them.', confirm: 'Roll back', destructive: true }))) return;
    try { setMsg((await rollbackPack('config', to)).text); } catch (e) { setMsg(e instanceof Error ? e.message : String(e)); }
    void refreshConfig(); void refreshUploads();
  };

  return (
    <AppShell path="/admin/identity">
      <main class="pro-main" aria-label="Configuration and keys">
        <div class="pro-head">
          <div>
            <p class="pro-crumb"><a href="/admin/identity">Administration</a> / Configuration</p>
            <h1 class="pro-title">Configuration and keys</h1>
            <p class="pro-sub">What is in force, who can change it, how it is stored, and what changed recently, as this device reports it.</p>
          </div>
        </div>
        <AdminTabs current="/admin/config" />
        <Show when={msg()}><p class="pro-sub" role="status" style={{ margin: 0 }}>{msg()}</p></Show>

        <div class="cfg-grid">
            <div class="pcard" aria-label="Configuration in force">
              <p class="l0-label">Configuration in force</p>
              <span class="cfg-big">{c() ? `${STATE[c()!.state] ?? c()!.state}${c()!.generation ? ` · generation ${c()!.generation}` : ''}` : 'Not reported'}</span>
              <span class="prow"><span>Bundle floor</span><span>{c()?.floor ?? '—'}</span></span>
              <span class="prow"><span>Internet file</span><span>{floorRow('wan')}</span></span>
              <span class="prow"><span>Wi-Fi file</span><span>{floorRow('wifi')}</span></span>
              <span class="prow"><span>Firewall file</span><span>{floorRow('policy')}</span></span>
              <span class="prow"><span>Automatic rollback</span><span>{c()?.auto_rollback ? 'on (bundles only)' : 'off'}</span></span>
              <Show when={c()?.live && c()!.live!.phase !== 'idle'}><span class="prow"><span>Now</span><span>{c()!.live!.phase}</span></span></Show>
              <div class="l0-card-foot"><a class="hp-btn" href="/network/wan/advanced">Change settings</a></div>
            </div>

            <div class="pcard" aria-label="Who can change it">
              <p class="l0-label">Who can change it</p>
              <span class="cfg-big">{a()?.state === 'CONFIG UNPROTECTED' ? 'Not protected' : a()?.owner_enrolled ? 'Only your signing key' : a() ? 'The image key' : 'Not reported'}</span>
              <span class="prow"><span>Signing key it trusts (internet, Wi-Fi, firewall)</span><span>{a()?.owner_enrolled ? `${fp(a()!.owner_key)} · generation ${a()!.owner_generation}` : 'none yet'}</span></span>
              <span class="prow"><span>Image key (block lists, threat intel)</span><span>{fp(a()?.vendor_key)}</span></span>
              <span class="prow"><span>This device's id</span><span>{devId()}</span></span>
              <div class="l0-card-foot"><a class="hp-btn" href="/admin/identity">Manage your signing key</a></div>
            </div>

            <div class="pcard" aria-label="Stored settings">
              <p class="l0-label">Stored settings</p>
              <span class="cfg-big">{c()?.at_rest ? (c()!.at_rest!.secrets_protected && c()!.at_rest!.device_key ? 'Sealed with the device key' : c()!.at_rest!.volatile_ram_only ? 'Kept in memory only' : 'Not protected at rest') : 'Not reported'}</span>
              <Show when={c()?.at_rest}>
                <span class="prow"><span>Encrypted at rest</span><span>{c()!.at_rest!.sealed ? 'yes' : 'no'}</span></span>
                <span class="prow"><span>Passwords protected</span><span>{c()!.at_rest!.secrets_protected ? 'yes' : 'no'}</span></span>
                <span class="prow"><span>Device key</span><span>{c()!.at_rest!.device_key ? 'present' : 'missing'}</span></span>
              </Show>
              <p class="pcard-note" style={{ margin: 0 }}>{sample() ? 'Sample: on a device this says how its settings are protected at rest.' : restNote()}</p>
            </div>
          </div>

          <div class="cfg-grid cfg-grid--2">
            <div class="pcard" aria-label="How changes apply">
              <p class="l0-label">How changes apply</p>
              <span class="prow"><span>Firewall, routes, internet</span><span>live · kept by itself when the internet works (2 min)</span></span>
              <span class="prow"><span>Wi-Fi, management network</span><span>live · you press Keep within 5 min</span></span>
              <span class="prow"><span>Single files (no bundle)</span><span>next restart · no automatic rollback</span></span>
              <span class="prow"><span>OS update, factory reset</span><span>restart</span></span>
              <p class="pcard-note" style={{ margin: 0 }}>A bundle is the whole configuration: a section left out of a new bundle is removed.</p>
            </div>

            <div class="pcard" aria-label="Recent changes">
              <p class="l0-label">Recent changes (journal)</p>
              <For each={[...journal()].reverse().slice(0, 8)} fallback={<p class="pcard-note" style={{ margin: 0 }}>Nothing recorded yet.</p>}>{(r) => (
                <span class="prow"><span>{TYPE[r.type] ?? r.type} · {describe(r.detail)}</span><span class={r.result === 'ok' ? '' : 'cfg-refused'}>{r.result === 'ok' ? 'applied' : r.result}</span></span>
              )}</For>
              <div class="l0-card-foot">
                <Show when={sample()}>
                  <span class="gate gate--off"><span class="gate-body" ref={(el) => el.setAttribute('inert', '')} aria-hidden="true"><button class="hp-btn">Roll back to 8</button></span><span class="gate-reason" role="note">Preview: no device is answering.</span></span>
                </Show>
                <Show when={!sample() && typeof cfgSlot()?.rollback_to === 'number'}>
                  <button class="hp-btn" onClick={() => void rollBack(cfgSlot()!.rollback_to!)}>Roll back to {cfgSlot()!.rollback_to}</button>
                </Show>
                <RestartButton />
              </div>
            </div>
          </div>
      </main>
    </AppShell>
  );
};

export default ConfigurationApp;
